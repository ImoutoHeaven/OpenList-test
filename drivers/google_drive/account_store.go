package google_drive

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

type accountStoreFlushRequest struct {
	targetRev uint64
	resultCh  chan error
}

type fileAccountStore struct {
	mu           sync.RWMutex
	path         string
	accounts     []accountConfig
	positions    map[int]int
	rev          uint64
	persistedRev uint64
	closed       bool

	signalCh chan struct{}
	flushCh  chan accountStoreFlushRequest
	stopCh   chan struct{}
	doneCh   chan struct{}

	persistFn func(string, string) error
	backoffFn func(int) time.Duration
	stopOnce  sync.Once
}

type persistedAccountFileEntry struct {
	Name         string          `json:"name,omitempty"`
	ClientID     string          `json:"client_id,omitempty"`
	ClientSecret string          `json:"client_secret,omitempty"`
	Token        json.RawMessage `json:"token"`
}

func newAccountStore(initial []accountConfig, path string) (*fileAccountStore, error) {
	return newAccountStoreWithHooks(initial, path, persistAccountsJSONFile, defaultAccountStoreBackoff)
}

func newAccountStoreWithHooks(initial []accountConfig, path string, persistFn func(string, string) error, backoffFn func(int) time.Duration) (*fileAccountStore, error) {
	if persistFn == nil {
		persistFn = persistAccountsJSONFile
	}
	if backoffFn == nil {
		backoffFn = defaultAccountStoreBackoff
	}
	if err := validateAccountStorePath(path); err != nil {
		return nil, err
	}

	accounts := cloneAccountConfigs(initial)
	positions := make(map[int]int, len(accounts))
	for i, account := range accounts {
		positions[account.Index] = i
	}

	store := &fileAccountStore{
		path:         path,
		accounts:     accounts,
		positions:    positions,
		rev:          1,
		persistedRev: 1,
		signalCh:     make(chan struct{}, 1),
		flushCh:      make(chan accountStoreFlushRequest),
		stopCh:       make(chan struct{}),
		doneCh:       make(chan struct{}),
		persistFn:    persistFn,
		backoffFn:    backoffFn,
	}
	go store.run()
	return store, nil
}

func persistAccountsJSONFile(path string, payload string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("google_drive: accounts_json must be an absolute path")
	}

	dir := filepath.Dir(path)
	tmpFile, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("google_drive: create accounts_json temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmpFile.Chmod(0o600); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("google_drive: chmod accounts_json temp file: %w", err)
	}
	if _, err := tmpFile.WriteString(payload); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("google_drive: write accounts_json temp file: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("google_drive: sync accounts_json temp file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("google_drive: close accounts_json temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("google_drive: replace accounts_json file: %w", err)
	}
	cleanup = false
	return nil
}

func (s *fileAccountStore) setToken(index int, tokenJSON string) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	position, ok := s.positions[index]
	if !ok {
		s.mu.Unlock()
		return
	}
	s.accounts[position].TokenJSON = tokenJSON
	s.rev++
	s.mu.Unlock()

	select {
	case s.signalCh <- struct{}{}:
	default:
	}
}

func (s *fileAccountStore) flush(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}

	targetRev, persistedRev := s.currentRevisions()
	if persistedRev >= targetRev {
		return nil
	}

	req := accountStoreFlushRequest{
		targetRev: targetRev,
		resultCh:  make(chan error, 1),
	}

	select {
	case <-s.doneCh:
		if currentTarget, currentPersisted := s.currentRevisions(); currentPersisted >= currentTarget {
			return nil
		}
		return context.Canceled
	case s.flushCh <- req:
	case <-ctx.Done():
		return ctx.Err()
	}

	select {
	case err := <-req.resultCh:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *fileAccountStore) shutdown(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		if err := s.flush(ctx); err != nil {
			s.stopOnce.Do(func() {
				close(s.stopCh)
			})
			select {
			case <-s.doneCh:
			case <-ctx.Done():
			}
			return err
		}
		if s.sealIfClean() {
			break
		}
	}
	s.stopOnce.Do(func() {
		close(s.stopCh)
	})
	select {
	case <-s.doneCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *fileAccountStore) sealIfClean() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.persistedRev < s.rev {
		return false
	}
	s.closed = true
	return true
}

func (s *fileAccountStore) run() {
	defer close(s.doneCh)
	for {
		select {
		case req := <-s.flushCh:
			req.resultCh <- s.persistPending(req.targetRev)
		case <-s.signalCh:
			_ = s.persistPending(0)
		case <-s.stopCh:
			return
		}
	}
}

func (s *fileAccountStore) persistPending(targetRev uint64) error {
	attempt := 0
	for {
		select {
		case <-s.stopCh:
			return nil
		default:
		}

		accounts, currentRev, currentPersisted := s.snapshot()
		if currentPersisted >= currentRev && (targetRev == 0 || currentPersisted >= targetRev) {
			return nil
		}

		payload, err := marshalPersistedAccounts(accounts)
		if err != nil {
			return err
		}
		if err := s.persistFn(s.path, payload); err != nil {
			attempt++
			log.WithError(err).Warn("google_drive: accounts_json persist failed")
			if !s.waitBackoff(attempt) {
				return nil
			}
			continue
		}

		s.markPersisted(currentRev)
		attempt = 0
		if targetRev > 0 {
			_, persistedAfterWrite := s.currentRevisions()
			if persistedAfterWrite >= targetRev {
				return nil
			}
			continue
		}
		latestRev, latestPersisted := s.currentRevisions()
		if latestPersisted >= latestRev {
			return nil
		}
	}
}

func (s *fileAccountStore) waitBackoff(attempt int) bool {
	delay := s.backoffFn(attempt)
	if delay <= 0 {
		select {
		case <-s.stopCh:
			return false
		default:
			return true
		}
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-s.stopCh:
		return false
	}
}

func (s *fileAccountStore) snapshot() ([]accountConfig, uint64, uint64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneAccountConfigs(s.accounts), s.rev, s.persistedRev
}

func (s *fileAccountStore) currentRevisions() (uint64, uint64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rev, s.persistedRev
}

func (s *fileAccountStore) markPersisted(rev uint64) {
	s.mu.Lock()
	if rev > s.persistedRev {
		s.persistedRev = rev
	}
	s.mu.Unlock()
}

func marshalPersistedAccounts(accounts []accountConfig) (string, error) {
	entries := make([]persistedAccountFileEntry, 0, len(accounts))
	for _, account := range accounts {
		tokenJSON, err := normalizeAccountTokenJSON(json.RawMessage(account.TokenJSON))
		if err != nil {
			return "", err
		}
		entry := persistedAccountFileEntry{
			Name:         account.Name,
			ClientID:     strings.TrimSpace(account.PersistClientID),
			ClientSecret: strings.TrimSpace(account.PersistClientSecret),
			Token:        json.RawMessage(tokenJSON),
		}
		entries = append(entries, entry)
	}
	payload, err := json.Marshal(entries)
	if err != nil {
		return "", fmt.Errorf("google_drive: marshal accounts_json payload: %w", err)
	}
	return string(payload), nil
}

func cloneAccountConfigs(accounts []accountConfig) []accountConfig {
	cloned := make([]accountConfig, len(accounts))
	copy(cloned, accounts)
	return cloned
}

func validateAccountStorePath(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("google_drive: accounts_json must be an absolute path")
	}
	dir := filepath.Dir(path)
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("google_drive: validate accounts_json path: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("google_drive: accounts_json parent must be a directory")
	}
	probe, err := os.CreateTemp(dir, "."+filepath.Base(path)+".probe-*")
	if err != nil {
		return fmt.Errorf("google_drive: validate accounts_json path: %w", err)
	}
	probePath := probe.Name()
	if err := probe.Close(); err != nil {
		_ = os.Remove(probePath)
		return fmt.Errorf("google_drive: validate accounts_json path: %w", err)
	}
	if err := os.Remove(probePath); err != nil {
		return fmt.Errorf("google_drive: validate accounts_json path: %w", err)
	}
	return nil
}

func defaultAccountStoreBackoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	delay := time.Duration(attempt) * 100 * time.Millisecond
	if delay > time.Second {
		return time.Second
	}
	return delay
}
