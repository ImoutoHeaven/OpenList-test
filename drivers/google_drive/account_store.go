package google_drive

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

type accountStoreFlushRequest struct {
	targetRev uint64
	resultCh  chan error
}

type accountStorePersistFn func(string, string, []byte) ([]byte, error)

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

	persistSnapshotFn accountStorePersistFn
	backoffFn         func(int) time.Duration
	persistedSnapshot []byte
	pendingSnapshot   []byte
	stopOnce          sync.Once
}

type sharedFileAccountStore struct {
	core    *fileAccountStore
	refs    int
	closing bool
	done    chan struct{}
}

type fileAccountStoreHandle struct {
	key   string
	entry *sharedFileAccountStore

	shutdownOnce sync.Once
	shutdownDone chan struct{}
	shutdownErr  error
}

var sharedFileAccountStores = struct {
	sync.Mutex
	entries map[string]*sharedFileAccountStore
}{
	entries: make(map[string]*sharedFileAccountStore),
}

var errAccountStoreIdentityMismatch = errors.New("google_drive: accounts_json identity changed while persisting")

type persistedAccountFileEntry struct {
	Name         string          `json:"name,omitempty"`
	ClientID     string          `json:"client_id,omitempty"`
	ClientSecret string          `json:"client_secret,omitempty"`
	Token        json.RawMessage `json:"token"`
}

type accountsJSONFormat int

const (
	accountsJSONFormatJSONArray accountsJSONFormat = iota
	accountsJSONFormatJSONL
)

var persistedCredentialFields = []string{"token", "client_id", "client_secret"}

func newAccountStore(initial []accountConfig, path string, sourceSnapshot []byte) (*fileAccountStore, error) {
	return newAccountStoreWithHooks(initial, path, nil, defaultAccountStoreBackoff, sourceSnapshot)
}

func attachAccountStore(ctx context.Context, initial []accountConfig, path string, sourceSnapshot []byte) (accountStore, error) {
	return attachAccountStoreWithHooks(ctx, initial, path, nil, defaultAccountStoreBackoff, sourceSnapshot)
}

func attachAccountStoreWithHooks(ctx context.Context, initial []accountConfig, path string, persistFn accountStorePersistFn, backoffFn func(int) time.Duration, sourceSnapshot []byte) (accountStore, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	path = filepath.Clean(path)
	if err := validateAccountStorePath(path); err != nil {
		return nil, err
	}

	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		sharedFileAccountStores.Lock()
		entry := sharedFileAccountStores.entries[path]
		if entry == nil {
			core, err := newAccountStoreWithHooks(initial, path, persistFn, backoffFn, sourceSnapshot)
			if err != nil {
				sharedFileAccountStores.Unlock()
				return nil, err
			}
			if err := ctx.Err(); err != nil {
				sharedFileAccountStores.Unlock()
				_ = core.shutdown(context.Background())
				return nil, err
			}
			entry = &sharedFileAccountStore{core: core, refs: 1, done: make(chan struct{})}
			sharedFileAccountStores.entries[path] = entry
			sharedFileAccountStores.Unlock()
			handle := newFileAccountStoreHandle(path, entry)
			if err := ctx.Err(); err != nil {
				_ = handle.shutdown(context.Background())
				return nil, err
			}
			return handle, nil
		}
		if entry.closing {
			done := entry.done
			sharedFileAccountStores.Unlock()
			select {
			case <-done:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		if err := ctx.Err(); err != nil {
			sharedFileAccountStores.Unlock()
			return nil, err
		}
		currentSnapshot, err := readAccountSemanticSnapshot(path)
		if err != nil {
			sharedFileAccountStores.Unlock()
			return nil, fmt.Errorf("%w: read current account snapshot: %v", errAccountStoreIdentityMismatch, err)
		}
		if !bytes.Equal(currentSnapshot, sourceSnapshot) {
			sharedFileAccountStores.Unlock()
			return nil, fmt.Errorf("%w: account source changed during attachment", errAccountStoreIdentityMismatch)
		}
		if err := entry.core.validateAttachment(initial, sourceSnapshot); err != nil {
			sharedFileAccountStores.Unlock()
			return nil, err
		}
		entry.refs++
		sharedFileAccountStores.Unlock()
		handle := newFileAccountStoreHandle(path, entry)
		if err := ctx.Err(); err != nil {
			_ = handle.shutdown(context.Background())
			return nil, err
		}
		return handle, nil
	}
}

func newFileAccountStoreHandle(key string, entry *sharedFileAccountStore) *fileAccountStoreHandle {
	return &fileAccountStoreHandle{
		key:          key,
		entry:        entry,
		shutdownDone: make(chan struct{}),
	}
}

func newAccountStoreWithHooks(initial []accountConfig, path string, persistFn accountStorePersistFn, backoffFn func(int) time.Duration, sourceSnapshot []byte) (*fileAccountStore, error) {
	path = filepath.Clean(path)
	if persistFn == nil {
		persistFn = persistAccountsJSONFileChecked
	}
	if backoffFn == nil {
		backoffFn = defaultAccountStoreBackoff
	}
	if err := validateAccountStorePath(path); err != nil {
		return nil, err
	}
	var err error
	if sourceSnapshot == nil {
		sourceSnapshot, err = readAccountSemanticSnapshot(path)
		if err != nil {
			return nil, err
		}
	} else {
		currentSnapshot, err := readAccountSemanticSnapshot(path)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(currentSnapshot, sourceSnapshot) {
			return nil, fmt.Errorf("%w: account source changed during initialization", errAccountStoreIdentityMismatch)
		}
	}

	accounts := cloneAccountConfigs(initial)
	positions := make(map[int]int, len(accounts))
	for i, account := range accounts {
		positions[account.Index] = i
	}

	store := &fileAccountStore{
		path:              path,
		accounts:          accounts,
		positions:         positions,
		rev:               1,
		persistedRev:      1,
		signalCh:          make(chan struct{}, 1),
		flushCh:           make(chan accountStoreFlushRequest),
		stopCh:            make(chan struct{}),
		doneCh:            make(chan struct{}),
		backoffFn:         backoffFn,
		persistedSnapshot: sourceSnapshot,
		persistSnapshotFn: persistFn,
	}
	go store.run()
	return store, nil
}

func persistAccountsJSONFileChecked(path string, payload string, expectedSnapshot []byte) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("google_drive: accounts_json must be an absolute path")
	}

	existingContent, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("google_drive: read accounts_json file: %w", err)
	}
	if expectedSnapshot != nil {
		actualSnapshot, err := semanticAccountsSnapshot(existingContent)
		if err != nil {
			return nil, fmt.Errorf("%w: read current account snapshot: %v", errAccountStoreIdentityMismatch, err)
		}
		if !bytes.Equal(actualSnapshot, expectedSnapshot) {
			return nil, fmt.Errorf("%w: on-disk account snapshot changed", errAccountStoreIdentityMismatch)
		}
	}

	mergedPayload, err := mergePersistedAccountsJSON(existingContent, payload)
	if err != nil {
		return nil, err
	}
	intendedSnapshot, err := semanticAccountsSnapshot([]byte(mergedPayload))
	if err != nil {
		return nil, fmt.Errorf("google_drive: build persisted account snapshot: %w", err)
	}

	dir := filepath.Dir(path)
	tmpFile, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return nil, fmt.Errorf("google_drive: create accounts_json temp file: %w", err)
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
		return nil, fmt.Errorf("google_drive: chmod accounts_json temp file: %w", err)
	}
	if _, err := tmpFile.WriteString(mergedPayload); err != nil {
		_ = tmpFile.Close()
		return nil, fmt.Errorf("google_drive: write accounts_json temp file: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return nil, fmt.Errorf("google_drive: sync accounts_json temp file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return nil, fmt.Errorf("google_drive: close accounts_json temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return nil, fmt.Errorf("google_drive: replace accounts_json file: %w", err)
	}
	cleanup = false
	return intendedSnapshot, nil
}

func readAccountSemanticSnapshot(path string) ([]byte, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("google_drive: read accounts_json file: %w", err)
	}
	return semanticAccountsSnapshot(content)
}

func semanticAccountsSnapshot(content []byte) ([]byte, error) {
	entries, _, _, err := decodeAccountsJSONObjects(content)
	if err != nil {
		return nil, err
	}
	canonicalEntries := make([]any, 0, len(entries))
	for _, entry := range entries {
		entry = cloneJSONEntry(entry)
		if rawName, ok := entry["name"]; ok {
			var name string
			if err := json.Unmarshal(rawName, &name); err == nil {
				trimmedName, err := json.Marshal(strings.TrimSpace(name))
				if err != nil {
					return nil, fmt.Errorf("google_drive: marshal account name snapshot: %w", err)
				}
				entry["name"] = trimmedName
			}
		}
		rawEntry, err := json.Marshal(entry)
		if err != nil {
			return nil, fmt.Errorf("google_drive: marshal account snapshot: %w", err)
		}
		var value any
		decoder := json.NewDecoder(bytes.NewReader(rawEntry))
		decoder.UseNumber()
		if err := decoder.Decode(&value); err != nil {
			return nil, fmt.Errorf("google_drive: parse account snapshot: %w", err)
		}
		canonicalEntries = append(canonicalEntries, value)
	}
	return json.Marshal(canonicalEntries)
}

func cloneJSONEntry(entry map[string]json.RawMessage) map[string]json.RawMessage {
	clone := make(map[string]json.RawMessage, len(entry))
	for key, value := range entry {
		clone[key] = append(json.RawMessage(nil), value...)
	}
	return clone
}

func decodeAccountsJSONObjects(content []byte) ([]map[string]json.RawMessage, accountsJSONFormat, bool, error) {
	raw := string(content)
	hasTrailingNewline := strings.HasSuffix(raw, "\n")
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, accountsJSONFormatJSONArray, hasTrailingNewline, fmt.Errorf("google_drive: accounts_json must not be empty")
	}

	if strings.HasPrefix(trimmed, "[") {
		var entries []map[string]json.RawMessage
		if err := json.Unmarshal([]byte(trimmed), &entries); err != nil {
			return nil, accountsJSONFormatJSONArray, hasTrailingNewline, fmt.Errorf("google_drive: parse accounts_json: %w", err)
		}
		if len(entries) == 0 {
			return nil, accountsJSONFormatJSONArray, hasTrailingNewline, fmt.Errorf("google_drive: accounts_json must not be empty")
		}
		return entries, accountsJSONFormatJSONArray, hasTrailingNewline, nil
	}

	lines := strings.Split(trimmed, "\n")
	entries := make([]map[string]json.RawMessage, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var entry map[string]json.RawMessage
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			return nil, accountsJSONFormatJSONL, hasTrailingNewline, fmt.Errorf("google_drive: parse accounts_json: %w", err)
		}
		entries = append(entries, entry)
	}
	if len(entries) == 0 {
		return nil, accountsJSONFormatJSONL, hasTrailingNewline, fmt.Errorf("google_drive: accounts_json must not be empty")
	}
	return entries, accountsJSONFormatJSONL, hasTrailingNewline, nil
}

func encodeAccountsJSONObjects(entries []map[string]json.RawMessage, format accountsJSONFormat, hasTrailingNewline bool) (string, error) {
	switch format {
	case accountsJSONFormatJSONArray:
		payload, err := json.Marshal(entries)
		if err != nil {
			return "", fmt.Errorf("google_drive: marshal accounts_json payload: %w", err)
		}
		return string(payload), nil
	case accountsJSONFormatJSONL:
		lines := make([]string, len(entries))
		for i, entry := range entries {
			payload, err := json.Marshal(entry)
			if err != nil {
				return "", fmt.Errorf("google_drive: marshal accounts_json payload: %w", err)
			}
			lines[i] = string(payload)
		}
		payload := strings.Join(lines, "\n")
		if hasTrailingNewline {
			payload += "\n"
		}
		return payload, nil
	default:
		return "", fmt.Errorf("google_drive: unknown accounts_json format %d", format)
	}
}

func mergePersistedCredentialFields(existing, updated map[string]json.RawMessage) {
	if existing == nil {
		return
	}
	for _, field := range persistedCredentialFields {
		value, ok := updated[field]
		if !ok {
			delete(existing, field)
			continue
		}
		if current, ok := existing[field]; ok && equalJSONRaw(current, value) {
			continue
		}
		existing[field] = append(json.RawMessage(nil), value...)
	}
}

func equalJSONRaw(left, right json.RawMessage) bool {
	var leftValue, rightValue any
	if json.Unmarshal(left, &leftValue) != nil || json.Unmarshal(right, &rightValue) != nil {
		return false
	}
	return reflect.DeepEqual(leftValue, rightValue)
}

func mergePersistedAccountsJSON(existingContent []byte, updatedPayload string) (string, error) {
	existingEntries, format, hasTrailingNewline, err := decodeAccountsJSONObjects(existingContent)
	if err != nil {
		return "", err
	}
	updatedEntries, _, _, err := decodeAccountsJSONObjects([]byte(updatedPayload))
	if err != nil {
		return "", err
	}
	if len(existingEntries) != len(updatedEntries) {
		return "", fmt.Errorf("%w: entry count changed from %d to %d", errAccountStoreIdentityMismatch, len(existingEntries), len(updatedEntries))
	}

	for i := range existingEntries {
		existingName, err := persistedAccountName(existingEntries[i])
		if err != nil {
			return "", fmt.Errorf("%w at entry %d: %v", errAccountStoreIdentityMismatch, i, err)
		}
		updatedName, err := persistedAccountName(updatedEntries[i])
		if err != nil {
			return "", fmt.Errorf("%w at entry %d: %v", errAccountStoreIdentityMismatch, i, err)
		}
		if existingName != updatedName {
			return "", fmt.Errorf("%w at entry %d: %q changed to %q", errAccountStoreIdentityMismatch, i, existingName, updatedName)
		}
		if existingEntries[i] == nil {
			existingEntries[i] = make(map[string]json.RawMessage)
		}
		mergePersistedCredentialFields(existingEntries[i], updatedEntries[i])
	}

	return encodeAccountsJSONObjects(existingEntries, format, hasTrailingNewline)
}

func persistedAccountName(entry map[string]json.RawMessage) (string, error) {
	if entry == nil {
		return "", nil
	}
	rawName, ok := entry["name"]
	if !ok {
		return "", nil
	}
	var name string
	if err := json.Unmarshal(rawName, &name); err != nil {
		return "", fmt.Errorf("name must be a string: %w", err)
	}
	return strings.TrimSpace(name), nil
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

func (s *fileAccountStore) validateAttachment(initial []accountConfig, sourceSnapshot []byte) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return context.Canceled
	}
	if !bytes.Equal(sourceSnapshot, s.persistedSnapshot) && !bytes.Equal(sourceSnapshot, s.pendingSnapshot) {
		return fmt.Errorf("%w: shared writer snapshot differs", errAccountStoreIdentityMismatch)
	}
	if !accountStoreLayoutsMatch(s.accounts, initial) {
		return fmt.Errorf("%w: shared writer entry layout differs", errAccountStoreIdentityMismatch)
	}
	return nil
}

func accountStoreLayoutsMatch(current, incoming []accountConfig) bool {
	if len(current) != len(incoming) {
		return false
	}
	for index := range current {
		left, right := current[index], incoming[index]
		if left.Index != right.Index || strings.TrimSpace(left.Name) != strings.TrimSpace(right.Name) ||
			strings.TrimSpace(left.PersistClientID) != strings.TrimSpace(right.PersistClientID) ||
			strings.TrimSpace(left.PersistClientSecret) != strings.TrimSpace(right.PersistClientSecret) {
			return false
		}
	}
	return true
}

func (h *fileAccountStoreHandle) setToken(index int, tokenJSON string) {
	h.entry.core.setToken(index, tokenJSON)
}

func (h *fileAccountStoreHandle) flush(ctx context.Context) error {
	return h.entry.core.flush(ctx)
}

func (h *fileAccountStoreHandle) shutdown(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	h.shutdownOnce.Do(func() {
		go func() {
			h.shutdownErr = releaseFileAccountStore(h.key, h.entry, ctx)
			close(h.shutdownDone)
		}()
	})
	select {
	case <-h.shutdownDone:
		return h.shutdownErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

func releaseFileAccountStore(key string, entry *sharedFileAccountStore, ctx context.Context) error {
	sharedFileAccountStores.Lock()
	current := sharedFileAccountStores.entries[key]
	if current == nil || current != entry {
		sharedFileAccountStores.Unlock()
		return nil
	}
	entry.refs--
	if entry.refs > 0 {
		sharedFileAccountStores.Unlock()
		return nil
	}
	entry.closing = true
	sharedFileAccountStores.Unlock()

	err := entry.core.shutdown(ctx)
	// Keep the path registered as closing until the writer goroutine has
	// stopped, so an attachment cannot create a second writer during shutdown.
	<-entry.core.doneCh

	sharedFileAccountStores.Lock()
	if sharedFileAccountStores.entries[key] == entry {
		delete(sharedFileAccountStores.entries, key)
		close(entry.done)
	}
	sharedFileAccountStores.Unlock()
	return err
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
		expectedSnapshot := s.expectedSnapshot()
		actualSnapshot, err := readAccountSemanticSnapshot(s.path)
		if err != nil {
			return fmt.Errorf("%w: read current account snapshot: %v", errAccountStoreIdentityMismatch, err)
		}
		if !bytes.Equal(actualSnapshot, expectedSnapshot) {
			return fmt.Errorf("%w: on-disk account snapshot changed", errAccountStoreIdentityMismatch)
		}
		// The renamed file is visible before the writer acknowledges its revision.
		// Attachments may observe this exact writer-owned snapshot in that window.
		pendingPayload, err := mergePersistedAccountsJSON(expectedSnapshot, payload)
		if err != nil {
			return err
		}
		pendingSnapshot, err := semanticAccountsSnapshot([]byte(pendingPayload))
		if err != nil {
			return err
		}
		s.mu.Lock()
		s.pendingSnapshot = pendingSnapshot
		s.mu.Unlock()
		acknowledgedSnapshot, err := s.persistSnapshotFn(s.path, payload, expectedSnapshot)
		s.mu.Lock()
		if err == nil && len(acknowledgedSnapshot) > 0 {
			if currentRev > s.persistedRev {
				s.persistedRev = currentRev
			}
			s.persistedSnapshot = append([]byte(nil), acknowledgedSnapshot...)
		}
		s.pendingSnapshot = nil
		s.mu.Unlock()
		if err != nil {
			if errors.Is(err, errAccountStoreIdentityMismatch) {
				return err
			}
			attempt++
			log.WithError(err).Warn("google_drive: accounts_json persist failed")
			if !s.waitBackoff(attempt) {
				return nil
			}
			continue
		}
		if len(acknowledgedSnapshot) == 0 {
			return fmt.Errorf("google_drive: account persistence returned an empty snapshot acknowledgment")
		}
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

func (s *fileAccountStore) expectedSnapshot() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]byte(nil), s.persistedSnapshot...)
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
