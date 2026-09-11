package google_drive

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/OpenListTeam/OpenList/v4/internal/db"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"gorm.io/gorm"
)

const (
	googleDriveAccountProvider  = "GoogleDrive"
	accountHealthEvidenceTTL    = 10 * time.Minute
	accountHealthCooldown       = 24 * time.Hour
	accountHealthProbeInterval  = time.Hour
	accountHealthTrialLifetime  = 180 * time.Second
	accountHealthProbeBudget    = 2
	accountHealthBoundaryBudget = 1
	maxAccountHealthName        = 256
	maxAccountHealthFileID      = 1024
	maxAccountHealthEventID     = 256
	maxAccountHealthReason      = 4096
)

var accountHealthBackoffs = [...]time.Duration{30 * time.Second, 60 * time.Second, 120 * time.Second}

// AccountHealthOutcome is the terminal result of a download authorization.
type AccountHealthOutcome string

const (
	AccountHealthSuccess   AccountHealthOutcome = "success"
	AccountHealthFailure   AccountHealthOutcome = "failure"
	AccountHealthAbandoned AccountHealthOutcome = "abandoned"
)

// AccountHealthLease identifies the health generation used for one download
// authorization. Trial leases are serialized across every mount sharing the
// same trimmed account name.
type AccountHealthLease struct {
	AccountKey  string
	AccountName string
	Generation  uint64
	TrialID     string
	TrialFileID string
	Trial       bool
	ExpiresAt   time.Time
}

// AccountHealthReportInput is the portion of a signed authorization report
// consumed by account health. Ticket validation belongs to the link API.
type AccountHealthReportInput struct {
	AccountName string
	FileID      string
	EventID     string
	Outcome     AccountHealthOutcome
	StatusCode  int
	Reason      string
	Generation  uint64
	TrialID     string
}

// AccountHealthReportResult describes an accepted or fenced report.
type AccountHealthReportResult struct {
	Applied       bool
	Duplicate     bool
	Stale         bool
	Generation    uint64
	CooldownUntil time.Time
	RetryAfter    time.Duration
}

// AccountHealthSnapshot is useful to the link API and to operational tests.
type AccountHealthSnapshot struct {
	AccountKey       string
	AccountName      string
	Generation       uint64
	CooldownUntil    time.Time
	NextProbeAt      time.Time
	BackoffUntil     time.Time
	BackoffLevel     int
	EvidenceFileIDs  []string
	ProbeRoundBudget int
	ProbeRoundUsed   int
	ProbeFileIDs     []string
	ProbeRequired    bool
	LiveTrialID      string
	LiveTrialFileID  string
	LiveTrialUntil   time.Time
}

// AccountHealthUnavailableError tells callers when a shared account cannot
// accept a download authorization yet.
type AccountHealthUnavailableError struct {
	AccountName string
	RetryAfter  time.Duration
	Reason      string
}

func (e *AccountHealthUnavailableError) Error() string {
	if e == nil {
		return "google_drive: account unavailable"
	}
	if e.Reason == "" {
		return fmt.Sprintf("google_drive: account %q unavailable", e.AccountName)
	}
	return fmt.Sprintf("google_drive: account %q unavailable: %s", e.AccountName, e.Reason)
}

func (e *AccountHealthUnavailableError) RetryAfterDuration() time.Duration {
	if e == nil || e.RetryAfter < 0 {
		return 0
	}
	return e.RetryAfter
}

type accountHealthTrial struct {
	id        string
	fileID    string
	expiresAt time.Time
}

type accountHealthState struct {
	mu sync.Mutex

	key        string
	name       string
	database   *gorm.DB
	generation uint64

	cooldownUntil time.Time
	nextProbeAt   time.Time
	probeBudget   int
	probeUsed     int
	probeFileIDs  map[string]struct{}
	probeRequired bool
	trial         *accountHealthTrial

	evidence     map[string]time.Time
	eventIDs     map[string]time.Time
	backoffUntil time.Time
	backoffLevel int
}

type accountHealthStateBackup struct {
	generation    uint64
	cooldownUntil time.Time
	nextProbeAt   time.Time
	probeBudget   int
	probeUsed     int
	probeFileIDs  map[string]struct{}
	probeRequired bool
	trial         *accountHealthTrial
	evidence      map[string]time.Time
	eventIDs      map[string]time.Time
	backoffUntil  time.Time
	backoffLevel  int
}

func (s *accountHealthState) backup() accountHealthStateBackup {
	backup := accountHealthStateBackup{
		generation:    s.generation,
		cooldownUntil: s.cooldownUntil,
		nextProbeAt:   s.nextProbeAt,
		probeBudget:   s.probeBudget,
		probeUsed:     s.probeUsed,
		probeFileIDs:  cloneStringSet(s.probeFileIDs),
		probeRequired: s.probeRequired,
		evidence:      cloneTimeMap(s.evidence),
		eventIDs:      cloneTimeMap(s.eventIDs),
		backoffUntil:  s.backoffUntil,
		backoffLevel:  s.backoffLevel,
	}
	if s.trial != nil {
		trial := *s.trial
		backup.trial = &trial
	}
	return backup
}

func (b accountHealthStateBackup) restore(state *accountHealthState) {
	state.generation = b.generation
	state.cooldownUntil = b.cooldownUntil
	state.nextProbeAt = b.nextProbeAt
	state.probeBudget = b.probeBudget
	state.probeUsed = b.probeUsed
	state.probeFileIDs = cloneStringSet(b.probeFileIDs)
	state.probeRequired = b.probeRequired
	state.evidence = cloneTimeMap(b.evidence)
	state.eventIDs = cloneTimeMap(b.eventIDs)
	state.backoffUntil = b.backoffUntil
	state.backoffLevel = b.backoffLevel
	if b.trial != nil {
		trial := *b.trial
		state.trial = &trial
	} else {
		state.trial = nil
	}
}

func cloneStringSet(source map[string]struct{}) map[string]struct{} {
	clone := make(map[string]struct{}, len(source))
	for value := range source {
		clone[value] = struct{}{}
	}
	return clone
}

func cloneTimeMap(source map[string]time.Time) map[string]time.Time {
	clone := make(map[string]time.Time, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}

type accountHealthRuntime struct {
	mu       sync.Mutex
	states   map[string]*accountHealthState
	db       *gorm.DB
	now      func() time.Time
	durable  bool
	loadFn   func(string) (*model.GoogleDriveAccountHealth, error)
	saveFn   func(*model.GoogleDriveAccountHealth) error
	sequence uint64
}

func lockAccountHealthMutex(ctx context.Context, mutex *sync.Mutex) error {
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		if mutex.TryLock() {
			if err := ctx.Err(); err != nil {
				mutex.Unlock()
				return err
			}
			return nil
		}
		timer := time.NewTimer(time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func lockAccountHealthState(ctx context.Context, state *accountHealthState) error {
	return lockAccountHealthMutex(ctx, &state.mu)
}

var sharedAccountHealth = newDurableAccountHealthRuntime(time.Now)

func newAccountHealthRuntime(now func() time.Time) *accountHealthRuntime {
	if now == nil {
		now = time.Now
	}
	return &accountHealthRuntime{
		states: make(map[string]*accountHealthState),
		now:    now,
	}
}

func newDurableAccountHealthRuntime(now func() time.Time) *accountHealthRuntime {
	runtime := newAccountHealthRuntime(now)
	runtime.durable = true
	return runtime
}

func newAccountHealthRuntimeWithPersistence(now func() time.Time, load func(string) (*model.GoogleDriveAccountHealth, error), save func(*model.GoogleDriveAccountHealth) error) *accountHealthRuntime {
	runtime := newAccountHealthRuntime(now)
	runtime.loadFn = load
	runtime.saveFn = save
	return runtime
}

func accountHealthKey(name string) string {
	identity := googleDriveAccountProvider + "\x00" + strings.TrimSpace(name)
	digest := sha256.Sum256([]byte(identity))
	return hex.EncodeToString(digest[:])
}

func validateAccountHealthIdentity(name, fileID string) (string, string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", "", fmt.Errorf("google_drive: account name must be nonempty")
	}
	if len(name) > maxAccountHealthName {
		return "", "", fmt.Errorf("google_drive: account name exceeds %d characters", maxAccountHealthName)
	}
	fileID = strings.TrimSpace(fileID)
	if fileID == "" {
		return "", "", fmt.Errorf("google_drive: file ID must be nonempty")
	}
	if len(fileID) > maxAccountHealthFileID {
		return "", "", fmt.Errorf("google_drive: file ID exceeds %d characters", maxAccountHealthFileID)
	}
	return name, fileID, nil
}

func (r *accountHealthRuntime) get(name string) (*accountHealthState, error) {
	return r.getWithContext(context.Background(), name)
}

func (r *accountHealthRuntime) getWithContext(ctx context.Context, name string) (*accountHealthState, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("google_drive: account name must be nonempty")
	}
	key := accountHealthKey(name)
	database := db.GetDb()
	if r.loadFn != nil {
		database = nil
	}
	if r.durable && database == nil {
		return nil, fmt.Errorf("google_drive: database is not initialized for account health")
	}
	if err := lockAccountHealthMutex(ctx, &r.mu); err != nil {
		return nil, err
	}
	defer r.mu.Unlock()
	previousStates, previousDB := r.states, r.db
	states := r.states
	if r.db != database {
		states = make(map[string]*accountHealthState)
	}
	if state, ok := states[key]; ok {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		r.states, r.db = states, database
		return state, nil
	}

	state := &accountHealthState{
		key:          key,
		name:         name,
		database:     database,
		generation:   1,
		probeFileIDs: make(map[string]struct{}),
		evidence:     make(map[string]time.Time),
		eventIDs:     make(map[string]time.Time),
	}
	if r.loadFn != nil || database != nil {
		var persisted *model.GoogleDriveAccountHealth
		var err error
		if r.loadFn != nil {
			persisted, err = r.loadFn(key)
		} else {
			persisted, err = db.GetGoogleDriveAccountHealthContextOn(ctx, database, key)
		}
		if err == nil {
			if err := state.load(persisted); err != nil {
				r.states, r.db = previousStates, previousDB
				return nil, err
			}
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			r.states, r.db = previousStates, previousDB
			return nil, err
		} else {
			// Install the candidate runtime while this lock is held so initial
			// persistence and cache publication use one database.
			r.states, r.db = states, database
			if err := r.persistLockedContext(ctx, state); err != nil {
				r.states, r.db = previousStates, previousDB
				return nil, err
			}
		}
	}
	if err := ctx.Err(); err != nil {
		r.states, r.db = previousStates, previousDB
		return nil, err
	}
	states[key] = state
	r.states, r.db = states, database
	return state, nil
}

func (s *accountHealthState) load(record *model.GoogleDriveAccountHealth) error {
	if record == nil {
		return nil
	}
	s.key = record.AccountKey
	if persistedName := strings.TrimSpace(record.AccountName); persistedName != "" {
		s.name = persistedName
	}
	if s.generation = record.Generation; s.generation == 0 {
		s.generation = 1
	}
	s.cooldownUntil = record.CooldownUntil
	s.nextProbeAt = record.NextProbeAt
	s.probeBudget = max(record.ProbeBudget, 0)
	s.probeUsed = max(record.ProbeUsed, 0)
	s.probeRequired = record.ProbeRequired
	s.probeFileIDs = make(map[string]struct{})
	if strings.TrimSpace(record.ProbeFileIDs) != "" {
		var fileIDs []string
		if err := json.Unmarshal([]byte(record.ProbeFileIDs), &fileIDs); err != nil {
			return fmt.Errorf("google_drive: parse persisted probe file IDs: %w", err)
		}
		for _, fileID := range fileIDs {
			if fileID = strings.TrimSpace(fileID); fileID != "" {
				s.probeFileIDs[fileID] = struct{}{}
			}
		}
	}
	if record.LiveTrialID != "" {
		s.trial = &accountHealthTrial{
			id:        record.LiveTrialID,
			fileID:    record.LiveTrialFileID,
			expiresAt: record.LiveTrialUntil,
		}
	}
	return nil
}

func (r *accountHealthRuntime) persistLocked(state *accountHealthState) error {
	return r.persistLockedContext(context.Background(), state)
}

func (r *accountHealthRuntime) persistLockedContext(ctx context.Context, state *accountHealthState) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if r.saveFn == nil && state.database == nil {
		return nil
	}
	fileIDs := make([]string, 0, len(state.probeFileIDs))
	for fileID := range state.probeFileIDs {
		fileIDs = append(fileIDs, fileID)
	}
	sort.Strings(fileIDs)
	encodedFileIDs, err := json.Marshal(fileIDs)
	if err != nil {
		return fmt.Errorf("google_drive: marshal probe file IDs: %w", err)
	}
	record := &model.GoogleDriveAccountHealth{
		AccountKey:    state.key,
		AccountName:   state.name,
		Generation:    state.generation,
		CooldownUntil: state.cooldownUntil,
		NextProbeAt:   state.nextProbeAt,
		ProbeBudget:   state.probeBudget,
		ProbeUsed:     state.probeUsed,
		ProbeFileIDs:  string(encodedFileIDs),
		ProbeRequired: state.probeRequired,
		UpdatedAt:     r.now(),
	}
	if state.trial != nil {
		record.LiveTrialID = state.trial.id
		record.LiveTrialFileID = state.trial.fileID
		record.LiveTrialUntil = state.trial.expiresAt
	}
	if r.saveFn != nil {
		return r.saveFn(record)
	}
	return db.SaveGoogleDriveAccountHealthContextOn(ctx, state.database, record)
}

func (r *accountHealthRuntime) newID(prefix string) string {
	var random [12]byte
	if _, err := rand.Read(random[:]); err == nil {
		return prefix + "-" + hex.EncodeToString(random[:])
	}
	sequence := atomic.AddUint64(&r.sequence, 1)
	return fmt.Sprintf("%s-%d-%d", prefix, r.now().UnixNano(), sequence)
}

func (r *accountHealthRuntime) expireTrialLocked(state *accountHealthState, now time.Time) bool {
	if state.trial == nil || now.Before(state.trial.expiresAt) {
		return false
	}
	state.trial = nil
	if state.probeRequired {
		state.backoffLevel = max(state.backoffLevel, 1)
		backoffUntil := now.Add(accountHealthBackoffs[state.backoffLevel-1])
		if backoffUntil.After(state.backoffUntil) {
			state.backoffUntil = backoffUntil
		}
	}
	return true
}

func (r *accountHealthRuntime) expireCooldownLocked(state *accountHealthState, now time.Time) bool {
	if state.cooldownUntil.IsZero() || now.Before(state.cooldownUntil) {
		return false
	}
	state.cooldownUntil = time.Time{}
	state.nextProbeAt = time.Time{}
	state.probeBudget = accountHealthBoundaryBudget
	state.probeUsed = 0
	state.probeFileIDs = make(map[string]struct{})
	state.probeRequired = true
	state.trial = nil
	state.backoffUntil = time.Time{}
	state.backoffLevel = 0
	state.generation++
	return true
}

func (r *accountHealthRuntime) pruneEvidenceLocked(state *accountHealthState, now time.Time) {
	cutoff := now.Add(-accountHealthEvidenceTTL)
	for fileID, observedAt := range state.evidence {
		if !observedAt.After(cutoff) {
			delete(state.evidence, fileID)
		}
	}
	for eventID, observedAt := range state.eventIDs {
		if !observedAt.After(cutoff) {
			delete(state.eventIDs, eventID)
		}
	}
}

func (r *accountHealthRuntime) unavailable(state *accountHealthState, now time.Time, reason string, retryAt time.Time) error {
	retryAfter := time.Duration(0)
	if !retryAt.IsZero() && retryAt.After(now) {
		retryAfter = retryAt.Sub(now)
	}
	return &AccountHealthUnavailableError{
		AccountName: state.name,
		RetryAfter:  retryAfter,
		Reason:      reason,
	}
}

func (r *accountHealthRuntime) reserveTrialLocked(state *accountHealthState, fileID string, now time.Time) (AccountHealthLease, error) {
	if state.trial != nil {
		return AccountHealthLease{}, r.unavailable(state, now, "trial already in flight", state.trial.expiresAt)
	}
	if state.probeUsed >= state.probeBudget {
		return AccountHealthLease{}, r.unavailable(state, now, "probe opportunities exhausted", state.nextProbeAt)
	}
	if _, used := state.probeFileIDs[fileID]; used {
		return AccountHealthLease{}, r.unavailable(state, now, "file already used in probe round", state.nextProbeAt)
	}
	trial := &accountHealthTrial{
		id:        r.newID("trial"),
		fileID:    fileID,
		expiresAt: now.Add(accountHealthTrialLifetime),
	}
	state.trial = trial
	state.probeUsed++
	state.probeFileIDs[fileID] = struct{}{}
	if err := r.persistLocked(state); err != nil {
		state.probeUsed--
		delete(state.probeFileIDs, fileID)
		state.trial = nil
		return AccountHealthLease{}, err
	}
	return AccountHealthLease{
		AccountKey:  state.key,
		AccountName: state.name,
		Generation:  state.generation,
		TrialID:     trial.id,
		TrialFileID: trial.fileID,
		Trial:       true,
		ExpiresAt:   trial.expiresAt,
	}, nil
}

func (r *accountHealthRuntime) acquire(ctx context.Context, name, fileID string) (AccountHealthLease, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return AccountHealthLease{}, err
	}
	name, fileID, err := validateAccountHealthIdentity(name, fileID)
	if err != nil {
		return AccountHealthLease{}, err
	}
	state, err := r.getWithContext(ctx, name)
	if err != nil {
		return AccountHealthLease{}, err
	}

	now := r.now()
	state.mu.Lock()
	defer state.mu.Unlock()
	backup := state.backup()
	changed := r.expireTrialLocked(state, now)
	if r.expireCooldownLocked(state, now) {
		changed = true
	}
	r.pruneEvidenceLocked(state, now)
	if state.trial != nil {
		if changed {
			if err := r.persistLocked(state); err != nil {
				backup.restore(state)
				return AccountHealthLease{}, err
			}
		}
		return AccountHealthLease{}, r.unavailable(state, now, "trial already in flight", state.trial.expiresAt)
	}
	if state.probeRequired {
		if now.Before(state.backoffUntil) {
			if changed {
				if err := r.persistLocked(state); err != nil {
					backup.restore(state)
					return AccountHealthLease{}, err
				}
			}
			return AccountHealthLease{}, r.unavailable(state, now, "probe required after recovery", state.backoffUntil)
		}
		if state.probeBudget <= state.probeUsed {
			state.probeBudget = accountHealthBoundaryBudget
			state.probeUsed = 0
			state.probeFileIDs = make(map[string]struct{})
			changed = true
		}
		lease, err := r.reserveTrialLocked(state, fileID, now)
		if err != nil && changed {
			backup.restore(state)
		}
		return lease, err
	}

	if !state.cooldownUntil.IsZero() {
		if now.Before(state.backoffUntil) {
			if changed {
				if err := r.persistLocked(state); err != nil {
					backup.restore(state)
					return AccountHealthLease{}, err
				}
			}
			return AccountHealthLease{}, r.unavailable(state, now, "short backoff active", state.backoffUntil)
		}
		if !now.Before(state.nextProbeAt) {
			state.probeBudget = accountHealthProbeBudget
			state.probeUsed = 0
			state.probeFileIDs = make(map[string]struct{})
			state.nextProbeAt = now.Add(accountHealthProbeInterval)
			if err := r.persistLocked(state); err != nil {
				backup.restore(state)
				return AccountHealthLease{}, err
			}
			lease, err := r.reserveTrialLocked(state, fileID, now)
			if err != nil {
				backup.restore(state)
			}
			return lease, err
		}
		if state.probeBudget > state.probeUsed {
			if now.Before(state.backoffUntil) {
				if changed {
					if err := r.persistLocked(state); err != nil {
						backup.restore(state)
						return AccountHealthLease{}, err
					}
				}
				return AccountHealthLease{}, r.unavailable(state, now, "short backoff active", state.backoffUntil)
			}
			lease, err := r.reserveTrialLocked(state, fileID, now)
			if err != nil && changed {
				backup.restore(state)
			}
			return lease, err
		}
		if changed {
			if err := r.persistLocked(state); err != nil {
				backup.restore(state)
				return AccountHealthLease{}, err
			}
		}
		return AccountHealthLease{}, r.unavailable(state, now, "cooldown active", state.nextProbeAt)
	}

	// A pending probe opportunity has priority over normal selection.
	if state.probeBudget > state.probeUsed {
		if now.Before(state.backoffUntil) {
			if changed {
				if err := r.persistLocked(state); err != nil {
					backup.restore(state)
					return AccountHealthLease{}, err
				}
			}
			return AccountHealthLease{}, r.unavailable(state, now, "short backoff active", state.backoffUntil)
		}
		lease, err := r.reserveTrialLocked(state, fileID, now)
		if err != nil && changed {
			backup.restore(state)
		}
		return lease, err
	}

	if now.Before(state.backoffUntil) {
		if changed {
			if err := r.persistLocked(state); err != nil {
				backup.restore(state)
				return AccountHealthLease{}, err
			}
		}
		return AccountHealthLease{}, r.unavailable(state, now, "short backoff active", state.backoffUntil)
	}
	if changed {
		if err := r.persistLocked(state); err != nil {
			backup.restore(state)
			return AccountHealthLease{}, err
		}
	}
	return AccountHealthLease{
		AccountKey:  state.key,
		AccountName: state.name,
		Generation:  state.generation,
	}, nil
}

func (r *accountHealthRuntime) report(ctx context.Context, input AccountHealthReportInput) (AccountHealthReportResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return AccountHealthReportResult{}, err
	}
	name, fileID, err := validateAccountHealthIdentity(input.AccountName, input.FileID)
	if err != nil {
		return AccountHealthReportResult{}, err
	}
	input.AccountName = name
	input.FileID = fileID
	if input.EventID == "" {
		input.EventID = r.newID("event")
	}
	if len(input.EventID) > maxAccountHealthEventID {
		return AccountHealthReportResult{}, fmt.Errorf("google_drive: account health event ID exceeds %d characters", maxAccountHealthEventID)
	}
	if len(input.TrialID) > maxAccountHealthEventID {
		return AccountHealthReportResult{}, fmt.Errorf("google_drive: account health trial ID exceeds %d characters", maxAccountHealthEventID)
	}
	if len(input.Reason) > maxAccountHealthReason {
		return AccountHealthReportResult{}, fmt.Errorf("google_drive: account health reason exceeds %d characters", maxAccountHealthReason)
	}
	switch input.Outcome {
	case AccountHealthSuccess, AccountHealthFailure, AccountHealthAbandoned:
	default:
		return AccountHealthReportResult{}, fmt.Errorf("google_drive: unknown account health outcome %q", input.Outcome)
	}
	if input.Generation == 0 {
		return AccountHealthReportResult{}, fmt.Errorf("google_drive: account health generation must be nonzero")
	}
	state, err := r.getWithContext(ctx, name)
	if err != nil {
		return AccountHealthReportResult{}, err
	}

	now := r.now()
	if err := lockAccountHealthState(ctx, state); err != nil {
		return AccountHealthReportResult{}, err
	}
	defer state.mu.Unlock()
	backup := state.backup()
	persisted := false
	if err := ctx.Err(); err != nil {
		backup.restore(state)
		return AccountHealthReportResult{}, err
	}
	changed := r.expireTrialLocked(state, now)
	if r.expireCooldownLocked(state, now) {
		changed = true
	}
	r.pruneEvidenceLocked(state, now)
	if err := ctx.Err(); err != nil {
		backup.restore(state)
		return AccountHealthReportResult{}, err
	}
	if _, duplicate := state.eventIDs[input.EventID]; duplicate {
		if changed {
			if err := r.persistLockedContext(ctx, state); err != nil {
				backup.restore(state)
				return AccountHealthReportResult{}, err
			}
			persisted = true
		}
		if err := ctx.Err(); err != nil {
			if !persisted {
				backup.restore(state)
			}
			return AccountHealthReportResult{}, err
		}
		return AccountHealthReportResult{
			Duplicate:     true,
			Generation:    state.generation,
			CooldownUntil: state.cooldownUntil,
			RetryAfter:    retryAfter(now, state.cooldownUntil, state.backoffUntil),
		}, nil
	}
	precedingCooldownFailure := input.Generation < state.generation &&
		state.generation-input.Generation == 1 &&
		!state.cooldownUntil.IsZero() && now.Before(state.cooldownUntil) &&
		input.Outcome == AccountHealthFailure && input.TrialID == "" &&
		isValidatedDownloadQuotaReason(input.StatusCode, input.Reason)
	if input.Generation != state.generation && !precedingCooldownFailure {
		if changed {
			if err := r.persistLockedContext(ctx, state); err != nil {
				backup.restore(state)
				return AccountHealthReportResult{}, err
			}
			persisted = true
		}
		if err := ctx.Err(); err != nil {
			if !persisted {
				backup.restore(state)
			}
			return AccountHealthReportResult{}, err
		}
		return AccountHealthReportResult{
			Stale:         true,
			Generation:    state.generation,
			CooldownUntil: state.cooldownUntil,
			RetryAfter:    retryAfter(now, state.cooldownUntil, state.backoffUntil),
		}, nil
	}
	matchingTrial := false
	if state.trial != nil {
		switch {
		case input.TrialID == "":
			// Ordinary feedback never consumes the live trial, even for its file.
		case input.TrialID == state.trial.id && input.FileID == state.trial.fileID:
			matchingTrial = true
		default:
			return AccountHealthReportResult{}, fmt.Errorf("google_drive: account health trial reference is invalid")
		}
	} else if input.TrialID != "" {
		return AccountHealthReportResult{}, fmt.Errorf("google_drive: account health trial is no longer active")
	}

	if err := ctx.Err(); err != nil {
		backup.restore(state)
		return AccountHealthReportResult{}, err
	}
	wasTrial := matchingTrial
	state.eventIDs[input.EventID] = now
	if matchingTrial {
		state.trial = nil
		changed = true
	}
	result := AccountHealthReportResult{Applied: true, Generation: state.generation}
	switch input.Outcome {
	case AccountHealthSuccess:
		state.trial = nil
		state.evidence = make(map[string]time.Time)
		state.eventIDs = map[string]time.Time{input.EventID: now}
		state.backoffUntil = time.Time{}
		state.backoffLevel = 0
		state.cooldownUntil = time.Time{}
		state.nextProbeAt = time.Time{}
		state.probeBudget = 0
		state.probeUsed = 0
		state.probeFileIDs = make(map[string]struct{})
		state.probeRequired = false
		state.generation++
		result.Generation = state.generation
		changed = true
	case AccountHealthFailure:
		if isValidatedDownloadQuotaReason(input.StatusCode, input.Reason) {
			state.evidence[fileID] = now
			if !precedingCooldownFailure {
				state.backoffLevel = min(state.backoffLevel+1, len(accountHealthBackoffs))
				backoffUntil := now.Add(accountHealthBackoffs[state.backoffLevel-1])
				if backoffUntil.After(state.backoffUntil) {
					state.backoffUntil = backoffUntil
				}
				if state.cooldownUntil.IsZero() {
					state.probeRequired = true
				}
				if len(state.evidence) >= 3 && state.cooldownUntil.IsZero() {
					state.trial = nil
					state.cooldownUntil = now.Add(accountHealthCooldown)
					state.nextProbeAt = now.Add(accountHealthProbeInterval)
					state.probeBudget = 0
					state.probeUsed = 0
					state.probeFileIDs = make(map[string]struct{})
					state.probeRequired = false
					state.generation++
					result.Generation = state.generation
				}
			}
			changed = true
		} else if wasTrial {
			state.backoffLevel = max(state.backoffLevel, 1)
			backoffUntil := now.Add(accountHealthBackoffs[state.backoffLevel-1])
			if backoffUntil.After(state.backoffUntil) {
				state.backoffUntil = backoffUntil
			}
			changed = true
		}
	case AccountHealthAbandoned:
		// A cancelled/expired trial consumes its reservation but creates no evidence.
		if wasTrial && state.probeRequired {
			state.backoffLevel = max(state.backoffLevel, 1)
			backoffUntil := now.Add(accountHealthBackoffs[state.backoffLevel-1])
			if backoffUntil.After(state.backoffUntil) {
				state.backoffUntil = backoffUntil
			}
		}
		changed = true
	}
	if changed {
		if err := r.persistLockedContext(ctx, state); err != nil {
			backup.restore(state)
			return AccountHealthReportResult{}, err
		}
		persisted = true
	}
	if err := ctx.Err(); err != nil {
		if !persisted {
			backup.restore(state)
		}
		return AccountHealthReportResult{}, err
	}
	result.CooldownUntil = state.cooldownUntil
	result.RetryAfter = retryAfter(now, state.cooldownUntil, state.backoffUntil)
	return result, nil
}

func (r *accountHealthRuntime) snapshot(ctx context.Context, name string) (AccountHealthSnapshot, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return AccountHealthSnapshot{}, err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return AccountHealthSnapshot{}, fmt.Errorf("google_drive: account name must be nonempty")
	}
	state, err := r.getWithContext(ctx, name)
	if err != nil {
		return AccountHealthSnapshot{}, err
	}
	now := r.now()
	state.mu.Lock()
	defer state.mu.Unlock()
	backup := state.backup()
	changed := r.expireTrialLocked(state, now)
	if r.expireCooldownLocked(state, now) {
		changed = true
	}
	r.pruneEvidenceLocked(state, now)
	if changed {
		if err := r.persistLocked(state); err != nil {
			backup.restore(state)
			return AccountHealthSnapshot{}, err
		}
	}
	return state.snapshot(now), nil
}

func (s *accountHealthState) snapshot(now time.Time) AccountHealthSnapshot {
	evidence := make([]string, 0, len(s.evidence))
	for fileID := range s.evidence {
		evidence = append(evidence, fileID)
	}
	sort.Strings(evidence)
	probeFileIDs := make([]string, 0, len(s.probeFileIDs))
	for fileID := range s.probeFileIDs {
		probeFileIDs = append(probeFileIDs, fileID)
	}
	sort.Strings(probeFileIDs)
	result := AccountHealthSnapshot{
		AccountKey:       s.key,
		AccountName:      s.name,
		Generation:       s.generation,
		CooldownUntil:    s.cooldownUntil,
		NextProbeAt:      s.nextProbeAt,
		BackoffUntil:     s.backoffUntil,
		BackoffLevel:     s.backoffLevel,
		EvidenceFileIDs:  evidence,
		ProbeRoundBudget: s.probeBudget,
		ProbeRoundUsed:   s.probeUsed,
		ProbeFileIDs:     probeFileIDs,
		ProbeRequired:    s.probeRequired,
	}
	if s.trial != nil {
		result.LiveTrialID = s.trial.id
		result.LiveTrialFileID = s.trial.fileID
		result.LiveTrialUntil = s.trial.expiresAt
	}
	return result
}

func retryAfter(now time.Time, cooldownUntil, backoffUntil time.Time) time.Duration {
	deadline := cooldownUntil
	if deadline.IsZero() || (!backoffUntil.IsZero() && backoffUntil.Before(deadline)) {
		deadline = backoffUntil
	}
	if deadline.IsZero() || !deadline.After(now) {
		return 0
	}
	return deadline.Sub(now)
}

func isValidatedDownloadQuotaReason(statusCode int, reason string) bool {
	return statusCode >= 400 && statusCode < 600 && strings.Contains(strings.ToLower(strings.TrimSpace(reason)), "downloadquota")
}

// AcquireGoogleDriveAccountHealth reserves a usable generation or a serialized
// probe opportunity for the shared account.
func AcquireGoogleDriveAccountHealth(ctx context.Context, accountName, fileID string) (AccountHealthLease, error) {
	return sharedAccountHealth.acquire(ctx, accountName, fileID)
}

// ReportGoogleDriveAccountHealth applies one idempotent terminal report.
func ReportGoogleDriveAccountHealth(ctx context.Context, input AccountHealthReportInput) (AccountHealthReportResult, error) {
	return sharedAccountHealth.report(ctx, input)
}

// GetGoogleDriveAccountHealth returns the current process and durable state.
func GetGoogleDriveAccountHealth(ctx context.Context, accountName string) (AccountHealthSnapshot, error) {
	return sharedAccountHealth.snapshot(ctx, accountName)
}

// ResetGoogleDriveAccountHealthForTests clears only the in-memory registry.
// Database rows remain so restart recovery can be tested explicitly.
func ResetGoogleDriveAccountHealthForTests() {
	sharedAccountHealth.mu.Lock()
	sharedAccountHealth.states = make(map[string]*accountHealthState)
	sharedAccountHealth.db = db.GetDb()
	sharedAccountHealth.mu.Unlock()
}
