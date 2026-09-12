package google_drive

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/OpenListTeam/OpenList/v4/internal/db"
	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"gorm.io/gorm"
)

const (
	googleDriveAccountProvider = "GoogleDrive"
	quotaAuthorityStateKey     = "GoogleDrive"
	maxQuotaAccountName        = 256
	maxQuotaFileID             = 1024
	maxQuotaEventID            = 256
	maxQuotaReason             = 4096
	quotaEvidenceTTL           = 10 * time.Minute
	quotaReceiptTTL            = 20 * time.Minute
	quotaSampleStateTTL        = 24 * time.Hour
	quotaCooldownTTL           = 24 * time.Hour
	quotaUncertainTTL          = time.Minute
	quotaReservationTTL        = 180 * time.Second
	quotaPermissionTTL         = 30 * time.Second
	quotaProbeInterval         = time.Hour
	quotaProbeBudget           = 1
)

const (
	quotaOutcomeSuccess   = "success"
	quotaOutcomeAbandoned = "abandoned"
)

type quotaAuthorityMode string

const (
	quotaModeNormal     quotaAuthorityMode = "normal"
	quotaModeDiagnostic quotaAuthorityMode = "diagnostic"
	quotaModeProbe      quotaAuthorityMode = "probe"
)

type quotaOpportunityScope string

const (
	quotaScopeDiagnostic  quotaOpportunityScope = "diagnostic"
	quotaScopeFile        quotaOpportunityScope = "file"
	quotaScopeAccount     quotaOpportunityScope = "account"
	quotaScopeFileAccount quotaOpportunityScope = "file_account"
)

type quotaPairEvidence struct {
	QuotaAt   time.Time `json:"quota_at"`
	ControlAt time.Time `json:"control_at"`
}

type quotaObservation struct {
	EventID           string    `json:"event_id"`
	ObservationID     string    `json:"observation_id"`
	EventType         string    `json:"event_type"`
	Provider          string    `json:"provider"`
	AccountName       string    `json:"account_name"`
	FileID            string    `json:"file_id"`
	Outcome           string    `json:"outcome"`
	StatusCode        int       `json:"status_code"`
	Reason            string    `json:"reason"`
	AccountGeneration uint64    `json:"account_generation"`
	FileGeneration    uint64    `json:"file_generation"`
	TrialID           string    `json:"trial_id,omitempty"`
	ExecutionClaimID  string    `json:"execution_claim_id,omitempty"`
	At                time.Time `json:"at"`
}

type quotaEventReceipt struct {
	Fingerprint string    `json:"fingerprint"`
	At          time.Time `json:"at"`
}

// quotaAuthorizationSample tracks the success observation requested for one
// issued authorization. The ticket itself is represented by TicketHash so a
// durable authority snapshot does not duplicate opaque signed credentials.
type quotaAuthorizationSample struct {
	TicketHash        string    `json:"ticket_hash"`
	AccountName       string    `json:"account_name"`
	FileID            string    `json:"file_id"`
	AccountGeneration uint64    `json:"account_generation"`
	FileGeneration    uint64    `json:"file_generation"`
	ObservationID     string    `json:"observation_id"`
	RequestedAt       time.Time `json:"requested_at"`
	AcknowledgedAt    time.Time `json:"acknowledged_at"`
	Pending           bool      `json:"pending"`
	QuotaPending      bool      `json:"quota_pending"`
}

type quotaOpportunity struct {
	ID                string                `json:"id"`
	Mode              quotaAuthorityMode    `json:"mode"`
	Scope             quotaOpportunityScope `json:"scope"`
	AccountName       string                `json:"account_name"`
	FileID            string                `json:"file_id"`
	AccountGeneration uint64                `json:"account_generation"`
	FileGeneration    uint64                `json:"file_generation"`
	ExpiresAt         time.Time             `json:"expires_at"`
	ClaimExpiresAt    time.Time             `json:"claim_expires_at,omitempty"`
	ObservationID     string                `json:"observation_id,omitempty"`
	Claimed           bool                  `json:"claimed"`
	ExecutionClaimID  string                `json:"execution_claim_id,omitempty"`
}

type quotaAccountState struct {
	Key           string                       `json:"key"`
	Name          string                       `json:"name"`
	Generation    uint64                       `json:"generation"`
	CooldownUntil time.Time                    `json:"cooldown_until"`
	NextProbeAt   time.Time                    `json:"next_probe_at"`
	BackoffUntil  time.Time                    `json:"backoff_until"`
	ProbeUsed     int                          `json:"probe_used"`
	ProbeRequired bool                         `json:"probe_required"`
	Probe         *quotaOpportunity            `json:"probe,omitempty"`
	Evidence      map[string]quotaPairEvidence `json:"evidence"`
}

type quotaFileState struct {
	Key            string            `json:"key"`
	FileID         string            `json:"file_id"`
	Generation     uint64            `json:"generation"`
	CooldownUntil  time.Time         `json:"cooldown_until"`
	NextProbeAt    time.Time         `json:"next_probe_at"`
	BackoffUntil   time.Time         `json:"backoff_until"`
	ProbeUsed      int               `json:"probe_used"`
	ProbeRequired  bool              `json:"probe_required"`
	Probe          *quotaOpportunity `json:"probe,omitempty"`
	Diagnostic     *quotaOpportunity `json:"diagnostic,omitempty"`
	DiagnosticUsed int               `json:"diagnostic_used"`
	QuotaPending   bool              `json:"quota_pending"`
	QuotaPendingAt time.Time         `json:"quota_pending_at,omitempty"`
}

type quotaAuthoritySnapshot struct {
	Accounts             map[string]*quotaAccountState       `json:"accounts"`
	Files                map[string]*quotaFileState          `json:"files"`
	Observations         map[string]quotaObservation         `json:"observations"`
	Receipts             map[string]quotaEventReceipt        `json:"receipts"`
	Consumed             map[string]quotaOpportunity         `json:"consumed"`
	AuthorizationSamples map[string]quotaAuthorizationSample `json:"authorization_samples"`
}

type quotaAuthorityRuntime struct {
	mu                   sync.Mutex
	now                  func() time.Time
	durable              bool
	accounts             map[string]*quotaAccountState
	files                map[string]*quotaFileState
	observations         map[string]quotaObservation
	receipts             map[string]quotaEventReceipt
	consumed             map[string]quotaOpportunity
	authorizationSamples map[string]quotaAuthorizationSample
	database             *gorm.DB
	loaded               bool
	sequence             uint64
}

type quotaAuthorityDecision struct {
	Allow               bool
	Reason              string
	RetryAfter          time.Duration
	Mode                quotaAuthorityMode
	AccountName         string
	ObservationID       string
	ReservationID       string
	ExecutionClaimID    string
	AccountGeneration   uint64
	FileGeneration      uint64
	ReportSuccess       bool
	PermissionExpiresAt time.Time
}

type quotaPermissionContext struct {
	Ticket          string
	IssuedAt        int64
	PermitExpiresAt int64
}

var sharedQuotaAuthority = newDurableQuotaAuthorityRuntime(time.Now)

func newQuotaAuthorityRuntime(now func() time.Time) *quotaAuthorityRuntime {
	if now == nil {
		now = time.Now
	}
	return &quotaAuthorityRuntime{
		now:                  now,
		accounts:             make(map[string]*quotaAccountState),
		files:                make(map[string]*quotaFileState),
		observations:         make(map[string]quotaObservation),
		receipts:             make(map[string]quotaEventReceipt),
		consumed:             make(map[string]quotaOpportunity),
		authorizationSamples: make(map[string]quotaAuthorizationSample),
	}
}

func newDurableQuotaAuthorityRuntime(now func() time.Time) *quotaAuthorityRuntime {
	runtime := newQuotaAuthorityRuntime(now)
	runtime.durable = true
	return runtime
}

func quotaAccountKey(name string) string {
	return googleDriveAccountProvider + "\x00" + strings.TrimSpace(name)
}

func quotaFileKey(fileID string) string {
	return googleDriveAccountProvider + "\x00" + strings.TrimSpace(fileID)
}

func quotaAuthorizationKey(ticket string) string {
	digest := sha256.Sum256([]byte(strings.TrimSpace(ticket)))
	return hex.EncodeToString(digest[:])
}

func (r *quotaAuthorityRuntime) loadLocked(ctx context.Context) error {
	if !r.durable {
		return nil
	}
	database := db.GetDb()
	if database == nil {
		return nil
	}
	if r.loaded && r.database == database {
		return nil
	}
	previousDatabase, previousLoaded := r.database, r.loaded
	r.database = database
	r.loaded = true
	if previousDatabase != database {
		r.accounts = make(map[string]*quotaAccountState)
		r.files = make(map[string]*quotaFileState)
		r.observations = make(map[string]quotaObservation)
		r.receipts = make(map[string]quotaEventReceipt)
		r.consumed = make(map[string]quotaOpportunity)
		r.authorizationSamples = make(map[string]quotaAuthorizationSample)
	}
	row, err := db.GetGoogleDriveQuotaAuthorityContextOn(ctx, database, quotaAuthorityStateKey)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
		r.database, r.loaded = previousDatabase, previousLoaded
		return err
	}
	var snapshot quotaAuthoritySnapshot
	if err := json.Unmarshal([]byte(row.Payload), &snapshot); err != nil {
		r.database, r.loaded = previousDatabase, previousLoaded
		return fmt.Errorf("google_drive: decode quota authority state: %w", err)
	}
	if snapshot.Accounts == nil {
		snapshot.Accounts = make(map[string]*quotaAccountState)
	}
	if snapshot.Files == nil {
		snapshot.Files = make(map[string]*quotaFileState)
	}
	if snapshot.Observations == nil {
		snapshot.Observations = make(map[string]quotaObservation)
	}
	if snapshot.Receipts == nil {
		snapshot.Receipts = make(map[string]quotaEventReceipt)
	}
	if snapshot.Consumed == nil {
		snapshot.Consumed = make(map[string]quotaOpportunity)
	}
	if snapshot.AuthorizationSamples == nil {
		snapshot.AuthorizationSamples = make(map[string]quotaAuthorizationSample)
	}
	r.accounts, r.files, r.observations, r.receipts, r.consumed, r.authorizationSamples = snapshot.Accounts, snapshot.Files, snapshot.Observations, snapshot.Receipts, snapshot.Consumed, snapshot.AuthorizationSamples
	return nil
}

func (r *quotaAuthorityRuntime) snapshotLocked() quotaAuthoritySnapshot {
	return quotaAuthoritySnapshot{
		Accounts:             r.accounts,
		Files:                r.files,
		Observations:         r.observations,
		Receipts:             r.receipts,
		Consumed:             r.consumed,
		AuthorizationSamples: r.authorizationSamples,
	}
}

func (r *quotaAuthorityRuntime) restoreLocked(snapshot quotaAuthoritySnapshot) {
	r.accounts, r.files, r.observations, r.receipts, r.consumed, r.authorizationSamples = snapshot.Accounts, snapshot.Files, snapshot.Observations, snapshot.Receipts, snapshot.Consumed, snapshot.AuthorizationSamples
}

func cloneQuotaAuthoritySnapshot(snapshot quotaAuthoritySnapshot) (quotaAuthoritySnapshot, error) {
	payload, err := json.Marshal(snapshot)
	if err != nil {
		return quotaAuthoritySnapshot{}, err
	}
	var clone quotaAuthoritySnapshot
	if err := json.Unmarshal(payload, &clone); err != nil {
		return quotaAuthoritySnapshot{}, err
	}
	if clone.Accounts == nil {
		clone.Accounts = make(map[string]*quotaAccountState)
	}
	if clone.Files == nil {
		clone.Files = make(map[string]*quotaFileState)
	}
	if clone.Observations == nil {
		clone.Observations = make(map[string]quotaObservation)
	}
	if clone.Receipts == nil {
		clone.Receipts = make(map[string]quotaEventReceipt)
	}
	if clone.Consumed == nil {
		clone.Consumed = make(map[string]quotaOpportunity)
	}
	if clone.AuthorizationSamples == nil {
		clone.AuthorizationSamples = make(map[string]quotaAuthorizationSample)
	}
	return clone, nil
}

func (r *quotaAuthorityRuntime) persistLocked(ctx context.Context) error {
	if !r.durable || r.database == nil {
		return nil
	}
	payload, err := json.Marshal(r.snapshotLocked())
	if err != nil {
		return fmt.Errorf("google_drive: encode quota authority state: %w", err)
	}
	return db.SaveGoogleDriveQuotaAuthorityContextOn(ctx, r.database, &model.GoogleDriveQuotaAuthority{
		Key:       quotaAuthorityStateKey,
		Payload:   string(payload),
		UpdatedAt: r.now(),
	})
}

func (r *quotaAuthorityRuntime) getAccountLocked(name string) *quotaAccountState {
	name = strings.TrimSpace(name)
	key := quotaAccountKey(name)
	account := r.accounts[key]
	if account == nil {
		account = &quotaAccountState{Key: key, Name: name, Generation: 1, Evidence: make(map[string]quotaPairEvidence)}
		r.accounts[key] = account
	} else if account.Generation == 0 {
		account.Generation = 1
	}
	if account.Evidence == nil {
		account.Evidence = make(map[string]quotaPairEvidence)
	}
	return account
}

func (r *quotaAuthorityRuntime) getFileLocked(fileID string) *quotaFileState {
	fileID = strings.TrimSpace(fileID)
	key := quotaFileKey(fileID)
	file := r.files[key]
	if file == nil {
		file = &quotaFileState{Key: key, FileID: fileID, Generation: 1}
		r.files[key] = file
	} else if file.Generation == 0 {
		file.Generation = 1
	}
	return file
}

func quotaRetryAfter(now, first, second time.Time) time.Duration {
	deadline := first
	if deadline.IsZero() || (!second.IsZero() && second.Before(deadline)) {
		deadline = second
	}
	if deadline.IsZero() || !deadline.After(now) {
		return 0
	}
	return deadline.Sub(now)
}

func (r *quotaAuthorityRuntime) quotaPendingRetryAfterLocked(file *quotaFileState, now time.Time) time.Duration {
	deadline := now.Add(quotaUncertainTTL)
	if !file.QuotaPendingAt.IsZero() {
		deadline = minQuotaDeadline(deadline, file.QuotaPendingAt.Add(quotaReservationTTL), now)
	}
	if !file.BackoffUntil.IsZero() {
		deadline = minQuotaDeadline(deadline, file.BackoffUntil, now)
	}
	for _, opportunity := range []*quotaOpportunity{file.Diagnostic, file.Probe} {
		if opportunity == nil {
			continue
		}
		opportunityDeadline := opportunity.ExpiresAt
		if opportunity.Claimed && !opportunity.ClaimExpiresAt.IsZero() {
			opportunityDeadline = opportunity.ClaimExpiresAt
		}
		deadline = minQuotaDeadline(deadline, opportunityDeadline, now)
	}
	if deadline.After(now) {
		return deadline.Sub(now)
	}
	return quotaUncertainTTL
}

func quotaExecutionBackoffLocked(file *quotaFileState, account *quotaAccountState, now time.Time) (string, time.Duration) {
	if file != nil && file.BackoffUntil.After(now) {
		return "uncertain file backoff", file.BackoffUntil.Sub(now)
	}
	if account != nil && account.BackoffUntil.After(now) {
		return "uncertain account backoff", account.BackoffUntil.Sub(now)
	}
	return "", 0
}

func isGoogleDriveQuotaFeedback(provider string, statusCode int, reason string) bool {
	return strings.EqualFold(strings.TrimSpace(provider), googleDriveAccountProvider) && driver.IsQualifyingDownloadQuotaResponse(statusCode, reason)
}

func minQuotaDeadline(current, candidate, now time.Time) time.Time {
	if candidate.After(now) && candidate.Before(current) {
		return candidate
	}
	return current
}

func maxQuotaTime(first, second time.Time) time.Time {
	if second.After(first) {
		return second
	}
	return first
}

func (r *quotaAuthorityRuntime) expireLocked(now time.Time) bool {
	changed := false
	for _, account := range r.accounts {
		if account.Probe != nil {
			if account.Probe.Claimed && !account.Probe.ClaimExpiresAt.IsZero() && !now.Before(account.Probe.ClaimExpiresAt) {
				if account.Probe.Mode == quotaModeProbe && account.CooldownUntil.IsZero() && account.ProbeRequired {
					account.BackoffUntil = maxQuotaTime(account.BackoffUntil, now.Add(quotaUncertainTTL))
				}
				r.consumed[account.Probe.ID] = *account.Probe
				account.Probe = nil
				changed = true
			} else if !account.Probe.Claimed && !now.Before(account.Probe.ExpiresAt) {
				account.Probe = nil
				changed = true
			}
		}
		if !account.CooldownUntil.IsZero() && !now.Before(account.CooldownUntil) {
			account.CooldownUntil = time.Time{}
			account.NextProbeAt = time.Time{}
			account.ProbeUsed = 0
			account.ProbeRequired = true
			account.BackoffUntil = time.Time{}
			account.Generation++
			changed = true
		}
		if !account.BackoffUntil.IsZero() && !now.Before(account.BackoffUntil) {
			account.BackoffUntil = time.Time{}
			changed = true
		}
	}
	for _, file := range r.files {
		for _, opportunity := range []*quotaOpportunity{file.Diagnostic, file.Probe} {
			if opportunity == nil {
				continue
			}
			if opportunity.Claimed && !opportunity.ClaimExpiresAt.IsZero() && !now.Before(opportunity.ClaimExpiresAt) {
				if opportunity.Mode == quotaModeProbe && file.CooldownUntil.IsZero() && file.ProbeRequired {
					file.BackoffUntil = maxQuotaTime(file.BackoffUntil, now.Add(quotaUncertainTTL))
				}
				r.consumed[opportunity.ID] = *opportunity
				if opportunity.Mode == quotaModeDiagnostic && file.CooldownUntil.IsZero() && file.BackoffUntil.Before(now.Add(quotaUncertainTTL)) {
					file.BackoffUntil = now.Add(quotaUncertainTTL)
				}
				if file.Diagnostic != nil && file.Diagnostic.ID == opportunity.ID {
					file.Diagnostic = nil
				}
				if file.Probe != nil && file.Probe.ID == opportunity.ID {
					file.Probe = nil
				}
				changed = true
			} else if !opportunity.Claimed && !now.Before(opportunity.ExpiresAt) {
				if file.Diagnostic != nil && file.Diagnostic.ID == opportunity.ID {
					file.Diagnostic = nil
				}
				if file.Probe != nil && file.Probe.ID == opportunity.ID {
					file.Probe = nil
				}
				changed = true
			}
		}
		if file.QuotaPending && file.Diagnostic == nil && file.Probe == nil && !file.QuotaPendingAt.IsZero() && !now.Before(file.QuotaPendingAt.Add(quotaReservationTTL)) {
			file.QuotaPending = false
			file.QuotaPendingAt = time.Time{}
			if file.CooldownUntil.IsZero() {
				file.BackoffUntil = maxQuotaTime(file.BackoffUntil, now.Add(quotaUncertainTTL))
			}
			changed = true
		}
		if !file.CooldownUntil.IsZero() && !now.Before(file.CooldownUntil) {
			file.CooldownUntil = time.Time{}
			file.NextProbeAt = time.Time{}
			file.ProbeUsed = 0
			file.ProbeRequired = true
			file.BackoffUntil = time.Time{}
			file.QuotaPending = false
			file.QuotaPendingAt = time.Time{}
			file.Generation++
			changed = true
		}
		if !file.BackoffUntil.IsZero() && !now.Before(file.BackoffUntil) {
			file.BackoffUntil = time.Time{}
			file.DiagnosticUsed = 0
			file.QuotaPending = false
			file.QuotaPendingAt = time.Time{}
			changed = true
		}
	}
	cutoff := now.Add(-quotaEvidenceTTL)
	for id, observation := range r.observations {
		if !observation.At.After(cutoff) {
			delete(r.observations, id)
			changed = true
		}
	}
	receiptCutoff := now.Add(-quotaReceiptTTL)
	for id, receipt := range r.receipts {
		if !receipt.At.After(receiptCutoff) {
			delete(r.receipts, id)
			changed = true
		}
	}
	for id, opportunity := range r.consumed {
		if opportunity.ClaimExpiresAt.IsZero() || !opportunity.ClaimExpiresAt.Add(quotaReceiptTTL).After(now) {
			delete(r.consumed, id)
			changed = true
		}
	}
	sampleCutoff := now.Add(-quotaSampleStateTTL)
	for key, sample := range r.authorizationSamples {
		lastAt := sample.RequestedAt
		if sample.AcknowledgedAt.After(lastAt) {
			lastAt = sample.AcknowledgedAt
		}
		if lastAt.IsZero() || !lastAt.After(sampleCutoff) {
			delete(r.authorizationSamples, key)
			changed = true
		}
	}
	if changed {
		r.retireUnclaimedStaleOpportunitiesLocked()
		r.clearResolvedQuotaPendingSamplesLocked("", now)
	}
	return changed
}

func (r *quotaAuthorityRuntime) newID(prefix string) string {
	r.sequence++
	return fmt.Sprintf("%s-%d-%d", prefix, r.now().UnixNano(), r.sequence)
}

func (r *quotaAuthorityRuntime) hasRecentOtherFileSuccessLocked(accountName, fileID string, now time.Time) bool {
	cutoff := now.Add(-quotaEvidenceTTL)
	for _, observation := range r.observations {
		if observation.EventType == "success" && observation.AccountName != accountName && observation.FileID == fileID && observation.At.After(cutoff) {
			return true
		}
	}
	return false
}

func (r *quotaAuthorityRuntime) hasRecentOtherFileForAccountLocked(accountName, fileID string, now time.Time) bool {
	cutoff := now.Add(-quotaEvidenceTTL)
	for _, observation := range r.observations {
		if observation.EventType != "success" || observation.AccountName != accountName || observation.FileID == fileID || !observation.At.After(cutoff) {
			continue
		}
		if otherFile := r.files[quotaFileKey(observation.FileID)]; otherFile == nil || !otherFile.CooldownUntil.After(observation.At) {
			return true
		}
	}
	return false
}

func (r *quotaAuthorityRuntime) preferProbeCandidates(ctx context.Context, fileID string, candidates []string) ([]string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := r.loadLocked(ctx); err != nil {
		return nil, err
	}
	now := r.now()
	file := r.getFileLocked(fileID)
	type candidate struct {
		name  string
		score int
	}
	ordered := make([]candidate, 0, len(candidates))
	for _, name := range candidates {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		account := r.getAccountLocked(name)
		score := 0
		fileProbeDue := file.CooldownUntil.After(now) && !file.NextProbeAt.IsZero() && !now.Before(file.NextProbeAt) && !account.CooldownUntil.After(now)
		accountProbeDue := account.CooldownUntil.After(now) && !account.NextProbeAt.IsZero() && !now.Before(account.NextProbeAt)
		if fileProbeDue && r.hasRecentOtherFileForAccountLocked(name, file.FileID, now) {
			score = 1
		}
		if accountProbeDue && r.hasRecentOtherFileSuccessLocked(name, file.FileID, now) {
			score = 1
		}
		ordered = append(ordered, candidate{name: name, score: score})
	}
	sort.SliceStable(ordered, func(left, right int) bool {
		return ordered[left].score > ordered[right].score
	})
	result := make([]string, 0, len(ordered))
	for _, item := range ordered {
		result = append(result, item.name)
	}
	return result, nil
}

func (r *quotaAuthorityRuntime) reserveProbeLocked(file *quotaFileState, account *quotaAccountState, forFile bool, now time.Time) quotaAuthorityDecision {
	scope := quotaScopeAccount
	if forFile {
		scope = quotaScopeFile
		if account.ProbeRequired && account.Probe == nil && account.ProbeUsed < quotaProbeBudget && !account.BackoffUntil.After(now) && !account.CooldownUntil.After(now) {
			scope = quotaScopeFileAccount
		}
	}
	opportunity := &quotaOpportunity{
		ID:                r.newID("probe"),
		Mode:              quotaModeProbe,
		Scope:             scope,
		AccountName:       account.Name,
		FileID:            file.FileID,
		AccountGeneration: account.Generation,
		FileGeneration:    file.Generation,
		ExpiresAt:         now.Add(quotaReservationTTL),
		ObservationID:     r.newID("observation"),
	}
	if forFile {
		file.Probe = opportunity
		if scope == "file_account" {
			account.Probe = opportunity
		}
	} else {
		account.Probe = opportunity
		account.ProbeRequired = true
	}
	return quotaAuthorityDecision{Allow: true, Mode: quotaModeProbe, AccountName: account.Name, ObservationID: opportunity.ObservationID, ReservationID: opportunity.ID, AccountGeneration: account.Generation, FileGeneration: file.Generation, ReportSuccess: true}
}

func (r *quotaAuthorityRuntime) authorize(ctx context.Context, accountName, fileID string) (quotaAuthorityDecision, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if strings.TrimSpace(accountName) == "" || strings.TrimSpace(fileID) == "" {
		return quotaAuthorityDecision{}, fmt.Errorf("google_drive: quota authority identity is empty")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return quotaAuthorityDecision{}, err
	}
	if err := r.loadLocked(ctx); err != nil {
		return quotaAuthorityDecision{}, err
	}
	backup, err := cloneQuotaAuthoritySnapshot(r.snapshotLocked())
	if err != nil {
		return quotaAuthorityDecision{}, err
	}
	now := r.now()
	if r.expireLocked(now) {
		if err := r.persistLocked(ctx); err != nil {
			r.restoreLocked(backup)
			return quotaAuthorityDecision{}, err
		}
	}
	account := r.getAccountLocked(accountName)
	file := r.getFileLocked(fileID)
	if reason, retryAfter := quotaExecutionBackoffLocked(file, account, now); reason != "" {
		return quotaAuthorityDecision{Reason: reason, RetryAfter: retryAfter, FileGeneration: file.Generation, AccountGeneration: account.Generation}, nil
	}
	if file.Probe != nil && !file.Probe.Claimed && file.Probe.AccountName == account.Name {
		return quotaAuthorityDecision{Allow: true, Mode: quotaModeProbe, AccountName: account.Name, ObservationID: file.Probe.ObservationID, ReservationID: file.Probe.ID, AccountGeneration: account.Generation, FileGeneration: file.Generation, ReportSuccess: true}, nil
	}
	if account.Probe != nil && !account.Probe.Claimed && account.Probe.FileID == file.FileID && account.Probe.AccountName == account.Name {
		return quotaAuthorityDecision{Allow: true, Mode: quotaModeProbe, AccountName: account.Name, ObservationID: account.Probe.ObservationID, ReservationID: account.Probe.ID, AccountGeneration: account.Generation, FileGeneration: file.Generation, ReportSuccess: true}, nil
	}
	if file.QuotaPending {
		if err := r.persistLocked(ctx); err != nil {
			r.restoreLocked(backup)
			return quotaAuthorityDecision{}, err
		}
		return quotaAuthorityDecision{Reason: "quota decision pending", RetryAfter: r.quotaPendingRetryAfterLocked(file, now), FileGeneration: file.Generation, AccountGeneration: account.Generation}, nil
	}
	if file.Probe != nil || account.Probe != nil {
		if err := r.persistLocked(ctx); err != nil {
			r.restoreLocked(backup)
			return quotaAuthorityDecision{}, err
		}
		return quotaAuthorityDecision{Reason: "opportunity busy", RetryAfter: quotaReservationTTL, FileGeneration: file.Generation, AccountGeneration: account.Generation}, nil
	}
	if file.CooldownUntil.After(now) && !account.CooldownUntil.After(now) && !file.NextProbeAt.IsZero() && !now.Before(file.NextProbeAt) && file.ProbeUsed < quotaProbeBudget {
		decision := r.reserveProbeLocked(file, account, true, now)
		if err := r.persistLocked(ctx); err != nil {
			r.restoreLocked(backup)
			return quotaAuthorityDecision{}, err
		}
		return decision, nil
	}
	if file.CooldownUntil.After(now) {
		if !account.CooldownUntil.After(now) && !file.NextProbeAt.IsZero() && !now.Before(file.NextProbeAt) && file.ProbeUsed >= quotaProbeBudget {
			file.ProbeUsed = 0
			file.NextProbeAt = time.Time{}
			file.ProbeRequired = true
			decision := r.reserveProbeLocked(file, account, true, now)
			if err := r.persistLocked(ctx); err != nil {
				r.restoreLocked(backup)
				return quotaAuthorityDecision{}, err
			}
			return decision, nil
		}
		if err := r.persistLocked(ctx); err != nil {
			r.restoreLocked(backup)
			return quotaAuthorityDecision{}, err
		}
		return quotaAuthorityDecision{Reason: "file cooldown", RetryAfter: quotaRetryAfter(now, file.CooldownUntil, file.NextProbeAt), FileGeneration: file.Generation, AccountGeneration: account.Generation}, nil
	}
	if account.CooldownUntil.After(now) {
		if !account.NextProbeAt.IsZero() && !now.Before(account.NextProbeAt) && account.ProbeUsed >= quotaProbeBudget {
			account.ProbeUsed = 0
			account.NextProbeAt = time.Time{}
			account.ProbeRequired = true
			decision := r.reserveProbeLocked(file, account, false, now)
			if err := r.persistLocked(ctx); err != nil {
				r.restoreLocked(backup)
				return quotaAuthorityDecision{}, err
			}
			return decision, nil
		}
		if !account.NextProbeAt.IsZero() && !now.Before(account.NextProbeAt) && account.ProbeUsed < quotaProbeBudget {
			decision := r.reserveProbeLocked(file, account, false, now)
			if err := r.persistLocked(ctx); err != nil {
				r.restoreLocked(backup)
				return quotaAuthorityDecision{}, err
			}
			return decision, nil
		}
		if err := r.persistLocked(ctx); err != nil {
			r.restoreLocked(backup)
			return quotaAuthorityDecision{}, err
		}
		return quotaAuthorityDecision{Reason: "account unavailable", RetryAfter: quotaRetryAfter(now, account.CooldownUntil, account.NextProbeAt), FileGeneration: file.Generation, AccountGeneration: account.Generation}, nil
	}
	if file.ProbeRequired && !account.CooldownUntil.After(now) && file.ProbeUsed < quotaProbeBudget {
		decision := r.reserveProbeLocked(file, account, true, now)
		if err := r.persistLocked(ctx); err != nil {
			r.restoreLocked(backup)
			return quotaAuthorityDecision{}, err
		}
		return decision, nil
	}
	if account.ProbeRequired && !file.BackoffUntil.After(now) && account.ProbeUsed < quotaProbeBudget {
		decision := r.reserveProbeLocked(file, account, false, now)
		if err := r.persistLocked(ctx); err != nil {
			r.restoreLocked(backup)
			return quotaAuthorityDecision{}, err
		}
		return decision, nil
	}
	if file.Diagnostic != nil && !file.Diagnostic.Claimed {
		if err := r.persistLocked(ctx); err != nil {
			r.restoreLocked(backup)
			return quotaAuthorityDecision{}, err
		}
		return quotaAuthorityDecision{Reason: "opportunity busy", RetryAfter: file.Diagnostic.ExpiresAt.Sub(now), FileGeneration: file.Generation, AccountGeneration: account.Generation}, nil
	}
	if account.ProbeRequired && account.Probe != nil && !account.Probe.Claimed {
		if err := r.persistLocked(ctx); err != nil {
			r.restoreLocked(backup)
			return quotaAuthorityDecision{}, err
		}
		return quotaAuthorityDecision{Reason: "opportunity busy", RetryAfter: account.Probe.ExpiresAt.Sub(now), FileGeneration: file.Generation, AccountGeneration: account.Generation}, nil
	}
	decision := quotaAuthorityDecision{
		Allow:             true,
		Mode:              quotaModeNormal,
		AccountName:       account.Name,
		ObservationID:     r.newID("observation"),
		FileGeneration:    file.Generation,
		AccountGeneration: account.Generation,
		ReportSuccess:     true,
	}
	if err := r.persistLocked(ctx); err != nil {
		r.restoreLocked(backup)
		return quotaAuthorityDecision{}, err
	}
	return decision, nil
}

func quotaAccountAvailableLocked(file *quotaFileState, account *quotaAccountState, now time.Time) bool {
	if account == nil || account.CooldownUntil.After(now) || account.Probe != nil {
		return false
	}
	reason, _ := quotaExecutionBackoffLocked(file, account, now)
	return reason == ""
}

func (r *quotaAuthorityRuntime) chooseCandidateLocked(fileID, excluded string, candidates []string, now time.Time) (string, *quotaAccountState) {
	file := r.getFileLocked(fileID)
	var fallback string
	var fallbackAccount *quotaAccountState
	for _, candidateName := range candidates {
		candidateName = strings.TrimSpace(candidateName)
		if candidateName == "" || candidateName == strings.TrimSpace(excluded) {
			continue
		}
		account := r.getAccountLocked(candidateName)
		if !quotaAccountAvailableLocked(file, account, now) {
			continue
		}
		if fallback == "" {
			fallback, fallbackAccount = candidateName, account
		}
		for _, observation := range r.observations {
			if observation.AccountName != candidateName || observation.Outcome != string(quotaOutcomeSuccess) || observation.FileID == file.FileID || !observation.At.After(now.Add(-quotaEvidenceTTL)) {
				continue
			}
			return candidateName, account
		}
	}
	return fallback, fallbackAccount
}

func (r *quotaAuthorityRuntime) chooseRequiredProbeCandidateLocked(file *quotaFileState, excluded string, candidates []string, now time.Time) (bool, *quotaAccountState) {
	if file == nil {
		return false, nil
	}
	trimmedExcluded := strings.TrimSpace(excluded)
	for _, candidateName := range candidates {
		candidateName = strings.TrimSpace(candidateName)
		if candidateName == "" || candidateName == trimmedExcluded {
			continue
		}
		account := r.getAccountLocked(candidateName)
		if !quotaAccountAvailableLocked(file, account, now) {
			continue
		}
		if file.ProbeRequired && file.Probe == nil && file.ProbeUsed < quotaProbeBudget {
			return true, account
		}
		if account.ProbeRequired && account.Probe == nil && account.ProbeUsed < quotaProbeBudget {
			return false, account
		}
	}
	return false, nil
}

func (r *quotaAuthorityRuntime) nextDiagnostic(ctx context.Context, fileID, excluded string, candidates []string) (quotaAuthorityDecision, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return quotaAuthorityDecision{}, err
	}
	if err := r.loadLocked(ctx); err != nil {
		return quotaAuthorityDecision{}, err
	}
	backup, err := cloneQuotaAuthoritySnapshot(r.snapshotLocked())
	if err != nil {
		return quotaAuthorityDecision{}, err
	}
	now := r.now()
	r.expireLocked(now)
	file := r.getFileLocked(fileID)
	if file.CooldownUntil.After(now) {
		if err := r.persistLocked(ctx); err != nil {
			r.restoreLocked(backup)
			return quotaAuthorityDecision{}, err
		}
		return quotaAuthorityDecision{Reason: "file cooldown", RetryAfter: quotaRetryAfter(now, file.CooldownUntil, file.NextProbeAt), FileGeneration: file.Generation}, nil
	}
	if file.BackoffUntil.After(now) {
		if err := r.persistLocked(ctx); err != nil {
			r.restoreLocked(backup)
			return quotaAuthorityDecision{}, err
		}
		return quotaAuthorityDecision{Reason: "uncertain file backoff", RetryAfter: file.BackoffUntil.Sub(now), FileGeneration: file.Generation}, nil
	}
	activeProbe := file.Probe
	if activeProbe == nil {
		for _, account := range r.accounts {
			if account.Probe != nil && account.Probe.FileID == file.FileID {
				activeProbe = account.Probe
				break
			}
		}
	}
	if activeProbe != nil {
		if err := r.persistLocked(ctx); err != nil {
			r.restoreLocked(backup)
			return quotaAuthorityDecision{}, err
		}
		retryAfter := activeProbe.ExpiresAt.Sub(now)
		if activeProbe.Claimed && !activeProbe.ClaimExpiresAt.IsZero() {
			retryAfter = activeProbe.ClaimExpiresAt.Sub(now)
		}
		return quotaAuthorityDecision{Reason: "opportunity busy", RetryAfter: retryAfter, FileGeneration: file.Generation}, nil
	}
	if file.Diagnostic != nil {
		opportunity := file.Diagnostic
		if opportunity.Claimed {
			if err := r.persistLocked(ctx); err != nil {
				r.restoreLocked(backup)
				return quotaAuthorityDecision{}, err
			}
			return quotaAuthorityDecision{Reason: "opportunity busy", RetryAfter: opportunity.ClaimExpiresAt.Sub(now), FileGeneration: file.Generation}, nil
		}
		account := r.getAccountLocked(opportunity.AccountName)
		if !quotaOpportunityMatches(opportunity, account, file, quotaModeDiagnostic, opportunity.ObservationID) {
			file.Diagnostic = nil
		} else {
			if err := r.persistLocked(ctx); err != nil {
				r.restoreLocked(backup)
				return quotaAuthorityDecision{}, err
			}
			return quotaAuthorityDecision{Allow: true, Mode: opportunity.Mode, AccountName: opportunity.AccountName, ObservationID: opportunity.ObservationID, ReservationID: opportunity.ID, AccountGeneration: account.Generation, FileGeneration: file.Generation, ReportSuccess: true}, nil
		}
	}
	probeExcluded := excluded
	if !file.QuotaPending {
		probeExcluded = ""
	}
	if forFile, account := r.chooseRequiredProbeCandidateLocked(file, probeExcluded, candidates, now); account != nil {
		decision := r.reserveProbeLocked(file, account, forFile, now)
		if err := r.persistLocked(ctx); err != nil {
			r.restoreLocked(backup)
			return quotaAuthorityDecision{}, err
		}
		return decision, nil
	}
	if !file.QuotaPending {
		if name, account := r.chooseNormalNextPlanAccountLocked(fileID, excluded, candidates, now); account != nil {
			decision := quotaAuthorityDecision{
				Allow:             true,
				Mode:              quotaModeNormal,
				AccountName:       name,
				ObservationID:     r.newID("observation"),
				AccountGeneration: account.Generation,
				FileGeneration:    file.Generation,
				ReportSuccess:     true,
			}
			if err := r.persistLocked(ctx); err != nil {
				r.restoreLocked(backup)
				return quotaAuthorityDecision{}, err
			}
			return decision, nil
		}
	}
	if excludedAccount := r.accounts[quotaAccountKey(excluded)]; excludedAccount != nil && excludedAccount.CooldownUntil.After(now) {
		name, account := r.chooseNormalNextPlanAccountLocked(fileID, excluded, candidates, now)
		if account == nil {
			if err := r.persistLocked(ctx); err != nil {
				r.restoreLocked(backup)
				return quotaAuthorityDecision{}, err
			}
			return quotaAuthorityDecision{Reason: "account unavailable", RetryAfter: quotaRetryAfter(now, excludedAccount.CooldownUntil, excludedAccount.NextProbeAt), FileGeneration: file.Generation}, nil
		}
		file.QuotaPending = false
		file.QuotaPendingAt = time.Time{}
		r.clearResolvedQuotaPendingSamplesLocked(file.FileID, now)
		decision := quotaAuthorityDecision{Allow: true, Mode: quotaModeNormal, AccountName: name, ObservationID: r.newID("observation"), AccountGeneration: account.Generation, FileGeneration: file.Generation, ReportSuccess: true}
		if err := r.persistLocked(ctx); err != nil {
			r.restoreLocked(backup)
			return quotaAuthorityDecision{}, err
		}
		return decision, nil
	}
	if file.DiagnosticUsed >= 2 {
		file.BackoffUntil = now.Add(quotaUncertainTTL)
		if err := r.persistLocked(ctx); err != nil {
			r.restoreLocked(backup)
			return quotaAuthorityDecision{}, err
		}
		return quotaAuthorityDecision{Reason: "uncertain file backoff", RetryAfter: quotaUncertainTTL, FileGeneration: file.Generation}, nil
	}
	name, account := r.chooseCandidateLocked(fileID, excluded, candidates, now)
	if account == nil {
		file.BackoffUntil = now.Add(quotaUncertainTTL)
		if err := r.persistLocked(ctx); err != nil {
			r.restoreLocked(backup)
			return quotaAuthorityDecision{}, err
		}
		return quotaAuthorityDecision{Reason: "uncertain file backoff", RetryAfter: quotaUncertainTTL, FileGeneration: file.Generation}, nil
	}
	opportunity := &quotaOpportunity{
		ID:                r.newID("diagnostic"),
		Mode:              quotaModeDiagnostic,
		Scope:             quotaScopeDiagnostic,
		AccountName:       name,
		FileID:            file.FileID,
		AccountGeneration: account.Generation,
		FileGeneration:    file.Generation,
		ExpiresAt:         now.Add(quotaReservationTTL),
		ObservationID:     r.newID("observation"),
	}
	file.Diagnostic = opportunity
	if err := r.persistLocked(ctx); err != nil {
		r.restoreLocked(backup)
		return quotaAuthorityDecision{}, err
	}
	return quotaAuthorityDecision{Allow: true, Mode: opportunity.Mode, AccountName: opportunity.AccountName, ObservationID: opportunity.ObservationID, ReservationID: opportunity.ID, AccountGeneration: account.Generation, FileGeneration: file.Generation, ReportSuccess: true}, nil
}

func (r *quotaAuthorityRuntime) hasRecentSuccessLocked(accountName, fileID string, now time.Time) bool {
	cutoff := now.Add(-quotaEvidenceTTL)
	for _, observation := range r.observations {
		if observation.EventType != "success" || observation.AccountName != accountName || observation.FileID != fileID || !observation.At.After(cutoff) {
			continue
		}
		account := r.accounts[quotaAccountKey(accountName)]
		if account != nil && observation.AccountGeneration != 0 && observation.AccountGeneration != account.Generation {
			continue
		}
		file := r.files[quotaFileKey(fileID)]
		if file != nil && observation.FileGeneration != 0 && observation.FileGeneration != file.Generation {
			continue
		}
		return true
	}
	return false
}

func (r *quotaAuthorityRuntime) chooseNormalNextPlanAccountLocked(fileID, excluded string, candidates []string, now time.Time) (string, *quotaAccountState) {
	file := r.getFileLocked(fileID)
	if file.CooldownUntil.After(now) || file.BackoffUntil.After(now) || file.ProbeRequired || file.Probe != nil {
		return "", nil
	}
	for _, account := range r.accounts {
		if account.Probe != nil && account.Probe.FileID == file.FileID {
			return "", nil
		}
	}
	eligible := func(account *quotaAccountState) bool {
		if !quotaAccountAvailableLocked(file, account, now) || account.ProbeRequired {
			return false
		}
		return true
	}
	excluded = strings.TrimSpace(excluded)
	if excluded != "" {
		account := r.getAccountLocked(excluded)
		if eligible(account) && r.hasRecentSuccessLocked(account.Name, file.FileID, now) {
			return account.Name, account
		}
	}
	name, account := r.chooseCandidateLocked(fileID, excluded, candidates, now)
	if eligible(account) {
		return name, account
	}
	if excluded == "" {
		return "", nil
	}
	for _, candidate := range candidates {
		if strings.TrimSpace(candidate) != excluded {
			continue
		}
		account = r.getAccountLocked(candidate)
		if eligible(account) {
			return account.Name, account
		}
		return "", nil
	}
	return "", nil
}

// normalPermissionSampleLocked keeps the first success request attached to a
// ticket through permit renewal. Once that observation is acknowledged, a
// later request can open one fresh sampling window when evidence is stale.
func (r *quotaAuthorityRuntime) normalPermissionSampleLocked(ticket, accountName, fileID string, accountGeneration, fileGeneration uint64, observationID string, now time.Time) (string, bool, bool) {
	ticket = strings.TrimSpace(ticket)
	observationID = strings.TrimSpace(observationID)
	if ticket == "" || observationID == "" {
		return observationID, false, false
	}
	key := quotaAuthorizationKey(ticket)
	sample, exists := r.authorizationSamples[key]
	if !exists || sample.TicketHash == "" {
		sample = quotaAuthorizationSample{
			TicketHash:        key,
			AccountName:       strings.TrimSpace(accountName),
			FileID:            strings.TrimSpace(fileID),
			AccountGeneration: accountGeneration,
			FileGeneration:    fileGeneration,
			ObservationID:     observationID,
			RequestedAt:       now,
			Pending:           true,
		}
		r.authorizationSamples[key] = sample
		return observationID, true, true
	}
	// A signed ticket is immutable. Treat an unexpected identity as a stale
	// sample and leave the existing record untouched.
	if sample.AccountName != strings.TrimSpace(accountName) || sample.FileID != strings.TrimSpace(fileID) {
		return sample.ObservationID, false, false
	}
	if sample.AccountGeneration != accountGeneration || sample.FileGeneration != fileGeneration {
		sample.AccountGeneration = accountGeneration
		sample.FileGeneration = fileGeneration
		sample.ObservationID = r.newID("observation")
		sample.RequestedAt = now
		sample.AcknowledgedAt = time.Time{}
		sample.Pending = true
		sample.QuotaPending = false
		r.authorizationSamples[key] = sample
		return sample.ObservationID, true, true
	}
	if sample.QuotaPending {
		return sample.ObservationID, false, false
	}
	if sample.Pending {
		if sample.ObservationID == "" {
			sample.ObservationID = observationID
			r.authorizationSamples[key] = sample
			return observationID, true, true
		}
		return sample.ObservationID, true, false
	}
	if !sample.AcknowledgedAt.IsZero() && now.Sub(sample.AcknowledgedAt) >= quotaEvidenceTTL && !r.hasRecentSuccessLocked(sample.AccountName, sample.FileID, now) {
		sample.ObservationID = r.newID("observation")
		sample.RequestedAt = now
		sample.AcknowledgedAt = time.Time{}
		sample.Pending = true
		r.authorizationSamples[key] = sample
		return sample.ObservationID, true, true
	}
	return sample.ObservationID, false, false
}

func (r *quotaAuthorityRuntime) acknowledgeNormalSampleLocked(input driver.DownloadAuthorizationFeedback, observationID string, now time.Time) bool {
	if strings.TrimSpace(input.Ticket) == "" || input.TrialID != "" || strings.TrimSpace(observationID) == "" {
		return false
	}
	key := quotaAuthorizationKey(input.Ticket)
	sample, exists := r.authorizationSamples[key]
	if !exists {
		sample = quotaAuthorizationSample{
			TicketHash:        key,
			AccountName:       strings.TrimSpace(input.AccountName),
			FileID:            strings.TrimSpace(input.FileID),
			AccountGeneration: input.Generation,
			FileGeneration:    input.FileGeneration,
			ObservationID:     observationID,
		}
	}
	if sample.AccountName != "" && (sample.AccountName != strings.TrimSpace(input.AccountName) || sample.FileID != strings.TrimSpace(input.FileID) || sample.AccountGeneration != input.Generation || sample.FileGeneration != input.FileGeneration) {
		return false
	}
	if sample.ObservationID != "" && sample.ObservationID != observationID {
		return false
	}
	sample.AccountName = strings.TrimSpace(input.AccountName)
	sample.FileID = strings.TrimSpace(input.FileID)
	sample.AccountGeneration = input.Generation
	sample.FileGeneration = input.FileGeneration
	sample.ObservationID = observationID
	sample.AcknowledgedAt = now
	sample.Pending = false
	r.authorizationSamples[key] = sample
	return true
}

func (r *quotaAuthorityRuntime) clearResolvedQuotaPendingSamplesLocked(fileID string, now time.Time) {
	for key, sample := range r.authorizationSamples {
		if !sample.QuotaPending || (fileID != "" && sample.FileID != fileID) {
			continue
		}
		account := r.accounts[quotaAccountKey(sample.AccountName)]
		if account != nil && account.CooldownUntil.After(now) {
			continue
		}
		file := r.files[quotaFileKey(sample.FileID)]
		if file != nil && file.CooldownUntil.After(now) {
			continue
		}
		sample.QuotaPending = false
		sample.ObservationID = r.newID("observation")
		r.authorizationSamples[key] = sample
	}
}

func quotaOpportunityMatches(opportunity *quotaOpportunity, account *quotaAccountState, file *quotaFileState, mode quotaAuthorityMode, observationID string) bool {
	if opportunity == nil || account == nil || file == nil {
		return false
	}
	return opportunity.AccountName == account.Name && opportunity.FileID == file.FileID && opportunity.Mode == mode && opportunity.AccountGeneration == account.Generation && opportunity.FileGeneration == file.Generation && (observationID == "" || opportunity.ObservationID == observationID)
}

func (r *quotaAuthorityRuntime) permission(ctx context.Context, accountName, fileID string, accountGeneration, fileGeneration uint64, mode quotaAuthorityMode, observationID, reservationID, operation, claimID string, contexts ...quotaPermissionContext) (quotaAuthorityDecision, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return quotaAuthorityDecision{}, err
	}
	if err := r.loadLocked(ctx); err != nil {
		return quotaAuthorityDecision{}, err
	}
	backup, err := cloneQuotaAuthoritySnapshot(r.snapshotLocked())
	if err != nil {
		return quotaAuthorityDecision{}, err
	}
	now := r.now()
	permissionContext := quotaPermissionContext{}
	if len(contexts) > 0 {
		permissionContext = contexts[0]
	}
	ticket := permissionContext.Ticket
	if r.expireLocked(now) {
		if err := r.persistLocked(ctx); err != nil {
			r.restoreLocked(backup)
			return quotaAuthorityDecision{}, err
		}
	}
	account := r.getAccountLocked(accountName)
	file := r.getFileLocked(fileID)
	decision := quotaAuthorityDecision{Mode: mode, AccountName: account.Name, ObservationID: observationID, FileGeneration: file.Generation, AccountGeneration: account.Generation, ReservationID: reservationID, ExecutionClaimID: claimID, ReportSuccess: mode != quotaModeNormal}
	if permissionContext.PermitExpiresAt > now.Unix() {
		decision.PermissionExpiresAt = time.Unix(permissionContext.PermitExpiresAt, 0)
	} else if mode == quotaModeNormal {
		decision.PermissionExpiresAt = now.Add(quotaPermissionTTL)
	}
	if mode != quotaModeNormal && (accountGeneration != 0 && accountGeneration != account.Generation || fileGeneration != 0 && fileGeneration != file.Generation) {
		decision.Reason = "stale authorization generation"
		return decision, nil
	}
	if mode == quotaModeNormal && ticket != "" {
		if sample, ok := r.authorizationSamples[quotaAuthorizationKey(ticket)]; ok && sample.QuotaPending {
			decision.Allow = false
			decision.ObservationID = sample.ObservationID
			decision.Reason = "authorization awaiting quota decision"
			decision.RetryAfter = quotaUncertainTTL
			decision.ReportSuccess = false
			return decision, nil
		}
	}
	if mode == quotaModeNormal && file.QuotaPending {
		issuedBeforeQuota := permissionContext.IssuedAt > 0 && !file.QuotaPendingAt.IsZero() && time.Unix(permissionContext.IssuedAt, 0).Before(file.QuotaPendingAt)
		permitLive := permissionContext.PermitExpiresAt > now.Unix()
		if !issuedBeforeQuota || !permitLive {
			decision.Allow = false
			decision.Reason = "quota decision pending"
			decision.RetryAfter = r.quotaPendingRetryAfterLocked(file, now)
			decision.ReportSuccess = false
			return decision, nil
		}
	}
	if operation == "release" {
		if reservationID == "" {
			return quotaAuthorityDecision{}, fmt.Errorf("google_drive: reservation ID is required for release")
		}
		if file.Diagnostic != nil && file.Diagnostic.ID == reservationID {
			if !quotaOpportunityMatches(file.Diagnostic, account, file, mode, observationID) {
				decision.Reason = "stale opportunity"
				return decision, nil
			}
			if file.Diagnostic.Claimed {
				decision.Reason = "opportunity already claimed"
				return decision, nil
			}
			file.Diagnostic = nil
			if err := r.persistLocked(ctx); err != nil {
				r.restoreLocked(backup)
				return quotaAuthorityDecision{}, err
			}
			decision.Allow = true
			decision.Reason = "reservation released"
			return decision, nil
		}
		if file.Probe != nil && file.Probe.ID == reservationID {
			if !quotaOpportunityMatches(file.Probe, account, file, mode, observationID) {
				decision.Reason = "stale opportunity"
				return decision, nil
			}
			if file.Probe.Claimed {
				decision.Reason = "opportunity already claimed"
				return decision, nil
			}
			if account.Probe != nil && account.Probe.ID == reservationID {
				account.Probe = nil
			}
			file.Probe = nil
			if err := r.persistLocked(ctx); err != nil {
				r.restoreLocked(backup)
				return quotaAuthorityDecision{}, err
			}
			decision.Allow = true
			decision.Reason = "reservation released"
			return decision, nil
		}
		if account.Probe != nil && account.Probe.ID == reservationID {
			if !quotaOpportunityMatches(account.Probe, account, file, mode, observationID) {
				decision.Reason = "stale opportunity"
				return decision, nil
			}
			if account.Probe.Claimed {
				decision.Reason = "opportunity already claimed"
				return decision, nil
			}
			if file.Probe != nil && file.Probe.ID == reservationID {
				file.Probe = nil
			}
			account.Probe = nil
			if err := r.persistLocked(ctx); err != nil {
				r.restoreLocked(backup)
				return quotaAuthorityDecision{}, err
			}
			decision.Allow = true
			decision.Reason = "reservation released"
			return decision, nil
		}
		if _, consumed := r.consumed[reservationID]; consumed {
			decision.Reason = "opportunity already claimed or expired"
			return decision, nil
		}
		decision.Allow = true
		decision.Reason = "reservation release already applied"
		return decision, nil
	}
	var opportunity *quotaOpportunity
	if mode == quotaModeDiagnostic {
		opportunity = file.Diagnostic
	} else if mode == quotaModeProbe {
		if file.Probe != nil && file.Probe.ID == reservationID {
			opportunity = file.Probe
		} else if account.Probe != nil && account.Probe.ID == reservationID {
			opportunity = account.Probe
		}
		if opportunity != nil && !quotaOpportunityMatches(opportunity, account, file, mode, observationID) {
			return quotaAuthorityDecision{Reason: "stale opportunity", FileGeneration: file.Generation, AccountGeneration: account.Generation}, nil
		}
	}
	if reason, retryAfter := quotaExecutionBackoffLocked(file, account, now); reason != "" {
		idempotentClaim := opportunity != nil && opportunity.Claimed && claimID != "" && opportunity.ExecutionClaimID == claimID && (operation == "claim" || operation == "check")
		if !idempotentClaim {
			decision.Reason = reason
			decision.RetryAfter = retryAfter
			return decision, nil
		}
	}
	if (mode == quotaModeNormal || opportunity == nil) && file.CooldownUntil.After(now) {
		decision.Reason = "file cooldown"
		decision.RetryAfter = quotaRetryAfter(now, file.CooldownUntil, file.NextProbeAt)
		return decision, nil
	}
	if (mode == quotaModeNormal || opportunity == nil) && account.CooldownUntil.After(now) {
		decision.Reason = "account unavailable"
		decision.RetryAfter = quotaRetryAfter(now, account.CooldownUntil, account.NextProbeAt)
		return decision, nil
	}
	if mode == quotaModeNormal {
		sampleObservationID, reportSuccess, sampleChanged := r.normalPermissionSampleLocked(ticket, account.Name, file.FileID, account.Generation, file.Generation, decision.ObservationID, now)
		decision.ObservationID = sampleObservationID
		decision.ReportSuccess = reportSuccess
		if sampleChanged {
			if err := r.persistLocked(ctx); err != nil {
				r.restoreLocked(backup)
				return quotaAuthorityDecision{}, err
			}
		}
		decision.Allow = true
		return decision, nil
	}
	if opportunity == nil || opportunity.ID != reservationID {
		decision.Reason = "opportunity busy"
		decision.RetryAfter = quotaReservationTTL
		return decision, nil
	}
	if opportunity.Claimed {
		if !opportunity.ClaimExpiresAt.IsZero() && !now.Before(opportunity.ClaimExpiresAt) {
			r.consumed[opportunity.ID] = *opportunity
			if opportunity.Mode == quotaModeDiagnostic && file.CooldownUntil.IsZero() && file.BackoffUntil.Before(now.Add(quotaUncertainTTL)) {
				file.BackoffUntil = now.Add(quotaUncertainTTL)
			}
			if file.Diagnostic != nil && file.Diagnostic.ID == opportunity.ID {
				file.Diagnostic = nil
			}
			if file.Probe != nil && file.Probe.ID == opportunity.ID {
				file.Probe = nil
			}
			if account.Probe != nil && account.Probe.ID == opportunity.ID {
				account.Probe = nil
			}
			if err := r.persistLocked(ctx); err != nil {
				r.restoreLocked(backup)
				return quotaAuthorityDecision{}, err
			}
			decision.Reason = "execution permission expired"
			decision.PermissionExpiresAt = time.Time{}
			return decision, nil
		}
		if (operation == "claim" || operation == "check") && opportunity.ExecutionClaimID == claimID && claimID != "" {
			decision.Allow = true
			decision.ExecutionClaimID = claimID
			decision.PermissionExpiresAt = opportunity.ClaimExpiresAt
			return decision, nil
		}
		decision.Reason = "opportunity already claimed"
		return decision, nil
	}
	if operation != "claim" {
		decision.Allow = true
		return decision, nil
	}
	if claimID == "" {
		return quotaAuthorityDecision{}, fmt.Errorf("google_drive: execution claim ID is required")
	}
	opportunity.Claimed = true
	opportunity.ExecutionClaimID = claimID
	opportunity.ClaimExpiresAt = now.Add(quotaPermissionTTL)
	decision.PermissionExpiresAt = opportunity.ClaimExpiresAt
	if mode == quotaModeDiagnostic && file.DiagnosticUsed < 2 {
		file.DiagnosticUsed++
	}
	if mode == quotaModeProbe {
		if file.Probe != nil && file.Probe.ID == opportunity.ID {
			file.ProbeUsed++
			file.NextProbeAt = now.Add(quotaProbeInterval)
		}
		if account.Probe != nil && account.Probe.ID == opportunity.ID {
			account.ProbeUsed++
			account.NextProbeAt = now.Add(quotaProbeInterval)
		}
	}
	decision.Allow = true
	decision.ExecutionClaimID = claimID
	if err := r.persistLocked(ctx); err != nil {
		r.restoreLocked(backup)
		return quotaAuthorityDecision{}, err
	}
	return decision, nil
}

func quotaObservationFingerprint(input driver.DownloadAuthorizationFeedback) string {
	canonical := struct {
		AuthorityProtocol int    `json:"authority_protocol"`
		Ticket            string `json:"ticket"`
		PermitProof       string `json:"permit_proof"`
		ObservationID     string `json:"observation_id"`
		EventType         string `json:"event_type"`
		Outcome           string `json:"outcome"`
		StatusCode        int    `json:"status_code"`
		Reason            string `json:"reason"`
	}{
		AuthorityProtocol: input.AuthorityProtocol,
		Ticket:            input.Ticket,
		PermitProof: func() string {
			if input.Permit == nil {
				return ""
			}
			return input.Permit.Proof
		}(),
		ObservationID: strings.TrimSpace(input.ObservationID),
		EventType:     strings.ToLower(strings.TrimSpace(input.EventType)),
		Outcome:       strings.ToLower(strings.TrimSpace(input.Outcome)),
		StatusCode:    input.StatusCode,
		Reason:        truncateQuotaUTF8(input.Reason, maxQuotaReason),
	}
	payload, _ := json.Marshal(canonical)
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}

func truncateQuotaUTF8(value string, limit int) string {
	value = strings.TrimSpace(value)
	if len(value) <= limit {
		return value
	}
	value = value[:limit]
	for len(value) > 0 && !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}

func (r *quotaAuthorityRuntime) report(ctx context.Context, input driver.DownloadAuthorizationFeedback) (driver.DownloadAuthorizationReportResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if input.AuthorityProtocol != model.DownloadAuthorityProtocol {
		return driver.DownloadAuthorizationReportResult{}, fmt.Errorf("google_drive: authority_protocol must be %d", model.DownloadAuthorityProtocol)
	}
	if strings.TrimSpace(input.Provider) != googleDriveAccountProvider {
		return driver.DownloadAuthorizationReportResult{}, fmt.Errorf("google_drive: quota report provider is invalid")
	}
	if strings.TrimSpace(input.AccountName) == "" || strings.TrimSpace(input.FileID) == "" || len(strings.TrimSpace(input.AccountName)) > maxQuotaAccountName || len(strings.TrimSpace(input.FileID)) > maxQuotaFileID {
		return driver.DownloadAuthorizationReportResult{}, fmt.Errorf("google_drive: quota report identity is empty")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return driver.DownloadAuthorizationReportResult{}, err
	}
	if err := r.loadLocked(ctx); err != nil {
		return driver.DownloadAuthorizationReportResult{}, err
	}
	backup, err := cloneQuotaAuthoritySnapshot(r.snapshotLocked())
	if err != nil {
		return driver.DownloadAuthorizationReportResult{}, err
	}
	now := r.now()
	if r.expireLocked(now) {
		if err := r.persistLocked(ctx); err != nil {
			r.restoreLocked(backup)
			return driver.DownloadAuthorizationReportResult{}, err
		}
	}
	account := r.getAccountLocked(input.AccountName)
	file := r.getFileLocked(input.FileID)
	eventType := strings.ToLower(strings.TrimSpace(input.EventType))
	if eventType == "" {
		eventType = driver.NormalizeDownloadAuthorizationEventType(input.EventType, input.Outcome, input.StatusCode, input.Reason)
	}
	input.Outcome = strings.ToLower(strings.TrimSpace(input.Outcome))
	if input.StatusCode < 0 || input.StatusCode > 599 {
		return driver.DownloadAuthorizationReportResult{}, fmt.Errorf("google_drive: quota report status code is invalid")
	}
	if err := driver.ValidateDownloadAuthorizationFeedback(eventType, input.Outcome, input.StatusCode, input.Reason); err != nil {
		return driver.DownloadAuthorizationReportResult{}, fmt.Errorf("google_drive: quota report is invalid: %w", err)
	}
	if len(input.Reason) > maxQuotaReason || len(input.ObservationID) > maxQuotaEventID {
		return driver.DownloadAuthorizationReportResult{}, fmt.Errorf("google_drive: quota report field is too long")
	}
	observationID := strings.TrimSpace(input.ObservationID)
	if observationID == "" {
		observationID = r.newID("observation")
	}
	eventID := driver.CanonicalDownloadAuthorizationEventID(observationID, eventType)
	if input.EventID != "" && input.EventID != eventID {
		return driver.DownloadAuthorizationReportResult{}, fmt.Errorf("google_drive: event ID does not match observation")
	}
	if input.Generation == 0 {
		return driver.DownloadAuthorizationReportResult{}, fmt.Errorf("google_drive: account generation must be nonzero")
	}
	if input.FileGeneration == 0 {
		return driver.DownloadAuthorizationReportResult{}, fmt.Errorf("google_drive: file generation must be nonzero")
	}
	input.AuthorityProtocol = model.DownloadAuthorityProtocol
	input.EventID = eventID
	input.ObservationID = observationID
	input.EventType = eventType
	fingerprint := quotaObservationFingerprint(input)
	if receipt, ok := r.receipts[eventID]; ok {
		if receipt.Fingerprint != fingerprint {
			return driver.DownloadAuthorizationReportResult{}, &driver.DownloadAuthorizationConflictError{EventID: eventID, Reason: "google_drive: conflicting reuse of event ID"}
		}
		return driver.DownloadAuthorizationReportResult{AuthorityProtocol: model.DownloadAuthorityProtocol, Duplicate: true, Generation: account.Generation, CooldownUntil: file.CooldownUntil, RetryAfter: quotaRetryAfter(now, file.CooldownUntil, file.BackoffUntil)}, nil
	}
	var wasDiagnostic, wasFileProbe, wasAccountProbe bool
	if input.TrialID != "" {
		var opportunity *quotaOpportunity
		if file.Diagnostic != nil && file.Diagnostic.ID == input.TrialID {
			opportunity = file.Diagnostic
		} else if file.Probe != nil && file.Probe.ID == input.TrialID {
			opportunity = file.Probe
		} else if account.Probe != nil && account.Probe.ID == input.TrialID {
			opportunity = account.Probe
		} else if consumed, ok := r.consumed[input.TrialID]; ok {
			opportunity = &consumed
		}
		if opportunity == nil || !opportunity.Claimed {
			return driver.DownloadAuthorizationReportResult{}, fmt.Errorf("google_drive: execution claim is required before reporting")
		}
		if opportunity.ExecutionClaimID == "" || opportunity.ExecutionClaimID != input.ExecutionClaimID {
			return driver.DownloadAuthorizationReportResult{}, fmt.Errorf("google_drive: execution claim identity is invalid")
		}
		// The link API authenticates reports during the bounded delivery grace
		// after ClaimExpiresAt. The retained claim identity still fences the
		// report; expiry alone does not discard a valid completed execution.
		wasDiagnostic = opportunity.Mode == quotaModeDiagnostic && opportunity.Scope == quotaScopeDiagnostic
		wasFileProbe = opportunity.Mode == quotaModeProbe && (opportunity.Scope == quotaScopeFile || opportunity.Scope == quotaScopeFileAccount)
		wasAccountProbe = opportunity.Mode == quotaModeProbe && (opportunity.Scope == quotaScopeAccount || opportunity.Scope == quotaScopeFileAccount)
	}
	if input.Generation != account.Generation || input.FileGeneration != file.Generation {
		r.receipts[eventID] = quotaEventReceipt{Fingerprint: fingerprint, At: now}
		if err := r.persistLocked(ctx); err != nil {
			r.restoreLocked(backup)
			return driver.DownloadAuthorizationReportResult{}, err
		}
		return driver.DownloadAuthorizationReportResult{AuthorityProtocol: model.DownloadAuthorityProtocol, Stale: true, Generation: account.Generation, CooldownUntil: file.CooldownUntil, RetryAfter: quotaRetryAfter(now, file.CooldownUntil, file.BackoffUntil)}, nil
	}
	if eventType == "quota" && !isGoogleDriveQuotaFeedback(input.Provider, input.StatusCode, input.Reason) {
		return driver.DownloadAuthorizationReportResult{}, fmt.Errorf("google_drive: quota report does not match a qualifying Google response")
	}
	if eventType == "quota" && !file.QuotaPending {
		file.QuotaPending = true
		file.QuotaPendingAt = now
	}
	observation := quotaObservation{EventID: eventID, ObservationID: observationID, EventType: eventType, Provider: googleDriveAccountProvider, AccountName: strings.TrimSpace(input.AccountName), FileID: strings.TrimSpace(input.FileID), Outcome: input.Outcome, StatusCode: input.StatusCode, Reason: normalizedQuotaReason(input.Reason), AccountGeneration: input.Generation, FileGeneration: input.FileGeneration, TrialID: input.TrialID, ExecutionClaimID: input.ExecutionClaimID, At: now}
	r.observations[eventID] = observation
	r.receipts[eventID] = quotaEventReceipt{Fingerprint: quotaObservationFingerprint(input), At: now}
	// Only an eligible success acknowledges the current requested observation.
	// Neutral failures and quota suspensions keep the success request pending.
	if eventType == quotaOutcomeSuccess {
		r.acknowledgeNormalSampleLocked(input, observationID, now)
	}
	if eventType == "quota" && input.TrialID == "" && strings.TrimSpace(input.Ticket) != "" {
		key := quotaAuthorizationKey(input.Ticket)
		if sample, ok := r.authorizationSamples[key]; ok && sample.ObservationID == observationID {
			sample.QuotaPending = true
			r.authorizationSamples[key] = sample
		}
	}
	if input.TrialID != "" {
		if file.Diagnostic != nil && file.Diagnostic.ID == input.TrialID {
			file.Diagnostic = nil
		}
		if file.Probe != nil && file.Probe.ID == input.TrialID {
			file.Probe = nil
		}
		if account.Probe != nil && account.Probe.ID == input.TrialID {
			account.Probe = nil
		}
		if wasDiagnostic || wasFileProbe {
			file.QuotaPending = false
			file.QuotaPendingAt = time.Time{}
			r.clearResolvedQuotaPendingSamplesLocked(file.FileID, now)
		}
		if eventType != "success" {
			if wasDiagnostic && file.CooldownUntil.IsZero() {
				file.BackoffUntil = now.Add(quotaUncertainTTL)
			}
			if wasFileProbe && file.CooldownUntil.IsZero() && file.ProbeRequired {
				file.BackoffUntil = now.Add(quotaUncertainTTL)
			}
			if wasAccountProbe && account.CooldownUntil.IsZero() && account.ProbeRequired {
				account.BackoffUntil = now.Add(quotaUncertainTTL)
			}
		}
	}
	if input.Outcome == string(quotaOutcomeSuccess) || eventType == "success" {
		if input.TrialID == "" {
			r.clearResolvedQuotaPendingSamplesLocked(file.FileID, now)
		}
		// Only the probe that owned this execution can recover its target.
		if input.TrialID != "" && eventType == "success" {
			if wasFileProbe {
				file.ProbeRequired = false
				file.ProbeUsed = 0
				file.NextProbeAt = time.Time{}
				file.BackoffUntil = time.Time{}
				if file.CooldownUntil.After(now) {
					file.CooldownUntil = time.Time{}
					file.Generation++
				}
			}
			if wasAccountProbe {
				account.ProbeRequired = false
				account.ProbeUsed = 0
				account.NextProbeAt = time.Time{}
				account.BackoffUntil = time.Time{}
				if account.CooldownUntil.After(now) {
					account.CooldownUntil = time.Time{}
					account.Generation++
				}
				if file.CooldownUntil.IsZero() {
					file.QuotaPending = false
					file.QuotaPendingAt = time.Time{}
					r.clearResolvedQuotaPendingSamplesLocked(file.FileID, now)
				}
			}
			if wasDiagnostic {
				file.QuotaPending = false
				file.QuotaPendingAt = time.Time{}
			}
		}
	}
	if eventType == "quota" || eventType == "success" {
		r.evaluateLocked(now)
		r.retireUnclaimedStaleOpportunitiesLocked()
		if !file.CooldownUntil.IsZero() {
			file.QuotaPending = false
			file.QuotaPendingAt = time.Time{}
		}
		if eventType == "quota" && input.TrialID == "" && file.DiagnosticUsed == 0 {
			file.DiagnosticUsed = 1
		}
		if eventType == "quota" && input.TrialID != "" && file.CooldownUntil.IsZero() && file.Diagnostic == nil {
			file.BackoffUntil = now.Add(quotaUncertainTTL)
		}
	}
	if err := r.persistLocked(ctx); err != nil {
		r.restoreLocked(backup)
		return driver.DownloadAuthorizationReportResult{}, err
	}
	return driver.DownloadAuthorizationReportResult{AuthorityProtocol: model.DownloadAuthorityProtocol, Applied: true, Generation: account.Generation, CooldownUntil: file.CooldownUntil, RetryAfter: quotaRetryAfter(now, file.CooldownUntil, file.BackoffUntil)}, nil
}

func normalizedQuotaReason(reason string) string {
	lower := strings.ToLower(reason)
	for _, keyword := range []string{"quota", "exceed", "limit"} {
		if strings.Contains(lower, keyword) {
			return keyword
		}
	}
	return ""
}

func (r *quotaAuthorityRuntime) evaluateLocked(now time.Time) {
	cutoff := now.Add(-quotaEvidenceTTL)
	quotas := make(map[string]map[string]quotaObservation)
	successes := make(map[string]map[string][]quotaObservation)
	for _, observation := range r.observations {
		if !observation.At.After(cutoff) {
			continue
		}
		if account := r.accounts[quotaAccountKey(observation.AccountName)]; account != nil && account.CooldownUntil.After(now) {
			continue
		}
		if file := r.files[quotaFileKey(observation.FileID)]; file != nil && file.CooldownUntil.After(observation.At) {
			continue
		}
		switch observation.EventType {
		case "quota":
			if quotas[observation.FileID] == nil {
				quotas[observation.FileID] = make(map[string]quotaObservation)
			}
			if current, ok := quotas[observation.FileID][observation.AccountName]; !ok || observation.At.After(current.At) {
				quotas[observation.FileID][observation.AccountName] = observation
			}
		case "success":
			if successes[observation.AccountName] == nil {
				successes[observation.AccountName] = make(map[string][]quotaObservation)
			}
			successes[observation.AccountName][observation.FileID] = append(successes[observation.AccountName][observation.FileID], observation)
		}
	}
	for _, account := range r.accounts {
		if account.Evidence == nil {
			account.Evidence = make(map[string]quotaPairEvidence)
		}
		for fileID, byAccount := range quotas {
			quota, ok := byAccount[account.Name]
			if !ok {
				continue
			}
			controlAt, ok := latestOtherAccountSuccess(successes, account.Name, fileID, quota.At)
			if ok {
				account.Evidence[fileID] = quotaPairEvidence{QuotaAt: quota.At, ControlAt: controlAt}
			}
		}
	}
	for fileID, byAccount := range quotas {
		file := r.getFileLocked(fileID)
		if file.CooldownUntil.After(now) {
			continue
		}
		eligible := 0
		controlled := false
		for accountName, quota := range byAccount {
			if _, ok := successes[accountName]; !ok || !hasOtherFileSuccess(successes[accountName], fileID, cutoff) {
				continue
			}
			eligible++
			if successAtOrAfterByOtherAccount(successes, accountName, fileID, quota.At) {
				controlled = true
			}
		}
		if eligible >= 2 && !controlled {
			file.CooldownUntil = now.Add(quotaCooldownTTL)
			file.NextProbeAt = now.Add(quotaProbeInterval)
			file.ProbeUsed = 0
			file.ProbeRequired = false
			file.Diagnostic = nil
			file.Generation++
			for _, account := range r.accounts {
				delete(account.Evidence, fileID)
			}
		}
	}
	for _, account := range r.accounts {
		if account.CooldownUntil.After(now) {
			continue
		}
		paired := 0
		for _, evidence := range account.Evidence {
			if evidence.QuotaAt.After(cutoff) && evidence.ControlAt.After(cutoff) && !evidence.ControlAt.Before(evidence.QuotaAt) {
				paired++
			}
		}
		if paired >= 3 {
			account.CooldownUntil = now.Add(quotaCooldownTTL)
			account.NextProbeAt = now.Add(quotaProbeInterval)
			account.ProbeUsed = 0
			account.ProbeRequired = false
			account.Generation++
		}
	}
}

// retireUnclaimedStaleOpportunitiesLocked drops unclaimed opportunities whose
// stored generation no longer matches the current account or file generation.
func (r *quotaAuthorityRuntime) retireUnclaimedStaleOpportunitiesLocked() {
	for _, file := range r.files {
		if file.Diagnostic != nil && !file.Diagnostic.Claimed {
			account := r.accounts[quotaAccountKey(file.Diagnostic.AccountName)]
			if !quotaOpportunityMatches(file.Diagnostic, account, file, quotaModeDiagnostic, file.Diagnostic.ObservationID) {
				file.Diagnostic = nil
			}
		}
		if file.Probe != nil && !file.Probe.Claimed {
			account := r.accounts[quotaAccountKey(file.Probe.AccountName)]
			if !quotaOpportunityMatches(file.Probe, account, file, quotaModeProbe, file.Probe.ObservationID) {
				file.Probe = nil
			}
		}
	}
	for _, account := range r.accounts {
		if account.Probe != nil && !account.Probe.Claimed {
			file := r.files[quotaFileKey(account.Probe.FileID)]
			if !quotaOpportunityMatches(account.Probe, account, file, quotaModeProbe, account.Probe.ObservationID) {
				account.Probe = nil
			}
		}
	}
}

func latestOtherAccountSuccess(successes map[string]map[string][]quotaObservation, accountName, fileID string, quotaAt time.Time) (time.Time, bool) {
	var latest time.Time
	for otherName, byFile := range successes {
		if otherName == accountName {
			continue
		}
		for _, success := range byFile[fileID] {
			if success.At.Before(quotaAt) || success.At.Before(latest) {
				continue
			}
			latest = success.At
		}
	}
	return latest, !latest.IsZero()
}

func successAtOrAfterByOtherAccount(successes map[string]map[string][]quotaObservation, accountName, fileID string, quotaAt time.Time) bool {
	_, ok := latestOtherAccountSuccess(successes, accountName, fileID, quotaAt)
	return ok
}

func hasOtherFileSuccess(byFile map[string][]quotaObservation, fileID string, cutoff time.Time) bool {
	for otherFileID, observations := range byFile {
		if otherFileID == fileID {
			continue
		}
		for _, observation := range observations {
			if observation.At.After(cutoff) {
				return true
			}
		}
	}
	return false
}

func (r *quotaAuthorityRuntime) resetForTests() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.accounts = make(map[string]*quotaAccountState)
	r.files = make(map[string]*quotaFileState)
	r.observations = make(map[string]quotaObservation)
	r.receipts = make(map[string]quotaEventReceipt)
	r.consumed = make(map[string]quotaOpportunity)
	r.loaded = false
	r.database = nil
	if r.durable {
		if database := db.GetDb(); database != nil {
			_ = database.Where("key = ?", quotaAuthorityStateKey).Delete(&model.GoogleDriveQuotaAuthority{}).Error
		}
	}
}

func (r *quotaAuthorityRuntime) getFileState(ctx context.Context, fileID string) (quotaFileState, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.loadLocked(ctx); err != nil {
		return quotaFileState{}, err
	}
	file := r.getFileLocked(fileID)
	clone, err := cloneQuotaAuthoritySnapshot(quotaAuthoritySnapshot{Files: map[string]*quotaFileState{file.Key: file}})
	if err != nil {
		return quotaFileState{}, err
	}
	return *clone.Files[file.Key], nil
}

func resetGoogleDriveQuotaAuthorityForTests() {
	sharedQuotaAuthority.resetForTests()
}

func getGoogleDriveQuotaFileState(ctx context.Context, fileID string) (cooldownUntil time.Time, generation uint64, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	sharedQuotaAuthority.mu.Lock()
	defer sharedQuotaAuthority.mu.Unlock()
	if err := sharedQuotaAuthority.loadLocked(ctx); err != nil {
		return time.Time{}, 0, err
	}
	file := sharedQuotaAuthority.getFileLocked(fileID)
	return file.CooldownUntil, file.Generation, nil
}

func sortedQuotaAccountNames(accounts []accountRuntime) []string {
	names := make([]string, 0, len(accounts))
	for _, account := range accounts {
		if name := strings.TrimSpace(account.Name); name != "" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

func (d *GoogleDrive) quotaAccountCandidates() []string {
	d.accountStateMu.RLock()
	accounts := append([]accountRuntime(nil), d.accounts...)
	d.accountStateMu.RUnlock()
	if len(accounts) != 0 {
		return sortedQuotaAccountNames(accounts)
	}
	return []string{"singleton:" + strings.TrimSpace(d.GetStorage().MountPath)}
}

func (d *GoogleDrive) quotaAccountIndex(name string) (int, bool) {
	d.accountStateMu.RLock()
	defer d.accountStateMu.RUnlock()
	for index, account := range d.accounts {
		if strings.TrimSpace(account.Name) == strings.TrimSpace(name) {
			return index, true
		}
	}
	return -1, false
}

func (d *GoogleDrive) preferredQuotaAccountOrder(ctx context.Context, fileID string, order []int) ([]int, error) {
	type candidate struct {
		index int
		name  string
	}
	refs := make([]candidate, 0, len(order))
	for _, index := range order {
		account, err := d.accountSnapshot(index)
		if err != nil {
			return nil, err
		}
		refs = append(refs, candidate{index: index, name: strings.TrimSpace(account.Name)})
	}
	names := make([]string, 0, len(refs))
	for _, ref := range refs {
		names = append(names, ref.name)
	}
	preferred, err := sharedQuotaAuthority.preferProbeCandidates(ctx, fileID, names)
	if err != nil {
		return nil, err
	}
	result := make([]int, 0, len(refs))
	used := make([]bool, len(refs))
	for _, name := range preferred {
		for index, ref := range refs {
			if !used[index] && ref.name == name {
				used[index] = true
				result = append(result, ref.index)
				break
			}
		}
	}
	for index, ref := range refs {
		if !used[index] {
			result = append(result, ref.index)
		}
	}
	return result, nil
}

func (d *GoogleDrive) acquireQuotaAuthorityAuthorization(ctx context.Context, request driver.DownloadAuthorizationRequest) (driver.DownloadAuthorizationResult, error) {
	fileID := strings.TrimSpace(request.FileID)
	if fileID == "" {
		return driver.DownloadAuthorizationResult{}, fmt.Errorf("google_drive: download file ID is required")
	}
	if request.Feedback != nil {
		d.invalidateJSONCredential(*request.Feedback)
		d.invalidateSingletonCredential(*request.Feedback)
	}
	var (
		decision quotaAuthorityDecision
		err      error
		selected accountSnapshot
	)
	if request.Feedback != nil && driver.NormalizeDownloadAuthorizationEventType(request.Feedback.EventType, request.Feedback.Outcome, request.Feedback.StatusCode, request.Feedback.Reason) == "quota" && isGoogleDriveQuotaFeedback(request.Feedback.Provider, request.Feedback.StatusCode, request.Feedback.Reason) {
		candidates := d.quotaAccountCandidates()
		decision, err = sharedQuotaAuthority.reportAndNext(ctx, *request.Feedback, candidates)
		if err != nil {
			return driver.DownloadAuthorizationResult{}, err
		}
		if !decision.Allow {
			return driver.DownloadAuthorizationResult{}, &driver.DownloadAuthorizationUnavailableError{Reason: "google_drive: " + decision.Reason, RetryAfter: decision.RetryAfter}
		}
		selectedIndex, ok := d.quotaAccountIndex(decision.AccountName)
		if !ok {
			return driver.DownloadAuthorizationResult{}, &driver.DownloadAuthorizationUnavailableError{Reason: "google_drive: authority-selected account is unavailable", RetryAfter: time.Second}
		}
		selected, err = d.accountSnapshot(selectedIndex)
		if err != nil {
			return driver.DownloadAuthorizationResult{}, err
		}
		selected, err = d.ensureUsableDownloadAccount(ctx, selectedIndex, selected)
		if err != nil {
			return driver.DownloadAuthorizationResult{}, err
		}
	} else if request.Feedback == nil && strings.EqualFold(strings.TrimSpace(request.Operation), "next_plan") {
		candidates := d.quotaAccountCandidates()
		decision, err = sharedQuotaAuthority.nextDiagnostic(ctx, fileID, request.OriginalAccountName, candidates)
		if err != nil {
			return driver.DownloadAuthorizationResult{}, err
		}
		if !decision.Allow {
			return driver.DownloadAuthorizationResult{}, &driver.DownloadAuthorizationUnavailableError{Reason: "google_drive: " + decision.Reason, RetryAfter: decision.RetryAfter}
		}
		selectedIndex, ok := d.quotaAccountIndex(decision.AccountName)
		if !ok {
			return driver.DownloadAuthorizationResult{}, &driver.DownloadAuthorizationUnavailableError{Reason: "google_drive: authority-selected account is unavailable", RetryAfter: time.Second}
		}
		selected, err = d.accountSnapshot(selectedIndex)
		if err != nil {
			return driver.DownloadAuthorizationResult{}, err
		}
		selected, err = d.ensureUsableDownloadAccount(ctx, selectedIndex, selected)
		if err != nil {
			return driver.DownloadAuthorizationResult{}, err
		}
	} else if request.Feedback != nil {
		// Ordinary transport/authentication outcomes keep the original account;
		// they never trigger quota-driven rotation. The authority still records
		// the terminal observation so requested samples and probes can close.
		feedbackResult, feedbackErr := sharedQuotaAuthority.report(ctx, *request.Feedback)
		if feedbackErr != nil {
			return driver.DownloadAuthorizationResult{}, feedbackErr
		}
		if feedbackResult.Stale && request.Feedback.TrialID != "" {
			return driver.DownloadAuthorizationResult{}, &driver.DownloadAuthorizationUnavailableError{Reason: "google_drive: stale execution observation", RetryAfter: feedbackResult.RetryAfter}
		}
		name := strings.TrimSpace(request.Feedback.AccountName)
		selectedIndex := -1
		if name != "" {
			selectedIndex, _ = d.quotaAccountIndex(name)
		}
		if selectedIndex < 0 {
			if !strings.HasPrefix(name, "singleton:") {
				return driver.DownloadAuthorizationResult{}, &driver.DownloadAuthorizationUnavailableError{Reason: "google_drive: original authorization account is unavailable", RetryAfter: time.Second}
			}
			selected, err = d.ensureUsableSingletonAccount(ctx)
			if err != nil {
				return driver.DownloadAuthorizationResult{}, err
			}
			selected.Name = name
		} else {
			selected, err = d.accountSnapshot(selectedIndex)
			if err != nil {
				return driver.DownloadAuthorizationResult{}, err
			}
			selected, err = d.ensureUsableDownloadAccount(ctx, selectedIndex, selected)
			if err != nil {
				return driver.DownloadAuthorizationResult{}, err
			}
		}
		decision, err = sharedQuotaAuthority.authorize(ctx, selected.Name, fileID)
		if err != nil {
			return driver.DownloadAuthorizationResult{}, err
		}
	} else {
		d.accountStateMu.RLock()
		accountCount := len(d.accounts)
		d.accountStateMu.RUnlock()
		if accountCount == 0 {
			name := "singleton:" + strings.TrimSpace(d.GetStorage().MountPath)
			selected, err = d.ensureUsableSingletonAccount(ctx)
			if err != nil {
				return driver.DownloadAuthorizationResult{}, err
			}
			selected.Name = name
			decision, err = sharedQuotaAuthority.authorize(ctx, name, fileID)
			if err != nil {
				return driver.DownloadAuthorizationResult{}, err
			}
		} else {
			d.accountStateMu.Lock()
			if d.accountPool == nil {
				d.accountPool = newAccountPool(d.modeCfg.SelectionPolicy, d.accounts)
			}
			pool := d.accountPool
			accountCount := len(d.accounts)
			d.accountStateMu.Unlock()
			order := pool.nextDownloadAttemptOrder(accountCount)
			order, err = d.preferredQuotaAccountOrder(ctx, fileID, order)
			if err != nil {
				return driver.DownloadAuthorizationResult{}, err
			}
			for _, candidateIndex := range order {
				candidate, candidateErr := d.accountSnapshot(candidateIndex)
				if candidateErr != nil {
					err = candidateErr
					continue
				}
				if request.OriginalAccountName != "" && strings.TrimSpace(candidate.Name) == strings.TrimSpace(request.OriginalAccountName) {
					continue
				}
				candidate, candidateErr = d.ensureUsableDownloadAccount(ctx, candidateIndex, candidate)
				if candidateErr != nil {
					err = candidateErr
					continue
				}
				candidateDecision, candidateErr := sharedQuotaAuthority.authorize(ctx, candidate.Name, fileID)
				if candidateErr != nil {
					err = candidateErr
					continue
				}
				if !candidateDecision.Allow {
					if candidateDecision.RetryAfter > 0 && (decision.RetryAfter == 0 || candidateDecision.RetryAfter < decision.RetryAfter) {
						decision.RetryAfter = candidateDecision.RetryAfter
					}
					decision.Reason = candidateDecision.Reason
					continue
				}
				selected, decision = candidate, candidateDecision
				break
			}
			if selected.Name == "" {
				if decision.RetryAfter > 0 {
					return driver.DownloadAuthorizationResult{}, &driver.DownloadAuthorizationUnavailableError{Reason: "google_drive: no eligible download account: " + decision.Reason, RetryAfter: decision.RetryAfter}
				}
				if err != nil {
					return driver.DownloadAuthorizationResult{}, &driver.DownloadAuthorizationUnavailableError{Reason: "google_drive: no usable Google Drive download account: " + err.Error(), RetryAfter: time.Second}
				}
				return driver.DownloadAuthorizationResult{}, &driver.DownloadAuthorizationUnavailableError{Reason: "google_drive: no usable Google Drive download account", RetryAfter: time.Second}
			}
		}
	}
	if !decision.Allow {
		return driver.DownloadAuthorizationResult{}, &driver.DownloadAuthorizationUnavailableError{Reason: "google_drive: " + decision.Reason, RetryAfter: decision.RetryAfter}
	}
	result := googleDownloadAuthorizationResult(request, selected)
	result.AuthorityProtocol = model.DownloadAuthorityProtocol
	result.Mode = string(decision.Mode)
	if result.Mode == "" {
		result.Mode = string(quotaModeNormal)
	}
	result.ObservationID = decision.ObservationID
	result.ReservationID = decision.ReservationID
	result.ExecutionClaimID = decision.ExecutionClaimID
	if result.Mode != string(quotaModeNormal) {
		result.TrialID = decision.ReservationID
	}
	result.Generation = decision.AccountGeneration
	result.FileGeneration = decision.FileGeneration
	result.ReportSuccess = decision.ReportSuccess
	result.Allow = true
	result.CredentialExpiresAt = result.ExpiresAt
	return result, nil
}

func (r *quotaAuthorityRuntime) reportAndNext(ctx context.Context, input driver.DownloadAuthorizationFeedback, candidates []string) (quotaAuthorityDecision, error) {
	result, err := r.report(ctx, input)
	if err != nil {
		return quotaAuthorityDecision{}, err
	}
	if result.Stale {
		return quotaAuthorityDecision{Reason: "stale authorization", RetryAfter: result.RetryAfter}, nil
	}
	if result.Duplicate {
		r.mu.Lock()
		if err := r.loadLocked(ctx); err != nil {
			r.mu.Unlock()
			return quotaAuthorityDecision{}, err
		}
		file := r.getFileLocked(input.FileID)
		if file.Diagnostic == nil {
			r.mu.Unlock()
			return quotaAuthorityDecision{Reason: "observation already handled", FileGeneration: file.Generation}, nil
		}
		r.mu.Unlock()
	}
	return r.nextDiagnostic(ctx, input.FileID, input.AccountName, candidates)
}

func (d *GoogleDrive) CheckDownloadPermission(ctx context.Context, request driver.DownloadPermissionRequest) (driver.DownloadPermissionResult, error) {
	if request.AuthorityProtocol != model.DownloadAuthorityProtocol {
		return driver.DownloadPermissionResult{}, fmt.Errorf("google_drive: authority_protocol must be %d", model.DownloadAuthorityProtocol)
	}
	if request.Provider != googleDriveAccountProvider || strings.TrimSpace(request.AccountName) == "" || strings.TrimSpace(request.FileID) == "" {
		return driver.DownloadPermissionResult{}, fmt.Errorf("google_drive: permission identity is invalid")
	}
	if request.CredentialGeneration != 0 {
		if index, ok := d.quotaAccountIndex(request.AccountName); ok {
			account, err := d.accountSnapshot(index)
			if err != nil {
				return driver.DownloadPermissionResult{}, err
			}
			if account.CredentialGeneration != request.CredentialGeneration {
				return driver.DownloadPermissionResult{
					AuthorityProtocol: model.DownloadAuthorityProtocol,
					Allow:             false,
					Reason:            "authorization expired",
					AccountName:       request.AccountName,
					AccountGeneration: request.Generation,
					FileGeneration:    request.FileGeneration,
					Mode:              request.Mode,
					ObservationID:     request.ObservationID,
					ReservationID:     request.ReservationID,
				}, nil
			}
		} else if strings.HasPrefix(request.AccountName, "singleton:") {
			d.accountStateMu.RLock()
			currentGeneration := max(d.singleCredentialGeneration, 1)
			d.accountStateMu.RUnlock()
			if currentGeneration != request.CredentialGeneration {
				return driver.DownloadPermissionResult{
					AuthorityProtocol: model.DownloadAuthorityProtocol,
					Allow:             false,
					Reason:            "authorization expired",
					AccountName:       request.AccountName,
					AccountGeneration: request.Generation,
					FileGeneration:    request.FileGeneration,
					Mode:              request.Mode,
					ObservationID:     request.ObservationID,
					ReservationID:     request.ReservationID,
				}, nil
			}
		} else {
			return driver.DownloadPermissionResult{
				AuthorityProtocol: model.DownloadAuthorityProtocol,
				Allow:             false,
				Reason:            "authorization account is unavailable",
				AccountName:       request.AccountName,
				FileGeneration:    request.FileGeneration,
				AccountGeneration: request.Generation,
			}, nil
		}
	}
	mode := quotaAuthorityMode(strings.ToLower(strings.TrimSpace(request.Mode)))
	if mode == "" {
		mode = quotaModeNormal
	}
	decision, err := sharedQuotaAuthority.permission(ctx, request.AccountName, request.FileID, request.Generation, request.FileGeneration, mode, request.ObservationID, request.ReservationID, strings.ToLower(strings.TrimSpace(request.Operation)), request.ExecutionClaimID, quotaPermissionContext{Ticket: request.Ticket, IssuedAt: request.IssuedAt, PermitExpiresAt: request.PermitExpiresAt})
	if err != nil {
		return driver.DownloadPermissionResult{}, err
	}
	return driver.DownloadPermissionResult{
		AuthorityProtocol: model.DownloadAuthorityProtocol,
		Allow:             decision.Allow,
		Reason:            decision.Reason,
		RetryAfter:        decision.RetryAfter,
		FileGeneration:    decision.FileGeneration,
		AccountGeneration: decision.AccountGeneration,
		AccountName:       request.AccountName,
		Mode:              string(decision.Mode),
		ObservationID:     decision.ObservationID,
		ReservationID:     decision.ReservationID,
		ExecutionClaimID:  decision.ExecutionClaimID,
		ReportSuccess:     decision.ReportSuccess,
		ExpiresAt:         decision.PermissionExpiresAt,
	}, nil
}

func (d *GoogleDrive) reportQuotaAuthority(ctx context.Context, report driver.DownloadAuthorizationReport) (driver.DownloadAuthorizationReportResult, error) {
	if report.AuthorityProtocol != model.DownloadAuthorityProtocol {
		return driver.DownloadAuthorizationReportResult{}, fmt.Errorf("google_drive: authority_protocol must be %d", model.DownloadAuthorityProtocol)
	}
	if _, ok := d.quotaAccountIndex(report.AccountName); !ok && !strings.HasPrefix(strings.TrimSpace(report.AccountName), "singleton:") {
		return driver.DownloadAuthorizationReportResult{AuthorityProtocol: model.DownloadAuthorityProtocol, Stale: true}, nil
	}
	d.invalidateJSONCredential(report)
	d.invalidateSingletonCredential(report)
	if report.CredentialGeneration != 0 {
		if index, ok := d.quotaAccountIndex(report.AccountName); ok {
			account, err := d.accountSnapshot(index)
			if err != nil {
				return driver.DownloadAuthorizationReportResult{}, err
			}
			if account.CredentialGeneration != 0 && account.CredentialGeneration != report.CredentialGeneration {
				return driver.DownloadAuthorizationReportResult{AuthorityProtocol: model.DownloadAuthorityProtocol, Stale: true}, nil
			}
		} else if strings.HasPrefix(strings.TrimSpace(report.AccountName), "singleton:") {
			d.accountStateMu.RLock()
			currentGeneration := max(d.singleCredentialGeneration, 1)
			d.accountStateMu.RUnlock()
			if currentGeneration != report.CredentialGeneration {
				return driver.DownloadAuthorizationReportResult{AuthorityProtocol: model.DownloadAuthorityProtocol, Stale: true}, nil
			}
		} else {
			return driver.DownloadAuthorizationReportResult{AuthorityProtocol: model.DownloadAuthorityProtocol, Stale: true}, nil
		}
	}
	if report.EventType == "" {
		if strings.EqualFold(report.Outcome, string(quotaOutcomeSuccess)) {
			report.EventType = "success"
		} else if strings.EqualFold(report.Outcome, string(quotaOutcomeAbandoned)) {
			report.EventType = "abandoned"
		}
		if report.EventType == "" {
			report.EventType = driver.NormalizeDownloadAuthorizationEventType(report.EventType, report.Outcome, report.StatusCode, report.Reason)
		}
	}
	if report.EventID == "" && report.ObservationID != "" {
		report.EventID = driver.CanonicalDownloadAuthorizationEventID(report.ObservationID, report.EventType)
	}
	result, err := sharedQuotaAuthority.report(ctx, report)
	if err != nil {
		return driver.DownloadAuthorizationReportResult{}, err
	}
	return result, nil
}
