package driver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/OpenListTeam/OpenList/v4/internal/model"
)

// DownloadAuthorizationRequest carries the already-resolved file identity to
// a driver that can issue a download URL without performing a content probe.
type DownloadAuthorizationRequest struct {
	AuthorityProtocol   int
	MountPath           string
	LeafPath            string
	FileID              string
	File                model.Obj
	LinkArgs            model.LinkArgs
	Feedback            *DownloadAuthorizationFeedback
	Ticket              string
	Operation           string
	ExecutionClaimID    string
	OriginalAccountName string
}

// DownloadAuthorizationFeedback is a verified terminal result for a prior
// authorization. The link API has already checked its signed identity.
type DownloadAuthorizationFeedback struct {
	AuthorityProtocol    int
	Ticket               string
	Provider             string
	MountPath            string
	LeafPath             string
	FileID               string
	AccountName          string
	Generation           uint64
	FileGeneration       uint64
	TrialID              string
	ExecutionClaimID     string
	CredentialGeneration uint64
	Permit               *model.DownloadExecutionPermission
	ObservationID        string
	EventType            string
	EventID              string
	Outcome              string
	StatusCode           int
	Reason               string
}

// DownloadAuthorizationResult is the driver's usable link plus the identity
// that the link API signs into its download envelope.
type DownloadAuthorizationResult struct {
	AuthorityProtocol    int
	Link                 *model.Link
	Provider             string
	MountPath            string
	LeafPath             string
	FileID               string
	AccountName          string
	Generation           uint64
	FileGeneration       uint64
	TrialID              string
	CredentialGeneration uint64
	ReportSuccess        bool
	ExpiresAt            time.Time
	CredentialExpiresAt  time.Time
	Mode                 string
	ObservationID        string
	ReservationID        string
	ExecutionClaimID     string
	Allow                bool
	Reason               string
	RetryAfter           time.Duration
}

// DownloadAuthorizationReport is an alias because acquire feedback and
// report-only input have the same verified identity and terminal fields.
type DownloadAuthorizationReport = DownloadAuthorizationFeedback

// DownloadAuthorizationReportResult describes the durable result of a
// report. RetryAfter is advisory and is expressed as a duration.
type DownloadAuthorizationReportResult struct {
	AuthorityProtocol int
	Applied           bool
	Duplicate         bool
	Stale             bool
	Generation        uint64
	CooldownUntil     time.Time
	RetryAfter        time.Duration
	Reason            string
}

// DownloadPermissionRequest asks the authority to check, claim, or release
// the permission associated with an already issued authorization.
type DownloadPermissionRequest struct {
	AuthorityProtocol    int
	MountPath            string
	LeafPath             string
	FileID               string
	Provider             string
	AccountName          string
	Generation           uint64
	FileGeneration       uint64
	IssuedAt             int64
	PermitExpiresAt      int64
	CredentialGeneration uint64
	Mode                 string
	ObservationID        string
	ReservationID        string
	Ticket               string
	Permit               *model.DownloadExecutionPermission
	Operation            string
	ExecutionClaimID     string
}

// DownloadPermissionResult is the authority's current execution decision.
type DownloadPermissionResult struct {
	AuthorityProtocol int
	Permission        *model.DownloadExecutionPermission
	Allow             bool
	Reason            string
	RetryAfter        time.Duration
	FileGeneration    uint64
	AccountGeneration uint64
	AccountName       string
	Mode              string
	ObservationID     string
	ReservationID     string
	ExecutionClaimID  string
	ReportSuccess     bool
	ExpiresAt         time.Time
}

// CanonicalDownloadAuthorizationEventID returns the stable event identifier
// shared by OpenList and download workers.
func CanonicalDownloadAuthorizationEventID(observationID, eventType string) string {
	payload := strings.TrimSpace(observationID) + "\x00" + strings.ToLower(strings.TrimSpace(eventType))
	digest := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(digest[:])
}

// IsQualifyingDownloadQuotaResponse identifies the response shape that may be
// treated as a Google Drive quota observation after the provider is verified.
func IsQualifyingDownloadQuotaResponse(statusCode int, reason string) bool {
	if statusCode != 403 && statusCode != 429 {
		return false
	}
	reason = strings.ToLower(reason)
	return strings.Contains(reason, "quota") || strings.Contains(reason, "exceed") || strings.Contains(reason, "limit")
}

// NormalizeDownloadAuthorizationEventType derives the canonical event type
// used by both API validation and the Google authority.
func NormalizeDownloadAuthorizationEventType(eventType, outcome string, statusCode int, reason string) string {
	if normalized := strings.ToLower(strings.TrimSpace(eventType)); normalized != "" {
		return normalized
	}
	outcome = strings.ToLower(strings.TrimSpace(outcome))
	switch outcome {
	case "success":
		return "success"
	case "abandoned":
		return "abandoned"
	case "quota":
		return "quota"
	}
	if IsQualifyingDownloadQuotaResponse(statusCode, reason) {
		return "quota"
	}
	return "failure"
}

// ValidateDownloadAuthorizationFeedback enforces the event/outcome/status
// matrix shared by the administrator API and the Google authority.
func ValidateDownloadAuthorizationFeedback(eventType, outcome string, statusCode int, reason string) error {
	eventType = strings.ToLower(strings.TrimSpace(eventType))
	outcome = strings.ToLower(strings.TrimSpace(outcome))
	switch eventType {
	case "success":
		if outcome != "success" || (statusCode != 200 && statusCode != 206) {
			return fmt.Errorf("success requires outcome success and status 200 or 206")
		}
	case "quota":
		if (outcome != "failure" && outcome != "quota") || !IsQualifyingDownloadQuotaResponse(statusCode, reason) {
			return fmt.Errorf("quota requires a qualifying 403 or 429 response")
		}
	case "failure":
		if outcome != "failure" {
			return fmt.Errorf("failure requires outcome failure")
		}
	case "abandoned":
		if outcome != "abandoned" {
			return fmt.Errorf("abandoned requires outcome abandoned")
		}
	default:
		return fmt.Errorf("event type is invalid")
	}
	return nil
}

// DownloadAuthorizationUnavailableError gives the API a bounded retry hint
// when a driver has no currently usable account or authorization.
type DownloadAuthorizationUnavailableError struct {
	RetryAfter time.Duration
	Reason     string
}

// DownloadAuthorizationConflictError is a terminal immutable-event conflict.
// Callers must record it instead of retrying the same payload indefinitely.
type DownloadAuthorizationConflictError struct {
	EventID string
	Reason  string
}

func (e *DownloadAuthorizationConflictError) Error() string {
	if e == nil || e.Reason == "" {
		return "download authorization event conflicts with an existing payload"
	}
	return e.Reason
}

func (e *DownloadAuthorizationUnavailableError) Error() string {
	if e == nil || e.Reason == "" {
		return "download authorization is temporarily unavailable"
	}
	return e.Reason
}

func (e *DownloadAuthorizationUnavailableError) RetryAfterDuration() time.Duration {
	if e == nil || e.RetryAfter < 0 {
		return 0
	}
	return e.RetryAfter
}

// DownloadAuthorizer is an optional driver seam for issuing a direct
// download URL from a resolved file identity and reporting its result.
// Drivers that do not implement it retain the normal Link behavior.
type DownloadAuthorizer interface {
	AcquireDownloadAuthorization(context.Context, DownloadAuthorizationRequest) (DownloadAuthorizationResult, error)
	ReportDownloadAuthorization(context.Context, DownloadAuthorizationReport) (DownloadAuthorizationReportResult, error)
}

// DownloadPermissionAuthorizer is optional so generic drivers keep their
// ordinary Link behavior while authority-aware drivers get the strict permit
// lifecycle.
type DownloadPermissionAuthorizer interface {
	CheckDownloadPermission(context.Context, DownloadPermissionRequest) (DownloadPermissionResult, error)
}
