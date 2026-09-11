package driver

import (
	"context"
	"time"

	"github.com/OpenListTeam/OpenList/v4/internal/model"
)

// DownloadAuthorizationRequest carries the already-resolved file identity to
// a driver that can issue a download URL without performing a content probe.
type DownloadAuthorizationRequest struct {
	MountPath string
	LeafPath  string
	FileID    string
	File      model.Obj
	LinkArgs  model.LinkArgs
	Exclude   []DownloadAuthorizationExclusion
	Feedback  *DownloadAuthorizationFeedback
}

// DownloadAuthorizationExclusion identifies a previously tried account.
// Ticket signature and path/leaf checks are performed by the link API.
type DownloadAuthorizationExclusion struct {
	Provider             string
	MountPath            string
	LeafPath             string
	FileID               string
	AccountName          string
	Generation           uint64
	TrialID              string
	CredentialGeneration uint64
}

// DownloadAuthorizationFeedback is a verified terminal result for a prior
// authorization. The link API has already checked its signed identity.
type DownloadAuthorizationFeedback struct {
	Provider             string
	MountPath            string
	LeafPath             string
	FileID               string
	AccountName          string
	Generation           uint64
	TrialID              string
	CredentialGeneration uint64
	EventID              string
	Outcome              string
	StatusCode           int
	Reason               string
}

// DownloadAuthorizationResult is the driver's usable link plus the identity
// that the link API signs into its download envelope.
type DownloadAuthorizationResult struct {
	Link                 *model.Link
	Provider             string
	MountPath            string
	LeafPath             string
	FileID               string
	AccountName          string
	Generation           uint64
	TrialID              string
	CredentialGeneration uint64
	ReportSuccess        bool
	ExpiresAt            time.Time
}

// DownloadAuthorizationReport is an alias because acquire feedback and
// report-only input have the same verified identity and terminal fields.
type DownloadAuthorizationReport = DownloadAuthorizationFeedback

// DownloadAuthorizationReportResult describes the durable result of a
// report. RetryAfter is advisory and is expressed as a duration.
type DownloadAuthorizationReportResult struct {
	Applied       bool
	Duplicate     bool
	Stale         bool
	Generation    uint64
	CooldownUntil time.Time
	RetryAfter    time.Duration
}

// DownloadAuthorizationUnavailableError gives the API a bounded retry hint
// when a driver has no currently usable account or authorization.
type DownloadAuthorizationUnavailableError struct {
	RetryAfter time.Duration
	Reason     string
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
