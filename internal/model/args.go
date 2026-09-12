package model

import (
	"context"
	"io"
	"net/http"
	"time"

	"github.com/OpenListTeam/OpenList/v4/pkg/http_range"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
)

type ListArgs struct {
	ReqPath            string
	S3ShowPlaceholder  bool
	Refresh            bool
	WithStorageDetails bool
}

type LinkArgs struct {
	IP           string
	Header       http.Header
	Type         string
	Redirect     bool
	ForceRefresh bool
}

type Link struct {
	URL         string        `json:"url"`    // most common way
	Header      http.Header   `json:"header"` // needed header (for url)
	RangeReader RangeReaderIF `json:"-"`      // recommended way if can't use URL
	MFile       File          `json:"-"`      // best for local,smb... file system, which exposes MFile

	Expiration *time.Duration // local cache expire Duration

	//for accelerating request, use multi-thread downloading
	Concurrency   int                    `json:"concurrency"`
	PartSize      int                    `json:"part_size"`
	ContentLength int64                  `json:"-"` // 转码视频、缩略图
	Size          int64                  `json:"size"`
	Download      *DownloadAuthorization `json:"download"`

	utils.SyncClosers `json:"-"`
}

const DownloadAuthorityProtocol = 2

// DownloadAuthorization is the signed server-side authorization accompanying
// a link returned by the administrator download API. The permit is deliberately
// separate from the long-lived transport authorization.
type DownloadAuthorization struct {
	AuthorityProtocol   int64                        `json:"authority_protocol"`
	Provider            string                       `json:"provider"`
	Ticket              string                       `json:"ticket"`
	ExpiresAt           int64                        `json:"expires_at"`
	CredentialExpiresAt int64                        `json:"credential_expires_at,omitempty"`
	ReportSuccess       bool                         `json:"report_success"`
	Permit              *DownloadExecutionPermission `json:"permit"`
}

// DownloadExecutionPermission is an opaque, short-lived permission to open
// the transport URL. Workers store proof and never interpret its claims.
type DownloadExecutionPermission struct {
	AuthorityProtocol int64  `json:"authority_protocol"`
	Proof             string `json:"proof"`
	ValidForMS        int64  `json:"valid_for_ms"`
	Mode              string `json:"mode"`
	ObservationID     string `json:"observation_id"`
	ReportSuccess     bool   `json:"report_success"`
	Allow             bool   `json:"allow"`
	Reason            string `json:"reason,omitempty"`
	RetryAfterMS      int64  `json:"retry_after_ms,omitempty"`
	ReservationID     string `json:"reservation_id,omitempty"`
	ExecutionClaimID  string `json:"execution_claim_id,omitempty"`
}

// DownloadFeedback is the terminal content result sent with a replacement
// acquisition or a report-only link request.
type DownloadFeedback struct {
	AuthorityProtocol int64                        `json:"authority_protocol"`
	Ticket            string                       `json:"ticket"`
	Permit            *DownloadExecutionPermission `json:"permit"`
	ObservationID     string                       `json:"observation_id"`
	EventType         string                       `json:"event_type"`
	EventID           string                       `json:"event_id,omitempty"`
	Outcome           string                       `json:"outcome"`
	StatusCode        int                          `json:"status_code"`
	Reason            string                       `json:"reason"`
}

type OtherArgs struct {
	Obj    Obj
	Method string
	Data   interface{}
}

type FsOtherArgs struct {
	Path   string      `json:"path" form:"path"`
	Method string      `json:"method" form:"method"`
	Data   interface{} `json:"data" form:"data"`
}

type ArchiveArgs struct {
	Password string
	LinkArgs
}

type ArchiveInnerArgs struct {
	ArchiveArgs
	InnerPath string
}

type ArchiveMetaArgs struct {
	ArchiveArgs
	Refresh bool
}

type ArchiveListArgs struct {
	ArchiveInnerArgs
	Refresh bool
}

type ArchiveDecompressArgs struct {
	ArchiveInnerArgs
	CacheFull     bool
	PutIntoNewDir bool
}

type SharingListArgs struct {
	Refresh bool
	Pwd     string
}

type SharingArchiveMetaArgs struct {
	ArchiveMetaArgs
	Pwd string
}

type SharingArchiveListArgs struct {
	ArchiveListArgs
	Pwd string
}

type SharingLinkArgs struct {
	Pwd string
	LinkArgs
}

type RangeReaderIF interface {
	RangeRead(ctx context.Context, httpRange http_range.Range) (io.ReadCloser, error)
}

type RangeReadCloserIF interface {
	RangeReaderIF
	utils.ClosersIF
}

var _ RangeReadCloserIF = (*RangeReadCloser)(nil)

type RangeReadCloser struct {
	RangeReader RangeReaderIF
	utils.Closers
}

func (r *RangeReadCloser) RangeRead(ctx context.Context, httpRange http_range.Range) (io.ReadCloser, error) {
	rc, err := r.RangeReader.RangeRead(ctx, httpRange)
	r.Add(rc)
	return rc, err
}
