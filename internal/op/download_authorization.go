package op

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/errs"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	pkgsign "github.com/OpenListTeam/OpenList/v4/pkg/sign"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
	"github.com/google/uuid"
)

const (
	linkAPIActionAcquire  = "acquire"
	linkAPIActionCheck    = "check"
	linkAPIActionReport   = "report"
	linkAPIActionNextPlan = "next_plan"
	linkAPITicketVersion  = model.DownloadAuthorityProtocol
	linkAPIProtocol       = model.DownloadAuthorityProtocol

	maxLinkAPIPath        = 4096
	maxLinkAPITicket      = 16384
	maxLinkAPIEventID     = 256
	maxLinkAPIReason      = 4096
	maxLinkAPIName        = 256
	maxLinkAPIFileID      = 1024
	maxLinkAPIProof       = 16384
	maxLinkAPIObservation = 256
	linkAPIPermissionTTL  = 30 * time.Second
	linkAPIReportGrace    = 15 * time.Minute
	linkAPIReleaseTTL     = 5 * time.Second
)

// LinkAPIRequest describes the administrator download authorization request.
type LinkAPIRequest struct {
	AuthorityProtocol int
	Action            string
	Path              string
	Args              model.LinkArgs
	Feedback          *model.DownloadFeedback
	Ticket            string
	Permit            *model.DownloadExecutionPermission
	Operation         string
	ExecutionClaimID  string
}

type linkAPIRequestError struct{ err error }

func (e *linkAPIRequestError) Error() string { return e.err.Error() }
func (e *linkAPIRequestError) Unwrap() error { return e.err }

func invalidLinkAPIRequest(format string, args ...any) error {
	return &linkAPIRequestError{err: fmt.Errorf(format, args...)}
}

// IsLinkAPIRequestError reports a malformed or invalid signed API request.
func IsLinkAPIRequestError(err error) bool {
	_, ok := err.(*linkAPIRequestError)
	return ok
}

// IsLinkAPIConflictError reports an immutable observation payload conflict.
func IsLinkAPIConflictError(err error) bool {
	var conflict *driver.DownloadAuthorizationConflictError
	return errors.As(err, &conflict)
}

type linkAPITarget struct {
	storage       driver.Driver
	actualPath    string
	requestedPath string
	leafPath      string
	file          model.Obj
	fileID        string
	provider      string
}

type linkAPITicketClaims struct {
	AuthorityProtocol    int    `json:"authority_protocol"`
	Version              int    `json:"v"`
	RequestedPath        string `json:"path"`
	MountPath            string `json:"mount"`
	LeafPath             string `json:"leaf"`
	FileID               string `json:"file_id"`
	Provider             string `json:"provider"`
	AccountName          string `json:"account_name,omitempty"`
	TrialID              string `json:"trial_id,omitempty"`
	CredentialGeneration uint64 `json:"credential_generation,omitempty"`
	IssuanceID           string `json:"issuance_id"`
	IssuedAt             int64  `json:"issued_at"`
	ExpiresAt            int64  `json:"expires_at"`
	CredentialExpiresAt  int64  `json:"credential_expires_at,omitempty"`
}

type linkAPIPermitClaims struct {
	AuthorityProtocol    int    `json:"authority_protocol"`
	TicketHash           string `json:"ticket_hash"`
	Provider             string `json:"provider"`
	MountPath            string `json:"mount"`
	LeafPath             string `json:"leaf"`
	FileID               string `json:"file_id"`
	AccountName          string `json:"account_name,omitempty"`
	Generation           uint64 `json:"generation,omitempty"`
	FileGeneration       uint64 `json:"file_generation,omitempty"`
	CredentialGeneration uint64 `json:"credential_generation,omitempty"`
	Mode                 string `json:"mode"`
	ObservationID        string `json:"observation_id"`
	ReportSuccess        bool   `json:"report_success"`
	Allow                bool   `json:"allow"`
	Reason               string `json:"reason,omitempty"`
	ReservationID        string `json:"reservation_id,omitempty"`
	ExecutionClaimID     string `json:"execution_claim_id,omitempty"`
	PermitID             string `json:"permit_id"`
	IssuedAt             int64  `json:"issued_at"`
	ExpiresAt            int64  `json:"expires_at"`
}

type linkAPIVerifiedTicket struct {
	claims linkAPITicketClaims
}

func (r LinkAPIRequest) normalized() (string, string, error) {
	if r.AuthorityProtocol != linkAPIProtocol {
		return "", "", invalidLinkAPIRequest("authority_protocol must be %d", linkAPIProtocol)
	}
	action := strings.ToLower(strings.TrimSpace(r.Action))
	if action == "" {
		return "", "", invalidLinkAPIRequest("action is required")
	}
	if action != linkAPIActionAcquire && action != linkAPIActionCheck && action != linkAPIActionReport && action != linkAPIActionNextPlan {
		return "", "", invalidLinkAPIRequest("action must be acquire, check, report, or next_plan")
	}
	if strings.TrimSpace(r.Path) == "" {
		return "", "", invalidLinkAPIRequest("path is required")
	}
	path := utils.FixAndCleanPath(r.Path)
	if path == "" || len(path) > maxLinkAPIPath {
		return "", "", invalidLinkAPIRequest("path is empty or exceeds %d characters", maxLinkAPIPath)
	}
	return action, path, nil
}

// ResolveLinkAPI executes one administrator download authorization operation.
// Acquire returns a Link; report returns a terminal report result and no Link.
func ResolveLinkAPI(ctx context.Context, request LinkAPIRequest) (*model.Link, *driver.DownloadAuthorizationReportResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	action, path, err := request.normalized()
	if err != nil {
		return nil, nil, err
	}
	if action == linkAPIActionCheck {
		permission, err := checkLinkAPIPermission(ctx, path, request)
		if err != nil {
			return nil, nil, err
		}
		return permissionLink(permission), nil, nil
	}
	if action == linkAPIActionNextPlan {
		if request.Feedback == nil && strings.TrimSpace(request.Ticket) == "" {
			return nil, nil, invalidLinkAPIRequest("next_plan requires ticket or feedback")
		}
		request.Action = linkAPIActionAcquire
		request.Operation = "next_plan"
	}
	if action == linkAPIActionReport {
		if request.Feedback == nil {
			return nil, nil, invalidLinkAPIRequest("report requires feedback")
		}
		result, err := reportLinkAPI(ctx, path, request)
		return nil, &result, err
	}
	link, err := acquireLinkAPI(ctx, path, request)
	return link, nil, err
}

func acquireLinkAPI(ctx context.Context, requestedPath string, apiRequest LinkAPIRequest) (*model.Link, error) {
	args := apiRequest.Args
	feedback := apiRequest.Feedback
	if _, err := downloadAuthorizationSigner(); err != nil {
		return nil, err
	}
	if requestedPath == "" || len(requestedPath) > maxLinkAPIPath {
		return nil, invalidLinkAPIRequest("path is empty or exceeds %d characters", maxLinkAPIPath)
	}
	if apiRequest.AuthorityProtocol != linkAPIProtocol {
		return nil, invalidLinkAPIRequest("authority_protocol must be %d", linkAPIProtocol)
	}

	var (
		feedbackTicket *linkAPIVerifiedTicket
		target         linkAPITarget
		err            error
	)
	if feedback != nil {
		feedbackTicket, err = verifyLinkAPIFeedbackForAcquire(feedback)
		if err != nil {
			return nil, err
		}
		if feedbackTicket.claims.RequestedPath != requestedPath {
			return nil, invalidLinkAPIRequest("feedback ticket is bound to a different path")
		}
		target, err = resolveLinkAPITicketTarget(ctx, feedbackTicket.claims)
	} else if apiRequest.Operation == "next_plan" && apiRequest.Ticket != "" {
		anchor, anchorErr := verifyLinkAPITicket(apiRequest.Ticket)
		if anchorErr != nil {
			return nil, anchorErr
		}
		if anchor.claims.RequestedPath != requestedPath {
			return nil, invalidLinkAPIRequest("ticket is bound to a different path")
		}
		target, err = resolveLinkAPITicketTarget(ctx, anchor.claims)
	} else {
		target, err = resolveLinkAPITarget(ctx, requestedPath)
	}
	if err != nil {
		return nil, err
	}

	var feedbackValue *driver.DownloadAuthorizationFeedback
	if feedbackTicket != nil {
		if err := validateLinkAPITicketTarget(feedbackTicket.claims, target); err != nil {
			return nil, err
		}
		feedback := ticketToFeedback(feedbackTicket.claims, feedback)
		if feedback.Permit == nil || feedback.Permit.Proof == "" {
			return nil, invalidLinkAPIRequest("acquire feedback requires execution permission proof")
		}
		permit, permitErr := verifyLinkAPIPermit(feedback.Permit.Proof, true)
		if permitErr != nil {
			return nil, permitErr
		}
		if err := validateLinkAPIPermit(permit.claims, apiRequest.Feedback.Ticket, feedbackTicket.claims, target, apiRequest.Feedback); err != nil {
			return nil, err
		}
		feedback.ObservationID = permit.claims.ObservationID
		feedback.AccountName = permit.claims.AccountName
		feedback.Generation = permit.claims.Generation
		feedback.FileGeneration = permit.claims.FileGeneration
		feedback.CredentialGeneration = permit.claims.CredentialGeneration
		feedback.EventType = normalizeEventType(apiRequest.Feedback.EventType, apiRequest.Feedback.Outcome, apiRequest.Feedback.StatusCode, apiRequest.Feedback.Reason)
		if apiRequest.Feedback.EventID != "" && apiRequest.Feedback.EventID != driver.CanonicalDownloadAuthorizationEventID(feedback.ObservationID, feedback.EventType) {
			return nil, invalidLinkAPIRequest("feedback event_id does not match observation")
		}
		feedback.EventID = driver.CanonicalDownloadAuthorizationEventID(feedback.ObservationID, feedback.EventType)
		feedback.ExecutionClaimID = permit.claims.ExecutionClaimID
		feedbackValue = &feedback
	}

	driverRequest := driver.DownloadAuthorizationRequest{
		AuthorityProtocol: linkAPIProtocol,
		MountPath:         target.storage.GetStorage().MountPath,
		LeafPath:          target.leafPath,
		FileID:            target.fileID,
		File:              target.file,
		LinkArgs:          args,
		Feedback:          feedbackValue,
		Ticket:            apiRequest.Ticket,
		Operation:         apiRequest.Operation,
		ExecutionClaimID:  apiRequest.ExecutionClaimID,
		OriginalAccountName: func() string {
			if apiRequest.Operation != "next_plan" || apiRequest.Ticket == "" {
				return ""
			}
			anchor, _ := verifyLinkAPITicket(apiRequest.Ticket)
			if anchor == nil {
				return ""
			}
			return anchor.claims.AccountName
		}(),
	}

	var result driver.DownloadAuthorizationResult
	if authorizer, ok := target.storage.(driver.DownloadAuthorizer); ok {
		result, err = authorizer.AcquireDownloadAuthorization(ctx, driverRequest)
	} else {
		var link *model.Link
		link, err = target.storage.Link(ctx, target.file, args)
		result = driver.DownloadAuthorizationResult{
			Link:      link,
			Provider:  target.provider,
			MountPath: utils.FixAndCleanPath(target.storage.GetStorage().MountPath),
			LeafPath:  target.leafPath,
			FileID:    target.fileID,
			ExpiresAt: time.Time{},
		}
	}
	if err != nil {
		return nil, err
	}
	if result.AuthorityProtocol != 0 && result.AuthorityProtocol != linkAPIProtocol {
		return nil, invalidLinkAPIRequest("download authorization returned an unsupported authority_protocol")
	}
	if result.AuthorityProtocol == 0 {
		result.AuthorityProtocol = linkAPIProtocol
	}
	keepAuthorization := false
	defer func() {
		if !keepAuthorization {
			closeLink(result.Link)
			releaseDownloadAuthorization(ctx, target, result)
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if result.Link == nil {
		return nil, fmt.Errorf("download authorization returned no link")
	}

	if result.Provider == "" {
		result.Provider = target.provider
	}
	if result.MountPath == "" {
		result.MountPath = utils.FixAndCleanPath(target.storage.GetStorage().MountPath)
	}
	if result.LeafPath == "" {
		result.LeafPath = target.leafPath
	}
	if result.FileID == "" {
		result.FileID = target.fileID
	}
	if feedback != nil {
		result.ReportSuccess = true
	}
	if result.Provider != target.provider || result.MountPath != utils.FixAndCleanPath(target.storage.GetStorage().MountPath) || result.LeafPath != target.leafPath || result.FileID != target.fileID {
		return nil, invalidLinkAPIRequest("download authorization changed the resolved file identity")
	}
	if !isActualDirectLink(ctx, target.storage.GetStorage(), target.leafPath, result.Link, requestedPath) {
		return nil, errs.NewErr(errs.NotSupport, "storage %s cannot provide a real upstream downloadable URL for %s", target.storage.GetStorage().MountPath, requestedPath)
	}

	expiresAt, err := linkAPIExpiry(result.ExpiresAt)
	if err != nil {
		return nil, err
	}
	credentialExpiresAt := expiresAt
	if !result.CredentialExpiresAt.IsZero() {
		credentialExpiresAt = result.CredentialExpiresAt.Unix()
		if credentialExpiresAt <= 0 || credentialExpiresAt < time.Now().Unix() {
			return nil, invalidLinkAPIRequest("download credential has expired")
		}
		if credentialExpiresAt > expiresAt {
			credentialExpiresAt = expiresAt
		}
	}
	claims := linkAPITicketClaims{
		AuthorityProtocol:    linkAPIProtocol,
		Version:              linkAPITicketVersion,
		RequestedPath:        requestedPath,
		MountPath:            result.MountPath,
		LeafPath:             result.LeafPath,
		FileID:               result.FileID,
		Provider:             result.Provider,
		AccountName:          result.AccountName,
		TrialID:              result.TrialID,
		CredentialGeneration: result.CredentialGeneration,
		IssuanceID:           uuid.NewString(),
		IssuedAt:             time.Now().Unix(),
		ExpiresAt:            expiresAt,
		CredentialExpiresAt:  credentialExpiresAt,
	}
	ticket, err := signLinkAPITicket(claims)
	if err != nil {
		return nil, err
	}
	if len(ticket) > maxLinkAPITicket {
		return nil, invalidLinkAPIRequest("download authorization ticket exceeds %d characters", maxLinkAPITicket)
	}
	result.Link.Size = target.file.GetSize()
	result.Link.Download = &model.DownloadAuthorization{
		AuthorityProtocol:   linkAPIProtocol,
		Provider:            result.Provider,
		Ticket:              ticket,
		ExpiresAt:           expiresAt,
		CredentialExpiresAt: credentialExpiresAt,
		ReportSuccess:       result.ReportSuccess,
	}
	permission, err := issueLinkAPIPermission(ticket, claims, result, "acquire")
	if err != nil {
		return nil, err
	}
	result.Link.Download.Permit = &permission
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	keepAuthorization = true
	return result.Link, nil
}

func verifyLinkAPIFeedbackForAcquire(feedback *model.DownloadFeedback) (*linkAPIVerifiedTicket, error) {
	if feedback != nil && driver.NormalizeDownloadAuthorizationEventType(feedback.EventType, feedback.Outcome, feedback.StatusCode, feedback.Reason) == "quota" {
		return verifyLinkAPIFeedbackForReport(feedback)
	}
	return verifyLinkAPIFeedback(feedback)
}

func reportLinkAPI(ctx context.Context, requestedPath string, apiRequest LinkAPIRequest) (driver.DownloadAuthorizationReportResult, error) {
	feedback := apiRequest.Feedback
	if _, err := downloadAuthorizationSigner(); err != nil {
		return driver.DownloadAuthorizationReportResult{}, err
	}
	if requestedPath == "" || len(requestedPath) > maxLinkAPIPath {
		return driver.DownloadAuthorizationReportResult{}, invalidLinkAPIRequest("path is empty or exceeds %d characters", maxLinkAPIPath)
	}
	verified, err := verifyLinkAPIFeedbackForReport(feedback)
	if err != nil {
		return driver.DownloadAuthorizationReportResult{}, err
	}
	if verified.claims.RequestedPath != requestedPath {
		return driver.DownloadAuthorizationReportResult{}, invalidLinkAPIRequest("feedback ticket is bound to a different path")
	}
	target, err := resolveLinkAPITicketTarget(ctx, verified.claims)
	if err != nil {
		return driver.DownloadAuthorizationReportResult{}, err
	}
	if err := validateLinkAPITicketTarget(verified.claims, target); err != nil {
		return driver.DownloadAuthorizationReportResult{}, err
	}
	report := ticketToFeedback(verified.claims, feedback)
	if feedback.AuthorityProtocol != 0 && feedback.AuthorityProtocol != linkAPIProtocol {
		return driver.DownloadAuthorizationReportResult{}, invalidLinkAPIRequest("feedback authority_protocol must be %d", linkAPIProtocol)
	}
	if feedback.Permit == nil || strings.TrimSpace(feedback.Permit.Proof) == "" {
		return driver.DownloadAuthorizationReportResult{}, invalidLinkAPIRequest("report requires execution permission proof")
	}
	permit, err := verifyLinkAPIPermit(feedback.Permit.Proof, true)
	if err != nil {
		return driver.DownloadAuthorizationReportResult{}, err
	}
	if err := validateLinkAPIPermit(permit.claims, feedback.Ticket, verified.claims, target, feedback); err != nil {
		return driver.DownloadAuthorizationReportResult{}, err
	}
	report.Permit = feedback.Permit
	report.AuthorityProtocol = linkAPIProtocol
	report.AccountName = permit.claims.AccountName
	report.Generation = permit.claims.Generation
	report.FileGeneration = permit.claims.FileGeneration
	report.CredentialGeneration = permit.claims.CredentialGeneration
	report.ObservationID = permit.claims.ObservationID
	report.EventType = normalizeEventType(feedback.EventType, feedback.Outcome, feedback.StatusCode, feedback.Reason)
	report.ExecutionClaimID = permit.claims.ExecutionClaimID
	if feedback.EventID != "" && feedback.EventID != driver.CanonicalDownloadAuthorizationEventID(report.ObservationID, report.EventType) {
		return driver.DownloadAuthorizationReportResult{}, invalidLinkAPIRequest("feedback event_id does not match observation")
	}
	report.EventID = driver.CanonicalDownloadAuthorizationEventID(report.ObservationID, report.EventType)
	if feedback.ObservationID != "" && feedback.ObservationID != report.ObservationID {
		return driver.DownloadAuthorizationReportResult{}, invalidLinkAPIRequest("feedback observation_id does not match permission")
	}
	if authorizer, ok := target.storage.(driver.DownloadAuthorizer); ok {
		result, reportErr := authorizer.ReportDownloadAuthorization(ctx, report)
		result.AuthorityProtocol = linkAPIProtocol
		return result, reportErr
	}
	return driver.DownloadAuthorizationReportResult{AuthorityProtocol: linkAPIProtocol, Applied: true}, nil
}

func checkLinkAPIPermission(ctx context.Context, requestedPath string, apiRequest LinkAPIRequest) (driver.DownloadPermissionResult, error) {
	if apiRequest.AuthorityProtocol != linkAPIProtocol {
		return driver.DownloadPermissionResult{}, invalidLinkAPIRequest("authority_protocol must be %d", linkAPIProtocol)
	}
	if strings.TrimSpace(apiRequest.Ticket) == "" {
		return driver.DownloadPermissionResult{}, invalidLinkAPIRequest("check requires ticket")
	}
	verified, err := verifyLinkAPITicket(apiRequest.Ticket)
	if err != nil {
		return driver.DownloadPermissionResult{}, err
	}
	if verified.claims.RequestedPath != requestedPath {
		return driver.DownloadPermissionResult{}, invalidLinkAPIRequest("ticket is bound to a different request path")
	}
	target, err := resolveLinkAPITicketTarget(ctx, verified.claims)
	if err != nil {
		return driver.DownloadPermissionResult{}, err
	}
	if apiRequest.Permit == nil || strings.TrimSpace(apiRequest.Permit.Proof) == "" {
		return driver.DownloadPermissionResult{}, invalidLinkAPIRequest("check requires execution permission proof")
	}
	operation := strings.ToLower(strings.TrimSpace(apiRequest.Operation))
	if operation == "" {
		operation = "check"
	}
	if operation != "check" && operation != "claim" && operation != "release" {
		return driver.DownloadPermissionResult{}, invalidLinkAPIRequest("check operation must be check, claim, or release")
	}
	permit, err := verifyLinkAPIPermit(apiRequest.Permit.Proof, false)
	if err != nil {
		if operation == "claim" || operation == "release" {
			permit, err = verifyLinkAPIPermitForReservation(apiRequest.Permit.Proof)
		} else {
			permit, err = verifyLinkAPIPermitForRenewal(apiRequest.Permit.Proof)
			if err == nil && permit.claims.Mode != "normal" {
				err = invalidLinkAPIRequest("single-use execution permission is expired")
			}
		}
		if err != nil {
			return driver.DownloadPermissionResult{}, err
		}
	}
	if err := validateLinkAPIPermit(permit.claims, apiRequest.Ticket, verified.claims, target, nil); err != nil {
		return driver.DownloadPermissionResult{}, err
	}
	executionClaimID := apiRequest.ExecutionClaimID
	if operation == "check" && executionClaimID == "" {
		executionClaimID = permit.claims.ExecutionClaimID
	}
	request := driver.DownloadPermissionRequest{
		AuthorityProtocol:    linkAPIProtocol,
		MountPath:            verified.claims.MountPath,
		LeafPath:             verified.claims.LeafPath,
		FileID:               verified.claims.FileID,
		Provider:             verified.claims.Provider,
		AccountName:          verified.claims.AccountName,
		Generation:           permit.claims.Generation,
		FileGeneration:       permit.claims.FileGeneration,
		IssuedAt:             verified.claims.IssuedAt,
		PermitExpiresAt:      permit.claims.ExpiresAt,
		CredentialGeneration: verified.claims.CredentialGeneration,
		Mode:                 permit.claims.Mode,
		ObservationID:        permit.claims.ObservationID,
		ReservationID:        permit.claims.ReservationID,
		Ticket:               apiRequest.Ticket,
		Permit:               apiRequest.Permit,
		Operation:            operation,
		ExecutionClaimID:     executionClaimID,
	}
	if authorizer, ok := target.storage.(driver.DownloadPermissionAuthorizer); ok {
		result, err := authorizer.CheckDownloadPermission(ctx, request)
		if err != nil {
			return driver.DownloadPermissionResult{}, err
		}
		if result.AuthorityProtocol == 0 {
			result.AuthorityProtocol = linkAPIProtocol
		}
		if result.ExpiresAt.IsZero() && permit.claims.ExpiresAt > time.Now().Unix() {
			result.ExpiresAt = time.Unix(permit.claims.ExpiresAt, 0)
		}
		permission, issueErr := issueLinkAPIPermission(apiRequest.Ticket, verified.claims, driver.DownloadAuthorizationResult{
			AuthorityProtocol:    linkAPIProtocol,
			Provider:             verified.claims.Provider,
			MountPath:            verified.claims.MountPath,
			LeafPath:             verified.claims.LeafPath,
			FileID:               verified.claims.FileID,
			AccountName:          result.AccountName,
			Generation:           result.AccountGeneration,
			FileGeneration:       result.FileGeneration,
			CredentialGeneration: verified.claims.CredentialGeneration,
			Mode:                 result.Mode,
			ObservationID:        result.ObservationID,
			ReservationID:        result.ReservationID,
			ExecutionClaimID:     result.ExecutionClaimID,
			ReportSuccess:        result.ReportSuccess,
			Allow:                result.Allow,
			Reason:               result.Reason,
			RetryAfter:           result.RetryAfter,
			ExpiresAt:            result.ExpiresAt,
		}, operation)
		if issueErr != nil {
			return driver.DownloadPermissionResult{}, issueErr
		}
		result.Permission = &permission
		return result, nil
	}
	if operation == "release" && permit.claims.ReservationID == "" {
		return driver.DownloadPermissionResult{}, invalidLinkAPIRequest("release requires an unclaimed reservation")
	}
	if operation == "claim" && permit.claims.Mode != "normal" && strings.TrimSpace(apiRequest.ExecutionClaimID) == "" {
		return driver.DownloadPermissionResult{}, invalidLinkAPIRequest("claim requires execution_claim_id")
	}
	result := driver.DownloadPermissionResult{
		AuthorityProtocol: linkAPIProtocol,
		Allow:             permit.claims.Allow,
		Reason:            permit.claims.Reason,
		AccountName:       verified.claims.AccountName,
		Mode:              permit.claims.Mode,
		ObservationID:     permit.claims.ObservationID,
		ReservationID:     permit.claims.ReservationID,
		FileGeneration:    permit.claims.FileGeneration,
		AccountGeneration: permit.claims.Generation,
		ReportSuccess:     permit.claims.ReportSuccess,
		ExpiresAt: func() time.Time {
			if permit.claims.ExpiresAt > time.Now().Unix() {
				return time.Unix(permit.claims.ExpiresAt, 0)
			}
			return time.Time{}
		}(),
	}
	permission, issueErr := issueLinkAPIPermission(apiRequest.Ticket, verified.claims, driver.DownloadAuthorizationResult{
		Provider:             verified.claims.Provider,
		MountPath:            verified.claims.MountPath,
		LeafPath:             verified.claims.LeafPath,
		FileID:               verified.claims.FileID,
		AccountName:          result.AccountName,
		Generation:           result.AccountGeneration,
		FileGeneration:       result.FileGeneration,
		CredentialGeneration: verified.claims.CredentialGeneration,
		Mode:                 result.Mode,
		ObservationID:        result.ObservationID,
		ReservationID:        result.ReservationID,
		ExecutionClaimID:     result.ExecutionClaimID,
		ReportSuccess:        result.ReportSuccess,
		Allow:                result.Allow,
		Reason:               result.Reason,
		RetryAfter:           result.RetryAfter,
		ExpiresAt:            result.ExpiresAt,
	}, operation)
	if issueErr != nil {
		return driver.DownloadPermissionResult{}, issueErr
	}
	result.Permission = &permission
	return result, nil
}

func permissionLink(result driver.DownloadPermissionResult) *model.Link {
	permission := result.Permission
	if permission == nil {
		permission = &model.DownloadExecutionPermission{}
	}
	permission.AuthorityProtocol = linkAPIProtocol
	permission.Allow = result.Allow
	if result.Reason != "" {
		permission.Reason = result.Reason
	}
	if result.RetryAfter > 0 {
		permission.RetryAfterMS = result.RetryAfter.Milliseconds()
	}
	return &model.Link{Download: &model.DownloadAuthorization{
		AuthorityProtocol: linkAPIProtocol,
		ReportSuccess:     permission.ReportSuccess,
		Permit:            permission,
	}}
}

func resolveLinkAPITarget(ctx context.Context, requestedPath string) (linkAPITarget, error) {
	ctx = ensureLinkAPIBalanceState(ctx, true)
	storage, actualPath, leafPath, err := ResolveActualStoragePath(ctx, requestedPath)
	if err != nil {
		return linkAPITarget{}, err
	}
	file, err := GetUnwrap(ctx, storage, actualPath)
	if err != nil {
		return linkAPITarget{}, err
	}
	if file == nil {
		return linkAPITarget{}, errs.ObjectNotFound
	}
	if file.IsDir() {
		return linkAPITarget{}, errs.NotFile
	}
	target := newLinkAPITarget(storage, actualPath, requestedPath, leafPath, file)
	if isCanonicalGoogleProvider(target.provider) && target.fileID == "" {
		return linkAPITarget{}, invalidLinkAPIRequest("Google Drive file ID is empty")
	}
	return target, nil
}

func resolveLinkAPITicketTarget(ctx context.Context, claims linkAPITicketClaims) (linkAPITarget, error) {
	mountPath := utils.FixAndCleanPath(claims.MountPath)
	leafPath := utils.FixAndCleanPath(claims.LeafPath)
	if leafPath == "" || (mountPath != "/" && leafPath != mountPath && !utils.IsSubPath(mountPath, leafPath)) {
		return linkAPITarget{}, invalidLinkAPIRequest("ticket leaf binding is invalid")
	}
	storage, err := GetStorageByMountPath(mountPath)
	if err != nil {
		return linkAPITarget{}, invalidLinkAPIRequest("ticket storage is unavailable")
	}
	actualPath := utils.FixAndCleanPath(strings.TrimPrefix(leafPath, mountPath))
	file, err := GetUnwrap(ctx, storage, actualPath)
	if err != nil {
		return linkAPITarget{}, invalidLinkAPIRequest("ticket file is unavailable")
	}
	if file == nil || file.IsDir() {
		return linkAPITarget{}, invalidLinkAPIRequest("ticket file is unavailable")
	}
	target := newLinkAPITarget(storage, actualPath, claims.RequestedPath, leafPath, file)
	if isCanonicalGoogleProvider(target.provider) && target.fileID == "" {
		return linkAPITarget{}, invalidLinkAPIRequest("ticket Google Drive file ID is empty")
	}
	if target.fileID != claims.FileID || target.provider != claims.Provider {
		return linkAPITarget{}, invalidLinkAPIRequest("ticket file binding is invalid")
	}
	return target, nil
}

func newLinkAPITarget(storage driver.Driver, actualPath, requestedPath, leafPath string, file model.Obj) linkAPITarget {
	fileID := strings.TrimSpace(file.GetID())
	provider := strings.TrimSpace(storage.Config().Name)
	if provider == "" {
		provider = strings.TrimSpace(storage.GetStorage().Driver)
	}
	if isCanonicalGoogleProvider(provider) {
		provider = "GoogleDrive"
	} else if fileID == "" {
		fileID = utils.FixAndCleanPath(leafPath)
	}
	return linkAPITarget{
		storage:       storage,
		actualPath:    utils.FixAndCleanPath(actualPath),
		requestedPath: utils.FixAndCleanPath(requestedPath),
		leafPath:      utils.FixAndCleanPath(leafPath),
		file:          file,
		fileID:        fileID,
		provider:      provider,
	}
}

func validateLinkAPITicketTarget(claims linkAPITicketClaims, target linkAPITarget) error {
	if claims.RequestedPath != target.requestedPath || claims.MountPath != utils.FixAndCleanPath(target.storage.GetStorage().MountPath) || claims.LeafPath != target.leafPath || claims.FileID != target.fileID || claims.Provider != target.provider {
		return invalidLinkAPIRequest("ticket is bound to a different request or file")
	}
	return nil
}

func linkAPIExpiry(candidate time.Time) (int64, error) {
	now := time.Now()
	hours := getSettingInt(conf.LinkExpiration)
	if candidate.IsZero() {
		if hours > 0 {
			candidate = now.Add(time.Duration(hours) * time.Hour)
		} else {
			candidate = now.Add(time.Hour)
		}
	} else if hours > 0 {
		configuredExpiry := now.Add(time.Duration(hours) * time.Hour)
		if configuredExpiry.Before(candidate) {
			candidate = configuredExpiry
		}
	}
	if !candidate.After(now) || candidate.Unix() <= now.Unix() {
		return 0, invalidLinkAPIRequest("download authorization has expired")
	}
	return candidate.Unix(), nil
}

func signLinkAPITicket(claims linkAPITicketClaims) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal download ticket: %w", err)
	}
	signer, err := downloadAuthorizationSigner()
	if err != nil {
		return "", err
	}
	signature := signer.Sign(string(payload), claims.ExpiresAt)
	if signature == "" {
		return "", fmt.Errorf("sign download ticket")
	}
	return base64.RawURLEncoding.EncodeToString(payload) + "." + signature, nil
}

func isCanonicalGoogleProvider(provider string) bool {
	provider = strings.TrimSpace(provider)
	return strings.EqualFold(provider, "GoogleDrive") || strings.EqualFold(provider, "google_drive")
}

func signLinkAPIPermit(claims linkAPIPermitClaims) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal execution permission: %w", err)
	}
	signer, err := downloadAuthorizationSigner()
	if err != nil {
		return "", err
	}
	signature := signer.Sign(string(payload), claims.ExpiresAt)
	if signature == "" {
		return "", fmt.Errorf("sign execution permission")
	}
	return base64.RawURLEncoding.EncodeToString(payload) + "." + signature, nil
}

func downloadAuthorizationTicketHash(ticket string) string {
	digest := sha256.Sum256([]byte(ticket))
	return hex.EncodeToString(digest[:])
}

func isDownloadAuthorizationTicketHash(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

type linkAPIVerifiedPermit struct {
	claims linkAPIPermitClaims
}

func verifyLinkAPIPermit(proof string, allowGrace bool) (*linkAPIVerifiedPermit, error) {
	return verifyLinkAPIPermitWithOptions(proof, allowGrace, false, false)
}

func verifyLinkAPIPermitForRenewal(proof string) (*linkAPIVerifiedPermit, error) {
	return verifyLinkAPIPermitWithOptions(proof, false, true, false)
}

func verifyLinkAPIPermitForReservation(proof string) (*linkAPIVerifiedPermit, error) {
	permit, err := verifyLinkAPIPermitWithOptions(proof, false, false, true)
	if err != nil {
		return nil, err
	}
	if permit.claims.Mode == "normal" || permit.claims.ReservationID == "" {
		return nil, invalidLinkAPIRequest("expired execution permission is not a single-use reservation")
	}
	return permit, nil
}

func verifyLinkAPIPermitWithOptions(proof string, allowGrace, allowExpiredNormal, allowExpiredAny bool) (*linkAPIVerifiedPermit, error) {
	if proof == "" || len(proof) > maxLinkAPIProof {
		return nil, invalidLinkAPIRequest("execution permission proof is empty or exceeds %d characters", maxLinkAPIProof)
	}
	parts := strings.Split(proof, ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, invalidLinkAPIRequest("execution permission proof format is invalid")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || len(payload) == 0 || len(payload) > maxLinkAPIProof {
		return nil, invalidLinkAPIRequest("execution permission proof payload is invalid")
	}
	var claims linkAPIPermitClaims
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&claims); err != nil {
		return nil, invalidLinkAPIRequest("execution permission claims are invalid")
	}
	if claims.AuthorityProtocol != linkAPIProtocol || !isDownloadAuthorizationTicketHash(claims.TicketHash) || claims.IssuedAt <= 0 || claims.ExpiresAt <= 0 || claims.ExpiresAt < claims.IssuedAt || claims.Provider == "" || len(claims.Provider) > maxLinkAPIName || claims.MountPath == "" || len(claims.MountPath) > maxLinkAPIPath || claims.LeafPath == "" || len(claims.LeafPath) > maxLinkAPIPath || claims.FileID == "" || len(claims.FileID) > maxLinkAPIFileID || claims.Mode == "" || len(claims.Mode) > maxLinkAPIName || claims.ObservationID == "" || len(claims.ObservationID) > maxLinkAPIObservation || claims.PermitID == "" || len(claims.PermitID) > maxLinkAPIEventID {
		return nil, invalidLinkAPIRequest("execution permission claims are invalid")
	}
	signer, err := downloadAuthorizationSigner()
	if err != nil {
		return nil, err
	}
	if signer.Sign(string(payload), claims.ExpiresAt) != parts[1] {
		return nil, invalidLinkAPIRequest("execution permission proof is invalid")
	}
	now := time.Now().Unix()
	if claims.ExpiresAt <= now {
		if allowExpiredAny || (allowExpiredNormal && claims.Mode == "normal") {
			return &linkAPIVerifiedPermit{claims: claims}, nil
		}
		if !allowGrace || now-claims.ExpiresAt > int64(linkAPIReportGrace/time.Second) {
			return nil, invalidLinkAPIRequest("execution permission is expired")
		}
	}
	return &linkAPIVerifiedPermit{claims: claims}, nil
}

func issueLinkAPIPermission(ticket string, ticketClaims linkAPITicketClaims, result driver.DownloadAuthorizationResult, operation string) (model.DownloadExecutionPermission, error) {
	mode := strings.ToLower(strings.TrimSpace(result.Mode))
	if mode == "" {
		if result.TrialID != "" || result.ReservationID != "" {
			mode = "diagnostic"
		} else {
			mode = "normal"
		}
	}
	if mode != "normal" && mode != "diagnostic" && mode != "probe" {
		return model.DownloadExecutionPermission{}, invalidLinkAPIRequest("execution permission mode is invalid")
	}
	allow := result.Allow
	if !allow && result.Reason == "" {
		allow = true
	}
	observationID := strings.TrimSpace(result.ObservationID)
	if observationID == "" {
		observationID = uuid.NewString()
	}
	if len(observationID) > maxLinkAPIObservation {
		return model.DownloadExecutionPermission{}, invalidLinkAPIRequest("observation_id exceeds %d characters", maxLinkAPIObservation)
	}
	ttl := linkAPIPermissionTTL
	if !result.ExpiresAt.IsZero() {
		if until := time.Until(result.ExpiresAt); until < ttl {
			ttl = until
		}
	}
	if ttl <= 0 {
		return model.DownloadExecutionPermission{}, invalidLinkAPIRequest("execution permission has expired")
	}
	if ttl > linkAPIPermissionTTL {
		ttl = linkAPIPermissionTTL
	}
	issuedAt := time.Now()
	expiresAt := issuedAt.Add(ttl)
	if ticketClaims.ExpiresAt > 0 && expiresAt.Unix() >= ticketClaims.ExpiresAt {
		expiresAt = time.Unix(ticketClaims.ExpiresAt, 0)
	}
	if !expiresAt.After(issuedAt) {
		return model.DownloadExecutionPermission{}, invalidLinkAPIRequest("execution permission has expired")
	}
	claims := linkAPIPermitClaims{
		AuthorityProtocol:    linkAPIProtocol,
		TicketHash:           downloadAuthorizationTicketHash(ticket),
		Provider:             ticketClaims.Provider,
		MountPath:            ticketClaims.MountPath,
		LeafPath:             ticketClaims.LeafPath,
		FileID:               ticketClaims.FileID,
		AccountName:          ticketClaims.AccountName,
		Generation:           result.Generation,
		FileGeneration:       result.FileGeneration,
		CredentialGeneration: ticketClaims.CredentialGeneration,
		Mode:                 mode,
		ObservationID:        observationID,
		ReportSuccess:        result.ReportSuccess,
		Allow:                allow,
		Reason:               boundedString(result.Reason, maxLinkAPIReason),
		ReservationID:        result.ReservationID,
		ExecutionClaimID:     result.ExecutionClaimID,
		PermitID:             uuid.NewString(),
		IssuedAt:             issuedAt.Unix(),
		ExpiresAt:            expiresAt.Unix(),
	}
	proof, err := signLinkAPIPermit(claims)
	if err != nil {
		return model.DownloadExecutionPermission{}, err
	}
	if len(proof) > maxLinkAPIProof {
		return model.DownloadExecutionPermission{}, invalidLinkAPIRequest("execution permission proof exceeds %d characters", maxLinkAPIProof)
	}
	permission := model.DownloadExecutionPermission{
		AuthorityProtocol: linkAPIProtocol,
		Proof:             proof,
		ValidForMS:        expiresAt.Sub(issuedAt).Milliseconds(),
		Mode:              mode,
		ObservationID:     observationID,
		ReportSuccess:     result.ReportSuccess,
		Allow:             allow,
		Reason:            claims.Reason,
		RetryAfterMS:      result.RetryAfter.Milliseconds(),
		ReservationID:     result.ReservationID,
		ExecutionClaimID:  result.ExecutionClaimID,
	}
	if operation == "claim" && permission.ExecutionClaimID == "" {
		return model.DownloadExecutionPermission{}, invalidLinkAPIRequest("claim requires execution_claim_id")
	}
	return permission, nil
}

func boundedString(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}

func validateLinkAPIPermit(permit linkAPIPermitClaims, authorizationTicket string, ticket linkAPITicketClaims, target linkAPITarget, feedback *model.DownloadFeedback) error {
	if permit.AuthorityProtocol != linkAPIProtocol || !isDownloadAuthorizationTicketHash(permit.TicketHash) {
		return invalidLinkAPIRequest("execution permission is invalid")
	}
	if authorizationTicket == "" || permit.TicketHash != downloadAuthorizationTicketHash(authorizationTicket) {
		return invalidLinkAPIRequest("execution permission is bound to a different authorization")
	}
	if permit.Provider != ticket.Provider || permit.MountPath != ticket.MountPath || permit.LeafPath != ticket.LeafPath || permit.FileID != ticket.FileID || permit.AccountName != ticket.AccountName || permit.CredentialGeneration != ticket.CredentialGeneration {
		return invalidLinkAPIRequest("execution permission identity is invalid")
	}
	if err := validateLinkAPITicketTarget(ticket, target); err != nil {
		return err
	}
	if feedback != nil {
		if !permit.Allow {
			return invalidLinkAPIRequest("denied execution permission cannot be reported")
		}
		if permit.Mode != "normal" && strings.TrimSpace(permit.ExecutionClaimID) == "" {
			return invalidLinkAPIRequest("single-use execution claim is required before reporting")
		}
		if feedback.ObservationID != "" && feedback.ObservationID != permit.ObservationID {
			return invalidLinkAPIRequest("feedback observation_id does not match execution permission")
		}
		if feedback.Permit == nil || feedback.Permit.Proof == "" {
			return invalidLinkAPIRequest("feedback execution permission is required")
		}
	}
	return nil
}

func normalizeEventType(eventType, outcome string, statusCode int, reason string) string {
	return driver.NormalizeDownloadAuthorizationEventType(eventType, outcome, statusCode, reason)
}

func verifyLinkAPITicket(ticket string) (*linkAPIVerifiedTicket, error) {
	return verifyLinkAPITicketWithGrace(ticket, 0)
}

func verifyLinkAPITicketForReport(ticket string) (*linkAPIVerifiedTicket, error) {
	return verifyLinkAPITicketWithGrace(ticket, int64(linkAPIReportGrace/time.Second))
}

func verifyLinkAPITicketWithGrace(ticket string, expiryGraceSeconds int64) (*linkAPIVerifiedTicket, error) {
	if ticket == "" || len(ticket) > maxLinkAPITicket {
		return nil, invalidLinkAPIRequest("ticket is empty or exceeds %d characters", maxLinkAPITicket)
	}
	parts := strings.Split(ticket, ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, invalidLinkAPIRequest("ticket format is invalid")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || len(payload) == 0 || len(payload) > maxLinkAPITicket {
		return nil, invalidLinkAPIRequest("ticket payload is invalid")
	}
	var claims linkAPITicketClaims
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&claims); err != nil {
		return nil, invalidLinkAPIRequest("ticket claims are invalid")
	}
	if claims.AuthorityProtocol != linkAPIProtocol || claims.Version != linkAPITicketVersion || claims.ExpiresAt <= 0 || claims.IssuedAt <= 0 || claims.IssuanceID == "" || len(claims.RequestedPath) == 0 || len(claims.RequestedPath) > maxLinkAPIPath || len(claims.MountPath) == 0 || len(claims.MountPath) > maxLinkAPIPath || len(claims.LeafPath) == 0 || len(claims.LeafPath) > maxLinkAPIPath || len(claims.Provider) == 0 || len(claims.Provider) > maxLinkAPIName || len(claims.FileID) == 0 || len(claims.FileID) > maxLinkAPIFileID || len(claims.AccountName) > maxLinkAPIName || len(claims.TrialID) > maxLinkAPIEventID {
		return nil, invalidLinkAPIRequest("ticket claims are invalid")
	}
	signer, err := downloadAuthorizationSigner()
	if err != nil {
		return nil, err
	}
	if signer.Sign(string(payload), claims.ExpiresAt) != parts[1] {
		return nil, invalidLinkAPIRequest("ticket is invalid or expired")
	}
	if claims.ExpiresAt <= time.Now().Unix() && (expiryGraceSeconds <= 0 || time.Now().Unix()-claims.ExpiresAt > expiryGraceSeconds) {
		return nil, invalidLinkAPIRequest("ticket is expired")
	}
	return &linkAPIVerifiedTicket{claims: claims}, nil
}

func downloadAuthorizationSigner() (pkgsign.Sign, error) {
	item, err := GetSettingItemByKey(conf.Token)
	if err != nil || item == nil || strings.TrimSpace(item.Value) == "" {
		return nil, fmt.Errorf("download authorization signing key is unavailable")
	}
	return pkgsign.NewHMACSign([]byte(item.Value)), nil
}

func verifyLinkAPIFeedback(feedback *model.DownloadFeedback) (*linkAPIVerifiedTicket, error) {
	return verifyLinkAPIFeedbackWithTicketVerifier(feedback, verifyLinkAPITicket)
}

func verifyLinkAPIFeedbackForReport(feedback *model.DownloadFeedback) (*linkAPIVerifiedTicket, error) {
	return verifyLinkAPIFeedbackWithTicketVerifier(feedback, verifyLinkAPITicketForReport)
}

func verifyLinkAPIFeedbackWithTicketVerifier(feedback *model.DownloadFeedback, verifyTicket func(string) (*linkAPIVerifiedTicket, error)) (*linkAPIVerifiedTicket, error) {
	if feedback == nil {
		return nil, invalidLinkAPIRequest("feedback is required")
	}
	if feedback.AuthorityProtocol != linkAPIProtocol {
		return nil, invalidLinkAPIRequest("feedback authority_protocol must be %d", linkAPIProtocol)
	}
	if strings.TrimSpace(feedback.EventID) != "" && len(feedback.EventID) > maxLinkAPIEventID {
		return nil, invalidLinkAPIRequest("feedback event_id exceeds %d characters", maxLinkAPIEventID)
	}
	if strings.TrimSpace(feedback.ObservationID) != "" && len(feedback.ObservationID) > maxLinkAPIObservation {
		return nil, invalidLinkAPIRequest("feedback observation_id exceeds %d characters", maxLinkAPIObservation)
	}
	if len(feedback.Reason) > maxLinkAPIReason {
		return nil, invalidLinkAPIRequest("feedback reason exceeds %d characters", maxLinkAPIReason)
	}
	if feedback.StatusCode < 0 || feedback.StatusCode > 599 {
		return nil, invalidLinkAPIRequest("feedback status_code is invalid")
	}
	eventType := normalizeEventType(feedback.EventType, feedback.Outcome, feedback.StatusCode, feedback.Reason)
	if err := validateFeedbackSemantics(eventType, feedback.Outcome, feedback.StatusCode, feedback.Reason); err != nil {
		return nil, err
	}
	return verifyTicket(feedback.Ticket)
}

func validateFeedbackSemantics(eventType, outcome string, statusCode int, reason string) error {
	if err := driver.ValidateDownloadAuthorizationFeedback(eventType, outcome, statusCode, reason); err != nil {
		return invalidLinkAPIRequest("download feedback is invalid: %v", err)
	}
	return nil
}

func ticketToFeedback(claims linkAPITicketClaims, feedback *model.DownloadFeedback) driver.DownloadAuthorizationFeedback {
	return driver.DownloadAuthorizationFeedback{
		AuthorityProtocol:    linkAPIProtocol,
		Ticket:               feedback.Ticket,
		Provider:             claims.Provider,
		MountPath:            claims.MountPath,
		LeafPath:             claims.LeafPath,
		FileID:               claims.FileID,
		AccountName:          claims.AccountName,
		TrialID:              claims.TrialID,
		CredentialGeneration: claims.CredentialGeneration,
		Permit:               feedback.Permit,
		ObservationID:        feedback.ObservationID,
		EventType:            feedback.EventType,
		EventID:              feedback.EventID,
		Outcome:              feedback.Outcome,
		StatusCode:           feedback.StatusCode,
		Reason:               feedback.Reason,
	}
}

func releaseDownloadAuthorization(ctx context.Context, target linkAPITarget, result driver.DownloadAuthorizationResult) {
	if result.TrialID == "" || result.AccountName == "" {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), linkAPIReleaseTTL)
	defer cancel()
	provider := result.Provider
	if provider == "" {
		provider = target.provider
	}
	mountPath := result.MountPath
	if mountPath == "" {
		mountPath = utils.FixAndCleanPath(target.storage.GetStorage().MountPath)
	}
	leafPath := result.LeafPath
	if leafPath == "" {
		leafPath = target.leafPath
	}
	fileID := result.FileID
	if fileID == "" {
		fileID = target.fileID
	}
	if result.AuthorityProtocol != linkAPIProtocol {
		return
	}
	permissionAuthorizer, ok := target.storage.(driver.DownloadPermissionAuthorizer)
	if !ok {
		return
	}
	_, _ = permissionAuthorizer.CheckDownloadPermission(cleanupCtx, driver.DownloadPermissionRequest{
		AuthorityProtocol:    linkAPIProtocol,
		MountPath:            mountPath,
		LeafPath:             leafPath,
		FileID:               fileID,
		Provider:             provider,
		AccountName:          result.AccountName,
		Generation:           result.Generation,
		FileGeneration:       result.FileGeneration,
		CredentialGeneration: result.CredentialGeneration,
		Mode:                 result.Mode,
		ObservationID:        result.ObservationID,
		ReservationID:        firstNonEmpty(result.ReservationID, result.TrialID),
		Operation:            "release",
	})
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
