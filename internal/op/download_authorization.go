package op

import (
	"context"
	"encoding/base64"
	"encoding/json"
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
	linkAPIActionAcquire = "acquire"
	linkAPIActionReport  = "report"
	linkAPITicketVersion = 1

	maxLinkAPIPath    = 4096
	maxLinkAPITicket  = 16384
	maxLinkAPIExclude = 4
	maxLinkAPIEventID = 256
	maxLinkAPIReason  = 4096
	maxLinkAPIName    = 256
	maxLinkAPIFileID  = 1024
	linkAPIReleaseTTL = 5 * time.Second
)

// LinkAPIRequest describes the administrator download authorization request.
type LinkAPIRequest struct {
	Action   string
	Path     string
	Args     model.LinkArgs
	Feedback *model.DownloadFeedback
	Exclude  []string
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
	Version              int    `json:"v"`
	RequestedPath        string `json:"path"`
	MountPath            string `json:"mount"`
	LeafPath             string `json:"leaf"`
	FileID               string `json:"file_id"`
	Provider             string `json:"provider"`
	AccountName          string `json:"account_name,omitempty"`
	Generation           uint64 `json:"generation,omitempty"`
	TrialID              string `json:"trial_id,omitempty"`
	CredentialGeneration uint64 `json:"credential_generation,omitempty"`
	IssuanceID           string `json:"issuance_id"`
	IssuedAt             int64  `json:"issued_at"`
	ExpiresAt            int64  `json:"expires_at"`
}

type linkAPIVerifiedTicket struct {
	claims linkAPITicketClaims
}

func (r LinkAPIRequest) normalized() (string, string, error) {
	action := strings.ToLower(strings.TrimSpace(r.Action))
	if action == "" {
		return "", "", invalidLinkAPIRequest("action is required")
	}
	if action != linkAPIActionAcquire && action != linkAPIActionReport {
		return "", "", invalidLinkAPIRequest("action must be acquire or report")
	}
	if strings.TrimSpace(r.Path) == "" {
		return "", "", invalidLinkAPIRequest("path is required")
	}
	path := utils.FixAndCleanPath(r.Path)
	if path == "" || len(path) > maxLinkAPIPath {
		return "", "", invalidLinkAPIRequest("path is empty or exceeds %d characters", maxLinkAPIPath)
	}
	if len(r.Exclude) > maxLinkAPIExclude {
		return "", "", invalidLinkAPIRequest("exclude must contain at most %d tickets", maxLinkAPIExclude)
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
	if action == linkAPIActionReport {
		if request.Feedback == nil {
			return nil, nil, invalidLinkAPIRequest("report requires feedback")
		}
		if len(request.Exclude) != 0 {
			return nil, nil, invalidLinkAPIRequest("report does not accept exclude tickets")
		}
		result, err := reportLinkAPI(ctx, path, request.Feedback)
		return nil, &result, err
	}
	link, err := acquireLinkAPI(ctx, path, request.Args, request.Feedback, request.Exclude)
	return link, nil, err
}

func acquireLinkAPI(ctx context.Context, requestedPath string, args model.LinkArgs, feedback *model.DownloadFeedback, excludeTickets []string) (*model.Link, error) {
	if _, err := downloadAuthorizationSigner(); err != nil {
		return nil, err
	}
	if requestedPath == "" || len(requestedPath) > maxLinkAPIPath {
		return nil, invalidLinkAPIRequest("path is empty or exceeds %d characters", maxLinkAPIPath)
	}
	if len(excludeTickets) > maxLinkAPIExclude {
		return nil, invalidLinkAPIRequest("exclude must contain at most %d tickets", maxLinkAPIExclude)
	}

	var (
		feedbackTicket *linkAPIVerifiedTicket
		target         linkAPITarget
		err            error
	)
	if feedback != nil {
		feedbackTicket, err = verifyLinkAPIFeedback(feedback)
		if err != nil {
			return nil, err
		}
		if feedbackTicket.claims.RequestedPath != requestedPath {
			return nil, invalidLinkAPIRequest("feedback ticket is bound to a different path")
		}
		target, err = resolveLinkAPITicketTarget(ctx, feedbackTicket.claims)
	} else if len(excludeTickets) > 0 {
		// Reuse the first signed leaf as the request anchor. This keeps a
		// balance or alias resolution stable while the caller presents prior
		// account attempts without a new feedback event.
		anchor, anchorErr := verifyLinkAPITicket(excludeTickets[0])
		if anchorErr != nil {
			return nil, anchorErr
		}
		if anchor.claims.RequestedPath != requestedPath {
			return nil, invalidLinkAPIRequest("exclusion ticket is bound to a different path")
		}
		target, err = resolveLinkAPITicketTarget(ctx, anchor.claims)
	} else {
		target, err = resolveLinkAPITarget(ctx, requestedPath)
	}
	if err != nil {
		return nil, err
	}

	exclusions := make([]driver.DownloadAuthorizationExclusion, 0, len(excludeTickets))
	for _, ticket := range excludeTickets {
		verified, verifyErr := verifyLinkAPITicket(ticket)
		if verifyErr != nil {
			return nil, verifyErr
		}
		if verifyErr = validateLinkAPITicketTarget(verified.claims, target); verifyErr != nil {
			return nil, verifyErr
		}
		exclusions = append(exclusions, ticketToExclusion(verified.claims))
	}

	var feedbackValue *driver.DownloadAuthorizationFeedback
	if feedbackTicket != nil {
		if err := validateLinkAPITicketTarget(feedbackTicket.claims, target); err != nil {
			return nil, err
		}
		feedback := ticketToFeedback(feedbackTicket.claims, feedback)
		feedbackValue = &feedback
	}

	request := driver.DownloadAuthorizationRequest{
		MountPath: target.storage.GetStorage().MountPath,
		LeafPath:  target.leafPath,
		FileID:    target.fileID,
		File:      target.file,
		LinkArgs:  args,
		Exclude:   exclusions,
		Feedback:  feedbackValue,
	}

	var result driver.DownloadAuthorizationResult
	if authorizer, ok := target.storage.(driver.DownloadAuthorizer); ok {
		result, err = authorizer.AcquireDownloadAuthorization(ctx, request)
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
	if feedback != nil || len(excludeTickets) > 0 {
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
	claims := linkAPITicketClaims{
		Version:              linkAPITicketVersion,
		RequestedPath:        requestedPath,
		MountPath:            result.MountPath,
		LeafPath:             result.LeafPath,
		FileID:               result.FileID,
		Provider:             result.Provider,
		AccountName:          result.AccountName,
		Generation:           result.Generation,
		TrialID:              result.TrialID,
		CredentialGeneration: result.CredentialGeneration,
		IssuanceID:           uuid.NewString(),
		IssuedAt:             time.Now().Unix(),
		ExpiresAt:            expiresAt,
	}
	ticket, err := signLinkAPITicket(claims)
	if err != nil {
		return nil, err
	}
	result.Link.Size = target.file.GetSize()
	result.Link.Download = &model.DownloadAuthorization{
		Provider:      result.Provider,
		Ticket:        ticket,
		ExpiresAt:     expiresAt,
		ReportSuccess: result.ReportSuccess,
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	keepAuthorization = true
	return result.Link, nil
}

func reportLinkAPI(ctx context.Context, requestedPath string, feedback *model.DownloadFeedback) (driver.DownloadAuthorizationReportResult, error) {
	if _, err := downloadAuthorizationSigner(); err != nil {
		return driver.DownloadAuthorizationReportResult{}, err
	}
	if requestedPath == "" || len(requestedPath) > maxLinkAPIPath {
		return driver.DownloadAuthorizationReportResult{}, invalidLinkAPIRequest("path is empty or exceeds %d characters", maxLinkAPIPath)
	}
	verified, err := verifyLinkAPIFeedback(feedback)
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
	if authorizer, ok := target.storage.(driver.DownloadAuthorizer); ok {
		return authorizer.ReportDownloadAuthorization(ctx, report)
	}
	return driver.DownloadAuthorizationReportResult{Applied: true}, nil
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
	return newLinkAPITarget(storage, actualPath, requestedPath, leafPath, file), nil
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
	if target.fileID != claims.FileID || target.provider != claims.Provider {
		return linkAPITarget{}, invalidLinkAPIRequest("ticket file binding is invalid")
	}
	return target, nil
}

func newLinkAPITarget(storage driver.Driver, actualPath, requestedPath, leafPath string, file model.Obj) linkAPITarget {
	fileID := strings.TrimSpace(file.GetID())
	if fileID == "" {
		fileID = utils.FixAndCleanPath(leafPath)
	}
	provider := strings.TrimSpace(storage.Config().Name)
	if provider == "" {
		provider = strings.TrimSpace(storage.GetStorage().Driver)
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

func verifyLinkAPITicket(ticket string) (*linkAPIVerifiedTicket, error) {
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
	if claims.Version != linkAPITicketVersion || claims.ExpiresAt <= 0 || claims.IssuedAt <= 0 || claims.IssuanceID == "" || len(claims.RequestedPath) == 0 || len(claims.RequestedPath) > maxLinkAPIPath || len(claims.MountPath) == 0 || len(claims.MountPath) > maxLinkAPIPath || len(claims.LeafPath) == 0 || len(claims.LeafPath) > maxLinkAPIPath || len(claims.Provider) == 0 || len(claims.Provider) > maxLinkAPIName || len(claims.FileID) == 0 || len(claims.FileID) > maxLinkAPIFileID || len(claims.AccountName) > maxLinkAPIName || len(claims.TrialID) > maxLinkAPIEventID {
		return nil, invalidLinkAPIRequest("ticket claims are invalid")
	}
	signer, err := downloadAuthorizationSigner()
	if err != nil {
		return nil, err
	}
	if err := signer.Verify(string(payload), parts[1]); err != nil {
		return nil, invalidLinkAPIRequest("ticket is invalid or expired")
	}
	if claims.ExpiresAt < time.Now().Unix() {
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
	if feedback == nil {
		return nil, invalidLinkAPIRequest("feedback is required")
	}
	if strings.TrimSpace(feedback.EventID) == "" || len(feedback.EventID) > maxLinkAPIEventID {
		return nil, invalidLinkAPIRequest("feedback event_id is empty or exceeds %d characters", maxLinkAPIEventID)
	}
	if len(feedback.Reason) > maxLinkAPIReason {
		return nil, invalidLinkAPIRequest("feedback reason exceeds %d characters", maxLinkAPIReason)
	}
	switch feedback.Outcome {
	case "success", "failure", "abandoned":
	default:
		return nil, invalidLinkAPIRequest("feedback outcome is invalid")
	}
	if feedback.StatusCode < 0 || feedback.StatusCode > 599 {
		return nil, invalidLinkAPIRequest("feedback status_code is invalid")
	}
	if feedback.Outcome == "success" && (feedback.StatusCode < 200 || feedback.StatusCode >= 300) {
		return nil, invalidLinkAPIRequest("successful feedback requires a 2xx status_code")
	}
	return verifyLinkAPITicket(feedback.Ticket)
}

func ticketToExclusion(claims linkAPITicketClaims) driver.DownloadAuthorizationExclusion {
	return driver.DownloadAuthorizationExclusion{
		Provider:             claims.Provider,
		MountPath:            claims.MountPath,
		LeafPath:             claims.LeafPath,
		FileID:               claims.FileID,
		AccountName:          claims.AccountName,
		Generation:           claims.Generation,
		TrialID:              claims.TrialID,
		CredentialGeneration: claims.CredentialGeneration,
	}
}

func ticketToFeedback(claims linkAPITicketClaims, feedback *model.DownloadFeedback) driver.DownloadAuthorizationFeedback {
	return driver.DownloadAuthorizationFeedback{
		Provider:             claims.Provider,
		MountPath:            claims.MountPath,
		LeafPath:             claims.LeafPath,
		FileID:               claims.FileID,
		AccountName:          claims.AccountName,
		Generation:           claims.Generation,
		TrialID:              claims.TrialID,
		CredentialGeneration: claims.CredentialGeneration,
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
	authorizer, ok := target.storage.(driver.DownloadAuthorizer)
	if !ok {
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
	_, _ = authorizer.ReportDownloadAuthorization(cleanupCtx, driver.DownloadAuthorizationReport{
		Provider:             provider,
		MountPath:            mountPath,
		LeafPath:             leafPath,
		FileID:               fileID,
		AccountName:          result.AccountName,
		Generation:           result.Generation,
		TrialID:              result.TrialID,
		CredentialGeneration: result.CredentialGeneration,
		EventID:              "abandoned-" + uuid.NewString(),
		Outcome:              "abandoned",
	})
}
