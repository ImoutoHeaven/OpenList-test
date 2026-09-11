package google_drive

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
)

const (
	googleDownloadTokenSafetyWindow = 30 * time.Second
	googleDownloadDefaultLifetime   = time.Hour
)

// AcquireDownloadAuthorization issues a media URL from the resolved Google
// file ID. It deliberately does not call the metadata endpoint or preflight
// the content URL.
func (d *GoogleDrive) AcquireDownloadAuthorization(ctx context.Context, request driver.DownloadAuthorizationRequest) (driver.DownloadAuthorizationResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if request.File == nil || strings.TrimSpace(request.FileID) == "" {
		return driver.DownloadAuthorizationResult{}, fmt.Errorf("google_drive: download file identity is empty")
	}
	if !d.modeCfg.Enabled {
		if request.Feedback != nil {
			d.invalidateSingletonCredential(*request.Feedback)
		}
		if singletonDownloadExcluded(request, d.GetStorage().MountPath) {
			return driver.DownloadAuthorizationResult{}, &driver.DownloadAuthorizationUnavailableError{Reason: "google_drive: singleton account was already tried", RetryAfter: time.Second}
		}
		account, err := d.ensureUsableSingletonAccount(ctx)
		if err != nil {
			return driver.DownloadAuthorizationResult{}, err
		}
		return googleDownloadAuthorizationResult(request, account, AccountHealthLease{}), nil
	}

	d.accountStateMu.Lock()
	accountCount := len(d.accounts)
	if d.accountPool == nil {
		d.accountPool = newAccountPool(d.modeCfg.SelectionPolicy, d.accounts)
	}
	pool := d.accountPool
	d.accountStateMu.Unlock()
	if accountCount == 0 {
		return driver.DownloadAuthorizationResult{}, &driver.DownloadAuthorizationUnavailableError{Reason: "google_drive: accounts_json has no usable accounts", RetryAfter: time.Second}
	}
	order := pool.nextDownloadAttemptOrder(accountCount)
	if len(order) == 0 {
		return driver.DownloadAuthorizationResult{}, &driver.DownloadAuthorizationUnavailableError{Reason: "google_drive: accounts_json has no usable accounts", RetryAfter: time.Second}
	}
	excluded := make(map[string]struct{}, len(request.Exclude))
	for _, item := range request.Exclude {
		if name := strings.TrimSpace(item.AccountName); name != "" {
			excluded[name] = struct{}{}
		}
	}
	if request.Feedback != nil {
		if err := d.reportDownloadFeedback(ctx, *request.Feedback); err != nil {
			return driver.DownloadAuthorizationResult{}, err
		}
	}

	var lastErr error
	var retryAfter time.Duration
	for _, index := range order {
		account, err := d.accountSnapshot(index)
		if err != nil {
			lastErr = err
			continue
		}
		if _, skip := excluded[account.Name]; skip {
			continue
		}
		account, err = d.ensureUsableDownloadAccount(ctx, index, account)
		if err != nil {
			lastErr = err
			continue
		}
		selection, err := d.acquireDownloadAccount(ctx, request.FileID, index)
		if err != nil {
			lastErr = err
			if unavailable, ok := err.(interface{ RetryAfterDuration() time.Duration }); ok {
				if wait := unavailable.RetryAfterDuration(); wait > 0 && (retryAfter == 0 || wait < retryAfter) {
					retryAfter = wait
				}
			}
			continue
		}
		return googleDownloadAuthorizationResult(request, selection.account, selection.health), nil
	}

	if retryAfter > 0 {
		return driver.DownloadAuthorizationResult{}, &driver.DownloadAuthorizationUnavailableError{Reason: "google_drive: all download accounts are cooling down", RetryAfter: retryAfter}
	}
	if lastErr != nil {
		return driver.DownloadAuthorizationResult{}, &driver.DownloadAuthorizationUnavailableError{Reason: "google_drive: no usable Google Drive download account: " + lastErr.Error(), RetryAfter: time.Second}
	}
	return driver.DownloadAuthorizationResult{}, &driver.DownloadAuthorizationUnavailableError{Reason: "google_drive: all requested download accounts were excluded", RetryAfter: time.Second}
}

func singletonDownloadExcluded(request driver.DownloadAuthorizationRequest, mountPath string) bool {
	mountPath = utils.FixAndCleanPath(mountPath)
	for _, exclusion := range request.Exclude {
		if exclusion.AccountName == "" && utils.FixAndCleanPath(exclusion.MountPath) == mountPath && exclusion.FileID == request.FileID {
			return true
		}
	}
	return false
}

func googleDownloadAuthorizationResult(request driver.DownloadAuthorizationRequest, account accountSnapshot, health AccountHealthLease) driver.DownloadAuthorizationResult {
	accessToken := account.Token.AccessToken
	expiresAt := tokenExpiry(account.Token.Expiry)
	if expiresAt.IsZero() {
		expiresAt = time.Now().Add(googleDownloadDefaultLifetime)
	}
	if !health.ExpiresAt.IsZero() && health.ExpiresAt.Before(expiresAt) {
		expiresAt = health.ExpiresAt
	}
	return driver.DownloadAuthorizationResult{
		Link: &model.Link{
			URL: fmt.Sprintf("https://www.googleapis.com/drive/v3/files/%s?includeItemsFromAllDrives=true&supportsAllDrives=true&alt=media&acknowledgeAbuse=true", url.PathEscape(request.FileID)),
			Header: http.Header{
				"Authorization": []string{"Bearer " + accessToken},
			},
		},
		Provider:             googleDriveAccountProvider,
		FileID:               request.FileID,
		AccountName:          account.Name,
		Generation:           health.Generation,
		TrialID:              health.TrialID,
		CredentialGeneration: account.CredentialGeneration,
		ReportSuccess:        health.Trial || request.Feedback != nil || len(request.Exclude) > 0,
		ExpiresAt:            expiresAt,
	}
}

func (d *GoogleDrive) ensureUsableDownloadAccount(ctx context.Context, index int, account accountSnapshot) (accountSnapshot, error) {
	if strings.TrimSpace(account.Token.AccessToken) == "" || tokenExpiresSoon(account.Token.Expiry, time.Now()) || account.InvalidCredentialGeneration == account.CredentialGeneration {
		if err := d.refreshAccountIfNeeded(ctx, index); err != nil {
			return accountSnapshot{}, err
		}
		return d.accountSnapshot(index)
	}
	return account, nil
}

func (d *GoogleDrive) ensureUsableSingletonAccount(ctx context.Context) (accountSnapshot, error) {
	if err := d.refreshTokenIfNeededWithContext(ctx); err != nil {
		return accountSnapshot{}, err
	}
	d.accountStateMu.RLock()
	accessToken := d.AccessToken
	generation := max(d.singleCredentialGeneration, 1)
	tokenExpiryValue := d.singleTokenExpiry
	d.accountStateMu.RUnlock()
	return accountSnapshot{
		Token:                oauthTokenView{AccessToken: accessToken, Expiry: tokenExpiryValue},
		CredentialGeneration: generation,
	}, nil
}

func (d *GoogleDrive) invalidateJSONCredential(feedback driver.DownloadAuthorizationFeedback) {
	if feedback.StatusCode != http.StatusUnauthorized || feedback.AccountName == "" || feedback.CredentialGeneration == 0 {
		return
	}
	d.accountStateMu.Lock()
	defer d.accountStateMu.Unlock()
	for index := range d.accounts {
		account := &d.accounts[index]
		generation := max(account.CredentialGeneration, 1)
		if account.Name == feedback.AccountName && feedback.CredentialGeneration == generation {
			account.InvalidCredentialGeneration = generation
			return
		}
	}
}

func (d *GoogleDrive) invalidateSingletonCredential(feedback driver.DownloadAuthorizationFeedback) {
	if feedback.StatusCode != http.StatusUnauthorized || feedback.CredentialGeneration == 0 {
		return
	}
	d.accountStateMu.Lock()
	generation := max(d.singleCredentialGeneration, 1)
	if feedback.CredentialGeneration == generation {
		d.singleCredentialGeneration = generation
		d.singleInvalidCredentialGeneration = generation
	}
	d.accountStateMu.Unlock()
}

func (d *GoogleDrive) repairSingletonCredentialWithContext(ctx context.Context) error {
	d.accountStateMu.Lock()
	generation := max(d.singleCredentialGeneration, 1)
	d.singleCredentialGeneration = generation
	d.singleInvalidCredentialGeneration = generation
	d.accountStateMu.Unlock()
	return d.refreshTokenIfNeededWithContext(ctx)
}

func tokenExpiresSoon(raw string, now time.Time) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}
	expiry, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		if seconds, parseErr := strconv.ParseInt(raw, 10, 64); parseErr == nil {
			expiry = time.Unix(seconds, 0)
		} else {
			return false
		}
	}
	return !expiry.After(now.Add(googleDownloadTokenSafetyWindow))
}

func tokenExpiry(raw string) time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}
	}
	if expiry, err := time.Parse(time.RFC3339, raw); err == nil {
		return expiry
	}
	seconds, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return time.Time{}
	}
	return time.Unix(seconds, 0)
}

func (d *GoogleDrive) reportDownloadFeedback(ctx context.Context, feedback driver.DownloadAuthorizationFeedback) error {
	d.invalidateJSONCredential(feedback)
	d.invalidateSingletonCredential(feedback)
	if d.accountHealth == nil || feedback.AccountName == "" {
		return nil
	}
	_, err := d.accountHealth.report(ctx, AccountHealthReportInput{
		AccountName: feedback.AccountName,
		FileID:      feedback.FileID,
		EventID:     feedback.EventID,
		Outcome:     AccountHealthOutcome(feedback.Outcome),
		StatusCode:  feedback.StatusCode,
		Reason:      feedback.Reason,
		Generation:  feedback.Generation,
		TrialID:     feedback.TrialID,
	})
	return err
}

func (d *GoogleDrive) ReportDownloadAuthorization(ctx context.Context, report driver.DownloadAuthorizationReport) (driver.DownloadAuthorizationReportResult, error) {
	d.invalidateJSONCredential(report)
	d.invalidateSingletonCredential(report)
	if d.accountHealth == nil || report.AccountName == "" {
		return driver.DownloadAuthorizationReportResult{Applied: true}, nil
	}
	result, err := d.accountHealth.report(ctx, AccountHealthReportInput{
		AccountName: report.AccountName,
		FileID:      report.FileID,
		EventID:     report.EventID,
		Outcome:     AccountHealthOutcome(report.Outcome),
		StatusCode:  report.StatusCode,
		Reason:      report.Reason,
		Generation:  report.Generation,
		TrialID:     report.TrialID,
	})
	if err != nil {
		return driver.DownloadAuthorizationReportResult{}, err
	}
	return driver.DownloadAuthorizationReportResult{
		Applied:       result.Applied,
		Duplicate:     result.Duplicate,
		Stale:         result.Stale,
		Generation:    result.Generation,
		CooldownUntil: result.CooldownUntil,
		RetryAfter:    result.RetryAfter,
	}, nil
}

var _ driver.DownloadAuthorizer = (*GoogleDrive)(nil)
