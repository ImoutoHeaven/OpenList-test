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
	if request.AuthorityProtocol != model.DownloadAuthorityProtocol {
		return driver.DownloadAuthorizationResult{}, fmt.Errorf("google_drive: authority_protocol must be %d", model.DownloadAuthorityProtocol)
	}
	return d.acquireQuotaAuthorityAuthorization(ctx, request)
}

func googleDownloadAuthorizationResult(request driver.DownloadAuthorizationRequest, account accountSnapshot) driver.DownloadAuthorizationResult {
	accessToken := account.Token.AccessToken
	expiresAt := tokenExpiry(account.Token.Expiry)
	if expiresAt.IsZero() {
		expiresAt = time.Now().Add(googleDownloadDefaultLifetime)
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
		Generation:           1,
		CredentialGeneration: account.CredentialGeneration,
		ReportSuccess:        request.Feedback != nil,
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

func (d *GoogleDrive) ReportDownloadAuthorization(ctx context.Context, report driver.DownloadAuthorizationReport) (driver.DownloadAuthorizationReportResult, error) {
	if report.AuthorityProtocol != model.DownloadAuthorityProtocol {
		return driver.DownloadAuthorizationReportResult{}, fmt.Errorf("google_drive: authority_protocol must be %d", model.DownloadAuthorityProtocol)
	}
	return d.reportQuotaAuthority(ctx, report)
}

var _ driver.DownloadAuthorizer = (*GoogleDrive)(nil)
