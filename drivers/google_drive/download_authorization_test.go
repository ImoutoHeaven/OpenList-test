package google_drive

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/OpenListTeam/OpenList/v4/drivers/base"
	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/stretchr/testify/require"
)

func TestGoogleDriveAcquireDownloadAuthorizationConstructsMediaURLWithoutMetadataPreflight(t *testing.T) {
	resetGoogleDriveQuotaAuthorityForTests()
	d := newAccountsJSONDriverWithTokens([]string{"token-0"})
	oldClient := base.RestyClient
	base.RestyClient = newTestRestyClient().SetTransport(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("unexpected Google request during authorization")
	}))
	t.Cleanup(func() { base.RestyClient = oldClient })

	result, err := d.AcquireDownloadAuthorization(context.Background(), driver.DownloadAuthorizationRequest{
		AuthorityProtocol: model.DownloadAuthorityProtocol,
		FileID:            "file-123",
		File:              &model.Object{ID: "file-123", Size: 42},
	})
	require.NoError(t, err)
	require.Equal(t, "https://www.googleapis.com/drive/v3/files/file-123?includeItemsFromAllDrives=true&supportsAllDrives=true&alt=media&acknowledgeAbuse=true", result.Link.URL)
	require.Equal(t, "Bearer token-0", result.Link.Header.Get("Authorization"))
	require.True(t, result.ReportSuccess)
}

func TestGoogleDriveAcquireDownloadAuthorizationRefreshesExpiredCredentialOnceConcurrently(t *testing.T) {
	resetGoogleDriveQuotaAuthorityForTests()
	d := newAccountsJSONDriverWithTokens([]string{"expired-token"})
	d.accounts[0].Token.Expiry = time.Now().Add(-time.Minute).Format(time.RFC3339)

	var refreshCalls atomic.Int32
	oldClient := base.RestyClient
	base.RestyClient = newTestRestyClient().SetTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != "https://www.googleapis.com/oauth2/v4/token" {
			return nil, fmt.Errorf("unexpected Google request: %s", req.URL)
		}
		refreshCalls.Add(1)
		return newHTTPResponse(http.StatusOK, `{"access_token":"fresh-token","expires_in":3600}`, map[string]string{"Content-Type": "application/json"}), nil
	}))
	t.Cleanup(func() { base.RestyClient = oldClient })

	const calls = 8
	results := make(chan driver.DownloadAuthorizationResult, calls)
	errs := make(chan error, calls)
	var wg sync.WaitGroup
	for i := 0; i < calls; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := d.AcquireDownloadAuthorization(context.Background(), driver.DownloadAuthorizationRequest{
				AuthorityProtocol: model.DownloadAuthorityProtocol,
				FileID:            "file-123",
				File:              &model.Object{ID: "file-123", Size: 42},
			})
			if err != nil {
				errs <- err
				return
			}
			results <- result
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		t.Fatalf("authorization failed: %v", err)
	}
	require.Equal(t, int32(1), refreshCalls.Load())
	for result := range results {
		require.Equal(t, "Bearer fresh-token", result.Link.Header.Get("Authorization"))
	}
	require.False(t, tokenExpiresSoon(d.accounts[0].Token.Expiry, time.Now()))
}

func TestGoogleDriveSingletonMetadata401UsesSharedCredentialInstallAndExpiry(t *testing.T) {
	d := &GoogleDrive{
		Storage: model.Storage{MountPath: "/singleton-metadata"},
		Addition: Addition{
			RefreshToken: "refresh-token",
			ClientID:     "client-id",
			ClientSecret: "client-secret",
		},
		AccessToken: "stale-token",
	}
	var metadataCalls atomic.Int32
	var refreshCalls atomic.Int32
	oldClient := base.RestyClient
	base.RestyClient = newTestRestyClient().SetTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.String() {
		case "https://www.googleapis.com/oauth2/v4/token":
			refreshCalls.Add(1)
			return newHTTPResponse(http.StatusOK, `{"access_token":"repaired-token","expires_in":3600}`, map[string]string{"Content-Type": "application/json"}), nil
		default:
			if req.URL.Host != "www.googleapis.com" || !strings.Contains(req.URL.Path, "/drive/v3/files/") {
				return nil, fmt.Errorf("unexpected Google request: %s", req.URL)
			}
			if metadataCalls.Add(1) == 1 {
				return newHTTPResponse(http.StatusUnauthorized, `{"error":{"code":401}}`, map[string]string{"Content-Type": "application/json"}), nil
			}
			return newHTTPResponse(http.StatusOK, `{}`, map[string]string{"Content-Type": "application/json"}), nil
		}
	}))
	t.Cleanup(func() { base.RestyClient = oldClient })

	link, err := d.Link(context.Background(), &model.Object{ID: "file-1", Name: "file-1"}, model.LinkArgs{})
	require.NoError(t, err)
	require.Equal(t, "Bearer repaired-token", link.Header.Get("Authorization"))
	require.Equal(t, int32(1), refreshCalls.Load())
	require.Equal(t, uint64(2), d.singleCredentialGeneration)
	require.False(t, tokenExpiresSoon(d.singleTokenExpiry, time.Now()))

	_, err = d.AcquireDownloadAuthorization(context.Background(), driver.DownloadAuthorizationRequest{
		AuthorityProtocol: model.DownloadAuthorityProtocol,
		FileID:            "file-1",
		File:              &model.Object{ID: "file-1", Size: 1},
	})
	require.NoError(t, err)
	require.Equal(t, int32(1), refreshCalls.Load())
}

func TestGoogleDriveSingletonOrdinaryFeedbackReusesOriginalAccount(t *testing.T) {
	resetGoogleDriveQuotaAuthorityForTests()
	d := &GoogleDrive{
		Storage:     model.Storage{MountPath: "/singleton-feedback"},
		AccessToken: "singleton-token",
	}

	request := driver.DownloadAuthorizationRequest{
		AuthorityProtocol: model.DownloadAuthorityProtocol,
		FileID:            "file-1",
		File:              &model.Object{ID: "file-1", Size: 1},
	}
	first, err := d.AcquireDownloadAuthorization(context.Background(), request)
	require.NoError(t, err)
	require.Equal(t, "singleton:/singleton-feedback", first.AccountName)

	feedback := &driver.DownloadAuthorizationFeedback{
		AuthorityProtocol: model.DownloadAuthorityProtocol,
		Ticket:            "singleton-feedback-ticket",
		Provider:          googleDriveAccountProvider,
		AccountName:       first.AccountName,
		FileID:            first.FileID,
		Generation:        first.Generation,
		FileGeneration:    first.FileGeneration,
		ObservationID:     first.ObservationID,
		EventType:         "failure",
		EventID:           driver.CanonicalDownloadAuthorizationEventID(first.ObservationID, "failure"),
		Outcome:           "failure",
		StatusCode:        http.StatusBadGateway,
		Reason:            "upstream connection failed",
	}
	replacement, err := d.AcquireDownloadAuthorization(context.Background(), driver.DownloadAuthorizationRequest{
		AuthorityProtocol: model.DownloadAuthorityProtocol,
		FileID:            request.FileID,
		File:              request.File,
		Feedback:          feedback,
	})
	require.NoError(t, err)
	require.Equal(t, first.AccountName, replacement.AccountName)
	require.Equal(t, "Bearer singleton-token", replacement.Link.Header.Get("Authorization"))
}

func TestGoogleDriveJSONL401RepairIgnoresValidExpiryFastPathAndFencesOldGeneration(t *testing.T) {
	resetGoogleDriveQuotaAuthorityForTests()
	d := newAccountsJSONDriverWithTokens([]string{"stale-token"})
	d.accounts[0].Token.Expiry = time.Now().Add(time.Hour).Format(time.RFC3339)
	d.accountPool = newAccountPool("round_robin", d.accounts)
	first, err := d.AcquireDownloadAuthorization(context.Background(), driver.DownloadAuthorizationRequest{
		AuthorityProtocol: model.DownloadAuthorityProtocol,
		FileID:            "file-1",
		File:              &model.Object{ID: "file-1", Size: 1},
	})
	require.NoError(t, err)
	feedback := driver.DownloadAuthorizationFeedback{
		AuthorityProtocol:    model.DownloadAuthorityProtocol,
		Ticket:               "jsonl-401-ticket",
		Provider:             googleDriveAccountProvider,
		AccountName:          first.AccountName,
		FileID:               "file-1",
		Generation:           first.Generation,
		FileGeneration:       first.FileGeneration,
		CredentialGeneration: first.CredentialGeneration,
		ObservationID:        "jsonl-401-observation",
		EventType:            "failure",
		EventID:              driver.CanonicalDownloadAuthorizationEventID("jsonl-401-observation", "failure"),
		Outcome:              "failure",
		StatusCode:           http.StatusUnauthorized,
	}
	_, err = d.ReportDownloadAuthorization(context.Background(), driver.DownloadAuthorizationReport(feedback))
	require.NoError(t, err)

	var refreshCalls atomic.Int32
	oldClient := base.RestyClient
	base.RestyClient = newTestRestyClient().SetTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != "https://www.googleapis.com/oauth2/v4/token" {
			return nil, fmt.Errorf("unexpected Google request: %s", req.URL)
		}
		refreshCalls.Add(1)
		return newHTTPResponse(http.StatusOK, `{"access_token":"repaired-token","expires_in":3600}`, map[string]string{"Content-Type": "application/json"}), nil
	}))
	t.Cleanup(func() { base.RestyClient = oldClient })

	d.accountPool = newAccountPool("round_robin", d.accounts)
	repaired, err := d.AcquireDownloadAuthorization(context.Background(), driver.DownloadAuthorizationRequest{
		AuthorityProtocol: model.DownloadAuthorityProtocol,
		FileID:            "file-1",
		File:              &model.Object{ID: "file-1", Size: 1},
	})
	require.NoError(t, err)
	require.Equal(t, "Bearer repaired-token", repaired.Link.Header.Get("Authorization"))
	require.Equal(t, uint64(2), repaired.CredentialGeneration)
	require.Equal(t, int32(1), refreshCalls.Load())

	_, err = d.ReportDownloadAuthorization(context.Background(), driver.DownloadAuthorizationReport{
		AuthorityProtocol:    model.DownloadAuthorityProtocol,
		Ticket:               "jsonl-old-401-ticket",
		Provider:             googleDriveAccountProvider,
		AccountName:          first.AccountName,
		FileID:               "file-1",
		Generation:           first.Generation,
		FileGeneration:       first.FileGeneration,
		CredentialGeneration: first.CredentialGeneration,
		ObservationID:        "jsonl-old-401-observation",
		EventType:            "failure",
		EventID:              driver.CanonicalDownloadAuthorizationEventID("jsonl-old-401-observation", "failure"),
		Outcome:              "failure",
		StatusCode:           http.StatusUnauthorized,
	})
	require.NoError(t, err)
	d.accountPool = newAccountPool("round_robin", d.accounts)
	latest, err := d.AcquireDownloadAuthorization(context.Background(), driver.DownloadAuthorizationRequest{
		AuthorityProtocol: model.DownloadAuthorityProtocol,
		FileID:            "file-1",
		File:              &model.Object{ID: "file-1", Size: 1},
	})
	require.NoError(t, err)
	require.Equal(t, "Bearer repaired-token", latest.Link.Header.Get("Authorization"))
	require.Equal(t, int32(1), refreshCalls.Load())
}

func TestGoogleDriveUnavailablePoolUsesEarliestPositiveDelay(t *testing.T) {
	resetGoogleDriveQuotaAuthorityForTests()
	clock := &quotaTestClock{now: time.Unix(1_700_000_000, 0)}
	sharedQuotaAuthority.mu.Lock()
	sharedQuotaAuthority.durable = false
	sharedQuotaAuthority.now = clock.Now
	sharedQuotaAuthority.getAccountLocked("delay-account-0").BackoffUntil = clock.Now().Add(30 * time.Second)
	sharedQuotaAuthority.getAccountLocked("delay-account-1").BackoffUntil = clock.Now().Add(60 * time.Second)
	sharedQuotaAuthority.mu.Unlock()
	t.Cleanup(func() {
		sharedQuotaAuthority.mu.Lock()
		sharedQuotaAuthority.durable = true
		sharedQuotaAuthority.now = time.Now
		sharedQuotaAuthority.mu.Unlock()
		resetGoogleDriveQuotaAuthorityForTests()
	})
	d := newAccountsJSONDriverWithTokens([]string{"token-0", "token-1"})
	d.accounts[0].Name = "delay-account-0"
	d.accounts[1].Name = "delay-account-1"
	d.accountPool = newAccountPool("round_robin", d.accounts)
	_, err := d.AcquireDownloadAuthorization(context.Background(), driver.DownloadAuthorizationRequest{
		AuthorityProtocol: model.DownloadAuthorityProtocol,
		FileID:            "target-file",
		File:              &model.Object{ID: "target-file", Size: 1},
	})
	var unavailable *driver.DownloadAuthorizationUnavailableError
	require.ErrorAs(t, err, &unavailable)
	require.Equal(t, 30*time.Second, unavailable.RetryAfter)
}
