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
	d := newAccountsJSONDriverWithTokens([]string{"token-0"})
	oldClient := base.RestyClient
	base.RestyClient = newTestRestyClient().SetTransport(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("unexpected Google request during authorization")
	}))
	t.Cleanup(func() { base.RestyClient = oldClient })

	result, err := d.AcquireDownloadAuthorization(context.Background(), driver.DownloadAuthorizationRequest{
		FileID: "file-123",
		File:   &model.Object{ID: "file-123", Size: 42},
	})
	require.NoError(t, err)
	require.Equal(t, "https://www.googleapis.com/drive/v3/files/file-123?includeItemsFromAllDrives=true&supportsAllDrives=true&alt=media&acknowledgeAbuse=true", result.Link.URL)
	require.Equal(t, "Bearer token-0", result.Link.Header.Get("Authorization"))
	require.False(t, result.ReportSuccess)
}

func TestGoogleDriveAcquireDownloadAuthorizationCarriesTheSelectedHealthLease(t *testing.T) {
	clock := &accountHealthTestClock{now: time.Now()}
	health := newAccountHealthRuntime(clock.Now)
	initial, err := health.acquire(context.Background(), "account-0", "seed-file")
	require.NoError(t, err)
	failure, err := health.report(context.Background(), AccountHealthReportInput{
		AccountName: "account-0",
		FileID:      "quota-file",
		EventID:     "quota-event",
		Outcome:     AccountHealthFailure,
		StatusCode:  http.StatusForbidden,
		Reason:      "downloadQuotaExceeded",
		Generation:  initial.Generation,
	})
	require.NoError(t, err)
	clock.Advance(failure.RetryAfter)

	d := newAccountsJSONDriverWithTokens([]string{"token-0"})
	d.accountHealth = health
	result, err := d.AcquireDownloadAuthorization(context.Background(), driver.DownloadAuthorizationRequest{
		FileID: "trial-file",
		File:   &model.Object{ID: "trial-file", Size: 42},
	})
	require.NoError(t, err)
	require.Equal(t, "account-0", result.AccountName)
	require.Equal(t, initial.Generation, result.Generation)
	require.NotEmpty(t, result.TrialID)
	require.True(t, result.ReportSuccess)
	require.WithinDuration(t, clock.Now().Add(180*time.Second), result.ExpiresAt, time.Second)
}

func TestGoogleDriveAcquireDownloadAuthorizationRefreshesExpiredCredentialOnceConcurrently(t *testing.T) {
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
				FileID: "file-123",
				File:   &model.Object{ID: "file-123", Size: 42},
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

func TestGoogleDriveSingleton401RepairHonorsExclusionsAndFencesOlderCredentialReports(t *testing.T) {
	d := &GoogleDrive{
		Storage: model.Storage{MountPath: "/singleton"},
		Addition: Addition{
			RefreshToken: "refresh-token",
			ClientID:     "client-id",
			ClientSecret: "client-secret",
		},
		AccessToken: "stale-token",
	}
	d.modeCfg = downloadModeConfig{}
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

	request := driver.DownloadAuthorizationRequest{
		MountPath: "/singleton",
		LeafPath:  "/singleton/file.bin",
		FileID:    "file-1",
		File:      &model.Object{ID: "file-1", Size: 1},
	}
	first, err := d.AcquireDownloadAuthorization(context.Background(), request)
	require.NoError(t, err)
	require.Equal(t, uint64(1), first.CredentialGeneration)

	_, err = d.ReportDownloadAuthorization(context.Background(), driver.DownloadAuthorizationReport{
		Provider:             googleDriveAccountProvider,
		MountPath:            "/singleton",
		LeafPath:             "/singleton/file.bin",
		FileID:               "file-1",
		CredentialGeneration: first.CredentialGeneration,
		EventID:              "singleton-401",
		Outcome:              string(AccountHealthFailure),
		StatusCode:           http.StatusUnauthorized,
	})
	require.NoError(t, err)

	request.Exclude = []driver.DownloadAuthorizationExclusion{{
		MountPath: "/singleton",
		LeafPath:  "/singleton/file.bin",
		FileID:    "file-1",
	}}
	_, err = d.AcquireDownloadAuthorization(context.Background(), request)
	var unavailable *driver.DownloadAuthorizationUnavailableError
	require.ErrorAs(t, err, &unavailable)
	require.Equal(t, int32(0), refreshCalls.Load(), "excluded singleton must not refresh and retry")

	request.Exclude = nil
	repaired, err := d.AcquireDownloadAuthorization(context.Background(), request)
	require.NoError(t, err)
	require.Equal(t, "Bearer fresh-token", repaired.Link.Header.Get("Authorization"))
	require.Equal(t, uint64(2), repaired.CredentialGeneration)
	require.Equal(t, int32(1), refreshCalls.Load())

	_, err = d.ReportDownloadAuthorization(context.Background(), driver.DownloadAuthorizationReport{
		Provider:             googleDriveAccountProvider,
		MountPath:            "/singleton",
		LeafPath:             "/singleton/file.bin",
		FileID:               "file-1",
		CredentialGeneration: first.CredentialGeneration,
		EventID:              "singleton-old-401",
		Outcome:              string(AccountHealthFailure),
		StatusCode:           http.StatusUnauthorized,
	})
	require.NoError(t, err)
	latest, err := d.AcquireDownloadAuthorization(context.Background(), request)
	require.NoError(t, err)
	require.Equal(t, "Bearer fresh-token", latest.Link.Header.Get("Authorization"))
	require.Equal(t, int32(1), refreshCalls.Load(), "old credential report must not invalidate the repaired credential")
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

	_, err = d.ReportDownloadAuthorization(context.Background(), driver.DownloadAuthorizationReport{
		Provider:             googleDriveAccountProvider,
		MountPath:            "/singleton-metadata",
		LeafPath:             "/singleton-metadata/file-1",
		FileID:               "file-1",
		CredentialGeneration: 1,
		EventID:              "old-metadata-401",
		Outcome:              string(AccountHealthFailure),
		StatusCode:           http.StatusUnauthorized,
	})
	require.NoError(t, err)
	_, err = d.AcquireDownloadAuthorization(context.Background(), driver.DownloadAuthorizationRequest{
		FileID: "file-1",
		File:   &model.Object{ID: "file-1", Size: 1},
	})
	require.NoError(t, err)
	require.Equal(t, int32(1), refreshCalls.Load())
}

func TestGoogleDriveJSONLFeedbackSelectsDifferentAccountAndDuplicateReportIsIdempotent(t *testing.T) {
	clock := &accountHealthTestClock{now: time.Now()}
	d := newAccountsJSONDriverWithTokens([]string{"token-0", "token-1"})
	d.accounts[0].Name = "jsonl-test-account-0"
	d.accounts[1].Name = "jsonl-test-account-1"
	d.accountPool = newAccountPool("round_robin", d.accounts)
	d.accountHealth = newAccountHealthRuntime(clock.Now)

	first, err := d.AcquireDownloadAuthorization(context.Background(), driver.DownloadAuthorizationRequest{
		FileID: "file-1",
		File:   &model.Object{ID: "file-1", Size: 1},
	})
	require.NoError(t, err)
	require.Contains(t, []string{"jsonl-test-account-0", "jsonl-test-account-1"}, first.AccountName)
	feedback := driver.DownloadAuthorizationFeedback{
		Provider:             googleDriveAccountProvider,
		AccountName:          first.AccountName,
		FileID:               "file-1",
		Generation:           first.Generation,
		CredentialGeneration: first.CredentialGeneration,
		EventID:              "quota-file-1",
		Outcome:              string(AccountHealthFailure),
		StatusCode:           http.StatusForbidden,
		Reason:               "downloadQuotaExceeded",
	}
	replacement, err := d.AcquireDownloadAuthorization(context.Background(), driver.DownloadAuthorizationRequest{
		FileID:   "file-1",
		File:     &model.Object{ID: "file-1", Size: 1},
		Exclude:  []driver.DownloadAuthorizationExclusion{{AccountName: first.AccountName}},
		Feedback: &feedback,
	})
	require.NoError(t, err)
	require.NotEqual(t, first.AccountName, replacement.AccountName)
	require.True(t, replacement.ReportSuccess)

	duplicate, err := d.ReportDownloadAuthorization(context.Background(), driver.DownloadAuthorizationReport(feedback))
	require.NoError(t, err)
	require.True(t, duplicate.Duplicate)
}

func TestGoogleDriveJSONL401RepairIgnoresValidExpiryFastPathAndFencesOldGeneration(t *testing.T) {
	d := newAccountsJSONDriverWithTokens([]string{"stale-token"})
	d.accounts[0].Token.Expiry = time.Now().Add(time.Hour).Format(time.RFC3339)
	d.accountPool = newAccountPool("round_robin", d.accounts)
	first, err := d.AcquireDownloadAuthorization(context.Background(), driver.DownloadAuthorizationRequest{
		FileID: "file-1",
		File:   &model.Object{ID: "file-1", Size: 1},
	})
	require.NoError(t, err)
	feedback := driver.DownloadAuthorizationFeedback{
		Provider:             googleDriveAccountProvider,
		AccountName:          first.AccountName,
		FileID:               "file-1",
		Generation:           first.Generation,
		CredentialGeneration: first.CredentialGeneration,
		EventID:              "jsonl-401",
		Outcome:              string(AccountHealthFailure),
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
		FileID: "file-1",
		File:   &model.Object{ID: "file-1", Size: 1},
	})
	require.NoError(t, err)
	require.Equal(t, "Bearer repaired-token", repaired.Link.Header.Get("Authorization"))
	require.Equal(t, uint64(2), repaired.CredentialGeneration)
	require.Equal(t, int32(1), refreshCalls.Load())

	_, err = d.ReportDownloadAuthorization(context.Background(), driver.DownloadAuthorizationReport{
		Provider:             googleDriveAccountProvider,
		AccountName:          first.AccountName,
		FileID:               "file-1",
		Generation:           first.Generation,
		CredentialGeneration: first.CredentialGeneration,
		EventID:              "jsonl-old-401",
		Outcome:              string(AccountHealthFailure),
		StatusCode:           http.StatusUnauthorized,
	})
	require.NoError(t, err)
	d.accountPool = newAccountPool("round_robin", d.accounts)
	latest, err := d.AcquireDownloadAuthorization(context.Background(), driver.DownloadAuthorizationRequest{
		FileID: "file-1",
		File:   &model.Object{ID: "file-1", Size: 1},
	})
	require.NoError(t, err)
	require.Equal(t, "Bearer repaired-token", latest.Link.Header.Get("Authorization"))
	require.Equal(t, int32(1), refreshCalls.Load())
}

func TestGoogleDriveUnavailablePoolUsesEarliestPositiveDelay(t *testing.T) {
	clock := &accountHealthTestClock{now: time.Now()}
	health := newAccountHealthRuntime(clock.Now)
	for index, accountName := range []string{"delay-account-0", "delay-account-1"} {
		state, err := health.get(accountName)
		require.NoError(t, err)
		state.mu.Lock()
		state.probeRequired = true
		state.backoffUntil = clock.Now().Add(time.Duration(30+30*index) * time.Second)
		state.mu.Unlock()
	}
	state, err := health.get("delay-account-1")
	require.NoError(t, err)
	state.mu.Lock()
	state.backoffUntil = clock.Now().Add(60 * time.Second)
	state.mu.Unlock()

	d := newAccountsJSONDriverWithTokens([]string{"token-0", "token-1"})
	d.accounts[0].Name = "delay-account-0"
	d.accounts[1].Name = "delay-account-1"
	d.accountPool = newAccountPool("round_robin", d.accounts)
	d.accountHealth = health
	_, err = d.AcquireDownloadAuthorization(context.Background(), driver.DownloadAuthorizationRequest{
		FileID: "target-file",
		File:   &model.Object{ID: "target-file", Size: 1},
	})
	var unavailable *driver.DownloadAuthorizationUnavailableError
	require.ErrorAs(t, err, &unavailable)
	require.Equal(t, 30*time.Second, unavailable.RetryAfter)
}
