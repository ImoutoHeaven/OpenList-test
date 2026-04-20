package google_drive

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/OpenListTeam/OpenList/v4/drivers/base"
	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/internal/db"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/pkg/http_range"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
	"github.com/go-resty/resty/v2"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestGoogleDriveModeConfig_DefaultsAndValidation(t *testing.T) {
	zero := 0

	cfg, err := validateDownloadModeConfig(Addition{RefreshToken: "legacy-refresh"})
	require.NoError(t, err)
	require.False(t, cfg.Enabled)

	_, err = validateDownloadModeConfig(Addition{AccountsJSON: "relative/accounts.json"})
	require.ErrorContains(t, err, "accounts_json must be an absolute path")

	cfg, err = validateDownloadModeConfig(Addition{AccountsJSON: "/tmp/accounts.json"})
	require.NoError(t, err)
	require.True(t, cfg.Enabled)
	require.Equal(t, "round_robin", cfg.SelectionPolicy)
	require.Equal(t, 2, cfg.DownloadRetryMax)

	cfg, err = validateDownloadModeConfig(Addition{AccountsJSON: "/tmp/accounts.json", DownloadRetryMax: &zero})
	require.NoError(t, err)
	require.Equal(t, 0, cfg.DownloadRetryMax)
}

func TestGoogleDriveModeConfig_RejectsNegativeRetryAndUnknownPolicy(t *testing.T) {
	neg := -1
	_, err := validateDownloadModeConfig(Addition{AccountsJSON: "/tmp/accounts.json", DownloadRetryMax: &neg})
	require.ErrorContains(t, err, "download_retry_max")
	_, err = validateDownloadModeConfig(Addition{RefreshToken: "legacy-refresh", DownloadRetryMax: &neg})
	require.ErrorContains(t, err, "download_retry_max")

	_, err = validateDownloadModeConfig(Addition{AccountsJSON: "/tmp/accounts.json", AccountSelectionPolicy: "weighted"})
	require.ErrorContains(t, err, "account_selection_policy")
	_, err = validateDownloadModeConfig(Addition{RefreshToken: "legacy-refresh", AccountSelectionPolicy: "weighted"})
	require.ErrorContains(t, err, "account_selection_policy")
}

func TestGoogleDriveParseAccountsJSON_AcceptsArrayAndJSONL(t *testing.T) {
	arrayPath := writeTempAccountsFile(t, `[{"token":{"access_token":"a","refresh_token":"ra"}}]`)
	arrayAccounts, err := parseAccountsJSON(arrayPath, Addition{})
	require.NoError(t, err)
	require.Len(t, arrayAccounts, 1)

	jsonlPath := writeTempAccountsFile(t, "{\"token\":{\"access_token\":\"a\",\"refresh_token\":\"ra\"}}\n{\"token\":{\"access_token\":\"b\",\"refresh_token\":\"rb\"}}")
	jsonlAccounts, err := parseAccountsJSON(jsonlPath, Addition{})
	require.NoError(t, err)
	require.Len(t, jsonlAccounts, 2)
}

func TestGoogleDriveParseAccountsJSON_RejectsInvalidContent(t *testing.T) {
	_, err := parseAccountsJSON(writeTempAccountsFile(t, "[]"), Addition{})
	require.ErrorContains(t, err, "must not be empty")

	_, err = parseAccountsJSON(writeTempAccountsFile(t, `[{"token":"not-an-object"}]`), Addition{})
	require.ErrorContains(t, err, "token must be a JSON object")

	_, err = parseAccountsJSON(writeTempAccountsFile(t, `[{"token":{}}]`), Addition{})
	require.ErrorContains(t, err, "access_token")

	_, err = parseAccountsJSON(writeTempAccountsFile(t, `[{"token":{"foo":"bar"}}]`), Addition{})
	require.ErrorContains(t, err, "access_token")

	_, err = parseAccountsJSON(writeTempAccountsFile(t, `[{"token":{"access_token":"a","expiry":"invalid-time"}}]`), Addition{})
	require.ErrorContains(t, err, "parseable OAuth token JSON")
}

func TestGoogleDriveParseAccountsJSON_AppliesNameAndCredentialFallbacks(t *testing.T) {
	path := writeTempAccountsFile(t, `[
		{"token":{"access_token":"a","refresh_token":"ra"}},
		{"name":"named","client_id":"entry-id","client_secret":"entry-secret","token":{"access_token":"b","refresh_token":"rb"}}
	]`)
	accounts, err := parseAccountsJSON(path, Addition{ClientID: "driver-id", ClientSecret: "driver-secret"})
	require.NoError(t, err)
	require.Equal(t, "account-0", accounts[0].Name)
	require.Equal(t, "driver-id", accounts[0].ClientID)
	require.Equal(t, "driver-secret", accounts[0].ClientSecret)
	require.Equal(t, "named", accounts[1].Name)
	require.Equal(t, "entry-id", accounts[1].ClientID)
	require.Equal(t, "entry-secret", accounts[1].ClientSecret)
}

func TestGoogleDriveInitAccountsJSONMode_BootstrapsPrimaryAccountToken(t *testing.T) {
	path := writeTempAccountsFile(t, `[
		{"token":{"access_token":"primary-token","refresh_token":"r0"}},
		{"token":{"access_token":"secondary-token","refresh_token":"r1"}}
	]`)

	d := &GoogleDrive{Addition: Addition{AccountsJSON: path}}
	d.modeCfg = downloadModeConfig{
		Enabled:          true,
		AccountsPath:     path,
		SelectionPolicy:  "round_robin",
		DownloadRetryMax: 2,
	}

	require.NoError(t, d.initAccountsJSONMode(context.Background()))
	require.Len(t, d.accounts, 2)
	require.Equal(t, "primary-token", d.AccessToken)
}

func TestGoogleDrivePrimaryAccountRouting_ListUsesIndexZeroToken(t *testing.T) {
	d, authRecorder := newAccountsJSONDriverForRequestTest(t, []string{"primary-token", "secondary-token"})

	_, err := d.getFiles("root")
	require.NoError(t, err)
	require.Equal(t, "Bearer primary-token", authRecorder.LastAuthorization())
}

func TestGoogleDrivePrimaryAccountRouting_ListRefreshesPrimaryAccountOn401(t *testing.T) {
	initGoogleDriveTestEnv(t)

	recorder := &authRecorder{}
	requestCount := 0
	oldClient := base.RestyClient
	base.RestyClient = newTestRestyClient().SetTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case isRefreshRequest(req):
			require.Equal(t, "refresh-0", req.URL.Query().Get("refresh_ui"))
			return newHTTPResponse(http.StatusOK, `{"refresh_token":"refresh-0-next","access_token":"refreshed-primary-token"}`, map[string]string{"Content-Type": "application/json"}), nil
		default:
			recorder.record(req.Header.Get("Authorization"))
			requestCount++
			if requestCount == 1 {
				return newHTTPResponse(http.StatusUnauthorized, `{"error":{"code":401,"message":"unauthorized"}}`, map[string]string{"Content-Type": "application/json"}), nil
			}
			return newHTTPResponse(http.StatusOK, `{"files":[],"nextPageToken":""}`, map[string]string{"Content-Type": "application/json"}), nil
		}
	}))
	t.Cleanup(func() {
		base.RestyClient = oldClient
	})

	d := newAccountsJSONDriverWithTokens([]string{"expired-primary-token", "secondary-token"})
	d.UseOnlineAPI = true
	d.APIAddress = "https://refresh.example"

	_, err := d.getFiles("root")
	require.NoError(t, err)
	require.Equal(t, []string{"Bearer expired-primary-token", "Bearer refreshed-primary-token"}, recorder.AllAuthorizations())
	require.Equal(t, "refreshed-primary-token", d.AccessToken)
	require.Equal(t, "refreshed-primary-token", d.accounts[0].Token.AccessToken)
	require.Equal(t, "refresh-0-next", d.accounts[0].Token.RefreshToken)
}

func TestGoogleDrivePrimaryAccountRouting_PutUsesIndexZeroToken(t *testing.T) {
	d, authRecorder := newAccountsJSONDriverForUploadTest(t, []string{"primary-token", "secondary-token"})

	err := d.Put(context.Background(), &model.Object{ID: "root", IsFolder: true}, newMemoryFileStreamer("f.bin", []byte("abc")), func(float64) {})
	require.NoError(t, err)
	require.Equal(t, "Bearer primary-token", authRecorder.FirstAuthorization())
}

func TestGoogleDrivePrimaryAccountRouting_PutRefreshesPrimaryAccountOnBootstrap401(t *testing.T) {
	initGoogleDriveTestEnv(t)

	recorder := &authRecorder{}
	bootstrapCount := 0
	oldNoRedirectClient := base.NoRedirectClient
	base.NoRedirectClient = newTestNoRedirectClient().SetTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		recorder.record(req.Header.Get("Authorization"))
		bootstrapCount++
		if bootstrapCount == 1 {
			return newHTTPResponse(http.StatusUnauthorized, `{"error":{"code":401,"message":"unauthorized"}}`, map[string]string{"Content-Type": "application/json"}), nil
		}
		return newHTTPResponse(http.StatusOK, `{}`, map[string]string{"Content-Type": "application/json", "Location": "https://upload.example/session"}), nil
	}))
	t.Cleanup(func() {
		base.NoRedirectClient = oldNoRedirectClient
	})

	oldClient := base.RestyClient
	base.RestyClient = newTestRestyClient().SetTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case isRefreshRequest(req):
			require.Equal(t, "refresh-0", req.URL.Query().Get("refresh_ui"))
			return newHTTPResponse(http.StatusOK, `{"refresh_token":"refresh-0-next","access_token":"refreshed-primary-token"}`, map[string]string{"Content-Type": "application/json"}), nil
		case isUploadSessionRequest(req):
			recorder.record(req.Header.Get("Authorization"))
			return newHTTPResponse(http.StatusOK, `{}`, map[string]string{"Content-Type": "application/json"}), nil
		default:
			return nil, fmt.Errorf("unexpected url: %s", req.URL.String())
		}
	}))
	t.Cleanup(func() {
		base.RestyClient = oldClient
	})

	d := newAccountsJSONDriverWithTokens([]string{"expired-primary-token", "secondary-token"})
	d.UseOnlineAPI = true
	d.APIAddress = "https://refresh.example"

	err := d.Put(context.Background(), &model.Object{ID: "root", IsFolder: true}, newMemoryFileStreamer("f.bin", []byte("abc")), func(float64) {})
	require.NoError(t, err)
	require.Equal(t, []string{"Bearer expired-primary-token", "Bearer refreshed-primary-token", "Bearer refreshed-primary-token"}, recorder.AllAuthorizations())
	require.Equal(t, "refreshed-primary-token", d.AccessToken)
}

func TestGoogleDrivePrimaryAccountRouting_PutRefreshesPrimaryAccountOnChunk401(t *testing.T) {
	initGoogleDriveTestEnv(t)

	chunkRecorder := &authRecorder{}
	oldNoRedirectClient := base.NoRedirectClient
	base.NoRedirectClient = newTestNoRedirectClient().SetTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return newHTTPResponse(http.StatusOK, `{}`, map[string]string{"Content-Type": "application/json", "Location": "https://upload.example/session"}), nil
	}))
	t.Cleanup(func() {
		base.NoRedirectClient = oldNoRedirectClient
	})

	chunkCount := 0
	oldHTTPClient := base.HttpClient
	base.HttpClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		chunkRecorder.record(req.Header.Get("Authorization"))
		chunkCount++
		if chunkCount == 1 {
			return newHTTPResponse(http.StatusUnauthorized, `{"error":{"code":401,"message":"unauthorized"}}`, map[string]string{"Content-Type": "application/json"}), nil
		}
		return newHTTPResponse(http.StatusOK, `{}`, map[string]string{"Content-Type": "application/json"}), nil
	})}
	t.Cleanup(func() {
		base.HttpClient = oldHTTPClient
	})

	oldClient := base.RestyClient
	base.RestyClient = newTestRestyClient().SetTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case isRefreshRequest(req):
			require.Equal(t, "refresh-0", req.URL.Query().Get("refresh_ui"))
			return newHTTPResponse(http.StatusOK, `{"refresh_token":"refresh-0-next","access_token":"refreshed-primary-token"}`, map[string]string{"Content-Type": "application/json"}), nil
		default:
			return nil, fmt.Errorf("unexpected url: %s", req.URL.String())
		}
	}))
	t.Cleanup(func() {
		base.RestyClient = oldClient
	})

	d := newAccountsJSONDriverWithTokens([]string{"expired-primary-token", "secondary-token"})
	d.UseOnlineAPI = true
	d.APIAddress = "https://refresh.example"
	d.ChunkSize = 1

	err := d.Put(context.Background(), &model.Object{ID: "root", IsFolder: true}, newMemoryFileStreamer("big.bin", bytes.Repeat([]byte("a"), 1024*1024)), func(float64) {})
	require.NoError(t, err)
	require.Equal(t, []string{"Bearer expired-primary-token", "Bearer refreshed-primary-token"}, chunkRecorder.AllAuthorizations())
	require.Equal(t, "refreshed-primary-token", d.AccessToken)
}

func TestGoogleDrivePrimaryAccountRouting_PutRetriesTransientChunkFailuresWithoutRotation(t *testing.T) {
	initGoogleDriveTestEnv(t)

	chunkRecorder := &authRecorder{}
	oldNoRedirectClient := base.NoRedirectClient
	base.NoRedirectClient = newTestNoRedirectClient().SetTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return newHTTPResponse(http.StatusOK, `{}`, map[string]string{"Content-Type": "application/json", "Location": "https://upload.example/session"}), nil
	}))
	t.Cleanup(func() {
		base.NoRedirectClient = oldNoRedirectClient
	})

	chunkCount := 0
	oldHTTPClient := base.HttpClient
	base.HttpClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		chunkRecorder.record(req.Header.Get("Authorization"))
		chunkCount++
		if chunkCount == 1 {
			return newHTTPResponse(http.StatusInternalServerError, `{"error":{"code":500,"message":"backend error"}}`, map[string]string{"Content-Type": "application/json"}), nil
		}
		return newHTTPResponse(http.StatusOK, `{}`, map[string]string{"Content-Type": "application/json"}), nil
	})}
	t.Cleanup(func() {
		base.HttpClient = oldHTTPClient
	})

	oldClient := base.RestyClient
	base.RestyClient = newTestRestyClient().SetTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("unexpected url: %s", req.URL.String())
	}))
	t.Cleanup(func() {
		base.RestyClient = oldClient
	})

	d := newAccountsJSONDriverWithTokens([]string{"primary-token", "secondary-token"})
	d.ChunkSize = 1

	err := d.Put(context.Background(), &model.Object{ID: "root", IsFolder: true}, newMemoryFileStreamer("big.bin", bytes.Repeat([]byte("a"), 1024*1024)), func(float64) {})
	require.NoError(t, err)
	require.Equal(t, []string{"Bearer primary-token", "Bearer primary-token"}, chunkRecorder.AllAuthorizations())
	require.Equal(t, "primary-token", d.AccessToken)
	require.Equal(t, "primary-token", d.accounts[0].Token.AccessToken)
	require.Equal(t, "secondary-token", d.accounts[1].Token.AccessToken)
}

func TestGoogleDrivePrimaryAccountRouting_PutRetriesTransientPrimaryRefreshFailuresWithoutRotation(t *testing.T) {
	initGoogleDriveTestEnv(t)

	chunkRecorder := &authRecorder{}
	oldNoRedirectClient := base.NoRedirectClient
	base.NoRedirectClient = newTestNoRedirectClient().SetTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return newHTTPResponse(http.StatusOK, `{}`, map[string]string{"Content-Type": "application/json", "Location": "https://upload.example/session"}), nil
	}))
	t.Cleanup(func() {
		base.NoRedirectClient = oldNoRedirectClient
	})

	chunkCount := 0
	oldHTTPClient := base.HttpClient
	base.HttpClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		chunkRecorder.record(req.Header.Get("Authorization"))
		chunkCount++
		if chunkCount < 3 {
			return newHTTPResponse(http.StatusUnauthorized, `{"error":{"code":401,"message":"unauthorized"}}`, map[string]string{"Content-Type": "application/json"}), nil
		}
		return newHTTPResponse(http.StatusOK, `{}`, map[string]string{"Content-Type": "application/json"}), nil
	})}
	t.Cleanup(func() {
		base.HttpClient = oldHTTPClient
	})

	refreshCount := 0
	oldClient := base.RestyClient
	base.RestyClient = newTestRestyClient().SetTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case isRefreshRequest(req):
			refreshCount++
			if refreshCount == 1 {
				return nil, fmt.Errorf("temporary refresh failure")
			}
			require.Equal(t, "refresh-0", req.URL.Query().Get("refresh_ui"))
			return newHTTPResponse(http.StatusOK, `{"refresh_token":"refresh-0-next","access_token":"refreshed-primary-token"}`, map[string]string{"Content-Type": "application/json"}), nil
		default:
			return nil, fmt.Errorf("unexpected url: %s", req.URL.String())
		}
	}))
	t.Cleanup(func() {
		base.RestyClient = oldClient
	})

	d := newAccountsJSONDriverWithTokens([]string{"expired-primary-token", "secondary-token"})
	d.UseOnlineAPI = true
	d.APIAddress = "https://refresh.example"
	d.ChunkSize = 1

	err := d.Put(context.Background(), &model.Object{ID: "root", IsFolder: true}, newMemoryFileStreamer("big.bin", bytes.Repeat([]byte("a"), 1024*1024)), func(float64) {})
	require.NoError(t, err)
	require.Equal(t, 2, refreshCount)
	require.Equal(t, []string{"Bearer expired-primary-token", "Bearer expired-primary-token", "Bearer refreshed-primary-token"}, chunkRecorder.AllAuthorizations())
	require.Equal(t, "refreshed-primary-token", d.AccessToken)
	require.Equal(t, "refreshed-primary-token", d.accounts[0].Token.AccessToken)
	require.Equal(t, "secondary-token", d.accounts[1].Token.AccessToken)
}

func TestGoogleDrivePrimaryAccountRouting_PutSmallUploadFinalPUTRetriesPrimaryAccountOnRepeated401AndPersistsRefresh(t *testing.T) {
	initGoogleDriveTestEnv(t)

	accountsPath := writeTempAccountsFile(t, `[
		{"name":"account-0","token":{"access_token":"expired-primary-token","refresh_token":"refresh-0"}},
		{"name":"account-1","token":{"access_token":"secondary-token","refresh_token":"refresh-1"}}
	]`)
	d := &GoogleDrive{
		Addition: Addition{
			AccountsJSON: accountsPath,
			UseOnlineAPI: true,
			APIAddress:   "https://refresh.example",
			ChunkSize:    5,
		},
		modeCfg: downloadModeConfig{
			Enabled:          true,
			AccountsPath:     accountsPath,
			SelectionPolicy:  "round_robin",
			DownloadRetryMax: 2,
		},
	}
	require.NoError(t, d.initAccountsJSONMode(context.Background()))
	t.Cleanup(func() {
		_ = d.Drop(context.Background())
	})

	oldNoRedirectClient := base.NoRedirectClient
	base.NoRedirectClient = newTestNoRedirectClient().SetTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		require.Equal(t, "Bearer expired-primary-token", req.Header.Get("Authorization"))
		return newHTTPResponse(http.StatusOK, `{}`, map[string]string{"Content-Type": "application/json", "Location": "https://upload.example/session"}), nil
	}))
	t.Cleanup(func() {
		base.NoRedirectClient = oldNoRedirectClient
	})

	uploadRecorder := &authRecorder{}
	refreshCount := 0
	finalPutCount := 0
	oldClient := base.RestyClient
	base.RestyClient = newTestRestyClient().SetTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case isRefreshRequest(req):
			refreshCount++
			if refreshCount == 1 {
				require.Equal(t, "refresh-0", req.URL.Query().Get("refresh_ui"))
				return newHTTPResponse(http.StatusOK, `{"refresh_token":"refresh-0-next-1","access_token":"refreshed-primary-token-1"}`, map[string]string{"Content-Type": "application/json"}), nil
			}
			require.Equal(t, "refresh-0-next-1", req.URL.Query().Get("refresh_ui"))
			return newHTTPResponse(http.StatusOK, `{"refresh_token":"refresh-0-next-2","access_token":"refreshed-primary-token-2"}`, map[string]string{"Content-Type": "application/json"}), nil
		case isUploadSessionRequest(req):
			uploadRecorder.record(req.Header.Get("Authorization"))
			finalPutCount++
			if finalPutCount < 3 {
				return newHTTPResponse(http.StatusUnauthorized, `{"error":{"code":401,"message":"unauthorized"}}`, map[string]string{"Content-Type": "application/json"}), nil
			}
			return newHTTPResponse(http.StatusOK, `{}`, map[string]string{"Content-Type": "application/json"}), nil
		default:
			return nil, fmt.Errorf("unexpected url: %s", req.URL.String())
		}
	}))
	t.Cleanup(func() {
		base.RestyClient = oldClient
	})

	err := d.Put(context.Background(), &model.Object{ID: "root", IsFolder: true}, newMemoryFileStreamer("f.bin", []byte("abc")), func(float64) {})
	require.NoError(t, err)
	require.Equal(t, 2, refreshCount)
	require.Equal(t, []string{
		"Bearer expired-primary-token",
		"Bearer refreshed-primary-token-1",
		"Bearer refreshed-primary-token-2",
	}, uploadRecorder.AllAuthorizations())
	require.Equal(t, "refreshed-primary-token-2", d.AccessToken)
	require.Equal(t, "refreshed-primary-token-2", d.accounts[0].Token.AccessToken)
	require.Equal(t, "secondary-token", d.accounts[1].Token.AccessToken)
	require.Eventually(t, func() bool {
		return accountsFileContainsAccessToken(t, accountsPath, 0, "refreshed-primary-token-2") &&
			accountsFileContainsAccessToken(t, accountsPath, 1, "secondary-token")
	}, time.Second, 10*time.Millisecond)
}

func TestGoogleDrivePrimaryAccountRouting_PutSmallUploadFinalPUTSurvivesMoreThanThree401RefreshCycles(t *testing.T) {
	initGoogleDriveTestEnv(t)

	accountsPath := writeTempAccountsFile(t, `[
		{"name":"account-0","token":{"access_token":"expired-primary-token","refresh_token":"refresh-0"}},
		{"name":"account-1","token":{"access_token":"secondary-token","refresh_token":"refresh-1"}}
	]`)
	d := &GoogleDrive{
		Addition: Addition{
			AccountsJSON: accountsPath,
			UseOnlineAPI: true,
			APIAddress:   "https://refresh.example",
			ChunkSize:    5,
		},
		modeCfg: downloadModeConfig{
			Enabled:          true,
			AccountsPath:     accountsPath,
			SelectionPolicy:  "round_robin",
			DownloadRetryMax: 2,
		},
	}
	require.NoError(t, d.initAccountsJSONMode(context.Background()))
	t.Cleanup(func() {
		_ = d.Drop(context.Background())
	})

	oldNoRedirectClient := base.NoRedirectClient
	base.NoRedirectClient = newTestNoRedirectClient().SetTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		require.Equal(t, "Bearer expired-primary-token", req.Header.Get("Authorization"))
		return newHTTPResponse(http.StatusOK, `{}`, map[string]string{"Content-Type": "application/json", "Location": "https://upload.example/session"}), nil
	}))
	t.Cleanup(func() {
		base.NoRedirectClient = oldNoRedirectClient
	})

	uploadRecorder := &authRecorder{}
	refreshCount := 0
	finalPutCount := 0
	oldClient := base.RestyClient
	base.RestyClient = newTestRestyClient().SetTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case isRefreshRequest(req):
			refreshCount++
			expectedRefreshToken := "refresh-0"
			if refreshCount > 1 {
				expectedRefreshToken = fmt.Sprintf("refresh-0-next-%d", refreshCount-1)
			}
			require.Equal(t, expectedRefreshToken, req.URL.Query().Get("refresh_ui"))
			return newHTTPResponse(http.StatusOK, fmt.Sprintf(`{"refresh_token":"refresh-0-next-%d","access_token":"refreshed-primary-token-%d"}`, refreshCount, refreshCount), map[string]string{"Content-Type": "application/json"}), nil
		case isUploadSessionRequest(req):
			uploadRecorder.record(req.Header.Get("Authorization"))
			finalPutCount++
			if finalPutCount <= 4 {
				return newHTTPResponse(http.StatusUnauthorized, `{"error":{"code":401,"message":"unauthorized"}}`, map[string]string{"Content-Type": "application/json"}), nil
			}
			return newHTTPResponse(http.StatusOK, `{}`, map[string]string{"Content-Type": "application/json"}), nil
		default:
			return nil, fmt.Errorf("unexpected url: %s", req.URL.String())
		}
	}))
	t.Cleanup(func() {
		base.RestyClient = oldClient
	})

	err := d.Put(context.Background(), &model.Object{ID: "root", IsFolder: true}, newMemoryFileStreamer("f.bin", []byte("abc")), func(float64) {})
	require.NoError(t, err)
	require.Equal(t, 4, refreshCount)
	require.Equal(t, []string{
		"Bearer expired-primary-token",
		"Bearer refreshed-primary-token-1",
		"Bearer refreshed-primary-token-2",
		"Bearer refreshed-primary-token-3",
		"Bearer refreshed-primary-token-4",
	}, uploadRecorder.AllAuthorizations())
	require.Equal(t, "refreshed-primary-token-4", d.AccessToken)
	require.Equal(t, "refreshed-primary-token-4", d.accounts[0].Token.AccessToken)
	require.Equal(t, "secondary-token", d.accounts[1].Token.AccessToken)
	require.Eventually(t, func() bool {
		return accountsFileContainsAccessToken(t, accountsPath, 0, "refreshed-primary-token-4") &&
			accountsFileContainsAccessToken(t, accountsPath, 1, "secondary-token")
	}, time.Second, 10*time.Millisecond)
}

func TestGoogleDrivePrimaryAccountRouting_PutSmallUploadFinalPUTReturnsNon401ImmediatelyWithoutRotation(t *testing.T) {
	initGoogleDriveTestEnv(t)

	accountsPath := writeTempAccountsFile(t, `[
		{"name":"account-0","token":{"access_token":"primary-token","refresh_token":"refresh-0"}},
		{"name":"account-1","token":{"access_token":"secondary-token","refresh_token":"refresh-1"}}
	]`)
	d := &GoogleDrive{
		Addition: Addition{
			AccountsJSON: accountsPath,
			UseOnlineAPI: true,
			APIAddress:   "https://refresh.example",
			ChunkSize:    5,
		},
		modeCfg: downloadModeConfig{
			Enabled:          true,
			AccountsPath:     accountsPath,
			SelectionPolicy:  "round_robin",
			DownloadRetryMax: 2,
		},
	}
	require.NoError(t, d.initAccountsJSONMode(context.Background()))
	t.Cleanup(func() {
		_ = d.Drop(context.Background())
	})

	oldNoRedirectClient := base.NoRedirectClient
	base.NoRedirectClient = newTestNoRedirectClient().SetTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		require.Equal(t, "Bearer primary-token", req.Header.Get("Authorization"))
		return newHTTPResponse(http.StatusOK, `{}`, map[string]string{"Content-Type": "application/json", "Location": "https://upload.example/session"}), nil
	}))
	t.Cleanup(func() {
		base.NoRedirectClient = oldNoRedirectClient
	})

	uploadRecorder := &authRecorder{}
	oldClient := base.RestyClient
	base.RestyClient = newTestRestyClient().SetTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case isRefreshRequest(req):
			return nil, fmt.Errorf("unexpected refresh request: %s", req.URL.String())
		case isUploadSessionRequest(req):
			uploadRecorder.record(req.Header.Get("Authorization"))
			return newHTTPResponse(http.StatusInternalServerError, `{"error":{"code":500,"message":"backend error"}}`, map[string]string{"Content-Type": "application/json"}), nil
		default:
			return nil, fmt.Errorf("unexpected url: %s", req.URL.String())
		}
	}))
	t.Cleanup(func() {
		base.RestyClient = oldClient
	})

	err := d.Put(context.Background(), &model.Object{ID: "root", IsFolder: true}, newMemoryFileStreamer("f.bin", []byte("abc")), func(float64) {})
	require.Error(t, err)
	require.ErrorContains(t, err, "backend error")
	require.Equal(t, []string{"Bearer primary-token"}, uploadRecorder.AllAuthorizations())
	require.Equal(t, "primary-token", d.AccessToken)
	require.Equal(t, "primary-token", d.accounts[0].Token.AccessToken)
	require.Equal(t, "secondary-token", d.accounts[1].Token.AccessToken)
}

func TestGoogleDriveSingleAccountRefresh_LegacyBranchesRemainUnchanged(t *testing.T) {
	t.Run("online api branch still refreshes refresh_token and access_token", func(t *testing.T) {
		d, requestURL := newLegacyOnlineRefreshDriverForTest(t)

		_, err := d.request(requestURL, http.MethodGet, nil, nil)
		require.NoError(t, err)
		require.Equal(t, "online-access-token", d.AccessToken)
		require.Equal(t, "online-refresh-token", d.RefreshToken)
	})

	t.Run("oauth branch still refreshes access_token without introducing new persistence behavior", func(t *testing.T) {
		d, requestURL := newLegacyOAuthRefreshDriverForTest(t)

		_, err := d.request(requestURL, http.MethodGet, nil, nil)
		require.NoError(t, err)
		require.Equal(t, "oauth-access-token", d.AccessToken)
	})

	t.Run("link uses refreshed authorization header after single-account refresh", func(t *testing.T) {
		d := newLegacyOAuthLinkDriverForTest(t)

		link, err := d.Link(context.Background(), &model.Object{ID: "file-1", Name: "file-1"}, model.LinkArgs{})
		require.NoError(t, err)
		require.Equal(t, "Bearer oauth-access-token", link.Header.Get("Authorization"))
	})

	t.Run("chunk upload retries after single-account refresh", func(t *testing.T) {
		initGoogleDriveTestEnv(t)

		oldNoRedirectClient := base.NoRedirectClient
		base.NoRedirectClient = newTestNoRedirectClient().SetTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
			require.Equal(t, "Bearer stale-access-token", req.Header.Get("Authorization"))
			return newHTTPResponse(http.StatusOK, `{}`, map[string]string{"Content-Type": "application/json", "Location": "https://upload.example/session"}), nil
		}))
		t.Cleanup(func() {
			base.NoRedirectClient = oldNoRedirectClient
		})

		chunkRecorder := &authRecorder{}
		chunkCount := 0
		oldHTTPClient := base.HttpClient
		base.HttpClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			chunkRecorder.record(req.Header.Get("Authorization"))
			chunkCount++
			if chunkCount == 1 {
				return newHTTPResponse(http.StatusUnauthorized, `{"error":{"code":401,"message":"unauthorized"}}`, map[string]string{"Content-Type": "application/json"}), nil
			}
			return newHTTPResponse(http.StatusOK, `{}`, map[string]string{"Content-Type": "application/json"}), nil
		})}
		t.Cleanup(func() {
			base.HttpClient = oldHTTPClient
		})

		refreshCount := 0
		oldClient := base.RestyClient
		base.RestyClient = newTestRestyClient().SetTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.String() == "https://www.googleapis.com/oauth2/v4/token" {
				refreshCount++
				return newHTTPResponse(http.StatusOK, `{"access_token":"oauth-access-token"}`, map[string]string{"Content-Type": "application/json"}), nil
			}
			return nil, fmt.Errorf("unexpected url: %s", req.URL.String())
		}))
		t.Cleanup(func() {
			base.RestyClient = oldClient
		})

		d := &GoogleDrive{
			Addition:    Addition{RefreshToken: "legacy-refresh-token", ClientID: "client-id", ClientSecret: "client-secret", ChunkSize: 1},
			AccessToken: "stale-access-token",
		}

		err := d.Put(context.Background(), &model.Object{ID: "root", IsFolder: true}, newMemoryFileStreamer("big.bin", bytes.Repeat([]byte("a"), 1024*1024)), func(float64) {})
		require.NoError(t, err)
		require.Equal(t, 1, refreshCount)
		require.Equal(t, []string{"Bearer stale-access-token", "Bearer oauth-access-token"}, chunkRecorder.AllAuthorizations())
		require.Equal(t, "oauth-access-token", d.AccessToken)
	})

	t.Run("chunk upload retries transient non-401 api failures in single-account mode", func(t *testing.T) {
		initGoogleDriveTestEnv(t)

		oldNoRedirectClient := base.NoRedirectClient
		base.NoRedirectClient = newTestNoRedirectClient().SetTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
			require.Equal(t, "Bearer stale-access-token", req.Header.Get("Authorization"))
			return newHTTPResponse(http.StatusOK, `{}`, map[string]string{"Content-Type": "application/json", "Location": "https://upload.example/session"}), nil
		}))
		t.Cleanup(func() {
			base.NoRedirectClient = oldNoRedirectClient
		})

		chunkRecorder := &authRecorder{}
		chunkCount := 0
		oldHTTPClient := base.HttpClient
		base.HttpClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			chunkRecorder.record(req.Header.Get("Authorization"))
			chunkCount++
			if chunkCount == 1 {
				return newHTTPResponse(http.StatusInternalServerError, `{"error":{"code":500,"message":"backend error"}}`, map[string]string{"Content-Type": "application/json"}), nil
			}
			return newHTTPResponse(http.StatusOK, `{}`, map[string]string{"Content-Type": "application/json"}), nil
		})}
		t.Cleanup(func() {
			base.HttpClient = oldHTTPClient
		})

		oldClient := base.RestyClient
		base.RestyClient = newTestRestyClient().SetTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return nil, fmt.Errorf("unexpected refresh request: %s", req.URL.String())
		}))
		t.Cleanup(func() {
			base.RestyClient = oldClient
		})

		d := &GoogleDrive{
			Addition:    Addition{RefreshToken: "legacy-refresh-token", ClientID: "client-id", ClientSecret: "client-secret", ChunkSize: 1},
			AccessToken: "stale-access-token",
		}

		err := d.Put(context.Background(), &model.Object{ID: "root", IsFolder: true}, newMemoryFileStreamer("big.bin", bytes.Repeat([]byte("a"), 1024*1024)), func(float64) {})
		require.NoError(t, err)
		require.Equal(t, []string{"Bearer stale-access-token", "Bearer stale-access-token"}, chunkRecorder.AllAuthorizations())
		require.Equal(t, "stale-access-token", d.AccessToken)
	})

	t.Run("chunk upload retries when single-account refresh fails transiently", func(t *testing.T) {
		initGoogleDriveTestEnv(t)

		oldNoRedirectClient := base.NoRedirectClient
		base.NoRedirectClient = newTestNoRedirectClient().SetTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
			require.Equal(t, "Bearer stale-access-token", req.Header.Get("Authorization"))
			return newHTTPResponse(http.StatusOK, `{}`, map[string]string{"Content-Type": "application/json", "Location": "https://upload.example/session"}), nil
		}))
		t.Cleanup(func() {
			base.NoRedirectClient = oldNoRedirectClient
		})

		chunkRecorder := &authRecorder{}
		chunkCount := 0
		oldHTTPClient := base.HttpClient
		base.HttpClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			chunkRecorder.record(req.Header.Get("Authorization"))
			chunkCount++
			if chunkCount < 3 {
				return newHTTPResponse(http.StatusUnauthorized, `{"error":{"code":401,"message":"unauthorized"}}`, map[string]string{"Content-Type": "application/json"}), nil
			}
			return newHTTPResponse(http.StatusOK, `{}`, map[string]string{"Content-Type": "application/json"}), nil
		})}
		t.Cleanup(func() {
			base.HttpClient = oldHTTPClient
		})

		refreshCount := 0
		oldClient := base.RestyClient
		base.RestyClient = newTestRestyClient().SetTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.String() == "https://www.googleapis.com/oauth2/v4/token" {
				refreshCount++
				if refreshCount == 1 {
					return nil, fmt.Errorf("temporary oauth failure")
				}
				return newHTTPResponse(http.StatusOK, `{"access_token":"oauth-access-token"}`, map[string]string{"Content-Type": "application/json"}), nil
			}
			return nil, fmt.Errorf("unexpected url: %s", req.URL.String())
		}))
		t.Cleanup(func() {
			base.RestyClient = oldClient
		})

		d := &GoogleDrive{
			Addition:    Addition{RefreshToken: "legacy-refresh-token", ClientID: "client-id", ClientSecret: "client-secret", ChunkSize: 1},
			AccessToken: "stale-access-token",
		}

		err := d.Put(context.Background(), &model.Object{ID: "root", IsFolder: true}, newMemoryFileStreamer("big.bin", bytes.Repeat([]byte("a"), 1024*1024)), func(float64) {})
		require.NoError(t, err)
		require.Equal(t, 2, refreshCount)
		require.Equal(t, []string{"Bearer stale-access-token", "Bearer stale-access-token", "Bearer oauth-access-token"}, chunkRecorder.AllAuthorizations())
		require.Equal(t, "oauth-access-token", d.AccessToken)
	})
}

func TestGoogleDriveLinkRotation_SwitchesOnRetryableStatuses(t *testing.T) {
	d, _ := newAccountsJSONDriverForLinkTest(t,
		[]string{"token-0", "token-1", "token-2"},
		[]scriptedDriveResponse{
			{Status: 401, Body: `{"error":{"code":401}}`},
			{Status: 429, Body: `{"error":{"code":429}}`},
			{Status: 200, Body: `{}`},
		},
	)

	link, err := d.Link(context.Background(), &model.Object{ID: "file-1", Name: "file-1"}, model.LinkArgs{})
	require.NoError(t, err)
	require.Equal(t, "Bearer token-2", link.Header.Get("Authorization"))
}

func TestGoogleDriveLinkRotation_SwitchesOnRetryableQuota403(t *testing.T) {
	d, _ := newAccountsJSONDriverForLinkTest(t,
		[]string{"token-0", "token-1"},
		[]scriptedDriveResponse{
			{Status: 403, Body: `{"error":{"errors":[{"reason":"quotaExceeded"}]}}`},
			{Status: 200, Body: `{}`},
		},
	)

	link, err := d.Link(context.Background(), &model.Object{ID: "file-1", Name: "file-1"}, model.LinkArgs{})
	require.NoError(t, err)
	require.Equal(t, "Bearer token-1", link.Header.Get("Authorization"))
}

func TestGoogleDriveLinkRotation_StopsOnNonRetryable403(t *testing.T) {
	d, _ := newAccountsJSONDriverForLinkTest(t,
		[]string{"token-0", "token-1"},
		[]scriptedDriveResponse{{Status: 403, Body: `{"error":{"errors":[{"reason":"insufficientFilePermissions"}]}}`}},
	)

	_, err := d.Link(context.Background(), &model.Object{ID: "file-1", Name: "file-1"}, model.LinkArgs{})
	require.Error(t, err)
	require.ErrorContains(t, err, "non-retryable")
}

func TestGoogleDriveLinkRotation_RespectsBudgetAndNoReplacement(t *testing.T) {
	d, recorder := newAccountsJSONDriverForLinkTest(t,
		[]string{"token-0", "token-1"},
		[]scriptedDriveResponse{
			{Status: 503, Body: `{"error":{"code":503}}`},
			{Status: 503, Body: `{"error":{"code":503}}`},
		},
	)
	d.modeCfg.DownloadRetryMax = 10

	_, err := d.Link(context.Background(), &model.Object{ID: "file-1", Name: "file-1"}, model.LinkArgs{})
	require.Error(t, err)
	require.Equal(t, []string{"Bearer token-0", "Bearer token-1"}, recorder.AllAuthorizations())
	require.ErrorContains(t, err, "account-0")
	require.ErrorContains(t, err, "account-1")
	require.ErrorContains(t, err, "503")
}

func TestGoogleDriveLinkRotation_SelectionPolicySupportsRoundRobinAndRandom(t *testing.T) {
	t.Run("round_robin advances first-account cursor across requests", func(t *testing.T) {
		d, _ := newAccountsJSONDriverForLinkTest(t,
			[]string{"token-0", "token-1", "token-2"},
			[]scriptedDriveResponse{{Status: 200, Body: `{}`}, {Status: 200, Body: `{}`}},
		)
		d.modeCfg.SelectionPolicy = "round_robin"
		d.accountPool = newAccountPool("round_robin", d.accounts)

		firstLink, err := d.Link(context.Background(), &model.Object{ID: "file-1", Name: "file-1"}, model.LinkArgs{})
		require.NoError(t, err)
		secondLink, err := d.Link(context.Background(), &model.Object{ID: "file-2", Name: "file-2"}, model.LinkArgs{})
		require.NoError(t, err)

		require.NotEqual(t, firstLink.Header.Get("Authorization"), secondLink.Header.Get("Authorization"))
	})

	t.Run("random returns unique attempts inside one request", func(t *testing.T) {
		d, recorder := newAccountsJSONDriverForLinkTest(t,
			[]string{"token-0", "token-1", "token-2"},
			[]scriptedDriveResponse{{Status: 503, Body: `{"error":{"code":503}}`}, {Status: 503, Body: `{"error":{"code":503}}`}, {Status: 200, Body: `{}`}},
		)
		d.modeCfg.SelectionPolicy = "random"
		d.accountPool = newAccountPool("random", d.accounts)

		_, err := d.Link(context.Background(), &model.Object{ID: "file-1", Name: "file-1"}, model.LinkArgs{})
		require.NoError(t, err)
		require.Len(t, recorder.AllAuthorizations(), 3)
		require.ElementsMatch(t, []string{"Bearer token-0", "Bearer token-1", "Bearer token-2"}, recorder.AllAuthorizations())
	})
}

func TestGoogleDriveAccountsJSONRefresh_UsesOnlineAPIAndPersistsUpdatedToken(t *testing.T) {
	d, accountsPath := newAccountsJSONDriverWithRefreshHooks(t)
	require.NoError(t, d.refreshPrimaryAccount(context.Background()))
	require.Eventually(t, func() bool {
		return accountsFileContainsAccessToken(t, accountsPath, 0, "online-access-token")
	}, time.Second, 10*time.Millisecond)
}

func TestGoogleDriveAccountsJSONRefresh_UsesOAuthFallbackWhenOnlineAPIIsDisabled(t *testing.T) {
	d, accountsPath := newAccountsJSONDriverWithOAuthRefreshHooks(t)
	require.NoError(t, d.refreshPrimaryAccount(context.Background()))
	require.Equal(t, "oauth-access-token", d.accounts[0].Token.AccessToken)
	require.Eventually(t, func() bool {
		return accountsFileContainsAccessToken(t, accountsPath, 0, "oauth-access-token")
	}, time.Second, 10*time.Millisecond)
	assertAccountsFileOmitsCredentials(t, accountsPath, 0)
}

func TestGoogleDriveAccountsJSONRefresh_OAuthFallbackPersistsRotatedRefreshToken(t *testing.T) {
	d, accountsPath := newAccountsJSONDriverWithRotatingOAuthRefreshHooks(t)
	require.NoError(t, d.refreshPrimaryAccount(context.Background()))
	require.Equal(t, "oauth-access-token", d.accounts[0].Token.AccessToken)
	require.Equal(t, "refresh-0-next", d.accounts[0].Token.RefreshToken)
	require.Eventually(t, func() bool {
		return accountsFileContainsAccessToken(t, accountsPath, 0, "oauth-access-token") &&
			accountsFileContainsRefreshToken(t, accountsPath, 0, "refresh-0-next")
	}, time.Second, 10*time.Millisecond)
}

func TestGoogleDriveAccountsJSONRefresh_SerializesConcurrentSameAccountRefreshes(t *testing.T) {
	initGoogleDriveTestEnv(t)

	accountsPath := writeTempAccountsFile(t, `[
		{"name":"account-0","token":{"access_token":"stale-access-token","refresh_token":"refresh-0"}}
	]`)
	d := &GoogleDrive{
		Addition: Addition{
			AccountsJSON: accountsPath,
			UseOnlineAPI: true,
			APIAddress:   "https://refresh.example",
		},
		modeCfg: downloadModeConfig{
			Enabled:          true,
			AccountsPath:     accountsPath,
			SelectionPolicy:  "round_robin",
			DownloadRetryMax: 2,
		},
	}
	require.NoError(t, d.initAccountsJSONMode(context.Background()))
	t.Cleanup(func() {
		_ = d.Drop(context.Background())
	})

	var refreshZeroCalls int32
	var refreshNextCalls int32
	firstStarted := make(chan struct{})
	allowFirst := make(chan struct{})
	var releaseFirst sync.Once
	t.Cleanup(func() {
		releaseFirst.Do(func() {
			close(allowFirst)
		})
	})

	oldClient := base.RestyClient
	base.RestyClient = newTestRestyClient().SetTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Query().Get("refresh_ui") {
		case "refresh-0":
			call := atomic.AddInt32(&refreshZeroCalls, 1)
			if call == 1 {
				close(firstStarted)
				<-allowFirst
				return newHTTPResponse(http.StatusOK, `{"refresh_token":"refresh-0-next-1","access_token":"access-token-1"}`, map[string]string{"Content-Type": "application/json"}), nil
			}
			return newHTTPResponse(http.StatusOK, `{"refresh_token":"refresh-0-next-2","access_token":"access-token-2"}`, map[string]string{"Content-Type": "application/json"}), nil
		case "refresh-0-next-1":
			atomic.AddInt32(&refreshNextCalls, 1)
			return newHTTPResponse(http.StatusOK, `{"refresh_token":"refresh-0-next-2","access_token":"access-token-2"}`, map[string]string{"Content-Type": "application/json"}), nil
		default:
			return nil, fmt.Errorf("unexpected refresh token: %s", req.URL.Query().Get("refresh_ui"))
		}
	}))
	t.Cleanup(func() {
		base.RestyClient = oldClient
	})

	errCh := make(chan error, 2)
	secondStarted := make(chan struct{})
	go func() {
		errCh <- d.refreshPrimaryAccount(context.Background())
	}()

	select {
	case <-firstStarted:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for first refresh to start")
	}

	go func() {
		close(secondStarted)
		errCh <- d.refreshPrimaryAccount(context.Background())
	}()
	<-secondStarted

	require.Never(t, func() bool {
		return atomic.LoadInt32(&refreshZeroCalls) > 1
	}, 100*time.Millisecond, 5*time.Millisecond)

	releaseFirst.Do(func() {
		close(allowFirst)
	})

	require.NoError(t, <-errCh)
	require.NoError(t, <-errCh)
	require.Equal(t, int32(1), atomic.LoadInt32(&refreshZeroCalls))
	require.Equal(t, int32(1), atomic.LoadInt32(&refreshNextCalls))
	require.Equal(t, "access-token-2", d.AccessToken)
	require.Equal(t, "access-token-2", d.accounts[0].Token.AccessToken)
	require.Equal(t, "refresh-0-next-2", d.accounts[0].Token.RefreshToken)
	require.Eventually(t, func() bool {
		entries := readPersistedAccountsFile(t, accountsPath)
		if len(entries) != 1 {
			return false
		}
		var token oauthTokenView
		require.NoError(t, json.Unmarshal(entries[0].Token, &token))
		return token.AccessToken == "access-token-2" && token.RefreshToken == "refresh-0-next-2"
	}, time.Second, 10*time.Millisecond)
}

func TestGoogleDriveConcurrentAccountStateAccess_IsRaceFree(t *testing.T) {
	initGoogleDriveTestEnv(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(server.Close)

	oldClient := base.RestyClient
	base.RestyClient = newTestRestyClient()
	t.Cleanup(func() {
		base.RestyClient = oldClient
	})

	d := newAccountsJSONDriverWithTokens([]string{"primary-token", "secondary-token", "tertiary-token"})

	start := make(chan struct{})
	errCh := make(chan error, 4)
	var wg sync.WaitGroup

	writer := func(prefix string) {
		defer wg.Done()
		<-start
		for i := 0; i < 200; i++ {
			err := d.updateAccountToken(0, oauthTokenView{
				AccessToken:  fmt.Sprintf("%s-access-%d", prefix, i),
				RefreshToken: fmt.Sprintf("%s-refresh-%d", prefix, i),
			})
			if err != nil {
				errCh <- err
				return
			}
			runtime.Gosched()
		}
	}

	reader := func() {
		defer wg.Done()
		<-start
		for i := 0; i < 200; i++ {
			if _, _, err := d.requestDownloadWithRotation(context.Background(), server.URL, http.MethodGet, nil, nil); err != nil {
				errCh <- err
				return
			}
			if _, err := d.request(server.URL, http.MethodGet, nil, nil); err != nil {
				errCh <- err
				return
			}
			runtime.Gosched()
		}
	}

	wg.Add(4)
	go writer("writer-a")
	go writer("writer-b")
	go reader()
	go reader()
	close(start)
	wg.Wait()
	close(errCh)

	for err := range errCh {
		require.NoError(t, err)
	}
}

func TestGoogleDriveDrop_FlushesStoreAndHonorsContext(t *testing.T) {
	d := newAccountsJSONDriverWithBlockingStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	err := d.Drop(ctx)
	require.Error(t, err)
	require.ErrorIs(t, err, ctx.Err())
}

func TestGoogleDriveDrop_AttemptsFlushAndShutdownAfterRefreshWaitTimeout(t *testing.T) {
	store := &recordingAccountStore{}
	d := &GoogleDrive{
		modeCfg:      downloadModeConfig{Enabled: true},
		accountStore: store,
	}
	require.NoError(t, d.beginAccountRefresh())
	defer d.endAccountRefresh()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	err := d.Drop(ctx)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Equal(t, int32(1), atomic.LoadInt32(&store.flushCalls))
	require.Equal(t, int32(1), atomic.LoadInt32(&store.shutdownCalls))
}

func TestGoogleDriveDrop_DoesNotRewriteCleanAccountsJSONWithFallbackCredentials(t *testing.T) {
	accountsContent := `[{"name":"account-0","token":{"access_token":"stale-access-token","refresh_token":"refresh-0"}}]`
	accountsPath := writeTempAccountsFile(t, accountsContent)
	d := &GoogleDrive{
		Addition: Addition{
			AccountsJSON: accountsPath,
			ClientID:     "driver-client-id",
			ClientSecret: "driver-client-secret",
		},
		modeCfg: downloadModeConfig{
			Enabled:          true,
			AccountsPath:     accountsPath,
			SelectionPolicy:  "round_robin",
			DownloadRetryMax: 2,
		},
	}

	require.NoError(t, d.initAccountsJSONMode(context.Background()))
	require.NoError(t, d.Drop(context.Background()))
	content, err := os.ReadFile(accountsPath)
	require.NoError(t, err)
	require.Equal(t, accountsContent, string(content))
}

func TestGoogleDriveDrop_WaitsForInFlightRefreshPersistence(t *testing.T) {
	initGoogleDriveTestEnv(t)

	accountsPath := writeTempAccountsFile(t, `[
		{"name":"account-0","token":{"access_token":"stale-access-token","refresh_token":"refresh-0"}}
	]`)
	d := &GoogleDrive{
		Addition: Addition{
			AccountsJSON: accountsPath,
			UseOnlineAPI: true,
			APIAddress:   "https://refresh.example",
		},
		modeCfg: downloadModeConfig{
			Enabled:          true,
			AccountsPath:     accountsPath,
			SelectionPolicy:  "round_robin",
			DownloadRetryMax: 2,
		},
	}
	require.NoError(t, d.initAccountsJSONMode(context.Background()))

	refreshStarted := make(chan struct{}, 1)
	allowRefresh := make(chan struct{})
	oldClient := base.RestyClient
	base.RestyClient = newTestRestyClient().SetTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case isRefreshRequest(req):
			refreshStarted <- struct{}{}
			<-allowRefresh
			return newHTTPResponse(http.StatusOK, `{"refresh_token":"refresh-0-next","access_token":"refreshed-primary-token"}`, map[string]string{"Content-Type": "application/json"}), nil
		default:
			return nil, fmt.Errorf("unexpected url: %s", req.URL.String())
		}
	}))
	t.Cleanup(func() {
		base.RestyClient = oldClient
	})

	refreshDone := make(chan error, 1)
	go func() {
		refreshDone <- d.refreshPrimaryAccount(context.Background())
	}()
	<-refreshStarted

	dropDone := make(chan error, 1)
	go func() {
		dropDone <- d.Drop(context.Background())
	}()

	select {
	case err := <-dropDone:
		t.Fatalf("Drop returned before in-flight refresh completed: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	close(allowRefresh)
	require.NoError(t, <-refreshDone)
	require.NoError(t, <-dropDone)
	require.Equal(t, "refreshed-primary-token", d.AccessToken)
	require.Eventually(t, func() bool {
		return accountsFileContainsAccessToken(t, accountsPath, 0, "refreshed-primary-token")
	}, time.Second, 10*time.Millisecond)
}

type authRecorder struct {
	mu             sync.Mutex
	authorizations []string
}

func (r *authRecorder) record(value string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.authorizations = append(r.authorizations, value)
}

func (r *authRecorder) LastAuthorization() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.authorizations) == 0 {
		return ""
	}
	return r.authorizations[len(r.authorizations)-1]
}

func (r *authRecorder) FirstAuthorization() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.authorizations) == 0 {
		return ""
	}
	return r.authorizations[0]
}

func (r *authRecorder) AllAuthorizations() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	res := make([]string, len(r.authorizations))
	copy(res, r.authorizations)
	return res
}

type scriptedDriveResponse struct {
	Status int
	Body   string
}

var googleDriveTestEnvOnce sync.Once

func initGoogleDriveTestEnv(t *testing.T) {
	t.Helper()

	googleDriveTestEnvOnce.Do(func() {
		dbHandle, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
		require.NoError(t, err)
		conf.Conf = conf.DefaultConfig("data")
		db.Init(dbHandle)
	})
}

func newAccountsJSONDriverForRequestTest(t *testing.T, tokens []string) (*GoogleDrive, *authRecorder) {
	t.Helper()
	initGoogleDriveTestEnv(t)

	responses := []scriptedDriveResponse{{Status: 200, Body: `{"files":[],"nextPageToken":""}`}}
	return newAccountsJSONDriverForRestyTest(t, tokens, responses)
}

func newAccountsJSONDriverForUploadTest(t *testing.T, tokens []string) (*GoogleDrive, *authRecorder) {
	t.Helper()
	initGoogleDriveTestEnv(t)

	recorder := &authRecorder{}
	oldNoRedirectClient := base.NoRedirectClient
	base.NoRedirectClient = newTestNoRedirectClient()
	base.NoRedirectClient.SetTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		recorder.record(req.Header.Get("Authorization"))
		return newHTTPResponse(http.StatusOK, `{}`, map[string]string{"Content-Type": "application/json", "Location": "https://upload.example/session"}), nil
	}))
	t.Cleanup(func() {
		base.NoRedirectClient = oldNoRedirectClient
	})

	oldClient := base.RestyClient
	base.RestyClient = newTestRestyClient().SetTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		recorder.record(req.Header.Get("Authorization"))
		return newHTTPResponse(http.StatusOK, `{}`, map[string]string{"Content-Type": "application/json"}), nil
	}))
	t.Cleanup(func() {
		base.RestyClient = oldClient
	})

	d := newAccountsJSONDriverWithTokens(tokens)
	return d, recorder
}

func newAccountsJSONDriverForLinkTest(t *testing.T, tokens []string, responses []scriptedDriveResponse) (*GoogleDrive, *authRecorder) {
	t.Helper()
	initGoogleDriveTestEnv(t)
	return newAccountsJSONDriverForRestyTest(t, tokens, responses)
}

func newAccountsJSONDriverForRestyTest(t *testing.T, tokens []string, responses []scriptedDriveResponse) (*GoogleDrive, *authRecorder) {
	t.Helper()
	initGoogleDriveTestEnv(t)

	recorder := &authRecorder{}
	oldClient := base.RestyClient
	base.RestyClient = newTestRestyClient().SetTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		recorder.record(req.Header.Get("Authorization"))
		if len(responses) == 0 {
			return newHTTPResponse(http.StatusOK, `{}`, map[string]string{"Content-Type": "application/json"}), nil
		}
		resp := responses[0]
		responses = responses[1:]
		return newHTTPResponse(resp.Status, resp.Body, map[string]string{"Content-Type": "application/json"}), nil
	}))
	t.Cleanup(func() {
		base.RestyClient = oldClient
	})

	d := newAccountsJSONDriverWithTokens(tokens)
	return d, recorder
}

func newLegacyOnlineRefreshDriverForTest(t *testing.T) (*GoogleDrive, string) {
	t.Helper()
	initGoogleDriveTestEnv(t)

	requestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer stale-access-token" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"code":401,"message":"unauthorized"}}`))
	}))
	t.Cleanup(requestServer.Close)

	refreshServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "legacy-refresh-token", r.URL.Query().Get("refresh_ui"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"refresh_token":"online-refresh-token","access_token":"online-access-token"}`))
	}))
	t.Cleanup(refreshServer.Close)

	oldClient := base.RestyClient
	base.RestyClient = newTestRestyClient()
	t.Cleanup(func() {
		base.RestyClient = oldClient
	})

	d := &GoogleDrive{Addition: Addition{RefreshToken: "legacy-refresh-token", UseOnlineAPI: true, APIAddress: refreshServer.URL}, AccessToken: "stale-access-token"}
	return d, requestServer.URL
}

func newLegacyOAuthRefreshDriverForTest(t *testing.T) (*GoogleDrive, string) {
	t.Helper()
	initGoogleDriveTestEnv(t)

	requestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer stale-access-token" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"code":401,"message":"unauthorized"}}`))
	}))
	t.Cleanup(requestServer.Close)

	oldClient := base.RestyClient
	base.RestyClient = newTestRestyClient().SetTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() == "https://www.googleapis.com/oauth2/v4/token" {
			return newHTTPResponse(http.StatusOK, `{"access_token":"oauth-access-token"}`, map[string]string{"Content-Type": "application/json"}), nil
		}
		return http.DefaultTransport.RoundTrip(req)
	}))
	t.Cleanup(func() {
		base.RestyClient = oldClient
	})

	d := &GoogleDrive{Addition: Addition{RefreshToken: "legacy-refresh-token", ClientID: "client-id", ClientSecret: "client-secret"}, AccessToken: "stale-access-token"}
	return d, requestServer.URL
}

func newLegacyOAuthLinkDriverForTest(t *testing.T) *GoogleDrive {
	t.Helper()
	initGoogleDriveTestEnv(t)

	requestCount := 0
	oldClient := base.RestyClient
	base.RestyClient = newTestRestyClient().SetTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case req.URL.String() == "https://www.googleapis.com/oauth2/v4/token":
			return newHTTPResponse(http.StatusOK, `{"access_token":"oauth-access-token"}`, map[string]string{"Content-Type": "application/json"}), nil
		default:
			requestCount++
			if requestCount == 1 {
				require.Equal(t, "Bearer stale-access-token", req.Header.Get("Authorization"))
				return newHTTPResponse(http.StatusUnauthorized, `{"error":{"code":401,"message":"unauthorized"}}`, map[string]string{"Content-Type": "application/json"}), nil
			}
			require.Equal(t, "Bearer oauth-access-token", req.Header.Get("Authorization"))
			return newHTTPResponse(http.StatusOK, `{}`, map[string]string{"Content-Type": "application/json"}), nil
		}
	}))
	t.Cleanup(func() {
		base.RestyClient = oldClient
	})

	return &GoogleDrive{
		Addition:    Addition{RefreshToken: "legacy-refresh-token", ClientID: "client-id", ClientSecret: "client-secret"},
		AccessToken: "stale-access-token",
	}
}

func newAccountsJSONDriverWithRefreshHooks(t *testing.T) (*GoogleDrive, string) {
	t.Helper()
	initGoogleDriveTestEnv(t)

	accountsPath := writeTempAccountsFile(t, `[
		{"name":"account-0","token":{"access_token":"stale-access-token","refresh_token":"refresh-0"}}
	]`)

	d := &GoogleDrive{
		Addition: Addition{
			AccountsJSON: accountsPath,
			UseOnlineAPI: true,
			APIAddress:   "https://refresh.example",
			ClientID:     "driver-client-id",
			ClientSecret: "driver-client-secret",
		},
		modeCfg: downloadModeConfig{
			Enabled:          true,
			AccountsPath:     accountsPath,
			SelectionPolicy:  "round_robin",
			DownloadRetryMax: 2,
		},
	}
	require.NoError(t, d.initAccountsJSONMode(context.Background()))
	t.Cleanup(func() {
		_ = d.Drop(context.Background())
	})

	oldClient := base.RestyClient
	base.RestyClient = newTestRestyClient().SetTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case isRefreshRequest(req):
			require.Equal(t, "refresh-0", req.URL.Query().Get("refresh_ui"))
			return newHTTPResponse(http.StatusOK, `{"refresh_token":"refresh-0-next","access_token":"online-access-token"}`, map[string]string{"Content-Type": "application/json"}), nil
		default:
			return nil, fmt.Errorf("unexpected url: %s", req.URL.String())
		}
	}))
	t.Cleanup(func() {
		base.RestyClient = oldClient
	})

	return d, accountsPath
}

func newAccountsJSONDriverWithOAuthRefreshHooks(t *testing.T) (*GoogleDrive, string) {
	t.Helper()
	initGoogleDriveTestEnv(t)

	accountsPath := writeTempAccountsFile(t, `[
		{"name":"account-0","token":{"access_token":"stale-access-token","refresh_token":"refresh-0"}}
	]`)

	d := &GoogleDrive{
		Addition: Addition{
			AccountsJSON: accountsPath,
			UseOnlineAPI: false,
			ClientID:     "driver-client-id",
			ClientSecret: "driver-client-secret",
		},
		modeCfg: downloadModeConfig{
			Enabled:          true,
			AccountsPath:     accountsPath,
			SelectionPolicy:  "round_robin",
			DownloadRetryMax: 2,
		},
	}
	require.NoError(t, d.initAccountsJSONMode(context.Background()))
	t.Cleanup(func() {
		_ = d.Drop(context.Background())
	})

	oldClient := base.RestyClient
	base.RestyClient = newTestRestyClient().SetTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() == "https://www.googleapis.com/oauth2/v4/token" {
			body, err := io.ReadAll(req.Body)
			require.NoError(t, err)
			require.Contains(t, string(body), "refresh_token=refresh-0")
			require.Contains(t, string(body), "client_id=driver-client-id")
			require.Contains(t, string(body), "client_secret=driver-client-secret")
			return newHTTPResponse(http.StatusOK, `{"access_token":"oauth-access-token"}`, map[string]string{"Content-Type": "application/json"}), nil
		}
		return nil, fmt.Errorf("unexpected url: %s", req.URL.String())
	}))
	t.Cleanup(func() {
		base.RestyClient = oldClient
	})

	return d, accountsPath
}

func newAccountsJSONDriverWithRotatingOAuthRefreshHooks(t *testing.T) (*GoogleDrive, string) {
	t.Helper()
	initGoogleDriveTestEnv(t)

	accountsPath := writeTempAccountsFile(t, `[
		{"name":"account-0","token":{"access_token":"stale-access-token","refresh_token":"refresh-0"}}
	]`)

	d := &GoogleDrive{
		Addition: Addition{
			AccountsJSON: accountsPath,
			UseOnlineAPI: false,
			ClientID:     "driver-client-id",
			ClientSecret: "driver-client-secret",
		},
		modeCfg: downloadModeConfig{
			Enabled:          true,
			AccountsPath:     accountsPath,
			SelectionPolicy:  "round_robin",
			DownloadRetryMax: 2,
		},
	}
	require.NoError(t, d.initAccountsJSONMode(context.Background()))
	t.Cleanup(func() {
		_ = d.Drop(context.Background())
	})

	oldClient := base.RestyClient
	base.RestyClient = newTestRestyClient().SetTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() == "https://www.googleapis.com/oauth2/v4/token" {
			body, err := io.ReadAll(req.Body)
			require.NoError(t, err)
			require.Contains(t, string(body), "refresh_token=refresh-0")
			return newHTTPResponse(http.StatusOK, `{"access_token":"oauth-access-token","refresh_token":"refresh-0-next"}`, map[string]string{"Content-Type": "application/json"}), nil
		}
		return nil, fmt.Errorf("unexpected url: %s", req.URL.String())
	}))
	t.Cleanup(func() {
		base.RestyClient = oldClient
	})

	return d, accountsPath
}

func newAccountsJSONDriverWithBlockingStore(t *testing.T) *GoogleDrive {
	t.Helper()
	return &GoogleDrive{
		modeCfg:      downloadModeConfig{Enabled: true},
		accountStore: blockingAccountStore{},
	}
}

func newAccountsJSONDriverWithTokens(tokens []string) *GoogleDrive {
	accounts := make([]accountRuntime, 0, len(tokens))
	for index, token := range tokens {
		tokenJSON := fmt.Sprintf(`{"access_token":%q,"refresh_token":%q}`, token, fmt.Sprintf("refresh-%d", index))
		accounts = append(accounts, accountRuntime{
			Index:        index,
			Name:         fmt.Sprintf("account-%d", index),
			TokenJSON:    tokenJSON,
			Token:        oauthTokenView{AccessToken: token, RefreshToken: fmt.Sprintf("refresh-%d", index)},
			ClientID:     "client-id",
			ClientSecret: "client-secret",
		})
	}

	d := &GoogleDrive{Addition: Addition{ChunkSize: 5}, modeCfg: downloadModeConfig{Enabled: true, SelectionPolicy: "round_robin", DownloadRetryMax: 2}, accounts: accounts, accountStore: noopAccountStore{}}
	d.accountPool = newAccountPool(d.modeCfg.SelectionPolicy, d.accounts)
	_ = d.syncPrimaryAccessToken()
	return d
}

type blockingAccountStore struct{}

func (blockingAccountStore) setToken(int, string) {}

func (blockingAccountStore) flush(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

func (blockingAccountStore) shutdown(context.Context) error {
	return nil
}

type recordingAccountStore struct {
	flushCalls    int32
	shutdownCalls int32
}

func (s *recordingAccountStore) setToken(int, string) {}

func (s *recordingAccountStore) flush(context.Context) error {
	atomic.AddInt32(&s.flushCalls, 1)
	return nil
}

func (s *recordingAccountStore) shutdown(context.Context) error {
	atomic.AddInt32(&s.shutdownCalls, 1)
	return nil
}

type memoryFileStreamer struct {
	*bytes.Reader
	obj   model.Object
	exist model.Obj
}

func newMemoryFileStreamer(name string, content []byte) *memoryFileStreamer {
	return &memoryFileStreamer{
		Reader: bytes.NewReader(content),
		obj: model.Object{
			Name: name,
			Size: int64(len(content)),
		},
	}
}

func (m *memoryFileStreamer) Close() error { return nil }

func (m *memoryFileStreamer) Add(io.Closer) {}

func (m *memoryFileStreamer) AddIfCloser(any) {}

func (m *memoryFileStreamer) GetSize() int64 { return m.obj.GetSize() }

func (m *memoryFileStreamer) GetName() string { return m.obj.GetName() }

func (m *memoryFileStreamer) ModTime() time.Time { return m.obj.ModTime() }

func (m *memoryFileStreamer) CreateTime() time.Time { return m.obj.CreateTime() }

func (m *memoryFileStreamer) IsDir() bool { return false }

func (m *memoryFileStreamer) GetHash() utils.HashInfo { return utils.HashInfo{} }

func (m *memoryFileStreamer) GetID() string { return m.obj.GetID() }

func (m *memoryFileStreamer) GetPath() string { return m.obj.GetPath() }

func (m *memoryFileStreamer) GetMimetype() string { return "application/octet-stream" }

func (m *memoryFileStreamer) NeedStore() bool { return false }

func (m *memoryFileStreamer) IsForceStreamUpload() bool { return false }

func (m *memoryFileStreamer) GetExist() model.Obj { return m.exist }

func (m *memoryFileStreamer) SetExist(obj model.Obj) { m.exist = obj }

func (m *memoryFileStreamer) RangeRead(http_range.Range) (io.Reader, error) {
	_, _ = m.Reader.Seek(0, io.SeekStart)
	return m.Reader, nil
}

func (m *memoryFileStreamer) CacheFullAndWriter(up *model.UpdateProgress, writer io.Writer) (model.File, error) {
	_, _ = m.Reader.Seek(0, io.SeekStart)
	if writer != nil {
		_, err := io.Copy(writer, m.Reader)
		if err != nil {
			return nil, err
		}
	}
	_, _ = m.Reader.Seek(0, io.SeekStart)
	return bytes.NewReader(nil), nil
}

func (m *memoryFileStreamer) SetTmpFile(file model.File) {}

func (m *memoryFileStreamer) GetFile() model.File { return nil }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func newTestRestyClient() *resty.Client {
	return resty.New().SetRetryCount(0)
}

func newTestNoRedirectClient() *resty.Client {
	return resty.New().SetRetryCount(0).SetRedirectPolicy(resty.RedirectPolicyFunc(func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}))
}

func newHTTPResponse(status int, body string, headers map[string]string) *http.Response {
	resp := &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
	for key, value := range headers {
		resp.Header.Set(key, value)
	}
	return resp
}

func isRefreshRequest(req *http.Request) bool {
	return req.URL.Host == "refresh.example" && req.URL.Path == ""
}

func isUploadSessionRequest(req *http.Request) bool {
	return req.URL.Host == "upload.example" && req.URL.Path == "/session"
}

func writeTempAccountsFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "accounts.json")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func accountsFileContainsAccessToken(t *testing.T, path string, index int, expected string) bool {
	t.Helper()
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	var entries []struct {
		Token struct {
			AccessToken string `json:"access_token"`
		} `json:"token"`
	}
	require.NoError(t, json.Unmarshal(content, &entries))
	if index < 0 || index >= len(entries) {
		return false
	}
	return entries[index].Token.AccessToken == expected
}

func accountsFileContainsRefreshToken(t *testing.T, path string, index int, expected string) bool {
	t.Helper()
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	var entries []struct {
		Token struct {
			RefreshToken string `json:"refresh_token"`
		} `json:"token"`
	}
	require.NoError(t, json.Unmarshal(content, &entries))
	if index < 0 || index >= len(entries) {
		return false
	}
	return entries[index].Token.RefreshToken == expected
}

func assertAccountsFileOmitsCredentials(t *testing.T, path string, index int) {
	t.Helper()
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	var entries []map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(content, &entries))
	require.True(t, index >= 0 && index < len(entries))
	require.NotContains(t, entries[index], "client_id")
	require.NotContains(t, entries[index], "client_secret")
}
