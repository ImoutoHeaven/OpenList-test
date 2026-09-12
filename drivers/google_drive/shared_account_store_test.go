package google_drive

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAccountStore_SharedDriverMountsPersistDifferentEntries(t *testing.T) {
	initGoogleDriveTestEnv(t)
	path := writeTempAccountsFile(t, `[
		{"name":"writer-first","token":{"access_token":"first-old","refresh_token":"first-refresh"}},
		{"name":"writer-second","token":{"access_token":"second-old","refresh_token":"second-refresh"}},
		{"name":"writer-second","token":{"access_token":"duplicate","refresh_token":"duplicate-refresh"}}
	]`)
	cleanPath := filepath.Join(filepath.Dir(path), ".", filepath.Base(path))
	newDriver := func(accountsPath string) *GoogleDrive {
		return &GoogleDrive{
			Addition: Addition{AccountsJSON: accountsPath},
			modeCfg: downloadModeConfig{
				Enabled:          true,
				AccountsPath:     accountsPath,
				SelectionPolicy:  "round_robin",
				DownloadRetryMax: 2,
			},
		}
	}
	first, second := newDriver(path), newDriver(cleanPath)
	require.NoError(t, first.initAccountsJSONMode(context.Background()))
	require.NoError(t, second.initAccountsJSONMode(context.Background()))
	t.Cleanup(func() {
		_ = first.Drop(context.Background())
		_ = second.Drop(context.Background())
	})

	require.NoError(t, first.updateAccountToken(0, oauthTokenView{AccessToken: "first-new", RefreshToken: "first-refresh-new"}))
	require.NoError(t, second.updateAccountToken(1, oauthTokenView{AccessToken: "second-new", RefreshToken: "second-refresh-new"}))
	require.NoError(t, first.accountStore.flush(context.Background()))
	require.NoError(t, second.accountStore.flush(context.Background()))
	require.NoError(t, first.Drop(context.Background()))

	require.NoError(t, second.updateAccountToken(0, oauthTokenView{AccessToken: "first-final", RefreshToken: "first-refresh-final"}))
	require.NoError(t, second.accountStore.flush(context.Background()))
	require.NoError(t, second.Drop(context.Background()))

	entries := readPersistedAccountsFile(t, path)
	require.Len(t, entries, 3)
	assertPersistedTokenEquals(t, path, 0, `{"access_token":"first-final","refresh_token":"first-refresh-final"}`)
	assertPersistedTokenEquals(t, path, 1, `{"access_token":"second-new","refresh_token":"second-refresh-new"}`)
	assertPersistedTokenEquals(t, path, 2, `{"access_token":"duplicate","refresh_token":"duplicate-refresh"}`)

	reattached := newDriver(path)
	require.NoError(t, reattached.initAccountsJSONMode(context.Background()))
	require.Equal(t, "first-final", reattached.accounts[0].Token.AccessToken)
	require.Equal(t, "second-new", reattached.accounts[1].Token.AccessToken)
	require.NoError(t, reattached.Drop(context.Background()))

}

func TestAccountStore_SharedHandlesPersistDistinctEntriesAndSurviveDrop(t *testing.T) {
	path := writeTempAccountsFile(t, `[
		{"name":"first","token":{"access_token":"first-old","refresh_token":"first-refresh"}},
		{"name":"shared","token":{"access_token":"duplicate","refresh_token":"duplicate-refresh"}},
		{"name":"second","token":{"access_token":"second-old","refresh_token":"second-refresh"}},
		{"name":"shared","token":{"access_token":"duplicate-two","refresh_token":"duplicate-two-refresh"}}
	]`)
	accountsPathWithDot := filepath.Join(filepath.Dir(path), ".", filepath.Base(path))
	parsed, sourceSnapshot, err := parseAccountsJSON(path, Addition{})
	require.NoError(t, err)

	first, err := attachAccountStore(context.Background(), parsed, path, sourceSnapshot)
	require.NoError(t, err)
	second, err := attachAccountStore(context.Background(), parsed, accountsPathWithDot, sourceSnapshot)
	require.NoError(t, err)
	firstHandle := first.(*fileAccountStoreHandle)
	secondHandle := second.(*fileAccountStoreHandle)
	require.Same(t, firstHandle.entry, secondHandle.entry)

	first.setToken(0, `{"access_token":"first-new","refresh_token":"first-refresh-new"}`)
	second.setToken(2, `{"access_token":"second-new","refresh_token":"second-refresh-new"}`)
	require.NoError(t, first.flush(context.Background()))
	require.NoError(t, second.flush(context.Background()))

	require.NoError(t, first.shutdown(context.Background()))
	second.setToken(0, `{"access_token":"first-final","refresh_token":"first-refresh-final"}`)
	require.NoError(t, second.flush(context.Background()))
	require.NoError(t, second.shutdown(context.Background()))

	entries := readPersistedAccountsFile(t, path)
	require.Len(t, entries, 4)
	assertPersistedTokenEquals(t, path, 0, `{"access_token":"first-final","refresh_token":"first-refresh-final"}`)
	assertPersistedTokenEquals(t, path, 1, `{"access_token":"duplicate","refresh_token":"duplicate-refresh"}`)
	assertPersistedTokenEquals(t, path, 2, `{"access_token":"second-new","refresh_token":"second-refresh-new"}`)
	assertPersistedTokenEquals(t, path, 3, `{"access_token":"duplicate-two","refresh_token":"duplicate-two-refresh"}`)

	reattached, err := attachAccountStore(context.Background(), parsed, path, sourceSnapshot)
	require.ErrorIs(t, err, errAccountStoreIdentityMismatch)
	require.Nil(t, reattached)

	parsed, sourceSnapshot, err = parseAccountsJSON(path, Addition{})
	require.NoError(t, err)
	reattached, err = attachAccountStore(context.Background(), parsed, path, sourceSnapshot)
	require.NoError(t, err)
	require.NoError(t, reattached.shutdown(context.Background()))
}

func TestAccountStore_SharedHandleAttachmentAndFinalShutdownAreSerialized(t *testing.T) {
	path := writeTempAccountsFile(t, `[{"name":"account","token":{"access_token":"old","refresh_token":"refresh"}}]`)
	parsed, sourceSnapshot, err := parseAccountsJSON(path, Addition{})
	require.NoError(t, err)

	persistStarted := make(chan struct{})
	allowPersist := make(chan struct{})
	var persistCalls atomic.Int32
	persist := func(path, payload string, _ []byte) ([]byte, error) {
		if persistCalls.Add(1) == 1 {
			close(persistStarted)
			<-allowPersist
		}
		if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
			return nil, err
		}
		return semanticAccountsSnapshot([]byte(payload))
	}
	first, err := attachAccountStoreWithHooks(context.Background(), parsed, path, persist, func(int) time.Duration { return 0 }, sourceSnapshot)
	require.NoError(t, err)
	first.setToken(0, `{"access_token":"first","refresh_token":"first-refresh"}`)
	select {
	case <-persistStarted:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for shared writer persistence")
	}

	second, err := attachAccountStore(context.Background(), parsed, path, sourceSnapshot)
	require.NoError(t, err)
	require.Same(t, first.(*fileAccountStoreHandle).entry, second.(*fileAccountStoreHandle).entry)
	second.setToken(0, `{"access_token":"second","refresh_token":"second-refresh"}`)
	require.NoError(t, second.shutdown(context.Background()))

	firstShutdown := make(chan error, 1)
	go func() { firstShutdown <- first.shutdown(context.Background()) }()
	require.Eventually(t, func() bool {
		sharedFileAccountStores.Lock()
		defer sharedFileAccountStores.Unlock()
		entry := sharedFileAccountStores.entries[filepath.Clean(path)]
		return entry != nil && entry.closing
	}, time.Second, time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err = attachAccountStore(ctx, parsed, path, sourceSnapshot)
	require.ErrorIs(t, err, context.DeadlineExceeded)

	close(allowPersist)
	require.NoError(t, <-firstShutdown)

	parsed, sourceSnapshot, err = parseAccountsJSON(path, Addition{})
	require.NoError(t, err)
	reattached, err := attachAccountStore(context.Background(), parsed, path, sourceSnapshot)
	require.NoError(t, err)
	require.NoError(t, reattached.shutdown(context.Background()))
	assertPersistedTokenEquals(t, path, 0, `{"access_token":"second","refresh_token":"second-refresh"}`)
}

func TestAccountStore_SharedAttachmentRejectsManualSnapshotChanges(t *testing.T) {
	path := writeTempAccountsFile(t, `[{"name":"account","token":{"access_token":"old","refresh_token":"refresh"}}]`)
	parsed, sourceSnapshot, err := parseAccountsJSON(path, Addition{})
	require.NoError(t, err)
	first, err := attachAccountStore(context.Background(), parsed, path, sourceSnapshot)
	require.NoError(t, err)
	defer func() { _ = first.shutdown(context.Background()) }()

	manual := `[{"name":"account","token":{"access_token":"manual","refresh_token":"refresh"}}]`
	require.NoError(t, os.WriteFile(path, []byte(manual), 0o600))
	updatedParsed, updatedSnapshot, err := parseAccountsJSON(path, Addition{})
	require.NoError(t, err)
	_, err = attachAccountStore(context.Background(), updatedParsed, path, updatedSnapshot)
	require.ErrorIs(t, err, errAccountStoreIdentityMismatch)
}

func TestAccountStore_AttachDuringPersistAcknowledgment(t *testing.T) {
	initGoogleDriveTestEnv(t)
	path := writeTempAccountsFile(t, `{"name":"account","note":"preserved","token":{"access_token":"old","refresh_token":"refresh"}}
{"name":"account","token":{"access_token":"duplicate","refresh_token":"duplicate-refresh"}}
`)
	parsed, snapshot, err := parseAccountsJSON(path, Addition{})
	require.NoError(t, err)
	written := make(chan struct{})
	acknowledge := make(chan struct{})
	persist := func(path, payload string, expected []byte) ([]byte, error) {
		next, err := persistAccountsJSONFileChecked(path, payload, expected)
		close(written)
		<-acknowledge
		return next, err
	}
	first, err := attachAccountStoreWithHooks(context.Background(), parsed, path, persist, defaultAccountStoreBackoff, snapshot)
	require.NoError(t, err)
	defer func() { _ = first.shutdown(context.Background()) }()
	first.setToken(0, `{"access_token":"new","refresh_token":"refresh"}`)
	<-written
	second := &GoogleDrive{
		Addition: Addition{AccountsJSON: path},
		modeCfg:  downloadModeConfig{Enabled: true, AccountsPath: path, SelectionPolicy: "round_robin"},
	}
	err = second.initAccountsJSONMode(context.Background())
	close(acknowledge)
	require.NoError(t, err)
	require.Equal(t, "new", second.accounts[0].Token.AccessToken)
	require.Len(t, second.accounts, 1)
	require.NoError(t, second.Drop(context.Background()))
	persisted, _, err := parseAccountsJSON(path, Addition{})
	require.NoError(t, err)
	require.Len(t, persisted, 2)
	require.JSONEq(t, `{"access_token":"duplicate","refresh_token":"duplicate-refresh"}`, persisted[1].TokenJSON)
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Contains(t, string(content), `"note":"preserved"`)
}
