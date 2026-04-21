package google_drive

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
)

func TestAccountStore_PersistsTokenObjectsWithAtomicReplace(t *testing.T) {
	path := writeTempAccountsFile(t, `[{"name":"acc","token":{"access_token":"old","refresh_token":"rold"}}]`)
	store, err := newAccountStore([]accountConfig{{Index: 0, Name: "acc", TokenJSON: `{"access_token":"old","refresh_token":"rold"}`}}, path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.shutdown(context.Background()) })

	store.setToken(0, `{"access_token":"new","refresh_token":"rnew"}`)
	require.NoError(t, store.flush(context.Background()))
	assertPersistedTokenIsJSONObject(t, path)
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestAccountStore_DoesNotFlushCleanInitialState(t *testing.T) {
	path := writeTempAccountsFile(t, `[{"name":"acc","token":{"access_token":"seed","refresh_token":"rseed"}}]`)
	var persistCalls int32
	store, err := newAccountStoreWithHooks(
		[]accountConfig{{Index: 0, Name: "acc", TokenJSON: `{"access_token":"seed","refresh_token":"rseed"}`}},
		path,
		func(_ string, _ string) error {
			atomic.AddInt32(&persistCalls, 1)
			return nil
		},
		func(int) time.Duration { return time.Millisecond },
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.shutdown(context.Background()) })

	require.NoError(t, store.flush(context.Background()))
	require.Equal(t, int32(0), atomic.LoadInt32(&persistCalls))
}

func TestAccountStore_DoesNotMaterializeFallbackCredentials(t *testing.T) {
	path := writeTempAccountsFile(t, `[{"name":"acc","token":{"access_token":"seed","refresh_token":"rseed"}}]`)
	accounts, err := parseAccountsJSON(path, Addition{ClientID: "driver-client-id", ClientSecret: "driver-client-secret"})
	require.NoError(t, err)
	store, err := newAccountStore(accounts, path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.shutdown(context.Background()) })

	store.setToken(0, `{"access_token":"updated","refresh_token":"rupdated"}`)
	require.NoError(t, store.flush(context.Background()))

	entries := readPersistedAccountsFile(t, path)
	require.Len(t, entries, 1)
	require.Empty(t, entries[0].ClientID)
	require.Empty(t, entries[0].ClientSecret)
}

func TestAccountStore_PreservesExplicitAccountCredentials(t *testing.T) {
	path := writeTempAccountsFile(t, `[{"name":"acc","client_id":"entry-client-id","client_secret":"entry-client-secret","token":{"access_token":"seed","refresh_token":"rseed"}}]`)
	accounts, err := parseAccountsJSON(path, Addition{ClientID: "driver-client-id", ClientSecret: "driver-client-secret"})
	require.NoError(t, err)
	store, err := newAccountStore(accounts, path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.shutdown(context.Background()) })

	store.setToken(0, `{"access_token":"updated","refresh_token":"rupdated"}`)
	require.NoError(t, store.flush(context.Background()))

	entries := readPersistedAccountsFile(t, path)
	require.Len(t, entries, 1)
	require.Equal(t, "entry-client-id", entries[0].ClientID)
	require.Equal(t, "entry-client-secret", entries[0].ClientSecret)
}

func TestAccountStore_PreservesJSONLShapeAndUnknownFields(t *testing.T) {
	path := writeTempAccountsFile(t, "{\"token\":{\"access_token\":\"seed\",\"refresh_token\":\"rseed\"},\"custom\":\"keep\"}\n{\"name\":\"named\",\"token\":{\"access_token\":\"seed-2\",\"refresh_token\":\"rseed-2\"},\"enabled\":true}\n")
	accounts, err := parseAccountsJSON(path, Addition{})
	require.NoError(t, err)
	store, err := newAccountStore(accounts, path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.shutdown(context.Background()) })

	store.setToken(0, `{"access_token":"updated","refresh_token":"rupdated"}`)
	require.NoError(t, store.flush(context.Background()))

	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	require.True(t, strings.HasSuffix(string(raw), "\n"))
	require.False(t, strings.HasPrefix(strings.TrimSpace(string(raw)), "["))

	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	require.Len(t, lines, 2)

	var first map[string]json.RawMessage
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &first))
	require.JSONEq(t, `{"access_token":"updated","refresh_token":"rupdated"}`, string(first["token"]))
	require.JSONEq(t, `"keep"`, string(first["custom"]))
	_, hasGeneratedName := first["name"]
	require.False(t, hasGeneratedName)

	var second map[string]json.RawMessage
	require.NoError(t, json.Unmarshal([]byte(lines[1]), &second))
	require.JSONEq(t, `{"access_token":"seed-2","refresh_token":"rseed-2"}`, string(second["token"]))
	require.JSONEq(t, `true`, string(second["enabled"]))
	require.JSONEq(t, `"named"`, string(second["name"]))
}

func TestAccountStore_PreservesJSONArrayShapeAndUnknownFields(t *testing.T) {
	path := writeTempAccountsFile(t, `[{"token":{"access_token":"seed","refresh_token":"rseed"},"custom":"keep"},{"name":"named","token":{"access_token":"seed-2","refresh_token":"rseed-2"},"enabled":true}]`)
	accounts, err := parseAccountsJSON(path, Addition{})
	require.NoError(t, err)
	store, err := newAccountStore(accounts, path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.shutdown(context.Background()) })

	store.setToken(0, `{"access_token":"updated","refresh_token":"rupdated"}`)
	require.NoError(t, store.flush(context.Background()))

	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(strings.TrimSpace(string(raw)), "["))

	var entries []map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &entries))
	require.Len(t, entries, 2)
	require.JSONEq(t, `{"access_token":"updated","refresh_token":"rupdated"}`, string(entries[0]["token"]))
	require.JSONEq(t, `"keep"`, string(entries[0]["custom"]))
	_, hasGeneratedName := entries[0]["name"]
	require.False(t, hasGeneratedName)
	require.JSONEq(t, `{"access_token":"seed-2","refresh_token":"rseed-2"}`, string(entries[1]["token"]))
	require.JSONEq(t, `true`, string(entries[1]["enabled"]))
	require.JSONEq(t, `"named"`, string(entries[1]["name"]))
}

func TestAccountStore_CoalescesRapidUpdatesAndRetriesTransientFailures(t *testing.T) {
	path := writeTempAccountsFile(t, `[{"name":"acc","token":{"access_token":"seed","refresh_token":"rseed"}}]`)
	var persistCalls int32
	store, err := newAccountStoreWithHooks(
		[]accountConfig{{Index: 0, Name: "acc", TokenJSON: `{"access_token":"seed","refresh_token":"rseed"}`}},
		path,
		func(_ string, payload string) error {
			if atomic.AddInt32(&persistCalls, 1) == 1 {
				return fmt.Errorf("transient persist failure")
			}
			return os.WriteFile(path, []byte(payload), 0o600)
		},
		func(int) time.Duration { return time.Millisecond },
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.shutdown(context.Background()) })

	store.setToken(0, `{"access_token":"mid","refresh_token":"rmid"}`)
	store.setToken(0, `{"access_token":"latest","refresh_token":"rlatest"}`)
	require.NoError(t, store.flush(context.Background()))

	require.True(t, atomic.LoadInt32(&persistCalls) >= 2)
	assertPersistedTokenEquals(t, path, 0, `{"access_token":"latest","refresh_token":"rlatest"}`)
}

func TestAccountStore_PersistsSignalTriggeredUpdatesEventually(t *testing.T) {
	path := writeTempAccountsFile(t, `[{"name":"acc","token":{"access_token":"seed","refresh_token":"rseed"}}]`)
	store, err := newAccountStore([]accountConfig{{Index: 0, Name: "acc", TokenJSON: `{"access_token":"seed","refresh_token":"rseed"}`}}, path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.shutdown(context.Background()) })

	store.setToken(0, `{"access_token":"updated","refresh_token":"rupdated"}`)
	require.Eventually(t, func() bool {
		entries := readPersistedAccountsFile(t, path)
		if len(entries) != 1 {
			return false
		}
		var token map[string]any
		require.NoError(t, json.Unmarshal(entries[0].Token, &token))
		return token["access_token"] == "updated"
	}, time.Second, 10*time.Millisecond)
}

func TestAccountStore_LogsPersistFailuresBeforeRetrying(t *testing.T) {
	path := writeTempAccountsFile(t, `[{"name":"acc","token":{"access_token":"seed","refresh_token":"rseed"}}]`)
	hook := test.NewGlobal()
	defer hook.Reset()

	var attempts int32
	store, err := newAccountStoreWithHooks(
		[]accountConfig{{Index: 0, Name: "acc", TokenJSON: `{"access_token":"seed","refresh_token":"rseed"}`}},
		path,
		func(_ string, payload string) error {
			if atomic.AddInt32(&attempts, 1) == 1 {
				return fmt.Errorf("persist failed once")
			}
			return os.WriteFile(path, []byte(payload), 0o600)
		},
		func(int) time.Duration { return time.Millisecond },
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.shutdown(context.Background()) })

	store.setToken(0, `{"access_token":"updated","refresh_token":"rupdated"}`)
	require.NoError(t, store.flush(context.Background()))
	require.Len(t, hook.Entries, 1)
	require.Equal(t, log.WarnLevel, hook.LastEntry().Level)
	require.Contains(t, hook.LastEntry().Message, "accounts_json persist failed")
}

func assertPersistedTokenIsJSONObject(t *testing.T, path string) {
	t.Helper()

	entries := readPersistedAccountsFile(t, path)
	require.Len(t, entries, 1)
	require.True(t, len(entries[0].Token) > 0)
	require.Equal(t, byte('{'), entries[0].Token[0])
	var token map[string]any
	require.NoError(t, json.Unmarshal(entries[0].Token, &token))
	require.Equal(t, "new", token["access_token"])
	require.Equal(t, "rnew", token["refresh_token"])
}

func assertPersistedTokenEquals(t *testing.T, path string, index int, expected string) {
	t.Helper()

	entries := readPersistedAccountsFile(t, path)
	require.True(t, index >= 0 && index < len(entries))
	var actualToken map[string]any
	require.NoError(t, json.Unmarshal(entries[index].Token, &actualToken))
	var expectedToken map[string]any
	require.NoError(t, json.Unmarshal([]byte(expected), &expectedToken))
	require.Equal(t, expectedToken, actualToken)
}

type persistedAccountEntry struct {
	Name         string          `json:"name"`
	ClientID     string          `json:"client_id,omitempty"`
	ClientSecret string          `json:"client_secret,omitempty"`
	Token        json.RawMessage `json:"token"`
}

func readPersistedAccountsFile(t *testing.T, path string) []persistedAccountEntry {
	t.Helper()

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	var entries []persistedAccountEntry
	require.NoError(t, json.Unmarshal(content, &entries))
	return entries
}
