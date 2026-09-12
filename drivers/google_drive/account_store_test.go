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
	store, err := newAccountStore([]accountConfig{{Index: 0, Name: "acc", TokenJSON: `{"access_token":"old","refresh_token":"rold"}`}}, path, nil)
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
		func(_ string, _ string, _ []byte) ([]byte, error) {
			atomic.AddInt32(&persistCalls, 1)
			return nil, nil
		},
		func(int) time.Duration { return time.Millisecond },
		nil,
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.shutdown(context.Background()) })

	require.NoError(t, store.flush(context.Background()))
	require.Equal(t, int32(0), atomic.LoadInt32(&persistCalls))
}

func TestAccountStore_DoesNotMaterializeFallbackCredentials(t *testing.T) {
	path := writeTempAccountsFile(t, `[{"name":"acc","token":{"access_token":"seed","refresh_token":"rseed"}}]`)
	accounts, _, err := parseAccountsJSON(path, Addition{ClientID: "driver-client-id", ClientSecret: "driver-client-secret"})
	require.NoError(t, err)
	store, err := newAccountStore(accounts, path, nil)
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
	accounts, _, err := parseAccountsJSON(path, Addition{ClientID: "driver-client-id", ClientSecret: "driver-client-secret"})
	require.NoError(t, err)
	store, err := newAccountStore(accounts, path, nil)
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
	path := writeTempAccountsFile(t, "{\"name\":\"first\",\"token\":{\"access_token\":\"seed\",\"refresh_token\":\"rseed\"},\"custom\":\"keep\"}\n{\"name\":\"named\",\"token\":{\"access_token\":\"seed-2\",\"refresh_token\":\"rseed-2\"},\"enabled\":true}\n")
	accounts, _, err := parseAccountsJSON(path, Addition{})
	require.NoError(t, err)
	store, err := newAccountStore(accounts, path, nil)
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
	require.JSONEq(t, `"first"`, string(first["name"]))

	var second map[string]json.RawMessage
	require.NoError(t, json.Unmarshal([]byte(lines[1]), &second))
	require.JSONEq(t, `{"access_token":"seed-2","refresh_token":"rseed-2"}`, string(second["token"]))
	require.JSONEq(t, `true`, string(second["enabled"]))
	require.JSONEq(t, `"named"`, string(second["name"]))
}

func TestAccountStore_PreservesJSONArrayShapeAndUnknownFields(t *testing.T) {
	path := writeTempAccountsFile(t, `[{"name":"first","token":{"access_token":"seed","refresh_token":"rseed"},"custom":"keep"},{"name":"named","token":{"access_token":"seed-2","refresh_token":"rseed-2"},"enabled":true}]`)
	accounts, _, err := parseAccountsJSON(path, Addition{})
	require.NoError(t, err)
	store, err := newAccountStore(accounts, path, nil)
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
	require.JSONEq(t, `"first"`, string(entries[0]["name"]))
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
		func(_ string, payload string, _ []byte) ([]byte, error) {
			if atomic.AddInt32(&persistCalls, 1) == 1 {
				return nil, fmt.Errorf("transient persist failure")
			}
			if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
				return nil, err
			}
			return readAccountSemanticSnapshot(path)
		},
		func(int) time.Duration { return time.Millisecond },
		nil,
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
	store, err := newAccountStore([]accountConfig{{Index: 0, Name: "acc", TokenJSON: `{"access_token":"seed","refresh_token":"rseed"}`}}, path, nil)
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
		func(_ string, payload string, _ []byte) ([]byte, error) {
			if atomic.AddInt32(&attempts, 1) == 1 {
				return nil, fmt.Errorf("persist failed once")
			}
			if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
				return nil, err
			}
			return readAccountSemanticSnapshot(path)
		},
		func(int) time.Duration { return time.Millisecond },
		nil,
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.shutdown(context.Background()) })

	store.setToken(0, `{"access_token":"updated","refresh_token":"rupdated"}`)
	require.NoError(t, store.flush(context.Background()))
	require.Len(t, hook.Entries, 1)
	require.Equal(t, log.WarnLevel, hook.LastEntry().Level)
	require.Contains(t, hook.LastEntry().Message, "accounts_json persist failed")
}

func TestAccountStore_RejectsOnDiskIdentityReorderWithoutOverwriting(t *testing.T) {
	path := writeTempAccountsFile(t, `[{"name":"first","token":{"access_token":"seed-1"}},{"name":"second","token":{"access_token":"seed-2"}}]`)
	store, err := newAccountStore([]accountConfig{
		{Index: 0, Name: "first", TokenJSON: `{"access_token":"seed-1"}`},
		{Index: 1, Name: "second", TokenJSON: `{"access_token":"seed-2"}`},
	}, path, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.shutdown(context.Background()) })
	reordered := `[{"name":"second","token":{"access_token":"external-2"}},{"name":"first","token":{"access_token":"external-1"}}]`
	require.NoError(t, os.WriteFile(path, []byte(reordered), 0o600))
	store.setToken(0, `{"access_token":"updated"}`)
	err = store.flush(context.Background())
	require.ErrorIs(t, err, errAccountStoreIdentityMismatch)
	content, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	require.Equal(t, reordered, string(content))
}

func TestAccountStore_RejectsOnDiskIdentityRenameWithoutOverwriting(t *testing.T) {
	path := writeTempAccountsFile(t, `[{"name":"first","token":{"access_token":"seed-1"}},{"name":"second","token":{"access_token":"seed-2"}}]`)
	store, err := newAccountStore([]accountConfig{
		{Index: 0, Name: "first", TokenJSON: `{"access_token":"seed-1"}`},
		{Index: 1, Name: "second", TokenJSON: `{"access_token":"seed-2"}`},
	}, path, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.shutdown(context.Background()) })
	renamed := `[{"name":"renamed","token":{"access_token":"external-1"}},{"name":"second","token":{"access_token":"external-2"}}]`
	require.NoError(t, os.WriteFile(path, []byte(renamed), 0o600))
	store.setToken(0, `{"access_token":"updated"}`)
	err = store.flush(context.Background())
	require.ErrorIs(t, err, errAccountStoreIdentityMismatch)
	content, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	require.Equal(t, renamed, string(content))
}

func TestAccountStore_RejectsSameNameCredentialChangesWithoutOverwriting(t *testing.T) {
	original := `[{"name":"same","token":{"access_token":"first"}},{"name":"same","token":{"access_token":"second"}}]`
	path := writeTempAccountsFile(t, original)
	store, err := newAccountStore([]accountConfig{
		{Index: 0, Name: "same", TokenJSON: `{"access_token":"first"}`},
		{Index: 1, Name: "same", TokenJSON: `{"access_token":"second"}`},
	}, path, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.shutdown(context.Background()) })
	swapped := `[{"name":"same","token":{"access_token":"second"}},{"name":"same","token":{"access_token":"first"}}]`
	require.NoError(t, os.WriteFile(path, []byte(swapped), 0o600))
	store.setToken(0, `{"access_token":"updated"}`)
	err = store.flush(context.Background())
	require.ErrorIs(t, err, errAccountStoreIdentityMismatch)
	content, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	require.Equal(t, swapped, string(content))
	_ = store.shutdown(context.Background())

	path = writeTempAccountsFile(t, original)
	store, err = newAccountStore([]accountConfig{
		{Index: 0, Name: "same", TokenJSON: `{"access_token":"first"}`},
		{Index: 1, Name: "same", TokenJSON: `{"access_token":"second"}`},
	}, path, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.shutdown(context.Background()) })
	altered := `[{"name":"same","token":{"access_token":"external"}},{"name":"same","token":{"access_token":"second"}}]`
	require.NoError(t, os.WriteFile(path, []byte(altered), 0o600))
	store.setToken(0, `{"access_token":"updated"}`)
	err = store.flush(context.Background())
	require.ErrorIs(t, err, errAccountStoreIdentityMismatch)
	content, readErr = os.ReadFile(path)
	require.NoError(t, readErr)
	require.Equal(t, altered, string(content))
}

func TestAccountStore_AcceptsHarmlessJSONRepresentationChanges(t *testing.T) {
	path := writeTempAccountsFile(t, `[{"name":" same ","token":{"refresh_token":"refresh","access_token":"seed"}}]`)
	store, err := newAccountStore([]accountConfig{{Index: 0, Name: "same", TokenJSON: `{"access_token":"seed","refresh_token":"refresh"}`}}, path, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.shutdown(context.Background()) })
	representation := "[ {\"token\": { \"access_token\": \"seed\", \"refresh_token\": \"refresh\" }, \"name\": \"same\" } ]"
	require.NoError(t, os.WriteFile(path, []byte(representation), 0o600))
	store.setToken(0, `{"access_token":"updated","refresh_token":"refresh"}`)
	require.NoError(t, store.flush(context.Background()))
	entries := readPersistedAccountsFile(t, path)
	require.Len(t, entries, 1)
	assertPersistedTokenEquals(t, path, 0, `{"access_token":"updated","refresh_token":"refresh"}`)
}

func TestAccountStore_UsesIntendedSnapshotAfterPostWriteExternalEdit(t *testing.T) {
	path := writeTempAccountsFile(t, `[{"name":"same","token":{"access_token":"first"}},{"name":"same","token":{"access_token":"second"}}]`)
	mutateAfterWrite := true
	store, err := newAccountStoreWithHooks(
		[]accountConfig{
			{Index: 0, Name: "same", TokenJSON: `{"access_token":"first"}`},
			{Index: 1, Name: "same", TokenJSON: `{"access_token":"second"}`},
		},
		path,
		func(path, payload string, _ []byte) ([]byte, error) {
			if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
				return nil, err
			}
			intended, err := semanticAccountsSnapshot([]byte(payload))
			if err != nil {
				return nil, err
			}
			if mutateAfterWrite {
				var entries []map[string]json.RawMessage
				content, err := os.ReadFile(path)
				if err != nil {
					return nil, err
				}
				if err := json.Unmarshal(content, &entries); err != nil {
					return nil, err
				}
				entries[1]["token"] = json.RawMessage(`{"access_token":"external"}`)
				external, err := json.Marshal(entries)
				if err != nil {
					return nil, err
				}
				if err := os.WriteFile(path, external, 0o600); err != nil {
					return nil, err
				}
				mutateAfterWrite = false
			}
			return intended, nil
		},
		func(int) time.Duration { return 0 },
		nil,
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.shutdown(context.Background()) })
	store.setToken(0, `{"access_token":"updated"}`)
	require.NoError(t, store.flush(context.Background()))
	store.setToken(0, `{"access_token":"updated-again"}`)
	require.ErrorIs(t, store.flush(context.Background()), errAccountStoreIdentityMismatch)
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	var entries []map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(content, &entries))
	require.JSONEq(t, `{"access_token":"external"}`, string(entries[1]["token"]))
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
