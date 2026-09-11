package google_drive

import (
	"context"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/OpenListTeam/OpenList/v4/drivers/base"
	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	internaldb "github.com/OpenListTeam/OpenList/v4/internal/db"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestGoogleDriveSingleRefresh_WaiterCancellationDoesNotRefreshAfterUnlock(t *testing.T) {
	d := &GoogleDrive{
		Addition:                   Addition{RefreshToken: "refresh-token"},
		AccessToken:                "usable-token",
		singleCredentialGeneration: 1,
		singleTokenExpiry:          time.Now().Add(time.Hour).Format(time.RFC3339),
	}
	d.singleRefreshMu.Lock()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- d.refreshTokenIfNeededWithContext(ctx)
	}()

	select {
	case err := <-done:
		require.ErrorIs(t, err, context.DeadlineExceeded)
	case <-time.After(time.Second):
		t.Fatal("refresh waiter ignored context cancellation")
	}

	d.singleRefreshMu.Unlock()
	select {
	case err := <-done:
		t.Fatalf("refresh waiter returned twice: %v", err)
	default:
	}
	require.Equal(t, "usable-token", d.AccessToken)
}

func TestGoogleDriveSingleRefresh_OnlinePersistenceReceivesCallerContext(t *testing.T) {
	oldDB := internaldb.GetDb()
	oldConf := conf.Conf
	database, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "ticket02-single-refresh-context.sqlite")), &gorm.Config{})
	require.NoError(t, err)
	conf.Conf = conf.DefaultConfig(t.TempDir())
	internaldb.Init(database)
	t.Cleanup(func() {
		if sqlDB, dbErr := database.DB(); dbErr == nil {
			_ = sqlDB.Close()
		}
		conf.Conf = oldConf
		if oldDB != nil {
			internaldb.Init(oldDB)
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var seenContext context.Context
	callbackName := "ticket02-cancel-single-refresh-save"
	err = database.Callback().Create().Before("gorm:create").Register(callbackName, func(tx *gorm.DB) {
		seenContext = tx.Statement.Context
		cancel()
		tx.Error = tx.Statement.Context.Err()
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Callback().Create().Remove(callbackName) })

	oldClient := base.RestyClient
	base.RestyClient = newTestRestyClient().SetTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return newHTTPResponse(http.StatusOK, `{"refresh_token":"new-refresh-token","access_token":"new-access-token"}`, map[string]string{"Content-Type": "application/json"}), nil
	}))
	t.Cleanup(func() { base.RestyClient = oldClient })

	d := &GoogleDrive{
		Storage: model.Storage{MountPath: "/ticket02-single-refresh-context"},
		Addition: Addition{
			RefreshToken: "refresh-token",
			UseOnlineAPI: true,
			APIAddress:   "https://refresh.example",
		},
	}
	err = d.refreshTokenWithContext(ctx)
	require.ErrorIs(t, err, context.Canceled)
	require.Same(t, ctx, seenContext)
}
