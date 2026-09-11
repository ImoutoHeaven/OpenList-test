package google_drive

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	internaldb "github.com/OpenListTeam/OpenList/v4/internal/db"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

type accountHealthTestClock struct {
	mu  sync.Mutex
	now time.Time
}

func newAccountHealthTestClock() *accountHealthTestClock {
	return &accountHealthTestClock{now: time.Unix(1_700_000_000, 0)}
}

func (c *accountHealthTestClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *accountHealthTestClock) Set(value time.Time) {
	c.mu.Lock()
	c.now = value
	c.mu.Unlock()
}

func (c *accountHealthTestClock) Advance(delta time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(delta)
	c.mu.Unlock()
}

func reportTestQuotaFailure(t *testing.T, runtime *accountHealthRuntime, clock *accountHealthTestClock, accountName, fileID, eventID string, generation uint64) {
	t.Helper()
	result, err := runtime.report(context.Background(), AccountHealthReportInput{
		AccountName: accountName,
		FileID:      fileID,
		EventID:     eventID,
		Outcome:     AccountHealthFailure,
		StatusCode:  403,
		Reason:      "downloadQuotaExceeded",
		Generation:  generation,
	})
	require.NoError(t, err)
	require.True(t, result.Applied)
	clock.Advance(2 * time.Minute)
}

func TestAccountHealth_DistinctQuotaFilesUseBackoffAndFixedCooldown(t *testing.T) {
	clock := newAccountHealthTestClock()
	runtime := newAccountHealthRuntime(clock.Now)
	const accountName = "shared-account"

	initial, err := runtime.acquire(context.Background(), accountName, "file-0")
	require.NoError(t, err)
	require.Equal(t, uint64(1), initial.Generation)
	require.False(t, initial.Trial)

	reportTestQuotaFailure(t, runtime, clock, accountName, "file-1", "event-1", initial.Generation)
	reportTestQuotaFailure(t, runtime, clock, accountName, "file-2", "event-2", initial.Generation)
	reportTestQuotaFailure(t, runtime, clock, accountName, "file-3", "event-3", initial.Generation)

	state, err := runtime.snapshot(context.Background(), accountName)
	require.NoError(t, err)
	require.Equal(t, []string{"file-1", "file-2", "file-3"}, state.EvidenceFileIDs)
	require.Equal(t, 3, state.BackoffLevel)
	require.Equal(t, uint64(2), state.Generation)
	require.WithinDuration(t, clock.Now().Add(24*time.Hour-2*time.Minute), state.CooldownUntil, time.Nanosecond)

	duplicate, err := runtime.report(context.Background(), AccountHealthReportInput{
		AccountName: accountName,
		FileID:      "file-1",
		EventID:     "event-1",
		Outcome:     AccountHealthFailure,
		StatusCode:  403,
		Reason:      "DOWNLOADQUOTAEXCEEDED",
		Generation:  initial.Generation,
	})
	require.NoError(t, err)
	require.True(t, duplicate.Duplicate)

	repeated, err := runtime.report(context.Background(), AccountHealthReportInput{
		AccountName: accountName,
		FileID:      "file-1",
		EventID:     "event-4",
		Outcome:     AccountHealthFailure,
		StatusCode:  403,
		Reason:      "downloadQuotaExceeded",
		Generation:  state.Generation,
	})
	require.NoError(t, err)
	require.True(t, repeated.Applied)
	stateAfterRepeat, err := runtime.snapshot(context.Background(), accountName)
	require.NoError(t, err)
	require.Equal(t, state.CooldownUntil, stateAfterRepeat.CooldownUntil)
	require.Equal(t, state.EvidenceFileIDs, stateAfterRepeat.EvidenceFileIDs)

	stale, err := runtime.report(context.Background(), AccountHealthReportInput{
		AccountName: accountName,
		FileID:      "file-1",
		EventID:     "stale-success",
		Outcome:     AccountHealthSuccess,
		Generation:  initial.Generation,
	})
	require.NoError(t, err)
	require.True(t, stale.Stale)
	stateAfterStale, err := runtime.snapshot(context.Background(), accountName)
	require.NoError(t, err)
	require.Equal(t, state.CooldownUntil, stateAfterStale.CooldownUntil)
}

func TestAccountHealth_QuotaBackoffRequiresOneSerializedTrialAndOrdinaryFeedbackKeepsTrial(t *testing.T) {
	clock := newAccountHealthTestClock()
	runtime := newAccountHealthRuntime(clock.Now)
	const accountName = "backoff-trial-account"

	ordinary, err := runtime.acquire(context.Background(), accountName, "ordinary-file")
	require.NoError(t, err)
	failure, err := runtime.report(context.Background(), AccountHealthReportInput{
		AccountName: accountName,
		FileID:      "quota-file",
		EventID:     "quota-failure",
		Outcome:     AccountHealthFailure,
		StatusCode:  403,
		Reason:      "downloadQuotaExceeded",
		Generation:  ordinary.Generation,
	})
	require.NoError(t, err)
	require.True(t, failure.Applied)
	clock.Set(clock.Now().Add(failure.RetryAfter))

	trial, err := runtime.acquire(context.Background(), accountName, "trial-file")
	require.NoError(t, err)
	require.True(t, trial.Trial)
	require.Equal(t, ordinary.Generation, trial.Generation)

	var blocked int
	var blockedMu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			_, err := runtime.acquire(context.Background(), accountName, fmt.Sprintf("concurrent-%d", index))
			var unavailable *AccountHealthUnavailableError
			if errors.As(err, &unavailable) {
				blockedMu.Lock()
				blocked++
				blockedMu.Unlock()
				return
			}
			require.NoError(t, err)
		}(i)
	}
	wg.Wait()
	require.Equal(t, 8, blocked)

	ordinaryFeedback, err := runtime.report(context.Background(), AccountHealthReportInput{
		AccountName: accountName,
		FileID:      trial.TrialFileID,
		EventID:     "ordinary-feedback",
		Outcome:     AccountHealthFailure,
		StatusCode:  500,
		Generation:  ordinary.Generation,
	})
	require.NoError(t, err)
	require.True(t, ordinaryFeedback.Applied)
	state, err := runtime.snapshot(context.Background(), accountName)
	require.NoError(t, err)
	require.Equal(t, trial.TrialID, state.LiveTrialID)
	require.Equal(t, []string{"quota-file"}, state.EvidenceFileIDs)

	_, err = runtime.report(context.Background(), AccountHealthReportInput{
		AccountName: accountName,
		FileID:      trial.TrialFileID,
		EventID:     "trial-success",
		Outcome:     AccountHealthSuccess,
		Generation:  trial.Generation,
		TrialID:     trial.TrialID,
	})
	require.NoError(t, err)
	state, err = runtime.snapshot(context.Background(), accountName)
	require.NoError(t, err)
	require.Empty(t, state.LiveTrialID)
	require.False(t, state.ProbeRequired)
}

func TestAccountHealth_CurrentSuccessRetiresOutstandingTrialAndAllowsNormalAcquire(t *testing.T) {
	clock := newAccountHealthTestClock()
	runtime := newAccountHealthRuntime(clock.Now)
	const accountName = "success-retires-trial"
	ordinary, err := runtime.acquire(context.Background(), accountName, "ordinary-file")
	require.NoError(t, err)
	failure, err := runtime.report(context.Background(), AccountHealthReportInput{
		AccountName: accountName,
		FileID:      "quota-file",
		EventID:     "success-retire-quota",
		Outcome:     AccountHealthFailure,
		StatusCode:  403,
		Reason:      "downloadQuotaExceeded",
		Generation:  ordinary.Generation,
	})
	require.NoError(t, err)
	clock.Set(clock.Now().Add(failure.RetryAfter))
	trial, err := runtime.acquire(context.Background(), accountName, "trial-file")
	require.NoError(t, err)
	require.True(t, trial.Trial)

	result, err := runtime.report(context.Background(), AccountHealthReportInput{
		AccountName: accountName,
		FileID:      "ordinary-success-file",
		EventID:     "ordinary-success",
		Outcome:     AccountHealthSuccess,
		Generation:  trial.Generation,
	})
	require.NoError(t, err)
	require.True(t, result.Applied)
	state, err := runtime.snapshot(context.Background(), accountName)
	require.NoError(t, err)
	require.Empty(t, state.LiveTrialID)
	require.False(t, state.ProbeRequired)
	require.Equal(t, trial.Generation+1, state.Generation)

	normal, err := runtime.acquire(context.Background(), accountName, "normal-after-success")
	require.NoError(t, err)
	require.False(t, normal.Trial)
	stale, err := runtime.report(context.Background(), AccountHealthReportInput{
		AccountName: accountName,
		FileID:      trial.TrialFileID,
		EventID:     "retired-trial-result",
		Outcome:     AccountHealthFailure,
		StatusCode:  500,
		Generation:  trial.Generation,
		TrialID:     trial.TrialID,
	})
	require.NoError(t, err)
	require.True(t, stale.Stale)
}

func TestAccountHealth_CooldownTransitionRetiresOlderLiveTrial(t *testing.T) {
	clock := newAccountHealthTestClock()
	runtime := newAccountHealthRuntime(clock.Now)
	const accountName = "cooldown-retires-trial"
	ordinary, err := runtime.acquire(context.Background(), accountName, "ordinary-file")
	require.NoError(t, err)
	failure, err := runtime.report(context.Background(), AccountHealthReportInput{
		AccountName: accountName,
		FileID:      "file-1",
		EventID:     "retire-event-1",
		Outcome:     AccountHealthFailure,
		StatusCode:  403,
		Reason:      "downloadQuotaExceeded",
		Generation:  ordinary.Generation,
	})
	require.NoError(t, err)
	clock.Set(clock.Now().Add(failure.RetryAfter))
	trial, err := runtime.acquire(context.Background(), accountName, "file-2")
	require.NoError(t, err)
	require.True(t, trial.Trial)

	for eventID, fileID := range map[string]string{"retire-event-2": "file-3", "retire-event-3": "file-4"} {
		result, reportErr := runtime.report(context.Background(), AccountHealthReportInput{
			AccountName: accountName,
			FileID:      fileID,
			EventID:     eventID,
			Outcome:     AccountHealthFailure,
			StatusCode:  403,
			Reason:      "downloadQuotaExceeded",
			Generation:  trial.Generation,
		})
		require.NoError(t, reportErr)
		require.True(t, result.Applied)
	}
	state, err := runtime.snapshot(context.Background(), accountName)
	require.NoError(t, err)
	require.Empty(t, state.LiveTrialID)
	require.False(t, state.CooldownUntil.IsZero())
	require.Equal(t, trial.Generation+1, state.Generation)

	stale, err := runtime.report(context.Background(), AccountHealthReportInput{
		AccountName: accountName,
		FileID:      trial.TrialFileID,
		EventID:     "retired-cooldown-trial-result",
		Outcome:     AccountHealthSuccess,
		Generation:  trial.Generation,
		TrialID:     trial.TrialID,
	})
	require.NoError(t, err)
	require.True(t, stale.Stale)
}

func TestAccountHealth_CooldownBoundaryRetiresUnexpectedLiveHourlyTrial(t *testing.T) {
	clock := newAccountHealthTestClock()
	runtime := newAccountHealthRuntime(clock.Now)
	const accountName = "boundary-retires-trial"
	initial, err := runtime.acquire(context.Background(), accountName, "seed")
	require.NoError(t, err)
	for i, fileID := range []string{"file-1", "file-2", "file-3"} {
		reportTestQuotaFailure(t, runtime, clock, accountName, fileID, fmt.Sprintf("boundary-event-%d", i), initial.Generation)
	}
	cooldown, err := runtime.snapshot(context.Background(), accountName)
	require.NoError(t, err)
	state, err := runtime.get(accountName)
	require.NoError(t, err)
	state.mu.Lock()
	state.trial = &accountHealthTrial{
		id:        "old-hourly-trial",
		fileID:    "old-hourly-file",
		expiresAt: cooldown.CooldownUntil.Add(time.Hour),
	}
	state.probeBudget = accountHealthProbeBudget
	state.probeUsed = 1
	state.probeFileIDs = map[string]struct{}{"old-hourly-file": {}}
	state.mu.Unlock()

	clock.Set(cooldown.CooldownUntil)
	boundary, err := runtime.acquire(context.Background(), accountName, "boundary-file")
	require.NoError(t, err)
	require.True(t, boundary.Trial)
	require.NotEqual(t, "old-hourly-trial", boundary.TrialID)
	require.Equal(t, cooldown.Generation+1, boundary.Generation)
	stale, err := runtime.report(context.Background(), AccountHealthReportInput{
		AccountName: accountName,
		FileID:      "old-hourly-file",
		EventID:     "old-hourly-result",
		Outcome:     AccountHealthSuccess,
		Generation:  cooldown.Generation,
		TrialID:     "old-hourly-trial",
	})
	require.NoError(t, err)
	require.True(t, stale.Stale)
}

func TestAccountHealth_RejectsGenerationZeroWithoutChangingCooldown(t *testing.T) {
	clock := newAccountHealthTestClock()
	runtime := newAccountHealthRuntime(clock.Now)
	const accountName = "generation-account"
	initial, err := runtime.acquire(context.Background(), accountName, "seed")
	require.NoError(t, err)
	for i, fileID := range []string{"file-1", "file-2", "file-3"} {
		reportTestQuotaFailure(t, runtime, clock, accountName, fileID, fmt.Sprintf("generation-event-%d", i), initial.Generation)
	}
	before, err := runtime.snapshot(context.Background(), accountName)
	require.NoError(t, err)
	_, err = runtime.report(context.Background(), AccountHealthReportInput{
		AccountName: accountName,
		FileID:      "file-new",
		EventID:     "missing-generation",
		Outcome:     AccountHealthSuccess,
	})
	require.ErrorContains(t, err, "generation must be nonzero")
	after, err := runtime.snapshot(context.Background(), accountName)
	require.NoError(t, err)
	require.Equal(t, before.Generation, after.Generation)
	require.Equal(t, before.CooldownUntil, after.CooldownUntil)
	require.Equal(t, before.EvidenceFileIDs, after.EvidenceFileIDs)
}

func TestAccountHealth_PrecedingGenerationQuotaPreservesCooldownBackoff(t *testing.T) {
	clock := newAccountHealthTestClock()
	runtime := newAccountHealthRuntime(clock.Now)
	const accountName = "cooldown-preceding-account"
	initial, err := runtime.acquire(context.Background(), accountName, "seed")
	require.NoError(t, err)
	for i, fileID := range []string{"file-1", "file-2", "file-3"} {
		reportTestQuotaFailure(t, runtime, clock, accountName, fileID, fmt.Sprintf("cooldown-event-%d", i), initial.Generation)
	}
	cooldown, err := runtime.snapshot(context.Background(), accountName)
	require.NoError(t, err)
	deadline := cooldown.CooldownUntil
	probeAt := cooldown.NextProbeAt
	backoffLevel := cooldown.BackoffLevel
	backoffUntil := cooldown.BackoffUntil
	clock.Set(probeAt.Add(-time.Second))
	preceding, err := runtime.report(context.Background(), AccountHealthReportInput{
		AccountName: accountName,
		FileID:      "preceding-file",
		EventID:     "preceding-quota",
		Outcome:     AccountHealthFailure,
		StatusCode:  403,
		Reason:      "downloadQuotaExceeded",
		Generation:  initial.Generation,
	})
	require.NoError(t, err)
	require.True(t, preceding.Applied)
	withBackoff, err := runtime.snapshot(context.Background(), accountName)
	require.NoError(t, err)
	require.Equal(t, deadline, withBackoff.CooldownUntil)
	require.Equal(t, probeAt, withBackoff.NextProbeAt)
	require.Equal(t, backoffLevel, withBackoff.BackoffLevel)
	require.Equal(t, backoffUntil, withBackoff.BackoffUntil)
	require.Contains(t, withBackoff.EvidenceFileIDs, "preceding-file")

	staleSuccess, err := runtime.report(context.Background(), AccountHealthReportInput{
		AccountName: accountName,
		FileID:      "preceding-file",
		EventID:     "preceding-stale-success",
		Outcome:     AccountHealthSuccess,
		Generation:  initial.Generation,
	})
	require.NoError(t, err)
	require.True(t, staleSuccess.Stale)
	staleFailure, err := runtime.report(context.Background(), AccountHealthReportInput{
		AccountName: accountName,
		FileID:      "another-old-file",
		EventID:     "preceding-stale-failure",
		Outcome:     AccountHealthFailure,
		StatusCode:  500,
		Generation:  initial.Generation,
	})
	require.NoError(t, err)
	require.True(t, staleFailure.Stale)
}

func TestAccountHealth_CurrentGenerationSecondProbeFailureBlocksNextRound(t *testing.T) {
	clock := newAccountHealthTestClock()
	runtime := newAccountHealthRuntime(clock.Now)
	const accountName = "cooldown-current-account"
	initial, err := runtime.acquire(context.Background(), accountName, "seed")
	require.NoError(t, err)
	for i, fileID := range []string{"file-1", "file-2", "file-3"} {
		reportTestQuotaFailure(t, runtime, clock, accountName, fileID, fmt.Sprintf("current-event-%d", i), initial.Generation)
	}
	cooldown, err := runtime.snapshot(context.Background(), accountName)
	require.NoError(t, err)
	clock.Set(cooldown.NextProbeAt)
	firstTrial, err := runtime.acquire(context.Background(), accountName, "probe-first")
	require.NoError(t, err)
	require.True(t, firstTrial.Trial)
	firstFailure, err := runtime.report(context.Background(), AccountHealthReportInput{
		AccountName: accountName,
		FileID:      firstTrial.TrialFileID,
		EventID:     "current-first-failure",
		Outcome:     AccountHealthFailure,
		StatusCode:  500,
		Generation:  firstTrial.Generation,
		TrialID:     firstTrial.TrialID,
	})
	require.NoError(t, err)
	require.True(t, firstFailure.Applied)
	nextProbeAt := cooldown.NextProbeAt.Add(accountHealthProbeInterval)
	clock.Set(nextProbeAt.Add(-2 * time.Second))
	secondTrial, err := runtime.acquire(context.Background(), accountName, "probe-second")
	require.NoError(t, err)
	require.True(t, secondTrial.Trial)
	probeRound, err := runtime.snapshot(context.Background(), accountName)
	require.NoError(t, err)
	require.Equal(t, accountHealthProbeBudget, probeRound.ProbeRoundBudget)
	require.Equal(t, 2, probeRound.ProbeRoundUsed)

	clock.Set(nextProbeAt.Add(-time.Second))
	secondFailure, err := runtime.report(context.Background(), AccountHealthReportInput{
		AccountName: accountName,
		FileID:      secondTrial.TrialFileID,
		EventID:     "current-second-failure",
		Outcome:     AccountHealthFailure,
		StatusCode:  500,
		Generation:  secondTrial.Generation,
		TrialID:     secondTrial.TrialID,
	})
	require.NoError(t, err)
	require.True(t, secondFailure.Applied)
	withBackoff, err := runtime.snapshot(context.Background(), accountName)
	require.NoError(t, err)
	require.Equal(t, nextProbeAt, withBackoff.NextProbeAt)
	require.Equal(t, 2, withBackoff.ProbeRoundUsed)

	clock.Set(nextProbeAt)
	_, err = runtime.acquire(context.Background(), accountName, "next-round-too-early")
	var unavailable *AccountHealthUnavailableError
	require.ErrorAs(t, err, &unavailable)
	require.Contains(t, unavailable.Reason, "short backoff")
	clock.Set(withBackoff.BackoffUntil)
	nextTrial, err := runtime.acquire(context.Background(), accountName, "next-round-after-backoff")
	require.NoError(t, err)
	require.True(t, nextTrial.Trial)
}

func TestAccountHealth_ProbeRoundsAreSerialAndBoundaryRequiresSuccess(t *testing.T) {
	clock := newAccountHealthTestClock()
	runtime := newAccountHealthRuntime(clock.Now)
	const accountName = "probe-account"
	initial, err := runtime.acquire(context.Background(), accountName, "seed")
	require.NoError(t, err)
	for i, fileID := range []string{"file-1", "file-2", "file-3"} {
		reportTestQuotaFailure(t, runtime, clock, accountName, fileID, fmt.Sprintf("event-%d", i), initial.Generation)
	}
	cooldown, err := runtime.snapshot(context.Background(), accountName)
	require.NoError(t, err)

	clock.Set(cooldown.NextProbeAt)
	trial, err := runtime.acquire(context.Background(), accountName, "probe-1")
	require.NoError(t, err)
	require.True(t, trial.Trial)
	require.Equal(t, uint64(2), trial.Generation)

	var wg sync.WaitGroup
	var unavailable int
	var unavailableMu sync.Mutex
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := runtime.acquire(context.Background(), accountName, "probe-other")
			var blocked *AccountHealthUnavailableError
			if errors.As(err, &blocked) {
				unavailableMu.Lock()
				unavailable++
				unavailableMu.Unlock()
				return
			}
			require.NoError(t, err)
		}()
	}
	wg.Wait()
	require.Equal(t, 8, unavailable)

	_, err = runtime.report(context.Background(), AccountHealthReportInput{
		AccountName: accountName,
		FileID:      trial.TrialFileID,
		EventID:     "probe-abandoned",
		Outcome:     AccountHealthAbandoned,
		Generation:  trial.Generation,
		TrialID:     trial.TrialID,
	})
	require.NoError(t, err)
	secondTrial, err := runtime.acquire(context.Background(), accountName, "after-abandon")
	require.NoError(t, err)
	require.True(t, secondTrial.Trial)
	_, err = runtime.report(context.Background(), AccountHealthReportInput{
		AccountName: accountName,
		FileID:      secondTrial.TrialFileID,
		EventID:     "second-probe-abandoned",
		Outcome:     AccountHealthAbandoned,
		Generation:  secondTrial.Generation,
		TrialID:     secondTrial.TrialID,
	})
	require.NoError(t, err)
	_, err = runtime.acquire(context.Background(), accountName, "after-abandon")
	var blocked *AccountHealthUnavailableError
	require.ErrorAs(t, err, &blocked)

	clock.Set(cooldown.CooldownUntil)
	boundary, err := runtime.acquire(context.Background(), accountName, "boundary")
	require.NoError(t, err)
	require.True(t, boundary.Trial)
	failed, err := runtime.report(context.Background(), AccountHealthReportInput{
		AccountName: accountName,
		FileID:      boundary.TrialFileID,
		EventID:     "boundary-failure",
		Outcome:     AccountHealthFailure,
		StatusCode:  500,
		Generation:  boundary.Generation,
		TrialID:     boundary.TrialID,
	})
	require.NoError(t, err)
	require.True(t, failed.Applied)
	clock.Advance(30 * time.Second)

	var trials int
	var trialMu sync.Mutex
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			lease, err := runtime.acquire(context.Background(), accountName, fmt.Sprintf("retry-%d", index))
			if err == nil && lease.Trial {
				trialMu.Lock()
				trials++
				trialMu.Unlock()
				return
			}
			var blocked *AccountHealthUnavailableError
			if errors.As(err, &blocked) {
				return
			}
			require.NoError(t, err)
		}(i)
	}
	wg.Wait()
	require.Equal(t, 1, trials)

	state, err := runtime.snapshot(context.Background(), accountName)
	require.NoError(t, err)
	require.True(t, state.ProbeRequired)
	require.NotEmpty(t, state.LiveTrialID)
	_, err = runtime.report(context.Background(), AccountHealthReportInput{
		AccountName: accountName,
		FileID:      state.LiveTrialFileID,
		EventID:     "boundary-success",
		Outcome:     AccountHealthSuccess,
		Generation:  state.Generation,
		TrialID:     state.LiveTrialID,
	})
	require.NoError(t, err)
	state, err = runtime.snapshot(context.Background(), accountName)
	require.NoError(t, err)
	require.False(t, state.ProbeRequired)
	require.True(t, state.CooldownUntil.IsZero())
	lease, err := runtime.acquire(context.Background(), accountName, "normal")
	require.NoError(t, err)
	require.False(t, lease.Trial)
}

func TestAccountHealth_GORMReloadsDurableProbeAndRetriesAfterClosedDatabase(t *testing.T) {
	initGoogleDriveTestEnv(t)
	oldDB := internaldb.GetDb()
	oldConf := conf.Conf
	dbPath := filepath.Join(t.TempDir(), "account-health.sqlite")
	naming := schema.NamingStrategy{TablePrefix: "ticket01_"}
	openDatabase := func() *gorm.DB {
		database, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{NamingStrategy: naming})
		require.NoError(t, err)
		return database
	}
	database := openDatabase()
	conf.Conf = conf.DefaultConfig(t.TempDir())
	internaldb.Init(database)
	closeDatabase := func(database *gorm.DB) {
		if database == nil {
			return
		}
		sqlDB, err := database.DB()
		if err == nil {
			_ = sqlDB.Close()
		}
	}
	t.Cleanup(func() {
		closeDatabase(database)
		conf.Conf = oldConf
		if oldDB != nil {
			internaldb.Init(oldDB)
		}
	})

	clock := newAccountHealthTestClock()
	runtime := newDurableAccountHealthRuntime(clock.Now)
	upper, err := runtime.acquire(context.Background(), "CaseDistinct", "upper-file")
	require.NoError(t, err)
	lower, err := runtime.acquire(context.Background(), "casedistinct", "lower-file")
	require.NoError(t, err)
	require.NotEqual(t, upper.AccountKey, lower.AccountKey)
	caseReloaded := newDurableAccountHealthRuntime(clock.Now)
	upperReloaded, err := caseReloaded.snapshot(context.Background(), "CaseDistinct")
	require.NoError(t, err)
	lowerReloaded, err := caseReloaded.snapshot(context.Background(), "casedistinct")
	require.NoError(t, err)
	require.Equal(t, upper.AccountKey, upperReloaded.AccountKey)
	require.Equal(t, lower.AccountKey, lowerReloaded.AccountKey)
	require.NotEqual(t, upperReloaded.AccountKey, lowerReloaded.AccountKey)
	lease, err := runtime.acquire(context.Background(), "gorm-account", "seed")
	require.NoError(t, err)
	for i, fileID := range []string{"file-1", "file-2", "file-3"} {
		result, reportErr := runtime.report(context.Background(), AccountHealthReportInput{
			AccountName: "gorm-account",
			FileID:      fileID,
			EventID:     fmt.Sprintf("gorm-event-%d", i),
			Outcome:     AccountHealthFailure,
			StatusCode:  403,
			Reason:      "downloadQuotaExceeded",
			Generation:  lease.Generation,
		})
		require.NoError(t, reportErr)
		require.True(t, result.Applied)
		clock.Advance(2 * time.Minute)
	}
	cooldown, err := runtime.snapshot(context.Background(), "gorm-account")
	require.NoError(t, err)
	require.Equal(t, uint64(2), cooldown.Generation)
	clock.Set(cooldown.NextProbeAt)
	trial, err := runtime.acquire(context.Background(), "gorm-account", "probe-file")
	require.NoError(t, err)
	require.True(t, trial.Trial)

	persisted, err := internaldb.GetGoogleDriveAccountHealthContextOn(context.Background(), database, accountHealthKey("gorm-account"))
	require.NoError(t, err)
	require.Equal(t, trial.Generation, persisted.Generation)
	require.Equal(t, accountHealthProbeBudget, persisted.ProbeBudget)
	require.Equal(t, 1, persisted.ProbeUsed)
	require.Equal(t, trial.TrialID, persisted.LiveTrialID)
	require.Equal(t, "probe-file", persisted.LiveTrialFileID)

	reloadedRuntime := newDurableAccountHealthRuntime(clock.Now)
	reloaded, err := reloadedRuntime.snapshot(context.Background(), "gorm-account")
	require.NoError(t, err)
	require.Equal(t, trial.Generation, reloaded.Generation)
	require.Equal(t, trial.TrialID, reloaded.LiveTrialID)
	require.Equal(t, 1, reloaded.ProbeRoundUsed)

	failedDB, err := database.DB()
	require.NoError(t, err)
	require.NoError(t, failedDB.Close())
	report := AccountHealthReportInput{
		AccountName: "gorm-account",
		FileID:      trial.TrialFileID,
		EventID:     "gorm-retry-event",
		Outcome:     AccountHealthAbandoned,
		Generation:  trial.Generation,
		TrialID:     trial.TrialID,
	}
	_, err = reloadedRuntime.report(context.Background(), report)
	require.Error(t, err)

	database = openDatabase()
	internaldb.Init(database)
	retry, err := reloadedRuntime.report(context.Background(), report)
	require.NoError(t, err)
	require.True(t, retry.Applied)
	final, err := reloadedRuntime.snapshot(context.Background(), "gorm-account")
	require.NoError(t, err)
	require.Empty(t, final.LiveTrialID)
	require.Equal(t, trial.Generation, final.Generation)
	require.Equal(t, 1, final.ProbeRoundUsed)
}

type accountHealthTestPersistence struct {
	mu       sync.Mutex
	rows     map[string]*model.GoogleDriveAccountHealth
	failNext bool
}

func (p *accountHealthTestPersistence) load(key string) (*model.GoogleDriveAccountHealth, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	row, ok := p.rows[key]
	if !ok {
		return nil, gorm.ErrRecordNotFound
	}
	copy := *row
	return &copy, nil
}

func (p *accountHealthTestPersistence) save(row *model.GoogleDriveAccountHealth) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failNext {
		p.failNext = false
		return errors.New("injected health persistence failure")
	}
	copy := *row
	p.rows[row.AccountKey] = &copy
	return nil
}

func TestAccountHealth_SaveFailureRollsBackForIdempotentRetryAndReload(t *testing.T) {
	clock := newAccountHealthTestClock()
	persistence := &accountHealthTestPersistence{rows: make(map[string]*model.GoogleDriveAccountHealth)}
	runtime := newAccountHealthRuntimeWithPersistence(clock.Now, persistence.load, persistence.save)
	lease, err := runtime.acquire(context.Background(), "durable-account", "seed")
	require.NoError(t, err)
	persistence.mu.Lock()
	persistence.failNext = true
	persistence.mu.Unlock()

	input := AccountHealthReportInput{
		AccountName: "durable-account",
		FileID:      "file-1",
		EventID:     "retry-event",
		Outcome:     AccountHealthFailure,
		StatusCode:  403,
		Reason:      "downloadQuotaExceeded",
		Generation:  lease.Generation,
	}
	_, err = runtime.report(context.Background(), input)
	require.Error(t, err)
	retry, err := runtime.report(context.Background(), input)
	require.NoError(t, err)
	require.True(t, retry.Applied)
	clock.Advance(2 * time.Minute)
	second, err := runtime.report(context.Background(), AccountHealthReportInput{
		AccountName: "durable-account",
		FileID:      "file-2",
		EventID:     "durable-event-2",
		Outcome:     AccountHealthFailure,
		StatusCode:  403,
		Reason:      "downloadQuotaExceeded",
		Generation:  lease.Generation,
	})
	require.NoError(t, err)
	require.True(t, second.Applied)
	clock.Advance(2 * time.Minute)
	third, err := runtime.report(context.Background(), AccountHealthReportInput{
		AccountName: "durable-account",
		FileID:      "file-3",
		EventID:     "durable-event-3",
		Outcome:     AccountHealthFailure,
		StatusCode:  403,
		Reason:      "downloadQuotaExceeded",
		Generation:  lease.Generation,
	})
	require.NoError(t, err)
	require.True(t, third.Applied)

	reloaded := newAccountHealthRuntimeWithPersistence(clock.Now, persistence.load, persistence.save)
	state, err := reloaded.snapshot(context.Background(), "durable-account")
	require.NoError(t, err)
	require.Equal(t, uint64(2), state.Generation)
	require.False(t, state.CooldownUntil.IsZero())
}

func TestDeduplicateAccountConfigsKeepsFirstCredentialRecordAndOriginalIndexes(t *testing.T) {
	active := deduplicateAccountConfigs([]accountConfig{
		{Index: 0, Name: " shared "},
		{Index: 1, Name: "shared"},
		{Index: 2, Name: "other"},
	})
	require.Len(t, active, 2)
	require.Equal(t, 0, active[0].Index)
	require.Equal(t, "shared", active[0].Name)
	require.Equal(t, 2, active[1].Index)
}

func TestGoogleDriveMountsShareTrimmedAccountHealth(t *testing.T) {
	clock := newAccountHealthTestClock()
	runtime := newAccountHealthRuntime(clock.Now)
	accounts := []accountRuntime{{
		Index: 0,
		Name:  "shared",
		Token: oauthTokenView{AccessToken: "token"},
	}}
	otherAccounts := []accountRuntime{{
		Index: 0,
		Name:  " shared ",
		Token: oauthTokenView{AccessToken: "other-token"},
	}}
	firstMount := &GoogleDrive{
		accounts:      accounts,
		accountHealth: runtime,
		accountPool:   newAccountPool("round_robin", accounts),
	}
	secondMount := &GoogleDrive{
		accounts:      otherAccounts,
		accountHealth: runtime,
		accountPool:   newAccountPool("round_robin", otherAccounts),
	}

	first, err := firstMount.acquireDownloadAccount(context.Background(), "file-1", 0)
	require.NoError(t, err)
	require.False(t, first.health.Trial)
	result, err := runtime.report(context.Background(), AccountHealthReportInput{
		AccountName: "shared",
		FileID:      "file-1",
		EventID:     "mount-event",
		Outcome:     AccountHealthFailure,
		StatusCode:  403,
		Reason:      "downloadQuotaExceeded",
		Generation:  first.health.Generation,
	})
	require.NoError(t, err)
	require.True(t, result.Applied)
	_, err = secondMount.acquireDownloadAccount(context.Background(), "file-2", 0)
	var blocked *AccountHealthUnavailableError
	require.ErrorAs(t, err, &blocked)
}

func TestGoogleDriveAccountsJSON_DuplicateNameUpdatesFirstRecordOnly(t *testing.T) {
	initGoogleDriveTestEnv(t)
	path := writeTempAccountsFile(t, `[
		{"name":" shared ","token":{"access_token":"first","refresh_token":"refresh-first"}},
		{"name":"shared","token":{"refresh_token":"refresh-duplicate","access_token":"duplicate"}},
		{"name":"other","token":{"access_token":"other","refresh_token":"refresh-other"}}
	]`)
	d := &GoogleDrive{
		Addition: Addition{AccountsJSON: path},
		modeCfg: downloadModeConfig{
			Enabled:          true,
			AccountsPath:     path,
			SelectionPolicy:  "round_robin",
			DownloadRetryMax: 2,
		},
	}
	require.NoError(t, d.initAccountsJSONMode(context.Background()))
	t.Cleanup(func() { _ = d.Drop(context.Background()) })
	require.Len(t, d.accounts, 2)
	require.Equal(t, 0, d.accounts[0].Index)
	require.Equal(t, 2, d.accounts[1].Index)
	originalEntries := readPersistedAccountsFile(t, path)
	originalDuplicateToken := string(originalEntries[1].Token)

	require.NoError(t, d.updateAccountToken(0, oauthTokenView{
		AccessToken:  "first-updated",
		RefreshToken: "refresh-first-updated",
	}))
	require.NoError(t, d.updateAccountToken(1, oauthTokenView{
		AccessToken:  "other-updated",
		RefreshToken: "refresh-other-updated",
	}))
	require.NoError(t, d.accountStore.flush(context.Background()))
	require.NoError(t, d.updateAccountToken(0, oauthTokenView{
		AccessToken:  "first-updated-again",
		RefreshToken: "refresh-first-updated-again",
	}))
	require.NoError(t, d.accountStore.flush(context.Background()))

	entries := readPersistedAccountsFile(t, path)
	require.Len(t, entries, 3)
	var firstToken, duplicateToken, otherToken oauthTokenView
	require.NoError(t, json.Unmarshal(entries[0].Token, &firstToken))
	require.NoError(t, json.Unmarshal(entries[1].Token, &duplicateToken))
	require.NoError(t, json.Unmarshal(entries[2].Token, &otherToken))
	require.Equal(t, "first-updated-again", firstToken.AccessToken)
	require.Equal(t, originalDuplicateToken, string(entries[1].Token))
	require.Equal(t, "duplicate", duplicateToken.AccessToken)
	require.Equal(t, "other-updated", otherToken.AccessToken)
}

func TestAccountHealthContextCancellationBoundsRuntimeAndStateLocks(t *testing.T) {
	clock := newAccountHealthTestClock()
	runtime := newAccountHealthRuntime(clock.Now)
	runtime.mu.Lock()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := runtime.getWithContext(ctx, "blocked-runtime")
		done <- err
	}()
	time.Sleep(5 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("runtime lock wait ignored context cancellation")
	}
	if _, ok := runtime.states[accountHealthKey("blocked-runtime")]; ok {
		t.Fatal("canceled runtime lookup installed state after the lock was released")
	}
	runtime.mu.Unlock()

	state, err := runtime.get("blocked-state")
	require.NoError(t, err)
	state.mu.Lock()
	ctx, cancel = context.WithCancel(context.Background())
	doneReport := make(chan error, 1)
	go func() {
		_, reportErr := runtime.report(ctx, AccountHealthReportInput{
			AccountName: "blocked-state",
			FileID:      "blocked-file",
			EventID:     "blocked-event",
			Outcome:     AccountHealthFailure,
			StatusCode:  500,
			Generation:  1,
		})
		doneReport <- reportErr
	}()
	time.Sleep(5 * time.Millisecond)
	cancel()
	select {
	case reportErr := <-doneReport:
		require.ErrorIs(t, reportErr, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("state lock wait ignored context cancellation")
	}
	if _, ok := state.eventIDs["blocked-event"]; ok {
		t.Fatal("canceled report mutated state after the lock blocker was released")
	}
	state.mu.Unlock()
}

func TestAccountHealthContextCancellationBoundsDatabaseLookup(t *testing.T) {
	initGoogleDriveTestEnv(t)
	oldDB := internaldb.GetDb()
	oldConf := conf.Conf
	database, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "ticket02-context-query.sqlite")), &gorm.Config{
		NamingStrategy: schema.NamingStrategy{TablePrefix: "ticket02_context_query_"},
	})
	require.NoError(t, err)
	conf.Conf = conf.DefaultConfig(t.TempDir())
	internaldb.Init(database)
	cleanup := func() {
		if sqlDB, dbErr := database.DB(); dbErr == nil {
			_ = sqlDB.Close()
		}
		conf.Conf = oldConf
		if oldDB != nil {
			internaldb.Init(oldDB)
		}
	}
	t.Cleanup(cleanup)

	clock := newAccountHealthTestClock()
	runtime := newDurableAccountHealthRuntime(clock.Now)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	started := make(chan struct{})
	callbackName := "ticket02-block-account-health-query"
	err = database.Callback().Query().Before("gorm:query").Register(callbackName, func(tx *gorm.DB) {
		select {
		case <-started:
		default:
			close(started)
		}
		<-tx.Statement.Context.Done()
		tx.Error = tx.Statement.Context.Err()
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Callback().Query().Remove(callbackName) })

	startedAt := time.Now()
	_, err = runtime.getWithContext(ctx, "blocked-query")
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, time.Since(startedAt), time.Second)
	select {
	case <-started:
	default:
		t.Fatal("database lookup callback did not run")
	}
	require.Empty(t, runtime.states)
}

func TestAccountHealthInitialPersistenceReceivesContextAndLeavesNoLateState(t *testing.T) {
	initGoogleDriveTestEnv(t)
	oldDB := internaldb.GetDb()
	oldConf := conf.Conf
	database, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "ticket02-context-create.sqlite")), &gorm.Config{
		NamingStrategy: schema.NamingStrategy{TablePrefix: "ticket02_context_create_"},
	})
	require.NoError(t, err)
	conf.Conf = conf.DefaultConfig(t.TempDir())
	internaldb.Init(database)
	cleanup := func() {
		if sqlDB, dbErr := database.DB(); dbErr == nil {
			_ = sqlDB.Close()
		}
		conf.Conf = oldConf
		if oldDB != nil {
			internaldb.Init(oldDB)
		}
	}
	t.Cleanup(cleanup)

	clock := newAccountHealthTestClock()
	runtime := newDurableAccountHealthRuntime(clock.Now)
	ctx, cancel := context.WithCancel(context.Background())
	var seenContext context.Context
	callbackName := "ticket02-cancel-account-health-create"
	err = database.Callback().Create().Before("gorm:create").Register(callbackName, func(tx *gorm.DB) {
		seenContext = tx.Statement.Context
		cancel()
		tx.Error = tx.Statement.Context.Err()
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Callback().Create().Remove(callbackName) })

	_, err = runtime.getWithContext(ctx, "initial-create")
	require.ErrorIs(t, err, context.Canceled)
	require.Same(t, ctx, seenContext)
	require.Empty(t, runtime.states)
	_, err = internaldb.GetGoogleDriveAccountHealthContextOn(context.Background(), database, accountHealthKey("initial-create"))
	require.ErrorIs(t, err, gorm.ErrRecordNotFound)
}

func TestAccountHealthPersistenceUsesStateDatabaseHandle(t *testing.T) {
	initGoogleDriveTestEnv(t)
	oldDB := internaldb.GetDb()
	oldConf := conf.Conf
	databaseA, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "ticket02-state-database-a.sqlite")), &gorm.Config{
		NamingStrategy: schema.NamingStrategy{TablePrefix: "ticket02_state_a_"},
	})
	require.NoError(t, err)
	databaseB, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "ticket02-state-database-b.sqlite")), &gorm.Config{
		NamingStrategy: schema.NamingStrategy{TablePrefix: "ticket02_state_b_"},
	})
	require.NoError(t, err)
	conf.Conf = conf.DefaultConfig(t.TempDir())
	require.NoError(t, databaseA.AutoMigrate(new(model.GoogleDriveAccountHealth)))
	require.NoError(t, databaseB.AutoMigrate(new(model.GoogleDriveAccountHealth)))
	internaldb.Init(databaseA)
	t.Cleanup(func() {
		if sqlDB, dbErr := databaseA.DB(); dbErr == nil {
			_ = sqlDB.Close()
		}
		if sqlDB, dbErr := databaseB.DB(); dbErr == nil {
			_ = sqlDB.Close()
		}
		conf.Conf = oldConf
		if oldDB != nil {
			internaldb.Init(oldDB)
		}
	})

	runtime := newDurableAccountHealthRuntime(time.Now)
	state, err := runtime.get("state-owned-account")
	require.NoError(t, err)
	require.Same(t, databaseA, state.database)

	internaldb.Init(databaseB)
	state.mu.Lock()
	state.generation++
	err = runtime.persistLocked(state)
	state.mu.Unlock()
	require.NoError(t, err)

	_, err = internaldb.GetGoogleDriveAccountHealthContextOn(context.Background(), databaseB, accountHealthKey("state-owned-account"))
	require.ErrorIs(t, err, gorm.ErrRecordNotFound)
	loaded, err := internaldb.GetGoogleDriveAccountHealthContextOn(context.Background(), databaseA, accountHealthKey("state-owned-account"))
	require.NoError(t, err)
	require.Equal(t, state.generation, loaded.Generation)
}
