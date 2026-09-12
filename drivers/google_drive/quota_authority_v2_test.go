package google_drive

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	internaldb "github.com/OpenListTeam/OpenList/v4/internal/db"
	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/stretchr/testify/require"
)

type quotaTestClock struct {
	mu  sync.Mutex
	now time.Time
}

func newQuotaTestClock() *quotaTestClock {
	return &quotaTestClock{now: time.Unix(1_700_000_000, 0)}
}

func (c *quotaTestClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *quotaTestClock) Advance(delta time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(delta)
	c.mu.Unlock()
}

func quotaTestReport(account, file, observation, eventType, outcome, reason string, generation, fileGeneration uint64) driver.DownloadAuthorizationFeedback {
	return driver.DownloadAuthorizationFeedback{
		AuthorityProtocol: model.DownloadAuthorityProtocol,
		Ticket:            "ticket-" + account + "-" + file,
		Provider:          googleDriveAccountProvider,
		AccountName:       account,
		FileID:            file,
		Generation:        generation,
		FileGeneration:    fileGeneration,
		ObservationID:     observation,
		EventType:         eventType,
		EventID:           driver.CanonicalDownloadAuthorizationEventID(observation, eventType),
		Outcome:           outcome,
		StatusCode: func() int {
			if eventType == "quota" {
				return http.StatusForbidden
			}
			return http.StatusOK
		}(),
		Reason: reason,
	}
}

func TestQuotaAuthorityV2PairedControlsCoolAccountButNotOnFailuresAlone(t *testing.T) {
	clock := newQuotaTestClock()
	runtime := newQuotaAuthorityRuntime(clock.Now)
	ctx := context.Background()

	for _, fileID := range []string{"control-1", "control-2", "control-3"} {
		decision, err := runtime.authorize(ctx, "account", fileID)
		require.NoError(t, err)
		_, err = runtime.report(ctx, quotaTestReport("account", fileID, "quota-"+fileID, "quota", "failure", "quota", decision.AccountGeneration, decision.FileGeneration))
		require.NoError(t, err)
		clock.Advance(time.Second)
		control, err := runtime.authorize(ctx, "other", fileID)
		require.NoError(t, err)
		_, err = runtime.report(ctx, quotaTestReport("other", fileID, "late-success-"+fileID, "success", "success", "", control.AccountGeneration, control.FileGeneration))
		require.NoError(t, err)
		if fileID != "control-3" {
			require.True(t, runtime.getAccountLocked("account").CooldownUntil.IsZero())
		}
	}

	account := runtime.getAccountLocked("account")
	file := runtime.getFileLocked("control-1")
	require.False(t, account.CooldownUntil.IsZero())
	require.Equal(t, uint64(2), account.Generation)
	require.True(t, file.CooldownUntil.IsZero())
}

func TestQuotaAuthorityV2FileControlTakesPrecedenceOverFileCooldown(t *testing.T) {
	clock := newQuotaTestClock()
	runtime := newQuotaAuthorityRuntime(clock.Now)
	ctx := context.Background()
	control, err := runtime.authorize(ctx, "account-a", "control-a")
	require.NoError(t, err)
	_, err = runtime.report(ctx, quotaTestReport("account-a", "control-a", "control-a", "success", "success", "", control.AccountGeneration, control.FileGeneration))
	require.NoError(t, err)
	first, err := runtime.authorize(ctx, "account-a", "restricted")
	require.NoError(t, err)
	_, err = runtime.report(ctx, quotaTestReport("account-a", "restricted", "quota-a", "quota", "failure", "limit", first.AccountGeneration, first.FileGeneration))
	require.NoError(t, err)
	clock.Advance(time.Second)
	control, err = runtime.authorize(ctx, "account-b", "control-b")
	require.NoError(t, err)
	_, err = runtime.report(ctx, quotaTestReport("account-b", "control-b", "control-b", "success", "success", "", control.AccountGeneration, control.FileGeneration))
	require.NoError(t, err)
	secondSuccess, err := runtime.authorize(ctx, "account-b", "restricted")
	require.NoError(t, err)
	_, err = runtime.report(ctx, quotaTestReport("account-b", "restricted", "success-b", "success", "success", "", secondSuccess.AccountGeneration, secondSuccess.FileGeneration))
	require.NoError(t, err)
	secondQuota, err := runtime.authorize(ctx, "account-b", "restricted")
	require.NoError(t, err)
	_, err = runtime.report(ctx, quotaTestReport("account-b", "restricted", "quota-b", "quota", "failure", "limit", secondQuota.AccountGeneration, secondQuota.FileGeneration))
	require.NoError(t, err)

	file := runtime.getFileLocked("restricted")
	require.True(t, file.CooldownUntil.IsZero())
	evidence, ok := runtime.getAccountLocked("account-a").Evidence["restricted"]
	require.True(t, ok)
	require.False(t, evidence.ControlAt.IsZero())
}

func TestQuotaAuthorityV2SingleUseReleaseAndClaimAreDistinct(t *testing.T) {
	clock := newQuotaTestClock()
	runtime := newQuotaAuthorityRuntime(clock.Now)
	ctx := context.Background()
	initial, err := runtime.authorize(ctx, "account-a", "restricted")
	require.NoError(t, err)
	_, err = runtime.report(ctx, quotaTestReport("account-a", "restricted", "quota", "quota", "failure", "quota", initial.AccountGeneration, initial.FileGeneration))
	require.NoError(t, err)
	blocked, err := runtime.permission(ctx, "account-a", "restricted", initial.AccountGeneration, initial.FileGeneration, quotaModeNormal, "", "", "check", "", quotaPermissionContext{Ticket: "ticket-account-a-restricted"})
	require.NoError(t, err)
	require.False(t, blocked.Allow)
	require.Contains(t, blocked.Reason, "quota decision")
	plan, err := runtime.nextDiagnostic(ctx, "restricted", "account-a", []string{"account-a", "account-b"})
	require.NoError(t, err)
	require.True(t, plan.Allow)
	require.Equal(t, quotaModeDiagnostic, plan.Mode)
	firstReservationID := plan.ReservationID
	firstObservationID := plan.ObservationID

	checked, err := runtime.permission(ctx, "account-b", "restricted", plan.AccountGeneration, plan.FileGeneration, quotaModeDiagnostic, plan.ObservationID, plan.ReservationID, "check", "")
	require.NoError(t, err)
	require.True(t, checked.Allow)
	released, err := runtime.permission(ctx, "account-b", "restricted", plan.AccountGeneration, plan.FileGeneration, quotaModeDiagnostic, plan.ObservationID, plan.ReservationID, "release", "")
	require.NoError(t, err)
	require.True(t, released.Allow)
	replayRelease, err := runtime.permission(ctx, "account-b", "restricted", plan.AccountGeneration, plan.FileGeneration, quotaModeDiagnostic, plan.ObservationID, firstReservationID, "release", "")
	require.NoError(t, err)
	require.True(t, replayRelease.Allow)

	plan, err = runtime.nextDiagnostic(ctx, "restricted", "account-a", []string{"account-a", "account-b"})
	require.NoError(t, err)
	replayAfterNew, err := runtime.permission(ctx, "account-b", "restricted", plan.AccountGeneration, plan.FileGeneration, quotaModeDiagnostic, firstObservationID, firstReservationID, "release", "")
	require.NoError(t, err)
	require.True(t, replayAfterNew.Allow)
	require.NotNil(t, runtime.getFileLocked("restricted").Diagnostic)
	claimed, err := runtime.permission(ctx, "account-b", "restricted", plan.AccountGeneration, plan.FileGeneration, quotaModeDiagnostic, plan.ObservationID, plan.ReservationID, "claim", "claim-1")
	require.NoError(t, err)
	require.True(t, claimed.Allow)
	checkedAfterClaim, err := runtime.permission(ctx, "account-b", "restricted", plan.AccountGeneration, plan.FileGeneration, quotaModeDiagnostic, plan.ObservationID, plan.ReservationID, "check", "claim-1")
	require.NoError(t, err)
	require.True(t, checkedAfterClaim.Allow)
	require.Equal(t, claimed.PermissionExpiresAt, checkedAfterClaim.PermissionExpiresAt)
	idempotent, err := runtime.permission(ctx, "account-b", "restricted", plan.AccountGeneration, plan.FileGeneration, quotaModeDiagnostic, plan.ObservationID, plan.ReservationID, "claim", "claim-1")
	require.NoError(t, err)
	require.True(t, idempotent.Allow)
	otherClaim, err := runtime.permission(ctx, "account-b", "restricted", plan.AccountGeneration, plan.FileGeneration, quotaModeDiagnostic, plan.ObservationID, plan.ReservationID, "claim", "claim-2")
	require.NoError(t, err)
	require.False(t, otherClaim.Allow)
	releasedClaim, err := runtime.permission(ctx, "account-b", "restricted", plan.AccountGeneration, plan.FileGeneration, quotaModeDiagnostic, plan.ObservationID, plan.ReservationID, "release", "")
	require.NoError(t, err)
	require.False(t, releasedClaim.Allow)
}

func TestQuotaAuthorityV2BoundaryProbeConsumesOnceAndExpiresClaim(t *testing.T) {
	clock := newQuotaTestClock()
	runtime := newQuotaAuthorityRuntime(clock.Now)
	ctx := context.Background()
	file := runtime.getFileLocked("boundary")
	file.CooldownUntil = clock.Now().Add(-time.Second)
	file.Generation = 4

	plan, err := runtime.authorize(ctx, "account-a", "boundary")
	require.NoError(t, err)
	require.True(t, plan.Allow)
	require.Equal(t, quotaModeProbe, plan.Mode)
	require.Equal(t, 0, runtime.getFileLocked("boundary").ProbeUsed)

	claimed, err := runtime.permission(ctx, "account-a", "boundary", plan.AccountGeneration, plan.FileGeneration, quotaModeProbe, plan.ObservationID, plan.ReservationID, "claim", "execution-1")
	require.NoError(t, err)
	require.True(t, claimed.Allow)
	require.Equal(t, 1, runtime.getFileLocked("boundary").ProbeUsed)
	clock.Advance(31 * time.Second)
	expired, err := runtime.permission(ctx, "account-a", "boundary", plan.AccountGeneration, plan.FileGeneration, quotaModeProbe, plan.ObservationID, plan.ReservationID, "claim", "execution-1")
	require.NoError(t, err)
	require.False(t, expired.Allow)
	_, consumed := runtime.consumed[plan.ReservationID]
	require.True(t, consumed)
	require.True(t, runtime.getFileLocked("boundary").BackoffUntil.After(clock.Now()))
	lateReport := quotaTestReport("account-a", "boundary", plan.ObservationID, "failure", "failure", "network", plan.AccountGeneration, plan.FileGeneration)
	lateReport.TrialID = plan.ReservationID
	lateReport.ExecutionClaimID = "execution-1"
	late, err := runtime.report(ctx, lateReport)
	require.NoError(t, err)
	require.True(t, late.Applied)
}

func TestQuotaAuthorityV2FileProbeCanStartOneNewRoundAfterAnHour(t *testing.T) {
	clock := newQuotaTestClock()
	runtime := newQuotaAuthorityRuntime(clock.Now)
	ctx := context.Background()
	account := runtime.getAccountLocked("probe-account")
	file := runtime.getFileLocked("probe-file")
	file.CooldownUntil = clock.Now().Add(2 * time.Hour)
	file.NextProbeAt = clock.Now()
	runtime.observations["other-file-success"] = quotaObservation{
		EventID: "other-file-success", ObservationID: "other-file-success", EventType: "success", Provider: googleDriveAccountProvider,
		AccountName: account.Name, FileID: "other-file", Outcome: "success", AccountGeneration: account.Generation, At: clock.Now(),
	}

	first, err := runtime.authorize(ctx, account.Name, file.FileID)
	require.NoError(t, err)
	require.Equal(t, quotaModeProbe, first.Mode)
	claimed, err := runtime.permission(ctx, account.Name, file.FileID, first.AccountGeneration, first.FileGeneration, quotaModeProbe, first.ObservationID, first.ReservationID, "claim", "probe-claim")
	require.NoError(t, err)
	require.True(t, claimed.Allow)
	_, err = runtime.report(ctx, driver.DownloadAuthorizationFeedback{
		AuthorityProtocol: model.DownloadAuthorityProtocol,
		Ticket:            "probe-ticket",
		Provider:          googleDriveAccountProvider,
		AccountName:       account.Name,
		FileID:            file.FileID,
		Generation:        first.AccountGeneration,
		FileGeneration:    first.FileGeneration,
		TrialID:           first.ReservationID,
		ExecutionClaimID:  claimed.ExecutionClaimID,
		ObservationID:     first.ObservationID,
		EventType:         "failure",
		EventID:           driver.CanonicalDownloadAuthorizationEventID(first.ObservationID, "failure"),
		Outcome:           "failure",
		StatusCode:        http.StatusBadGateway,
	})
	require.NoError(t, err)
	require.Equal(t, 1, runtime.getFileLocked(file.FileID).ProbeUsed)

	clock.Advance(59 * time.Minute)
	runtime.observations["recent-other-file-success"] = quotaObservation{
		EventID: "recent-other-file-success", ObservationID: "recent-other-file-success", EventType: "success", Provider: googleDriveAccountProvider,
		AccountName: account.Name, FileID: "other-file", Outcome: "success", AccountGeneration: account.Generation, At: clock.Now(),
	}
	clock.Advance(time.Minute + time.Second)
	second, err := runtime.authorize(ctx, account.Name, file.FileID)
	require.NoError(t, err)
	require.Equal(t, quotaModeProbe, second.Mode)
	require.NotEqual(t, first.ReservationID, second.ReservationID)
}

func TestQuotaAuthorityV2QuotaRoundBlocksNewGrantsButHonorsLivePriorPermit(t *testing.T) {
	clock := newQuotaTestClock()
	runtime := newQuotaAuthorityRuntime(clock.Now)
	ctx := context.Background()
	issued, err := runtime.authorize(ctx, "account-a", "pending-file")
	require.NoError(t, err)
	feedback := quotaTestReport("account-a", "pending-file", issued.ObservationID, "quota", "failure", "quota", issued.AccountGeneration, issued.FileGeneration)
	feedback.Ticket = "original-ticket"
	_, err = runtime.report(ctx, feedback)
	require.NoError(t, err)

	newGrant, err := runtime.authorize(ctx, "account-b", "pending-file")
	require.NoError(t, err)
	require.False(t, newGrant.Allow)
	require.Contains(t, newGrant.Reason, "quota decision")

	livePrior, err := runtime.permission(ctx, "account-a", "pending-file", issued.AccountGeneration, issued.FileGeneration, quotaModeNormal, issued.ObservationID, "", "check", "", quotaPermissionContext{
		Ticket:          "prior-ticket",
		IssuedAt:        clock.Now().Add(-time.Second).Unix(),
		PermitExpiresAt: clock.Now().Add(time.Second).Unix(),
	})
	require.NoError(t, err)
	require.True(t, livePrior.Allow)

	expiredPrior, err := runtime.permission(ctx, "account-a", "pending-file", issued.AccountGeneration, issued.FileGeneration, quotaModeNormal, issued.ObservationID, "", "check", "", quotaPermissionContext{
		Ticket:          "expired-prior-ticket",
		IssuedAt:        clock.Now().Add(-time.Second).Unix(),
		PermitExpiresAt: clock.Now().Add(-time.Second).Unix(),
	})
	require.NoError(t, err)
	require.False(t, expiredPrior.Allow)
}

func TestQuotaAuthorityV2PendingQuotaRoundEventuallyReleasesAfterLostReference(t *testing.T) {
	clock := newQuotaTestClock()
	runtime := newQuotaAuthorityRuntime(clock.Now)
	ctx := context.Background()
	issued, err := runtime.authorize(ctx, "account-a", "lost-reference-file")
	require.NoError(t, err)
	feedback := quotaTestReport("account-a", "lost-reference-file", issued.ObservationID, "quota", "failure", "quota", issued.AccountGeneration, issued.FileGeneration)
	feedback.Ticket = "lost-reference-ticket"
	_, err = runtime.report(ctx, feedback)
	require.NoError(t, err)

	clock.Advance(quotaReservationTTL + time.Second)
	blocked, err := runtime.authorize(ctx, "account-b", "lost-reference-file")
	require.NoError(t, err)
	require.False(t, blocked.Allow)
	require.False(t, runtime.getFileLocked("lost-reference-file").QuotaPending)
	require.Contains(t, blocked.Reason, "backoff")

	clock.Advance(quotaUncertainTTL + time.Second)
	recovered, err := runtime.authorize(ctx, "account-b", "lost-reference-file")
	require.NoError(t, err)
	require.True(t, recovered.Allow)
}

func TestQuotaAuthorityV2DiagnosticSuccessResolvesOriginalQuotaSuspension(t *testing.T) {
	clock := newQuotaTestClock()
	runtime := newQuotaAuthorityRuntime(clock.Now)
	ctx := context.Background()
	issued, err := runtime.authorize(ctx, "account-a", "diagnostic-resolution-file")
	require.NoError(t, err)
	quota := quotaTestReport("account-a", "diagnostic-resolution-file", issued.ObservationID, "quota", "failure", "quota", issued.AccountGeneration, issued.FileGeneration)
	quota.Ticket = "account-a-ticket"
	_, err = runtime.report(ctx, quota)
	require.NoError(t, err)
	plan, err := runtime.nextDiagnostic(ctx, "diagnostic-resolution-file", "account-a", []string{"account-a", "account-b"})
	require.NoError(t, err)
	require.True(t, plan.Allow)
	claimed, err := runtime.permission(ctx, "account-b", "diagnostic-resolution-file", plan.AccountGeneration, plan.FileGeneration, quotaModeDiagnostic, plan.ObservationID, plan.ReservationID, "claim", "diagnostic-resolution-claim")
	require.NoError(t, err)
	require.True(t, claimed.Allow)
	_, err = runtime.report(ctx, driver.DownloadAuthorizationFeedback{
		AuthorityProtocol: model.DownloadAuthorityProtocol,
		Ticket:            "account-b-ticket",
		Provider:          googleDriveAccountProvider,
		AccountName:       "account-b",
		FileID:            "diagnostic-resolution-file",
		Generation:        plan.AccountGeneration,
		FileGeneration:    plan.FileGeneration,
		TrialID:           plan.ReservationID,
		ExecutionClaimID:  claimed.ExecutionClaimID,
		ObservationID:     plan.ObservationID,
		EventType:         "success",
		EventID:           driver.CanonicalDownloadAuthorizationEventID(plan.ObservationID, "success"),
		Outcome:           "success",
		StatusCode:        200,
	})
	require.NoError(t, err)

	resumed, err := runtime.permission(ctx, "account-a", "diagnostic-resolution-file", issued.AccountGeneration, issued.FileGeneration, quotaModeNormal, issued.ObservationID, "", "check", "", quotaPermissionContext{
		Ticket:          "account-a-ticket",
		IssuedAt:        clock.Now().Add(-time.Second).Unix(),
		PermitExpiresAt: clock.Now().Add(time.Second).Unix(),
	})
	require.NoError(t, err)
	require.True(t, resumed.Allow)
	require.NotContains(t, resumed.Reason, "quota decision")
}

func TestQuotaAuthorityV2ResolvedQuotaRotatesAcknowledgedNormalObservation(t *testing.T) {
	for _, scenario := range []struct {
		name               string
		acknowledgeSuccess bool
	}{
		{name: "after acknowledged success", acknowledgeSuccess: true},
		{name: "before success acknowledgment", acknowledgeSuccess: false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			clock := newQuotaTestClock()
			runtime := newQuotaAuthorityRuntime(clock.Now)
			ctx := context.Background()
			ticket := "same-normal-ticket-" + scenario.name

			issued, err := runtime.authorize(ctx, "account-a", "reusable-file")
			require.NoError(t, err)
			first, err := runtime.permission(ctx, "account-a", "reusable-file", issued.AccountGeneration, issued.FileGeneration, quotaModeNormal, issued.ObservationID, "", "check", "", quotaPermissionContext{
				Ticket:          ticket,
				IssuedAt:        clock.Now().Unix(),
				PermitExpiresAt: clock.Now().Add(time.Minute).Unix(),
			})
			require.NoError(t, err)
			require.True(t, first.Allow)
			require.True(t, first.ReportSuccess)

			if scenario.acknowledgeSuccess {
				success := quotaTestReport("account-a", "reusable-file", first.ObservationID, "success", "success", "", issued.AccountGeneration, issued.FileGeneration)
				success.Ticket = ticket
				result, reportErr := runtime.report(ctx, success)
				require.NoError(t, reportErr)
				require.True(t, result.Applied)

				acknowledged, permissionErr := runtime.permission(ctx, "account-a", "reusable-file", issued.AccountGeneration, issued.FileGeneration, quotaModeNormal, first.ObservationID, "", "check", "", quotaPermissionContext{
					Ticket:          ticket,
					IssuedAt:        clock.Now().Unix(),
					PermitExpiresAt: clock.Now().Add(time.Minute).Unix(),
				})
				require.NoError(t, permissionErr)
				require.True(t, acknowledged.Allow)
				require.False(t, acknowledged.ReportSuccess)
				require.Equal(t, first.ObservationID, acknowledged.ObservationID)
			}

			quota := quotaTestReport("account-a", "reusable-file", first.ObservationID, "quota", "failure", "quota", issued.AccountGeneration, issued.FileGeneration)
			quota.Ticket = ticket
			result, err := runtime.report(ctx, quota)
			require.NoError(t, err)
			require.True(t, result.Applied)

			backoff, err := runtime.nextDiagnostic(ctx, "reusable-file", "account-a", []string{"account-a"})
			require.NoError(t, err)
			require.False(t, backoff.Allow)
			require.Contains(t, backoff.Reason, "backoff")

			clock.Advance(quotaUncertainTTL + time.Second)
			renewed, err := runtime.permission(ctx, "account-a", "reusable-file", issued.AccountGeneration, issued.FileGeneration, quotaModeNormal, first.ObservationID, "", "check", "", quotaPermissionContext{
				Ticket:          ticket,
				IssuedAt:        clock.Now().Add(-time.Second).Unix(),
				PermitExpiresAt: clock.Now().Add(time.Minute).Unix(),
			})
			require.NoError(t, err)
			require.True(t, renewed.Allow)
			require.Equal(t, !scenario.acknowledgeSuccess, renewed.ReportSuccess)
			require.NotEqual(t, first.ObservationID, renewed.ObservationID)

			secondQuota := quotaTestReport("account-a", "reusable-file", renewed.ObservationID, "quota", "failure", "quota", issued.AccountGeneration, issued.FileGeneration)
			secondQuota.Ticket = ticket
			result, err = runtime.report(ctx, secondQuota)
			require.NoError(t, err)
			require.True(t, result.Applied)
			require.False(t, result.Duplicate)

			blocked, err := runtime.permission(ctx, "account-a", "reusable-file", issued.AccountGeneration, issued.FileGeneration, quotaModeNormal, renewed.ObservationID, "", "check", "", quotaPermissionContext{
				Ticket:          ticket,
				IssuedAt:        clock.Now().Unix(),
				PermitExpiresAt: clock.Now().Add(time.Minute).Unix(),
			})
			require.NoError(t, err)
			require.False(t, blocked.Allow)
			require.Contains(t, blocked.Reason, "quota decision")
		})
	}
}

func TestQuotaAuthorityV2SuccessfulSingleUseNextPlanReturnsNormal(t *testing.T) {
	for _, target := range []string{"file", "account", "diagnostic"} {
		t.Run(target, func(t *testing.T) {
			clock := newQuotaTestClock()
			runtime := newQuotaAuthorityRuntime(clock.Now)
			ctx := context.Background()
			candidates := []string{"A"}
			if target == "file" {
				file := runtime.getFileLocked("X")
				file.CooldownUntil = clock.Now().Add(23 * time.Hour)
				file.NextProbeAt = clock.Now().Add(-time.Second)
			} else if target == "account" {
				account := runtime.getAccountLocked("A")
				account.CooldownUntil = clock.Now().Add(23 * time.Hour)
				account.NextProbeAt = clock.Now().Add(-time.Second)
			}

			plan, err := runtime.authorize(ctx, "A", "X")
			require.NoError(t, err)
			if target == "diagnostic" {
				candidates = []string{"A", "B"}
				_, err = runtime.report(ctx, quotaTestReport("A", "X", plan.ObservationID, "quota", "failure", "quota", plan.AccountGeneration, plan.FileGeneration))
				require.NoError(t, err)
				plan, err = runtime.nextDiagnostic(ctx, "X", "A", candidates)
				require.NoError(t, err)
			}
			require.True(t, plan.Allow)
			require.NotEqual(t, quotaModeNormal, plan.Mode)

			claimed, err := runtime.permission(ctx, plan.AccountName, "X", plan.AccountGeneration, plan.FileGeneration, plan.Mode, plan.ObservationID, plan.ReservationID, "claim", "root-once")
			require.NoError(t, err)
			require.True(t, claimed.Allow)
			report := quotaTestReport(plan.AccountName, "X", plan.ObservationID, "success", "success", "download_success", plan.AccountGeneration, plan.FileGeneration)
			report.TrialID = plan.ReservationID
			report.ExecutionClaimID = "root-once"
			result, err := runtime.report(ctx, report)
			require.NoError(t, err)
			require.True(t, result.Applied)

			next, err := runtime.nextDiagnostic(ctx, "X", plan.AccountName, candidates)
			require.NoError(t, err)
			require.True(t, next.Allow)
			require.Equal(t, quotaModeNormal, next.Mode)
			require.Empty(t, next.ReservationID)
			require.Equal(t, plan.AccountName, next.AccountName)
		})
	}
}

func TestQuotaAuthorityV2DueFileProbeFallsBackWithoutRecentControl(t *testing.T) {
	clock := newQuotaTestClock()
	runtime := newQuotaAuthorityRuntime(clock.Now)
	ctx := context.Background()
	account := runtime.getAccountLocked("fallback-account")
	file := runtime.getFileLocked("fallback-file")
	file.CooldownUntil = clock.Now().Add(2 * time.Hour)
	file.NextProbeAt = clock.Now()
	file.ProbeUsed = quotaProbeBudget

	plan, err := runtime.authorize(ctx, account.Name, file.FileID)
	require.NoError(t, err)
	require.True(t, plan.Allow)
	require.Equal(t, quotaModeProbe, plan.Mode)
}

func TestQuotaAuthorityV2IntersectingBoundaryProbesShareOneExecution(t *testing.T) {
	clock := newQuotaTestClock()
	runtime := newQuotaAuthorityRuntime(clock.Now)
	ctx := context.Background()
	account := runtime.getAccountLocked("boundary-account")
	account.CooldownUntil = clock.Now().Add(-time.Second)
	file := runtime.getFileLocked("boundary-file")
	file.CooldownUntil = clock.Now().Add(-time.Second)

	plan, err := runtime.authorize(ctx, account.Name, file.FileID)
	require.NoError(t, err)
	require.True(t, plan.Allow)
	require.Equal(t, quotaModeProbe, plan.Mode)
	require.Equal(t, quotaScopeFileAccount, runtime.getFileLocked(file.FileID).Probe.Scope)
	require.Same(t, runtime.getFileLocked(file.FileID).Probe, runtime.getAccountLocked(account.Name).Probe)

	unrelated, err := runtime.authorize(ctx, account.Name, "another-file")
	require.NoError(t, err)
	require.False(t, unrelated.Allow)
	require.Contains(t, unrelated.Reason, "opportunity busy")

	claimed, err := runtime.permission(ctx, account.Name, file.FileID, plan.AccountGeneration, plan.FileGeneration, quotaModeProbe, plan.ObservationID, plan.ReservationID, "claim", "boundary-claim")
	require.NoError(t, err)
	require.True(t, claimed.Allow)
	require.Equal(t, 1, runtime.getFileLocked(file.FileID).ProbeUsed)
	require.Equal(t, 1, runtime.getAccountLocked(account.Name).ProbeUsed)
	result, err := runtime.report(ctx, driver.DownloadAuthorizationFeedback{
		AuthorityProtocol: model.DownloadAuthorityProtocol,
		Ticket:            "boundary-ticket",
		Provider:          googleDriveAccountProvider,
		AccountName:       account.Name,
		FileID:            file.FileID,
		Generation:        plan.AccountGeneration,
		FileGeneration:    plan.FileGeneration,
		TrialID:           plan.ReservationID,
		ExecutionClaimID:  claimed.ExecutionClaimID,
		ObservationID:     plan.ObservationID,
		EventType:         "success",
		EventID:           driver.CanonicalDownloadAuthorizationEventID(plan.ObservationID, "success"),
		Outcome:           "success",
		StatusCode:        200,
	})
	require.NoError(t, err)
	require.True(t, result.Applied)
	require.True(t, runtime.getFileLocked(file.FileID).CooldownUntil.IsZero())
	require.True(t, runtime.getAccountLocked(account.Name).CooldownUntil.IsZero())
}

func TestQuotaAuthorityV2ReleasedDueProbeDoesNotConsumeHourlySchedule(t *testing.T) {
	clock := newQuotaTestClock()
	runtime := newQuotaAuthorityRuntime(clock.Now)
	ctx := context.Background()

	file := runtime.getFileLocked("released-file-probe")
	file.CooldownUntil = clock.Now().Add(time.Hour)
	file.NextProbeAt = clock.Now()
	firstFile, err := runtime.authorize(ctx, "file-probe-account", file.FileID)
	require.NoError(t, err)
	require.Equal(t, quotaModeProbe, firstFile.Mode)
	releasedFile, err := runtime.permission(ctx, firstFile.AccountName, file.FileID, firstFile.AccountGeneration, firstFile.FileGeneration, quotaModeProbe, firstFile.ObservationID, firstFile.ReservationID, "release", "")
	require.NoError(t, err)
	require.True(t, releasedFile.Allow)
	secondFile, err := runtime.authorize(ctx, "file-probe-account", file.FileID)
	require.NoError(t, err)
	require.Equal(t, quotaModeProbe, secondFile.Mode)
	require.Equal(t, 0, runtime.getFileLocked(file.FileID).ProbeUsed)
	require.True(t, runtime.getFileLocked(file.FileID).NextProbeAt.Equal(clock.Now().Add(0)))

	account := runtime.getAccountLocked("account-probe-account")
	account.CooldownUntil = clock.Now().Add(time.Hour)
	account.NextProbeAt = clock.Now()
	secondTarget, err := runtime.authorize(ctx, account.Name, "account-probe-file")
	require.NoError(t, err)
	require.Equal(t, quotaModeProbe, secondTarget.Mode)
	releasedAccount, err := runtime.permission(ctx, account.Name, "account-probe-file", secondTarget.AccountGeneration, secondTarget.FileGeneration, quotaModeProbe, secondTarget.ObservationID, secondTarget.ReservationID, "release", "")
	require.NoError(t, err)
	require.True(t, releasedAccount.Allow)
	thirdTarget, err := runtime.authorize(ctx, account.Name, "account-probe-file")
	require.NoError(t, err)
	require.Equal(t, quotaModeProbe, thirdTarget.Mode)
	require.Equal(t, 0, runtime.getAccountLocked(account.Name).ProbeUsed)
}

func TestQuotaAuthorityV2ProbeSuccessOnlyRecoversItsOwnedTarget(t *testing.T) {
	clock := newQuotaTestClock()
	runtime := newQuotaAuthorityRuntime(clock.Now)
	ctx := context.Background()
	account := runtime.getAccountLocked("target-account")
	file := runtime.getFileLocked("target-file")
	file.CooldownUntil = clock.Now().Add(time.Hour)
	file.NextProbeAt = clock.Now()

	fileProbe, err := runtime.authorize(ctx, account.Name, file.FileID)
	require.NoError(t, err)
	require.Equal(t, quotaModeProbe, fileProbe.Mode)
	claimedFile, err := runtime.permission(ctx, account.Name, file.FileID, fileProbe.AccountGeneration, fileProbe.FileGeneration, quotaModeProbe, fileProbe.ObservationID, fileProbe.ReservationID, "claim", "file-claim")
	require.NoError(t, err)
	require.True(t, claimedFile.Allow)

	account.CooldownUntil = clock.Now().Add(time.Hour)
	account.NextProbeAt = clock.Now()
	accountProbe, err := runtime.authorize(ctx, account.Name, "account-target-file")
	require.NoError(t, err)
	require.Equal(t, quotaModeProbe, accountProbe.Mode)
	claimedAccount, err := runtime.permission(ctx, account.Name, "account-target-file", accountProbe.AccountGeneration, accountProbe.FileGeneration, quotaModeProbe, accountProbe.ObservationID, accountProbe.ReservationID, "claim", "account-claim")
	require.NoError(t, err)
	require.True(t, claimedAccount.Allow)

	fileResult, err := runtime.report(ctx, driver.DownloadAuthorizationFeedback{
		AuthorityProtocol: model.DownloadAuthorityProtocol,
		Ticket:            "file-probe-ticket",
		Provider:          googleDriveAccountProvider,
		AccountName:       account.Name,
		FileID:            file.FileID,
		Generation:        fileProbe.AccountGeneration,
		FileGeneration:    fileProbe.FileGeneration,
		TrialID:           fileProbe.ReservationID,
		ExecutionClaimID:  claimedFile.ExecutionClaimID,
		ObservationID:     fileProbe.ObservationID,
		EventType:         "success",
		EventID:           driver.CanonicalDownloadAuthorizationEventID(fileProbe.ObservationID, "success"),
		Outcome:           "success",
		StatusCode:        200,
	})
	require.NoError(t, err)
	require.True(t, fileResult.Applied)
	require.True(t, runtime.getFileLocked(file.FileID).CooldownUntil.IsZero())
	require.False(t, runtime.getAccountLocked(account.Name).CooldownUntil.IsZero())

	accountResult, err := runtime.report(ctx, driver.DownloadAuthorizationFeedback{
		AuthorityProtocol: model.DownloadAuthorityProtocol,
		Ticket:            "account-probe-ticket",
		Provider:          googleDriveAccountProvider,
		AccountName:       account.Name,
		FileID:            "account-target-file",
		Generation:        accountProbe.AccountGeneration,
		FileGeneration:    accountProbe.FileGeneration,
		TrialID:           accountProbe.ReservationID,
		ExecutionClaimID:  claimedAccount.ExecutionClaimID,
		ObservationID:     accountProbe.ObservationID,
		EventType:         "success",
		EventID:           driver.CanonicalDownloadAuthorizationEventID(accountProbe.ObservationID, "success"),
		Outcome:           "success",
		StatusCode:        200,
	})
	require.NoError(t, err)
	require.True(t, accountResult.Applied)
	require.True(t, runtime.getAccountLocked(account.Name).CooldownUntil.IsZero())
}

func TestQuotaAuthorityV2DueFileProbePrefersRecentControlWhenAvailable(t *testing.T) {
	clock := newQuotaTestClock()
	runtime := newQuotaAuthorityRuntime(clock.Now)
	file := runtime.getFileLocked("preferred-file")
	file.CooldownUntil = clock.Now().Add(time.Hour)
	file.NextProbeAt = clock.Now()
	runtime.observations["preferred-success"] = quotaObservation{
		EventID: "preferred-success", ObservationID: "preferred-success", EventType: "success", Provider: googleDriveAccountProvider,
		AccountName: "account-with-control", FileID: "other-file", Outcome: "success", At: clock.Now(),
	}
	preferred, err := runtime.preferProbeCandidates(context.Background(), file.FileID, []string{"account-without-control", "account-with-control"})
	require.NoError(t, err)
	require.Equal(t, []string{"account-with-control", "account-without-control"}, preferred)
}

func TestQuotaAuthorityV2NextPlanUsesNormalReplacementForIndependentlyCooledAccount(t *testing.T) {
	clock := newQuotaTestClock()
	runtime := newQuotaAuthorityRuntime(clock.Now)
	ctx := context.Background()
	accountA := runtime.getAccountLocked("cooled-account")
	accountA.CooldownUntil = clock.Now().Add(time.Hour)
	file := runtime.getFileLocked("healthy-file")
	file.QuotaPending = true
	file.QuotaPendingAt = clock.Now()

	plan, err := runtime.nextDiagnostic(ctx, file.FileID, accountA.Name, []string{accountA.Name, "replacement-account"})
	require.NoError(t, err)
	require.True(t, plan.Allow)
	require.Equal(t, quotaModeNormal, plan.Mode)
	require.Equal(t, "replacement-account", plan.AccountName)
	require.Empty(t, plan.ReservationID)
	require.False(t, runtime.getFileLocked(file.FileID).QuotaPending)
}

func TestQuotaAuthorityV2HourlyAccountProbeUsesRecentOtherAccountSuccess(t *testing.T) {
	clock := newQuotaTestClock()
	runtime := newQuotaAuthorityRuntime(clock.Now)
	ctx := context.Background()
	account := runtime.getAccountLocked("cooled-account")
	account.CooldownUntil = clock.Now().Add(time.Hour)
	account.NextProbeAt = clock.Now()
	account.Generation = 3
	file := runtime.getFileLocked("requested")
	other := runtime.getAccountLocked("healthy-account")
	runtime.observations["success"] = quotaObservation{
		EventID: "success", ObservationID: "success", EventType: "success", Provider: googleDriveAccountProvider,
		AccountName: other.Name, FileID: file.FileID, Outcome: "success", AccountGeneration: other.Generation, FileGeneration: file.Generation, At: clock.Now(),
	}

	plan, err := runtime.authorize(ctx, account.Name, file.FileID)
	require.NoError(t, err)
	require.True(t, plan.Allow)
	require.Equal(t, quotaModeProbe, plan.Mode)
	require.Equal(t, plan.ReservationID, runtime.getAccountLocked(account.Name).Probe.ID)
}

func TestQuotaAuthorityV2CanonicalEventRejectsConflictingPayload(t *testing.T) {
	clock := newQuotaTestClock()
	runtime := newQuotaAuthorityRuntime(clock.Now)
	ctx := context.Background()
	first, err := runtime.authorize(ctx, "account-a", "file-a")
	require.NoError(t, err)
	input := quotaTestReport("account-a", "file-a", "obs", "quota", "failure", "quota", first.AccountGeneration, first.FileGeneration)
	_, err = runtime.report(ctx, input)
	require.NoError(t, err)
	input.Reason = "limit"
	_, err = runtime.report(ctx, input)
	require.ErrorContains(t, err, "conflicting reuse")
}

func TestQuotaAuthorityV2ReceiptOutlivesEvidenceWindow(t *testing.T) {
	clock := newQuotaTestClock()
	runtime := newQuotaAuthorityRuntime(clock.Now)
	ctx := context.Background()
	issued, err := runtime.authorize(ctx, "account", "receipt-file")
	require.NoError(t, err)
	input := quotaTestReport("account", "receipt-file", "receipt-observation", "quota", "failure", "quota", issued.AccountGeneration, issued.FileGeneration)
	first, err := runtime.report(ctx, input)
	require.NoError(t, err)
	require.True(t, first.Applied)

	clock.Advance(quotaEvidenceTTL + time.Second)
	duplicate, err := runtime.report(ctx, input)
	require.NoError(t, err)
	require.True(t, duplicate.Duplicate)
	require.Empty(t, runtime.observations)
	require.Len(t, runtime.receipts, 1)

	input.Reason = "limit"
	_, err = runtime.report(ctx, input)
	require.ErrorContains(t, err, "conflicting reuse")
}

func TestQuotaAuthorityV2ConsumedClaimRetainsGraceReportThenExpires(t *testing.T) {
	clock := newQuotaTestClock()
	runtime := newQuotaAuthorityRuntime(clock.Now)
	ctx := context.Background()
	file := runtime.getFileLocked("consumed-grace-file")
	file.CooldownUntil = clock.Now().Add(time.Hour)
	file.NextProbeAt = clock.Now()
	plan, err := runtime.authorize(ctx, "consumed-grace-account", file.FileID)
	require.NoError(t, err)
	require.True(t, plan.Allow)
	claimed, err := runtime.permission(ctx, plan.AccountName, file.FileID, plan.AccountGeneration, plan.FileGeneration, quotaModeProbe, plan.ObservationID, plan.ReservationID, "claim", "grace-claim")
	require.NoError(t, err)
	require.True(t, claimed.Allow)

	clock.Advance(quotaPermissionTTL + time.Second)
	expired, err := runtime.permission(ctx, plan.AccountName, file.FileID, plan.AccountGeneration, plan.FileGeneration, quotaModeProbe, plan.ObservationID, plan.ReservationID, "check", "grace-claim")
	require.NoError(t, err)
	require.False(t, expired.Allow)
	_, retained := runtime.consumed[plan.ReservationID]
	require.True(t, retained)

	lateReport := quotaTestReport(plan.AccountName, file.FileID, plan.ObservationID, "failure", "failure", "late network failure", plan.AccountGeneration, plan.FileGeneration)
	lateReport.TrialID = plan.ReservationID
	lateReport.ExecutionClaimID = claimed.ExecutionClaimID
	late, err := runtime.report(ctx, lateReport)
	require.NoError(t, err)
	require.True(t, late.Applied)

	clock.Advance(quotaReceiptTTL + time.Second)
	stale, err := runtime.permission(ctx, plan.AccountName, file.FileID, plan.AccountGeneration, plan.FileGeneration, quotaModeProbe, plan.ObservationID, plan.ReservationID, "claim", "new-claim")
	require.NoError(t, err)
	require.False(t, stale.Allow)
	_, retained = runtime.consumed[plan.ReservationID]
	require.False(t, retained)
	require.Nil(t, runtime.getFileLocked(file.FileID).Probe)
	_, err = runtime.report(ctx, lateReport)
	require.ErrorContains(t, err, "execution claim is required")
}

func TestQuotaAuthorityV2PendingSamplesExpireAfterStateTTL(t *testing.T) {
	clock := newQuotaTestClock()
	runtime := newQuotaAuthorityRuntime(clock.Now)
	ctx := context.Background()
	issued, err := runtime.authorize(ctx, "pending-sample-account", "pending-sample-file")
	require.NoError(t, err)
	checked, err := runtime.permission(ctx, issued.AccountName, "pending-sample-file", issued.AccountGeneration, issued.FileGeneration, quotaModeNormal, issued.ObservationID, "", "check", "", quotaPermissionContext{Ticket: "pending-sample-ticket"})
	require.NoError(t, err)
	require.True(t, checked.ReportSuccess)
	key := quotaAuthorizationKey("pending-sample-ticket")
	sample, ok := runtime.authorizationSamples[key]
	require.True(t, ok)
	sample.Pending = true
	sample.RequestedAt = clock.Now().Add(-quotaSampleStateTTL - time.Second)
	runtime.authorizationSamples[key] = sample

	clock.Advance(quotaSampleStateTTL + time.Second)
	_, err = runtime.authorize(ctx, "cleanup-trigger-account", "cleanup-trigger-file")
	require.NoError(t, err)
	_, ok = runtime.authorizationSamples[key]
	require.False(t, ok)
}

func TestQuotaAuthorityV2ObservationFingerprintGoldenVectors(t *testing.T) {
	require.Equal(t, "2aa5f1df1c00b50ce3275e354512bf94fc8760791f4fd7a46adfa8a9d62ffa6a", driver.CanonicalDownloadAuthorizationEventID("obs-1", "quota"))
	if got, want := quotaObservationFingerprint(driver.DownloadAuthorizationFeedback{
		AuthorityProtocol: model.DownloadAuthorityProtocol,
		Ticket:            "opaque.ticket.signature",
		Permit:            &model.DownloadExecutionPermission{Proof: "opaque.permit.signature"},
		ObservationID:     "obs-1",
		EventType:         "quota",
		Outcome:           "failure",
		StatusCode:        http.StatusForbidden,
		Reason:            "quota",
	}), "307e3a16775a856e939a1070a91d764b150da78c0dc0df97b10581fcb6c2d5ea"; got != want {
		t.Fatalf("ASCII fingerprint mismatch: got %s want %s", got, want)
	}
	if got, want := quotaObservationFingerprint(driver.DownloadAuthorizationFeedback{
		AuthorityProtocol: model.DownloadAuthorityProtocol,
		Ticket:            "opaque.ticket.signature",
		Permit:            &model.DownloadExecutionPermission{Proof: "opaque.permit.signature"},
		ObservationID:     "obs-1",
		EventType:         "quota",
		Outcome:           "failure",
		StatusCode:        http.StatusForbidden,
		Reason:            "quota <>&\u2028\u2029中",
	}), "369b357db4630c8ad8cf3ed127f079b8f6cebffd383099384c1cd9f78657ec65"; got != want {
		t.Fatalf("Unicode fingerprint mismatch: got %s want %s", got, want)
	}
}

func TestQuotaAuthorityV2NormalRenewalKeepsFirstSuccessObservationPending(t *testing.T) {
	clock := newQuotaTestClock()
	runtime := newQuotaAuthorityRuntime(clock.Now)
	ctx := context.Background()

	issued, err := runtime.authorize(ctx, "account", "first-success")
	require.NoError(t, err)
	require.True(t, issued.ReportSuccess)
	clock.Advance(31 * time.Second)

	renewed, err := runtime.permission(ctx, "account", "first-success", issued.AccountGeneration, issued.FileGeneration, quotaModeNormal, issued.ObservationID, "", "check", "", quotaPermissionContext{Ticket: "ticket-first-success"})
	require.NoError(t, err)
	require.True(t, renewed.Allow)
	require.True(t, renewed.ReportSuccess)
	require.Equal(t, issued.ObservationID, renewed.ObservationID)

	_, err = runtime.report(ctx, driver.DownloadAuthorizationFeedback{
		AuthorityProtocol: model.DownloadAuthorityProtocol,
		Ticket:            "ticket-first-success",
		Provider:          googleDriveAccountProvider,
		AccountName:       "account",
		FileID:            "first-success",
		Generation:        issued.AccountGeneration,
		FileGeneration:    issued.FileGeneration,
		ObservationID:     issued.ObservationID,
		EventType:         "success",
		EventID:           driver.CanonicalDownloadAuthorizationEventID(issued.ObservationID, "success"),
		Outcome:           "success",
		StatusCode:        http.StatusOK,
	})
	require.NoError(t, err)

	acknowledged, err := runtime.permission(ctx, "account", "first-success", issued.AccountGeneration, issued.FileGeneration, quotaModeNormal, issued.ObservationID, "", "check", "", quotaPermissionContext{Ticket: "ticket-first-success"})
	require.NoError(t, err)
	require.True(t, acknowledged.Allow)
	require.False(t, acknowledged.ReportSuccess)
	require.Equal(t, issued.ObservationID, acknowledged.ObservationID)
}

func TestQuotaAuthorityV2NeutralFailureDoesNotCompletePendingSuccessSample(t *testing.T) {
	clock := newQuotaTestClock()
	runtime := newQuotaAuthorityRuntime(clock.Now)
	ctx := context.Background()
	issued, err := runtime.authorize(ctx, "account", "neutral-sample")
	require.NoError(t, err)
	first, err := runtime.permission(ctx, "account", "neutral-sample", issued.AccountGeneration, issued.FileGeneration, quotaModeNormal, issued.ObservationID, "", "check", "", quotaPermissionContext{Ticket: "neutral-sample-ticket"})
	require.NoError(t, err)
	require.True(t, first.ReportSuccess)

	failure := driver.DownloadAuthorizationFeedback{
		AuthorityProtocol: model.DownloadAuthorityProtocol,
		Ticket:            "neutral-sample-ticket",
		Provider:          googleDriveAccountProvider,
		AccountName:       "account",
		FileID:            "neutral-sample",
		Generation:        issued.AccountGeneration,
		FileGeneration:    issued.FileGeneration,
		ObservationID:     first.ObservationID,
		EventType:         "failure",
		EventID:           driver.CanonicalDownloadAuthorizationEventID(first.ObservationID, "failure"),
		Outcome:           "failure",
		StatusCode:        500,
		Reason:            "temporary transport failure",
	}
	_, err = runtime.report(ctx, failure)
	require.NoError(t, err)
	afterFailure, err := runtime.permission(ctx, "account", "neutral-sample", issued.AccountGeneration, issued.FileGeneration, quotaModeNormal, first.ObservationID, "", "check", "", quotaPermissionContext{Ticket: "neutral-sample-ticket"})
	require.NoError(t, err)
	require.True(t, afterFailure.ReportSuccess)
	require.Equal(t, first.ObservationID, afterFailure.ObservationID)

	success := failure
	success.EventType = "success"
	success.EventID = driver.CanonicalDownloadAuthorizationEventID(first.ObservationID, "success")
	success.Outcome = "success"
	success.StatusCode = 200
	success.Reason = ""
	_, err = runtime.report(ctx, success)
	require.NoError(t, err)
	afterSuccess, err := runtime.permission(ctx, "account", "neutral-sample", issued.AccountGeneration, issued.FileGeneration, quotaModeNormal, first.ObservationID, "", "check", "", quotaPermissionContext{Ticket: "neutral-sample-ticket"})
	require.NoError(t, err)
	require.False(t, afterSuccess.ReportSuccess)
}

func TestQuotaAuthorityV2GenerationChangeRotatesPendingObservationAndFencesOldReport(t *testing.T) {
	for _, newReportFirst := range []bool{false, true} {
		clock := newQuotaTestClock()
		runtime := newQuotaAuthorityRuntime(clock.Now)
		ctx := context.Background()
		issued, err := runtime.authorize(ctx, "account", "generation-file")
		require.NoError(t, err)
		first, err := runtime.permission(ctx, "account", "generation-file", issued.AccountGeneration, issued.FileGeneration, quotaModeNormal, issued.ObservationID, "", "check", "", quotaPermissionContext{Ticket: "generation-ticket"})
		require.NoError(t, err)
		file := runtime.getFileLocked("generation-file")
		file.Generation++
		second, err := runtime.permission(ctx, "account", "generation-file", issued.AccountGeneration, issued.FileGeneration, quotaModeNormal, first.ObservationID, "", "check", "", quotaPermissionContext{Ticket: "generation-ticket"})
		require.NoError(t, err)
		require.True(t, second.Allow)
		require.True(t, second.ReportSuccess)
		require.NotEqual(t, first.ObservationID, second.ObservationID)

		oldReport := quotaTestReport("account", "generation-file", first.ObservationID, "success", "success", "", issued.AccountGeneration, issued.FileGeneration)
		newReport := quotaTestReport("account", "generation-file", second.ObservationID, "success", "success", "", issued.AccountGeneration, file.Generation)
		if newReportFirst {
			applied, reportErr := runtime.report(ctx, newReport)
			require.NoError(t, reportErr)
			require.True(t, applied.Applied)
		}
		stale, reportErr := runtime.report(ctx, oldReport)
		require.NoError(t, reportErr)
		require.True(t, stale.Stale)
		if !newReportFirst {
			applied, reportErr := runtime.report(ctx, newReport)
			require.NoError(t, reportErr)
			require.True(t, applied.Applied)
		}
	}
}

func TestQuotaAuthorityV2AccountBackoffBlocksDueFileProbe(t *testing.T) {
	clock := newQuotaTestClock()
	runtime := newQuotaAuthorityRuntime(clock.Now)
	ctx := context.Background()
	account := runtime.getAccountLocked("backoff-account")
	account.ProbeRequired = true
	account.ProbeUsed = quotaProbeBudget
	account.BackoffUntil = clock.Now().Add(quotaUncertainTTL)
	file := runtime.getFileLocked("due-file")
	file.CooldownUntil = clock.Now().Add(2 * time.Hour)
	file.NextProbeAt = clock.Now()

	blocked, err := runtime.authorize(ctx, account.Name, file.FileID)
	require.NoError(t, err)
	require.False(t, blocked.Allow)
	require.Contains(t, blocked.Reason, "account backoff")
	require.Nil(t, runtime.getFileLocked(file.FileID).Probe)
	require.Nil(t, runtime.getAccountLocked(account.Name).Probe)

	healthy, err := runtime.authorize(ctx, "healthy-account", file.FileID)
	require.NoError(t, err)
	require.True(t, healthy.Allow)
	require.Equal(t, quotaModeProbe, healthy.Mode)
	require.Equal(t, quotaScopeFile, runtime.getFileLocked(file.FileID).Probe.Scope)
	healthyClaim, err := runtime.permission(ctx, healthy.AccountName, file.FileID, healthy.AccountGeneration, healthy.FileGeneration, quotaModeProbe, healthy.ObservationID, healthy.ReservationID, "claim", "healthy-claim")
	require.NoError(t, err)
	require.True(t, healthyClaim.Allow)

	stillBlocked, err := runtime.authorize(ctx, account.Name, file.FileID)
	require.NoError(t, err)
	require.False(t, stillBlocked.Allow)
	require.Contains(t, stillBlocked.Reason, "account backoff")

	report := quotaTestReport(healthy.AccountName, file.FileID, healthy.ObservationID, "failure", "failure", "network", healthy.AccountGeneration, healthy.FileGeneration)
	report.TrialID = healthy.ReservationID
	report.ExecutionClaimID = healthyClaim.ExecutionClaimID
	result, err := runtime.report(ctx, report)
	require.NoError(t, err)
	require.True(t, result.Applied)

	clock.Advance(quotaProbeInterval + time.Second)
	recovered, err := runtime.authorize(ctx, account.Name, file.FileID)
	require.NoError(t, err)
	require.True(t, recovered.Allow)
	require.Equal(t, quotaModeProbe, recovered.Mode)
}

func TestQuotaAuthorityV2FileBackoffBlocksDueAccountProbe(t *testing.T) {
	clock := newQuotaTestClock()
	runtime := newQuotaAuthorityRuntime(clock.Now)
	ctx := context.Background()
	account := runtime.getAccountLocked("file-backoff-account")
	account.CooldownUntil = clock.Now().Add(time.Hour)
	account.NextProbeAt = clock.Now()
	file := runtime.getFileLocked("file-backoff-file")
	file.BackoffUntil = clock.Now().Add(quotaUncertainTTL)

	blocked, err := runtime.authorize(ctx, account.Name, file.FileID)
	require.NoError(t, err)
	require.False(t, blocked.Allow)
	require.Contains(t, blocked.Reason, "file backoff")
	require.Nil(t, runtime.getAccountLocked(account.Name).Probe)

	clock.Advance(quotaUncertainTTL + time.Second)
	recovered, err := runtime.authorize(ctx, account.Name, file.FileID)
	require.NoError(t, err)
	require.True(t, recovered.Allow)
	require.Equal(t, quotaModeProbe, recovered.Mode)
	require.Equal(t, quotaScopeAccount, runtime.getAccountLocked(account.Name).Probe.Scope)
}

func TestQuotaAuthorityV2AccountBackoffBlocksNormalPermissionRenewal(t *testing.T) {
	clock := newQuotaTestClock()
	runtime := newQuotaAuthorityRuntime(clock.Now)
	ctx := context.Background()
	issued, err := runtime.authorize(ctx, "permission-backoff-account", "permission-backoff-file")
	require.NoError(t, err)
	require.True(t, issued.Allow)

	account := runtime.getAccountLocked(issued.AccountName)
	account.BackoffUntil = clock.Now().Add(quotaUncertainTTL)
	blocked, err := runtime.permission(ctx, issued.AccountName, "permission-backoff-file", issued.AccountGeneration, issued.FileGeneration, quotaModeNormal, issued.ObservationID, "", "check", "", quotaPermissionContext{
		Ticket:          "permission-backoff-ticket",
		IssuedAt:        clock.Now().Unix(),
		PermitExpiresAt: clock.Now().Add(time.Minute).Unix(),
	})
	require.NoError(t, err)
	require.False(t, blocked.Allow)
	require.Contains(t, blocked.Reason, "account backoff")

	clock.Advance(quotaUncertainTTL + time.Second)
	recovered, err := runtime.permission(ctx, issued.AccountName, "permission-backoff-file", issued.AccountGeneration, issued.FileGeneration, quotaModeNormal, issued.ObservationID, "", "check", "", quotaPermissionContext{
		Ticket:          "permission-backoff-ticket",
		IssuedAt:        clock.Now().Add(-time.Second).Unix(),
		PermitExpiresAt: clock.Now().Add(time.Minute).Unix(),
	})
	require.NoError(t, err)
	require.True(t, recovered.Allow)
}

func TestQuotaAuthorityV2NormalPermissionRequestsOneFreshSampleAfterEvidenceWindow(t *testing.T) {
	clock := newQuotaTestClock()
	runtime := newQuotaAuthorityRuntime(clock.Now)
	ctx := context.Background()

	issued, err := runtime.authorize(ctx, "account", "sample-window")
	require.NoError(t, err)
	first, err := runtime.permission(ctx, "account", "sample-window", issued.AccountGeneration, issued.FileGeneration, quotaModeNormal, issued.ObservationID, "", "check", "", quotaPermissionContext{Ticket: "ticket-sample-window"})
	require.NoError(t, err)
	require.True(t, first.ReportSuccess)
	_, err = runtime.report(ctx, driver.DownloadAuthorizationFeedback{
		AuthorityProtocol: model.DownloadAuthorityProtocol,
		Ticket:            "ticket-sample-window",
		Provider:          googleDriveAccountProvider,
		AccountName:       "account",
		FileID:            "sample-window",
		Generation:        issued.AccountGeneration,
		FileGeneration:    issued.FileGeneration,
		ObservationID:     first.ObservationID,
		EventType:         " SUCCESS ",
		EventID:           driver.CanonicalDownloadAuthorizationEventID(first.ObservationID, "success"),
		Outcome:           " SUCCESS ",
		StatusCode:        http.StatusOK,
	})
	require.NoError(t, err)

	clock.Advance(quotaEvidenceTTL + time.Second)
	refreshed, err := runtime.permission(ctx, "account", "sample-window", issued.AccountGeneration, issued.FileGeneration, quotaModeNormal, first.ObservationID, "", "check", "", quotaPermissionContext{Ticket: "ticket-sample-window"})
	require.NoError(t, err)
	require.True(t, refreshed.Allow)
	require.True(t, refreshed.ReportSuccess)
	require.NotEqual(t, first.ObservationID, refreshed.ObservationID)

	repeated, err := runtime.permission(ctx, "account", "sample-window", issued.AccountGeneration, issued.FileGeneration, quotaModeNormal, first.ObservationID, "", "check", "", quotaPermissionContext{Ticket: "ticket-sample-window"})
	require.NoError(t, err)
	require.True(t, repeated.Allow)
	require.True(t, repeated.ReportSuccess)
	require.Equal(t, refreshed.ObservationID, repeated.ObservationID)
}

func TestGoogleDriveV2QuotaFeedbackReservesOneDifferentAccountAndSuccessClosesRound(t *testing.T) {
	resetGoogleDriveQuotaAuthorityForTests()
	d := newAccountsJSONDriverWithTokens([]string{"token-a", "token-b"})
	request := driver.DownloadAuthorizationRequest{
		AuthorityProtocol: model.DownloadAuthorityProtocol,
		FileID:            "shared-file",
		File:              &model.Object{ID: "shared-file", Size: 1},
	}
	first, err := d.AcquireDownloadAuthorization(context.Background(), request)
	require.NoError(t, err)
	require.Equal(t, "account-0", first.AccountName)

	feedback := driver.DownloadAuthorizationFeedback{
		AuthorityProtocol: model.DownloadAuthorityProtocol,
		Provider:          googleDriveAccountProvider,
		AccountName:       first.AccountName,
		FileID:            request.FileID,
		Generation:        first.Generation,
		FileGeneration:    first.FileGeneration,
		ObservationID:     first.ObservationID,
		EventType:         "quota",
		EventID:           driver.CanonicalDownloadAuthorizationEventID(first.ObservationID, "quota"),
		Outcome:           "failure",
		StatusCode:        http.StatusForbidden,
		Reason:            "quota",
	}
	replacement, err := d.AcquireDownloadAuthorization(context.Background(), driver.DownloadAuthorizationRequest{
		AuthorityProtocol: model.DownloadAuthorityProtocol,
		FileID:            request.FileID,
		File:              request.File,
		Feedback:          &feedback,
	})
	require.NoError(t, err)
	require.Equal(t, "account-1", replacement.AccountName)
	require.Equal(t, string(quotaModeDiagnostic), replacement.Mode)
	require.NotEmpty(t, replacement.ReservationID)
	_, err = d.ReportDownloadAuthorization(context.Background(), driver.DownloadAuthorizationReport{
		AuthorityProtocol: model.DownloadAuthorityProtocol,
		Provider:          googleDriveAccountProvider,
		AccountName:       replacement.AccountName,
		FileID:            request.FileID,
		Generation:        replacement.Generation,
		FileGeneration:    replacement.FileGeneration,
		TrialID:           replacement.ReservationID,
		ObservationID:     replacement.ObservationID,
		EventType:         "success",
		EventID:           driver.CanonicalDownloadAuthorizationEventID(replacement.ObservationID, "success"),
		Outcome:           "success",
		StatusCode:        http.StatusOK,
	})
	require.ErrorContains(t, err, "execution claim is required")
	claimed, err := d.CheckDownloadPermission(context.Background(), driver.DownloadPermissionRequest{
		AuthorityProtocol:    model.DownloadAuthorityProtocol,
		Provider:             googleDriveAccountProvider,
		AccountName:          replacement.AccountName,
		FileID:               request.FileID,
		Generation:           replacement.Generation,
		FileGeneration:       replacement.FileGeneration,
		CredentialGeneration: replacement.CredentialGeneration,
		Mode:                 replacement.Mode,
		ObservationID:        replacement.ObservationID,
		ReservationID:        replacement.ReservationID,
		Operation:            "claim",
		ExecutionClaimID:     "execution-1",
	})
	require.NoError(t, err)
	require.True(t, claimed.Allow)

	result, err := d.ReportDownloadAuthorization(context.Background(), driver.DownloadAuthorizationReport{
		AuthorityProtocol: model.DownloadAuthorityProtocol,
		Provider:          googleDriveAccountProvider,
		AccountName:       replacement.AccountName,
		FileID:            request.FileID,
		Generation:        replacement.Generation,
		FileGeneration:    replacement.FileGeneration,
		TrialID:           replacement.ReservationID,
		ExecutionClaimID:  claimed.ExecutionClaimID,
		ObservationID:     replacement.ObservationID,
		EventType:         "success",
		EventID:           driver.CanonicalDownloadAuthorizationEventID(replacement.ObservationID, "success"),
		Outcome:           "success",
		StatusCode:        http.StatusOK,
	})
	require.NoError(t, err)
	require.True(t, result.Applied)
	cooldown, _, err := getGoogleDriveQuotaFileState(context.Background(), request.FileID)
	require.NoError(t, err)
	require.True(t, cooldown.IsZero())
}

func TestQuotaAuthorityV2NextPlanKeepsRequiredTrialBoundaries(t *testing.T) {
	for _, target := range []string{"file", "alternative account", "cooled account replacement", "sole original account"} {
		t.Run(target, func(t *testing.T) {
			clock := newQuotaTestClock()
			runtime := newQuotaAuthorityRuntime(clock.Now)
			excluded := "A"
			candidates := []string{"B"}
			if target == "file" {
				runtime.getFileLocked("X").CooldownUntil = clock.Now().Add(-time.Second)
			} else {
				runtime.getAccountLocked("B").CooldownUntil = clock.Now().Add(-time.Second)
			}
			if target == "sole original account" {
				excluded = "B"
			}
			if target == "cooled account replacement" {
				runtime.getAccountLocked("A").CooldownUntil = clock.Now().Add(time.Hour)
				runtime.getFileLocked("X").QuotaPending = true
			}

			plan, err := runtime.nextDiagnostic(context.Background(), "X", excluded, candidates)
			require.NoError(t, err)
			require.True(t, plan.Allow)
			require.Equal(t, quotaModeProbe, plan.Mode)
			require.NotEmpty(t, plan.ReservationID)

			claimed, err := runtime.permission(context.Background(), plan.AccountName, "X", plan.AccountGeneration, plan.FileGeneration, plan.Mode, plan.ObservationID, plan.ReservationID, "claim", "boundary-owner")
			require.NoError(t, err)
			require.True(t, claimed.Allow)
			report := quotaTestReport(plan.AccountName, "X", plan.ObservationID, "success", "success", "download_success", plan.AccountGeneration, plan.FileGeneration)
			report.TrialID = plan.ReservationID
			report.ExecutionClaimID = claimed.ExecutionClaimID
			result, err := runtime.report(context.Background(), report)
			require.NoError(t, err)
			require.True(t, result.Applied)

			next, err := runtime.nextDiagnostic(context.Background(), "X", plan.AccountName, candidates)
			require.NoError(t, err)
			require.True(t, next.Allow)
			require.Equal(t, quotaModeNormal, next.Mode)
			require.Empty(t, next.ReservationID)
		})
	}
}

func TestQuotaAuthorityV2NextPlanDoesNotOverlapActiveProbe(t *testing.T) {
	for _, scope := range []string{"file", "account"} {
		t.Run(scope, func(t *testing.T) {
			clock := newQuotaTestClock()
			runtime := newQuotaAuthorityRuntime(clock.Now)
			if scope == "file" {
				runtime.getFileLocked("X").CooldownUntil = clock.Now().Add(-time.Second)
			} else {
				runtime.getAccountLocked("A").CooldownUntil = clock.Now().Add(-time.Second)
			}
			probe, err := runtime.authorize(context.Background(), "A", "X")
			require.NoError(t, err)
			require.True(t, probe.Allow)
			require.Equal(t, quotaModeProbe, probe.Mode)
			claimed, err := runtime.permission(context.Background(), "A", "X", probe.AccountGeneration, probe.FileGeneration, probe.Mode, probe.ObservationID, probe.ReservationID, "claim", "active-probe")
			require.NoError(t, err)
			require.True(t, claimed.Allow)

			next, err := runtime.nextDiagnostic(context.Background(), "X", "A", []string{"A", "B"})
			require.NoError(t, err)
			require.False(t, next.Allow)
			require.Contains(t, next.Reason, "opportunity busy")

			report := quotaTestReport("A", "X", probe.ObservationID, "success", "success", "download_success", probe.AccountGeneration, probe.FileGeneration)
			report.TrialID = probe.ReservationID
			report.ExecutionClaimID = claimed.ExecutionClaimID
			result, err := runtime.report(context.Background(), report)
			require.NoError(t, err)
			require.True(t, result.Applied)
			recovered, err := runtime.nextDiagnostic(context.Background(), "X", "A", []string{"A", "B"})
			require.NoError(t, err)
			require.True(t, recovered.Allow)
			require.Equal(t, quotaModeNormal, recovered.Mode)
		})
	}
}

func TestQuotaAuthorityV2DurableSnapshotReloadsCooldownAndConsumedClaim(t *testing.T) {
	initGoogleDriveTestEnv(t)
	database := internaldb.GetDb()
	require.NotNil(t, database)
	database.Where("key = ?", quotaAuthorityStateKey).Delete(&model.GoogleDriveQuotaAuthority{})
	t.Cleanup(func() {
		database.Where("key = ?", quotaAuthorityStateKey).Delete(&model.GoogleDriveQuotaAuthority{})
	})
	clock := newQuotaTestClock()
	runtime := newDurableQuotaAuthorityRuntime(clock.Now)
	ctx := context.Background()
	first, err := runtime.authorize(ctx, "account-a", "durable-file")
	require.NoError(t, err)
	_, err = runtime.report(ctx, quotaTestReport("account-a", "durable-file", "durable-quota", "quota", "failure", "quota", first.AccountGeneration, first.FileGeneration))
	require.NoError(t, err)
	plan, err := runtime.nextDiagnostic(ctx, "durable-file", "account-a", []string{"account-a", "account-b"})
	require.NoError(t, err)
	require.True(t, plan.Allow)
	claimed, err := runtime.permission(ctx, "account-b", "durable-file", plan.AccountGeneration, plan.FileGeneration, quotaModeDiagnostic, plan.ObservationID, plan.ReservationID, "claim", "durable-claim")
	require.NoError(t, err)
	require.True(t, claimed.Allow)

	reloaded := newDurableQuotaAuthorityRuntime(clock.Now)
	state, err := reloaded.getFileState(ctx, "durable-file")
	require.NoError(t, err)
	require.NotNil(t, state.Diagnostic)
	require.True(t, state.Diagnostic.Claimed)
	require.Equal(t, "durable-claim", state.Diagnostic.ExecutionClaimID)
}
