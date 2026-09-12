package op_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	driverpkg "github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
)

func executionPermissionExpiry(t *testing.T, proof string) int64 {
	t.Helper()
	parts := strings.Split(proof, ".")
	if len(parts) != 2 {
		t.Fatalf("invalid execution permission proof: %q", proof)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode execution permission proof: %v", err)
	}
	var claims struct {
		ExpiresAt int64 `json:"expires_at"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("decode execution permission claims: %v", err)
	}
	return claims.ExpiresAt
}

func executionPermissionGenerations(t *testing.T, proof string) (uint64, uint64) {
	t.Helper()
	parts := strings.Split(proof, ".")
	if len(parts) != 2 {
		t.Fatalf("invalid execution permission proof: %q", proof)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode execution permission proof: %v", err)
	}
	var claims struct {
		Generation     uint64 `json:"generation"`
		FileGeneration uint64 `json:"file_generation"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("decode execution permission claims: %v", err)
	}
	return claims.Generation, claims.FileGeneration
}

func TestResolveLinkAPIV2ContractBindsPermitAndCanonicalReportIdentity(t *testing.T) {
	mountPath := uniqueMountPath(t, "authority-v2-contract")
	mustCreateAuthorizationTestStorage(t, mountPath, authorizationTestBehavior{
		files: map[string]authorizationTestFile{"/file.bin": {id: "file-id", size: 7}},
	})
	seedLinkAPISigningToken(t)
	path := mountPath + "/file.bin"

	link, _, err := op.ResolveLinkAPI(context.Background(), op.LinkAPIRequest{
		AuthorityProtocol: model.DownloadAuthorityProtocol,
		Action:            "acquire",
		Path:              path,
	})
	if err != nil {
		t.Fatalf("v2 acquire failed: %v", err)
	}
	if link == nil || link.Download == nil || link.Download.Permit == nil {
		t.Fatal("v2 acquire did not return a signed execution permit")
	}
	if got, want := link.Download.AuthorityProtocol, int64(model.DownloadAuthorityProtocol); got != want {
		t.Fatalf("expected download authority protocol %d, got %d", want, got)
	}
	permit := *link.Download.Permit
	if permit.AuthorityProtocol != model.DownloadAuthorityProtocol || !permit.Allow || permit.Mode != "normal" || permit.ObservationID == "" || permit.ValidForMS <= 0 || permit.Proof == "" {
		t.Fatalf("unexpected acquire permit: %+v", permit)
	}
	ticket := link.Download.Ticket
	if err := link.Close(); err != nil {
		t.Fatalf("close acquired link: %v", err)
	}

	parts := strings.Split(ticket, ".")
	if len(parts) != 2 {
		t.Fatalf("expected signed ticket, got %q", ticket)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode signed ticket: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("decode ticket claims: %v", err)
	}
	if got, want := int(claims["authority_protocol"].(float64)), model.DownloadAuthorityProtocol; got != want {
		t.Fatalf("expected ticket authority protocol %d, got %d", want, got)
	}

	checked, _, err := op.ResolveLinkAPI(context.Background(), op.LinkAPIRequest{
		AuthorityProtocol: model.DownloadAuthorityProtocol,
		Action:            "check",
		Path:              path,
		Ticket:            ticket,
		Permit:            &permit,
		Operation:         "check",
	})
	if err != nil {
		t.Fatalf("v2 permission check failed: %v", err)
	}
	if checked == nil || checked.Download == nil || checked.Download.Permit == nil || checked.Download.Permit.Proof == permit.Proof {
		t.Fatal("v2 check did not publish a fresh permit proof")
	}
	checkedPermit := *checked.Download.Permit
	if !checkedPermit.Allow || checkedPermit.Mode != "normal" || checkedPermit.ObservationID != permit.ObservationID {
		t.Fatalf("unexpected checked permit: %+v", checkedPermit)
	}

	_, result, err := op.ResolveLinkAPI(context.Background(), op.LinkAPIRequest{
		AuthorityProtocol: model.DownloadAuthorityProtocol,
		Action:            "report",
		Path:              path,
		Feedback: &model.DownloadFeedback{
			AuthorityProtocol: model.DownloadAuthorityProtocol,
			Ticket:            ticket,
			Permit:            &checkedPermit,
			ObservationID:     checkedPermit.ObservationID,
			EventType:         "success",
			Outcome:           "success",
			StatusCode:        http.StatusOK,
		},
	})
	if err != nil {
		t.Fatalf("v2 report failed: %v", err)
	}
	if result == nil || !result.Applied || result.AuthorityProtocol != model.DownloadAuthorityProtocol {
		t.Fatalf("unexpected v2 report result: %+v", result)
	}

}

func TestResolveLinkAPIV2LongReferenceKeepsRenewalProofBounded(t *testing.T) {
	mountPath := uniqueMountPath(t, "long-authority-"+strings.Repeat("x", 3000))
	mustCreateAuthorizationTestStorage(t, mountPath, authorizationTestBehavior{
		files: map[string]authorizationTestFile{"/file.bin": {id: "long-file-id", size: 7}},
	})
	seedLinkAPISigningToken(t)
	path := mountPath + "/file.bin"
	if len(path) >= maxLinkAPIPathForTest {
		t.Fatalf("fixture path is too long: %d", len(path))
	}
	link, _, err := op.ResolveLinkAPI(context.Background(), op.LinkAPIRequest{
		AuthorityProtocol: model.DownloadAuthorityProtocol,
		Action:            "acquire",
		Path:              path,
	})
	if err != nil {
		t.Fatalf("acquire accepted path: %v", err)
	}
	defer link.Close()
	if got := len(link.Download.Permit.Proof); got > 16384 {
		t.Fatalf("issued permission proof exceeds its validation boundary: %d", got)
	}
	checked, _, err := op.ResolveLinkAPI(context.Background(), op.LinkAPIRequest{
		AuthorityProtocol: model.DownloadAuthorityProtocol,
		Action:            "check",
		Operation:         "check",
		Path:              path,
		Ticket:            link.Download.Ticket,
		Permit:            link.Download.Permit,
	})
	if err != nil {
		t.Fatalf("authority rejected its newly issued long reference: %v", err)
	}
	defer checked.Close()
	if checked.Download == nil || checked.Download.Permit == nil || !checked.Download.Permit.Allow {
		t.Fatal("long reference renewal did not return an executable permission")
	}
}

func TestResolveLinkAPIV2OversizedReferencesReleaseReservations(t *testing.T) {
	for _, oversized := range []string{"ticket", "proof"} {
		t.Run(oversized, func(t *testing.T) {
			seedLinkAPISigningToken(t)
			mountPrefix := uniqueMountPath(t, "oversized-authority")
			mountPath := mountPrefix
			reason := "reserved opportunity"
			if oversized == "ticket" {
				mountPath += strings.Repeat("x", 4095-len(mountPrefix)-len("/file.bin"))
			} else {
				reason = strings.Repeat("<", 4096)
			}
			drv := mustCreateAuthorizationTestStorage(t, mountPath, authorizationTestBehavior{
				files: map[string]authorizationTestFile{"/file.bin": {id: "oversized-file-id", size: 7}},
				acquire: func(driverpkg.DownloadAuthorizationRequest) driverpkg.DownloadAuthorizationResult {
					return driverpkg.DownloadAuthorizationResult{
						Link:          &model.Link{URL: "https://download.example.com/file.bin"},
						AccountName:   "trial-account",
						Generation:    1,
						TrialID:       "root-reservation",
						ReservationID: "root-reservation",
						Mode:          "diagnostic",
						Allow:         false,
						Reason:        reason,
					}
				},
			})
			link, _, err := op.ResolveLinkAPI(context.Background(), op.LinkAPIRequest{
				AuthorityProtocol: model.DownloadAuthorityProtocol,
				Action:            "acquire",
				Path:              mountPath + "/file.bin",
			})
			if err == nil {
				_ = link.Close()
				t.Fatalf("issued oversized %s reference", oversized)
			}
			if !op.IsLinkAPIRequestError(err) {
				t.Fatalf("expected bounded %s issuance failure, got %v", oversized, err)
			}
			if got := drv.permissionCalls.Load(); got != 1 {
				t.Fatalf("expected one neutral reservation release, got %d", got)
			}
			if got := drv.lastPermissionContextErr(); got != nil {
				t.Fatalf("reservation release lost its detached context: %v", got)
			}
		})
	}
}

func TestResolveLinkAPIV2CheckKeepsLivePermitDeadlineFixed(t *testing.T) {
	mountPath := uniqueMountPath(t, "authority-v2-deadline")
	mustCreateAuthorizationTestStorage(t, mountPath, authorizationTestBehavior{
		files: map[string]authorizationTestFile{"/file.bin": {id: "file-id", size: 7}},
	})
	seedLinkAPISigningToken(t)
	path := mountPath + "/file.bin"
	link, _, err := op.ResolveLinkAPI(context.Background(), op.LinkAPIRequest{
		AuthorityProtocol: model.DownloadAuthorityProtocol,
		Action:            "acquire",
		Path:              path,
	})
	if err != nil {
		t.Fatalf("v2 acquire failed: %v", err)
	}
	t.Cleanup(func() { _ = link.Close() })
	initialDeadline := executionPermissionExpiry(t, link.Download.Permit.Proof)
	checked, _, err := op.ResolveLinkAPI(context.Background(), op.LinkAPIRequest{
		AuthorityProtocol: model.DownloadAuthorityProtocol,
		Action:            "check",
		Path:              path,
		Ticket:            link.Download.Ticket,
		Permit:            link.Download.Permit,
		Operation:         "check",
	})
	if err != nil {
		t.Fatalf("v2 deadline check failed: %v", err)
	}
	if got := executionPermissionExpiry(t, checked.Download.Permit.Proof); got != initialDeadline {
		t.Fatalf("live permit deadline moved: initial=%d checked=%d", initialDeadline, got)
	}
}

const maxLinkAPIPathForTest = 4096

func TestResolveLinkAPIV2NormalRenewalUsesCurrentPermissionGenerations(t *testing.T) {
	mountPath := uniqueMountPath(t, "authority-v2-generation-rebind")
	storage := mustCreateAuthorizationTestStorage(t, mountPath, authorizationTestBehavior{
		files: map[string]authorizationTestFile{"/file.bin": {id: "file-id", size: 7}},
		acquire: func(driverpkg.DownloadAuthorizationRequest) driverpkg.DownloadAuthorizationResult {
			return driverpkg.DownloadAuthorizationResult{
				Link:                 &model.Link{URL: "https://download.example.com/file.bin"},
				AccountName:          "account",
				Generation:           1,
				FileGeneration:       1,
				CredentialGeneration: 1,
				Allow:                true,
			}
		},
	})
	seedLinkAPISigningToken(t)
	path := mountPath + "/file.bin"
	link, _, err := op.ResolveLinkAPI(context.Background(), op.LinkAPIRequest{
		AuthorityProtocol: model.DownloadAuthorityProtocol,
		Action:            "acquire",
		Path:              path,
	})
	if err != nil {
		t.Fatalf("v2 acquire failed: %v", err)
	}
	defer link.Close()
	storage.behavior.check = func(_ context.Context, request driverpkg.DownloadPermissionRequest) driverpkg.DownloadPermissionResult {
		return driverpkg.DownloadPermissionResult{
			AuthorityProtocol: model.DownloadAuthorityProtocol,
			Allow:             true,
			AccountName:       request.AccountName,
			FileGeneration:    2,
			AccountGeneration: 2,
			Mode:              request.Mode,
			ObservationID:     request.ObservationID,
			ReportSuccess:     true,
		}
	}
	checked, _, err := op.ResolveLinkAPI(context.Background(), op.LinkAPIRequest{
		AuthorityProtocol: model.DownloadAuthorityProtocol,
		Action:            "check",
		Path:              path,
		Ticket:            link.Download.Ticket,
		Permit:            link.Download.Permit,
		Operation:         "check",
	})
	if err != nil {
		t.Fatalf("v2 current-generation check failed: %v", err)
	}
	accountGeneration, fileGeneration := executionPermissionGenerations(t, checked.Download.Permit.Proof)
	if accountGeneration != 2 || fileGeneration != 2 {
		t.Fatalf("renewed permit did not bind current state generations: account=%d file=%d", accountGeneration, fileGeneration)
	}
}
