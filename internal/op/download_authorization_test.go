package op_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	stdpath "path"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/OpenListTeam/OpenList/v4/drivers/alias"
	driverpkg "github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/errs"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
	pkgsign "github.com/OpenListTeam/OpenList/v4/pkg/sign"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
)

func downloadTicketHashForTest(ticket string) string {
	digest := sha256.Sum256([]byte(ticket))
	return hex.EncodeToString(digest[:])
}

func resignDownloadReference(t *testing.T, reference string, field string, value any, expiresAt int64) string {
	t.Helper()
	parts := strings.Split(reference, ".")
	if len(parts) != 2 {
		t.Fatalf("invalid signed reference: %q", reference)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode signed reference: %v", err)
	}
	claims := make(map[string]any)
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("decode signed reference claims: %v", err)
	}
	claims[field] = value
	payload, err = json.Marshal(claims)
	if err != nil {
		t.Fatalf("encode signed reference claims: %v", err)
	}
	signer := pkgsign.NewHMACSign([]byte(mustGetSettingItem(t, "token").Value))
	return base64.RawURLEncoding.EncodeToString(payload) + "." + signer.Sign(string(payload), expiresAt)
}

func TestResolveLinkAPIRejectsTamperedExpiredAndCrossFileReportsBeforeDriverMutation(t *testing.T) {
	mountPath := uniqueMountPath(t, "authorization-boundary")
	driver := mustCreateAuthorizationTestStorage(t, mountPath, authorizationTestBehavior{
		files: map[string]authorizationTestFile{
			"/file.bin":  {id: "file-id", size: 7},
			"/other.bin": {id: "other-id", size: 9},
		},
	})
	seedLinkAPISigningToken(t)
	path := mountPath + "/file.bin"
	link, _, err := op.ResolveLinkAPI(context.Background(), op.LinkAPIRequest{AuthorityProtocol: model.DownloadAuthorityProtocol, Action: "acquire", Path: path})
	if err != nil {
		t.Fatalf("acquire failed: %v", err)
	}
	ticket := link.Download.Ticket
	_ = link.Close()

	report := func(path, ticket, eventID string) error {
		_, _, err := op.ResolveLinkAPI(context.Background(), op.LinkAPIRequest{
			AuthorityProtocol: model.DownloadAuthorityProtocol,
			Action:            "report",
			Path:              path,
			Feedback: &model.DownloadFeedback{
				AuthorityProtocol: model.DownloadAuthorityProtocol,
				Ticket:            ticket,
				Permit:            link.Download.Permit,
				ObservationID:     link.Download.Permit.ObservationID,
				EventType:         "failure",
				EventID:           eventID,
				Outcome:           "failure",
				StatusCode:        http.StatusInternalServerError,
				Reason:            "upstream failed",
			},
		})
		return err
	}

	tamperedSuffix := "x"
	if ticket[len(ticket)-1:] == tamperedSuffix {
		tamperedSuffix = "y"
	}
	tampered := ticket[:len(ticket)-1] + tamperedSuffix
	if err := report(path, tampered, "tampered"); err == nil || !op.IsLinkAPIRequestError(err) {
		t.Fatalf("expected tampered ticket request error, got %v", err)
	}

	parts := strings.Split(ticket, ".")
	if len(parts) != 2 {
		t.Fatalf("expected signed ticket payload and signature, got %q", ticket)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode ticket payload: %v", err)
	}
	token := mustGetSettingItem(t, "token").Value
	expiredSignature := pkgsign.NewHMACSign([]byte(token)).Sign(string(payload), time.Now().Add(-time.Hour).Unix())
	if err := report(path, parts[0]+"."+expiredSignature, "expired"); err == nil || !op.IsLinkAPIRequestError(err) {
		t.Fatalf("expected expired ticket request error, got %v", err)
	}

	if err := report(mountPath+"/other.bin", ticket, "cross-file"); err == nil || !op.IsLinkAPIRequestError(err) {
		t.Fatalf("expected cross-file ticket request error, got %v", err)
	}
	_, _, err = op.ResolveLinkAPI(context.Background(), op.LinkAPIRequest{
		AuthorityProtocol: model.DownloadAuthorityProtocol,
		Action:            "report",
		Path:              path,
		Feedback: &model.DownloadFeedback{
			AuthorityProtocol: model.DownloadAuthorityProtocol,
			Ticket:            ticket,
			Permit:            link.Download.Permit,
			ObservationID:     link.Download.Permit.ObservationID,
			EventType:         "success",
			EventID:           "invalid-success-status",
			Outcome:           "success",
			StatusCode:        http.StatusInternalServerError,
		},
	})
	if err == nil || !op.IsLinkAPIRequestError(err) {
		t.Fatalf("expected inconsistent success status request error, got %v", err)
	}
	if got := driver.reportCalls.Load(); got != 0 {
		t.Fatalf("expected invalid reports to avoid driver mutation, got %d reports", got)
	}
	_, _, err = op.ResolveLinkAPI(context.Background(), op.LinkAPIRequest{
		AuthorityProtocol: model.DownloadAuthorityProtocol,
		Action:            "report",
		Path:              path,
		Feedback: &model.DownloadFeedback{
			AuthorityProtocol: model.DownloadAuthorityProtocol,
			Ticket:            ticket,
			Permit:            link.Download.Permit,
			ObservationID:     link.Download.Permit.ObservationID,
			EventType:         "success",
			Outcome:           "failure",
			StatusCode:        http.StatusForbidden,
			Reason:            "quota",
		},
	})
	if err == nil || !op.IsLinkAPIRequestError(err) {
		t.Fatalf("expected inconsistent success event/outcome request error, got %v", err)
	}
	if got := driver.reportCalls.Load(); got != 0 {
		t.Fatalf("expected semantically invalid report to avoid driver mutation, got %d reports", got)
	}
}

func TestResolveLinkAPILateQuotaCanSelectReplacementDuringReportGrace(t *testing.T) {
	mountPath := uniqueMountPath(t, "authorization-late-quota")
	driver := mustCreateAuthorizationTestStorage(t, mountPath, authorizationTestBehavior{
		files: map[string]authorizationTestFile{"/file.bin": {id: "file-id", size: 7}},
	})
	seedLinkAPISigningToken(t)
	path := mountPath + "/file.bin"
	initial, _, err := op.ResolveLinkAPI(context.Background(), op.LinkAPIRequest{
		AuthorityProtocol: model.DownloadAuthorityProtocol,
		Action:            "acquire",
		Path:              path,
	})
	if err != nil {
		t.Fatalf("initial acquire failed: %v", err)
	}
	defer initial.Close()
	expiredAt := time.Now().Add(-time.Minute).Unix()
	expiredTicket := resignDownloadReference(t, initial.Download.Ticket, "expires_at", expiredAt, expiredAt)
	permitClaimsTicket := expiredTicket
	expiredPermitProof := resignDownloadReference(t, initial.Download.Permit.Proof, "expires_at", expiredAt, expiredAt)
	expiredPermitProof = resignDownloadReference(t, expiredPermitProof, "issued_at", expiredAt-60, expiredAt)
	expiredPermitProof = resignDownloadReference(t, expiredPermitProof, "ticket_hash", downloadTicketHashForTest(permitClaimsTicket), expiredAt)
	expiredPermit := *initial.Download.Permit
	expiredPermit.Proof = expiredPermitProof

	replacement, _, err := op.ResolveLinkAPI(context.Background(), op.LinkAPIRequest{
		AuthorityProtocol: model.DownloadAuthorityProtocol,
		Action:            "next_plan",
		Path:              path,
		Feedback: &model.DownloadFeedback{
			AuthorityProtocol: model.DownloadAuthorityProtocol,
			Ticket:            expiredTicket,
			Permit:            &expiredPermit,
			ObservationID:     initial.Download.Permit.ObservationID,
			EventType:         "quota",
			Outcome:           "failure",
			StatusCode:        http.StatusForbidden,
			Reason:            "quota",
		},
	})
	if err != nil {
		t.Fatalf("late quota replacement failed: %v", err)
	}
	if replacement == nil || replacement.Download == nil || replacement.Download.Ticket == expiredTicket {
		t.Fatal("expected a fresh replacement authorization during report grace")
	}
	if got := driver.acquireCalls.Load(); got != 2 {
		t.Fatalf("expected one initial and one replacement acquisition, got %d", got)
	}

	_, _, err = op.ResolveLinkAPI(context.Background(), op.LinkAPIRequest{
		AuthorityProtocol: model.DownloadAuthorityProtocol,
		Action:            "next_plan",
		Path:              path,
		Ticket:            expiredTicket,
	})
	if err == nil || !op.IsLinkAPIRequestError(err) {
		t.Fatalf("expected expired ticket-only next_plan rejection, got %v", err)
	}
	_ = replacement.Close()
}

func TestResolveLinkAPIValidFeedbackAndInvalidExclusionDoNotMutateDriver(t *testing.T) {
	mountPath := uniqueMountPath(t, "authorization-exclusion")
	driver := mustCreateAuthorizationTestStorage(t, mountPath, authorizationTestBehavior{
		files: map[string]authorizationTestFile{"/file.bin": {id: "file-id", size: 7}},
	})
	seedLinkAPISigningToken(t)
	path := mountPath + "/file.bin"
	initial, _, err := op.ResolveLinkAPI(context.Background(), op.LinkAPIRequest{AuthorityProtocol: model.DownloadAuthorityProtocol, Action: "acquire", Path: path})
	if err != nil {
		t.Fatalf("initial acquire failed: %v", err)
	}
	_ = initial.Close()
	tamperedPermit := *initial.Download.Permit
	tamperedPermit.Proof += "-tampered"

	_, _, err = op.ResolveLinkAPI(context.Background(), op.LinkAPIRequest{
		AuthorityProtocol: model.DownloadAuthorityProtocol,
		Action:            "acquire",
		Path:              path,
		Feedback: &model.DownloadFeedback{
			AuthorityProtocol: model.DownloadAuthorityProtocol,
			Ticket:            initial.Download.Ticket,
			Permit:            &tamperedPermit,
			ObservationID:     initial.Download.Permit.ObservationID,
			EventType:         "failure",
			EventID:           "valid-feedback",
			Outcome:           "failure",
			StatusCode:        http.StatusForbidden,
			Reason:            "downloadQuotaExceeded",
		},
	})
	if err == nil || !op.IsLinkAPIRequestError(err) {
		t.Fatalf("expected invalid permit request error, got %v", err)
	}
	if got := driver.acquireCalls.Load(); got != 1 {
		t.Fatalf("expected invalid permit to stop before replacement acquire, got %d acquires", got)
	}
	if got := driver.reportCalls.Load(); got != 0 {
		t.Fatalf("expected valid feedback to remain unapplied when permit is invalid, got %d reports", got)
	}
}

func TestResolveLinkAPIAliasFeedbackRetainsSignedLeaf(t *testing.T) {
	leafMount := uniqueMountPath(t, "authorization-leaf")
	leaf := mustCreateAuthorizationTestStorage(t, leafMount, authorizationTestBehavior{
		files: map[string]authorizationTestFile{"/file.bin": {id: "leaf-file-id", size: 7}},
	})
	aliasMount := uniqueMountPath(t, "authorization-alias")
	mustCreateStorage(t, model.Storage{
		MountPath: aliasMount,
		Driver:    "Alias",
		Addition: mustMarshal(t, alias.Addition{
			Paths:           leafMount,
			ProtectSameName: true,
		}),
	})
	seedLinkAPISigningToken(t)
	requestedPath := aliasMount + "/file.bin"
	link, _, err := op.ResolveLinkAPI(context.Background(), op.LinkAPIRequest{AuthorityProtocol: model.DownloadAuthorityProtocol, Action: "acquire", Path: requestedPath})
	if err != nil {
		t.Fatalf("alias acquire failed: %v", err)
	}
	if got, want := leaf.lastAcquireMount(), leafMount; got != want {
		t.Fatalf("expected acquire to select concrete leaf mount %q, got %q", want, got)
	}
	ticket := link.Download.Ticket
	_ = link.Close()
	_, result, err := op.ResolveLinkAPI(context.Background(), op.LinkAPIRequest{
		AuthorityProtocol: model.DownloadAuthorityProtocol,
		Action:            "report",
		Path:              requestedPath,
		Feedback: &model.DownloadFeedback{
			AuthorityProtocol: model.DownloadAuthorityProtocol,
			Ticket:            ticket,
			Permit:            link.Download.Permit,
			ObservationID:     link.Download.Permit.ObservationID,
			EventType:         "failure",
			EventID:           "",
			Outcome:           "failure",
			StatusCode:        http.StatusInternalServerError,
			Reason:            "content failed",
		},
	})
	if err != nil {
		t.Fatalf("alias report failed: %v", err)
	}
	if result == nil || !result.Applied {
		t.Fatalf("expected alias report to be applied, got %+v", result)
	}
	if got := leaf.reportCalls.Load(); got != 1 {
		t.Fatalf("expected report on signed concrete leaf, got %d reports", got)
	}
}

func TestResolveLinkAPINextPlanTicketRetainsSignedLeaf(t *testing.T) {
	leafMount := uniqueMountPath(t, "next-plan-leaf")
	leaf := mustCreateAuthorizationTestStorage(t, leafMount, authorizationTestBehavior{
		files: map[string]authorizationTestFile{"/file.bin": {id: "next-plan-file-id", size: 7}},
	})
	aliasMount := uniqueMountPath(t, "next-plan-alias")
	mustCreateStorage(t, model.Storage{
		MountPath: aliasMount,
		Driver:    "Alias",
		Addition: mustMarshal(t, alias.Addition{
			Paths:           leafMount,
			ProtectSameName: true,
		}),
	})
	seedLinkAPISigningToken(t)
	requestedPath := aliasMount + "/file.bin"
	initial, _, err := op.ResolveLinkAPI(context.Background(), op.LinkAPIRequest{
		AuthorityProtocol: model.DownloadAuthorityProtocol,
		Action:            "acquire",
		Path:              requestedPath,
	})
	if err != nil {
		t.Fatalf("initial acquire failed: %v", err)
	}
	defer initial.Close()
	initialRequest := leaf.lastAcquireRequest()

	next, _, err := op.ResolveLinkAPI(context.Background(), op.LinkAPIRequest{
		AuthorityProtocol: model.DownloadAuthorityProtocol,
		Action:            "next_plan",
		Path:              requestedPath,
		Ticket:            initial.Download.Ticket,
	})
	if err != nil {
		t.Fatalf("ticket-only next_plan failed: %v", err)
	}
	defer next.Close()
	nextRequest := leaf.lastAcquireRequest()
	if nextRequest.Operation != "next_plan" || nextRequest.Ticket != initial.Download.Ticket {
		t.Fatalf("expected next_plan to retain the original signed ticket, got %+v", nextRequest)
	}
	if nextRequest.MountPath != initialRequest.MountPath || nextRequest.LeafPath != initialRequest.LeafPath || nextRequest.FileID != initialRequest.FileID {
		t.Fatalf("ticket-only next_plan changed the signed physical leaf: initial=%+v next=%+v", initialRequest, nextRequest)
	}
}

func TestResolveLinkAPICanceledIssuanceReleasesTrialWithDetachedContext(t *testing.T) {
	mountPath := uniqueMountPath(t, "authorization-cancel")
	driver := mustCreateAuthorizationTestStorage(t, mountPath, authorizationTestBehavior{
		files: map[string]authorizationTestFile{"/file.bin": {id: "file-id", size: 7}},
		acquire: func(driverpkg.DownloadAuthorizationRequest) driverpkg.DownloadAuthorizationResult {
			return driverpkg.DownloadAuthorizationResult{
				Link:        &model.Link{URL: "https://download.example.com/file.bin"},
				AccountName: "trial-account",
				Generation:  1,
				TrialID:     "trial-1",
			}
		},
	})
	seedLinkAPISigningToken(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := op.ResolveLinkAPI(ctx, op.LinkAPIRequest{AuthorityProtocol: model.DownloadAuthorityProtocol, Action: "acquire", Path: mountPath + "/file.bin"})
	if err == nil {
		t.Fatal("expected canceled issuance to fail")
	}
	if got := driver.permissionCalls.Load(); got != 1 {
		t.Fatalf("expected canceled issuance to release the trial, got %d permission releases", got)
	}
	if driver.lastPermissionContextErr() != nil {
		t.Fatalf("expected detached release context, got %v", driver.lastPermissionContextErr())
	}
}

func TestResolveLinkAPIIssuanceFailureReleasesTrial(t *testing.T) {
	mountPath := uniqueMountPath(t, "authorization-issuance-failure")
	driver := mustCreateAuthorizationTestStorage(t, mountPath, authorizationTestBehavior{
		files: map[string]authorizationTestFile{"/file.bin": {id: "file-id", size: 7}},
		acquire: func(driverpkg.DownloadAuthorizationRequest) driverpkg.DownloadAuthorizationResult {
			return driverpkg.DownloadAuthorizationResult{
				Link:        &model.Link{URL: "/invalid-relative-url"},
				AccountName: "trial-account",
				Generation:  1,
				TrialID:     "trial-1",
			}
		},
	})
	seedLinkAPISigningToken(t)
	_, _, err := op.ResolveLinkAPI(context.Background(), op.LinkAPIRequest{AuthorityProtocol: model.DownloadAuthorityProtocol, Action: "acquire", Path: mountPath + "/file.bin"})
	if err == nil {
		t.Fatal("expected invalid authorization URL to fail")
	}
	if got := driver.permissionCalls.Load(); got != 1 {
		t.Fatalf("expected failed issuance to release the trial, got %d permission releases", got)
	}
}

const authorizationTestDriverName = "TestDownloadAuthorizer"

var authorizationTestDriverOnce sync.Once

var authorizationTestFixtures = struct {
	sync.Mutex
	byMountPath map[string]authorizationTestBehavior
}{byMountPath: map[string]authorizationTestBehavior{}}

type authorizationTestBehavior struct {
	files   map[string]authorizationTestFile
	acquire func(driverpkg.DownloadAuthorizationRequest) driverpkg.DownloadAuthorizationResult
	check   func(context.Context, driverpkg.DownloadPermissionRequest) driverpkg.DownloadPermissionResult
}

type authorizationTestFile struct {
	id   string
	size int64
}

func mustCreateAuthorizationTestStorage(t *testing.T, mountPath string, behavior authorizationTestBehavior) *authorizationTestDriver {
	t.Helper()
	authorizationTestDriverOnce.Do(func() {
		op.RegisterDriver(func() driverpkg.Driver { return &authorizationTestDriver{} })
	})
	authorizationTestFixtures.Lock()
	authorizationTestFixtures.byMountPath[mountPath] = behavior
	authorizationTestFixtures.Unlock()
	t.Cleanup(func() {
		authorizationTestFixtures.Lock()
		delete(authorizationTestFixtures.byMountPath, mountPath)
		authorizationTestFixtures.Unlock()
	})
	drv := mustCreateStorage(t, model.Storage{
		MountPath: mountPath,
		Driver:    authorizationTestDriverName,
		Addition:  mustMarshal(t, driverpkg.RootPath{RootFolderPath: "/"}),
	})
	result, ok := drv.(*authorizationTestDriver)
	if !ok {
		t.Fatalf("expected authorization test driver, got %T", drv)
	}
	return result
}

type authorizationTestDriver struct {
	model.Storage
	addition driverpkg.RootPath
	files    map[string]*model.Object
	behavior authorizationTestBehavior

	acquireCalls         atomic.Int32
	reportCalls          atomic.Int32
	permissionCalls      atomic.Int32
	mu                   sync.Mutex
	lastAcquire          driverpkg.DownloadAuthorizationRequest
	reportContextErr     error
	permissionContextErr error
}

func (d *authorizationTestDriver) Config() driverpkg.Config {
	return driverpkg.Config{Name: authorizationTestDriverName, DefaultRoot: "/"}
}

func (d *authorizationTestDriver) GetAddition() driverpkg.Additional { return &d.addition }
func (d *authorizationTestDriver) Init(context.Context) error {
	authorizationTestFixtures.Lock()
	d.behavior = authorizationTestFixtures.byMountPath[d.MountPath]
	authorizationTestFixtures.Unlock()
	d.files = make(map[string]*model.Object, len(d.behavior.files))
	for path, file := range d.behavior.files {
		d.files[path] = &model.Object{ID: file.id, Path: path, Name: stdpath.Base(path), Size: file.size}
	}
	return nil
}
func (d *authorizationTestDriver) Drop(context.Context) error { return nil }
func (d *authorizationTestDriver) List(context.Context, model.Obj, model.ListArgs) ([]model.Obj, error) {
	return nil, errs.NotImplement
}
func (d *authorizationTestDriver) Get(_ context.Context, path string) (model.Obj, error) {
	if path == "/" {
		return &model.Object{Path: "/", Name: "Root", IsFolder: true}, nil
	}
	file, ok := d.files[utils.FixAndCleanPath(path)]
	if !ok {
		return nil, errs.ObjectNotFound
	}
	copy := *file
	return &copy, nil
}
func (d *authorizationTestDriver) Link(context.Context, model.Obj, model.LinkArgs) (*model.Link, error) {
	return &model.Link{URL: "https://download.example.com/file.bin"}, nil
}
func (d *authorizationTestDriver) AcquireDownloadAuthorization(_ context.Context, request driverpkg.DownloadAuthorizationRequest) (driverpkg.DownloadAuthorizationResult, error) {
	d.acquireCalls.Add(1)
	d.mu.Lock()
	d.lastAcquire = request
	d.mu.Unlock()
	if d.behavior.acquire != nil {
		return d.behavior.acquire(request), nil
	}
	return driverpkg.DownloadAuthorizationResult{Link: &model.Link{URL: "https://download.example.com/file.bin"}}, nil
}
func (d *authorizationTestDriver) ReportDownloadAuthorization(ctx context.Context, _ driverpkg.DownloadAuthorizationReport) (driverpkg.DownloadAuthorizationReportResult, error) {
	d.reportCalls.Add(1)
	d.mu.Lock()
	d.reportContextErr = ctx.Err()
	d.mu.Unlock()
	return driverpkg.DownloadAuthorizationReportResult{Applied: true}, nil
}

func (d *authorizationTestDriver) CheckDownloadPermission(ctx context.Context, request driverpkg.DownloadPermissionRequest) (driverpkg.DownloadPermissionResult, error) {
	d.permissionCalls.Add(1)
	d.mu.Lock()
	d.permissionContextErr = ctx.Err()
	d.mu.Unlock()
	if d.behavior.check != nil {
		return d.behavior.check(ctx, request), nil
	}
	return driverpkg.DownloadPermissionResult{
		AuthorityProtocol: model.DownloadAuthorityProtocol,
		Allow:             true,
		AccountName:       request.AccountName,
		FileGeneration:    request.FileGeneration,
		AccountGeneration: request.Generation,
		Mode:              request.Mode,
		ObservationID:     request.ObservationID,
		ReservationID:     request.ReservationID,
	}, nil
}

func (d *authorizationTestDriver) lastAcquireMount() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.lastAcquire.MountPath
}

func (d *authorizationTestDriver) lastAcquireRequest() driverpkg.DownloadAuthorizationRequest {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.lastAcquire
}

func (d *authorizationTestDriver) lastReportContextErr() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.reportContextErr
}

func (d *authorizationTestDriver) lastPermissionContextErr() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.permissionContextErr
}

func seedLinkAPISigningToken(t *testing.T) {
	t.Helper()
	item, existed := mustGetOrCreateSettingItem(t, "token", "download-authorization-test-token")
	if !existed {
		t.Cleanup(func() { mustDeleteSettingItem(t, "token") })
		return
	}
	original := item
	if item.Value == "" {
		item.Value = "download-authorization-test-token"
		mustSaveSettingItem(t, item)
		t.Cleanup(func() { mustSaveSettingItem(t, original) })
	}
}

var _ driverpkg.Driver = (*authorizationTestDriver)(nil)
var _ driverpkg.Getter = (*authorizationTestDriver)(nil)
var _ driverpkg.DownloadAuthorizer = (*authorizationTestDriver)(nil)
var _ driverpkg.DownloadPermissionAuthorizer = (*authorizationTestDriver)(nil)
