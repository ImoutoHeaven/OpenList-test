package op_test

import (
	"context"
	"encoding/base64"
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
	link, _, err := op.ResolveLinkAPI(context.Background(), op.LinkAPIRequest{Action: "acquire", Path: path})
	if err != nil {
		t.Fatalf("acquire failed: %v", err)
	}
	ticket := link.Download.Ticket
	_ = link.Close()

	report := func(path, ticket, eventID string) error {
		_, _, err := op.ResolveLinkAPI(context.Background(), op.LinkAPIRequest{
			Action: "report",
			Path:   path,
			Feedback: &model.DownloadFeedback{
				Ticket:     ticket,
				EventID:    eventID,
				Outcome:    "failure",
				StatusCode: http.StatusInternalServerError,
				Reason:     "upstream failed",
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
		Action: "report",
		Path:   path,
		Feedback: &model.DownloadFeedback{
			Ticket:     ticket,
			EventID:    "invalid-success-status",
			Outcome:    "success",
			StatusCode: http.StatusInternalServerError,
		},
	})
	if err == nil || !op.IsLinkAPIRequestError(err) {
		t.Fatalf("expected inconsistent success status request error, got %v", err)
	}
	if got := driver.reportCalls.Load(); got != 0 {
		t.Fatalf("expected invalid reports to avoid driver mutation, got %d reports", got)
	}
}

func TestResolveLinkAPIValidFeedbackAndInvalidExclusionDoNotMutateDriver(t *testing.T) {
	mountPath := uniqueMountPath(t, "authorization-exclusion")
	driver := mustCreateAuthorizationTestStorage(t, mountPath, authorizationTestBehavior{
		files: map[string]authorizationTestFile{"/file.bin": {id: "file-id", size: 7}},
	})
	seedLinkAPISigningToken(t)
	path := mountPath + "/file.bin"
	initial, _, err := op.ResolveLinkAPI(context.Background(), op.LinkAPIRequest{Action: "acquire", Path: path})
	if err != nil {
		t.Fatalf("initial acquire failed: %v", err)
	}
	_ = initial.Close()

	_, _, err = op.ResolveLinkAPI(context.Background(), op.LinkAPIRequest{
		Action: "acquire",
		Path:   path,
		Feedback: &model.DownloadFeedback{
			Ticket:     initial.Download.Ticket,
			EventID:    "valid-feedback",
			Outcome:    "failure",
			StatusCode: http.StatusForbidden,
			Reason:     "downloadQuotaExceeded",
		},
		Exclude: []string{initial.Download.Ticket + "-tampered"},
	})
	if err == nil || !op.IsLinkAPIRequestError(err) {
		t.Fatalf("expected invalid exclusion request error, got %v", err)
	}
	if got := driver.acquireCalls.Load(); got != 1 {
		t.Fatalf("expected invalid exclusion to stop before replacement acquire, got %d acquires", got)
	}
	if got := driver.reportCalls.Load(); got != 0 {
		t.Fatalf("expected valid feedback to remain unapplied when exclusion is invalid, got %d reports", got)
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
	link, _, err := op.ResolveLinkAPI(context.Background(), op.LinkAPIRequest{Action: "acquire", Path: requestedPath})
	if err != nil {
		t.Fatalf("alias acquire failed: %v", err)
	}
	if got, want := leaf.lastAcquireMount(), leafMount; got != want {
		t.Fatalf("expected acquire to select concrete leaf mount %q, got %q", want, got)
	}
	ticket := link.Download.Ticket
	_ = link.Close()
	_, result, err := op.ResolveLinkAPI(context.Background(), op.LinkAPIRequest{
		Action: "report",
		Path:   requestedPath,
		Feedback: &model.DownloadFeedback{
			Ticket:     ticket,
			EventID:    "alias-report",
			Outcome:    "failure",
			StatusCode: http.StatusInternalServerError,
			Reason:     "content failed",
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
	_, _, err := op.ResolveLinkAPI(ctx, op.LinkAPIRequest{Action: "acquire", Path: mountPath + "/file.bin"})
	if err == nil {
		t.Fatal("expected canceled issuance to fail")
	}
	if got := driver.reportCalls.Load(); got != 1 {
		t.Fatalf("expected canceled issuance to release the trial, got %d reports", got)
	}
	if driver.lastReportContextErr() != nil {
		t.Fatalf("expected detached release context, got %v", driver.lastReportContextErr())
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
	_, _, err := op.ResolveLinkAPI(context.Background(), op.LinkAPIRequest{Action: "acquire", Path: mountPath + "/file.bin"})
	if err == nil {
		t.Fatal("expected invalid authorization URL to fail")
	}
	if got := driver.reportCalls.Load(); got != 1 {
		t.Fatalf("expected failed issuance to release the trial, got %d reports", got)
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

	acquireCalls     atomic.Int32
	reportCalls      atomic.Int32
	mu               sync.Mutex
	lastAcquire      driverpkg.DownloadAuthorizationRequest
	reportContextErr error
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

func (d *authorizationTestDriver) lastAcquireMount() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.lastAcquire.MountPath
}

func (d *authorizationTestDriver) lastReportContextErr() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.reportContextErr
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
