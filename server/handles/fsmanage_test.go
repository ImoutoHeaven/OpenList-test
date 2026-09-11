package handles

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	stdpath "path"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/internal/db"
	driverpkg "github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/errs"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
	"github.com/gin-gonic/gin"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func init() {
	dB, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	conf.Conf = conf.DefaultConfig("data")
	db.Init(dB)
	if _, err := op.GetSettingItemByKey(conf.Token); err != nil {
		if err := op.SaveSettingItem(&model.SettingItem{Key: conf.Token, Value: "link-api-test-token"}); err != nil {
			panic("failed to seed link API signing token")
		}
	}
	gin.SetMode(gin.TestMode)
}

func TestLinkHandler_ReturnsLeafDirectURLWithoutPProxyFallback(t *testing.T) {
	storage := mustCreateLinkHandlerTestStorage(t, uniqueLinkHandlerMountPath(t), linkHandlerStubBehavior{
		files: []string{"/file.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{
				URL: "https://download.example.com/file.bin",
				Header: http.Header{
					"Authorization": []string{"Bearer token"},
				},
			}, nil
		},
	})

	recorder := callLinkHandler(t, linkHandlerRequest{
		path:       storage.MountPath + "/file.bin",
		bodyJSON:   `{"action":"acquire","path":"` + storage.MountPath + `/file.bin","refresh":false}`,
		rawQuery:   "type=download&refresh=1",
		remoteAddr: "203.0.113.9:3456",
		headers: http.Header{
			"Content-Type":  []string{"application/json"},
			"X-Test-Header": []string{"present"},
		},
	})

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d with body %s", recorder.Code, recorder.Body.String())
	}

	resp := decodeLinkHandlerResp(t, recorder)
	if got, want := resp.Code, 200; got != want {
		t.Fatalf("expected response code %d, got %d with body %s", want, got, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "/p/") {
		t.Fatalf("expected response body without /p/ fallback, got %s", recorder.Body.String())
	}

	var link model.Link
	if err := json.Unmarshal(resp.Data, &link); err != nil {
		t.Fatalf("failed to decode link payload: %v", err)
	}
	if got, want := link.URL, "https://download.example.com/file.bin"; got != want {
		t.Fatalf("expected direct leaf URL %q, got %q", want, got)
	}
	if link.Download == nil || link.Download.Provider == "" || link.Download.Ticket == "" || link.Download.ExpiresAt <= time.Now().Unix() {
		t.Fatalf("expected signed download envelope, got %+v", link.Download)
	}
	if got, want := link.Size, int64(1); got != want {
		t.Fatalf("expected authoritative size %d, got %d", want, got)
	}
	if got, want := link.Header.Get("Authorization"), "Bearer token"; got != want {
		t.Fatalf("expected Authorization header %q, got %q", want, got)
	}
	if got, want := storage.lastLinkArgs.Type, "download"; got != want {
		t.Fatalf("expected link type %q, got %q", want, got)
	}
	if !storage.lastLinkArgs.ForceRefresh {
		t.Fatal("expected refresh query override to set ForceRefresh")
	}
	if got, want := storage.lastLinkArgs.IP, "203.0.113.9"; got != want {
		t.Fatalf("expected client IP %q, got %q", want, got)
	}
	if got, want := storage.lastLinkArgs.Header.Get("X-Test-Header"), "present"; got != want {
		t.Fatalf("expected forwarded request header %q, got %q", want, got)
	}
	if storage.lastLinkArgs.Redirect {
		t.Fatal("expected link resolver to avoid Redirect=true for /api/fs/link")
	}
	if got, want := storage.linkCalls, 1; got != want {
		t.Fatalf("expected exactly one leaf link call, got %d", got)
	}
	if got, want := storage.getCalls, 1; got != want {
		t.Fatalf("expected exactly one leaf object lookup, got %d", got)
	}
	if got, want := storage.getLastPath, "/file.bin"; got != want {
		t.Fatalf("expected leaf object lookup path %q, got %q", want, got)
	}
	if got, want := storage.linkLastFilePath, "/file.bin"; got != want {
		t.Fatalf("expected leaf link path %q, got %q", want, got)
	}
	if storage.lastLinkArgs.Header == nil {
		t.Fatal("expected forwarded request headers to be preserved")
	}
	if got, want := storage.lastLinkArgs.Header.Get("Content-Type"), "application/json"; got != want {
		t.Fatalf("expected forwarded Content-Type %q, got %q", want, got)
	}
	if storage.lastLinkArgs.Header.Get("Authorization") != "" {
		t.Fatal("expected only caller request headers to be forwarded into LinkArgs")
	}
	if string(resp.Data) == "null" {
		t.Fatal("expected success payload data to be non-null")
	}
	if !json.Valid(resp.Data) {
		t.Fatalf("expected valid JSON payload, got %s", string(resp.Data))
	}
	if link.URL == "" {
		t.Fatal("expected non-empty direct URL")
	}
	if got := storage.lastLinkArgs.Header.Get("X-Forwarded-For"); got != "" {
		t.Fatalf("expected no synthetic forwarded headers, got %q", got)
	}
	if got := storage.lastLinkArgs.Header.Get("X-Real-IP"); got != "" {
		t.Fatalf("expected no synthetic real-ip headers, got %q", got)
	}
	if storage.lastLinkArgs.Header.Values("X-Test-Header")[0] != "present" {
		t.Fatalf("expected preserved header values, got %v", storage.lastLinkArgs.Header.Values("X-Test-Header"))
	}
	if storage.lastLinkArgs.Type == "" {
		t.Fatal("expected type query to be preserved")
	}
	if storage.lastLinkArgs.IP == "" {
		t.Fatal("expected client IP to be preserved")
	}
	if storage.lastLinkArgs.Header == nil || len(storage.lastLinkArgs.Header) == 0 {
		t.Fatal("expected request headers to be preserved on the leaf Link call")
	}
}

func TestLinkHandler_ReturnsJSONErrorWhenLeafHasNoExternalURLAndNoDownProxyURL(t *testing.T) {
	storage := mustCreateLinkHandlerTestStorage(t, uniqueLinkHandlerMountPath(t), linkHandlerStubBehavior{
		files: []string{"/stream-only.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{}, nil
		},
	})

	recorder := callLinkHandler(t, linkHandlerRequest{
		path:       storage.MountPath + "/stream-only.bin",
		bodyJSON:   `{"action":"acquire","path":"` + storage.MountPath + `/stream-only.bin","refresh":true}`,
		remoteAddr: "198.51.100.44:9876",
		headers: http.Header{
			"Content-Type": []string{"application/json"},
		},
	})

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected HTTP 500, got %d with body %s", recorder.Code, recorder.Body.String())
	}

	resp := decodeLinkHandlerResp(t, recorder)
	if got, want := resp.Code, 500; got != want {
		t.Fatalf("expected response code %d, got %d with body %s", want, got, recorder.Body.String())
	}
	if string(resp.Data) != "null" {
		t.Fatalf("expected nil data payload, got %s", string(resp.Data))
	}
	if strings.Contains(recorder.Body.String(), "/p/") {
		t.Fatalf("expected error body without /p/ fallback, got %s", recorder.Body.String())
	}
	if resp.Message == "" {
		t.Fatal("expected non-empty error message")
	}
}

func TestLinkHandler_ReportOnlyAcceptsSignedGenericTicketWithoutReplacement(t *testing.T) {
	storage := mustCreateLinkHandlerTestStorage(t, uniqueLinkHandlerMountPath(t), linkHandlerStubBehavior{
		files: []string{"/file.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/file.bin"}, nil
		},
	})
	path := storage.MountPath + "/file.bin"
	acquire := callLinkHandler(t, linkHandlerRequest{
		path:     path,
		bodyJSON: `{"action":"acquire","path":"` + path + `"}`,
		headers:  http.Header{"Content-Type": []string{"application/json"}},
	})
	acquireResp := decodeLinkHandlerResp(t, acquire)
	if acquireResp.Code != http.StatusOK {
		t.Fatalf("expected acquire success, got %s", acquire.Body.String())
	}
	var link model.Link
	if err := json.Unmarshal(acquireResp.Data, &link); err != nil {
		t.Fatalf("failed to decode acquired link: %v", err)
	}
	if link.Download == nil {
		t.Fatal("expected acquired link ticket")
	}
	replacement := callLinkHandler(t, linkHandlerRequest{
		path:     path,
		bodyJSON: `{"action":"acquire","path":"` + path + `","feedback":{"ticket":"` + link.Download.Ticket + `","event_id":"generic-failure-1","outcome":"failure","status_code":500,"reason":"upstream failed"},"exclude":["` + link.Download.Ticket + `"]}`,
		headers:  http.Header{"Content-Type": []string{"application/json"}},
	})
	replacementResp := decodeLinkHandlerResp(t, replacement)
	if replacementResp.Code != http.StatusOK {
		t.Fatalf("expected replacement acquire success, got %s", replacement.Body.String())
	}
	var replacementLink model.Link
	if err := json.Unmarshal(replacementResp.Data, &replacementLink); err != nil {
		t.Fatalf("failed to decode replacement link: %v", err)
	}
	if replacementLink.Download == nil || !replacementLink.Download.ReportSuccess {
		t.Fatalf("expected generic recovery authorization to request success reporting, got %+v", replacementLink.Download)
	}

	report := callLinkHandler(t, linkHandlerRequest{
		path:     path,
		bodyJSON: `{"action":"report","path":"` + path + `","feedback":{"ticket":"` + replacementLink.Download.Ticket + `","event_id":"generic-report-1","outcome":"failure","status_code":500,"reason":"upstream failed"}}`,
		headers:  http.Header{"Content-Type": []string{"application/json"}},
	})
	reportResp := decodeLinkHandlerResp(t, report)
	if reportResp.Code != http.StatusOK {
		t.Fatalf("expected report success, got %s", report.Body.String())
	}
	var reportData struct {
		Applied bool `json:"applied"`
	}
	if err := json.Unmarshal(reportResp.Data, &reportData); err != nil {
		t.Fatalf("failed to decode report result: %v", err)
	}
	if !reportData.Applied {
		t.Fatal("expected generic report to be acknowledged")
	}
	if got, want := storage.linkCalls, 2; got != want {
		t.Fatalf("expected report-only operation to issue no replacement link, got %d link calls", got)
	}
}

func TestLinkHandler_RequiresExplicitAction(t *testing.T) {
	recorder := callLinkHandler(t, linkHandlerRequest{
		path:     "/missing/file.bin",
		bodyJSON: `{"path":"/missing/file.bin"}`,
		headers:  http.Header{"Content-Type": []string{"application/json"}},
	})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected missing action HTTP 400, got %d with body %s", recorder.Code, recorder.Body.String())
	}
	resp := decodeLinkHandlerResp(t, recorder)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected missing action to return code %d, got %d", http.StatusBadRequest, resp.Code)
	}
}

func TestLinkHandler_MissingPathReturnsBadRequest(t *testing.T) {
	recorder := callLinkHandler(t, linkHandlerRequest{
		bodyJSON: `{"action":"acquire"}`,
		headers:  http.Header{"Content-Type": []string{"application/json"}},
	})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected missing path HTTP 400, got %d with body %s", recorder.Code, recorder.Body.String())
	}
}

func TestLinkHandler_FailsClosedWhenDownloadSigningKeyIsUnavailable(t *testing.T) {
	storage := mustCreateLinkHandlerTestStorage(t, uniqueLinkHandlerMountPath(t), linkHandlerStubBehavior{
		files: []string{"/file.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/file.bin"}, nil
		},
	})
	item, err := op.GetSettingItemByKey(conf.Token)
	if err != nil {
		t.Fatalf("failed to read signing token: %v", err)
	}
	original := *item
	t.Cleanup(func() {
		copy := original
		if err := op.SaveSettingItem(&copy); err != nil {
			t.Errorf("failed to restore signing token: %v", err)
		}
	})
	empty := original
	empty.Value = ""
	if err := op.SaveSettingItem(&empty); err != nil {
		t.Fatalf("failed to clear signing token: %v", err)
	}

	path := storage.MountPath + "/file.bin"
	recorder := callLinkHandler(t, linkHandlerRequest{
		path:     path,
		bodyJSON: `{"action":"acquire","path":"` + path + `"}`,
		headers:  http.Header{"Content-Type": []string{"application/json"}},
	})
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected missing signing key HTTP 500, got %d with body %s", recorder.Code, recorder.Body.String())
	}
	if got := storage.linkCalls; got != 0 {
		t.Fatalf("expected missing signing key to stop before Link, got %d calls", got)
	}
}

func TestLinkHandler_UnavailablePoolReturnsHTTP503AndRetryAfter(t *testing.T) {
	mountPath := uniqueLinkHandlerMountPath(t)
	driver := mustCreateUnavailableLinkHandlerStorage(t, mountPath)
	path := mountPath + "/file.bin"
	recorder := callLinkHandler(t, linkHandlerRequest{
		path:     path,
		bodyJSON: `{"action":"acquire","path":"` + path + `"}`,
		headers:  http.Header{"Content-Type": []string{"application/json"}},
	})
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected unavailable HTTP 503, got %d with body %s", recorder.Code, recorder.Body.String())
	}
	if got, want := recorder.Header().Get("Retry-After"), "42"; got != want {
		t.Fatalf("expected Retry-After %q, got %q", want, got)
	}
	if got := driver.acquireCalls.Load(); got != 1 {
		t.Fatalf("expected one unavailable authorization attempt, got %d", got)
	}
}

type linkHandlerRequest struct {
	path       string
	bodyJSON   string
	rawQuery   string
	remoteAddr string
	headers    http.Header
}

type linkHandlerResp struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

func callLinkHandler(t *testing.T, req linkHandlerRequest) *httptest.ResponseRecorder {
	t.Helper()

	request, err := http.NewRequest(http.MethodPost, "/api/fs/link?"+req.rawQuery, bytes.NewBufferString(req.bodyJSON))
	if err != nil {
		t.Fatalf("failed to build request: %v", err)
	}
	request.RemoteAddr = req.remoteAddr
	request.Header = req.headers.Clone()
	request = request.WithContext(context.WithValue(request.Context(), conf.ApiUrlKey, "https://example.test"))

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = request

	Link(ctx)
	return recorder
}

func decodeLinkHandlerResp(t *testing.T, recorder *httptest.ResponseRecorder) linkHandlerResp {
	t.Helper()

	var resp linkHandlerResp
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response %s: %v", recorder.Body.String(), err)
	}
	return resp
}

const linkHandlerStubDriverName = "TestLinkHandlerActualDownloadStub"

var registerLinkHandlerStubDriverOnce sync.Once

var linkHandlerFixtures = struct {
	sync.Mutex
	byMountPath map[string]linkHandlerStubBehavior
}{
	byMountPath: map[string]linkHandlerStubBehavior{},
}

type linkHandlerStubBehavior struct {
	files   []string
	link    func(model.Obj, model.LinkArgs) (*model.Link, error)
	linkErr error
}

func uniqueLinkHandlerMountPath(t *testing.T) string {
	t.Helper()

	name := strings.ToLower(t.Name())
	replacer := strings.NewReplacer("/", "-", "_", "-", " ", "-")
	return "/test-link-handler/" + replacer.Replace(name)
}

func mustCreateLinkHandlerTestStorage(t *testing.T, mountPath string, behavior linkHandlerStubBehavior) *linkHandlerStubDriver {
	t.Helper()

	registerLinkHandlerStubDriverOnce.Do(func() {
		op.RegisterDriver(func() driverpkg.Driver {
			return &linkHandlerStubDriver{}
		})
	})

	linkHandlerFixtures.Lock()
	linkHandlerFixtures.byMountPath[mountPath] = behavior
	linkHandlerFixtures.Unlock()
	t.Cleanup(func() {
		linkHandlerFixtures.Lock()
		delete(linkHandlerFixtures.byMountPath, mountPath)
		linkHandlerFixtures.Unlock()
	})

	drv := mustCreateLinkHandlerStorage(t, model.Storage{
		MountPath: mountPath,
		Driver:    linkHandlerStubDriverName,
		Addition:  mustMarshalLinkHandlerAddition(t, driverpkg.RootPath{RootFolderPath: "/"}),
	})

	stub, ok := drv.(*linkHandlerStubDriver)
	if !ok {
		t.Fatalf("expected %q to be a *linkHandlerStubDriver, got %T", mountPath, drv)
	}
	return stub
}

func mustCreateLinkHandlerStorage(t *testing.T, storage model.Storage) driverpkg.Driver {
	t.Helper()

	id, err := op.CreateStorage(context.Background(), storage)
	if err != nil {
		t.Fatalf("failed to create storage %q: %v", storage.MountPath, err)
	}
	t.Cleanup(func() {
		if err := op.DeleteStorageById(context.Background(), id); err != nil {
			t.Fatalf("failed to delete storage %q: %v", storage.MountPath, err)
		}
	})
	drv, err := op.GetStorageByMountPath(storage.MountPath)
	if err != nil {
		t.Fatalf("failed to load storage %q: %v", storage.MountPath, err)
	}
	return drv
}

func mustMarshalLinkHandlerAddition(t *testing.T, value any) string {
	t.Helper()

	bs, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("failed to marshal test addition: %v", err)
	}
	return string(bs)
}

type linkHandlerStubDriver struct {
	model.Storage

	addition driverpkg.RootPath
	files    map[string]*model.Object
	link     func(model.Obj, model.LinkArgs) (*model.Link, error)
	linkErr  error

	getCalls         int
	linkCalls        int
	getLastPath      string
	linkLastFilePath string
	lastLinkArgs     model.LinkArgs
}

func (d *linkHandlerStubDriver) Config() driverpkg.Config {
	return driverpkg.Config{Name: linkHandlerStubDriverName, DefaultRoot: "/", OnlyLinkMFile: true}
}

func (d *linkHandlerStubDriver) GetAddition() driverpkg.Additional {
	return &d.addition
}

func (d *linkHandlerStubDriver) Init(ctx context.Context) error {
	linkHandlerFixtures.Lock()
	fixture, ok := linkHandlerFixtures.byMountPath[d.MountPath]
	linkHandlerFixtures.Unlock()
	if !ok {
		return errs.NewErr(errs.StorageNotFound, "missing stub fixture for %s", d.MountPath)
	}

	d.files = make(map[string]*model.Object, len(fixture.files))
	for _, filePath := range fixture.files {
		cleanPath := utils.FixAndCleanPath(filePath)
		d.files[cleanPath] = &model.Object{
			Path:     cleanPath,
			Name:     stdpath.Base(cleanPath),
			Size:     1,
			Modified: time.Unix(1, 0),
		}
	}
	d.link = fixture.link
	d.linkErr = fixture.linkErr
	d.getCalls = 0
	d.linkCalls = 0
	d.getLastPath = ""
	d.linkLastFilePath = ""
	d.lastLinkArgs = model.LinkArgs{}
	return nil
}

func (d *linkHandlerStubDriver) Drop(ctx context.Context) error {
	return nil
}

func (d *linkHandlerStubDriver) List(ctx context.Context, dir model.Obj, args model.ListArgs) ([]model.Obj, error) {
	if !dir.IsDir() {
		return nil, errs.NotFolder
	}
	if dir.GetPath() != "/" {
		return nil, errs.ObjectNotFound
	}

	paths := make([]string, 0, len(d.files))
	for filePath := range d.files {
		if stdpath.Dir(filePath) == "/" {
			paths = append(paths, filePath)
		}
	}
	sort.Strings(paths)

	objs := make([]model.Obj, 0, len(paths))
	for _, filePath := range paths {
		objs = append(objs, cloneLinkHandlerObject(d.files[filePath]))
	}
	return objs, nil
}

func (d *linkHandlerStubDriver) Get(ctx context.Context, path string) (model.Obj, error) {
	d.getCalls++
	path = utils.FixAndCleanPath(path)
	d.getLastPath = path
	if path == "/" {
		return &model.Object{Path: "/", Name: "Root", Modified: d.Modified, IsFolder: true}, nil
	}
	obj, ok := d.files[path]
	if !ok {
		return nil, errs.ObjectNotFound
	}
	return cloneLinkHandlerObject(obj), nil
}

func (d *linkHandlerStubDriver) Link(ctx context.Context, file model.Obj, args model.LinkArgs) (*model.Link, error) {
	d.linkCalls++
	d.lastLinkArgs = args
	if file != nil {
		d.linkLastFilePath = file.GetPath()
	}
	if d.linkErr != nil {
		return nil, d.linkErr
	}
	if d.link == nil {
		return &model.Link{}, nil
	}
	return d.link(file, args)
}

func cloneLinkHandlerObject(obj *model.Object) *model.Object {
	clone := *obj
	return &clone
}

var _ driverpkg.Driver = (*linkHandlerStubDriver)(nil)
var _ driverpkg.Getter = (*linkHandlerStubDriver)(nil)

const unavailableLinkHandlerStubDriverName = "TestLinkHandlerUnavailableAuthorizer"

var registerUnavailableLinkHandlerStubOnce sync.Once

func mustCreateUnavailableLinkHandlerStorage(t *testing.T, mountPath string) *unavailableLinkHandlerDriver {
	t.Helper()
	registerUnavailableLinkHandlerStubOnce.Do(func() {
		op.RegisterDriver(func() driverpkg.Driver { return &unavailableLinkHandlerDriver{} })
	})
	linkHandlerFixtures.Lock()
	linkHandlerFixtures.byMountPath[mountPath] = linkHandlerStubBehavior{files: []string{"/file.bin"}}
	linkHandlerFixtures.Unlock()
	t.Cleanup(func() {
		linkHandlerFixtures.Lock()
		delete(linkHandlerFixtures.byMountPath, mountPath)
		linkHandlerFixtures.Unlock()
	})
	drv := mustCreateLinkHandlerStorage(t, model.Storage{
		MountPath: mountPath,
		Driver:    unavailableLinkHandlerStubDriverName,
		Addition:  mustMarshalLinkHandlerAddition(t, driverpkg.RootPath{RootFolderPath: "/"}),
	})
	result, ok := drv.(*unavailableLinkHandlerDriver)
	if !ok {
		t.Fatalf("expected unavailable authorizer driver, got %T", drv)
	}
	return result
}

type unavailableLinkHandlerDriver struct {
	linkHandlerStubDriver
	acquireCalls atomic.Int32
}

func (d *unavailableLinkHandlerDriver) Config() driverpkg.Config {
	return driverpkg.Config{Name: unavailableLinkHandlerStubDriverName, DefaultRoot: "/"}
}

func (d *unavailableLinkHandlerDriver) AcquireDownloadAuthorization(context.Context, driverpkg.DownloadAuthorizationRequest) (driverpkg.DownloadAuthorizationResult, error) {
	d.acquireCalls.Add(1)
	return driverpkg.DownloadAuthorizationResult{}, &driverpkg.DownloadAuthorizationUnavailableError{
		Reason:     "account pool unavailable",
		RetryAfter: 42 * time.Second,
	}
}

func (d *unavailableLinkHandlerDriver) ReportDownloadAuthorization(context.Context, driverpkg.DownloadAuthorizationReport) (driverpkg.DownloadAuthorizationReportResult, error) {
	return driverpkg.DownloadAuthorizationReportResult{Applied: true}, nil
}

var _ driverpkg.DownloadAuthorizer = (*unavailableLinkHandlerDriver)(nil)
