package handles

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	stdpath "path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/OpenListTeam/OpenList/v4/drivers/alias"
	_ "github.com/OpenListTeam/OpenList/v4/internal/archive"
	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	driverpkg "github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/errs"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
	"github.com/OpenListTeam/OpenList/v4/internal/sign"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
	"github.com/OpenListTeam/OpenList/v4/server/common"
	"github.com/OpenListTeam/OpenList/v4/server/middlewares"
	"github.com/gin-gonic/gin"
)

const downTestFilePath = "/file.zzzroute"

func TestDownHandler_ProxyURLOwnerRedirectsToOwnerNamespaceURL(t *testing.T) {
	leafMount := uniqueDownMountPath(t, "leaf")
	mustCreateDownStubStorage(t, leafMount, downStubBehavior{
		files: []string{downTestFilePath},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{MFile: strings.NewReader("proxy-leaf-body")}, nil
		},
	}, model.Proxy{})

	nativeOwnerMount := uniqueDownMountPath(t, "native-owner")
	mustCreateAliasStorage(t, nativeOwnerMount, leafMount, model.Proxy{WebProxy: true})

	proxyOwnerMount := uniqueDownMountPath(t, "proxy-owner")
	mustCreateAliasStorage(t, proxyOwnerMount, nativeOwnerMount, model.Proxy{DownProxyURL: "https://proxy.example.com"})

	outerMount := uniqueDownMountPath(t, "outer")
	mustCreateAliasStorage(t, outerMount, proxyOwnerMount, model.Proxy{})

	resp := callDownHandler(t, outerMount+downTestFilePath, "")

	if got, want := resp.Code, http.StatusFound; got != want {
		t.Fatalf("expected HTTP %d, got %d with body %s", want, got, resp.Body.String())
	}
	expected := common.GenerateDownProxyURL(&model.Storage{Proxy: model.Proxy{DownProxyURL: "https://proxy.example.com"}}, proxyOwnerMount+downTestFilePath)
	if got := resp.Header().Get("Location"); got != expected {
		t.Fatalf("expected redirect %q, got %q", expected, got)
	}
}

func TestDownHandler_NativeProxyOwnerRedirectsToCanonicalOwnerPPath(t *testing.T) {
	leafMount := uniqueDownMountPath(t, "leaf")
	mustCreateNonProxyDownStubStorage(t, leafMount, downStubBehavior{
		files: []string{downTestFilePath},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/native.bin"}, nil
		},
	}, model.Proxy{})

	nativeOwnerMount := uniqueDownMountPath(t, "native-owner")
	mustCreateAliasStorage(t, nativeOwnerMount, leafMount, model.Proxy{WebProxy: true})

	outerMount := uniqueDownMountPath(t, "outer")
	mustCreateAliasStorage(t, outerMount, nativeOwnerMount, model.Proxy{})

	resp := callDownHandler(t, outerMount+downTestFilePath, "")

	if got, want := resp.Code, http.StatusFound; got != want {
		t.Fatalf("expected HTTP %d, got %d with body %s", want, got, resp.Body.String())
	}
	expected := canonicalTestProxyURL("https://example.test", nativeOwnerMount+downTestFilePath)
	if got := resp.Header().Get("Location"); got != expected {
		t.Fatalf("expected redirect %q, got %q", expected, got)
	}
}

func TestDownHandler_NativeProxyCanonicalRedirectIncludesSignWhenNextHopRequiresIt(t *testing.T) {
	leafMount := uniqueDownMountPath(t, "leaf")
	mustCreateNonProxyDownStubStorage(t, leafMount, downStubBehavior{
		files: []string{downTestFilePath},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/native.bin"}, nil
		},
	}, model.Proxy{})

	nativeOwnerMount := uniqueDownMountPath(t, "native-owner")
	mustCreateLinkHandlerStorage(t, model.Storage{
		MountPath:  nativeOwnerMount,
		Driver:     "Alias",
		Addition:   mustMarshalLinkHandlerAddition(t, alias.Addition{Paths: leafMount, ProtectSameName: true}),
		EnableSign: true,
		Proxy:      model.Proxy{WebProxy: true},
	})

	outerMount := uniqueDownMountPath(t, "outer")
	mustCreateAliasStorage(t, outerMount, nativeOwnerMount, model.Proxy{})

	resp := callDownHandler(t, outerMount+downTestFilePath, "")

	if got, want := resp.Code, http.StatusFound; got != want {
		t.Fatalf("expected HTTP %d, got %d with body %s", want, got, resp.Body.String())
	}
	expected := canonicalSignedTestProxyURL("https://example.test", nativeOwnerMount+downTestFilePath)
	if got := resp.Header().Get("Location"); got != expected {
		t.Fatalf("expected redirect %q, got %q", expected, got)
	}
}

func TestDownHandler_NativeProxyBalanceOwnerUsesNextHopSignRequirement(t *testing.T) {
	balanceMount := uniqueDownMountPath(t, "balance-owner-current-pin-sign")
	mustCreateNonProxyDownStubStorageWithSign(t, balanceMount, downStubBehavior{
		files: []string{downTestFilePath},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/base-signed-native.bin"}, nil
		},
	}, true, model.Proxy{WebProxy: true})
	mustCreateNonProxyDownStubStorage(t, balanceMount+".balance", downStubBehavior{
		files: []string{downTestFilePath},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/balance-unsigned-native.bin"}, nil
		},
	}, model.Proxy{WebProxy: true})

	resp := callDownHandler(t, balanceMount+downTestFilePath, "")

	if got, want := resp.Code, http.StatusFound; got != want {
		t.Fatalf("expected HTTP %d, got %d with body %s", want, got, resp.Body.String())
	}
	expected := canonicalSignedTestProxyURL("https://example.test", balanceMount+downTestFilePath)
	if got := resp.Header().Get("Location"); got != expected {
		t.Fatalf("expected redirect %q using next-hop sign requirement, got %q", expected, got)
	}
}

func TestDownHandler_ProxyURLOwnerRejectsMalformedExternalProxyURL(t *testing.T) {
	leafMount := uniqueDownMountPath(t, "leaf")
	mustCreateDownStubStorage(t, leafMount, downStubBehavior{
		files: []string{downTestFilePath},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{MFile: strings.NewReader("proxy-leaf-body")}, nil
		},
	}, model.Proxy{})

	proxyOwnerMount := uniqueDownMountPath(t, "proxy-owner-invalid")
	mustCreateAliasStorage(t, proxyOwnerMount, leafMount, model.Proxy{DownProxyURL: "https://"})

	resp := callDownHandler(t, proxyOwnerMount+downTestFilePath, "")

	if got, want := resp.Code, http.StatusInternalServerError; got != want {
		t.Fatalf("expected HTTP %d for malformed external proxy URL, got %d with body %s", want, got, resp.Body.String())
	}
	if got := resp.Header().Get("Location"); got != "" {
		t.Fatalf("expected no redirect location for malformed external proxy URL, got %q", got)
	}
	if got := resp.Body.String(); !strings.Contains(got, "https://") {
		t.Fatalf("expected error body to mention malformed proxy base, got %q", got)
	}
}

func TestCanonicalOwnerProxyURL_UsesPolicyOwnerNearestMetaForPasswordSign(t *testing.T) {
	leafMount := uniqueDownMountPath(t, "leaf")
	mustCreateNonProxyDownStubStorage(t, leafMount, downStubBehavior{
		files: []string{downTestFilePath},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/native.bin"}, nil
		},
	}, model.Proxy{})

	nativeOwnerMount := uniqueDownMountPath(t, "native-owner-password-sign")
	mustCreateAliasStorage(t, nativeOwnerMount, leafMount, model.Proxy{WebProxy: true})
	mustCreateDownloadMeta(t, model.Meta{
		Path:     nativeOwnerMount,
		Password: "owner-secret",
		PSub:     true,
	})

	outerMount := uniqueDownMountPath(t, "outer")
	mustCreateAliasStorage(t, outerMount, nativeOwnerMount, model.Proxy{})

	route, err := op.ResolveWebDownloadRoute(context.Background(), outerMount+downTestFilePath)
	if err != nil {
		t.Fatalf("expected route resolution success, got %v", err)
	}
	ctx := newCanonicalProxyURLTestContext(t, nil)

	redirectURL, err := canonicalOwnerProxyURL(ctx, route, nil)
	if err != nil {
		t.Fatalf("expected canonical redirect, got %v", err)
	}
	expected := canonicalSignedTestProxyURL("https://example.test", nativeOwnerMount+downTestFilePath)
	if got := redirectURL; got != expected {
		t.Fatalf("expected owner-meta signed redirect %q, got %q", expected, got)
	}
}

func TestCanonicalOwnerProxyURL_UsesNextHopBalanceOwnerSignRequirement(t *testing.T) {
	balanceMount := uniqueDownMountPath(t, "balance-owner-sign")
	registerDownDriver(t, downNoProxyDriverName, nonProxyDownStubConfig())
	downFixtures.Lock()
	downFixtures.byMountPath[balanceMount] = downStubBehavior{
		files: []string{downTestFilePath},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/balance-one.bin"}, nil
		},
	}
	downFixtures.byMountPath[balanceMount+".balance"] = downStubBehavior{
		files: []string{downTestFilePath},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/balance-two.bin"}, nil
		},
	}
	downFixtures.Unlock()
	t.Cleanup(func() {
		downFixtures.Lock()
		delete(downFixtures.byMountPath, balanceMount)
		delete(downFixtures.byMountPath, balanceMount+".balance")
		downFixtures.Unlock()
	})

	mustCreateLinkHandlerStorage(t, model.Storage{
		MountPath:  balanceMount,
		Driver:     downNoProxyDriverName,
		Addition:   mustMarshalLinkHandlerAddition(t, driverpkg.RootPath{RootFolderPath: "/"}),
		EnableSign: true,
		Proxy:      model.Proxy{WebProxy: true},
	})
	mustCreateLinkHandlerStorage(t, model.Storage{
		MountPath: balanceMount + ".balance",
		Driver:    downNoProxyDriverName,
		Addition:  mustMarshalLinkHandlerAddition(t, driverpkg.RootPath{RootFolderPath: "/"}),
		Proxy:     model.Proxy{WebProxy: true},
	})

	requestCtx := op.EnsureLinkAPIBalanceStateForRequest(context.Background())
	route, err := op.ResolveWebDownloadRoute(requestCtx, balanceMount+downTestFilePath)
	if err != nil {
		t.Fatalf("expected route resolution success, got %v", err)
	}
	if got, want := route.PolicyOwnerRawPath, balanceMount+downTestFilePath; got != want {
		t.Fatalf("expected virtual owner path %q, got %q", want, got)
	}
	if got, want := route.PolicyOwnerStorage.GetStorage().MountPath, balanceMount+".balance"; got != want {
		t.Fatalf("expected current request owner storage %q, got %q", want, got)
	}
	ctx := newCanonicalProxyURLTestContext(t, nil)
	ctx.Request = ctx.Request.WithContext(context.WithValue(requestCtx, conf.ApiUrlKey, "https://example.test"))

	redirectURL, err := canonicalOwnerProxyURL(ctx, route, nil)
	if err != nil {
		t.Fatalf("expected canonical redirect, got %v", err)
	}
	expected := canonicalSignedTestProxyURL("https://example.test", balanceMount+downTestFilePath)
	if got := redirectURL; got != expected {
		t.Fatalf("expected canonical redirect %q using next-hop sign requirement, got %q", expected, got)
	}
}

func TestProxyHandler_NonOwnerRequestWithoutCurrentPathSignIsRejectedBeforeCanonicalRedirect(t *testing.T) {
	leafMount := uniqueDownMountPath(t, "leaf")
	mustCreateNonProxyDownStubStorage(t, leafMount, downStubBehavior{
		files: []string{downTestFilePath},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/native.bin"}, nil
		},
	}, model.Proxy{})

	ownerMount := uniqueDownMountPath(t, "native-owner")
	mustCreateAliasStorage(t, ownerMount, leafMount, model.Proxy{WebProxy: true})

	outerMount := uniqueDownMountPath(t, "outer-owner-meta")
	mustCreateAliasStorage(t, outerMount, ownerMount, model.Proxy{})
	mustCreateDownloadMeta(t, model.Meta{
		Path:     outerMount,
		Password: "outer-secret",
		PSub:     true,
	})

	resp := callProxyHandlerThroughMiddleware(t, outerMount+downTestFilePath, "d=1")

	if got, want := resp.Code, http.StatusUnauthorized; got != want {
		t.Fatalf("expected HTTP %d, got %d with body %s", want, got, resp.Body.String())
	}
	if got := resp.Header().Get("Location"); got != "" {
		t.Fatalf("expected no redirect before current-hop authorization, got %q", got)
	}
}

func TestProxyHandler_NonOwnerRequestWithCurrentPathSignRedirectsWithOwnerPathSignWhenRequired(t *testing.T) {
	leafMount := uniqueDownMountPath(t, "leaf")
	mustCreateNonProxyDownStubStorage(t, leafMount, downStubBehavior{
		files: []string{downTestFilePath},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/native.bin"}, nil
		},
	}, model.Proxy{})

	ownerMount := uniqueDownMountPath(t, "native-owner")
	mustCreateLinkHandlerStorage(t, model.Storage{
		MountPath:  ownerMount,
		Driver:     "Alias",
		Addition:   mustMarshalLinkHandlerAddition(t, alias.Addition{Paths: leafMount, ProtectSameName: true}),
		EnableSign: true,
		Proxy:      model.Proxy{WebProxy: true},
	})

	outerMount := uniqueDownMountPath(t, "outer-owner-meta")
	mustCreateAliasStorage(t, outerMount, ownerMount, model.Proxy{})
	mustCreateDownloadMeta(t, model.Meta{
		Path:     outerMount,
		Password: "outer-secret",
		PSub:     true,
	})

	query := url.Values{"d": {"1"}, "sign": {sign.Sign(outerMount + downTestFilePath)}}
	resp := callProxyHandlerThroughMiddleware(t, outerMount+downTestFilePath, query.Encode())

	if got, want := resp.Code, http.StatusFound; got != want {
		t.Fatalf("expected HTTP %d, got %d with body %s", want, got, resp.Body.String())
	}
	expected := canonicalSignedTestProxyURLWithQuery("https://example.test", ownerMount+downTestFilePath, url.Values{"d": {"1"}})
	if got := resp.Header().Get("Location"); got != expected {
		t.Fatalf("expected canonical owner redirect %q, got %q", expected, got)
	}
}

func TestProxyHandler_BalanceOwnerUsesOneSelectionForSignDecisionAndProxyExecution(t *testing.T) {
	balanceMount := uniqueDownMountPath(t, "balance-owner-single-selection")
	mustCreateNonProxyDownStubStorageWithSign(t, balanceMount, downStubBehavior{
		files: []string{downTestFilePath},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{MFile: strings.NewReader("base-signed-member-body")}, nil
		},
	}, true, model.Proxy{WebProxy: true, ProxyRange: true})
	mustCreateNonProxyDownStubStorage(t, balanceMount+".balance", downStubBehavior{
		files: []string{downTestFilePath},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{MFile: strings.NewReader("balance-unsigned-member-body")}, nil
		},
	}, model.Proxy{WebProxy: true, ProxyRange: true})

	resp := callProxyHandlerThroughMiddleware(t, balanceMount+downTestFilePath, "d=1")

	if got, want := resp.Code, http.StatusOK; got != want {
		t.Fatalf("expected HTTP %d, got %d with body %s", want, got, resp.Body.String())
	}
	if got, want := resp.Body.String(), "balance-unsigned-member-body"; got != want {
		t.Fatalf("expected proxy body %q from the same previewed owner member, got %q", want, got)
	}
}

func TestDownThenProxy_BalanceOwnerCanonicalURLRemainsUsableWhenNextRequestRotates(t *testing.T) {
	balanceMount := uniqueDownMountPath(t, "balance-owner-next-hop")
	mustCreateNonProxyDownStubStorageWithSign(t, balanceMount, downStubBehavior{
		files: []string{downTestFilePath},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{MFile: strings.NewReader("base-signed-next-hop-body")}, nil
		},
	}, true, model.Proxy{WebProxy: true})
	mustCreateNonProxyDownStubStorage(t, balanceMount+".balance", downStubBehavior{
		files: []string{downTestFilePath},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{MFile: strings.NewReader("balance-unsigned-next-hop-body")}, nil
		},
	}, model.Proxy{WebProxy: true})

	downResp := callDownHandler(t, balanceMount+downTestFilePath, "")
	if got, want := downResp.Code, http.StatusFound; got != want {
		t.Fatalf("expected down redirect HTTP %d, got %d with body %s", want, got, downResp.Body.String())
	}
	if got, want := downResp.Header().Get("Location"), canonicalSignedTestProxyURL("https://example.test", balanceMount+downTestFilePath); got != want {
		t.Fatalf("expected canonical redirect %q that remains valid for the next request, got %q", want, got)
	}
	proxyResp := callDownloadLocationThroughMiddleware(t, downResp.Header().Get("Location"))

	if got, want := proxyResp.Code, http.StatusOK; got != want {
		t.Fatalf("expected next-hop proxy HTTP %d after fresh-request rotation, got %d with body %s", want, got, proxyResp.Body.String())
	}
	if got, want := proxyResp.Body.String(), "base-signed-next-hop-body"; got != want {
		t.Fatalf("expected next-hop proxy body %q from the rotated signed member, got %q", want, got)
	}
}

func TestDownHandler_BalanceCurrentHopAuthorizationReusesRequestLocalPinDespiteConcurrentAdvance(t *testing.T) {
	balanceMount := uniqueDownMountPath(t, "balance-current-hop-down-pin")
	mustCreateNonProxyDownStubStorageWithSign(t, balanceMount, downStubBehavior{
		files: []string{downTestFilePath},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/signed-member.bin"}, nil
		},
	}, true, model.Proxy{})
	mustCreateNonProxyDownStubStorage(t, balanceMount+".balance", downStubBehavior{
		files: []string{downTestFilePath},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/unsigned-member.bin"}, nil
		},
	}, model.Proxy{})

	resp := callDownHandlerThroughMiddlewareWithInterposer(t, balanceMount+downTestFilePath, "", simulateConcurrentBalanceAdvance(t))

	if got, want := resp.Code, http.StatusFound; got != want {
		t.Fatalf("expected HTTP %d, got %d with body %s", want, got, resp.Body.String())
	}
	if got, want := resp.Header().Get("Location"), "https://download.example.com/unsigned-member.bin"; got != want {
		t.Fatalf("expected redirect %q from request-local pinned member, got %q", want, got)
	}
}

func TestProxyHandler_BalanceCurrentHopAuthorizationReusesRequestLocalPinDespiteConcurrentAdvance(t *testing.T) {
	balanceMount := uniqueDownMountPath(t, "balance-current-hop-proxy-pin")
	mustCreateNonProxyDownStubStorageWithSign(t, balanceMount, downStubBehavior{
		files: []string{downTestFilePath},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{MFile: strings.NewReader("signed-member-body")}, nil
		},
	}, true, model.Proxy{WebProxy: true})
	mustCreateNonProxyDownStubStorage(t, balanceMount+".balance", downStubBehavior{
		files: []string{downTestFilePath},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{MFile: strings.NewReader("unsigned-member-body")}, nil
		},
	}, model.Proxy{WebProxy: true})

	resp := callProxyHandlerThroughMiddlewareWithInterposer(t, balanceMount+downTestFilePath, "d=1", simulateConcurrentBalanceAdvance(t))

	if got, want := resp.Code, http.StatusOK; got != want {
		t.Fatalf("expected HTTP %d, got %d with body %s", want, got, resp.Body.String())
	}
	if got, want := resp.Body.String(), "unsigned-member-body"; got != want {
		t.Fatalf("expected proxy body %q from request-local pinned member, got %q", want, got)
	}
}

func TestArchiveDown_BalanceCurrentHopAuthorizationDoesNotAdvanceGlobalSelection(t *testing.T) {
	balanceMount := uniqueDownMountPath(t, "archive-balance-down")
	mustCreateArchiveDownStubStorageWithSign(t, balanceMount, downStubBehavior{
		files: []string{downTestFilePath},
		archiveGet: func(args model.ArchiveInnerArgs) (model.Obj, error) {
			return &model.Object{Path: args.InnerPath, Name: stdpath.Base(args.InnerPath), Size: 1}, nil
		},
		archiveExtract: func(model.Obj, model.ArchiveInnerArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/archive-signed-member.bin"}, nil
		},
	}, true, model.Proxy{WebProxy: true})
	mustCreateArchiveDownStubStorage(t, balanceMount+".balance", downStubBehavior{
		files: []string{downTestFilePath},
		archiveGet: func(args model.ArchiveInnerArgs) (model.Obj, error) {
			return &model.Object{Path: args.InnerPath, Name: stdpath.Base(args.InnerPath), Size: 1}, nil
		},
		archiveExtract: func(model.Obj, model.ArchiveInnerArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/archive-unsigned-member.bin"}, nil
		},
	}, model.Proxy{})

	resp := callArchiveDownHandlerThroughMiddleware(t, balanceMount+downTestFilePath, url.Values{"inner": {"/nested/file.bin"}}.Encode())

	if got, want := resp.Code, http.StatusFound; got != want {
		t.Fatalf("expected HTTP %d, got %d with body %s", want, got, resp.Body.String())
	}
	if got, want := resp.Header().Get("Location"), "https://download.example.com/archive-unsigned-member.bin"; got != want {
		t.Fatalf("expected redirect %q from the first archive selection, got %q", want, got)
	}
}

func TestArchiveProxy_BalanceCurrentHopAuthorizationDoesNotAdvanceGlobalSelection(t *testing.T) {
	balanceMount := uniqueDownMountPath(t, "archive-balance-proxy")
	mustCreateArchiveDownStubStorageWithSign(t, balanceMount, downStubBehavior{
		files: []string{downTestFilePath},
		archiveGet: func(args model.ArchiveInnerArgs) (model.Obj, error) {
			return &model.Object{Path: args.InnerPath, Name: stdpath.Base(args.InnerPath), Size: 1}, nil
		},
		archiveExtract: func(model.Obj, model.ArchiveInnerArgs) (*model.Link, error) {
			return &model.Link{MFile: strings.NewReader("archive-signed-member-body")}, nil
		},
	}, true, model.Proxy{WebProxy: true})
	mustCreateArchiveDownStubStorage(t, balanceMount+".balance", downStubBehavior{
		files: []string{downTestFilePath},
		archiveGet: func(args model.ArchiveInnerArgs) (model.Obj, error) {
			return &model.Object{Path: args.InnerPath, Name: stdpath.Base(args.InnerPath), Size: 1}, nil
		},
		archiveExtract: func(model.Obj, model.ArchiveInnerArgs) (*model.Link, error) {
			return &model.Link{MFile: strings.NewReader("archive-unsigned-member-body")}, nil
		},
	}, model.Proxy{})

	resp := callArchiveProxyHandlerThroughMiddleware(t, balanceMount+downTestFilePath, url.Values{"inner": {"/nested/file.bin"}}.Encode())

	if got, want := resp.Code, http.StatusForbidden; got != want {
		t.Fatalf("expected HTTP %d, got %d with body %s", want, got, resp.Body.String())
	}
	if got := resp.Header().Get("Location"); got != "" {
		t.Fatalf("expected no redirect for non-proxy archive member, got %q", got)
	}
}

func TestArchiveDown_BalanceCurrentHopAuthorizationReusesRequestLocalPinDespiteConcurrentAdvance(t *testing.T) {
	balanceMount := uniqueDownMountPath(t, "archive-balance-down-interposed")
	mustCreateArchiveDownStubStorageWithSign(t, balanceMount, downStubBehavior{
		files: []string{downTestFilePath},
		archiveGet: func(args model.ArchiveInnerArgs) (model.Obj, error) {
			return &model.Object{Path: args.InnerPath, Name: stdpath.Base(args.InnerPath), Size: 1}, nil
		},
		archiveExtract: func(model.Obj, model.ArchiveInnerArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/archive-signed-member-interposed.bin"}, nil
		},
	}, true, model.Proxy{WebProxy: true})
	mustCreateArchiveDownStubStorage(t, balanceMount+".balance", downStubBehavior{
		files: []string{downTestFilePath},
		archiveGet: func(args model.ArchiveInnerArgs) (model.Obj, error) {
			return &model.Object{Path: args.InnerPath, Name: stdpath.Base(args.InnerPath), Size: 1}, nil
		},
		archiveExtract: func(model.Obj, model.ArchiveInnerArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/archive-unsigned-member-interposed.bin"}, nil
		},
	}, model.Proxy{})

	resp := callArchiveDownHandlerThroughMiddlewareWithInterposer(t, balanceMount+downTestFilePath, url.Values{"inner": {"/nested/file.bin"}}.Encode(), simulateConcurrentBalanceAdvance(t))

	if got, want := resp.Code, http.StatusFound; got != want {
		t.Fatalf("expected HTTP %d, got %d with body %s", want, got, resp.Body.String())
	}
	if got, want := resp.Header().Get("Location"), "https://download.example.com/archive-unsigned-member-interposed.bin"; got != want {
		t.Fatalf("expected redirect %q from request-local pinned archive member, got %q", want, got)
	}
}

func TestArchiveProxy_BalanceCurrentHopAuthorizationReusesRequestLocalPinDespiteConcurrentAdvance(t *testing.T) {
	balanceMount := uniqueDownMountPath(t, "archive-balance-proxy-interposed")
	mustCreateArchiveDownStubStorageWithSign(t, balanceMount, downStubBehavior{
		files: []string{downTestFilePath},
		archiveGet: func(args model.ArchiveInnerArgs) (model.Obj, error) {
			return &model.Object{Path: args.InnerPath, Name: stdpath.Base(args.InnerPath), Size: 1}, nil
		},
		archiveExtract: func(model.Obj, model.ArchiveInnerArgs) (*model.Link, error) {
			return &model.Link{MFile: strings.NewReader("archive-signed-member-interposed-body")}, nil
		},
	}, true, model.Proxy{WebProxy: true})
	mustCreateArchiveDownStubStorage(t, balanceMount+".balance", downStubBehavior{
		files: []string{downTestFilePath},
		archiveGet: func(args model.ArchiveInnerArgs) (model.Obj, error) {
			return &model.Object{Path: args.InnerPath, Name: stdpath.Base(args.InnerPath), Size: 1}, nil
		},
		archiveExtract: func(model.Obj, model.ArchiveInnerArgs) (*model.Link, error) {
			return &model.Link{MFile: strings.NewReader("archive-unsigned-member-interposed-body")}, nil
		},
	}, model.Proxy{})

	resp := callArchiveProxyHandlerThroughMiddlewareWithInterposer(t, balanceMount+downTestFilePath, url.Values{"inner": {"/nested/file.bin"}}.Encode(), simulateConcurrentBalanceAdvance(t))

	if got, want := resp.Code, http.StatusForbidden; got != want {
		t.Fatalf("expected HTTP %d, got %d with body %s", want, got, resp.Body.String())
	}
	if got := resp.Header().Get("Location"); got != "" {
		t.Fatalf("expected no redirect for pinned non-proxy archive member, got %q", got)
	}
}

func TestArchiveInternalExtract_BalanceCurrentHopAuthorizationReusesRequestLocalPinDespiteConcurrentAdvance(t *testing.T) {
	balanceMount := uniqueDownMountPath(t, "archive-balance-internal-extract-interposed")
	archiveTestZipPath := "/archive.zip"
	signedArchive := mustBuildArchiveZipPayload(t, map[string]string{"nested/file.bin": "archive-signed-member-internal-body"})
	unsignedArchive := mustBuildArchiveZipPayload(t, map[string]string{"nested/file.bin": "archive-unsigned-member-internal-body"})
	mustCreateArchiveDownStubStorageWithSign(t, balanceMount, downStubBehavior{
		files: []string{archiveTestZipPath},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{MFile: bytes.NewReader(signedArchive), ContentLength: int64(len(signedArchive))}, nil
		},
	}, true, model.Proxy{})
	mustCreateArchiveDownStubStorage(t, balanceMount+".balance", downStubBehavior{
		files: []string{archiveTestZipPath},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{MFile: bytes.NewReader(unsignedArchive), ContentLength: int64(len(unsignedArchive))}, nil
		},
	}, model.Proxy{})

	resp := callArchiveInternalExtractHandlerThroughMiddlewareWithInterposer(t, balanceMount+archiveTestZipPath, url.Values{"inner": {"/nested/file.bin"}}.Encode(), simulateConcurrentBalanceAdvance(t))

	if got, want := resp.Code, http.StatusOK; got != want {
		t.Fatalf("expected HTTP %d, got %d with body %s", want, got, resp.Body.String())
	}
	if got, want := resp.Body.String(), "archive-unsigned-member-internal-body"; got != want {
		t.Fatalf("expected internal extract body %q from request-local pinned archive member, got %q", want, got)
	}
}

func TestArchiveDown_AliasWrappedBalanceReusesRequestLocalPinDespiteConcurrentAdvance(t *testing.T) {
	baseMount := uniqueDownMountPath(t, "archive-alias-down-triple-balance")
	archiveTestZipPath := "/archive.zip"
	innerPath := "/nested/file.bin"
	previewRoute, err := op.ResolveWebDownloadRoutePreview(context.Background(), baseMount+archiveTestZipPath)
	if err == nil {
		t.Fatalf("expected preview to fail before storages are created")
	}

	var advanceOnce sync.Once
	fixtures := map[string]struct {
		listedName   string
		redirectURL  string
		afterGet     func(context.Context, string)
		createDriver func(*testing.T, string, downStubBehavior) *downStubDriver
	}{
		baseMount: {
			listedName:  "base.bin",
			redirectURL: "https://download.example.com/archive-alias-base.bin",
			createDriver: func(t *testing.T, mountPath string, behavior downStubBehavior) *downStubDriver {
				return mustCreateArchiveDownStubStorage(t, mountPath, behavior, model.Proxy{})
			},
		},
		baseMount + ".balance1": {
			listedName:  "file.bin",
			redirectURL: "https://download.example.com/archive-alias-balance1.bin",
			afterGet: func(context.Context, string) {
				advanceOnce.Do(func() {
					if _, err := op.ResolveWebDownloadRoute(context.Background(), baseMount+archiveTestZipPath); err != nil {
						t.Fatalf("expected concurrent balance advance success, got %v", err)
					}
				})
			},
			createDriver: func(t *testing.T, mountPath string, behavior downStubBehavior) *downStubDriver {
				return mustCreateArchiveDownStubStorage(t, mountPath, behavior, model.Proxy{})
			},
		},
		baseMount + ".balance2": {
			listedName:  "balance2.bin",
			redirectURL: "https://download.example.com/archive-alias-balance2.bin",
			createDriver: func(t *testing.T, mountPath string, behavior downStubBehavior) *downStubDriver {
				return mustCreateArchiveDownStubStorage(t, mountPath, behavior, model.Proxy{})
			},
		},
	}
	for mountPath, fixture := range fixtures {
		fixture := fixture
		fixture.createDriver(t, mountPath, downStubBehavior{
			files: []string{archiveTestZipPath},
			archiveList: func(args model.ArchiveInnerArgs) ([]model.Obj, error) {
				return []model.Obj{&model.Object{
					Path:     stdpath.Join(args.InnerPath, fixture.listedName),
					Name:     fixture.listedName,
					Size:     1,
					Modified: time.Unix(1, 0),
				}}, nil
			},
			archiveExtract: func(model.Obj, model.ArchiveInnerArgs) (*model.Link, error) {
				return &model.Link{URL: fixture.redirectURL}, nil
			},
			afterGet: fixture.afterGet,
		})
	}

	aliasMount := uniqueDownMountPath(t, "archive-alias-down-owner")
	mustCreateAliasStorage(t, aliasMount, baseMount, model.Proxy{})

	previewRoute, err = op.ResolveWebDownloadRoutePreview(context.Background(), baseMount+archiveTestZipPath)
	if err != nil {
		t.Fatalf("expected preview route resolution success, got %v", err)
	}
	if got, want := previewRoute.LeafMountPath, baseMount+".balance1"; got != want {
		t.Fatalf("expected first pinned archive sibling %q, got %q", want, got)
	}

	resp := callArchiveDownHandlerThroughMiddleware(t, aliasMount+archiveTestZipPath, url.Values{"inner": {innerPath}}.Encode())

	if got, want := resp.Code, http.StatusFound; got != want {
		t.Fatalf("expected HTTP %d, got %d with body %s", want, got, resp.Body.String())
	}
	if got, want := resp.Header().Get("Location"), fixtures[previewRoute.LeafMountPath].redirectURL; got != want {
		t.Fatalf("expected redirect %q from pinned archive sibling %q, got %q", want, previewRoute.LeafMountPath, got)
	}
}

func TestArchiveProxy_AliasWrappedBalanceReusesRequestLocalPinDespiteConcurrentAdvance(t *testing.T) {
	baseMount := uniqueDownMountPath(t, "archive-alias-proxy-triple-balance")
	archiveTestZipPath := "/archive.zip"
	innerPath := "/nested/file.bin"

	var advanceOnce sync.Once
	fixtures := map[string]struct {
		listedName   string
		proxyBody    string
		afterGet     func(context.Context, string)
		createDriver func(*testing.T, string, downStubBehavior) *downStubDriver
	}{
		baseMount: {
			listedName: "base.bin",
			proxyBody:  "archive-alias-base-body",
			createDriver: func(t *testing.T, mountPath string, behavior downStubBehavior) *downStubDriver {
				return mustCreateArchiveDownStubStorage(t, mountPath, behavior, model.Proxy{})
			},
		},
		baseMount + ".balance1": {
			listedName: "file.bin",
			proxyBody:  "archive-alias-balance1-body",
			afterGet: func(context.Context, string) {
				advanceOnce.Do(func() {
					if _, err := op.ResolveWebDownloadRoute(context.Background(), baseMount+archiveTestZipPath); err != nil {
						t.Fatalf("expected concurrent balance advance success, got %v", err)
					}
				})
			},
			createDriver: func(t *testing.T, mountPath string, behavior downStubBehavior) *downStubDriver {
				return mustCreateArchiveDownStubStorage(t, mountPath, behavior, model.Proxy{})
			},
		},
		baseMount + ".balance2": {
			listedName: "balance2.bin",
			proxyBody:  "archive-alias-balance2-body",
			createDriver: func(t *testing.T, mountPath string, behavior downStubBehavior) *downStubDriver {
				return mustCreateArchiveDownStubStorage(t, mountPath, behavior, model.Proxy{})
			},
		},
	}
	for mountPath, fixture := range fixtures {
		fixture := fixture
		fixture.createDriver(t, mountPath, downStubBehavior{
			files: []string{archiveTestZipPath},
			archiveList: func(args model.ArchiveInnerArgs) ([]model.Obj, error) {
				return []model.Obj{&model.Object{
					Path:     stdpath.Join(args.InnerPath, fixture.listedName),
					Name:     fixture.listedName,
					Size:     1,
					Modified: time.Unix(1, 0),
				}}, nil
			},
			archiveExtract: func(model.Obj, model.ArchiveInnerArgs) (*model.Link, error) {
				return &model.Link{MFile: strings.NewReader(fixture.proxyBody)}, nil
			},
			afterGet: fixture.afterGet,
		})
	}

	aliasMount := uniqueDownMountPath(t, "archive-alias-proxy-owner")
	mustCreateAliasStorage(t, aliasMount, baseMount, model.Proxy{WebProxy: true})

	previewRoute, err := op.ResolveWebDownloadRoutePreview(context.Background(), baseMount+archiveTestZipPath)
	if err != nil {
		t.Fatalf("expected preview route resolution success, got %v", err)
	}
	if got, want := previewRoute.LeafMountPath, baseMount+".balance1"; got != want {
		t.Fatalf("expected first pinned archive sibling %q, got %q", want, got)
	}

	resp := callArchiveProxyHandlerThroughMiddleware(t, aliasMount+archiveTestZipPath, url.Values{"inner": {innerPath}}.Encode())

	if got, want := resp.Code, http.StatusOK; got != want {
		t.Fatalf("expected HTTP %d, got %d with body %s", want, got, resp.Body.String())
	}
	if got, want := resp.Body.String(), fixtures[previewRoute.LeafMountPath].proxyBody; got != want {
		t.Fatalf("expected proxy body %q from pinned archive sibling %q, got %q", want, previewRoute.LeafMountPath, got)
	}
}

func TestArchiveInternalExtract_AliasWrappedBalanceReusesRequestLocalPinDespiteConcurrentAdvance(t *testing.T) {
	baseMount := uniqueDownMountPath(t, "archive-alias-internal-triple-balance")
	archiveTestZipPath := "/archive.zip"
	innerPath := "/nested/file.bin"

	var advanceOnce sync.Once
	fixtures := map[string]struct {
		archiveBytes []byte
		extracted    string
		afterGet     func(context.Context, string)
		createDriver func(*testing.T, string, downStubBehavior) *downStubDriver
	}{
		baseMount: {
			archiveBytes: mustBuildArchiveZipPayload(t, map[string]string{"nested/file.bin": "archive-alias-base-internal-body"}),
			extracted:    "archive-alias-base-internal-body",
			createDriver: func(t *testing.T, mountPath string, behavior downStubBehavior) *downStubDriver {
				return mustCreateArchiveDownStubStorage(t, mountPath, behavior, model.Proxy{})
			},
		},
		baseMount + ".balance1": {
			archiveBytes: mustBuildArchiveZipPayload(t, map[string]string{"nested/file.bin": "archive-alias-balance1-internal-body"}),
			extracted:    "archive-alias-balance1-internal-body",
			afterGet: func(context.Context, string) {
				advanceOnce.Do(func() {
					if _, err := op.ResolveWebDownloadRoute(context.Background(), baseMount+archiveTestZipPath); err != nil {
						t.Fatalf("expected concurrent balance advance success, got %v", err)
					}
				})
			},
			createDriver: func(t *testing.T, mountPath string, behavior downStubBehavior) *downStubDriver {
				return mustCreateArchiveDownStubStorage(t, mountPath, behavior, model.Proxy{})
			},
		},
		baseMount + ".balance2": {
			archiveBytes: mustBuildArchiveZipPayload(t, map[string]string{"nested/file.bin": "archive-alias-balance2-internal-body"}),
			extracted:    "archive-alias-balance2-internal-body",
			createDriver: func(t *testing.T, mountPath string, behavior downStubBehavior) *downStubDriver {
				return mustCreateArchiveDownStubStorage(t, mountPath, behavior, model.Proxy{})
			},
		},
	}
	for mountPath, fixture := range fixtures {
		fixture := fixture
		fixture.createDriver(t, mountPath, downStubBehavior{
			files: []string{archiveTestZipPath},
			link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
				return &model.Link{MFile: bytes.NewReader(fixture.archiveBytes), ContentLength: int64(len(fixture.archiveBytes))}, nil
			},
			afterGet: fixture.afterGet,
		})
	}

	aliasMount := uniqueDownMountPath(t, "archive-alias-internal-owner")
	mustCreateAliasStorage(t, aliasMount, baseMount, model.Proxy{})

	previewRoute, err := op.ResolveWebDownloadRoutePreview(context.Background(), baseMount+archiveTestZipPath)
	if err != nil {
		t.Fatalf("expected preview route resolution success, got %v", err)
	}
	if got, want := previewRoute.LeafMountPath, baseMount+".balance1"; got != want {
		t.Fatalf("expected first pinned archive sibling %q, got %q", want, got)
	}

	resp := callArchiveInternalExtractHandlerThroughMiddlewareWithInterposer(t, aliasMount+archiveTestZipPath, url.Values{"inner": {innerPath}}.Encode(), nil)

	if got, want := resp.Code, http.StatusOK; got != want {
		t.Fatalf("expected HTTP %d, got %d with body %s", want, got, resp.Body.String())
	}
	if got, want := resp.Body.String(), fixtures[previewRoute.LeafMountPath].extracted; got != want {
		t.Fatalf("expected internal extract body %q from pinned archive sibling %q, got %q", want, previewRoute.LeafMountPath, got)
	}
}

func TestDownHandler_NativeProxyCanonicalRedirectUsesAPIBasePrefix(t *testing.T) {
	leafMount := uniqueDownMountPath(t, "leaf")
	mustCreateNonProxyDownStubStorage(t, leafMount, downStubBehavior{
		files: []string{downTestFilePath},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/native.bin"}, nil
		},
	}, model.Proxy{})

	nativeOwnerMount := uniqueDownMountPath(t, "native-owner")
	mustCreateAliasStorage(t, nativeOwnerMount, leafMount, model.Proxy{WebProxy: true})

	outerMount := uniqueDownMountPath(t, "outer")
	mustCreateAliasStorage(t, outerMount, nativeOwnerMount, model.Proxy{})

	resp := callDownHandlerWithAPI(t, outerMount+downTestFilePath, "", "https://example.test/openlist")

	if got, want := resp.Code, http.StatusFound; got != want {
		t.Fatalf("expected HTTP %d, got %d with body %s", want, got, resp.Body.String())
	}
	expected := canonicalTestProxyURL("https://example.test/openlist", nativeOwnerMount+downTestFilePath)
	if got := resp.Header().Get("Location"); got != expected {
		t.Fatalf("expected redirect %q, got %q", expected, got)
	}
}

func TestDownHandler_NativeProxyCanonicalRedirectPreservesRawQuery(t *testing.T) {
	leafMount := uniqueDownMountPath(t, "leaf")
	mustCreateNonProxyDownStubStorage(t, leafMount, downStubBehavior{
		files: []string{downTestFilePath},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/native.bin"}, nil
		},
	}, model.Proxy{})

	nativeOwnerMount := uniqueDownMountPath(t, "native-owner")
	mustCreateAliasStorage(t, nativeOwnerMount, leafMount, model.Proxy{WebProxy: true})

	outerMount := uniqueDownMountPath(t, "outer")
	mustCreateAliasStorage(t, outerMount, nativeOwnerMount, model.Proxy{})

	resp := callDownHandler(t, outerMount+downTestFilePath, "raw=true")

	if got, want := resp.Code, http.StatusFound; got != want {
		t.Fatalf("expected HTTP %d, got %d with body %s", want, got, resp.Body.String())
	}
	expected := canonicalTestProxyURLWithQuery("https://example.test", nativeOwnerMount+downTestFilePath, url.Values{"raw": {"true"}})
	if got := resp.Header().Get("Location"); got != expected {
		t.Fatalf("expected redirect %q, got %q", expected, got)
	}
}

func TestDownHandler_AllWrapper302RedirectsToLeafUpstreamURL(t *testing.T) {
	leafMount := uniqueDownMountPath(t, "leaf")
	mustCreateNonProxyDownStubStorage(t, leafMount, downStubBehavior{
		files: []string{downTestFilePath},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/direct.bin"}, nil
		},
	}, model.Proxy{})

	innerMount := uniqueDownMountPath(t, "inner")
	mustCreateAliasStorage(t, innerMount, leafMount, model.Proxy{})

	outerMount := uniqueDownMountPath(t, "outer")
	mustCreateAliasStorage(t, outerMount, innerMount, model.Proxy{})

	resp := callDownHandler(t, outerMount+downTestFilePath, "")

	if got, want := resp.Code, http.StatusFound; got != want {
		t.Fatalf("expected HTTP %d, got %d with body %s", want, got, resp.Body.String())
	}
	if got, want := resp.Header().Get("Location"), "https://download.example.com/direct.bin"; got != want {
		t.Fatalf("expected redirect %q, got %q", want, got)
	}
}

func TestDownHandler_Redirect302RejectsLeafLocalProxyURL(t *testing.T) {
	leafMount := uniqueDownMountPath(t, "leaf")
	mustCreateNonProxyDownStubStorage(t, leafMount, downStubBehavior{
		files: []string{downTestFilePath},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "/p/should-not-emit"}, nil
		},
	}, model.Proxy{})

	outerMount := uniqueDownMountPath(t, "outer")
	mustCreateAliasStorage(t, outerMount, leafMount, model.Proxy{})

	resp := callDownHandler(t, outerMount+downTestFilePath, "")

	if got, want := resp.Code, http.StatusInternalServerError; got != want {
		t.Fatalf("expected HTTP %d, got %d with body %s", want, got, resp.Body.String())
	}
	if got := resp.Header().Get("Location"); got != "" {
		t.Fatalf("expected no redirect location for invalid leaf target, got %q", got)
	}
}

func TestProxyHandler_NativeProxyCanonicalizesToOwnerPath(t *testing.T) {
	leafMount := uniqueDownMountPath(t, "leaf")
	mustCreateNonProxyDownStubStorage(t, leafMount, downStubBehavior{
		files: []string{downTestFilePath},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/native.bin"}, nil
		},
	}, model.Proxy{})

	nativeOwnerMount := uniqueDownMountPath(t, "native-owner")
	mustCreateAliasStorage(t, nativeOwnerMount, leafMount, model.Proxy{WebProxy: true})

	outerMount := uniqueDownMountPath(t, "outer")
	mustCreateAliasStorage(t, outerMount, nativeOwnerMount, model.Proxy{})

	resp := callProxyHandler(t, outerMount+downTestFilePath, "")

	if got, want := resp.Code, http.StatusFound; got != want {
		t.Fatalf("expected HTTP %d, got %d with body %s", want, got, resp.Body.String())
	}
	expected := canonicalTestProxyURL("https://example.test", nativeOwnerMount+downTestFilePath)
	if got := resp.Header().Get("Location"); got != expected {
		t.Fatalf("expected redirect %q, got %q", expected, got)
	}
}

func TestProxyHandler_NativeProxyCanonicalRedirectUsesAPIBasePrefix(t *testing.T) {
	leafMount := uniqueDownMountPath(t, "leaf")
	mustCreateNonProxyDownStubStorage(t, leafMount, downStubBehavior{
		files: []string{downTestFilePath},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/native.bin"}, nil
		},
	}, model.Proxy{})

	nativeOwnerMount := uniqueDownMountPath(t, "native-owner")
	mustCreateAliasStorage(t, nativeOwnerMount, leafMount, model.Proxy{WebProxy: true})

	outerMount := uniqueDownMountPath(t, "outer")
	mustCreateAliasStorage(t, outerMount, nativeOwnerMount, model.Proxy{})

	resp := callProxyHandlerWithAPI(t, outerMount+downTestFilePath, "", "https://example.test/openlist")

	if got, want := resp.Code, http.StatusFound; got != want {
		t.Fatalf("expected HTTP %d, got %d with body %s", want, got, resp.Body.String())
	}
	expected := canonicalTestProxyURL("https://example.test/openlist", nativeOwnerMount+downTestFilePath)
	if got := resp.Header().Get("Location"); got != expected {
		t.Fatalf("expected redirect %q, got %q", expected, got)
	}
}

func TestProxyHandler_ProxyURLOwnerWithoutD1RedirectsExternally(t *testing.T) {
	leafMount := uniqueDownMountPath(t, "leaf")
	mustCreateDownStubStorage(t, leafMount, downStubBehavior{
		files: []string{downTestFilePath},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{MFile: strings.NewReader("proxy-leaf-body")}, nil
		},
	}, model.Proxy{})

	nativeOwnerMount := uniqueDownMountPath(t, "native-owner")
	mustCreateAliasStorage(t, nativeOwnerMount, leafMount, model.Proxy{WebProxy: true})

	proxyOwnerMount := uniqueDownMountPath(t, "proxy-owner")
	mustCreateAliasStorage(t, proxyOwnerMount, nativeOwnerMount, model.Proxy{DownProxyURL: "https://proxy.example.com"})

	resp := callProxyHandler(t, proxyOwnerMount+downTestFilePath, "d=0")

	if got, want := resp.Code, http.StatusFound; got != want {
		t.Fatalf("expected HTTP %d, got %d with body %s", want, got, resp.Body.String())
	}
	expected := common.GenerateDownProxyURL(&model.Storage{Proxy: model.Proxy{DownProxyURL: "https://proxy.example.com"}}, proxyOwnerMount+downTestFilePath)
	if got := resp.Header().Get("Location"); got != expected {
		t.Fatalf("expected redirect %q, got %q", expected, got)
	}
}

func TestProxyHandler_ProxyURLOwnerWithD1CanonicalizesToOwnerPathOnce(t *testing.T) {
	leafMount := uniqueDownMountPath(t, "leaf")
	mustCreateDownStubStorage(t, leafMount, downStubBehavior{
		files: []string{downTestFilePath},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{MFile: strings.NewReader("proxy-leaf-body")}, nil
		},
	}, model.Proxy{})

	nativeOwnerMount := uniqueDownMountPath(t, "native-owner")
	mustCreateAliasStorage(t, nativeOwnerMount, leafMount, model.Proxy{WebProxy: true})

	proxyOwnerMount := uniqueDownMountPath(t, "proxy-owner")
	mustCreateAliasStorage(t, proxyOwnerMount, nativeOwnerMount, model.Proxy{DownProxyURL: "https://proxy.example.com"})

	outerMount := uniqueDownMountPath(t, "outer")
	mustCreateAliasStorage(t, outerMount, proxyOwnerMount, model.Proxy{})

	resp := callProxyHandler(t, outerMount+downTestFilePath, "d=1")

	if got, want := resp.Code, http.StatusFound; got != want {
		t.Fatalf("expected HTTP %d, got %d with body %s", want, got, resp.Body.String())
	}
	expected := canonicalTestProxyURLWithD1("https://example.test", proxyOwnerMount+downTestFilePath)
	if got := resp.Header().Get("Location"); got != expected {
		t.Fatalf("expected canonical owner redirect %q, got %q", expected, got)
	}
}

func TestProxyHandler_ProxyURLOwnerWithD1CanonicalizationIncludesSignWhenNextHopRequiresIt(t *testing.T) {
	leafMount := uniqueDownMountPath(t, "leaf")
	mustCreateDownStubStorage(t, leafMount, downStubBehavior{
		files: []string{downTestFilePath},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{MFile: strings.NewReader("proxy-leaf-body")}, nil
		},
	}, model.Proxy{})

	nativeOwnerMount := uniqueDownMountPath(t, "native-owner")
	mustCreateAliasStorage(t, nativeOwnerMount, leafMount, model.Proxy{WebProxy: true})

	proxyOwnerMount := uniqueDownMountPath(t, "proxy-owner")
	mustCreateLinkHandlerStorage(t, model.Storage{
		MountPath:  proxyOwnerMount,
		Driver:     "Alias",
		Addition:   mustMarshalLinkHandlerAddition(t, alias.Addition{Paths: nativeOwnerMount, ProtectSameName: true}),
		EnableSign: true,
		Proxy:      model.Proxy{DownProxyURL: "https://proxy.example.com"},
	})

	outerMount := uniqueDownMountPath(t, "outer")
	mustCreateAliasStorage(t, outerMount, proxyOwnerMount, model.Proxy{})

	resp := callProxyHandler(t, outerMount+downTestFilePath, "d=1")

	if got, want := resp.Code, http.StatusFound; got != want {
		t.Fatalf("expected HTTP %d, got %d with body %s", want, got, resp.Body.String())
	}
	expected := canonicalSignedTestProxyURLWithQuery("https://example.test", proxyOwnerMount+downTestFilePath, url.Values{"d": {"1"}})
	if got := resp.Header().Get("Location"); got != expected {
		t.Fatalf("expected canonical owner redirect %q, got %q", expected, got)
	}
}

func TestProxyHandler_ProxyURLOwnerWithD1CanonicalizesOnceAndPreservesRawQuery(t *testing.T) {
	leafMount := uniqueDownMountPath(t, "leaf")
	mustCreateDownStubStorage(t, leafMount, downStubBehavior{
		files: []string{downTestFilePath},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{MFile: strings.NewReader("proxy-leaf-body")}, nil
		},
	}, model.Proxy{})

	nativeOwnerMount := uniqueDownMountPath(t, "native-owner")
	mustCreateAliasStorage(t, nativeOwnerMount, leafMount, model.Proxy{WebProxy: true})

	proxyOwnerMount := uniqueDownMountPath(t, "proxy-owner")
	mustCreateAliasStorage(t, proxyOwnerMount, nativeOwnerMount, model.Proxy{DownProxyURL: "https://proxy.example.com"})

	outerMount := uniqueDownMountPath(t, "outer")
	mustCreateAliasStorage(t, outerMount, proxyOwnerMount, model.Proxy{})

	resp := callProxyHandler(t, outerMount+downTestFilePath, "d=1&raw=true")

	if got, want := resp.Code, http.StatusFound; got != want {
		t.Fatalf("expected HTTP %d, got %d with body %s", want, got, resp.Body.String())
	}
	expected := canonicalTestProxyURLWithQuery("https://example.test", proxyOwnerMount+downTestFilePath, url.Values{"d": {"1"}, "raw": {"true"}})
	if got := resp.Header().Get("Location"); got != expected {
		t.Fatalf("expected canonical owner redirect %q, got %q", expected, got)
	}
}

func TestProxyHandler_ProxyURLOwnerWithD1BypassesExternalProxyAndStreamsLeaf(t *testing.T) {
	leafMount := uniqueDownMountPath(t, "leaf")
	mustCreateDownStubStorage(t, leafMount, downStubBehavior{
		files: []string{downTestFilePath},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{MFile: strings.NewReader("proxy-leaf-body")}, nil
		},
	}, model.Proxy{})

	nativeOwnerMount := uniqueDownMountPath(t, "native-owner")
	mustCreateAliasStorage(t, nativeOwnerMount, leafMount, model.Proxy{WebProxy: true})

	proxyOwnerMount := uniqueDownMountPath(t, "proxy-owner")
	mustCreateAliasStorage(t, proxyOwnerMount, nativeOwnerMount, model.Proxy{DownProxyURL: "https://proxy.example.com"})

	resp := callProxyHandler(t, proxyOwnerMount+downTestFilePath, "d=1")

	if got, want := resp.Code, http.StatusOK; got != want {
		t.Fatalf("expected HTTP %d, got %d with body %s", want, got, resp.Body.String())
	}
	if got := resp.Header().Get("Location"); got != "" {
		t.Fatalf("expected no redirect after canonical owner path, got %q", got)
	}
	if got, want := resp.Body.String(), "proxy-leaf-body"; got != want {
		t.Fatalf("expected streamed body %q, got %q", want, got)
	}
}

func TestProxyHandler_ProxyURLOwnerWithD1RejectsLeafOpenListLocalURLAfterOwnerRoutingSettles(t *testing.T) {
	var (
		mu           sync.Mutex
		outboundHops []string
	)
	localProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		outboundHops = append(outboundHops, r.URL.String())
		mu.Unlock()
		_, _ = io.WriteString(w, "recursive-hop-body")
	}))
	defer localProxy.Close()

	leafMount := uniqueDownMountPath(t, "leaf-openlist-local")
	mustCreateNonProxyDownStubStorage(t, leafMount, downStubBehavior{
		files: []string{downTestFilePath},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			leafPath := leafMount + downTestFilePath
			localURL := localProxy.URL + "/p" + utils.EncodePath(leafPath, true) + "?type=parsed&sign=" + sign.Sign(leafPath)
			return &model.Link{URL: localURL}, nil
		},
	}, model.Proxy{})

	proxyOwnerMount := uniqueDownMountPath(t, "proxy-owner-local")
	mustCreateAliasStorage(t, proxyOwnerMount, leafMount, model.Proxy{DownProxyURL: "https://proxy.example.com"})

	resp := callProxyHandlerWithAPI(t, proxyOwnerMount+downTestFilePath, "d=1", localProxy.URL)

	if got, want := resp.Code, http.StatusInternalServerError; got != want {
		t.Fatalf("expected HTTP %d after rejecting local recursive proxy target, got %d with body %s", want, got, resp.Body.String())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(outboundHops) != 0 {
		t.Fatalf("expected no outbound recursive proxy requests, got %v", outboundHops)
	}
}

func TestProxyHandler_ProxyURLOwnerWithD1RejectsRootBaseSameHostLocalAPIPath(t *testing.T) {
	var (
		mu           sync.Mutex
		outboundHops []string
	)
	localAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		outboundHops = append(outboundHops, r.URL.String())
		mu.Unlock()
		_, _ = io.WriteString(w, "root-base-local-hop-body")
	}))
	defer localAPI.Close()

	leafMount := uniqueDownMountPath(t, "leaf-root-base-local-api")
	mustCreateNonProxyDownStubStorage(t, leafMount, downStubBehavior{
		files: []string{downTestFilePath},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			leafPath := leafMount + downTestFilePath
			localURL := localAPI.URL + "/api/fs/get?path=" + url.QueryEscape(leafPath)
			return &model.Link{URL: localURL}, nil
		},
	}, model.Proxy{})

	proxyOwnerMount := uniqueDownMountPath(t, "proxy-owner-root-base-local-api")
	mustCreateAliasStorage(t, proxyOwnerMount, leafMount, model.Proxy{DownProxyURL: "https://proxy.example.com"})

	resp := callProxyHandlerWithAPI(t, proxyOwnerMount+downTestFilePath, "d=1", localAPI.URL)

	if got, want := resp.Code, http.StatusInternalServerError; got != want {
		t.Fatalf("expected HTTP %d after rejecting root-base same-host local path, got %d with body %s", want, got, resp.Body.String())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(outboundHops) != 0 {
		t.Fatalf("expected no outbound recursive proxy requests for root-base same-host local path, got %v", outboundHops)
	}
}

func TestProxyHandler_ProxyURLOwnerWithD1AllowsRootBaseSameHostNonAPIURLAndProxiesOnce(t *testing.T) {
	var (
		mu           sync.Mutex
		outboundHops []string
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		outboundHops = append(outboundHops, r.URL.String())
		mu.Unlock()
		_, _ = io.WriteString(w, "root-base-same-host-upstream-body")
	}))
	defer upstream.Close()

	leafMount := uniqueDownMountPath(t, "leaf-root-base-same-host-upstream")
	mustCreateNonProxyDownStubStorage(t, leafMount, downStubBehavior{
		files: []string{downTestFilePath},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: upstream.URL + "/files/direct.bin"}, nil
		},
	}, model.Proxy{})

	proxyOwnerMount := uniqueDownMountPath(t, "proxy-owner-root-base-same-host-upstream")
	mustCreateAliasStorage(t, proxyOwnerMount, leafMount, model.Proxy{DownProxyURL: "https://proxy.example.com"})

	resp := callProxyHandlerWithAPI(t, proxyOwnerMount+downTestFilePath, "d=1", upstream.URL)

	if got, want := resp.Code, http.StatusOK; got != want {
		t.Fatalf("expected HTTP %d after proxying same-host non-API URL, got %d with body %s", want, got, resp.Body.String())
	}
	if got, want := resp.Body.String(), "root-base-same-host-upstream-body"; got != want {
		t.Fatalf("expected proxied body %q, got %q", want, got)
	}
	mu.Lock()
	defer mu.Unlock()
	if got, want := len(outboundHops), 1; got != want {
		t.Fatalf("expected exactly %d outbound proxy request, got %d (%v)", want, got, outboundHops)
	}
	if got, want := outboundHops[0], "/files/direct.bin"; got != want {
		t.Fatalf("expected outbound request path %q, got %q", want, got)
	}
}

func TestProxyHandler_ProxyURLOwnerWithD1AllowsNonRootBaseSameHostNonAPIURLUnderAPIBaseAndProxiesOnce(t *testing.T) {
	var (
		mu           sync.Mutex
		outboundHops []string
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		outboundHops = append(outboundHops, r.URL.String())
		mu.Unlock()
		_, _ = io.WriteString(w, "non-root-base-same-host-upstream-body")
	}))
	defer upstream.Close()

	leafMount := uniqueDownMountPath(t, "leaf-non-root-base-same-host-upstream")
	mustCreateNonProxyDownStubStorage(t, leafMount, downStubBehavior{
		files: []string{downTestFilePath},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: upstream.URL + "/openlist/files/direct.bin"}, nil
		},
	}, model.Proxy{})

	proxyOwnerMount := uniqueDownMountPath(t, "proxy-owner-non-root-base-same-host-upstream")
	mustCreateAliasStorage(t, proxyOwnerMount, leafMount, model.Proxy{DownProxyURL: "https://proxy.example.com"})

	resp := callProxyHandlerWithAPI(t, proxyOwnerMount+downTestFilePath, "d=1", upstream.URL+"/openlist")

	if got, want := resp.Code, http.StatusOK; got != want {
		t.Fatalf("expected HTTP %d after proxying same-host non-API URL under API base, got %d with body %s", want, got, resp.Body.String())
	}
	if got, want := resp.Body.String(), "non-root-base-same-host-upstream-body"; got != want {
		t.Fatalf("expected proxied body %q, got %q", want, got)
	}
	mu.Lock()
	defer mu.Unlock()
	if got, want := len(outboundHops), 1; got != want {
		t.Fatalf("expected exactly %d outbound proxy request, got %d (%v)", want, got, outboundHops)
	}
	if got, want := outboundHops[0], "/openlist/files/direct.bin"; got != want {
		t.Fatalf("expected outbound request path %q, got %q", want, got)
	}
}

func TestProxyHandler_ProxyURLOwnerWithD1RejectsNonRootBasePLocalRoute(t *testing.T) {
	var (
		mu           sync.Mutex
		outboundHops []string
	)
	localAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		outboundHops = append(outboundHops, r.URL.String())
		mu.Unlock()
		_, _ = io.WriteString(w, "non-root-base-p-local-hop-body")
	}))
	defer localAPI.Close()

	leafMount := uniqueDownMountPath(t, "leaf-non-root-base-p-local")
	mustCreateNonProxyDownStubStorage(t, leafMount, downStubBehavior{
		files: []string{downTestFilePath},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: localAPI.URL + "/openlist/p/local-file"}, nil
		},
	}, model.Proxy{})

	proxyOwnerMount := uniqueDownMountPath(t, "proxy-owner-non-root-base-p-local")
	mustCreateAliasStorage(t, proxyOwnerMount, leafMount, model.Proxy{DownProxyURL: "https://proxy.example.com"})

	resp := callProxyHandlerWithAPI(t, proxyOwnerMount+downTestFilePath, "d=1", localAPI.URL+"/openlist")

	if got, want := resp.Code, http.StatusInternalServerError; got != want {
		t.Fatalf("expected HTTP %d after rejecting non-root-base /openlist/p local path, got %d with body %s", want, got, resp.Body.String())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(outboundHops) != 0 {
		t.Fatalf("expected no outbound recursive proxy requests for non-root-base /openlist/p local path, got %v", outboundHops)
	}
}

func TestProxyHandler_ProxyURLOwnerWithD1RejectsNonRootBaseDLocalRoute(t *testing.T) {
	var (
		mu           sync.Mutex
		outboundHops []string
	)
	localAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		outboundHops = append(outboundHops, r.URL.String())
		mu.Unlock()
		_, _ = io.WriteString(w, "non-root-base-d-local-hop-body")
	}))
	defer localAPI.Close()

	leafMount := uniqueDownMountPath(t, "leaf-non-root-base-d-local")
	mustCreateNonProxyDownStubStorage(t, leafMount, downStubBehavior{
		files: []string{downTestFilePath},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: localAPI.URL + "/openlist/d/local-file"}, nil
		},
	}, model.Proxy{})

	proxyOwnerMount := uniqueDownMountPath(t, "proxy-owner-non-root-base-d-local")
	mustCreateAliasStorage(t, proxyOwnerMount, leafMount, model.Proxy{DownProxyURL: "https://proxy.example.com"})

	resp := callProxyHandlerWithAPI(t, proxyOwnerMount+downTestFilePath, "d=1", localAPI.URL+"/openlist")

	if got, want := resp.Code, http.StatusInternalServerError; got != want {
		t.Fatalf("expected HTTP %d after rejecting non-root-base /openlist/d local path, got %d with body %s", want, got, resp.Body.String())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(outboundHops) != 0 {
		t.Fatalf("expected no outbound recursive proxy requests for non-root-base /openlist/d local path, got %v", outboundHops)
	}
}

func TestProxyHandler_ProxyURLOwnerWithD1AllowsNonRootBaseFilesNonLocalRouteAndProxiesOnce(t *testing.T) {
	var (
		mu           sync.Mutex
		outboundHops []string
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		outboundHops = append(outboundHops, r.URL.String())
		mu.Unlock()
		_, _ = io.WriteString(w, "non-root-base-files-upstream-body")
	}))
	defer upstream.Close()

	leafMount := uniqueDownMountPath(t, "leaf-non-root-base-files-upstream")
	mustCreateNonProxyDownStubStorage(t, leafMount, downStubBehavior{
		files: []string{downTestFilePath},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: upstream.URL + "/openlist/files/direct.bin"}, nil
		},
	}, model.Proxy{})

	proxyOwnerMount := uniqueDownMountPath(t, "proxy-owner-non-root-base-files-upstream")
	mustCreateAliasStorage(t, proxyOwnerMount, leafMount, model.Proxy{DownProxyURL: "https://proxy.example.com"})

	resp := callProxyHandlerWithAPI(t, proxyOwnerMount+downTestFilePath, "d=1", upstream.URL+"/openlist")

	if got, want := resp.Code, http.StatusOK; got != want {
		t.Fatalf("expected HTTP %d after proxying non-root-base /openlist/files upstream URL, got %d with body %s", want, got, resp.Body.String())
	}
	if got, want := resp.Body.String(), "non-root-base-files-upstream-body"; got != want {
		t.Fatalf("expected proxied body %q, got %q", want, got)
	}
	mu.Lock()
	defer mu.Unlock()
	if got, want := len(outboundHops), 1; got != want {
		t.Fatalf("expected exactly %d outbound proxy request, got %d (%v)", want, got, outboundHops)
	}
	if got, want := outboundHops[0], "/openlist/files/direct.bin"; got != want {
		t.Fatalf("expected outbound request path %q, got %q", want, got)
	}
}

func TestProxyHandler_ProxyURLOwnerWithD1RejectsBalanceSameHostLocalAPIPath(t *testing.T) {
	var (
		mu           sync.Mutex
		outboundHops []string
	)
	localAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		outboundHops = append(outboundHops, r.URL.String())
		mu.Unlock()
		_, _ = io.WriteString(w, "balance-local-hop-body")
	}))
	defer localAPI.Close()

	leafMount := uniqueDownMountPath(t, "leaf-balance-local-api")
	mustCreateNonProxyDownStubStorage(t, leafMount, downStubBehavior{
		files: []string{downTestFilePath},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			leafPath := leafMount + downTestFilePath
			localURL := localAPI.URL + "/openlist.balance/api/fs/get?path=" + url.QueryEscape(leafPath)
			return &model.Link{URL: localURL}, nil
		},
	}, model.Proxy{})

	proxyOwnerMount := uniqueDownMountPath(t, "proxy-owner-balance-local-api")
	mustCreateAliasStorage(t, proxyOwnerMount, leafMount, model.Proxy{DownProxyURL: "https://proxy.example.com"})

	resp := callProxyHandlerWithAPI(t, proxyOwnerMount+downTestFilePath, "d=1", localAPI.URL+"/openlist.balance")

	if got, want := resp.Code, http.StatusInternalServerError; got != want {
		t.Fatalf("expected HTTP %d after rejecting .balance recursive proxy target, got %d with body %s", want, got, resp.Body.String())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(outboundHops) != 0 {
		t.Fatalf("expected no outbound recursive proxy requests, got %v", outboundHops)
	}
}

func TestProxyHandler_NativeProxyRejectsNeteaseStyleLeafLocalProxyURL(t *testing.T) {
	textTypesSetting, textTypesExisted := mustGetOrCreateDownSettingItem(t, conf.TextTypes, "")
	t.Cleanup(func() {
		if textTypesExisted {
			mustSaveDownSettingItem(t, textTypesSetting)
		} else {
			mustSaveDownSettingItem(t, model.SettingItem{Key: conf.TextTypes, Value: ""})
		}
	})
	if !utils.SliceContains(strings.Split(textTypesSetting.Value, ","), "lrc") {
		if textTypesSetting.Value == "" {
			textTypesSetting.Value = "lrc"
		} else {
			textTypesSetting.Value += ",lrc"
		}
		mustSaveDownSettingItem(t, textTypesSetting)
	}

	var (
		mu           sync.Mutex
		outboundHops []string
	)
	localProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		outboundHops = append(outboundHops, r.URL.String())
		mu.Unlock()
		_, _ = io.WriteString(w, "netease-recursive-hop-body")
	}))
	defer localProxy.Close()

	lyricPath := "/song.lrc"
	lyricMount := uniqueDownMountPath(t, "netease-lyric")
	mustCreateNonProxyDownStubStorage(t, lyricMount, downStubBehavior{
		files: []string{lyricPath},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			leafPath := lyricMount + lyricPath
			localURL := localProxy.URL + "/p" + utils.EncodePath(leafPath, true) + "?type=parsed&sign=" + sign.Sign(leafPath)
			return &model.Link{URL: localURL}, nil
		},
	}, model.Proxy{})

	resp := callProxyHandlerWithAPI(t, lyricMount+lyricPath, "", localProxy.URL)

	if got, want := resp.Code, http.StatusInternalServerError; got != want {
		t.Fatalf("expected HTTP %d after rejecting Netease-style local proxy leaf, got %d with body %s", want, got, resp.Body.String())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(outboundHops) != 0 {
		t.Fatalf("expected no outbound recursive proxy requests for local lyric leaf, got %v", outboundHops)
	}
}

func TestProxyHandler_Redirect302RouteRejectsProxyAccess(t *testing.T) {
	leafMount := uniqueDownMountPath(t, "leaf")
	mustCreateNonProxyDownStubStorage(t, leafMount, downStubBehavior{
		files: []string{downTestFilePath},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/direct.bin"}, nil
		},
	}, model.Proxy{})

	outerMount := uniqueDownMountPath(t, "outer")
	mustCreateAliasStorage(t, outerMount, leafMount, model.Proxy{})

	resp := callProxyHandler(t, outerMount+downTestFilePath, "")

	if got, want := resp.Code, http.StatusForbidden; got != want {
		t.Fatalf("expected HTTP %d, got %d with body %s", want, got, resp.Body.String())
	}
}

func TestProxyHandler_ProxyURLOwnerRejectsMalformedExternalProxyURL(t *testing.T) {
	leafMount := uniqueDownMountPath(t, "leaf")
	mustCreateDownStubStorage(t, leafMount, downStubBehavior{
		files: []string{downTestFilePath},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{MFile: strings.NewReader("proxy-leaf-body")}, nil
		},
	}, model.Proxy{})

	proxyOwnerMount := uniqueDownMountPath(t, "proxy-owner-invalid")
	mustCreateAliasStorage(t, proxyOwnerMount, leafMount, model.Proxy{DownProxyURL: "https://"})

	resp := callProxyHandler(t, proxyOwnerMount+downTestFilePath, "")

	if got, want := resp.Code, http.StatusInternalServerError; got != want {
		t.Fatalf("expected HTTP %d for malformed external proxy URL, got %d with body %s", want, got, resp.Body.String())
	}
	if got := resp.Header().Get("Location"); got != "" {
		t.Fatalf("expected no redirect location for malformed external proxy URL, got %q", got)
	}
	if got := resp.Body.String(); !strings.Contains(got, "https://") {
		t.Fatalf("expected error body to mention malformed proxy base, got %q", got)
	}
}

func TestFsGet_RawURLUsesOwnerProxyURLWhenEffectivePolicyIsProxyURL(t *testing.T) {
	leafMount := uniqueDownMountPath(t, "leaf")
	mustCreateDownStubStorage(t, leafMount, downStubBehavior{
		files: []string{downTestFilePath},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{MFile: strings.NewReader("proxy-leaf-body")}, nil
		},
	}, model.Proxy{})

	nativeOwnerMount := uniqueDownMountPath(t, "native-owner")
	mustCreateAliasStorage(t, nativeOwnerMount, leafMount, model.Proxy{WebProxy: true})

	proxyOwnerMount := uniqueDownMountPath(t, "proxy-owner")
	mustCreateAliasStorage(t, proxyOwnerMount, nativeOwnerMount, model.Proxy{DownProxyURL: "https://proxy.example.com"})

	outerMount := uniqueDownMountPath(t, "outer")
	mustCreateAliasStorage(t, outerMount, proxyOwnerMount, model.Proxy{})

	resp := callFsGetHandler(t, outerMount+downTestFilePath)

	expected := common.GenerateDownProxyURL(&model.Storage{Proxy: model.Proxy{DownProxyURL: "https://proxy.example.com"}}, proxyOwnerMount+downTestFilePath)
	if got := resp.Data.RawURL; got != expected {
		t.Fatalf("expected raw_url %q, got %q", expected, got)
	}
}

func TestFsGet_RawURLMatchesFreshRequestLocalBalanceRouteAcrossThreeSiblings(t *testing.T) {
	baseMount := uniqueDownMountPath(t, "triple-balance")
	urlsByMount := map[string]string{
		baseMount:               "https://download.example.com/base.bin",
		baseMount + ".balance1": "https://download.example.com/balance1.bin",
		baseMount + ".balance2": "https://download.example.com/balance2.bin",
	}
	for mountPath, directURL := range urlsByMount {
		directURL := directURL
		mustCreateNonProxyDownStubStorage(t, mountPath, downStubBehavior{
			files: []string{downTestFilePath},
			link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
				return &model.Link{URL: directURL}, nil
			},
		}, model.Proxy{})
	}

	expectedRoute, err := op.ResolveWebDownloadRoutePreview(context.Background(), baseMount+downTestFilePath)
	if err != nil {
		t.Fatalf("expected preview route resolution success, got %v", err)
	}
	expectedURL, ok := urlsByMount[expectedRoute.LeafMountPath]
	if !ok {
		t.Fatalf("expected preview route to select one of the configured siblings, got leaf mount %q", expectedRoute.LeafMountPath)
	}

	resp := callFsGetHandler(t, baseMount+downTestFilePath)

	if got := resp.Data.RawURL; got != expectedURL {
		t.Fatalf("expected raw_url %q from fresh request-local route leaf %q, got %q", expectedURL, expectedRoute.LeafMountPath, got)
	}
}

func TestFsGet_RawURLUsesAbsoluteCanonicalPURLWhenEffectivePolicyIsNativeProxy(t *testing.T) {
	leafMount := uniqueDownMountPath(t, "leaf")
	mustCreateNonProxyDownStubStorage(t, leafMount, downStubBehavior{
		files: []string{downTestFilePath},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/native.bin"}, nil
		},
	}, model.Proxy{})

	nativeOwnerMount := uniqueDownMountPath(t, "native-owner")
	mustCreateAliasStorage(t, nativeOwnerMount, leafMount, model.Proxy{WebProxy: true})

	outerMount := uniqueDownMountPath(t, "outer")
	mustCreateAliasStorage(t, outerMount, nativeOwnerMount, model.Proxy{})

	resp := callFsGetHandler(t, outerMount+downTestFilePath)

	expected := canonicalTestProxyURL("https://example.test", nativeOwnerMount+downTestFilePath)
	if got := resp.Data.RawURL; got != expected {
		t.Fatalf("expected raw_url %q, got %q", expected, got)
	}
}

func TestFsGet_RawURLUsesSignedCanonicalPURLWhenNextHopRequiresIt(t *testing.T) {
	leafMount := uniqueDownMountPath(t, "leaf")
	mustCreateNonProxyDownStubStorage(t, leafMount, downStubBehavior{
		files: []string{downTestFilePath},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/native.bin"}, nil
		},
	}, model.Proxy{})

	nativeOwnerMount := uniqueDownMountPath(t, "native-owner")
	mustCreateLinkHandlerStorage(t, model.Storage{
		MountPath:  nativeOwnerMount,
		Driver:     "Alias",
		Addition:   mustMarshalLinkHandlerAddition(t, alias.Addition{Paths: leafMount, ProtectSameName: true}),
		EnableSign: true,
		Proxy:      model.Proxy{WebProxy: true},
	})

	outerMount := uniqueDownMountPath(t, "outer")
	mustCreateAliasStorage(t, outerMount, nativeOwnerMount, model.Proxy{})

	resp := callFsGetHandler(t, outerMount+downTestFilePath)

	expected := canonicalSignedTestProxyURL("https://example.test", nativeOwnerMount+downTestFilePath)
	if got := resp.Data.RawURL; got != expected {
		t.Fatalf("expected raw_url %q, got %q", expected, got)
	}
}

func TestFsGet_RawURLNativeProxyUsesNextHopBalanceOwnerSignRequirement(t *testing.T) {
	balanceMount := uniqueDownMountPath(t, "balance-owner-raw-url-sign")
	mustCreateNonProxyDownStubStorageWithSign(t, balanceMount, downStubBehavior{
		files: []string{downTestFilePath},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/base-signed-native.bin"}, nil
		},
	}, true, model.Proxy{WebProxy: true})
	mustCreateNonProxyDownStubStorage(t, balanceMount+".balance", downStubBehavior{
		files: []string{downTestFilePath},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/balance-unsigned-native.bin"}, nil
		},
	}, model.Proxy{WebProxy: true})

	_ = callFsGetHandler(t, balanceMount+downTestFilePath)

	previewRoute, err := op.ResolveWebDownloadRoutePreview(context.Background(), balanceMount+downTestFilePath)
	if err != nil {
		t.Fatalf("expected preview route resolution success, got %v", err)
	}
	if got, want := previewRoute.PolicyOwnerStorage.GetStorage().MountPath, balanceMount; got != want {
		t.Fatalf("expected second request to pin signed owner %q, got %q", want, got)
	}

	resp := callFsGetHandler(t, balanceMount+downTestFilePath)
	nextHopPreview, err := op.ResolveWebDownloadRoutePreview(context.Background(), balanceMount+downTestFilePath)
	if err != nil {
		t.Fatalf("expected next-hop preview route resolution success, got %v", err)
	}
	if got, want := nextHopPreview.PolicyOwnerStorage.GetStorage().MountPath, balanceMount+".balance"; got != want {
		t.Fatalf("expected fresh next hop to rotate to unsigned owner %q, got %q", want, got)
	}

	expected := canonicalTestProxyURL("https://example.test", balanceMount+downTestFilePath)
	if got := resp.Data.RawURL; got != expected {
		t.Fatalf("expected raw_url %q using next-hop sign requirement after current signed owner %q, got %q", expected, previewRoute.PolicyOwnerStorage.GetStorage().MountPath, got)
	}
}

func TestFsGet_RawURLNativeProxyPreservesTypeQuery(t *testing.T) {
	leafMount := uniqueDownMountPath(t, "leaf")
	mustCreateNonProxyDownStubStorage(t, leafMount, downStubBehavior{
		files: []string{downTestFilePath},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/native.bin"}, nil
		},
	}, model.Proxy{})

	nativeOwnerMount := uniqueDownMountPath(t, "native-owner")
	mustCreateAliasStorage(t, nativeOwnerMount, leafMount, model.Proxy{WebProxy: true})

	outerMount := uniqueDownMountPath(t, "outer")
	mustCreateAliasStorage(t, outerMount, nativeOwnerMount, model.Proxy{})

	resp := callFsGetHandlerWithQuery(t, outerMount+downTestFilePath, "type=download")

	expected := canonicalTestProxyURLWithQuery("https://example.test", nativeOwnerMount+downTestFilePath, url.Values{"type": {"download"}})
	if got := resp.Data.RawURL; got != expected {
		t.Fatalf("expected raw_url %q, got %q", expected, got)
	}
}

func TestFsGet_RawURLUsesLeafUpstreamURLWhenEffectivePolicyIsRedirect302(t *testing.T) {
	leafMount := uniqueDownMountPath(t, "leaf")
	mustCreateNonProxyDownStubStorage(t, leafMount, downStubBehavior{
		files: []string{downTestFilePath},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/direct.bin"}, nil
		},
	}, model.Proxy{})

	outerMount := uniqueDownMountPath(t, "outer")
	mustCreateAliasStorage(t, outerMount, leafMount, model.Proxy{})

	resp := callFsGetHandler(t, outerMount+downTestFilePath)

	if got, want := resp.Data.RawURL, "https://download.example.com/direct.bin"; got != want {
		t.Fatalf("expected raw_url %q, got %q", want, got)
	}
}

func TestFsGet_RawURLRedirect302PassesTypeToLeafLink(t *testing.T) {
	leafMount := uniqueDownMountPath(t, "leaf")
	leaf := mustCreateNonProxyDownStubStorage(t, leafMount, downStubBehavior{
		files: []string{downTestFilePath},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/direct.bin"}, nil
		},
	}, model.Proxy{})

	outerMount := uniqueDownMountPath(t, "outer")
	mustCreateAliasStorage(t, outerMount, leafMount, model.Proxy{})

	resp := callFsGetHandlerWithQuery(t, outerMount+downTestFilePath, "type=preview")

	if got, want := resp.Data.RawURL, "https://download.example.com/direct.bin"; got != want {
		t.Fatalf("expected raw_url %q, got %q", want, got)
	}
	if got, want := leaf.lastLinkArgs.Type, "preview"; got != want {
		t.Fatalf("expected leaf Link type %q, got %q", want, got)
	}
}

func TestFsGet_RawURLMatchesDownRedirect302ForwardedQueryWhenEnabled(t *testing.T) {
	forwardSetting, forwardExisted := mustGetOrCreateDownSettingItem(t, conf.ForwardDirectLinkParams, "false")
	ignoreSetting, ignoreExisted := mustGetOrCreateDownSettingItem(t, conf.IgnoreDirectLinkParams, "sign,openlist_ts,raw")
	t.Cleanup(func() {
		if forwardExisted {
			mustSaveDownSettingItem(t, forwardSetting)
		} else {
			mustSaveDownSettingItem(t, model.SettingItem{Key: conf.ForwardDirectLinkParams, Value: "false"})
		}
		if ignoreExisted {
			mustSaveDownSettingItem(t, ignoreSetting)
		} else {
			mustSaveDownSettingItem(t, model.SettingItem{Key: conf.IgnoreDirectLinkParams, Value: "sign,openlist_ts,raw"})
		}
	})

	forwardSetting.Value = "true"
	mustSaveDownSettingItem(t, forwardSetting)
	ignoreSetting.Value = "sign,openlist_ts,raw"
	mustSaveDownSettingItem(t, ignoreSetting)

	leafMount := uniqueDownMountPath(t, "leaf-forwarded-raw-url")
	mustCreateNonProxyDownStubStorage(t, leafMount, downStubBehavior{
		files: []string{downTestFilePath},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/direct.bin?from=leaf"}, nil
		},
	}, model.Proxy{})

	outerMount := uniqueDownMountPath(t, "outer-forwarded-raw-url")
	mustCreateAliasStorage(t, outerMount, leafMount, model.Proxy{})

	query := "token=abc&raw=true"
	downResp := callDownHandler(t, outerMount+downTestFilePath, query)
	if got, want := downResp.Code, http.StatusFound; got != want {
		t.Fatalf("expected /d redirect HTTP %d, got %d with body %s", want, got, downResp.Body.String())
	}

	expected := "https://download.example.com/direct.bin?from=leaf&token=abc"
	if got := downResp.Header().Get("Location"); got != expected {
		t.Fatalf("expected /d redirect location %q, got %q", expected, got)
	}

	fsGetResp := callFsGetHandlerWithQuery(t, outerMount+downTestFilePath, query)
	if got := fsGetResp.Data.RawURL; got != expected {
		t.Fatalf("expected raw_url %q to match /d redirect semantics, got %q", expected, got)
	}
}

func TestFsGet_RawURLRejectsLeafRelativeURLWhenEffectivePolicyIsRedirect302(t *testing.T) {
	leafMount := uniqueDownMountPath(t, "leaf")
	mustCreateNonProxyDownStubStorage(t, leafMount, downStubBehavior{
		files: []string{downTestFilePath},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "relative/file.bin"}, nil
		},
	}, model.Proxy{})

	outerMount := uniqueDownMountPath(t, "outer")
	mustCreateAliasStorage(t, outerMount, leafMount, model.Proxy{})

	resp := callFsGetHandlerExpectCode(t, outerMount+downTestFilePath, 500)
	if resp.Data.RawURL != "" {
		t.Fatalf("expected empty raw_url when redirect target is invalid, got %q", resp.Data.RawURL)
	}
}

func TestFsGet_RawURLRejectsMalformedExternalProxyURL(t *testing.T) {
	leafMount := uniqueDownMountPath(t, "leaf")
	mustCreateDownStubStorage(t, leafMount, downStubBehavior{
		files: []string{downTestFilePath},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{MFile: strings.NewReader("proxy-leaf-body")}, nil
		},
	}, model.Proxy{})

	proxyOwnerMount := uniqueDownMountPath(t, "proxy-owner-invalid")
	mustCreateAliasStorage(t, proxyOwnerMount, leafMount, model.Proxy{DownProxyURL: "https://"})

	resp := callFsGetHandlerExpectCode(t, proxyOwnerMount+downTestFilePath, 500)
	if resp.Data.RawURL != "" {
		t.Fatalf("expected empty raw_url for malformed external proxy URL, got %q", resp.Data.RawURL)
	}
	if !strings.Contains(resp.Message, "https://") {
		t.Fatalf("expected error message to mention malformed proxy base, got %q", resp.Message)
	}
}

func TestFsGet_ProviderUsesPinnedAliasPassThroughSiblingAcrossThreeSiblings(t *testing.T) {
	baseMount := uniqueDownMountPath(t, "provider-triple-balance")
	fixtures := map[string]struct {
		rawURL   string
		size     int64
		provider string
		create   func(*testing.T, string, downStubBehavior) *downStubDriver
	}{
		baseMount: {
			rawURL:   "https://download.example.com/provider-base.bin",
			size:     101,
			provider: downProxyDriverName,
			create: func(t *testing.T, mountPath string, behavior downStubBehavior) *downStubDriver {
				return mustCreateDownStubStorage(t, mountPath, behavior, model.Proxy{})
			},
		},
		baseMount + ".balance1": {
			rawURL:   "https://download.example.com/provider-balance1.bin",
			size:     202,
			provider: downNoProxyDriverName,
			create: func(t *testing.T, mountPath string, behavior downStubBehavior) *downStubDriver {
				return mustCreateNonProxyDownStubStorage(t, mountPath, behavior, model.Proxy{})
			},
		},
		baseMount + ".balance2": {
			rawURL:   "https://download.example.com/provider-balance2.bin",
			size:     303,
			provider: downProxyDriverName,
			create: func(t *testing.T, mountPath string, behavior downStubBehavior) *downStubDriver {
				return mustCreateDownStubStorage(t, mountPath, behavior, model.Proxy{})
			},
		},
	}
	for mountPath, fixture := range fixtures {
		fixture := fixture
		fixture.create(t, mountPath, downStubBehavior{
			files:     []string{downTestFilePath},
			fileSizes: map[string]int64{downTestFilePath: fixture.size},
			link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
				return &model.Link{URL: fixture.rawURL}, nil
			},
		})
	}

	aliasMount := uniqueDownMountPath(t, "provider-pass-through")
	mustCreateLinkHandlerStorage(t, model.Storage{
		MountPath: aliasMount,
		Driver:    "Alias",
		Addition: mustMarshalLinkHandlerAddition(t, alias.Addition{
			Paths:               baseMount,
			ProtectSameName:     true,
			ProviderPassThrough: true,
		}),
	})

	previewRoute, err := op.ResolveWebDownloadRoutePreview(context.Background(), aliasMount+downTestFilePath)
	if err != nil {
		t.Fatalf("expected preview route resolution success, got %v", err)
	}
	expectedFixture, ok := fixtures[previewRoute.LeafMountPath]
	if !ok {
		t.Fatalf("expected preview route to select one of the configured siblings, got leaf mount %q", previewRoute.LeafMountPath)
	}

	resp := callFsGetHandler(t, aliasMount+downTestFilePath)

	if got, want := resp.Data.RawURL, expectedFixture.rawURL; got != want {
		t.Fatalf("expected raw_url %q from pinned sibling %q, got %q", want, previewRoute.LeafMountPath, got)
	}
	if got, want := resp.Data.Size, expectedFixture.size; got != want {
		t.Fatalf("expected object size %d from pinned sibling %q, got %d", want, previewRoute.LeafMountPath, got)
	}
	if got, want := resp.Data.Provider, expectedFixture.provider; got != want {
		t.Fatalf("expected provider %q from pinned sibling %q, got %q", want, previewRoute.LeafMountPath, got)
	}
}

func TestFsGet_ProviderPassThroughDoesNotConsumeExtraAuthoritativeBalanceAdvance(t *testing.T) {
	baseMount := uniqueDownMountPath(t, "provider-triple-advance")
	fixtures := map[string]struct {
		rawURL   string
		size     int64
		provider string
		create   func(*testing.T, string, downStubBehavior) *downStubDriver
	}{
		baseMount: {
			rawURL:   "https://download.example.com/provider-base.bin",
			size:     101,
			provider: downProxyDriverName,
			create: func(t *testing.T, mountPath string, behavior downStubBehavior) *downStubDriver {
				return mustCreateDownStubStorage(t, mountPath, behavior, model.Proxy{})
			},
		},
		baseMount + ".balance1": {
			rawURL:   "https://download.example.com/provider-balance1.bin",
			size:     202,
			provider: downNoProxyDriverName,
			create: func(t *testing.T, mountPath string, behavior downStubBehavior) *downStubDriver {
				return mustCreateNonProxyDownStubStorage(t, mountPath, behavior, model.Proxy{})
			},
		},
		baseMount + ".balance2": {
			rawURL:   "https://download.example.com/provider-balance2.bin",
			size:     303,
			provider: downProxyDriverName,
			create: func(t *testing.T, mountPath string, behavior downStubBehavior) *downStubDriver {
				return mustCreateDownStubStorage(t, mountPath, behavior, model.Proxy{})
			},
		},
	}
	for mountPath, fixture := range fixtures {
		fixture := fixture
		fixture.create(t, mountPath, downStubBehavior{
			files:     []string{downTestFilePath},
			fileSizes: map[string]int64{downTestFilePath: fixture.size},
			link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
				return &model.Link{URL: fixture.rawURL}, nil
			},
		})
	}

	aliasMount := uniqueDownMountPath(t, "provider-pass-through")
	mustCreateLinkHandlerStorage(t, model.Storage{
		MountPath: aliasMount,
		Driver:    "Alias",
		Addition: mustMarshalLinkHandlerAddition(t, alias.Addition{
			Paths:               baseMount,
			ProtectSameName:     true,
			ProviderPassThrough: true,
		}),
	})

	beforeRoute, err := op.ResolveWebDownloadRoutePreview(context.Background(), aliasMount+downTestFilePath)
	if err != nil {
		t.Fatalf("expected pre-request preview success, got %v", err)
	}
	if got, want := beforeRoute.LeafMountPath, baseMount+".balance1"; got != want {
		t.Fatalf("expected first authoritative selection preview %q, got %q", want, got)
	}

	resp := callFsGetHandler(t, aliasMount+downTestFilePath)
	if got, want := resp.Data.Provider, fixtures[beforeRoute.LeafMountPath].provider; got != want {
		t.Fatalf("expected provider %q from the first authoritative selection, got %q", want, got)
	}
	if got, want := resp.Data.Size, fixtures[beforeRoute.LeafMountPath].size; got != want {
		t.Fatalf("expected object size %d from the first authoritative selection, got %d", want, got)
	}

	afterRoute, err := op.ResolveWebDownloadRoutePreview(context.Background(), aliasMount+downTestFilePath)
	if err != nil {
		t.Fatalf("expected post-request preview success, got %v", err)
	}
	if got, want := afterRoute.LeafMountPath, baseMount+".balance2"; got != want {
		t.Fatalf("expected next authoritative preview %q after one FsGet request, got %q", want, got)
	}
}

func TestFsGet_RelatedUsesSamePinnedSiblingAsRawURLAcrossThreeSiblings(t *testing.T) {
	baseMount := uniqueDownMountPath(t, "related-triple-balance")
	fixtures := map[string]struct {
		rawURL       string
		relatedNames []string
	}{
		baseMount: {
			rawURL:       "https://download.example.com/base-episode.mkv",
			relatedNames: []string{"episode-base.ass", "episode-base.srt"},
		},
		baseMount + ".balance1": {
			rawURL:       "https://download.example.com/balance1-episode.mkv",
			relatedNames: []string{"episode-balance1.ass", "episode-balance1.srt"},
		},
		baseMount + ".balance2": {
			rawURL:       "https://download.example.com/balance2-episode.mkv",
			relatedNames: []string{"episode-balance2.ass", "episode-balance2.srt"},
		},
	}
	for mountPath, fixture := range fixtures {
		fixture := fixture
		files := []string{"/episode.mkv", "/unrelated.txt"}
		for _, relatedName := range fixture.relatedNames {
			files = append(files, "/"+relatedName)
		}
		mustCreateNonProxyDownStubStorage(t, mountPath, downStubBehavior{
			files: files,
			link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
				return &model.Link{URL: fixture.rawURL}, nil
			},
		}, model.Proxy{})
	}

	previewRoute, err := op.ResolveWebDownloadRoutePreview(context.Background(), baseMount+"/episode.mkv")
	if err != nil {
		t.Fatalf("expected preview route resolution success, got %v", err)
	}
	if got, want := previewRoute.LeafMountPath, baseMount+".balance1"; got != want {
		t.Fatalf("expected fresh request to pin sibling %q, got %q", want, got)
	}
	expectedFixture := fixtures[previewRoute.LeafMountPath]

	resp := callFsGetHandler(t, baseMount+"/episode.mkv")

	if got, want := resp.Data.RawURL, expectedFixture.rawURL; got != want {
		t.Fatalf("expected raw_url %q from pinned sibling %q, got %q", want, previewRoute.LeafMountPath, got)
	}
	gotRelatedNames := objRespNames(resp.Data.Related)
	if got, want := strings.Join(gotRelatedNames, ","), strings.Join(expectedFixture.relatedNames, ","); got != want {
		t.Fatalf("expected related names %q from pinned sibling %q, got %q", want, previewRoute.LeafMountPath, got)
	}
}

func TestFsGet_RelatedDoesNotConsumeExtraAuthoritativeBalanceAdvance(t *testing.T) {
	baseMount := uniqueDownMountPath(t, "related-triple-advance")
	for mountPath, rawURL := range map[string]string{
		baseMount:               "https://download.example.com/base-episode.mkv",
		baseMount + ".balance1": "https://download.example.com/balance1-episode.mkv",
		baseMount + ".balance2": "https://download.example.com/balance2-episode.mkv",
	} {
		rawURL := rawURL
		mustCreateNonProxyDownStubStorage(t, mountPath, downStubBehavior{
			files: []string{"/episode.mkv", "/episode-sidecar.srt"},
			link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
				return &model.Link{URL: rawURL}, nil
			},
		}, model.Proxy{})
	}

	beforeRoute, err := op.ResolveWebDownloadRoutePreview(context.Background(), baseMount+"/episode.mkv")
	if err != nil {
		t.Fatalf("expected pre-request preview success, got %v", err)
	}
	if got, want := beforeRoute.LeafMountPath, baseMount+".balance1"; got != want {
		t.Fatalf("expected first authoritative selection preview %q, got %q", want, got)
	}

	resp := callFsGetHandler(t, baseMount+"/episode.mkv")
	if got, want := resp.Data.RawURL, "https://download.example.com/balance1-episode.mkv"; got != want {
		t.Fatalf("expected raw_url %q from the first authoritative selection, got %q", want, got)
	}

	afterRoute, err := op.ResolveWebDownloadRoutePreview(context.Background(), baseMount+"/episode.mkv")
	if err != nil {
		t.Fatalf("expected post-request preview success, got %v", err)
	}
	if got, want := afterRoute.LeafMountPath, baseMount+".balance2"; got != want {
		t.Fatalf("expected next authoritative preview %q after one FsGet request, got %q", want, got)
	}
}

func TestFsGet_SignUsesPinnedUnsignedSiblingInsteadOfNextSignedPreview(t *testing.T) {
	baseMount := uniqueDownMountPath(t, "sign-triple-unsigned-first")
	middlewareMount := uniqueDownMountPath(t, "sign-middleware-proof")
	fixtures := map[string]struct {
		rawURL       string
		relatedNames []string
		enableSign   bool
	}{
		baseMount: {
			rawURL:       "https://download.example.com/base-episode.mkv",
			relatedNames: []string{"episode-base.ass", "episode-base.srt"},
			enableSign:   false,
		},
		baseMount + ".balance1": {
			rawURL:       "https://download.example.com/balance1-episode.mkv",
			relatedNames: []string{"episode-balance1.ass", "episode-balance1.srt"},
			enableSign:   false,
		},
		baseMount + ".balance2": {
			rawURL:       "https://download.example.com/balance2-episode.mkv",
			relatedNames: []string{"episode-balance2.ass", "episode-balance2.srt"},
			enableSign:   true,
		},
	}
	for mountPath, fixture := range fixtures {
		fixture := fixture
		files := []string{"/episode.mkv", "/unrelated.txt"}
		for _, relatedName := range fixture.relatedNames {
			files = append(files, "/"+relatedName)
		}
		mustCreateNonProxyDownStubStorageWithSign(t, mountPath, downStubBehavior{
			files: files,
			link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
				return &model.Link{URL: fixture.rawURL}, nil
			},
		}, fixture.enableSign, model.Proxy{})
	}
	for mountPath, fixture := range map[string]struct {
		rawURL       string
		relatedNames []string
		enableSign   bool
	}{
		middlewareMount: {
			rawURL:       "https://download.example.com/base-episode.mkv",
			relatedNames: []string{"episode-base.ass", "episode-base.srt"},
			enableSign:   false,
		},
		middlewareMount + ".balance1": {
			rawURL:       "https://download.example.com/balance1-episode.mkv",
			relatedNames: []string{"episode-balance1.ass", "episode-balance1.srt"},
			enableSign:   false,
		},
		middlewareMount + ".balance2": {
			rawURL:       "https://download.example.com/balance2-episode.mkv",
			relatedNames: []string{"episode-balance2.ass", "episode-balance2.srt"},
			enableSign:   true,
		},
	} {
		fixture := fixture
		files := []string{"/episode.mkv", "/unrelated.txt"}
		for _, relatedName := range fixture.relatedNames {
			files = append(files, "/"+relatedName)
		}
		mustCreateNonProxyDownStubStorageWithSign(t, mountPath, downStubBehavior{
			files: files,
			link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
				return &model.Link{URL: fixture.rawURL}, nil
			},
		}, fixture.enableSign, model.Proxy{})
	}

	previewRoute, err := op.ResolveWebDownloadRoutePreview(context.Background(), baseMount+"/episode.mkv")
	if err != nil {
		t.Fatalf("expected preview route resolution success, got %v", err)
	}
	if got, want := previewRoute.LeafMountPath, baseMount+".balance1"; got != want {
		t.Fatalf("expected first pinned sibling %q, got %q", want, got)
	}
	expectedFixture := fixtures[previewRoute.LeafMountPath]

	resp := callFsGetHandler(t, baseMount+"/episode.mkv")

	if got, want := resp.Data.RawURL, expectedFixture.rawURL; got != want {
		t.Fatalf("expected raw_url %q from pinned sibling %q, got %q", want, previewRoute.LeafMountPath, got)
	}
	gotRelatedNames := objRespNames(resp.Data.Related)
	if got, want := strings.Join(gotRelatedNames, ","), strings.Join(expectedFixture.relatedNames, ","); got != want {
		t.Fatalf("expected related names %q from pinned sibling %q, got %q", want, previewRoute.LeafMountPath, got)
	}
	if got := resp.Data.Sign; got != "" {
		t.Fatalf("expected empty main sign from unsigned pinned sibling %q, got %q", previewRoute.LeafMountPath, got)
	}
	for _, related := range resp.Data.Related {
		if related.Sign != "" {
			t.Fatalf("expected empty related sign for %q from unsigned pinned sibling %q, got %q", related.Name, previewRoute.LeafMountPath, related.Sign)
		}
	}

	ctx := op.EnsureLinkAPIBalanceStateForRequest(context.Background())
	ctx, needSign, err := common.IsPathSignRequiredForRequest(ctx, middlewareMount+"/episode.mkv")
	if err != nil {
		t.Fatalf("expected request-local sign check success, got %v", err)
	}
	if needSign {
		t.Fatalf("expected request-local sign requirement to stay false for first pinned middleware sibling under %q", middlewareMount)
	}
	route, err := op.ResolveWebDownloadRoute(ctx, middlewareMount+"/episode.mkv")
	if err != nil {
		t.Fatalf("expected request-local route resolution success, got %v", err)
	}
	if got, want := route.LeafMountPath, middlewareMount+".balance1"; got != want {
		t.Fatalf("expected middleware request-local route to pin sibling %q, got %q", want, got)
	}
	_, parentNeedSign, err := common.IsPathSignRequiredForRequest(ctx, middlewareMount)
	if err != nil {
		t.Fatalf("expected request-local parent sign check success, got %v", err)
	}
	if parentNeedSign {
		t.Fatalf("expected related-item sign requirement to stay false for pinned middleware sibling %q", middlewareMount+".balance1")
	}
}

func TestFsGet_SignUsesPinnedSignedSiblingInsteadOfNextUnsignedPreview(t *testing.T) {
	baseMount := uniqueDownMountPath(t, "sign-triple-signed-second")
	fixtures := map[string]struct {
		rawURL       string
		relatedNames []string
		enableSign   bool
	}{
		baseMount: {
			rawURL:       "https://download.example.com/base-episode.mkv",
			relatedNames: []string{"episode-base.ass", "episode-base.srt"},
			enableSign:   false,
		},
		baseMount + ".balance1": {
			rawURL:       "https://download.example.com/balance1-episode.mkv",
			relatedNames: []string{"episode-balance1.ass", "episode-balance1.srt"},
			enableSign:   false,
		},
		baseMount + ".balance2": {
			rawURL:       "https://download.example.com/balance2-episode.mkv",
			relatedNames: []string{"episode-balance2.ass", "episode-balance2.srt"},
			enableSign:   true,
		},
	}
	for mountPath, fixture := range fixtures {
		fixture := fixture
		files := []string{"/episode.mkv", "/unrelated.txt"}
		for _, relatedName := range fixture.relatedNames {
			files = append(files, "/"+relatedName)
		}
		mustCreateNonProxyDownStubStorageWithSign(t, mountPath, downStubBehavior{
			files: files,
			link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
				return &model.Link{URL: fixture.rawURL}, nil
			},
		}, fixture.enableSign, model.Proxy{})
	}

	firstPreview, err := op.ResolveWebDownloadRoutePreview(context.Background(), baseMount+"/episode.mkv")
	if err != nil {
		t.Fatalf("expected first preview route resolution success, got %v", err)
	}
	if got, want := firstPreview.LeafMountPath, baseMount+".balance1"; got != want {
		t.Fatalf("expected first pinned sibling %q, got %q", want, got)
	}
	_ = callFsGetHandler(t, baseMount+"/episode.mkv")

	secondPreview, err := op.ResolveWebDownloadRoutePreview(context.Background(), baseMount+"/episode.mkv")
	if err != nil {
		t.Fatalf("expected second preview route resolution success, got %v", err)
	}
	if got, want := secondPreview.LeafMountPath, baseMount+".balance2"; got != want {
		t.Fatalf("expected second pinned sibling %q, got %q", want, got)
	}
	expectedFixture := fixtures[secondPreview.LeafMountPath]

	resp := callFsGetHandler(t, baseMount+"/episode.mkv")

	if got, want := resp.Data.RawURL, expectedFixture.rawURL; got != want {
		t.Fatalf("expected raw_url %q from pinned sibling %q, got %q", want, secondPreview.LeafMountPath, got)
	}
	gotRelatedNames := objRespNames(resp.Data.Related)
	if got, want := strings.Join(gotRelatedNames, ","), strings.Join(expectedFixture.relatedNames, ","); got != want {
		t.Fatalf("expected related names %q from pinned sibling %q, got %q", want, secondPreview.LeafMountPath, got)
	}
	expectedMainSign := sign.Sign(baseMount + "/episode.mkv")
	if got, want := resp.Data.Sign, expectedMainSign; got != want {
		t.Fatalf("expected main sign %q from signed pinned sibling %q, got %q", want, secondPreview.LeafMountPath, got)
	}
	for _, related := range resp.Data.Related {
		expectedRelatedSign := sign.Sign(baseMount + "/" + related.Name)
		if related.Sign != expectedRelatedSign {
			t.Fatalf("expected related sign %q for %q from signed pinned sibling %q, got %q", expectedRelatedSign, related.Name, secondPreview.LeafMountPath, related.Sign)
		}
	}
}

func TestProxyHandler_ProxyURLOwnerWithD1UsesLeafPathWhilePreservingOwnerCanonicalPath(t *testing.T) {
	leafBaseMount := uniqueDownMountPath(t, "leaf-owner-separation")
	leafOne := mustCreateDownStubStorage(t, leafBaseMount, downStubBehavior{
		files: []string{downTestFilePath},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{MFile: strings.NewReader("member-one-body")}, nil
		},
	}, model.Proxy{})
	leafTwo := mustCreateDownStubStorage(t, leafBaseMount+".balance", downStubBehavior{
		files: []string{downTestFilePath},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{MFile: strings.NewReader("member-two-body")}, nil
		},
	}, model.Proxy{})

	proxyOwnerMount := uniqueDownMountPath(t, "proxy-owner-separation")
	mustCreateAliasStorage(t, proxyOwnerMount, leafBaseMount, model.Proxy{DownProxyURL: "https://proxy.example.com"})

	resp := callProxyHandler(t, proxyOwnerMount+downTestFilePath, "d=1")

	if got, want := resp.Code, http.StatusOK; got != want {
		t.Fatalf("expected HTTP %d, got %d with body %s", want, got, resp.Body.String())
	}
	if got := resp.Header().Get("Location"); got != "" {
		t.Fatalf("expected no redirect after canonical owner path, got %q", got)
	}
	switch got := resp.Body.String(); got {
	case "member-one-body":
		if got, want := leafOne.linkCalls, 1; got != want {
			t.Fatalf("expected selected leaf-one member link call count %d, got %d", want, got)
		}
		if got := leafTwo.linkCalls; got != 0 {
			t.Fatalf("expected non-selected leaf-two member to stay unused, got %d link calls", got)
		}
	case "member-two-body":
		if got := leafOne.linkCalls; got != 0 {
			t.Fatalf("expected non-selected leaf-one member to stay unused, got %d link calls", got)
		}
		if got, want := leafTwo.linkCalls, 1; got != want {
			t.Fatalf("expected selected leaf-two member link call count %d, got %d", want, got)
		}
	default:
		t.Fatalf("expected streamed body from exactly one resolved leaf member, got %q", got)
	}
}

func TestProxyHandler_NativeProxyOwnerProxyRangeUsesOwnerSettingWhenLeafDisablesRange(t *testing.T) {
	body := "proxy-range-body"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = io.WriteString(w, body)
	}))
	defer upstream.Close()

	leafMount := uniqueDownMountPath(t, "leaf-range-off")
	mustCreateNonProxyDownStubStorage(t, leafMount, downStubBehavior{
		files: []string{downTestFilePath},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: upstream.URL + "/file.bin", ContentLength: int64(len(body))}, nil
		},
	}, model.Proxy{})

	nativeOwnerMount := uniqueDownMountPath(t, "native-owner-range-on")
	mustCreateLinkHandlerStorage(t, model.Storage{
		MountPath: nativeOwnerMount,
		Driver:    "Alias",
		Addition:  mustMarshalLinkHandlerAddition(t, alias.Addition{Paths: leafMount, ProtectSameName: true}),
		Proxy: model.Proxy{
			WebProxy:   true,
			ProxyRange: true,
		},
	})

	resp := callProxyHandlerWithHeaders(t, nativeOwnerMount+downTestFilePath, "", http.Header{"Range": {"bytes=0-3"}})

	if got, want := resp.Code, http.StatusPartialContent; got != want {
		t.Fatalf("expected HTTP %d, got %d with body %s", want, got, resp.Body.String())
	}
	if got, want := resp.Body.String(), body[:4]; got != want {
		t.Fatalf("expected ranged body %q, got %q", want, got)
	}
}

func TestProxyHandler_NativeProxyOwnerProxyRangeIgnoresLeafSettingWhenOwnerDisablesRange(t *testing.T) {
	body := "proxy-range-body"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = io.WriteString(w, body)
	}))
	defer upstream.Close()

	leafMount := uniqueDownMountPath(t, "leaf-range-on")
	mustCreateNonProxyDownStubStorage(t, leafMount, downStubBehavior{
		files: []string{downTestFilePath},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: upstream.URL + "/file.bin", ContentLength: int64(len(body))}, nil
		},
	}, model.Proxy{ProxyRange: true})

	nativeOwnerMount := uniqueDownMountPath(t, "native-owner-range-off")
	mustCreateAliasStorage(t, nativeOwnerMount, leafMount, model.Proxy{WebProxy: true})

	resp := callProxyHandlerWithHeaders(t, nativeOwnerMount+downTestFilePath, "", http.Header{"Range": {"bytes=0-3"}})

	if got, want := resp.Code, http.StatusOK; got != want {
		t.Fatalf("expected HTTP %d, got %d with body %s", want, got, resp.Body.String())
	}
	if got, want := resp.Body.String(), body; got != want {
		t.Fatalf("expected transparent proxy body %q, got %q", want, got)
	}
}

type fsGetEnvelope struct {
	Code    int       `json:"code"`
	Message string    `json:"message"`
	Data    FsGetResp `json:"data"`
}

func callDownHandler(t *testing.T, rawPath, rawQuery string) *httptest.ResponseRecorder {
	t.Helper()
	return callDownloadEntry(t, http.MethodGet, "/d"+utils.EncodePath(rawPath, true), rawPath, rawQuery, Down)
}

func callDownHandlerWithAPI(t *testing.T, rawPath, rawQuery, apiURL string) *httptest.ResponseRecorder {
	t.Helper()
	return callDownloadEntryWithAPI(t, http.MethodGet, "/d"+utils.EncodePath(rawPath, true), rawPath, rawQuery, apiURL, Down)
}

func callProxyHandler(t *testing.T, rawPath, rawQuery string) *httptest.ResponseRecorder {
	t.Helper()
	return callDownloadEntry(t, http.MethodGet, "/p"+utils.EncodePath(rawPath, true), rawPath, rawQuery, Proxy)
}

func callProxyHandlerWithAPI(t *testing.T, rawPath, rawQuery, apiURL string) *httptest.ResponseRecorder {
	t.Helper()
	return callDownloadEntryWithAPI(t, http.MethodGet, "/p"+utils.EncodePath(rawPath, true), rawPath, rawQuery, apiURL, Proxy)
}

func callProxyHandlerWithHeaders(t *testing.T, rawPath, rawQuery string, headers http.Header) *httptest.ResponseRecorder {
	t.Helper()
	return callDownloadEntryWithAPIAndHeaders(t, http.MethodGet, "/p"+utils.EncodePath(rawPath, true), rawPath, rawQuery, "https://example.test", headers, Proxy)
}

func callProxyHandlerThroughMiddleware(t *testing.T, rawPath, rawQuery string) *httptest.ResponseRecorder {
	t.Helper()
	return callDownloadRouteThroughMiddleware(t, http.MethodGet, "/p"+utils.EncodePath(rawPath, true), rawQuery, "https://example.test")
}

func callProxyHandlerThroughMiddlewareWithInterposer(t *testing.T, rawPath, rawQuery string, interposer gin.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	return callDownloadRouteWithInterposerThroughMiddleware(t, http.MethodGet, "/p/*path", "/p"+utils.EncodePath(rawPath, true), rawQuery, "https://example.test", Proxy, interposer)
}

func callArchiveDownHandlerThroughMiddleware(t *testing.T, rawPath, rawQuery string) *httptest.ResponseRecorder {
	t.Helper()
	return callArchiveRouteThroughMiddleware(t, http.MethodGet, "/ad/*path", "/ad"+utils.EncodePath(rawPath, true), rawQuery, ArchiveDown)
}

func callArchiveDownHandlerThroughMiddlewareWithInterposer(t *testing.T, rawPath, rawQuery string, interposer gin.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	return callArchiveRouteWithInterposerThroughMiddleware(t, http.MethodGet, "/ad/*path", "/ad"+utils.EncodePath(rawPath, true), rawQuery, ArchiveDown, interposer)
}

func callArchiveProxyHandlerThroughMiddleware(t *testing.T, rawPath, rawQuery string) *httptest.ResponseRecorder {
	t.Helper()
	return callArchiveRouteThroughMiddleware(t, http.MethodGet, "/ap/*path", "/ap"+utils.EncodePath(rawPath, true), rawQuery, ArchiveProxy)
}

func callArchiveProxyHandlerThroughMiddlewareWithInterposer(t *testing.T, rawPath, rawQuery string, interposer gin.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	return callArchiveRouteWithInterposerThroughMiddleware(t, http.MethodGet, "/ap/*path", "/ap"+utils.EncodePath(rawPath, true), rawQuery, ArchiveProxy, interposer)
}

func callArchiveInternalExtractHandlerThroughMiddlewareWithInterposer(t *testing.T, rawPath, rawQuery string, interposer gin.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	return callArchiveRouteWithInterposerThroughMiddleware(t, http.MethodGet, "/ae/*path", "/ae"+utils.EncodePath(rawPath, true), rawQuery, ArchiveInternalExtract, interposer)
}

func callDownHandlerThroughMiddlewareWithInterposer(t *testing.T, rawPath, rawQuery string, interposer gin.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	return callDownloadRouteWithInterposerThroughMiddleware(t, http.MethodGet, "/d/*path", "/d"+utils.EncodePath(rawPath, true), rawQuery, "https://example.test", Down, interposer)
}

func callDownloadLocationThroughMiddleware(t *testing.T, location string) *httptest.ResponseRecorder {
	t.Helper()
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatalf("failed to parse redirect location %q: %v", location, err)
	}
	apiURL := parsed.Scheme + "://" + parsed.Host
	return callDownloadRouteThroughMiddleware(t, http.MethodGet, parsed.EscapedPath(), parsed.RawQuery, apiURL)
}

func callDownloadRouteThroughMiddleware(t *testing.T, method, targetPath, rawQuery, apiURL string) *httptest.ResponseRecorder {
	t.Helper()
	return callDownloadRouteWithInterposerThroughMiddleware(t, method, "/p/*path", targetPath, rawQuery, apiURL, Proxy, nil)
}

func callArchiveRouteThroughMiddleware(t *testing.T, method, routePattern, targetPath, rawQuery string, handler gin.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	return callArchiveRouteWithInterposerThroughMiddleware(t, method, routePattern, targetPath, rawQuery, handler, nil)
}

func callArchiveRouteWithInterposerThroughMiddleware(t *testing.T, method, routePattern, targetPath, rawQuery string, handler gin.HandlerFunc, interposer gin.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	requestURL := targetPath
	if rawQuery != "" {
		requestURL += "?" + rawQuery
	}
	request, err := http.NewRequest(method, requestURL, nil)
	if err != nil {
		t.Fatalf("failed to build archive middleware request: %v", err)
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		common.GinWithValue(c, conf.ApiUrlKey, "https://example.test")
		c.Next()
	})
	handlers := []gin.HandlerFunc{middlewares.PathParse, middlewares.Down(sign.VerifyArchive)}
	if interposer != nil {
		handlers = append(handlers, interposer)
	}
	handlers = append(handlers, handler)
	router.GET(routePattern, handlers...)
	router.HEAD(routePattern, handlers...)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	return recorder
}

func callDownloadRouteWithInterposerThroughMiddleware(t *testing.T, method, routePattern, targetPath, rawQuery, apiURL string, handler gin.HandlerFunc, interposer gin.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	requestURL := targetPath
	if rawQuery != "" {
		requestURL += "?" + rawQuery
	}
	request, err := http.NewRequest(method, requestURL, nil)
	if err != nil {
		t.Fatalf("failed to build middleware route request: %v", err)
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		common.GinWithValue(c, conf.ApiUrlKey, apiURL)
		c.Next()
	})
	handlers := []gin.HandlerFunc{middlewares.PathParse, middlewares.Down(sign.Verify)}
	if interposer != nil {
		handlers = append(handlers, interposer)
	}
	handlers = append(handlers, handler)
	router.GET(routePattern, handlers...)
	router.HEAD(routePattern, handlers...)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	return recorder
}

func simulateConcurrentBalanceAdvance(t *testing.T) gin.HandlerFunc {
	t.Helper()
	return func(c *gin.Context) {
		rawPath := c.Request.Context().Value(conf.PathKey).(string)
		if _, err := op.ResolveWebDownloadRoute(context.Background(), rawPath); err != nil {
			t.Fatalf("failed to simulate concurrent balance advance for %q: %v", rawPath, err)
		}
		c.Next()
	}
}

func callDownloadEntry(t *testing.T, method, targetPath, rawPath, rawQuery string, handler func(*gin.Context)) *httptest.ResponseRecorder {
	t.Helper()
	return callDownloadEntryWithAPIAndHeaders(t, method, targetPath, rawPath, rawQuery, "https://example.test", nil, handler)
}

func callDownloadEntryWithAPI(t *testing.T, method, targetPath, rawPath, rawQuery, apiURL string, handler func(*gin.Context)) *httptest.ResponseRecorder {
	t.Helper()
	return callDownloadEntryWithAPIAndHeaders(t, method, targetPath, rawPath, rawQuery, apiURL, nil, handler)
}

func callDownloadEntryWithAPIAndHeaders(t *testing.T, method, targetPath, rawPath, rawQuery, apiURL string, headers http.Header, handler func(*gin.Context)) *httptest.ResponseRecorder {
	t.Helper()
	requestURL := targetPath
	if rawQuery != "" {
		requestURL += "?" + rawQuery
	}
	request, err := http.NewRequest(method, requestURL, nil)
	if err != nil {
		t.Fatalf("failed to build request: %v", err)
	}
	ctxWithPath := context.WithValue(request.Context(), conf.PathKey, rawPath)
	ctxWithAPI := context.WithValue(ctxWithPath, conf.ApiUrlKey, apiURL)
	request = request.WithContext(ctxWithAPI)
	if headers != nil {
		request.Header = headers.Clone()
	}

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = request

	handler(ctx)
	return recorder
}

func newCanonicalProxyURLTestContext(t *testing.T, meta *model.Meta) *gin.Context {
	t.Helper()

	request, err := http.NewRequest(http.MethodGet, "/p/test", nil)
	if err != nil {
		t.Fatalf("failed to build canonical proxy request: %v", err)
	}
	ctxWithAPI := context.WithValue(request.Context(), conf.ApiUrlKey, "https://example.test")
	if meta != nil {
		ctxWithAPI = context.WithValue(ctxWithAPI, conf.MetaKey, meta)
	}
	request = request.WithContext(ctxWithAPI)

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = request
	return ctx
}

func callFsGetHandler(t *testing.T, reqPath string) fsGetEnvelope {
	t.Helper()
	return callFsGetHandlerExpectCode(t, reqPath, 200)
}

func callFsGetHandlerWithQuery(t *testing.T, reqPath, rawQuery string) fsGetEnvelope {
	t.Helper()
	return callFsGetHandlerExpectCodeWithQuery(t, reqPath, rawQuery, 200)
}

func callFsGetHandlerExpectCode(t *testing.T, reqPath string, wantCode int) fsGetEnvelope {
	t.Helper()
	return callFsGetHandlerExpectCodeWithQuery(t, reqPath, "", wantCode)
}

func callFsGetHandlerExpectCodeWithQuery(t *testing.T, reqPath, rawQuery string, wantCode int) fsGetEnvelope {
	t.Helper()
	requestURL := "/api/fs/get?path=" + url.QueryEscape(reqPath)
	if rawQuery != "" {
		requestURL += "&" + rawQuery
	}
	request, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		t.Fatalf("failed to build request: %v", err)
	}
	ctxWithAPI := context.WithValue(request.Context(), conf.ApiUrlKey, "https://example.test")
	request = request.WithContext(ctxWithAPI)

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = request

	FsGet(ctx, &FsGetReq{Path: reqPath}, &model.User{Role: model.ADMIN, BasePath: "/"})

	var resp fsGetEnvelope
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response %s: %v", recorder.Body.String(), err)
	}
	if resp.Code != wantCode {
		t.Fatalf("expected response code %d, got %d with body %s", wantCode, resp.Code, recorder.Body.String())
	}
	return resp
}

func mustGetOrCreateDownSettingItem(t *testing.T, key, defaultValue string) (model.SettingItem, bool) {
	t.Helper()

	item, err := op.GetSettingItemByKey(key)
	if err == nil {
		return *item, true
	}
	created := model.SettingItem{Key: key, Value: defaultValue}
	mustSaveDownSettingItem(t, created)
	return created, false
}

func mustSaveDownSettingItem(t *testing.T, item model.SettingItem) {
	t.Helper()

	copy := item
	if err := op.SaveSettingItem(&copy); err != nil {
		t.Fatalf("failed to save setting %q: %v", item.Key, err)
	}
}

func mustCreateDownStubStorage(t *testing.T, mountPath string, behavior downStubBehavior, proxy model.Proxy) *downStubDriver {
	t.Helper()
	return mustCreateConfiguredDownStubStorage(t, mountPath, downProxyDriverName, proxyCapableDownStubConfig(), behavior, proxy)
}

func mustCreateNonProxyDownStubStorage(t *testing.T, mountPath string, behavior downStubBehavior, proxy model.Proxy) *downStubDriver {
	t.Helper()
	return mustCreateConfiguredDownStubStorage(t, mountPath, downNoProxyDriverName, nonProxyDownStubConfig(), behavior, proxy)
}

func mustCreateNonProxyDownStubStorageWithSign(t *testing.T, mountPath string, behavior downStubBehavior, enableSign bool, proxy model.Proxy) *downStubDriver {
	t.Helper()
	registerDownDriver(t, downNoProxyDriverName, nonProxyDownStubConfig())

	downFixtures.Lock()
	downFixtures.byMountPath[mountPath] = behavior
	downFixtures.Unlock()
	t.Cleanup(func() {
		downFixtures.Lock()
		delete(downFixtures.byMountPath, mountPath)
		downFixtures.Unlock()
	})

	drv := mustCreateLinkHandlerStorage(t, model.Storage{
		MountPath:  mountPath,
		Driver:     downNoProxyDriverName,
		Addition:   mustMarshalLinkHandlerAddition(t, driverpkg.RootPath{RootFolderPath: "/"}),
		EnableSign: enableSign,
		Proxy:      proxy,
	})

	stub, ok := drv.(*downStubDriver)
	if !ok {
		t.Fatalf("expected %q to be a *downStubDriver, got %T", mountPath, drv)
	}
	return stub
}

func mustCreateArchiveDownStubStorage(t *testing.T, mountPath string, behavior downStubBehavior, proxy model.Proxy) *downStubDriver {
	t.Helper()
	return mustCreateConfiguredDownStubStorage(t, mountPath, downNoProxyDriverName, nonProxyDownStubConfig(), behavior, proxy)
}

func mustCreateArchiveDownStubStorageWithSign(t *testing.T, mountPath string, behavior downStubBehavior, enableSign bool, proxy model.Proxy) *downStubDriver {
	t.Helper()
	registerDownDriver(t, downNoProxyDriverName, nonProxyDownStubConfig())

	downFixtures.Lock()
	downFixtures.byMountPath[mountPath] = behavior
	downFixtures.Unlock()
	t.Cleanup(func() {
		downFixtures.Lock()
		delete(downFixtures.byMountPath, mountPath)
		downFixtures.Unlock()
	})

	drv := mustCreateLinkHandlerStorage(t, model.Storage{
		MountPath:  mountPath,
		Driver:     downNoProxyDriverName,
		Addition:   mustMarshalLinkHandlerAddition(t, driverpkg.RootPath{RootFolderPath: "/"}),
		EnableSign: enableSign,
		Proxy:      proxy,
	})

	stub, ok := drv.(*downStubDriver)
	if !ok {
		t.Fatalf("expected %q to be a *downStubDriver, got %T", mountPath, drv)
	}
	return stub
}

func mustCreateAliasStorage(t *testing.T, mountPath, targetMount string, proxy model.Proxy) {
	t.Helper()
	mustCreateLinkHandlerStorage(t, model.Storage{
		MountPath: mountPath,
		Driver:    "Alias",
		Addition: mustMarshalLinkHandlerAddition(t, alias.Addition{
			Paths:           targetMount,
			ProtectSameName: true,
		}),
		Proxy: proxy,
	})
}

func mustCreateDownloadMeta(t *testing.T, meta model.Meta) *model.Meta {
	t.Helper()

	if err := op.CreateMeta(&meta); err != nil {
		t.Fatalf("failed to create meta for %q: %v", meta.Path, err)
	}
	created, err := op.GetMetaByPath(meta.Path)
	if err != nil {
		t.Fatalf("failed to load created meta for %q: %v", meta.Path, err)
	}
	t.Cleanup(func() {
		if err := op.DeleteMetaById(created.ID); err != nil {
			t.Fatalf("failed to delete meta %q: %v", meta.Path, err)
		}
	})
	return created
}

func uniqueDownMountPath(t *testing.T, suffix string) string {
	t.Helper()
	name := strings.ToLower(t.Name())
	replacer := strings.NewReplacer("/", "-", "_", "-", " ", "-")
	return "/test-down-handler/" + replacer.Replace(name) + "-" + suffix
}

func objRespNames(objs []ObjResp) []string {
	names := make([]string, 0, len(objs))
	for _, obj := range objs {
		names = append(names, obj.Name)
	}
	sort.Strings(names)
	return names
}

const downProxyDriverName = "TestDownHandlerProxyStub"
const downNoProxyDriverName = "TestDownHandlerNoProxyStub"

var registerDownProxyStubDriverOnce sync.Once
var registerDownNoProxyStubDriverOnce sync.Once

var downFixtures = struct {
	sync.Mutex
	byMountPath map[string]downStubBehavior
}{
	byMountPath: map[string]downStubBehavior{},
}

type downStubBehavior struct {
	files          []string
	fileSizes      map[string]int64
	link           func(model.Obj, model.LinkArgs) (*model.Link, error)
	linkErr        error
	archiveList    func(model.ArchiveInnerArgs) ([]model.Obj, error)
	archiveGet     func(model.ArchiveInnerArgs) (model.Obj, error)
	archiveExtract func(model.Obj, model.ArchiveInnerArgs) (*model.Link, error)
	afterGet       func(context.Context, string)
}

func mustCreateConfiguredDownStubStorage(t *testing.T, mountPath, driverName string, cfg driverpkg.Config, behavior downStubBehavior, proxy model.Proxy) *downStubDriver {
	t.Helper()
	registerDownDriver(t, driverName, cfg)

	downFixtures.Lock()
	downFixtures.byMountPath[mountPath] = behavior
	downFixtures.Unlock()
	t.Cleanup(func() {
		downFixtures.Lock()
		delete(downFixtures.byMountPath, mountPath)
		downFixtures.Unlock()
	})

	drv := mustCreateLinkHandlerStorage(t, model.Storage{
		MountPath: mountPath,
		Driver:    driverName,
		Addition:  mustMarshalLinkHandlerAddition(t, driverpkg.RootPath{RootFolderPath: "/"}),
		Proxy:     proxy,
	})

	stub, ok := drv.(*downStubDriver)
	if !ok {
		t.Fatalf("expected %q to be a *downStubDriver, got %T", mountPath, drv)
	}
	return stub
}

func registerDownDriver(t *testing.T, driverName string, cfg driverpkg.Config) {
	t.Helper()
	switch driverName {
	case downProxyDriverName:
		registerDownProxyStubDriverOnce.Do(func() {
			downCfg := cfg
			op.RegisterDriver(func() driverpkg.Driver {
				return &downStubDriver{config: downCfg}
			})
		})
	case downNoProxyDriverName:
		registerDownNoProxyStubDriverOnce.Do(func() {
			downCfg := cfg
			op.RegisterDriver(func() driverpkg.Driver {
				return &downStubDriver{config: downCfg}
			})
		})
	default:
		t.Fatalf("unexpected down test driver name %q", driverName)
	}
}

func proxyCapableDownStubConfig() driverpkg.Config {
	return driverpkg.Config{Name: downProxyDriverName, DefaultRoot: "/", OnlyLinkMFile: true}
}

func nonProxyDownStubConfig() driverpkg.Config {
	return driverpkg.Config{Name: downNoProxyDriverName, DefaultRoot: "/"}
}

func canonicalTestProxyPath(rawPath string) string {
	return canonicalTestProxyPathWithQuery(rawPath, nil)
}

func canonicalTestProxyPathWithD1(rawPath string) string {
	return canonicalTestProxyPathWithQuery(rawPath, url.Values{"d": {"1"}})
}

func canonicalTestProxyURL(apiURL, rawPath string) string {
	return canonicalTestProxyURLWithQuery(apiURL, rawPath, nil)
}

func canonicalTestProxyURLWithD1(apiURL, rawPath string) string {
	return canonicalTestProxyURLWithQuery(apiURL, rawPath, url.Values{"d": {"1"}})
}

func canonicalTestProxyURLWithQuery(apiURL, rawPath string, query url.Values) string {
	return strings.TrimSuffix(apiURL, "/") + canonicalTestProxyPathWithQuery(rawPath, query)
}

func canonicalTestProxyPathWithQuery(rawPath string, query url.Values) string {
	query = cloneTestQuery(query)
	encodedPath := "/p" + utils.EncodePath(rawPath, true)
	if len(query) == 0 {
		return encodedPath
	}
	return encodedPath + "?" + query.Encode()
}

func canonicalSignedTestProxyURL(apiURL, rawPath string) string {
	return canonicalSignedTestProxyURLWithQuery(apiURL, rawPath, nil)
}

func canonicalSignedTestProxyURLWithQuery(apiURL, rawPath string, query url.Values) string {
	return strings.TrimSuffix(apiURL, "/") + canonicalSignedTestProxyPathWithQuery(rawPath, query)
}

func canonicalSignedTestProxyPathWithQuery(rawPath string, query url.Values) string {
	query = cloneTestQuery(query)
	if query == nil {
		query = url.Values{}
	}
	query.Set("sign", sign.Sign(rawPath))
	return "/p" + utils.EncodePath(rawPath, true) + "?" + query.Encode()
}

func cloneTestQuery(query url.Values) url.Values {
	if query == nil {
		return nil
	}
	cloned := make(url.Values, len(query))
	for key, values := range query {
		cloned[key] = append([]string(nil), values...)
	}
	return cloned
}

func mustBuildArchiveZipPayload(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("failed to create zip entry %q: %v", name, err)
		}
		if _, err := io.WriteString(w, content); err != nil {
			t.Fatalf("failed to write zip entry %q: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("failed to close zip writer: %v", err)
	}
	return buf.Bytes()
}

type downStubDriver struct {
	model.Storage

	config         driverpkg.Config
	addition       driverpkg.RootPath
	files          map[string]*model.Object
	link           func(model.Obj, model.LinkArgs) (*model.Link, error)
	linkErr        error
	archiveList    func(model.ArchiveInnerArgs) ([]model.Obj, error)
	archiveGet     func(model.ArchiveInnerArgs) (model.Obj, error)
	archiveExtract func(model.Obj, model.ArchiveInnerArgs) (*model.Link, error)
	afterGet       func(context.Context, string)

	getCalls         int
	linkCalls        int
	getLastPath      string
	linkLastFilePath string
	lastLinkArgs     model.LinkArgs
}

func (d *downStubDriver) Config() driverpkg.Config {
	if d.config.Name == "" {
		return proxyCapableDownStubConfig()
	}
	return d.config
}

func (d *downStubDriver) GetAddition() driverpkg.Additional {
	return &d.addition
}

func (d *downStubDriver) Init(ctx context.Context) error {
	downFixtures.Lock()
	fixture, ok := downFixtures.byMountPath[d.MountPath]
	downFixtures.Unlock()
	if !ok {
		return errs.NewErr(errs.StorageNotFound, "missing down stub fixture for %s", d.MountPath)
	}

	d.files = make(map[string]*model.Object, len(fixture.files))
	for _, filePath := range fixture.files {
		cleanPath := utils.FixAndCleanPath(filePath)
		size := int64(1)
		if fixture.fileSizes != nil {
			if customSize, ok := fixture.fileSizes[cleanPath]; ok {
				size = customSize
			}
		}
		d.files[cleanPath] = &model.Object{
			Path:     cleanPath,
			Name:     stdpath.Base(cleanPath),
			Size:     size,
			Modified: time.Unix(1, 0),
		}
	}
	d.link = fixture.link
	d.linkErr = fixture.linkErr
	d.archiveList = fixture.archiveList
	d.archiveGet = fixture.archiveGet
	d.archiveExtract = fixture.archiveExtract
	d.afterGet = fixture.afterGet
	d.getCalls = 0
	d.linkCalls = 0
	d.getLastPath = ""
	d.linkLastFilePath = ""
	d.lastLinkArgs = model.LinkArgs{}
	return nil
}

func (d *downStubDriver) Drop(ctx context.Context) error {
	return nil
}

func (d *downStubDriver) List(ctx context.Context, dir model.Obj, args model.ListArgs) ([]model.Obj, error) {
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
		objs = append(objs, cloneDownObject(d.files[filePath]))
	}
	return objs, nil
}

func (d *downStubDriver) Get(ctx context.Context, path string) (model.Obj, error) {
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
	if d.afterGet != nil {
		d.afterGet(ctx, path)
	}
	return cloneDownObject(obj), nil
}

func (d *downStubDriver) Link(ctx context.Context, file model.Obj, args model.LinkArgs) (*model.Link, error) {
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

func (d *downStubDriver) GetArchiveMeta(ctx context.Context, obj model.Obj, args model.ArchiveArgs) (model.ArchiveMeta, error) {
	return nil, errs.NotImplement
}

func (d *downStubDriver) ListArchive(ctx context.Context, obj model.Obj, args model.ArchiveInnerArgs) ([]model.Obj, error) {
	if d.archiveList == nil {
		return nil, errs.NotImplement
	}
	return d.archiveList(args)
}

func (d *downStubDriver) ArchiveGet(ctx context.Context, obj model.Obj, args model.ArchiveInnerArgs) (model.Obj, error) {
	if d.archiveGet == nil {
		return nil, errs.NotImplement
	}
	return d.archiveGet(args)
}

func (d *downStubDriver) Extract(ctx context.Context, obj model.Obj, args model.ArchiveInnerArgs) (*model.Link, error) {
	if d.archiveExtract == nil {
		return nil, errs.NotImplement
	}
	return d.archiveExtract(obj, args)
}

func cloneDownObject(obj *model.Object) *model.Object {
	clone := *obj
	return &clone
}

var _ driverpkg.Driver = (*downStubDriver)(nil)
var _ driverpkg.Getter = (*downStubDriver)(nil)
var _ driverpkg.ArchiveGetter = (*downStubDriver)(nil)
var _ driverpkg.ArchiveReader = (*downStubDriver)(nil)
