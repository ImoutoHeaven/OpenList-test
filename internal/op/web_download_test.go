package op_test

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/OpenListTeam/OpenList/v4/drivers/alias"
	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	driverpkg "github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
	internalsign "github.com/OpenListTeam/OpenList/v4/internal/sign"
	"github.com/OpenListTeam/OpenList/v4/server/common"
)

func TestResolveWebDownloadRoute_UsesFirstNon302OwnerAcrossNestedAliasChain(t *testing.T) {
	leafMount := uniqueMountPath(t, "leaf")
	mustCreateWebDownloadStubStorage(t, leafMount, stubBehavior{
		files: []string{"/file.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/file.bin"}, nil
		},
	}, model.Proxy{WebProxy: true})

	nativeOwnerMount := uniqueMountPath(t, "native-owner")
	mustCreateStorage(t, model.Storage{
		MountPath: nativeOwnerMount,
		Driver:    "Alias",
		Addition: mustMarshal(t, alias.Addition{
			Paths:           leafMount,
			ProtectSameName: true,
		}),
		Proxy: model.Proxy{WebProxy: true},
	})

	proxyOwnerMount := uniqueMountPath(t, "proxy-owner")
	mustCreateStorage(t, model.Storage{
		MountPath: proxyOwnerMount,
		Driver:    "Alias",
		Addition: mustMarshal(t, alias.Addition{
			Paths:           nativeOwnerMount,
			ProtectSameName: true,
		}),
		Proxy: model.Proxy{DownProxyURL: "https://proxy.example.com"},
	})

	topMount := uniqueMountPath(t, "top")
	mustCreateStorage(t, model.Storage{
		MountPath: topMount,
		Driver:    "Alias",
		Addition: mustMarshal(t, alias.Addition{
			Paths:           proxyOwnerMount,
			ProtectSameName: true,
		}),
	})

	route, err := op.ResolveWebDownloadRoute(context.Background(), topMount+"/file.bin")
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if got, want := route.EffectivePolicy, op.WebDownloadProxyURL; got != want {
		t.Fatalf("expected policy %q, got %q", want, got)
	}
	if got, want := route.PolicyOwnerRawPath, proxyOwnerMount+"/file.bin"; got != want {
		t.Fatalf("expected owner path %q, got %q", want, got)
	}
	if got, want := route.LeafRawPath, leafMount+"/file.bin"; got != want {
		t.Fatalf("expected leaf path %q, got %q", want, got)
	}
	if got, want := len(route.Nodes), 4; got != want {
		t.Fatalf("expected %d ordered nodes, got %d", want, got)
	}
	if got, want := route.Nodes[0].Policy, op.WebDownloadRedirect302; got != want {
		t.Fatalf("expected top wrapper policy %q, got %q", want, got)
	}
	if got, want := route.Nodes[1].Policy, op.WebDownloadProxyURL; got != want {
		t.Fatalf("expected first non-302 owner policy %q, got %q", want, got)
	}
	if got, want := route.Nodes[2].Policy, op.WebDownloadNativeProxy; got != want {
		t.Fatalf("expected nested wrapper policy %q, got %q", want, got)
	}
	if got, want := route.Nodes[3].Policy, op.WebDownloadNativeProxy; got != want {
		t.Fatalf("expected leaf policy %q, got %q", want, got)
	}
}

func TestResolveWebDownloadRoute_AllWrapper302FallsBackToLeafPolicy(t *testing.T) {
	leafMount := uniqueMountPath(t, "leaf")
	mustCreateWebDownloadStubStorage(t, leafMount, stubBehavior{
		files: []string{"/file.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/file.bin"}, nil
		},
	}, model.Proxy{WebProxy: true})

	innerMount := uniqueMountPath(t, "inner")
	mustCreateStorage(t, model.Storage{
		MountPath: innerMount,
		Driver:    "Alias",
		Addition: mustMarshal(t, alias.Addition{
			Paths:           leafMount,
			ProtectSameName: true,
		}),
	})

	outerMount := uniqueMountPath(t, "outer")
	mustCreateStorage(t, model.Storage{
		MountPath: outerMount,
		Driver:    "Alias",
		Addition: mustMarshal(t, alias.Addition{
			Paths:           innerMount,
			ProtectSameName: true,
		}),
	})

	route, err := op.ResolveWebDownloadRoute(context.Background(), outerMount+"/file.bin")
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if got, want := route.EffectivePolicy, op.WebDownloadNativeProxy; got != want {
		t.Fatalf("expected policy %q, got %q", want, got)
	}
	if got, want := route.PolicyOwnerRawPath, leafMount+"/file.bin"; got != want {
		t.Fatalf("expected leaf owner path %q, got %q", want, got)
	}
	if got, want := route.LeafRawPath, leafMount+"/file.bin"; got != want {
		t.Fatalf("expected leaf raw path %q, got %q", want, got)
	}
	if got, want := route.Nodes[0].Policy, op.WebDownloadRedirect302; got != want {
		t.Fatalf("expected outer wrapper policy %q, got %q", want, got)
	}
	if got, want := route.Nodes[1].Policy, op.WebDownloadRedirect302; got != want {
		t.Fatalf("expected inner wrapper policy %q, got %q", want, got)
	}
	if got, want := route.Nodes[2].Policy, op.WebDownloadNativeProxy; got != want {
		t.Fatalf("expected leaf policy %q, got %q", want, got)
	}
}

func TestResolveWebDownloadRoute_AliasFirstExistingTargetWins(t *testing.T) {
	firstMount := uniqueMountPath(t, "leaf-one")
	firstLeaf := mustCreateWebDownloadStubStorage(t, firstMount, stubBehavior{
		files: []string{"/file.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/first.bin"}, nil
		},
	}, model.Proxy{})
	secondMount := uniqueMountPath(t, "leaf-two")
	secondLeaf := mustCreateWebDownloadStubStorage(t, secondMount, stubBehavior{
		files: []string{"/file.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/second.bin"}, nil
		},
	}, model.Proxy{})

	aliasMount := uniqueMountPath(t, "alias")
	mustCreateStorage(t, model.Storage{
		MountPath: aliasMount,
		Driver:    "Alias",
		Addition: mustMarshal(t, alias.Addition{
			Paths:           "docs:" + firstMount + "\ndocs:" + secondMount,
			ProtectSameName: true,
		}),
	})

	route, err := op.ResolveWebDownloadRoute(context.Background(), aliasMount+"/file.bin")
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if got, want := route.LeafRawPath, firstMount+"/file.bin"; got != want {
		t.Fatalf("expected first existing target leaf path %q, got %q", want, got)
	}
	if got := firstLeaf.getCalls; got == 0 {
		t.Fatal("expected first alias target to be probed for object existence")
	}
	if got := secondLeaf.getCalls; got != 0 {
		t.Fatalf("expected later alias targets to be skipped after first existing target, got %d get calls", got)
	}
}

func TestResolveWebDownloadRoute_KeepsOwnerPathSeparateFromChosenLeafBalanceMember(t *testing.T) {
	leafBaseMount := uniqueMountPath(t, "leaf")
	mustCreateWebDownloadStubStorage(t, leafBaseMount, stubBehavior{
		files: []string{"/file.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/member-one.bin"}, nil
		},
	}, model.Proxy{})
	mustCreateWebDownloadStubStorage(t, leafBaseMount+".balance", stubBehavior{
		files: []string{"/file.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/member-two.bin"}, nil
		},
	}, model.Proxy{})

	aliasMount := uniqueMountPath(t, "alias")
	mustCreateStorage(t, model.Storage{
		MountPath: aliasMount,
		Driver:    "Alias",
		Addition: mustMarshal(t, alias.Addition{
			Paths:           leafBaseMount,
			ProtectSameName: true,
		}),
		Proxy: model.Proxy{DownProxyURL: "https://proxy.example.com"},
	})

	route, err := op.ResolveWebDownloadRoute(context.Background(), aliasMount+"/file.bin")
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if got, want := route.EffectivePolicy, op.WebDownloadProxyURL; got != want {
		t.Fatalf("expected policy %q, got %q", want, got)
	}
	if got, want := route.PolicyOwnerRawPath, aliasMount+"/file.bin"; got != want {
		t.Fatalf("expected owner path %q, got %q", want, got)
	}
	if got, want := route.LeafVirtualMountPath, leafBaseMount; got != want {
		t.Fatalf("expected leaf virtual mount %q, got %q", want, got)
	}
	if got := route.LeafMountPath; got != leafBaseMount && got != leafBaseMount+".balance" {
		t.Fatalf("expected chosen leaf mount to be one of %q or %q, got %q", leafBaseMount, leafBaseMount+".balance", got)
	}
	if got, want := route.LeafRawPath, route.LeafMountPath+"/file.bin"; got != want {
		t.Fatalf("expected chosen leaf raw path %q, got %q", want, got)
	}
	if route.PolicyOwnerRawPath == route.LeafRawPath {
		t.Fatalf("expected owner path and leaf path to differ, both were %q", route.PolicyOwnerRawPath)
	}
}

func TestResolveWebDownloadRoute_NestedBalanceGroupsRemainIndependent(t *testing.T) {
	innerBaseMount := uniqueMountPath(t, "inner")
	mustCreateWebDownloadStubStorage(t, innerBaseMount, stubBehavior{
		files: []string{"/file.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/inner-one.bin"}, nil
		},
	}, model.Proxy{})
	mustCreateWebDownloadStubStorage(t, innerBaseMount+".balance", stubBehavior{
		files: []string{"/file.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/inner-two.bin"}, nil
		},
	}, model.Proxy{})

	outerBaseMount := uniqueMountPath(t, "outer")
	mustCreateStorage(t, model.Storage{
		MountPath: outerBaseMount,
		Driver:    "Alias",
		Addition: mustMarshal(t, alias.Addition{
			Paths:           innerBaseMount,
			ProtectSameName: true,
		}),
	})
	mustCreateStorage(t, model.Storage{
		MountPath: outerBaseMount + ".balance",
		Driver:    "Alias",
		Addition: mustMarshal(t, alias.Addition{
			Paths:           innerBaseMount,
			ProtectSameName: true,
		}),
		Proxy: model.Proxy{DownProxyURL: "https://outer-proxy.example.com"},
	})

	route, err := op.ResolveWebDownloadRoute(context.Background(), outerBaseMount+"/file.bin")
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if got, want := route.EffectivePolicy, op.WebDownloadProxyURL; got != want {
		t.Fatalf("expected effective policy %q, got %q", want, got)
	}
	if got, want := route.PolicyOwnerRawPath, outerBaseMount+"/file.bin"; got != want {
		t.Fatalf("expected outer owner virtual path %q, got %q", want, got)
	}
	if got, want := route.LeafVirtualMountPath, innerBaseMount; got != want {
		t.Fatalf("expected inner leaf virtual mount %q, got %q", want, got)
	}
	if got, want := route.LeafMountPath, innerBaseMount+".balance"; got != want {
		t.Fatalf("expected inner chosen balance leaf mount %q, got %q", want, got)
	}
	if got, want := route.LeafRawPath, innerBaseMount+".balance/file.bin"; got != want {
		t.Fatalf("expected inner chosen balance leaf path %q, got %q", want, got)
	}
	if got, want := len(route.Nodes), 2; got != want {
		t.Fatalf("expected %d ordered nodes, got %d", want, got)
	}
	if got, want := route.Nodes[0].MountPath, outerBaseMount+".balance"; got != want {
		t.Fatalf("expected outer chosen balance node mount path %q, got %q", want, got)
	}
	if got, want := route.Nodes[0].RawPath, outerBaseMount+".balance/file.bin"; got != want {
		t.Fatalf("expected outer chosen balance node raw path %q, got %q", want, got)
	}
	if got, want := route.Nodes[1].MountPath, innerBaseMount+".balance"; got != want {
		t.Fatalf("expected inner chosen balance node mount path %q, got %q", want, got)
	}
	if got, want := route.Nodes[1].RawPath, innerBaseMount+".balance/file.bin"; got != want {
		t.Fatalf("expected inner chosen balance node raw path %q, got %q", want, got)
	}
}

func TestResolveWebDownloadRoute_NestedIndependentBalanceGroupsKeepOuterProxyOwner(t *testing.T) {
	innerOriginMount := uniqueMountPath(t, "inner-origin")
	mustCreateWebDownloadStubStorage(t, innerOriginMount, stubBehavior{
		files: []string{"/file.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/inner-origin.bin"}, nil
		},
	}, model.Proxy{})
	mustCreateWebDownloadStubStorage(t, innerOriginMount+".balance", stubBehavior{
		files: []string{"/file.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/inner-origin-balance.bin"}, nil
		},
	}, model.Proxy{})

	outerBalanceMount := uniqueMountPath(t, "outer-balance")
	mustCreateStorage(t, model.Storage{
		MountPath: outerBalanceMount,
		Driver:    "Alias",
		Addition: mustMarshal(t, alias.Addition{
			Paths:           innerOriginMount,
			ProtectSameName: true,
		}),
		Proxy: model.Proxy{},
	})
	mustCreateStorage(t, model.Storage{
		MountPath: outerBalanceMount + ".balance",
		Driver:    "Alias",
		Addition: mustMarshal(t, alias.Addition{
			Paths:           innerOriginMount,
			ProtectSameName: true,
		}),
		Proxy: model.Proxy{DownProxyURL: "https://outer-proxy.example.com"},
	})

	aliasMount := uniqueMountPath(t, "alias")
	mustCreateStorage(t, model.Storage{
		MountPath: aliasMount,
		Driver:    "Alias",
		Addition: mustMarshal(t, alias.Addition{
			Paths:           outerBalanceMount,
			ProtectSameName: true,
		}),
	})

	sawProxyOwner := false
	for request := 0; request < 2; request++ {
		route, err := op.ResolveWebDownloadRoute(context.Background(), aliasMount+"/file.bin")
		if err != nil {
			t.Fatalf("request %d: expected success, got %v", request+1, err)
		}
		if got, want := route.Nodes[0].RawPath, aliasMount+"/file.bin"; got != want {
			t.Fatalf("request %d: expected outer alias node raw path %q, got %q", request+1, want, got)
		}
		if got, want := route.LeafVirtualMountPath, innerOriginMount; got != want {
			t.Fatalf("request %d: expected inner virtual mount %q, got %q", request+1, want, got)
		}
		if !strings.HasPrefix(route.LeafRawPath, innerOriginMount) {
			t.Fatalf("request %d: expected chosen inner leaf path under %q, got %q", request+1, innerOriginMount, route.LeafRawPath)
		}
		if got := route.Nodes[1].RawPath; got != outerBalanceMount+"/file.bin" && got != outerBalanceMount+".balance/file.bin" {
			t.Fatalf("request %d: expected outer balance node raw path to be one of %q or %q, got %q", request+1, outerBalanceMount+"/file.bin", outerBalanceMount+".balance/file.bin", got)
		}
		if route.EffectivePolicy != op.WebDownloadProxyURL {
			continue
		}
		sawProxyOwner = true
		if got, want := route.PolicyOwnerRawPath, outerBalanceMount+"/file.bin"; got != want {
			t.Fatalf("request %d: expected outer proxy owner path %q, got %q", request+1, want, got)
		}
		if route.PolicyOwnerRawPath == route.LeafRawPath {
			t.Fatalf("request %d: expected owner path and leaf path to remain separated for the proxy-owning request, both were %q", request+1, route.PolicyOwnerRawPath)
		}
		if got, want := route.Nodes[1].RawPath, outerBalanceMount+".balance/file.bin"; got != want {
			t.Fatalf("request %d: expected proxy-owning outer balance node raw path %q, got %q", request+1, want, got)
		}
	}
	if !sawProxyOwner {
		t.Fatalf("expected one of two successive requests to reach the outer proxy-owning balance member under %q", outerBalanceMount)
	}
}

func TestResolveWebDownloadRoute_LeafDirectLinkRejectsVirtualBalanceProxyDerivedURL(t *testing.T) {
	leafBaseMount := uniqueMountPath(t, "leaf")
	mustCreateWebDownloadStubStorage(t, leafBaseMount, stubBehavior{
		files: []string{"/file.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/member-one.bin"}, nil
		},
		downProxyURL: "https://proxy.example.com",
	}, model.Proxy{DownProxyURL: "https://proxy.example.com"})
	selectedLeaf := mustCreateWebDownloadStubStorage(t, leafBaseMount+".balance", stubBehavior{
		files: []string{"/file.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/member-two.bin"}, nil
		},
		downProxyURL: "https://proxy.example.com",
	}, model.Proxy{DownProxyURL: "https://proxy.example.com"})
	virtualProxyURL := common.GenerateDownProxyURL(selectedLeaf.GetStorage(), leafBaseMount+"/file.bin")
	selectedLeaf.link = func(model.Obj, model.LinkArgs) (*model.Link, error) {
		return &model.Link{URL: virtualProxyURL}, nil
	}

	route, err := op.ResolveWebDownloadRoute(context.Background(), leafBaseMount+"/file.bin")
	if err != nil {
		t.Fatalf("expected route resolution success, got %v", err)
	}
	if got, want := route.LeafMountPath, leafBaseMount+".balance"; got != want {
		t.Fatalf("expected chosen balance leaf mount %q, got %q", want, got)
	}
	if got, want := route.LeafRawPath, leafBaseMount+".balance/file.bin"; got != want {
		t.Fatalf("expected concrete balance leaf path %q, got %q", want, got)
	}
	if got, unwanted := virtualProxyURL, common.GenerateDownProxyURL(selectedLeaf.GetStorage(), route.LeafRawPath); got == unwanted {
		t.Fatalf("test setup must return virtual proxy URL, got concrete URL %q", got)
	}
	_, _, err = op.WebDownloadLeafDirectLink(context.Background(), route, model.LinkArgs{})
	if err == nil {
		t.Fatal("expected direct leaf link validation to reject virtual balance down_proxy_url")
	}
}

func TestWebDownloadCanonicalProxyPath_UsesSameSignerAsProxyVerificationAfterSaveSettings(t *testing.T) {
	tokenSetting, tokenExisted := mustGetOrCreateSettingItem(t, conf.Token, "token-before-web-download-sign-test")
	expireSetting, expireExisted := mustGetOrCreateSettingItem(t, conf.LinkExpiration, "0")
	t.Cleanup(func() {
		if tokenExisted {
			mustSaveSettingItem(t, tokenSetting)
		} else {
			mustDeleteSettingItem(t, conf.Token)
		}
		if expireExisted {
			mustSaveSettingItem(t, expireSetting)
		} else {
			mustDeleteSettingItem(t, conf.LinkExpiration)
		}
		internalsign.Instance()
		op.RefreshLinkAPISigner()
	})

	zeroExpiration := expireSetting
	zeroExpiration.Value = "0"
	mustSaveSettingItem(t, zeroExpiration)

	initialToken := tokenSetting
	initialToken.Value = tokenSetting.Value + "-web-download-old"
	mustSaveSettingItem(t, initialToken)
	internalsign.Instance()
	op.RefreshLinkAPISigner()

	route := &op.WebDownloadRoute{PolicyOwnerRawPath: "/test-web-download/signed/file.bin"}
	if _, err := op.WebDownloadCanonicalProxyPath(route, nil, true); err != nil {
		t.Fatalf("expected canonical proxy path generation success, got %v", err)
	}

	updatedToken := initialToken
	updatedToken.Value = initialToken.Value + "-updated"
	mustSaveSettingsThroughHandler(t, updatedToken)
	internalsign.Instance()

	canonicalPath, err := op.WebDownloadCanonicalProxyPath(route, url.Values{"d": {"1"}}, true)
	if err != nil {
		t.Fatalf("expected canonical proxy path generation success after SaveSettings, got %v", err)
	}
	parsed, err := url.Parse(canonicalPath)
	if err != nil {
		t.Fatalf("failed to parse canonical proxy path %q: %v", canonicalPath, err)
	}
	signValue := parsed.Query().Get("sign")
	if signValue == "" {
		t.Fatalf("expected canonical proxy path %q to include sign", canonicalPath)
	}
	if err := internalsign.Verify(route.PolicyOwnerRawPath, signValue); err != nil {
		t.Fatalf("expected canonical sign %q to verify for %q after SaveSettings, got %v", signValue, route.PolicyOwnerRawPath, err)
	}
}

func mustCreateWebDownloadStubStorage(t *testing.T, mountPath string, behavior stubBehavior, proxy model.Proxy) *stubLinkDriver {
	t.Helper()

	registerStubDriverOnce.Do(func() {
		op.RegisterDriver(func() driverpkg.Driver {
			return &stubLinkDriver{}
		})
	})

	stubFixtures.Lock()
	stubFixtures.byMountPath[mountPath] = behavior
	stubFixtures.Unlock()
	t.Cleanup(func() {
		stubFixtures.Lock()
		delete(stubFixtures.byMountPath, mountPath)
		stubFixtures.Unlock()
	})

	drv := mustCreateStorage(t, model.Storage{
		MountPath: mountPath,
		Driver:    stubDriverName,
		Addition:  mustMarshal(t, driverpkg.RootPath{RootFolderPath: "/"}),
		Proxy:     proxy,
	})

	stub, ok := drv.(*stubLinkDriver)
	if !ok {
		t.Fatalf("expected %q to be a *stubLinkDriver, got %T", mountPath, drv)
	}
	return stub
}
