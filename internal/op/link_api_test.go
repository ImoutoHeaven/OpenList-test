package op_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	stdpath "path"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/OpenListTeam/OpenList/v4/drivers/alias"
	"github.com/OpenListTeam/OpenList/v4/drivers/strm"
	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/internal/db"
	driverpkg "github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/errs"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
	internalsign "github.com/OpenListTeam/OpenList/v4/internal/sign"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
	"github.com/OpenListTeam/OpenList/v4/server/common"
	serverhandles "github.com/OpenListTeam/OpenList/v4/server/handles"
	"github.com/gin-gonic/gin"
)

func TestResolveActualLink_PrefersLeafDirectURLOverDownProxyURL(t *testing.T) {
	mountPath := uniqueMountPath(t, "leaf")
	leaf := mustCreateStubStorage(t, mountPath, stubBehavior{
		files: []string{"/file.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{
				URL: "https://download.example.com/file.bin",
				Header: http.Header{
					"Authorization": []string{"Bearer token"},
				},
			}, nil
		},
		downProxyURL: "https://proxy.example.com",
	})

	link, err := op.ResolveActualLink(context.Background(), mountPath+"/file.bin", model.LinkArgs{})
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}

	if got, want := link.URL, "https://download.example.com/file.bin"; got != want {
		t.Fatalf("expected direct URL %q, got %q", want, got)
	}
	if got, want := link.Header.Get("Authorization"), "Bearer token"; got != want {
		t.Fatalf("expected Authorization header %q, got %q", want, got)
	}
	if downProxyURL := common.GenerateDownProxyURL(leaf.GetStorage(), mountPath+"/file.bin"); link.URL == downProxyURL {
		t.Fatalf("expected direct URL branch, got down_proxy_url branch %q", link.URL)
	}
}

func TestResolveActualLink_FailsWhenLeafHasNoRealUpstreamURL(t *testing.T) {
	mountPath := uniqueMountPath(t, "leaf")
	mustCreateStubStorage(t, mountPath, stubBehavior{
		files: []string{"/file.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{
				Header: http.Header{
					"Authorization": []string{"Bearer hidden"},
				},
			}, nil
		},
		downProxyURL:     "https://proxy.example.com",
		disableProxySign: true,
	})

	_, err := op.ResolveActualLink(context.Background(), mountPath+"/file.bin", model.LinkArgs{})
	if err == nil {
		t.Fatal("expected error when leaf has no real upstream URL")
	}
}

func TestResolveActualLink_FailsWhenLeafReturnsOpenListLocalURL(t *testing.T) {
	mountPath := uniqueMountPath(t, "leaf")
	mustCreateStubStorage(t, mountPath, stubBehavior{
		files: []string{"/file.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{
				URL: "https://example.test/p/local-file?sign=local",
				Header: http.Header{
					"Authorization": []string{"Bearer local"},
				},
			}, nil
		},
		downProxyURL:     "https://proxy.example.com",
		disableProxySign: true,
	})

	ctx := context.WithValue(context.Background(), conf.ApiUrlKey, "https://example.test")
	_, err := op.ResolveActualLink(ctx, mountPath+"/file.bin", model.LinkArgs{})
	if err == nil {
		t.Fatal("expected error when leaf returns OpenList-local URL")
	}
}

func TestResolveActualLink_FailsWhenLeafReturnsOpenListLocalPURLOutsideAPIBasePrefix(t *testing.T) {
	mountPath := uniqueMountPath(t, "leaf")
	mustCreateStubStorage(t, mountPath, stubBehavior{
		files: []string{"/file.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://example.test/p/local-file?sign=local"}, nil
		},
	})

	ctx := context.WithValue(context.Background(), conf.ApiUrlKey, "https://example.test/openlist")
	_, err := op.ResolveActualLink(ctx, mountPath+"/file.bin", model.LinkArgs{})
	if err == nil {
		t.Fatal("expected error when leaf returns same-host /p URL outside non-root API base prefix")
	}
}

func TestResolveActualLink_FailsWhenLeafReturnsOpenListLocalDURLOutsideAPIBasePrefix(t *testing.T) {
	mountPath := uniqueMountPath(t, "leaf")
	mustCreateStubStorage(t, mountPath, stubBehavior{
		files: []string{"/file.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://example.test/d/local-file"}, nil
		},
	})

	ctx := context.WithValue(context.Background(), conf.ApiUrlKey, "https://example.test/openlist")
	_, err := op.ResolveActualLink(ctx, mountPath+"/file.bin", model.LinkArgs{})
	if err == nil {
		t.Fatal("expected error when leaf returns same-host /d URL outside non-root API base prefix")
	}
}

func TestResolveActualLink_RejectsRootBaseSameHostOpenListLocalAPIURL(t *testing.T) {
	mountPath := uniqueMountPath(t, "leaf")
	mustCreateStubStorage(t, mountPath, stubBehavior{
		files: []string{"/file.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://example.test/api/fs/get?path=/file.bin"}, nil
		},
	})

	ctx := context.WithValue(context.Background(), conf.ApiUrlKey, "https://example.test")
	_, err := op.ResolveActualLink(ctx, mountPath+"/file.bin", model.LinkArgs{})
	if err == nil {
		t.Fatal("expected error when leaf returns same-host root-base /api URL")
	}
}

func TestResolveActualLink_AllowsRootBaseSameHostNonAPIAbsoluteURL(t *testing.T) {
	mountPath := uniqueMountPath(t, "leaf")
	const directURL = "https://example.test/files/direct.bin"
	mustCreateStubStorage(t, mountPath, stubBehavior{
		files: []string{"/file.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: directURL}, nil
		},
	})

	ctx := context.WithValue(context.Background(), conf.ApiUrlKey, "https://example.test")
	link, err := op.ResolveActualLink(ctx, mountPath+"/file.bin", model.LinkArgs{})
	if err != nil {
		t.Fatalf("expected same-host non-API absolute upstream URL to be allowed, got %v", err)
	}
	if got := link.URL; got != directURL {
		t.Fatalf("expected direct URL %q, got %q", directURL, got)
	}
}

func TestResolveActualLink_RejectsNonRootBaseSameHostOpenListLocalAPIURL(t *testing.T) {
	mountPath := uniqueMountPath(t, "leaf")
	mustCreateStubStorage(t, mountPath, stubBehavior{
		files: []string{"/file.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://example.test/openlist/api/fs/get?path=/file.bin"}, nil
		},
	})

	ctx := context.WithValue(context.Background(), conf.ApiUrlKey, "https://example.test/openlist")
	_, err := op.ResolveActualLink(ctx, mountPath+"/file.bin", model.LinkArgs{})
	if err == nil {
		t.Fatal("expected error when leaf returns same-host non-root-base /openlist/api URL")
	}
}

func TestResolveActualLink_RejectsNonRootBasePrefixedPLocalRoute(t *testing.T) {
	mountPath := uniqueMountPath(t, "leaf")
	mustCreateStubStorage(t, mountPath, stubBehavior{
		files: []string{"/file.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://example.test/openlist/p/local-file"}, nil
		},
	})

	ctx := context.WithValue(context.Background(), conf.ApiUrlKey, "https://example.test/openlist")
	_, err := op.ResolveActualLink(ctx, mountPath+"/file.bin", model.LinkArgs{})
	if err == nil {
		t.Fatal("expected error when leaf returns same-host non-root-base /openlist/p URL")
	}
}

func TestResolveActualLink_RejectsNonRootBasePrefixedDLocalRoute(t *testing.T) {
	mountPath := uniqueMountPath(t, "leaf")
	mustCreateStubStorage(t, mountPath, stubBehavior{
		files: []string{"/file.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://example.test/openlist/d/local-file"}, nil
		},
	})

	ctx := context.WithValue(context.Background(), conf.ApiUrlKey, "https://example.test/openlist")
	_, err := op.ResolveActualLink(ctx, mountPath+"/file.bin", model.LinkArgs{})
	if err == nil {
		t.Fatal("expected error when leaf returns same-host non-root-base /openlist/d URL")
	}
}

func TestResolveActualLink_AllowsNonRootBaseFilesNonLocalRoute(t *testing.T) {
	mountPath := uniqueMountPath(t, "leaf")
	const directURL = "https://example.test/openlist/files/direct.bin"
	mustCreateStubStorage(t, mountPath, stubBehavior{
		files: []string{"/file.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: directURL}, nil
		},
	})

	ctx := context.WithValue(context.Background(), conf.ApiUrlKey, "https://example.test/openlist")
	link, err := op.ResolveActualLink(ctx, mountPath+"/file.bin", model.LinkArgs{})
	if err != nil {
		t.Fatalf("expected same-host /openlist/files upstream URL to be allowed, got %v", err)
	}
	if got := link.URL; got != directURL {
		t.Fatalf("expected direct URL %q, got %q", directURL, got)
	}
}

func TestResolveActualLink_AllowsNonRootBaseSameHostNonAPIAbsoluteURLs(t *testing.T) {
	t.Run("under_api_base", func(t *testing.T) {
		mountPath := uniqueMountPath(t, "leaf")
		const directURL = "https://example.test/openlist/files/direct.bin"
		mustCreateStubStorage(t, mountPath, stubBehavior{
			files: []string{"/file.bin"},
			link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
				return &model.Link{URL: directURL}, nil
			},
		})

		ctx := context.WithValue(context.Background(), conf.ApiUrlKey, "https://example.test/openlist")
		link, err := op.ResolveActualLink(ctx, mountPath+"/file.bin", model.LinkArgs{})
		if err != nil {
			t.Fatalf("expected same-host non-API absolute upstream URL under the API base to be allowed, got %v", err)
		}
		if got := link.URL; got != directURL {
			t.Fatalf("expected direct URL %q, got %q", directURL, got)
		}
	})

	t.Run("outside_api_base", func(t *testing.T) {
		mountPath := uniqueMountPath(t, "leaf")
		const directURL = "https://example.test/files/direct.bin"
		mustCreateStubStorage(t, mountPath, stubBehavior{
			files: []string{"/file.bin"},
			link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
				return &model.Link{URL: directURL}, nil
			},
		})

		ctx := context.WithValue(context.Background(), conf.ApiUrlKey, "https://example.test/openlist")
		link, err := op.ResolveActualLink(ctx, mountPath+"/file.bin", model.LinkArgs{})
		if err != nil {
			t.Fatalf("expected same-host non-API absolute upstream URL outside the API base to be allowed, got %v", err)
		}
		if got := link.URL; got != directURL {
			t.Fatalf("expected direct URL %q, got %q", directURL, got)
		}
	})
}

func TestResolveActualLink_RejectsNonRootBaseBalanceSameHostOpenListLocalAPIURL(t *testing.T) {
	mountPath := uniqueMountPath(t, "leaf")
	mustCreateStubStorage(t, mountPath, stubBehavior{
		files: []string{"/file.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://example.test/openlist.balance/api/fs/get?path=/file.bin"}, nil
		},
	})

	ctx := context.WithValue(context.Background(), conf.ApiUrlKey, "https://example.test/openlist.balance")
	_, err := op.ResolveActualLink(ctx, mountPath+"/file.bin", model.LinkArgs{})
	if err == nil {
		t.Fatal("expected error when leaf returns same-host non-root-base /openlist.balance/api URL")
	}
}

func TestResolveActualLink_AllowsNonRootBaseBalanceSameHostNonAPIAbsoluteURL(t *testing.T) {
	mountPath := uniqueMountPath(t, "leaf")
	const directURL = "https://example.test/openlist.balance/files/direct.bin"
	mustCreateStubStorage(t, mountPath, stubBehavior{
		files: []string{"/file.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: directURL}, nil
		},
	})

	ctx := context.WithValue(context.Background(), conf.ApiUrlKey, "https://example.test/openlist.balance")
	link, err := op.ResolveActualLink(ctx, mountPath+"/file.bin", model.LinkArgs{})
	if err != nil {
		t.Fatalf("expected same-host non-API absolute upstream URL under .balance API base to be allowed, got %v", err)
	}
	if got := link.URL; got != directURL {
		t.Fatalf("expected direct URL %q, got %q", directURL, got)
	}
}

func TestResolveActualLink_FailsWhenLeafReturnsRelativeURL(t *testing.T) {
	mountPath := uniqueMountPath(t, "leaf")
	mustCreateStubStorage(t, mountPath, stubBehavior{
		files: []string{"/file.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{
				URL: "/p/relative-file?sign=relative",
				Header: http.Header{
					"Authorization": []string{"Bearer relative"},
				},
			}, nil
		},
		downProxyURL:     "https://proxy.example.com",
		disableProxySign: true,
	})

	_, err := op.ResolveActualLink(context.Background(), mountPath+"/file.bin", model.LinkArgs{})
	if err == nil {
		t.Fatal("expected error when leaf returns relative URL")
	}
}

func TestResolveActualLink_FailsWhenResolvedLeafWouldFallbackToDownProxyURL(t *testing.T) {
	leafMount := uniqueMountPath(t, "leaf")
	leaf := mustCreateStubStorage(t, leafMount, stubBehavior{
		files: []string{"/file.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{}, nil
		},
		downProxyURL:     "https://proxy.example.com",
		disableProxySign: true,
	})

	aliasMount := uniqueMountPath(t, "alias")
	mustCreateStorage(t, model.Storage{
		MountPath: aliasMount,
		Driver:    "Alias",
		Addition: mustMarshal(t, alias.Addition{
			Paths:           "docs:" + leafMount,
			ProtectSameName: true,
		}),
	})

	_, err := op.ResolveActualLink(context.Background(), aliasMount+"/file.bin", model.LinkArgs{})
	if err == nil {
		t.Fatal("expected error when resolved leaf only has down_proxy_url fallback")
	}
	if got, want := leaf.linkCalls, 1; got != want {
		t.Fatalf("expected resolved leaf link call count %d, got %d", want, got)
	}
}

func TestResolveActualLink_FailsWhenLeafWouldOnlyProduceSignedDownProxyURL(t *testing.T) {
	mountPath := uniqueMountPath(t, "leaf")
	mustCreateStubStorage(t, mountPath, stubBehavior{
		files: []string{"/signed.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{}, nil
		},
		downProxyURL: "https://proxy.example.com",
	})

	_, err := op.ResolveActualLink(context.Background(), mountPath+"/signed.bin", model.LinkArgs{})
	if err == nil {
		t.Fatal("expected error when signed down_proxy_url fallback is the only available result")
	}
}

func TestResolveActualLink_FailsWhenLeafReturnsUnsignedSynthesizedExternalDownProxyURL(t *testing.T) {
	mountPath := uniqueMountPath(t, "leaf")
	leaf := mustCreateStubStorage(t, mountPath, stubBehavior{
		files: []string{"/file.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{}, nil
		},
		downProxyURL:     "https://proxy.example.com",
		disableProxySign: true,
	})
	proxyURL := common.GenerateDownProxyURL(leaf.GetStorage(), mountPath+"/file.bin")
	if strings.Contains(proxyURL, "?sign=") {
		t.Fatalf("expected unsigned synthesized proxy URL, got %q", proxyURL)
	}
	leaf.link = func(model.Obj, model.LinkArgs) (*model.Link, error) {
		return &model.Link{URL: proxyURL}, nil
	}

	_, err := op.ResolveActualLink(context.Background(), mountPath+"/file.bin", model.LinkArgs{})
	if err == nil {
		t.Fatal("expected error when leaf returns synthesized unsigned external down_proxy_url")
	}
}

func TestResolveActualLink_FailsWhenLeafReturnsUnsignedSynthesizedExternalDownProxyURLWithFragment(t *testing.T) {
	mountPath := uniqueMountPath(t, "leaf")
	leaf := mustCreateStubStorage(t, mountPath, stubBehavior{
		files: []string{"/file.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{}, nil
		},
		downProxyURL:     "https://proxy.example.com",
		disableProxySign: true,
	})
	proxyURL := common.GenerateDownProxyURL(leaf.GetStorage(), mountPath+"/file.bin") + "#x"
	leaf.link = func(model.Obj, model.LinkArgs) (*model.Link, error) {
		return &model.Link{URL: proxyURL}, nil
	}

	_, err := op.ResolveActualLink(context.Background(), mountPath+"/file.bin", model.LinkArgs{})
	if err == nil {
		t.Fatal("expected error when leaf returns synthesized unsigned external down_proxy_url with fragment suffix")
	}
}

func TestResolveActualLink_FailsWhenLeafReturnsUnsignedSynthesizedExternalDownProxyURLWithExtraQuery(t *testing.T) {
	mountPath := uniqueMountPath(t, "leaf")
	leaf := mustCreateStubStorage(t, mountPath, stubBehavior{
		files: []string{"/file.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{}, nil
		},
		downProxyURL:     "https://proxy.example.com",
		disableProxySign: true,
	})
	proxyURL := common.GenerateDownProxyURL(leaf.GetStorage(), mountPath+"/file.bin") + "?extra=1"
	leaf.link = func(model.Obj, model.LinkArgs) (*model.Link, error) {
		return &model.Link{URL: proxyURL}, nil
	}

	_, err := op.ResolveActualLink(context.Background(), mountPath+"/file.bin", model.LinkArgs{})
	if err == nil {
		t.Fatal("expected error when leaf returns synthesized unsigned external down_proxy_url with extra query suffix")
	}
}

func TestResolveActualLink_FailsWhenLeafReturnsSignedSynthesizedExternalDownProxyURL(t *testing.T) {
	leafMount := uniqueMountPath(t, "leaf")
	leaf := mustCreateStubStorage(t, leafMount, stubBehavior{
		files: []string{"/signed.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{}, nil
		},
		downProxyURL: "https://proxy.example.com",
	})
	proxyURL := common.GenerateDownProxyURL(leaf.GetStorage(), leafMount+"/signed.bin")
	if !strings.Contains(proxyURL, "?sign=") {
		t.Fatalf("expected signed synthesized proxy URL, got %q", proxyURL)
	}
	leaf.link = func(model.Obj, model.LinkArgs) (*model.Link, error) {
		return &model.Link{URL: proxyURL}, nil
	}

	aliasMount := uniqueMountPath(t, "alias")
	mustCreateStorage(t, model.Storage{
		MountPath: aliasMount,
		Driver:    "Alias",
		Addition: mustMarshal(t, alias.Addition{
			Paths:           leafMount,
			ProtectSameName: true,
		}),
	})

	_, err := op.ResolveActualLink(context.Background(), aliasMount+"/signed.bin", model.LinkArgs{})
	if err == nil {
		t.Fatal("expected error when leaf returns signed synthesized external down_proxy_url for the resolved leaf path")
	}
}

func TestResolveActualLink_FailsWhenLeafReturnsSigningEnabledDownProxyURLWithoutSign(t *testing.T) {
	mountPath := uniqueMountPath(t, "leaf")
	leaf := mustCreateStubStorage(t, mountPath, stubBehavior{
		files: []string{"/signed.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{}, nil
		},
		downProxyURL: "https://proxy.example.com",
	})
	leaf.link = func(model.Obj, model.LinkArgs) (*model.Link, error) {
		return &model.Link{URL: "https://proxy.example.com" + utils.EncodePath(mountPath+"/signed.bin", true)}, nil
	}

	_, err := op.ResolveActualLink(context.Background(), mountPath+"/signed.bin", model.LinkArgs{})
	if err == nil {
		t.Fatal("expected error when leaf returns signing-enabled down_proxy_url path without sign")
	}
}

func TestResolveActualLink_FailsWhenLeafReturnsSigningEnabledDownProxyURLWithInvalidSign(t *testing.T) {
	mountPath := uniqueMountPath(t, "leaf")
	leaf := mustCreateStubStorage(t, mountPath, stubBehavior{
		files: []string{"/signed.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{}, nil
		},
		downProxyURL: "https://proxy.example.com",
	})
	leaf.link = func(model.Obj, model.LinkArgs) (*model.Link, error) {
		return &model.Link{URL: "https://proxy.example.com" + utils.EncodePath(mountPath+"/signed.bin", true) + "?sign=definitely-invalid"}, nil
	}

	_, err := op.ResolveActualLink(context.Background(), mountPath+"/signed.bin", model.LinkArgs{})
	if err == nil {
		t.Fatal("expected error when leaf returns signing-enabled down_proxy_url path with invalid sign")
	}
}

func TestResolveActualLink_FailsWhenLeafReturnsMalformedQueryBaseDownProxyDerivedURL(t *testing.T) {
	mountPath := uniqueMountPath(t, "leaf")
	leaf := mustCreateStubStorage(t, mountPath, stubBehavior{
		files: []string{"/file.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{}, nil
		},
		downProxyURL:     "https://proxy.example.com?foo=1",
		disableProxySign: true,
	})
	leaf.link = func(model.Obj, model.LinkArgs) (*model.Link, error) {
		return &model.Link{URL: "https://proxy.example.com?foo=1" + utils.EncodePath(mountPath+"/file.bin", true)}, nil
	}

	_, err := op.ResolveActualLink(context.Background(), mountPath+"/file.bin", model.LinkArgs{})
	if err == nil {
		t.Fatal("expected error when leaf returns malformed-query down_proxy_url-derived URL")
	}
}

func TestResolveActualLink_FailsWhenLeafReturnsMalformedFragmentBaseDownProxyDerivedURL(t *testing.T) {
	mountPath := uniqueMountPath(t, "leaf")
	leaf := mustCreateStubStorage(t, mountPath, stubBehavior{
		files: []string{"/file.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{}, nil
		},
		downProxyURL:     "https://proxy.example.com#frag",
		disableProxySign: true,
	})
	leaf.link = func(model.Obj, model.LinkArgs) (*model.Link, error) {
		return &model.Link{URL: "https://proxy.example.com#frag" + utils.EncodePath(mountPath+"/file.bin", true)}, nil
	}

	_, err := op.ResolveActualLink(context.Background(), mountPath+"/file.bin", model.LinkArgs{})
	if err == nil {
		t.Fatal("expected error when leaf returns malformed-fragment down_proxy_url-derived URL")
	}
}

func TestResolveActualLink_FailsWhenLeafReturnsSignedSynthesizedExternalDownProxyURLWithExtraQuery(t *testing.T) {
	leafMount := uniqueMountPath(t, "leaf")
	leaf := mustCreateStubStorage(t, leafMount, stubBehavior{
		files: []string{"/signed.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{}, nil
		},
		downProxyURL: "https://proxy.example.com",
	})
	proxyURL := common.GenerateDownProxyURL(leaf.GetStorage(), leafMount+"/signed.bin") + "&extra=1"
	leaf.link = func(model.Obj, model.LinkArgs) (*model.Link, error) {
		return &model.Link{URL: proxyURL}, nil
	}

	aliasMount := uniqueMountPath(t, "alias")
	mustCreateStorage(t, model.Storage{
		MountPath: aliasMount,
		Driver:    "Alias",
		Addition: mustMarshal(t, alias.Addition{
			Paths:           leafMount,
			ProtectSameName: true,
		}),
	})

	_, err := op.ResolveActualLink(context.Background(), aliasMount+"/signed.bin", model.LinkArgs{})
	if err == nil {
		t.Fatal("expected error when leaf returns signed synthesized external down_proxy_url with extra query suffix")
	}
}

func TestResolveActualLink_FailsWhenLeafReturnsSignedSynthesizedExternalDownProxyURLWithFragment(t *testing.T) {
	leafMount := uniqueMountPath(t, "leaf")
	leaf := mustCreateStubStorage(t, leafMount, stubBehavior{
		files: []string{"/signed.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{}, nil
		},
		downProxyURL: "https://proxy.example.com",
	})
	proxyURL := common.GenerateDownProxyURL(leaf.GetStorage(), leafMount+"/signed.bin") + "#x"
	leaf.link = func(model.Obj, model.LinkArgs) (*model.Link, error) {
		return &model.Link{URL: proxyURL}, nil
	}

	_, err := op.ResolveActualLink(context.Background(), leafMount+"/signed.bin", model.LinkArgs{})
	if err == nil {
		t.Fatal("expected error when leaf returns signed synthesized external down_proxy_url with fragment suffix")
	}
}

func TestResolveActualLink_FailsWhenBalanceLeafReturnsConcreteDownProxyURL(t *testing.T) {
	leafBaseMount := uniqueMountPath(t, "leaf")
	mustCreateStubStorage(t, leafBaseMount, stubBehavior{
		files: []string{"/file.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/member-one.bin"}, nil
		},
		downProxyURL: "https://proxy.example.com",
	})
	selectedLeaf := mustCreateStubStorage(t, leafBaseMount+".balance", stubBehavior{
		files: []string{"/file.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/member-two.bin"}, nil
		},
		downProxyURL: "https://proxy.example.com",
	})
	concreteProxyURL := common.GenerateDownProxyURL(selectedLeaf.GetStorage(), leafBaseMount+".balance/file.bin")
	if got, unwanted := concreteProxyURL, common.GenerateDownProxyURL(selectedLeaf.GetStorage(), leafBaseMount+"/file.bin"); got == unwanted {
		t.Fatalf("test setup must return the concrete balance member proxy URL, got virtual URL %q", got)
	}
	selectedLeaf.link = func(model.Obj, model.LinkArgs) (*model.Link, error) {
		return &model.Link{URL: concreteProxyURL}, nil
	}

	_, err := op.ResolveActualLink(context.Background(), leafBaseMount+"/file.bin", model.LinkArgs{})
	if err == nil {
		t.Fatal("expected error when balance leaf returns synthesized external down_proxy_url for the concrete member path")
	}
	if got, want := selectedLeaf.linkCalls, 1; got != want {
		t.Fatalf("expected chosen balance leaf link call count %d, got %d", want, got)
	}
}

func TestResolveActualLink_FailsWhenTokenRefreshWouldOnlyAffectDownProxyURLFallback(t *testing.T) {
	tokenSetting, tokenExisted := mustGetOrCreateSettingItem(t, conf.Token, "token-before-link-api-test")
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

	mountPath := uniqueMountPath(t, "leaf")
	mustCreateStubStorage(t, mountPath, stubBehavior{
		files: []string{"/file.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{}, nil
		},
		downProxyURL: "https://proxy.example.com",
	})

	initialToken := mustResetTokenThroughHandler(t)
	_, err := op.ResolveActualLink(context.Background(), mountPath+"/file.bin", model.LinkArgs{})
	if err == nil {
		t.Fatal("expected error when token refresh would only affect down_proxy_url fallback")
	}

	updatedToken := tokenSetting
	updatedToken.Value = initialToken + "-via-save-settings"
	mustSaveSettingsThroughHandler(t, updatedToken)

	_, err = op.ResolveActualLink(context.Background(), mountPath+"/file.bin", model.LinkArgs{})
	if err == nil {
		t.Fatal("expected error after SaveSettings when only down_proxy_url fallback would change")
	}

	resetToken := mustResetTokenThroughHandler(t)
	if resetToken == initialToken {
		t.Fatalf("expected ResetToken to issue a new token, got %q", resetToken)
	}

	_, err = op.ResolveActualLink(context.Background(), mountPath+"/file.bin", model.LinkArgs{})
	if err == nil {
		t.Fatal("expected error after ResetToken when only down_proxy_url fallback would change")
	}
}

func TestResolveActualLink_AliasStopsAtFirstResolvableTargetPath(t *testing.T) {
	firstMount := uniqueMountPath(t, "leaf-one")
	secondMount := uniqueMountPath(t, "leaf-two")
	firstLeaf := mustCreateStubStorage(t, firstMount, stubBehavior{
		files: []string{"/file.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{MFile: strings.NewReader("stream-only")}, nil
		},
	})
	secondLeaf := mustCreateStubStorage(t, secondMount, stubBehavior{
		files: []string{"/file.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/file.bin"}, nil
		},
	})

	aliasMount := uniqueMountPath(t, "alias")
	mustCreateStorage(t, model.Storage{
		MountPath: aliasMount,
		Driver:    "Alias",
		Addition: mustMarshal(t, alias.Addition{
			Paths:           "docs:" + firstMount + "\ndocs:" + secondMount,
			ProtectSameName: true,
		}),
	})

	_, err := op.ResolveActualLink(context.Background(), aliasMount+"/file.bin", model.LinkArgs{})
	if err == nil {
		t.Fatal("expected alias resolution to fail after the first resolvable target path")
	}
	if got := firstLeaf.linkCalls; got != 1 {
		t.Fatalf("expected first alias target to be linked once, got %d", got)
	}
	if got := secondLeaf.linkCalls; got != 0 {
		t.Fatalf("expected later alias targets to be skipped after the first resolvable path, got %d link calls", got)
	}
}

func TestResolveActualLink_AliasFirstExistingTargetWinsEvenWhenOtherTargetHasDifferentLeaf(t *testing.T) {
	firstMount := uniqueMountPath(t, "origin-one")
	firstLeaf := mustCreateStubStorage(t, firstMount, stubBehavior{
		files: []string{"/file-A.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/origin-one.bin"}, nil
		},
	})
	secondMount := uniqueMountPath(t, "origin-two")
	secondLeaf := mustCreateStubStorage(t, secondMount, stubBehavior{
		files: []string{"/file-A.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/origin-two.bin"}, nil
		},
	})

	aliasMount := uniqueMountPath(t, "alias-first-existing")
	mustCreateStorage(t, model.Storage{
		MountPath: aliasMount,
		Driver:    "Alias",
		Addition: mustMarshal(t, alias.Addition{
			Paths:           "docs:" + firstMount + "\ndocs:" + secondMount,
			ProtectSameName: true,
		}),
	})

	link, err := op.ResolveActualLink(context.Background(), aliasMount+"/file-A.bin", model.LinkArgs{})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if got, want := link.URL, "https://download.example.com/origin-one.bin"; got != want {
		t.Fatalf("expected first existing origin upstream %q, got %q", want, got)
	}
	if got, want := firstLeaf.linkCalls, 1; got != want {
		t.Fatalf("expected first leaf link call count %d, got %d", want, got)
	}
	if got := secondLeaf.linkCalls; got != 0 {
		t.Fatalf("expected later alias target to stay unselected after first existing target, got %d link calls", got)
	}
}

func TestResolveActualLink_AliasContinuesPastMountedButMissingTargetUntilObjectExists(t *testing.T) {
	firstMount := uniqueMountPath(t, "leaf-one")
	firstLeaf := mustCreateStubStorage(t, firstMount, stubBehavior{})
	secondMount := uniqueMountPath(t, "leaf-two")
	secondLeaf := mustCreateStubStorage(t, secondMount, stubBehavior{
		files: []string{"/file.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/file.bin"}, nil
		},
	})

	aliasMount := uniqueMountPath(t, "alias")
	mustCreateStorage(t, model.Storage{
		MountPath: aliasMount,
		Driver:    "Alias",
		Addition: mustMarshal(t, alias.Addition{
			Paths:           "docs:" + firstMount + "\ndocs:" + secondMount,
			ProtectSameName: true,
		}),
	})

	link, err := op.ResolveActualLink(context.Background(), aliasMount+"/file.bin", model.LinkArgs{})
	if err != nil {
		t.Fatalf("expected alias to keep probing until a real downstream object exists, got error: %v", err)
	}
	if got, want := link.URL, "https://download.example.com/file.bin"; got != want {
		t.Fatalf("expected downstream direct URL %q, got %q", want, got)
	}
	if got := firstLeaf.linkCalls; got != 0 {
		t.Fatalf("expected missing first alias target to never reach link resolution, got %d link calls", got)
	}
	if got := secondLeaf.linkCalls; got != 1 {
		t.Fatalf("expected second alias target to resolve exactly once, got %d link calls", got)
	}
}

func TestResolveActualLink_NestedAliasBalanceContinuesPastMissingAliasTarget(t *testing.T) {
	missingOriginMount := uniqueMountPath(t, "origin-missing")
	missingOrigin := mustCreateStubStorage(t, missingOriginMount, stubBehavior{})
	existingOriginMount := uniqueMountPath(t, "origin-existing")
	existingOrigin := mustCreateStubStorage(t, existingOriginMount, stubBehavior{
		files: []string{"/file.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/file.bin"}, nil
		},
	})
	unusedOriginMount := uniqueMountPath(t, "origin-unused")
	unusedOrigin := mustCreateStubStorage(t, unusedOriginMount, stubBehavior{
		files: []string{"/file.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/unused.bin"}, nil
		},
	})

	backendMount := uniqueMountPath(t, "backend")
	mustCreateStorage(t, model.Storage{
		MountPath: backendMount,
		Driver:    "Alias",
		Addition: mustMarshal(t, alias.Addition{
			Paths:           unusedOriginMount,
			ProtectSameName: true,
		}),
	})
	mustCreateStorage(t, model.Storage{
		MountPath: backendMount + ".balance",
		Driver:    "Alias",
		Addition: mustMarshal(t, alias.Addition{
			Paths:           "origin:" + missingOriginMount + "\norigin:" + existingOriginMount,
			ProtectSameName: true,
		}),
	})

	workerMount := uniqueMountPath(t, "worker")
	mustCreateStorage(t, model.Storage{
		MountPath: workerMount,
		Driver:    "Alias",
		Addition: mustMarshal(t, alias.Addition{
			Paths:           unusedOriginMount,
			ProtectSameName: true,
		}),
	})
	mustCreateStorage(t, model.Storage{
		MountPath: workerMount + ".balance",
		Driver:    "Alias",
		Addition: mustMarshal(t, alias.Addition{
			Paths:           backendMount,
			ProtectSameName: true,
		}),
	})

	guestMount := uniqueMountPath(t, "guest")
	mustCreateStorage(t, model.Storage{
		MountPath: guestMount,
		Driver:    "Alias",
		Addition: mustMarshal(t, alias.Addition{
			Paths:           workerMount,
			ProtectSameName: true,
		}),
	})

	link, err := op.ResolveActualLink(context.Background(), guestMount+"/file.bin", model.LinkArgs{})
	if err != nil {
		t.Fatalf("expected nested alias balance path to resolve through the existing origin target, got error: %v", err)
	}
	if got, want := link.URL, "https://download.example.com/file.bin"; got != want {
		t.Fatalf("expected downstream direct URL %q, got %q", want, got)
	}
	if got := missingOrigin.linkCalls; got != 0 {
		t.Fatalf("expected missing origin target to never reach link resolution, got %d link calls", got)
	}
	if got := existingOrigin.linkCalls; got != 1 {
		t.Fatalf("expected existing origin target to resolve exactly once, got %d link calls", got)
	}
	if got := unusedOrigin.linkCalls; got != 0 {
		t.Fatalf("expected alternate balance siblings to be skipped, got %d link calls", got)
	}
}

func TestResolveActualLink_AliasBalanceUsesChosenMemberOnly(t *testing.T) {
	baseMount := uniqueMountPath(t, "balance")
	successful := mustCreateStubStorage(t, baseMount, stubBehavior{
		files: []string{"/file.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/file.bin"}, nil
		},
	})
	failing := mustCreateStubStorage(t, baseMount+".balance", stubBehavior{
		files: []string{"/file.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{MFile: strings.NewReader("stream-only")}, nil
		},
	})

	aliasMount := uniqueMountPath(t, "alias")
	mustCreateStorage(t, model.Storage{
		MountPath: aliasMount,
		Driver:    "Alias",
		Addition: mustMarshal(t, alias.Addition{
			Paths:           "docs:" + baseMount,
			ProtectSameName: true,
		}),
	})

	_, err := op.ResolveActualLink(context.Background(), aliasMount+"/file.bin", model.LinkArgs{})
	if err == nil {
		t.Fatal("expected alias -> balance resolution to fail for the chosen member without probing alternates")
	}
	if got := failing.linkCalls; got != 1 {
		t.Fatalf("expected the chosen balance member to be linked once, got %d", got)
	}
	if got := successful.linkCalls; got != 0 {
		t.Fatalf("expected alternate balance members to be skipped, got %d link calls", got)
	}
}

func TestResolveActualStoragePath_AliasReturnsResolvedDownstreamRawPath(t *testing.T) {
	leafMount := uniqueMountPath(t, "leaf")
	mustCreateStubStorage(t, leafMount, stubBehavior{
		files: []string{"/file.bin"},
	})

	aliasMount := uniqueMountPath(t, "alias")
	mustCreateStorage(t, model.Storage{
		MountPath: aliasMount,
		Driver:    "Alias",
		Addition: mustMarshal(t, alias.Addition{
			Paths:           "docs:" + leafMount + "\nmirror:/does-not-exist",
			ProtectSameName: true,
		}),
	})

	storage, actualPath, resolvedPath, err := op.ResolveActualStoragePath(context.Background(), aliasMount+"/docs/file.bin")
	if err != nil {
		t.Fatalf("expected alias path to resolve, got error: %v", err)
	}
	if got, want := storage.GetStorage().MountPath, leafMount; got != want {
		t.Fatalf("expected downstream leaf storage %q, got %q", want, got)
	}
	if got, want := actualPath, "/file.bin"; got != want {
		t.Fatalf("expected downstream actual path %q, got %q", want, got)
	}
	if got, want := resolvedPath, leafMount+"/file.bin"; got != want {
		t.Fatalf("expected resolved downstream raw path %q, got %q", want, got)
	}
	if got, unwanted := resolvedPath, aliasMount+"/docs/file.bin"; got == unwanted {
		t.Fatalf("expected alias to return downstream raw path, got wrapper raw path %q", got)
	}
}

func TestResolveActualStoragePath_StrmPassThroughRealFileResolvesDownstreamPathWithoutProxyLogic(t *testing.T) {
	leafMount := uniqueMountPath(t, "leaf")
	mustCreateStubStorage(t, leafMount, stubBehavior{
		files: []string{"/movie.mkv"},
	})

	strmMount := uniqueMountPath(t, "strm")
	mustCreateStorage(t, model.Storage{
		MountPath: strmMount,
		Driver:    "Strm",
		Addition: mustMarshal(t, strm.Addition{
			Paths:      "library:" + leafMount,
			EncodePath: true,
		}),
	})

	storage, actualPath, resolvedPath, err := op.ResolveActualStoragePath(context.Background(), strmMount+"/movie.mkv")
	if err != nil {
		t.Fatalf("expected strm pass-through path to resolve, got error: %v", err)
	}
	if got, want := storage.GetStorage().MountPath, leafMount; got != want {
		t.Fatalf("expected downstream leaf storage %q, got %q", want, got)
	}
	if got, want := actualPath, "/movie.mkv"; got != want {
		t.Fatalf("expected downstream actual path %q, got %q", want, got)
	}
	if got, want := resolvedPath, leafMount+"/movie.mkv"; got != want {
		t.Fatalf("expected resolved leaf path %q, got %q", want, got)
	}
}

func TestResolveActualLink_StrmRealDownstreamStrmFileResolvesAsPassThroughDownload(t *testing.T) {
	leafMount := uniqueMountPath(t, "leaf")
	leaf := mustCreateStubStorage(t, leafMount, stubBehavior{
		files: []string{"/movie.strm"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/movie.strm"}, nil
		},
	})

	strmMount := uniqueMountPath(t, "strm")
	mustCreateStorage(t, model.Storage{
		MountPath: strmMount,
		Driver:    "Strm",
		Addition: mustMarshal(t, strm.Addition{
			Paths:      "library:" + leafMount,
			EncodePath: true,
		}),
	})

	link, err := op.ResolveActualLink(context.Background(), strmMount+"/movie.strm", model.LinkArgs{})
	if err != nil {
		t.Fatalf("expected real downstream .strm file to resolve, got error: %v", err)
	}
	if got, want := link.URL, "https://download.example.com/movie.strm"; got != want {
		t.Fatalf("expected downstream direct URL %q, got %q", want, got)
	}
	if got := leaf.linkCalls; got != 1 {
		t.Fatalf("expected downstream leaf link to be used once, got %d calls", got)
	}
	if got := link.Header.Get("Authorization"); got != "" {
		t.Fatalf("expected no unexpected headers, got %q", got)
	}
	if link.MFile != nil {
		t.Fatal("expected pass-through real file download, got virtual MFile result")
	}
	if link.RangeReader != nil {
		t.Fatal("expected pass-through real file download, got RangeReader result")
	}
	if strings.Contains(link.URL, "/p/") {
		t.Fatalf("expected real downstream file result, got local proxy URL %q", link.URL)
	}
}

func TestResolveActualLink_StrmContinuesPastMountedButMissingTargetUntilObjectExists(t *testing.T) {
	firstMount := uniqueMountPath(t, "leaf-one")
	firstLeaf := mustCreateStubStorage(t, firstMount, stubBehavior{})
	secondMount := uniqueMountPath(t, "leaf-two")
	secondLeaf := mustCreateStubStorage(t, secondMount, stubBehavior{
		files: []string{"/movie.mkv"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/movie.mkv"}, nil
		},
	})

	strmMount := uniqueMountPath(t, "strm")
	mustCreateStorage(t, model.Storage{
		MountPath: strmMount,
		Driver:    "Strm",
		Addition: mustMarshal(t, strm.Addition{
			Paths:      "library:" + firstMount + "\nlibrary:" + secondMount,
			EncodePath: true,
		}),
	})

	link, err := op.ResolveActualLink(context.Background(), strmMount+"/movie.mkv", model.LinkArgs{})
	if err != nil {
		t.Fatalf("expected strm to keep probing until a real downstream object exists, got error: %v", err)
	}
	if got, want := link.URL, "https://download.example.com/movie.mkv"; got != want {
		t.Fatalf("expected downstream direct URL %q, got %q", want, got)
	}
	if got := firstLeaf.linkCalls; got != 0 {
		t.Fatalf("expected missing first target to never reach leaf link resolution, got %d link calls", got)
	}
	if got := secondLeaf.linkCalls; got != 1 {
		t.Fatalf("expected second target to resolve exactly once, got %d link calls", got)
	}
}

func TestResolveActualLink_StrmContinuesPastBalanceTargetWhoseChosenMemberIsMissingObject(t *testing.T) {
	firstMount := uniqueMountPath(t, "balance-one")
	firstAlternate := mustCreateStubStorage(t, firstMount, stubBehavior{
		files: []string{"/movie.mkv"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/should-not-be-used.mkv"}, nil
		},
	})
	firstChosenMissing := mustCreateStubStorage(t, firstMount+".balance", stubBehavior{})
	secondMount := uniqueMountPath(t, "leaf-two")
	secondLeaf := mustCreateStubStorage(t, secondMount, stubBehavior{
		files: []string{"/movie.mkv"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/movie.mkv"}, nil
		},
	})

	strmMount := uniqueMountPath(t, "strm")
	mustCreateStorage(t, model.Storage{
		MountPath: strmMount,
		Driver:    "Strm",
		Addition: mustMarshal(t, strm.Addition{
			Paths:      "library:" + firstMount + "\nlibrary:" + secondMount,
			EncodePath: true,
		}),
	})

	link, err := op.ResolveActualLink(context.Background(), strmMount+"/movie.mkv", model.LinkArgs{})
	if err != nil {
		t.Fatalf("expected strm to skip balance target whose chosen member is missing and continue probing, got error: %v", err)
	}
	if got, want := link.URL, "https://download.example.com/movie.mkv"; got != want {
		t.Fatalf("expected downstream direct URL %q, got %q", want, got)
	}
	if got := firstAlternate.linkCalls; got != 0 {
		t.Fatalf("expected alternate balance sibling on the skipped target to be untouched, got %d link calls", got)
	}
	if got := firstChosenMissing.linkCalls; got != 0 {
		t.Fatalf("expected missing chosen balance sibling on the skipped target to never reach link resolution, got %d link calls", got)
	}
	if got := secondLeaf.linkCalls; got != 1 {
		t.Fatalf("expected second target to resolve exactly once, got %d link calls", got)
	}
}

func TestResolveActualLink_StrmKeepsProbeAndResolutionOnSameChosenBalanceMemberPerRequest(t *testing.T) {
	firstMount := uniqueMountPath(t, "balance-one")
	firstAlternate := mustCreateStubStorage(t, firstMount, stubBehavior{})
	firstChosen := mustCreateStubStorage(t, firstMount+".balance", stubBehavior{
		files: []string{"/movie.mkv"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/pinned-balance.mkv"}, nil
		},
	})
	secondMount := uniqueMountPath(t, "leaf-two")
	secondLeaf := mustCreateStubStorage(t, secondMount, stubBehavior{
		files: []string{"/movie.mkv"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/movie.mkv"}, nil
		},
	})

	strmMount := uniqueMountPath(t, "strm")
	mustCreateStorage(t, model.Storage{
		MountPath: strmMount,
		Driver:    "Strm",
		Addition: mustMarshal(t, strm.Addition{
			Paths:      "library:" + firstMount + "\nlibrary:" + secondMount,
			EncodePath: true,
		}),
	})

	ctx := context.Background()
	if !op.HasLinkAPIObject(ctx, firstMount+"/movie.mkv") {
		t.Fatal("expected initial probe to pin the first target's chosen balance member")
	}

	link, err := op.ResolveActualLink(ctx, strmMount+"/movie.mkv", model.LinkArgs{})
	if err != nil {
		t.Fatalf("expected original request to keep its pinned balance choice through authoritative resolution, got error: %v", err)
	}
	if got, want := link.URL, "https://download.example.com/pinned-balance.mkv"; got != want {
		t.Fatalf("expected downstream direct URL %q, got %q", want, got)
	}
	if got := firstAlternate.linkCalls; got != 0 {
		t.Fatalf("expected original request not to switch to the other balance sibling after probe-time pinning, got %d alternate link calls", got)
	}
	if got := firstChosen.linkCalls; got != 1 {
		t.Fatalf("expected pinned chosen balance member to serve only the original request, got %d link calls", got)
	}
	if got := secondLeaf.linkCalls; got != 0 {
		t.Fatalf("expected original request to stay on the first target instead of falling through, got %d second-target link calls", got)
	}
}

func TestResolveActualLink_StrmProbePinningAdvancesGlobalBalanceSelectionExactlyOnce(t *testing.T) {
	probeMount := uniqueMountPath(t, "probe-balance")
	mustCreateStubStorage(t, probeMount, stubBehavior{
		files: []string{"/movie.mkv"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/member-one.mkv"}, nil
		},
	})
	mustCreateStubStorage(t, probeMount+".balance", stubBehavior{
		files: []string{"/movie.mkv"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/member-two.mkv"}, nil
		},
	})
	controlMount := uniqueMountPath(t, "control-balance")
	mustCreateStubStorage(t, controlMount, stubBehavior{
		files: []string{"/movie.mkv"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/member-one.mkv"}, nil
		},
	})
	mustCreateStubStorage(t, controlMount+".balance", stubBehavior{
		files: []string{"/movie.mkv"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/member-two.mkv"}, nil
		},
	})

	strmMount := uniqueMountPath(t, "strm")
	mustCreateStorage(t, model.Storage{
		MountPath: strmMount,
		Driver:    "Strm",
		Addition: mustMarshal(t, strm.Addition{
			Paths:      "library:" + probeMount,
			EncodePath: true,
		}),
	})

	probeBefore := op.GetBalancedStorage(probeMount + "/movie.mkv")
	controlBefore := op.GetBalancedStorage(controlMount + "/movie.mkv")
	if probeBefore == nil || controlBefore == nil {
		t.Fatal("expected initial global balance selections to exist")
	}
	if got, want := strings.HasSuffix(probeBefore.GetStorage().MountPath, ".balance"), strings.HasSuffix(controlBefore.GetStorage().MountPath, ".balance"); got != want {
		t.Fatalf("expected probe/control groups to start from the same sibling kind, want balance=%t got balance=%t", want, got)
	}

	link, err := op.ResolveActualLink(context.Background(), strmMount+"/movie.mkv", model.LinkArgs{})
	if err != nil {
		t.Fatalf("expected strm request-local probe pinning to resolve successfully, got error: %v", err)
	}
	if got, want := link.URL, "https://download.example.com/member-one.mkv"; got != want {
		t.Fatalf("expected request-local pinning to stay on the same chosen member within the Link API request, want %q got %q", want, got)
	}

	probeAfter := op.GetBalancedStorage(probeMount + "/movie.mkv")
	controlAfter := op.GetBalancedStorage(controlMount + "/movie.mkv")
	if probeAfter == nil || controlAfter == nil {
		t.Fatal("expected fresh global balance selections to stay available after Link API probe pinning")
	}
	if got, want := strings.HasSuffix(controlAfter.GetStorage().MountPath, ".balance"), false; got != want {
		t.Fatalf("expected control group to advance to the non-balance sibling after one direct authoritative step, want balance=%t got balance=%t", want, got)
	}
	if got, want := strings.HasSuffix(probeAfter.GetStorage().MountPath, ".balance"), true; got != want {
		t.Fatalf("expected wrapped Link API request to consume exactly one authoritative advance overall, want balance=%t got balance=%t", want, got)
	}
}

func TestHasLinkAPIObject_ReusesCycleGuardAcrossNestedStrmProbeRecursion(t *testing.T) {
	leafMount := uniqueMountPath(t, "leaf")
	leaf := mustCreateStubStorage(t, leafMount, stubBehavior{
		files: []string{"/movie.mkv"},
	})

	outerLoopMount := uniqueMountPath(t, "outer-loop")
	innerLoopMount := uniqueMountPath(t, "inner-loop")
	registerLoopProbeDriversOnce.Do(func() {
		op.RegisterDriver(func() driverpkg.Driver { return &outerLoopProbeDriver{} })
		op.RegisterDriver(func() driverpkg.Driver { return &innerLoopProbeDriver{} })
	})
	outer := mustCreateLoopProbeStorage(t, model.Storage{MountPath: outerLoopMount, Driver: outerLoopProbeDriverName, Addition: mustMarshal(t, driverpkg.RootPath{RootFolderPath: "/"})}).(*outerLoopProbeDriver)
	inner := mustCreateLoopProbeStorage(t, model.Storage{MountPath: innerLoopMount, Driver: innerLoopProbeDriverName, Addition: mustMarshal(t, driverpkg.RootPath{RootFolderPath: "/"})}).(*innerLoopProbeDriver)
	outer.innerRawPath = innerLoopMount + "/movie.mkv"
	inner.outerRawPath = outerLoopMount + "/movie.mkv"
	inner.delegateRawPath = leafMount + "/movie.mkv"
	t.Cleanup(func() {
		outer.resolveCalls = 0
		outer.innerRawPath = ""
		inner.resolveCalls = 0
		inner.outerRawPath = ""
		inner.delegateRawPath = ""
	})

	if !op.HasLinkAPIObject(context.Background(), outerLoopMount+"/movie.mkv") {
		t.Fatal("expected nested probe recursion with shared seen-set to reach the delegated real object")
	}
	if got := outer.resolveCalls; got != 1 {
		t.Fatalf("expected shared seen-set to stop the loop before a second outer resolve, got %d calls", got)
	}
	if got := inner.resolveCalls; got != 1 {
		t.Fatalf("expected inner loop probe to resolve exactly once, got %d calls", got)
	}
	if got := leaf.getCalls; got != 1 {
		t.Fatalf("expected delegated leaf object lookup once, got %d calls", got)
	}
}

func TestResolveActualLink_StrmVirtualObjectReturnsError(t *testing.T) {
	leafMount := uniqueMountPath(t, "leaf")
	mustCreateStubStorage(t, leafMount, stubBehavior{
		files: []string{"/movie.mkv"},
	})

	strmMount := uniqueMountPath(t, "strm")
	mustCreateStorage(t, model.Storage{
		MountPath: strmMount,
		Driver:    "Strm",
		Addition: mustMarshal(t, strm.Addition{
			Paths:      "library:" + leafMount,
			EncodePath: true,
		}),
	})

	_, err := op.ResolveActualLink(context.Background(), strmMount+"/movie.strm", model.LinkArgs{})
	if err == nil {
		t.Fatal("expected virtual .strm object resolution to fail")
	}
}

func TestResolveActualLink_StrmBalanceUsesChosenMemberOnly(t *testing.T) {
	baseMount := uniqueMountPath(t, "balance")
	successful := mustCreateStubStorage(t, baseMount, stubBehavior{
		files: []string{"/movie.mkv"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/movie.mkv"}, nil
		},
	})
	failing := mustCreateStubStorage(t, baseMount+".balance", stubBehavior{
		files: []string{"/movie.mkv"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{MFile: strings.NewReader("stream-only")}, nil
		},
	})

	strmMount := uniqueMountPath(t, "strm")
	mustCreateStorage(t, model.Storage{
		MountPath: strmMount,
		Driver:    "Strm",
		Addition: mustMarshal(t, strm.Addition{
			Paths:      "library:" + baseMount,
			EncodePath: true,
		}),
	})

	_, err := op.ResolveActualLink(context.Background(), strmMount+"/movie.mkv", model.LinkArgs{})
	if err == nil {
		t.Fatal("expected strm -> balance resolution to fail for the chosen member without probing alternates")
	}
	if got := failing.linkCalls; got != 1 {
		t.Fatalf("expected the chosen balance member to be linked once, got %d", got)
	}
	if got := successful.linkCalls; got != 0 {
		t.Fatalf("expected alternate balance members to be skipped, got %d link calls", got)
	}
}

func TestResolveActualLink_BalanceUsesChosenMemberOnly(t *testing.T) {
	baseMount := uniqueMountPath(t, "balance")
	successful := mustCreateStubStorage(t, baseMount, stubBehavior{
		files: []string{"/file.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/file.bin"}, nil
		},
	})
	failing := mustCreateStubStorage(t, baseMount+".balance", stubBehavior{
		files: []string{"/file.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{MFile: strings.NewReader("stream-only")}, nil
		},
	})

	_, err := op.ResolveActualLink(context.Background(), baseMount+"/file.bin", model.LinkArgs{})
	if err == nil {
		t.Fatal("expected chosen balance member to fail without probing alternates")
	}
	if got := failing.linkCalls; got != 1 {
		t.Fatalf("expected the chosen balance member to be linked once, got %d", got)
	}
	if got := successful.linkCalls; got != 0 {
		t.Fatalf("expected alternate balance members to be skipped, got %d link calls", got)
	}
}

func TestResolveActualLink_BalanceAdvancesAuthoritativeProgressionWithoutRequestLocalPin(t *testing.T) {
	baseMount := uniqueMountPath(t, "balance")
	mustCreateStubStorage(t, baseMount, stubBehavior{
		files: []string{"/file.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/member-one.bin"}, nil
		},
	})
	mustCreateStubStorage(t, baseMount+".balance", stubBehavior{
		files: []string{"/file.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/member-two.bin"}, nil
		},
	})

	for i, want := range []string{
		"https://download.example.com/member-two.bin",
		"https://download.example.com/member-one.bin",
		"https://download.example.com/member-two.bin",
	} {
		link, err := op.ResolveActualLink(context.Background(), baseMount+"/file.bin", model.LinkArgs{})
		if err != nil {
			t.Fatalf("request %d: expected success, got error: %v", i+1, err)
		}
		if got := link.URL; got != want {
			t.Fatalf("request %d: expected authoritative balance progression URL %q, got %q", i+1, want, got)
		}
	}
}

func TestResolveActualLink_NestedAliasBalanceAdvancesAcrossRequestsAfterProbeFallback(t *testing.T) {
	baseMount := uniqueMountPath(t, "balance")
	mustCreateStubStorage(t, baseMount, stubBehavior{
		files: []string{"/file.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/member-one.bin"}, nil
		},
	})
	mustCreateStubStorage(t, baseMount+".balance", stubBehavior{
		files: []string{"/file.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/member-two.bin"}, nil
		},
	})

	wrapperMount := uniqueMountPath(t, "alias")
	mustCreateStorage(t, model.Storage{
		MountPath: wrapperMount,
		Driver:    "Alias",
		Addition: mustMarshal(t, alias.Addition{
			Paths:           baseMount,
			ProtectSameName: true,
		}),
	})

	for i, want := range []string{
		"https://download.example.com/member-two.bin",
		"https://download.example.com/member-one.bin",
		"https://download.example.com/member-two.bin",
	} {
		link, err := op.ResolveActualLink(context.Background(), wrapperMount+"/file.bin", model.LinkArgs{})
		if err != nil {
			t.Fatalf("request %d: expected success, got error: %v", i+1, err)
		}
		if got := link.URL; got != want {
			t.Fatalf("request %d: expected nested wrapper balance progression URL %q, got %q", i+1, want, got)
		}
	}
}

func TestResolveActualLink_ReusesPinnedBalanceAcrossFailedNestedBranchesInSingleRequest(t *testing.T) {
	baseMount := uniqueMountPath(t, "balance")
	memberOne := mustCreateStubStorage(t, baseMount, stubBehavior{
		files: []string{"/file.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/member-one.bin"}, nil
		},
	})
	memberTwoMissing := mustCreateStubStorage(t, baseMount+".balance", stubBehavior{})

	branchOneMount := uniqueMountPath(t, "branch-one")
	mustCreateStorage(t, model.Storage{
		MountPath: branchOneMount,
		Driver:    "Alias",
		Addition: mustMarshal(t, alias.Addition{
			Paths:           baseMount,
			ProtectSameName: true,
		}),
	})
	branchTwoMount := uniqueMountPath(t, "branch-two")
	mustCreateStorage(t, model.Storage{
		MountPath: branchTwoMount,
		Driver:    "Alias",
		Addition: mustMarshal(t, alias.Addition{
			Paths:           baseMount,
			ProtectSameName: true,
		}),
	})

	topMount := uniqueMountPath(t, "top")
	mustCreateStorage(t, model.Storage{
		MountPath: topMount,
		Driver:    "Alias",
		Addition: mustMarshal(t, alias.Addition{
			Paths:           "docs:" + branchOneMount + "\ndocs:" + branchTwoMount,
			ProtectSameName: true,
		}),
	})

	_, err := op.ResolveActualLink(context.Background(), topMount+"/file.bin", model.LinkArgs{})
	if err == nil {
		t.Fatal("expected request to keep the first chosen missing balance member across duplicate nested branches")
	}
	if got := memberOne.linkCalls; got != 0 {
		t.Fatalf("expected duplicate nested branches not to retry the alternate balance sibling in the same request, got %d link calls", got)
	}
	if got := memberTwoMissing.linkCalls; got != 0 {
		t.Fatalf("expected missing chosen balance sibling to never reach link resolution, got %d link calls", got)
	}

	link, err := op.ResolveActualLink(context.Background(), topMount+"/file.bin", model.LinkArgs{})
	if err != nil {
		t.Fatalf("expected next request to advance to the other balance sibling, got error: %v", err)
	}
	if got, want := link.URL, "https://download.example.com/member-one.bin"; got != want {
		t.Fatalf("expected next request to resolve through %q, got %q", want, got)
	}
}

func TestResolveActualLink_ProbePinnedBalanceRequestsDoNotCollapseSameMemberAcrossOverlap(t *testing.T) {
	baseMount := uniqueMountPath(t, "balance")
	mustCreateStubStorage(t, baseMount, stubBehavior{
		files: []string{"/file.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/member-one.bin"}, nil
		},
	})
	mustCreateStubStorage(t, baseMount+".balance", stubBehavior{
		files: []string{"/file.bin"},
		link: func(model.Obj, model.LinkArgs) (*model.Link, error) {
			return &model.Link{URL: "https://download.example.com/member-two.bin"}, nil
		},
	})

	wrapperMount := uniqueMountPath(t, "alias")
	mustCreateStorage(t, model.Storage{
		MountPath: wrapperMount,
		Driver:    "Alias",
		Addition: mustMarshal(t, alias.Addition{
			Paths:           baseMount,
			ProtectSameName: true,
		}),
	})

	start := make(chan struct{})
	type result struct {
		url string
		err error
	}
	results := make(chan result, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			link, err := op.ResolveActualLink(context.Background(), wrapperMount+"/file.bin", model.LinkArgs{})
			if err != nil {
				results <- result{err: err}
				return
			}
			results <- result{url: link.URL}
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	seen := map[string]int{}
	for res := range results {
		if res.err != nil {
			t.Fatalf("expected overlapped request to resolve successfully, got error: %v", res.err)
		}
		seen[res.url]++
	}
	if got, want := len(seen), 2; got != want {
		t.Fatalf("expected overlapped requests to split across both balance members, got %v", seen)
	}
	if got, want := seen["https://download.example.com/member-one.bin"], 1; got != want {
		t.Fatalf("expected exactly one overlapped request to use member one, got counts %v", seen)
	}
	if got, want := seen["https://download.example.com/member-two.bin"], 1; got != want {
		t.Fatalf("expected exactly one overlapped request to use member two, got counts %v", seen)
	}

	next, err := op.ResolveActualLink(context.Background(), wrapperMount+"/file.bin", model.LinkArgs{})
	if err != nil {
		t.Fatalf("expected follow-up request to resolve successfully, got error: %v", err)
	}
	if got, want := next.URL, "https://download.example.com/member-two.bin"; got != want {
		t.Fatalf("expected follow-up request to continue global progression at %q, got %q", want, got)
	}
}

func uniqueMountPath(t *testing.T, suffix string) string {
	t.Helper()

	name := strings.ToLower(t.Name())
	replacer := strings.NewReplacer("/", "-", "_", "-", " ", "-")
	return "/test-link-api/" + replacer.Replace(name) + "-" + suffix
}

func mustCreateStorage(t *testing.T, storage model.Storage) driverpkg.Driver {
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

func mustCreateLoopProbeStorage(t *testing.T, storage model.Storage) driverpkg.Driver {
	t.Helper()
	return mustCreateStorage(t, storage)
}

func mustMarshal(t *testing.T, value any) string {
	t.Helper()

	bytes, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("failed to marshal test addition: %v", err)
	}
	return string(bytes)
}

func mustGetSettingItem(t *testing.T, key string) model.SettingItem {
	t.Helper()

	item, err := op.GetSettingItemByKey(key)
	if err != nil {
		t.Fatalf("failed to load setting %q: %v", key, err)
	}
	return *item
}

func mustGetOrCreateSettingItem(t *testing.T, key, defaultValue string) (model.SettingItem, bool) {
	t.Helper()

	item, err := op.GetSettingItemByKey(key)
	if err == nil {
		return *item, true
	}
	created := model.SettingItem{Key: key, Value: defaultValue}
	mustSaveSettingItem(t, created)
	return created, false
}

func mustSaveSettingItem(t *testing.T, item model.SettingItem) {
	t.Helper()

	copy := item
	if err := op.SaveSettingItem(&copy); err != nil {
		t.Fatalf("failed to save setting %q: %v", item.Key, err)
	}
}

func mustSaveSettingsThroughHandler(t *testing.T, items ...model.SettingItem) {
	t.Helper()

	body, err := json.Marshal(items)
	if err != nil {
		t.Fatalf("failed to marshal settings request: %v", err)
	}

	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	request, err := http.NewRequest(http.MethodPost, "/api/admin/setting/save", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("failed to build settings request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	ctx.Request = request

	serverhandles.SaveSettings(ctx)

	var resp struct {
		Code int `json:"code"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode settings response: %v", err)
	}
	if resp.Code != 200 {
		t.Fatalf("expected SaveSettings success, got http=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func mustResetTokenThroughHandler(t *testing.T) string {
	t.Helper()

	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	request, err := http.NewRequest(http.MethodPost, "/api/admin/setting/reset_token", nil)
	if err != nil {
		t.Fatalf("failed to build ResetToken request: %v", err)
	}
	ctx.Request = request

	serverhandles.ResetToken(ctx)

	var resp struct {
		Code int    `json:"code"`
		Data string `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode ResetToken response: %v", err)
	}
	if resp.Code != 200 || resp.Data == "" {
		t.Fatalf("expected ResetToken success with token, got http=%d body=%s", recorder.Code, recorder.Body.String())
	}
	return resp.Data
}

func mustDeleteSettingItem(t *testing.T, key string) {
	t.Helper()

	if err := db.DeleteSettingItemByKey(key); err != nil {
		t.Fatalf("failed to delete setting %q: %v", key, err)
	}
	op.SettingCacheUpdate()
}

const stubDriverName = "TestLinkAPIStub"

var registerStubDriverOnce sync.Once

var stubFixtures = struct {
	sync.Mutex
	byMountPath map[string]stubBehavior
}{
	byMountPath: map[string]stubBehavior{},
}

type stubBehavior struct {
	files            []string
	link             func(model.Obj, model.LinkArgs) (*model.Link, error)
	linkErr          error
	downProxyURL     string
	disableProxySign bool
}

func mustCreateStubStorage(t *testing.T, mountPath string, behavior stubBehavior) *stubLinkDriver {
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
		Proxy: model.Proxy{
			DownProxyURL:     behavior.downProxyURL,
			DisableProxySign: behavior.disableProxySign,
		},
	})

	stub, ok := drv.(*stubLinkDriver)
	if !ok {
		t.Fatalf("expected %q to be a *stubLinkDriver, got %T", mountPath, drv)
	}
	return stub
}

type stubLinkDriver struct {
	model.Storage

	addition driverpkg.RootPath
	files    map[string]*model.Object
	link     func(model.Obj, model.LinkArgs) (*model.Link, error)
	linkErr  error

	getCalls  int
	linkCalls int
}

func (d *stubLinkDriver) Config() driverpkg.Config {
	return driverpkg.Config{Name: stubDriverName, DefaultRoot: "/"}
}

func (d *stubLinkDriver) GetAddition() driverpkg.Additional {
	return &d.addition
}

func (d *stubLinkDriver) Init(ctx context.Context) error {
	stubFixtures.Lock()
	fixture, ok := stubFixtures.byMountPath[d.MountPath]
	stubFixtures.Unlock()
	if !ok {
		return errors.New("missing stub fixture for " + d.MountPath)
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
	return nil
}

func (d *stubLinkDriver) Drop(ctx context.Context) error {
	return nil
}

func (d *stubLinkDriver) List(ctx context.Context, dir model.Obj, args model.ListArgs) ([]model.Obj, error) {
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
		objs = append(objs, cloneObject(d.files[filePath]))
	}
	return objs, nil
}

func (d *stubLinkDriver) Get(ctx context.Context, path string) (model.Obj, error) {
	d.getCalls++
	path = utils.FixAndCleanPath(path)
	if path == "/" {
		return &model.Object{
			Path:     "/",
			Name:     "Root",
			Modified: d.Modified,
			IsFolder: true,
		}, nil
	}
	obj, ok := d.files[path]
	if !ok {
		return nil, errs.ObjectNotFound
	}
	return cloneObject(obj), nil
}

func (d *stubLinkDriver) Link(ctx context.Context, file model.Obj, args model.LinkArgs) (*model.Link, error) {
	d.linkCalls++
	if d.linkErr != nil {
		return nil, d.linkErr
	}
	if d.link == nil {
		return nil, errors.New("stub link function not configured")
	}
	return d.link(file, args)
}

func cloneObject(obj *model.Object) *model.Object {
	clone := *obj
	return &clone
}

var _ driverpkg.Driver = (*stubLinkDriver)(nil)
var _ driverpkg.Getter = (*stubLinkDriver)(nil)

const outerLoopProbeDriverName = "TestLinkAPIOuterLoopProbe"
const innerLoopProbeDriverName = "TestLinkAPIInnerLoopProbe"

var registerLoopProbeDriversOnce sync.Once

type outerLoopProbeDriver struct {
	model.Storage

	addition     driverpkg.RootPath
	innerRawPath string
	resolveCalls int
}

func (d *outerLoopProbeDriver) Config() driverpkg.Config {
	return driverpkg.Config{Name: outerLoopProbeDriverName, DefaultRoot: "/"}
}

func (d *outerLoopProbeDriver) GetAddition() driverpkg.Additional {
	return &d.addition
}

func (d *outerLoopProbeDriver) Init(ctx context.Context) error { return nil }
func (d *outerLoopProbeDriver) Drop(ctx context.Context) error { return nil }
func (d *outerLoopProbeDriver) List(ctx context.Context, dir model.Obj, args model.ListArgs) ([]model.Obj, error) {
	return nil, errs.NotImplement
}
func (d *outerLoopProbeDriver) Link(ctx context.Context, file model.Obj, args model.LinkArgs) (*model.Link, error) {
	return nil, errs.NotImplement
}
func (d *outerLoopProbeDriver) ResolveLinkAPIRawPath(ctx context.Context, rawPath string) (string, error) {
	d.resolveCalls++
	if d.resolveCalls > 2 {
		return "", errs.ObjectNotFound
	}
	return d.innerRawPath, nil
}

type innerLoopProbeDriver struct {
	model.Storage

	addition        driverpkg.RootPath
	outerRawPath    string
	delegateRawPath string
	resolveCalls    int
}

func (d *innerLoopProbeDriver) Config() driverpkg.Config {
	return driverpkg.Config{Name: innerLoopProbeDriverName, DefaultRoot: "/"}
}

func (d *innerLoopProbeDriver) GetAddition() driverpkg.Additional {
	return &d.addition
}

func (d *innerLoopProbeDriver) Init(ctx context.Context) error { return nil }
func (d *innerLoopProbeDriver) Drop(ctx context.Context) error { return nil }
func (d *innerLoopProbeDriver) List(ctx context.Context, dir model.Obj, args model.ListArgs) ([]model.Obj, error) {
	return nil, errs.NotImplement
}
func (d *innerLoopProbeDriver) Link(ctx context.Context, file model.Obj, args model.LinkArgs) (*model.Link, error) {
	return nil, errs.NotImplement
}
func (d *innerLoopProbeDriver) ResolveLinkAPIRawPath(ctx context.Context, rawPath string) (string, error) {
	d.resolveCalls++
	if !op.HasLinkAPIObject(ctx, d.outerRawPath) {
		return d.delegateRawPath, nil
	}
	return "", errs.ObjectNotFound
}

var _ driverpkg.Driver = (*outerLoopProbeDriver)(nil)
var _ driverpkg.Driver = (*innerLoopProbeDriver)(nil)
