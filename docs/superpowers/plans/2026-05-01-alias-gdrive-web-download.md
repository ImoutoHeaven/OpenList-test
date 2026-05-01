# Alias + GoogleDrive Web Download Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Separate real-upstream `Link API` extraction from browser-facing web-download routing so nested alias and `.balance` chains honor the first non-`302` policy owner while `/api/fs/link` returns only real leaf upstream URLs.

**Architecture:** Add a dedicated web-download route resolver in `internal/op` that preserves ordered wrapper nodes, selected policy owner, and resolved leaf member in one per-request result. Migrate `/d/*`, `/p/*`, and `fsread` `raw_url` to consume that route instead of direct leaf-only proxy checks, and tighten `ResolveActualLink` so it rejects every proxy-derived fallback.

**Tech Stack:** Go, Gin, existing `internal/op` storage-resolution helpers, existing alias `ResolveLinkAPIRawPath` support, existing balance pinning state in `internal/op/link_api.go`, existing handler/unit tests in `internal/op` and `server/handles`

---

## File Structure

Planned file responsibilities for this change:

- Modify: `internal/op/link_api.go`
Purpose: tighten `ResolveActualLink` to require real leaf upstream URLs only; add shared helper(s) for validating real upstream link results instead of proxy-derived fallbacks.

- Modify: `internal/op/link_api.go`
Purpose: preserve the existing nested alias and balance resolution behavior as the repo-backed reference point for the new web-download resolver while keeping real-upstream validation and request-local balance handling consistent.

- Create: `internal/op/web_download.go`
Purpose: define the `WebDownloadRoute` model, ordered route nodes, unified browser-download native-proxy classification, route resolution over alias and balance chains, canonical owner-path helpers, and entry-point-specific URL-emission helpers.

- Create: `internal/op/web_download_test.go`
Purpose: unit-test the new web-download route resolver independently from handlers, covering nested alias, owner selection, `.balance` pinning, alias merge routing, and canonical emitted path rules.

- Modify: `server/handles/down.go`
Purpose: replace direct `fs.GetStorage`/`ShouldProxy`/`canProxy` browser-routing logic with `WebDownloadRoute` consumption for `/d/*` and `/p/*`.

- Modify: `server/handles/fsread.go`
Purpose: replace leaf-only `raw_url` generation with owner-aware `WebDownloadRoute` generation while preserving provider lookup behavior.

- Modify: `internal/op/link_api_test.go`
Purpose: rewrite current proxy-fallback expectations for `ResolveActualLink`, preserve existing alias/balance routing expectations that stay valid, and add any missing `ActualLink` contract coverage.

- Modify: `server/handles/fsmanage_test.go`
Purpose: keep `/api/fs/link` handler tests aligned with the tightened real-upstream-only contract.

- Create: `server/handles/down_test.go`
Purpose: add HTTP handler tests for `/d/*` and `/p/*` owner-policy behavior, canonicalization, `d=1` bypass, and no recursion.

## TASK_GROUP 1: Freeze `ActualLink` To Real-Upstream-Only Behavior

### Task 1: Convert `ResolveActualLink` tests away from proxy fallback

**Files:**
- Modify: `internal/op/link_api_test.go`
- Modify: `server/handles/fsmanage_test.go`

- [ ] **Step 1: Write the failing test updates for `ResolveActualLink` proxy-fallback cases**

Update every existing test that currently treats `down_proxy_url` fallback as a valid `ResolveActualLink` outcome so the contract instead requires an error.

Required expectation changes:

```go
func TestResolveActualLink_FailsWhenLeafHasNoRealUpstreamURL(t *testing.T) {
    _, err := op.ResolveActualLink(context.Background(), mountPath+"/file.bin", model.LinkArgs{})
    if err == nil {
        t.Fatal("expected error when leaf has no real upstream URL")
    }
}

func TestResolveActualLink_FailsWhenLeafReturnsOpenListLocalURL(t *testing.T) {
    _, err := op.ResolveActualLink(ctx, mountPath+"/file.bin", model.LinkArgs{})
    if err == nil {
        t.Fatal("expected error when leaf returns OpenList-local URL")
    }
}

func TestResolveActualLink_FailsWhenLeafReturnsRelativeURL(t *testing.T) {
    _, err := op.ResolveActualLink(context.Background(), mountPath+"/file.bin", model.LinkArgs{})
    if err == nil {
        t.Fatal("expected error when leaf returns relative URL")
    }
}

func TestResolveActualLink_FailsWhenResolvedLeafWouldFallbackToDownProxyURL(t *testing.T) {
    _, err := op.ResolveActualLink(context.Background(), aliasMount+"/file.bin", model.LinkArgs{})
    if err == nil {
        t.Fatal("expected error when resolved leaf only has down_proxy_url fallback")
    }
}

func TestResolveActualLink_FailsWhenLeafWouldOnlyProduceSignedDownProxyURL(t *testing.T) {
    _, err := op.ResolveActualLink(context.Background(), mountPath+"/signed.bin", model.LinkArgs{})
    if err == nil {
        t.Fatal("expected error when signed down_proxy_url fallback is the only available result")
    }
}

func TestResolveActualLink_FailsWhenTokenRefreshWouldOnlyAffectDownProxyURLFallback(t *testing.T) {
    _, err := op.ResolveActualLink(context.Background(), mountPath+"/file.bin", model.LinkArgs{})
    if err == nil {
        t.Fatal("expected error when token refresh would only affect down_proxy_url fallback")
    }
}
```

- [ ] **Step 2: Run the focused `ResolveActualLink` tests and verify they fail for the right reason**

Run: `go test ./internal/op -run 'TestResolveActualLink_(FailsWhenLeafHasNoRealUpstreamURL|FailsWhenLeafReturnsOpenListLocalURL|FailsWhenLeafReturnsRelativeURL|FailsWhenResolvedLeafWouldFallbackToDownProxyURL|FailsWhenLeafWouldOnlyProduceSignedDownProxyURL|FailsWhenTokenRefreshWouldOnlyAffectDownProxyURLFallback)' -count=1`

Expected: FAIL because `ResolveActualLink` still synthesizes `down_proxy_url` fallback today.

- [ ] **Step 3: Write the failing handler expectation for `/api/fs/link`**

Keep the existing handler-level error test and preserve its explicit error assertions so the handler clearly treats non-upstream leaf results as failure.

Assertion shape:

```go
func TestLinkHandler_ReturnsJSONErrorWhenLeafHasNoExternalURLAndNoDownProxyURL(t *testing.T) {
    if got, want := resp.Code, 500; got != want {
        t.Fatalf("expected response code %d, got %d", want, got)
    }
    if string(resp.Data) != "null" {
        t.Fatalf("expected nil data payload, got %s", string(resp.Data))
    }
}
```

- [ ] **Step 4: Run the handler tests and verify the tightened `/api/fs/link` contract tests pass**

Run: `go test ./server/handles -run 'TestLinkHandler_(ReturnsLeafDirectURLWithoutPProxyFallback|ReturnsJSONErrorWhenLeafHasNoExternalURLAndNoDownProxyURL)' -count=1`

Expected: PASS. `/api/fs/link` must continue to report an error and must not return `/p/*` or `down_proxy_url` fallback.

- [ ] **Step 5: Commit**

```bash
git add internal/op/link_api_test.go server/handles/fsmanage_test.go
git commit -m "test: lock link api to real upstream URLs"
```

### Task 2: Tighten `ResolveActualLink` implementation to reject proxy-derived results

**Files:**
- Modify: `internal/op/link_api.go`
- Modify: `internal/op/link_api_test.go`
- Modify: `server/handles/fsmanage_test.go`

- [ ] **Step 1: Implement a shared real-upstream validation helper and remove `down_proxy_url` fallback from `ResolveActualLink`**

Implementation requirements:

```go
func ResolveActualLink(ctx context.Context, rawPath string, args model.LinkArgs) (*model.Link, error) {
    storage, actualPath, _, err := ResolveActualStoragePath(ctx, rawPath)
    if err != nil {
        return nil, err
    }

    file, err := GetUnwrap(ctx, storage, actualPath)
    if err != nil {
        return nil, err
    }

    leafArgs := args
    leafArgs.Redirect = false
    link, err := storage.Link(ctx, file, leafArgs)
    if err != nil {
        return nil, err
    }

    if !isActualDirectLink(ctx, link) {
        closeLink(link)
        return nil, errs.NewErr(errs.NotSupport,
            "storage %s cannot provide a real upstream downloadable URL for %s",
            storage.GetStorage().MountPath,
            rawPath,
        )
    }

    return link, nil
}
```

Constraints:

1. Do not call `generateDownProxyURL` inside `ResolveActualLink` anymore.
2. Keep the existing leaf-object and balance/alias resolution behavior intact.
3. Preserve leaf-supplied headers when the upstream URL is valid.

- [ ] **Step 2: Run the focused `ResolveActualLink` tests and verify they pass**

Run: `go test ./internal/op -run 'TestResolveActualLink_(PrefersLeafDirectURLOverDownProxyURL|FailsWhenLeafHasNoRealUpstreamURL|FailsWhenLeafReturnsOpenListLocalURL|FailsWhenLeafReturnsRelativeURL|FailsWhenResolvedLeafWouldFallbackToDownProxyURL|FailsWhenLeafWouldOnlyProduceSignedDownProxyURL|FailsWhenTokenRefreshWouldOnlyAffectDownProxyURLFallback)' -count=1`

Expected: PASS. The direct-upstream case succeeds; every former fallback case now fails cleanly.

- [ ] **Step 3: Run the `/api/fs/link` handler tests and verify they still pass**

Run: `go test ./server/handles -run 'TestLinkHandler_(ReturnsLeafDirectURLWithoutPProxyFallback|ReturnsJSONErrorWhenLeafHasNoExternalURLAndNoDownProxyURL)' -count=1`

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/op/link_api.go internal/op/link_api_test.go server/handles/fsmanage_test.go
git commit -m "fix: require real upstream urls from link api"
```

## TASK_GROUP 2: Add A Dedicated Web-Download Route Resolver

### Task 3: Add resolver-first tests for owner selection, alias merge, and balance separation

**Files:**
- Create: `internal/op/web_download_test.go`

- [ ] **Step 1: Write the failing resolver tests for policy-owner selection**

Add focused tests that express the required route result without going through handlers.

Test skeletons:

```go
func TestResolveWebDownloadRoute_UsesFirstNon302OwnerAcrossNestedAliasChain(t *testing.T) {
    // alias1 redirect_302 -> alias2 proxy_url -> alias3 native_proxy -> leaf native_proxy
    route, err := op.ResolveWebDownloadRoute(context.Background(), topMount+"/file.bin")
    if err != nil {
        t.Fatalf("expected success, got %v", err)
    }
    if got, want := route.EffectivePolicy, op.WebDownloadProxyURL; got != want {
        t.Fatalf("expected policy %q, got %q", want, got)
    }
    if got, want := route.PolicyOwnerRawPath, alias2Mount+"/file.bin"; got != want {
        t.Fatalf("expected owner path %q, got %q", want, got)
    }
}

func TestResolveWebDownloadRoute_AllWrapper302FallsBackToLeafPolicy(t *testing.T) {
    route, err := op.ResolveWebDownloadRoute(context.Background(), wrapperMount+"/file.bin")
    if err != nil {
        t.Fatalf("expected success, got %v", err)
    }
    if got, want := route.PolicyOwnerRawPath, leafMount+"/file.bin"; got != want {
        t.Fatalf("expected leaf owner path %q, got %q", want, got)
    }
}
```

- [ ] **Step 2: Write the failing resolver tests for alias merge and balance-path separation**

Add coverage for:

1. first existing alias target wins for route resolution
2. owner path differs from resolved leaf path when alias wraps a balance member
3. nested balance groups remain independent

Assertion skeleton:

```go
func TestResolveWebDownloadRoute_AliasFirstExistingTargetWins(t *testing.T) {
    route, err := op.ResolveWebDownloadRoute(context.Background(), aliasMount+"/file.bin")
    if err != nil {
        t.Fatalf("expected success, got %v", err)
    }
    if got, want := route.LeafRawPath, firstExistingLeafMount+"/file.bin"; got != want {
        t.Fatalf("expected first existing target leaf path %q, got %q", want, got)
    }
}

func TestResolveWebDownloadRoute_KeepsOwnerPathSeparateFromChosenLeafBalanceMember(t *testing.T) {
    route, err := op.ResolveWebDownloadRoute(context.Background(), aliasMount+"/file.bin")
    if err != nil {
        t.Fatalf("expected success, got %v", err)
    }
    if route.PolicyOwnerRawPath == route.LeafRawPath {
        t.Fatalf("expected owner path and leaf path to differ for wrapped balance leaf")
    }
}
```

- [ ] **Step 3: Run the new resolver test file and verify it fails because the resolver does not exist yet**

Run: `go test ./internal/op -run 'TestResolveWebDownloadRoute_' -count=1`

Expected: FAIL with missing symbol or missing behavior because `ResolveWebDownloadRoute` and its model are not implemented yet.

- [ ] **Step 4: Commit**

```bash
git add internal/op/web_download_test.go
git commit -m "test: define web download route behavior"
```

### Task 4: Implement the `WebDownloadRoute` model and resolver in `internal/op`

**Files:**
- Create: `internal/op/web_download.go`
- Modify: `internal/op/link_api.go`
- Modify: `internal/op/web_download_test.go`

- [ ] **Step 1: Define the route model and policy enums**

Add the route types in `internal/op/web_download.go`.

Type skeleton:

```go
type WebDownloadPolicyKind string

const (
    WebDownloadRedirect302 WebDownloadPolicyKind = "redirect_302"
    WebDownloadProxyURL    WebDownloadPolicyKind = "proxy_url"
    WebDownloadNativeProxy WebDownloadPolicyKind = "native_proxy"
)

type WebDownloadNode struct {
    Storage    driver.Driver
    MountPath  string
    RawPath    string
    ActualPath string
    Policy     WebDownloadPolicyKind
}

type WebDownloadRoute struct {
    RequestRawPath       string
    Nodes                []WebDownloadNode
    EffectivePolicy      WebDownloadPolicyKind
    PolicyOwnerIndex     int
    PolicyOwnerStorage   driver.Driver
    PolicyOwnerRawPath   string
    LeafStorage          driver.Driver
    LeafVirtualMountPath string
    LeafMountPath        string
    LeafRawPath          string
    LeafActualPath       string
}
```

- [ ] **Step 2: Implement unified browser-download policy classification**

Add a helper that classifies one node using the spec's rule.

Behavior skeleton:

```go
func classifyWebDownloadPolicy(storage driver.Driver, filename string) WebDownloadPolicyKind {
    if storage.GetStorage().DownProxyURL != "" {
        return WebDownloadProxyURL
    }
    if storage.Config().MustProxy() || storage.GetStorage().WebProxy {
        return WebDownloadNativeProxy
    }
    ext := utils.Ext(filename)
    if utils.SliceContains(conf.SlicesMap[conf.ProxyTypes], ext) || utils.SliceContains(conf.SlicesMap[conf.TextTypes], ext) {
        return WebDownloadNativeProxy
    }
    return WebDownloadRedirect302
}
```

Constraint: do not include WebDAV policy in this browser-download classifier.

- [ ] **Step 3: Implement recursive route resolution over alias and balance chains**

Use a request-local balance state, keep alias first-existing-target semantics, and build ordered nodes.

Resolution skeleton:

```go
func ResolveWebDownloadRoute(ctx context.Context, rawPath string) (*WebDownloadRoute, error) {
    // normalize path
    // ensure request-local balance state
    // resolve one branch through wrappers to one leaf
    // append nodes outer -> inner
    // compute policy owner as first non-redirect_302 node, else leaf
    // return immutable route result
}
```

Required behaviors:

1. reuse alias branch-selection semantics from the existing actual-link path-resolution flow
2. keep one chosen balance member per virtual mount path per request
3. store both owner path and leaf path
4. never let balance member path overwrite owner path

- [ ] **Step 4: Run the new resolver tests and verify they pass**

Run: `go test ./internal/op -run 'TestResolveWebDownloadRoute_' -count=1`

Expected: PASS.

- [ ] **Step 5: Run the existing balance and nested-resolution regression tests**

Run: `go test ./internal/op -run 'TestResolveActual(Link|StoragePath)_(Alias|NestedAlias|Balance|Strm)|TestHasLinkAPIObject_' -count=1`

Expected: PASS. Existing actual-link and balance pinning behavior should remain intact except for the already-updated real-upstream-only contract tests.

- [ ] **Step 6: Commit**

```bash
git add internal/op/web_download.go internal/op/web_download_test.go internal/op/link_api.go
git commit -m "feat: add web download route resolver"
```

## TASK_GROUP 3: Switch Browser Download Entry Points To The Route Resolver

### Task 5: Add `/d/*` and `/p/*` handler tests for owner-path routing and canonicalization

**Files:**
- Create: `server/handles/down_test.go`

- [ ] **Step 1: Write the failing `/d/*` redirect tests**

Add handler tests covering:

1. `proxy_url` owner redirects to owner-based external proxy URL
2. `native_proxy` owner redirects to canonical `/p/<owner path>`
3. all-wrapper-302 case redirects to real upstream leaf URL

Test skeleton:

```go
func TestDownHandler_ProxyURLOwnerRedirectsToOwnerNamespaceURL(t *testing.T) {
    resp := callDownHandler(...)
    if got, want := resp.Code, http.StatusFound; got != want {
        t.Fatalf("expected HTTP %d, got %d", want, got)
    }
    if got := resp.Header().Get("Location"); got != expectedOwnerProxyURL {
        t.Fatalf("expected redirect %q, got %q", expectedOwnerProxyURL, got)
    }
}

func TestDownHandler_NativeProxyOwnerRedirectsToCanonicalOwnerPPath(t *testing.T) {
    if got := resp.Header().Get("Location"); got != expectedCanonicalProxyURL {
        t.Fatalf("expected redirect %q, got %q", expectedCanonicalProxyURL, got)
    }
}
```

- [ ] **Step 2: Write the failing `/p/*` tests for canonicalization and `d=1` bypass**

Add coverage for:

1. `/p/*` canonicalizes to owner path before local proxy execution
2. `proxy_url` owner without `d=1` redirects externally
3. `proxy_url` owner with `d=1` locally proxies through the leaf
4. `redirect_302` route rejects proxy access
5. non-owner `proxy_url` request with `d=1` redirects exactly once to the canonical owner path before local proxy execution
6. canonical owner-path `proxy_url` request with `d=1` does not emit another `/p/*` redirect

Assertion skeleton:

```go
func TestProxyHandler_ProxyURLOwnerWithD1BypassesExternalProxyAndStreamsLeaf(t *testing.T) {
    resp := callProxyHandler(... rawQuery: "d=1")
    if got, want := resp.Code, http.StatusOK; got != want {
        t.Fatalf("expected HTTP %d, got %d", want, got)
    }
    if got := resp.Body.String(); got != "expected streamed body" {
        t.Fatalf("expected streamed body, got %q", got)
    }
}

func TestProxyHandler_ProxyURLOwnerWithD1CanonicalizesToOwnerPathOnce(t *testing.T) {
    resp := callProxyHandler(... path: nonOwnerPath, rawQuery: "d=1")
    if got, want := resp.Code, http.StatusFound; got != want {
        t.Fatalf("expected HTTP %d, got %d", want, got)
    }
    if got := resp.Header().Get("Location"); got != expectedCanonicalOwnerProxyURL {
        t.Fatalf("expected canonical owner redirect %q, got %q", expectedCanonicalOwnerProxyURL, got)
    }
}

func TestProxyHandler_ProxyURLOwnerWithD1DoesNotRedirectAfterCanonicalOwnerPath(t *testing.T) {
    resp := callProxyHandler(... path: ownerPath, rawQuery: "d=1")
    if got := resp.Header().Get("Location"); got != "" {
        t.Fatalf("expected no recursive redirect after canonical owner path, got %q", got)
    }
}
```

- [ ] **Step 3: Run the new handler tests and verify they fail before implementation**

Run: `go test ./server/handles -run 'Test(DownHandler|ProxyHandler)_' -count=1`

Expected: FAIL because `/d/*` and `/p/*` still use direct leaf-only storage lookups.

- [ ] **Step 4: Commit**

```bash
git add server/handles/down_test.go
git commit -m "test: define owner-aware download handler behavior"
```

### Task 6: Migrate `/d/*` and `/p/*` to consume `WebDownloadRoute`

**Files:**
- Modify: `server/handles/down.go`
- Modify: `internal/op/web_download.go`
- Modify: `server/handles/down_test.go`

- [ ] **Step 1: Add route-consumption helpers for canonical owner URLs and external owner proxy URLs**

Add short helper functions that convert a route into entry-point-specific URLs.

Helper skeleton:

```go
func canonicalOwnerProxyURL(c *gin.Context, route *op.WebDownloadRoute, query url.Values) (string, error)
func externalOwnerProxyURL(route *op.WebDownloadRoute) (string, error)
```

Behavior requirements:

1. canonical `/p/*` URLs preserve `type` when present
2. canonical `/p/*` URLs preserve or regenerate required path signatures
3. external proxy URLs use the owner path and the owner's `down_proxy_url` signing contract
4. `proxy_url` bypass is keyed to query parameter `d=1`, not merely to the presence of a `d` key

- [ ] **Step 2: Replace `/d/*` leaf-only proxy decision logic with route-driven branching**

Implementation skeleton:

```go
func Down(c *gin.Context) {
    rawPath := c.Request.Context().Value(conf.PathKey).(string)
    route, err := op.ResolveWebDownloadRoute(c.Request.Context(), rawPath)
    if err != nil {
        common.ErrorPage(c, err, 500)
        return
    }

    switch route.EffectivePolicy {
    case op.WebDownloadProxyURL:
        // redirect to external owner proxy URL
    case op.WebDownloadNativeProxy:
        // redirect to canonical /p/<owner path>
    case op.WebDownloadRedirect302:
        // fetch real upstream from leaf only and redirect
    }
}
```

- [ ] **Step 3: Replace `/p/*` logic with route-driven canonicalization and local proxy execution**

Implementation skeleton:

```go
func Proxy(c *gin.Context) {
    rawPath := c.Request.Context().Value(conf.PathKey).(string)
    route, err := op.ResolveWebDownloadRoute(c.Request.Context(), rawPath)
    if err != nil {
        common.ErrorPage(c, err, 500)
        return
    }

    switch route.EffectivePolicy {
    case op.WebDownloadRedirect302:
        common.ErrorPage(c, errors.New("proxy not allowed"), 403)
    case op.WebDownloadProxyURL:
        if c.Query("d") != "1" {
            // redirect externally using owner path
            return
        }
        // canonicalize to owner path if needed, else locally proxy leaf link
    case op.WebDownloadNativeProxy:
        // canonicalize to owner path if needed, else locally proxy leaf link
    }
}
```

Constraint: when local proxy execution begins, obtain the link from `route.LeafStorage` + `route.LeafActualPath`, not by re-calling `fs.Link` on the wrapper raw path.

- [ ] **Step 4: Run the new `/d/*` and `/p/*` tests and verify they pass**

Run: `go test ./server/handles -run 'Test(DownHandler|ProxyHandler)_' -count=1`

Expected: PASS.

- [ ] **Step 5: Run the full existing handler test suite and verify no regressions**

Run: `go test ./server/handles -count=1`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add server/handles/down.go internal/op/web_download.go server/handles/down_test.go
git commit -m "fix: route browser downloads by owner policy"
```

### Task 7: Switch `fsread` `raw_url` generation to `WebDownloadRoute`

**Files:**
- Modify: `server/handles/fsread.go`
- Modify: `server/handles/down_test.go`
- Modify: `internal/op/web_download.go`

- [ ] **Step 1: Add the failing `raw_url` handler tests**

Add handler tests that assert `raw_url` matches the same owner-aware result as `/d/*`.

Assertion skeleton:

```go
func TestFsGet_RawURLUsesOwnerProxyURLWhenEffectivePolicyIsProxyURL(t *testing.T) {
    resp := callFsGetHandler(...)
    if got, want := resp.Data.RawURL, expectedOwnerProxyURL; got != want {
        t.Fatalf("expected raw_url %q, got %q", want, got)
    }
}

func TestFsGet_RawURLUsesAbsoluteCanonicalPURLWhenEffectivePolicyIsNativeProxy(t *testing.T) {
    if got, want := resp.Data.RawURL, expectedAbsoluteProxyURL; got != want {
        t.Fatalf("expected raw_url %q, got %q", want, got)
    }
}

func TestFsGet_RawURLUsesLeafUpstreamURLWhenEffectivePolicyIsRedirect302(t *testing.T) {
    if got, want := resp.Data.RawURL, expectedLeafUpstreamURL; got != want {
        t.Fatalf("expected raw_url %q, got %q", want, got)
    }
}
```

- [ ] **Step 2: Run the focused `raw_url` tests and verify they fail before implementation**

Run: `go test ./server/handles -run 'TestFsGet_RawURL' -count=1`

Expected: FAIL because `fsread.go` still computes `raw_url` from direct leaf-only checks.

- [ ] **Step 3: Replace `raw_url` generation with route-based emission**

Implementation skeleton:

```go
if !obj.IsDir() {
    route, err := op.ResolveWebDownloadRoute(c.Request.Context(), reqPath)
    if err != nil {
        common.ErrorResp(c, err, 500)
        return
    }

    switch route.EffectivePolicy {
    case op.WebDownloadProxyURL:
        rawURL = ownerExternalProxyURL
    case op.WebDownloadNativeProxy:
        rawURL = absoluteCanonicalProxyURL
    case op.WebDownloadRedirect302:
        rawURL = resolvedLeafUpstreamURL
    }
}
```

Constraint: provider lookup remains based on the existing object/storage information; only `raw_url` generation changes.

- [ ] **Step 4: Run the focused `raw_url` tests and verify they pass**

Run: `go test ./server/handles -run 'TestFsGet_RawURL' -count=1`

Expected: PASS.

- [ ] **Step 5: Run the full handler test suite and verify it stays green**

Run: `go test ./server/handles -count=1`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add server/handles/fsread.go server/handles/down_test.go internal/op/web_download.go
git commit -m "fix: align fs raw urls with web download routing"
```

## TASK_GROUP 4: Final Regression Coverage And Verification

### Task 8: Add or update regression coverage for nested balance groups and alias-first-existing routing across both contracts

**Files:**
- Modify: `internal/op/web_download_test.go`
- Modify: `internal/op/link_api_test.go`
- Modify: `server/handles/down_test.go`
- Modify: `internal/op/web_download.go`
- Modify: `server/handles/down.go`
- Modify: `server/handles/fsread.go`
- Modify: `internal/op/link_api.go`

- [ ] **Step 1: Add the failing stress-scenario tests from the approved recap**

Cover the approved nested scenario shape:

```go
func TestResolveWebDownloadRoute_NestedIndependentBalanceGroupsKeepOuterProxyOwner(t *testing.T) {
    route, err := op.ResolveWebDownloadRoute(context.Background(), alias1Mount+"/file.bin")
    if err != nil {
        t.Fatalf("expected success, got %v", err)
    }
    if got, want := route.PolicyOwnerRawPath, chosenAlias2BalanceMount+"/file.bin"; got != want {
        t.Fatalf("expected outer proxy owner %q, got %q", want, got)
    }
    if !strings.HasPrefix(route.LeafRawPath, chosenOriginMount+"/") {
        t.Fatalf("expected chosen origin leaf path under %q, got %q", chosenOriginMount, route.LeafRawPath)
    }
}

func TestResolveActualLink_AliasFirstExistingTargetWinsEvenWhenOtherTargetHasDifferentLeaf(t *testing.T) {
    link, err := op.ResolveActualLink(context.Background(), aliasMount+"/file-A.bin", model.LinkArgs{})
    if err != nil {
        t.Fatalf("expected success, got %v", err)
    }
    if got := link.URL; got != expectedOrigin1UpstreamURL {
        t.Fatalf("expected first existing origin upstream %q, got %q", expectedOrigin1UpstreamURL, got)
    }
}
```

- [ ] **Step 2: Run focused regression tests and verify they pass**

Run: `go test ./internal/op ./server/handles -run 'TestResolve(WebDownloadRoute|ActualLink)_|Test(DownHandler|ProxyHandler|FsGet_RawURL)_' -count=1`

Expected: PASS.

- [ ] **Step 3: Make the minimal implementation adjustments required by any failing regression and keep the route model stable**

Allowed implementation adjustments:

1. fix owner-path rewriting
2. fix canonical `/p/*` emission
3. fix route-local balance pin bookkeeping
4. fix alias first-existing-target branch locking

Disallowed changes:

1. reintroducing `ResolveActualLink` proxy fallback
2. allowing browser download handlers to recompute policy from direct leaf-only lookups
3. allowing selected alias branches or balance members to change after selection inside one request

- [ ] **Step 4: Run the target verification matrix and verify it passes**

Run: `go test ./internal/op ./server/handles -count=1`

Expected: PASS.

- [ ] **Step 5: Run the broader repo verification relevant to touched packages**

Run: `go test ./... -count=1`

Expected: PASS. If unrelated pre-existing failures appear, stop and document the exact failing packages before claiming completion.

- [ ] **Step 6: Commit**

```bash
git add internal/op/web_download_test.go internal/op/link_api_test.go server/handles/down_test.go server/handles/fsread.go server/handles/down.go internal/op/web_download.go internal/op/link_api.go
git commit -m "fix: preserve alias web download policy through nested balance chains"
```

## Self-Review

### Spec coverage

1. `ActualLink` real-upstream-only contract is covered by Task 1 and Task 2.
2. Dedicated `WebDownloadRoute` resolver and policy-owner selection are covered by Task 3 and Task 4.
3. `/d/*` and `/p/*` owner-aware behavior and canonicalization are covered by Task 5 and Task 6.
4. `raw_url` alignment is covered by Task 7.
5. Nested alias/balance independence and alias merge semantics are covered by Task 8.

### Placeholder scan

1. No `TBD`, `TODO`, or `implement later` placeholders remain.
2. Each task names exact files and verification commands.
3. Code snippets stay at API, contract, assertion, and sequencing level rather than freezing unrelated implementation internals.

### Type consistency

1. The plan consistently uses `WebDownloadRoute`, `WebDownloadNode`, `WebDownloadPolicyKind`, `PolicyOwnerRawPath`, and `LeafRawPath` across all tasks.
2. `ResolveActualLink` remains the real-upstream-only resolver and `ResolveWebDownloadRoute` remains the browser-download resolver throughout the plan.
