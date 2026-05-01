# Alias + GoogleDrive Web Download Design Spec

## Goal

Restore correct browser download behavior for alias-wrapped `google_drive` mounts by separating real-upstream extraction from browser download routing, preserving alias-path proxy semantics through nested alias and `.balance` chains, and fixing the current `Link API` contract drift that still falls back to proxy URLs.

## Non-Goals

1. This change does not alter sharing download routes in this iteration.
2. This change does not alter WebDAV routing behavior in this iteration.
3. This change does not alter archive-specific download flows in this iteration.
4. This change does not make `.balance` a merge layer. Object merge semantics remain an alias responsibility.
5. This change does not add a compatibility mode that preserves the current `Link API` proxy fallback behavior.

## Scope

This design changes the behavior of the following entry points:

1. `server/handles/down.go` `/d/*`
2. `server/handles/down.go` `/p/*`
3. `server/handles/fsread.go` `raw_url`
4. `server/handles/fsmanage.go` `/api/fs/link`

This design introduces a new web-download route resolver that is separate from the existing actual-link resolver.

## Actors And Entry Points

1. Browser users who click or navigate to `/d/*`
2. Browser users or clients that explicitly request `/p/*`
3. UI clients that consume `raw_url` from `fsread`
4. Programmatic callers that consume `/api/fs/link`

## Functional Behavior

### 1. `ActualLink` Contract

`ActualLink` is the contract used by `/api/fs/link`.

Required behavior:

1. The request path is resolved to one concrete leaf object using existing path-resolution rules, including alias object existence routing and `.balance` member selection.
2. The returned link is valid only when the resolved leaf storage returns a real upstream absolute URL and the leaf headers required to consume that upstream URL.
3. `ActualLink` must reject and return an error for any of the following leaf results:
   1. empty URL
   2. relative URL
   3. OpenList-local `/p/*` or `/d/*` URL
   4. any URL synthesized from `down_proxy_url`
4. `ActualLink` must ignore all proxy behavior, including:
   1. alias `down_proxy_url`
   2. alias local proxy behavior
   3. leaf `down_proxy_url`
   4. leaf local proxy behavior
5. When the leaf cannot provide a real upstream URL, `ActualLink` must fail and must not fall back to any proxy URL.

### 2. `WebDownload` Contract

`WebDownload` is the contract used by `/d/*`, `/p/*`, and `raw_url`.

Required behavior:

1. `WebDownload` must resolve the request into an ordered access chain from outermost wrapper to innermost leaf.
2. Each node in that chain has one web-download policy:
   1. `redirect_302`
   2. `proxy_url`
   3. `native_proxy`
3. Policy classification rules are deterministic:
   1. a node with non-empty `down_proxy_url` is `proxy_url`
   2. otherwise, a node is `native_proxy` when the requested file matches the unified browser-download local-proxy rule: the storage `MustProxy` contract is true, or `web_proxy` is enabled, or the requested extension is included in configured `proxy_types`, or the requested extension is included in configured `text_types`
   3. otherwise, the node is `redirect_302`
4. The unified browser-download local-proxy rule is shared by `/d/*`, `/p/*`, and `raw_url`.
5. WebDAV-specific proxy policy does not classify browser-download behavior in this iteration.
6. The effective web-download policy is the first non-`redirect_302` policy from outermost to innermost.
7. If every wrapper node is `redirect_302`, the resolved leaf node decides the effective policy.
8. Local proxy does not globally outrank proxy URL. Node order is the only cross-node priority rule.
9. The emitted browser-facing object path for `proxy_url` and `/p/*` redirects is the full requested object path rewritten into the policy owner's namespace. It is not the original request path and not the resolved leaf path.
10. Emitted OpenList-local `/p/*` URLs must preserve the query parameters that affect the next OpenList hop, including canonical-path signatures required by the entry point and the requested `type` value when present.
11. Emitted external `down_proxy_url` URLs must preserve the full requested object path in the policy-owner namespace and must preserve the existing proxy-signing contract controlled by `disable_proxy_sign`.

### 3. Alias Merge And Existence Routing

Alias merge behavior remains authoritative for deciding which branch owns a file.

Required behavior:

1. Alias multi-target lookup must preserve existing `exist file first path wins` semantics.
2. When an alias target path does not contain the requested object, resolution may continue to later alias targets.
3. Once an alias target path is the first path that contains the requested object, later alias targets must not be consulted for either `ActualLink` or `WebDownload` routing.
4. Download-policy failure after a branch is selected does not permit branch switching to a later alias target.

### 4. `.balance` Behavior

`.balance` remains a member-selection layer, not a merge layer.

Required behavior:

1. Every balance group is keyed by its virtual mount path and selects one concrete member for the current request.
2. Within one request, repeated resolution of the same balance group must reuse the same concrete member.
3. Across requests, balance rotation must continue the current authoritative progression behavior.
4. Concurrent requests may still resolve to different members according to existing balance behavior.
5. If a chosen balance member fails to produce a downloadable result, resolution must not probe alternate balance members within that same request.
6. Distinct balance groups in the same nested chain must keep independent pinned-member state.

### 5. Separation Of Policy Owner Path And Leaf Path

The web-download resolver must keep policy ownership separate from content origin.

Required behavior:

1. The policy-owner path identifies which node controls browser-visible proxy behavior.
2. The leaf path identifies which concrete leaf member provides the actual upstream content.
3. Browser-visible URLs use the policy-owner path.
4. Local proxy content fetching uses the resolved leaf path.
5. Balance member paths must never replace the policy-owner path in emitted proxy URLs or `/p/*` canonical URLs.
6. The policy-owner path always includes the full requested object suffix under the policy owner's namespace, not only the policy owner's mount root.

### 6. `/d/*` Behavior

`/d/*` performs first-hop browser download routing.

Required behavior:

1. `/d/*` must resolve the request through the `WebDownload` resolver.
2. If the effective policy is `proxy_url`, `/d/*` must return HTTP 302 to the policy owner's `down_proxy_url` plus the full requested object path rewritten into the policy-owner namespace.
3. If the effective policy is `native_proxy`, `/d/*` must return HTTP 302 to canonical `/p/<policy-owner-path>` and must preserve the request query parameters required for the next OpenList hop, including `type` when present and any required path-signing behavior.
4. If the effective policy is `redirect_302`, `/d/*` must obtain the resolved leaf's real upstream URL and return HTTP 302 to that upstream URL.
5. `/d/*` must not recompute browser download routing from a direct leaf-only storage lookup.
6. `/d/*` must not fall back from a chosen owner policy to a different owner policy.

### 7. `/p/*` Behavior

`/p/*` executes local proxy behavior or explicit proxy-address bypass behavior.

Required behavior:

1. `/p/*` must resolve the request through the `WebDownload` resolver.
2. If the effective policy is `redirect_302`, `/p/*` must reject the request as proxy-not-allowed.
3. If the current request path is not the policy-owner path and the effective policy is `native_proxy`, `/p/*` must redirect to canonical `/p/<policy-owner-path>` before proxy execution and must preserve the query parameters required for the next OpenList hop, including `type` when present and any required path-signing behavior.
4. If the current request path is not the policy-owner path, the effective policy is `proxy_url`, and query parameter `d=1` is present, `/p/*` must redirect to canonical `/p/<policy-owner-path>?d=1` before proxy execution and must preserve the requested `type` value when present together with the canonical-path signature required for the next OpenList hop.
5. If the effective policy is `proxy_url` and query parameter `d=1` is absent, `/p/*` must redirect to the policy owner's `down_proxy_url` plus the full requested object path rewritten into the policy-owner namespace.
6. If the effective policy is `native_proxy` and the current request path equals the policy-owner path, `/p/*` must locally proxy the resolved leaf upstream result.
7. If the effective policy is `proxy_url`, query parameter `d=1` is present, and the current request path equals the policy-owner path, `/p/*` must bypass the external proxy URL and locally proxy the resolved leaf upstream result.
8. `/p/*` local proxy execution must fetch content from the resolved leaf path and must not restart browser-policy routing from the top of the wrapper chain.
9. `/p/*` must not recursively redirect to itself after the canonical owner path is reached.

### 8. `raw_url` Behavior

`raw_url` must match the web-download contract for the same object.

Required behavior:

1. When the effective policy is `proxy_url`, `raw_url` is the policy owner's `down_proxy_url` plus the policy-owner path.
2. When the effective policy is `native_proxy`, `raw_url` is an absolute OpenList URL rooted at the current API base and pointing to canonical `/p/<policy-owner-path>` with the path-signing contract required by the `fsread` entry point.
3. When the effective policy is `redirect_302`, `raw_url` is the resolved leaf's real upstream URL.
4. `raw_url` must not recompute the result from a direct leaf-only proxy check.

## State And Data Contracts

### 1. Web-Download Route Model

The web-download resolver must produce one immutable per-request route result with the following semantics:

1. original request raw path
2. ordered node list from outermost wrapper to innermost leaf
3. resolved policy owner node
4. policy-owner path including the full requested object suffix in the policy owner's namespace
5. effective policy kind
6. resolved leaf storage
7. resolved leaf virtual mount path for balance bookkeeping
8. resolved concrete leaf mount path
9. resolved leaf raw path
10. resolved leaf actual path
11. route-resolution result independent from any one emitted URL form so that `/d/*`, `/p/*`, and `raw_url` can consume the same route while applying entry-point-specific emission rules

### 2. Node Model

Each node in the ordered route list must carry:

1. storage reference
2. node mount path
3. node raw path
4. node actual path
5. node policy kind

### 3. Balance Pin State

Per-request balance pin state must be keyed by virtual mount path and must map that virtual mount path to the chosen concrete member mount path.

## Error Handling And Edge Cases

1. `ActualLink` returns an error when the resolved leaf cannot provide a valid real upstream absolute URL.
2. `ActualLink` returns an error when the resolved leaf returns an OpenList-local URL or any proxy-derived URL.
3. Route resolution succeeds independently from URL emission. Failure to emit one entry-point-specific URL form does not invalidate the resolved route.
4. `/d/*` returns an error when the effective policy is `proxy_url` and the chosen owner cannot emit a valid external proxy URL for that redirect branch.
5. `/p/*` returns an error when the effective policy is `proxy_url`, query parameter `d=1` is absent, and the chosen owner cannot emit a valid external proxy URL for that redirect branch.
6. `/d/*` or `/p/*` local-proxy execution returns an error when the resolved leaf cannot provide a usable upstream result for local proxying.
7. `/d/*` or `raw_url` returns an error when the effective policy is `redirect_302` and the resolved leaf cannot produce a valid real upstream absolute URL.
8. No entry point in scope may silently fall back from one selected policy owner to another policy owner.
9. No entry point in scope may silently re-enter the old leaf-only proxy decision path after the web-download route is resolved.

## Acceptance Criteria

1. Nested alias requests with a top-level `redirect_302` wrapper and a deeper alias `proxy_url` owner produce browser-visible URLs owned by that deeper alias path.
2. Nested alias requests with all wrappers at `redirect_302` honor the resolved leaf policy.
3. `google_drive` leaf local-proxy requirements no longer override an outer alias `proxy_url` owner.
4. `/api/fs/link` succeeds only when the resolved leaf provides a valid real upstream URL and headers.
5. `/api/fs/link` fails when the resolved leaf provides only proxy-derived behavior.
6. Alias multi-target requests preserve `exist file first path wins` semantics for both `ActualLink` and `WebDownload`.
7. `.balance` rotation continues across requests and remains pinned within one request.
8. Distinct `.balance` groups in one nested chain keep independent pinned-member state.
9. `/p/*` canonicalizes to the policy-owner path and does not loop after canonicalization.
10. `raw_url` matches the same web-download result that `/d/*` would emit for the same request path.

## Locked Assumptions

1. Alias merge continues to be the only layer responsible for cross-target object existence selection.
2. `.balance` continues to represent independent per-group member selection and not file-set merge behavior.
3. Sharing, WebDAV, and archive-specific download flows remain unchanged in this iteration.
4. Balance behavior remains defined by these product requirements: per-request member pinning, continued cross-request rotation, independent nested balance-group state, and no alternate-member probing after one member is selected for the request.
