# Alias + GoogleDrive Web Download Recap

## Approval Status

Approved by the user on 2026-05-01 as the final recap for spec and plan drafting.

## Problem Statement

OpenList currently collapses alias-wrapped download requests to the leaf storage too early. For `google_drive` mounts, which are `OnlyProxy`, this causes `/d/*`, `/p/*`, and UI download URLs to ignore alias-level download proxy settings and to behave as if the request had targeted the leaf `google_drive` mount directly.

## Approved Product Truth

1. `ActualLink` and `WebDownload` are separate contracts.
2. `ActualLink` exists for `/api/fs/link`-style programmatic callers.
3. `ActualLink` must return only the leaf remote's real upstream download URL plus headers.
4. `ActualLink` must ignore all `down_proxy_url` and all local proxy behavior, including leaf `down_proxy_url`, leaf local proxy, alias `down_proxy_url`, and alias local proxy.
5. `ActualLink` must fail when the leaf cannot provide a real upstream URL.
6. `ActualLink` must never return OpenList-local `/p/*` or `/d/*` URLs, relative URLs, or any composed proxy URL fallback.
7. `WebDownload` exists for browser-facing download entry points.
8. `WebDownload` must preserve the access-path semantics of nested alias wrappers.
9. Each wrapper or leaf node in the resolved access chain has one of three web-download policies: `redirect_302`, `proxy_url`, or `native_proxy`.
10. Within a node, `down_proxy_url` means `proxy_url` and has precedence over that same node's local-proxy behavior.
11. Across nodes, the effective policy is the first non-`redirect_302` policy from outermost to innermost.
12. Local proxy must not globally outrank proxy URL. Layer order decides.
13. If every wrapper in the chain is `redirect_302`, the resolved leaf policy decides the web-download behavior.
14. The path used for emitted proxy URLs or `/p/*` redirects is the policy owner's path, not the original request path and not the leaf path.
15. `alias` is responsible for existence-based merge behavior.
16. `balance` is not a merge layer. `balance` only chooses one member for the current request.
17. For alias multi-target routing, `exist file first path wins` remains required: once a file is found on the first existing target path, later targets must not be consulted for download routing.
18. `balance` member choice must remain pinned within one request and continue existing cross-request rotation behavior.
19. Distinct balance groups in the same nested chain must rotate independently and must not overwrite each other's pinned member state.
20. `WebDownload` must expose the policy-owner path to the browser while using the chosen leaf member path internally to fetch the real upstream link.

## Approved In-Scope Entry Points

1. `server/handles/down.go` `/d/*`
2. `server/handles/down.go` `/p/*`
3. `server/handles/fsread.go` `raw_url`
4. `server/handles/fsmanage.go` `/api/fs/link` contract fix

## Approved Out-of-Scope Entry Points

1. Sharing download routes in this iteration
2. WebDAV behavior in this iteration
3. Archive-specific download flows in this iteration

## Required Behavioral Outcomes

1. `/api/fs/link` must be a real-upstream extractor only.
2. `/d/*` and `/p/*` must use a dedicated web-download resolver rather than direct leaf-only storage lookup.
3. `/d/*` must redirect to the policy owner's `down_proxy_url` when the effective policy is `proxy_url`.
4. `/d/*` must redirect to canonical `/p/<policy-owner-path>` when the effective policy is `native_proxy`.
5. `/d/*` must redirect to the leaf's real upstream URL when the effective policy is `redirect_302`.
6. `/p/*` must not recurse indefinitely. It must canonicalize to the policy-owner path when needed and locally proxy only after the owner path is reached.
7. `raw_url` must match the same owner-based web-download result that `/d/*` would emit for the same object.

## Concrete Stress Scenario Confirmed By User

For the nested chain below, `balance` groups remain independent and alias-level policy remains authoritative:

```text
alias1 (302)
-> alias2.balance1 (proxy_url) | alias2.balance2 (different proxy_url)
-> alias3.balance3 (302) | alias3.balance4 (302)
-> origin1_googledrive (native_proxy) | origin2_googledrive (native_proxy)
```

Approved interpretation:

1. `WebDownload` picks the first non-`302` policy owner from the outermost resolved chain.
2. In that example, the chosen `alias2.balanceN` node owns the browser-visible proxy behavior.
3. The chosen `alias3.balanceN` and `originN_googledrive` path only decide where local proxying fetches content from.
4. `ActualLink` ignores every proxy layer in that chain and succeeds only if the chosen leaf `originN_googledrive` returns a real upstream URL.
