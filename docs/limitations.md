[中文](./limitations_CN.md)

# Limitations and Caveats

## CDN Pipeline — What Gets Converted

The CDN pipeline converts these Cloudflare rule types to CloudFront equivalents:

| Rule Type | CloudFront Equivalent |
|-----------|----------------------|
| Redirect Rules | CloudFront Functions (viewer-request) |
| URL Rewrite Rules | CloudFront Functions (viewer-request) |
| Configuration Rules | Distribution settings (TLS, HTTP version, protocol policy) |
| Origin Rules | CloudFront Functions (`updateRequestOrigin`) or independent cache behaviors |
| Bulk Redirects | KVS + CloudFront Functions |
| Request Header Transform | CloudFront Functions + Origin Request Policy |
| Cache Rules (TTL / cache key) | Cache policies on cache behaviors |
| Cache Rules (conditional "Bypass cache") | Viewer-request CloudFront Function that forces a cache miss for matching requests (see below); unconditional bypass → a custom cache policy with CachingDisabled semantics (all TTLs 0, no cache-key inputs) |
| Cloud Connector Rules | Independent cache behaviors with separate origins |
| Custom Error Rules | CloudFront custom error responses |
| Response Header Transform | Response Headers Policy + CloudFront Functions (viewer-response) |
| Compression Rules | Cache policy `enable_gzip` / `enable_brotli` |

### Conditional cache bypass

CloudFront has no request-time "skip the cache" switch — the cache decision is fixed by the cache policy on a behavior, and behaviors are selected only by path (not by cookie/header/query). To convert a Cloudflare Cache Rule that conditionally bypasses cache (e.g. bypass when a `wordpress_logged_in` cookie is present, or `?test=true`), the tool emits a viewer-request CloudFront Function that, for matching requests, injects a header (`x-cf-cache-bypass`) with a per-request-unique value that is part of the cache key. Each matching request then gets a unique cache key → always a miss → always fetched from origin. This is a forced **miss**, not a true skip (the response is still stored, under a one-time key that's never reused), but the effect for the viewer is identical.

Supported bypass conditions: any field the converter can evaluate at the edge — cookies (`http.cookie`, `http.request.cookies["name"]`), named request headers (`http.request.headers["name"]`), named query args (`http.request.uri.args["name"]`), query / user-agent / path substrings, method, referer, and the geo/device `CloudFront-Viewer-*` fields — as an existence check or a scalar value comparison. (The bypass condition runs through the same CFF condition renderer as every other rule type, so whatever converts elsewhere converts here too.)

Caveats:
- The multi-value form `any(http.request.cookies["x"][*] == "v")` (and the header/arg equivalents) is **not** converted — it's reported non-convertible rather than guessed at.
- Because the bypass writes into the cache key, it costs a CFF invocation on the behaviors it runs on and produces one-time cache entries for matching requests (harmless — they're never re-served and age out).

### Origin forwarding & Host override

Cloudflare forwards the full request to origin; CloudFront strips everything not in the cache key unless an **origin request policy (ORP)** forwards it. Each behavior's ORP is chosen by this priority (all-or-nothing per domain, so a behavior never ends up under-forwarded relative to its CFF):

1. **S3 + OAC origin → no ORP.** OAC signs the request (SigV4); forwarding the viewer Host or arbitrary headers breaks the signature (403). CloudFront sets Host to the bucket domain itself.
2. **Any behavior in the domain needs CloudFront native headers** (`CloudFront-Viewer-Country`, device flags, etc., because some rule reads them) → a **custom ORP** (`allViewerAndWhitelistCloudFront`) is attached to **every** non-S3 behavior of that domain. It forwards all viewer headers (including Host) **plus** the CloudFront-* native headers, so a CFF that reads a native header sees it on whichever behavior it runs on.
3. **Otherwise → managed AllViewer** — forwards all viewer headers (including Host), matching Cloudflare's default.

A **Host override** (Cloudflare Origin Rule) does **not** change this choice — it's orthogonal. The origin Host is set in the CFF via `cf.updateRequestOrigin({hostHeader})`, whose explicit value wins over whatever Host the ORP forwards (verified live), so a behavior can both need native headers (→ custom ORP, which also forwards Host) **and** override the Host, with no conflict. There is no "Host override → drop the viewer Host" ORP (the old `AllViewerExceptHostHeader` choice was removed — it stranded non-matching requests and bought nothing, since `hostHeader` already wins).

## CDN Pipeline — What Does NOT Get Converted

### Rule types not processed

| Item | Reason | Alternative |
|------|--------|-------------|
| Page Rules (legacy) | Deprecated by Cloudflare. Migrate to modern rule types first, then use this tool. | Cloudflare migration guide |
| Snippets | JavaScript code running on Cloudflare's V8 runtime. While Snippets cannot use storage bindings (KV, D1, R2, DO), they can use `fetch()` (subrequests), `HTMLRewriter`, and `request.body` — none of which are available in CloudFront Functions. Snippets that only manipulate headers, URLs, and cookies are theoretically convertible, but these use cases are already covered by Cloudflare's declarative rule types (Redirect Rules, Transform Rules, etc.) which this tool does convert. Snippets that use `fetch()`, `HTMLRewriter`, or body access require Lambda@Edge. | Evaluate each Snippet individually. Simple header/URL logic → CloudFront Functions. `fetch()` or `HTMLRewriter` → Lambda@Edge. `request.cf.botManagement` → AWS WAF Bot Control. |
| Workers | TypeScript/JavaScript with full Cloudflare platform bindings (KV, Durable Objects, R2, D1, Queues, etc.). Arbitrary business logic that requires understanding intent to rewrite. | Lambda@Edge for request/response processing. Complex Workers may need standalone Lambda behind CloudFront, or a full application rewrite. |
| URL Normalization | CloudFront normalizes URIs per RFC 3986 by default. No conversion needed. | N/A |
| Managed Transforms (except True-Client-IP) | Cloudflare-specific features. | CloudFront native equivalents where available |
| Trace | Cloudflare-specific testing feature. | CloudWatch Logs, CloudFront real-time logs |

### Settings within convertible rule types that cannot be mapped

| Setting | Rule Type | Reason | Alternative |
|---------|-----------|--------|-------------|
| `ip.src` / `ip.src in` conditions | Cache Rules, Compression Rules | CloudFront Functions cannot control cache or compression decisions | AWS WAF IP-based rules |
| `ip.src in $list_name` with CIDR entries | All rule types | CFF `event.viewer.ip` is a single IP; cannot perform CIDR matching | AWS WAF IP set with Count action + custom header (see WAF + Custom Header Pattern in conversion_report.md) |
| `serve_stale` (SWR/SIE) | Cache Rules | No CloudFront cache policy equivalent | Origin `Cache-Control: stale-while-revalidate` (limited) |
| `origin_error_page_passthru` | Cache Rules | Requires Lambda@Edge to intercept origin errors | Lambda@Edge origin-response |
| Custom error with inline content > 1 KB | Custom Error Rules | Inline content exceeds CloudFront KVS 1024-character value limit | Deploy error page as static file + `response_page_path` |
| Custom error with inline content + response-phase condition | Custom Error Rules | CFF viewer-response does not execute on 4xx+ responses | Deploy error page as static file on origin |
| Custom error with unsupported status code | Custom Error Rules | CloudFront only supports: 400, 403, 404, 405, 414, 416, 500–504 | Lambda@Edge origin-response |
| Custom error with dynamic headers/logic | Custom Error Rules | CFF and L@E viewer-response do not execute on 4xx+ responses | Lambda@Edge origin-response |
| `browser_check` | Configuration | No CloudFront equivalent | AWS WAF Bot Control |
| `minify` (HTML/CSS/JS) | Configuration | Not supported natively in CloudFront | Origin-side minification |
| `rocket_loader` | Configuration | Cloudflare-specific JS optimization | N/A |
| `hotlink_protection` | Configuration | Requires custom referer-checking logic | Lambda@Edge |
| Device detection headers (UA regex) | Request Header Transform | CloudFront provides native device detection | Origin Request Policy with `CloudFront-Is-*-Viewer` headers |
| Dynamic values with non-mappable CF variables | Request/Response Header Transform | CloudFront Functions cannot evaluate all Cloudflare expressions | Manual review |
| Cloud Connector with non-path expressions | Cloud Connector | CloudFront cache behaviors only match on path patterns | Manual origin configuration |
| Disallowed/read-only response headers | Response Header Transform | CloudFront restricts modification of certain headers (`Via`, `X-Amz-Cf-*`, etc.) | N/A |

### CORS with `credentials: true` and wildcard origin

Cloudflare allows `Access-Control-Allow-Credentials: true` with `Access-Control-Allow-Origin: *`. CloudFront's Response Headers Policy rejects this combination per the CORS spec.

The tool works around this by replacing `*` with TLD wildcard patterns (`*.com`, `*.net`, `*.io`, etc. — ~60 common TLDs). CloudFront matches the request `Origin` header against these patterns and echoes back the exact origin value, satisfying the CORS spec.

Limitations:
- Origins on TLDs not in the default list will not match. Add patterns to `policies.tf` as needed.
- Scheme-less wildcard patterns (`*.com`) do not match origins with non-standard ports (e.g., `http://example.com:8080`). CloudFront only serves on ports 80/443, so this only affects cross-origin requests *from* non-standard-port origins.
- When the Cloudflare rule used `add` operation (not `set`), `origin_override` is set to `false`. In this mode, CloudFront only returns CORS headers when the request contains an `Origin` header. Cloudflare adds CORS headers unconditionally regardless of request headers. This difference only affects non-browser clients (curl, SDKs) — browsers always send `Origin` for cross-origin requests.

### CloudFront Function size limit

CloudFront Functions have a **hard** 10 KB size limit (not raisable via Service Quotas or AWS Support). Viewer events are CloudFront-Functions-only — this tool never falls back to Lambda@Edge for viewer-request/response, because L@E adds latency and per-request cost and changes the execution model.

When a domain's `viewer_request.js` or `viewer_response.js` exceeds 10 KB, the tool minifies it; if it still exceeds the limit, the **whole domain** is reported `SIZE_EXCEEDED` for human intervention (a CFF can't be partially deployed, and request/response are one logical unit). The tool does not silently drop operations or hand-migrate them to Lambda@Edge. The options are to simplify or split the Cloudflare rules for that host, or drop rules that can't fit. (`origin_override` always stays in the CFF as `cf.updateRequestOrigin`. Lambda@Edge is used only for the default-cache-behavior TTL origin-response — never for viewer events, and never for custom errors.)

### CloudFront quota limits

Quotas are labeled **soft** (raisable) or **hard** (must redesign). Most soft quotas are raised self-service via Service Quotas; a few (e.g. Functions per account) aren't in Service Quotas and need an AWS Support case. The conversion report states which for each warning, so you don't file a request for an unraisable limit.

| Resource | Limit | Soft/Hard | What happens when exceeded |
|----------|-------|-----------|---------------------------|
| CloudFront Functions per account | 100 | Soft (Support case) | Content-hash dedup shares identical CFF across domains (e.g., 54 domains → 5 CFF). Checked post-dedup; warning in conversion report if still exceeded. This quota is **not** in Service Quotas — raise it via an AWS Support case, not the self-service console |
| Distributions per account | 500 | Soft | Warning (one distribution per proxied host) |
| KeyValueStores per account | 50 | Soft | Warning (one per host needing KVS) |
| Cache behaviors per distribution | 75 | Soft | Validation error + warning — raise via Service Quotas or reduce Cloudflare rules |
| Custom cache/ORP/RHP policies per account | 20 each | Soft | Warning |
| Cache policy headers / cookies / query strings (whitelist) | 10 each | Soft | Validation error + warning — the config won't deploy until raised via Service Quotas |
| Origin request policy headers | 10 | Soft | Warning |
| Combined query/header/cookie **name length** per policy | 1024 | Hard | Warning (cannot be raised) |
| CloudFront Function size | 10 KB | Hard | Domain reported `SIZE_EXCEEDED` (see above) |

### Cloudflare match fields with no CloudFront equivalent

| Field | Reason |
|-------|--------|
| `cf.edge.server_port`, `cf.zone.name`, `cf.metal.id`, `cf.ray_id` | Cloudflare-specific internal fields |
| `cf.tls_client_auth.*` | mTLS certificate fields not available in CloudFront Functions |
| `ip.src.subdivision_2_iso_code` | CloudFront only provides first-level subdivision |
| `http.request.timestamp.sec/msec` | Use `Date.now()` in CloudFront Functions instead |

### Regex limitations

CloudFront path patterns only support `*` and `?` wildcards — no regex. When a Cloudflare rule uses a regex/complex path expression that cannot be mapped to a single wildcard pattern:

- **Cache Rules** (TTL / cache-key settings): a cache setting is applied to a specific behavior's cache policy, so its scope must be expressible as that behavior's path pattern. A scope that isn't (regex, a multi-field AND, a negated path) is recorded **non-convertible** and reported — it is not routed to a Lambda@Edge conditional-cache handler (that sink existed once, consumed nothing, and silently dropped rules; it was removed).
- **Other rule types** (redirect, rewrite, header transform, cache **bypass**): these run in a CloudFront Function, which evaluates the full condition per-request. They land on the default `"*"` behavior with the condition rendered into the CFF JS (`request.uri`-based matching), so a regex/complex path still works — it just isn't a separate cache behavior.

### What happens to non-convertible items

Non-convertible items are **not silently dropped**. The pipeline:
1. Records each one in the IR with a `reason` string
2. Aggregates them in `conversion_report.md` (generated by the finalizer)
3. The report groups items by domain and rule type for human review

## WAF Pipeline — What Does NOT Get Converted

| Item | Reason | Alternative |
|------|--------|-------------|
| Cloudflare Managed Rules (OWASP, etc.) | Use AWS WAF's own managed rule groups | AWS Managed Rules for WAF |
| API Abuse Detection | Cloudflare-specific ML feature | AWS WAF Bot Control + custom rules |
| SaaS / mTLS configurations | Fundamentally different architecture | Manual design required |

### AWS WAF hard caps and how the tool fits them

AWS enforces several per-WebACL caps that **cannot** be raised (not even via Service Quotas or Support):

| Cap | Limit | How the tool handles it |
|-----|-------|-------------------------|
| Rate-based rules per WebACL | 10 | Overflow rate-based rules are packed into referenced **rule groups** (≤4 each), which don't count against the 10. |
| Reference statements per WebACL | 50 (IP-set + regex-set + rule-group + **managed-rule-group** references all count) | Overflow IP-set references are packed into rule groups; the WebACL pays 1 reference per group. |
| WCU per WebACL | 5000 (over 1500 = extra charges) | Computed exactly from the assembled template. If a WebACL exceeds 5000 the tool reports `STATUS: BLOCKED` — it cannot be reduced by packing, so you must simplify the rules. |
| Rate-based / rule-group | ≤4 rate-based rules, ≤50 references, ≤5000 WCU per group | The packer respects these when filling groups. |

The packer preserves Cloudflare's fixed phase order (custom → rate → managed) and rewrites label keys to the correct form when a rule moves into a rule group. So the default output is **2 WebACLs** even for configs that reference far more than 50 IP sets — a per-host split is no longer forced by the 50-reference cap. A config is only undeployable (`STATUS: BLOCKED`, template still written for inspection) when a WebACL's WCU exceeds 5000 or a single rule is too complex to fit one rule group.

### Rate-limit semantics that change

- **`mitigation_timeout` (block duration) is lost.** Cloudflare can block a client for a fixed period after a breach; AWS WAF only blocks while the trailing-window rate stays over the limit (unblocks ~≤30s after it drops). Every affected rule is listed in the report — it is not silently dropped.
- **Low thresholds are scaled up, never dropped.** AWS's minimum rate limit is 10 per evaluation window ({60,120,300,600}s); a Cloudflare rate below that is scaled to the first legal window, with a 10/600s fallback. Slightly more permissive, noted in the report.
- **Counters are per-WebACL-instance.** One WebACL attached to N CloudFront distributions shares one counter across them (matches Cloudflare's zone-wide intent). The tool does not merge distinct rate rules (a shared counter would throttle a client spreading across paths at a fraction of each rule's intended threshold).

## General Limitations

### Manual review required

AI-generated configurations require manual review before production deployment. Pay special attention to:
- Complex conditional logic and regular expressions
- Origin routing rules (verify correct backend mapping)
- Cache TTL values (verify business requirements)
- Security-sensitive headers

### Large-scale configurations

- **API rate limits** may slow down parallel processing. See the README for guidance on adjusting batch size.

### Features not configured by this tool

- **CloudFront access logging** — involves decisions (S3 bucket, log format, shared vs per-domain) outside migration scope
- **Lambda@Edge origin-response** — this IS fully automated when a rule needs it (the default-cache-behavior TTL handler): the IAM role, archive, Lambda function, and `qualified_arn` reference in `main.tf` are all generated by the scaffold. The tool does **not** generate a Lambda@Edge origin-response for custom-error rules — those convert to native `custom_error_response`, or a CFF+KVS inline error page, or are reported non-convertible (see the Custom Error rows above). There is no Lambda@Edge for viewer events either — a CFF over 10 KB is reported `SIZE_EXCEEDED` for human intervention, never split to L@E.
- **DNS cutover** — the tool generates CloudFront distributions but does not modify DNS records. You must update DNS to point to CloudFront after verifying the configuration.
