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
| Cache Rules (conditional "Bypass cache") | Viewer-request CloudFront Function that forces a cache miss for matching requests (see below); unconditional bypass → managed CachingDisabled policy |
| Cloud Connector Rules | Independent cache behaviors with separate origins |
| Custom Error Rules | CloudFront custom error responses |
| Response Header Transform | Response Headers Policy + CloudFront Functions (viewer-response) |
| Compression Rules | Cache policy `enable_gzip` / `enable_brotli` |

### Conditional cache bypass

CloudFront has no request-time "skip the cache" switch — the cache decision is fixed by the cache policy on a behavior, and behaviors are selected only by path (not by cookie/header/query). To convert a Cloudflare Cache Rule that conditionally bypasses cache (e.g. bypass when a `wordpress_logged_in` cookie is present, or `?test=true`), the tool emits a viewer-request CloudFront Function that, for matching requests, injects a header (`x-cf-cache-bypass`) with a per-request-unique value that is part of the cache key. Each matching request then gets a unique cache key → always a miss → always fetched from origin. This is a forced **miss**, not a true skip (the response is still stored, under a one-time key that's never reused), but the effect for the viewer is identical.

Supported bypass conditions: cookies (`http.cookie`, `http.request.cookies["name"]`), named request headers (`http.request.headers["name"]`), named query args (`http.request.uri.args["name"]`), and query / user-agent / path substrings — existence or a scalar value comparison.

Caveats:
- The multi-value form `any(http.request.cookies["x"][*] == "v")` (and the header/arg equivalents) is **not** converted — it's reported non-convertible rather than guessed at.
- Because the bypass writes into the cache key, it costs a CFF invocation on the behaviors it runs on and produces one-time cache entries for matching requests (harmless — they're never re-served and age out).

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

When a domain's `viewer_request.js` or `viewer_response.js` exceeds 10 KB, the tool minifies it; if it still exceeds the limit, the **whole domain** is reported `SIZE_EXCEEDED` for human intervention (a CFF can't be partially deployed, and request/response are one logical unit). The tool does not silently drop operations or hand-migrate them to Lambda@Edge. The options are to simplify or split the Cloudflare rules for that host, or drop rules that can't fit. (`origin_override` always stays in the CFF as `cf.updateRequestOrigin`. Lambda@Edge is used only for genuine origin events — the default-cache / custom-error origin-response — not for viewer events.)

### CloudFront quota limits

Quotas are labeled **soft** (raisable via Service Quotas) or **hard** (must redesign). The conversion report states which for each warning, so you don't file a Support request for an unraisable limit.

| Resource | Limit | Soft/Hard | What happens when exceeded |
|----------|-------|-----------|---------------------------|
| CloudFront Functions per account | 100 | Soft | Content-hash dedup shares identical CFF across domains (e.g., 54 domains → 5 CFF). Checked post-dedup; warning in conversion report if still exceeded — raise via Service Quotas |
| Distributions per account | 500 | Soft | Warning (one distribution per proxied host) |
| KeyValueStores per account | 50 | Soft | Warning (one per host needing KVS) |
| Cache behaviors per distribution | 75 | Soft | Validation error + warning — raise via Service Quotas or reduce Cloudflare rules |
| Custom cache/ORP/RHP policies per account | 20 each | Soft | Warning |
| Cache policy headers / cookies / query strings (whitelist) | 10 each | Soft | Warning — raise via Service Quotas |
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
- **Lambda@Edge origin-response** — this IS fully automated when a rule needs it (default-cache / custom-error origin-response): the IAM role, archive, Lambda function, and `qualified_arn` reference in `main.tf` are all generated by the scaffold. There is no Lambda@Edge for viewer events — a CFF over 10 KB is reported `SIZE_EXCEEDED` for human intervention, never split to L@E.
- **DNS cutover** — the tool generates CloudFront distributions but does not modify DNS records. You must update DNS to point to CloudFront after verifying the configuration.
