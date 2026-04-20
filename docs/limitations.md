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
| Cache Rules | Cache policies on cache behaviors |
| Cloud Connector Rules | Independent cache behaviors with separate origins |
| Custom Error Rules | CloudFront custom error responses |
| Response Header Transform | Response Headers Policy + CloudFront Functions (viewer-response) |
| Compression Rules | Cache policy `enable_gzip` / `enable_brotli` |

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
| Query string-only rewrite | URL Rewrite | CloudFront Functions cannot modify query strings independently | Lambda@Edge |
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

CloudFront Functions have a 10 KB size limit after minification. When a domain's `viewer_request.js` exceeds this limit:

1. If the function contains `origin_override` operations, those are split out to a Lambda@Edge origin-request handler, reducing the CFF size.
2. If the CFF still exceeds 10 KB after splitting, the lowest-priority operations are removed and marked as `non_convertible`. They are **not** escalated to Lambda@Edge viewer-request — viewer events only use CloudFront Functions.

### CloudFront quota limits

| Resource | Limit | What happens when exceeded |
|----------|-------|---------------------------|
| CloudFront Functions per account | 100 | Warning in conversion report. Not listed as adjustable in Service Quotas — contact AWS Support to inquire, but approval is not guaranteed |
| Cache behaviors per distribution | 75 | Pipeline error — reduce Cloudflare rules |
| Cache policy headers (whitelist) | 10 | Marked non_convertible |
| Cache policy cookies (whitelist) | 10 | Marked non_convertible |
| Cache policy query strings (whitelist) | 10 | Marked non_convertible |
| Origin request policy headers | 10 | Marked non_convertible |

### Cloudflare match fields with no CloudFront equivalent

| Field | Reason |
|-------|--------|
| `cf.edge.server_port`, `cf.zone.name`, `cf.metal.id`, `cf.ray_id` | Cloudflare-specific internal fields |
| `cf.tls_client_auth.*` | mTLS certificate fields not available in CloudFront Functions |
| `ip.src.subdivision_2_iso_code` | CloudFront only provides first-level subdivision |
| `http.request.timestamp.sec/msec` | Use `Date.now()` in CloudFront Functions instead |

### Regex limitations

CloudFront path patterns only support `*` and `?` wildcards — no regex. When a Cloudflare rule uses a regex path expression that cannot be mapped to a wildcard pattern:

- **Cache Rules**: routed to Lambda@Edge origin-response, which evaluates the regex at runtime and sets `Cache-Control` headers accordingly.
- **Other rule types** (redirect, rewrite, header transform): assigned to the default `"*"` behavior with the original expression preserved as `raw_expression` for CloudFront Function JS generation.

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
- **Lambda@Edge origin-request deployment** — when CFF exceeds 10 KB and origin_override ops are split to Lambda@Edge, the generated `origin_request_handler.js` includes a comment with the `main.tf` entry you need to add manually after deploying the Lambda function. This only applies to domains where CFF size overflow triggers the split — most domains won't need this. Lambda@Edge origin-response is fully automated (IAM role, archive, Lambda function, and `qualified_arn` reference in `main.tf` are all generated by the scaffold).
- **DNS cutover** — the tool generates CloudFront distributions but does not modify DNS records. You must update DNS to point to CloudFront after verifying the configuration.
