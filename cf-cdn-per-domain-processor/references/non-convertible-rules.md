# Non-Convertible Cloudflare Rules

This document lists Cloudflare rules and fields that **cannot** be automatically converted to CloudFront equivalents by the CDN pipeline, along with explanations and alternatives.

> **Scope**: This document covers the full IR-based CDN pipeline (`cf-cdn-per-domain-processor`), which converts Cloudflare rules to CloudFront cache behaviors, policies, distribution settings, and CloudFront Functions. Rules listed here as non-convertible cannot be expressed in ANY of these CloudFront mechanisms.

## Fully Convertible Rule Types (handled by cf-cdn-per-domain-processor)

The following rule types ARE converted by the pipeline — do NOT mark them as non-convertible at the rule-type level. Individual rules within these types may still be non-convertible if they use unsupported fields or expressions.

| Rule Type | Converted To | Notes |
|-----------|-------------|-------|
| Redirect Rules | CF Function viewer_request_ops (redirect) + distribution_settings (HTTP→HTTPS) | Simple HTTP→HTTPS uses viewer_protocol_policy, not a function |
| URL Rewrite Rules | CF Function viewer_request_ops (rewrite) | Query-only rewrites flagged as needing Lambda@Edge |
| Configuration Rules | distribution_settings (TLS, HTTP version, protocol policy) | Cloudflare-specific settings (minify, rocket_loader, etc.) are non-convertible |
| Origin Rules | CF Function viewer_request_ops (origin_override) | S3 OAC-redundant rules skipped silently |
| Bulk Redirects | KVS + CF Function viewer_request_ops (bulk_redirect) | Account-level redirect lists → KVS entries |
| Request Header Transform | CF Function viewer_request_ops (set/add/remove_header) + ORP | Remove ops use ORP allExcept; device detection uses native CF headers |
| Cache Rules | cache_policy on cache behaviors | Last-match-wins semantics; serve_stale and origin_error_page_passthru are non-convertible |
| Cloud Connector | Separate cache behaviors with appropriate origins | Only path-based expressions; non-path expressions are non-convertible |
| Custom Error Rules | custom_error_responses (distribution-level) + Lambda@Edge | Simple status remap → CF custom_error_response; advanced → Lambda@Edge |
| Response Header Transform | response_headers_policy + CF Function viewer_response_ops | Static headers → RHP; conditional/dynamic → viewer_response_ops |
| Compression Rules | cache_policy enable_gzip/enable_brotli | Unsupported algorithms silently ignored |

## Non-Convertible Items Within Convertible Rule Types

These are specific settings or expressions within otherwise-convertible rule types that cannot be mapped to CloudFront.

### Configuration Rules — Non-Convertible Settings

| Cloudflare Setting | Reason | Alternative |
|-------------------|--------|-------------|
| `browser_check` | Browser Integrity Check has no CloudFront equivalent | AWS WAF Bot Control |
| `minify` | HTML/CSS/JS minification not supported natively in CloudFront | Origin-side minification |
| `rocket_loader` | Cloudflare-specific JS optimization | Not applicable |
| `hotlink_protection` | Requires custom referer-checking logic | Lambda@Edge custom logic |

### Cache Rules — Non-Convertible Settings

| Cloudflare Setting | Reason | Alternative |
|-------------------|--------|-------------|
| `serve_stale` (SWR/SIE) | No direct CloudFront cache policy equivalent | Origin Cache-Control stale-while-revalidate (limited support) |
| `origin_error_page_passthru` | Requires Lambda@Edge to intercept origin errors | Lambda@Edge origin-response |
| Regex path expressions | CloudFront path patterns only support `*` and `?` wildcards | Map to default `"*"` behavior |

### URL Rewrite Rules — Non-Convertible Settings

| Cloudflare Setting | Reason | Alternative |
|-------------------|--------|-------------|
| Query string-only rewrite (`action_parameters.uri.query`) | CF Functions cannot modify query strings independently | Lambda@Edge |

### Request Header Transform — Non-Convertible Settings

| Cloudflare Setting | Reason | Alternative |
|-------------------|--------|-------------|
| Dynamic values using `concat()` with non-mappable CF variables | CF Functions cannot evaluate all Cloudflare expressions | Manual review |
| Device detection headers (e.g., `X-Is-Mobile` from UA regex) | CloudFront provides native device detection headers | Use CloudFront Origin Request Policy with `CloudFront-Is-Mobile-Viewer` etc. |

### Cloud Connector — Non-Convertible Expressions

| Expression Type | Reason | Alternative |
|----------------|--------|-------------|
| `expression: true` (all requests) | Cannot be expressed as a CloudFront cache behavior path pattern | Manual origin configuration |
| Non-URI-path conditions (header, geo, etc.) | CloudFront cache behaviors only match on path patterns | Manual origin configuration |

## Fully Non-Convertible Rule Types

These rule types are NOT processed by the CDN pipeline at all.

### Page Rules (Legacy)
**Convertible**: ❌ No

**Reasons**:
1. Deprecated by Cloudflare — being phased out in favor of modern rule types
2. Most capabilities are covered by newer rule types that the pipeline already converts
3. Users should migrate to modern Cloudflare rules first, then use this tool

### Snippets
**Convertible**: ❌ No

**Reason**: Snippets are arbitrary JavaScript code, not declarative configuration. Cannot be automatically converted.

### URL Normalization
**Convertible**: ❌ No (not needed)

**Reason**: CloudFront normalizes URI paths consistent with RFC 3986 before cache behavior matching. No conversion needed — skip silently.

### Managed Transforms (except True-Client-IP)
**Convertible**: ❌ No (except True-Client-IP)

**Reason**: Some should use CloudFront configuration instead; others are Cloudflare-specific features.

### Trace
**Convertible**: ❌ No

**Reason**: Cloudflare-specific testing feature. Use CloudFront testing tools and CloudWatch Logs.

## Non-Convertible Match Fields

### Cloudflare-Specific Fields

| Field | Reason |
|-------|--------|
| `cf.edge.server_port` | Cloudflare-specific; CloudFront always uses 80 or 443 |
| `cf.zone.name` | Cloudflare-specific |
| `cf.metal.id` | Cloudflare-specific server identifier |
| `cf.ray_id` | Cloudflare-specific request ID (use `event.context.requestId` in CloudFront) |
| `http.request.timestamp.sec/msec` | Cloudflare-specific (use `Date.now()` in CF Functions) |
| `cf.tls_client_auth.*` | mTLS certificate fields not available in CF Functions |
| `ip.src.subdivision_2_iso_code` | CloudFront only provides first-level subdivision |
| `cf.edge.server_ip` | Server IPs change after migration; rules become meaningless |

### Response-Phase Fields

| Field | Reason |
|-------|--------|
| Response status code matching | CF Functions not invoked for HTTP 400+ responses |
| Response error type | Cloudflare-specific; use Lambda@Edge origin-response |
| SSL/TLS fields | Use CloudFront distribution configuration |
| Client certificate verified | mTLS verification happens before function execution |

### Special Cases

| Field | Reason |
|-------|--------|
| `ip.src.continent` = `"T1"` (Tor) | Security rule, not geographic — convert via WAF skill instead |

## Explanation Strategy

When encountering non-convertible items, the processor should:

1. Add an entry to the `non_convertible` list in the IR with a clear `reason` string
2. Include the original Cloudflare rule ID in `cf_source_rule`
3. Specify the `rule_type` for categorization
4. Set `shadowed: false` (unless the rule is actually shadowed)

The conversion report (`conversion_report.md`) generated by `cf-cdn-ir-finalizer` aggregates all non-convertible items across all domains for human review.
