# Convertible Cloudflare Rules

This document lists all Cloudflare transformation rules that can be converted to CloudFront Functions.

## From Rules > Settings

### Bulk Redirects
**Convertible**: ✅ Yes

- Define a large number of URL redirects at the account level
- Convert to CloudFront Key Value Store
- Cloudflare account-level bulk redirect lists → CloudFront KVS JSON file

**Conversion approach**:
- Extract redirect mappings from `List-Items-redirect-bulk_<LIST_NAME>.txt`
- Create KVS entries with prefix `redirect:` (e.g., `redirect:/old-path`)
- Value contains destination URL

### True-Client-IP (Managed Transformation)
**Convertible**: ✅ Yes (only this managed transform)

- Add `True-Client-IP` header with client's IP address
- Convert to CloudFront Function that adds header from `event.viewer.ip`

**Other Managed Transforms**: ❌ Not convertible
- Some should use CloudFront configuration
- Others are Cloudflare-specific features not supported by AWS

## From Rules > Overview

### Redirect Rules
**Convertible**: ✅ Partial

**Convert**:
- Complex redirect rules with conditions
- Dynamic redirects based on headers, geo, etc.
- Path-based redirects with transformations

**Do NOT convert**:
- Simple `http://*` → `https://*` redirects
  - **Reason**: Use CloudFront distribution settings (Viewer Protocol Policy: Redirect HTTP to HTTPS)
  - No function needed

### URL Rewrite Rules
**Convertible**: ✅ Yes

- Rewrite the URL path and query string
- Convert all URL rewrite rules to CloudFront Function logic
- Modify `request.uri` or `request.querystring`

### Request Header Transform Rules
**Convertible**: ✅ Partial

**Convert**:
- Adding headers (static or dynamic)
- Modifying existing headers
- **Special case**: Replace "Cloudflare" with "CloudFront" in header values
  - Example: `X-From-CDN: Cloudflare` → `X-From-CDN: CloudFront`

**Do NOT convert**:
1. **Removing headers or cookies**
   - **Reason**: Use CloudFront Origin Request Policy
   - No function needed

2. **Cloudflare-specific features**
   - Bot Score headers (e.g., `X-Bot-Score`)
   - Threat Score headers
   - **Reason**: Cloudflare-specific data not available in CloudFront

3. **Device detection headers**
   - Example: `X-Is-Mobile: true` based on User-Agent
   - **Reason**: CloudFront provides native viewer headers
   - Use Origin Request Policy to include `CloudFront-Is-Mobile-Viewer`
   - No function needed

**Before conversion**: Review `cloudfront-viewer-headers.md` to understand available CloudFront headers



## Convertible Match Fields

These Cloudflare fields can be matched in CloudFront Functions:

### URI Fields
- `http.request.full_uri` → Construct from `request.uri` + `request.rawQueryString()`
- `http.request.uri.path` → `request.uri`
- `http.request.uri` → `request.uri` + query string
- `http.request.uri.query` → `request.rawQueryString()`
- `raw.http.request.full_uri` → Same as above (ignore URL normalization)
- `raw.http.request.uri.path` → Same as above
- `raw.http.request.uri` → Same as above
- `raw.http.request.uri.query` → Same as above

**Note**: Cloudflare URL normalization is fundamentally different from CloudFront. Do not attempt to replicate normalization behavior.

### Host and Method
- `http.host` → `request.headers.host.value`
- `http.request.method` → `request.method`

### Headers
- `http.referer` → `request.headers.referer.value`
- `http.user_agent` → `request.headers['user-agent'].value`
- `http.x_forwarded_for` → `request.headers['x-forwarded-for'].value`

### Cookies
- `http.cookie` → `request.cookies`

### IP and Geo Fields
- `ip.src` → `event.viewer.ip`
- `ip.src.asnum` → `request.headers['cloudfront-viewer-asn'].value`
- `ip.src.country` → `request.headers['cloudfront-viewer-country'].value`
- `ip.src.city` → `request.headers['cloudfront-viewer-city'].value`
- `ip.src.lat` → `request.headers['cloudfront-viewer-latitude'].value`
- `ip.src.lon` → `request.headers['cloudfront-viewer-longitude'].value`
- `ip.src.subdivision_1_iso_code` → Combine `cloudfront-viewer-country` + `cloudfront-viewer-country-region` with hyphen
  - Example: Country `CN` + Region `GD` = `CN-GD`

### Continent and EU
- `ip.src.continent` → Derive from country code using continent mapping (see `continent-countries.md`)
  - **Decision**: If only a few countries needed, hardcode in function
  - **Decision**: If many countries needed, use KVS with prefix `continent:`

- `ip.src.is_in_european_union` → Check against EU country list
  - EU countries: `['AT','BE','BG','CY','CZ','DE','DK','EE','ES','FI','FR','GR','HR','HU','IE','IT','LT','LU','LV','MT','NL','PL','PT','RO','SE','SI','SK']`
  - **Decision**: If function size allows, hardcode array in function
  - **Decision**: If function size constrained, use KVS with prefix `eu:`

### HTTP Version
- `http.request.version` → `request.headers['cloudfront-viewer-http-version'].value`

## Optimization Guidelines

### Host Matching
For patterns like `*.example.com`:

```javascript
// ❌ BAD - Complex regex
if (/^.*\.example\.com$/.test(host)) { }

// ✅ GOOD - String method
if (host.endsWith('.example.com')) { }
```

### Path Matching
For patterns like `/path/*`:

```javascript
// ❌ BAD - Regex
if (/^\/path\/.*$/.test(uri)) { }

// ✅ GOOD - String method
if (uri.startsWith('/path/')) { }
```

### Combined Matching
For URL patterns like `https://*.example.com/path/*`:

Break into components:
1. Host: `host.endsWith('.example.com')`
2. URI: `uri.startsWith('/path/')`
3. Query: `rawQueryString()` if needed

## Summary

**Convertible rule types**:
- Bulk Redirects → KVS
- True-Client-IP → Function
- Complex Redirect Rules → Function
- URL Rewrite Rules → Function
- Header Transform Rules (selective) → Function

**Key principle**: If it can be done with CloudFront configuration (cache policy, origin request policy, distribution settings), don't use a function.
