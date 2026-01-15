# URL Conversion Examples

This document explains how Cloudflare and CloudFront handle URLs differently, and provides conversion patterns. **Read this when converting rules that match or transform URLs** to understand how to correctly map Cloudflare URL fields to CloudFront equivalents.

## Cloudflare URL Field Breakdown

Cloudflare provides multiple URI match fields that capture different parts of the URL:

**Example URL**: `https://www.example.com/free-cookies?code=C7K543#section-anchor`

| Cloudflare Field | Value | Description |
|-----------------|-------|-------------|
| `http.request.full_uri` | `https://www.example.com/free-cookies?code=C7K543` | Full URL (schema + host + path + query) |
| `http.request.uri` | `/free-cookies?code=C7K543` | Path + query string |
| `http.request.uri.path` | `/free-cookies` | Path only |
| `http.request.uri.query` | `code=C7K543` | Query string only (no `?` delimiter) |

**Query string arguments**:
- `http.request.uri.args["include"][*]` - All values of parameter `include`
- `http.request.uri.args["include"][0]` - First value of parameter `include`

## CloudFront URL Structure

These rules have explicit `preserve_query_string` parameter:
- Dynamic values work on **URI path only** (no query string)
- Query string handling is controlled by the `preserve_query_string` flag
- When `true`: Cloudflare automatically appends original query string to target URL
- When `false`: Query string is discarded

### Example: Redirect Rule with preserve_query_string

**Cloudflare Redirect Rule**:
```
Source: /old/test
Target: /new/test
preserve_query_string: true
Request: /old/test?foo=bar
Result: /new/test?foo=bar (query string auto-appended by Cloudflare)
```

**CloudFront Function conversion**:
```javascript
// Check preserve_query_string flag from rule configuration
if (preserveQueryString) {
    const qs = request.rawQueryString();
    finalUrl = qs ? targetUrl + '?' + qs : targetUrl;
} else {
    finalUrl = targetUrl;  // Discard query string
}
```

## Single Redirects with Wildcard Pattern

When using wildcard pattern mode in Single Redirects:
- Wildcards capture complete URL segments including query string
- Use `${1}`, `${2}` for wildcard replacement

### Example: Wildcard Pattern in Single Redirect

**Cloudflare Single Redirect**:
```
Pattern: /blog/*/comments
Target: /articles/${1}/discussion
Request: /blog/2024-post/comments?page=2

Cloudflare behavior:
- ${1} captures: "2024-post"
- Result: /articles/2024-post/discussion?page=2
```

**CloudFront Function conversion**:
```javascript
// Extract path segment and preserve query string
const match = uri.match(/^\/blog\/([^\/]+)\/comments$/);
if (match) {
    const captured = match[1];  // "2024-post"
    const qs = request.rawQueryString();
    const targetPath = '/articles/' + captured + '/discussion';
    const finalUrl = qs ? targetPath + '?' + qs : targetPath;
    return {
        statusCode: 301,
        headers: {location: {value: finalUrl}}
    };
}
```

## Accessing URL Components in CloudFront Functions

```javascript
function handler(event) {
    const request = event.request;
    
    // Host (domain)
    const host = request.headers.host.value;  // "www.example.com"
    
    // URI path (no query string)
    const uri = request.uri;  // "/free-cookies"
    
    // Query string (separate method call)
    const qs = request.rawQueryString();  // "code=C7K543"
    
    // Reconstruct full URL if needed
    const fullUrl = 'https://' + host + uri + (qs ? '?' + qs : '');
    
    return request;
}
```

## Conversion Checklist

When converting Cloudflare rules to CloudFront Functions:

- [ ] **Redirect Rules** → Check `preserve_query_string` flag, append if true
- [ ] **Bulk Redirects** → Check `preserve_query_string` flag in KVS value
- [ ] **Single Redirects (wildcard mode)** → Reconstruct path + query string for `${1}`, `${2}`, etc.
- [ ] **Single Redirects (custom expression)** → Check if rule has preserve query string setting
