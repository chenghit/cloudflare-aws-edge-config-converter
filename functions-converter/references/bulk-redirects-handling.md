# Bulk Redirects Handling

## Critical Requirements

When processing Cloudflare bulk redirects, you MUST handle ALL parameters correctly to generate complete KVS entries.

## Bulk Redirect Parameters

Each bulk redirect entry has these parameters:

```json
{
  "redirect": {
    "source_url": "example.com/path",
    "target_url": "https://example.com/new-path",
    "status_code": 301,
    "include_subdomains": true,
    "preserve_query_string": true
  }
}
```

### Parameter Meanings

1. **`source_url`**: Source URL pattern (without protocol)
2. **`target_url`**: Destination URL (with protocol)
3. **`status_code`**: HTTP status code (301 or 302)
4. **`include_subdomains`**: If true, match all subdomains
5. **`preserve_query_string`**: If true, append original query string to target

### Default Values

- `status_code`: 301 (if not specified)
- `include_subdomains`: false (if not specified)
- `preserve_query_string`: false (if not specified)

## KVS Key Generation Rules

### Rule 1: include_subdomains = false

Generate ONE KVS entry with exact host match:

```json
{
  "key": "redirect:example.com/path",
  "value": "301|0|https://example.com/new-path"
}
```

### Rule 2: include_subdomains = true

Generate TWO KVS entries:
1. Exact domain match
2. Subdomain wildcard match (with leading dot)

```json
{
  "key": "redirect:example.com/path",
  "value": "301|1|https://example.com/new-path"
},
{
  "key": "redirect:.example.com/path",
  "value": "301|1|https://example.com/new-path"
}
```

**Why two entries?**
- `example.com/path` matches exact domain
- `.example.com/path` matches any subdomain (cdn.example.com, www.example.com, etc.)

## Function Lookup Logic

When `include_subdomains = true`, the function must try BOTH lookups:

```javascript
// Try exact host match first
try {
    const dest = await kvsHandle.get(`redirect:${host}${uri}`);
    return redirect(dest);
} catch (err) {}

// Try subdomain match (replace first segment with dot)
if (host.includes('.')) {
    const subdomain = '.' + host.substring(host.indexOf('.') + 1);
    try {
        const dest = await kvsHandle.get(`redirect:${subdomain}${uri}`);
        return redirect(dest);
    } catch (err) {}
}
```

## KVS Value Format

**Format**: `{status_code}|{preserve_qs}|{target_url}`

- `status_code`: 301 or 302
- `preserve_qs`: `1` (true) or `0` (false)
- `target_url`: Full destination URL with protocol

**Example**:
```
301|1|https://example.com/new-path
```

This means: 301 redirect, preserve query string, to https://example.com/new-path

## Query String Handling

### preserve_query_string = 0 (false)

Target URL is used as-is, original query string is discarded:

```javascript
return {
    statusCode: 301,
    headers: {location: {value: targetUrl}}
};
```

### preserve_query_string = 1 (true)

Append original query string to target URL:

```javascript
const qs = request.rawQueryString();
if (qs) {
    const separator = targetUrl.includes('?') ? '&' : '?';
    finalUrl = `${targetUrl}${separator}${qs}`;
} else {
    finalUrl = targetUrl;
}
```

## Complete Example

### Cloudflare Bulk Redirect Entry

```json
{
  "redirect": {
    "source_url": "example.com/about",
    "target_url": "https://cdn.example.com/news",
    "status_code": 301,
    "include_subdomains": true,
    "preserve_query_string": true
  }
}
```

### Generated KVS Entries

```json
{
  "key": "redirect:example.com/about",
  "value": "301|1|https://cdn.example.com/news"
},
{
  "key": "redirect:.example.com/about",
  "value": "301|1|https://cdn.example.com/news"
}
```

### CloudFront Function Logic

```javascript
import cf from 'cloudfront';

const kvsHandle = cf.kvs();

async function handler(event) {
    const request = event.request;
    const uri = request.uri;
    const host = request.headers.host.value;
    
    // Try exact host match
    let redirectData = await tryRedirect(`redirect:${host}${uri}`);
    
    // Try subdomain match if exact match failed
    if (!redirectData && host.includes('.')) {
        const subdomain = '.' + host.substring(host.indexOf('.') + 1);
        redirectData = await tryRedirect(`redirect:${subdomain}${uri}`);
    }
    
    if (redirectData) {
        const parts = redirectData.split('|');
        const statusCode = parts[0];
        const preserveQs = parts[1];
        const targetUrl = parts[2];
        const qs = request.rawQueryString();
        let finalUrl = targetUrl;
        
        if (preserveQs === '1' && qs) {
            const separator = targetUrl.includes('?') ? '&' : '?';
            finalUrl = `${targetUrl}${separator}${qs}`;
        }
        
        return {
            statusCode: parseInt(statusCode),
            headers: {location: {value: finalUrl}}
        };
    }
    
    return request;
}

async function tryRedirect(key) {
    try {
        return await kvsHandle.get(key);
    } catch (err) {
        return null;
    }
}
```

## Validation Checklist

Before generating KVS file, verify:

- [ ] Each bulk redirect with `include_subdomains: true` generates TWO KVS entries
- [ ] Each bulk redirect with `include_subdomains: false` generates ONE KVS entry
- [ ] Status code is stored (default 301 if not specified)
- [ ] `preserve_query_string` flag is stored as `1` or `0` (default 0 if not specified)
- [ ] Target URL includes protocol (https://)
- [ ] Source URL does NOT include protocol
- [ ] KVS keys use format: `redirect:{host}{path}`
- [ ] Subdomain keys use format: `redirect:.{domain}{path}` (note the leading dot)

## Common Mistakes to Avoid

❌ **Mistake 1**: Only generating one KVS entry when `include_subdomains: true`

```json
// WRONG - Missing subdomain entry
{"key": "redirect:example.com/path", "value": "301|1|..."}
```

✅ **Correct**:
```json
{"key": "redirect:example.com/path", "value": "301|1|..."},
{"key": "redirect:.example.com/path", "value": "301|1|..."}
```

❌ **Mistake 2**: Not storing status code or preserve_query_string flag

```json
// WRONG - Missing metadata
{"key": "redirect:example.com/path", "value": "https://example.com/new"}
```

✅ **Correct**:
```json
{"key": "redirect:example.com/path", "value": "301|1|https://example.com/new"}
```

❌ **Mistake 3**: Using "true"/"false" instead of 1/0

```json
// WRONG - Wastes characters
{"key": "redirect:example.com/path", "value": "301|true|https://example.com/new"}
```

✅ **Correct**:
```json
{"key": "redirect:example.com/path", "value": "301|1|https://example.com/new"}
```

❌ **Mistake 4**: Subdomain key without leading dot

```json
// WRONG - Missing leading dot
{"key": "redirect:example.com/path", "value": "301|1|..."}
```

✅ **Correct**:
```json
{"key": "redirect:.example.com/path", "value": "301|1|..."}
```

## Summary

**For each bulk redirect entry:**

1. Parse all parameters (use defaults if missing)
2. Generate KVS entries:
   - If `include_subdomains: false` → 1 entry
   - If `include_subdomains: true` → 2 entries (exact + subdomain)
3. Store metadata in value: `{status}|{preserve_qs}|{target}`
   - Use `1` for true, `0` for false (saves characters)
4. Generate function logic to:
   - Try exact host match first
   - Try subdomain match if needed
   - Parse metadata from value (check `=== '1'`)
   - Handle query string preservation correctly
