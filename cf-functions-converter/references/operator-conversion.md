# Cloudflare Operators to CloudFront Conversion

This document provides detailed conversion rules for Cloudflare Rules Language operators to CloudFront Functions JavaScript code.

## Overview

Cloudflare uses a domain-specific language with operators like `eq`, `contains`, `wildcard`, and `matches`. CloudFront Functions use JavaScript. This guide shows how to convert each operator type.

**Core principle**: Optimize simple operators to string methods, preserve complex regex unchanged.

## Comparison Operators

### Equal (`eq`) / Not Equal (`ne`)

**Cloudflare:**
```
http.host eq "example.com"
http.host ne "old.example.com"
```

**CloudFront:**
```javascript
if (host === 'example.com') { }
if (host !== 'old.example.com') { }
```

### Contains

**Cloudflare:**
```
http.user_agent contains "Mobi"
http.request.uri.path contains "/admin/"
```

**CloudFront:**
```javascript
const ua = request.headers['user-agent'];
if (ua && ua.value.includes('Mobi')) { }

if (uri.includes('/admin/')) { }
```

### Wildcard (case-insensitive)

**Pattern: Suffix wildcard `*.domain`**

**Cloudflare:**
```
http.host wildcard r"*.example.com"
```

**CloudFront:**
```javascript
if (host.endsWith('.example.com')) { }
```

**Pattern: Prefix wildcard `/path/*`**

**Cloudflare:**
```
http.request.uri.path wildcard r"/api/*"
http.request.full_uri wildcard r"https://*.example.com/files/*"
```

**CloudFront:**
```javascript
if (uri.startsWith('/api/')) { }

// For full URI wildcard, break into components:
if (host.endsWith('.example.com') && uri.startsWith('/files/')) { }
```

**Pattern: Protocol wildcard `http*://`**

**Cloudflare:**
```
http.request.full_uri wildcard r"http://*"
```

**CloudFront:**
```javascript
// This is typically used for HTTP→HTTPS redirect
// Don't convert - use CloudFront distribution settings instead
// Mark as non-convertible
```

### Strict Wildcard (case-sensitive)

**Cloudflare:**
```
http.request.uri.path strict wildcard r"/AdminTeam/*"
```

**CloudFront:**
```javascript
// Same as wildcard, but JavaScript string methods are case-sensitive by default
if (uri.startsWith('/AdminTeam/')) { }
```

### Matches (regex)

**CRITICAL: Preserve original regex unchanged**

**Cloudflare:**
```
http.request.uri.path matches r"^/products/([0-9]+)/([a-z\-]+)$"
http.request.uri.path matches "^/blog/([0-9]{4})/([0-9]{2})/([a-z0-9\\-]+)$"
```

**CloudFront:**
```javascript
// Keep regex exactly as-is (remove r prefix, handle escaping)
if (/^\/products\/([0-9]+)\/([a-z\-]+)$/.test(uri)) { }
if (/^\/blog\/([0-9]{4})\/([0-9]{2})\/([a-z0-9\-]+)$/.test(uri)) { }
```

**Why preserve?**
- User explicitly chose `matches` operator for complex pattern
- `matches` requires Business/Enterprise plan - intentional use
- Changing to string methods would alter matching logic

### In Set

**Cloudflare:**
```
http.host in {"a.com" "b.com" "c.com"}
ip.src.country in {"CN" "US" "GB"}
```

**CloudFront:**
```javascript
if (['a.com', 'b.com', 'c.com'].includes(host)) { }

const country = request.headers['cloudfront-viewer-country'];
if (country && ['CN', 'US', 'GB'].includes(country.value)) { }
```

## Functions

### starts_with()

**Cloudflare:**
```
starts_with(http.request.uri.path, "/api/")
```

**CloudFront:**
```javascript
if (uri.startsWith('/api/')) { }
```

### ends_with()

**Cloudflare:**
```
ends_with(http.request.uri.path, ".html")
```

**CloudFront:**
```javascript
if (uri.endsWith('.html')) { }
```

### lower()

**Cloudflare:**
```
lower(http.request.uri.path) contains "/wp-login.php"
```

**CloudFront:**
```javascript
if (uri.toLowerCase().includes('/wp-login.php')) { }
```

## Logical Operators

### AND

**Cloudflare:**
```
http.host eq "example.com" and ip.src.country eq "CN"
```

**CloudFront:**
```javascript
const country = request.headers['cloudfront-viewer-country'];
if (host === 'example.com' && country && country.value === 'CN') { }
```

### OR

**Cloudflare:**
```
http.host eq "a.com" or http.host eq "b.com"
```

**CloudFront:**
```javascript
if (host === 'a.com' || host === 'b.com') { }

// Or better:
if (['a.com', 'b.com'].includes(host)) { }
```

### NOT

**Cloudflare:**
```
not http.user_agent contains "bot"
```

**CloudFront:**
```javascript
const ua = request.headers['user-agent'];
if (!ua || !ua.value.includes('bot')) { }
```

## Complex Expressions

### Nested Conditions

**Cloudflare:**
```
(http.host eq "example.com" and ip.src.country eq "CN") or 
(http.host eq "example.net" and ip.src.country eq "US")
```

**CloudFront:**
```javascript
const country = request.headers['cloudfront-viewer-country'];
const countryCode = country ? country.value : undefined;

if ((host === 'example.com' && countryCode === 'CN') ||
    (host === 'example.net' && countryCode === 'US')) {
    // ...
}
```

### Multiple Wildcards

**Cloudflare:**
```
http.request.full_uri wildcard r"https://*.example.com/files/*"
```

**CloudFront:**
```javascript
// Break into components
if (host.endsWith('.example.com') && uri.startsWith('/files/')) { }
```

## Conversion Decision Tree

```
For each Cloudflare expression:

1. Identify operator type:
   ├─ eq/ne → Use === or !==
   ├─ contains → Use includes()
   ├─ wildcard (simple suffix *.domain) → Use endsWith()
   ├─ wildcard (simple prefix /path/*) → Use startsWith()
   ├─ wildcard (complex pattern) → Break into components
   ├─ strict wildcard → Same as wildcard (JS is case-sensitive)
   ├─ matches → Keep original regex
   ├─ starts_with() → Use startsWith()
   ├─ ends_with() → Use endsWith()
   ├─ in {...} → Use [...].includes()
   └─ lower() → Use toLowerCase()

2. Handle logical operators:
   ├─ and → &&
   ├─ or → ||
   └─ not → !

3. Preserve rule execution order from Cloudflare JSON array
```

## Special Cases

### HTTP to HTTPS Redirect

**Cloudflare:**
```
http.request.full_uri wildcard r"http://*"
```

**Action**: Mark as non-convertible. Use CloudFront distribution settings (Viewer Protocol Policy: Redirect HTTP to HTTPS).

### Case-Insensitive Matching

**Cloudflare:**
```
lower(http.request.uri.path) eq "/admin"
```

**CloudFront:**
```javascript
if (uri.toLowerCase() === '/admin') { }
```

### Regex with Capture Groups

**Cloudflare:**
```
http.request.uri.path matches r"^/products/([0-9]+)/([a-z\-]+)$"
target_url: regex_replace(http.request.uri.path, "^/products/([0-9]+)/([a-z\\-]+)$", "/items/${1}?slug=${2}")
```

**CloudFront:**
```javascript
const match = uri.match(/^\/products\/([0-9]+)\/([a-z\-]+)$/);
if (match) {
    const productId = match[1];
    const slug = match[2];
    const targetUrl = '/items/' + productId + '?slug=' + slug;
    return redirect(302, targetUrl);
}
```

## Validation Checklist

When converting Cloudflare expressions:

- [ ] `eq`/`ne` converted to `===`/`!==`
- [ ] `contains` converted to `includes()`
- [ ] Simple `wildcard` patterns converted to `startsWith()`/`endsWith()`
- [ ] `matches` regex preserved unchanged
- [ ] `starts_with()`/`ends_with()` functions converted to string methods
- [ ] `in {...}` converted to `[...].includes()`
- [ ] Logical operators (`and`, `or`, `not`) converted to `&&`, `||`, `!`
- [ ] Rule execution order preserved from Cloudflare configuration
- [ ] No optional chaining (`?.`) or destructuring used
