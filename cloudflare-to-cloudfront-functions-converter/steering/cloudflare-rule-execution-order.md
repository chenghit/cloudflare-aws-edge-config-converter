# Cloudflare Rule Execution Order

This document describes the order in which Cloudflare processes rules for incoming HTTP requests. Understanding this order is critical when converting to CloudFront Functions to ensure the generated code logic follows the same sequence.

## Full Execution Flow

```
[HTTP Request]
↓
URL Normalization (Make incoming request URLs consistent)
↓
Redirect Rules (Redirect visitors to another page)
↓
URL Rewrites (Rewrite the URL path and query string)
↓
Page Rules (Apply legacy rules to your traffic) [NOT CONVERTED - see non-convertible-rules.md]
↓
Configuration Rules (Control Cloudflare features granularly)
↓
Origin Rules (Change the destination origin server)
↓
IP Access Rules (Allow or block by IP, country, or ASN)
↓
DDoS protection (Prevent distributed denial-of-service (DDoS))
↓
Web Application Firewall (Mitigate attack traffic)
↓
Bots (Mitigate bot traffic)
↓
Rate Limiting (Define rate limits for requests)
↓
Bulk Redirects (Define a large number of URL redirects at the account level)
↓
Modify Request Header (Transform HTTP headers)
↓
Cache Rules (Customize cache settings)
↓
Snippets (Modify your site with JavaScript code)
↓
Cloud Connector (Route traffic to public clouds)
↓
Workers (Build full-stack applications)
↓
Load Balancing (Distribute traffic between origins)
↓
[Origin server]
↓
Custom Error Rules (Customize origin or Cloudflare error responses)
↓
Modify Response Header (Transform HTTP response headers)
↓
Compression Rules (Compress responses)
↓
[End user]
```

## Convertible Rules in Execution Order

The following rules can be converted to CloudFront Functions and must follow this execution order:

1. **Redirect Rules** - Complex redirects with conditions
2. **URL Rewrites** - Rewrite URL path and query string
3. **Bulk Redirects** - Large number of URL redirects
4. **Request Header Transforms** - Add/modify request headers (including True-Client-IP)

**Note**: Page Rules are NOT converted by this skill (see non-convertible-rules.md for details).

**CRITICAL: Rule Priority vs Execution Order**

**Execution order**: Rules execute in the sequence shown in the full flow diagram above.

**Priority when conflicts exist**: If Page Rules and modern rules (Redirect Rules, URL Rewrites, Request Header Transforms) configure conflicting behavior for the same request, modern rules take precedence and override the conflicting parts of Page Rules.

**Note**: The Web Console "Traffic Sequence" visualization may show Page Rules earlier in the flow, but this does not reflect conflict resolution priority. Page Rules are not converted by this skill.

**When converting to CloudFront Functions**:
- Generate code in execution order (Redirect Rules → URL Rewrites → Bulk Redirects → Request Header Transforms)
- If Page Rules exist, they are not converted (see non-convertible-rules.md)

## Within-Project Rule Order

Within each rule type, rules must be processed in the order they appear in the summary document (Rule 1, Rule 2, Rule 3...).

**This order comes from the `rules` array in Cloudflare's JSON configuration**, where array index 0 is Rule 1, index 1 is Rule 2, etc.

**When generating CloudFront Functions from the summary:**
- Process rules in numerical order (Rule 1 first, then Rule 2, then Rule 3...)
- First matching rule wins (early return for redirects)
- Preserve exact order to maintain behavior parity with Cloudflare

**Example code structure:**
```javascript
// Rule 1: Most specific
if (uri === '/special-case') {
    return { statusCode: 301, headers: { location: { value: '/target-1' } } };
}

// Rule 2: Medium specificity
if (uri.startsWith('/special-')) {
    return { statusCode: 301, headers: { location: { value: '/target-2' } } };
}

// Rule 3: Catch-all
return { statusCode: 301, headers: { location: { value: '/target-3' } } };
```

## Code Structure Template

When generating CloudFront Functions, organize code logic in this order:

```javascript
import cf from 'cloudfront';

async function handler(event) {
    const request = event.request;
    const uri = request.uri;
    const host = request.headers.host.value;
    
    // 1. Redirect Rules (if any)
    // Execute first - highest priority redirects
    // Check conditions and return redirect response if matched
    
    // 2. URL Rewrites (if any)
    // Modify request.uri based on rewrite rules
    // This affects subsequent bulk redirect matching
    
    // 3. Bulk Redirects (if any)
    // Check KVS for bulk redirect matches
    // Use the potentially rewritten URI from step 2
    
    // 4. Request Header Transforms (if any)
    // Add/modify/remove request headers
    // - True-Client-IP: Add header from event.viewer.ip
    // - Custom headers: Add based on conditions
    // - Replace "Cloudflare" with "CloudFront" in header values
    
    return request;
}
```

## Critical Ordering Rules

### Rule 1: Redirect Rules Before Bulk Redirects

If both exist, Redirect Rules execute first:

```javascript
// ✅ CORRECT ORDER
// Check Redirect Rules first
if (uri === '/special-case' && country === 'US') {
    return {
        statusCode: 302,
        headers: { location: { value: 'https://us.example.com' } }
    };
}

// Then check Bulk Redirects
const redirectKey = 'redirect:' + host + uri;
const redirectData = await kvs.get(redirectKey);
if (redirectData) {
    // Process bulk redirect
}
```

### Rule 2: URL Rewrites Before Bulk Redirects

Rewritten URLs should be checked against bulk redirect patterns:

```javascript
// ✅ CORRECT ORDER
// Apply URL Rewrite first
if (uri.startsWith('/old-path/')) {
    request.uri = uri.replace('/old-path/', '/new-path/');
}

// Then check Bulk Redirects with the rewritten URI
const redirectKey = 'redirect:' + host + request.uri;
const redirectData = await kvs.get(redirectKey);
```

### Rule 3: Header Transforms Last

Request header modifications happen after all redirect decisions:

```javascript
// ✅ CORRECT ORDER
// All redirect logic first
if (shouldRedirect) {
    return redirectResponse;
}

// Then modify headers
request.headers['true-client-ip'] = { value: event.viewer.ip };
request.headers['x-from-cdn'] = { value: 'CloudFront' };

return request;
```

## Common Mistakes to Avoid

### ❌ Wrong: Header Transforms Before Redirects

```javascript
// ❌ WRONG - Wasting CPU on headers that won't be used
request.headers['true-client-ip'] = { value: event.viewer.ip };

if (shouldRedirect) {
    return redirectResponse; // Headers are discarded
}
```

### ❌ Wrong: Bulk Redirects Before URL Rewrites

```javascript
// ❌ WRONG - Checking original URI instead of rewritten URI
const redirectData = await kvs.get('redirect:' + host + uri);

// URL rewrite happens too late
if (uri.startsWith('/old-path/')) {
    request.uri = uri.replace('/old-path/', '/new-path/');
}
```

## Performance Optimization

Follow execution order while optimizing for performance:

1. **Early returns**: Return redirect responses as soon as matched
2. **Avoid redundant checks**: Don't check bulk redirects if already redirected
3. **Sequential logic**: Process rules in order, skip remaining if matched

```javascript
// ✅ OPTIMIZED
// Check Redirect Rules (early return if matched)
if (redirectRuleMatched) {
    return redirectResponse;
}

// Check URL Rewrites (modify URI)
if (rewriteRuleMatched) {
    request.uri = newUri;
}

// Check Bulk Redirects (early return if matched)
const redirectData = await kvs.get(redirectKey);
if (redirectData) {
    return redirectResponse;
}

// Only modify headers if no redirect occurred
request.headers['true-client-ip'] = { value: event.viewer.ip };

return request;
```
