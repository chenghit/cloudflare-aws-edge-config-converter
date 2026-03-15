# CloudFront Functions Runtime 2.0 — Complete Reference

This document covers all Runtime 2.0 features needed for CDN migration code generation.
Use this as the authoritative reference for generating CloudFront Function JavaScript.

---

## Handler Signature

```javascript
// Synchronous (no KVS or async operations needed)
function handler(event) {
    const request = event.request;
    return request;
}

// Async (required when using await — KVS, etc.)
async function handler(event) {
    const request = event.request;
    return request;
}
```

`async` is only required when using `await`. Both forms are valid in Runtime 2.0.

---

## Import Statement

Required only when using `cf.*` APIs (KVS, edgeLocation, updateRequestOrigin):

```javascript
import cf from 'cloudfront';
```

Must be the **first line** of the file if present. Not needed for header-only operations or `rawQueryString()`.

---

## rawQueryString() Method

Does **not** require `import cf`. Called directly on `request`.

```javascript
function handler(event) {
    const request = event.request;
    const qs = request.rawQueryString();
    // Returns: "name=John&age=25"  (no leading '?')
    // Returns: ""                  (URL has '?' but no params — falsy, safe to skip)
    // Returns: undefined           (URL has no '?' at all — falsy, safe to skip)

    // Safe usage in redirects — both "" and undefined are falsy,
    // so neither case appends a trailing '?' to the target URL:
    const queryPart = qs ? '?' + qs : '';
    return {
        statusCode: 301,
        headers: { location: { value: '/new-path' + queryPart } }
    };
}
```

---

## cf.kvs() — Key Value Store

```javascript
import cf from 'cloudfront';

const kvsHandle = cf.kvs();  // Initialize outside handler for reuse

async function handler(event) {
    const request = event.request;

    // get() — returns string by default; throws if key not found
    try {
        const value = await kvsHandle.get('myKey');
        // With format option:
        const jsonValue = await kvsHandle.get('myKey', { format: 'json' });
    } catch (e) {
        // Key not found — handle gracefully
    }

    // exists() — returns boolean, never throws
    const found = await kvsHandle.exists('myKey');

    return request;
}
```

**Critical**: Use sequential `await`, NOT `Promise.all()` for KVS calls:

```javascript
// CORRECT — sequential
const val1 = await kvsHandle.get('key1');
const val2 = await kvsHandle.get('key2');

// WRONG — exceeds memory limits
const [val1, val2] = await Promise.all([kvsHandle.get('key1'), kvsHandle.get('key2')]);
```

---

## cf.updateRequestOrigin() — Dynamic Origin Routing

**Viewer-request only.** Correct signature: `cf.updateRequestOrigin({...})` — no `request` argument.

### Custom origin (ALB, API Gateway, custom server)

```javascript
import cf from 'cloudfront';

function handler(event) {
    cf.updateRequestOrigin({
        domainName: 'example-1234567890.us-east-1.elb.amazonaws.com',
        timeouts: {
            readTimeout: 30,
            connectionTimeout: 5
        },
        customHeaders: {
            'x-stage': 'production',
            'x-region': 'us-east-1'
        }
    });
    return event.request;
}
```

### Custom origin with port/protocol override

```javascript
cf.updateRequestOrigin({
    domainName: 'api-backend.example.com',
    originPath: '/v2',
    customOriginConfig: {
        port: 443,
        protocol: 'https',
        sslProtocols: ['TLSv1.2']
    }
});
```

`customOriginConfig` fields: `port` (required), `protocol` (required: `"http"` | `"https"`),
`sslProtocols` (required: array of `"SSLv3"` | `"TLSv1"` | `"TLSv1.1"` | `"TLSv1.2"`),
`ipAddressType` (optional: `"ipv4"` | `"ipv6"` | `"dualstack"`).

### Top-level properties reference

| Property | Type | Notes |
|----------|------|-------|
| `domainName` | string | DNS name (not IP). Up to 253 chars |
| `hostHeader` | string | Override Host header to origin (non-S3 only) |
| `originPath` | string | Must start with `/`, must NOT end with `/` |
| `customHeaders` | object | `{"key": "value"}` format (NOT `{value: "..."}`) |
| `connectionAttempts` | number | 1–3 |
| `originShield` | object | `{enabled, region}` |
| `originAccessControlConfig` | object | S3 OAC: `{enabled, signingBehavior, signingProtocol, originType}` |
| `timeouts` | object | `{readTimeout, connectionTimeout, keepAliveTimeout, responseCompletionTimeout}` |
| `customOriginConfig` | object | Non-S3: `{port, protocol, sslProtocols, ipAddressType}` |
| `sni` | string | TLS SNI hostname (non-S3 only) |
| `allowedCertificateNames` | array | Valid cert names for TLS validation (up to 20) |

Unspecified properties inherit from the existing origin config.

### S3 origin with OAC

```javascript
import cf from 'cloudfront';

function handler(event) {
    const request = event.request;
    const country = (request.headers['cloudfront-viewer-country'] || {value: ''}).value;
    const regionMap = { 'DE': 'eu-central-1', 'JP': 'ap-northeast-1' };
    const region = regionMap[country] || 'us-east-1';

    cf.updateRequestOrigin({
        domainName: 'my-bucket.s3.' + region + '.amazonaws.com',
        originAccessControlConfig: {
            enabled: true,
            region: region,
            signingBehavior: 'always',   // 'always' | 'never' | 'no-override'
            signingProtocol: 'sigv4',
            originType: 's3'             // 's3' | 'mediapackagev2' | 'mediastore' | 'lambda'
        }
    });
    return request;
}
```

### Select existing origin by ID

```javascript
import cf from 'cloudfront';

function handler(event) {
    // Select an origin already defined in the distribution config by its origin ID
    cf.selectRequestOriginById('my-api-origin-id');

    // With optional overrides (hostHeader, sni, allowedCertificateNames):
    // cf.selectRequestOriginById('my-api-origin-id', { hostHeader: 'test.example.com' });

    return event.request;
}
```

---

## cf.edgeLocation — Edge Metadata

**Viewer-request only** (empty for viewer-response).

```javascript
import cf from 'cloudfront';

function handler(event) {
    const name   = cf.edgeLocation.name;      // IATA code, e.g. "SEA"
    const ip     = cf.edgeLocation.serverIp;  // IPv4 or IPv6
    const region = cf.edgeLocation.region;    // REC region, e.g. "us-west-2"
    return event.request;
}
```

---

## Supported JavaScript Syntax

**Allowed in Runtime 2.0:**
- `const`, `let`
- `async` / `await`
- `import` (ES module syntax)
- Template literals: `` `Hello ${name}` ``
- Arrow functions: `(x) => x + 1`
- `for...of` loops
- `try...catch`
- `Promise.all()`, `Promise.allSettled()`, `Promise.any()`, `Promise.race()`
- `Promise.prototype.then()`, `Promise.prototype.catch()`, `Promise.prototype.finally()`
- `Buffer`, `TextEncoder`, `TextDecoder`
- `atob()`, `btoa()`
- `String.prototype.replaceAll()`

**⚠️ MEMORY WARNING for Promise combinators and chain methods:**
AWS documentation explicitly warns: "Using promise combinators (for example, Promise.all,
Promise.any) and promise chain methods (for example, then and catch) can require high
function memory usage. If your function exceeds the maximum function memory quota, it
will fail to execute." AWS recommends using sequential `await` instead.

**For this pipeline: ALWAYS use sequential `await` instead of Promise combinators.**
While `Promise.all()` and `.then()/.catch()` are technically valid syntax, they risk
exceeding memory limits in functions that perform multiple KVS lookups. The js-validator
will flag `Promise.all` usage as a warning (not an error) since it is syntactically
valid but operationally risky.

**FORBIDDEN in Runtime 2.0 (will cause runtime error):**
- Optional chaining: `obj?.prop` ❌
- Array destructuring: `const [a, b] = arr` ❌
- Object destructuring: `const { x } = obj` ❌
- `eval()` or `Function()` constructor ❌
- `setTimeout`, `setImmediate` ❌
- Network calls (XHR, fetch, HTTP) ❌
- File system access ❌
- `require()` (use `import` instead) ❌

**DISCOURAGED (syntactically valid but operationally risky — avoid in this pipeline):**
- `Promise.all()`, `Promise.any()`, `Promise.race()` — risk exceeding memory quota
- `.then()`, `.catch()` chains — risk exceeding memory quota; use `await` instead

**Use these patterns instead:**

```javascript
// Instead of optional chaining:
// BAD:  const country = request.headers['cloudfront-viewer-country']?.value;
// GOOD:
const countryHeader = request.headers['cloudfront-viewer-country'];
const country = countryHeader ? countryHeader.value : '';

// Instead of destructuring:
// BAD:  const { value } = request.headers.host;
// GOOD:
const value = request.headers.host.value;

// Instead of array destructuring:
// BAD:  const [status, target] = parts;
// GOOD:
const status = parts[0];
const target = parts[1];
```

---

## Viewer-Response Restrictions

- **Does NOT execute** when origin returns HTTP 400+ (use Lambda@Edge origin-response instead)
- **Cannot read** the original response body (can only replace it entirely)
- **Cannot modify** query strings (read-only in viewer-response)
- `cf.edgeLocation` is empty
- Can modify response headers, status code, cookies

---

## Complete Bulk Redirect Example

KVS keys include the host: `redirect:{host}{uri}`. Subdomain wildcard keys use
a leading dot: `redirect:.{domain}{uri}`. `preserve_qs` is `1`/`0`, not `true`/`false`.

```javascript
import cf from 'cloudfront';

const kvsHandle = cf.kvs();

async function handler(event) {
    const request = event.request;
    const host = request.headers.host.value;
    const uri = request.uri;

    // Try exact host match
    let kvsValue = null;
    try {
        kvsValue = await kvsHandle.get('redirect:' + host + uri);
    } catch (e) {}

    // Try subdomain match if exact match failed
    if (kvsValue === null && host.includes('.')) {
        const dotHost = '.' + host;
        try {
            kvsValue = await kvsHandle.get('redirect:' + dotHost + uri);
        } catch (e) {}
    }

    if (kvsValue !== null) {
        const parts = kvsValue.split('|');
        const statusCode = parseInt(parts[0], 10);
        const preserveQS = parts[1] === '1';
        let target = parts[2];
        if (preserveQS) {
            const qs = request.rawQueryString();
            if (qs) {
                const sep = target.includes('?') ? '&' : '?';
                target = target + sep + qs;
            }
        }
        return {
            statusCode: statusCode,
            headers: { location: { value: target } }
        };
    }

    return request;
}
```
