# Cloudflare to CloudFront Field Mapping

This document provides detailed mappings between Cloudflare rule fields and CloudFront Functions equivalents.

## Request URI Fields

| Cloudflare Field | CloudFront Equivalent | Notes |
|-----------------|----------------------|-------|
| `http.request.uri` | `request.uri` + query string | Full URI including query |
| `http.request.uri.path` | `request.uri` | Path only, no query string |
| `http.request.uri.query` | `request.rawQueryString()` | Query string without leading `?` |
| `http.request.full_uri` | Construct from components | `https://${host}${uri}${qs}` |
| `raw.http.request.uri` | Same as above | Ignore normalization differences |
| `raw.http.request.uri.path` | `request.uri` | Ignore normalization differences |
| `raw.http.request.uri.query` | `request.rawQueryString()` | Ignore normalization differences |

### Example: Accessing URI Components

```javascript
async function handler(event) {
    const request = event.request;
    
    // Path only
    const path = request.uri; // e.g., "/products/item"
    
    // Query string
    const qs = request.rawQueryString(); // e.g., "id=123&color=red"
    
    // Full URI
    const host = request.headers.host.value;
    const fullUri = qs ? `https://${host}${path}?${qs}` : `https://${host}${path}`;
    
    return request;
}
```

## Host and Method

| Cloudflare Field | CloudFront Equivalent | Notes |
|-----------------|----------------------|-------|
| `http.host` | `request.headers.host.value` | Hostname from Host header |
| `http.request.method` | `request.method` | GET, POST, PUT, DELETE, etc. |

### Example: Accessing Host and Method

```javascript
async function handler(event) {
    const request = event.request;
    
    const host = request.headers.host.value; // e.g., "example.com"
    const method = request.method; // e.g., "GET"
    
    if (method === 'POST' && host === 'api.example.com') {
        // Handle API POST request
    }
    
    return request;
}
```

## HTTP Headers

| Cloudflare Field | CloudFront Equivalent | Notes |
|-----------------|----------------------|-------|
| `http.referer` | `request.headers.referer` | Referrer header (check existence first) |
| `http.user_agent` | `request.headers['user-agent']` | User-Agent header (check existence first) |
| `http.x_forwarded_for` | `request.headers['x-forwarded-for']` | X-Forwarded-For header (check existence first) |
| `http.cookie` | `request.cookies` | Cookie object |

### Example: Accessing Headers

```javascript
async function handler(event) {
    const request = event.request;
    
    const referer = request.headers.referer ? request.headers.referer.value : undefined;
    const userAgent = request.headers['user-agent'] ? request.headers['user-agent'].value : undefined;
    const xForwardedFor = request.headers['x-forwarded-for'] ? request.headers['x-forwarded-for'].value : undefined;
    
    // Check if header exists before using
    if (referer && referer.includes('google.com')) {
        request.headers['x-traffic-source'] = { value: 'google' };
    }
    
    return request;
}
```

## Cookies

| Cloudflare Field | CloudFront Equivalent | Notes |
|-----------------|----------------------|-------|
| `http.cookie` | `request.cookies` | Access all cookies |
| Specific cookie | `request.cookies.cookieName` | Access specific cookie (check existence first) |

### Example: Accessing Cookies

```javascript
async function handler(event) {
    const request = event.request;
    
    // Get specific cookie
    const sessionId = request.cookies.sessionId ? request.cookies.sessionId.value : undefined;
    const authToken = request.cookies.auth ? request.cookies.auth.value : undefined;
    
    // Check if cookie exists
    if (request.cookies.premium) {
        request.headers['x-user-tier'] = { value: 'premium' };
    }
    
    return request;
}
```

## IP Address

| Cloudflare Field | CloudFront Equivalent | Notes |
|-----------------|----------------------|-------|
| `ip.src` | `event.viewer.ip` | Client IP address (IPv4 or IPv6) |

### Example: Accessing Client IP

```javascript
async function handler(event) {
    const request = event.request;
    
    const clientIp = event.viewer.ip; // e.g., "203.0.113.42"
    
    // Add to custom header
    request.headers['x-client-ip'] = { value: clientIp };
    
    return request;
}
```

## Geographic Fields

All geographic fields require CloudFront viewer headers to be configured in Origin Request Policy.

| Cloudflare Field | CloudFront Equivalent | Notes |
|-----------------|----------------------|-------|
| `ip.src.country` | `request.headers['cloudfront-viewer-country']` | ISO 3166-1 alpha-2 code (check existence first) |
| `ip.src.city` | `request.headers['cloudfront-viewer-city']` | City name (check existence first) |
| `ip.src.lat` | `request.headers['cloudfront-viewer-latitude']` | Latitude coordinate (check existence first) |
| `ip.src.lon` | `request.headers['cloudfront-viewer-longitude']` | Longitude coordinate (check existence first) |
| `ip.src.subdivision_1_iso_code` | Combine country + region | See below |
| `ip.src.continent` | Derive from country code | See `continent-countries.md` |
| `ip.src.is_in_european_union` | Check against EU list | See below |

### Example: Accessing Geographic Data

```javascript
async function handler(event) {
    const request = event.request;
    
    const country = request.headers['cloudfront-viewer-country'] ? request.headers['cloudfront-viewer-country'].value : undefined;
    const city = request.headers['cloudfront-viewer-city'] ? request.headers['cloudfront-viewer-city'].value : undefined;
    const lat = request.headers['cloudfront-viewer-latitude'] ? request.headers['cloudfront-viewer-latitude'].value : undefined;
    const lon = request.headers['cloudfront-viewer-longitude'] ? request.headers['cloudfront-viewer-longitude'].value : undefined;
    
    if (country === 'US') {
        request.headers['x-region'] = { value: 'north-america' };
    }
    
    return request;
}
```

### Subdivision ISO Code

Cloudflare's `ip.src.subdivision_1_iso_code` combines country and region with a hyphen.

```javascript
async function handler(event) {
    const request = event.request;
    
    const country = request.headers['cloudfront-viewer-country'] ? request.headers['cloudfront-viewer-country'].value : undefined; // e.g., "CN"
    const region = request.headers['cloudfront-viewer-country-region'] ? request.headers['cloudfront-viewer-country-region'].value : undefined; // e.g., "GD"
    
    if (country && region) {
        const subdivisionCode = `${country}-${region}`; // e.g., "CN-GD"
        
        // Use subdivision code for matching
        if (subdivisionCode === 'CN-GD') {
            // Guangdong, China
        }
    }
    
    return request;
}
```

### Continent Mapping

Cloudflare's `ip.src.continent` must be derived from country code.

**CRITICAL**: Continent codes (AS, EU, AF, etc.) are NOT country codes. You must map country → continent.

**Strategy: Always use KVS**

Store country-to-continent mapping in KVS with prefix `continent:`. This keeps function size small and makes updates easier.

**KVS entries format:**
```json
{
  "data": [
    {"key": "continent:US", "value": "NA"},
    {"key": "continent:CN", "value": "AS"},
    {"key": "continent:GB", "value": "EU"}
  ]
}
```

See `continent-countries.md` for complete list of all 239 country-to-continent mappings.

**CloudFront Function:**
```javascript
import cf from 'cloudfront';

const kvsHandle = cf.kvs();

async function handler(event) {
    const request = event.request;
    const uri = request.uri;
    const country = request.headers['cloudfront-viewer-country'] ? request.headers['cloudfront-viewer-country'].value : undefined;
    
    if (country) {
        try {
            const continent = await kvsHandle.get(`continent:${country}`);
            // Example: Redirect Asia users to Asia-specific page
            if (continent === 'AS' && uri === '/welcome') {
                return {
                    statusCode: 302,
                    headers: {
                        'location': { value: '/asia/welcome' }
                    }
                };
            }
        } catch (err) {
            // Country not in mapping, continue with default behavior
        }
    }
    
    return request;
}
```

**Why always use KVS:**
- Reduces function size significantly
- Easier to update country mappings without redeploying function
- Complete coverage of all 195+ countries available

### EU Country Check

Cloudflare's `ip.src.is_in_european_union` checks if country is in EU.

EU countries (27): `AT, BE, BG, CY, CZ, DE, DK, EE, ES, FI, FR, GR, HR, HU, IE, IT, LT, LU, LV, MT, NL, PL, PT, RO, SE, SI, SK`

**Strategy: Always use KVS**

Store EU country flags in KVS with prefix `eu:`. This keeps function size small.

**KVS entries format:**
```json
{
  "data": [
    {"key": "eu:AT", "value": "1"},
    {"key": "eu:BE", "value": "1"},
    {"key": "eu:BG", "value": "1"}
  ]
}
```

**CloudFront Function:**
```javascript
import cf from 'cloudfront';

const kvsHandle = cf.kvs();

async function handler(event) {
    const request = event.request;
    const uri = request.uri;
    const country = request.headers['cloudfront-viewer-country'] ? request.headers['cloudfront-viewer-country'].value : undefined;
    
    let isEU = false;
    if (country) {
        try {
            await kvsHandle.get(`eu:${country}`);
            isEU = true;
        } catch (err) {
            // Not EU country, isEU remains false
        }
    }
    
    // Example: Redirect EU users to EU-specific page
    if (isEU && uri === '/welcome') {
        return {
            statusCode: 302,
            headers: {
                'location': { value: '/eu/welcome' }
            }
        };
    }
    
    // Example: Redirect non-EU users to global page
    if (!isEU && uri === '/welcome') {
        return {
            statusCode: 302,
            headers: {
                'location': { value: '/global/welcome' }
            }
        };
    }
    
    return request;
}
```

**Why always use KVS:**
- Reduces function size (saves ~162 bytes)
- Consistent approach with continent mapping
- Easier to update if EU membership changes

## Network Fields

| Cloudflare Field | CloudFront Equivalent | Notes |
|-----------------|----------------------|-------|
| `ip.src.asnum` | `request.headers['cloudfront-viewer-asn']` | Autonomous System Number (check existence first) |

### Example: Accessing ASN

```javascript
async function handler(event) {
    const request = event.request;
    
    const asn = request.headers['cloudfront-viewer-asn'] ? request.headers['cloudfront-viewer-asn'].value : undefined; // e.g., "4134"
    
    // Block specific ASN
    if (asn === '12345') {
        return {
            statusCode: 403,
            statusDescription: 'Forbidden',
            headers: {
                'content-type': { value: 'text/plain' }
            }
        };
    }
    
    return request;
}
```

## Protocol Fields

| Cloudflare Field | CloudFront Equivalent | Notes |
|-----------------|----------------------|-------|
| `http.request.version` | `request.headers['cloudfront-viewer-http-version']` | HTTP version (check existence first) |

### Example: Accessing HTTP Version

```javascript
async function handler(event) {
    const request = event.request;
    
    const httpVersion = request.headers['cloudfront-viewer-http-version'] ? request.headers['cloudfront-viewer-http-version'].value : undefined;
    
    if (httpVersion === '2.0') {
        request.headers['x-http2-enabled'] = { value: 'true' };
    }
    
    return request;
}
```

## Device Detection

CloudFront provides native device detection headers. Do NOT convert Cloudflare header transformation rules that add device detection headers. Instead, use CloudFront Origin Request Policy.

| Cloudflare Logic | CloudFront Header | Configure In |
|-----------------|-------------------|--------------|
| Add `X-Is-Mobile` based on UA | `CloudFront-Is-Mobile-Viewer` | Origin Request Policy |
| Add `X-Is-Desktop` based on UA | `CloudFront-Is-Desktop-Viewer` | Origin Request Policy |
| Add `X-Is-Tablet` based on UA | `CloudFront-Is-Tablet-Viewer` | Origin Request Policy |
| Add `X-Is-SmartTV` based on UA | `CloudFront-Is-SmartTV-Viewer` | Origin Request Policy |

## Query String Handling

### Method 1: Raw Query String (Recommended for Simple Cases)

Use `rawQueryString()` when you need the complete query string without modification.

```javascript
const qs = request.rawQueryString();

// Returns:
// - "param1=value1&param2=value2" if query string exists
// - "" if URL has ? but no parameters
// - undefined if no query string

// Example: Preserve query string in redirect
const newLocation = qs ? `https://example.com${uri}?${qs}` : `https://example.com${uri}`;
```

**Advantages**:
- Simple and fast
- Preserves original encoding
- No parsing overhead

**Limitations**:
- Cannot modify individual parameters
- Cannot handle multiValue parameters separately

### Method 2: Parsed Query Parameters (Required for Modifications)

Use `request.querystring` when you need to access or modify individual parameters.

```javascript
// Access parsed query parameters
const id = request.querystring.id ? request.querystring.id.value : undefined;
const category = request.querystring.category ? request.querystring.category.value : undefined;

// Check if parameter exists
if (request.querystring.debug) {
    const debugValue = request.querystring.debug.value;
}
```

**Advantages**:
- Can modify individual parameters
- Can handle multiValue parameters
- Can add/remove parameters

**Limitations**:
- Requires manual reconstruction for redirects
- More complex code

### Handling MultiValue Parameters

Some query parameters can have multiple values (e.g., `?tag=value1&tag=value2&tag=value3`).

```javascript
// Check if parameter has multiple values
if (request.querystring.tag && request.querystring.tag.multiValue) {
    // Access all values
    const values = request.querystring.tag.multiValue.map(v => v.value);
    // e.g., ["value1", "value2", "value3"]
} else if (request.querystring.tag) {
    // Single value
    const value = request.querystring.tag.value;
}
```

### Reconstructing Query String from Parsed Parameters

When you need to preserve query string in redirects after accessing parsed parameters:

```javascript
function reconstructQueryString(querystring) {
    const qs = [];
    for (const key in querystring) {
        if (querystring[key].multiValue) {
            // Handle multiple values for same parameter
            for (let i = 0; i < querystring[key].multiValue.length; i++) {
                qs.push(key + "=" + querystring[key].multiValue[i].value);
            }
        } else {
            // Handle single value
            qs.push(key + "=" + querystring[key].value);
        }
    }
    return qs.length > 0 ? '?' + qs.join('&') : '';
}

// Usage in redirect
const queryString = reconstructQueryString(request.querystring);
return {
    statusCode: 301,
    statusDescription: 'Moved Permanently',
    headers: {
        location: { value: 'https://example.com' + uri + queryString }
    }
};
```

### Complete Example: Redirect with Query String Preservation

```javascript
function redirect(location, statusCode, statusDescription) {
    return {
        statusCode: statusCode || 301,
        statusDescription: statusDescription || 'Moved Permanently',
        headers: { location: { value: location } }
    };
}

async function handler(event) {
    const request = event.request;
    const host = request.headers.host.value;
    const uri = request.uri;
    
    // Simple redirect without query string
    if (host === 'old.example.com') {
        return redirect('https://new.example.com/');
    }
    
    // Redirect preserving query string (Method 1: rawQueryString)
    if (host === 'simple.example.com') {
        const qs = request.rawQueryString();
        const queryString = qs ? '?' + qs : '';
        return redirect('https://www.example.com' + uri + queryString);
    }
    
    // Redirect preserving query string (Method 2: parsed querystring)
    // Use this when you need to handle multiValue parameters
    if (host === 'complex.example.com') {
        const qs = [];
        for (const key in request.querystring) {
            if (request.querystring[key].multiValue) {
                for (let i = 0; i < request.querystring[key].multiValue.length; i++) {
                    qs.push(key + "=" + request.querystring[key].multiValue[i].value);
                }
            } else {
                qs.push(key + "=" + request.querystring[key].value);
            }
        }
        const queryString = qs.length > 0 ? '?' + qs.join('&') : '';
        return redirect('https://www.example.com' + uri + queryString);
    }
    
    return request;
}
```

### Modify Query String

```javascript
// Add query parameter
request.querystring.newParam = { value: 'newValue' };

// Modify existing parameter
if (request.querystring.id) {
    request.querystring.id.value = 'modified-id';
}

// Remove query parameter
delete request.querystring.unwantedParam;

// After modifications, reconstruct query string for redirect
const queryString = reconstructQueryString(request.querystring);
```

### Decision Guide: Which Method to Use?

| Scenario | Recommended Method | Reason |
|----------|-------------------|--------|
| Simple redirect preserving query string | `rawQueryString()` | Faster, simpler |
| Need to check specific parameter value | `request.querystring` | Can access individual params |
| Need to modify parameters | `request.querystring` | Can modify before redirect |
| MultiValue parameters exist | `request.querystring` | Must handle multiValue array |
| Add/remove parameters | `request.querystring` | Can manipulate params |
| Just pass through unchanged | `rawQueryString()` | Most efficient |

## Special Considerations

### CloudFront-Viewer-Address Format

The `cloudfront-viewer-address` header includes both IP and port: `ip:port`

```javascript
const viewerAddress = request.headers['cloudfront-viewer-address'] ? request.headers['cloudfront-viewer-address'].value : undefined;
// e.g., "203.0.113.42:54321"

// Extract IP only
const clientIp = event.viewer.ip; // Recommended

// Or parse from viewer-address
if (viewerAddress) {
    const parts = viewerAddress.split(':');
    const ip = parts[0];
    const port = parts[1];
    // Use ip and port as needed
}
```

### Header Name Case Sensitivity

All header names in CloudFront Functions event object are **lowercase**.

```javascript
// ✅ CORRECT
const country = request.headers['cloudfront-viewer-country'] ? request.headers['cloudfront-viewer-country'].value : undefined;

// ❌ WRONG - Wrong case (header names must be lowercase)
const country = request.headers['CloudFront-Viewer-Country'] ? request.headers['CloudFront-Viewer-Country'].value : undefined;
```

### Checking Header Existence

Always check if a header exists before accessing its value to avoid runtime errors.

```javascript
// ✅ CORRECT - Safe access with conditional check
const country = request.headers['cloudfront-viewer-country'] 
    ? request.headers['cloudfront-viewer-country'].value 
    : undefined;

// ❌ WRONG - Will throw TypeError if header missing
const country = request.headers['cloudfront-viewer-country'].value;
```

## Complete Example: Multiple Field Access

```javascript
import cf from 'cloudfront';

const kvsHandle = cf.kvs();

async function handler(event) {
    const request = event.request;
    
    // URI components
    const uri = request.uri;
    const qs = request.rawQueryString();
    const host = request.headers.host.value;
    
    // Client info
    const clientIp = event.viewer.ip;
    const method = request.method;
    
    // Geographic
    const country = request.headers['cloudfront-viewer-country'] ? request.headers['cloudfront-viewer-country'].value : undefined;
    const city = request.headers['cloudfront-viewer-city'] ? request.headers['cloudfront-viewer-city'].value : undefined;
    
    // Network
    const asn = request.headers['cloudfront-viewer-asn'] ? request.headers['cloudfront-viewer-asn'].value : undefined;
    
    // Headers
    const userAgent = request.headers['user-agent'] ? request.headers['user-agent'].value : undefined;
    const referer = request.headers.referer ? request.headers.referer.value : undefined;
    
    // Cookies
    const sessionId = request.cookies.sessionId ? request.cookies.sessionId.value : undefined;
    
    // Example: Redirect based on country
    if (country === 'CN') {
        return {
            statusCode: 302,
            statusDescription: 'Found',
            headers: {
                'location': { value: 'https://cn.example.com' + uri }
            }
        };
    }
    
    // Example: Add custom headers
    request.headers['x-client-country'] = { value: country || 'unknown' };
    request.headers['x-client-ip'] = { value: clientIp };
    
    return request;
}
```
