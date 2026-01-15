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
| `http.referer` | `request.headers.referer?.value` | Referrer header |
| `http.user_agent` | `request.headers['user-agent']?.value` | User-Agent header |
| `http.x_forwarded_for` | `request.headers['x-forwarded-for']?.value` | X-Forwarded-For header |
| `http.cookie` | `request.cookies` | Cookie object |

### Example: Accessing Headers

```javascript
async function handler(event) {
    const request = event.request;
    
    const referer = request.headers.referer?.value;
    const userAgent = request.headers['user-agent']?.value;
    const xForwardedFor = request.headers['x-forwarded-for']?.value;
    
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
| Specific cookie | `request.cookies.cookieName?.value` | Access specific cookie |

### Example: Accessing Cookies

```javascript
async function handler(event) {
    const request = event.request;
    
    // Get specific cookie
    const sessionId = request.cookies.sessionId?.value;
    const authToken = request.cookies.auth?.value;
    
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
| `ip.src.country` | `request.headers['cloudfront-viewer-country']?.value` | ISO 3166-1 alpha-2 code |
| `ip.src.city` | `request.headers['cloudfront-viewer-city']?.value` | City name |
| `ip.src.lat` | `request.headers['cloudfront-viewer-latitude']?.value` | Latitude coordinate |
| `ip.src.lon` | `request.headers['cloudfront-viewer-longitude']?.value` | Longitude coordinate |
| `ip.src.subdivision_1_iso_code` | Combine country + region | See below |
| `ip.src.continent` | Derive from country code | See `continent-countries.md` |
| `ip.src.is_in_european_union` | Check against EU list | See below |

### Example: Accessing Geographic Data

```javascript
async function handler(event) {
    const request = event.request;
    
    const country = request.headers['cloudfront-viewer-country']?.value; // e.g., "US"
    const city = request.headers['cloudfront-viewer-city']?.value; // e.g., "Seattle"
    const lat = request.headers['cloudfront-viewer-latitude']?.value; // e.g., "47.60620"
    const lon = request.headers['cloudfront-viewer-longitude']?.value; // e.g., "-122.33210"
    
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
    
    const country = request.headers['cloudfront-viewer-country']?.value; // e.g., "CN"
    const region = request.headers['cloudfront-viewer-country-region']?.value; // e.g., "GD"
    
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

**Decision Guide**:
- Need 1-2 continents with <100 countries total? → Hardcode arrays
- Need 3+ continents or >100 countries? → Use KVS
- Performance critical? → Prefer hardcoding (no KVS latency)

**Option 1: Hardcode (Recommended for 1-2 continents)**
```javascript
async function handler(event) {
    const request = event.request;
    const country = request.headers['cloudfront-viewer-country']?.value;
    
    const continentMap = {
        'US': 'NA', 'CA': 'NA', 'MX': 'NA',
        'GB': 'EU', 'DE': 'EU', 'FR': 'EU',
        'CN': 'AS', 'JP': 'AS', 'IN': 'AS',
        'BR': 'SA', 'AR': 'SA', 'CL': 'SA',
        'AU': 'OC', 'NZ': 'OC'
    };
    
    const continent = continentMap[country];
    if (continent) {
        request.headers['x-continent'] = { value: continent };
    }
    
    return request;
}
```

**Option 2: Use KVS (For 3+ continents or >100 countries)**

If you need complete coverage (195+ countries) or many continents, use KVS:
```javascript
import cf from 'cloudfront';

const kvsHandle = cf.kvs();

async function handler(event) {
    const request = event.request;
    const country = request.headers['cloudfront-viewer-country']?.value;
    
    if (country) {
        try {
            const continent = await kvsHandle.get(`continent:${country}`);
            request.headers['x-continent'] = { value: continent };
        } catch (err) {
            console.log(`Country ${country} not in mapping`);
        }
    }
    
    return request;
}
```

### EU Country Check

Cloudflare's `ip.src.is_in_european_union` checks if country is in EU.

EU countries (27): `AT, BE, BG, CY, CZ, DE, DK, EE, ES, FI, FR, GR, HR, HU, IE, IT, LT, LU, LV, MT, NL, PL, PT, RO, SE, SI, SK`

**Decision**: ALWAYS hardcode (only 27 countries = ~162 bytes, static list, frequently checked)

**Option 1: Hardcode in function (Recommended)**
```javascript
async function handler(event) {
    const request = event.request;
    const country = request.headers['cloudfront-viewer-country']?.value;
    
    const euCountries = ['AT','BE','BG','CY','CZ','DE','DK','EE','ES','FI','FR','GR','HR','HU','IE','IT','LT','LU','LV','MT','NL','PL','PT','RO','SE','SI','SK'];
    
    if (euCountries.includes(country)) {
        request.headers['x-gdpr-required'] = { value: 'true' };
    }
    
    return request;
}
```

**Option 2: Use KVS (Only if function size constrained)**

If function size is approaching 10KB limit and you need to free up space:
```javascript
import cf from 'cloudfront';

const kvsHandle = cf.kvs();

async function handler(event) {
    const request = event.request;
    const country = request.headers['cloudfront-viewer-country']?.value;
    
    if (country) {
        try {
            await kvsHandle.get(`eu:${country}`); // If exists, it's EU
            request.headers['x-gdpr-required'] = { value: 'true' };
        } catch (err) {
            // Not EU country
        }
    }
    
    return request;
}
```

## Network Fields

| Cloudflare Field | CloudFront Equivalent | Notes |
|-----------------|----------------------|-------|
| `ip.src.asnum` | `request.headers['cloudfront-viewer-asn']?.value` | Autonomous System Number |

### Example: Accessing ASN

```javascript
async function handler(event) {
    const request = event.request;
    
    const asn = request.headers['cloudfront-viewer-asn']?.value; // e.g., "4134"
    
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
| `http.request.version` | `request.headers['cloudfront-viewer-http-version']?.value` | HTTP version (e.g., "2.0", "1.1") |

### Example: Accessing HTTP Version

```javascript
async function handler(event) {
    const request = event.request;
    
    const httpVersion = request.headers['cloudfront-viewer-http-version']?.value;
    
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
const id = request.querystring.id?.value;
const category = request.querystring.category?.value;

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
if (request.querystring.tag?.multiValue) {
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
const viewerAddress = request.headers['cloudfront-viewer-address']?.value;
// e.g., "203.0.113.42:54321"

// Extract IP only
const clientIp = event.viewer.ip; // Recommended

// Or parse from viewer-address
if (viewerAddress) {
    const [ip, port] = viewerAddress.split(':');
    console.log(`IP: ${ip}, Port: ${port}`);
}
```

### Header Name Case Sensitivity

All header names in CloudFront Functions event object are **lowercase**.

```javascript
// ✅ CORRECT
const country = request.headers['cloudfront-viewer-country']?.value;

// ❌ WRONG
const country = request.headers['CloudFront-Viewer-Country']?.value;
```

### Optional Chaining

Always use optional chaining (`?.`) when accessing headers that might not exist.

```javascript
// ✅ CORRECT - Won't throw error if header missing
const country = request.headers['cloudfront-viewer-country']?.value;

// ❌ WRONG - Will throw error if header missing
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
    const country = request.headers['cloudfront-viewer-country']?.value;
    const city = request.headers['cloudfront-viewer-city']?.value;
    
    // Network
    const asn = request.headers['cloudfront-viewer-asn']?.value;
    
    // Headers
    const userAgent = request.headers['user-agent']?.value;
    const referer = request.headers.referer?.value;
    
    // Cookies
    const sessionId = request.cookies.sessionId?.value;
    
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
