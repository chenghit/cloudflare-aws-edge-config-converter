# CloudFront Functions Helper Methods (Runtime 2.0)

CloudFront Functions JavaScript Runtime 2.0 provides additional helper methods. To use these methods, import the `cloudfront` module:

```javascript
import cf from 'cloudfront';
```

## 1. Edge Location Metadata

**Availability**: Viewer Request functions only (empty for Viewer Response)

Access metadata about the edge location processing the request:

```javascript
cf.edgeLocation = {
    name: "SEA",              // Three-letter IATA airport code
    serverIp: "1.2.3.4",      // IPv4 or IPv6 address of the server
    region: "us-west-2"       // Expected Regional Edge Cache (REC) region
}
```

### Properties

- **`name`**: Three-letter IATA airport code of the edge location (e.g., `SEA`, `NRT`, `LHR`)
- **`serverIp`**: IPv4 or IPv6 address of the CloudFront server processing the request
- **`region`**: AWS region of the Regional Edge Cache (REC) that will be used on cache miss

### Example Usage

```javascript
import cf from 'cloudfront';

async function handler(event) {
    const request = event.request;
    
    // Add edge location info to custom header
    request.headers['x-edge-location'] = { 
        value: cf.edgeLocation.name 
    };
    
    // Log edge location details
    console.log(`Edge: ${cf.edgeLocation.name}, IP: ${cf.edgeLocation.serverIp}, REC: ${cf.edgeLocation.region}`);
    
    return request;
}
```

### Important Notes

- **Origin Failover**: CloudFront Functions are NOT triggered a second time during origin failover
- **Viewer Response**: This object is empty for viewer-response functions

## 2. Query String Methods

**Availability**: Both viewer-request and viewer-response functions

CloudFront Functions provide two ways to handle query strings:

### Method A: `rawQueryString()` - Simple and Fast

Get the unparsed, unmodified query string from the request URL.

```javascript
const queryString = request.rawQueryString();
```

**Return Values**:
- **String**: Full query string (without leading `?`) if parameters exist
- **Empty string `""`**: If URL contains `?` but no parameters
- **`undefined`**: If URL has no query string and no `?`

**Use when**:
- Simple pass-through (preserve query string in redirects)
- No need to modify individual parameters
- Performance critical

**Examples**:

```javascript
// Case 1: Full query string
// URL: https://example.com/page?name=John&age=25
const qs = request.rawQueryString();
// Returns: "name=John&age=25"

// Case 2: Empty query string
// URL: https://example.com/page?
const qs = request.rawQueryString();
// Returns: ""

// Case 3: No query string
// URL: https://example.com/page
const qs = request.rawQueryString();
// Returns: undefined

// Redirect preserving query string
const qs = request.rawQueryString();
const queryString = qs ? '?' + qs : '';
return {
    statusCode: 301,
    statusDescription: 'Moved Permanently',
    headers: {
        location: { value: 'https://new.example.com' + request.uri + queryString }
    }
};
```

### Method B: `request.querystring` - For Modifications

Access parsed query parameters as an object. Required when handling multiValue parameters or modifying individual parameters.

```javascript
// Access individual parameters
const id = request.querystring.id ? request.querystring.id.value : undefined;
const category = request.querystring.category ? request.querystring.category.value : undefined;
```

**Use when**:
- Need to access/modify individual parameters
- Handling multiValue parameters (e.g., `?tag=val1&tag=val2`)
- Adding/removing parameters

**Handling MultiValue Parameters**:

```javascript
// Check for multiValue
if (request.querystring.tag && request.querystring.tag.multiValue) {
    // Multiple values: ?tag=val1&tag=val2&tag=val3
    for (let i = 0; i < request.querystring.tag.multiValue.length; i++) {
        const value = request.querystring.tag.multiValue[i].value;
    }
} else if (request.querystring.tag) {
    // Single value: ?tag=val1
    const value = request.querystring.tag.value;
}
```

**Reconstructing Query String**:

When you need to preserve query string after accessing parsed parameters:

```javascript
function reconstructQueryString(querystring) {
    const qs = [];
    for (const key in querystring) {
        if (querystring[key].multiValue) {
            for (let i = 0; i < querystring[key].multiValue.length; i++) {
                qs.push(key + "=" + querystring[key].multiValue[i].value);
            }
        } else {
            qs.push(key + "=" + querystring[key].value);
        }
    }
    return qs.length > 0 ? '?' + qs.join('&') : '';
}

// Usage
const queryString = reconstructQueryString(request.querystring);
return {
    statusCode: 301,
    headers: {
        location: { value: 'https://example.com' + request.uri + queryString }
    }
};
```

### Complete Example: Both Methods

```javascript
async function handler(event) {
    const request = event.request;
    const host = request.headers.host.value;
    const uri = request.uri;
    
    // Method A: Simple redirect with rawQueryString()
    if (host === 'simple.example.com') {
        const qs = request.rawQueryString();
        const queryString = qs ? '?' + qs : '';
        return {
            statusCode: 301,
            headers: {
                location: { value: 'https://www.example.com' + uri + queryString }
            }
        };
    }
    
    // Method B: Handle multiValue parameters
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
        return {
            statusCode: 301,
            headers: {
                location: { value: 'https://www.example.com' + uri + queryString }
            }
        };
    }
    
    return request;
}
```

## 3. Key Value Store (KVS)

**Availability**: Both viewer-request and viewer-response functions

Access CloudFront Key Value Store for dynamic data lookups.

### Initialize KVS Handle

```javascript
import cf from 'cloudfront';

const kvsHandle = cf.kvs();
```

**Important**: This will fail if no Key Value Store is associated with the function.

### Get Value from KVS

```javascript
async function handler(event) {
    const request = event.request;
    
    try {
        const value = await kvsHandle.get('myKey');
        console.log(`Found value: ${value}`);
    } catch (err) {
        console.log(`Key not found: ${err}`);
    }
    
    return request;
}
```

### Example: URL Path Rewriting

```javascript
import cf from 'cloudfront';

const kvsHandle = cf.kvs();

async function handler(event) {
    const request = event.request;
    
    // Use first segment of pathname as key
    // Example: http(s)://domain/<key>/something/else
    const pathSegments = request.uri.split('/');
    const key = pathSegments[1];
    
    try {
        // Replace first path segment with KVS value
        pathSegments[1] = await kvsHandle.get(key);
        const newUri = pathSegments.join('/');
        console.log(`${request.uri} -> ${newUri}`);
        request.uri = newUri;
    } catch (err) {
        // No change if key not found
        console.log(`${request.uri} | ${err}`);
    }
    
    return request;
}
```

### Example: Bulk Redirects

```javascript
import cf from 'cloudfront';

const kvsHandle = cf.kvs();

async function handler(event) {
    const request = event.request;
    const uri = request.uri;
    
    try {
        // Look up redirect destination
        const destination = await kvsHandle.get(uri);
        
        // Return redirect response
        return {
            statusCode: 301,
            statusDescription: 'Moved Permanently',
            headers: {
                'location': { value: destination }
            }
        };
    } catch (err) {
        // No redirect found, continue with original request
        return request;
    }
}
```

### KVS Best Practices

1. **Sequential await**: Use sequential `await` instead of `Promise.all()` to avoid memory limits
2. **Error handling**: Always wrap KVS operations in `try...catch` blocks
3. **Memory limit**: Maximum 2MB function memory
4. **Execution time**: KVS lookups add latency (~1ms per lookup)

```javascript
// ❌ BAD - Uses Promise.all()
const [val1, val2] = await Promise.all([
    kvsHandle.get('key1'),
    kvsHandle.get('key2')
]);

// ✅ GOOD - Sequential await with error handling
let val1, val2;
try {
    val1 = await kvsHandle.get('key1');
} catch (err) {
    console.log('key1 not found');
}
try {
    val2 = await kvsHandle.get('key2');
} catch (err) {
    console.log('key2 not found');
}
```

## 4. Update Request Origin (Dynamic Origin Selection)

**Availability**: Viewer Request functions only

Dynamically change the origin for a request.

```javascript
cf.updateRequestOrigin(request, {
    domainName: 'new-origin.example.com',
    port: 443,
    protocol: 'https',
    path: '/api/v2',
    customHeaders: {
        'x-custom-header': { value: 'custom-value' }
    }
});
```

### Parameters

- **`domainName`**: Origin domain name
- **`port`**: Origin port (80, 443, or custom)
- **`protocol`**: `http` or `https`
- **`path`**: Path prefix to prepend to request URI
- **`customHeaders`**: Custom headers to add to origin request

### Example Usage

```javascript
import cf from 'cloudfront';

async function handler(event) {
    const request = event.request;
    const host = request.headers.host.value;
    
    // Route different hosts to different origins
    if (host.startsWith('api.')) {
        cf.updateRequestOrigin(request, {
            domainName: 'api-backend.example.com',
            port: 443,
            protocol: 'https',
            customHeaders: {
                'x-forwarded-host': { value: host }
            }
        });
    } else if (host.startsWith('static.')) {
        cf.updateRequestOrigin(request, {
            domainName: 'static-assets.s3.amazonaws.com',
            port: 443,
            protocol: 'https'
        });
    }
    
    return request;
}
```

## Complete Example: Combining Multiple Helper Methods

```javascript
import cf from 'cloudfront';

const kvsHandle = cf.kvs();

async function handler(event) {
    const request = event.request;
    
    // Log edge location
    console.log(`Processing at edge: ${cf.edgeLocation.name}`);
    
    // Get raw query string
    const qs = request.rawQueryString();
    if (qs && qs.includes('debug=true')) {
        request.headers['x-debug'] = { value: 'enabled' };
    }
    
    // Check for redirect in KVS
    try {
        const redirectUrl = await kvsHandle.get(request.uri);
        return {
            statusCode: 301,
            statusDescription: 'Moved Permanently',
            headers: {
                'location': { value: redirectUrl }
            }
        };
    } catch (err) {
        // No redirect, continue processing
    }
    
    // Dynamic origin selection based on path
    if (request.uri.startsWith('/api/')) {
        cf.updateRequestOrigin(request, {
            domainName: 'api.example.com',
            port: 443,
            protocol: 'https'
        });
    }
    
    return request;
}
```

## Additional Resources

More code examples available at: https://github.com/aws-samples/amazon-cloudfront-functions
