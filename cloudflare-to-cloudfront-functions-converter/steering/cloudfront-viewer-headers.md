# CloudFront Viewer Headers

CloudFront can add special headers to requests that provide information about the viewer (client). These headers are only available if configured in the **Origin Request Policy**.

## Always Available Headers

These headers are available in CloudFront Functions without any configuration:

- Standard HTTP headers (host, user-agent, referer, etc.)
- `event.viewer.ip` - Client IP address

## CloudFront Viewer Headers (Require Origin Request Policy Configuration)

### Device Type Headers

- `CloudFront-Is-Desktop-Viewer` - `true` or `false`
- `CloudFront-Is-Mobile-Viewer` - `true` or `false`
- `CloudFront-Is-SmartTV-Viewer` - `true` or `false`
- `CloudFront-Is-Tablet-Viewer` - `true` or `false`
- `CloudFront-Is-Android-Viewer` - `true` or `false`
- `CloudFront-Is-IOS-Viewer` - `true` or `false`

### Geographic Headers (Available for non-AWS IPs)

- `CloudFront-Viewer-Country` - Two-letter country code (ISO 3166-1 alpha-2)
- `CloudFront-Viewer-Country-Name` - Full country name
- `CloudFront-Viewer-Country-Region` - First-level subdivision code (e.g., `GD` for Guangdong)
- `CloudFront-Viewer-Country-Region-Name` - Full region name (e.g., `Guangdong`)
- `CloudFront-Viewer-City` - City name
- `CloudFront-Viewer-Latitude` - Latitude coordinate (e.g., `22.54550`)
- `CloudFront-Viewer-Longitude` - Longitude coordinate (e.g., `114.06830`)
- `CloudFront-Viewer-Time-Zone` - Time zone (e.g., `Asia/Shanghai`)

**Note**: Postal code and metro code are NOT available in CloudFront Functions:
- ❌ `CloudFront-Viewer-Postal-Code` - Not available
- ❌ `CloudFront-Viewer-Metro-Code` - Not available

### Network Headers

- `CloudFront-Viewer-Address` - Client IP and port (format: `ip:port`, e.g., `14.155.12.123:61246`)
- `CloudFront-Viewer-ASN` - Autonomous System Number (e.g., `4134`)

### Protocol Headers

- `CloudFront-Viewer-Http-Version` - HTTP version (e.g., `2.0`, `1.1`)
- `CloudFront-Viewer-TLS` - TLS version and cipher (e.g., `TLSv1.3:TLS_AES_128_GCM_SHA256:connectionReused`)
- `CloudFront-Forwarded-Proto` - Original protocol (`http` or `https`)

### Security Headers

- `CloudFront-Viewer-JA3-Fingerprint` - JA3 TLS fingerprint
- `CloudFront-Viewer-JA4-Fingerprint` - JA4 TLS fingerprint

### Request Metadata Headers

- `CloudFront-Viewer-Header-Count` - Number of headers in request
- `CloudFront-Viewer-Header-Order` - Order of headers (colon-separated)

## Example Event with Viewer Headers

```javascript
{
    "headers": {
        "host": { "value": "d2uloqf425abcd.cloudfront.net" },
        "user-agent": { "value": "Mozilla/5.0 ..." },
        
        // Device detection
        "cloudfront-is-desktop-viewer": { "value": "true" },
        "cloudfront-is-mobile-viewer": { "value": "false" },
        "cloudfront-is-tablet-viewer": { "value": "false" },
        
        // Geographic
        "cloudfront-viewer-country": { "value": "CN" },
        "cloudfront-viewer-country-name": { "value": "China" },
        "cloudfront-viewer-country-region": { "value": "GD" },
        "cloudfront-viewer-country-region-name": { "value": "Guangdong" },
        "cloudfront-viewer-city": { "value": "Shenzhen" },
        "cloudfront-viewer-latitude": { "value": "22.54550" },
        "cloudfront-viewer-longitude": { "value": "114.06830" },
        "cloudfront-viewer-time-zone": { "value": "Asia/Shanghai" },
        
        // Network
        "cloudfront-viewer-address": { "value": "14.155.12.123:61246" },
        "cloudfront-viewer-asn": { "value": "4134" },
        
        // Protocol
        "cloudfront-viewer-http-version": { "value": "2.0" },
        "cloudfront-viewer-tls": { "value": "TLSv1.3:TLS_AES_128_GCM_SHA256:connectionReused" },
        "cloudfront-forwarded-proto": { "value": "https" }
    }
}
```

## Accessing Viewer Headers in Code

```javascript
// Get country code
const country = request.headers['cloudfront-viewer-country']?.value;

// Get client IP (without port)
const clientIp = event.viewer.ip;

// Get client IP with port
const clientAddress = request.headers['cloudfront-viewer-address']?.value;
const [ip, port] = clientAddress ? clientAddress.split(':') : [clientIp, ''];

// Get ASN
const asn = request.headers['cloudfront-viewer-asn']?.value;

// Check if mobile device
const isMobile = request.headers['cloudfront-is-mobile-viewer']?.value === 'true';

// Get geographic coordinates
const lat = request.headers['cloudfront-viewer-latitude']?.value;
const lon = request.headers['cloudfront-viewer-longitude']?.value;

// Get HTTP version
const httpVersion = request.headers['cloudfront-viewer-http-version']?.value;
```

## Important Notes

1. **Header names are lowercase** in CloudFront Functions event object
2. **CloudFront-Viewer-Address format**: Always `ip:port`, not just IP
3. **Geographic headers**: Only available for non-AWS IP addresses
4. **Origin Request Policy required**: These headers must be configured in Origin Request Policy to appear in the event
5. **Case sensitivity**: Use lowercase when accessing headers (e.g., `cloudfront-viewer-country`, not `CloudFront-Viewer-Country`)

## Cloudflare to CloudFront Header Mapping

| Cloudflare Field | CloudFront Equivalent |
|-----------------|----------------------|
| `ip.src` | `event.viewer.ip` |
| `ip.src.asnum` | `cloudfront-viewer-asn` header |
| `ip.src.country` | `cloudfront-viewer-country` header |
| `ip.src.city` | `cloudfront-viewer-city` header |
| `ip.src.lat` | `cloudfront-viewer-latitude` header |
| `ip.src.lon` | `cloudfront-viewer-longitude` header |
| `ip.src.subdivision_1_iso_code` | Combine `cloudfront-viewer-country` + `cloudfront-viewer-country-region` |
| `http.request.version` | `cloudfront-viewer-http-version` header |
| `http.host` | `host` header |
| `http.user_agent` | `user-agent` header |
| `http.referer` | `referer` header |
| `http.x_forwarded_for` | `x-forwarded-for` header |
