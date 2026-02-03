# CloudFront Functions Event Structure

The `event` object is the input to your CloudFront Function. Your function returns only the `request` or `response` object, not the complete `event` object.

## Complete Event Object Example

This example shows a viewer-request event for a standard distribution:

```json
{
    "version": "1.0",
    "context": {
        "distributionDomainName": "d111111abcdef8.cloudfront.net",
        "distributionId": "EDFDVBD6EXAMPLE",
        "eventType": "viewer-request",
        "requestId": "EXAMPLEntjQpEXAMPLE_SG5Z-EXAMPLEPmPfEXAMPLEu3EqEXAMPLE=="
    },
    "viewer": {
        "ip": "198.51.100.11"
    },
    "request": {
        "method": "GET",
        "uri": "/media/index.mpd",
        "querystring": {
            "ID": {"value": "42"},
            "Exp": {"value": "1619740800"},
            "TTL": {"value": "1440"},
            "NoValue": {"value": ""},
            "querymv": {
                "value": "val1",
                "multiValue": [
                    {"value": "val1"},
                    {"value": "val2,val3"}
                ]
            }
        },
        "headers": {
            "host": {"value": "video.example.com"},
            "user-agent": {"value": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:83.0) Gecko/20100101 Firefox/83.0"},
            "accept": {
                "value": "application/json",
                "multiValue": [
                    {"value": "application/json"},
                    {"value": "application/xml"},
                    {"value": "text/html"}
                ]
            },
            "accept-language": {"value": "en-GB,en;q=0.5"},
            "accept-encoding": {"value": "gzip, deflate, br"},
            "origin": {"value": "https://website.example.com"},
            "referer": {"value": "https://website.example.com/videos/12345678?action=play"},
            "cloudfront-viewer-country": {"value": "GB"}
        },
        "cookies": {
            "Cookie1": {"value": "value1"},
            "Cookie2": {"value": "value2"},
            "cookie_consent": {"value": "true"},
            "cookiemv": {
                "value": "value3",
                "multiValue": [
                    {"value": "value3"},
                    {"value": "value4"}
                ]
            }
        }
    },
    "response": {
        "statusCode": 200,
        "statusDescription": "OK",
        "headers": {
            "date": {"value": "Mon, 04 Apr 2021 18:57:56 GMT"},
            "server": {"value": "gunicorn/19.9.0"},
            "access-control-allow-origin": {"value": "*"},
            "access-control-allow-credentials": {"value": "true"},
            "content-type": {"value": "application/json"},
            "content-length": {"value": "701"}
        },
        "cookies": {
            "ID": {
                "value": "id1234",
                "attributes": "Expires=Wed, 05 Apr 2021 07:28:00 GMT"
            },
            "Cookie1": {
                "value": "val1",
                "attributes": "Secure; Path=/; Domain=example.com; Expires=Wed, 05 Apr 2021 07:28:00 GMT",
                "multiValue": [
                    {
                        "value": "val1",
                        "attributes": "Secure; Path=/; Domain=example.com; Expires=Wed, 05 Apr 2021 07:28:00 GMT"
                    },
                    {
                        "value": "val2",
                        "attributes": "Path=/cat; Domain=example.com; Expires=Wed, 10 Jan 2021 07:28:00 GMT"
                    }
                ]
            }
        }
    }
}
```

## Key Components

### Context
- `distributionDomainName`: CloudFront domain name
- `distributionId`: Distribution ID
- `eventType`: `viewer-request` or `viewer-response`
- `requestId`: Unique request identifier

### Viewer
- `ip`: Client IP address (IPv4 or IPv6)

### Request Object

#### Method
- `method`: HTTP method (GET, POST, PUT, DELETE, etc.)

#### URI
- `uri`: Request URI path (e.g., `/media/index.mpd`)

#### Query String
- `querystring`: Object with query parameters
- Each parameter has `value` property
- Multi-value parameters have `multiValue` array

#### Headers
- `headers`: Object with HTTP headers
- Header names are lowercase
- Each header has `value` property
- Multi-value headers have `multiValue` array

#### Cookies
- `cookies`: Object with cookies
- Each cookie has `value` property
- Multi-value cookies have `multiValue` array

## Accessing Event Data

### Get viewer IP
```javascript
const clientIp = event.viewer.ip;
```

### Get request URI
```javascript
const uri = event.request.uri;
```

### Get query string
```javascript
// Get specific query parameter
const id = event.request.querystring.ID ? request.querystring.ID.value : undefined;

// Get raw query string
const rawQs = event.request.rawQueryString();
```

### Get headers
```javascript
// Get specific header
const host = event.request.headers.host ? request.headers.host.value : undefined;
const country = event.request.headers['cloudfront-viewer-country'] ? request.headers['cloudfront-viewer-country'].value : undefined;

// Check if header exists
if (event.request.headers['user-agent']) {
    const ua = event.request.headers['user-agent'].value;
}
```

### Get cookies
```javascript
// Get specific cookie
const sessionId = event.request.cookies.sessionId ? request.cookies.sessionId.value : undefined;

// Check if cookie exists
if (event.request.cookies.auth) {
    const authToken = event.request.cookies.auth.value;
}
```

## Modifying Request

### Modify URI
```javascript
event.request.uri = '/new/path';
```

### Add/Modify header
```javascript
event.request.headers['x-custom-header'] = { value: 'custom-value' };
```

### Add/Modify cookie
```javascript
event.request.cookies['new-cookie'] = { value: 'cookie-value' };
```

### Redirect
```javascript
return {
    statusCode: 301,
    statusDescription: 'Moved Permanently',
    headers: {
        'location': { value: 'https://example.com/new-location' }
    }
};
```

## Multi-Tenant Distributions

For multi-tenant distributions, the `context` object uses `endpoint` instead of `distributionDomainName`:

```json
{
    "context": {
        "endpoint": "d111111abcdef8.cloudfront.net",
        "distributionId": "EDFDVBD6EXAMPLE",
        "eventType": "viewer-request",
        "requestId": "..."
    }
}
```
