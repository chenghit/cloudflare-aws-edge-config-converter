# Non-Convertible Cloudflare Rules

This document lists Cloudflare transformation rules that **cannot** be automatically converted to CloudFront Functions, along with explanations and alternatives.

## From Rules > Settings

### URL Normalization
**Convertible**: ❌ No

**Reason**: No needed. CloudFront normalizes URI paths consistent with RFC 3986 and then matches the path with the correct cache behavior. Once the cache behavior is matched, CloudFront sends the raw URI path to the origin.

### Managed Transforms (except True-Client-IP)
**Convertible**: ❌ No (except True-Client-IP)

**Reasons**:
1. Some should use CloudFront configuration instead
2. Others are Cloudflare-specific features not supported by AWS

**Examples of non-convertible managed transforms**:
- Remove `X-Powered-By` header → Use CloudFront Response Header Policy
- Add security headers → Use CloudFront Response Header Policy
- Cloudflare-specific headers → Not available in CloudFront

## From Rules > Overview

### Page Rules (Legacy)
**Convertible**: ❌ No

**Reasons**:
1. **Deprecated by Cloudflare** - Page Rules are being phased out in favor of modern rule types (Redirect Rules, URL Rewrite Rules, etc.)
2. **Functionality overlap** - Most Page Rule capabilities are now covered by newer rule types that this skill already converts
3. **Better migration path** - Users should migrate to modern Cloudflare rules first, then migrate to CloudFront
4. **Low ROI** - Most Page Rule settings (30+ options) either:
   - Should use CloudFront configuration instead (Cache TTL, SSL, etc.)
   - Are Cloudflare-specific features not supported by CloudFront (Polish, Rocket Loader, etc.)
   - Only 3 settings would actually need function conversion (Forwarding URL, Query String Sort, True Client IP)

**Recommendation**: 
- If still using Page Rules, first migrate to modern Cloudflare rule types (Redirect Rules, URL Rewrite Rules, etc.)
- Then use this skill to convert the modern rules to CloudFront Functions
- This avoids converting deprecated configuration formats

### Simple HTTP→HTTPS Redirects
**Convertible**: ❌ No

**Pattern**: `http://*` → `https://*`

**Reason**: CloudFront has native configuration for this

**Alternative**: 
- Use CloudFront Distribution Settings
- Set Viewer Protocol Policy to "Redirect HTTP to HTTPS"
- No function needed

### Configuration Rules
**Convertible**: ❌ No

**Reason**: These are CDN configuration settings, not transformation logic

**Examples**:
- Cache TTL settings → Use CloudFront Cache Policy
- Origin selection → Use CloudFront Origin Groups or distribution settings
- Compression settings → Use CloudFront Cache Policy

**Alternative**: Configure equivalent settings in CloudFront distribution

### Origin Rules
**Convertible**: ❌ No (not in current version)

**Reason**: Complex and requires manual intervention

**Cloudflare Origin Rules capabilities**:
1. **Host Header Override**
   - **Scenario 1**: Forward viewer request Host header to origin → Use CloudFront Origin Request Policy
   - **Scenario 2**: Don't forward viewer request Host header to origin → Use CloudFront Origin Request Policy
   - **Scenario 3**: Dynamically change Host header value (viewer Host = "domain A", origin = "domain B", need Host = "domain C")
     - For **non-cacheable objects** with simple origin change → Use CloudFront Function `cf.updateRequestOrigin()` helper method
     - For **cacheable objects** → Use Lambda@Edge origin-request event (more cost-effective)
   - **Reason for Lambda@Edge**: CloudFront Functions run on every request (including cache hits), Lambda@Edge origin-request only runs on cache misses

2. **Destination Port Override**
   - Cloudflare: Override port in rules
   - CloudFront: Configure port in origin settings
   - **Alternative**: Set port when defining origin

3. **Dynamic Origin Selection**
   - CloudFront Functions now support `cf.updateRequestOrigin()` helper method
   - However, Cloudflare Origin Rules don't map 1:1 to CloudFront
   - User intent is unclear from configuration alone
   - **Alternative**: Manual conversion with human review

**Conclusion**: Origin Rules require manual intervention for accurate conversion

### Page Rules (Non-Convertible Settings)
**Convertible**: ❌ No (for most settings)

**Reason**: Most Page Rule settings are CDN configuration, not transformation logic

**Non-convertible Page Rule settings and their CloudFront alternatives**:

1. **Always Use HTTPS** → Use CloudFront Viewer Protocol Policy (Redirect HTTP to HTTPS)
2. **Automatic HTTPS Rewrites** → Use CloudFront configuration
3. **Browser Cache TTL** → Use CloudFront Cache Policy
4. **Browser Integrity Check** → Use AWS WAF Bot Control Managed Rule Group
5. **Bypass Cache on Cookie** → Use Lambda@Edge origin-response function
6. **Cache By Device Type** → Use CloudFront Cache Policy with device type headers
7. **Cache Deception Armor** → Use Lambda@Edge origin-response function
8. **Cache Level** → Use CloudFront Cache Policy
9. **Cache on Cookie** → Use CloudFront Cache Policy
10. **Cache TTL by Status Code** → Use CloudFront Custom Error Response
11. **Custom Cache Key** → Use CloudFront Cache Policy
12. **Disable Zaraz** → Not supported by CloudFront
13. **Edge Cache TTL** → Use CloudFront Cache Policy
14. **Email Obfuscation** → Not supported by CloudFront
15. **IP Geolocation Header** → Use CloudFront Cache Policy to include `CloudFront-Viewer-Country` header
16. **Mirage** → Not supported by CloudFront (deprecated feature)
17. **Opportunistic Encryption** → Not supported by CloudFront
18. **Origin Cache Control** → Use CloudFront Cache Policy
19. **Origin Error Page Pass-thru** → Use CloudFront Custom Error Response
20. **Polish** → Use AWS Dynamic Image Transformation for CloudFront solution
21. **Resolve Override** → Use Lambda@Edge origin-request function or CloudFront Function `cf.updateRequestOrigin()` method
22. **Respect Strong ETags** → Natively supported by CloudFront (no configuration needed)
23. **Response Buffering** → Not supported by CloudFront
24. **Rocket Loader** → Not supported by CloudFront
25. **SSL** → Natively supported by CloudFront (configure in distribution settings)

**Note**: Only 3 Page Rule settings are convertible to CloudFront Functions:
- Forwarding URL (redirects)
- Query String Sort
- True Client IP Header

All other settings should use CloudFront native configuration or are not supported.

### Cache Rules
**Convertible**: ❌ No

**Reason**: CDN configuration, not transformation logic

**Alternative**: Use CloudFront Cache Policy

### Custom Error Rules
**Convertible**: ❌ No

**Reasons**:
1. **CloudFront native custom error responses**:
   - Can change response error code
   - Can configure custom error pages
   - Can set error cache TTL
   - But can only match specific response codes
   - Cannot match HTTP request parameters (URI, headers, etc.)

2. **Custom error pages**:
   - CloudFront: Points to S3 bucket URI
   - Cloudflare: Uses Workers Static Assets or KV-Asset-Handler
   - **Migration required**: Move static assets to S3 first

3. **Response Error Type**:
   - Cloudflare-specific feature
   - CloudFront Functions not invoked for 4xx/5xx responses
   - **Alternative**: Use Lambda@Edge for response manipulation

4. **Custom Error Rules are reactive**:
   - Replace errors that already occurred
   - Not proactive like firewall rules
   - Must match response error codes
   - **Alternative**: Use CloudFront custom error responses configuration

**Conclusion**: Use CloudFront configuration, not functions

### Response Header Transform Rules
**Convertible**: ❌ No (not in current version)

**Reason**: Too many possibilities, requires careful analysis

**Technical Note**:
- CloudFront Functions CAN modify response headers in viewer-response events
- However, CloudFront Functions are triggered on EVERY request (even cache hits)
- For cacheable objects (images, PDFs, static files), this is inefficient and costly

**Scenarios**:
1. **Static response headers** → Use CloudFront Response Header Policy (most efficient)
2. **Dynamic headers for cacheable objects** → Use Lambda@Edge origin-response (only runs on cache miss)
3. **Dynamic headers for non-cacheable requests** → Could use CloudFront Function viewer-response
4. **Read-only headers** → Cannot modify/remove (e.g., `Content-Length`, `Transfer-Encoding`)

**Example - Why Lambda@Edge is better for cacheable objects**:
- Cloudflare rule: Add `Link` header to PDF responses
- CloudFront Function viewer-response: Runs on every request (1M requests = 1M executions)
- Lambda@Edge origin-response: Runs only on cache miss (1M requests with 90% cache hit = 100K executions)
- **Cost savings**: Lambda@Edge is more economical for cacheable content

**Conclusion**: Deferred to future version. Requires manual intervention and cost analysis.

### Compression Rules
**Convertible**: ❌ No

**Reason**: CDN configuration

**Alternative**: Use CloudFront Cache Policy compression settings

### Managed Transforms (except True-Client-IP)
**Convertible**: ❌ No

**Reason**: Should use CloudFront configuration or are Cloudflare-specific

**Alternative**: Review each transform and configure equivalent in CloudFront

### Snippets
**Convertible**: ❌ No (not in current version)

**Reason**: Snippets are JavaScript code, not configuration

**Cloudflare Snippets**:
- Similar to CloudFront Functions
- Arbitrary JavaScript code
- High degree of freedom
- Cannot be converted to rule expressions

**Conclusion**: Requires manual code review and conversion. Deferred to future version.

### Cloud Connector
**Convertible**: ❌ No

**Reason**: CDN feature for fast origin access to cloud storage

**Alternative**: Configure CloudFront origin to point to S3 or other AWS storage

### Trace
**Convertible**: ❌ No

**Reason**: Cloudflare-specific testing feature

**Alternative**: Use CloudFront testing tools and CloudWatch Logs

## Non-Convertible Match Fields

### SSL Fields
**Convertible**: ❌ No

**Reason**: Use CloudFront distribution configuration

**Alternative**: Configure SSL/TLS settings in CloudFront distribution

### Response Error Type
**Convertible**: ❌ No

**Reason**: Cloudflare-specific feature

**Details**:
- CloudFront Functions run before origin request
- CloudFront Functions not invoked for 4xx/5xx responses from origin
- Cannot match error types in viewer-request functions

**Alternative**: Use Lambda@Edge viewer-response or origin-response events

### Client Certificate Verified
**Convertible**: ❌ No

**Reason**: CloudFront mTLS not fully supported in Functions

**Details**:
- CloudFront supports mTLS
- CloudFront has Connection Functions
- But no Client Certificate Verified header available in CloudFront Functions
- mTLS verification happens during connection, before function execution

**Alternative**: Manual configuration of mTLS in CloudFront. Not suitable for automatic conversion.

### Continent (Tor)
**Convertible**: ❌ No

**Reason**: Security rule, not transformation rule

**Details**:
- In Cloudflare, the continent field value `Tor` does not represent a geographic continent
- `Tor` refers to the Tor anonymity network
- This is a security-related match condition, not a geographic transformation rule
- Should be converted using the Cloudflare to AWS WAF skill instead

**Alternative**: Use the Cloudflare to AWS WAF Converter skill to convert this security rule to AWS WAF

### Cloudflare-Specific Fields

#### `cf.edge.server_port`
**Convertible**: ❌ No

**Reason**: Cloudflare-specific field

**Note**: CloudFront always uses port 80 or 443, no need to expose

#### `cf.zone.name`
**Convertible**: ❌ No

**Reason**: Cloudflare-specific field

#### `cf.metal.id`
**Convertible**: ❌ No

**Reason**: Cloudflare-specific field (server identifier)

#### `cf.ray_id`
**Convertible**: ❌ No

**Reason**: Cloudflare-specific request ID

**Alternative**: Use CloudFront request ID from `event.context.requestId`

#### `http.request.timestamp.sec` and `http.request.timestamp.msec`
**Convertible**: ❌ No

**Reason**: Cloudflare-specific fields

**Alternative**: Generate timestamp in CloudFront Function if needed:
```javascript
const timestamp = Date.now();
```

#### `cf.tls_client_auth.*`
**Convertible**: ❌ No

**Reason**: mTLS certificate fields not available in CloudFront Functions

**Details**:
- CloudFront supports mTLS
- CloudFront has Connection Functions
- But certificate details not exposed to CloudFront Functions
- Requires Connection Function (different from CloudFront Function)

**Conclusion**: Not suitable for automatic conversion. Requires manual intervention.

#### `ip.src.subdivision_2_iso_code`
**Convertible**: ❌ No

**Reason**: Cloudflare-specific field (second-level subdivision)

**Note**: CloudFront only provides first-level subdivision (`CloudFront-Viewer-Country-Region`)

#### `cf.edge.server_ip`
**Convertible**: ❌ No

**Reason**: Server IP changes after migration, rule becomes meaningless

**Details**:
- CloudFront provides `cf.edgeLocation.serverIp` helper method
- But after migrating from Cloudflare to CloudFront, server IPs will be different
- Any rules matching Cloudflare server IPs are no longer valid
- No point in converting these rules

**Conclusion**: Do not convert. User should review intent and rewrite rule if needed.

### Response Status Code
**Convertible**: ❌ No

**Reason**: CloudFront Functions not invoked for 4xx/5xx responses

**Details**:
- CloudFront doesn't invoke edge functions for viewer-response events when origin returns HTTP status code 400 or higher
- Cannot match response status codes in CloudFront Functions

**Alternative**: Use Lambda@Edge for response status code manipulation

## Summary Table

| Rule/Field | Convertible | Alternative |
|-----------|-------------|-------------|
| URL Normalization | ❌ | No needed |
| Simple HTTP→HTTPS Redirect | ❌ | CloudFront Viewer Protocol Policy |
| Configuration Rules | ❌ | CloudFront Cache/Origin Policies |
| Origin Rules | ❌ | CloudFront Origin Settings (manual) |
| Cache Rules | ❌ | CloudFront Cache Policy |
| Custom Error Rules | ❌ | CloudFront Custom Error Responses |
| Response Header Transform | ❌ | Response Header Policy / Lambda@Edge origin-response (for cacheable objects) |
| Compression Rules | ❌ | CloudFront Cache Policy |
| Snippets | ❌ | Manual code review (future version) |
| Cloud Connector | ❌ | CloudFront Origin Configuration |
| Trace | ❌ | CloudFront testing tools |
| SSL Fields | ❌ | CloudFront Distribution Settings |
| Response Error Type | ❌ | Lambda@Edge |
| Client Certificate Verified | ❌ | Manual mTLS configuration |
| Continent (Tor) | ❌ | Use Cloudflare to AWS WAF skill |
| Cloudflare-specific fields | ❌ | Not available in CloudFront |
| Response Status Code | ❌ | Lambda@Edge |

## Explanation Strategy

When encountering non-convertible rules, explain to user:

1. **What the Cloudflare rule does**
2. **Why it cannot be automatically converted**
3. **What CloudFront alternative exists** (if any)
4. **Whether manual intervention is needed**

**Important**: Do NOT provide detailed step-by-step manual conversion instructions. Users will determine implementation details themselves based on their specific requirements.
