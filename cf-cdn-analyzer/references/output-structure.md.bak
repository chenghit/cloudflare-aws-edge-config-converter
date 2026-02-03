# Output Structure: hostname-based-config-summary.md

## File Structure

```markdown
# Cloudflare CDN Configuration Summary

## Summary
- Total Proxied DNS Records: X
- Total Rules: Y
- IP-based Origins (Non-convertible): Z

⚠️ **Important: Implicit Cloudflare Default Cache Behavior**

All proxied hostnames rely on Cloudflare's default cache behavior (not visible in config files):
- Static files (70+ extensions) are automatically cached for 2 hours
- HTML and JSON are NOT cached by default
- CloudFront requires explicit configuration to replicate this behavior
- See reference: `cloudflare-default-cache-behavior.md`

### Proxied Hostnames (CNAME Records Only)
| Hostname | Record Type | Value | Apply Default Cache Behavior? |
|----------|-------------|-------|-------------------------------|
| example.com | CNAME | origin.example.com | Yes / No |
| www.example.com | CNAME | origin.example.com | Yes / No |
| cdn.example.com | CNAME | cdn-origin.example.com | Yes / No |

**Instructions:** For each hostname, edit the last column to keep ONLY your choice (delete the other option).

Example:
- If you want default cache behavior: Change `Yes / No` to `Yes`
- If you don't want default cache behavior: Change `Yes / No` to `No`

**When to choose "Yes":**
- This hostname serves static files (images, CSS, JS, fonts, etc.) AND
- Relies on Cloudflare's default cache behavior (2-hour TTL for 70+ extensions)

**When to choose "No":**
- This hostname does not serve static files (e.g., API-only, dynamic content only), OR
- This hostname serves static files BUT uses custom Cache Rules exclusively (not relying on default behavior)

---

## DNS Record: example.com
- Type: CNAME
- Value: origin.example.com
- Proxied: Yes
- Status: ✅ Convertible
- Total Rules: 15

### Redirect Rules (2 rules)
| Rule ID | Priority | Match Expression | Target URL | Status Code |
|---------|----------|------------------|------------|-------------|
| redirect-1 | 1 | `http.request.uri.path eq "/old"` | `/new` | 301 |

### URL Rewrite Rules (2 rules)
| Rule ID | Priority | Match Expression | Rewrite Action |
|---------|----------|------------------|----------------|
| rewrite-1 | 1 | `http.request.uri.path matches "^/api/v1/(.*)"` | `/v2/$1` |

### Bulk Redirects (3 rules)
| Rule ID | Priority | Source URL | Target URL | Status Code | Include Subdomains | Preserve Query String |
|---------|----------|------------|------------|-------------|-------------------|----------------------|
| bulk-1 | 1 | example.com/old | example.com/new | 301 | No | Yes |

### Request Header Transform Rules (2 rules)
| Rule ID | Priority | Match Expression | Header Action |
|---------|----------|------------------|---------------|
| header-1 | 1 | `http.request.uri.path matches "^/api/.*"` | Set `X-API-Version: 2.0` |

### Managed Transforms
| Transform Type | Enabled |
|----------------|---------|
| True-Client-IP Header | Yes |

### Cache Rules (5 rules)
| Rule ID | Priority | Match Expression | Action | Settings |
|---------|----------|------------------|--------|----------|
| cache-1 | 1 | `http.request.uri.path matches "^/api/.*"` | Set cache TTL | TTL: 0s |
| cache-2 | 2 | `http.request.uri.path matches ".*\\.jpg$"` | Set cache TTL | TTL: 86400s |

### Origin Rules (3 rules)
| Rule ID | Priority | Match Expression | Action | Settings |
|---------|----------|------------------|--------|----------|
| origin-1 | 1 | `http.request.uri.path matches "^/api/.*"` | Override origin | Host: api-backend.example.com |

### Custom Error Rules (1 rule)
| Rule ID | Error Code | Custom Response |
|---------|------------|-----------------|
| error-1 | 404 | Custom 404 page |

### Custom Pages
| Error Type | State | Custom URL |
|------------|-------|------------|
| 500_errors | default | (Using Cloudflare default) |
| 1000_errors | custom | https://example.com/errors/cloudflare.html |

### Response Header Transform Rules (1 rule)
| Rule ID | Priority | Match Expression | Header Action |
|---------|----------|------------------|---------------|
| resp-header-1 | 1 | `true` | Set `X-Frame-Options: DENY` |

### Compression Rules (1 rule)
| Rule ID | Priority | Match Expression | Compression Type |
|---------|----------|------------------|------------------|
| compress-1 | 1 | `true` | Gzip, Brotli |

---

## DNS Record: api.example.com
[Repeat same structure for each proxied DNS record]

---

## Global Rules (no http.host match)
These rules may apply to multiple DNS records. User decision required for assignment.

### Cache Rules (2 rules)
[Same table structure as above]

---

## Non-Convertible Items

### IP-Based Origins
| Hostname | Record Type | IP Address | Reason |
|----------|-------------|------------|--------|
| api.example.com | A | 203.0.113.10 | CloudFront doesn't support IP-based origins |

---

## Next Steps

1. Review this summary for completeness
2. For IP-based origins: Set up ALB/NLB or use domain names before proceeding
3. Run the Planner skill to determine CloudFront implementation methods
```

## Rule Grouping Logic

### How to Determine Which Rules Apply to a Hostname

**1. Exact Match:**
- Rule expression contains `http.host eq "example.com"`
- This rule ONLY applies to example.com

**2. Wildcard Match:**
- Rule expression contains `http.host matches ".*\\.example\\.com"`
- This rule applies to all subdomains of example.com

**3. Multiple Hosts (OR condition):**
- Rule expression contains `(http.host eq "example.com") or (http.host eq "www.example.com")`
- This rule applies to both hostnames

**4. No Host Match (Global Rule):**
- Rule expression does NOT contain `http.host`
- This rule may apply to ALL proxied hostnames
- Mark as "Global Rule" and list separately

### Preserving Rule Priority

**CRITICAL:** Maintain the exact order from Cloudflare configuration files.

- Cloudflare executes rules in priority order (lower number = higher priority)
- CloudFront also uses priority-based execution
- Changing order may break intended behavior

**Example:**
```
Original Cloudflare order:
1. cache-1 (priority: 1)
2. cache-2 (priority: 2)
3. cache-3 (priority: 3)

Output must preserve this order in the table.
```

### Handling Rules with Complex Expressions

**Example: Combined Conditions**
```
Expression: (http.host eq "example.com") and (http.request.uri.path matches "^/api/.*")
```

**Grouping:**
- This rule applies to: example.com
- Include full expression in "Match Expression" column
- Do NOT split the rule

**Example: Multiple Hosts**
```
Expression: (http.host in {"example.com" "www.example.com"}) and (http.request.uri.path eq "/test")
```

**Grouping:**
- This rule applies to: example.com AND www.example.com
- List this rule under BOTH hostnames
- Note: "Shared with [other hostname]" in the table

## Table Column Definitions

### Cache Rules
- **Rule ID**: Cloudflare rule ID
- **Priority**: Cloudflare rule priority (lower = higher priority)
- **Match Expression**: Full Cloudflare expression
- **Action**: Cache action (e.g., "Set cache TTL", "Bypass cache")
- **Settings**: Cache settings (e.g., "TTL: 3600s", "Edge TTL: 7200s")

### Origin Rules
- **Rule ID**: Cloudflare rule ID
- **Priority**: Cloudflare rule priority
- **Match Expression**: Full Cloudflare expression
- **Action**: Origin action (e.g., "Override origin", "Override host header")
- **Settings**: Origin settings (e.g., "Host: backend.example.com")

### Redirect Rules
- **Rule ID**: Cloudflare rule ID
- **Priority**: Cloudflare rule priority
- **Match Expression**: Full Cloudflare expression
- **Target URL**: Redirect target
- **Status Code**: HTTP status code (301, 302, 307, 308)

### URL Rewrite Rules
- **Rule ID**: Cloudflare rule ID
- **Priority**: Cloudflare rule priority
- **Match Expression**: Full Cloudflare expression
- **Rewrite Action**: Rewrite target (e.g., "/v2/$1")

### Header Transform Rules
- **Rule ID**: Cloudflare rule ID
- **Priority**: Cloudflare rule priority
- **Match Expression**: Full Cloudflare expression
- **Header Action**: Header operation (e.g., "Set X-Custom: value", "Remove X-Old")

### Compression Rules
- **Rule ID**: Cloudflare rule ID
- **Priority**: Cloudflare rule priority
- **Match Expression**: Full Cloudflare expression
- **Compression Type**: Compression algorithms (e.g., "Gzip, Brotli")

### Custom Error Rules
- **Rule ID**: Cloudflare rule ID
- **Error Code**: HTTP error code (e.g., 404, 500)
- **Custom Response**: Custom error page or response

### Custom Pages
- **Error Type**: Error page type (e.g., "500_errors", "1000_errors", "waf_block")
- **State**: "default" (using Cloudflare default) or "custom" (using custom page)
- **Custom URL**: URL of custom error page (if state is "custom")

### Managed Transforms
- **Transform Type**: Type of managed transform (e.g., "True-Client-IP Header")
- **Enabled**: Whether the transform is enabled (Yes/No)

### Bulk Redirects
- **Rule ID**: Cloudflare rule ID
- **Priority**: Rule priority
- **Source URL**: Source URL pattern
- **Target URL**: Redirect target
- **Status Code**: HTTP status code (301, 302, 307, 308)
- **Include Subdomains**: Whether to include subdomains (Yes/No)
- **Preserve Query String**: Whether to preserve query string (Yes/No)
