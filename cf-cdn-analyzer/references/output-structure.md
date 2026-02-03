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
- Total Rules: 5

### Redirect Rules (1 rule)
| Priority | Match Expression | Target URL | Status Code |
|----------|------------------|------------|-------------|
| 1 | `http.host eq "example.com" and http.request.uri.path eq "/old"` | `/new` | 301 |

### URL Rewrite Rules (1 rule)
| Priority | Match Expression | Rewrite Action |
|----------|------------------|----------------|
| 1 | `http.host eq "example.com" and http.request.uri.path matches "^/api/v1/(.*)"` | `/v2/$1` |

### Bulk Redirects (1 rule)
| Priority | Source URL | Target URL | Status Code | Include Subdomains | Preserve Query String |
|----------|------------|------------|-------------|-------------------|----------------------|
| 1 | example.com/old | example.com/new | 301 | No | Yes |

### Request Header Transform Rules (1 rule)
| Priority | Match Expression | Header Action |
|----------|------------------|---------------|
| 1 | `http.host eq "example.com" and http.request.uri.path matches "^/api/.*"` | Set `X-API-Version: 2.0` |

### Cache Rules (1 rule)
| Priority | Match Expression | Action | Settings |
|----------|------------------|--------|----------|
| 1 | `http.host eq "example.com" and http.request.uri.path matches "^/api/.*"` | Set cache TTL | TTL: 0s |

### Origin Rules (1 rule)
| Priority | Match Expression | Action | Settings |
|----------|------------------|--------|----------|
| 1 | `http.request.full_uri wildcard "https://example.com/api/*"` | Override origin | Host: api-backend.example.com |

### Custom Error Rules (1 rule)
| Error Code | Custom Response |
|------------|-----------------|
| 404 | Custom 404 page |

### Custom Pages
| Error Type | State | Custom URL |
|------------|-------|------------|
| 500_errors | default | (Using Cloudflare default) |
| 1000_errors | custom | https://example.com/errors/cloudflare.html |

### Response Header Transform Rules (1 rule)
| Priority | Match Expression | Header Action |
|----------|------------------|---------------|
| 1 | `http.host eq "example.com" and http.request.uri.path wildcard "/docs/*"` | Set `X-Custom-Header: value` |

### Compression Rules (1 rule)
| Priority | Match Expression | Compression Type |
|----------|------------------|------------------|
| 1 | `http.host eq "example.com"` | Gzip, Brotli |

---

## DNS Record: api.example.com
[Repeat same structure for each proxied DNS record]

---

## Global Rules (no http.host match)
These rules may apply to multiple DNS records. User decision required for assignment.

### Managed Transforms (Zone-level)
| Transform Type | Enabled |
|----------------|---------|
| True-Client-IP Header | Yes |

### Cache Rules (2 rules)
[Same table structure as above]

---

## Orphaned Rules (Hostname Not in Proxied DNS Records)

These rules reference hostnames that are not proxied. This may indicate outdated or misconfigured rules.

### Hostname: old.example.com (Not Proxied)

#### Bulk Redirects (2 rules)
| Priority | Source URL | Target URL | Status Code |
|----------|------------|------------|-------------|
| 1 | old.example.com/about | /about-us | 301 |
| 2 | old.example.com/contact | /contact-us | 301 |

**Note**: These rules will not take effect because the hostname is not proxied through Cloudflare. Consider deleting these rules or proxying the hostname.

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

**CRITICAL RULE: A rule can ONLY be listed under a specific DNS record if its Match Expression explicitly matches that exact hostname. If not, it MUST be listed as a Global Rule or Orphaned Rule.**

**Step 1: Check if rule specifies hostname**

**No hostname specified (Global Rule):**
- Rule expression does NOT contain `http.host` AND does NOT contain hostname in `http.request.full_uri`
- Examples:
  - `true` → Global (applies to all requests)
  - `http.request.uri.path eq "/test"` → Global (no hostname filter)
  - `http.user_agent contains "bot"` → Global (no hostname filter)
- **Result**: Mark as "Global Rule"
- **DO NOT** list under any specific DNS record, even if you think it "might" apply

**Hostname specified:**
- Rule expression contains `http.host` OR contains hostname in `http.request.full_uri`
- Continue to Step 2

**Step 2: Check if hostname uses wildcard for all subdomains**

**Wildcard matching all subdomains (Global Rule):**
- Expression contains `*.example.com` or `.*\\.example\\.com` pattern
- Examples:
  - `http.host wildcard "*.example.com"`
  - `http.host matches ".*\\.example\\.com"`
  - `http.request.full_uri wildcard r"https://*.example.com/path/*"`
- **Result**: Mark as "Global Rule" - applies to multiple hostnames

**Specific hostname (Specific Rule):**
- Expression specifies exact hostname(s)
- Examples:
  - `http.host eq "cdn.example.com"` → Only cdn.example.com
  - `http.host in {"example.com" "www.example.com"}` → Both example.com and www.example.com
  - `http.request.full_uri wildcard r"https://cdn.example.com/path/*"` → Only cdn.example.com
- **Result**: Check if hostname is in proxied DNS records
  - If YES: List under that DNS record
  - If NO: List under "Orphaned Rules" section

**Special Case: Bulk Redirects**

Bulk Redirects specify source URL directly (format: `hostname/path`). Extract hostname from source URL and check if it's in proxied DNS records:
- If YES: List under that DNS record
- If NO: List under "Orphaned Rules"

### Orphaned Rules

Rules that reference hostnames not in the proxied DNS records list should be grouped in a separate "Orphaned Rules" section. This indicates:
- Outdated rules that should be deleted
- Rules for hostnames that were un-proxied but rules not cleaned up
- Configuration errors

**Example:**
```markdown
## Orphaned Rules (Hostname Not in Proxied DNS Records)

These rules reference hostnames that are not proxied. This may indicate outdated or misconfigured rules.

### Hostname: old.example.com (Not Proxied)

#### Bulk Redirects (2 rules)
| Priority | Source URL | Target URL | Status Code |
|----------|------------|------------|-------------|
| 1 | old.example.com/about | /about-us | 301 |
| 2 | old.example.com/contact | /contact-us | 301 |

#### Cache Rules (1 rule)
| Priority | Match Expression | Action | Settings |
|----------|------------------|--------|----------|
| 1 | `http.host eq "old.example.com"` | Set cache TTL | TTL: 3600s |

**Note**: These rules will not take effect because the hostname is not proxied through Cloudflare.
```

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
- **Priority**: Cloudflare rule priority (lower = higher priority)
- **Match Expression**: Full Cloudflare expression
- **Action**: Cache action (e.g., "Set cache TTL", "Bypass cache")
- **Settings**: Cache settings (e.g., "TTL: 3600s", "Edge TTL: 7200s")

### Origin Rules
- **Priority**: Cloudflare rule priority
- **Match Expression**: Full Cloudflare expression
- **Action**: Origin action (e.g., "Override origin", "Override host header")
- **Settings**: Origin settings (e.g., "Host: backend.example.com")

### Redirect Rules
- **Priority**: Cloudflare rule priority
- **Match Expression**: Full Cloudflare expression
- **Target URL**: Redirect target
- **Status Code**: HTTP status code (301, 302, 307, 308)

### URL Rewrite Rules
- **Priority**: Cloudflare rule priority
- **Match Expression**: Full Cloudflare expression
- **Rewrite Action**: Rewrite target (e.g., "/v2/$1")

### Header Transform Rules
- **Priority**: Cloudflare rule priority
- **Match Expression**: Full Cloudflare expression
- **Header Action**: Header operation (e.g., "Set X-Custom: value", "Remove X-Old")

### Compression Rules
- **Priority**: Cloudflare rule priority
- **Match Expression**: Full Cloudflare expression
- **Compression Type**: Compression algorithms (e.g., "Gzip, Brotli")

### Custom Error Rules
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
- **Priority**: Rule priority
- **Source URL**: Source URL pattern
- **Target URL**: Redirect target
- **Status Code**: HTTP status code (301, 302, 307, 308)
- **Include Subdomains**: Whether to include subdomains (Yes/No)
- **Preserve Query String**: Whether to preserve query string (Yes/No)
