# Output Structure: hostname-based-config-summary.md

## File Structure

```markdown
# Cloudflare CDN Configuration Summary

## Zone Information
- **Zone Domain**: example.com
- **Apex Domain**: example.com

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
| Hostname | Record Type | Value | CNAME Flattening | Content Type | Apply Default Cache Behavior? |
|----------|-------------|-------|------------------|--------------|-------------------------------|
| example.com | CNAME | origin.example.com | No | dynamic / static / mixed | Yes / No |
| www.example.com | CNAME | origin.example.com | No | dynamic / static / mixed | Yes / No |
| cdn.example.com | CNAME | cdn-origin.example.com | No | dynamic / static / mixed | Yes / No |

**Instructions:** For each hostname, edit the columns to keep ONLY your choice (delete the other options).

**Content Type column:**
- `dynamic`: Only serves dynamic content (APIs, server-rendered pages)
- `static`: Only serves static files (images, CSS, JS, fonts)
- `mixed`: Serves both dynamic and static content

**Apply Default Cache Behavior column:**
- `Yes`: Apply Cloudflare's default cache behavior (2-hour TTL for 70+ static file extensions)
- `No`: Do not apply default cache behavior

Example:
```
Before: | example.com | CNAME | origin.example.com | No | dynamic / static / mixed | Yes / No |
After:  | example.com | CNAME | origin.example.com | No | mixed | Yes |
```

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
- CNAME Flattening: No
- Proxied: Yes
- Status: ✅ Convertible
- Total Rules: 5

### Cache Behavior: /api/*
| Rule Type | Priority | Match Expression | Action | Notes |
|-----------|----------|------------------|--------|-------|
| Origin Rule | 1 | `http.request.full_uri wildcard "https://example.com/api/*"` | Override origin: api-backend.example.com | |
| Cache Rule | 2 | `http.host eq "example.com" and http.request.uri.path wildcard "/api/*"` | TTL: 0s | |

### Cache Behavior: /docs/*
| Rule Type | Priority | Match Expression | Action | Notes |
|-----------|----------|------------------|--------|-------|
| Response Header Transform | 1 | `http.host eq "example.com" and http.request.uri.path wildcard "/docs/*"` | Set `X-Custom-Header: value` | |

### Cache Behavior: /old
| Rule Type | Priority | Match Expression | Action | Notes |
|-----------|----------|------------------|--------|-------|
| Redirect Rule | 1 | `http.host eq "example.com" and http.request.uri.path eq "/old"` | `/new` 301 | |

### Cache Behavior: * (Default)
Rules with no convertible path condition (no path, non-convertible path, or hostname-only).

| Rule Type | Priority | Match Expression | Action | Notes |
|-----------|----------|------------------|--------|-------|
| URL Rewrite Rule | 2 | `http.host eq "example.com" and http.request.uri.path matches "^/api/v1/(.*)"` | `/v2/$1` | ⚠️ Non-convertible path |
| Request Header Transform | 3 | `http.host eq "example.com" and http.request.uri.path matches "^/api/.*"` | Set `X-API-Version: 2.0` | ⚠️ Non-convertible path |
| Compression Rule | 4 | `http.host eq "example.com"` | Gzip, Brotli | |
| Custom Error Rule | - | 404 | Custom 404 page | |

---

## DNS Record: api.example.com
[Repeat same structure for each proxied DNS record]

---

## Global Rules (no http.host match)
These rules may apply to multiple DNS records. Grouped by path pattern, same as hostname sections.

### Managed Transforms (Zone-level)
| Transform Type | Enabled |
|----------------|---------|
| True-Client-IP Header | Yes |

### Cache Behavior: /content/*
| Rule Type | Priority | Match Expression | Action | Notes |
|-----------|----------|------------------|--------|-------|
| Cache Rule | 1 | `http.request.uri.path wildcard "/content/*"` | TTL: 3600s | |

### Cache Behavior: * (Default)
| Rule Type | Priority | Match Expression | Action | Notes |
|-----------|----------|------------------|--------|-------|
| Request Header Transform | 1 | `true` | Set `X-CDN-Vendor: CloudFront` | |

---

## Orphaned Rules (Hostname Not in Proxied DNS Records)

These rules reference hostnames that are not proxied. This may indicate outdated or misconfigured rules.

### Hostname: old.example.com (Not Proxied)

#### Cache Behavior: * (Default)
| Rule Type | Priority | Match Expression | Action | Notes |
|-----------|----------|------------------|--------|-------|
| Bulk Redirect | 1 | old.example.com/about | /about-us 301 | |
| Bulk Redirect | 2 | old.example.com/contact | /contact-us 301 | |

**Note**: These rules will not take effect because the hostname is not proxied through Cloudflare. Consider deleting these rules or proxying the hostname.

---

## Custom Pages (Zone-level)

Cloudflare-specific challenge and error page templates. These are zone-level settings and do NOT map to specific hostnames.

| Error Type | State | Custom URL |
|------------|-------|------------|
| basic_challenge | default | (Using Cloudflare default) |
| waf_block | custom | https://example.com/errors/blocked.html |
| 500_errors | default | (Using Cloudflare default) |

**Note**: Custom Pages are Cloudflare-specific and have no direct CloudFront equivalent. They are listed here for reference only. No migration action required.

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

#### Cache Behavior: * (Default)
| Rule Type | Priority | Match Expression | Action | Notes |
|-----------|----------|------------------|--------|-------|
| Bulk Redirect | 1 | old.example.com/about | /about-us 301 | |
| Cache Rule | 2 | `http.host eq "old.example.com"` | TTL: 3600s | |

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

All rules within a hostname or Global Rules section are grouped by Cache Behavior (path pattern), using a unified table format:

### Unified Cache Behavior Table
- **Rule Type**: Type of Cloudflare rule (Cache Rule, Origin Rule, Redirect Rule, URL Rewrite Rule, Request Header Transform, Response Header Transform, Compression Rule, Custom Error Rule, Bulk Redirect)
- **Priority**: Cloudflare rule priority (lower = higher priority). Preserve original order within each rule type. Use `-` for rule types that have no priority (Custom Error Rules).
- **Match Expression**: Full Cloudflare expression. For Custom Error Rules, use the HTTP error code (e.g., `404`, `429`) instead of an expression.
- **Action**: What the rule does (e.g., "Override origin: backend.example.com", "TTL: 0s", "Redirect to /new 301", "Set X-Header: value", "Gzip, Brotli", "Custom XML response")
- **Notes**: Any special conditions, e.g.:
  - `⚠️ Non-convertible path` — path expression uses regex/negation, cannot be a CloudFront path pattern
  - `⚠️ Contains non-path condition` — expression has both a path condition and a non-path condition (geo, IP, UA, etc.)
  - `⚠️ Query string in full_uri` — original expression includes query string condition
  - `⚠️ Overlapping with [pattern]` — this path pattern overlaps with another, ordering matters

### Managed Transforms
Listed separately as zone-level settings (not grouped by path pattern):
- **Transform Type**: Type of managed transform (e.g., "True-Client-IP Header")
- **Enabled**: Whether the transform is enabled (Yes/No)

### Custom Pages
Listed separately as zone-level settings (not grouped by path pattern):
- **Error Type**: Error page type (e.g., "500_errors", "waf_block")
- **State**: "default" or "custom"
- **Custom URL**: URL of custom error page (if state is "custom")
