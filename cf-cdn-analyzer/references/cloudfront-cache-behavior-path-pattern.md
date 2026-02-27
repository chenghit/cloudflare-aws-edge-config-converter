# CloudFront Cache Behavior and Path Pattern

## Why Group Rules by Path Pattern

CloudFront's configuration model is fundamentally different from Cloudflare's.

**Cloudflare:** Rules are independent. Each rule has its own match expression and action. Multiple rules can match the same request and execute in sequence.

**CloudFront:** Everything is attached to a Cache Behavior. A Cache Behavior is the atomic configuration unit of a CloudFront Distribution. It defines:
- Which origin to use
- Which Cache Policy to apply (including compression settings)
- Which Origin Request Policy to apply
- Which Response Headers Policy to apply
- Which CloudFront Functions or Lambda@Edge to invoke
- TTL settings, HTTPS policy, allowed methods, etc.

A Cache Behavior is selected by matching the request URI path against a **path pattern**. The first matching path pattern wins.

**Consequence for migration:** Rules that apply to the same path pattern must be grouped together — they will all be implemented within the same Cache Behavior. Rules that apply to different path patterns require separate Cache Behaviors.

**The Analyzer's job is only to group rules by Cache Behavior (path pattern). It does NOT decide how to implement each rule within the Cache Behavior — that is the Planner's job.**

This is why the Analyzer must group rules by path pattern within each hostname, not just by hostname.

---

## CloudFront Path Pattern Specification

Source: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/DownloadDistValuesCacheBehavior.html

### Allowed Characters

- Letters: `A-Z`, `a-z` (case-sensitive)
- Digits: `0-9`
- Special: `_ - . * $ / ~ " ' @ : +`
- Ampersand: `&` (encoded as `&amp;` in transit)

**Not supported:** Regular expressions, character classes, anchors, or any other regex syntax.

### Wildcard Characters

| Character | Meaning |
|-----------|---------|
| `*` | Matches 0 or more characters (including `/`) |
| `?` | Matches exactly 1 character |

### Constraints

- Maximum length: **255 characters**
- Case-sensitive: `*.jpg` does NOT match `LOGO.JPG`
- Query strings and cookies are ignored during path matching
- The default cache behavior always uses `*` and cannot be changed
- Path normalization: CloudFront normalizes URIs per RFC 3986 before matching (removes `//`, `.`, etc.)

---

## Converting Cloudflare Expressions to Path Patterns

### Convertible Patterns

| Cloudflare Expression | CloudFront Path Pattern |
|----------------------|------------------------|
| `http.request.uri.path eq "/about"` | `/about` |
| `http.request.uri.path wildcard "/api/*"` | `/api/*` |
| `http.request.uri.path wildcard "/images/*.jpg"` | `/images/*.jpg` |
| `http.request.uri.path.extension eq "css"` | `*.css` |
| `starts_with(http.request.uri.path, "/static/")` | `/static/*` |
| `ends_with(http.request.uri.path, "index.html")` | `*index.html` |
| `http.request.full_uri wildcard "https://hostname/path/*"` | `/path/*` (extract path portion only) |

### Non-Convertible Path Conditions

These Cloudflare path expressions **cannot** be directly represented as a CloudFront path pattern. Rules using these are grouped under the **default behavior (`*`)**.

| Cloudflare Expression | Reason |
|----------------------|--------|
| `http.request.uri.path matches r"^/api/v[0-9]+/"` | Regex not supported |
| `not http.request.uri.path wildcard "/api/*"` | Negation not supported |

### Requires Splitting (Convertible After Split)

These expressions cannot map to a single path pattern but can be converted after splitting into multiple rules. Each split produces a separate Cache Behavior. **The original file counts as 1 rule, but the summary will have multiple rows.**

| Cloudflare Expression | How to Handle |
|----------------------|---------------|
| `http.request.uri.path.extension in {"jpg" "png" "gif"}` | Split into `*.jpg`, `*.png`, `*.gif` — each becomes a separate Cache Behavior |
| `http.request.uri.path.extension in {"jpg" "png" ... }` (> 5 extensions) | Too many to split — place under `* (Default)` with note `⚠️ Too many extensions to split into Cache Behaviors — recommend Lambda@Edge` |
| `path eq "/a" or path eq "/b"` | Split into `/a` and `/b` — each becomes a separate Cache Behavior |
| `http.request.uri.path matches r"^/foo/(.*)"` with multiple branches separated by `\|` | Simple regex OR with `^/prefix/(.*)` branches — split into `/foo/*`, `/bar/*` — each becomes a separate Cache Behavior |

**Simple regex OR pattern (convertible):** A `matches r"..."` expression is convertible if ALL of the following are true:
1. The regex consists of multiple branches separated by `|`
2. Every branch matches the pattern `^/prefix(.*)` or `^/prefix/(.*)`
3. No branch contains character classes `[...]`, quantifiers `+`, `{n,m}`, lookaheads, or other complex regex syntax

If any branch fails these conditions, the entire expression is non-convertible → default behavior (`*`).

### No Path Condition

Rules whose match expression contains no path condition at all (hostname-only, IP, geo, user-agent, cookie, header, `true`, etc.) belong to the **default behavior (`*`)**.

---

## Path Pattern Grouping Algorithm

For each rule within a hostname, determine its Cache Behavior group:

**Step 1: Extract path condition**

Look for path-related fields in the expression:
- `http.request.uri.path eq "..."` → exact path
- `http.request.uri.path wildcard "..."` → wildcard path
- `http.request.uri.path.extension eq "..."` → `*.<ext>`
- `starts_with(http.request.uri.path, "/foo/")` → `/foo/*` (**CONVERTIBLE** — do NOT mark as non-convertible)
- `ends_with(http.request.uri.path, "index.html")` → `*index.html` (**CONVERTIBLE** — do NOT mark as non-convertible)
- `http.request.full_uri wildcard "https://hostname/path/*"` → extract `/path/*`

**Step 2: Check convertibility**

If the path condition uses regex (`matches r"..."`), check if it is a simple OR pattern:
- **Simple regex OR** (all branches match `^/prefix(.*)` or `^/prefix/(.*)`): → requires splitting → split into one row per branch
- **Complex regex** (contains character classes, quantifiers, lookaheads, etc.): → non-convertible → default behavior (`*`)

If the path condition uses multiple extensions (`extension in {...}`):
- **≤ 5 extensions** → split into separate rows, one per extension
- **> 5 extensions** → assign to default behavior (`*`) with note `⚠️ Too many extensions to split into Cache Behaviors — recommend Lambda@Edge`

If the path condition uses OR across multiple distinct paths → split into separate rows, one per path.

If the path condition uses simple regex OR (all branches match `^/prefix(.*)`) → split into separate rows, one per branch.

**CRITICAL: OR path splitting is mandatory.** `path wildcard "/a/*" or path wildcard "/b/*"` MUST produce TWO rows — one under `### Cache Behavior: /a/*` and one under `### Cache Behavior: /b/*`. Never assign only the first path and drop the rest.

**CRITICAL: OR expressions where ALL branches share the same path do NOT require splitting.** First extract the path from each OR branch. If all branches have the same path, it is ONE rule under that path's Cache Behavior with `⚠️ Contains non-path condition`. Example:
```
http.request.uri.path eq "/welcome.html" and ip.src.country eq "CN"
or http.request.uri.path eq "/welcome.html" and ip.src.country eq "DE"
```
→ ONE row under `### Cache Behavior: /welcome.html`, note `⚠️ Contains non-path condition`. Do NOT split.

If there is no path condition → default behavior (`*`).

**CRITICAL: `starts_with()` and `ends_with()` are ALWAYS convertible.**
- `starts_with(http.request.uri.path, "/foo")` → `/foo*`
- `ends_with(http.request.uri.path, "index.html")` → `*index.html`
Never classify these as non-convertible.

**Step 3: Assign to group**

- Convertible path condition → assign to that path pattern
- No path condition or non-convertible → assign to default behavior (`*`)

**Step 4: Handle mixed conditions (path + non-path)**

If a rule has both a convertible path condition AND a non-path condition (e.g., `path wildcard "/api/*" and ip.src.country eq "CN"`):
- Assign to the path pattern group (`/api/*`)
- Mark the non-path condition with a note: "⚠️ Contains non-path condition"

**Step 5: Handle `http.request.full_uri` with query string**

If the expression is `http.request.full_uri wildcard "https://hostname/path/*?key=value"`:
- Extract path portion only: `/path/*`
- Mark with a note: "⚠️ Original expression includes query string condition — query string handling may require Cache Policy or Origin Request Policy"

---

## Special Cases

### Overlapping Path Patterns

When multiple rules produce path patterns where one contains the other (e.g., `/api/*` and `/api/v2/*`), both are valid Cache Behaviors. Note them in the output so the Planner can determine the correct ordering.

Example:
```
/api/v2/*   ← must be listed BEFORE /api/* in CloudFront
/api/*
```

Mark overlapping patterns with: "⚠️ Overlapping with [other pattern] — ordering matters"

### Bulk Redirects with `include_subdomains: true`

If a Bulk Redirect has `include_subdomains: true` and the source is an apex domain (e.g., `example.com/path`), it applies to all subdomains → treat as a **Global Rule** and group by path pattern within the Global Rules section.

### Multiple Extensions (`extension in {...}`)

- **≤ 5 extensions**: Split into separate rows, one per extension. Each copy gets the same action as the original rule.
  - `extension in {"jpg" "png" "gif"}` → Row 1: `*.jpg`, Row 2: `*.png`, Row 3: `*.gif`
- **> 5 extensions**: Too many Cache Behaviors — place under `* (Default)` with note `⚠️ Too many extensions to split into Cache Behaviors — recommend Lambda@Edge`

---

## Output Structure Within Each Hostname Section

All rule types (Cache Rules, Origin Rules, Redirect Rules, URL Rewrite Rules, Header Transform Rules, Compression Rules, Custom Error Rules) are grouped by Cache Behavior, not by rule type.

```markdown
## DNS Record: example.com

### Cache Behavior: /api/*
| Rule Type | Priority | Match Expression | Action | Notes |
|-----------|----------|------------------|--------|-------|
| Origin Rule | 1 | `...` | Override origin: api-backend.example.com | |
| Cache Rule | 1 | `...` | TTL: 0s | |
| Request Header Transform | 1 | `... and ip.src.country eq "CN"` | Set X-Region: CN | ⚠️ Contains non-path condition |

### Cache Behavior: /static/*
| Rule Type | Priority | Match Expression | Action | Notes |
|-----------|----------|------------------|--------|-------|
| Cache Rule | 1 | `...` | TTL: 86400s | |
| Compression Rule | 1 | `...` | Brotli + Gzip | |

### Cache Behavior: * (Default)
Rules with no convertible path condition.

| Rule Type | Priority | Match Expression | Action | Notes |
|-----------|----------|------------------|--------|-------|
| Request Header Transform | 1 | `true` | Set X-CDN-Vendor: CloudFront | |
| Redirect Rule | 1 | `ip.src.country eq "CN"` | Redirect to /cn/ | |
| Cache Rule | 1 | `http.request.uri.path matches r"^/v[0-9]+"` | TTL: 300s | ⚠️ Non-convertible path |
```
