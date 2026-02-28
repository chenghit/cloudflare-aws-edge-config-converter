---
name: cf-cdn-analyzer-validator
description: Validates the output of cf-cdn-analyzer by cross-checking hostname-based-config-summary.md against the original Cloudflare configuration files. Use this skill after cf-cdn-analyzer has generated its summary. Fixes errors directly in the summary file. Triggers on requests like "validate CDN analysis" or "validate analyzer output".
---

# Cloudflare CDN Analyzer Validator

Validate `cloudflare-cdn-analysis/hostname-based-config-summary.md` by cross-checking it against the original Cloudflare configuration files. Fix errors directly in the summary. Do NOT re-run the full analysis workflow.

**Language Adaptation**: Write output files in the language specified in the query (e.g., "Generate output files in Chinese"). If no language is specified, default to English.

## Input

- `cloudflare-cdn-analysis/hostname-based-config-summary.md` — the file to validate and fix
- Cloudflare configuration directory path (provided in the invocation prompt, same path used by the analyzer, e.g. "Validate CDN analysis in /path/to/cloudflare-config")
- Validation round number (provided in the invocation prompt, e.g. "This is validation round 2")

## Output Directory

All output files written to `cloudflare-cdn-analysis/`.

```
cloudflare-cdn-analysis/
├── hostname-based-config-summary.md   # Modified in-place if issues found
└── validator-report.md                # Validation report (overwrite each round)
```

## Workflow

### 1. Read Inputs

**CRITICAL: The Cloudflare configuration directory path must be provided in the invocation prompt.**

Expected format: "Validate CDN analysis in /path/to/cloudflare-config. This is validation round N."

1. Read `cloudflare-cdn-analysis/hostname-based-config-summary.md`
2. Use glob to find all original Cloudflare configuration files under the provided config path:
   - Zone-level: `**/DNS.txt`, `**/SaaS-Fallback-Origin.txt`, `**/Cache-Rules.txt`, `**/Origin-Rules.txt`, `**/Compression-Rules.txt`, `**/Redirect-Rules.txt`, `**/URL-Rewrite-Rules.txt`, `**/Request-Header-Transform.txt`, `**/Response-Header-Transform.txt`, `**/Custom-Error-Rules.txt`, `**/Custom-Pages.txt`, `**/Managed-Transforms.txt`
   - Account-level: `**/Bulk-Redirect-Rules.txt`, `**/List-Items-redirect-*.txt`
3. Read all found configuration files
4. Note the validation round number from the prompt (default: 1 if not specified)

**If config path not provided in prompt:** Stop immediately. Return error: "Cloudflare configuration directory path is required. The main agent must include the config path in the invocation prompt."

**If `hostname-based-config-summary.md` does not exist:** Stop immediately. Return error: "hostname-based-config-summary.md not found in cloudflare-cdn-analysis/. Run cf-cdn-analyzer first."

**If no original configuration files found:** Stop immediately. Return error: "Original Cloudflare configuration files not found. Provide the same config directory path used with cf-cdn-analyzer."

### 2. Run Validation Checks

Run all checks below. Collect all issues before fixing anything.

---

#### Check 1: Proxied Hostname Count

Count proxied records in `DNS.txt` (records where `proxied: true`, type A, AAAA, or CNAME). DNS-only records (proxied: false) are not in scope — ignore them completely. If the summary contains any non-proxied hostname sections, remove them.

Compare with the number of DNS record sections in the summary.

**Pass condition:** Count matches.

**Fail:** Record the discrepancy. Note which hostnames are missing or extra.

---

#### Check 2: Rule Coverage (No Missing or Extra Rules)

For each rule type file (Cache-Rules.txt, Origin-Rules.txt, Redirect-Rules.txt, URL-Rewrite-Rules.txt, Request-Header-Transform.txt, Response-Header-Transform.txt, Compression-Rules.txt, Custom-Error-Rules.txt), go through every rule in the original file and verify it appears in the summary.

**Excluded from this check:**
- `Bulk-Redirect-Rules.txt` and `List-Items-redirect-*.txt` — verified separately in Check 7 (Bulk Redirects section)
- `Custom-Pages.txt` — zone-level settings, not rules, verified in their own section

For each rule in the original file:
1. Find the corresponding row(s) in the summary by matching the rule's expression against summary rows
2. A rule that was split (OR paths, ≤5 extensions, simple regex OR) will have multiple rows — all must be present
3. A rule with >5 extensions appears as ONE row under `* (Default)` — verify it is there

Then check the reverse: for each row in the summary, verify it corresponds to a rule in the original file. Rows with no matching original rule are extra and must be removed.

**Pass condition:** Every original rule has at least one corresponding summary row; every summary row corresponds to an original rule.

**Fail:** Record which rules are missing from the summary, or which summary rows have no corresponding original rule.

---

#### Check 3: Rule Classification Spot-Check

For each rule type, sample up to 5 rules (or all rules if fewer than 5). For each sampled rule, apply a two-level check:

**Level 1 — Hostname classification:**
```
1. Does expression contain http.host or hostname in http.request.full_uri?
   NO → must be in Global Rules section
   YES → continue

2. Does it use wildcard for all subdomains?
   YES → must be in Global Rules section
   NO → continue

3. Is the specific hostname in proxied DNS records?
   YES → must be under that hostname's DNS Record section
   NO → must be in Orphaned Rules section
```

**Level 2 — Path pattern (Cache Behavior) classification:**

Within the correct hostname section, determine which Cache Behavior the rule belongs to:

**Step 1: Extract path condition from expression**
- `http.request.uri.path eq "/foo"` → exact path `/foo`
- `http.request.uri.path wildcard "/api/*"` → `/api/*`
- `http.request.uri.path.extension eq "css"` → `*.css`
- `starts_with(http.request.uri.path, "/static/")` → `/static/*` (**CONVERTIBLE** — never non-convertible)
- `ends_with(http.request.uri.path, "index.html")` → `*index.html` (**CONVERTIBLE** — never non-convertible)
- `http.request.full_uri wildcard "https://hostname/path/*"` → extract path portion `/path/*` only (ignore hostname and query string)
- No path field in expression → no path condition

**Step 2: Check if path condition is convertible**

**FIRST: If expression uses `matches r"..."`, check for simple regex OR BEFORE deciding non-convertible:**
- **Simple regex OR** (all branches match `^/prefix(.*)` or `^/prefix/(.*)`, no `[...]`/`+`/`{n,m}`/lookaheads): → requires splitting → one row per branch under `### Cache Behavior: /prefix/*`
- **Complex regex** (any branch contains `[...]`, `+`, `{n,m}`, lookaheads, or is not `^/prefix(.*)`): → non-convertible → `* (Default)`

Non-convertible if ANY of:
- Uses `matches r"..."` with complex regex (as defined above)
- Uses `not` on a path condition
- Contains only non-path fields: `ip.src`, `http.user_agent`, `http.cookie`, `http.request.headers`, `http.host` alone, `true`, etc.

**CRITICAL: `starts_with()` and `ends_with()` are ALWAYS convertible.**
- `starts_with(http.request.uri.path, "/foo")` → `/foo*`
- `ends_with(http.request.uri.path, "index.html")` → `*index.html`
If either is placed under `* (Default)` with `⚠️ 非可转换路径`, that is an error — move it to the correct Cache Behavior section.

Requires splitting (not non-convertible):
- Uses `http.request.uri.path.extension in {...}` (multiple extensions):
  - **≤ 5 extensions** → split into one row per extension, each under its own `### Cache Behavior: *.<ext>`
  - **> 5 extensions** → must be under `### Cache Behavior: * (Default)` with note `⚠️ Too many extensions to split into Cache Behaviors — recommend Lambda@Edge`. If it is incorrectly split into individual `*.<ext>` Cache Behaviors, that is an error — consolidate into default.
- OR across multiple paths → split into one row per path
- Uses `matches r"..."` where ALL branches match `^/prefix(.*)` or `^/prefix/(.*)` (simple regex OR) → split into one row per branch, each under `### Cache Behavior: /prefix/*`

**CRITICAL: OR path splitting must be complete.** If a rule expression contains `path wildcard "/a/*" or path wildcard "/b/*"`, the summary MUST have TWO rows for this rule — one under `### Cache Behavior: /a/*` and one under `### Cache Behavior: /b/*`. If only one path is present, that is an error — add the missing row(s).

**CRITICAL: Simple regex OR splitting must be complete.** If a rule uses `matches r"^/a/(.*)|^/b/(.*)"`, the summary MUST have one row per branch. If any branch is missing, that is an error — add the missing row(s).

**CRITICAL: OR expressions where ALL branches share the same path do NOT require splitting.** Extract the path from each OR branch. If all branches have the same path, it must be ONE row under that path's Cache Behavior with `⚠️ Contains non-path condition`. If it is incorrectly placed under `* (Default)` or split into multiple rows, that is an error.

**Step 3: Assign**
- Convertible path → must be under `### Cache Behavior: {path pattern}`
- No path condition OR non-convertible → must be under `### Cache Behavior: * (Default)`
- Mixed (convertible path + non-path condition like geo/IP/UA) → must be under `### Cache Behavior: {path pattern}` with `⚠️ Contains non-path condition` note

**Pass condition:** Each sampled rule is in the correct hostname section AND the correct Cache Behavior subsection.

**Fail:** Record the rule expression, its current location, and where it should be.

**Special cases:**
- Bulk Redirects: must be in their own `## Bulk Redirects (Zone-level)` section — do NOT check hostname or path classification for bulk redirects
- Managed Transforms: always Global Rule, not grouped by path pattern (separate zone-level table)
- Custom Pages: always in their own `## Custom Pages (Zone-level)` section

---

#### Check 4: Rule Priority Order

Within each Cache Behavior section, verify that rules appear in ascending priority order (priority 1 first, then 2, then 3...). Priority ordering is per rule type within a Cache Behavior — e.g., all Cache Rules in a behavior should be in order, all Redirect Rules in order, etc.

**Pass condition:** Rules are in correct priority order within each section.

**Fail:** Record which section and rule type has incorrect ordering.

---

#### Check 5: IP-Based Origin Detection

For each proxied A or AAAA record in DNS.txt, verify it appears in the "Non-Convertible Items → IP-Based Origins" section of the summary.

**Pass condition:** All IP-based origins are listed as non-convertible.

**Fail:** Record which hostnames are missing from the non-convertible section.

---

#### Check 6: Orphaned Rule Detection

For each rule that references a specific hostname, verify that hostname exists in the proxied DNS records. If not, the rule must be in the "Orphaned Rules" section.

**Pass condition:** No specific-hostname rules are incorrectly placed under a DNS record section when that hostname is not proxied.

**Fail:** Record the misplaced rules.

---

#### Check 7: Bulk Redirects Coverage

For each entry in `Bulk-Redirect-Rules.txt` and referenced `List-Items-redirect-*.txt`, verify it appears in the `## Bulk Redirects (Zone-level)` section of the summary with correct source URL, target URL, status code, `include_subdomains` flag, and query string preservation.

**Pass condition:** Every bulk redirect entry is present in the Bulk Redirects section; no extra entries exist.

**Fail:** Record missing or extra bulk redirect entries.

---

### 3. Determine Status

- **PASS**: All checks passed. No changes needed.
- **FIXED**: One or more checks failed. Fix the issues directly in `hostname-based-config-summary.md`, then set status to FIXED.
- **CANNOT_FIX**: Issues found that cannot be resolved by editing the summary (e.g., the original config files are ambiguous or contradictory). List these issues for user review.

### 4. Fix Issues (if FIXED)

For each issue found:

- **Missing hostname section**: Add the DNS record section with its rules extracted from the original config files, grouped by Cache Behavior path pattern.
- **Extra hostname section**: Remove the section (hostname not in proxied DNS records).
- **Missing or extra rules**: Add missing rules or remove extra rows. Place each rule in the correct Cache Behavior section based on hostname and path pattern classification.
- **Misclassified rule (wrong hostname section)**: Move the rule to the correct section (Global / Specific / Orphaned).
- **Misclassified rule (wrong Cache Behavior)**: Move the rule to the correct `### Cache Behavior: {pattern}` subsection within the correct hostname section.
- **Missing rule split**: If a rule with OR paths or multiple extensions is not split, split it into separate rows under the appropriate Cache Behavior sections.
- **Wrong priority order**: Reorder rows within the Cache Behavior section.
- **Missing IP-based origin**: Add the hostname to the Non-Convertible Items section.

After all fixes, re-read the modified summary and verify the fixed checks pass before writing the report.

### 5. Write Validator Report

Write `cloudflare-cdn-analysis/validator-report.md` (overwrite if exists):

```markdown
# Validator Report
Validation Round: {N}
Status: PASS | FIXED | CANNOT_FIX

## Current Issues
{Empty if PASS. List unresolved issues if CANNOT_FIX.}

## Changes Made This Round
{Empty if PASS. List each fix applied if FIXED.}
- Example: Moved rule `http.host eq "cdn.example.com"` from Global Rules to DNS Record: cdn.example.com (Cache Rules)
- Example: Added missing hostname section for www.example.com (2 Cache Rules, 1 Redirect Rule)

## Cannot Fix (Requires User Action)
{Empty unless CANNOT_FIX. Describe what the user needs to do manually.}

## Changelog
{Append one line per round, newest first}
- Round {N}: {PASS | FIXED (X issues) | CANNOT_FIX (X issues)} — {one-sentence summary of what was fixed or what cannot be fixed, e.g. "added missing Custom Error Rules section" or "moved 2 misclassified rules to Global Rules"}
- Round {N-1}: ...
```

**CRITICAL**: Preserve the existing Changelog section from the previous report when overwriting. Read the old report first, extract the Changelog, append the new entry, then write the new report.

### 6. Return Result

End your response with this exact block:

```
---RESULT---
STATUS: PASS | FIXED | CANNOT_FIX
OUTPUT_FILES:
  - cloudflare-cdn-analysis/validator-report.md
NEXT_ACTION: Proceed to user review | Run validator again | Request user input
ISSUES_COUNT: {number of issues found, 0 if PASS}
---END---
```
