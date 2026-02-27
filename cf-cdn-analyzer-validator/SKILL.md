---
name: cf-cdn-analyzer-validator
description: Validates the output of cf-cdn-analyzer by cross-checking hostname-based-config-summary.md against the original Cloudflare configuration files. Use this skill after cf-cdn-analyzer has generated its summary. Fixes errors directly in the summary file. Triggers on requests like "validate CDN analysis" or "validate analyzer output".
---

# Cloudflare CDN Analyzer Validator

Validate `cloudflare-cdn-analysis/hostname-based-config-summary.md` by cross-checking it against the original Cloudflare configuration files. Fix errors directly in the summary. Do NOT re-run the full analysis workflow.

**Language Adaptation**: Write output files in the same language as the user's conversation.

## Input

- `cloudflare-cdn-analysis/hostname-based-config-summary.md` — the file to validate and fix
- Original Cloudflare configuration files (same path used by the analyzer)
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

1. Read `cloudflare-cdn-analysis/hostname-based-config-summary.md`
2. Use glob to find all original Cloudflare configuration files (same patterns as analyzer):
   - Zone-level: `**/DNS.txt`, `**/SaaS-Fallback-Origin.txt`, `**/Cache-Rules.txt`, `**/Origin-Rules.txt`, `**/Compression-Rules.txt`, `**/Redirect-Rules.txt`, `**/URL-Rewrite-Rules.txt`, `**/Request-Header-Transform.txt`, `**/Response-Header-Transform.txt`, `**/Custom-Error-Rules.txt`, `**/Custom-Pages.txt`, `**/Managed-Transforms.txt`
   - Account-level: `**/Bulk-Redirect-Rules.txt`, `**/List-Items-redirect-*.txt`
3. Read all found configuration files
4. Note the validation round number from the prompt (default: 1 if not specified)

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

#### Check 2: Rule Count Per Hostname

For each rule type file (Cache-Rules.txt, Origin-Rules.txt, Redirect-Rules.txt, URL-Rewrite-Rules.txt, Request-Header-Transform.txt, Response-Header-Transform.txt, Compression-Rules.txt, Custom-Error-Rules.txt), count the total number of rules.

**Custom Pages (`Custom-Pages.txt`) are NOT rules — they are zone-level settings. They must appear in their own `## Custom Pages (Zone-level)` section and are NOT counted in the rule total. Do NOT add Custom Pages to the Non-Convertible Items section.**

Compare with the total number of rows across all sections (Specific + Global + Orphaned) in the summary for that rule type.

**Pass condition:** Total rule count matches for each rule type.

**Fail:** Record which rule type has a count mismatch and by how much.

---

#### Check 3: Rule Classification Spot-Check

For each rule type, sample up to 5 rules (or all rules if fewer than 5). For each sampled rule, apply the classification algorithm:

```
1. Does expression contain http.host or hostname in http.request.full_uri?
   NO → must be Global Rule
   YES → continue

2. Does it use wildcard for all subdomains?
   (patterns: *.example.com, .*\.example\.com, .*\\.example\\.com)
   YES → must be Global Rule
   NO → continue

3. Is the specific hostname in proxied DNS records?
   YES → must be Specific Rule under that hostname
   NO → must be Orphaned Rule
```

**Pass condition:** Each sampled rule is in the correct section.

**Fail:** Record the rule expression, its current location in the summary, and where it should be.

**Special cases:**
- Bulk Redirects: extract hostname from source URL, apply same algorithm
- Managed Transforms: always Global Rule
- Custom Pages: always in their own section (not Global or Specific)

---

#### Check 4: Rule Priority Order

For each hostname section and each rule type, verify that rules appear in ascending priority order (priority 1 first, then 2, then 3...).

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

### 3. Determine Status

- **PASS**: All checks passed. No changes needed.
- **FIXED**: One or more checks failed. Fix the issues directly in `hostname-based-config-summary.md`, then set status to FIXED.
- **CANNOT_FIX**: Issues found that cannot be resolved by editing the summary (e.g., the original config files are ambiguous or contradictory). List these issues for user review.

### 4. Fix Issues (if FIXED)

For each issue found:

- **Missing hostname section**: Add the DNS record section with its rules extracted from the original config files.
- **Extra hostname section**: Remove the section (hostname not in proxied DNS records).
- **Rule count mismatch**: Find the missing/extra rules by comparing summary rows against original config file entries. Add missing rules or remove extra rows.
- **Misclassified rule**: Move the rule to the correct section (Global / Specific / Orphaned).
- **Wrong priority order**: Reorder rows within the section.
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
