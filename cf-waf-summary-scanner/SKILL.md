---
name: cf-waf-summary-scanner
description: Pre-scans the WAF security rules summary to extract a structured rule index (rule_index.json). This is the first validation stage (V0) — it only extracts information, does not validate or modify the summary. Use after cf-waf-analyzer has generated cloudflare-security-rules-summary.md.
---

# WAF Summary Scanner (V0)

Extract a structured rule index from `cloudflare-to-aws-waf/cloudflare-security-rules-summary.md`. This index enables parallel validation by downstream validators.

**This skill ONLY extracts information. It does NOT validate or modify the summary.**

**Language Adaptation**: Write output files in the language specified in the query. Default to English.

## Input

- `cloudflare-to-aws-waf/cloudflare-security-rules-summary.md` — the summary to scan

## Output

- `cloudflare-to-aws-waf/rule_index.json` — structured rule index

## Workflow

### 1. Read Summary

Read `cloudflare-to-aws-waf/cloudflare-security-rules-summary.md` in full.

**If file does not exist:** Stop. Return error: "Summary file not found. Run cf-waf-analyzer first."

### 2. Extract Rule Index

Scan each section of the summary and extract the following for every rule:

**From Section 2 (IP Access Rules):**
For each rule entry:
- `position`: Sequential position within this section (1-based)
- `name`: Rule name or identifier
- `convertibility`: "yes", "partial", or "no"

**From Section 3 (WAF Custom Rules):**
For each rule entry:
- `position`: Sequential position within this section (1-based)
- `name`: Rule name
- `type`: "skip" if the rule's action is Skip, otherwise the action name (e.g., "block", "challenge", "js_challenge", "managed_challenge", "interactive_challenge", "log")
- `convertibility`: "yes", "partial", or "no"
- `labels`: (only for skip rules) Array of RuleLabels listed in the summary (e.g., `["skip:http_ratelimit", "skip:all_remaining_custom_rules"]`)

**From Section 4 (Rate Limiting Rules):**
For each rule entry:
- `position`: Sequential position within this section (1-based)
- `name`: Rule name
- `convertibility`: "yes", "partial", or "no"

**Derive `skip_labels_present`:**
Scan all skip rules' labels and set three boolean flags:
- `all_remaining_custom_rules`: true if ANY skip rule has `skip:all_remaining_custom_rules`
- `http_ratelimit`: true if ANY skip rule has `skip:http_ratelimit`
- `http_request_firewall_managed`: true if ANY skip rule has `skip:http_request_firewall_managed`

### 3. Write rule_index.json

Write the extracted data to `cloudflare-to-aws-waf/rule_index.json` in this exact format:

```json
{
  "ip_access_rules": {
    "count": 20,
    "rules": [
      { "position": 1, "name": "block-cn-ips", "convertibility": "yes" }
    ]
  },
  "custom_rules": {
    "count": 150,
    "skip_labels_present": {
      "all_remaining_custom_rules": true,
      "http_ratelimit": true,
      "http_request_firewall_managed": true
    },
    "rules": [
      { "position": 1, "name": "block-bad-ua", "type": "block", "convertibility": "yes" },
      { "position": 3, "name": "skip-managed-for-office", "type": "skip", "convertibility": "yes", "labels": ["skip:http_request_firewall_managed"] }
    ]
  },
  "rate_limiting_rules": {
    "count": 30,
    "rules": [
      { "position": 1, "name": "rate-limit-api", "convertibility": "yes" }
    ]
  }
}
```

**CRITICAL:** The `count` field MUST equal the length of the `rules` array in each section. If you are unsure about a rule's position or attributes, include it anyway — the orchestrator will run a deterministic count validation script after this step.

### 4. Return Result

```
---RESULT---
STATUS: COMPLETE
OUTPUT_FILES:
  - cloudflare-to-aws-waf/rule_index.json
COUNTS:
  ip_access_rules: <number>
  custom_rules: <number>
  rate_limiting_rules: <number>
---END---
```
