---
name: cf-waf-analyzer
description: Analyzes Cloudflare security configurations (WAF custom rules, rate limiting rules, IP access rules, IP/ASN lists) and generates structured IR JSON for AWS WAF migration. Use this skill when you need to analyze Cloudflare security rules, understand WAF rule convertibility, or prepare security configuration IR before converting to AWS WAF. This skill reads CloudflareBackup configuration files, parses rule expressions, determines convertibility status, and generates per-batch IR JSON files. This skill does NOT generate Terraform code - it only analyzes and produces structured IR.
---

# Cloudflare WAF Config Analyzer

Analyze Cloudflare security configurations and generate structured IR JSON for AWS WAF migration.

**CRITICAL: When activated, your FIRST action is:**
1. Read the reference documents specified for your batch (Step 0 in Workflow)
2. Then follow Workflow steps sequentially

**DO NOT:**
- Generate Terraform code
- Skip reading reference documents
- Deviate from the Workflow

**Language Adaptation**: Generate output files in the language specified in the query (e.g., "Generate output files in Chinese"). If no language is specified, default to English. Note: JSON field names are always English; only human-readable string values (like `non_convertible_reason`) follow the language setting.

## Path Resolution

Reference files in `references/` directory. User data from path provided by user.

## Output Directory

**All output files will be written to**: `cloudflare-to-aws-waf/` in current working directory.

**File Structure:**
```
cloudflare-to-aws-waf/
├── waf_ir_ip.json       # Batch A1 output
├── waf_ir_custom.json   # Batch A2 output
└── waf_ir_rate.json     # Batch A3 output
```

**CRITICAL**: The output directory `cloudflare-to-aws-waf/` is pre-created by the orchestrator (waf-init.sh). Do NOT create it yourself.

## Scope

**⚠️ CRITICAL: ALL rate-based rules are ALWAYS convertible.** If marking as "cannot convert" due to limit < 10, you're wrong. Read `references/common-mistakes.md` Mistake 0.

**In Scope:** WAF custom rules, rate limiting rules, IP access rules, IP/ASN lists

**Out of Scope:** Redirect/rewrite rules, header transforms, bulk redirects, page rules, Terraform code generation

## Workflow

### 0. Read Reference Documents (CRITICAL - Must be first)

The orchestrator invokes this skill in 3 batches. Each batch processes specific rule types and outputs a specific JSON file.

**Batch A1 (IP Lists + IP Access Rules):**
- Read: `references/field-conversions.md`, `references/non-convertible-rules.md`
- Process: IP-Lists.txt, List-Items-*.txt, IP-Access-Rules.txt
- Output: `waf_ir_ip.json`

**Batch A2 (WAF Custom Rules):**
- Read: ALL 5 reference documents
- Process: WAF-Custom-Rules.txt, IP-Lists.txt, List-Items-*.txt
- Output: `waf_ir_custom.json`

**Batch A3 (Rate Limiting Rules):**
- Read: `references/action-conversions.md`, `references/common-mistakes.md`, `references/non-convertible-rules.md`
- Process: Rate-limits.txt
- Input from query: skip_labels text (e.g., `http_ratelimit=true all_remaining_custom_rules=true http_request_firewall_managed=true`)
- Output: `waf_ir_rate.json`

### 1. Validate Input

Extract the config path from the query — look for any absolute path (starting with `/` or `~`).

**If no path found in query:** STOP immediately. Return error: "Configuration directory path is required."

### 2. Discover and Read Configuration Files

**Step 2.1:** Based on your batch, use glob to find the relevant files:
- **Batch A1**: `**/IP-Lists.txt`, `**/List-Items-*.txt`, `**/IP-Access-Rules.txt`
- **Batch A2**: `**/WAF-Custom-Rules.txt`, `**/IP-Lists.txt`, `**/List-Items-*.txt`
- **Batch A3**: `**/Rate-limits.txt`

**Step 2.2:** If NO relevant configuration files found, STOP: "No configuration files found for this batch."

**Step 2.3:** If duplicate files found (same filename in multiple locations), STOP: "Found duplicate configuration files."

**Step 2.4:** Read all discovered files. For each list in `IP-Lists.txt`, read corresponding `List-Items-ip-<name>.txt` or `List-Items-asn-<name>.txt`.

**Step 2.5:** Missing files = assume no rules of that type. Missing list items = mark rules using that list as "partially convertible".

### 3. Parse Cloudflare Configuration

Parse JSON to Cloudflare rule expressions. Process ALL rules in the file — `managed_challenge` is a valid action to convert (→ AWS WAF `challenge {}`), not a managed ruleset.

**Non-convertible fields** (require manual intervention): Client Certificate Verified, MIME Type, European Union, bot fields (`cf.verified_bot_category`, `cf.bot_management.*`), fraud fields (`cf.waf.credential_check.*`), attack score fields (`cf.waf.score*`)

**Conversion strategy:**
- Only non-convertible fields: Fully non-convertible → `"convertibility": "no"`
- Convertible OR non-convertible: Partial → `"convertibility": "partial"`
- Convertible AND non-convertible: Fully non-convertible → `"convertibility": "no"` (AND requires both)

### 4. Generate IR JSON

**CRITICAL: Preserve Rule Order.** Both Cloudflare and AWS WAF execute rules sequentially. Maintain the exact order from original configuration files. Use `position` field (1-indexed) to record order.

---

#### Batch A1: `waf_ir_ip.json`

```json
{
  "ip_lists": [
    {
      "name": "block_list_1",
      "kind": "ip",
      "conversion": "ip_set",
      "items_ipv4": ["100.0.0.0/24"],
      "items_ipv6": ["2001:db8::/32"]
    },
    {
      "name": "asn_list_1",
      "kind": "asn",
      "conversion": "asn_inline",
      "items": [1234, 5678]
    }
  ],
  "ip_access_rules": {
    "count": 2,
    "rules": [
      {
        "position": 1,
        "name": "block-single-ip",
        "mode": "block",
        "target": "ip",
        "value": "198.51.100.1",
        "convertibility": "yes",
        "aws_statement_type": "ip_set_reference_statement",
        "split_count": 1
      },
      {
        "position": 2,
        "name": "block-mixed-range",
        "mode": "block",
        "target": "ip_range",
        "value": "198.51.100.0/24, 2001:db8::/32",
        "convertibility": "yes",
        "aws_statement_type": "ip_set_reference_statement",
        "split_count": 2,
        "ip_sets": [
          { "name": "block-mixed-range-ipv4", "addresses": ["198.51.100.0/24"] },
          { "name": "block-mixed-range-ipv6", "addresses": ["2001:db8::/32"] }
        ]
      }
    ]
  }
}
```

**IP Lists rules:**
- `kind: "ip"` → `conversion: "ip_set"`, split items into `items_ipv4` and `items_ipv6`
- `kind: "asn"` → `conversion: "asn_inline"`, keep items as integer array
- Empty list → `conversion: "empty"`, no items
- Redirect list → `conversion: "out_of_scope"`

**IP Access Rules:**
- `split_count > 1` and `ip_sets` only when value contains mixed IPv4/IPv6. Most rules have `split_count: 1` with no `ip_sets`.
- `name` = descriptive name derived from the rule (Cloudflare IP Access Rules don't have names — derive from mode + target + value)

**non_convertible_notes** (MANDATORY — output empty array if none). In practice IP Access Rules are always convertible, but include the field for consistency:
```json
{
  "ip_lists": [...],
  "ip_access_rules": {...},
  "non_convertible_notes": []
}
```

---

#### Batch A2: `waf_ir_custom.json`

```json
{
  "custom_rules": {
    "count": 3,
    "skip_labels_present": {
      "all_remaining_custom_rules": false,
      "http_ratelimit": false,
      "http_request_firewall_managed": false
    },
    "rules": [
      {
        "position": 1,
        "name": "block-bad-ua",
        "action": "block",
        "expression": "(http.user_agent contains \"BadBot\")",
        "convertibility": "yes",
        "aws_statement_type": "byte_match_statement",
        "split": {
          "required": false,
          "total_aws_rules": 1
        },
        "scope_down": {
          "skip_all_remaining_custom_rules": false
        }
      }
    ]
  },
  "non_convertible_notes": []
}
```

**skip_labels_present** (MANDATORY — always output all 3 keys):
- Scan all rules for `action: "skip"`. For each skip rule:
  - If `action_parameters.phases` contains `"http_ratelimit"` → `http_ratelimit: true`
  - If `action_parameters.phases` contains `"http_request_firewall_managed"` → `http_request_firewall_managed: true`
  - If `action_parameters.ruleset` is `"current"` → `all_remaining_custom_rules: true`
- If no skip rules exist, all three are `false`.

**For skip action rules**, include additional fields:
```json
{
  "action": "skip",
  "action_parameters": {
    "phases": ["http_request_firewall_managed"],
    "ruleset": "current"
  },
  "labels": [
    "skip:http_request_firewall_managed",
    "skip:all_remaining_custom_rules"
  ]
}
```
- `action_parameters`: copy verbatim from Cloudflare config
- `labels`: derive from action_parameters (phases → skip:{phase}, ruleset:current → skip:all_remaining_custom_rules)
- Only include labels for phases that actually exist — do NOT assume phases

**For rules requiring splitting:**
```json
{
  "split": {
    "required": true,
    "phase1_branches": 2,
    "phase2_ipv4_ipv6": true,
    "total_aws_rules": 3,
    "branches": [
      {
        "branch": 1,
        "aws_statement_type": "ip_set_reference_statement",
        "ip_set_name": "rule-name-branch-1"
      },
      {
        "branch": 2,
        "aws_statement_type": "geo_match_statement"
      }
    ]
  },
  "ip_sets": [
    { "name": "rule-name-branch-1-ipv4", "addresses": ["100.0.0.1/32"] },
    { "name": "rule-name-branch-1-ipv6", "addresses": ["2001:db8::1/128"] }
  ]
}
```

Splitting rules (from `references/nesting-and-splitting.md`):
1. **Phase 1 — Top-level OR**: If expression has top-level OR branches, each branch becomes a separate AWS rule
2. **Phase 2 — IPv4/IPv6**: For each branch referencing IP lists with both IPv4 and IPv6, split into two rules
3. **Cascading count**: total = (branches with mixed IP × 2) + (branches without × 1)
4. **IP Sets**: Separate sets per branch, named `<rule-name>-branch-<N>-ipv4/ipv6`. NEVER combine IPs from different branches.
5. **Rate-limiting rules are NEVER split** — do not add splitting info for them

**scope_down:**
- `skip_all_remaining_custom_rules: true` if this rule's position is after any skip rule that has `skip:all_remaining_custom_rules` label
- Skip rules themselves always have `skip_all_remaining_custom_rules: false`

**Challenge action mapping** — include `aws_action` field when the Cloudflare action differs from the AWS action name:
- `managed_challenge` → `"aws_action": "challenge"`
- `js_challenge` → `"aws_action": "challenge"`
- `interactive_challenge` → `"aws_action": "captcha"`
- `block`, `allow`, `skip`, `challenge` → no `aws_action` field needed (action name maps directly or is handled specially)

**For partial rules**, include:
```json
{
  "convertibility": "partial",
  "convertible_expression": "(http.request.uri.path contains \"/api\")",
  "non_convertible_reason": "cf.bot_management.score — use AWS WAF Bot Control",
  "aws_statement_type": "byte_match_statement"
}
```

**non_convertible_notes** (MANDATORY — output empty array if none):
```json
{
  "non_convertible_notes": [
    {
      "rule": "partial-bot-rule",
      "field": "cf.bot_management.score",
      "reason": "Cloudflare bot scoring is proprietary",
      "aws_equivalent": "AWS WAF Bot Control managed rule group",
      "manual_action": "Enable Bot Control, select protection level"
    }
  ]
}
```

---

#### Batch A3: `waf_ir_rate.json`

**Read skip_labels from query.** The orchestrator embeds a line like:
`Skip labels from custom rules: http_ratelimit=true all_remaining_custom_rules=false http_request_firewall_managed=true`

Parse each `key=value` pair. Use `http_ratelimit` value to fill `scope_down.skip_http_ratelimit` for every rate-limiting rule.

```json
{
  "rate_limiting_rules": {
    "count": 2,
    "rules": [
      {
        "position": 1,
        "name": "rate-limit-api",
        "expression": "(http.request.uri.path contains \"/api\")",
        "convertibility": "yes",
        "requests_per_period": 100,
        "period": 60,
        "aws_limit": 100,
        "aws_evaluation_window_sec": 60,
        "calculation_notes": "60s: 100×(60/60)=100 ≥ 10 ✓",
        "mandatory_fallback": false,
        "scope_down": {
          "skip_http_ratelimit": true
        },
        "aws_statement_type": "byte_match_statement"
      }
    ]
  },
  "non_convertible_notes": []
}
```

**Rate-limit calculation algorithm (CRITICAL):**
1. For EACH window in [60, 120, 300, 600] seconds: `limit = requests_per_period × (window / period)`
2. Use the FIRST window where limit ≥ 10
3. If ALL four windows produce limit < 10: mandatory fallback `aws_limit=10, aws_evaluation_window_sec=600, mandatory_fallback=true`
4. Record calculation for ALL four windows in `calculation_notes`
5. **AWS WAF minimum Limit is 10. NEVER output aws_limit below 10.**

**scope_down.skip_http_ratelimit**: Set to `true` if the skip_labels from query show `http_ratelimit=true`. Set to `false` if `http_ratelimit=false`.

**Rate-limiting rules are NEVER split.** Do not include `split` field.

**For partial rate-limiting rules** (expression contains non-convertible fields):
- `convertibility: "partial"`, include `convertible_expression` and `non_convertible_reason`
- Add entry to `non_convertible_notes`

**non_convertible_notes** (MANDATORY — output empty array if none).

### Return Result

After the JSON file is written, end your response with:

```
---RESULT---
STATUS: COMPLETE
BATCH: <A1|A2|A3>
OUTPUT_FILES:
  - cloudflare-to-aws-waf/<filename>.json
---END---
```
