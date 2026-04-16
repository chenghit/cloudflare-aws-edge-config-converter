# Design: Per-Domain WebACL with Host-Based Rule Splitting

Author: chenghit
Date: 2026-04-16
Status: Draft (v5)

## Problem

### 1. IP set reference limit exceeded

A real customer's Cloudflare config uses extensive inline IP lists in custom rules. The current pipeline creates all IP sets globally and references them from 2 fixed WebACLs. With 60+ inline IP sets, each WebACL references all of them, exceeding the AWS WAF hard limit of **50 IP set + regex set references per WebACL**.

### 2. All rules duplicated to both WebACLs

The current pipeline creates 2 WebACLs (website vs API/file) with **identical rules**. Every rule — including host-specific ones — is duplicated. This wastes IP set references and WCU.

### 3. No host-aware rule placement

Rules like `biz-callback-skip` (applies only to `biz-callback*` domains) are placed in all WebACLs, even those bound to unrelated domains like `cdn.c.letsmakeit.link`.

### 4. Missing security features

No search engine labeling rule, no always-on challenge for landing pages, no per-domain-type Anti-DDoS configuration.

## Solution

### Core change: one WebACL per domain

Each proxied domain gets its own CloudFront distribution (CDN pipeline) and its own WebACL. A domain's WebACL contains only:
- Global rules (no host condition)
- Rules whose host condition matches that domain
- Host-specific OR branches extracted from multi-domain rules

This eliminates the IP set reference problem: each WebACL only references IP sets from its applicable rules.

### New pipeline flow

```
waf-pipeline.sh calls in sequence:
  A1: waf-analyze-ip.py        → waf_ir_ip.json          (unchanged)
  A2: waf-analyze-custom.py    → waf_ir_custom.json       (add host extraction)
  A3: waf-analyze-rate.py      → waf_ir_rate.json         (unchanged)
  merge: waf-merge-ir.py       → waf_ir.json              (unchanged)
  count: waf-count-validate.py  → count check             (unchanged)
  validate: waf-validate-ir.py → round-trip + consistency  (unchanged)
  NEW: waf-check-split.py      → decides split mode        (auto, no user input)
  IF split needed:
    NEW: waf-split-by-host.py  → waf_ir_split.json        (host-based splitting)
  generate: waf-generate-cfn.py → waf-cloudformation.json  (per-domain or 2-WebACL)
  readme: waf-generate-readme.py → README                  (updated)
```

The pipeline remains fully deterministic Python, zero LLM, **zero user input**.

### Auto-split and dedup decision (no user input)

The pipeline automatically decides split mode and dedup based on IP set counts. Three-step decision tree:

```
Step 1: total_ip_sets (named + inline) <= 50?
  → YES: legacy mode (2 WebACLs), no dedup. DONE.
  → NO:  proceed to Step 2.

Step 2: split per-domain.
  → Verify each domain's IP set reference count <= 50 (should always pass after split).
  → Proceed to Step 3.

Step 3: inline IP set count (excluding named lists) > 100?
  → YES: cross-rule dedup (merge inline IP sets with identical content). 
  → NO:  no dedup. DONE.
```

**Step 1** uses total IP sets (named + inline) because the 50 limit is per-WebACL references and both types count. **Step 3** only checks inline IP sets because named lists (account-level) are user-managed and must not be merged.

Split per-domain does NOT increase IP set resource count — inline IP sets are created as CloudFormation resources once, and multiple WebACLs reference the same resource via `Fn::GetAtt`.

IP set count formula:
```python
def count_ip_sets(ir):
    """Count total IP set resources (named + inline). Used for Step 1 (50 limit)."""
    count = 0
    # Named IP lists: each may produce IPv4 + IPv6 = up to 2 IP sets
    for lst in ir.get("ip_lists", []):
        if lst.get("conversion") == "ip_set":
            if lst.get("items_ipv4"): count += 1
            if lst.get("items_ipv6"): count += 1
        # ASN lists use AsnMatchStatement, not IP sets — don't count
    # Inline IP sets (unique by content)
    seen = set()
    for section in ("ip_access_rules", "custom_rules", "rate_limiting_rules"):
        for rule in ir.get(section, {}).get("rules", []):
            for ipset in rule.get("ip_sets", []):
                addrs = tuple(sorted(ipset.get("addresses", [])))
                version = "IPV6" if any(is_ipv6(a) for a in addrs) else "IPV4"
                key = (version, addrs)
                if key not in seen:
                    seen.add(key)
                    count += 1
    return count

def count_inline_ip_sets(ir):
    """Count inline IP sets only (excluding named lists). Used for Step 3 (100 limit)."""
    seen = set()
    for section in ("ip_access_rules", "custom_rules", "rate_limiting_rules"):
        for rule in ir.get(section, {}).get("rules", []):
            for ipset in rule.get("ip_sets", []):
                addrs = tuple(sorted(ipset.get("addresses", [])))
                version = "IPV6" if any(is_ipv6(a) for a in addrs) else "IPV4"
                key = (version, addrs)
                seen.add(key)
    return len(seen)
```

No user input needed. No domain type classification. No pipeline pause.

When split mode is active, **all domains get the same security configuration**: default Anti-DDoS AMR (challenge enabled) + search engine labeling + always-on challenge (Count action). The deployment guide tells users how to customize per-domain after deployment (disable challenge for API-only domains, exclude API paths for mixed domains).

## Detailed Design

### 1. Host extraction in analyzer (waf-analyze-custom.py)

After parsing the expression into a condition tree, extract host scope per rule:

```python
def extract_host_scope(cond):
    """Returns dict with host info for the rule.
    
    Returns:
        {
            "type": "global" | "single_host" | "multi_host" | "contains",
            "hosts": ["domain1", "domain2"],        # for single/multi/in
            "contains": ["keyword"],                 # for contains
            "branches": [                            # for OR rules with per-branch hosts
                {"host": "domain1", "host_op": "eq", "condition": <subtree>},
                {"host": None, "host_op": None, "condition": <subtree>},  # global branch
            ]
        }
    """
```

The condition tree already has `field: "http.host"` nodes. Walk the tree:

- **Top-level OR**: each OR branch may have a different host. Extract per-branch.
- **Top-level AND with host**: single host applies to entire rule.
- **No host field**: global rule.
- **`eq` operator**: exact match → `single_host`, `hosts: ["domain"]`.
- **`in` operator**: set match → `multi_host`, `hosts: ["d1", "d2", "d3"]`. Parse the value string `{"d1" "d2" "d3"}` to extract domain list.
- **`contains` operator**: keyword match → `contains`, applies to all domains containing that keyword.

**IP Access Rules**: These have no host condition (zone-wide). `waf-split-by-host.py` treats any rule missing `host_scope` as `{"type": "global"}` — no changes needed to `waf-analyze-ip.py`.

Store in IR as `host_scope` field on each rule.

### 2. Rule splitting (waf-split-by-host.py)

New script. Input: `waf_ir.json` + `config_path` (to read DNS.txt). Output: `waf_ir_split.json`.

**Domain list source**: `waf-split-by-host.py` reads DNS.txt from `config_path`, extracts all **proxied** A/AAAA/CNAME records' hostnames. Only proxied domains get CloudFront distributions and therefore need WebACLs. Non-proxied records are ignored.

```python
def extract_proxied_domains(config_path):
    """Read DNS.txt, return list of proxied hostnames."""
    dns_path = find_file(config_path, "DNS.txt")
    with open(dns_path) as f:
        data = json.load(f)
    return sorted(set(
        r["name"] for r in data["result"]
        if r.get("proxied") and r["type"] in ("A", "AAAA", "CNAME")
    ))
```

For each domain, determine which rules apply:

```python
def rules_for_domain(all_rules, domain):
    """Return list of rules applicable to this domain, with conditions adjusted."""
    result = []
    for rule in all_rules:
        scope = rule["host_scope"]
        
        if scope["type"] == "global":
            # No host condition → applies to all domains
            result.append(rule)  # keep original conditions
            
        elif scope["type"] == "single_host":
            if scope["hosts"][0] == domain:
                # Strip host condition (redundant — WebACL only serves this domain)
                result.append(strip_host_condition(rule))
                
        elif scope["type"] == "multi_host":
            if domain in scope["hosts"]:
                # Strip host condition for this domain
                result.append(strip_host_condition_for_domain(rule, domain))
                
        elif scope["type"] == "contains":
            for keyword in scope["contains"]:
                if keyword in domain:
                    result.append(strip_host_condition(rule))  # strip host contains (redundant)
                    break
                    
        elif scope["type"] == "branched":
            # OR rule with per-branch hosts — extract applicable branches
            applicable_branches = []
            for branch in scope["branches"]:
                if branch["host"] is None:  # global branch
                    applicable_branches.append(branch["condition"])
                elif branch["host"] == domain:
                    applicable_branches.append(strip_host_from_branch(branch["condition"]))
                elif branch.get("host_op") == "contains" and branch["host"] in domain:
                    applicable_branches.append(strip_host_from_branch(branch["condition"]))
            
            if applicable_branches:
                new_rule = copy_rule_with_branches(rule, applicable_branches)
                result.append(new_rule)
    
    return result
```

**Stripping host conditions**: When a WebACL only serves one domain, `http.host eq "domain"` is always true and can be removed. This simplifies the statement and reduces nesting depth.

- `AND(host eq "d", other_cond)` → `other_cond` (strip host, keep rest)
- `AND(host eq "d", uri contains "/path", ip in {…})` → `AND(uri contains "/path", ip in {…})`
- If stripping leaves a single-element AND → unwrap to the single element
- If branched OR extraction leaves a single applicable branch → unwrap (no OR wrapper). `copy_rule_with_branches(rule, [single])` must return the single branch's condition directly, not `{"op": "or", "items": [single]}`.

**Branched OR rules** (like `biz-callback-skip`):

Original:
```
OR(
  AND(host contains "biz-callback", ip in {5 IPs}),
  AND(host eq "biz-callback-stg...", uri contains "/xapi/docusign/webhook", ip in {19 IPs}),
  AND(host eq "biz-callback...", uri contains "/xapi/docusign/webhook", ip in {10 IPs}),
  AND(host eq "biz-callback-stg...", uri contains "/xapi/tiger/token", ip in {2 IPs}),
  AND(host eq "biz-callback-loadtest...", uri contains "/xapi/tiger/token", ip in {2 IPs})
)
```

For `biz-callback.c.letsmakeit.link`:
- Branch 1 matches (contains "biz-callback") → keep, strip host
- Branch 3 matches (eq exact) → keep, strip host
- Branches 2, 4, 5 don't match → drop

Result:
```
OR(
  ip in {5 IPs},
  AND(uri contains "/xapi/docusign/webhook", ip in {10 IPs})
)
```

Only 2 IP sets instead of 5.

### 3. IP set deduplication (waf-generate-cfn.py)

**Only runs when inline IP set count > 100** (Step 3 of the decision tree). Named lists (account-level) are never merged.

When dedup is active, inline IP sets with identical `(IPAddressVersion, sorted(Addresses))` across different rules share one CloudFormation resource.

```python
def deduplicate_inline_ip_sets(all_rules):
    """Merge inline IP sets with identical content. Named lists are excluded.
    
    Returns:
        ip_set_resources: dict of logical_id → CloudFormation resource
        ip_set_map: dict of original_name → logical_id
    """
    content_to_id = {}  # (version, tuple(sorted(addrs))) → logical_id
    ip_set_map = {}
    resources = {}
    
    for rule in all_rules:
        for ipset in rule.get("ip_sets", []):
            addrs = tuple(sorted(ipset["addresses"]))
            version = "IPV6" if any(is_ipv6(a) for a in addrs) else "IPV4"
            key = (version, addrs)
            
            if key in content_to_id:
                ip_set_map[ipset["name"]] = content_to_id[key]
            else:
                lid = unique_id(f"IPSet{ipset['name']}")
                content_to_id[key] = lid
                ip_set_map[ipset["name"]] = lid
                resources[lid] = build_ip_set_resource(ipset, version)
    
    return resources, ip_set_map
```

When dedup is NOT active, each inline IP set gets its own CloudFormation resource (current behavior). `ip_set_map` maps each name to its own unique logical ID — no merging.

**Important**: `conditions_to_statement()` must use `ip_set_map` to resolve `_ip_set_names` annotations to CloudFormation logical IDs. The existing `inline_ip_set_ids` dict in `conditions_to_statement()`'s context must be populated from `ip_set_map`. This ensures that when dedup is active, merged IP sets get the same `Fn::GetAtt` reference.

### 4. Per-domain WebACL generation (waf-generate-cfn.py)

Replace the current `build_webacl()` × 2 with a loop over domains:

```python
if mode == "legacy":
    # Current behavior: 2 WebACLs, all rules duplicated
    # Website WebACL: inject search engine label + Anti-DDoS with scope-down + always-on challenge
    website_injected = [
        build_search_engine_label_rule(priority=0),
        build_anti_ddos_rule(priority=1, scope_down_exclude_labels=["awswaf:search-engine"]),
    ]
    website_rules = website_injected + all_rules
    # Insert always-on challenge after rate-limiting rules
    rate_end = find_rate_rule_end(website_rules)
    website_rules.insert(rate_end, build_always_on_challenge_rule())
    website_rules.extend(managed_rules)
    resources["WebACLWebsite"] = build_webacl("waf-website", website_rules)
    
    # API/File WebACL: Anti-DDoS with challenge disabled, no search engine label, no always-on challenge
    api_rules = [build_anti_ddos_rule(priority=0, advanced=True)] + all_rules + managed_rules
    resources["WebACLApiFile"] = build_webacl("waf-api-file", api_rules)
else:
    # Per-domain WebACLs
    for domain in domains:
        sanitized = sanitize_webacl_name(domain)
        webacl_name = sanitized  # e.g. "biz-callback_c_letsmakeit_link"
        rules = split_ir[domain]["rules"]
        
        # All domains get the same security config:
        # 1. Search engine labeling rule (priority 0)
        # 2. Anti-DDoS AMR with scope-down excluding search engine label (priority 1)
        # 3. Customer rules (priority 2+)
        # 4. Always-on challenge (after rate-limiting, before managed rules)
        # 5. Managed rules
        
        injected = []
        injected.append(build_search_engine_label_rule(priority=0))
        injected.append(build_anti_ddos_rule(priority=1,
            scope_down_exclude_labels=["awswaf:search-engine"]))
        
        # Insert always-on challenge after rate-limiting rules
        rate_end = find_rate_rule_end(rules)
        rules.insert(rate_end, build_always_on_challenge_rule())
        
        all_domain_rules = injected + rules + managed_rules
        resources[f"WebACL{sanitize_logical_id(sanitized)}"] = build_webacl(
            webacl_name, all_domain_rules)
```

### 5. WebACL naming and CloudFormation logical IDs

Two different sanitization rules apply:

**WebACL Name** (AWS WAF `Name` property): Pattern `^[0-9A-Za-z_-]{1,128}$`. Letters, numbers, underscores, hyphens.

**Convention**: dots → `_` (underscore). Original hyphens preserved. Underscores are allowed per the API spec (`\w` = `[A-Za-z0-9_]`).

```
biz-callback.c.letsmakeit.link  → biz-callback_c_letsmakeit_link
api-loadtest.c.letsmakeit.link  → api-loadtest_c_letsmakeit_link
```

Full WebACL name is the sanitized hostname itself, e.g. `biz-callback_c_letsmakeit_link`.

**CloudFormation Logical ID**: Strictly alphanumeric `A-Za-z0-9` only. No hyphens, no underscores.

```python
def sanitize_logical_id(name):
    """For CloudFormation resource keys. Alphanumeric only."""
    return re.sub(r'[^A-Za-z0-9]', '', name)

def sanitize_webacl_name(hostname):
    """For AWS WAF Name property. Letters, numbers, underscores, hyphens."""
    return hostname.replace('.', '_')
```

Example:
- Hostname: `biz-callback.c.letsmakeit.link`
- WebACL Name: `cf-migrated-biz-callback_c_letsmakeit_link`
- Logical ID: `WebACLbizcallbackcletsmakeit link` → `WebACLbizcallbackcletsmakeitlink`

### 6. All domains get identical security configuration (split mode)

In split mode, every domain's WebACL gets the same injected rules:

| Rule | Priority | Purpose |
|------|----------|---------|
| search-engine-label | 0 | Count + label Googlebot/Bingbot/YandexBot |
| AntiDDoS AMR | 1 | Default challenge, scope-down excludes search engine label |
| (customer rules) | 2+ | Converted from Cloudflare |
| always-on-challenge | after rate-limit | **Count** on `/`, `/login`, `/signup` (user changes to Challenge after review) |
| (managed rules) | last | CRS, Known Bad Inputs, etc. |

Users customize per-domain after deployment via the post-deployment checklist (see Section 8).

### 7. Search engine labeling rule

Injected at priority 0 (before Anti-DDoS AMR) for `web_frontend` and `mixed` domains.

```json
{
  "Name": "search-engine-label",
  "Priority": 0,
  "Action": { "Count": {} },
  "Statement": {
    "OrStatement": {
      "Statements": [
        {
          "AndStatement": {
            "Statements": [
              {
                "ByteMatchStatement": {
                  "SearchString": "Googlebot",
                  "FieldToMatch": { "SingleHeader": { "Name": "user-agent" } },
                  "PositionalConstraint": "CONTAINS",
                  "TextTransformations": [{ "Priority": 0, "Type": "NONE" }]
                }
              },
              {
                "AsnMatchStatement": { "AsnList": [15169] }
              }
            ]
          }
        },
        {
          "AndStatement": {
            "Statements": [
              {
                "ByteMatchStatement": {
                  "SearchString": "bingbot",
                  "FieldToMatch": { "SingleHeader": { "Name": "user-agent" } },
                  "PositionalConstraint": "CONTAINS",
                  "TextTransformations": [{ "Priority": 0, "Type": "NONE" }]
                }
              },
              {
                "AsnMatchStatement": { "AsnList": [8075] }
              }
            ]
          }
        },
        {
          "AndStatement": {
            "Statements": [
              {
                "ByteMatchStatement": {
                  "SearchString": "YandexBot",
                  "FieldToMatch": { "SingleHeader": { "Name": "user-agent" } },
                  "PositionalConstraint": "CONTAINS",
                  "TextTransformations": [{ "Priority": 0, "Type": "NONE" }]
                }
              },
              {
                "AsnMatchStatement": { "AsnList": [13238] }
              }
            ]
          }
        }
      ]
    }
  },
  "RuleLabels": [{ "Name": "awswaf:search-engine" }],
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "search-engine-label"
  }
}
```

WCU: 3 (ByteMatch) + 3 (AsnMatch) = 6.

### 8. Always-on challenge rule

Injected after rate-limiting rules, before managed rules. **Action is Count (not Challenge)** — this is a safe default that does not block any traffic. Users must change to Challenge after reviewing which domains need it.

```json
{
  "Name": "always-on-challenge",
  "Action": { "Count": {} },
  "Statement": {
    "OrStatement": {
      "Statements": [
        {
          "ByteMatchStatement": {
            "SearchString": "/",
            "FieldToMatch": { "UriPath": {} },
            "PositionalConstraint": "EXACTLY",
            "TextTransformations": [{ "Priority": 0, "Type": "NONE" }]
          }
        },
        {
          "ByteMatchStatement": {
            "SearchString": "/login",
            "FieldToMatch": { "UriPath": {} },
            "PositionalConstraint": "EXACTLY",
            "TextTransformations": [{ "Priority": 0, "Type": "NONE" }]
          }
        },
        {
          "ByteMatchStatement": {
            "SearchString": "/signup",
            "FieldToMatch": { "UriPath": {} },
            "PositionalConstraint": "EXACTLY",
            "TextTransformations": [{ "Priority": 0, "Type": "NONE" }]
          }
        }
      ]
    }
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "always-on-challenge"
  }
}
```

WCU: 3 (ByteMatch).

Deployment guide must include a per-domain checklist:

> ⚠️ **WARNING: The `always-on-challenge` rule is deployed with Count action (monitoring only). It does NOT protect against DDoS until you change it to Challenge.**
>
> **Post-deployment checklist (per domain)**:
>
> 1. **Web-facing domains**: Change the `always-on-challenge` rule's action from Count to **Challenge**. Add your landing page paths (e.g., `/pricing`, `/about`, `/register`) to the rule's URI list.
> 2. **Mixed domains** (web frontend + API backend): Same as #1, but also ensure all API paths are excluded from challenge rules. API clients cannot solve challenges — unexcluded API paths will return 202 challenge responses.
> 3. **Pure API / static file domains** (no web frontend): Delete the `search-engine-label` rule and the `always-on-challenge` rule from the WebACL. In the Anti-DDoS AMR, disable challenge and set block sensitivity to medium.

### 9. Anti-DDoS AMR configuration

All domains get the same default configuration (challenge enabled, search engine excluded).

Note: `ManagedRuleGroupConfigs` with `AWSManagedRulesAntiDDoSRuleSet` requires `ClientSideActionConfig` (it's a required property). `ScopeDownStatement` is at the `ManagedRuleGroupStatement` level, not inside `ManagedRuleGroupConfigs`.

```json
{
  "Name": "AntiDDoS",
  "Priority": 1,
  "OverrideAction": { "None": {} },
  "Statement": {
    "ManagedRuleGroupStatement": {
      "VendorName": "AWS",
      "Name": "AWSManagedRulesAntiDDoSRuleSet",
      "ManagedRuleGroupConfigs": [
        {
          "AWSManagedRulesAntiDDoSRuleSet": {
            "ClientSideActionConfig": {
              "Challenge": {
                "UsageOfAction": "ENABLED",
                "Sensitivity": "HIGH"
              }
            },
            "SensitivityToBlock": "LOW"
          }
        }
      ],
      "ScopeDownStatement": {
        "NotStatement": {
          "Statement": {
            "LabelMatchStatement": {
              "Scope": "LABEL",
              "Key": "awswaf:search-engine"
            }
          }
        }
      }
    }
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "AntiDDoS"
  }
}
```

For API-only domains (or legacy mode API/File WebACL), users should modify after deployment:
- Set `UsageOfAction` to `DISABLED`
- Set `SensitivityToBlock` to `MEDIUM`
- Remove the `ScopeDownStatement` (no search engine exclusion needed)
- Delete the `search-engine-label` and `always-on-challenge` rules

The API/File WebACL in legacy mode uses this Anti-DDoS configuration (no search engine scope-down, challenge disabled):

```json
{
  "Name": "AntiDDoS",
  "Priority": 0,
  "OverrideAction": { "None": {} },
  "Statement": {
    "ManagedRuleGroupStatement": {
      "VendorName": "AWS",
      "Name": "AWSManagedRulesAntiDDoSRuleSet",
      "ManagedRuleGroupConfigs": [
        {
          "AWSManagedRulesAntiDDoSRuleSet": {
            "ClientSideActionConfig": {
              "Challenge": {
                "UsageOfAction": "DISABLED"
              }
            },
            "SensitivityToBlock": "MEDIUM"
          }
        }
      ]
    }
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "AntiDDoS"
  }
}
```

### 10. Quota validation

After generating all resources, check:

| Quota | Default | Check |
|-------|---------|-------|
| WebACLs per region | 100 | Warn if > 80 |
| IP sets per region | 100 | Warn if > 80 |
| IP set + regex references per WebACL | 50 | **Error** if exceeded |
| Rules per WebACL | 100 (soft) / 1500 (hard) | Warn if > 100 |
| WCU per WebACL | 5000 | Error if exceeded, warn if > 1500 |
| CloudFormation resources per stack | 500 | Error if exceeded |

If any domain's WebACL exceeds 50 IP set references even after dedup, the pipeline should:
1. Report which domain and how many references
2. Suggest the user open a quota increase case
3. NOT silently drop rules

### 11. CloudFormation stack structure

**Single stack.** All IP sets + all WebACLs in one stack.

Resource count formula: `IP sets (after dedup) + WebACLs + regex sets`. Rules are WebACL properties, not standalone resources.

Example: 14 domains + 12 IP sets (after dedup) = 26 resources. Even 100 domains + 50 IP sets = 150, well under the 500 resource limit. Multi-stack is not needed.

### 12. IP set deduplication details

**When dedup runs**: Only when inline IP set count > 100 (Step 3 of decision tree). Named lists (account-level) are never merged.

**Dedup scope**: Inline IP sets only, across all rules. Two inline IP sets with identical `(IPAddressVersion, sorted(Addresses))` share one CloudFormation resource.

**Naming**: The deduplicated IP set uses the name from the first rule that references it. Other rules reference the same logical ID.

**Deployment guide warning** (only when dedup was applied):
> The following inline IP sets were merged because they contain identical addresses. If you need to maintain separate lists for different rules in the future, duplicate the IP set in the AWS WAF console and update the rule references.
>
> | Merged IP Set | Original Rules |
> |---|---|
> | skip-rule-shared-ipv4 | skip-rule-1, skip-rule-2 |

### 13. Edge cases

**Rule with mixed global and host-specific OR branches**:
```
(ip.src in {bad_ips}) or (http.host eq "api.example.com" and ip.src in {api_ips})
```
Branch 1 is global (no host), branch 2 is host-specific.
- For `api.example.com`: both branches apply → keep full OR, strip host from branch 2
- For other domains: only branch 1 applies → single statement (no OR wrapper)

**Rule with `host contains` keyword matching NO DNS domains**:
```
http.host contains "legacy-app" and ip.src in {ips}
```
If no proxied domain in DNS.txt contains "legacy-app", this rule matches zero domains.
- **Drop the rule entirely** — it would never trigger in Cloudflare either.
- Add a warning in the deployment guide: "Rule '{name}' has `host contains \"{keyword}\"` but no proxied domain matches. Rule was excluded from all WebACLs."

**Rule with `host contains` keyword matching multiple domains**:
```
http.host contains "biz-callback" and ip.src in {ips}
```
Matches: `biz-callback.example.com`, `biz-callback-stg.example.com`, `biz-callback-loadtest.example.com`.
- For each matching domain: include the rule, strip host condition (since WebACL only serves one domain, the contains check is always true)
- For non-matching domains: exclude the rule

**Rule with `host in {d1 d2 d3}` where domains span different types**:
```
http.host in {"web.example.com" "api.example.com" "cdn.example.com"} and not ip.src in {whitelist}
```
- `web.example.com` (web_frontend) WebACL: include rule, strip host → `not ip.src in {whitelist}`
- `api.example.com` (api) WebACL: include rule, strip host → `not ip.src in {whitelist}`
- `cdn.example.com` (static) WebACL: include rule, strip host → `not ip.src in {whitelist}`
- Other domains: exclude rule

**Skip rule scope-down interaction**:
Skip rules emit labels. The scope-down `NOT label_match(skip:all_remaining_custom_rules)` is added to subsequent rules. This logic is unchanged — it operates within each domain's rule list after splitting.

Important: if a skip rule is excluded from a domain (because its host doesn't match), subsequent rules in that domain should NOT have the scope-down for that skip rule's label. The splitting step must re-derive scope-down based on the domain's actual rule list.

**Rate-limiting rules with no host condition**:
These are global — included in all domains' WebACLs. Each domain's rate counter is independent (different WebACL = different counter). This matches Cloudflare behavior where rate limiting is per-zone (all domains share one zone).

Actually, this is a semantic difference: Cloudflare counts across all domains in the zone, AWS WAF counts per-WebACL. Document this in the deployment guide as a known behavioral difference.

## Files Changed

| File | Change |
|------|--------|
| `waf-analyze-custom.py` | Add `host_scope` extraction to each rule in IR |
| `waf-analyze-rate.py` | Add `host_scope` extraction (same logic) |
| `waf-check-split.py` | **NEW** — count IP sets, decide legacy vs split mode |
| `waf-split-by-host.py` | **NEW** — split IR by domain, strip host conditions, re-derive scope-down |
| `waf-generate-cfn.py` | Per-domain WebACL loop (split mode), IP set dedup, injected rules (search engine label, always-on challenge, Anti-DDoS with scope-down) |
| `waf-generate-readme.py` | Per-domain deployment guide, dedup warnings, post-deployment checklist |
| `waf-pipeline.sh` | Add check-split and split-by-host steps |
| `waf_expr_parser.py` | No changes needed |
| `waf_common.py` | No changes needed |
| `waf-validate-ir.py` | Add host_scope validation |

## Pipeline UX Change

Current: fully automatic, no user input needed.

New: **still fully automatic, no user input needed.** The split decision is automatic based on IP set count.

```
$ bash waf-pipeline.sh ~/Downloads/cloudflare-config cloudflare-to-aws-waf

[WAF] A1: IP Lists + Access Rules ... OK
[WAF] A2: Custom Rules ... OK
[WAF] A3: Rate-Limiting Rules ... OK
[WAF] Merge IR ... OK
[WAF] Count Validate ... OK
[WAF] IR Validate ... OK
[WAF] Check split ... 17 IP sets > 50 limit? No → legacy mode (2 WebACLs)
[WAF] Generate CloudFormation ... OK: 19 resources, 2 WebACLs, 17 IP sets, WCU=1685

---RESULT---
SPEC: 1
STATUS: OK
OUTPUT_DIR: cloudflare-to-aws-waf
TEMPLATE: cloudflare-to-aws-waf/waf-cloudformation.json
```

When split is triggered:

```
$ bash waf-pipeline.sh ~/Downloads/cloudflare-config cloudflare-to-aws-waf

[WAF] A1: IP Lists + Access Rules ... OK
[WAF] A2: Custom Rules ... OK
[WAF] A3: Rate-Limiting Rules ... OK
[WAF] Merge IR ... OK
[WAF] Count Validate ... OK
[WAF] IR Validate ... OK
[WAF] Check split ... 63 IP sets > 50 limit → per-domain split mode (14 domains)
[WAF] Split by host ... OK: 14 domains, 8 global rules, 2 host-specific rules
[WAF] Generate CloudFormation ... OK: 26 resources, 14 WebACLs, 12 IP sets (5 deduped)

---RESULT---
SPEC: 1
STATUS: OK
OUTPUT_DIR: cloudflare-to-aws-waf
TEMPLATE: cloudflare-to-aws-waf/waf-cloudformation.json
```

## Open Questions

1. **Search engine ASN list completeness**: Current list covers Google (AS15169), Bing (AS8075), Yandex (AS13238). Baidu cannot be added — no confirmed ASN for its crawler. This is easy to extend later — just add entries to the OR statement.

2. **Rate-limiting semantic difference**: Cloudflare counts rate across all domains in a zone. Per-domain WebACLs count independently. Documented as a known behavioral difference in the deployment guide. No attempt to replicate zone-wide counting.
