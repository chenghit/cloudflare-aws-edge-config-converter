#!/usr/bin/env python3
"""waf-split-by-host.py — Split WAF IR by domain based on host conditions.

Reads waf_ir.json + DNS.txt, produces waf_ir_split.json with per-domain rule lists.
Host conditions are stripped (redundant when WebACL serves one domain).
Scope-down is re-derived per domain based on which skip rules are present.

Usage:
    python3 waf-split-by-host.py <config_path> <output_dir>
"""
import copy, glob, json, os, re, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def find_file(config_path, pattern):
    matches = glob.glob(os.path.join(config_path, "**", pattern), recursive=True)
    return matches[0] if matches else None


def extract_proxied_domains(config_path):
    """Read DNS.txt, return sorted list of proxied hostnames."""
    dns_path = find_file(config_path, "DNS.txt")
    if not dns_path:
        print("ERROR: DNS.txt not found", file=sys.stderr)
        sys.exit(2)
    try:
        with open(dns_path) as f:
            data = json.load(f)
    except (json.JSONDecodeError, ValueError):
        print(f"ERROR: DNS.txt is empty or invalid JSON: {dns_path}", file=sys.stderr)
        sys.exit(2)
    records = data.get("result", [])
    if isinstance(data.get("result"), dict):
        records = data["result"].get("records", [])
    return sorted(set(
        r["name"] for r in records
        if r.get("proxied") and r.get("type") in ("A", "AAAA", "CNAME")
    ))


# ── Condition tree manipulation ──────────────────────────────────────────────

def _strip_host_from_and(cond):
    """Remove http.host items from an AND condition. Returns simplified tree."""
    if cond.get("op") != "and":
        if "field" in cond and cond["field"] == "http.host":
            return None
        return cond
    others = [item for item in cond["items"]
              if not ("field" in item and item.get("field") == "http.host")]
    if len(others) == 0:
        return None
    if len(others) == 1:
        return others[0]
    return {"op": "and", "items": others}


def _strip_host_condition(rule):
    """Return a deep copy of rule with host conditions stripped from conditions."""
    new_rule = copy.deepcopy(rule)
    cond = new_rule.get("conditions") or new_rule.get("convertible_conditions")
    if cond is None:
        return new_rule
    stripped = _strip_host_from_and(cond)
    if "conditions" in new_rule and new_rule["conditions"] is not None:
        new_rule["conditions"] = stripped
    if "convertible_conditions" in new_rule and new_rule["convertible_conditions"] is not None:
        new_rule["convertible_conditions"] = stripped
    return new_rule


def _copy_rule_with_branches(rule, branches):
    """Create a deep copy of rule with only the given OR branches."""
    new_rule = copy.deepcopy(rule)
    if len(branches) == 1:
        new_cond = branches[0]
    else:
        new_cond = {"op": "or", "items": branches}
    if "conditions" in new_rule:
        new_rule["conditions"] = new_cond
    if "convertible_conditions" in new_rule:
        new_rule["convertible_conditions"] = new_cond
    # Recompute ip_sets: keep only those whose names appear in _ip_set_names in the new condition
    referenced_names = set()
    _collect_ip_set_names(new_cond, referenced_names)
    new_rule["ip_sets"] = [ip for ip in rule.get("ip_sets", []) if ip["name"] in referenced_names]
    return new_rule


def _collect_ip_set_names(obj, result):
    """Recursively collect _ip_set_names from condition tree."""
    if isinstance(obj, dict):
        for name in obj.get("_ip_set_names", []):
            result.add(name)
        for v in obj.values():
            if isinstance(v, (dict, list)):
                _collect_ip_set_names(v, result)
    elif isinstance(obj, list):
        for item in obj:
            _collect_ip_set_names(item, result)


# ── Rule assignment ──────────────────────────────────────────────────────────

def rules_for_domain(all_rules, domain, warnings):
    """Return list of rules applicable to this domain, with host conditions stripped."""
    result = []
    for rule in all_rules:
        scope = rule.get("host_scope", {"type": "global"})
        scope_type = scope.get("type", "global")

        if scope_type == "global":
            result.append(copy.deepcopy(rule))

        elif scope_type == "single_host":
            if scope["hosts"][0] == domain:
                result.append(_strip_host_condition(rule))

        elif scope_type == "multi_host":
            if domain in scope["hosts"]:
                result.append(_strip_host_condition(rule))

        elif scope_type == "contains":
            matched = False
            for keyword in scope.get("contains", []):
                if keyword in domain:
                    matched = True
                    break
            if matched:
                result.append(_strip_host_condition(rule))

        elif scope_type == "branched":
            applicable = []
            for branch in scope.get("branches", []):
                if branch["host"] is None:
                    applicable.append(copy.deepcopy(branch["condition"]))
                elif branch.get("host_op") == "eq" and branch["host"] == domain:
                    stripped = _strip_host_from_and(copy.deepcopy(branch["condition"])) if branch["condition"] else None
                    if stripped:
                        applicable.append(stripped)
                elif branch.get("host_op") == "contains" and branch["host"] in domain:
                    stripped = _strip_host_from_and(copy.deepcopy(branch["condition"])) if branch["condition"] else None
                    if stripped:
                        applicable.append(stripped)
            if applicable:
                result.append(_copy_rule_with_branches(rule, applicable))

    return result


def _rederive_scope_down(rules):
    """Re-derive scope_down for each rule based on which skip rules are present."""
    skip_all_remaining_seen = False
    skip_ratelimit_seen = False
    for rule in rules:
        action = rule.get("action", "")
        if action == "skip":
            rule["scope_down"] = {"skip_all_remaining_custom_rules": False}
            labels = rule.get("labels", [])
            if "skip:all_remaining_custom_rules" in labels:
                skip_all_remaining_seen = True
            if "skip:http_ratelimit" in labels:
                skip_ratelimit_seen = True
        else:
            rule["scope_down"] = {"skip_all_remaining_custom_rules": skip_all_remaining_seen}
    return skip_ratelimit_seen


def _check_unmatched_contains(all_rules, domains, warnings):
    """Warn about host contains rules that match no domain."""
    for rule in all_rules:
        scope = rule.get("host_scope", {})
        if scope.get("type") == "contains":
            for keyword in scope.get("contains", []):
                if not any(keyword in d for d in domains):
                    warnings.append(
                        f"Rule '{rule['name']}' has host contains \"{keyword}\" "
                        f"but no proxied domain matches. Rule excluded from all WebACLs.")


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 3:
        print("Usage: waf-split-by-host.py <config_path> <output_dir>", file=sys.stderr)
        sys.exit(1)

    config_path = os.path.expanduser(sys.argv[1])
    output_dir = os.path.expanduser(sys.argv[2])

    with open(os.path.join(output_dir, "waf_ir.json")) as f:
        ir = json.load(f)

    domains = extract_proxied_domains(config_path)
    if not domains:
        print("ERROR: No proxied domains found in DNS.txt", file=sys.stderr)
        print("\n---RESULT---\nSPEC: 1\nSTATUS: FATAL\nACTION: FIX\n"
              "CONTEXT: No proxied domains in DNS.txt")
        sys.exit(2)

    # Collect all rules from all sections
    all_custom = ir.get("custom_rules", {}).get("rules", [])
    all_rate = ir.get("rate_limiting_rules", {}).get("rules", [])
    all_ip_access = ir.get("ip_access_rules", {}).get("rules", [])

    warnings = []
    _check_unmatched_contains(all_custom + all_rate, domains, warnings)

    # Split per domain
    split_result = {"domains": {}, "warnings": warnings}
    global_count = 0
    host_specific_count = 0

    for domain in domains:
        custom_rules = rules_for_domain(all_custom, domain, warnings)
        rate_rules = rules_for_domain(all_rate, domain, warnings)
        ip_rules = [copy.deepcopy(r) for r in all_ip_access]  # always global

        # Re-derive scope_down for this domain's custom rules
        _rederive_scope_down(custom_rules)
        # Re-derive scope_down for rate rules
        skip_ratelimit = any(
            "skip:http_ratelimit" in r.get("labels", [])
            for r in custom_rules if r.get("action") == "skip"
        )
        for rr in rate_rules:
            rr["scope_down"] = {"skip_http_ratelimit": skip_ratelimit}

        split_result["domains"][domain] = {
            "custom_rules": custom_rules,
            "rate_limiting_rules": rate_rules,
            "ip_access_rules": ip_rules,
        }

    # Count global vs host-specific
    for rule in all_custom + all_rate:
        scope = rule.get("host_scope", {})
        if scope.get("type", "global") == "global":
            global_count += 1
        else:
            host_specific_count += 1

    # Preserve top-level IR fields
    split_result["ip_lists"] = ir.get("ip_lists", [])
    split_result["skip_labels_present"] = ir.get("custom_rules", {}).get("skip_labels_present", {})
    split_result["non_convertible_notes"] = ir.get("non_convertible_notes", [])

    out_path = os.path.join(output_dir, "waf_ir_split.json")
    with open(out_path, "w") as f:
        json.dump(split_result, f, indent=2, ensure_ascii=False)

    for w in warnings:
        print(f"  WARN: {w}", file=sys.stderr)

    print(f"OK: {len(domains)} domains, {global_count} global rules, "
          f"{host_specific_count} host-specific rules → {out_path}")
    print(f"\n---RESULT---\nSPEC: 1\nSTATUS: OK\nOUTPUT_FILE: {out_path}\n"
          f"DOMAINS: {len(domains)}\nGLOBAL_RULES: {global_count}\n"
          f"HOST_SPECIFIC_RULES: {host_specific_count}")


if __name__ == "__main__":
    main()
