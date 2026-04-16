#!/usr/bin/env python3
"""waf-analyze-custom.py — WAF Stage A2: Analyze Custom Rules.

Replaces cf-waf-analyzer LLM subagent batch A2. Reads WAF-Custom-Rules.txt,
parses expressions into conditions trees, determines convertibility,
extracts IP sets, and tracks skip labels.

Usage:
    python3 waf-analyze-custom.py <config_path> <output_dir>

Exit codes: 0 = OK, 1 = error.
"""
import json, sys, os, glob, re

# Import parser and shared utilities from same directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from waf_expr_parser import parse, extract_ip_sets, ParseError
from waf_common import (NON_CONVERTIBLE_FIELDS, NON_CONVERTIBLE_AWS_EQUIV,
                        classify_convertibility)

# ── Skip label derivation ────────────────────────────────────────────────────

def derive_skip_labels(action_parameters):
    """Derive skip labels from action_parameters."""
    labels = []
    phases = action_parameters.get("phases", [])
    if "http_ratelimit" in phases:
        labels.append("skip:http_ratelimit")
    if "http_request_firewall_managed" in phases:
        labels.append("skip:http_request_firewall_managed")
    if action_parameters.get("ruleset") == "current":
        labels.append("skip:all_remaining_custom_rules")
    return labels


# ── File discovery ───────────────────────────────────────────────────────────

def find_file(config_path, pattern):
    matches = glob.glob(os.path.join(config_path, "**", pattern), recursive=True)
    return matches[0] if matches else None


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 3:
        print("Usage: waf-analyze-custom.py <config_path> <output_dir>", file=sys.stderr)
        sys.exit(1)

    config_path = os.path.expanduser(sys.argv[1])
    output_dir = os.path.expanduser(sys.argv[2])

    custom_path = find_file(config_path, "WAF-Custom-Rules.txt")
    if not custom_path:
        # No custom rules — output empty
        ir = {"custom_rules": {"count": 0, "skip_labels_present": {
            "all_remaining_custom_rules": False, "http_ratelimit": False,
            "http_request_firewall_managed": False}, "rules": []},
              "non_convertible_notes": []}
        out_path = os.path.join(output_dir, "waf_ir_custom.json")
        json.dump(ir, open(out_path, "w"), indent=2)
        print(f"OK: 0 custom rules → {out_path}")
        return

    with open(custom_path) as f:
        data = json.load(f)

    raw_rules = data.get("result", {}).get("rules", [])
    if isinstance(data.get("result"), list):
        raw_rules = data["result"]

    rules = []
    non_convertible_notes = []
    skip_labels_present = {
        "all_remaining_custom_rules": False,
        "http_ratelimit": False,
        "http_request_firewall_managed": False,
    }

    # Track skip rules for scope_down
    skip_all_remaining_seen = False

    for i, raw in enumerate(raw_rules):
        action = raw.get("action", "")
        expression = raw.get("expression", "")
        description = raw.get("description", f"rule-{i+1}")

        entry = {
            "position": i + 1,
            "name": description,
            "action": action,
            "expression": expression,
            "convertibility": "yes",
        }

        # Parse expression
        try:
            cond = parse(expression)
            entry["conditions"] = cond
        except ParseError as e:
            entry["conditions"] = None
            entry["convertibility"] = "no"
            entry["parse_error"] = str(e)
            entry["non_convertible_reason"] = f"Expression parse error: {e}"
            non_convertible_notes.append({
                "rule": description, "field": "expression",
                "reason": f"Parse error: {e}",
                "aws_equivalent": "Manual conversion required",
                "manual_action": "Manually create AWS WAF rule",
            })
            rules.append(entry)
            continue

        # Convertibility
        conv, pruned, nc_fields = classify_convertibility(cond)
        entry["convertibility"] = conv
        if conv == "partial":
            entry["convertible_conditions"] = pruned
            entry["non_convertible_reason"] = ", ".join(nc_fields)
            for f in nc_fields:
                non_convertible_notes.append({
                    "rule": description, "field": f,
                    "reason": f"Non-convertible field: {f}",
                    "aws_equivalent": NON_CONVERTIBLE_AWS_EQUIV.get(f, "No direct equivalent"),
                    "manual_action": f"Configure AWS equivalent for {f}",
                })
        elif conv == "no":
            entry["non_convertible_reason"] = ", ".join(nc_fields)
            for f in nc_fields:
                non_convertible_notes.append({
                    "rule": description, "field": f,
                    "reason": f"Non-convertible field: {f}",
                    "aws_equivalent": NON_CONVERTIBLE_AWS_EQUIV.get(f, "No direct equivalent"),
                    "manual_action": f"Configure AWS equivalent for {f}",
                })

        # Extract IP sets
        if cond:
            ip_sets = extract_ip_sets(cond, description, i + 1)
            if ip_sets:
                entry["ip_sets"] = ip_sets

        # Skip action handling
        if action == "skip":
            ap = raw.get("action_parameters", {})
            entry["action_parameters"] = ap
            labels = derive_skip_labels(ap)
            entry["labels"] = labels
            if "skip:all_remaining_custom_rules" in labels:
                skip_labels_present["all_remaining_custom_rules"] = True
                skip_all_remaining_seen = True
            if "skip:http_ratelimit" in labels:
                skip_labels_present["http_ratelimit"] = True
            if "skip:http_request_firewall_managed" in labels:
                skip_labels_present["http_request_firewall_managed"] = True

        # Challenge action mapping
        if action in ("managed_challenge", "js_challenge"):
            entry["aws_action"] = "challenge"
        elif action == "interactive_challenge":
            entry["aws_action"] = "captcha"

        # Scope-down: skip rules never have scope-down; others get it if a skip rule was seen
        if action == "skip":
            entry["scope_down"] = {"skip_all_remaining_custom_rules": False}
        else:
            entry["scope_down"] = {"skip_all_remaining_custom_rules": skip_all_remaining_seen}

        rules.append(entry)

    ir = {
        "custom_rules": {
            "count": len(rules),
            "skip_labels_present": skip_labels_present,
            "rules": rules,
        },
        "non_convertible_notes": non_convertible_notes,
    }

    out_path = os.path.join(output_dir, "waf_ir_custom.json")
    with open(out_path, "w") as f:
        json.dump(ir, f, indent=2, ensure_ascii=False)

    skip_count = sum(1 for r in rules if r["action"] == "skip")
    partial_count = sum(1 for r in rules if r["convertibility"] == "partial")
    no_count = sum(1 for r in rules if r["convertibility"] == "no")
    print(f"OK: {len(rules)} custom rules ({skip_count} skip, {partial_count} partial, "
          f"{no_count} non-convertible) → {out_path}")
    print(f"\n---RESULT---\nSPEC: 1\nSTATUS: OK\nOUTPUT_FILE: {out_path}\n"
          f"RULE_COUNT: {len(rules)}\nSKIP_COUNT: {skip_count}")


if __name__ == "__main__":
    main()
