#!/usr/bin/env python3
"""waf-validate-ir.py — WAF Stage 2: Validate merged IR JSON.

Performs round-trip validation, IP set consistency, skip label consistency,
and scope_down flag verification. Replaces LLM validator.

Usage:
    python3 waf-validate-ir.py <config_path> <output_dir>

Exit codes: 0 = all PASS, 1 = some FAIL.
"""
import json, sys, os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from waf_expr_parser import round_trip_validate


def main():
    if len(sys.argv) < 3:
        print("Usage: waf-validate-ir.py <config_path> <output_dir>", file=sys.stderr)
        sys.exit(1)

    config_path = os.path.expanduser(sys.argv[1])
    output_dir = os.path.expanduser(sys.argv[2])

    ir_path = os.path.join(output_dir, "waf_ir.json")
    if not os.path.exists(ir_path):
        print(f"ERROR: {ir_path} not found", file=sys.stderr)
        sys.exit(1)

    with open(ir_path) as f:
        ir = json.load(f)

    errors = []
    warnings = []

    # ── Check 1: Round-trip validation for all rules with expressions ────────

    for section_key, section_name in [
        ("custom_rules", "Custom"),
        ("rate_limiting_rules", "Rate-limiting"),
    ]:
        section = ir.get(section_key, {})
        for rule in section.get("rules", []):
            expr = rule.get("expression", "")
            name = rule.get("name", "?")
            cond = rule.get("conditions")

            if not expr or cond is None:
                continue  # skip non-convertible or parse-error rules

            ok, _, err = round_trip_validate(expr)
            if not ok:
                errors.append(f"[{section_name}] {name}: round-trip FAIL — {err}")

    # ── Check 2: IP set consistency ──────────────────────────────────────────

    for section_key, section_name in [
        ("ip_access_rules", "IP Access"),
        ("custom_rules", "Custom"),
        ("rate_limiting_rules", "Rate-limiting"),
    ]:
        section = ir.get(section_key, {})
        for rule in section.get("rules", []):
            ip_sets = rule.get("ip_sets", [])
            for ipset in ip_sets:
                if not ipset.get("addresses"):
                    warnings.append(f"[{section_name}] {rule.get('name','?')}: "
                                    f"IP set '{ipset.get('name','')}' has no addresses")

    # ── Check 3: Skip label consistency ──────────────────────────────────────

    custom = ir.get("custom_rules", {})
    skip_labels_present = custom.get("skip_labels_present", {})
    actual_labels = set()
    for rule in custom.get("rules", []):
        for label in rule.get("labels", []):
            actual_labels.add(label)

    for key, label in [
        ("all_remaining_custom_rules", "skip:all_remaining_custom_rules"),
        ("http_ratelimit", "skip:http_ratelimit"),
        ("http_request_firewall_managed", "skip:http_request_firewall_managed"),
    ]:
        declared = skip_labels_present.get(key, False)
        present = label in actual_labels
        if declared != present:
            errors.append(f"skip_labels_present.{key}={declared} but label "
                          f"{'found' if present else 'not found'} in rules")

    # ── Check 4: Scope-down flags ────────────────────────────────────────────

    skip_all_seen = False
    for rule in custom.get("rules", []):
        if rule.get("action") == "skip":
            if rule.get("scope_down", {}).get("skip_all_remaining_custom_rules"):
                errors.append(f"Skip rule '{rule.get('name','')}' should not have "
                              f"skip_all_remaining_custom_rules scope-down")
            if "skip:all_remaining_custom_rules" in rule.get("labels", []):
                skip_all_seen = True
        else:
            expected = skip_all_seen
            actual = rule.get("scope_down", {}).get("skip_all_remaining_custom_rules", False)
            if actual != expected:
                errors.append(f"Rule '{rule.get('name','')}': scope_down.skip_all_remaining_custom_rules "
                              f"is {actual}, expected {expected}")

    # Rate-limiting scope-down
    skip_ratelimit = skip_labels_present.get("http_ratelimit", False)
    for rule in ir.get("rate_limiting_rules", {}).get("rules", []):
        actual = rule.get("scope_down", {}).get("skip_http_ratelimit", False)
        if actual != skip_ratelimit:
            errors.append(f"Rate rule '{rule.get('name','')}': scope_down.skip_http_ratelimit "
                          f"is {actual}, expected {skip_ratelimit}")

    # ── Report ───────────────────────────────────────────────────────────────

    total_rules = (ir.get("ip_access_rules", {}).get("count", 0) +
                   ir.get("custom_rules", {}).get("count", 0) +
                   ir.get("rate_limiting_rules", {}).get("count", 0))

    if errors:
        print(f"FAIL: {len(errors)} errors, {len(warnings)} warnings ({total_rules} rules)")
        for e in errors:
            print(f"  ERROR: {e}")
        for w in warnings:
            print(f"  WARN: {w}")
        print(f"\n---RESULT---\nSPEC: 1\nSTATUS: ERROR\nERRORS: {len(errors)}")
        sys.exit(1)
    else:
        print(f"PASS: {total_rules} rules validated, {len(warnings)} warnings")
        for w in warnings:
            print(f"  WARN: {w}")
        print(f"\n---RESULT---\nSPEC: 1\nSTATUS: OK\nRULES_VALIDATED: {total_rules}")
        sys.exit(0)


if __name__ == "__main__":
    main()
