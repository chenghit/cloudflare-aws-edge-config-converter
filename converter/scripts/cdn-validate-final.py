#!/usr/bin/env python3
"""cdn-validate-final.py — Stage 6: Validate finalized IR.

Usage:
    python3 cdn-validate-final.py <output_dir>

Validates all ir/final/*.json files against dedup_manifest.json.
Writes ir/validation/final/{hostname}-v2.json per domain.
Exit 0 = all PASS, 1 = any FAIL, 2 = fatal error.
"""
import json, sys, os, re

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cdn_common import pattern_contains


def validate_domain(ir, manifest_policies):
    """Validate a single domain's finalized IR. Returns (errors, warnings)."""
    errors = []
    warnings = []
    behaviors = ir.get("cache_behaviors", [])

    # Check 1: precedence strictly increasing
    precs = [b.get("precedence", 0) for b in behaviors]
    for i in range(1, len(precs)):
        if precs[i] <= precs[i - 1]:
            errors.append(
                f"Check1: precedence not strictly increasing at index {i}: "
                f"{precs[i-1]} → {precs[i]}"
            )
            break

    # Check 2: most-specific-first ordering (exact CloudFront-glob containment,
    # shared with finalize/scaffold — replaces the `?`-blind specificity heuristic).
    # A behavior must never be preceded by a LATER one that CONTAINS it: if an
    # earlier pattern is strictly contained by a later pattern, the later (broader)
    # one would have to sit first to not shadow it — so this ordering is wrong.
    non_default = [b for b in behaviors if b["path_pattern"] != "*"]
    for i in range(len(non_default)):
        pi = non_default[i]["path_pattern"]
        for j in range(i + 1, len(non_default)):
            pj = non_default[j]["path_pattern"]
            # pj (later) strictly contains pi (earlier) → pi should be first: OK.
            # pi (earlier) strictly contains pj (later) → broader-first → WRONG.
            if pattern_contains(pi, pj) and not pattern_contains(pj, pi):
                errors.append(
                    f"Check2: ordering wrong: '{pi}' (index {i}) contains "
                    f"'{pj}' (index {j}) but precedes it — the broader pattern would "
                    f"shadow the narrower under CloudFront first-match")
                break
        else:
            continue
        break

    # Check 3: cache behavior count ≤ 75
    if len(behaviors) > 75:
        errors.append(f"Check3: {len(behaviors)} cache behaviors exceeds CloudFront limit of 75")

    # Check 4: origin.domain valid
    for i, b in enumerate(behaviors):
        origin = b.get("origin", {})
        domain = origin.get("domain", "")
        if not domain:
            errors.append(f"Check4: cache_behaviors[{i}].origin.domain is empty")
        elif not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$', domain):
            errors.append(f"Check4: cache_behaviors[{i}].origin.domain '{domain}' invalid")

    # Check 5: path_pattern no duplicates
    patterns = [b["path_pattern"] for b in behaviors]
    seen = set()
    for p in patterns:
        if p in seen:
            errors.append(f"Check5: duplicate path_pattern '{p}'")
        seen.add(p)

    # Check 6: dedup_manifest.json structure valid (checked at top level)

    # Check 7: all policy_id references resolvable
    ref_keys = ["cache_policy_id", "origin_request_policy_id", "response_headers_policy_id"]
    for i, b in enumerate(behaviors):
        for key in ref_keys:
            pid = b.get(key)
            if pid and pid not in manifest_policies:
                errors.append(
                    f"Check7: cache_behaviors[{i}].{key} = '{pid}' "
                    f"not found in dedup_manifest.json"
                )

    return errors, warnings


def main():
    if len(sys.argv) < 2:
        print("Usage: cdn-validate-final.py <output_dir>", file=sys.stderr)
        sys.exit(2)

    output_dir = os.path.expanduser(sys.argv[1])
    final_dir = os.path.join(output_dir, "ir", "final")
    val_dir = os.path.join(output_dir, "ir", "validation", "final")
    manifest_path = os.path.join(output_dir, "shared", "dedup_manifest.json")
    os.makedirs(val_dir, exist_ok=True)

    # Load dedup manifest
    if not os.path.exists(manifest_path):
        print(f"ERROR: {manifest_path} not found", file=sys.stderr)
        sys.exit(2)
    with open(manifest_path) as f:
        manifest = json.load(f)
    manifest_policies = manifest.get("policies", {})

    # Check 6: manifest structure
    manifest_errors = []
    if "generated_at" not in manifest:
        manifest_errors.append("Check6: dedup_manifest.json missing generated_at")
    if "total_policies" not in manifest:
        manifest_errors.append("Check6: dedup_manifest.json missing total_policies")
    if not isinstance(manifest_policies, dict):
        manifest_errors.append("Check6: dedup_manifest.json policies is not an object")
    for pid, v in manifest_policies.items():
        if not pid.startswith("policy-"):
            manifest_errors.append(f"Check6: policy_id '{pid}' does not start with 'policy-'")
        for req_field in ("hash", "type", "count", "config"):
            if req_field not in v:
                manifest_errors.append(f"Check6: policy '{pid}' missing field '{req_field}'")

    report_path = os.path.join(output_dir, "conversion_report.md")
    if not os.path.exists(report_path):
        manifest_errors.append("conversion_report.md not found")

    if not os.path.isdir(final_dir):
        print(f"ERROR: {final_dir} not found", file=sys.stderr)
        sys.exit(2)

    json_files = sorted(f for f in os.listdir(final_dir) if f.endswith(".json"))
    if not json_files:
        print("ERROR: no finalized IR files found", file=sys.stderr)
        sys.exit(2)

    all_pass = True
    for filename in json_files:
        filepath = os.path.join(final_dir, filename)
        hostname = filename.replace(".json", "")

        try:
            with open(filepath) as f:
                ir = json.load(f)
        except json.JSONDecodeError as e:
            report = {
                "hostname": hostname,
                "validator": "cdn-validate-final",
                "status": "FAIL",
                "errors": [f"JSON parse error: {e}"],
                "warnings": [],
            }
            _write_report(val_dir, hostname, report)
            all_pass = False
            continue

        errors, warnings = validate_domain(ir, manifest_policies)
        errors.extend(manifest_errors)  # include manifest-level errors

        status = "FAIL" if errors else "PASS"
        report = {
            "hostname": hostname,
            "validator": "cdn-validate-final",
            "status": status,
            "errors": errors,
            "warnings": warnings,
        }
        _write_report(val_dir, hostname, report)

        if errors:
            all_pass = False
            print(f"FAIL: {hostname} ({len(errors)} errors)")
            for e in errors:
                print(f"  {e}")
        else:
            w = f" ({len(warnings)} warnings)" if warnings else ""
            print(f"PASS: {hostname}{w}")

    print(f"\n{'='*60}")
    print(f"Validated {len(json_files)} domains: {'ALL PASS' if all_pass else 'SOME FAILED'}")
    sys.exit(0 if all_pass else 1)


def _write_report(val_dir, hostname, report):
    path = os.path.join(val_dir, f"{hostname}-v2.json")
    with open(path, "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    main()
