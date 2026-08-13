#!/usr/bin/env python3
"""cdn-validate-chunk.py — Stage 4: Validate IR accumulator JSONs.

Usage:
    python3 cdn-validate-chunk.py <output_dir>

Validates all ir/accumulator/*.json files (skips *.error.json).
Writes ir/validation/chunk/{hostname}-v1.json per domain.
Exit 0 = all PASS, 1 = any FAIL, 2 = fatal error.
"""
import json, sys, os, re

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cdn_expr_parser import (FIELD_TO_ORP_HEADERS, extract_orp_headers,
                             validate_viewer_op, FORBIDDEN_HEADER_ADD_OP_TYPES)

# All valid CloudFront-Viewer-* headers that can appear in required_orp_headers
VALID_ORP_HEADERS = set()
for headers in FIELD_TO_ORP_HEADERS.values():
    VALID_ORP_HEADERS.update(headers)

# Valid viewer_request_ops type ordering groups (same index = same priority).
# Must match the section emission order in cdn-generate-js generate_viewer_request_js
# (the codegen re-groups by type, so this mirrors that order, not IR list order).
VR_OPS_ORDER_GROUP = {
    "redirect": 0,
    "rewrite": 1,
    "origin_override": 2,
    "bulk_redirect": 3,
    # cache_bypass is emitted BEFORE header transforms (it must read the original
    # viewer request, mirroring Cloudflare's phase order), and after redirect/
    # rewrite/bulk. Same group as headers so IR order [rewrite, cache_bypass,
    # set_request_header] is accepted; codegen emits bypass first within the group.
    "cache_bypass": 4,
    # NO add_request_header (round-19 finding 2): header `add` is non-convertible, so no add op
    # is ever emitted. An add_*_header op in an IR is a producer bug → Check3 rejects it.
    "set_request_header": 4, "remove_request_header": 4,
}

# Op types no producer may emit (header `add` has no faithful CloudFront conversion in either
# phase). Present in an IR → a hard validation error (the artifact would otherwise get a
# spurious EXACT claim + CFF artifact). Kept as a set so Check3 can name the offender.
_FORBIDDEN_OP_TYPES = FORBIDDEN_HEADER_ADD_OP_TYPES  # the ONE authority (cdn_expr_parser); `add` is NC both phases

REQUIRED_METADATA_FIELDS = [
    "hostname", "sanitized_name", "apex_domain", "cert_domain", "origin_type",
    "kvs_requirements",
]


def validate_domain(ir, filename):
    """Validate a single domain's IR accumulator. Returns (errors, warnings)."""
    errors = []
    warnings = []
    hostname = ir.get("metadata", {}).get("hostname", "")
    behaviors = ir.get("cache_behaviors", [])

    # Check 1: path_pattern and precedence existence and type
    for i, b in enumerate(behaviors):
        if "path_pattern" not in b:
            errors.append(f"Check1: cache_behaviors[{i}] missing path_pattern")
        elif not isinstance(b["path_pattern"], str):
            errors.append(f"Check1: cache_behaviors[{i}].path_pattern is not a string")
        if "precedence" not in b:
            errors.append(f"Check1: cache_behaviors[{i}] missing precedence")
        elif not isinstance(b["precedence"], int):
            errors.append(f"Check1: cache_behaviors[{i}].precedence is not an integer")

    # Check 2: origin.domain validity
    for i, b in enumerate(behaviors):
        origin = b.get("origin", {})
        domain = origin.get("domain", "")
        if not domain:
            errors.append(f"Check2: cache_behaviors[{i}].origin.domain is empty")
        elif not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$', domain):
            errors.append(f"Check2: cache_behaviors[{i}].origin.domain '{domain}' is not a valid hostname")

    # Check 3: viewer_request_ops entry completeness
    for i, b in enumerate(behaviors):
        for j, op in enumerate(b.get("viewer_request_ops", [])):
            if "type" not in op:
                errors.append(f"Check3: cache_behaviors[{i}].viewer_request_ops[{j}] missing type")
            elif op["type"] in _FORBIDDEN_OP_TYPES:
                errors.append(f"Check3: cache_behaviors[{i}].viewer_request_ops[{j}] has "
                              f"forbidden op type '{op['type']}' (header `add` is non-convertible)")
            if "cf_source_rule" not in op:
                errors.append(f"Check3: cache_behaviors[{i}].viewer_request_ops[{j}] missing cf_source_rule")
        for j, op in enumerate(b.get("viewer_response_ops", [])):
            if "type" not in op:
                errors.append(f"Check3: cache_behaviors[{i}].viewer_response_ops[{j}] missing type")
            elif op["type"] in _FORBIDDEN_OP_TYPES:
                errors.append(f"Check3: cache_behaviors[{i}].viewer_response_ops[{j}] has "
                              f"forbidden op type '{op['type']}' (header `add` is non-convertible)")

    # Check 3b: FULL viewer-op validator (round-26 finding 2 → round-27 finding 2 → review-2
    # finding 3). Every persisted viewer op must satisfy validate_viewer_op — the SINGLE op-shape +
    # condition authority the processor sink and the generator also consult (no separate, drifting
    # allow-lists). This is the persisted-IR HARD GATE for the "processor parses once, generator
    # renders the AST" boundary: it rejects an unknown op type (the generator would emit a bare
    # `// TODO` while the ledger claimed it converted), wrong phase, illegal redirect status_code,
    # non-bool preserve_query_string, invalid header name, UNKNOWN param, a leftover legacy raw
    # field, a lowered param wrong for its SLOT, AND a malformed/absent condition (list/str →
    # generator AttributeError; unknown-key dict → silent if(false); neither/both condition+raw).
    # It SUBSUMES the old Check11 (condition⊕raw mutual-exclusivity) for every registry op type.
    for i, b in enumerate(behaviors):
        for opsname, phase in (("viewer_request_ops", "request"), ("viewer_response_ops", "response")):
            for j, op in enumerate(b.get(opsname, [])):
                t = op.get("type", "")
                reason = validate_viewer_op(op, phase)
                if reason:
                    errors.append(f"Check3b: cache_behaviors[{i}].{opsname}[{j}] ({t}) "
                                  f"violates the viewer-op contract: {reason}")

    # Check 4: non_convertible reason non-empty
    for i, b in enumerate(behaviors):
        for j, nc in enumerate(b.get("non_convertible", [])):
            reason = nc.get("reason", "")
            if not reason or not reason.strip():
                errors.append(f"Check4: cache_behaviors[{i}].non_convertible[{j}] has empty reason")

    # Check 5: precedence uniqueness
    precs = [b.get("precedence") for b in behaviors if b.get("precedence") is not None]
    if len(precs) != len(set(precs)):
        dupes = [p for p in precs if precs.count(p) > 1]
        errors.append(f"Check5: duplicate precedence values: {sorted(set(dupes))}")

    # Check 6: viewer_request_ops type ordering (by group)
    for i, b in enumerate(behaviors):
        ops = b.get("viewer_request_ops", [])
        last_group = -1
        for j, op in enumerate(ops):
            op_type = op.get("type", "")
            group = VR_OPS_ORDER_GROUP.get(op_type, 99)
            if group < last_group:
                errors.append(
                    f"Check6: cache_behaviors[{i}].viewer_request_ops[{j}] "
                    f"type '{op_type}' is out of order (after '{ops[j-1].get('type', '')}')"
                )
                break
            last_group = group

    # Check 7: hostname matches filename
    expected_hostname = filename.replace(".json", "")
    if hostname != expected_hostname:
        errors.append(f"Check7: metadata.hostname '{hostname}' does not match filename '{expected_hostname}'")

    # Check 8: KVS requirements consistency
    kvs_req = ir.get("metadata", {}).get("kvs_requirements", {})
    kvs_data = ir.get("metadata", {}).get("kvs_data", [])
    has_any_kvs_flag = any(kvs_req.values())
    if has_any_kvs_flag and not kvs_data:
        errors.append("Check8: kvs_requirements has active flags but kvs_data is empty")
    if kvs_req.get("needs_redirects") and not any(e.get("key", "").startswith("redirect:") for e in kvs_data):
        errors.append("Check8: needs_redirects is true but no redirect: entries in kvs_data")

    # Check 9: metadata required fields
    metadata = ir.get("metadata", {})
    for field in REQUIRED_METADATA_FIELDS:
        if field not in metadata:
            errors.append(f"Check9: metadata missing required field '{field}'")

    # Check 10: no .error.json residual (checked at directory level, not here)

    # Check 11: a converted op must carry a STRUCTURED condition and NO raw_expression (round-27
    # review-3 finding 1 — the raw-drives-codegen seam is closed; raw is an NC diagnostic only).
    # Check3b's validate_viewer_op already enforces this for every registry op; this stays as an
    # explicit, independently-readable statement of the invariant (and catches a non-null raw on
    # any op shape).
    for i, b in enumerate(behaviors):
        for ops_name in ("viewer_request_ops", "viewer_response_ops"):
            for j, op in enumerate(b.get(ops_name, [])):
                if op.get("raw_expression") is not None:
                    errors.append(
                        f"Check11: cache_behaviors[{i}].{ops_name}[{j}] has a raw_expression — a "
                        "converted op must use a structured condition (raw is NC-diagnostic only)"
                    )
                if op.get("condition") is None:
                    errors.append(
                        f"Check11: cache_behaviors[{i}].{ops_name}[{j}] has no structured condition"
                    )

    # Check 12: required_orp_headers consistency
    for i, b in enumerate(behaviors):
        orp_headers = set(b.get("required_orp_headers", []))
        # 12a: all headers must be known
        for h in orp_headers:
            if h not in VALID_ORP_HEADERS:
                errors.append(f"Check12: cache_behaviors[{i}].required_orp_headers contains unknown header '{h}'")
        # 12b: conditions using geo fields must have corresponding ORP headers.
        # Reuse the parser's extract_orp_headers (same iter_condition_children
        # walk, incl. NOT items) so this validator can't drift from the producer.
        needed = set()
        for op in b.get("viewer_request_ops", []) + b.get("viewer_response_ops", []):
            cond = op.get("condition")
            if cond:
                needed.update(extract_orp_headers(cond))
        missing = needed - orp_headers
        if missing:
            warnings.append(
                f"Check12: cache_behaviors[{i}] conditions use fields requiring "
                f"ORP headers {sorted(missing)} but they are not in required_orp_headers"
            )

    # Check 13: required_orp_headers count ≤ 10 (SOFT quota — raisable).
    for i, b in enumerate(behaviors):
        orp_count = len(b.get("required_orp_headers", []))
        if orp_count > 10:
            warnings.append(
                f"Check13: cache_behaviors[{i}] has {orp_count} required_orp_headers "
                f"(default quota 10, SOFT — request a Service Quotas increase before deploying)"
            )

    # Check 14: cache policy headers/cookies/query_strings ≤ 10 (SOFT quota —
    # raisable via Service Quotas, but the config won't deploy until it's raised,
    # so flag as an error).
    for i, b in enumerate(behaviors):
        cp = b.get("cache_policy", {})
        ck = cp.get("cache_key", {})
        for key in ("headers", "cookies"):
            items = ck.get(key, [])
            if isinstance(items, list) and len(items) > 10:
                errors.append(
                    f"Check14: cache_behaviors[{i}].cache_policy.cache_key.{key} "
                    f"has {len(items)} items (default quota 10, SOFT — raise via Service Quotas)"
                )
        qs = ck.get("query_strings")
        if isinstance(qs, list) and len(qs) > 10:
            errors.append(
                f"Check14: cache_behaviors[{i}].cache_policy.cache_key.query_strings "
                f"has {len(qs)} items (default quota 10, SOFT — raise via Service Quotas)"
            )
        qs_list = ck.get("query_strings_list", [])
        if isinstance(qs_list, list) and len(qs_list) > 10:
            errors.append(
                f"Check14: cache_behaviors[{i}].cache_policy.cache_key.query_strings_list "
                f"has {len(qs_list)} items (default quota 10, SOFT — raise via Service Quotas)"
            )

    # Check 15: lambda_edge.origin_response structure (if non-null)
    le = ir.get("metadata", {}).get("lambda_edge", {})
    origin_resp = le.get("origin_response")
    if origin_resp is not None:
        if not isinstance(origin_resp, dict):
            errors.append("Check15: lambda_edge.origin_response is not an object")
        else:
            # Only "default_cache" is produced now (the conditional_cache /
            # conditional_cache_rules path was removed — no generator consumed it).
            resp_type = origin_resp.get("type")
            if resp_type == "default_cache":
                if "custom_ttl_map" not in origin_resp:
                    errors.append("Check15: lambda_edge.origin_response missing custom_ttl_map")
                elif not isinstance(origin_resp.get("custom_ttl_map"), dict):
                    errors.append("Check15: lambda_edge.origin_response.custom_ttl_map is not an object")
            else:
                errors.append(f"Check15: lambda_edge.origin_response.type is '{resp_type}', expected 'default_cache'")

    return errors, warnings


def main():
    if len(sys.argv) < 2:
        print("Usage: cdn-validate-chunk.py <output_dir>", file=sys.stderr)
        sys.exit(2)

    output_dir = os.path.expanduser(sys.argv[1])
    acc_dir = os.path.join(output_dir, "ir", "accumulator")
    val_dir = os.path.join(output_dir, "ir", "validation", "chunk")
    os.makedirs(val_dir, exist_ok=True)

    if not os.path.isdir(acc_dir):
        print(f"ERROR: {acc_dir} not found", file=sys.stderr)
        sys.exit(2)

    # Check 10: detect .error.json residuals
    error_files = [f for f in os.listdir(acc_dir) if f.endswith(".error.json")]

    json_files = sorted(f for f in os.listdir(acc_dir) if f.endswith(".json") and not f.endswith(".error.json"))
    if not json_files:
        print("ERROR: no accumulator JSON files found", file=sys.stderr)
        sys.exit(2)

    all_pass = True
    for filename in json_files:
        filepath = os.path.join(acc_dir, filename)
        hostname = filename.replace(".json", "")

        try:
            with open(filepath) as f:
                ir = json.load(f)
        except json.JSONDecodeError as e:
            report = {
                "hostname": hostname,
                "validator": "cdn-validate-chunk",
                "status": "FAIL",
                "errors": [f"JSON parse error: {e}"],
                "warnings": [],
            }
            _write_report(val_dir, hostname, report)
            all_pass = False
            print(f"FAIL: {hostname} (JSON parse error)")
            continue

        errors, warnings = validate_domain(ir, filename)

        # Check 10: add error if this domain has a .error.json
        err_file = f"{hostname}.error.json"
        if err_file in error_files:
            errors.append(f"Check10: {err_file} exists — preprocess failed for this domain")

        status = "FAIL" if errors else "PASS"
        report = {
            "hostname": hostname,
            "validator": "cdn-validate-chunk",
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

    # Summary
    print(f"\n{'='*60}")
    if error_files:
        print(f"⚠ Preprocess error files detected: {', '.join(error_files)}")
    print(f"Validated {len(json_files)} domains: {'ALL PASS' if all_pass else 'SOME FAILED'}")

    sys.exit(0 if all_pass else 1)


def _write_report(val_dir, hostname, report):
    path = os.path.join(val_dir, f"{hostname}-v1.json")
    with open(path, "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    main()
