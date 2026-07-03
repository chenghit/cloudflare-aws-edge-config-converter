#!/usr/bin/env python3
"""CDN JS validator — deterministic Python replacement for Stage 9 LLM.

Validates generated CloudFront Function JS and Lambda@Edge handlers.
Checks: forbidden syntax, required structure, IR coverage, KVS consistency, size.

Usage:
    python3 cdn-validate-js.py <output_dir>
"""
import json
import os
import re
import sys
from pathlib import Path

CFF_SIZE_LIMIT = 10240
LAMBDA_SIZE_LIMIT = 1_048_576  # 1 MB

FORBIDDEN_PATTERNS = [
    (r"\?\.", "optional chaining (?.)"),
    (r"\bconst\s*\{", "object destructuring (const {)"),
    (r"\blet\s*\{", "object destructuring (let {)"),
    (r"\bconst\s*\[", "array destructuring (const [)"),
    (r"\blet\s*\[", "array destructuring (let [)"),
    (r"\bPromise\.all\b", "Promise.all"),
    (r"\bPromise\.any\b", "Promise.any"),
    (r"\.then\s*\(", ".then()"),
    (r"\.catch\s*\(", ".catch()"),
]


def validate_domain(ir, output_dir, manifest=None):
    """Validate JS files for a single domain. Returns validation report dict."""
    hostname = ir["metadata"]["hostname"]
    sanitized = ir["metadata"]["sanitized_name"]
    domain_dir = os.path.join(output_dir, "terraform", "domains", sanitized)
    functions_dir = os.path.join(domain_dir, "functions")
    lambda_dir = os.path.join(domain_dir, "lambda")

    checks = []

    # Resolve JS file paths via dedup manifest (shared or independent)
    vr_path = None
    vresp_path = None

    if manifest:
        cfg = manifest.get("domain_config", {}).get(sanitized, {})
        vr_cfg = cfg.get("viewer_request", {})
        vresp_cfg = cfg.get("viewer_response", {})

        if vr_cfg.get("mode") == "shared":
            for sf in manifest.get("shared_functions", []):
                if sf["name"] == vr_cfg["name"] and sf["event_type"] == "viewer_request":
                    vr_path = os.path.join(output_dir, "terraform", sf["file"])
                    break
        elif vr_cfg.get("mode") == "independent":
            vr_path = os.path.join(functions_dir, f"{sanitized}_viewer_request.js")

        if vresp_cfg.get("mode") == "shared":
            for sf in manifest.get("shared_functions", []):
                if sf["name"] == vresp_cfg["name"] and sf["event_type"] == "viewer_response":
                    vresp_path = os.path.join(output_dir, "terraform", sf["file"])
                    break
        elif vresp_cfg.get("mode") == "independent":
            vresp_path = os.path.join(functions_dir, f"{sanitized}_viewer_response.js")
    else:
        # No manifest — legacy mode (pre-dedup)
        vr_path = os.path.join(functions_dir, f"{sanitized}_viewer_request.js")
        vresp_path = os.path.join(functions_dir, f"{sanitized}_viewer_response.js")

    if not vr_path or not os.path.exists(vr_path):
        checks.append({"name": "file_exists", "status": "FAIL", "detail": f"Missing viewer_request JS: {vr_path}"})
        return _report(hostname, "FAIL", checks)

    with open(vr_path) as f:
        vr_js = f.read()

    # 1. Forbidden syntax
    forbidden_found = []
    for pattern, desc in FORBIDDEN_PATTERNS:
        if re.search(pattern, vr_js):
            forbidden_found.append(desc)
    checks.append({
        "name": "forbidden_syntax",
        "status": "FAIL" if forbidden_found else "PASS",
        "detail": ", ".join(forbidden_found) if forbidden_found else None,
    })

    # 2. Required structure
    struct_issues = []
    needs_cf_import = "cf.kvs(" in vr_js or "cf.updateRequestOrigin(" in vr_js
    if needs_cf_import and "import cf from 'cloudfront'" not in vr_js:
        struct_issues.append("Missing: import cf from 'cloudfront'")
    if "async function handler(event)" not in vr_js and "async function handler (event)" not in vr_js:
        struct_issues.append("Missing: async function handler(event)")
    if "return request" not in vr_js and "return {statusCode" not in vr_js:
        struct_issues.append("Missing: return request or return response")
    # Broken-output signatures: a redirect to an empty Location or a rewrite to
    # an empty URI means the value was silently lost (past key-mismatch bugs).
    # NOTE: these strings are coupled to _generate_op_js's exact emit format in
    # cdn-generate-js.py (redirect body, rewrite `request.uri = ...`) and to the
    # `no CloudFront source for` marker in _dyn_field_to_js. If that emitted JS
    # is reformatted, update these signatures or the tripwires silently stop
    # matching. test_dynamic_values.py exercises the generator output directly.
    if "location: {value: ''}" in vr_js:
        struct_issues.append("redirect emits empty Location value")
    if "request.uri = '';" in vr_js:
        struct_issues.append("rewrite emits empty request.uri")
    # A field with no CloudFront source that leaked into emitted JS.
    if "no CloudFront source for" in vr_js:
        struct_issues.append("unresolved Cloudflare field leaked into JS")
    checks.append({
        "name": "required_structure",
        "status": "FAIL" if struct_issues else "PASS",
        "detail": "; ".join(struct_issues) if struct_issues else None,
    })

    # 3. IR coverage
    all_ops = []
    for beh in ir.get("cache_behaviors", []):
        all_ops.extend(beh.get("viewer_request_ops", []))
    coverage_issues = []
    for op in all_ops:
        op_type = op.get("type", "")
        if op_type == "redirect" and "statusCode" not in vr_js and "statusCode:" not in vr_js:
            coverage_issues.append(f"redirect op missing statusCode")
        elif op_type == "rewrite":
            params = op.get("params", {})
            wants_path = bool(params.get("path") or params.get("path_expression"))
            wants_query = bool(params.get("query_expression") or params.get("new_query"))
            if wants_path and "request.uri =" not in vr_js and "request.uri=" not in vr_js:
                coverage_issues.append("rewrite op missing request.uri assignment")
            if wants_query and "request.querystring" not in vr_js:
                coverage_issues.append("rewrite op missing request.querystring assignment")
        elif op_type == "origin_override":
            # May have been escalated to Lambda@Edge
            le_path = os.path.join(lambda_dir, "origin_request_handler.js")
            if "updateRequestOrigin" not in vr_js and not os.path.exists(le_path):
                coverage_issues.append(f"origin_override missing from both CFF and L@E")
        elif op_type == "bulk_redirect" and "redirect:" not in vr_js:
            coverage_issues.append(f"bulk_redirect missing KVS lookup")
        elif op_type == "serve_error_inline":
            kvs_key = op.get("params", {}).get("kvs_key", "")
            if kvs_key and kvs_key not in vr_js:
                coverage_issues.append(f"serve_error_inline missing KVS key: {kvs_key}")
    checks.append({
        "name": "ir_coverage",
        "status": "FAIL" if coverage_issues else "PASS",
        "ops_checked": len(all_ops),
        "detail": "; ".join(coverage_issues) if coverage_issues else None,
    })

    # 4. KVS consistency
    kvs_req = ir.get("metadata", {}).get("kvs_requirements", {})
    needs_kvs = any(kvs_req.values())
    has_kvs = "cf.kvs(" in vr_js
    kvs_issues = []
    if needs_kvs and not has_kvs:
        kvs_issues.append("IR requires KVS but cf.kvs() not found in JS")
    if not needs_kvs and has_kvs:
        kvs_issues.append("JS has cf.kvs() but IR has no KVS requirements")
    checks.append({
        "name": "kvs_consistency",
        "status": "FAIL" if kvs_issues else "PASS",
        "detail": "; ".join(kvs_issues) if kvs_issues else None,
    })

    # 5. Size limit
    vr_size = len(vr_js.encode("utf-8"))
    size_ok = vr_size <= CFF_SIZE_LIMIT
    checks.append({
        "name": "size_limit",
        "status": "PASS" if size_ok else "FAIL",
        "bytes": vr_size,
        "detail": f"{vr_size} bytes exceeds {CFF_SIZE_LIMIT}" if not size_ok else None,
    })

    # Validate viewer_response.js if exists
    if vresp_path and os.path.exists(vresp_path):
        with open(vresp_path) as f:
            vresp_js = f.read()
        resp_issues = []
        for pattern, desc in FORBIDDEN_PATTERNS:
            if re.search(pattern, vresp_js):
                resp_issues.append(desc)
        if "return response" not in vresp_js:
            resp_issues.append("Missing: return response")
        checks.append({
            "name": "viewer_response",
            "status": "FAIL" if resp_issues else "PASS",
            "detail": "; ".join(resp_issues) if resp_issues else None,
        })

    # Validate Lambda@Edge files if exist
    le_or_path = os.path.join(lambda_dir, "origin_request_handler.js")
    if os.path.exists(le_or_path):
        with open(le_or_path) as f:
            le_js = f.read()
        le_issues = []
        if "exports.handler" not in le_js:
            le_issues.append("Missing: exports.handler")
        if "callback(null, request)" not in le_js:
            le_issues.append("Missing: callback(null, request)")
        le_size = len(le_js.encode("utf-8"))
        if le_size > LAMBDA_SIZE_LIMIT:
            le_issues.append(f"Size {le_size} exceeds Lambda@Edge limit")
        checks.append({
            "name": "lambda_origin_request",
            "status": "FAIL" if le_issues else "PASS",
            "detail": "; ".join(le_issues) if le_issues else None,
        })

    overall = "FAIL" if any(c["status"] == "FAIL" for c in checks) else "PASS"
    return _report(hostname, overall, checks)


def _report(hostname, overall, checks):
    return {
        "hostname": hostname,
        "overall_status": overall,
        "checks": [{k: v for k, v in c.items() if v is not None} for c in checks],
    }


def main():
    if len(sys.argv) < 2:
        print("Usage: cdn-validate-js.py <output_dir>", file=sys.stderr)
        sys.exit(2)

    output_dir = sys.argv[1]
    ir_dir = os.path.join(output_dir, "ir", "final")
    val_dir = os.path.join(output_dir, "ir", "validation", "js")
    os.makedirs(val_dir, exist_ok=True)

    if not os.path.isdir(ir_dir):
        print(f"---RESULT---\nSPEC: 1\nSTATUS: FATAL\nACTION: FIX\nCONTEXT: IR directory not found: {ir_dir}")
        sys.exit(2)

    ir_files = sorted(Path(ir_dir).glob("*.json"))
    if not ir_files:
        print(f"---RESULT---\nSPEC: 1\nSTATUS: FATAL\nACTION: FIX\nCONTEXT: No IR files found in {ir_dir}")
        sys.exit(2)

    # Load manifest once (if exists)
    manifest_path = os.path.join(output_dir, "cff_dedup_manifest.json")
    manifest = None
    if os.path.exists(manifest_path):
        with open(manifest_path) as f:
            manifest = json.load(f)

    results = []
    for ir_file in ir_files:
        with open(ir_file) as f:
            ir = json.load(f)
        report = validate_domain(ir, output_dir, manifest)
        hostname = report["hostname"]
        # Write per-domain report
        report_path = os.path.join(val_dir, f"{hostname}-v3.json")
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)
        results.append(report)
        print(f"[VALIDATE] {hostname}: {report['overall_status']}", file=sys.stderr)

    pass_count = sum(1 for r in results if r["overall_status"] == "PASS")
    fail_count = sum(1 for r in results if r["overall_status"] == "FAIL")

    if fail_count == 0:
        print(f"\n---RESULT---\nSPEC: 1\nSTATUS: OK\nDOMAINS: {len(results)}\nPASSED: {pass_count}\n"
              f"POST_ACTION: If user language is not English, translate conversion_report.md to user language and save as conversion_report_{{lang}}.md")
    else:
        failed_items = "\n".join(
            f"  {r['hostname']}: {', '.join(c['name'] + '=' + c['status'] for c in r['checks'] if c['status'] == 'FAIL')}"
            for r in results if r["overall_status"] == "FAIL"
        )
        print(f"\n---RESULT---\nSPEC: 1\nSTATUS: ERROR\nPASSED: {pass_count}\nFAILED: {fail_count}\nFAILED_ITEMS:\n{failed_items}\nACTION: FIX\nCONTEXT: {fail_count} domain(s) failed JS validation")
        sys.exit(1)


if __name__ == "__main__":
    main()
