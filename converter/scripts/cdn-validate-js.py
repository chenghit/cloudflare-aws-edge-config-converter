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

    # Read viewer_response JS up front (if any) so broken-output tripwires can
    # scan it too — a dropped value or leaked field can occur in a response op
    # (set_response_header, redirect condition) just as in a request op.
    vresp_js = ""
    if vresp_path and os.path.exists(vresp_path):
        with open(vresp_path) as f:
            vresp_js = f.read()

    # 2. Required structure
    struct_issues = []
    needs_cf_import = "cf.kvs(" in vr_js or "cf.updateRequestOrigin(" in vr_js
    if needs_cf_import and "import cf from 'cloudfront'" not in vr_js:
        struct_issues.append("Missing: import cf from 'cloudfront'")
    if "async function handler(event)" not in vr_js and "async function handler (event)" not in vr_js:
        struct_issues.append("Missing: async function handler(event)")
    if "return request" not in vr_js and "return {statusCode" not in vr_js:
        struct_issues.append("Missing: return request or return response")
    struct_issues.extend(_broken_output_signatures(vr_js, vresp_js))
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
            # Look for the ASSIGNMENT (`request.querystring =`), not a bare
            # `request.querystring` read — the bulk_redirect template reads
            # `_qs(request.querystring)`, which would otherwise mask a dropped
            # query rewrite on any domain that also has bulk redirects.
            if wants_query and "request.querystring =" not in vr_js and "request.querystring=" not in vr_js:
                coverage_issues.append("rewrite op missing request.querystring assignment")
        elif op_type == "origin_override":
            # origin_override is always in the viewer-request CFF via
            # cf.updateRequestOrigin (viewer events are CFF-only — never
            # escalated to Lambda@Edge).
            if "updateRequestOrigin" not in vr_js:
                coverage_issues.append("origin_override missing updateRequestOrigin in CFF")
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

    # 4. KVS consistency. cf.kvs() emission is PER-HANDLER (a response-only KVS
    # need puts cf.kvs() in viewer_response.js, not viewer_request.js), so check
    # BOTH handlers — testing only vr_js would spuriously FAIL a response-only
    # KVS domain and abort the pipeline.
    # Validate each handler is SELF-consistent: it declares `cf.kvs()` iff it
    # actually reads `kvsHandle`. This is drift-proof — it doesn't compare
    # against the domain-wide kvs_requirements flag (which is per-domain, while
    # emission is per-handler, so a response-only need would false-FAIL a
    # vr_js-only check). A handle declared-but-unused, or used-but-undeclared
    # (ReferenceError), is the real defect to catch.
    kvs_issues = []
    for label, js in (("viewer_request", vr_js), ("viewer_response", vresp_js)):
        if not js:
            continue
        declares = "cf.kvs(" in js
        # "uses" = kvsHandle referenced OUTSIDE its own declaration. The handle
        # is emitted as `const kvsHandle = cf.kvs();`, and that line itself
        # contains the token "kvsHandle" — so strip the whole declaration before
        # looking, not just the `cf.kvs(` call (stripping only the call leaves
        # `const kvsHandle = )`, whose "kvsHandle" made `uses` always True and
        # the declared-but-unused arm dead).
        without_decl = re.sub(r"const\s+kvsHandle\s*=\s*cf\.kvs\([^)]*\)\s*;?", "", js)
        uses = "kvsHandle" in without_decl
        if uses and not declares:
            kvs_issues.append(f"{label}: uses kvsHandle without cf.kvs() (ReferenceError)")
        if declares and not uses:
            kvs_issues.append(f"{label}: declares cf.kvs() but never uses kvsHandle")
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

    # Validate viewer_response.js if exists (vresp_js already read above)
    if vresp_path and os.path.exists(vresp_path):
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

    # Validate the Lambda@Edge origin-RESPONSE handler if present (the only L@E
    # this tool emits — default-cache/custom-error origin-response; viewer events
    # are CFF-only, so there is no origin-request handler to validate).
    le_resp_path = os.path.join(lambda_dir, "default_cache_origin_response.js")
    if os.path.exists(le_resp_path):
        with open(le_resp_path) as f:
            le_js = f.read()
        le_issues = []
        if "exports.handler" not in le_js:
            le_issues.append("Missing: exports.handler")
        if "callback(null, response)" not in le_js and "callback(null, request)" not in le_js:
            le_issues.append("Missing: callback(null, ...)")
        le_size = len(le_js.encode("utf-8"))
        if le_size > LAMBDA_SIZE_LIMIT:
            le_issues.append(f"Size {le_size} exceeds Lambda@Edge limit")
        checks.append({
            "name": "lambda_origin_response",
            "status": "FAIL" if le_issues else "PASS",
            "detail": "; ".join(le_issues) if le_issues else None,
        })

    overall = "FAIL" if any(c["status"] == "FAIL" for c in checks) else "PASS"
    return _report(hostname, overall, checks)


def _broken_output_signatures(*js_sources):
    """Scan generated JS for signatures of a silently-lost action value.

    Applied to BOTH the viewer-request and viewer-response JS (a redirect to an
    empty Location, a rewrite to an empty URI, or a leaked no-source field can
    appear in either handler).

    These signatures are coupled to _generate_op_js's emit format in
    cdn-generate-js.py: the redirect body (`location: {value: ...}`), the
    rewrite assignment (`request.uri = ...`), and the `no CloudFront source
    for` leak marker emitted by _dyn_field_to_js / _resolve_expression_value.
    The leak marker is a stable contract shared with the generator; the two
    empty-value signatures track the redirect/rewrite emit format — if that
    format changes, update these.
    """
    issues = []
    combined = "\n".join(js_sources)
    if "location: {value: ''}" in combined:
        issues.append("redirect emits empty Location value")
    if "request.uri = '';" in combined:
        issues.append("rewrite emits empty request.uri")
    if "no CloudFront source for" in combined:
        issues.append("unresolved Cloudflare field leaked into JS")
    return issues


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
    s3_hosts = []  # hosts with an S3 origin — need a manual bucket-policy step
    for ir_file in ir_files:
        with open(ir_file) as f:
            ir = json.load(f)
        report = validate_domain(ir, output_dir, manifest)
        hostname = report["hostname"]
        if any(b.get("origin", {}).get("s3_origin") for b in ir.get("cache_behaviors", [])):
            s3_hosts.append(hostname)
        # Write per-domain report
        report_path = os.path.join(val_dir, f"{hostname}-v3.json")
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)
        results.append(report)
        print(f"[VALIDATE] {hostname}: {report['overall_status']}", file=sys.stderr)

    pass_count = sum(1 for r in results if r["overall_status"] == "PASS")
    fail_count = sum(1 for r in results if r["overall_status"] == "FAIL")

    # A CloudFront OAC is only half of S3 access — the user MUST also add an S3
    # bucket policy allowing the distribution, or every request 403s. The
    # converter can't do it (the bucket may be in another account, and the
    # distribution ARN isn't known until apply). Surface it so the agent tells
    # the user and doesn't report "done" on an S3 domain that will 403.
    # One POST_ACTION value, multi-step (2-space-indented continuation lines per
    # SCRIPT_STANDARDS / SKILL.md) — a second `POST_ACTION:` key would break parsing.
    s3_step = ""
    if s3_hosts:
        s3_step = (
            f"\n  MANDATORY MANUAL STEP for {len(s3_hosts)} S3-origin domain(s) "
            f"({', '.join(s3_hosts)}): the generated OAC is only the CloudFront side. "
            f"After `terraform apply`, the user MUST add an S3 bucket policy allowing "
            f"cloudfront.amazonaws.com with the distribution ARN (AWS:SourceArn), or S3 "
            f"returns 403 for every request. Exact policy JSON is in conversion_report.md "
            f"('Post-Deployment: S3 Bucket Policy'). Tell the user this is required. "
            f"(S3 website-endpoint origins instead need public read access — no OAC.)")

    # Build the DEPLOY_SUMMARY from cdn_summary.json (written by cdn-finalize +
    # cdn-generate-js). This is the LAST thing the agent sees for the CDN
    # pipeline, so every deploy concern must be here — intermediate step RESULTs
    # get diluted by later steps (esp. report translation).
    # cdn_summary.json is written by cdn-finalize (Stage 5) and augmented by
    # cdn-generate-js (Stage 8) — both run before this final step, so it MUST be
    # present and readable here. Defaulting to {} on failure would silently drop
    # every deploy concern — including a deploy-blocking QUOTA-REDESIGN — and
    # still print STATUS: OK. Fail LOUD instead: a hidden hard-limit breach is
    # far worse than a noisy stop.
    summary_lines = []
    summary_path = os.path.join(output_dir, "cdn_summary.json")
    try:
        with open(summary_path) as f:
            _s = json.load(f)
    except Exception as e:
        print(f"\n---RESULT---\nSPEC: 1\nSTATUS: FATAL\nACTION: FIX\n"
              f"CONTEXT: cdn_summary.json missing or unreadable ({e}) — it carries the "
              f"deploy summary and any quota blockers. Re-run Stage 5 (cdn-finalize) and "
              f"Stage 8 (cdn-generate-js) before this step. Refusing to report STATUS: OK "
              f"without it.")
        sys.exit(2)
    if _s:
        summary_lines.append(f"Domains: {_s.get('domains','?')}, unique policies: "
                             f"{_s.get('total_policies','?')}, CFF: {_s.get('cff_dedup','?')}, "
                             f"KVS stores: {_s.get('kvs_total','?')}")
        if _s.get("non_convertible_items"):
            summary_lines.append(f"{_s['non_convertible_items']} non-convertible item(s) — "
                                 f"see conversion_report.md.")
        if _s.get("skipped_domains"):
            summary_lines.append(f"SKIPPED domains: {', '.join(_s['skipped_domains'])}")
        # Warnings from cdn-finalize / cdn-generate-js already carry their own
        # action tag (QUOTA-RAISE = raise the quota then deploy; QUOTA-REDESIGN =
        # HARD limit, deploy blocked until the source is redesigned). Pass them
        # through verbatim — do NOT re-prefix — so the tag reaches the agent.
        for w in _s.get("warnings", []):
            summary_lines.append(w if w.startswith("QUOTA-") else f"QUOTA/WARNING — {w}")
    # Any HARD-limit breach makes the config undeployable as-is (no quota bump
    # exists) — surface it as a distinct deploy blocker the agent must not skip.
    redesign = [w for w in _s.get("warnings", []) if w.startswith("QUOTA-REDESIGN")]
    # ACM is the hardest prerequisite: the generated Terraform reads each cert via
    # `data "aws_acm_certificate"` (or an explicit ARN), so `terraform plan`
    # FAILS immediately if the cert isn't already ISSUED in us-east-1. This is a
    # deploy blocker for EVERY CDN deployment — always surface it, first.
    summary_lines.append("PRE-DEPLOY BLOCKER — ACM certificates MUST exist and be ISSUED in "
                         "us-east-1 (N. Virginia) BEFORE `terraform apply`, one covering every "
                         "custom domain (a `*.apex` wildcard works). CloudFront only accepts "
                         "us-east-1 certs; the Terraform looks them up via a data source, so a "
                         "missing/pending/wrong-region cert fails `terraform plan` outright. "
                         "Provision + validate them first.")
    if _s.get("s3_oac_bucket_policy_required"):
        summary_lines.append("PRE-DEPLOY ACTION — S3-origin domains need a manual S3 bucket "
                             "policy for the CloudFront OAC (else 403); policy JSON in "
                             "conversion_report.md. See POST_ACTION.")
    deploy_summary = ("\nDEPLOY_SUMMARY:\n" + "\n".join(f"  {l}" for l in summary_lines)) \
        if summary_lines else ""

    if fail_count == 0:
        # A HARD-limit (QUOTA-REDESIGN) breach means the artifact is generated but
        # NOT deployable as-is, and no quota increase will help. That is a
        # structural STATUS: BLOCKED (per SCRIPT_STANDARDS — same class as the WAF
        # generator's hard-cap block), not a free-text note under STATUS: OK, so
        # an agent can branch on it without parsing prose. Exit stays 0: the JS is
        # valid and the pipeline completed; BLOCKED carries the "don't deploy"
        # signal. The full DEPLOY_SUMMARY + POST_ACTION ride along either way.
        post_action = (
            f"POST_ACTION: Do ALL of the following, in order:"
            f"\n  1. REPORT the full DEPLOY_SUMMARY above to the user — every line — as the CDN completion summary."
            f" QUOTA-RAISE line(s) mean the conversion is correct but deploy is blocked until the user"
            f" requests that quota increase; relay each one so the user can raise it before applying."
            f"\n  2. Before ANY `terraform apply`, confirm with the user that ACM certificates are"
            f" already ISSUED in us-east-1 for every custom domain (see the PRE-DEPLOY BLOCKER line)."
            f" If not, tell them to provision + validate them first — apply will fail otherwise."
            f"{s3_step}"
            f"\n  3. If user language is not English, translate conversion_report.md to that language as conversion_report_{{lang}}.md.")
        if redesign:
            items = "\n".join(f"  {w}" for w in redesign)
            print(f"\n---RESULT---\nSPEC: 1\nSTATUS: BLOCKED\nDOMAINS: {len(results)}\nPASSED: {pass_count}"
                  f"{deploy_summary}\n"
                  f"BLOCKED_COUNT: {len(redesign)}\nBLOCKED_ITEMS:\n{items}\n"
                  f"ACTION: FIX\n"
                  f"CONTEXT: The Terraform was generated and the JS is valid, but the item(s) "
                  f"above breach a HARD CloudFront limit (not raisable via Service Quotas/Support). "
                  f"Deploy will be REJECTED as-is. Do NOT `terraform apply` — reduce/redesign the "
                  f"named item in the source Cloudflare config (e.g. split KVS data across stores), "
                  f"then re-run.\n"
                  f"{post_action}")
        else:
            print(f"\n---RESULT---\nSPEC: 1\nSTATUS: OK\nDOMAINS: {len(results)}\nPASSED: {pass_count}"
                  f"{deploy_summary}\n"
                  f"{post_action}")
    else:
        failed_items = "\n".join(
            f"  {r['hostname']}: {', '.join(c['name'] + '=' + c['status'] for c in r['checks'] if c['status'] == 'FAIL')}"
            for r in results if r["overall_status"] == "FAIL"
        )
        # A JS-validation failure on one domain must NOT bury a deploy blocker on
        # another. Carry the full DEPLOY_SUMMARY here too, and if any
        # QUOTA-REDESIGN hard-limit breach exists, call it out — it survives
        # fixing the JS failure and would otherwise be invisible in this branch.
        redesign_note = ""
        if redesign:
            redesign_note = ("\n⛔ DEPLOY BLOCKED (separate from the JS failures above) — the "
                             "DEPLOY_SUMMARY has QUOTA-REDESIGN line(s): a HARD CloudFront limit "
                             "is exceeded and cannot be raised. Even after the failed domains are "
                             "fixed, do NOT deploy until the source is redesigned. Report this to "
                             "the user.")
        print(f"\n---RESULT---\nSPEC: 1\nSTATUS: ERROR\nPASSED: {pass_count}\nFAILED: {fail_count}\n"
              f"FAILED_ITEMS:\n{failed_items}\nACTION: FIX\n"
              f"CONTEXT: {fail_count} domain(s) failed JS validation"
              f"{deploy_summary}{redesign_note}")
        sys.exit(1)


if __name__ == "__main__":
    main()
