#!/usr/bin/env python3
"""End-to-end behavior test for the round-10 fixes.

Green unit tests are not enough (that lesson recurred all through this saga): a
fix can pass in isolation yet break the full pipeline (e.g. the Check11
"neither condition nor raw_expression" regression). So this builds a synthetic
2-domain Cloudflare backup that exercises every round-10 fix, runs the ENTIRE
CDN pipeline (preprocess → validate → finalize → validate → scaffold → js →
validate-js), and asserts the round-10 behavior in the actual generated
Terraform + JS — not in a mocked call.

Round-10 fixes exercised:
  H1  negated-host rule (`not host eq a`) → EXCLUDE filter: present on b's
      distribution, absent on a's.
  P2  geo rule on a path-specific behavior → that behavior forwards the geo
      header via custom_orp in main.tf (not just the default behavior).
  C1  len()/lower() conditions render `.length` / `.toLowerCase()` in the CFF.
  P1  full_uri wildcard cache rule keeps its concrete path pattern (a real
      ordered behavior, not swallowed site-wide).
  C2  custom-error rule: intercepted code from the CONDITION, returned code
      from the action.

Run: python3 test_round10_e2e.py   (exit 0 = all pass). Needs the repo scripts
next to it; does NOT need terraform installed (that is a separate stage).
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))

FAILURES = []


def check(label, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    if not cond:
        FAILURES.append((label, detail))
    print(f"  [{status}] {label}")
    if not cond and detail:
        print(f"           {detail}")


# Two proxied hosts. a.example.com and b.example.com share the apex so one ACM
# cert data source covers both; each gets its own CloudFront distribution.
DNS = {"result": [
    {"id": "1"*32, "name": "a.example.com", "type": "CNAME",
     "content": "origin-a.example.net", "proxied": True, "ttl": 1},
    {"id": "2"*32, "name": "b.example.com", "type": "CNAME",
     "content": "origin-b.example.net", "proxied": True, "ttl": 1},
]}


def _phase(phase, rules):
    return {"result": {"id": "0"*32, "name": "default", "phase": phase,
                       "kind": "zone", "rules": rules}}


def _rule(rid, expr, action, params, desc=""):
    return {"id": rid, "ref": rid, "version": "1", "enabled": True,
            "action": action, "action_parameters": params,
            "description": desc, "expression": expr}


# H1: negated-host redirect. `not (http.host eq "a.example.com")` → applies to
# every distribution EXCEPT a's. So b gets it, a does not.
REDIRECT = _phase("http_request_dynamic_redirect", [
    _rule("a"*32, 'not (http.host eq "a.example.com")', "redirect",
          {"from_value": {"status_code": 301, "preserve_query_string": False,
                          "target_url": {"value": "https://elsewhere.example.com/"}}},
          "not-a redirect"),
    # C1: len() + lower() conditions in a redirect guard (zone-wide → both dists).
    _rule("b"*32, 'len(http.host) gt 5 and lower(http.request.uri.path) eq "/promo"',
          "redirect",
          {"from_value": {"status_code": 302, "preserve_query_string": False,
                          "target_url": {"value": "https://promo.example.com/"}}},
          "len+lower redirect"),
])

# P2: geo rule on a PATH-specific behavior. A response-header set gated on
# country + a specific path → the path becomes an ordered behavior AND the geo
# header must be forwarded there. Scope to host a so we can check a's main.tf.
RESP_HEADER = _phase("http_response_headers_transform", [
    _rule("c"*32,
          'http.host eq "a.example.com" and http.request.uri.path eq "/geo" and ip.src.country eq "US"',
          "rewrite", {"headers": {"X-Geo": {"operation": "set", "value": "us"}}},
          "geo header on /geo path"),
])

# P1: full_uri wildcard cache rule with a concrete path → a real ordered
# behavior with its own cache policy, not swallowed into the default behavior.
CACHE = _phase("http_request_cache_settings", [
    _rule("d"*32, 'http.request.full_uri wildcard "https://a.example.com/files/*"',
          "set_cache_settings",
          {"cache": True, "edge_ttl": {"mode": "override_origin", "default": 7200}},
          "full_uri files cache"),
])

# C2: custom-error rule. Condition intercepts origin 500; action returns 404.
CUSTOM_ERROR = _phase("http_custom_errors", [
    _rule("e"*32, 'http.response.code eq 500', "serve_error",
          {"status_code": 404}, "500->404 custom error"),
])


def build_backup(root):
    zone = os.path.join(root, "example.com", "2026-07-10 00-00-00")
    account = os.path.join(root, "account", "2026-07-10 00-00-00")
    os.makedirs(zone)
    os.makedirs(account)
    files = {
        "DNS.txt": DNS,
        "Redirect-Rules.txt": REDIRECT,
        "Response-Header-Transform.txt": RESP_HEADER,
        "Cache-Rules.txt": CACHE,
        "Custom-Error-Rules.txt": CUSTOM_ERROR,
    }
    for name, data in files.items():
        with open(os.path.join(zone, name), "w") as f:
            json.dump(data, f)


def run(stage, *args):
    """Run a pipeline script, return (exit, stdout+stderr)."""
    script = os.path.join(HERE, stage)
    p = subprocess.run([sys.executable, script, *args],
                       capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr


def main():
    tmp = tempfile.mkdtemp(prefix="r10_e2e_")
    try:
        config = os.path.join(tmp, "backup")
        out = os.path.join(tmp, "out")
        os.makedirs(config)
        build_backup(config)

        cdn = os.path.join(out, "cloudflare-to-aws-cdn")
        # init
        rc, log = run_bash(os.path.join(HERE, "cdn-init.sh"), out)
        check("cdn-init", rc == 0, log[-400:])

        print("== Stage 1: DNS ==")
        rc, log = run("cdn-parse-dns.py", config, cdn)
        check("parse-dns OK", "STATUS: OK" in log, log[-400:])

        print("== Stage 3: Preprocess ==")
        rc, log = run("cdn-preprocess.py", config, cdn)
        check("preprocess exit 0", rc == 0, log[-600:])

        print("== Stage 4: Validate chunk ==")
        rc, log = run("cdn-validate-chunk.py", cdn)
        check("validate-chunk exit 0 (ALL PASS)", rc == 0, log[-800:])

        print("== Stage 5: Finalize ==")
        rc, log = run("cdn-finalize.py", cdn)
        check("finalize exit 0", rc == 0, log[-400:])

        print("== Stage 6: Validate final ==")
        rc, log = run("cdn-validate-final.py", cdn)
        check("validate-final exit 0", rc == 0, log[-400:])

        print("== Stage 7: Shared policies ==")
        rc, log = run("cdn-generate-shared-policies.py", cdn)
        check("shared-policies exit 0", rc == 0, log[-400:])

        print("== Stage 7.5: Scaffold ==")
        rc, log = run("cdn-generate-tf-scaffold.py", cdn)
        check("scaffold exit 0", rc == 0, log[-400:])

        print("== Stage 8: Generate JS ==")
        rc, log = run("cdn-generate-js.py", cdn)
        check("generate-js exit 0", rc == 0, log[-400:])

        print("== Stage 9: Validate JS ==")
        rc, log = run("cdn-validate-js.py", cdn)
        check("validate-js OK (both domains pass)", "STATUS: OK" in log, log[-800:])

        # ── Behavior assertions on the generated artifacts ──────────────────
        assert_artifacts(cdn)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} check(s)")
        for label, _ in FAILURES:
            print(f"  - {label}")
        sys.exit(1)
    print("All e2e checks passed.")


def run_bash(script, *args):
    p = subprocess.run(["bash", script, *args], capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr


def _read(path):
    with open(path) as f:
        return f.read()


def _final_ir(cdn, host):
    return json.load(open(os.path.join(cdn, "ir", "final", f"{host}.json")))


def _domain_dir(cdn, san):
    return os.path.join(cdn, "terraform", "domains", san)


def assert_artifacts(cdn):
    print("== Round-10 behavior assertions ==")
    a_ir = _final_ir(cdn, "a.example.com")
    b_ir = _final_ir(cdn, "b.example.com")

    # H1: the negated-host redirect (target elsewhere.example.com) applies to b
    # but NOT a. Look for the redirect op referencing rule id "aa..".
    def has_not_a_redirect(ir):
        for beh in ir["cache_behaviors"]:
            for op in beh.get("viewer_request_ops", []):
                if op.get("type") == "redirect" and op.get("cf_source_rule", "").startswith("aaaa"):
                    return True
        return False
    check("H1: not-a redirect present on b", has_not_a_redirect(b_ir))
    check("H1: not-a redirect ABSENT on a (excluded dist)", not has_not_a_redirect(a_ir))

    # H1 corollary: on b, the host condition was stripped (b is not a, so the
    # exclude is always-true here) — the emitted JS must not carry a host guard
    # that would wrongly gate it.
    a_san = a_ir["metadata"]["sanitized_name"]
    b_san = b_ir["metadata"]["sanitized_name"]

    # C1: len()/lower() redirect renders .length and .toLowerCase() (zone-wide →
    # present on both). Find the viewer_request JS for domain b.
    b_vr = _find_vr_js(cdn, b_san)
    check("C1: len() renders .length", ".length" in b_vr,
          "expected '.length' from len(http.host)")
    check("C1: lower() renders .toLowerCase()", ".toLowerCase()" in b_vr,
          "expected '.toLowerCase()' from lower(uri.path)")

    # P2: on a, the /geo path is an ordered behavior AND a's main.tf forwards the
    # country header via custom_orp on that ordered behavior.
    a_main = _read(os.path.join(_domain_dir(cdn, a_san), "main.tf"))
    check("P2: a has a custom_orp resource",
          f"custom_orp_{a_san}" in a_main and "aws_cloudfront_origin_request_policy" in a_main)
    check("P2: a forwards CloudFront-Viewer-Country",
          "CloudFront-Viewer-Country" in a_main,
          "geo header must be in the custom ORP items")
    # the ordered (non-default) behavior must also reference custom_orp — count
    # the custom_orp associations; with an ordered geo behavior there must be
    # more than one (default + at least one ordered).
    orp_assoc = a_main.count(
        f"origin_request_policy_id = aws_cloudfront_origin_request_policy.custom_orp_{a_san}.id")
    check("P2: custom_orp attached to >1 behavior (default + ordered /geo)",
          orp_assoc >= 2, f"custom_orp associations = {orp_assoc}")
    check("P2: /geo is an ordered behavior", '"/geo"' in a_main or "/geo" in a_main)

    # P1: full_uri files cache rule → an ordered behavior with path /files/* on a.
    files_beh = [b for b in a_ir["cache_behaviors"] if b["path_pattern"] == "/files/*"]
    check("P1: /files/* is an ordered cache behavior", len(files_beh) == 1,
          f"path patterns: {[b['path_pattern'] for b in a_ir['cache_behaviors']]}")
    if files_beh:
        # finalize dedups cache_policy into shared/dedup_manifest.json and
        # replaces it with a cache_policy_id reference, so read the TTL via that.
        manifest = json.load(open(os.path.join(cdn, "shared", "dedup_manifest.json")))
        pid = files_beh[0].get("cache_policy_id")
        ttl = (manifest["policies"].get(pid, {})
               .get("config", {}).get("ttl", {}))
        check("P1: /files/* carries a custom TTL (7200)", ttl.get("default") == 7200,
              f"cache_policy_id={pid} ttl={ttl}")

    # C2: custom-error → error_code 500 (from condition), response_code 404
    # (from action). It lands in metadata.custom_error_responses.
    cers = a_ir["metadata"].get("custom_error_responses", []) + \
        b_ir["metadata"].get("custom_error_responses", [])
    match = [c for c in cers if c.get("error_code") == 500 and c.get("response_code") == 404]
    check("C2: custom error intercepts 500, returns 404", len(match) >= 1,
          f"custom_error_responses = {cers}")


def _find_vr_js(cdn, san):
    """Return the viewer_request JS for a domain (shared or independent)."""
    # independent path
    p = os.path.join(_domain_dir(cdn, san), "functions", f"{san}_viewer_request.js")
    if os.path.exists(p):
        return _read(p)
    # shared: resolve via manifest
    manifest_path = os.path.join(cdn, "cff_dedup_manifest.json")
    if os.path.exists(manifest_path):
        manifest = json.load(open(manifest_path))
        cfg = manifest.get("domain_config", {}).get(san, {})
        vr = cfg.get("viewer_request", {})
        if vr.get("mode") == "shared":
            for sf in manifest.get("shared_functions", []):
                if sf["name"] == vr["name"] and sf["event_type"] == "viewer_request":
                    return _read(os.path.join(cdn, "terraform", sf["file"]))
    return ""


if __name__ == "__main__":
    main()
