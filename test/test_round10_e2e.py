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

Run: python3 test_round10_e2e.py   (exit 0 = all pass). Runs the real pipeline
scripts from converter/scripts/; does NOT need terraform installed (that is a
separate stage).
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

# Production scripts live in converter/scripts/; this test lives in /test/ (a
# gitignored, development-only tree). Resolve the scripts dir from the repo root.
_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(_REPO, "converter", "scripts")

# Load the scaffold module so the managed-ORP UUIDs come from its constants
# (single source of truth) instead of being re-hardcoded in assertions.
import importlib.util as _ilu
_spec = _ilu.spec_from_file_location("cdn_scaffold", os.path.join(SCRIPTS, "cdn-generate-tf-scaffold.py"))
_scaf = _ilu.module_from_spec(_spec); _spec.loader.exec_module(_scaf)
ORP_ALL_VIEWER = _scaf._MANAGED_ORP_ALL_VIEWER
# Old AllViewerExceptHostHeader id — the ExceptHost branch was removed (host
# overrides now always use AllViewer, since updateRequestOrigin({hostHeader})
# wins over the forwarded Host). Kept here only to assert it is NEVER emitted.
ORP_EXCEPT_HOST = "b689b0a8-53d0-40ab-baf2-68738e2966ac"

FAILURES = []


def check(label, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    if not cond:
        FAILURES.append((label, detail))
    print(f"  [{status}] {label}")
    if not cond and detail:
        print(f"           {detail}")


# Proxied hosts sharing the apex (one ACM cert), each its own distribution.
#   a — geo/native-header rules → custom_orp
#   b — no native header, no host override → managed AllViewer (forward viewer Host)
#   c — an UNCONDITIONAL Origin Rule host_header override → AllViewer (updateRequestOrigin wins)
#   s — S3 (REST endpoint) origin → OAC, NO ORP (Host forwarding breaks SigV4)
#   d — a CONDITIONAL host_header override → must stay AllViewer (round-16 #3)
DNS = {"result": [
    {"id": "1"*32, "name": "a.example.com", "type": "CNAME",
     "content": "origin-a.example.net", "proxied": True, "ttl": 1},
    {"id": "2"*32, "name": "b.example.com", "type": "CNAME",
     "content": "origin-b.example.net", "proxied": True, "ttl": 1},
    {"id": "3"*32, "name": "c.example.com", "type": "CNAME",
     "content": "origin-c.example.net", "proxied": True, "ttl": 1},
    {"id": "4"*32, "name": "s.example.com", "type": "CNAME",
     "content": "assets-bucket.s3.us-east-1.amazonaws.com", "proxied": True, "ttl": 1},
    {"id": "5"*32, "name": "d.example.com", "type": "CNAME",
     "content": "origin-d.example.net", "proxied": True, "ttl": 1},
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
    # round-11 #1 (worst fail-open): `host ne b AND host eq a` == only a. The
    # round-10 algebra returned exclude[b] → applied to a AND b, and after
    # host-strip fired unconditionally on b. Must land ONLY on a's distribution.
    _rule("f"*32, 'http.host ne "b.example.com" and http.host eq "a.example.com"',
          "redirect",
          {"from_value": {"status_code": 307, "preserve_query_string": False,
                          "target_url": {"value": "https://only-a.example.com/"}}},
          "AND-negated-first redirect (a only)"),
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

# Q7c: an UNCONDITIONAL Origin Rule host_header override on c → behavior uses
# AllViewer (updateRequestOrigin({hostHeader}) wins over the forwarded viewer
# Host); the override sets Host via cf.updateRequestOrigin(hostHeader=…) in the
# CFF, never request.headers.host (read-only in viewer-request → 502).
ORIGIN = _phase("http_request_origin", [
    _rule("9"*32, 'http.host eq "c.example.com"', "route",
          {"host_header": "backend-c.internal.example.net"},
          "host override for c"),
    # round-16 #3: a CONDITIONAL host override on d, gated on a query-string test
    # (NOT a host-match, not a path pattern, not a geo field — so it survives
    # host-stripping as a real per-request condition, stays on the default
    # behavior, and pulls in no native header). The behavior must stay AllViewer:
    # dropping the viewer Host for ALL requests (ExceptHost) would strand the
    # non-matching requests with no Host.
    _rule("7"*32, 'http.host eq "d.example.com" and http.request.uri.query contains "beta"', "route",
          {"host_header": "backend-d.internal.example.net"},
          "conditional host override for d"),
    # S3 host-override: Cloudflare needs this (S3 routes by Host); on CloudFront
    # +OAC it's redundant and must be DROPPED, not emitted as a CFF op.
    _rule("8"*32, 'http.host eq "s.example.com"', "route",
          {"host_header": "assets-bucket.s3.us-east-1.amazonaws.com"},
          "S3 bucket host override (redundant on CloudFront)"),
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
        "Origin-Rules.txt": ORIGIN,
    }
    for name, data in files.items():
        with open(os.path.join(zone, name), "w") as f:
            json.dump(data, f)


def run(stage, *args):
    """Run a pipeline script, return (exit, stdout+stderr)."""
    script = os.path.join(SCRIPTS, stage)
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
        rc, log = run_bash(os.path.join(SCRIPTS, "cdn-init.sh"), out)
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
        assert_cff_scope()
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

    # round-11 #1: `host ne b AND host eq a` (rule ff..) == ONLY a. The round-10
    # bug applied it to a AND b and fired unconditionally on b. Must be present
    # on a, absent on b — the worst fail-open, verified end-to-end.
    def has_only_a_redirect(ir):
        for beh in ir["cache_behaviors"]:
            for op in beh.get("viewer_request_ops", []):
                if op.get("type") == "redirect" and op.get("cf_source_rule", "").startswith("ffff"):
                    return True
        return False
    check("R11#1: (host ne b AND host eq a) present on a", has_only_a_redirect(a_ir))
    check("R11#1: (host ne b AND host eq a) ABSENT on b (was fail-open)", not has_only_a_redirect(b_ir))

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

    # P2: on a, the /geo path is an ordered behavior AND a forwards the country
    # header via a SHARED custom ORP (deduped in shared/policies.tf by header
    # set), referenced from a's main.tf by a data source — NOT a per-domain
    # resource (54 identical per-domain resources used to blow the 20-ORP quota).
    a_main = _read(os.path.join(_domain_dir(cdn, a_san), "main.tf"))
    a_headers = sorted({h for beh in a_ir["cache_behaviors"]
                        for h in beh.get("required_orp_headers", [])})
    orp_h = _scaf.custom_orp_hash(a_headers)
    shared_pol = _read(os.path.join(cdn, "terraform", "shared", "policies.tf"))
    check("P2: shared custom ORP resource exists (deduped, not per-domain)",
          f'"custom_orp_{orp_h}"' in shared_pol
          and "aws_cloudfront_origin_request_policy" in shared_pol)
    check("P2: shared custom ORP forwards CloudFront-Viewer-Country",
          "CloudFront-Viewer-Country" in shared_pol,
          "geo header must be in the shared custom ORP items")
    check("P2: a's main.tf has NO per-domain custom_orp resource",
          'resource "aws_cloudfront_origin_request_policy"' not in a_main,
          "per-domain custom ORP resource must be gone (quota fix)")
    # a references the shared ORP by data source on >1 behavior (default + /geo).
    orp_assoc = a_main.count(
        f"origin_request_policy_id = data.aws_cloudfront_origin_request_policy.custom_orp_{orp_h}.id")
    check("P2: shared custom_orp referenced on >1 behavior (default + ordered /geo)",
          orp_assoc >= 2, f"custom_orp data-source references = {orp_assoc}")
    check("P2: a declares the shared ORP data source exactly once",
          a_main.count(f'data "aws_cloudfront_origin_request_policy" "custom_orp_{orp_h}"') == 1)
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

    # ── Q7 (round 13): cookie/query + Host origin-forwarding fidelity ──────────
    # a has geo native headers → shared custom_orp, which must forward all
    # cookies+query (Cloudflare forwards the full request; CloudFront strips
    # without an ORP). Now lives in shared/policies.tf, not the per-domain main.tf.
    check("Q7a: custom_orp forwards all cookies", 'cookie_behavior = "all"' in shared_pol)
    check("Q7a: custom_orp forwards all query strings", 'query_string_behavior = "all"' in shared_pol)
    # b has NO native header and NO host override → managed AllViewer (forwards
    # the original viewer Host, matching Cloudflare's default).
    b_main = _read(os.path.join(_domain_dir(cdn, b_san), "main.tf"))
    check("Q7b: b (no native, no override) uses managed AllViewer",
          ORP_ALL_VIEWER in b_main,
          "expected AllViewer managed ORP id")
    check("Q7b: b's default behavior has a forwarding ORP",
          "default_origin_request_policy_id" in b_main)
    # c has an UNCONDITIONAL Origin Rule host_header override → managed AllViewer
    # (NOT ExceptHost — updateRequestOrigin({hostHeader}) wins over the forwarded
    # Host, proven live, so ExceptHost buys nothing), and the CFF must use
    # updateRequestOrigin(hostHeader=…), NOT request.headers.host (which is
    # read-only in viewer-request → 502).
    c_ir = _final_ir(cdn, "c.example.com")
    c_san = c_ir["metadata"]["sanitized_name"]
    c_main = _read(os.path.join(_domain_dir(cdn, c_san), "main.tf"))
    check("Q7c: c (unconditional host override) uses AllViewer, not ExceptHost",
          ORP_ALL_VIEWER in c_main and ORP_EXCEPT_HOST not in c_main,
          "host override uses AllViewer; updateRequestOrigin sets the Host")
    c_vr = _find_vr_js(cdn, c_san)
    check("Q7c: c CFF sets host via updateRequestOrigin hostHeader",
          "hostHeader:" in c_vr and "backend-c.internal.example.net" in c_vr,
          "expected updateRequestOrigin({... hostHeader: ...})")
    check("Q7c: c CFF does NOT write read-only request.headers.host (502 bug)",
          "request.headers.host =" not in c_vr,
          "viewer-request Host is read-only → 502")

    # round-16 #3: d has a CONDITIONAL host override (country==CN). It must stay
    # AllViewer (forward viewer Host) — NOT AllViewerExceptHostHeader — so
    # non-matching requests keep their Host; the CFF's conditional
    # updateRequestOrigin(hostHeader) wins for matching requests.
    d_ir = _final_ir(cdn, "d.example.com")
    d_san = d_ir["metadata"]["sanitized_name"]
    d_main = _read(os.path.join(_domain_dir(cdn, d_san), "main.tf"))
    # A CONDITIONAL host override must use AllViewer (forward viewer Host), NOT
    # AllViewerExceptHostHeader — else non-matching requests lose their Host.
    check("R16#3: d (conditional host override) uses AllViewer, not ExceptHost",
          ORP_ALL_VIEWER in d_main and ORP_EXCEPT_HOST not in d_main,
          "conditional override must keep viewer Host for non-matching requests")
    d_vr = _find_vr_js(cdn, d_san)
    check("R16#3: d CFF sets host conditionally via updateRequestOrigin",
          "hostHeader:" in d_vr and "backend-d.internal.example.net" in d_vr)

    # round-14: viewer events are CFF-only — no auto Lambda@Edge escalation.
    # c has an origin_override, which used to be a candidate for L@E escalation;
    # it must render as a CFF updateRequestOrigin, and NO origin-request L@E
    # handler / functions.tf resource may be generated anywhere.
    check("R14: c origin_override stays in CFF (updateRequestOrigin)",
          "cf.updateRequestOrigin" in c_vr)
    import glob as _glob
    orh = _glob.glob(os.path.join(cdn, "terraform", "domains", "*", "lambda", "origin_request_handler.js"))
    check("R14: no viewer→L@E origin_request_handler.js generated", not orh,
          f"found: {orh}")
    ft_files = _glob.glob(os.path.join(cdn, "terraform", "domains", "*", "functions.tf"))
    ph = [f for f in ft_files if "LAMBDA_EDGE_PLACEHOLDER" in _read(f)]
    check("R14: no LAMBDA_EDGE_PLACEHOLDER left in functions.tf", not ph, f"found: {ph}")

    # ── S3 (round 15): OAC + no Host-forwarding ORP + redundant override dropped ─
    s_ir = _final_ir(cdn, "s.example.com")
    s_san = s_ir["metadata"]["sanitized_name"]
    s_main = _read(os.path.join(_domain_dir(cdn, s_san), "main.tf"))
    check("S3: OAC resource generated", "aws_cloudfront_origin_access_control" in s_main)
    check("S3: origin marked s3_origin", "s3_origin" in s_main and "origin_access_control_id" in s_main)
    # No ORP on any S3 behavior (Host/header forwarding breaks SigV4 → 403).
    check("S3: NO origin_request_policy_id on the S3 distribution",
          "origin_request_policy_id" not in s_main,
          "S3+OAC must not forward Host/headers")
    # No AllViewer/ExceptHost managed ORP id either.
    check("S3: no managed forward-all ORP id present",
          ORP_ALL_VIEWER not in s_main and ORP_EXCEPT_HOST not in s_main)
    # The redundant S3 host-override rule (id 88..) must be dropped — no
    # origin_override op, no updateRequestOrigin in the S3 domain's CFF.
    s_has_override = any(
        op.get("type") == "origin_override"
        for beh in s_ir["cache_behaviors"] for op in beh.get("viewer_request_ops", []))
    check("S3: redundant host-override rule dropped (no origin_override op)", not s_has_override)
    check("S3: no Host custom_origin_header on the S3 origin",
          'name = "Host"' not in s_main, "S3+OAC needs no Host override")


def assert_cff_scope():
    """#123 — the shared viewer CFF is attached per-behavior by scope, through the
    REAL generate_main_tf (the example config + the fixture above always have a
    zone-wide op, so a DROP never triggers there; this drives the generator with
    hand-built IRs that isolate each case). A behavior gets the CFF iff it has its
    own ops OR the default carries a zone-wide (scope='all') op."""
    def _mk(behs):
        return {"metadata": {"sanitized_name": "z", "hostname": "z.example.com",
                             "apex_domain": "example.com", "cert_domain": "*.example.com",
                             "custom_error_responses": [], "kvs_requirements": {},
                             "lambda_edge": {}},
                "cache_behaviors": behs}
    def _beh(pp, vr_ops):
        return {"path_pattern": pp, "precedence": 1,
                "origin": {"domain": "o.net", "s3_origin": False},
                "cache_policy": {"caching_disabled": False,
                    "ttl": {"min": 0, "default": 7200, "max": 86400},
                    "cache_key": {"headers": [], "cookies": [], "query_strings": "none",
                                  "query_strings_list": [], "query_strings_exclude": []}},
                "cache_policy_id": None, "origin_request_policy_id": None,
                "response_headers_policy_id": None,
                "viewer_request_ops": vr_ops, "viewer_response_ops": [],
                "distribution_settings": {"geo_restriction_type": "none",
                                          "geo_restriction_locations": []}}
    origins = [{"origin_id": "origin_z", "domain": "o.net", "s3_origin": False,
                "protocol": "https", "port": 443}]
    manifest = {"policies": {}}
    d2o = {"o.net": "origin_z"}

    # CASE A: default clean, only an ordered behavior has an op → default DROPS
    # its CFF, the ordered behavior keeps it.
    ir = _mk([_beh("*", []),
              _beh("/api/*", [{"type": "rewrite", "scope": "behavior",
                               "cf_source_rule": "r", "description": "d",
                               "condition": None, "raw_expression": None, "params": {}}])])
    tf = _scaf.generate_main_tf(ir, manifest, d2o, origins)
    vr = tf.count('event_type = "viewer-request"')
    check("R123-A: default-clean domain → CFF only on the ordered behavior (1 assoc)",
          vr == 1, f"expected 1 viewer-request assoc, got {vr}")

    # CASE B: default has a zone-wide (scope='all') op → EVERY behavior attaches.
    ir = _mk([_beh("*", [{"type": "set_request_header", "scope": "all",
                          "cf_source_rule": "r", "description": "d",
                          "condition": {"always": True}, "raw_expression": None,
                          "params": {"name": "X", "value": "1"}}]),
              _beh("/files/*", [])])
    tf = _scaf.generate_main_tf(ir, manifest, d2o, origins)
    vr = tf.count('event_type = "viewer-request"')
    check("R123-B: zone-wide default op → CFF on ALL behaviors (2 assocs)",
          vr == 2, f"expected 2 viewer-request assocs, got {vr}")

    # CASE C: default has only a 'default_only' op (path present, unconvertible)
    # → default attaches, the TTL-only ordered behavior DROPS.
    ir = _mk([_beh("*", [{"type": "cache_bypass", "scope": "default_only",
                          "cf_source_rule": "r", "description": "d",
                          "condition": {"field": "uri.path", "op": "matches", "value": "^/a.*$"},
                          "raw_expression": None, "params": {}}]),
              _beh("/files/*", [])])
    tf = _scaf.generate_main_tf(ir, manifest, d2o, origins)
    vr = tf.count('event_type = "viewer-request"')
    check("R123-C: default_only op → CFF on default only, TTL-only ordered DROPS (1 assoc)",
          vr == 1, f"expected 1 viewer-request assoc, got {vr}")


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
