#!/usr/bin/env python3
"""Placement-level regression for the native-mechanism condition invariant.

Root cause this locks down (found over review rounds 5–?): CloudFront's NATIVE
mechanisms — cache behavior settings, distribution settings, response-headers
policy, compression, cloud-connector origin — can only be scoped by a single path
pattern, NOT by a per-request predicate (header/cookie/geo/multi-path-OR). Only a
CloudFront Function can gate on an arbitrary condition, but it can't touch these
native settings. So a rule mapped to a native mechanism whose condition doesn't
reduce (after host-routing) to ONE path pattern CANNOT be carried faithfully and
must be reported non-convertible — never silently applied to `*` (widening) or
dropped. That invariant used to be enforced only for cache rules; native_placement
now enforces it for every native mechanism in _place_result.

Unlike processor-return unit tests, this asserts the FINAL PLACEMENT in the
preprocessed IR (where cache_policy / response_headers_policy / origin live and
where non_convertible is recorded) — the real end state a reviewer asked for.

Run: python3 test_native_placement.py  (exit 0 = all pass). Runs the real
parse-dns + preprocess; needs no terraform / AWS / boto3.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(_REPO, "converter", "scripts")

FAILURES = []


def check(label, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")
    if not cond:
        FAILURES.append((label, detail))
        if detail:
            print(f"           {detail}")


def _wrap(rules):
    return {"success": True, "result": {"rules": rules}}


def _rule(rid, expr, action, params, desc=""):
    return {"id": rid, "version": "1", "enabled": True, "action": action,
            "action_parameters": params, "description": desc, "expression": expr}


DNS = {"result": [{"id": "1" * 32, "name": "www.example.com", "type": "CNAME",
                   "content": "origin.example.net", "proxied": True, "ttl": 1}]}


def _run(stage, *args):
    p = subprocess.run([sys.executable, os.path.join(SCRIPTS, stage), *args],
                       capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr


def _preprocess(files):
    """Build a backup with the given per-phase files, run parse-dns + preprocess,
    return the single domain's accumulator IR."""
    tmp = tempfile.mkdtemp(prefix="native_place_")
    try:
        zone = os.path.join(tmp, "backup", "example.com", "2026-08-09 00-00-00")
        os.makedirs(os.path.join(tmp, "backup", "account", "2026-08-09 00-00-00"))
        os.makedirs(zone)
        with open(os.path.join(zone, "DNS.txt"), "w") as f:
            json.dump(DNS, f)
        for name, data in files.items():
            with open(os.path.join(zone, name), "w") as f:
                json.dump(data, f)
        cdn = os.path.join(tmp, "out")
        rc, log = _run("cdn-init.sh", cdn) if False else (0, "")
        subprocess.run(["bash", os.path.join(SCRIPTS, "cdn-init.sh"), cdn],
                       capture_output=True, text=True)
        cdn_dir = os.path.join(cdn, "cloudflare-to-aws-cdn")
        rc, log = _run("cdn-parse-dns.py", os.path.join(tmp, "backup"), cdn_dir)
        assert "STATUS: OK" in log, log[-400:]
        rc, log = _run("cdn-preprocess.py", os.path.join(tmp, "backup"), cdn_dir)
        assert rc == 0, log[-600:]
        acc = os.path.join(cdn_dir, "ir", "accumulator")
        files_out = [f for f in os.listdir(acc) if f.endswith(".json")]
        return json.load(open(os.path.join(acc, files_out[0])))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _behavior(ir, path):
    for b in ir["cache_behaviors"]:
        if b["path_pattern"] == path:
            return b
    return None


def _all_nc(ir):
    return [nc for b in ir["cache_behaviors"] for nc in b.get("non_convertible", [])]


# ── Compression (cache-policy attribute) ──────────────────────────────────────

print("== compression_setting placement ==")
# header condition (per-request) → non_convertible, NOT a global compression toggle
ir = _preprocess({"Compression-Rules.txt": _wrap([
    _rule("a" * 32, 'http.request.headers["x"] eq "1"', "set_config",
          {"algorithms": [{"name": "none"}]}, "no-compress when header x")])})
check("compression gated on header -> non_convertible", len(_all_nc(ir)) == 1,
      f"non_convertible={_all_nc(ir)}")
check("compression gated on header -> default behavior NOT toggled off",
      _behavior(ir, "*")["cache_policy"].get("enable_gzip", True) is True)

# path condition → lands on that path's behavior, default untouched
ir = _preprocess({"Compression-Rules.txt": _wrap([
    _rule("b" * 32, 'http.request.uri.path eq "/img"', "set_config",
          {"algorithms": [{"name": "gzip"}, {"name": "brotli"}]}, "compress /img")])})
check("compression gated on path -> /img behavior exists", _behavior(ir, "/img") is not None)
check("compression gated on path -> no non_convertible", len(_all_nc(ir)) == 0,
      f"non_convertible={_all_nc(ir)}")

# unconditional → default behavior, no non_convertible
ir = _preprocess({"Compression-Rules.txt": _wrap([
    _rule("c" * 32, "true", "set_config", {"algorithms": [{"name": "gzip"}]}, "compress all")])})
check("compression unconditional -> no non_convertible", len(_all_nc(ir)) == 0)


# ── Response-headers policy (per-behavior) ─────────────────────────────────────

print("== response_headers_policy placement ==")
# security header (HSTS) gated on a PATH → must land on that path's behavior
ir = _preprocess({"Response-Header-Transform.txt": _wrap([
    _rule("d" * 32, 'http.request.uri.path eq "/admin"', "rewrite",
          {"headers": {"Strict-Transport-Security": {"operation": "set", "value": "max-age=31536000"}}},
          "HSTS on /admin")])})
admin = _behavior(ir, "/admin")
check("HSTS on /admin -> /admin behavior exists", admin is not None)
check("HSTS on /admin -> header on /admin, not default",
      admin is not None and "Strict-Transport-Security" in admin["response_headers_policy"]["security_headers"]
      and "Strict-Transport-Security" not in _behavior(ir, "*")["response_headers_policy"]["security_headers"])

# STATIC security header (HSTS) gated on a header condition → the native RHP
# can't gate a per-request predicate, so placement FALLS BACK to a viewer-response
# CFF set_response_header op (which gates on any condition) rather than reporting
# non-convertible ("scope first, mechanism last", Finding 5). So: NO
# non_convertible, and a set_response_header op lands on the default behavior
# carrying the header condition.
ir = _preprocess({"Response-Header-Transform.txt": _wrap([
    _rule("e" * 32, 'http.request.headers["x"] eq "1"', "rewrite",
          {"headers": {"Strict-Transport-Security": {"operation": "set", "value": "max-age=31536000"}}},
          "HSTS on header-cond")])})
check("static security header gated on header -> CFF fallback, NOT non_convertible",
      len(_all_nc(ir)) == 0, f"nc={_all_nc(ir)}")
_resp_ops = _behavior(ir, "*")["viewer_response_ops"]
_hsts = [o for o in _resp_ops if o["params"].get("name") == "Strict-Transport-Security"]
check("static security header gated on header -> set_response_header op emitted",
      len(_hsts) == 1 and _hsts[0]["type"] == "set_response_header", f"ops={_resp_ops}")
check("static security header CFF fallback -> op carries the gating condition",
      len(_hsts) == 1 and _hsts[0].get("condition") is not None, f"op={_hsts[:1]}")
# The header must NOT also be applied unconditionally via the native RHP.
check("static security header CFF fallback -> NOT also in native security_headers",
      "Strict-Transport-Security" not in _behavior(ir, "*")["response_headers_policy"]["security_headers"])
# a NON-security dynamic header gated on a header condition → CFF op, NOT
# non_convertible (CFF gates on any condition). Confirms we didn't over-report.
ir = _preprocess({"Response-Header-Transform.txt": _wrap([
    _rule("g" * 32, 'http.request.headers["x"] eq "1"', "rewrite",
          {"headers": {"X-Custom": {"operation": "set", "value": "v"}}}, "custom hdr on header-cond")])})
check("non-security header gated on header -> CFF op, NOT non_convertible (no over-report)",
      len(_all_nc(ir)) == 0, f"nc={_all_nc(ir)}")
# CORS header gated on a multi-path OR → also CFF fallback (OR can't be one path).
ir = _preprocess({"Response-Header-Transform.txt": _wrap([
    _rule("h" * 32, 'http.request.uri.path eq "/a" or http.request.uri.path eq "/b"', "rewrite",
          {"headers": {"Access-Control-Allow-Origin": {"operation": "set", "value": "*"}}},
          "CORS on OR of paths")])})
check("CORS header gated on multi-path OR -> CFF fallback, NOT non_convertible",
      len(_all_nc(ir)) == 0, f"nc={_all_nc(ir)}")
_cors_ops = [o for b in ir["cache_behaviors"] for o in b["viewer_response_ops"]
             if o["params"].get("name") == "Access-Control-Allow-Origin"]
check("CORS header gated on multi-path OR -> set_response_header op emitted",
      len(_cors_ops) == 1 and _cors_ops[0]["type"] == "set_response_header", f"ops={_cors_ops}")


# ── Cloud connector (behavior origin) ──────────────────────────────────────────

print("== cloud_connector placement ==")
# header condition → non_convertible (can't re-point origin per request). Unlike a
# response header, this does NOT fall back to a CFF: updateRequestOrigin() to a
# private S3/R2/GCS/Azure origin is unsigned (403) without an OAC block the
# converter can't author — so it stays non_convertible with a reason that says so.
ir = _preprocess({"Cloud-Connector-Rules.txt": _wrap([
    {"id": "f" * 32, "enabled": True, "expression": 'http.request.headers["x"] eq "1"',
     "provider": "aws_s3", "description": "connector on header",
     "parameters": {"host": "bucket.s3.amazonaws.com"}}])})
check("cloud_connector gated on header -> non_convertible", len(_all_nc(ir)) == 1, f"nc={_all_nc(ir)}")
check("cloud_connector nc reason explains the no-CFF-fallback (OAC/403)",
      len(_all_nc(ir)) == 1 and "OAC" in _all_nc(ir)[0]["reason"], f"reason={_all_nc(ir)[:1]}")


# ── Configuration rule: ssl (per-behavior VPP) vs min_tls (distribution) ───────

print("== config_rule ssl / min_tls placement ==")
# ssl unconditional → viewer_protocol_policy on default distribution_settings
ir = _preprocess({"Configuration-Rules.txt": _wrap([
    _rule("1" * 32, "true", "set_config", {"ssl": "flexible"}, "ssl flexible sitewide")])})
check("ssl true -> viewer_protocol_policy set (allow-all), no non_convertible",
      _behavior(ir, "*")["distribution_settings"].get("viewer_protocol_policy") == "allow-all"
      and len(_all_nc(ir)) == 0, f"nc={_all_nc(ir)}, ds={_behavior(ir, '*')['distribution_settings']}")

# ssl gated on a path (per-request) → non_convertible (VPP is site-wide here)
ir = _preprocess({"Configuration-Rules.txt": _wrap([
    _rule("2" * 32, 'http.request.uri.path eq "/a"', "set_config", {"ssl": "full"}, "ssl on path")])})
check("ssl gated on path -> non_convertible (no widening)", len(_all_nc(ir)) == 1, f"nc={_all_nc(ir)}")

# min_tls unconditional → distribution minimum_protocol_version
ir = _preprocess({"Configuration-Rules.txt": _wrap([
    _rule("3" * 32, "true", "set_config", {"min_tls_version": "1.3"}, "min tls sitewide")])})
check("min_tls true -> minimum_protocol_version set, no non_convertible",
      _behavior(ir, "*")["distribution_settings"].get("minimum_protocol_version") == "TLSv1.2_2021"
      and len(_all_nc(ir)) == 0, f"ds={_behavior(ir, '*')['distribution_settings']}")

# min_tls gated on header → non_convertible
ir = _preprocess({"Configuration-Rules.txt": _wrap([
    _rule("4" * 32, 'http.request.headers["x"] eq "1"', "set_config", {"min_tls_version": "1.2"}, "min tls on header")])})
check("min_tls gated on header -> non_convertible", len(_all_nc(ir)) == 1, f"nc={_all_nc(ir)}")


# ── Global→ordered native overlay (Finding 1 / Task 5) ─────────────────────────
# A GLOBAL cache rule sets a site-wide TTL; a SEPARATE path-scoped rule creates an
# ordered behavior. CloudFront ordered behaviors don't inherit the default
# behavior's cache settings, so the global TTL must be FOLDED onto every ordered
# behavior that still holds factory defaults — else /admin would silently cache
# with the factory TTL, not the site-wide one the Cloudflare config set.
print("== global→ordered native overlay ==")
ir = _preprocess({
    # global: edge TTL override 60s, unconditional
    "Cache-Rules.txt": _wrap([
        _rule("a1" + "0" * 30, "true", "set_cache_settings",
              {"edge_ttl": {"mode": "override_origin", "default": 60}}, "global ttl 60"),
    ]),
    # a path-scoped security header creates the /admin ordered behavior
    "Response-Header-Transform.txt": _wrap([
        _rule("a2" + "0" * 30, 'http.request.uri.path eq "/admin"', "rewrite",
              {"headers": {"X-Frame-Options": {"operation": "set", "value": "DENY"}}},
              "xfo on /admin")]),
})
_admin = _behavior(ir, "/admin")
check("overlay: /admin ordered behavior exists", _admin is not None)
check("overlay: default behavior carries global TTL 60",
      _behavior(ir, "*")["cache_policy"]["ttl"]["default"] == 60,
      f"default ttl={_behavior(ir, '*')['cache_policy']['ttl']}")
check("overlay: global TTL 60 folded onto the ordered /admin behavior",
      _admin is not None and _admin["cache_policy"]["ttl"]["default"] == 60,
      f"/admin ttl={_admin['cache_policy']['ttl'] if _admin else None}")

# An ordered behavior with its OWN explicit TTL must WIN over the global (the
# overlay only fills behaviors still holding factory defaults).
ir = _preprocess({
    "Cache-Rules.txt": _wrap([
        _rule("b1" + "0" * 30, "true", "set_cache_settings",
              {"edge_ttl": {"mode": "override_origin", "default": 60}}, "global ttl 60"),
        _rule("b2" + "0" * 30, 'http.request.uri.path eq "/img"', "set_cache_settings",
              {"edge_ttl": {"mode": "override_origin", "default": 3600}}, "img ttl 3600"),
    ]),
})
_img = _behavior(ir, "/img")
check("overlay: ordered /img keeps its OWN TTL 3600 (global does not clobber)",
      _img is not None and _img["cache_policy"]["ttl"]["default"] == 3600,
      f"/img ttl={_img['cache_policy']['ttl'] if _img else None}")
check("overlay: default still 60 alongside the per-path override",
      _behavior(ir, "*")["cache_policy"]["ttl"]["default"] == 60)


if __name__ == "__main__":
    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} check(s)")
        for label, _ in FAILURES:
            print(f"  - {label}")
        sys.exit(1)
    print("All native-placement checks passed.")
