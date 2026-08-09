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

# STATIC security header (HSTS) gated on a header condition → goes through the
# RHP (native, path-scoped) branch, so the per-request condition can't gate it →
# non_convertible. (A NON-security/CORS header, or a dynamic value expression,
# takes the set_response_header CFF path instead and CAN gate on any condition —
# that's correct and not tested here.)
ir = _preprocess({"Response-Header-Transform.txt": _wrap([
    _rule("e" * 32, 'http.request.headers["x"] eq "1"', "rewrite",
          {"headers": {"Strict-Transport-Security": {"operation": "set", "value": "max-age=31536000"}}},
          "HSTS on header-cond")])})
check("static security header (RHP) gated on header -> non_convertible",
      len(_all_nc(ir)) == 1, f"nc={_all_nc(ir)}")
# a NON-security dynamic header gated on a header condition → CFF op, NOT
# non_convertible (CFF gates on any condition). Confirms we didn't over-report.
ir = _preprocess({"Response-Header-Transform.txt": _wrap([
    _rule("g" * 32, 'http.request.headers["x"] eq "1"', "rewrite",
          {"headers": {"X-Custom": {"operation": "set", "value": "v"}}}, "custom hdr on header-cond")])})
check("non-security header gated on header -> CFF op, NOT non_convertible (no over-report)",
      len(_all_nc(ir)) == 0, f"nc={_all_nc(ir)}")


# ── Cloud connector (behavior origin) ──────────────────────────────────────────

print("== cloud_connector placement ==")
# header condition → non_convertible (can't re-point origin per request)
ir = _preprocess({"Cloud-Connector-Rules.txt": _wrap([
    {"id": "f" * 32, "enabled": True, "expression": 'http.request.headers["x"] eq "1"',
     "provider": "aws_s3", "description": "connector on header",
     "parameters": {"host": "bucket.s3.amazonaws.com"}}])})
check("cloud_connector gated on header -> non_convertible", len(_all_nc(ir)) == 1, f"nc={_all_nc(ir)}")


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


if __name__ == "__main__":
    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} check(s)")
        for label, _ in FAILURES:
            print(f"  - {label}")
        sys.exit(1)
    print("All native-placement checks passed.")
