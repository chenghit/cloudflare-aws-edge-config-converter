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


# ── ACCEPTANCE: rule-order stacking, cross-overlap, F1 condition source ─────────
# These lock down the round-6 refactor's mandate (reviewer conditions F1/F2/F3):
# native effects replay in SOURCE-RULE order (last match wins), cross-overlap is
# reported not guessed, and an RHP result gates on its OWN screened condition.


def _ttl(beh):
    return beh["cache_policy"]["ttl"]["default"] if beh else None


print("== ACCEPTANCE: native effect replay in source-rule order (last match wins) ==")
# global TTL=60 (rule 1) THEN /admin TTL=3600 (rule 2): /admin's own more-specific
# rule is LAST → 3600 wins on /admin; default stays 60.
ir = _preprocess({"Cache-Rules.txt": _wrap([
    _rule("a1" + "0" * 30, "true", "x",
          {"edge_ttl": {"mode": "override_origin", "default": 60}}, "global 60"),
    _rule("a2" + "0" * 30, 'http.request.uri.path eq "/admin"', "x",
          {"edge_ttl": {"mode": "override_origin", "default": 3600}}, "admin 3600"),
])})
check("order: global-then-path -> /admin=3600 (own rule last)", _ttl(_behavior(ir, "/admin")) == 3600,
      f"/admin ttl={_ttl(_behavior(ir, '/admin'))}")
check("order: global-then-path -> default=60", _ttl(_behavior(ir, "*")) == 60)

# REVERSED source order — /admin TTL=3600 (rule 1) THEN global TTL=60 (rule 2):
# the global rule is LAST and CONTAINS /admin, so 60 wins EVERYWHERE (this is the
# exact case the reverted overlay got wrong — it hardcoded path-wins).
ir = _preprocess({"Cache-Rules.txt": _wrap([
    _rule("b1" + "0" * 30, 'http.request.uri.path eq "/admin"', "x",
          {"edge_ttl": {"mode": "override_origin", "default": 3600}}, "admin 3600"),
    _rule("b2" + "0" * 30, "true", "x",
          {"edge_ttl": {"mode": "override_origin", "default": 60}}, "global 60"),
])})
check("order: path-then-global -> /admin=60 (later global overrides, was 3600 bug)",
      _ttl(_behavior(ir, "/admin")) == 60, f"/admin ttl={_ttl(_behavior(ir, '/admin'))}")
check("order: path-then-global -> default=60", _ttl(_behavior(ir, "*")) == 60)

print("== ACCEPTANCE: cross-overlap native effect -> non_convertible (not guessed) ==")
# A cache behavior at *.js (created by an extension cache rule) and a compression
# rule scoped to /api/* GENUINELY cross-overlap: a request /api/x.js matches both,
# yet neither pattern contains the other. CloudFront can't apply compression to
# only the /api/ slice of the *.js behavior → non_convertible on that behavior.
ir = _preprocess({
    "Cache-Rules.txt": _wrap([
        _rule("c1" + "0" * 30, 'http.request.uri.path.extension in {"js"}', "x",
              {"edge_ttl": {"mode": "override_origin", "default": 30}}, "js behavior")]),
    "Compression-Rules.txt": _wrap([
        _rule("c2" + "0" * 30, 'http.request.uri.path wildcard "/api/*"',
              "x", {"algorithms": [{"name": "gzip"}]}, "compress /api/*")]),
})
# *.js behavior exists; /api/* compression cross-overlaps it (a /api/x.js request
# matches both, neither contains the other) → non_convertible recorded, NOT guessed.
_ncs = _all_nc(ir)
check("cross-overlap (/api/* vs *.js): reported non_convertible (not silently applied)",
      any("cross-overlap" in n.get("reason", "") for n in _ncs), f"nc={_ncs}")

print("== ACCEPTANCE: F1 -- RHP gates on its OWN screened condition (no silent false) ==")
# HSTS set on (mappable header OR unmappable bot-score). _screen_unmappable prunes
# the bot-score branch → the RHP result's condition is the pruned header-only cond,
# NOT the raw OR (which the OLD fallback re-parsed → rendered `false` → silent drop).
# Header condition can't reduce to a path → CFF fallback is NOT wired here (RHP is
# native), so this must be reported non_convertible with the header still visible —
# never a silent `non_convertible=0` drop.
ir = _preprocess({"Response-Header-Transform.txt": _wrap([
    _rule("d1" + "0" * 30,
          'http.request.headers["x"] eq "1" or cf.bot_management.score gt 30', "rewrite",
          {"headers": {"Strict-Transport-Security": {"operation": "set", "value": "max-age=1"}}},
          "hsts header-or-botscore")])})
# The pruned condition is header-only (a per-request predicate) → RHP can't gate it
# → non_convertible, and it is VISIBLE (not a silent drop).
check("F1: header-cond RHP after OR-prune -> non_convertible is recorded (not silent)",
      len(_all_nc(ir)) == 1, f"nc={_all_nc(ir)}")

print("== ACCEPTANCE: full_uri scheme -- https maps to path, http rejected ==")
# https:// full_uri cache rule → faithful path behavior (scheme redundant under
# redirect-to-https).
ir = _preprocess({"Cache-Rules.txt": _wrap([
    _rule("e1" + "0" * 30, 'http.request.full_uri wildcard "https://www.example.com/files/*"',
          "x", {"edge_ttl": {"mode": "override_origin", "default": 120}}, "https files")])})
check("scheme: https full_uri -> /files/* behavior, no non_convertible",
      _behavior(ir, "/files/*") is not None and len(_all_nc(ir)) == 0,
      f"behs={[b['path_pattern'] for b in ir['cache_behaviors']]} nc={_all_nc(ir)}")
# http:// full_uri cache rule → scheme can't be expressed as a path → non_convertible.
ir = _preprocess({"Cache-Rules.txt": _wrap([
    _rule("e2" + "0" * 30, 'http.request.full_uri wildcard "http://www.example.com/files/*"',
          "x", {"edge_ttl": {"mode": "override_origin", "default": 120}}, "http files")])})
check("scheme: http-only full_uri -> non_convertible (no silent scheme drop)",
      len(_all_nc(ir)) == 1 and _behavior(ir, "/files/*") is None,
      f"behs={[b['path_pattern'] for b in ir['cache_behaviors']]} nc={_all_nc(ir)}")

print("== ACCEPTANCE: every enabled rule leaves a trace (no silent drop) ==")
# A diverse rule set: a convertible cache rule, a non-convertible (geo) cache rule,
# and a security header. Every rule ID must appear SOMEWHERE (native effect applied
# → shows as a behavior it created / TTL; op; or non_convertible). We assert the
# invariant's contrapositive: no rule yields the INTERNAL "produced no output" nc.
ir = _preprocess({
    "Cache-Rules.txt": _wrap([
        _rule("f1" + "0" * 30, 'http.request.uri.path eq "/cached"', "x",
              {"edge_ttl": {"mode": "override_origin", "default": 300}}, "cached"),
        _rule("f2" + "0" * 30, 'ip.src.country eq "CN"', "x",
              {"edge_ttl": {"mode": "override_origin", "default": 5}}, "geo cache (nc)")]),
    "Response-Header-Transform.txt": _wrap([
        _rule("f3" + "0" * 30, "true", "rewrite",
              {"headers": {"X-Frame-Options": {"operation": "set", "value": "DENY"}}}, "xfo")]),
})
_internal = [n for n in _all_nc(ir) if "produced no output" in n.get("reason", "")]
check("invariant: no rule silently dropped (no INTERNAL 'produced no output')",
      len(_internal) == 0, f"orphans={_internal}")
# the geo cache rule specifically must be a VISIBLE non_convertible.
check("invariant: geo cache rule surfaced as non_convertible",
      any(n["cf_source_rule"].startswith("f2") for n in _all_nc(ir)), f"nc={_all_nc(ir)}")


def _cache_ttl(ir, path):
    b = _behavior(ir, path)
    return b["cache_policy"]["ttl"]["default"] if b else None


def _resp_ops(ir, path):
    b = _behavior(ir, path)
    return b["viewer_response_ops"] if b else []


# ── round-7 review: ordering, reset, case, VPP-scheme ──────────────────────────
print("== ACCEPTANCE(r7): native reset effects last-wins (F2) ==")
# override 60 then respect_origin (a RESET) → factory 7200 wins (was stuck at 60).
ir = _preprocess({"Cache-Rules.txt": _wrap([
    _rule("g1" + "0" * 30, "true", "x", {"edge_ttl": {"mode": "override_origin", "default": 60}}, "ttl 60"),
    _rule("g2" + "0" * 30, "true", "x", {"edge_ttl": {"mode": "respect_origin"}}, "respect (reset)")])})
check("F2: override then respect_origin -> factory TTL 7200 (reset wins)",
      _cache_ttl(ir, "*") == 7200, f"ttl={_cache_ttl(ir, '*')}")
# cache=false then cache=true (a RESET) → caching re-enabled (was stuck disabled).
ir = _preprocess({"Cache-Rules.txt": _wrap([
    _rule("h1" + "0" * 30, "true", "x", {"cache": False}, "no-cache"),
    _rule("h2" + "0" * 30, "true", "x", {"cache": True}, "cache (reset)")])})
check("F2: cache=false then cache=true -> caching_disabled False (reset wins)",
      _behavior(ir, "*")["cache_policy"]["caching_disabled"] is False)

print("== ACCEPTANCE(r7): mixed-op header stays in CFF, seq-ordered (F1/F3) ==")
# remove HSTS (rule1) then set HSTS (rule2). Mixed ops on one header → ALL to CFF
# (RHP empty), and the CFF ops carry ascending seq so `set` (later) wins over
# `remove`. Was: RHP set + CFF remove → RHP runs first, CFF removes → wrongly gone.
ir = _preprocess({"Response-Header-Transform.txt": _wrap([
    _rule("i1" + "0" * 30, "true", "rewrite",
          {"headers": {"Strict-Transport-Security": {"operation": "remove"}}}, "remove hsts"),
    _rule("i2" + "0" * 30, "true", "rewrite",
          {"headers": {"Strict-Transport-Security": {"operation": "set", "value": "max-age=1"}}}, "set hsts")])})
check("F3: mixed-op HSTS not in native RHP (moved to CFF)",
      "Strict-Transport-Security" not in _behavior(ir, "*")["response_headers_policy"]["security_headers"])
_hsts_ops = [o for o in _resp_ops(ir, "*") if o["params"].get("name") == "Strict-Transport-Security"]
check("F3: both HSTS ops in CFF (remove + set)", len(_hsts_ops) == 2, f"ops={_hsts_ops}")
check("F3: CFF ops seq-ascending so later `set` wins (remove.seq < set.seq)",
      len(_hsts_ops) == 2 and _hsts_ops[0]["seq"] < _hsts_ops[1]["seq"]
      and _hsts_ops[1]["type"] == "set_response_header",
      f"ops={[(o['type'], o.get('seq')) for o in _hsts_ops]}")

print("== ACCEPTANCE(r7): case-insensitive wildcard converts natively + warns (F4) ==")
# eq (case-sensitive) → native, NO warning.
ir = _preprocess({"Cache-Rules.txt": _wrap([
    _rule("j1" + "0" * 30, 'http.request.uri.path eq "/Api"', "x",
          {"edge_ttl": {"mode": "override_origin", "default": 30}}, "eq Api")])})
check("F4: eq (case-sensitive) -> native /Api, no case warning",
      _behavior(ir, "/Api") is not None and not ir["metadata"].get("conversion_warnings"))
# plain wildcard w/ letters → native (behavior created) BUT a case warning recorded.
ir = _preprocess({"Cache-Rules.txt": _wrap([
    _rule("j2" + "0" * 30, 'http.request.uri.path wildcard "/Admin/*"', "x",
          {"edge_ttl": {"mode": "override_origin", "default": 30}}, "wildcard Admin")])})
check("F4: case-insensitive wildcard -> native behavior created (converted)",
      _behavior(ir, "/Admin/*") is not None and len(_all_nc(ir)) == 0)
check("F4: case-insensitive wildcard -> case-difference warning recorded",
      any("case-INSENSITIVE" in w for w in ir["metadata"].get("conversion_warnings", [])),
      f"warnings={ir['metadata'].get('conversion_warnings')}")

print("== ACCEPTANCE(r7): full_uri https faithful only under redirect-to-https (F5) ==")
# default VPP (redirect-to-https): https full_uri -> native /files/*.
ir = _preprocess({"Cache-Rules.txt": _wrap([
    _rule("k1" + "0" * 30, 'http.request.full_uri wildcard "https://www.example.com/files/*"',
          "x", {"edge_ttl": {"mode": "override_origin", "default": 120}}, "https files")])})
check("F5: https full_uri under default (redirect-to-https) -> native /files/*",
      _behavior(ir, "/files/*") is not None and len(_all_nc(ir)) == 0)
# allow-all (ssl=flexible): https full_uri would widen to http -> non_convertible.
ir = _preprocess({
    "Configuration-Rules.txt": _wrap([
        _rule("k2" + "0" * 30, "true", "set_config", {"ssl": "flexible"}, "ssl flexible")]),
    "Cache-Rules.txt": _wrap([
        _rule("k3" + "0" * 30, 'http.request.full_uri wildcard "https://www.example.com/files/*"',
              "x", {"edge_ttl": {"mode": "override_origin", "default": 120}}, "https files")]),
})
check("F5: https full_uri under allow-all (ssl=flexible) -> non_convertible (no widen)",
      _behavior(ir, "/files/*") is None and len(_all_nc(ir)) >= 1,
      f"paths={[b['path_pattern'] for b in ir['cache_behaviors']]} nc={_all_nc(ir)}")


if __name__ == "__main__":
    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} check(s)")
        for label, _ in FAILURES:
            print(f"  - {label}")
        sys.exit(1)
    print("All native-placement checks passed.")
