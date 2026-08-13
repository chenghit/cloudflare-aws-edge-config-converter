#!/usr/bin/env python3
"""Regression tests for the WAF correctness fixes (branch waf-correctness-fixes).

Each pins a defect that silently produced a WRONG WebACL (or a false "success")
at conversion/backup time:

  1. Disabled Cloudflare rules were converted into live AWS rules (a disabled
     `skip` rule even injected a skip:* label). Now: dropped from the IR.
  2. Cloudflare `log` action fell through to the generator's Block default →
     a monitoring-only rule started BLOCKING. Now: log → AWS Count (+warning),
     and an unmapped action fails loud instead of defaulting to Block.
  3. Rate rules were converted ignoring `requests_to_origin` / `counting_expression`
     / non-IP `characteristics`, silently mis-limiting traffic. Now: those are
     non-convertible (the rate part can't be faithfully reproduced).
  4. A present-but-corrupt backup file was read as "0 rules" → an empty WAF
     reported as success. Now: present-but-malformed is FATAL; absent is OK.
  5. waf-count-validate counts ACTIVE source rules (== IR) and reports disabled
     separately, instead of comparing total-source to active-IR.

Run: python3 test_waf_correctness.py   (exit 0 = all pass)
"""
import contextlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile

_SCRIPTS = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "converter", "scripts")


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, os.path.join(_SCRIPTS, filename))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod  # waf-generate-cfn imports waf_expr_parser / waf_common
    spec.loader.exec_module(mod)
    return mod


_wc = _load("waf_common", "waf_common.py")
_cfn = _load("waf_generate_cfn", "waf-generate-cfn.py")

_MISSING = object()  # sentinel: distinguish an absent characteristics key from [] / None
FAILURES = []


def check(label, cond, detail=""):
    if not cond:
        FAILURES.append((label, detail))
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}" + ("" if cond else f"  — {detail}"))


def _write(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(obj, f)


def _run(script, *args):
    """Run a converter script as a subprocess; return (returncode, stdout+stderr)."""
    r = subprocess.run([sys.executable, os.path.join(_SCRIPTS, script), *args],
                       capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


def _cf_rules(rules):
    """Wrap a rules list in a well-formed Cloudflare rulesets API response."""
    return {"success": True, "result": {"rules": rules}}


def _raises_exit(fn):
    """True if fn() calls sys.exit (the FATAL path); False if it returns. The
    FATAL path prints a ---RESULT--- STATUS: FATAL block — swallow it so it can't
    pollute this (passing) suite's own stdout and be misread as a failure."""
    sink = io.StringIO()
    try:
        with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
            fn()
        return False
    except SystemExit:
        return True


def _mkdir(*parts):
    p = os.path.join(*parts)
    os.makedirs(p, exist_ok=True)
    return p


# ── 1. resolve_action: log→Count(+warn), fail-loud on unknown (fix #2) ──
print("== resolve_action (action mapping) ==")
_w = []
check("block → Block", _cfn.resolve_action("block", "r", _w) == {"Block": {}})
check("whitelist → Allow", _cfn.resolve_action("whitelist", "r", _w) == {"Allow": {}})
check("count → Count", _cfn.resolve_action("count", "r", _w) == {"Count": {}})
_w = []
check("log → Count (not Block)", _cfn.resolve_action("log", "r", _w) == {"Count": {}})
check("log emits a warning (enable AWS WAF logging)",
      len(_w) == 1 and "log" in _w[0] and "Count" in _w[0])
check("'log' is present in ACTION_MAP", _cfn.ACTION_MAP.get("log") == {"Count": {}})
_exit = None
try:
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        _cfn.resolve_action("frobnicate", "r", [])
except SystemExit as e:
    _exit = e.code
check("unknown action → fail loud (SystemExit, non-zero)", _exit not in (None, 0),
      f"got exit={_exit!r}")


# ── 2. load_backup_json: present-but-corrupt FATAL, valid OK (fix #4) ──
print("== load_backup_json (malformed input) ==")
with tempfile.TemporaryDirectory() as td:
    good = os.path.join(td, "good.txt")
    _write(good, {"success": True, "result": [1, 2, 3]})
    check("valid successful response → returned", _wc.load_backup_json(good, "x")["result"] == [1, 2, 3])

    bad_json = os.path.join(td, "bad.txt")
    with open(bad_json, "w") as f:
        f.write("{ not json")
    check("malformed JSON → FATAL (SystemExit)",
          _raises_exit(lambda: _wc.load_backup_json(bad_json, "x")))

    not_success = os.path.join(td, "ns.txt")
    _write(not_success, {"success": False, "errors": [{"message": "bad"}]})
    check("success:false → FATAL (SystemExit)",
          _raises_exit(lambda: _wc.load_backup_json(not_success, "x")))

    no_result = os.path.join(td, "nr.txt")
    _write(no_result, {"success": True})
    check("missing result key → FATAL (SystemExit)",
          _raises_exit(lambda: _wc.load_backup_json(no_result, "x")))


# ── 3. Custom analyzer: drop disabled, NC unknown action (fix #1, #2) ──
print("== waf-analyze-custom (disabled / unknown action) ==")
with tempfile.TemporaryDirectory() as td:
    _write(os.path.join(td, "z", "t", "WAF-Custom-Rules.txt"), _cf_rules([
        {"description": "keep", "action": "block", "enabled": True, "expression": 'http.host eq "a"'},
        {"description": "drop-disabled", "action": "block", "enabled": False, "expression": 'http.host eq "b"'},
        {"description": "weird", "action": "frobnicate", "enabled": True, "expression": 'http.host eq "c"'},
    ]))
    rc, out = _run("waf-analyze-custom.py", td, td)
    ir = json.load(open(os.path.join(td, "waf_ir_custom.json")))
    rules = {r["name"]: r for r in ir["custom_rules"]["rules"]}
    check("analyzer exits 0", rc == 0, out)
    check("disabled rule dropped from IR", "drop-disabled" not in rules)
    check("active count == 2 (disabled excluded)", ir["custom_rules"]["count"] == 2)
    check("enabled convertible rule kept as convertible", rules.get("keep", {}).get("convertibility") == "yes")
    check("unknown action → non-convertible (not silently Block)",
          rules.get("weird", {}).get("convertibility") == "no")


# ── 4. Rate analyzer: structure gate NCs unmappable counters (fix #3) ──
print("== waf-analyze-rate (rate-limit structure gate) ==")
with tempfile.TemporaryDirectory() as td:
    def _rl(**kw):
        base = {"requests_per_period": 100, "period": 60}
        base.update(kw)
        return base
    _write(os.path.join(td, "z", "t", "Rate-limits.txt"), _cf_rules([
        {"description": "origin", "action": "block", "enabled": True, "expression": 'http.host eq "a"',
         "ratelimit": _rl(requests_to_origin=True, characteristics=["ip.src", "cf.colo.id"])},
        {"description": "counting", "action": "block", "enabled": True, "expression": 'http.host eq "a"',
         "ratelimit": _rl(counting_expression='http.request.uri.path contains "/x"')},
        {"description": "extrachar", "action": "block", "enabled": True, "expression": 'http.host eq "a"',
         "ratelimit": _rl(characteristics=["http.request.headers[\"x\"]"])},
        {"description": "standard", "action": "block", "enabled": True, "expression": 'http.host eq "a"',
         "ratelimit": _rl(characteristics=["ip.src", "cf.colo.id"])},
        {"description": "logrule", "action": "log", "enabled": True, "expression": 'http.host eq "a"',
         "ratelimit": _rl(characteristics=["ip.src"])},
        {"description": "disabled", "action": "block", "enabled": False, "expression": 'http.host eq "a"',
         "ratelimit": _rl()},
        {"description": "badaction", "action": "frobnicate", "enabled": True, "expression": 'http.host eq "a"',
         "ratelimit": _rl(characteristics=["ip.src"])},
    ]))
    rc, out = _run("waf-analyze-rate.py", td, td)
    ir = json.load(open(os.path.join(td, "waf_ir_rate.json")))
    rules = {r["name"]: r for r in ir["rate_limiting_rules"]["rules"]}
    conv = {n: r["convertibility"] for n, r in rules.items()}
    check("analyzer exits 0", rc == 0, out)
    check("disabled rate rule dropped", "disabled" not in rules)
    check("count == 6 (disabled excluded, NC rules retained)", ir["rate_limiting_rules"]["count"] == 6)
    check("requests_to_origin → non-convertible", conv.get("origin") == "no")
    check("counting_expression → non-convertible", conv.get("counting") == "no")
    check("non-IP characteristic → non-convertible", conv.get("extrachar") == "no")
    check("unmappable rate action → non-convertible", conv.get("badaction") == "no")
    check("ip.src/cf.colo.id combo → still converts", conv.get("standard") != "no",
          f"got {conv.get('standard')}")
    check("log rate rule → still converts (mapped to Count downstream)", conv.get("logrule") != "no",
          f"got {conv.get('logrule')}")


# ── 5. Analyzer FATAL on present-but-corrupt source file (fix #4) ──
print("== analyzer FATAL vs OK on file presence ==")
with tempfile.TemporaryDirectory() as td:
    with open(os.path.join(_mkdir(td, "z", "t"), "WAF-Custom-Rules.txt"), "w") as f:
        f.write("{ corrupt")
    rc, out = _run("waf-analyze-custom.py", td, td)
    check("present-but-corrupt custom file → non-zero exit", rc != 0, f"exit={rc}")
    check("present-but-corrupt → STATUS: FATAL", "STATUS: FATAL" in out)
with tempfile.TemporaryDirectory() as td:
    _mkdir(td, "z", "t")  # no WAF-Custom-Rules.txt at all
    rc, out = _run("waf-analyze-custom.py", td, td)
    check("absent custom file → exit 0 (feature simply not backed up)", rc == 0, f"exit={rc}")


# ── 6. count-validate: active source count == IR, disabled reported (fix #5) ──
print("== waf-count-validate (active vs disabled) ==")
with tempfile.TemporaryDirectory() as td:
    _write(os.path.join(td, "z", "t", "WAF-Custom-Rules.txt"), _cf_rules([
        {"description": "a", "action": "block", "enabled": True, "expression": 'http.host eq "a"'},
        {"description": "b", "action": "block", "enabled": False, "expression": 'http.host eq "b"'},
    ]))
    # IR reflects the analyzer's output: 1 active custom rule, 0 rate, 0 ip.
    _write(os.path.join(td, "waf_ir.json"), {
        "custom_rules": {"count": 1, "rules": [{"name": "a"}]},
        "rate_limiting_rules": {"count": 0, "rules": []},
        "ip_access_rules": {"count": 0, "rules": []},
    })
    rc, out = _run("waf-count-validate.py", td, td)
    check("active source count (1) matches IR count (1) → exit 0", rc == 0, out)
    check("disabled count reported separately (custom=1)", "custom=1" in out and "disabled" in out, out)


# ── 7. backup_rules / backup_list shape validators (fix P1-A, import) ──
print("== backup shape validators ==")
check("backup_rules: {rules:[obj]} → rules",
      _wc.backup_rules({"result": {"rules": [{"a": 1}]}}, "p", "x") == [{"a": 1}])
check("backup_rules: bare list of objs → rules",
      _wc.backup_rules({"result": [{"a": 1}]}, "p", "x") == [{"a": 1}])
check("backup_rules: result={} → FATAL", _raises_exit(lambda: _wc.backup_rules({"result": {}}, "p", "x")))
check("backup_rules: rules is a dict → FATAL",
      _raises_exit(lambda: _wc.backup_rules({"result": {"rules": {}}}, "p", "x")))
check("backup_rules: non-dict rule → FATAL",
      _raises_exit(lambda: _wc.backup_rules({"result": {"rules": [1]}}, "p", "x")))
check("backup_list: list of objs → ok", _wc.backup_list({"result": [{"a": 1}]}, "p", "x") == [{"a": 1}])
check("backup_list: result is a dict → FATAL", _raises_exit(lambda: _wc.backup_list({"result": {}}, "p", "x")))
check("backup_list: non-dict entry → FATAL", _raises_exit(lambda: _wc.backup_list({"result": [1]}, "p", "x")))


# ── 8. analyzer FATAL on wrong result SHAPE (fix P1-A, end-to-end) ──
print("== analyzer FATAL on wrong result shape ==")
with tempfile.TemporaryDirectory() as td:
    _write(os.path.join(td, "z", "t", "WAF-Custom-Rules.txt"), {"success": True, "result": {}})
    rc, out = _run("waf-analyze-custom.py", td, td)
    check("custom result={} → FATAL (not silently 0 rules)", rc != 0 and "STATUS: FATAL" in out, out)
with tempfile.TemporaryDirectory() as td:
    _write(os.path.join(td, "z", "t", "Rate-limits.txt"), {"success": True, "result": {"rules": {}}})
    rc, out = _run("waf-analyze-rate.py", td, td)
    check("rate result.rules=dict → FATAL", rc != 0 and "STATUS: FATAL" in out, out)
with tempfile.TemporaryDirectory() as td:
    _write(os.path.join(td, "z", "t", "Rate-limits.txt"), {"success": True, "result": []})
    rc, out = _run("waf-analyze-rate.py", td, td)
    check("rate result=[] (bare empty list) → OK (0 rules)", rc == 0, out)
with tempfile.TemporaryDirectory() as td:
    _write(os.path.join(td, "z", "t", "WAF-Custom-Rules.txt"), {"success": True, "result": {}})
    _write(os.path.join(td, "waf_ir.json"), {"custom_rules": {"count": 0, "rules": []},
           "rate_limiting_rules": {"count": 0, "rules": []}, "ip_access_rules": {"count": 0, "rules": []}})
    rc, out = _run("waf-count-validate.py", td, td)
    check("count-validate: custom result={} → FATAL (not 0)", rc != 0 and "STATUS: FATAL" in out, out)


# ── 9. IP list items completeness (fix P1-B) ──
print("== IP list items completeness ==")
def _ip_lists(lists):
    return {"success": True, "result": lists}
def _ip_items(items):
    return {"success": True, "result": items}

with tempfile.TemporaryDirectory() as td:
    b = _mkdir(td, "account", "t")
    _write(os.path.join(b, "IP-Lists.txt"), _ip_lists([{"name": "blk", "kind": "ip", "num_items": 2}]))
    rc, out = _run("waf-analyze-ip.py", td, td)
    check("IP list num_items=2, items file MISSING → FATAL", rc != 0 and "STATUS: FATAL" in out, out)
with tempfile.TemporaryDirectory() as td:
    b = _mkdir(td, "account", "t")
    _write(os.path.join(b, "IP-Lists.txt"), _ip_lists([{"name": "blk", "kind": "ip", "num_items": 2}]))
    _write(os.path.join(b, "List-Items-ip-blk.txt"), _ip_items([{"ip": "1.2.3.4"}]))
    rc, out = _run("waf-analyze-ip.py", td, td)
    check("IP list declares 2 but 1 item found → FATAL (incomplete backup)",
          rc != 0 and "STATUS: FATAL" in out, out)
with tempfile.TemporaryDirectory() as td:
    b = _mkdir(td, "account", "t")
    _write(os.path.join(b, "IP-Lists.txt"), _ip_lists([{"name": "blk", "kind": "ip", "num_items": 2}]))
    _write(os.path.join(b, "List-Items-ip-blk.txt"), _ip_items([{"ip": "1.2.3.4"}, {"ip": "5.6.7.8"}]))
    rc, out = _run("waf-analyze-ip.py", td, td)
    check("IP list complete (2/2) → OK", rc == 0, out)
with tempfile.TemporaryDirectory() as td:
    b = _mkdir(td, "account", "t")
    _write(os.path.join(b, "IP-Lists.txt"), _ip_lists([{"name": "blk", "kind": "ip", "num_items": 0}]))
    rc, out = _run("waf-analyze-ip.py", td, td)
    check("IP list num_items=0, no items file → OK (empty)", rc == 0, out)


# ── 10. rate characteristics must contain ip.src (fix P1-C) ──
print("== rate characteristics must contain ip.src ==")
with tempfile.TemporaryDirectory() as td:
    def _rl2(chars=_MISSING):
        rl = {"requests_per_period": 100, "period": 60}
        if chars is not _MISSING:
            rl["characteristics"] = chars
        return rl
    _write(os.path.join(td, "z", "t", "Rate-limits.txt"), _cf_rules([
        {"description": "colo-only", "action": "block", "enabled": True,
         "expression": 'http.host eq "a"', "ratelimit": _rl2(["cf.colo.id"])},
        {"description": "empty-chars", "action": "block", "enabled": True,
         "expression": 'http.host eq "a"', "ratelimit": _rl2([])},
        {"description": "no-chars", "action": "block", "enabled": True,
         "expression": 'http.host eq "a"', "ratelimit": _rl2()},
        {"description": "ip-only", "action": "block", "enabled": True,
         "expression": 'http.host eq "a"', "ratelimit": _rl2(["ip.src"])},
    ]))
    rc, out = _run("waf-analyze-rate.py", td, td)
    ir = json.load(open(os.path.join(td, "waf_ir_rate.json")))
    conv = {r["name"]: r["convertibility"] for r in ir["rate_limiting_rules"]["rules"]}
    check("rate analyzer exits 0", rc == 0, out)
    check("cf.colo.id-only → NC (would be a per-source-IP counter otherwise)", conv.get("colo-only") == "no")
    check("empty characteristics → NC", conv.get("empty-chars") == "no")
    check("absent characteristics → NC (fail-closed)", conv.get("no-chars") == "no")
    check("ip.src-only → converts", conv.get("ip-only") != "no", f"got {conv.get('ip-only')}")


print()
if FAILURES:
    print(f"FAILED: {len(FAILURES)} check(s)")
    for label, detail in FAILURES:
        print(f"  - {label}: {detail}")
    sys.exit(1)
print("All WAF correctness checks passed.")
