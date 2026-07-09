#!/usr/bin/env python3
"""Regression tests for Cloudflare action values / match conditions that use
Rules-language fields (dynamic values), plus the static redirect/rewrite key
plumbing. These paths were a coverage blind spot (the example config has no
redirect/rewrite/dynamic-header rules), so this drives synthetic
Cloudflare-shaped rule JSON through the real processor + JS generator and
asserts the emitted JavaScript.

Run: python3 test_dynamic_values.py   (exit 0 = all pass)
"""
import importlib.util
import sys


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# Load modules by file path (hyphenated filenames aren't importable normally).
_parser = _load("cdn_expr_parser", "cdn_expr_parser.py")
sys.modules["cdn_expr_parser"] = _parser
_proc = _load("cdn_rule_processors", "cdn_rule_processors.py")
_gen = _load("cdn_generate_js", "cdn-generate-js.py")

FAILURES = []


def check(label, got, expect_substr=None, forbid_substr=None):
    ok = True
    if expect_substr is not None and expect_substr not in got:
        ok = False
    if forbid_substr is not None and forbid_substr in got:
        ok = False
    status = "PASS" if ok else "FAIL"
    if not ok:
        FAILURES.append((label, got, expect_substr, forbid_substr))
    print(f"  [{status}] {label}")
    if not ok:
        print(f"           got:    {got}")
        if expect_substr is not None:
            print(f"           expect: {expect_substr}")
        if forbid_substr is not None:
            print(f"           forbid: {forbid_substr}")


def emit(op):
    return " | ".join(_gen._generate_op_js(op, "cff")).strip()


# ── Redirect rule (from_value.target_url) ────────────────────────────────────

def redirect_rule(expr, target_url=None, target_expr=None, status=301):
    fv = {"status_code": status, "target_url": {}}
    if target_expr is not None:
        fv["target_url"]["expression"] = target_expr
    elif target_url is not None:
        fv["target_url"]["value"] = target_url
    return {"id": "r", "description": "t", "expression": expr,
            "action_parameters": {"from_value": fv}}


def rewrite_rule(expr, path=None, path_expr=None, query=None, query_expr=None):
    uri = {}
    if path_expr is not None:
        uri["path"] = {"expression": path_expr}
    elif path is not None:
        uri["path"] = {"value": path}
    if query_expr is not None:
        uri["query"] = {"expression": query_expr}
    elif query is not None:
        uri["query"] = {"value": query}
    return {"id": "r", "description": "t", "expression": expr,
            "action_parameters": {"uri": uri}}


def header_rule(expr, headers):
    return {"id": "r", "description": "t", "expression": expr,
            "action_parameters": {"headers": headers}}


def first_op(result):
    """Processors return a list or a single dict; return the first real op."""
    if isinstance(result, dict):
        return result
    return result[0] if result else None


print("== #1/#2 static redirect & rewrite (key unification) ==")
op = first_op(_proc.process_redirect_rule(redirect_rule("true", target_url="https://x.com/new"), {}, ""))
check("static redirect emits real Location", emit(op),
      expect_substr="https://x.com/new", forbid_substr="value: ''")
op = first_op(_proc.process_rewrite_rule(rewrite_rule("true", path="/newpath"), {}, ""))
check("static rewrite emits real uri", emit(op),
      expect_substr="request.uri = '/newpath'", forbid_substr="request.uri = '';")

print("== #3-#6 bare-field dynamic values ==")
op = first_op(_proc.process_redirect_rule(redirect_rule("true", target_expr="http.request.uri"), {}, ""))
check("bare-field redirect resolves accessor", emit(op),
      expect_substr="request.uri", forbid_substr="'http.request.uri'")
op = first_op(_proc.process_rewrite_rule(rewrite_rule("true", path_expr="http.request.uri"), {}, ""))
check("bare-field rewrite resolves accessor", emit(op),
      expect_substr="request.uri = request.uri", forbid_substr="'http.request.uri'")
op = first_op(_proc.process_request_header_transform(
    header_rule("true", {"X-IP": {"operation": "set", "expression": "ip.src"}}), {}, ""))
check("bare-field header ip.src", emit(op),
      expect_substr="event.viewer.ip", forbid_substr="'ip.src'")
op = first_op(_proc.process_request_header_transform(
    header_rule("true", {"X-H": {"operation": "set", "expression": "http.host"}}), {}, ""))
check("bare-field header http.host", emit(op),
      expect_substr="request.headers.host.value", forbid_substr="'http.host'")

print("== #7/#8 unmapped action value -> partial convert (non-convertible) ==")
res = _proc.process_request_header_transform(header_rule("true", {
    "X-IP": {"operation": "set", "expression": "ip.src"},
    "X-Bot": {"operation": "set", "expression": "cf.bot_management.score"},
    "X-WAF": {"operation": "set", "expression": "to_string(cf.waf.score)"},
}), {}, "")
types = [o["type"] for o in res]
nc = [o for o in res if o["type"] == "non_convertible"]
check("mappable header still converts (partial)", str(types),
      expect_substr="set_request_header")
check("unmapped bot header -> non_convertible", str(len(nc)), expect_substr="2")

print("== #9/#10 query rewrite ==")
op = first_op(_proc.process_rewrite_rule(rewrite_rule("true", query="a=1"), {}, ""))
check("static query rewrite", emit(op),
      expect_substr="request.querystring = 'a=1'", forbid_substr="request.uri = '';")
op = first_op(_proc.process_rewrite_rule(rewrite_rule("true", query_expr='concat("a=", ip.src.country)'), {}, ""))
check("dynamic query rewrite", emit(op), expect_substr="request.querystring =")
op = first_op(_proc.process_rewrite_rule(rewrite_rule("true", path="/p", query="a=1"), {}, ""))
js = emit(op)
check("path+query both emitted (uri)", js, expect_substr="request.uri = '/p'")
check("path+query both emitted (qs)", js, expect_substr="request.querystring = 'a=1'")

print("== #11 unmapped match condition (选项1: OR-drop, AND/bare-reject) ==")
def cond_result(expr):
    return _proc.process_redirect_rule(redirect_rule(expr, target_url="https://x.com"), {}, "")

r = cond_result("cf.bot_management.score gt 30")
check("bare unmapped condition -> non_convertible",
      r.get("type", "") if isinstance(r, dict) else "list",
      expect_substr="non_convertible")
r = cond_result('http.host eq "x.com" and cf.bot_management.score gt 30')
check("AND w/ unmapped -> non_convertible (no silent widening)",
      r.get("type", "") if isinstance(r, dict) else "list",
      expect_substr="non_convertible")
r = first_op(cond_result('http.host eq "x.com" or cf.bot_management.score gt 30'))
check("OR w/ unmapped -> drops branch, keeps host", str(r.get("condition")),
      expect_substr="'field': 'host'", forbid_substr="bot_management")

print("== no-regression: function-wrapped expressions still work ==")
op = first_op(_proc.process_redirect_rule(
    redirect_rule("true", target_expr='concat("https://x.com", http.request.uri.path)'), {}, ""))
check("concat redirect", emit(op), expect_substr="'https://x.com' + request.uri")
op = first_op(_proc.process_request_header_transform(
    header_rule("true", {"X-C": {"operation": "set", "expression": "concat(http.host, ip.src)"}}), {}, ""))
check("concat header", emit(op),
      expect_substr="request.headers.host.value + event.viewer.ip")


# ── #1 full_uri contains/eq/wildcard now truly convertible (was `false`) ──────

def redirect_cond_js(expr):
    """Run an expr through the redirect processor + generator, return the emitted
    condition JS (the `if (...)` guard) or a marker for non-convertible."""
    r = _proc.process_redirect_rule(redirect_rule(expr, target_url="https://x.com"), {}, "")
    if isinstance(r, dict) and r.get("type") == "non_convertible":
        return "NON_CONVERTIBLE"
    op = first_op(r)
    cond = op.get("condition")
    raw = op.get("raw_expression")
    if raw and not cond:
        cond = op.get("_parsed_condition") or _parser.parse_expression_full(raw)
    return _gen.condition_to_js(cond, "cff") or "None"

print("== #1 full_uri (contains/eq/no-scheme wildcard) -> real match, not false ==")
check("full_uri contains reconstructs URL", redirect_cond_js('http.request.full_uri contains "/admin"'),
      expect_substr="request.headers.host.value", forbid_substr="false")
check("full_uri eq reconstructs URL", redirect_cond_js('http.request.full_uri eq "https://x.com/p"'),
      expect_substr=".value + request.uri", forbid_substr="false")
check("full_uri no-scheme wildcard reconstructs URL", redirect_cond_js('http.request.full_uri wildcard "*/admin/*"'),
      expect_substr="request.uri", forbid_substr="=== 'false'")
check("full_uri scheme wildcard still host/path split (control)",
      redirect_cond_js('http.request.full_uri wildcard "https://x.com/admin/*"'),
      expect_substr="startsWith('/admin/')")

print("== #2 negated unmappable fails CLOSED (false), not open (!(false)) ==")
check("not_ op unmappable -> false", _gen.condition_to_js({"field": "subdivision_2", "op": "not_eq", "value": "x"}, "cff"),
      expect_substr="false", forbid_substr="!(false)")
check("logic-not wrapper unmappable -> false",
      _gen.condition_to_js({"logic": "not", "item": {"field": "subdivision_2", "op": "eq", "value": "x"}}, "cff"),
      expect_substr="false", forbid_substr="!(false)")

print("== subdivision_1 convertible / subdivision_2 non-convertible ==")
check("subdivision_1 -> Country-Region accessor",
      _gen.condition_to_js({"field": "subdivision_1", "op": "eq", "value": "CA"}, "cff"),
      expect_substr="cloudfront-viewer-country-region", forbid_substr="false")
check("subdivision_2 rule -> non_convertible",
      redirect_cond_js('ip.src.subdivision_2_iso_code eq "X"'), expect_substr="NON_CONVERTIBLE")

print("== #3 query_expression sha256 pulls in crypto import ==")
ir_crypto = {"metadata": {"hostname": "h", "sanitized_name": "h"}, "cache_behaviors": [{"viewer_request_ops": [
    {"type": "rewrite", "condition": None,
     "params": {"query_expression": 'concat("h=", encode_base64(sha256(http.host)))'}}], "viewer_response_ops": []}]}
vr = _gen.generate_viewer_request_js(ir_crypto)
check("sha256 query rewrite -> import crypto", vr, expect_substr="import crypto")
check("sha256 query rewrite -> createHash emitted", vr, expect_substr="crypto.createHash")

print("== #4 continent/is_eu in viewer-response: preamble + const request ==")
resp_ops = _proc.process_response_header_transform(
    header_rule('ip.src.continent eq "EU"', {"x-eu": {"operation": "set", "value": "1"}}), {}, "")
ir_resp = {"metadata": {"hostname": "h", "sanitized_name": "h", "kvs_id": "K"},
           "cache_behaviors": [{"viewer_request_ops": [], "viewer_response_ops": resp_ops}]}
resp_js = _gen.generate_viewer_response_js(ir_resp)
check("viewer-response defines request", resp_js, expect_substr="const request = event.request;")
check("viewer-response emits continent preamble", resp_js, expect_substr="kvsHandle.get('continent:")
check("viewer-response has no bare-undefined continent guard", resp_js, expect_substr="let continent = '';")

print("== #5 unparseable value_expression emits leak marker (not silent '') ==")
op = first_op(_proc.process_request_header_transform(
    header_rule("true", {"X-B": {"operation": "set", "expression": "broken((("}}), {}, ""))
check("parse failure tagged for validator", emit(op), expect_substr="no CloudFront source for")

print("== #9 deferred raw_expr parse tree cached on op (XOR invariant intact) ==")
res = _proc.process_origin_rule(
    {"id": "r", "expression": 'http.host eq "a.com" or http.host eq "b.com"',
     "action_parameters": {"origin": {"host": "o.com"}}}, {}, "")
op = first_op(res)
check("op carries _parsed_condition cache", str("_parsed_condition" in op), expect_substr="True")
check("condition/raw_expression still mutually exclusive",
      str(op.get("condition") is None and op.get("raw_expression") is not None), expect_substr="True")

# ── classifier alignment: every CF_FIELD_MAP value must be handled somewhere ──
print("== invariant: every mapped field is classifiable (no silent drift) ==")
_PREAMBLE = _gen._PREAMBLE_FIELDS
_SPECIAL = {"full_uri"}  # reconstructed, not a single accessor
unclassified = []
for short in sorted(set(_parser.CF_FIELD_MAP.values())):
    handled = (short in _gen.CFF_ACCESSORS or short in _gen.RESPONSE_ACCESSORS
               or short in _gen.LAMBDA_ACCESSORS or short in _PREAMBLE
               or short in _parser.UNMAPPABLE_FIELDS or short in _SPECIAL)
    if not handled:
        unclassified.append(short)
check("no CF_FIELD_MAP value is unclassified", str(unclassified),
      expect_substr="[]", forbid_substr="'")

print()
if FAILURES:
    print(f"FAILED: {len(FAILURES)} check(s)")
    sys.exit(1)
print("All checks passed.")
