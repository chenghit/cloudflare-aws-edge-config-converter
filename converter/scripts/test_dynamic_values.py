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

def redirect_rule(expr, target_url=None, target_expr=None, status=301, preserve_qs=False):
    fv = {"status_code": status, "target_url": {}, "preserve_query_string": preserve_qs}
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
        cond = _parser.parse_expression_full(raw)
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

print("== deferred raw_expr: XOR invariant intact, no stray cache key ==")
res = _proc.process_origin_rule(
    {"id": "r", "expression": 'http.host eq "a.com" or http.host eq "b.com"',
     "action_parameters": {"origin": {"host": "o.com"}}}, {}, "")
op = first_op(res)
# An OR expression is deferred as raw_expression (condition None). It must NOT
# also carry a structured condition, and must NOT leak the old _parsed_condition
# cache key (removed — it never survived _place_result's op rebuild anyway).
check("condition/raw_expression mutually exclusive",
      str(op.get("condition") is None and op.get("raw_expression") is not None), expect_substr="True")
check("no dead _parsed_condition key", str("_parsed_condition" in op), expect_substr="False")

def resp_js(ops):
    """Assemble a viewer_response.js from processor ops."""
    ir = {"metadata": {"hostname": "h", "sanitized_name": "h"},
          "cache_behaviors": [{"viewer_request_ops": [], "viewer_response_ops": ops}]}
    return _gen.generate_viewer_response_js(ir) or ""

def req_js(op):
    """Assemble a full viewer_request.js from a single op (so _qs is in scope)."""
    ir = {"metadata": {"hostname": "h", "sanitized_name": "h"},
          "cache_behaviors": [{"viewer_request_ops": [op], "viewer_response_ops": []}]}
    return _gen.generate_viewer_request_js(ir)

print("== #5 response-side sha256 header pulls import crypto (runtime fix) ==")
ops = _proc.process_response_header_transform(
    header_rule("true", {"x-sig": {"operation": "set", "expression": "encode_base64(sha256(http.host))"}}), {}, "")
rjs = resp_js(ops)
check("response sha256 -> import crypto", rjs, expect_substr="import crypto")
check("response sha256 -> createHash emitted", rjs, expect_substr="crypto.createHash")

print("== #6 add_*_header honors value_expression (was dropped to '') ==")
op = first_op(_proc.process_request_header_transform(
    header_rule("true", {"x-c": {"operation": "add", "expression": "concat(http.host, ip.src)"}}), {}, ""))
check("add_header resolves expression", emit(op),
      expect_substr="request.headers.host.value + event.viewer.ip", forbid_substr="{value: ''}")

print("== #7 unmappable action value -> clean per-rule non_convertible (no leak) ==")
r = _proc.process_redirect_rule(
    redirect_rule("true", target_expr='concat("https://x/", cf.bot_management.score)'), {}, "")
check("redirect target unmappable -> non_convertible",
      r.get("type", "") if isinstance(r, dict) else "list", expect_substr="non_convertible")
r = _proc.process_rewrite_rule(
    rewrite_rule("true", query_expr='concat("a=", cf.waf.score)'), {}, "")
check("rewrite query unmappable -> non_convertible",
      (r.get("type", "") if isinstance(r, dict) else "list"), expect_substr="non_convertible")
# mappable action value still converts (no over-rejection)
op = first_op(_proc.process_redirect_rule(
    redirect_rule("true", target_expr='concat("https://x/", http.request.uri.path)'), {}, ""))
check("mappable redirect expr still converts", str(op.get("type")), expect_substr="redirect")
check("mappable redirect emits no leak marker", emit(op), forbid_substr="no CloudFront source")

print("== #8 redirect preserve_query_string appends incoming query ==")
op = first_op(_proc.process_redirect_rule(
    redirect_rule("true", target_url="https://x.com/new", status=301, preserve_qs=True), {}, ""))
js = req_js(op)
check("preserve_qs appends _qs(request.querystring)", js, expect_substr="_qs(request.querystring)")
check("preserve_qs picks ? vs & delimiter", js, expect_substr="indexOf('?')")
op = first_op(_proc.process_redirect_rule(
    redirect_rule("true", target_url="https://x.com/new", status=301), {}, ""))
check("no preserve_qs stays simple", emit(op), forbid_substr="indexOf('?')")

print("== cf.kvs() takes NO argument (bound via TF association) ==")
# continent condition needs KVS -> the handle must be cf.kvs(), never cf.kvs('...')
kvs_ops = _proc.process_response_header_transform(
    header_rule('ip.src.continent eq "EU"', {"x": {"operation": "set", "value": "1"}}), {}, "")
kjs = resp_js(kvs_ops)
check("emits cf.kvs() with no arg", kjs, expect_substr="cf.kvs();", forbid_substr="cf.kvs('")
rq_op = first_op(_proc.process_redirect_rule(
    redirect_rule('ip.src in $blk', target_url="https://x"), {"blk": ["1.2.3.4"]}, ""))
rq_ir = {"metadata": {"hostname": "h", "sanitized_name": "h",
                      "kvs_requirements": {"needs_ip_lists": True}},
         "cache_behaviors": [{"viewer_request_ops": [rq_op], "viewer_response_ops": []}]}
rq = _gen.generate_viewer_request_js(rq_ir)
check("request handle also cf.kvs() no-arg", rq, expect_substr="cf.kvs();", forbid_substr="cf.kvs('")

print("== A: response_code in a REQUEST-phase action value -> non_convertible ==")
r = _proc.process_redirect_rule(
    redirect_rule("true", target_expr='concat("https://x/", to_string(http.response.code))'), {}, "")
check("request-phase response_code value -> non_convertible",
      r.get("type", "") if isinstance(r, dict) else "list", expect_substr="non_convertible")
# but response_code in a RESPONSE header value is fine (sourceable there)
ops = _proc.process_response_header_transform(
    header_rule("true", {"x-code": {"operation": "set", "expression": "to_string(http.response.code)"}}), {}, "")
types = [o["type"] for o in ops]
check("response-phase response_code value still converts", str(types), expect_substr="set_response_header")

print("== B: not ip.src in $list -> fail CLOSED (negated KVS lookup) ==")
r = _proc.process_redirect_rule(
    redirect_rule('not ip.src in $allow', target_url="https://blocked"), {"allow": ["1.2.3.4"]}, "")
op = first_op(r)
bjs = _gen.condition_to_js(op.get("condition"), "cff")
check("not-in-list emits negated KVS exists", bjs,
      expect_substr="!(await kvsHandle.exists", forbid_substr="!(false)")
# CIDR in a not-list is still safety-rejected
r = _proc.process_redirect_rule(
    redirect_rule('not ip.src in $cidr', target_url="https://x"), {"cidr": ["10.0.0.0/8"]}, "")
check("not-in-list with CIDR still rejected",
      r.get("type", "") if isinstance(r, dict) else "list", expect_substr="non_convertible")

print("== C: continent/is_eu in an OR condition -> preamble emitted (no undefined) ==")
ops = _proc.process_response_header_transform(
    header_rule('ip.src.continent eq "EU" or http.host eq "x.com"',
                {"x": {"operation": "set", "value": "1"}}), {}, "")
cjs = resp_js(ops)
check("OR-deferred continent still gets preamble", cjs, expect_substr="let continent = '';")
check("OR-deferred continent references defined var", cjs, expect_substr="kvsHandle.get('continent:")

print("== D: ip.src in an OR condition on a Cache Rule -> non_convertible ==")
r = _proc.process_cache_rule(
    {"id": "r", "expression": 'ip.src eq "1.2.3.4" or ip.src eq "5.6.7.8"',
     "action_parameters": {"cache": False}}, {}, "http_request_cache_settings")
check("ip.src-OR cache rule rejected (IP restriction not dropped)",
      (r.get("type", "") if isinstance(r, dict) else "list"), expect_substr="non_convertible")
# a geo OR (ip.src.country) must NOT trip the direct-ip guard
r = _proc.process_cache_rule(
    {"id": "r", "expression": 'ip.src.country eq "US" or ip.src.country eq "CA"',
     "action_parameters": {"cache": False}}, {}, "http_request_cache_settings")
check("ip.src.country-OR is not mistaken for direct ip.src",
      (r.get("type", "") if isinstance(r, dict) else "list"), forbid_substr="non_convertible")

print("== R1: is_eu condition references the isEU preamble var (not undefined) ==")
# is_eu must resolve to the exact variable the preamble declares.
check("is_eu accessor is isEU", _gen._get_accessor("is_eu"), expect_substr="isEU")
eu_ops = _proc.process_response_header_transform(
    header_rule("ip.src.is_in_european_union", {"x": {"operation": "set", "value": "1"}}), {}, "")
eu_js = resp_js(eu_ops)
check("preamble declares isEU", eu_js, expect_substr="let isEU")
check("condition references isEU", eu_js, expect_substr="if (isEU)")
# and the preamble var name matches what conditions use (no drift)
check("continent accessor matches preamble", _gen._get_accessor("continent"),
      expect_substr=_gen._PREAMBLE_ACCESSORS["continent"])

print("== R2: OR-deferred not-in-list is structured + resolved (no fail-open) ==")
r = _proc.process_redirect_rule(
    redirect_rule('not ip.src in $allow or http.host eq "x.com"', target_url="https://b"),
    {"allow": ["1.2.3.4"]}, "")
op = first_op(r)
if op.get("type") != "non_convertible":
    js = _gen.condition_to_js(op.get("condition")
                              or _parser.parse_expression_full(op.get("raw_expression")), "cff")
    check("OR not-in-list negated KVS lookup", js, expect_substr="!(await kvsHandle.exists")
    check("OR not-in-list no fail-open sentinel", js, forbid_substr="!(false)")
    check("OR not-in-list no leaked TODO", js, forbid_substr="TODO")

print("== R3: negation of a false-sentinel stays false (never !(false)) ==")
check("not_in_list unresolved -> false", _gen.condition_to_js({"field": "ip.src", "op": "not_in_list", "value": "$x"}, "cff"),
      expect_substr="false", forbid_substr="!(")
check("logic-not over unresolved in_list -> false",
      _gen.condition_to_js({"logic": "not", "item": {"field": "ip.src", "op": "in_list", "value": "$x"}}, "cff"),
      expect_substr="false", forbid_substr="!(")

print("== R4: continent in a RESPONSE op sets kvs_requirements (provisioning) ==")
# Mirror cdn-preprocess's KVS-requirements scan over BOTH op lists.
_kreq = {}
_resp_ops = _proc.process_response_header_transform(
    header_rule('ip.src.continent eq "EU"', {"x": {"operation": "set", "value": "1"}}), {}, "")
for _op in _resp_ops:
    _c = _op.get("condition")
    if _c:
        for _t in _parser.extract_kvs_triggers(_c):
            _kreq[_t] = True
check("response continent triggers needs_continent", str(_kreq.get("needs_continent")), expect_substr="True")

print("== R5: response_code in a REQUEST-phase condition -> non_convertible ==")
r = _proc.process_redirect_rule(redirect_rule("http.response.code eq 200", target_url="https://x"), {}, "")
check("request-phase response_code condition rejected",
      r.get("type", "") if isinstance(r, dict) else "list", expect_substr="non_convertible")
# response phase: response_code IS fine (must NOT be rejected)
check("response-phase response_code condition allowed (cff-only check)",
      str(_parser.condition_unmappable_fields({"field": "response_code", "op": "eq", "value": 200}, "response")),
      expect_substr="[]")

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
