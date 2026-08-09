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
import os
import sys

# Production scripts live in converter/scripts/; this test lives in /test/ (a
# gitignored, development-only tree). Resolve module paths against the repo
# layout so the test runs from any working directory.
_SCRIPTS = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "converter", "scripts")


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(
        name, os.path.join(_SCRIPTS, filename))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# Load modules by file path (hyphenated filenames aren't importable normally).
_parser = _load("cdn_expr_parser", "cdn_expr_parser.py")
sys.modules["cdn_expr_parser"] = _parser
_proc = _load("cdn_rule_processors", "cdn_rule_processors.py")
_gen = _load("cdn_generate_js", "cdn-generate-js.py")
_pre = _load("cdn_preprocess", "cdn-preprocess.py")
_fin = _load("cdn_finalize", "cdn-finalize.py")

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

print("== OR expressions are structured (not deferred to raw) ==")
res = _proc.process_origin_rule(
    {"id": "r", "expression": 'http.host eq "a.com" or http.host eq "b.com"',
     "action_parameters": {"origin": {"host": "o.com"}}}, {}, "")
op = first_op(res)
# Root fix: an OR is now structured via parse_expression_full — a proper
# {"logic": "or"} condition, NOT deferred to raw_expression. This is what kills
# the whole raw-deferral bandaid class.
check("OR yields structured condition", str(op.get("condition")), expect_substr="'logic': 'or'")
check("OR leaves raw_expression empty", str(op.get("raw_expression")), expect_substr="None")
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

print("== ROOT: OR is structured via full parser (not deferred to raw) ==")
c, raw = _parser.parse_expression('http.host eq "a" or http.request.uri.path eq "/b"')
check("OR parse yields structured cond", str(c), expect_substr="'logic': 'or'")
check("OR parse leaves no raw", str(raw), expect_substr="None")

print("== S1: not(OR containing ip.src list) doesn't crash ==")
for _e in ['ip.src in $allow or not (http.host eq "z.com" and ip.src in $deny)',
           'not (ip.src in $allow or http.host eq "x.com")']:
    try:
        _r = _proc.process_redirect_rule(
            {"id": "r", "description": "t", "expression": _e,
             "action_parameters": {"from_value": {"status_code": 302, "target_url": {"value": "https://b"}}}},
            {"allow": ["1.2.3.4"], "deny": ["9.9.9.9"]}, "")
        check(f"no crash: {_e[:32]}", (_r.get("type") if isinstance(_r, dict) else "list") or "ok",
              forbid_substr="__never__")
    except Exception as _ex:
        check(f"no crash: {_e[:32]}", f"CRASH {type(_ex).__name__}", forbid_substr="CRASH")

print("== S2: _NEVER is contagious (polarity-sound, no fail-open) ==")
# The generator's _NEVER backstop fails the WHOLE condition closed — it does NOT
# drop an un-evaluable OR branch (dropping-then-negating is fail-open under NOT;
# see the enumerative property test below). OR-branch pruning of merely-unmappable
# fields is the processor's job (_prune_unmappable), done before codegen.
check("OR with un-evaluable branch fails closed (contagious)",
      _gen.condition_to_js({"logic": "or", "parts": [
          {"field": "subdivision_2", "op": "eq", "value": "x"},
          {"field": "uri.path", "op": "eq", "value": "/a"}]}, "cff"),
      expect_substr="false")
check("X && un-evaluable collapses to false",
      _gen.condition_to_js({"logic": "and", "parts": [
          {"field": "uri.path", "op": "eq", "value": "/a"},
          {"field": "subdivision_2", "op": "eq", "value": "x"}]}, "cff"),
      expect_substr="false")
check("not(un-evaluable) stays false (no fail-open)",
      _gen.condition_to_js({"logic": "not", "item": {"logic": "or", "parts": [
          {"field": "subdivision_2", "op": "eq", "value": "x"}]}}, "cff"),
      expect_substr="false", forbid_substr="!(")
# The exact #1 fail-open: not(A or un-evaluable) must be false, NOT !(A).
check("not(A or un-evaluable) fails closed (finding #1)",
      _gen.condition_to_js({"logic": "not", "item": {"logic": "or", "parts": [
          {"field": "uri.path", "op": "eq", "value": "/a"},
          {"field": "continent", "op": "eq", "value": "EU"}]}}, "lambda"),
      expect_substr="false", forbid_substr="!(")
# #6: a real OR whose rendered form starts with a `/*` regex and ends in
# `=== false` must NOT be misread as a never-match sentinel and collapsed.
check("real OR ending in '=== false' not collapsed (structural sentinel)",
      _gen.condition_to_js({"logic": "or", "parts": [
          {"field": "uri.path", "op": "matches", "value": "*x"},
          {"field": "method", "op": "eq", "value": False}]}, "cff"),
      expect_substr="request.method === false", forbid_substr="/* ")

print("== S2b: None (always) parts handled, no crash / literal None ==")
check("not(always) -> false", _gen.condition_to_js({"logic": "not", "item": {"always": True}}, "cff"),
      expect_substr="false", forbid_substr="None")
check("and[X, always] drops always",
      _gen.condition_to_js({"logic": "and", "parts": [
          {"field": "uri.path", "op": "eq", "value": "/a"}, {"always": True}]}, "cff"),
      expect_substr="request.uri === '/a'", forbid_substr="None")
# #7: malformed logic nodes must not crash — fail closed (false) or unconditional.
check("malformed not-node (no item) doesn't crash",
      str(_gen.condition_to_js({"logic": "not"}, "cff")), expect_substr="false")
check("malformed and-node (no parts) doesn't crash",
      str(_gen.condition_to_js({"logic": "and"}, "cff")), forbid_substr="Error")

print("== S3: response op with in_kvs pulls cf.kvs() into response JS ==")
_ipop = _proc.process_response_header_transform(
    header_rule('ip.src in $blk', {"x": {"operation": "set", "value": "1"}}), {"blk": ["1.2.3.4"]}, "")
_ipjs = resp_js(_ipop)
check("response in_kvs -> cf.kvs()", _ipjs, expect_substr="cf.kvs()")

print("== S5/S6: non-ip.src named list -> non_convertible (not bogus IP-KVS) ==")
for _e in ['http.host in $hostlist or http.request.uri.path eq "/a"',
           'ip.src.country in $geo', 'ip.src.asnum in $asns']:
    _r = _proc.process_redirect_rule(
        {"id": "r", "description": "t", "expression": _e,
         "action_parameters": {"from_value": {"status_code": 302, "target_url": {"value": "https://b"}}}}, {}, "")
    check(f"{_e[:28]} -> non_convertible",
          _r.get("type", "") if isinstance(_r, dict) else "list", expect_substr="non_convertible")

print("== S7: continent/is_eu unmappable in Lambda@Edge target ==")
check("lambda continent -> false", _gen.condition_to_js({"field": "continent", "op": "eq", "value": "EU"}, "lambda"),
      expect_substr="false")
check("lambda is_eu -> false", _gen.condition_to_js({"field": "is_eu", "op": "eq", "value": True}, "lambda"),
      expect_substr="false")
check("(a) NOT(continent) still triggers KVS provisioning",
      str(_parser.extract_kvs_triggers({"logic": "not", "item": {"field": "continent", "op": "eq", "value": "EU"}})),
      expect_substr="needs_continent")

print("== T1: parenthesized OR is not truncated ==")
_c, _raw = _parser.parse_expression('(http.host eq "a.com" or http.host eq "b.com")')
check("(A or B) -> structured OR", str(_c), expect_substr="'logic': 'or'")
check("(A or B) keeps both branches", str(_c), expect_substr="b.com")

print("== T13: NOT-node walkers (iter_condition_children) — no skip, no crash ==")
# ip.src cache guard sees ip.src under NOT
check("ip.src under NOT trips cache guard",
      (lambda r: (r if isinstance(r, dict) else r[0]).get("type"))(
          _proc.process_cache_rule({"id": "r", "expression": 'not (ip.src eq "1.2.3.4")',
                                     "action_parameters": {"cache": False}}, {}, "http_request_cache_settings")),
      expect_substr="non_convertible")
# KVS trigger under NOT
check("continent under NOT triggers KVS",
      str(_parser.extract_kvs_triggers({"logic": "not", "item": {"field": "continent", "op": "eq", "value": "EU"}})),
      expect_substr="needs_continent")
# A single positive response_code eq leaf IS the code to serve.
check("single response_code eq -> the code",
      str(_proc._find_response_code_value({"field": "response_code", "op": "eq", "value": 502})),
      expect_substr="502")
# A CloudFront custom_error_response maps exactly ONE code → one response. A code
# under ANY logic node is not faithfully representable and must NOT be extracted:
#  - AND-scoped (code eq 500 and uri.path /api): custom errors are
#    per-distribution, can't scope by path → over-match if extracted.
#  - OR of codes: returning the first silently drops the others.
#  - under NOT: it's an exclusion, not the served code.
check("response_code AND-scoped is not extracted",
      str(_proc._find_response_code_value({"logic": "and", "parts": [
          {"field": "uri.path", "op": "eq", "value": "/api"},
          {"field": "response_code", "op": "eq", "value": 500}]})),
      expect_substr="None")
check("response_code OR-of-codes is not extracted",
      str(_proc._find_response_code_value({"logic": "or", "parts": [
          {"field": "response_code", "op": "eq", "value": 500},
          {"field": "response_code", "op": "eq", "value": 502}]})),
      expect_substr="None")
check("response_code under NOT is not extracted",
      str(_proc._find_response_code_value({"logic": "not",
          "item": {"field": "response_code", "op": "eq", "value": 404}})),
      expect_substr="None")
check("quoted response_code coerced to int",
      str(_proc._find_response_code_value({"field": "response_code", "op": "eq", "value": "404"})),
      expect_substr="404")
# path extraction on a NOT node doesn't crash and stays global
check("path pattern on NOT node -> * (no crash)",
      _proc._extract_path_pattern({"logic": "not", "item": {"field": "uri.path", "op": "eq", "value": "/a"}}, ""),
      expect_substr="*")
# negated host applies to every host EXCEPT x (NOT global — old behavior let it
# land on x's own distribution and, after host-strip, fire on x: fail-open).
# Assert BEHAVIOR (does it apply to a concrete host) not the internal shape.
def _applies_leaf(cond, hostname):
    return _pre.rule_applies_to_domain(
        _parser.extract_host_filter(cond, ""), hostname, "com")
check("not(host eq x) does NOT apply to x",
      str(_applies_leaf({"field": "host", "op": "not_eq", "value": "x.com"}, "x.com")),
      expect_substr="False")
check("not(host eq x) DOES apply to y",
      str(_applies_leaf({"field": "host", "op": "not_eq", "value": "x.com"}, "y.com")),
      expect_substr="True")
# iter_condition_children yields both parts and item
check("iter_condition_children yields item",
      str([c.get("field") for c in _parser.iter_condition_children(
          {"logic": "not", "item": {"field": "ip.src", "op": "eq", "value": "1"}})]),
      expect_substr="ip.src")

print("== T12: pathological deep-nested OR falls back to raw (no RecursionError) ==")
_deep = "(" * 3000 + 'http.host eq "x"' + ")" * 3000 + ' or http.host eq "y"'
try:
    _c, _raw = _parser.parse_expression(_deep)
    check("deep OR -> no crash", "ok", forbid_substr="__never__")
except RecursionError:
    check("deep OR -> no crash", "RecursionError", forbid_substr="RecursionError")

print("== U2: A and (B or C) keeps the OR branch (was dropped) ==")
_c, _raw = _parser.parse_expression(
    'http.host eq "a" and (http.request.uri.path eq "/x" or http.request.uri.path eq "/y")')
check("nested OR-in-AND keeps /y", str(_c), expect_substr="/y")
check("nested OR-in-AND has inner or", str(_c), expect_substr="'logic': 'or'")
_c, _raw = _parser.parse_expression(
    '(http.request.uri.path eq "/x" or http.request.uri.path eq "/y") and http.host eq "a"')
check("OR-in-AND (other order) keeps /y", str(_c), expect_substr="/y")

print("== U4: negated response_code not used as the error code ==")
check("not(code eq 404) -> no code extracted",
      str(_proc._find_response_code_value({"field": "response_code", "op": "not_eq", "value": 404})),
      expect_substr="None")
check("positive code eq 500 -> 500",
      str(_proc._find_response_code_value({"field": "response_code", "op": "eq", "value": 500})),
      expect_substr="500")

print("== U5: extension fan-out only when condition is purely extensions ==")
# pure extension set → fan out is allowed
check("pure ext set is fan-out-eligible",
      str(_pre._condition_is_pure_extension(
          {"field": "uri.path.extension", "op": "in", "value": ["pdf", "jpg"]})),
      expect_substr="True")
# host AND ext → NOT pure (must keep host scope, no global fan-out)
check("host AND ext is NOT fan-out-eligible",
      str(_pre._condition_is_pure_extension(
          {"logic": "and", "parts": [
              {"field": "host", "op": "eq", "value": "x"},
              {"field": "uri.path.extension", "op": "in", "value": ["pdf", "jpg"]}]})),
      expect_substr="False")

print("== U1: cache OR-split reads the structured condition ==")
# an OR of two path leaves → splits into per-path list
check("OR of two paths splits",
      str(_pre._try_split_or_cache_paths({"logic": "or", "parts": [
          {"field": "uri.path", "op": "eq", "value": "/a"},
          {"field": "uri.path", "op": "eq", "value": "/b"}]})),
      expect_substr="/a")
# a non-OR condition is not splittable (returns None → routed elsewhere)
check("non-OR condition not splittable",
      str(_pre._try_split_or_cache_paths({"field": "uri.path", "op": "eq", "value": "/a"})),
      expect_substr="None")

# ── classifier alignment: every CF_FIELD_MAP value must be handled somewhere ──
print("== invariant: every mapped field is classifiable (no silent drift) ==")
_PREAMBLE = _gen._PREAMBLE_FIELDS
_SPECIAL = {"full_uri", "cookie"}  # reconstructed, not a single accessor
# (cookie = http.cookie, rebuilt from request.cookies via the _cookieStr helper)
unclassified = []
for short in sorted(set(_parser.CF_FIELD_MAP.values())):
    handled = (short in _gen.CFF_ACCESSORS or short in _gen.RESPONSE_ACCESSORS
               or short in _gen.LAMBDA_ACCESSORS or short in _PREAMBLE
               or short in _parser.UNMAPPABLE_FIELDS or short in _SPECIAL)
    if not handled:
        unclassified.append(short)
check("no CF_FIELD_MAP value is unclassified", str(unclassified),
      expect_substr="[]", forbid_substr="'")

print("== V (round 8): host-strip, dead-sink, lambda/kvs, empty-OR ==")
# A: redundant host condition is stripped after host-routing
check("host-only strips to unconditional ({always:True}, not None)",
      str(_pre._strip_host_condition({"field": "host", "op": "eq", "value": "x"})),
      expect_substr="'always': True")
check("host AND path strips to just path",
      str(_pre._strip_host_condition({"logic": "and", "parts": [
          {"field": "host", "op": "eq", "value": "x"},
          {"field": "uri.path", "op": "eq", "value": "/api"}]})),
      expect_substr="'field': 'uri.path'")
# B: single-path gate rejects extension-eq (→*), accepts extension-in-one
check("ext eq is not single-path (would be site-wide)",
      str(_pre._cache_cond_is_single_path({"field": "uri.path.extension", "op": "eq", "value": "pdf"})),
      expect_substr="False")
check("ext in [one] is single-path",
      str(_pre._cache_cond_is_single_path({"field": "uri.path.extension", "op": "in", "value": ["pdf"]})),
      expect_substr="True")
# C: lambda in_kvs fails closed (no undefined kvsHandle)
check("lambda in_kvs -> false", _gen.condition_to_js({"field": "ip.src", "op": "in_kvs", "value": "deny"}, "lambda"),
      expect_substr="false")
check("cff in_kvs still works", _gen.condition_to_js({"field": "ip.src", "op": "in_kvs", "value": "deny"}, "cff"),
      expect_substr="kvsHandle.exists")
# F: empty OR fails closed (was None = fires always)
check("empty OR -> false (fail closed)",
      _gen.condition_to_js({"logic": "or", "parts": []}, "cff"), expect_substr="false")
check("empty AND -> unconditional (None)",
      str(_gen.condition_to_js({"logic": "and", "parts": []}, "cff")), expect_substr="None")
# G: dead code removed
check("_needs_kvs removed", str(hasattr(_gen, "_needs_kvs")), expect_substr="False")
check("_parse_single_condition removed", str(hasattr(_parser, "_parse_single_condition")), expect_substr="False")

print("== W (round 10): host-strip, len/lower, custom-error, full_uri cache ==")
# H1: negated host applies to every dist EXCEPT x (assert behavior per host, not
# the internal filter shape — round-12 replaced include/exclude with a tree).
def _applies_expr(expr, hostname):
    c, raw = _parser.parse_expression(expr)
    return _pre.rule_applies_to_domain(
        _parser.extract_host_filter(c, raw or expr), hostname, "com")
check("W-H1 not_eq host: not on x", str(_applies_expr('http.host ne "x.com"', "x.com")), expect_substr="False")
check("W-H1 not_eq host: on y", str(_applies_expr('http.host ne "x.com"', "y.com")), expect_substr="True")
check("W-H1 not(host in set): not on a", str(_applies_expr('not (http.host in {"a.com" "b.com"})', "a.com")), expect_substr="False")
check("W-H1 not(host in set): not on b", str(_applies_expr('not (http.host in {"a.com" "b.com"})', "b.com")), expect_substr="False")
check("W-H1 not(host in set): on c", str(_applies_expr('not (http.host in {"a.com" "b.com"})', "c.com")), expect_substr="True")
# `host eq a OR host ne b`: true for a (branch 1) and every host != b (branch 2);
# only b fails both -> applies everywhere except b.
check("W-H1 include OR exclude: on a", str(_applies_expr('http.host eq "a.com" or http.host ne "b.com"', "a.com")), expect_substr="True")
check("W-H1 include OR exclude: not on b", str(_applies_expr('http.host eq "a.com" or http.host ne "b.com"', "b.com")), expect_substr="False")
check("W-H1 include OR exclude: on c", str(_applies_expr('http.host eq "a.com" or http.host ne "b.com"', "c.com")), expect_substr="True")

# H2: strip ONLY host leaves the ROUTER consumed (eq/in/ne/not_in). A live host
# PREDICATE (len(host), host contains ...) is NOT consumed -> must be KEPT, or
# the predicate is silently dropped (fail-open). This is the exact bug the e2e
# test caught that the old "strip any host leaf" logic introduced.
check("W-H2 negated identity host strips (router consumed it)",
      str(_pre._strip_host_condition({"field": "host", "op": "not_eq", "value": "x.com"})),
      expect_substr="'always': True")
check("W-H2 len(host) predicate is KEPT (router did NOT consume it)",
      str(_pre._strip_host_condition({"field": "host", "op": "gt", "value": 5, "size_check": True})),
      expect_substr="'size_check': True", forbid_substr="always")
check("W-H2 host contains predicate is KEPT",
      str(_pre._strip_host_condition({"field": "host", "op": "contains", "value": "x"})),
      expect_substr="'op': 'contains'", forbid_substr="always")
check("W-H2 len(host) AND path keeps BOTH (only routing-host conjuncts strip)",
      str(_pre._strip_host_condition({"logic": "and", "parts": [
          {"field": "host", "op": "gt", "value": 5, "size_check": True},
          {"field": "uri.path", "op": "eq", "value": "/p"}]})),
      expect_substr="'size_check': True")

# C1: len() -> .length, lower()/upper() -> .toLowerCase()/.toUpperCase(), via
# the real parser (size_check / transform leaf modifiers) into condition_to_js.
check("W-C1 len(host) gt 5 renders .length",
      _gen.condition_to_js(_parser.parse_expression_full("len(http.host) gt 5"), "cff"),
      expect_substr=".length > 5")
check("W-C1 lower(host) eq renders .toLowerCase()",
      _gen.condition_to_js(_parser.parse_expression_full('lower(http.host) eq "x.com"'), "cff"),
      expect_substr=".toLowerCase() === 'x.com'")
check("W-C1 upper(uri.path) eq renders .toUpperCase()",
      _gen.condition_to_js(_parser.parse_expression_full('upper(http.request.uri.path) eq "/A"'), "cff"),
      expect_substr=".toUpperCase() === '/A'")

def _cjs(expr):
    return _gen.condition_to_js(_parser.parse_expression_full(expr), "cff")

# ── W-C1b: len() on an INDEXED cookie/header/arg — the REAL, Cloudflare-LEGAL case.
# In Cloudflare a cookies/headers/uri.args value is Map<Array<String>>, and len()
# accepts an Array, so `len(http.request.headers["rsc"])` is LEGAL and means the
# element COUNT (how many times the name appears), NOT the string length of a value.
# The dashboard "exists" operator emits `len(...) > 0`. Verified on a real CloudFront
# Function: a present-but-EMPTY header ("") has value "" / length 0 yet CF's len is 1,
# so `.value.length > 0` was a silent false-negative. The exists idiom (>0 / >=1 / !=0)
# renders as a pure existence check; other comparisons render the multiValue count,
# existence-GUARDED (a MISSING field's len is `missing` → every comparison is false).
check("W-C1b len(headers[rsc])>0 -> pure existence (CF exists idiom, NOT .value.length)",
      _cjs('len(http.request.headers["rsc"]) > 0'),
      expect_substr="request.headers['rsc'] !== undefined",
      forbid_substr=".value.length")
check("W-C1b len(cookies[sid]) gt 3 -> guarded occurrence count via multiValue",
      _cjs('len(http.request.cookies["sid"]) gt 3'),
      expect_substr="request.cookies['sid'] !== undefined && (request.cookies['sid'].multiValue ? request.cookies['sid'].multiValue.length : 1) > 3",
      forbid_substr=".value.length")

# W-C1b-missing: a MISSING indexed field's len is `missing` in Cloudflare, so ANY
# comparison is FALSE — never length 0. So every count form must be existence-guarded
# (else `len eq 0` / `ge 0` / `lt 1` fire on an absent field → silent widening).
# Assert the guard is present and it's NOT the raw-0 form `=== undefined ? 0`.
for _op in ('eq 0', 'ge 0', 'lt 1', 'le 0'):
    check(f"W-C1b-missing len(headers[x]) {_op} guards existence (missing->false, no widening)",
          _cjs(f'len(http.request.headers["x"]) {_op}'),
          expect_substr="request.headers['x'] !== undefined &&", forbid_substr="=== undefined ? 0")
check("W-C1b-missing negated count keeps missing->false via `=== undefined ||`",
      _cjs('not (len(http.request.headers["x"]) eq 0)'),
      expect_substr="request.headers['x'] === undefined ||", forbid_substr="=== undefined ? 0")

# ── W-C1b-robust: lower()/upper()/starts_with()/ends_with() wrapping a BARE indexed
# field, and `in {set}` / `eq` on a bare indexed field. NOTE these are NOT valid
# Cloudflare syntax — a Map<Array<String>> value can't be used directly as a String;
# Cloudflare requires `headers["x"][0]` (one element) or `headers["x"][*]` inside
# any()/all(). A real backup will NEVER contain these forms. These are ROBUSTNESS
# tests: the parser is lenient (it doesn't validate CF type rules), so if such an
# expression ever reaches it (edge/malformed input), the fix must still route the
# field through _map_field and carry the name — NOT leak `headers['']` (empty key,
# silent never-match). They assert the name survives, not that the form is legal.
check("W-C1b-robust lower(headers[x-env]) carries name (parser leniency, not legal CF)",
      _cjs('lower(http.request.headers["x-env"]) eq "prod"'),
      expect_substr="request.headers['x-env'].value.toLowerCase() === 'prod'", forbid_substr="headers['']")
check("W-C1b-robust upper(cookies[Theme]) carries name",
      _cjs('upper(http.request.cookies["Theme"]) eq "DARK"'),
      expect_substr="request.cookies['Theme'].value.toUpperCase() === 'DARK'", forbid_substr="cookies['']")
check("W-C1b-robust starts_with(headers[ref]) carries name",
      _cjs('starts_with(http.request.headers["ref"], "http")'),
      expect_substr="request.headers['ref'].value.startsWith('http')", forbid_substr="headers['']")
check("W-C1b-robust ends_with(uri.args[p]) carries name",
      _cjs('ends_with(http.request.uri.args["p"], ".json")'),
      expect_substr="request.querystring['p'].value.endsWith('.json')", forbid_substr="querystring['']")

# W-C1c-robust: `in {set}` on a bare indexed field — also not legal CF syntax (same
# array-as-string issue), a robustness test that the _field_expr `in` return carries
# the name (was dropping **extra → `request.cookies[''] ...`, silent never-match).
check("W-C1c-robust cookies[env] in {set} carries name, not empty key",
      _cjs('http.request.cookies["env"] in {"prod" "staging"}'),
      expect_substr="['prod', 'staging'].includes(request.cookies['env'].value)",
      forbid_substr="cookies['']")
check("W-C1c-robust headers[x-env] in {set} carries name (lowercased)",
      _cjs('http.request.headers["x-env"] in {"a" "b"}'),
      expect_substr="request.headers['x-env']", forbid_substr="headers['']")
check("W-C1c-robust uri.args[mode] in {set} carries name",
      _cjs('http.request.uri.args["mode"] in {"1"}'),
      expect_substr="request.querystring['mode']", forbid_substr="querystring['']")

# W-C1d: the LEGAL array forms Cloudflare actually uses — `headers["x"][0]` (one
# element) and `any(headers["x"][*] ...)` — are NOT structured by our parser; they
# must degrade to raw_expression (→ non-convertible / WARNING downstream), i.e.
# FAIL-VISIBLE, never silently mis-rendered. Assert parse_expression returns raw.
for _legal in ('http.request.headers["x"][0] eq "1"',
               'any(http.request.headers["x"][*] eq "1")'):
    _c, _raw = _parser.parse_expression(_legal)
    check(f"W-C1d legal array form {_legal[:38]}… -> raw (fail-visible, not silent)",
          "raw" if (_c is None and _raw) else f"structured:{_c}", expect_substr="raw")

# C2: custom error — intercepted code from the CONDITION, returned code from the
# action. Compound/OR/no-code conditions can't map -> non_convertible.
def _err(expr, status=None):
    ap = {} if status is None else {"status_code": status}
    return _proc.process_custom_error_rule(
        {"id": "e1", "description": "d", "expression": expr, "action_parameters": ap},
        {}, "http_custom_errors")
_r = _err("http.response.code eq 500", 404)
check("W-C2 error_code from condition (500)", str(_r.get("params", {}).get("error_code")), expect_substr="500")
check("W-C2 response_code from action (404)", str(_r.get("params", {}).get("response_code")), expect_substr="404")
# `code eq 500 and host eq x` is convertible: host eq x is a redundant per-host
# routing conjunct (this rule already reached x's distribution), so it reduces
# to a clean `code eq 500`. A NON-host scope (uri.path) still can't → non_conv.
_rc = _err('http.response.code eq 500 and http.host eq "x.com"', 404)
check("W-C2 code AND redundant-host -> convertible (500)",
      str(_rc.get("params", {}).get("error_code")), expect_substr="500")
check("W-C2 code AND uri.path -> non_convertible (real non-host scope)",
      _err('http.response.code eq 500 and http.request.uri.path eq "/api"', 404).get("type"),
      expect_substr="non_convertible")
check("W-C2 OR-of-codes -> non_convertible",
      _err("http.response.code eq 500 or http.response.code eq 502").get("type"),
      expect_substr="non_convertible")
check("W-C2 unsupported code (418) -> non_convertible",
      _err("http.response.code eq 418").get("type"), expect_substr="non_convertible")

# P1: full_uri wildcard cache leaf reduces to its concrete path pattern and IS a
# single-path scope (a real ordered behavior), not swallowed site-wide.
_fu = _parser.parse_expression_full('http.request.full_uri wildcard "https://x.com/files/*"')
check("W-P1 full_uri wildcard -> concrete path /files/*",
      _parser.extract_path_pattern_single(_fu), expect_substr="/files/*")
check("W-P1 full_uri wildcard IS single-path",
      str(_pre._cache_cond_is_single_path(_fu)), expect_substr="True")
check("W-P1 full_uri contains (no concrete path) is NOT single-path",
      str(_pre._cache_cond_is_single_path(
          _parser.parse_expression_full('http.request.full_uri contains "/files"'))),
      expect_substr="False")

print("== X (round 11): host-filter set algebra, negated leaves, regex, len coercion ==")
# The round-10 include/exclude host filter didn't compose. Reworked as
# satisfiability-set algebra (AND=intersect, OR=union, NOT=De Morgan pushdown).
# Assert applies() matches the SEMANTIC truth of each expression per host.
def _hf(e):
    c, raw = _parser.parse_expression(e)
    return _parser.extract_host_filter(c, raw or e)
def _applies(e, h):
    return _pre.rule_applies_to_domain(_hf(e), h, h.split(".", 1)[-1])

# #1 AND, negated-first conjunct: `host ne b and host eq a` == only a (NOT
# exclude[b], which would fire on c AND strip to always-true → every request).
check("X-#1 (host ne b AND host eq a) applies to a", str(_applies('http.host ne "b.com" and http.host eq "a.com"', "a.com")), expect_substr="True")
check("X-#1 (host ne b AND host eq a) NOT on c (was fail-open)", str(_applies('http.host ne "b.com" and http.host eq "a.com"', "c.com")), expect_substr="False")
# #4 OR of negated hosts (tautology, true everywhere) -> global, applies to all.
check("X-#4 (host ne a OR host ne b) applies to a (was dropped)", str(_applies('http.host ne "a.com" or http.host ne "b.com"', "a.com")), expect_substr="True")
# #5 NOT over (host AND path): fires on a for path != /x -> must apply to a.
check("X-#5 not(host eq a AND path /x) applies to a (was dropped)", str(_applies('not (http.host eq "a.com" and http.request.uri.path eq "/x")', "a.com")), expect_substr="True")
# #7 negated full_uri -> fires on other hosts too -> applies to b.
check("X-#7 not(full_uri wildcard a/admin) applies to b (was dropped)", str(_applies('not (http.request.full_uri wildcard "https://a.com/admin/*")', "b.com")), expect_substr="True")
# De Morgan sanity: not(host eq a or host eq b) == exclude both.
check("X negated-OR-of-hosts: not on a", str(_applies('not (http.host eq "a.com" or http.host eq "b.com")', "a.com")), expect_substr="False")
check("X negated-OR-of-hosts: not on b", str(_applies('not (http.host eq "a.com" or http.host eq "b.com")', "b.com")), expect_substr="False")
check("X negated-OR-of-hosts: on c", str(_applies('not (http.host eq "a.com" or http.host eq "b.com")', "c.com")), expect_substr="True")

# #7 cache placement: a NEGATED full_uri leaf is not a single path pattern.
check("X-#7 negated full_uri path -> * (not the excluded /admin/*)",
      _parser.extract_path_pattern_single(
          _parser.parse_expression_full('not (http.request.full_uri wildcard "https://a.com/admin/*")')),
      expect_substr="*")

# #2 negated extension set must NOT be extracted as positive.
check("X-#2 not(ext in {pdf} or ext eq jpg) -> [] (excluded, not cached)",
      str(_pre._extract_extensions_from_condition(_parser.parse_expression_full(
          'not (http.request.uri.path.extension in {"pdf"} or http.request.uri.path.extension eq "jpg")'))),
      expect_substr="[]")
check("X-#2 positive ext OR still collects both",
      str(_pre._extract_extensions_from_condition(_parser.parse_expression_full(
          'http.request.uri.path.extension in {"pdf"} or http.request.uri.path.extension eq "jpg"'))),
      expect_substr="jpg")

# #3 ip.src regex must match `not in` / == / != allowlist forms on the raw path.
check("X-#3 ip.src not in {...} trips guard", str(_proc._uses_ip_src(None, 'ip.src not in {1.2.3.4 5.6.7.8}')), expect_substr="True")
check("X-#3 ip.src != trips guard", str(_proc._uses_ip_src(None, 'ip.src != 1.2.3.4')), expect_substr="True")
check("X-#3 ip.src in string literal does NOT trip", str(_proc._uses_ip_src(None, 'http.request.uri contains "ip.src"')), expect_substr="False")

# #6 len()/lower() on full_uri now render .length / .toLowerCase().
check("X-#6 len(full_uri) renders .length", _gen.condition_to_js(_parser.parse_expression_full('len(http.request.full_uri) gt 20'), "cff"), expect_substr=".length > 20")
check("X-#6 lower(full_uri) renders .toLowerCase()", _gen.condition_to_js(_parser.parse_expression_full('lower(http.request.full_uri) eq "https://x.com/a"'), "cff"), expect_substr=".toLowerCase() ===")

# #10 quoted numeric length coerces to a number (=== not against a string).
check("X-#10 len(host) eq \"5\" coerces to number", _gen.condition_to_js(_parser.parse_expression_full('len(http.host) eq "5"'), "cff"), expect_substr=".length === 5", forbid_substr="=== '5'")

# #8 host in $namedlist is not pinnable -> global (processor rejects it), NOT a
# wrong include; and the standalone rule is caught non_convertible.
# host in $namedlist can't be pinned to a host set -> applies everywhere (not a
# bogus single-host include); the processor still rejects the named list as
# non_convertible separately.
check("X-#8 host in $list applies to any host (a)", str(_applies('http.host in $hostlist', "a.com")), expect_substr="True")
check("X-#8 host in $list applies to any host (b)", str(_applies('http.host in $hostlist', "b.com")), expect_substr="True")

# #9 validate-js unused-handle detection: stripping the whole declaration.
import re as _re
_no_decl = _re.sub(r"const\s+kvsHandle\s*=\s*cf\.kvs\([^)]*\)\s*;?", "", "const kvsHandle = cf.kvs();\nreturn request;\n")
check("X-#9 declared-but-unused handle detected (uses=False)", str("kvsHandle" in _no_decl), expect_substr="False")

# ── HOST-FILTER PROPERTY TEST: applies() == brute-force truth over host trees ─
# Enumerate host-condition trees (leaves: host eq/ne over {a,b}, plus a hostless
# path leaf), and for each candidate host verify rule_applies_to_domain matches
# the expression's actual boolean truth for SOME request to that host. This is
# the mechanical proof the include/exclude algebra composes soundly — it is what
# would have caught findings #1/#4/#5 (and did catch a fold-seed bug in the fix).
print("== Y (round 12): custom-error live-host predicate, int-coercion crash, ip.src literal ==")
# Q4/F3: custom-error drops only ROUTING host conjuncts; a LIVE host predicate
# (contains/len) is a real scope that must block extraction -> non_convertible.
def _yerr(expr, status=None):
    ap = {} if status is None else {"status_code": status}
    return _proc.process_custom_error_rule(
        {"id": "e", "description": "d", "expression": expr, "action_parameters": ap},
        {}, "http_custom_errors")
check("Y-F3 code AND host eq (routing) -> convertible",
      _yerr('http.response.code eq 500 and http.host eq "x.com"', 404).get("type"),
      expect_substr="custom_error_response")
check("Y-F3 code AND host contains (LIVE) -> non_convertible",
      _yerr('http.response.code eq 500 and http.host contains "internal"', 404).get("type"),
      expect_substr="non_convertible")
check("Y-F3 code AND len(host) (LIVE) -> non_convertible",
      _yerr('http.response.code eq 500 and len(http.host) gt 5', 404).get("type"),
      expect_substr="non_convertible")
# Q5/F6: a malformed length literal must NOT crash codegen — fail closed.
for _bad in ("--5", "5x", "-"):
    try:
        _js = _gen.condition_to_js({"field": "host", "op": "eq", "value": _bad, "size_check": True}, "cff")
        check(f"Y-F6 len eq {_bad!r} no crash", "ok", expect_substr="ok")
    except Exception as _ex:
        check(f"Y-F6 len eq {_bad!r} no crash", f"CRASH {type(_ex).__name__}", forbid_substr="CRASH")
check("Y-F6 len eq '5' coerces to int", _gen.condition_to_js({"field": "host", "op": "eq", "value": "5", "size_check": True}, "cff"),
      expect_substr=".length === 5", forbid_substr="=== '5'")
# Q6/F8: ip.src only inside a string literal must not trip the raw-path guard.
check("Y-F8 ip.src in literal -> not flagged",
      str(_proc._uses_ip_src(None, 'http.request.uri contains "ip.src eq 1.2.3.4"')), expect_substr="False")
check("Y-F8 real ip.src not in {...} -> flagged",
      str(_proc._uses_ip_src(None, 'ip.src not in {1.2.3.4}')), expect_substr="True")

print("== Z (round 13): origin Host override — CFF updateRequestOrigin, not read-only headers.host ==")
# Host is READ-ONLY in a viewer-request CloudFront Function; assigning
# request.headers.host fails validation → HTTP 502. A host override must go
# through cf.updateRequestOrigin({hostHeader: ...}) instead. (The Lambda@Edge
# origin-request target CAN write request.headers.host — Host is writable there.)
_oo = {"type": "origin_override", "cf_source_rule": "r", "description": "d",
       "condition": None, "raw_expression": None,
       "params": {"origin_host": "backend.example.net", "host_header": "vhost.example.com"}}
_cff = " | ".join(_gen._generate_op_js(_oo, "cff"))
check("Z CFF host override via updateRequestOrigin hostHeader", _cff, expect_substr="hostHeader: 'vhost.example.com'")
check("Z CFF does NOT write read-only request.headers.host (502)", _cff, forbid_substr="request.headers.host")
# (round-16: viewer origin_override is CFF-only; the Lambda@Edge branch was
# removed — viewer events never escalate to L@E. So there's no L@E-target
# origin_override codegen to assert here anymore.)
# Host-header-only override (no origin domain change) must NOT emit an empty
# domainName — `domainName: ''` would blank the origin and break the request.
_hoo = {"type": "origin_override", "cf_source_rule": "r", "description": "d",
        "condition": None, "raw_expression": None,
        "params": {"host_header": "vhost.example.com"}}  # no origin_host
_hoo_cff = " | ".join(_gen._generate_op_js(_hoo, "cff"))
check("Z host-only override emits hostHeader", _hoo_cff, expect_substr="hostHeader: 'vhost.example.com'")
check("Z host-only override no empty domainName (CFF)", _hoo_cff, forbid_substr="domainName: ''")

print("== property test: host filter never more restrictive than truth (depth-2, wildcards + full_uri) ==")
# Brute-force oracle for the host filter. Each leaf has a GROUND-TRUTH evaluator
# over (hostname, path_is_x); a tree's truth is the boolean combination. The
# filter APPLIES to host h iff SOME request to h (either path value) satisfies
# the condition. INVARIANT: the filter must never be MORE restrictive than that
# truth — got==False while real==True is a SILENT DROP. This enumerates the
# exact corners the round-11 review found silent-drops in: wildcard host values,
# full_uri leaves (atomic host∧path), and NOT over composite nodes. (This oracle
# caught two of my own round-12 fixes' bugs that spot-checks missed.)
import itertools as _it
_ZHOSTS = ["a.example.com", "b.example.com", "c.example.com"]
_OLEAVES = [
    ({"field": "host", "op": "eq", "value": "a.example.com"}, lambda h, px: h == "a.example.com"),
    ({"field": "host", "op": "ne", "value": "a.example.com"}, lambda h, px: h != "a.example.com"),
    ({"field": "host", "op": "eq", "value": "b.example.com"}, lambda h, px: h == "b.example.com"),
    ({"field": "uri.path", "op": "eq", "value": "/x"},        lambda h, px: px),
    ({"field": "full_uri", "op": "wildcard", "value": "https://a.example.com/x",
      "host_pattern": "a.example.com", "path_pattern": "/x"},  lambda h, px: h == "a.example.com" and px),
]
def _obuild(depth):
    for node, truth in _OLEAVES:
        yield (dict(node), truth)
    if depth == 0:
        return
    subs = list(_obuild(depth - 1))
    for node, truth in subs:
        yield ({"logic": "not", "item": node}, (lambda t: (lambda h, px: not t(h, px)))(truth))
    for (n1, t1), (n2, t2) in _it.product(subs, subs):
        yield ({"logic": "and", "parts": [n1, n2]}, (lambda a, b: (lambda h, px: a(h, px) and b(h, px)))(t1, t2))
        yield ({"logic": "or", "parts": [n1, n2]}, (lambda a, b: (lambda h, px: a(h, px) or b(h, px)))(t1, t2))
_o_viol = 0
for _node, _truth in _obuild(2):
    _filter = _parser.extract_host_filter(_node, "")
    for _h in _ZHOSTS:
        _got = _pre.rule_applies_to_domain(_filter, _h, "example.com")
        _real = _truth(_h, True) or _truth(_h, False)
        if _real and not _got:
            _o_viol += 1  # silent drop
check("host filter never more restrictive than truth (0 silent-drops)", str(_o_viol), expect_substr="0")

# ── PROPERTY TEST: no fail-open across ALL small condition trees ─────────────
# Enumerate every condition tree (depth ≤ 2) over three leaves — two mappable
# (a, b) and one un-evaluable in the lambda target (u = continent). Render each
# to JS, evaluate it, and assert the core invariant: whenever the generated
# expression E is TRUE, the ORIGINAL condition is true under BOTH interpretations
# of the un-evaluable leaf (i.e. the guarded op never fires when it shouldn't —
# NO FAIL-OPEN). This proves the whole class rather than spot-checking examples;
# it is what mechanically catches the NOT-over-OR polarity bug (finding #1).
print("== property test: condition rendering is never fail-open ==")
_LEAVES = {
    "a": {"field": "uri.path", "op": "eq", "value": "/a"},
    "b": {"field": "host", "op": "eq", "value": "/b"},
    "u": {"field": "continent", "op": "eq", "value": "EU"},  # un-evaluable in lambda
}

def _trees(depth):
    for s in _LEAVES:
        yield ("leaf", s)
    if depth == 0:
        return
    subs = list(_trees(depth - 1))
    for sub in subs:
        yield ("not", sub)
    for x in subs:
        for y in subs:
            yield ("and", x, y)
            yield ("or", x, y)

def _to_cond(t):
    if t[0] == "leaf":
        return dict(_LEAVES[t[1]])
    if t[0] == "not":
        return {"logic": "not", "item": _to_cond(t[1])}
    return {"logic": t[0], "parts": [_to_cond(t[1]), _to_cond(t[2])]}

def _sym(t, va, vb, vu):
    if t[0] == "leaf":
        return {"a": va, "b": vb, "u": vu}[t[1]]
    if t[0] == "not":
        return not _sym(t[1], va, vb, vu)
    l, r = _sym(t[1], va, vb, vu), _sym(t[2], va, vb, vu)
    return (l and r) if t[0] == "and" else (l or r)

def _js_fires(E, va, vb):
    if E is None:
        return True
    if E == "false":
        return False
    py = (E.replace("request.uri === '/a'", "va")
           .replace("request.headers.host[0].value === '/b'", "vb")
           .replace("!", "not ").replace("&&", " and ").replace("||", " or ")
           .replace("=== ", "== "))
    return bool(eval(py, {}, {"va": va, "vb": vb}))

_viol = 0
for _t in _trees(2):
    _E = _gen.condition_to_js(_to_cond(_t), "lambda")
    for _va in (False, True):
        for _vb in (False, True):
            if _js_fires(_E, _va, _vb) and not (
                    _sym(_t, _va, _vb, True) and _sym(_t, _va, _vb, False)):
                _viol += 1
check("no fail-open over all depth-2 condition trees", str(_viol), expect_substr="0")

print("== ZZ (round 14): viewer CFF-only (no L@E escalation), size guidance, quota soft/hard ==")
# origin_override renders as a CFF cf.updateRequestOrigin — NEVER escalated to
# Lambda@Edge for viewer events (latency/cost). The generator no longer has an
# escalation path or a generate_lambda_origin_request_js function.
_oo = {"type": "origin_override", "cf_source_rule": "r", "description": "d",
       "condition": None, "raw_expression": None,
       "params": {"origin_host": "backend.net", "host_header": "vhost.example.com"}}
check("ZZ origin_override is CFF updateRequestOrigin", " | ".join(_gen._generate_op_js(_oo, "cff")),
      expect_substr="cf.updateRequestOrigin")
check("ZZ no viewer→L@E escalation function remains",
      str(hasattr(_gen, "generate_lambda_origin_request_js")), expect_substr="False")
check("ZZ no dead process_domain remains",
      str(hasattr(_gen, "process_domain")), expect_substr="False")
# SIZE guidance: CONTEXT states the HARD limit; GUIDANCE states the
# no-L@E-for-viewer stance (split into two emit_result fields).
check("ZZ size context says HARD limit", _gen._SIZE_EXCEEDED_CONTEXT, expect_substr="HARD")
check("ZZ size guidance says do NOT use Lambda@Edge for viewer",
      _gen._SIZE_EXCEEDED_GUIDANCE, expect_substr="Lambda@Edge")
# Quota combined-name-length helper (finalize) — the HARD 1024 policy limit.
check("ZZ _combined_name_len sums string names",  # 2+3 + 11 = 16
      str(_fin._combined_name_len(["ab", "cde"], ["Header-Name"])), expect_substr="16")
check("ZZ _combined_name_len reads header dicts",
      str(_fin._combined_name_len([{"name": "X-Foo"}])), expect_substr="5")

print("== S3 (round 15): S3+OAC gets no Host-forwarding ORP; redundant S3 host-override dropped ==")
_scaf = _load("cdn_scaffold", "cdn-generate-tf-scaffold.py")
# S3+OAC behavior: NO ORP (forwarding Host breaks SigV4 → 403). Even with geo
# headers, S3 wins.
_s3b = {"viewer_request_ops": [], "origin": {"domain": "b.s3.us-east-1.amazonaws.com", "s3_origin": True}}
check("S3 behavior gets NO ORP (None)", str(_scaf._orp_reference(_s3b, [], "d")), expect_substr="None")
check("S3 behavior gets NO ORP even with geo headers",
      str(_scaf._orp_reference(_s3b, ["CloudFront-Viewer-Country"], "d")), expect_substr="None")
# server origin still forwards (AllViewer).
_srv = {"viewer_request_ops": [], "origin": {"domain": "o.example.net", "s3_origin": False}}
check("server behavior still gets AllViewer ORP",
      str(_scaf._orp_reference(_srv, [], "d")), expect_substr="216adef6")
# _is_s3_host recognizes REST + website endpoints, rejects non-S3.
check("_is_s3_host REST endpoint", str(_pre._is_s3_host("bucket.s3.amazonaws.com")), expect_substr="True")
check("_is_s3_host website endpoint", str(_pre._is_s3_host("bucket.s3-website-us-east-1.amazonaws.com")), expect_substr="True")
check("_is_s3_host rejects non-S3", str(_pre._is_s3_host("origin.example.net")), expect_substr="False")

# Redundant S3 host-override op is dropped at placement; a real cross-origin
# (non-S3) override is kept; a server-origin override is kept.
def _place_override(origin_type, params):
    dc = {"hostname": "x.example.com", "apex_domain": "example.com",
          "origin_type": origin_type, "origin_content": "bucket.s3.amazonaws.com"}
    ir = _pre.make_empty_ir(dc)
    _pre.find_or_create_behavior(ir, "*", dc, "bucket.s3.amazonaws.com")
    _pre._place_result(ir, {"type": "origin_override", "cf_source_rule": "r",
                            "description": "d", "condition": None, "raw_expression": None,
                            "params": params}, dc, "bucket.s3.amazonaws.com", None, "true")
    return sum(1 for b in ir["cache_behaviors"] for op in b.get("viewer_request_ops", [])
               if op["type"] == "origin_override")
check("S3 redundant host-override dropped", str(_place_override("s3", {"host_header": "bucket.s3.amazonaws.com"})), expect_substr="0")
check("S3 override to a DIFFERENT non-S3 origin kept", str(_place_override("s3", {"origin_host": "api.backend.net", "host_header": "api.backend.net"})), expect_substr="1")
check("server origin override kept", str(_place_override("server", {"host_header": "vhost.example.com"})), expect_substr="1")

print("== R16 (round 16): origin_override port/protocol, conditional host-override ORP, no-op drop ==")
def _oo_js(params, cond=None):
    op = {"type": "origin_override", "cf_source_rule": "r", "description": "d",
          "condition": cond, "raw_expression": None, "params": params}
    return " | ".join(_gen._generate_op_js(op, "cff"))
# #6: protocol inferred from port (not hardcoded https). HTTP ports → http.
check("R16-#6 port 8080 -> protocol http", _oo_js({"origin_host": "o.net", "origin_port": 8080}), expect_substr="protocol: 'http'")
check("R16-#6 port 80 -> protocol http", _oo_js({"origin_host": "o.net", "origin_port": 80}), expect_substr="protocol: 'http'")
check("R16-#6 port 443 -> protocol https", _oo_js({"origin_host": "o.net", "origin_port": 443}), expect_substr="protocol: 'https'")
check("R16-#6 port 8443 -> protocol https", _oo_js({"origin_host": "o.net", "origin_port": 8443}), expect_substr="protocol: 'https'")
# #1/#2/#4: no Lambda@Edge / request.origin.custom path remains in origin_override.
check("R16 origin_override has no L@E request.origin.custom",
      _oo_js({"origin_host": "o.net", "origin_port": 8080}), forbid_substr="request.origin.custom")
check("R16 host-only override emits hostHeader only (inherits rest)",
      _oo_js({"host_header": "v.com"}), expect_substr="hostHeader: 'v.com'", forbid_substr="customOriginConfig")
# #3: ALL host overrides -> AllViewer. updateRequestOrigin({hostHeader}) wins over
# the ORP-forwarded viewer Host (proven live on a real distribution), so both
# conditional and unconditional overrides keep AllViewer — the ExceptHost branch
# is gone (it stranded non-matching requests and bought nothing for matching ones).
_AV = _scaf._MANAGED_ORP_ALL_VIEWER
_EH_ID = "b689b0a8-53d0-40ab-baf2-68738e2966ac"  # old AllViewerExceptHostHeader — must NEVER be emitted now
_srvb = {"origin": {"domain": "o.net", "s3_origin": False}}
def _orp(ops): return _scaf._orp_reference({**_srvb, "viewer_request_ops": ops}, [], "d")
check("R16-#3 conditional host override -> AllViewer",
      _orp([{"type": "origin_override", "condition": {"field": "country", "op": "eq", "value": "CN"}, "params": {"host_header": "v.com"}}]),
      expect_substr=_AV, forbid_substr=_EH_ID)
check("R16-#3 unconditional host override -> AllViewer (not ExceptHost)",
      _orp([{"type": "origin_override", "condition": None, "params": {"host_header": "v.com"}}]),
      expect_substr=_AV, forbid_substr=_EH_ID)
check("R16-#3 host==origin (no real replace) -> AllViewer",
      _orp([{"type": "origin_override", "condition": None, "params": {"host_header": "o.net", "origin_host": "o.net"}}]),
      expect_substr=_AV, forbid_substr=_EH_ID)
assert not hasattr(_scaf, "_MANAGED_ORP_ALL_VIEWER_EXCEPT_HOST"), "ExceptHost constant should be removed"
assert not hasattr(_scaf, "_behavior_replaces_host_unconditionally"), "host-replace helper should be removed"
# #7: no-op origin_override (empty params) dropped at placement.
check("R16-#7 no-op origin_override dropped", str(_place_override("server", {})), expect_substr="0")

print("== CACHE BYPASS: cookie parsing, cache-buster codegen, CachingDisabled, header whitelist ==")
_BUSTER = _parser.CACHE_BYPASS_HEADER

# -- parse: the two supported cookie syntaxes + the unsupported value form --
def _pc(expr):
    c, r = _parser.parse_expression(expr)
    return c, r
c1, r1 = _pc('http.cookie contains "wordpress_logged_in"')
check("bypass parse: http.cookie -> cookie field", str(c1), expect_substr="'field': 'cookie'")
c2, r2 = _pc('http.request.cookies["wp-settings"]')
check("bypass parse: cookies[x] -> cookie_named existence", str(c2),
      expect_substr="'field': 'cookie_named'")
check("bypass parse: cookies[x] carries cookie_name", str(c2), expect_substr="'cookie_name': 'wp-settings'")
c3, r3 = _pc('any(http.request.cookies["app"][*] == "test")')
# value-comparison form is unsupported -> falls to raw (non-convertible), never silently parsed
check("bypass parse: any([*]==v) value form -> raw (not structured)",
      f"cond={c3} raw={'yes' if r3 else 'no'}", expect_substr="cond=None raw=yes")

# -- JS: cookie condition rendering --
def _cjs(expr):
    c, _ = _parser.parse_expression(expr)
    return _gen.condition_to_js(c, "cff")
check("bypass JS: http.cookie contains -> _cookieStr rebuild + includes (NOT request.headers.cookie)",
      _cjs('http.cookie contains "wp-"'),
      expect_substr="_cookieStr(request.cookies).includes('wp-')", forbid_substr="request.headers.cookie")
check("bypass JS: http.cookie contains matches across name=value boundary (whole-string)",
      _cjs('http.cookie contains "foo=bar"'),
      expect_substr="_cookieStr(request.cookies).includes('foo=bar')")
check("bypass JS: cookies[x] -> !== undefined",
      _cjs('http.request.cookies["wp-settings"]'),
      expect_substr="request.cookies['wp-settings'] !== undefined")
check("bypass JS: not cookies[x] -> === undefined",
      _cjs('not http.request.cookies["wp-settings"]'),
      expect_substr="request.cookies['wp-settings'] === undefined")

# -- codegen: the cache_bypass op = 4-segment cache-buster + mandatory else-delete --
def _bypass_js(expr):
    c, _ = _parser.parse_expression(expr)
    op = {"type": "cache_bypass", "cf_source_rule": "r", "description": "d",
          "condition": c, "raw_expression": None, "params": {}}
    return " | ".join(_gen._generate_op_js(op, "cff"))
_bj = _bypass_js('http.cookie contains "wordpress_logged_in"')
check("bypass codegen: injects the shared buster header", _bj, expect_substr=f"request.headers['{_BUSTER}']")
check("bypass codegen: 4 Math.random() segments (208-bit, concat not add/mul)",
      str(_bj.count("Math.random()")), expect_substr="4")
check("bypass codegen: segments joined by '-' (string concat)", _bj, expect_substr="+'-'+Math.random()")
check("bypass codegen: mandatory else-delete (anti cache-poisoning)",
      _bj, expect_substr=f"else {{ delete request.headers['{_BUSTER}']")

# -- placement: conditional -> cache_bypass op; unconditional -> CachingDisabled --
def _place_bypass(expr):
    dc = {"hostname": "shop.example.com", "apex_domain": "example.com",
          "origin_type": "custom", "origin_content": "o.net",
          "sanitized_name": "shop_example_com"}
    ir = _pre.make_empty_ir(dc)
    _pre.find_or_create_behavior(ir, "*", dc, "o.net")
    rule = {"id": "r", "description": "bypass", "expression": expr,
            "action_parameters": {"cache": False}}
    cond, raw = _parser.parse_expression(expr)
    result = _proc.process_cache_rule(rule, {}, "cache")
    cond2 = _pre._strip_host_condition(cond)
    _pre._strip_host_in_result(result)
    _pre._place_result(ir, result, dc, "o.net", cond2, expr)
    return ir
_irc = _place_bypass('http.cookie contains "wordpress_logged_in"')
_ops_c = [o["type"] for b in _irc["cache_behaviors"] for o in b["viewer_request_ops"]]
check("bypass placement: conditional -> cache_bypass op", str(_ops_c), expect_substr="cache_bypass")
check("bypass placement: conditional does NOT set caching_disabled",
      str(_irc["cache_behaviors"][0]["cache_policy"]["caching_disabled"]), expect_substr="False")
_iru = _place_bypass('true')
check("bypass placement: unconditional -> CachingDisabled, no op",
      f"cd={_iru['cache_behaviors'][0]['cache_policy']['caching_disabled']} "
      f"ops={[o['type'] for b in _iru['cache_behaviors'] for o in b['viewer_request_ops']]}",
      expect_substr="cd=True ops=[]")

# -- non-cookie bypass conditions: querystring, named header, named arg (the
#    "test bypass" use cases — ?test=true, an X-Bypass header — not just cookies) --
def _bypass_cond_js(expr):
    c, _ = _parser.parse_expression(expr)
    return _gen.condition_to_js(c, "cff") if c else "PARSE_FAILED"
check("bypass non-cookie: querystring substring (?test=true)",
      _bypass_cond_js('http.request.uri.query contains "test=true"'),
      expect_substr="_qs(request.querystring).includes('test=true')")
check("bypass non-cookie: named query arg value",
      _bypass_cond_js('http.request.uri.args["test"] eq "true"'),
      expect_substr="request.querystring['test'] !== undefined && request.querystring['test'].value === 'true'")
check("bypass non-cookie: named query arg existence",
      _bypass_cond_js('http.request.uri.args["debug"]'),
      expect_substr="request.querystring['debug'] !== undefined")
check("bypass non-cookie: named request header value (X-Bypass lowercased)",
      _bypass_cond_js('http.request.headers["X-Bypass"] eq "1"'),
      expect_substr="request.headers['x-bypass'] !== undefined && request.headers['x-bypass'].value === '1'")
check("bypass non-cookie: named request header existence",
      _bypass_cond_js('http.request.headers["x-debug"]'),
      expect_substr="request.headers['x-debug'] !== undefined")
check("bypass non-cookie: negated header existence -> === undefined",
      _bypass_cond_js('not http.request.headers["x-skip"]'),
      expect_substr="request.headers['x-skip'] === undefined")
# these must PLACE as a cache_bypass op, not non_convertible, not CachingDisabled
for _e, _lbl in [('http.request.headers["x-bypass"] eq "1"', "header value"),
                 ('http.request.uri.args["test"] eq "true"', "arg value"),
                 ('http.request.uri.query contains "test=true"', "query substring")]:
    _ir = _place_bypass(_e)
    _ops = [o["type"] for b in _ir["cache_behaviors"] for o in b["viewer_request_ops"]]
    _nc = sum(len(b["non_convertible"]) for b in _ir["cache_behaviors"])
    check(f"bypass placement: {_lbl} -> cache_bypass op (not non_conv)",
          f"ops={_ops} nc={_nc}", expect_substr="ops=['cache_bypass'] nc=0")

# -- the any(...[*]==v) form must NOT silently become a whole-behavior
#    CachingDisabled (that over-bypasses the entire distribution) — it's
#    non_convertible until value-form support lands. --
_ir_any = _place_bypass('any(http.request.uri.args["test"][*] == "true")')
_any_cd = any(b["cache_policy"].get("caching_disabled") for b in _ir_any["cache_behaviors"])
_any_nc = sum(len(b["non_convertible"]) for b in _ir_any["cache_behaviors"])
check("bypass any([*]==v): non_convertible, NOT silent CachingDisabled",
      f"caching_disabled={_any_cd} non_convertible={_any_nc}",
      expect_substr="caching_disabled=False non_convertible=1")

# -- whitelist single-source-of-truth: the buster header the codegen writes is the
#    same one the cache policy whitelists (can't drift — the ORP split-brain lesson) --
check("bypass whitelist: codegen header == parser constant", _BUSTER,
      expect_substr="x-cf-cache-bypass")
check("bypass whitelist: same constant appears in the emitted buster JS",
      str(_BUSTER in _bj), expect_substr="True")
# run the post-placement whitelist pass via process_domain and confirm every
# behavior's cache policy carries the header
def _domain_bypass_whitelist():
    dc = {"hostname": "shop.example.com", "apex_domain": "example.com",
          "origin_type": "custom", "origin_content": "o.net",
          "sanitized_name": "shop_example_com"}
    rules = {"cache": [{"id": "r", "description": "wp login bypass",
                        "expression": 'http.cookie contains "wordpress_logged_in"',
                        "action_parameters": {"cache": False}, "enabled": True}]}
    ir = _pre.process_domain("shop.example.com", dc, rules, {}, {}, {})
    return all(_BUSTER in b["cache_policy"]["cache_key"]["headers"]
               for b in ir["cache_behaviors"])
check("bypass whitelist: header added to ALL behaviors (shared CFF)",
      str(_domain_bypass_whitelist()), expect_substr="True")

print("== SCOPE (#123): op scope classification + condition_has_path_field ==")
# condition_has_path_field: distinguishes zone-wide (no path field) from
# path-scoped-but-unconvertible (has a path field).
check("scope: cookie-only cond has NO path field",
      str(_parser.condition_has_path_field(_parser.parse_expression('http.cookie contains "x"')[0])),
      expect_substr="False")
check("scope: regex path cond HAS a path field",
      str(_parser.condition_has_path_field(_parser.parse_expression('http.request.uri.path matches "^/a.*b$"')[0])),
      expect_substr="True")
check("scope: full_uri cond HAS a path field",
      str(_parser.condition_has_path_field(_parser.parse_expression('http.request.full_uri wildcard "https://h/x/*"')[0])),
      expect_substr="True")
check("scope: header+path AND cond HAS a path field (descends parts)",
      str(_parser.condition_has_path_field(_parser.parse_expression('http.request.headers["x"] eq "1" and http.request.uri.path matches "^/z.*$"')[0])),
      expect_substr="True")
# _op_scope on placed ops: no-path→all, unconvertible-path→default_only, pattern→behavior
def _scope_of(expr):
    dc = {"hostname": "shop.example.com", "apex_domain": "example.com",
          "origin_type": "custom", "origin_content": "o.net",
          "sanitized_name": "shop_example_com"}
    ir = _pre.make_empty_ir(dc); _pre.find_or_create_behavior(ir, "*", dc, "o.net")
    rule = {"id": "r", "description": "b", "expression": expr, "action_parameters": {"cache": False}}
    cond, raw = _parser.parse_expression(expr)
    result = _proc.process_cache_rule(rule, {}, "cache")
    cond2 = _pre._strip_host_condition(cond); _pre._strip_host_in_result(result)
    _pre._place_result(ir, result, dc, "o.net", cond2, expr)
    for b in ir["cache_behaviors"]:
        for o in b["viewer_request_ops"]:
            return o.get("scope"), b["path_pattern"]
    return None, None
check("scope: cookie bypass (no path) -> scope=all on *",
      str(_scope_of('http.cookie contains "wp"')), expect_substr="('all', '*')")
check("scope: path-pattern bypass -> scope=behavior on the ordered behavior",
      str(_scope_of('http.request.uri.path eq "/checkout"')), expect_substr="('behavior', '/checkout')")
check("scope: unconvertible-path bypass -> scope=default_only on *",
      str(_scope_of('http.request.uri.path matches "^/a.*b$" and http.cookie contains "wp"')),
      expect_substr="('default_only', '*')")
# _behavior_needs_cff: the CFF-attachment automation
def _needs_map(behs):
    ir = {"metadata": {}, "cache_behaviors": behs}
    return {b["path_pattern"]: _scaf._behavior_needs_cff(ir, b, "viewer_request_ops") for b in behs}
def _b(pp, ops): return {"path_pattern": pp, "viewer_request_ops": ops, "viewer_response_ops": []}
_zonewide = [{"type": "set_request_header", "scope": "all"}]
_pathop = [{"type": "rewrite", "scope": "behavior"}]
_defonly = [{"type": "cache_bypass", "scope": "default_only"}]
check("needs_cff: zone-wide default op -> ALL behaviors attach",
      str(_needs_map([_b("*", _zonewide), _b("/files/*", [])])),
      expect_substr="{'*': True, '/files/*': True}")
check("needs_cff: default clean, only ordered op -> default DROPS, ordered attaches",
      str(_needs_map([_b("*", []), _b("/api/*", _pathop)])),
      expect_substr="{'*': False, '/api/*': True}")
check("needs_cff: default_only op -> default attaches, TTL-only ordered DROPS",
      str(_needs_map([_b("*", _defonly), _b("/files/*", [])])),
      expect_substr="{'*': True, '/files/*': False}")

print()
if FAILURES:
    print(f"FAILED: {len(FAILURES)} check(s)")
    sys.exit(1)
print("All checks passed.")
