#!/usr/bin/env python3
"""Split from test_nc_provenance.py (round-2 test-split; behavior-preserving).
Shared setup + helpers live in test_nc_common."""
from test_nc_common import *  # noqa: F401,F403

print("== FINDING (spine) 32: malformed expression NC / shared CSP-quota validator ==")


# The status a SUCCESSFULLY-converted header conversion carries, BY PHASE (round-27 finding 5):
# a request-header set is a viewer-REQUEST CFF (always runs → EXACT); a response-header set is a
# viewer-RESPONSE CFF, which does NOT run on CloudFront-generated error responses → LOSSY_WITH_
# WARNING. (A header that can't accept that gap is NC'd upstream; a native-RHP security header is
# EXACT, tested separately.) Use this wherever a test converts the SAME expr on both phases.
def _hdr_ok(phase):
    return "LOSSY_WITH_WARNING" if phase == "response" else "EXACT"


# ── finding 1: a MALFORMED `expression` field must NC, not become a value-less EXACT ──
# expression="" / False / int is not a real dynamic value; it must reach NC on BOTH the
# response and request processors (shared root cause), not slip past `expression is not None`.
for _bad in ("", False, 123):
    _resp = _proc.process_response_header_transform(
        _hdr_rule("X-Custom", {"operation": "set", "expression": _bad}), {}, "response")
    check(f"#32 response header expression={_bad!r} -> NON_CONVERTIBLE",
          _status_of(_resp) == "NON_CONVERTIBLE", f"got {_status_of(_resp)}")
    _req = _proc.process_request_header_transform(
        _hdr_rule("X-Custom", {"operation": "set", "expression": _bad}), {}, "cff")
    check(f"#32 request header expression={_bad!r} -> NON_CONVERTIBLE",
          _status_of(_req) == "NON_CONVERTIBLE", f"got {_status_of(_req)}")
# a valid non-empty expression still converts (control — not over-rejecting). A response-header
# viewer-CFF converts as LOSSY (error-response gap, round-27 finding 5), not EXACT.
_ok = _proc.process_response_header_transform(
    _hdr_rule("X-Custom", {"operation": "set", "expression": "http.host"}), {}, "response")
check("#32 response header with a valid expression still converts (LOSSY, not over-rejected)",
      _status_of(_ok) == "LOSSY_WITH_WARNING", f"got {_status_of(_ok)}")
# value + expression on the same header is contradictory -> NC (both processors).
_both = _proc.process_response_header_transform(
    _hdr_rule("X-Custom", {"operation": "set", "value": "v", "expression": "http.host"}), {}, "response")
check("#32 value+expression together -> NON_CONVERTIBLE (contradictory)",
      _status_of(_both) == "NON_CONVERTIBLE", f"got {_status_of(_both)}")
# regression: a malformed expression must NOT override a legit value into an empty EXACT.
_shadow = _proc.process_response_header_transform(
    _hdr_rule("X-Custom", {"operation": "set", "value": "legit", "expression": ""}), {}, "response")
check("#32 empty expression alongside a value -> NC (not a value-less EXACT)",
      _status_of(_shadow) == "NON_CONVERTIBLE", f"got {_status_of(_shadow)}")

# ── finding 3: ONE shared CSP-quota validator; reject zero/negative/over-ceiling, NO clamp ──
check("#32 validate_csp_quota accepts default 1783", _cap.validate_csp_quota(1783) == 1783)
check("#32 validate_csp_quota accepts the 8192 ceiling", _cap.validate_csp_quota(8192) == 8192)
check("#32 validate_csp_quota accepts a numeric string ('4000')", _cap.validate_csp_quota("4000") == 4000)
for _bad in (0, -5, 8193, "abc", None, 1.5):
    _raised = False
    try:
        _cap.validate_csp_quota(_bad)
    except ValueError:
        _raised = True
    except TypeError:
        _raised = False   # must be a clean ValueError, not a raw TypeError
    check(f"#32 validate_csp_quota({_bad!r}) -> ValueError (rejected, not clamped)", _raised)
# NO CLAMP: 8193 must RAISE, never be silently reduced to 8192.
_clamped = None
try:
    _clamped = _cap.validate_csp_quota(8193)
except ValueError:
    _clamped = "REJECTED"
check("#32 validate_csp_quota(8193) is REJECTED, not clamped to 8192", _clamped == "REJECTED")

print("== FINDING (spine) 33: unparseable expression NC / non-string literal value NC ==")

# ── finding 1: a NON-EMPTY but UNPARSEABLE expression must NC, not become EXACT ──
# The round-14 gate only required a non-empty string; a value like " ", "(", "foo(" passed it
# but does NOT parse — the generator degrades it to an empty value + leak marker, so the
# LEDGER was wrongly EXACT. The parse gate now returns a reason on parse failure (not None).
for _e in (" ", "(", "foo(", "concat(", "))"):
    _r = _proc.process_response_header_transform(
        _hdr_rule("X-Custom", {"operation": "set", "expression": _e}), {}, "response")
    check(f"#33 response header unparseable expression {_e!r} -> NON_CONVERTIBLE",
          _status_of(_r) == "NON_CONVERTIBLE", f"got {_status_of(_r)}")
    _q = _proc.process_request_header_transform(
        _hdr_rule("X-Custom", {"operation": "set", "expression": _e}), {}, "cff")
    check(f"#33 request header unparseable expression {_e!r} -> NON_CONVERTIBLE",
          _status_of(_q) == "NON_CONVERTIBLE", f"got {_status_of(_q)}")
# control: a parseable field expression still converts (guards against over-rejection). Response
# viewer-CFF → LOSSY (round-27 finding 5), not EXACT.
check("#33 parseable expression (http.host) still converts (LOSSY on response)",
      _status_of(_proc.process_response_header_transform(
          _hdr_rule("X-Custom", {"operation": "set", "expression": "http.host"}), {}, "response"))
      == "LOSSY_WITH_WARNING")
# the tree-native field-source core: a real mappable field -> None (no false NC). Parse-failure ->
# NC is covered end-to-end by the processor cases above; the old string wrapper was
# removed in the round-2 bucket-C cleanup.
check("#33 find_unmappable_fields(http.host) is None (a real, mappable field)",
      _cep.find_unmappable_fields(_cep.parse_dynamic_expression("http.host"), "cff") is None)

# ── finding 2: a static literal `value` must be a STRING (empty ok); non-string -> NC ──
for _v in (123, True, ["a"], 1.5, {"x": 1}):
    _r = _proc.process_response_header_transform(
        _hdr_rule("X-Custom", {"operation": "set", "value": _v}), {}, "response")
    check(f"#33 response non-string value {_v!r} -> NON_CONVERTIBLE",
          _status_of(_r) == "NON_CONVERTIBLE", f"got {_status_of(_r)}")
    _q = _proc.process_request_header_transform(
        _hdr_rule("X-Custom", {"operation": "set", "value": _v}), {}, "cff")
    check(f"#33 request non-string value {_v!r} -> NON_CONVERTIBLE",
          _status_of(_q) == "NON_CONVERTIBLE", f"got {_status_of(_q)}")
# CORS with a non-string value is NC too (not LOSSY — the value can't be emitted).
check("#33 CORS non-string value (123) -> NON_CONVERTIBLE",
      _status_of(_proc.process_response_header_transform(
          _hdr_rule("Access-Control-Allow-Origin", {"operation": "set", "value": 123}), {}, "response"))
      == "NON_CONVERTIBLE")
# controls: empty string and a normal string are still accepted (string is the ONLY gate). A
# response-header set converts as LOSSY (viewer-response gap), not EXACT.
check("#33 empty-string value still accepted (LOSSY, not over-rejected)",
      _status_of(_proc.process_response_header_transform(
          _hdr_rule("X-Custom", {"operation": "set", "value": ""}), {}, "response")) == "LOSSY_WITH_WARNING")
check("#33 normal string value still converts (LOSSY on response)",
      _status_of(_proc.process_response_header_transform(
          _hdr_rule("X-Custom", {"operation": "set", "value": "ok"}), {}, "response")) == "LOSSY_WITH_WARNING")

print("== FINDING (spine) 34: shared header-input validator / set missing value+expression ==")

# ── finding 2: a `set` providing NEITHER value NOR expression -> NC (was value-less EXACT) ──
# Cover all FOUR header kinds (plain-custom, security, CORS) on BOTH processors — the bug was
# a `set` with no field became EXACT and the generator emitted an empty header.
_MISSING = {"operation": "set"}   # no value, no expression
for _kind, _name in [("plain-custom", "X-Custom"), ("security", "Strict-Transport-Security"),
                     ("CORS", "Access-Control-Allow-Origin"), ("security-xfo", "X-Frame-Options")]:
    _r = _proc.process_response_header_transform(_hdr_rule(_name, dict(_MISSING)), {}, "response")
    check(f"#34 response {_kind} `set` missing value+expression -> NON_CONVERTIBLE",
          _status_of(_r) == "NON_CONVERTIBLE", f"got {_status_of(_r)}")
_rq = _proc.process_request_header_transform(_hdr_rule("X-Custom", dict(_MISSING)), {}, "cff")
check("#34 request `set` missing value+expression -> NON_CONVERTIBLE",
      _status_of(_rq) == "NON_CONVERTIBLE", f"got {_status_of(_rq)}")
# controls that must still convert: explicit empty value, a remove (no fields needed). Both go
# through the response viewer-CFF → LOSSY (round-27 finding 5), converted (NOT NC).
check("#34 explicit `value: \"\"` is a valid empty-header set (LOSSY, not NC)",
      _status_of(_proc.process_response_header_transform(
          _hdr_rule("X-Custom", {"operation": "set", "value": ""}), {}, "response")) == "LOSSY_WITH_WARNING")
check("#34 `remove` needs neither value nor expression (LOSSY on response, converted)",
      _status_of(_proc.process_response_header_transform(
          _hdr_rule("X-Custom", {"operation": "remove"}), {}, "response")) == "LOSSY_WITH_WARNING")

# ── the shared validator itself (both processors call it — one source of truth) ──
_ALLOWED = ("set", "add", "remove")


def _vhi(cfg, phase="response", allowed=_ALLOWED):
    return _proc.validate_header_input(cfg, phase, allowed)


check("#34 validator: set missing both -> reason", isinstance(_vhi({"operation": "set"}, "response"), str))
check("#34 validator: set value+expression both -> reason",
      isinstance(_vhi({"operation": "set", "value": "v", "expression": "http.host"}, "response"), str))
check("#34 validator: non-string value -> reason",
      isinstance(_vhi({"operation": "set", "value": 123}, "response"), str))
check("#34 validator: empty expression -> reason",
      isinstance(_vhi({"operation": "set", "expression": ""}, "response"), str))
# PARSE ONCE (round-27 finding 4): validate_header_input is now STRUCTURAL-only — it no longer
# parses, so a syntactically-broken-but-nonempty expression passes IT (None) and the parse-failure
# NC moves to the single lowering step. Prove the check didn't vanish, just relocated: the
# structural validator accepts `foo(`, and the FULL processor still marks it NON_CONVERTIBLE.
check("#34 validator: unparseable expression -> None (structural pass; faithfulness = lowering)",
      _vhi({"operation": "set", "expression": "foo("}, "response") is None)
check("#34 processor: unparseable expression -> NON_CONVERTIBLE end-to-end (caught at lowering)",
      _status_of(_proc.process_response_header_transform(
          _hdr_rule("X-Test", {"operation": "set", "expression": "foo("}), {}, "response"))
      == "NON_CONVERTIBLE")
check("#34 validator: valid string value -> None (ok)",
      _vhi({"operation": "set", "value": "x"}, "response") is None)
check("#34 validator: explicit empty-string value -> None (ok)",
      _vhi({"operation": "set", "value": ""}, "response") is None)
check("#34 validator: valid parseable expression -> None (ok)",
      _vhi({"operation": "set", "expression": "http.host"}, "response") is None)
check("#34 validator: remove -> None (needs no field)",
      _vhi({"operation": "remove"}, "response") is None)
# default operation is `set` (a header_config with no `operation` still requires a field).
check("#34 validator: default-operation (no `operation` key) with no field -> reason (treated as set)",
      isinstance(_vhi({}, "response"), str))

print("== FINDING (spine) 35: full operation contract (remove-with-value / unknown op) ==")
_DC35 = {"hostname": "shop.example.com", "apex_domain": "example.com", "origin_type": "custom",
         "origin_content": "o.net", "sanitized_name": "shop_example_com"}


def _pd35(headers):
    return _pre.process_domain("shop.example.com", _DC35, {"response_header": [
        {"id": "h", "enabled": True, "expression": "true", "action": "rewrite",
         "action_parameters": {"headers": headers}}]}, {}, {}, {})


# ── finding 1: `remove` must forbid value/expression (else ignored leaves ~ EXACT) ──
for _extra in ({"value": "x"}, {"expression": "http.host"}, {"value": "x", "expression": "http.host"}):
    _cfg = dict({"operation": "remove"}, **_extra)
    _rr = _proc.process_response_header_transform(_hdr_rule("X-Custom", _cfg), {}, "response")
    check(f"#35 response remove + {sorted(_extra)} -> NON_CONVERTIBLE",
          _status_of(_rr) == "NON_CONVERTIBLE", f"got {_status_of(_rr)}")
    _rq = _proc.process_request_header_transform(_hdr_rule("X-Custom", _cfg), {}, "cff")
    check(f"#35 request remove + {sorted(_extra)} -> NON_CONVERTIBLE",
          _status_of(_rq) == "NON_CONVERTIBLE", f"got {_status_of(_rq)}")
# control: a clean remove still CONVERTS on both — request EXACT, response LOSSY (the viewer-
# response remove also doesn't run on error responses, round-27 finding 5).
check("#35 clean remove still converts (response LOSSY)",
      _status_of(_proc.process_response_header_transform(
          _hdr_rule("X-Custom", {"operation": "remove"}), {}, "response")) == "LOSSY_WITH_WARNING")
check("#35 clean remove still EXACT (request)",
      _status_of(_proc.process_request_header_transform(
          _hdr_rule("X-Custom", {"operation": "remove"}), {}, "cff")) == "EXACT")

# ── finding 1: unknown / None / non-string operation -> NC (no orphan {op}_header op) ──
for _op in ("bogus", None, 123, ""):
    _cfg = {"operation": _op, "value": "x"}
    _rr = _proc.process_response_header_transform(_hdr_rule("X-Custom", _cfg), {}, "response")
    check(f"#35 response operation={_op!r} -> NON_CONVERTIBLE (not an orphan op)",
          _status_of(_rr) == "NON_CONVERTIBLE", f"got {_status_of(_rr)}")
    _rq = _proc.process_request_header_transform(_hdr_rule("X-Custom", _cfg), {}, "cff")
    check(f"#35 request operation={_op!r} -> NON_CONVERTIBLE (not an orphan op)",
          _status_of(_rq) == "NON_CONVERTIBLE", f"got {_status_of(_rq)}")
# the produced op is genuinely a non_convertible RECORD, never a `{op}_response_header` type
# (an orphan a wired-op channel would never claim).
_orphan = _proc.process_response_header_transform(
    _hdr_rule("X-Custom", {"operation": "bogus", "value": "x"}), {}, "response")
check("#35 unknown-op result carries no `bogus_response_header` viewer op",
      all(o.get("type") != "bogus_response_header" for o in _orphan))

# ── validator: operation allow-list is per-phase (round-17) ──
check("#35 validator: unknown op -> reason", isinstance(_vhi({"operation": "bogus", "value": "x"}), str))
check("#35 validator: None op -> reason", isinstance(_vhi({"operation": None, "value": "x"}), str))
check("#35 validator: remove+value -> reason", isinstance(_vhi({"operation": "remove", "value": "x"}), str))
check("#35 validator: a phase that omits `add` from its allow-list -> reason",
      isinstance(_vhi({"operation": "add", "value": "x"}, "response", ("set", "remove")), str))
check("#35 validator: a phase that allows `add` (add in allow-list) -> None",
      _vhi({"operation": "add", "value": "x"}, "response", ("set", "add", "remove")) is None)

# ── no ignored-EXACT leaf / orphan inventory: a real process_domain run must be self-consistent ──
# remove-with-value: the whole header is NC, so NO claim may be EXACT for it, and every claim's
# source key is a real inventory leaf (the coordinator FATALs on an orphan — this asserts no FATAL
# AND no EXACT claim survives for the ignored config).
_ir35 = _pd35({"X-Custom": {"operation": "remove", "value": "ignored"}})
check("#35 process_domain(remove+value) returns an IR (no FATAL / orphan inventory)",
      isinstance(_ir35, dict) and "_claims" in _ir35)
_nc35 = [c for c in _ir35["_claims"] if c["status"] == "NON_CONVERTIBLE"
         and any(k[1] == "h" for k in c["source_keys"])]
_ex35 = [c for c in _ir35["_claims"] if c["status"] == "EXACT"
         and any(k[1] == "h" for k in c["source_keys"])]
check("#35 remove+value: the header unit is NON_CONVERTIBLE, with NO surviving EXACT claim",
      len(_nc35) == 1 and not _ex35, f"nc={len(_nc35)} exact={len(_ex35)}")
# unknown op via process_domain is also self-consistent (no orphan viewer op left unclaimed).
_ir35b = _pd35({"X-Custom": {"operation": "bogus", "value": "x"}})
check("#35 process_domain(unknown op) is self-consistent (IR built, header unit NC)",
      isinstance(_ir35b, dict)
      and any(c["status"] == "NON_CONVERTIBLE" and any(k[1] == "h" for k in c["source_keys"])
              for c in _ir35b["_claims"]))
check("#35 process_domain(unknown op) emits NO viewer op for the header (no orphan)",
      not any(o["params"].get("name") == "X-Custom"
              for b in _ir35b["cache_behaviors"] for o in b["viewer_response_ops"]))

print("== FINDING (spine) 36: request header has NO `add` operation (set/remove only) ==")


def _pd36req(headers):
    """A real process_domain run for a REQUEST header transform rule."""
    return _pre.process_domain("shop.example.com", _DC35, {"request_header": [
        {"id": "h", "enabled": True, "expression": "true", "action": "rewrite",
         "action_parameters": {"headers": headers}}]}, {}, {}, {})


# ── finding 1: request `add` is NON_CONVERTIBLE (Cloudflare defines only set/remove) ──
for _cfg in ({"operation": "add", "value": "x"}, {"operation": "add", "expression": "http.host"}):
    _rq = _proc.process_request_header_transform(_hdr_rule("X-Custom", _cfg), {}, "cff")
    check(f"#36 request add {sorted(_cfg)} -> NON_CONVERTIBLE",
          _status_of(_rq) == "NON_CONVERTIBLE", f"got {_status_of(_rq)}")
    check("#36 request add produces NO add_request_header op",
          all(o.get("type") != "add_request_header" for o in _rq))
# response `add` is STILL NC but via its own detailed reason (unchanged) — the two phases differ.
_resp_add = _proc.process_response_header_transform(
    _hdr_rule("X-Custom", {"operation": "add", "value": "x"}), {}, "response")
check("#36 response add still NON_CONVERTIBLE (detailed RHP-set-only reason)",
      _status_of(_resp_add) == "NON_CONVERTIBLE"
      and "set-only" in (_resp_add[0].get("reason", "") if _resp_add else ""))
# controls: request set / remove still convert EXACT.
check("#36 request set still EXACT",
      _status_of(_proc.process_request_header_transform(
          _hdr_rule("X-Custom", {"operation": "set", "value": "x"}), {}, "cff")) == "EXACT")
check("#36 request remove still EXACT",
      _status_of(_proc.process_request_header_transform(
          _hdr_rule("X-Custom", {"operation": "remove"}), {}, "cff")) == "EXACT")

# ── real process_domain: request add leaves NO add_request_header op and NO EXACT claim ──
_ir36 = _pd36req({"X-Custom": {"operation": "add", "value": "x"}})
check("#36 process_domain(request add) returns an IR (no FATAL / orphan inventory)",
      isinstance(_ir36, dict) and "_claims" in _ir36)
check("#36 request add: header unit is NON_CONVERTIBLE, NO surviving EXACT claim",
      any(c["status"] == "NON_CONVERTIBLE" and any(k[1] == "h" for k in c["source_keys"])
          for c in _ir36["_claims"])
      and not any(c["status"] == "EXACT" and any(k[1] == "h" for k in c["source_keys"])
                  for c in _ir36["_claims"]))
check("#36 request add: NO add_request_header op anywhere in the IR",
      not any(o.get("type") == "add_request_header"
              for b in _ir36["cache_behaviors"] for o in b["viewer_request_ops"]))

print("== FINDING (spine) 37: dynamic expr result-type + empty->delete codegen; add hard gate ==")
def _emit37(op):
    return " | ".join(_gen37._generate_op_js(op, "cff")).strip()


# ── finding 1a: dynamic expression RESULT TYPE must be a string ──
for _phase, _fn in (("response", _proc.process_response_header_transform),
                    ("request", _proc.process_request_header_transform)):
    # numeric result -> NC (a header value must be a string)
    for _e in ("123", "len(http.host)"):
        check(f"#37 {_phase} numeric expr {_e!r} -> NON_CONVERTIBLE",
              _status_of(_fn(_hdr_rule("X-Test", {"operation": "set", "expression": _e}), {}, _phase))
              == "NON_CONVERTIBLE", f"got {_e}")
    # to_string() is a LONG-TAIL function: as a USER source value it is NON_CONVERTIBLE under the
    # narrowed conversion policy (source allowlist = concat/lower/upper/regex_replace/wildcard_replace).
    # Its low-level renderer/type still work (see #43 oracle, #38(a) type matrix) and INTERNAL
    # producers may use it via source=False (True-Client-IP, #46) — but a user rule value → NC.
    check(f"#37 {_phase} to_string(len(...)) -> NON_CONVERTIBLE (long-tail, source-narrowed)",
          _status_of(_fn(_hdr_rule("X-Test", {"operation": "set",
              "expression": "to_string(len(http.host))"}), {}, _phase)) == "NON_CONVERTIBLE")
    # a plain string-valued field expression -> converts
    check(f"#37 {_phase} string field expr (http.host) -> {_hdr_ok(_phase)}",
          _status_of(_fn(_hdr_rule("X-Test", {"operation": "set",
              "expression": "http.host"}), {}, _phase)) == _hdr_ok(_phase))
    # a CONSTANT empty-string expression is VALID (becomes an empty->delete) -> converts, not NC
    check(f"#37 {_phase} constant empty expr '\"\"' -> {_hdr_ok(_phase)} (a valid delete, not NC)",
          _status_of(_fn(_hdr_rule("X-Test", {"operation": "set", "expression": '""'}), {}, _phase))
          == _hdr_ok(_phase))
# the parser type helper directly
check("#37 result_type: numeric literal -> number",
      _cep.dynamic_expression_result_type(_cep.parse_dynamic_expression("123")) == "number")
check("#37 result_type: string literal -> string",
      _cep.dynamic_expression_result_type(_cep.parse_dynamic_expression('"x"')) == "string")
check("#37 result_type: to_string(...) -> string",
      _cep.dynamic_expression_result_type(_cep.parse_dynamic_expression("to_string(len(http.host))")) == "string")
check("#37 result_type: len(...) -> number",
      _cep.dynamic_expression_result_type(_cep.parse_dynamic_expression("len(http.host)")) == "number")

# ── finding 1b: codegen — dynamic set = evaluate ONCE, empty/undefined -> delete, else set string ──
_dynop = _proc.process_response_header_transform(
    _hdr_rule("X-Test", {"operation": "set", "expression": "http.host"}), {}, "response")[0]
_dynjs = _emit37(_dynop)
check("#37 dynamic set evaluates the expression EXACTLY once (single `var _hv =` assignment)",
      _dynjs.count("var _hv =") == 1
      and _dynjs.count("request.headers.host.value") == 1, _dynjs)
check("#37 dynamic set deletes on empty/undefined result",
      "=== undefined" in _dynjs and "=== ''" in _dynjs and "delete response.headers['x-test']" in _dynjs,
      _dynjs)
check("#37 dynamic set assigns the PROVEN-string result directly (no String() type mask)",
      "{value: _hv}" in _dynjs and "String(" not in _dynjs, _dynjs)
# static value:"" is a plain empty-header SET, NOT a delete (must not be conflated).
_statop = _proc.process_response_header_transform(
    _hdr_rule("X-Test", {"operation": "set", "value": ""}), {}, "response")[0]
_statjs = _emit37(_statop)
check("#37 static value:\"\" sets an empty header (NOT a delete, no _hv temp)",
      "{value: ''}" in _statjs and "delete " not in _statjs and "_hv" not in _statjs, _statjs)
# a constant-empty dynamic expression lowers to the delete branch (not a set-empty).
_cedynop = _proc.process_response_header_transform(
    _hdr_rule("X-Test", {"operation": "set", "expression": '""'}), {}, "response")[0]
check("#37 constant-empty dynamic expr lowers to the empty->delete form",
      "delete response.headers['x-test']" in _emit37(_cedynop))

# ── finding 2: `add` viewer op is a HARD gate (FATAL), not a silently-wired EXACT ──
_beh37 = _ir_with_inventory([("rule", "z", "/x")])["cache_behaviors"][0]
for _t in ("add_request_header", "add_response_header", "add_header"):
    _ph = "response" if "response" in _t else "request"
    check(f"#37 _append_viewer_op({_t}) -> LedgerError (hard gate, not a wired op)",
          _raises_ledger(lambda t=_t, p=_ph: _pre._append_viewer_op(
              _beh37, p, type=t, cf_source_rule="z", description="", condition={"always": True},
              raw_expression=None, params={"name": "y"}, scope_pattern="*", seq=0,
              source_kind="rule", source_id="z", outcome_status=_pre.OUTCOME_EXACT)) is not None)
check("#37 add types are NOT in _WIRED_VIEWER_OP_TYPES",
      not any(t in _pre._WIRED_VIEWER_OP_TYPES
              for t in ("add_request_header", "add_response_header", "add_header")))

print("== FINDING (spine) 38: TABLE-DRIVEN expression-type matrix (round-20 stabilization) ==")
# The SINGLE type authority is cdn_expr_parser.dynamic_expression_result_type. This matrix
# enumerates the full state space the per-example rounds kept missing: every _DYN_FUNCS return
# type, all five type categories, field types, the polymorphic concat, and unknown→NC. It also
# asserts producer↔generator CONSISTENCY (a string result is EXACT and codegens {value:_hv}; a
# non-string is NC and never reaches the generator). Fail-closed is the invariant: only a
# provably-STRING result is EXACT.

# (a) result-type registry — one row per behavior, covering string/number/array/bytes/unknown.
_TYPE_CASES = [
    # (expr, expected_type) — ALL Cloudflare-LEGAL signatures (round-21: the type matrix uses
    # only well-formed calls; illegal signatures are a separate matrix in FINDING-39).
    ('"literal"', "string"), ("http.host", "string"), ("http.request.uri.path", "string"),
    ("lower(http.host)", "string"), ("upper(http.host)", "string"),
    ('substring(http.host, 0, 3)', "string"), ('concat(http.host, "/x")', "string"),
    ("to_string(len(http.host))", "string"),
    ('join(split(http.host, ".", 8), "-")', "string"),      # split needs the mandatory limit
    ("encode_base64(sha256(http.host))", "string"),
    ('lookup_json_string(http.host, "k")', "string"), ("url_decode(http.host)", "string"),
    ('regex_replace(http.host, "a", "b")', "string"),
    ("decode_base64(http.host)", "string"),                 # String->String (round-21 finding 2)
    ("123", "number"), ("len(http.host)", "number"),
    ('lookup_json_integer(http.host, "k")', "number"),
    ("http.response.code", "number"), ("ip.src.asnum", "number"),
    ("ip.src.is_in_european_union", "boolean"),             # Boolean (round-21 finding 4)
    ("ip.src", "ip"),
    ('split(http.host, ".", 8)', "array"),
    ("sha256(http.host)", "bytes"), ("remove_bytes(http.host, \"a\")", "bytes"),
    ("concat(http.host, len(http.host))", "unknown"),       # polymorphic: a non-string arg
]
for _expr, _want in _TYPE_CASES:
    _got = _cep.dynamic_expression_result_type(_cep.parse_dynamic_expression(_expr))
    check(f"#38 type[{_expr}] == {_want}", _got == _want, f"got {_got}")

# (b) completeness: EVERY _DYN_FUNCS entry has an explicit CONTRACT (concat is polymorphic) — no
# function silently falls through to unknown by omission.
_uncontracted = _cep._DYN_FUNCS - set(_cep._DYN_FUNC_CONTRACT) - {"concat"}
check("#38 every _DYN_FUNCS has an explicit function contract (none default to unknown)",
      _uncontracted == set(), f"uncontracted: {sorted(_uncontracted)}")

# (c) outcome per type category, on BOTH processors: a string result CONVERTS (request→EXACT,
# response→LOSSY per the viewer-response error gap, round-27 finding 5); everything else → NC.
# All LEGAL signatures (illegal ones are FINDING-39). Note phase: split is response-only.
# "converts" means _hdr_ok(phase); "NON_CONVERTIBLE" is phase-independent.
_OUTCOME_BY_EXPR = [
    # CORE source functions (SOURCE_CONVERTIBLE_FUNCTIONS) + a plain field → convert.
    ("http.host", "converts"), ("lower(http.host)", "converts"), ("upper(http.host)", "converts"),
    ('concat(http.host, "/x")', "converts"),
    # LONG-TAIL functions → NON_CONVERTIBLE as USER source values (narrowed policy). Their low-level
    # renderer/type are still exercised by #38(a)/#43; internal producers may use them via source=False.
    ("to_string(len(http.host))", "NON_CONVERTIBLE"), ("substring(http.host, 0, 3)", "NON_CONVERTIBLE"),
    ("encode_base64(sha256(http.host))", "NON_CONVERTIBLE"), ("decode_base64(http.host)", "NON_CONVERTIBLE"),
    # already NC by type/other reasons (unchanged).
    ("len(http.host)", "NON_CONVERTIBLE"), ("http.response.code", "NON_CONVERTIBLE"),
    ("sha256(http.host)", "NON_CONVERTIBLE"),
    ("concat(http.host, len(http.host))", "NON_CONVERTIBLE"),
]
for _expr, _want in _OUTCOME_BY_EXPR:
    for _phase, _fn in (("response", _proc.process_response_header_transform),
                        ("request", _proc.process_request_header_transform)):
        _st = _status_of(_fn(_hdr_rule("X-Test", {"operation": "set", "expression": _expr}), {}, _phase))
        _exp = _hdr_ok(_phase) if _want == "converts" else _want
        check(f"#38 {_phase} outcome[{_expr}] == {_exp}", _st == _exp, f"got {_st}")
# join/split are LONG-TAIL functions → NON_CONVERTIBLE as USER source values on BOTH phases now
# (the source-narrow supersedes the old response-only LOSSY). The renderer still works (#43 oracle).
check("#38 response join(split(...,limit)) -> NON_CONVERTIBLE (long-tail, source-narrowed)",
      _status_of(_proc.process_response_header_transform(
          _hdr_rule("X-Test", {"operation": "set", "expression": 'join(split(http.host, ".", 8), "-")'}),
          {}, "response")) == "NON_CONVERTIBLE")
check("#38 request join(split(...,limit)) -> NON_CONVERTIBLE (long-tail, source-narrowed)",
      _status_of(_proc.process_request_header_transform(
          _hdr_rule("X-Test", {"operation": "set", "expression": 'join(split(http.host, ".", 8), "-")'}),
          {}, "cff")) == "NON_CONVERTIBLE")

# (d) producer↔generator consistency: an EXACT dynamic value codegens `{value: _hv}` (proven
# string, no String() mask); a String() coercion would mask a type the gate should have
# rejected, so it must NEVER appear.
# CORE source functions only (the long-tail ones are now source-NC, so there's no converted op to
# codegen — their renderer is still exercised by the #43 oracle at the low level).
for _expr in ("http.host", 'concat(http.host, "/x")', "lower(http.host)"):
    _op = _proc.process_response_header_transform(
        _hdr_rule("X-Test", {"operation": "set", "expression": _expr}), {}, "response")[0]
    _js = " | ".join(_gen37._generate_op_js(_op, "cff")).strip()
    check(f"#38 codegen[{_expr}] assigns {{value: _hv}} directly (no String mask)",
          "{value: _hv}" in _js and "String(" not in _js, _js)

# (e) the value-type gate reason surfaces the offending type (actionable NC message).
_reason = _cep.value_expression_type_unconvertible("sha256(http.host)")
check("#38 type-gate reason names the non-string type (bytes)",
      _reason and "bytes" in _reason and "non-string" in _reason, _reason)
check("#38 type-gate returns None for a string result (no false NC)",
      _cep.value_expression_type_unconvertible("http.host") is None)

print("== FINDING (spine) 39: ILLEGAL-signature matrix — arg types / arity / phase / literals ==")
# The type-return table alone let signature-illegal-but-type-plausible expressions pass
# (round-21 finding 1). check_dynamic_expression_signature validates the WHOLE call recursively.
# Each row: (expr, phase, reason_substr) — must be rejected, with the reason naming the cause.
_ILLEGAL = [
    # (expr, context, reason_substr) — context is an EMIT CONTEXT (round-22).
    # wrong ARG TYPE
    ("lower(len(http.host))", "response_header", "argument 1 is number"),
    ("upper(len(http.host))", "response_header", "argument 1 is number"),
    ('join(http.host, "-")', "response_header", "argument 1 is string"),   # join wants Array first
    ("to_string(sha256(http.host))", "response_header", "argument 1 is bytes"),
    ("to_string(http.host)", "response_header", "argument 1 is string"),
    ('substring(http.host, http.host, 3)', "response_header", "argument 2 is string"),
    # wrong ARITY
    ("uuidv4(sha256(http.host), \"x\")", "url_rewrite", "argument"),   # uuidv4 arity (rewrite ctx)
    ("lower()", "response_header", "argument"),
    ('lower(http.host, "x")', "response_header", "argument"),
    ("len()", "response_header", "argument"),
    # CONTEXT restriction (round-22): split is response/custom-error only; rewrite-only funcs
    # are rejected in a header context.
    ('split(http.host, ".", 8)', "request_header", "not available in the request_header"),
    ('regex_replace(http.host, "a", "b")', "response_header", "not available"),
    ('remove_query_args(http.request.uri.query, "x")', "response_header", "not available"),
    # uuidv4 is TARGET-UNSUPPORTED (round-22 finding 2): NC in EVERY context (empty contexts),
    # because the renderer ignores the source bytes — not merely context-restricted.
    ("uuidv4(sha256(http.host))", "url_rewrite", "target-unsupported"),
    # NODE-SHAPE / literal constraints (round-22): non-empty literal separator, field-only
    # source, valid flags, mandatory 1..128 limit.
    ('split(http.host, ".")', "response_header", "takes 3 argument"),   # limit missing → arity
    ('split(http.host, ".", 0)', "response_header", "between 1 and 128"),
    ('split(http.host, ".", 200)', "response_header", "between 1 and 128"),
    ('split(http.host, ".", http.host)', "response_header", "argument 3 is string"),
    ('split(http.host, "", 8)', "response_header", "non-empty literal"),   # empty separator
    ('split(http.host, http.host, 8)', "response_header", "literal string"),  # dynamic separator
    ('decode_base64("YWJj")', "response_header", "must be a field"),    # literal source
    ('encode_base64(http.host, "x")', "response_header", "only 'u'/'p'"),   # bad flags
]
for _expr, _ctx, _sub in _ILLEGAL:
    _r = _cep.value_expression_type_unconvertible(_expr, _ctx)
    check(f"#39 illegal[{_expr} @{_ctx}] -> reason", isinstance(_r, str), f"got {_r!r}")
    check(f"#39 illegal[{_expr}] reason names the cause ({_sub!r})",
          _r is not None and _sub in _r, f"got {_r!r}")
    # end-to-end NON_CONVERTIBLE at the processor for the *_header contexts (rewrite-context
    # cases have no header processor — the signature-reason check above covers those).
    if _ctx in ("request_header", "response_header"):
        _fn = _proc.process_response_header_transform if _ctx == "response_header" \
            else _proc.process_request_header_transform
        _tgt = "response" if _ctx == "response_header" else "cff"
        check(f"#39 illegal[{_expr}] -> NON_CONVERTIBLE end-to-end",
              _status_of(_fn(_hdr_rule("X-Test", {"operation": "set", "expression": _expr}), {}, _tgt))
              == "NON_CONVERTIBLE")

# uuidv4 is target-unsupported in EVERY context (finding 2 — not just when the source field is
# unmappable; even uuidv4(sha256(...)) with a valid bytes source is NC), and end-to-end NC in a
# header (context=None also rejects it — belt & suspenders).
for _ctx in ("url_rewrite", "redirect", "request_header", "response_header", None):
    check(f"#39 uuidv4(sha256(host)) target-unsupported @{_ctx}",
          _cep.value_expression_type_unconvertible("uuidv4(sha256(http.host))", _ctx) is not None)
check("#39 uuidv4 -> NON_CONVERTIBLE end-to-end in a header",
      _status_of(_proc.process_response_header_transform(
          _hdr_rule("X-Test", {"operation": "set", "expression": "uuidv4(sha256(http.host))"}), {}, "response"))
      == "NON_CONVERTIBLE")

# An UNKNOWN function name doesn't tokenize as a call (only _DYN_FUNCS names do), so it's caught
# by the PARSE-failure gate, not the signature gate — still NON_CONVERTIBLE end-to-end. (The
# signature checker's own "unknown function" branch is a belt-and-suspenders guard the
# completeness test in FINDING-38(b) keeps unreachable — _DYN_FUNCS == contracted set.)
check("#39 unknown function (bogusfn) -> NON_CONVERTIBLE end-to-end (parse-failure gate)",
      _status_of(_proc.process_response_header_transform(
          _hdr_rule("X-Test", {"operation": "set", "expression": "bogusfn(http.host)"}), {}, "response"))
      == "NON_CONVERTIBLE")

# LEGAL controls that must NOT be over-rejected (guard against a too-strict contract): each is
# a well-formed Cloudflare call with a string result, in a context where it's permitted.
_LEGAL = [
    ("lower(http.host)", "response_header"), ("upper(http.host)", "response_header"),
    ("to_string(len(http.host))", "response_header"), ("to_string(ip.src)", "response_header"),
    ("to_string(ip.src.is_in_european_union)", "response_header"),   # Boolean input is legal
    ('substring(http.host, 0, 3)', "response_header"), ('substring(http.host, 2)', "response_header"),
    ('join(split(http.host, ".", 8), "-")', "response_header"),      # split response-only, here OK
    ("encode_base64(sha256(http.host))", "response_header"),         # documented signed-header use
    ("encode_base64(http.host)", "response_header"),                 # String input also legal
    ("encode_base64(http.host, \"up\")", "response_header"),         # valid flags
    ("decode_base64(http.host)", "response_header"),                 # field source
    ('lookup_json_string(http.host, "a", "b", "c")', "response_header"),   # variadic keys
    ("url_decode(http.host)", "response_header"), ('url_decode(http.host, "r")', "response_header"),
    # rewrite-only functions are legal in a url_rewrite context (proves the context gate isn't
    # a blanket ban — it's context-scoped).
    ('regex_replace(http.host, "a", "b")', "url_rewrite"),
    ('remove_query_args(http.request.uri.query, "x")', "url_rewrite"),
]
for _expr, _ctx in _LEGAL:
    check(f"#39 legal[{_expr} @{_ctx}] -> None (not over-rejected)",
          _cep.value_expression_type_unconvertible(_expr, _ctx) is None,
          f"got {_cep.value_expression_type_unconvertible(_expr, _ctx)!r}")

print("== FINDING (spine) 40: concat codegen — string `+` vs array .concat() (round-22) ==")
# concat is polymorphic: all-string → `+`; all-array → .concat(); mixed/bytes/unknown → NC. concat is
# source-core, but THIS array shape nests split/join (LONG-TAIL) → as a USER source value it is
# NON_CONVERTIBLE. The RENDERER capability is unchanged, verified below via an internal-lowered value
# (and the #43 contract→renderer oracle).
_ARRCONCAT = 'join(concat(split(http.host, ".", 8), split(http.host, ".", 8)), "-")'
# (a) as a USER source value → NON_CONVERTIBLE (split/join are not source-core).
check("#40 USER join(concat(array,array)) -> NON_CONVERTIBLE (long-tail split/join, source-narrowed)",
      _status_of(_proc.process_response_header_transform(
          _hdr_rule("X-Test", {"operation": "set", "expression": _ARRCONCAT}), {}, "response"))
      == "NON_CONVERTIBLE")
# (b) the low-level renderer still emits array .concat() — exercised via an internal-lowered value
# (source=False), since the source path no longer produces this op.
_aclv = _cep.lower_dynamic_value(_ARRCONCAT, "response_header", _cep.LOWERED_EMPTY_DELETE_HEADER, source=False)
_acop = {"type": "set_response_header", "cf_source_rule": "x", "description": "",
         "condition": {"always": True}, "params": {"name": "X-Test", "value_lowered": _aclv}}
_acjs = " | ".join(_gen37._generate_op_js(_acop, "cff")).strip()
check("#40 array concat codegens .concat() (NOT string `+`) [low-level renderer, source=False]",
      isinstance(_aclv, dict) and ".concat(" in _acjs
      and " + " not in _acjs.split("_hv =")[1].split(";")[0], _acjs)
# string concat stays `+` (parenthesized).
_scop = _proc.process_response_header_transform(
    _hdr_rule("X-Test", {"operation": "set", "expression": 'concat(http.host, "/x")'}), {}, "response")[0]
_scjs = " | ".join(_gen37._generate_op_js(_scop, "cff")).strip()
check("#40 string concat codegens `+` (parenthesized), not .concat()",
      " + " in _scjs and ".concat(" not in _scjs, _scjs)
# mixed string+array concat → unknown → NC (Cloudflare doesn't define it; fail closed).
check("#40 mixed concat(string, array) -> NON_CONVERTIBLE",
      _status_of(_proc.process_response_header_transform(
          _hdr_rule("X-Test", {"operation": "set",
              "expression": 'concat(http.host, split(http.host, ".", 8))'}), {}, "response"))
      == "NON_CONVERTIBLE")

print("== FINDING (spine) 41: NODE RUNTIME equivalence — run the generated JS, compare values ==")
# The reviewer's core ask: don't just assert the JS string shape — RUN it and compare the
# emitted header value to Cloudflare's semantics. Skipped gracefully if node is absent.
# NOTE (round-22 finding 4): this is a LOCAL JS-SEMANTICS test (Node v26), NOT a CloudFront
# runtime-equivalence proof. CloudFront Functions run a distinct cloudfront-js-2.0 runtime; Node
# success does not prove the same code runs there. AWS confirmed .concat()/Buffer/atob/crypto are
# supported so array concat has no compat issue, but true CloudFront-runtime validation belongs
# in an optional TestFunction integration test (runtime=cloudfront-js-2.0), out of scope here.
if not _NODE:
    # An ABSENT node is a SKIP, not a PASS (finding 4) — the runtime checks did not run.
    skip("#41 local JS-semantics tests", "node not installed")
else:
    class _JsRunError(Exception):
        pass

    def _run_header_js(expr, host):
        """Build the set_response_header CFF for `expr` from an INTERNAL-lowered value (source=False)
        and RUN it in node with request.host=host; return the emitted response.headers['x-test'] value
        (or None if deleted). This is a RENDERER runtime test — source=False so LONG-TAIL functions
        (now source-NC as USER values, tested by #37/#38/#60) still produce a runnable op, since the
        renderer's runtime output is source-agnostic. RAISES _JsRunError on a non-zero exit, any
        stderr, or unparseable stdout (finding 3). Returns "__NC__" only if lowering itself fails
        (a genuine low-level renderer/contract gap, e.g. a target-unsupported function)."""
        lv = _cep.lower_dynamic_value(expr, "response_header", _cep.LOWERED_EMPTY_DELETE_HEADER, source=False)
        if not isinstance(lv, dict):
            return "__NC__"
        op = {"type": "set_response_header", "cf_source_rule": "x", "description": "",
              "condition": {"always": True}, "params": {"name": "X-Test", "value_lowered": lv}}
        body = " | ".join(_gen37._generate_op_js(op, "cff")).strip().replace(" | ", "\n")
        js = (f"const response={{headers:{{}}}};"
              f"const request={{headers:{{host:{{value:{_json.dumps(host)}}}}}}};\n"
              f"{body}\n"
              f"const h=response.headers['x-test'];"
              f"process.stdout.write(JSON.stringify(h===undefined?null:h.value));")
        out = _subprocess.run([_NODE, "-e", js], capture_output=True, text=True, timeout=20)
        if out.returncode != 0:
            raise _JsRunError(f"node exit {out.returncode}: {out.stderr.strip()[:200]}")
        if out.stderr.strip():
            raise _JsRunError(f"node stderr: {out.stderr.strip()[:200]}")
        try:
            return _json.loads(out.stdout)   # may legitimately be null (deleted header)
        except Exception as e:
            raise _JsRunError(f"unparseable stdout {out.stdout!r}: {e}")

    def _check_js(label, expr, host, want):
        """Run + compare; a _JsRunError is a FAILURE (never silently passes)."""
        try:
            got = _run_header_js(expr, host)
        except _JsRunError as e:
            check(label, False, f"JS run failed: {e}")
            return
        check(label, got == want, f"got {got!r}, want {want!r}")

    # (expr, host, expected_emitted_value) — expected from Cloudflare semantics.
    _RUN_CASES = [
        ('concat(http.host, "/x")', "a.b.c", "a.b.c/x"),                 # string concat
        ("to_string(len(http.host))", "abcd", "4"),                     # to_string(number)
        ('join(concat(split(http.host, ".", 8), split(http.host, ".", 8)), "-")',
         "a.b.c", "a-b-c-a-b-c"),                                       # array concat → join
        ('join(split(http.host, ".", 8), "-")', "a.b.c", "a-b-c"),      # single array → join
        ('concat(concat(http.host, "-"), "end")', "x", "x-end"),        # nested concat
    ]
    for _expr, _host, _want in _RUN_CASES:
        _check_js(f"#41 localjs[{_expr} | host={_host}] emits {_want!r}", _expr, _host, _want)
    # empty dynamic result → header DELETED (null), not "" (Cloudflare empty→delete).
    _check_js("#41 localjs: empty dynamic result DELETES the header (null, not '')",
              'substring(http.host, 0, 0)', "abc", None)
    # SHA-256 signed header with FIXED input + FIXED expected digests (finding 4/5). Input "a"
    # is CHOSEN because sha256("a") base64 CONTAINS a '/' (…7/g… / …a/u…), so standard base64
    # and base64url DIFFER — the "u" test would pass with wrong (non-URL-safe) chars otherwise
    # (round-24 finding 5). Verifies the digest AND each encoding: no-pad, padded, url-safe.
    _SHA_A_NOPAD = "ypeBEsobvcr6wjGzmiPcTaeG7/gUfE5yuYB3ha/uSLs"     # has '/'
    _SHA_A_URL = "ypeBEsobvcr6wjGzmiPcTaeG7_gUfE5yuYB3ha_uSLs"       # '/' → '_'
    assert "/" in _SHA_A_NOPAD and "/" not in _SHA_A_URL and "_" in _SHA_A_URL  # test-integrity
    _check_js("#41 localjs: encode_base64(sha256(host)) == fixed base64 (no padding, has '/')",
              "encode_base64(sha256(http.host))", "a", _SHA_A_NOPAD)
    _check_js("#41 localjs: encode_base64(sha256(host), \"p\") == fixed base64 (padded)",
              'encode_base64(sha256(http.host), "p")', "a", _SHA_A_NOPAD + "=")
    _check_js("#41 localjs: encode_base64(sha256(host), \"u\") == base64url (URL-safe, '/'→'_')",
              'encode_base64(sha256(http.host), "u")', "a", _SHA_A_URL)
    # finding-3 guard: a crashing JS must SURFACE as a failure, not a silent None pass. Confirm
    # the helper raises _JsRunError on a throwing script (so _check_js would FAIL, not pass).
    _crash_detected = False
    try:
        _cop = _proc.process_response_header_transform(
            _hdr_rule("X-Test", {"operation": "set", "expression": "http.host"}), {}, "response")[0]
        _cbody = " | ".join(_gen37._generate_op_js(_cop, "cff")).strip().replace(" | ", "\n")
        # prepend a throw so the process exits non-zero with empty stdout
        _js = ("throw new Error('boom');\n" + _cbody)
        _o = _subprocess.run([_NODE, "-e", _js], capture_output=True, text=True, timeout=20)
        # emulate the helper's contract: non-zero exit → error, not a None result
        _crash_detected = _o.returncode != 0 and "boom" in _o.stderr
    except Exception:
        _crash_detected = False
    check("#41 localjs: a crashing script is a FAILURE, not a silent None (finding-3 guard)",
          _crash_detected)

print("== FINDING (spine) 42: redirect/rewrite value exprs go through the contract gate (r22 #1) ==")
# redirect/rewrite are ALREADY-WIRED producers, so their dynamic target/path/query must run the
# SAME two proofs as headers (unmappable-field + signature/type/context). Real producer tests.


def _redir_rule(target_expr):
    return {"id": "r", "description": "t", "expression": "true", "action": "redirect",
            "action_parameters": {"from_value": {"status_code": 301, "preserve_query_string": False,
                                                  "target_url": {"expression": target_expr}}}}


def _rewrite_rule(path_expr=None, query_expr=None):
    uri = {}
    if path_expr is not None:
        uri["path"] = {"expression": path_expr}
    if query_expr is not None:
        uri["query"] = {"expression": query_expr}
    return {"id": "w", "description": "t", "expression": "true", "action": "rewrite",
            "action_parameters": {"uri": uri}}


def _one_status(r):
    o = r if isinstance(r, dict) else (r[0] if r else {})
    return "NON_CONVERTIBLE" if o.get("type") == "non_convertible" else o.get("outcome_status")


# ILLEGAL in redirect/rewrite: signature (arg type), type (non-string result), context (a
# response-only function in a rewrite). Each must be NON_CONVERTIBLE at the real processor.
check("#42 redirect target lower(len(host)) -> NON_CONVERTIBLE (arg type)",
      _one_status(_proc.process_redirect_rule(_redir_rule("lower(len(http.host))"), {}, "")) == "NON_CONVERTIBLE")
check("#42 redirect target len(host) -> NON_CONVERTIBLE (numeric result)",
      _one_status(_proc.process_redirect_rule(_redir_rule("len(http.host)"), {}, "")) == "NON_CONVERTIBLE")
check("#42 rewrite path lower(len(host)) -> NON_CONVERTIBLE (arg type)",
      _one_status(_proc.process_rewrite_rule(_rewrite_rule(path_expr="lower(len(http.host))"), {}, "")) == "NON_CONVERTIBLE")
check("#42 rewrite path split(...) -> NON_CONVERTIBLE (split is response-only, not url_rewrite)",
      _one_status(_proc.process_rewrite_rule(_rewrite_rule(path_expr='split(http.host, ".", 8)'), {}, "")) == "NON_CONVERTIBLE")
check("#42 rewrite query join(http.host,...) -> NON_CONVERTIBLE (join wants Array first)",
      _one_status(_proc.process_rewrite_rule(_rewrite_rule(query_expr='join(http.host, "-")'), {}, "")) == "NON_CONVERTIBLE")
check("#42 redirect target uuidv4(sha256(host)) -> NON_CONVERTIBLE (target-unsupported)",
      _one_status(_proc.process_redirect_rule(_redir_rule("uuidv4(sha256(http.host))"), {}, "")) == "NON_CONVERTIBLE")
# LEGAL control group: well-formed string-valued targets/paths convert EXACT (no over-rejection).
check("#42 redirect concat(url, uri.path) -> EXACT",
      _one_status(_proc.process_redirect_rule(
          _redir_rule('concat("https://x.com", http.request.uri.path)'), {}, "")) == "EXACT")
check("#42 rewrite path regex_replace(...) -> EXACT (regex_replace IS legal in url_rewrite)",
      _one_status(_proc.process_rewrite_rule(
          _rewrite_rule(path_expr='regex_replace(http.request.uri.path, "^/a", "/b")'), {}, "")) == "EXACT")
check("#42 rewrite path lower(uri.path) -> EXACT",
      _one_status(_proc.process_rewrite_rule(
          _rewrite_rule(path_expr="lower(http.request.uri.path)"), {}, "")) == "EXACT")

print("== FINDING (spine) 43: CONTRACT→RENDERER table — every EXACT function renders + runs ==")
# The core round-24 invariant: the contract must only accept AST shapes the renderer FAITHFULLY
# emits. For EVERY contracted function that can be EXACT, generate its JS via dyn_expr_to_js and
# (when node is present) RUN it against a fixture, comparing to the Cloudflare-expected value —
# including non-literal args and a nested form. A renderer that throws / returns the wrong value
# is a FAILURE, catching contract↔renderer drift (findings 1/3/4 were exactly this drift).


def _dyn_func_names(node):
    """Collect the names of EVERY function called anywhere in a parsed dyn-expr tree (round-25
    finding 4: coverage must count NESTED functions, not just the outermost). So sha256 inside
    encode_base64(sha256(...)) counts as covered."""
    out = set()
    if isinstance(node, dict):
        if node.get("type") == "func_call" or "func" in node:
            if node.get("func"):
                out.add(node["func"])
        for k, v in node.items():
            if k != "type":
                out |= _dyn_func_names(v)
    elif isinstance(node, list):
        for it in node:
            out |= _dyn_func_names(it)
    return out


class _ContractOrRun(Exception):
    pass


def _render_and_run(expr, context, host, querystring=None):
    """CONTRACT-then-render-then-run (round-25 finding 4). FIRST assert the expression PASSES the
    contract in `context` (so a run-case can't accidentally use an expression the contract would
    reject); THEN render via the REAL generator and RUN in node. request.headers.host.value=host;
    request.querystring is a CFF-parsed object (supports multiValue: a list value → {multiValue:
    [{value:...}]}). Raises _ContractOrRun on a contract rejection or any node failure."""
    sig = _cep.value_expression_type_unconvertible(expr, context)
    if sig is not None:
        raise _ContractOrRun(f"contract REJECTED in {context}: {sig}")
    tree = _cep.parse_dynamic_expression(expr)
    js_expr = _gen37.dyn_expr_to_js(tree, "cff")

    def _qval(v):
        if isinstance(v, list):   # multiValue: CFF represents repeated params as multiValue[]
            return "{multiValue:[" + ",".join("{value:" + _js2.dumps(x) + "}" for x in v) + "]}"
        return "{value:" + _js2.dumps(v) + "}"
    qs_obj = "{}" if querystring is None else \
        "{" + ",".join(_js2.dumps(k) + ":" + _qval(v) for k, v in querystring.items()) + "}"
    request_js = "{headers:{host:{value:" + _js2.dumps(host) + "}}, querystring:" + qs_obj + "}"
    src = (f"{_QS_HELPER}\n"
           f"const request={request_js};"
           f"const event={{viewer:{{ip:'1.2.3.4'}}}};"
           f"let __v;try{{__v=({js_expr});}}catch(e){{process.stderr.write('THREW:'+e.message);process.exit(3);}}"
           f"process.stdout.write(JSON.stringify(__v===undefined?null:(Array.isArray(__v)?['__ARR__'].concat(__v):__v)));")
    out = _sp2.run([_NODE2, "-e", src], capture_output=True, text=True, timeout=20)
    if out.returncode != 0 or out.stderr.strip():
        raise _ContractOrRun(f"node failed ({out.returncode}): {out.stderr.strip()[:160]}")
    return _js2.loads(out.stdout)


# (expr, context, host, expected) — expected from Cloudflare semantics; arrays wrapped ['__ARR__',
# ...]. Every row is contract-checked in its context BEFORE render+run. Covers non-literal args,
# NESTED forms, and BRANCH/FLAG/ARITY variants (round-25 finding 4): base64 p/u/up, recursive
# url_decode, substring 2-arg & 3-arg, nested sha256, wildcard strict flag, negative substring.
_CONTRACT_RUN = [
    ("lower(http.host)", "response_header", "AB.C", "ab.c"),
    ("upper(http.host)", "response_header", "ab.c", "AB.C"),
    ("substring(http.host, 1, 3)", "response_header", "abcdef", "bc"),      # 3-arg
    ("substring(http.host, 2)", "response_header", "abcdef", "cdef"),       # 2-arg branch
    ('concat(http.host, "/", http.host)', "response_header", "x", "x/x"),
    ("to_string(len(http.host))", "response_header", "abcd", "4"),          # nested len (number)
    ('decode_base64(http.host)', "response_header", "YWJj", "abc"),
    ('lookup_json_string(http.host, "k")', "response_header", '{"k":"v"}', "v"),
    ('lookup_json_string(http.host, "a", "b")', "response_header", '{"a":{"b":"d"}}', "d"),
    ('url_decode(http.host)', "response_header", "a%20b", "a b"),
    ('url_decode(http.host, "r")', "response_header", "a%2520b", "a b"),    # recursive branch
    ("encode_base64(http.host)", "response_header", "abc", "YWJj"),         # no-flag branch
    ('encode_base64(http.host, "p")', "response_header", "ab", "YWI="),     # padded branch
    ('encode_base64(http.host, "u")', "response_header", "\xff\xfe", "__URLSAFE__"),  # url branch
    ("encode_base64(sha256(http.host))", "response_header", "a",           # nested sha256, no-flag
     "ypeBEsobvcr6wjGzmiPcTaeG7/gUfE5yuYB3ha/uSLs"),
    ('encode_base64(sha256(http.host), "u")', "response_header", "a",      # nested sha256, url flag
     "ypeBEsobvcr6wjGzmiPcTaeG7_gUfE5yuYB3ha_uSLs"),
    # number/array funcs are only EXACT WRAPPED into a string result — wrap them so they're a
    # legal header value; the coverage walker still counts the nested len/split/etc.
    ('to_string(len(http.host))', "response_header", "ab", "2"),           # len (number) via to_string
    ('to_string(lookup_json_integer(http.host, "n"))', "response_header", '{"n":42}', "42"),
    ('join(split(http.host, ".", 8), "-")', "response_header", "a.b.c", "a-b-c"),  # split (array) via join
    ('join(concat(split(http.host, ".", 8), split(http.host, ".", 8)), ",")', "response_header",
     "a.b", "a,b,a,b"),                                                     # all-array concat via join
    ('regex_replace(http.host, "a", "X")', "url_rewrite", "banana", "bXnana"),
    ('wildcard_replace(http.host, "a*c", "Z${1}Z")', "url_rewrite", "abbc", "ZbbZ"),
    ('wildcard_replace(http.host, "A*C", "Z${1}Z", "s")', "url_rewrite", "abbc", "abbc"),  # strict: no match
]
if not _NODE2:
    skip("#43 contract→renderer RUN tests", "node not installed")
else:
    for _row in _CONTRACT_RUN:
        _expr, _ctx, _host, _want = _row
        try:
            _got = _render_and_run(_expr, _ctx, _host)
        except _ContractOrRun as _e:
            check(f"#43 render+run[{_expr} @{_ctx}]", False, str(_e))
            continue
        if _want == "__URLSAFE__":
            # the "u" branch on raw bytes — just assert it ran to a url-safe string
            check(f"#43 render+run[{_expr}] runs to a url-safe string",
                  isinstance(_got, str) and "+" not in _got and "/" not in _got, f"got {_got!r}")
        else:
            check(f"#43 render+run[{_expr} @{_ctx} | {_host!r}] == {_want!r}", _got == _want,
                  f"got {_got!r}")
    # remove_query_args in url_rewrite: run with a querystring fixture, incl a MULTIVALUE param
    # (repeated ?x=..&x=..) — Cloudflare removes ALL occurrences (round-25 finding 4).
    try:
        _rqa = _render_and_run('remove_query_args(http.request.uri.query, "b")', "url_rewrite", "h",
                               querystring={"a": "1", "b": ["2", "9"], "c": "3"})
    except _ContractOrRun as _e:
        _rqa = f"__ERR__ {_e}"
    check("#43 remove_query_args drops ALL b (incl multiValue) -> 'a=1&c=3'",
          _rqa == "a=1&c=3", f"got {_rqa!r}")

# COMPLETENESS guard (round-25 finding 4): every contracted function that CAN appear in an EXACT
# expression must be exercised — counting NESTED names across all run-case ASTs, and NOT excluding
# bytes-result funcs (sha256 is bytes but nests inside an EXACT encode_base64). Only functions
# that are NC EVERYWHERE (empty contexts: uuidv4, remove_bytes) are exempt.
_covered = set()
for _row in _CONTRACT_RUN:
    _covered |= _dyn_func_names(_cep.parse_dynamic_expression(_row[0]))
_covered |= _dyn_func_names(_cep.parse_dynamic_expression(
    'remove_query_args(http.request.uri.query, "b")'))
_need_cover = set()
for _fn, _fc in _cep._DYN_FUNC_CONTRACT.items():
    if _fc.contexts is not None and not _fc.contexts:
        continue                     # NC in every context (uuidv4, remove_bytes) — never EXACT
    _need_cover.add(_fn)
_need_cover.add("concat")
check("#43 every EXACT-capable function (incl. nested bytes funcs) has a render+run case",
      _need_cover <= _covered, f"missing run-cases: {sorted(_need_cover - _covered)}")
# The oracle CAUGHT a real drift: substring with a NEGATIVE literal index (Cloudflare counts
# from the end; JS .substring() clamps to 0). Now rejected by the contract (round-25 finding 4).
check("#43 substring with a negative literal index -> NC (renderer can't reproduce)",
      _cep.value_expression_type_unconvertible("substring(http.host, -2)", "response_header") is not None)
check("#43 substring with non-negative indices still OK (no over-rejection)",
      _cep.value_expression_type_unconvertible("substring(http.host, 1, 3)", "response_header") is None)

print("== FINDING (spine) 44: FULL CHAIN — processor → JSON round-trip → generator → Node ==")
# The round-26 boundary proof: the ACTUAL production chain, not a hand-built op. Run the real
# processor → json.dumps/loads the op (proves the LoweredValue is JSON-safe AND survives the
# accumulator round-trip the pipeline does) → the real generator renders from the RELOADED op
# (no re-parse) → Node executes → compare to Cloudflare-expected. This is the boundary the prior
# rounds' P1s lived at: it now has one end-to-end test through real data, not just unit oracles.


def _proc_json_gen(op_fn, rule):
    """Run the real processor for `rule`, take the first op, JSON round-trip it, return the
    reloaded op (proves JSON-safety + accumulator survival). Returns the reloaded op or the NC."""
    ops = op_fn(rule, {}, "response")
    op = ops[0] if isinstance(ops, list) and ops else ops
    reloaded = _js44.loads(_js44.dumps(op))    # accumulator write→read
    return reloaded


if not _NODE2:
    skip("#44 full-chain (processor→JSON→generator→Node)", "node not installed")
else:
    # header dynamic value: processor lowers concat → JSON round-trip → generator renders →
    # Node runs on host="ab" → "ab/x".
    _op = _proc_json_gen(_proc.process_response_header_transform,
                         {"id": "h", "enabled": True, "expression": "true", "action": "rewrite",
                          "action_parameters": {"headers": {"X-C": {"operation": "set",
                              "expression": 'concat(http.host, "/x")'}}}})
    check("#44 reloaded header op has a valid LoweredValue (survived JSON round-trip)",
          _cep.validate_lowered_value(_op["params"]["value_lowered"], _cep.SLOT_RESPONSE_HEADER_VALUE) is None)
    _body = " | ".join(_gen37._generate_op_js(_op, "cff")).strip().replace(" | ", "\n")
    _src = ("const response={headers:{}};const request={headers:{host:{value:'ab'}}};\n"
            + _body + "\nprocess.stdout.write(JSON.stringify(response.headers['x-c']"
            "===undefined?null:response.headers['x-c'].value));")
    _out = _subprocess.run([_NODE2, "-e", _src], capture_output=True, text=True, timeout=20)
    check("#44 header dynamic full chain → 'ab/x'",
          _out.returncode == 0 and not _out.stderr.strip() and _js44.loads(_out.stdout) == "ab/x",
          f"rc={_out.returncode} out={_out.stdout!r} err={_out.stderr[:120]}")

    # redirect target: processor → JSON → generator → Node (location value).
    _rop = _proc_json_gen(lambda r, i, p: _proc.process_redirect_rule(r, i, p),
                          {"id": "r", "description": "t", "expression": "true", "action": "redirect",
                           "action_parameters": {"from_value": {"status_code": 301,
                               "preserve_query_string": False,
                               "target_url": {"expression": 'concat("https://x", http.request.uri.path)'}}}})
    check("#44 reloaded redirect op has a valid LoweredValue target",
          _cep.validate_lowered_value(_rop["params"]["target"], _cep.SLOT_REDIRECT_TARGET) is None)
    _rbody = " | ".join(_gen37._generate_op_js(_rop, "cff")).strip().replace(" | ", "\n")
    _rsrc = ("const request={uri:'/p', headers:{host:{value:'h'}}};\n"
             + "var __r = (function(){ " + _rbody + " })();\n"
             + "process.stdout.write(JSON.stringify(__r.headers.location.value));")
    _rout = _subprocess.run([_NODE2, "-e", _rsrc], capture_output=True, text=True, timeout=20)
    check("#44 redirect full chain → 'https://x/p'",
          _rout.returncode == 0 and _js44.loads(_rout.stdout) == "https://x/p",
          f"rc={_rout.returncode} out={_rout.stdout!r} err={_rout.stderr[:120]}")

    # rewrite clear-query: processor → JSON → generator → Node (querystring becomes {}).
    _wop = _proc_json_gen(lambda r, i, p: _proc.process_rewrite_rule(r, i, p),
                          {"id": "w", "description": "t", "expression": "true", "action": "rewrite",
                           "action_parameters": {"uri": {"query": {"value": ""}}}})
    check("#44 reloaded rewrite clear-query carries clear_query behavior ON the LoweredValue",
          _wop["params"]["query_lowered"].get("empty_behavior") == "clear_query"
          and _cep.validate_lowered_value(_wop["params"]["query_lowered"], _cep.SLOT_REWRITE_QUERY) is None)
    _wbody = " | ".join(_gen37._generate_op_js(_wop, "cff")).strip().replace(" | ", "\n")
    _wsrc = ("const request={uri:'/p', querystring:{a:{value:'1'}}, headers:{host:{value:'h'}}};\n"
             + _wbody + "\nprocess.stdout.write(JSON.stringify(Object.keys(request.querystring)));")
    _wout = _subprocess.run([_NODE2, "-e", _wsrc], capture_output=True, text=True, timeout=20)
    check("#44 rewrite clear-query full chain → querystring cleared to {}",
          _wout.returncode == 0 and _js44.loads(_wout.stdout) == [],
          f"rc={_wout.returncode} out={_wout.stdout!r} err={_wout.stderr[:120]}")

# A raw-only converted op (no LoweredValue) must FATAL in the generator, never silently no-op —
# the boundary's hard guarantee (round-26). Independent of node.
_rawonly = {"type": "redirect", "params": {"status_code": 301, "target_expression": "http.host"},
            "condition": {"always": True}}
_fatal = False
try:
    _gen37._generate_op_js(_rawonly, "cff")
except _gen37.LoweredError:
    _fatal = True
check("#44 raw-only converted op (no LoweredValue) → LoweredError FATAL (no silent fallback)",
      _fatal)


if __name__ == "__main__":
    report()
