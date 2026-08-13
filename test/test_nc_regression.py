#!/usr/bin/env python3
"""Split from test_nc_provenance.py (round-2 test-split; behavior-preserving).
Shared setup + helpers live in test_nc_common."""
from test_nc_common import *  # noqa: F401,F403

print("== FINDING (spine) 55: inline custom-error status must be a real HTTP status (r27 review-2 #5) ==")
def _ce(status):
    return _proc.process_custom_error_rule({"id": "ce", "description": "d", "expression": "true",
        "action_parameters": {"content": "<h1>err</h1>", "content_type": "text/html",
                              "status_code": status}}, {}, "response")
# An out-of-range / ill-typed PRESENT status_code is NC — validated on PRESENCE, never rewritten
# by a truthiness fallback (round-27 review-3 finding 2). 0 is a PRESENT invalid status → NC too
# (was: 0 is falsy → silently became 500 and EXACT, the bug the old test wrongly blessed).
for _bad in (99, 600, 999, "500", 0, False):
    _r = _ce(_bad)
    check(f"#55 inline custom-error status {_bad!r} -> NON_CONVERTIBLE",
          _status_of(_r if isinstance(_r, list) else [_r]) == "NON_CONVERTIBLE",
          f"got {_status_of(_r if isinstance(_r, list) else [_r])}")
# INLINE content is NON_CONVERTIBLE (step-3 decision #1) regardless of status — no CFF+KVS inline
# path. A well-formed inline rule (valid status or none) reaches the inline-NC branch AFTER the
# source-schema checks, so it gets the "inline content" reason (not a schema reason).
_ce_nostatus = _proc.process_custom_error_rule({"id": "ce", "description": "d", "expression": "true",
    "action_parameters": {"content": "<h1>err</h1>"}}, {}, "response")
_ce_nostatus_d = _ce_nostatus if isinstance(_ce_nostatus, dict) else _ce_nostatus[0]
check("#55 inline custom-error (well-formed, no status) -> NON_CONVERTIBLE with inline reason",
      _ce_nostatus_d.get("type") == "non_convertible"
      and "inline content" in _ce_nostatus_d.get("reason", ""), f"got {_ce_nostatus_d}")
# content-ABSENT custom-error still converts to a NATIVE custom_error_response (the KEPT path):
# intercept the origin status from the condition, remap via status_code.
_ce_native = _proc.process_custom_error_rule({"id": "ce", "description": "d",
    "expression": "http.response.code eq 404", "action_parameters": {"status_code": 404}}, {}, "response")
_ce_native = _ce_native if isinstance(_ce_native, dict) else _ce_native[0]
check("#55 content-ABSENT custom-error -> custom_error_response (native path kept)",
      _ce_native.get("type") == "custom_error_response", f"got {_ce_native}")
# custom-error SOURCE schema: malformed action_parameters -> NC, no crash (finding 2).
for _lbl, _ap in [("None", None), ("list", []), ("unknown sibling", {"content": "x", "future": 1}),
                  ("non-string content", {"content": 123}),
                  ("empty content_type", {"content": "x", "content_type": ""})]:
    _r = _proc.process_custom_error_rule({"id": "ce", "description": "d", "expression": "true",
                                          "action_parameters": _ap}, {}, "response")
    check(f"#55 custom-error action_parameters {_lbl} -> NON_CONVERTIBLE (no crash)",
          _status_of(_r if isinstance(_r, list) else [_r]) == "NON_CONVERTIBLE",
          f"got {_status_of(_r if isinstance(_r, list) else [_r])}")
# an explicit EMPTY content "" is STILL inline (presence, not truthiness) → NON_CONVERTIBLE.
_ce_empty = _proc.process_custom_error_rule({"id": "ce", "description": "d", "expression": "true",
    "action_parameters": {"content": "", "status_code": 404}}, {}, "response")
check("#55 inline custom-error with empty content '' -> NON_CONVERTIBLE (empty is still inline)",
      _status_of(_ce_empty if isinstance(_ce_empty, list) else [_ce_empty]) == "NON_CONVERTIBLE",
      f"got {_ce_empty}")
# a VALID status + inline content is STILL NON_CONVERTIBLE (inline body has no native equivalent).
_ce503 = _ce(503)
check("#55 inline custom-error valid status 503 + content -> NON_CONVERTIBLE (inline body)",
      _status_of(_ce503 if isinstance(_ce503, list) else [_ce503]) == "NON_CONVERTIBLE", f"got {_ce503}")
# op contract (Step 5): serve_error_inline is a RETIRED op type — rejected as UNKNOWN regardless of
# params (inline custom-error is permanently NC; a stray op fails loud, never re-renders the path).
_seri55 = _cep.validate_viewer_op_contract({"type": "serve_error_inline",
    "params": {"kvs_key": "error:x", "status_code": 999}}, "request")
check("#55 retired serve_error_inline op type is rejected as unknown (fails loud)",
      isinstance(_seri55, str) and "unknown op type" in _seri55, f"got {_seri55!r}")
# ── review-4 finding 3: content_type is only legal WITH content (else silently dropped) ──
_ce_ct_nocontent = _proc.process_custom_error_rule({"id": "ce", "description": "d",
    "expression": "true", "action_parameters": {"status_code": 404, "content_type": "text/html"}},
    {}, "response")
check("#55 content_type without content -> NON_CONVERTIBLE (not silently dropped)",
      _status_of(_ce_ct_nocontent if isinstance(_ce_ct_nocontent, list) else [_ce_ct_nocontent])
      == "NON_CONVERTIBLE",
      f"got {_status_of(_ce_ct_nocontent if isinstance(_ce_ct_nocontent, list) else [_ce_ct_nocontent])}")
# content_type WITH content passes the source schema (content_type is legal with content), but the
# rule is inline → NON_CONVERTIBLE (the schema check is distinct from the inline-body policy).
_ce_ct_ok = _proc.process_custom_error_rule({"id": "ce", "description": "d", "expression": "true",
    "action_parameters": {"content": "<h1>x</h1>", "content_type": "text/html", "status_code": 404}},
    {}, "response")
check("#55 content_type WITH content -> NON_CONVERTIBLE (schema OK, but inline body)",
      _status_of(_ce_ct_ok if isinstance(_ce_ct_ok, list) else [_ce_ct_ok]) == "NON_CONVERTIBLE",
      f"got {_ce_ct_ok}")

print("== FINDING (spine) 56: full_uri wildcard survives the FULL chain (r27 review-4 #2) ==")
# The parser splits a full_uri wildcard into host_pattern/path_pattern/scheme derived fields. A
# real redirect rule gated on one must survive process_domain → JSON round-trip → chunk validator
# → generator (the SINK gate + leaf schema must ALLOW those derived fields — a direct
# condition_to_js test wouldn't exercise the sink gate that regressed).
_DC56 = {"hostname": "fu.example.com", "apex_domain": "example.com", "origin_type": "custom",
         "origin_content": "o.net", "sanitized_name": "fu_example_com"}
_ir56 = _pre.process_domain("fu.example.com", _DC56,
    {"redirect": [{"id": "rd", "enabled": True,
        "expression": 'http.request.full_uri wildcard "https://fu.example.com/old/*"',
        "action": "redirect", "action_parameters": {"from_value": {"status_code": 301,
            "preserve_query_string": False, "target_url": {"value": "https://fu.example.com/new"}}}}]},
    {}, {}, {})
_redir56 = [o for b in _ir56["cache_behaviors"] for o in b.get("viewer_request_ops", [])
            if o.get("type") == "redirect"]
check("#56 full_uri wildcard redirect survived process_domain (op exists, not FATAL/NC)",
      len(_redir56) == 1, f"redirect ops={len(_redir56)}")
check("#56 the redirect op's full_uri wildcard condition carries derived host/path patterns",
      _redir56 and _redir56[0]["condition"].get("field") == "full_uri"
      and _redir56[0]["condition"].get("host_pattern") and _redir56[0]["condition"].get("path_pattern"),
      f"cond={_redir56[0]['condition'] if _redir56 else None}")
# the persisted op passes the full viewer-op gate (leaf schema + typed semantics).
check("#56 the persisted redirect op passes validate_viewer_op",
      _redir56 and _cep.validate_viewer_op(
          {k: v for k, v in _redir56[0].items() if not k.startswith("_")}, "request") is None,
      f"got {_cep.validate_viewer_op({k: v for k, v in _redir56[0].items() if not k.startswith('_')}, 'request') if _redir56 else 'no op'}")
# it renders to real JS (host + path wildcard match), not `false`.
if not _NODE2:
    skip("#56 full_uri wildcard renders (generator)", "node not installed")
else:
    _fujs = " | ".join(_gen37._generate_op_js(
        {k: v for k, v in _redir56[0].items() if not k.startswith("_")}, "cff"))
    check("#56 full_uri wildcard renders a host+path match (not `false`)",
          "statusCode: 301" in _fujs and "false" not in _fujs.split("if (")[1].split(")")[0]
          if "if (" in _fujs else False, f"js={_fujs[:160]}")
# a non-full_uri leaf carrying host_pattern is rejected by the leaf schema (derived fields are
# exclusive to the full_uri wildcard shape).
check("#56 host_pattern on a non-full_uri leaf -> structural reject",
      isinstance(_cep.validate_condition_tree({"field": "host", "op": "eq", "value": "a",
          "host_pattern": "x"}), str))

print("== FINDING (spine) 57: full_uri SCHEME-WILDCARD + one-sided/tampered rejects (step 2) ==")
# `*://host/path` parses to scheme=None. The OLD leaf schema rejected scheme=None
# (`not in ("http","https")`), so a real `*://host/path` redirect FATAL'd at the sink. It must now
# survive the full chain; a one-sided (host-only / path-only) or tampered-derived leaf must be
# rejected (the generator reads BOTH derived fields — cdn-generate-js ~397/402).
_ir57 = _pre.process_domain("fu2.example.com",
    {"hostname": "fu2.example.com", "apex_domain": "example.com", "origin_type": "custom",
     "origin_content": "o.net", "sanitized_name": "fu2_example_com"},
    {"redirect": [{"id": "rd2", "enabled": True,
        "expression": 'http.request.full_uri wildcard "*://fu2.example.com/old/*"',
        "action": "redirect", "action_parameters": {"from_value": {"status_code": 301,
            "preserve_query_string": False, "target_url": {"value": "https://fu2.example.com/new"}}}}]},
    {}, {}, {})
_redir57 = [o for b in _ir57["cache_behaviors"] for o in b.get("viewer_request_ops", [])
            if o.get("type") == "redirect"]
check("#57 scheme-wildcard `*://` redirect survived process_domain (not FATAL/NC)",
      len(_redir57) == 1, f"redirect ops={len(_redir57)}")
check("#57 condition carries host/path derived fields with scheme=None",
      _redir57 and _redir57[0]["condition"].get("host_pattern")
      and _redir57[0]["condition"].get("path_pattern")
      and _redir57[0]["condition"].get("scheme") is None,
      f"cond={_redir57[0]['condition'] if _redir57 else None}")
check("#57 persisted scheme-wildcard op passes validate_viewer_op (scheme=None accepted)",
      _redir57 and _cep.validate_viewer_op(
          {k: v for k, v in _redir57[0].items() if not k.startswith("_")}, "request") is None,
      f"got {_cep.validate_viewer_op({k: v for k, v in _redir57[0].items() if not k.startswith('_')}, 'request') if _redir57 else 'no op'}")
if not _NODE2:
    skip("#57 scheme-wildcard renders (generator)", "node not installed")
else:
    _fujs57 = " | ".join(_gen37._generate_op_js(
        {k: v for k, v in _redir57[0].items() if not k.startswith("_")}, "cff"))
    check("#57 scheme-wildcard renders a host+path match (not `false`)",
          "statusCode: 301" in _fujs57 and "false" not in _fujs57.split("if (")[1].split(")")[0]
          if "if (" in _fujs57 else False, f"js={_fujs57[:160]}")
check("#57 host_pattern-only leaf -> reject (path_pattern required)",
      isinstance(_cep.validate_condition_tree({"field": "full_uri", "op": "wildcard",
          "value": "*://h/p", "host_pattern": "h"}), str))
check("#57 path_pattern-only leaf -> reject (host_pattern required)",
      isinstance(_cep.validate_condition_tree({"field": "full_uri", "op": "wildcard",
          "value": "*://h/p", "path_pattern": "/p"}), str))
check("#57 well-formed scheme=None leaf (derived fields match value) -> accepted",
      _cep.validate_condition_tree({"field": "full_uri", "op": "wildcard", "value": "*://h/p",
          "host_pattern": "h", "path_pattern": "/p", "scheme": None}) is None)
check("#57 tampered derived host_pattern (disagrees with value) -> reject",
      isinstance(_cep.validate_condition_tree({"field": "full_uri", "op": "wildcard",
          "value": "*://h/p", "host_pattern": "EVIL", "path_pattern": "/p", "scheme": None}), str))

print("== FINDING (spine) 58: full_uri SCHEME/HOST-LESS wildcard `*/admin/*` (no derived fields) ==")
# `*/admin/*` has no scheme://host prefix, so _parse_full_uri_wildcard returns (None,None,None) and
# the parser emits a full_uri wildcard leaf WITHOUT derived fields; the generator reconstructs the
# absolute URL and matches it (cdn-generate-js ~408). This is a legit convertible shape — the leaf
# schema must NOT require derived fields on it. (Pre-existing bug: the pre-step-2 "neither" check AND
# step-2's blanket "require both" both FATAL'd it at the sink; confirmed NOT a step-2 regression.)
_ir58 = _pre.process_domain("ad.example.com",
    {"hostname": "ad.example.com", "apex_domain": "example.com", "origin_type": "custom",
     "origin_content": "o.net", "sanitized_name": "ad_example_com"},
    {"redirect": [{"id": "ra", "enabled": True,
        "expression": 'http.request.full_uri wildcard "*/admin/*"',
        "action": "redirect", "action_parameters": {"from_value": {"status_code": 301,
            "preserve_query_string": False, "target_url": {"value": "https://ad.example.com/new"}}}}]},
    {}, {}, {})
_redir58 = [o for b in _ir58["cache_behaviors"] for o in b.get("viewer_request_ops", [])
            if o.get("type") == "redirect"]
check("#58 no-derived `*/admin/*` redirect survived process_domain (not FATAL/NC)",
      len(_redir58) == 1, f"redirect ops={len(_redir58)}")
check("#58 the persisted no-derived op passes validate_viewer_op",
      _redir58 and _cep.validate_viewer_op(
          {k: v for k, v in _redir58[0].items() if not k.startswith("_")}, "request") is None,
      f"got {_cep.validate_viewer_op({k: v for k, v in _redir58[0].items() if not k.startswith('_')}, 'request') if _redir58 else 'no op'}")
check("#58 no-derived full_uri wildcard leaf -> validate_condition_tree accepts",
      _cep.validate_condition_tree({"field": "full_uri", "op": "wildcard",
          "value": "*/admin/*"}) is None)
check("#58 no-derived value but a stray host_pattern -> reject (require both)",
      isinstance(_cep.validate_condition_tree({"field": "full_uri", "op": "wildcard",
          "value": "*/admin/*", "host_pattern": "x"}), str))
if not _NODE2:
    skip("#58 `*/admin/*` renders (generator reconstruct branch)", "node not installed")
else:
    _fujs58 = " | ".join(_gen37._generate_op_js(
        {k: v for k, v in _redir58[0].items() if not k.startswith("_")}, "cff"))
    # STRONG assertion: the JS must reconstruct the absolute URL (host + uri concat) — a substring
    # unique to the reconstruct branch (the host/path branch emits two separate &&-joined wildcard
    # tests, never this concat). Guards against a future regression that wrongly routes */admin/*
    # through the derived host/path branch.
    check("#58 `*/admin/*` renders via the RECONSTRUCT branch (host+uri concat), redirect emitted",
          "'https://' + request.headers.host.value + request.uri" in _fujs58
          and "statusCode: 301" in _fujs58, f"js={_fujs58[:200]}")

print("== FINDING (spine) 59: numeric-geo condition fields → processor NC after the authority flip ==")
# NON_CONVERTIBLE_CONDITION_FIELDS now = {asnum,latitude,longitude,metro_code}. A numeric-geo
# condition must NC at the PROCESSOR (via the shared _screen_condition_semantics), never a sink FATAL,
# on EVERY condition-bearing family (the 7 that route through _screen_unmappable + the compression /
# cloud-connector bypass paths). The KEPT string-geo fields (country / continent) still convert.
import cdn_rule_processors as _p59
def _dom59(host, rules):
    ir = _pre.process_domain(host, {"hostname": host, "apex_domain": "example.com",
        "origin_type": "custom", "origin_content": "o.net", "sanitized_name": host.replace(".", "_")},
        rules, {}, {}, {})
    ops = [o.get("type") for b in ir["cache_behaviors"] for k in ("viewer_request_ops", "viewer_response_ops") for o in b.get(k, [])]
    ncs = [n for b in ir["cache_behaviors"] for n in b.get("non_convertible", [])]
    return ops, ncs
def _red59(e): return {"redirect": [{"id": "r", "enabled": True, "expression": e, "action": "redirect",
    "action_parameters": {"from_value": {"status_code": 301, "preserve_query_string": False,
        "target_url": {"value": "https://n59.example.com/n"}}}}]}
def _hdr59(ph, e): return {ph: [{"id": "h", "enabled": True, "expression": e, "action": "rewrite",
    "action_parameters": {"headers": {"X-T": {"operation": "set", "value": "v"}}}}]}
for _lbl, _host, _rules in [("redirect asnum", "n59a.example.com", _red59("(ip.src.asnum gt 1)")),
                            ("req-hdr latitude", "n59b.example.com", _hdr59("request_header", "(ip.src.lat gt 1.0)")),
                            ("resp-hdr metro", "n59c.example.com", _hdr59("response_header", '(ip.src.metro_code eq "x")'))]:
    _ops59, _ncs59 = _dom59(_host, _rules)
    check(f"#59 numeric-geo {_lbl} -> processor NC (no op, no FATAL)", not _ops59 and len(_ncs59) == 1,
          f"ops={_ops59} ncs={len(_ncs59)}")
_cr59 = _p59.process_compression_rule({"id": "c", "expression": "(ip.src.asnum gt 1)",
    "action_parameters": {"algorithms": [{"name": "gzip"}]}}, {}, "p")
check("#59 compression numeric-geo -> processor NC", _cr59.get("type") == "non_convertible", f"got {_cr59.get('type')}")
_cc59 = _p59.process_cloud_connector({"id": "cc", "expression": "(ip.src.lat gt 1.0)",
    "provider": "aws", "parameters": {"host": "o.net"}}, {}, "p")
check("#59 cloud-connector numeric-geo -> processor NC", _cc59.get("type") == "non_convertible", f"got {_cc59.get('type')}")
for _lbl, _e in [("country", '(ip.src.country eq "US")'), ("continent", '(ip.src.continent eq "EU")')]:
    _ops59k, _ncs59k = _dom59(f"k59{_lbl}.example.com", _red59(_e))
    check(f"#59 kept geo field {_lbl} still converts", "redirect" in _ops59k,
          f"ops={_ops59k} ncs={[n.get('reason','')[:40] for n in _ncs59k]}")

print("== FINDING (spine) 60: SOURCE vs INTERNAL function split — same to_string(ip.src), different outcome ==")
# Approach-C crux: to_string is NOT source-core, so a USER Cloudflare value using it is NC, but the
# INTERNAL True-Client-IP intrinsic (source=False) converts. The `origin` is PERSISTED so re-validation
# after the JSON round-trip keeps the distinction (else the persisted internal op would fail the sink).
import json as _json60
_usr60 = _proc.process_request_header_transform(
    _hdr_rule("X-Ip", {"operation": "set", "expression": "to_string(ip.src)"}), {}, "cff")
check("#60 USER header value to_string(ip.src) -> NON_CONVERTIBLE (source-narrowed)",
      _status_of(_usr60) == "NON_CONVERTIBLE", f"got {_status_of(_usr60)}")
_sub60 = _proc.process_request_header_transform(
    _hdr_rule("X-S", {"operation": "set", "expression": "substring(http.host, 0, 3)"}), {}, "cff")
check("#60 USER header value substring(...) -> NON_CONVERTIBLE (source-narrowed)",
      _status_of(_sub60) == "NON_CONVERTIBLE", f"got {_status_of(_sub60)}")
_int60 = _cep.lower_dynamic_value("to_string(ip.src)", "request_header",
                                  _cep.LOWERED_EMPTY_DELETE_HEADER, source=False)
check("#60 INTERNAL to_string(ip.src) (source=False) -> converts, raw preserved, origin=internal",
      isinstance(_int60, dict) and _int60.get("raw") == "to_string(ip.src)"
      and _int60.get("origin") == "internal", f"got {_int60!r}")
check("#60 internal LoweredValue re-verifies via the deep gate after a JSON round-trip (origin honored)",
      isinstance(_int60, dict) and _cep.validate_lowered_value(
          _json60.loads(_json60.dumps(_int60)), _cep.SLOT_REQUEST_HEADER_VALUE) is None,
      f"got {_cep.validate_lowered_value(_int60, _cep.SLOT_REQUEST_HEADER_VALUE) if isinstance(_int60, dict) else _int60!r}")
# discriminating control: the SAME value forced origin=source must be REJECTED by the deep gate (a
# real source value stays source-gated; origin reflects the producer, never user input).
_forge60 = _json60.loads(_json60.dumps(_int60)); _forge60["origin"] = "source"
check("#60 same value forced origin=source -> deep gate REJECTS (to_string not source-core)",
      isinstance(_cep.validate_lowered_value(_forge60, _cep.SLOT_REQUEST_HEADER_VALUE), str))

print("== FINDING (spine) 61: CORS credentials + wildcard -> whole-rule NON_CONVERTIBLE (step-3 #2) ==")
# Static Access-Control-Allow-Origin: * + Access-Control-Allow-Credentials: true → the WHOLE response
# header transform is NC (the Fetch/CORS standard forbids the combo; not faithfully convertible). NC
# the WHOLE rule (case-insensitive), never one leaf (that would leave the other + change CORS semantics).
def _rhx61(headers):
    return {"id": "cx", "description": "d", "expression": "true", "action": "rewrite",
            "action_parameters": {"headers": headers}}
def _st61(op, val): return {"operation": op, "value": val}
def _has_combo_nc61(r):
    return any(o.get("type") == "non_convertible" and "wildcard origin with credentials" in o.get("reason", "")
               for o in (r if isinstance(r, list) else [r]))
for _lbl, _hdrs in [
    ("set/set", {"Access-Control-Allow-Origin": _st61("set", "*"),
                 "Access-Control-Allow-Credentials": _st61("set", "true")}),
    ("add/add (example shape)", {"Access-Control-Allow-Origin": _st61("add", "*"),
                                 "Access-Control-Allow-Credentials": _st61("add", "true")}),
    ("case-insensitive names/value", {"access-control-allow-origin": _st61("set", "*"),
                                      "ACCESS-CONTROL-ALLOW-CREDENTIALS": _st61("set", "TRUE")}),
]:
    _r61 = _proc.process_response_header_transform(_rhx61(_hdrs), {}, "response")
    _ops61 = _r61 if isinstance(_r61, list) else [_r61]
    check(f"#61 CORS creds+wildcard [{_lbl}] -> whole-rule NON_CONVERTIBLE",
          _status_of(_ops61) == "NON_CONVERTIBLE" and _has_combo_nc61(_r61)
          and all(o.get("type") == "non_convertible" for o in _ops61),
          f"got {[o.get('type') for o in _ops61]}")
# CONTROLS: not the dangerous combo → the group scan must NOT fire (regardless of what they convert to).
_r61_public = _proc.process_response_header_transform(
    _rhx61({"Access-Control-Allow-Origin": _st61("set", "*")}), {}, "response")
check("#61 CONTROL ACAO:* alone (no credentials) -> NOT the CORS-combo NC (group scan doesn't fire)",
      not _has_combo_nc61(_r61_public))
_r61_specific = _proc.process_response_header_transform(
    _rhx61({"Access-Control-Allow-Origin": _st61("set", "https://app.example.com"),
            "Access-Control-Allow-Credentials": _st61("set", "true")}), {}, "response")
check("#61 CONTROL ACAC:true + SPECIFIC origin -> NOT the CORS-combo NC (only `*` triggers it)",
      not _has_combo_nc61(_r61_specific))

print("== FINDING (spine) 62: STEP-4 sink hardening — narrowed SOURCE NC's at the PROCESSOR, never FATALs the sink ==")
# The whole point of the scope reset (docs/conversion-policy.md): a legal-but-policy-NC SOURCE
# construct must become a first-class NC CLAIM at the PROCESSOR and NEVER reach _append_viewer_op —
# which would turn a source we simply don't convert into a whole-DOMAIN LedgerError (the recurring P1
# the reset killed). Run EACH narrowed category through the FULL process_domain and prove the sink
# contract: (a) NO LedgerError, (b) an NC claim owning real inventory leaves (report present), (c) NO
# viewer op emitted for the unit (it never reached the sink as a converted op). #59 covers numeric-geo
# via the legacy report; this is the ledger-level, explicit no-FATAL lock across ALL FOUR categories.
def _sink_int62(host, rules, unit_id):
    dc = {"hostname": host, "apex_domain": "example.com", "origin_type": "custom",
          "origin_content": "o.net", "sanitized_name": host.replace(".", "_")}
    fatal = _raises_ledger(lambda: _pre.process_domain(host, dc, rules, {}, {}, {}))
    if fatal is not None:
        return {"fatal": fatal}
    ir = _pre.process_domain(host, dc, rules, {}, {}, {})
    ops = [o["type"] for b in ir["cache_behaviors"]
           for k in ("viewer_request_ops", "viewer_response_ops") for o in b.get(k, [])]
    return {"fatal": None, "nc": _nc_keys(ir, unit_id), "leaves": _unit_leaves(ir, unit_id), "ops": ops}

_CATS62 = [
    ("numeric-geo (asnum condition)", "n62a.example.com", "r",
     {"redirect": [{"id": "r", "enabled": True, "expression": "(ip.src.asnum gt 1)", "action": "redirect",
        "action_parameters": {"from_value": {"status_code": 301, "preserve_query_string": False,
            "target_url": {"value": "https://n62.example.com/x"}}}}]}),
    ("long-tail source function (substring in a header value)", "n62b.example.com", "h",
     {"request_header": [{"id": "h", "enabled": True, "expression": "true", "action": "rewrite",
        "action_parameters": {"headers": {"X-S": {"operation": "set",
            "expression": "substring(http.host, 0, 3)"}}}}]}),
    ("custom-error inline content", "n62c.example.com", "ce",
     {"custom_error": [{"id": "ce", "enabled": True, "expression": "true", "action": "serve_error",
        "action_parameters": {"content": "<h1>x</h1>", "content_type": "text/html", "status_code": 503}}]}),
    ("CORS credentials + wildcard", "n62d.example.com", "cx",
     {"response_header": [{"id": "cx", "enabled": True, "expression": "true", "action": "rewrite",
        "action_parameters": {"headers": {
            "Access-Control-Allow-Origin": {"operation": "set", "value": "*"},
            "Access-Control-Allow-Credentials": {"operation": "set", "value": "true"}}}}]}),
]
for _lbl, _host, _uid, _rules in _CATS62:
    _r62 = _sink_int62(_host, _rules, _uid)
    check(f"#62 {_lbl}: process_domain does NOT raise LedgerError (NC'd at processor, not the sink)",
          _r62["fatal"] is None, f"FATAL: {_r62.get('fatal')}")
    check(f"#62 {_lbl}: produces a NON_CONVERTIBLE claim owning real leaves (report present)",
          _r62.get("fatal") is None and _r62["nc"] and set(_r62["nc"]) <= set(_r62["leaves"]),
          f"nc={_r62.get('nc')} leaves={_r62.get('leaves')}")
    check(f"#62 {_lbl}: NO viewer op emitted for the NC'd unit (never reached the sink as a converted op)",
          _r62.get("fatal") is None and not _r62["ops"], f"ops={_r62.get('ops')}")

print("== FINDING (spine) 63: STEP-4 sink hardening — _append_viewer_op still FATALs on INTERNAL producer bugs ==")
# The flip side, and the reviewer's guardrail: the sink is NOT loosened. A producer that emits a
# malformed op (unknown type, an `add` op, raw_expression residue, a bad LoweredValue, or a bad/absent
# condition) is a CONVERTER BUG and MUST FATAL at the single construction sink — never silently reach
# the persisted IR / generator. validate_viewer_op is unchanged; #50 proves the CONTRACT rejects these,
# this proves the SINK RAISES on them. Reuses _append_raises (base = a valid single-source op) so the
# ONLY variable is the injected fault. Step 4 confirms the sink handles producer bugs, it does NOT let
# policy-unsupported SOURCE bypass — that is already NC'd upstream (#62).
_BUGS63 = [
    ("unknown op type", dict(type="future_op", params={}, source_id="u")),
    ("header `add` op (no faithful CloudFront equivalent)", dict(type="add_request_header", source_id="u")),
    ("raw_expression residue (raw must not drive codegen)", dict(raw_expression="http.host", source_id="u")),
    ("bad LoweredValue (slot value gate)",
     dict(params={"name": "X", "value_lowered": {"kind": "bogus"}}, source_id="u")),
    ("bad condition shape (list, not a tree)", dict(condition=["not", "a", "dict"], source_id="u")),
    ("no structured condition (None on a converted op)", dict(condition=None, source_id="u")),
]
for _lbl, _kw in _BUGS63:
    check(f"#63 sink FATALs on producer bug: {_lbl}", _append_raises(**_kw) is not None,
          "expected LedgerError, got None (sink accepted a malformed op)")
# positive control: a valid single-source op is NOT over-rejected — Step 4 did not make the sink stricter.
check("#63 CONTROL: a valid single-source op still succeeds (no over-rejection)",
      _append_raises(source_kind="rule", source_id="u") is None)

print("== FINDING (spine) 64: continent value 'T1' (Tor pseudo-continent) -> processor NC (Block 1.5) ==")
# CloudFront's continent is DERIVED from the country code (continent KVS: ISO country →
# NA/EU/AS/AF/SA/OC/AN) and can NEVER be Cloudflare's Tor pseudo-continent "T1". A continent condition
# MENTIONING T1 is non-convertible in EVERY form — eq "T1" renders a never-match, ne "T1" an
# always-true branch, in {…T1…} can't match the T1 arm — all silent wrong conversions. NC at the
# PROCESSOR via the shared _screen_condition_semantics → validate_condition_semantics (op-agnostic),
# never a sink FATAL. Covers redirect + response-header paths to prove the shared screen fires.
for _lbl64, _host64, _rules64 in [
        ("redirect continent eq T1", "t64a.example.com", _red59('(ip.src.continent eq "T1")')),
        ("resp-hdr continent eq T1", "t64b.example.com", _hdr59("response_header", '(ip.src.continent eq "T1")')),
        ("redirect continent in {EU,T1}", "t64c.example.com", _red59('(ip.src.continent in {"EU" "T1"})')),
        ("redirect continent ne T1", "t64d.example.com", _red59('(ip.src.continent ne "T1")'))]:
    _ops64, _ncs64 = _dom59(_host64, _rules64)
    check(f"#64 {_lbl64} -> processor NC (no op, no FATAL)", not _ops64 and len(_ncs64) == 1,
          f"ops={_ops64} ncs={len(_ncs64)}")
# CONTROLS: a real continent value still converts — the screen is T1-specific, not continent-wide.
_ops64eu, _ncs64eu = _dom59("t64keu.example.com", _red59('(ip.src.continent eq "EU")'))
check("#64 CONTROL continent eq EU still converts (T1 screen is value-specific)",
      "redirect" in _ops64eu, f"ops={_ops64eu}")
_ops64set, _ncs64set = _dom59("t64kset.example.com", _red59('(ip.src.continent in {"EU" "NA"})'))
check("#64 CONTROL continent in {EU,NA} (no T1) still converts",
      "redirect" in _ops64set, f"ops={_ops64set}")


if __name__ == "__main__":
    report()
