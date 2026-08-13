#!/usr/bin/env python3
"""Split from test_nc_provenance.py (round-2 test-split; behavior-preserving).
Shared setup + helpers live in test_nc_common."""
from test_nc_common import *  # noqa: F401,F403

print("== FINDING (spine) 45: validate_lowered_value is the deep, SLOT-SPECIFIC persisted-IR gate ==")
# The persisted IR is INDEPENDENTLY re-verified from scratch — validate_lowered_value must NOT
# trust stored fields, and it keys on a SPECIFIC SLOT (round-27 finding 1), not a coarse context.
# Each case would pass a shallow/context-only check but is a lie or a slot violation; the gate must
# return a reason. A well-formed value in its correct slot returns None.
_V1 = _cep.LOWERED_SCHEMA_VERSION
_SREQ = _cep.SLOT_REQUEST_HEADER_VALUE
_SRESP = _cep.SLOT_RESPONSE_HEADER_VALUE
_SPATH = _cep.SLOT_REWRITE_PATH
_SQUERY = _cep.SLOT_REWRITE_QUERY
_SREDIR = _cep.SLOT_REDIRECT_TARGET
_good_lit = _cep.lower_literal_value("x", "request_header")
_good_dyn = _cep.lower_dynamic_value("concat(http.host, \"/x\")", "request_header",
                                     _cep.LOWERED_EMPTY_DELETE_HEADER)
check("#45 valid header literal in its slot -> None", _cep.validate_lowered_value(_good_lit, _SREQ) is None)
check("#45 valid header dynamic in its slot -> None", _cep.validate_lowered_value(_good_dyn, _SREQ) is None)

# ── round-27 finding 1: the four slot violations the coarse context gate let through ──
# (a) literal header + delete_header → would DELETE a static empty header the source set.
_lit_del = _cep.lower_literal_value("x", "request_header", _cep.LOWERED_EMPTY_DELETE_HEADER)
check("#45(1a) literal header + delete_header -> reason",
      isinstance(_cep.validate_lowered_value(_lit_del, _SREQ), str))
# (b) dynamic header + none → would KEEP a runtime-empty value (must delete on empty).
_dyn_none = _cep.lower_dynamic_value("concat(http.host, \"/x\")", "request_header",
                                     _cep.LOWERED_EMPTY_NONE)
check("#45(1b) dynamic header + none -> reason",
      isinstance(_cep.validate_lowered_value(_dyn_none, _SREQ), str))
# (c) empty literal rewrite PATH → would emit request.uri = ''.
_emptypath = _cep.lower_literal_value("", "url_rewrite", _cep.LOWERED_EMPTY_NONE)
check("#45(1c) empty literal rewrite path -> reason",
      isinstance(_cep.validate_lowered_value(_emptypath, _SPATH), str))
# (d) dynamic query + clear_query → would DISCARD the AST and blindly clear the query.
_dynq_clear = dict(_cep.lower_dynamic_value("concat(http.host, \"a\")", "url_rewrite",
                                            _cep.LOWERED_EMPTY_NONE))
_dynq_clear["empty_behavior"] = _cep.LOWERED_EMPTY_CLEAR_QUERY   # forge the illegal combo
check("#45(1d) dynamic rewrite query + clear_query -> reason",
      isinstance(_cep.validate_lowered_value(_dynq_clear, _SQUERY), str))
# the LEGAL counterparts of (a)-(d) all pass:
check("#45(1) header dynamic+delete OK", _cep.validate_lowered_value(_good_dyn, _SREQ) is None)
check("#45(1) rewrite path literal (non-empty)+none OK",
      _cep.validate_lowered_value(_cep.lower_literal_value("/p", "url_rewrite"), _SPATH) is None)
check("#45(1) empty query literal + clear_query OK",
      _cep.validate_lowered_value(_cep.lower_literal_value("", "url_rewrite", _cep.LOWERED_EMPTY_CLEAR_QUERY), _SQUERY) is None)
# path vs query SHARE context url_rewrite but are DIFFERENT slots: a clear_query value is legal in
# the query slot, ILLEGAL in the path slot (the coarse context gate couldn't tell them apart).
check("#45(1) clear_query value rejected in the PATH slot (slot > context)",
      isinstance(_cep.validate_lowered_value(
          _cep.lower_literal_value("", "url_rewrite", _cep.LOWERED_EMPTY_CLEAR_QUERY), _SPATH), str))

# ── the round-26 lie/shape checks, now slot-keyed ──
# LYING result_type: ast is len(...) (a number) but result_type claims string
_lying = dict(_good_dyn)
_lying["ast"] = _cep.parse_dynamic_expression("len(http.host)")   # number-typed tree
_lying["result_type"] = "string"                                  # the lie
check("#45 lying result_type (ast=len→number, claims string) -> reason",
      isinstance(_cep.validate_lowered_value(_lying, _SREQ), str))
# WRONG context: a value lowered for response_header presented in a request_header slot
check("#45 context mismatch (response value in request slot) -> reason",
      isinstance(_cep.validate_lowered_value(_cep.lower_literal_value("x", "response_header"), _SREQ), str))
# wrong schema_version (a future/drifted IR)
_badver = dict(_good_lit); _badver["schema_version"] = _V1 + 99
check("#45 wrong schema_version -> reason",
      isinstance(_cep.validate_lowered_value(_badver, _SREQ), str))
# unknown extra field on a literal (a leaf that would ride an EXACT claim un-checked)
_extra = dict(_good_lit); _extra["surprise"] = 1
check("#45 unknown extra field on a literal -> reason",
      isinstance(_cep.validate_lowered_value(_extra, _SREQ), str))
# non-string literal value
_nonstr = dict(_good_lit); _nonstr["value"] = 123
check("#45 non-string literal value -> reason",
      isinstance(_cep.validate_lowered_value(_nonstr, _SREQ), str))
# empty literal as a REDIRECT target (no faithful meaning) -> reason; but empty header is OK
check("#45 empty literal redirect target -> reason",
      isinstance(_cep.validate_lowered_value(_cep.lower_literal_value("", "redirect"), _SREDIR), str))
check("#45 empty literal header value -> None (empty header is legal)",
      _cep.validate_lowered_value(_cep.lower_literal_value("", "response_header"), _SRESP) is None)
# dynamic ast that FAILS the contract at reload (rewrite-only fn presented as a header value)
_ctxbad = _cep.lower_dynamic_value("regex_replace(http.host, \"a\", \"b\")", "url_rewrite")  # valid there
check("#45 rewrite-only fn dynamic is valid in the rewrite-path slot -> None",
      _cep.validate_lowered_value(_ctxbad, _SPATH) is None)
_ctxbad2 = dict(_ctxbad); _ctxbad2["context"] = "request_header"   # same ast, lie the context
_ctxbad2["empty_behavior"] = _cep.LOWERED_EMPTY_DELETE_HEADER
check("#45 rewrite-only fn ast presented as a header value -> reason (contract re-run on reload)",
      isinstance(_cep.validate_lowered_value(_ctxbad2, _SREQ), str))
# ── round-27 finding 3: a literal AST of a non-primitive type can't fake a string result ──
for _badval, _lbl in [({"x": 1}, "dict"), ([1], "list"), (None, "null")]:
    _fake = dict(_good_dyn)
    _fake["ast"] = {"type": "literal", "value": _badval}
    _fake["result_type"] = "string"
    check(f"#45(3) literal AST value={_lbl} claiming string -> reason",
          isinstance(_cep.validate_lowered_value(_fake, _SREQ), str))
# non-dict / missing-kind / bad slot
check("#45 non-dict LoweredValue -> reason", isinstance(_cep.validate_lowered_value("nope", _SREQ), str))
check("#45 unknown kind -> reason",
      isinstance(_cep.validate_lowered_value({"schema_version": _V1, "kind": "bogus",
                 "context": "request_header", "empty_behavior": "none"}, _SREQ), str))
check("#45 unknown slot -> reason",
      isinstance(_cep.validate_lowered_value(_good_lit, "not_a_slot"), str))

print("== FINDING (spine) 46: internal header producers emit valid LoweredValues (full chain) ==")
# The 3 internal producers (RHP rehome, browser_ttl, True-Client-IP) were migrated to LoweredValue
# (round-27). Drive the REAL producer, JSON round-trip its op (accumulator survival), and re-verify
# with the deep gate — the same guarantee the wired processors have. True-Client-IP must be a
# DYNAMIC intrinsic (to_string(ip.src)), NOT a $viewer_ip string sentinel.
_DC46 = {"hostname": "tci.example.com", "apex_domain": "example.com", "origin_type": "custom",
         "origin_content": "o.net", "sanitized_name": "tci_example_com"}


def _tci_op():
    ir = _pre.make_empty_ir(_DC46)
    beh = _pre.find_or_create_behavior(ir, "", _DC46, "o.net")
    _pre._process_managed_transforms(
        ir, {"managed_request_headers": [{"id": "add_true_client_ip_headers", "enabled": True}],
             "managed_response_headers": []}, beh)
    return _js44.loads(_js44.dumps(beh["viewer_request_ops"][0]))   # accumulator round-trip


_tci = _tci_op()
check("#46 True-Client-IP op is a set_request_header", _tci["type"] == "set_request_header")
check("#46 True-Client-IP carries NO raw $viewer_ip sentinel (params.value absent)",
      "value" not in _tci["params"] and _tci["params"].get("value_lowered", {}).get("kind") == "dynamic")
check("#46 True-Client-IP value_lowered re-verifies against request_header (deep gate)",
      _cep.validate_lowered_value(_tci["params"]["value_lowered"], _cep.SLOT_REQUEST_HEADER_VALUE) is None)
check("#46 True-Client-IP lowered from the ip.src intrinsic (raw = to_string(ip.src))",
      _tci["params"]["value_lowered"].get("raw") == "to_string(ip.src)")

if not _NODE2:
    skip("#46 True-Client-IP full chain (generator→Node)", "node not installed")
else:
    # generator renders the RELOADED op; Node proves it evaluates to the viewer IP intrinsic.
    _tbody = " | ".join(_gen37._generate_op_js(_tci, "cff")).strip().replace(" | ", "\n")
    _tsrc = ("const request={headers:{}}; const event={viewer:{ip:'203.0.113.7'}};\n"
             + _tbody + "\nprocess.stdout.write(JSON.stringify(request.headers['true-client-ip'].value));")
    _tout = _subprocess.run([_NODE2, "-e", _tsrc], capture_output=True, text=True, timeout=20)
    check("#46 True-Client-IP full chain → header set to event.viewer.ip",
          _tout.returncode == 0 and _js44.loads(_tout.stdout) == "203.0.113.7",
          f"rc={_tout.returncode} out={_tout.stdout!r} err={_tout.stderr[:160]}")

# ── browser_ttl internal producer: cache rule → set_response_header(cache-control) LoweredValue ──
# (round-27: the reviewer noted #46 only exercised True-Client-IP through the generator; cover the
# other two internal producers' FULL chain too — real process_domain → JSON round-trip → deep gate
# → generator → Node.)
_DC46b = {"hostname": "bt.example.com", "apex_domain": "example.com", "origin_type": "custom",
          "origin_content": "o.net", "sanitized_name": "bt_example_com"}
_ir46bt = _pre.process_domain("bt.example.com", _DC46b,
    {"cache": [{"id": "bt", "enabled": True, "expression": 'http.request.uri.path eq "/x"',
                "action": "set_cache_settings",
                "action_parameters": {"browser_ttl": {"mode": "override_origin", "default": 60}}}]},
    {}, {}, {})
_bt_ops = [_js44.loads(_js44.dumps(o)) for b in _ir46bt["cache_behaviors"]
           for o in b.get("viewer_response_ops", [])
           if o.get("type") == "set_response_header" and o["params"].get("name") == "cache-control"]
check("#46 browser_ttl → a set_response_header(cache-control) op with a valid LoweredValue",
      len(_bt_ops) >= 1
      and _cep.validate_lowered_value(_bt_ops[0]["params"]["value_lowered"],
                                      _cep.SLOT_RESPONSE_HEADER_VALUE) is None,
      f"ops={_bt_ops}")
if not _NODE2:
    skip("#46 browser_ttl full chain (generator→Node)", "node not installed")
elif _bt_ops:
    _btbody = " | ".join(_gen37._generate_op_js(_bt_ops[0], "cff")).strip().replace(" | ", "\n")
    # the browser_ttl rule is scoped to uri.path eq "/x", so the generated JS is guarded — set
    # request.uri to the matching path so the guarded body runs.
    _btsrc = ("const response={headers:{}}; const request={uri:'/x', headers:{}};\n"
              + _btbody + "\nprocess.stdout.write(JSON.stringify(response.headers['cache-control'].value));")
    _btout = _subprocess.run([_NODE2, "-e", _btsrc], capture_output=True, text=True, timeout=20)
    check("#46 browser_ttl full chain → Cache-Control: max-age=60",
          _btout.returncode == 0 and _js44.loads(_btout.stdout) == "max-age=60",
          f"rc={_btout.returncode} out={_btout.stdout!r} err={_btout.stderr[:160]}")

# ── RHP-rehome internal producer: a security header forced to CFF by a same-header CFF writer ──
# A static security header normally lands in the native RHP; but if a DYNAMIC set for the SAME
# header also exists (one-writer-per-header), the static one is REHOMED to a viewer-response CFF.
# Prove the rehomed op carries a valid LoweredValue and runs.
_DC46c = {"hostname": "rh.example.com", "apex_domain": "example.com", "origin_type": "custom",
          "origin_content": "o.net", "sanitized_name": "rh_example_com"}
_ir46rh = _pre.process_domain("rh.example.com", _DC46c,
    {"response_header": [
        {"id": "s1", "enabled": True, "expression": "true", "action": "rewrite",
         "action_parameters": {"headers": {"X-Frame-Options": {"operation": "set", "value": "SAMEORIGIN"}}}},
        {"id": "s2", "enabled": True, "expression": "true", "action": "rewrite",
         "action_parameters": {"headers": {"X-Frame-Options": {"operation": "set",
             "expression": "http.host"}}}}]},
    {}, {}, {})
_rh_ops = [_js44.loads(_js44.dumps(o)) for b in _ir46rh["cache_behaviors"]
           for o in b.get("viewer_response_ops", [])
           if o.get("type") == "set_response_header"
           and o["params"].get("name", "").lower() == "x-frame-options"
           and o["params"].get("value_lowered", {}).get("kind") == "literal"]
check("#46 RHP-rehome → a rehomed set_response_header literal op with a valid LoweredValue",
      len(_rh_ops) >= 1
      and _cep.validate_lowered_value(_rh_ops[0]["params"]["value_lowered"],
                                      _cep.SLOT_RESPONSE_HEADER_VALUE) is None,
      f"ops={[o['params'] for o in _rh_ops]}")
if not _NODE2:
    skip("#46 RHP-rehome full chain (generator→Node)", "node not installed")
elif _rh_ops:
    _rhbody = " | ".join(_gen37._generate_op_js(_rh_ops[0], "cff")).strip().replace(" | ", "\n")
    _rhsrc = ("const response={headers:{}}; const request={headers:{}};\n"
              + _rhbody + "\nprocess.stdout.write(JSON.stringify(response.headers['x-frame-options'].value));")
    _rhout = _subprocess.run([_NODE2, "-e", _rhsrc], capture_output=True, text=True, timeout=20)
    check("#46 RHP-rehome full chain → X-Frame-Options: SAMEORIGIN",
          _rhout.returncode == 0 and _js44.loads(_rhout.stdout) == "SAMEORIGIN",
          f"rc={_rhout.returncode} out={_rhout.stdout!r} err={_rhout.stderr[:160]}")


print("== FINDING (spine) 47: header transform OUTER-object schema (no crash, no dropped leaf) ==")
# The header processors used to do rule["action_parameters"].get("headers", {}).items() — a
# non-dict action_parameters AttributeError'd, a non-dict `headers` crashed .items(), an unknown
# sibling under action_parameters was silently ignored (then the rule falsely claimed EXACT), and
# a non-dict header_config crashed .get(). round-27 finding 3: each is now a clean NON_CONVERTIBLE.
_outer_cases = [
    ("action_parameters=None", {"id": "h", "enabled": True, "expression": "true",
        "action": "rewrite", "action_parameters": None}),
    ("action_parameters=list", {"id": "h", "enabled": True, "expression": "true",
        "action": "rewrite", "action_parameters": []}),
    ("action_parameters unknown sibling", {"id": "h", "enabled": True, "expression": "true",
        "action": "rewrite", "action_parameters": {"headers": {"X": {"operation": "set",
            "value": "v"}}, "future_field": 1}}),
    ("headers=None", {"id": "h", "enabled": True, "expression": "true", "action": "rewrite",
        "action_parameters": {"headers": None}}),
    ("headers=list", {"id": "h", "enabled": True, "expression": "true", "action": "rewrite",
        "action_parameters": {"headers": []}}),
    ("headers empty", {"id": "h", "enabled": True, "expression": "true", "action": "rewrite",
        "action_parameters": {"headers": {}}}),
]
def _status_any(out):
    # A whole-rule outer NC returns a BARE dict; a per-header result returns a LIST. Normalize
    # so the assertion covers both shapes (both are legitimate processor outputs).
    return _status_of(out if isinstance(out, list) else [out])


for _lbl, _rule in _outer_cases:
    for _phase, _fn in (("request", _proc.process_request_header_transform),
                        ("response", _proc.process_response_header_transform)):
        try:
            _st = _status_any(_fn(_rule, {}, _phase))
            _ok = _st == "NON_CONVERTIBLE"
            _dt = f"got {_st}"
        except Exception as _e:      # a crash is the bug this finding fixes
            _ok = False
            _dt = f"CRASHED: {type(_e).__name__}: {_e}"
        check(f"#47 {_phase}: {_lbl} -> NON_CONVERTIBLE (no crash)", _ok, _dt)
# a non-dict header_config NC's just that header, leaving a well-formed sibling convertible.
_mixed = {"id": "h", "enabled": True, "expression": "true", "action": "rewrite",
          "action_parameters": {"headers": {"X-Bad": "not-a-dict",
                                             "X-Good": {"operation": "set", "value": "v"}}}}
_mixed_ops = _proc.process_request_header_transform(_mixed, {}, "request")
check("#47 non-dict header_config NC's only itself (sibling still converts)",
      any(o.get("type") == "non_convertible" for o in _mixed_ops)
      and any(o.get("type") == "set_request_header" for o in _mixed_ops),
      f"ops={[o.get('type') for o in _mixed_ops]}")

print("== FINDING (spine) 48: viewer-response CFF outcome = LOSSY; request CFF = EXACT (r27 #5) ==")
# The viewer-response CFF does NOT run on CloudFront-generated error responses, so a response
# header set/dynamic/remove is LOSSY_WITH_WARNING (was wrongly EXACT). A REQUEST header uses the
# viewer-request CFF (always runs) → EXACT. Cover all three op kinds on both phases.
for _kind, _cfg in [("static set", {"operation": "set", "value": "v"}),
                    ("dynamic set", {"operation": "set", "expression": "http.host"}),
                    ("remove", {"operation": "remove"})]:
    _rs = _status_of(_proc.process_response_header_transform(_hdr_rule("X-P", _cfg), {}, "response"))
    check(f"#48 response {_kind} -> LOSSY_WITH_WARNING (viewer-response error gap)",
          _rs == "LOSSY_WITH_WARNING", f"got {_rs}")
    # request has set/remove/dynamic-set (no `add`) — all convert EXACT (viewer-request CFF).
    _qs = _status_of(_proc.process_request_header_transform(_hdr_rule("X-P", _cfg), {}, "request"))
    check(f"#48 request {_kind} -> EXACT (viewer-request CFF always runs)",
          _qs == "EXACT", f"got {_qs}")
# the LOSSY reason names the error-response gap (mechanism, not CORS-specific).
_r48 = _proc.process_response_header_transform(_hdr_rule("X-P", {"operation": "set", "value": "v"}), {}, "response")[0]
check("#48 the LOSSY reason names the viewer-response error-response gap",
      "error responses" in (_r48.get("outcome_reason") or ""), f"reason={_r48.get('outcome_reason')!r}")
# a NATIVE-RHP security header stays EXACT (fully covered by the RHP, no CFF gap).
_sec48 = _unit_claim(_rh31("Strict-Transport-Security", {"operation": "set", "value": "max-age=31536000"}), "h")
check("#48 native-RHP security header stays EXACT (RHP covers error responses)",
      (_sec48 or {}).get("status") == "EXACT", f"got {(_sec48 or {}).get('status')}")

print("== FINDING (spine) 49: header `remove` rejects unknown sibling fields (r27 #4) ==")
# {operation:remove, future:x} used to become an EXACT remove owning the whole header subtree —
# `future` falsely claimed converted. Now NC (unknown sibling). A clean remove still converts.
for _phase, _fn in (("response", _proc.process_response_header_transform),
                    ("request", _proc.process_request_header_transform)):
    _ru = _status_of(_fn(_hdr_rule("X-R", {"operation": "remove", "future": "x"}), {}, _phase))
    check(f"#49 {_phase} remove + unknown sibling 'future' -> NON_CONVERTIBLE",
          _ru == "NON_CONVERTIBLE", f"got {_ru}")
    # also a set with an unknown sibling
    _su = _status_of(_fn(_hdr_rule("X-R", {"operation": "set", "value": "v", "future": "x"}), {}, _phase))
    check(f"#49 {_phase} set + unknown sibling 'future' -> NON_CONVERTIBLE",
          _su == "NON_CONVERTIBLE", f"got {_su}")

print("== FINDING (spine) 50: persisted-IR op contract rejects malformed ops (r27 #2) ==")
# validate_viewer_op_contract is the shared authority. Prove the reviewer's counterexamples are
# rejected (the chunk gate + the _append_viewer_op sink both call it).
_good_redir = _cep.lower_literal_value("https://x", "redirect")
_good_rhv = _cep.lower_literal_value("v", "request_header")
_c50 = [
    ("unknown op type", {"type": "future_op", "params": {}}, "request"),
    ("redirect status 999", {"type": "redirect", "params": {"status_code": 999,
        "preserve_query_string": False, "target": _good_redir}}, "request"),
    ("preserve_query_string not bool", {"type": "redirect", "params": {"status_code": 301,
        "preserve_query_string": "false", "target": _good_redir}}, "request"),
    ("legacy target_expression beside target", {"type": "redirect", "params": {"status_code": 301,
        "preserve_query_string": False, "target": _good_redir, "target_expression": "http.host"}}, "request"),
    ("legacy value_expression beside value_lowered", {"type": "set_request_header",
        "params": {"name": "X", "value_lowered": _good_rhv, "value_expression": "http.host"}}, "request"),
    ("redirect in the response phase", {"type": "redirect", "params": {"status_code": 301,
        "preserve_query_string": False, "target": _good_redir}}, "response"),
    ("unknown param on a header op", {"type": "set_request_header",
        "params": {"name": "X", "value_lowered": _good_rhv, "surprise": 1}}, "request"),
    ("invalid header name", {"type": "set_request_header",
        "params": {"name": "X Y", "value_lowered": _good_rhv}}, "request"),
]
for _lbl, _op, _ph in _c50:
    check(f"#50 op contract rejects: {_lbl}",
          isinstance(_cep.validate_viewer_op_contract(_op, _ph), str),
          f"got {_cep.validate_viewer_op_contract(_op, _ph)!r}")
# a well-formed op of each wired type passes (no over-rejection).
check("#50 well-formed redirect passes",
      _cep.validate_viewer_op_contract({"type": "redirect", "params": {"status_code": 301,
          "preserve_query_string": True, "target": _good_redir}}, "request") is None)
check("#50 well-formed set_request_header passes",
      _cep.validate_viewer_op_contract({"type": "set_request_header",
          "params": {"name": "X-Ok", "value_lowered": _good_rhv}}, "request") is None)

print("== FINDING (spine) 51: RHP-rehome is LOSSY, shared gap reason (r27 review-2 #1) ==")
# A static security header REHOMED to the viewer-response CFF (forced by a same-header dynamic set)
# runs in the SAME function as the dynamic set → shares the error-response gap → LOSSY, not EXACT.
_DC51 = {"hostname": "rh2.example.com", "apex_domain": "example.com", "origin_type": "custom",
         "origin_content": "o.net", "sanitized_name": "rh2_example_com"}
_ir51 = _pre.process_domain("rh2.example.com", _DC51,
    {"response_header": [
        {"id": "st", "enabled": True, "expression": "true", "action": "rewrite",
         "action_parameters": {"headers": {"X-Frame-Options": {"operation": "set", "value": "SAMEORIGIN"}}}},
        {"id": "dy", "enabled": True, "expression": "true", "action": "rewrite",
         "action_parameters": {"headers": {"X-Frame-Options": {"operation": "set", "expression": "http.host"}}}}]},
    {}, {}, {})
_rh_claims = [c for c in _ir51["_claims"] if c["status"] != "NON_CONVERTIBLE"]
check("#51 rehomed static + dynamic X-Frame-Options are BOTH LOSSY (none EXACT)",
      _rh_claims and all(c["status"] == "LOSSY_WITH_WARNING" for c in _rh_claims),
      f"statuses={[c['status'] for c in _rh_claims]}")
check("#51 the rehome/response claims all carry the shared viewer-response gap reason",
      _rh_claims and all("viewer-response CloudFront Function" in (c.get("reason") or "")
                         for c in _rh_claims),
      f"reasons={[(c.get('reason') or '')[:40] for c in _rh_claims]}")

print("== FINDING (spine) 52: CFF header-mutation CAPABILITY gate (r27 review-2 #2) ==")
# A CFF can't set/remove read-only/disallowed headers (Host, Content-Length, Via, Warning, X-Amz-
# Cf-*, X-Edge-*, …) — HTTP 502 at runtime. The processor NCs such a source header; the op
# contract FATALs a hand-built one. Content-Length IS writable in a viewer-RESPONSE CFF.
_CAP = [("Host", "request", True), ("Content-Length", "request", True), ("Via", "request", True),
        ("Transfer-Encoding", "request", True), ("CDN-Loop", "request", True),
        ("Via", "response", True), ("Warning", "response", True),
        ("X-Amz-Cf-Id", "request", True), ("X-Edge-Result-Type", "response", True),
        ("X-Forwarded-Proto", "request", True), ("X-Real-IP", "request", True),
        # writable / normal → NOT blocked:
        ("Content-Length", "response", False), ("X-Custom", "request", False),
        ("X-Custom", "response", False), ("True-Client-IP", "request", False)]
for _nm, _ph, _blocked in _CAP:
    _r = _cep.header_mutation_capability_reason(_nm, _ph)
    check(f"#52 {_nm} @{_ph} -> {'NC' if _blocked else 'OK'}",
          (_r is not None) == _blocked, f"got {_r!r}")
# end-to-end at the processor: a Host request-header set is NON_CONVERTIBLE (not EXACT).
check("#52 processor: request set Host -> NON_CONVERTIBLE",
      _status_of(_proc.process_request_header_transform(
          _hdr_rule("Host", {"operation": "set", "value": "x"}), {}, "request")) == "NON_CONVERTIBLE")
check("#52 processor: response set Via -> NON_CONVERTIBLE",
      _status_of(_proc.process_response_header_transform(
          _hdr_rule("Via", {"operation": "set", "value": "x"}), {}, "response")) == "NON_CONVERTIBLE")
# op contract backstop: a hand-built set_request_header targeting Host is rejected.
check("#52 op contract rejects a set_request_header targeting Host",
      isinstance(_cep.validate_viewer_op_contract({"type": "set_request_header",
          "params": {"name": "Host", "value_lowered": _good_rhv}}, "request"), str))

print("== FINDING (spine) 53: op contract validates the CONDITION tree (r27 review-2 #3) ==")
# validate_condition_tree rejects a non-structured condition; validate_viewer_op wires it in.
_gt = _good_rhv
def _hop(cond, raw=None):   # a set_request_header op with a given condition/raw
    o = {"type": "set_request_header", "params": {"name": "X", "value_lowered": _gt}}
    if raw is not None:
        o["raw_expression"] = raw
    else:
        o["condition"] = cond
    return o
_BADCOND = [
    ("list condition", _hop([])),
    ("string condition", _hop("x")),
    ("unknown-key dict", _hop({"future": "x"})),
    ("leaf missing op", _hop({"field": "host"})),
    ("leaf missing field", _hop({"op": "eq", "value": "x"})),
    ("and with non-list parts", _hop({"logic": "and", "parts": "x"})),
    ("empty and parts", _hop({"logic": "and", "parts": []})),
    ("unknown logic", _hop({"logic": "xor", "parts": [{"field": "host", "op": "eq", "value": "a"}]})),
    ("not missing item", _hop({"logic": "not"})),
]
for _lbl, _op in _BADCOND:
    check(f"#53 op with {_lbl} -> rejected",
          isinstance(_cep.validate_viewer_op(_op, "request"), str),
          f"got {_cep.validate_viewer_op(_op, 'request')!r}")
# well-formed STRUCTURED conditions pass: a leaf, nested and/or/not, always, indexed leaf.
for _lbl, _op in [
    ("always", _hop({"always": True})),
    ("leaf", _hop({"field": "host", "op": "eq", "value": "a"})),
    ("nested and/or/not", _hop({"logic": "and", "parts": [
        {"field": "host", "op": "eq", "value": "a"},
        {"logic": "not", "item": {"logic": "or", "parts": [
            {"field": "uri.path", "op": "eq", "value": "/x"}]}}]})),
    ("header_named leaf", _hop({"field": "header_named", "op": "eq", "value": "y", "header_name": "x"})),
]:
    check(f"#53 op with {_lbl} -> valid",
          _cep.validate_viewer_op(_op, "request") is None,
          f"got {_cep.validate_viewer_op(_op, 'request')!r}")
# ── round-27 review-3 finding 1: raw_expression is CLOSED as a converted-op codegen path ──
# ANY raw_expression on a converted op is now rejected (raw is an NC diagnostic only), even a
# perfectly-parseable one — a converted op MUST carry a structured condition.
check("#53 op with a (parseable) raw_expression -> REJECTED (raw is NC-diagnostic only)",
      isinstance(_cep.validate_viewer_op(_hop(None, raw='http.host eq "a" or http.host eq "b"'), "request"), str))
check("#53 op with an unparseable raw_expression -> rejected",
      isinstance(_cep.validate_viewer_op(_hop(None, raw="foo("), "request"), str))
# no condition at all → rejected.
check("#53 op with NO condition -> rejected",
      isinstance(_cep.validate_viewer_op({"type": "set_request_header",
          "params": {"name": "X", "value_lowered": _gt}}, "request"), str))
# both condition and raw → rejected (raw present at all is the trigger).
check("#53 op with BOTH condition and raw -> rejected",
      isinstance(_cep.validate_viewer_op({"type": "set_request_header",
          "params": {"name": "X", "value_lowered": _gt},
          "condition": {"always": True}, "raw_expression": "http.host eq \"a\""}, "request"), str))
# the generator FATALs a malformed-condition op (last gate).
_lc_fatal = False
try:
    _gen37._generate_op_js(_hop([]), "cff")
except _gen37.LoweredError:
    _lc_fatal = True
check("#53 generator FATALs a list-condition op (last gate)", _lc_fatal)
# ── SEMANTIC executability (review-3 #1 → review-4 #1): the TYPED field × operator × value
# contract. A structurally-OK-but-non-executable OR type-mismatched leaf is rejected. ──
_BADSEM = [
    ("unknown operator", _hop({"field": "host", "op": "bogus", "value": "a"})),
    ("unmappable field", _hop({"field": "future", "op": "eq", "value": "a"})),
    ("missing value", _hop({"field": "host", "op": "eq"})),
    ("indexed field missing name", _hop({"field": "header_named", "op": "eq", "value": "a"})),
    ("unsupported transform", _hop({"field": "host", "op": "eq", "value": "a", "transform": "rot13"})),
    ("unresolved in_list", _hop({"field": "host", "op": "in_list", "value": "blk"})),
    ("in without a list value", _hop({"field": "country", "op": "in", "value": "US"})),
    ("bare-boolean on a string field", _hop({"field": "host", "op": "eq", "value": True})),
    # ── review-4 finding 1: the four field×op×value MISMATCHES that passed the independent checks ──
    ("list value on a scalar op", _hop({"field": "host", "op": "eq", "value": ["a", "b"]})),
    ("contains on a boolean field", _hop({"field": "is_eu", "op": "contains", "value": "x"})),
    ("matches with an int value", _hop({"field": "host", "op": "matches", "value": 123})),
    ("in_kvs with a non-string list name", _hop({"field": "ip.src", "op": "in_kvs", "value": 123})),
    ("in_kvs on a non-ip field", _hop({"field": "host", "op": "in_kvs", "value": "blk"})),
    ("numeric op on a string field", _hop({"field": "host", "op": "gt", "value": 5})),
    ("string op on a numeric field", _hop({"field": "asnum", "op": "contains", "value": "1"})),
    ("numeric field with a string value", _hop({"field": "asnum", "op": "eq", "value": "x"})),
    ("transform on a numeric (len) leaf", _hop({"field": "host", "op": "gt", "value": 5,
                                                "size_check": True, "transform": "lowercase"})),
    ("bare ip.src scalar compare", _hop({"field": "ip.src", "op": "eq", "value": "1.2.3.4"})),
    ("empty in list", _hop({"field": "country", "op": "in", "value": []})),
    ("mixed-type in list", _hop({"field": "country", "op": "in", "value": ["US", 1]})),
    ("in on a numeric field", _hop({"field": "asnum", "op": "in", "value": ["1", "2"]})),
]
for _lbl, _op in _BADSEM:
    check(f"#53 typed: {_lbl} -> rejected",
          isinstance(_cep.validate_viewer_op(_op, "request"), str),
          f"got {_cep.validate_viewer_op(_op, 'request')!r}")
# response-only field in a REQUEST-phase op → rejected; valid in a response op.
check("#53 typed: response_code field in a request op -> rejected",
      isinstance(_cep.validate_viewer_op(_hop({"field": "response_code", "op": "eq", "value": 500}), "request"), str))
# valid typed combos across every type:
_OKSEM = [
    ("string eq", _hop({"field": "host", "op": "eq", "value": "a"})),
    ("string contains", _hop({"field": "uri.path", "op": "contains", "value": "/x"})),
    ("string matches", _hop({"field": "host", "op": "matches", "value": "^a"})),
    ("string in-set", _hop({"field": "country", "op": "in", "value": ["US", "CA"]})),
    ("boolean eq true", _hop({"field": "is_eu", "op": "eq", "value": True})),
    ("boolean ne false", _hop({"field": "is_eu", "op": "ne", "value": False})),
    ("len (size_check) gt", _hop({"field": "host", "op": "gt", "value": 5, "size_check": True})),
    ("ip.src in_kvs", _hop({"field": "ip.src", "op": "in_kvs", "value": "blk"})),
    ("indexed existence value=true", _hop({"field": "header_named", "op": "eq", "value": True, "header_name": "x"})),
    ("indexed value compare", _hop({"field": "cookie_named", "op": "eq", "value": "v", "cookie_name": "c"})),
    ("string transform", _hop({"field": "host", "op": "eq", "value": "a", "transform": "lowercase"})),
]
for _lbl, _op in _OKSEM:
    check(f"#53 typed OK: {_lbl} -> valid",
          _cep.validate_viewer_op(_op, "request") is None,
          f"got {_cep.validate_viewer_op(_op, 'request')!r}")
# numeric-geo fields (asnum/lat/lon/metro): the TYPED contract STILL accepts a numeric gt (that layer
# is unchanged), but the conversion-POLICY layer (validate_condition_semantics via
# NON_CONVERTIBLE_CONDITION_FIELDS) now NCs them — two DISTINCT layers (the end-to-end policy path is
# exercised by #59). asnum was previously an _OKSEM "number gt -> valid" case; it's now policy-NC.
_ng53 = {"field": "asnum", "op": "gt", "value": 100}
check("#53 typed layer STILL accepts numeric gt (asnum)",
      _cep._condition_leaf_semantics(_ng53, "request") is None,
      f"got {_cep._condition_leaf_semantics(_ng53, 'request')!r}")
check("#53 policy layer NCs numeric-geo (asnum gt), distinct from the typed layer",
      isinstance(_cep.validate_condition_semantics(_ng53, "request"), str),
      f"got {_cep.validate_condition_semantics(_ng53, 'request')!r}")

print("== FINDING (spine) 54: origin-rule source + op schema (r27 review-2 #4) ==")
def _po(ap):
    return _proc.process_origin_rule({"id": "o", "description": "d", "expression": "true",
                                      "action_parameters": ap}, {}, "request")
# malformed / no-override sources → NON_CONVERTIBLE (no crash, no spurious EXACT).
for _lbl, _ap in [
    ("action_parameters=None", None),
    ("action_parameters=list", []),
    ("unknown sibling", {"host_header": "v.com", "future": "x"}),
    ("non-dict origin", {"origin": "x"}),
    ("int host_header", {"host_header": 123}),
    ("empty host", {"origin": {"host": ""}}),
    ("string port", {"origin": {"host": "o.net", "port": "8080"}}),
    ("port 0", {"origin": {"host": "o.net", "port": 0}}),
    ("port 65536", {"origin": {"host": "o.net", "port": 65536}}),
    ("no override", {}),
    ("empty origin+sni", {"origin": {}, "sni": {}}),
]:
    _r = _po(_ap)
    check(f"#54 origin rule {_lbl} -> NON_CONVERTIBLE (no crash)",
          _status_of(_r if isinstance(_r, list) else [_r]) == "NON_CONVERTIBLE",
          f"got {_status_of(_r if isinstance(_r, list) else [_r])}")
# a valid override converts (control), with the expected params.
_ok54 = _po({"origin": {"host": "backend.net", "port": 8443}, "host_header": "v.com"})
_ok54 = _ok54 if isinstance(_ok54, dict) else _ok54[0]
check("#54 valid origin override converts EXACT",
      _ok54.get("outcome_status") == "EXACT" and _ok54["params"].get("origin_port") == 8443
      and _ok54["params"].get("origin_host") == "backend.net"
      and _ok54["params"].get("host_header") == "v.com",
      f"got {_ok54}")
# op-contract: port 0 / empty host / no-override rejected at the persisted-op level too.
check("#54 op contract rejects origin_override port 0",
      isinstance(_cep.validate_viewer_op_contract({"type": "origin_override",
          "params": {"origin_host": "o.net", "origin_port": 0}}, "request"), str))
check("#54 op contract rejects origin_override with no override params",
      isinstance(_cep.validate_viewer_op_contract({"type": "origin_override", "params": {}}, "request"), str))


if __name__ == "__main__":
    report()
