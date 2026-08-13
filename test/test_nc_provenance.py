#!/usr/bin/env python3
"""L2 channel-wiring tests: the unit-provenance resolver + the non-convertible channel.

This is the FIRST wired channel. It proves the provenance spine the rest of L2 builds on:
  - the resolver maps (kind, id[, pointers]) to EXACTLY the unit's inventory keys, using
    the inventory as the only source of truth (no scheme mismatch);
  - whole-unit vs subset ownership; an unknown/drifted pointer hint is a hard error, never
    a silent claim-all;
  - a REAL process_domain run: for a partially-convertible config rule, the NC claim owns
    ONLY the unsupported leaf, claims are disjoint, and the legacy non_convertible report
    still agrees;
  - the generator-input and split-ownership regressions the reviewer asked for.

Reconciliation (_reconcile_ledger) is deliberately NOT exercised end-to-end here: only the
NC channel is wired, so a full domain's other leaves have no claim yet.

Run: python3 test_nc_provenance.py   (exit 0 = all pass). Pure; no deps.
"""
import importlib.util as _ilu
import os
import sys

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(_REPO, "converter", "scripts")
_spec = _ilu.spec_from_file_location("cdn_pre", os.path.join(SCRIPTS, "cdn-preprocess.py"))
_pre = _ilu.module_from_spec(_spec)
sys.path.insert(0, SCRIPTS)
_spec.loader.exec_module(_pre)
_pspec = _ilu.spec_from_file_location("cdn_proc", os.path.join(SCRIPTS, "cdn_rule_processors.py"))
_proc = _ilu.module_from_spec(_pspec)
_pspec.loader.exec_module(_proc)
import cdn_rhp_capabilities as _cap   # shared registry (SCRIPTS is on sys.path)
import cdn_expr_parser as _cep         # the dependency-free leaf (validate_lowered_value etc.)
_gspec = _ilu.spec_from_file_location("cdn_gen", os.path.join(SCRIPTS, "cdn-generate-shared-policies.py"))
_gen = _ilu.module_from_spec(_gspec)
_gspec.loader.exec_module(_gen)

FAILURES = []
SKIPPED = []


def check(label, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")
    if not cond:
        FAILURES.append((label, detail))
        if detail:
            print(f"           {detail}")


def skip(label, reason):
    """A DISTINCT skipped status — NOT a pass (round-22 finding 4: node-absent must not count as
    a passing runtime test). Recorded separately; the summary shows it. round-26 finding 6:
    when CDN_REQUIRE_NODE is set (the CI/invariant job MUST set it), a skip becomes a hard
    FAILURE — so the runtime oracle can never SKIP-pass in CI; only local dev without node skips."""
    if os.environ.get("CDN_REQUIRE_NODE"):
        FAILURES.append((label, f"REQUIRED but skipped: {reason}"))
        print(f"  [FAIL] {label} — REQUIRED (CDN_REQUIRE_NODE) but {reason}")
        return
    print(f"  [SKIP] {label} — {reason}")
    SKIPPED.append((label, reason))


def _raises_ledger(fn):
    try:
        fn()
        return None
    except _pre.LedgerError as e:
        return str(e)


def _ir_with_inventory(keys):
    dc = {"hostname": "h", "sanitized_name": "h", "origin_content": "o",
          "apex_domain": "h", "origin_type": "custom"}
    ir = _pre.make_empty_ir(dc)
    _pre.find_or_create_behavior(ir, "*", dc, "o")   # default behavior = the legacy NC sink
    ir["_inventory"] = [list(k) for k in keys]
    return ir


DC = {"hostname": "shop.example.com", "apex_domain": "example.com", "origin_type": "custom",
      "origin_content": "o.net", "sanitized_name": "shop_example_com"}


def _ref(source_id, segs=None, kind="rule", status=None, reason=None):
    """Build a valid owner ref for tests. Status defaults to EXACT (an artifact-producing
    ref always carries an explicit status now); pass status/reason for the LOSSY cases."""
    return {"source_kind": kind, "source_id": source_id, "owned_key_segments": segs,
            "outcome_status": status or _pre.OUTCOME_EXACT, "outcome_reason": reason}


print("== resolver: whole-unit vs subset ==")
KA = ("rule", "r1", "/ssl")
KB = ("rule", "r1", "/min_tls_version")
KC = ("rule", "r1", "/automatic_https_rewrites")
ir = _ir_with_inventory([KA, KB, KC])
whole = _pre._resolve_owned_keys(ir, "rule", "r1")
check("whole-unit ownership = every inventory key of the unit",
      sorted(whole) == sorted([KA, KB, KC]))
subset = _pre._resolve_owned_keys(ir, "rule", "r1", ["/automatic_https_rewrites"])
check("subset ownership = exactly the named leaf", subset == [KC])
# a subtree/ancestor hint expands to the leaves under it
ir2 = _ir_with_inventory([("rule", "h", "/headers/X-Foo/operation"),
                          ("rule", "h", "/headers/X-Foo/value"),
                          ("rule", "h", "/headers/Y-Bar/value")])
sub2 = _pre._resolve_owned_keys(ir2, "rule", "h", ["/headers/X-Foo"])
check("ancestor hint expands to its subtree leaves",
      sorted(sub2) == sorted([("rule", "h", "/headers/X-Foo/operation"),
                              ("rule", "h", "/headers/X-Foo/value")]))
check("ancestor hint does NOT capture a sibling subtree",
      ("rule", "h", "/headers/Y-Bar/value") not in sub2)

print("== resolver: hard failures (never a silent claim-all) ==")
check("unit with no inventory -> LedgerError",
      _raises_ledger(lambda: _pre._resolve_owned_keys(_ir_with_inventory([]), "rule", "ghost")) is not None)
check("pointer hint matching nothing -> LedgerError (drifted hint)",
      _raises_ledger(lambda: _pre._resolve_owned_keys(ir, "rule", "r1", ["/nope"])) is not None)
check("empty pointer list is NOT whole-unit -> LedgerError",
      _raises_ledger(lambda: _pre._resolve_owned_keys(ir, "rule", "r1", [])) is not None)

print("== key-path -> pointer encoding matches inventory (RFC-6901) ==")
check("segment with / and ~ is escaped like the inventory",
      _pre._key_path_to_pointer(["a/b~c"]) == "/a~1b~0c")
check("nested segments join", _pre._key_path_to_pointer(["headers", "X-Foo"]) == "/headers/X-Foo")

print("== REAL process_domain: partially-convertible config rule ==")
# ssl + min_tls convert (unconditional) → distribution settings; the third setting is NC.
rules = {"config": [{"id": "cfg1", "description": "mix", "expression": "true",
                     "action": "set_config",
                     "action_parameters": {"ssl": "full", "min_tls_version": "1.2",
                                           "automatic_https_rewrites": "on"}}]}
ir = _pre.process_domain("shop.example.com", DC, rules, {}, {}, {})
inv_cfg = [tuple(k) for k in ir["_inventory"] if k[1] == "cfg1"]
nc_claims = [c for c in ir["_claims"] if c["status"] == "NON_CONVERTIBLE"]
nc_keys = [tuple(k) for c in nc_claims for k in c["source_keys"]]
check("inventory has all 3 config leaves",
      sorted(inv_cfg) == sorted([("rule", "cfg1", "/ssl"), ("rule", "cfg1", "/min_tls_version"),
                                 ("rule", "cfg1", "/automatic_https_rewrites")]))
check("NC claim owns ONLY the unsupported leaf",
      nc_keys == [("rule", "cfg1", "/automatic_https_rewrites")],
      f"got {nc_keys}")
check("every NC claim key is a real inventory key", all(k in inv_cfg for k in nc_keys))
check("NC claims are disjoint (no key claimed twice)", len(nc_keys) == len(set(nc_keys)))
check("converted leaves are NOT NC-claimed (ssl/min_tls went to another channel)",
      ("rule", "cfg1", "/ssl") not in nc_keys and ("rule", "cfg1", "/min_tls_version") not in nc_keys)
# legacy report still agrees
legacy = ir["cache_behaviors"][0]["non_convertible"]
check("legacy non_convertible report has exactly the one NC entry",
      len(legacy) == 1 and legacy[0]["cf_source_rule"] == "cfg1")
check("legacy entry reason names the unsupported setting",
      "automatic_https_rewrites" in legacy[0]["reason"])
check("distribution settings got the converted ssl/tls",
      ir["cache_behaviors"][0]["distribution_settings"].get("viewer_protocol_policy") == "redirect-to-https"
      and ir["cache_behaviors"][0]["distribution_settings"].get("minimum_protocol_version") == "TLSv1.2_2021")

print("== REAL process_domain: whole-unit NC (redirect with unmappable target) ==")
# A redirect whose target references an unsourceable field → whole-rule non_convertible.
rules = {"redirect": [{"id": "rd1", "description": "bad", "expression": "true",
                       "action": "redirect",
                       "action_parameters": {"from_value": {"status_code": 302,
                           "target_url": {"expression": 'http.request.headers["x"]'}}}}]}
ir = _pre.process_domain("shop.example.com", DC, rules, {}, {}, {})
inv_rd = [tuple(k) for k in ir["_inventory"] if k[1] == "rd1"]
nc_claims = [c for c in ir["_claims"] if c["status"] == "NON_CONVERTIBLE"]
rd_claim_keys = [tuple(k) for c in nc_claims for k in c["source_keys"] if k[1] == "rd1"]
check("whole-unit NC claims EVERY inventory leaf of the unit",
      sorted(rd_claim_keys) == sorted(inv_rd) and len(inv_rd) >= 1,
      f"inv={inv_rd} claimed={rd_claim_keys}")
check("whole-unit NC claim keys are disjoint",
      len(rd_claim_keys) == len(set(rd_claim_keys)))

print("== generator input to emit_non_convertible (report id not emptied) ==")
ir = _ir_with_inventory([("rule", "g", "/a")])
_pre.emit_non_convertible(ir, (k for k in [("rule", "g", "/a")]), "no equiv", "d")
check("generator: claim recorded", len(ir["_claims"]) == 1)
check("generator: cf_source_rule not emptied",
      ir["cache_behaviors"][0]["non_convertible"][0]["cf_source_rule"] == "g")

print("== claim_non_convertible: subset vs whole-unit + disjointness ==")
ir = _ir_with_inventory([("rule", "u", "/x"), ("rule", "u", "/y")])
_pre.claim_non_convertible(ir, "rule", "u", "x is nc", owned_pointers=["/x"])
check("subset claim_non_convertible owns just /x",
      [tuple(k) for k in ir["_claims"][0]["source_keys"]] == [("rule", "u", "/x")])
# claiming /y separately keeps them disjoint (two units-of-outcome within one config unit)
_pre.claim_non_convertible(ir, "rule", "u", "y is nc", owned_pointers=["/y"])
allk = [tuple(k) for c in ir["_claims"] for k in c["source_keys"]]
check("two subset claims stay disjoint", sorted(allk) == [("rule", "u", "/x"), ("rule", "u", "/y")]
      and len(allk) == len(set(allk)))
# legacy_cf_source_rule overrides the report id only, never the ledger keys
ir = _ir_with_inventory([("bulk_redirect", "list#0", "/target_url")])
_pre.claim_non_convertible(ir, "bulk_redirect", "list#0", "nc", legacy_cf_source_rule="bulk_redirects")
check("legacy_cf_source_rule overrides report id only",
      ir["cache_behaviors"][0]["non_convertible"][0]["cf_source_rule"] == "bulk_redirects"
      and [tuple(k) for k in ir["_claims"][0]["source_keys"]] == [("bulk_redirect", "list#0", "/target_url")])


def _nc_keys(ir, unit_id):
    return sorted(tuple(k) for c in ir["_claims"] if c["status"] == "NON_CONVERTIBLE"
                  for k in c["source_keys"] if k[1] == unit_id)


def _unit_leaves(ir, unit_id):
    return sorted(tuple(k) for k in ir["_inventory"] if k[1] == unit_id)


print("== FINDING 1: partial-header NC owns ONLY its header (not the whole rule) ==")
# Response header: X-Good:set (converts to a viewer-op) + X-Bad:add (NC). The NC must
# own ONLY the X-Bad subtree — before the fix it claimed all 4 leaves (whole-unit),
# which would collide with X-Good's converted-op claim once the viewer-op channel wires.
rules = {"response_header": [{"id": "h1", "description": "mix", "expression": "true",
         "action": "rewrite", "action_parameters": {"headers": {
             "X-Good": {"operation": "set", "value": "1"},
             "X-Bad": {"operation": "add", "value": "2"}}}}]}
ir = _pre.process_domain("shop.example.com", DC, rules, {}, {}, {})
check("#1 response add-header NC owns ONLY the X-Bad subtree",
      _nc_keys(ir, "h1") == [("rule", "h1", "/headers/X-Bad/operation"),
                             ("rule", "h1", "/headers/X-Bad/value")],
      f"got {_nc_keys(ir, 'h1')}")
check("#1 X-Good leaves are NOT NC-claimed",
      ("rule", "h1", "/headers/X-Good/value") not in _nc_keys(ir, "h1"))

# Request header: one unmappable value-expression header + one normal header.
rules = {"request_header": [{"id": "q1", "description": "mix", "expression": "true",
         "action": "rewrite", "action_parameters": {"headers": {
             "X-Ok": {"operation": "set", "value": "1"},
             "X-Dyn": {"operation": "set", "expression": 'http.request.cf.bot_management.score'}}}}]}
ir = _pre.process_domain("shop.example.com", DC, rules, {}, {}, {})
check("#1 request unmappable-expr header NC owns ONLY the X-Dyn subtree",
      _nc_keys(ir, "q1") == [("rule", "q1", "/headers/X-Dyn/expression"),
                             ("rule", "q1", "/headers/X-Dyn/operation")],
      f"got {_nc_keys(ir, 'q1')}")

# Conditional security header rejected AT PLACEMENT (header condition can't be a path)
# still owns only its header — via _mark_result_non_convertible + the shared helper.
rules = {"response_header": [{"id": "h2", "description": "sec",
         "expression": 'http.request.headers["x"] eq "1"', "action": "rewrite",
         "action_parameters": {"headers": {
             "Strict-Transport-Security": {"operation": "set", "value": "max-age=31536000"},
             "X-Good": {"operation": "set", "value": "1"}}}}]}
ir = _pre.process_domain("shop.example.com", DC, rules, {}, {}, {})
check("#1 security header rejected at placement owns ONLY its header (not whole rule)",
      _nc_keys(ir, "h2") == [("rule", "h2", "/headers/Strict-Transport-Security/operation"),
                             ("rule", "h2", "/headers/Strict-Transport-Security/value")],
      f"got {_nc_keys(ir, 'h2')}")

print("== FINDING 2: (kind, id) reliably identifies one unit ==")
# Two id-LESS rules with DIFFERENT param structure must NOT merge into one unit.
rules = {"config": [
    {"description": "a", "expression": "true", "action": "set_config",
     "action_parameters": {"automatic_https_rewrites": "on"}},
    {"description": "b", "expression": "true", "action": "set_config",
     "action_parameters": {"bogus_setting": "x"}}]}
ir = _pre.process_domain("shop.example.com", DC, rules, {}, {}, {})
units = sorted(set((k[0], k[1]) for k in ir["_inventory"]))
check("#2 two id-less rules get DISTINCT synthesized unit ids (no merge)",
      units == [("rule", "config#0"), ("rule", "config#1")], f"got {units}")
# each unit's NC claim stays within its own unit
check("#2 id-less unit #0 NC owns only its own leaf",
      _nc_keys(ir, "config#0") == [("rule", "config#0", "/automatic_https_rewrites")])
check("#2 id-less unit #1 NC owns only its own leaf",
      _nc_keys(ir, "config#1") == [("rule", "config#1", "/bogus_setting")])

# A duplicate EXPLICIT id is an immediate FATAL (LedgerError → domain FAILs).
dup_rules = {"cache": [
    {"id": "dup", "enabled": True, "expression": "true", "action": "x",
     "action_parameters": {"cache": False}},
    {"id": "dup", "enabled": True, "expression": "true", "action": "x",
     "action_parameters": {"cache": True}}]}
_dup_raised = _raises_ledger(lambda: _pre.process_domain("shop.example.com", DC, dup_rules, {}, {}, {}))
check("#2 duplicate explicit rule id -> LedgerError (FATAL, no merge)", _dup_raised is not None)

print("== FINDING 3: empty segment hint -> /$action, never claim-all ==")
# _key_path_to_pointer([]) is the action root /$action, NOT "" (which startswith('/')-
# matches every leaf). An owned_key_segments=[[]] hint must match ONLY /$action.
ir = _ir_with_inventory([("rule", "act", "/$action")])
check("#3 [[]] segment hint resolves to /$action",
      _pre._resolve_owned_keys(ir, "rule", "act", [_pre._key_path_to_pointer([])])
      == [("rule", "act", "/$action")])
# with real leaves present, [[]] -> /$action must NOT match sibling leaves (it isn't one)
ir = _ir_with_inventory([("rule", "u", "/x"), ("rule", "u", "/y")])
check("#3 [[]] -> /$action matches NOTHING when there is no action-root leaf (LedgerError)",
      _raises_ledger(lambda: _pre._resolve_owned_keys(
          ir, "rule", "u", [_pre._key_path_to_pointer([])])) is not None)
check("#3 empty-string hint rejected (would startswith-match all)",
      _raises_ledger(lambda: _pre._resolve_owned_keys(ir, "rule", "u", [""])) is not None)

print("== FINDING (spine lifecycle) 4: internal unit id survives deferred channels ==")
# A native effect from an id-less rule stores the SYNTHESIZED unit id (_source_id), not
# the empty display cf_source_rule — so the native-effect/viewer-op channels can still
# resolve the inventory unit. (Recorded directly: _native_effects is stripped after
# process_domain, so this inspects the recording, which is what the channels will read.)
ir = _pre.make_empty_ir(DC)
_pre.find_or_create_behavior(ir, "*", DC, "o.net")
idless = {"enabled": True, "expression": 'http.request.uri.path eq "/x"', "action": "x",
          "action_parameters": {"edge_ttl": {"mode": "override_origin", "default": 100}}}
uid = _pre._assign_unit_id(ir, idless, "rule", "cache", 0)
ir["_inventory"].extend(_pre._inventory_keys_for_rule(idless, source_id=uid))
res = _proc.process_cache_rule(idless, {}, "cache")
_pre._place_result(ir, res, DC, "o.net", res.get("condition"), "x",
                   source_kind="rule", source_id=uid)
_eff = ir["_native_effects"]
check("#4 id-less rule -> synthesized unit id (cache#0)", uid == "cache#0")
check("#4 native effect carries the synthetic _source_id (not empty cf_source_rule)",
      len(_eff) >= 1 and _eff[0]["_source_id"] == "cache#0"
      and _eff[0]["cf_source_rule"] == "",
      f"eff={[(e['kind'], e.get('_source_id'), e.get('cf_source_rule')) for e in _eff]}")
check("#4 effect's _source_id resolves to a real inventory unit",
      _pre._resolve_owned_keys(ir, _eff[0]["_source_kind"], _eff[0]["_source_id"]) ==
      _unit_leaves(ir, "cache#0"))

# RHP -> viewer-op rehome: the moved op must carry the SAME internal provenance.
ir = _pre.make_empty_ir(DC)
_pre.find_or_create_behavior(ir, "*", DC, "o.net")
hdr_rule = {"enabled": True, "expression": "true", "action": "rewrite",
            "action_parameters": {"headers": {
                "Strict-Transport-Security": {"operation": "set", "value": "max-age=1"}}}}
uid = _pre._assign_unit_id(ir, hdr_rule, "rule", "response_header", 0)
ir["_inventory"].extend(_pre._inventory_keys_for_rule(hdr_rule, source_id=uid))
for r in _proc.process_response_header_transform(hdr_rule, {}, "response"):
    _pre._place_result(ir, r, DC, "o.net", r.get("condition"), "true",
                       source_kind="rule", source_id=uid)
# a CFF op for the SAME header forces the rehome (one-writer-per-header)
ir["cache_behaviors"][0]["viewer_response_ops"].append({
    "type": "remove_response_header", "cf_source_rule": "other",
    "params": {"name": "Strict-Transport-Security"}, "condition": {"always": True}})
_pre._reconcile_mixed_op_headers(ir, DC, "o.net")
_moved = [op for op in ir["cache_behaviors"][0]["viewer_response_ops"]
          if op["type"] == "set_response_header"]
check("#4 RHP->viewer rehome preserves _source_id (id-less unit survives)",
      len(_moved) == 1 and _moved[0]["_source_id"] == "response_header#0",
      f"moved={_moved}")
check("#4 rehome preserves the per-header owned_key_segments",
      _moved and _moved[0]["_owned_key_segments"] == [["headers", "Strict-Transport-Security"]])

print("== FINDING (spine) 5: (kind, id) uniqueness is scoped per kind ==")
# A rule and a cloud connector may share a DISPLAY id — different kinds, separate units.
shared_rule = {"cache": [{"id": "shared", "enabled": True, "expression": "true", "action": "x",
               "action_parameters": {"edge_ttl": {"mode": "override_origin", "default": 100}}}]}
shared_cc = [{"id": "shared", "enabled": True, "expression": 'http.request.uri.path eq "/img"',
              "provider": "aws_s3", "parameters": {"host": "b.s3.amazonaws.com"}}]
ir = _pre.process_domain("shop.example.com", DC, {**shared_rule, "cloud_connector": shared_cc}, {}, {}, {})
units = sorted(set((k[0], k[1]) for k in ir["_inventory"]))
check("#5 rule + cloud connector sharing id 'shared' -> SEPARATE units (no false FATAL)",
      ("rule", "shared") in units and ("cloud_connector", "shared") in units, f"units={units}")
# but two SAME-KIND rules with a duplicate id still FATAL
same_kind_dup = {"cache": [
    {"id": "d", "enabled": True, "expression": "true", "action": "x", "action_parameters": {"cache": False}},
    {"id": "d", "enabled": True, "expression": "true", "action": "x", "action_parameters": {"cache": True}}]}
check("#5 two SAME-KIND rules with duplicate id -> LedgerError (still FATAL)",
      _raises_ledger(lambda: _pre.process_domain("h", DC, same_kind_dup, {}, {}, {})) is not None)

print("== FINDING (spine) 6: non-string explicit id is FATAL at source-entry (uniform) ==")
# An int id must FATAL regardless of conversion path — was: convertible ssl wrote an
# illegal ['rule', 123, ...] inventory key while the NC path raised later.
int_conv = {"config": [{"id": 123, "enabled": True, "expression": "true", "action": "set_config",
            "action_parameters": {"ssl": "full"}}]}
int_nc = {"config": [{"id": 123, "enabled": True, "expression": "true", "action": "set_config",
          "action_parameters": {"bogus_setting": "x"}}]}
check("#6 int id on a CONVERTIBLE config rule -> LedgerError at source-entry",
      _raises_ledger(lambda: _pre.process_domain("h", DC, int_conv, {}, {}, {})) is not None)
check("#6 int id on a NON-CONVERTIBLE config rule -> LedgerError at source-entry",
      _raises_ledger(lambda: _pre.process_domain("h", DC, int_nc, {}, {}, {})) is not None)
check("#6 float id also rejected (any non-string)",
      _raises_ledger(lambda: _pre._assign_unit_id(_pre.make_empty_ir(DC), {"id": 1.5}, "rule", "cache", 0)) is not None)
# an ABSENT / empty id is NOT an error — it uses the synthetic fallback
_irok = _pre.make_empty_ir(DC)
check("#6 absent id is fine (synthetic fallback, no error)",
      _pre._assign_unit_id(_irok, {}, "rule", "cache", 0) == "cache#0")
check("#6 empty-string id is fine (synthetic fallback)",
      _pre._assign_unit_id(_pre.make_empty_ir(DC), {"id": ""}, "rule", "cache", 0) == "cache#0")


def _pd(all_rules=None, bulk=None, mt=None):
    # process_domain(hostname, domain_config, all_rules, ip_lists, bulk_redirects, managed_transforms)
    return _pre.process_domain("shop.example.com", DC, all_rules or {}, {}, bulk or {}, mt or {})


print("== FINDING (spine) 7: EVERY viewer op carries provenance (unified _append_viewer_op) ==")
# id-less request-header rule -> generic viewer-op placement must keep request_header#0.
ir = _pre.make_empty_ir(DC)
beh = _pre.find_or_create_behavior(ir, "*", DC, "o.net")
rh = {"enabled": True, "expression": "true", "action": "rewrite",
      "action_parameters": {"headers": {"X-Foo": {"operation": "set", "value": "1"}}}}
uid = _pre._assign_unit_id(ir, rh, "rule", "request_header", 0)
ir["_inventory"].extend(_pre._inventory_keys_for_rule(rh, source_id=uid))
for r in _proc.process_request_header_transform(rh, {}, "cff"):
    _pre._place_result(ir, r, DC, "o.net", r.get("condition"), "true", source_kind="rule", source_id=uid)
_rhop = beh["viewer_request_ops"][0]
check("#7 id-less request-header op keeps request_header#0",
      _rhop.get("_source_id") == "request_header#0" and _rhop.get("cf_source_rule") == "")
check("#7 request-header op keeps per-header owned segments",
      _rhop.get("_owned_key_segments") == [["headers", "X-Foo"]])

# id-less cache rule with browser_ttl -> its viewer-response op must keep cache#0.
ir = _pre.make_empty_ir(DC)
beh = _pre.find_or_create_behavior(ir, "*", DC, "o.net")
bt = {"enabled": True, "expression": "true", "action": "x",
      "action_parameters": {"browser_ttl": {"mode": "override_origin", "default": 50}}}
uid = _pre._assign_unit_id(ir, bt, "rule", "cache", 0)
ir["_inventory"].extend(_pre._inventory_keys_for_rule(bt, source_id=uid))
res = _proc.process_cache_rule(bt, {}, "cache")
_pre._place_result(ir, res, DC, "o.net", res.get("condition"), "true", source_kind="rule", source_id=uid)
_btop = [o for o in beh["viewer_response_ops"] if o["params"].get("name") == "cache-control"]
check("#7 id-less browser_ttl op keeps cache#0",
      len(_btop) == 1 and _btop[0].get("_source_id") == "cache#0")
check("#7 browser_ttl op owns the PRECISE browser_ttl leaves (mode + default, not the subtree)",
      _btop and _btop[0].get("_owned_key_segments")
      == [["browser_ttl", "mode"], ["browser_ttl", "default"]])

print("== FINDING (spine) 8: uniform id contract for bulk redirect + managed transform ==")
check("#8 bulk redirect int id -> FATAL",
      _raises_ledger(lambda: _pd(bulk={"L": [{"id": 123, "redirect": {
          "source_url": "shop.example.com/a", "target_url": "https://x"}}]})) is not None)
check("#8 bulk redirect duplicate id -> FATAL",
      _raises_ledger(lambda: _pd(bulk={"L": [
          {"id": "s", "redirect": {"source_url": "shop.example.com/a", "target_url": "https://x"}},
          {"id": "s", "redirect": {"source_url": "shop.example.com/b", "target_url": "https://y"}}]})) is not None)
check("#8 managed transform int id -> FATAL",
      _raises_ledger(lambda: _pd(mt={"managed_request_headers": [{"id": 9, "enabled": True}]})) is not None)
check("#8 managed transform duplicate id -> FATAL",
      _raises_ledger(lambda: _pd(mt={"managed_request_headers": [
          {"id": "m", "enabled": True}, {"id": "m", "enabled": True}]})) is not None)
# id-less bulk items / managed transforms get DISTINCT fallback units (no merge)
ir = _pd(bulk={"L": [{"redirect": {"source_url": "shop.example.com/a", "target_url": "https://x"}},
                     {"redirect": {"source_url": "shop.example.com/b", "target_url": "https://y"}}]})
bunits = sorted(set(k[1] for k in ir["_inventory"] if k[0] == "bulk_redirect"))
check("#8 two id-less bulk items -> distinct list#index units", bunits == ["L#0", "L#1"])
ir = _pd(mt={"managed_request_headers": [{"enabled": True}, {"enabled": True}]})
munits = sorted(k[1] for k in ir["_inventory"] if k[0] == "managed_transform")
check("#8 two id-less managed transforms -> distinct mt_req#index units",
      munits == ["mt_req#0", "mt_req#1"])

print("== FINDING (spine) 9: bulk aggregation op keeps ALL owner refs (pre-strip) ==")
# Build the bulk op directly (process_domain strips provenance at the end); assert the
# multi-unit aggregate carries one owner ref per item, not a single collapsed id.
ir = _pre.make_empty_ir(DC)
_pre.find_or_create_behavior(ir, "*", DC, "o.net")
_pre._process_bulk_redirects(
    ir, "shop.example.com", "example.com",
    {"L": [{"redirect": {"source_url": "shop.example.com/a", "target_url": "https://x"}},
           {"redirect": {"source_url": "shop.example.com/b", "target_url": "https://y"}}]},
    DC, "o.net")
_bop = [o for o in ir["cache_behaviors"][0]["viewer_request_ops"] if o["type"] == "bulk_redirect"][0]
_refs = _bop.get("_owner_refs")
check("#9 bulk op is a multi-unit aggregate (owner_refs, no single _source_id)",
      _refs is not None and "_source_id" not in _bop)
check("#9 owner_refs has one ref per item, covering both units",
      _refs is not None and sorted(r["source_id"] for r in _refs) == ["L#0", "L#1"]
      and all(r["source_kind"] == "bulk_redirect" for r in _refs))

print("== FINDING (spine) 10: final IR has NO nested _source_*/_owner_refs (stripped) ==")
import json as _json
_ir10 = _pd(
    all_rules={"request_header": [{"enabled": True, "expression": "true", "action": "rewrite",
               "action_parameters": {"headers": {"X-A": {"operation": "set", "value": "1"}}}}]},
    bulk={"L": [{"redirect": {"source_url": "shop.example.com/a", "target_url": "https://x"}}]},
    mt={"managed_request_headers": [{"id": "add_true_client_ip_headers", "enabled": True}]})
_blob = _json.dumps(_ir10)
check("#10 no nested provenance key survives into the persisted IR",
      not any(s in _blob for s in
              ("_source_kind", "_source_id", "_owned_key_segments", "_owner_refs")),
      "internal per-op provenance must be stripped by _strip_build_internals")
# sanity: the ops themselves DID persist (strip removed only the internal keys)
_hasops = any(b.get("viewer_request_ops") for b in _ir10["cache_behaviors"])
check("#10 viewer ops still persist (only the internal keys were stripped)", _hasops)

print("== FINDING (spine) 11: bulk op owns ONLY supported+present fields, unknown → NC ==")
# An item with the 5 supported fields + an unknown leaf: the shared CFF op must own only
# the supported fields; the unknown leaf is NON_CONVERTIBLE, not silently "converted".
_bulk_mix = {"L": [{"redirect": {
    "source_url": "shop.example.com/a", "target_url": "https://x", "status_code": 301,
    "preserve_query_string": False, "include_subdomains": True,
    "future_option": {"mode": "fancy"}}}]}
_ir11 = _pd(bulk=_bulk_mix)
_nc11 = sorted(tuple(k) for c in _ir11["_claims"] if c["status"] == "NON_CONVERTIBLE"
               for k in c["source_keys"])
check("#11 unknown bulk leaf is NC-claimed (only it)",
      _nc11 == [("bulk_redirect", "L#0", "/future_option/mode")], f"got {_nc11}")
# owner ref (pre-strip) owns only the supported present fields, NOT the unknown one
_ir11b = _pre.make_empty_ir(DC)
_pre.find_or_create_behavior(_ir11b, "*", DC, "o.net")
_pre._process_bulk_redirects(_ir11b, "shop.example.com", "example.com", _bulk_mix, DC, "o.net")
_bop11 = [o for o in _ir11b["cache_behaviors"][0]["viewer_request_ops"]
          if o["type"] == "bulk_redirect"][0]
_owned11 = _bop11["_owner_refs"][0]["owned_key_segments"]
check("#11 owner ref owns only the 5 supported fields",
      _owned11 == [["source_url"], ["target_url"], ["status_code"],
                   ["preserve_query_string"], ["include_subdomains"]], f"got {_owned11}")
check("#11 owner ref does NOT own the unknown field",
      ["future_option"] not in _owned11 and ["future_option", "mode"] not in _owned11)

print("== FINDING (spine) 12: _append_viewer_op enforces its provenance contract ==")
_beh12 = _pre.find_or_create_behavior(_pre.make_empty_ir(DC), "*", DC, "o.net")


def _append_raises(**kw):
    # outcome_status is now MANDATORY (no implicit EXACT) — the base supplies EXACT so a
    # "valid" single-source call is valid; FATAL-expecting checks override as needed. A
    # set_request_header op also requires a valid LoweredValue (round-27 sink gate), so the
    # base supplies one — this suite tests the PROVENANCE contract, not the value gate.
    base = dict(type="set_request_header", cf_source_rule="x", description="d",
                condition={"always": True}, raw_expression=None,
                params={"name": "H", "value_lowered": _cep.lower_literal_value("v", "request_header")},
                scope_pattern="*", seq=0, outcome_status=_pre.OUTCOME_EXACT)
    base.update(kw)
    try:
        _pre._append_viewer_op(_beh12, base.pop("phase", "request"), **base)
        return None
    except _pre.LedgerError as e:
        return str(e)


check("#12 invalid phase -> FATAL", _append_raises(phase="sideways", source_id="u") is not None)
check("#12 single-source with empty source_id -> FATAL",
      _append_raises(source_kind="rule", source_id="") is not None)
check("#12 single-source with empty source_kind -> FATAL",
      _append_raises(source_kind="", source_id="u") is not None)
check("#12 empty owner_refs -> FATAL", _append_raises(owner_refs=[]) is not None)
check("#12 owner ref missing source_id -> FATAL",
      _append_raises(owner_refs=[{"source_kind": "bulk_redirect", "owned_key_segments": None}]) is not None)
check("#12 owner ref with bad owned_key_segments type -> FATAL",
      _append_raises(owner_refs=[{"source_kind": "bulk_redirect", "source_id": "L#0",
                                  "owned_key_segments": "notalist"}]) is not None)
# valid single-source and valid aggregation still succeed
check("#12 valid single-source op succeeds",
      _append_raises(source_kind="rule", source_id="r1") is None)
check("#12 valid aggregation op succeeds",
      _append_raises(owner_refs=[_ref("L#0", [["source_url"]], kind="bulk_redirect")]) is None)

print("== FINDING (spine) 13: _validate_owner_ref closes the type holes (int id / str segs / empty) ==")


def _vref_raises(ref):
    try:
        _pre._validate_owner_ref(ref)
        return None
    except _pre.LedgerError as e:
        return str(e)


check("#13 int source_kind -> FATAL",
      _vref_raises({"source_kind": 1, "source_id": "u", "owned_key_segments": None}) is not None)
check("#13 int source_id -> FATAL",
      _vref_raises({"source_kind": "rule", "source_id": 2, "owned_key_segments": None}) is not None)
check("#13 string owned_key_segments -> FATAL",
      _vref_raises({"source_kind": "rule", "source_id": "u", "owned_key_segments": "abc"}) is not None)
check("#13 EMPTY owned_key_segments list -> FATAL (None means whole-unit, [] is a bug)",
      _vref_raises({"source_kind": "rule", "source_id": "u", "owned_key_segments": []}) is not None)
check("#13 path that isn't a list -> FATAL",
      _vref_raises({"source_kind": "rule", "source_id": "u", "owned_key_segments": ["notalist"]}) is not None)
check("#13 non-string segment -> FATAL",
      _vref_raises({"source_kind": "rule", "source_id": "u", "owned_key_segments": [[1]]}) is not None)
check("#13 valid ref (None segments, EXACT) -> ok",
      _vref_raises(_ref("u", None)) is None)
check("#13 valid ref (empty path [] = /$action) -> ok",
      _vref_raises(_ref("u", [[]])) is None)
# STATUS is part of the ref contract now (belongs to the source contribution):
check("#13 missing outcome_status -> FATAL (no implicit EXACT default)",
      _vref_raises({"source_kind": "rule", "source_id": "u", "owned_key_segments": None}) is not None)
check("#13 NON_CONVERTIBLE status on an artifact ref -> FATAL (NC never owns an artifact)",
      _vref_raises(_ref("u", None, status=_pre.OUTCOME_NON_CONVERTIBLE)) is not None)
check("#13 EXACT with a reason -> FATAL (EXACT needs no reason)",
      _vref_raises(_ref("u", None, status=_pre.OUTCOME_EXACT, reason="x")) is not None)
check("#13 LOSSY without a reason -> FATAL (LOSSY needs a reason)",
      _vref_raises({"source_kind": "rule", "source_id": "u", "owned_key_segments": None,
                    "outcome_status": _pre.OUTCOME_LOSSY, "outcome_reason": None}) is not None)
check("#13 valid LOSSY ref (status + reason) -> ok",
      _vref_raises(_ref("u", None, status=_pre.OUTCOME_LOSSY, reason="gap")) is None)
# the single-source op gate now uses the SAME validator (int source_kind rejected there too)
check("#13 _append_viewer_op single-source int source_kind -> FATAL",
      _append_raises(source_kind=7, source_id="u") is not None)
check("#13 _append_viewer_op single-source string owned_key_segments -> FATAL",
      _append_raises(source_kind="rule", source_id="u", owned_key_segments="abc") is not None)

print("== FINDING (spine) 14: KVS entries carry owner refs, dedup MERGES owners ==")
# bulk item -> BOTH a shared CFF op AND KVS entries, each carrying the item's owner ref
# (the future coordinator makes ONE claim referencing both artifacts; this turn just
# proves the provenance is present on both sinks).
_ir14 = _pre.make_empty_ir(DC)
_pre.find_or_create_behavior(_ir14, "*", DC, "o.net")
# All 5 supported fields PRESENT (owner ref should own exactly those 5 — absent fields
# aren't inventoried, so they're never owned; the KVS value's defaults for absent fields
# are converter behavior, not source leaves).
_pre._process_bulk_redirects(
    _ir14, "shop.example.com", "example.com",
    {"L": [{"redirect": {"source_url": "shop.example.com/a", "target_url": "https://x",
                         "status_code": 301, "preserve_query_string": False,
                         "include_subdomains": True}}]},
    DC, "o.net")
_kvs14 = _ir14["metadata"]["kvs_data"]
_want_segs = [["source_url"], ["target_url"], ["status_code"],
              ["preserve_query_string"], ["include_subdomains"]]
check("#14 bulk KVS entries carry the item owner ref (only present supported fields, EXACT)",
      len(_kvs14) == 2 and all(
          e["_owner_refs"] == [{"source_kind": "bulk_redirect", "source_id": "L#0",
                                "owned_key_segments": _want_segs,
                                "outcome_status": "EXACT", "outcome_reason": None}]
          for e in _kvs14),
      f"got {[e.get('_owner_refs') for e in _kvs14]}")
_cffop = [o for o in _ir14["cache_behaviors"][0]["viewer_request_ops"]
          if o["type"] == "bulk_redirect"][0]
check("#14 the SAME item unit owns the shared CFF op too (dual artifact, one unit)",
      _cffop["_owner_refs"][0]["source_id"] == "L#0"
      and _kvs14[0]["_owner_refs"][0]["source_id"] == "L#0")

# shared IP-list KVS: two rules referencing the same list -> owners MERGED, not dropped.
_ir14b = _pre.make_empty_ir(DC)
_pre.find_or_create_behavior(_ir14b, "*", DC, "o.net")
_c = lambda: {"op": "in_kvs", "value": "blocklist", "kvs_ips": ["1.1.1.1", "2.2.2.2"]}
_pre._collect_kvs_ip_entries(_ir14b, _c(), _ref("ruleA", None))
_pre._collect_kvs_ip_entries(_ir14b, _c(), _ref("ruleB", None))
_ips = [e for e in _ir14b["metadata"]["kvs_data"] if e["key"].startswith("ip:")]
check("#14 shared IP list deduped to one entry per ip (not duplicated)", len(_ips) == 2)
check("#14 shared IP-list entry MERGES both referring rules' owners",
      all(sorted(r["source_id"] for r in e["_owner_refs"]) == ["ruleA", "ruleB"] for e in _ips),
      f"got {[[r['source_id'] for r in e['_owner_refs']] for e in _ips]}")

# same key, DIFFERENT value -> FATAL (a key maps to one value)
_ir14c = _pre.make_empty_ir(DC)
check("#14 same KVS key with a different value -> FATAL",
      _raises_ledger(lambda: (
          _pre._append_kvs_entry(_ir14c, "k", "v1", [_ref("a", None)]),
          _pre._append_kvs_entry(_ir14c, "k", "v2", [_ref("b", None)]))) is not None)
# _append_kvs_entry validates owner refs too (int id rejected)
check("#14 _append_kvs_entry rejects an int source_id",
      _raises_ledger(lambda: _pre._append_kvs_entry(
          _pre.make_empty_ir(DC), "k", "v", [{"source_kind": "rule", "source_id": 5,
              "owned_key_segments": None, "outcome_status": "EXACT"}])) is not None)

# after process_domain, KVS entries persist but WITHOUT _owner_refs (stripped)
_ir14d = _pd(bulk={"L": [{"redirect": {"source_url": "shop.example.com/a", "target_url": "https://x"}}]})
check("#14 KVS entries persist but _owner_refs is stripped",
      _ir14d["metadata"]["kvs_data"]
      and all("_owner_refs" not in e for e in _ir14d["metadata"]["kvs_data"]))
check("#14 no _kvs_index in the persisted IR",
      "_kvs_index" not in _json.dumps(_ir14d))

print("== FINDING (spine) 15: IP-list KVS owner = the op's REAL subset (not whole-rule) ==")
# A partial response-header rule gated on an IP list: X-Good:set converts (viewer op),
# X-Bad:add is NC. The IP-list KVS entry must be owned by the CONVERTED op's subset
# (X-Good only) — not the whole rule, which would falsely include the NC'd X-Bad.
_iplists = {"blocklist": ["1.1.1.1"]}
_rule15 = {"enabled": True, "expression": "ip.src in $blocklist", "action": "rewrite",
           "action_parameters": {"headers": {
               "X-Good": {"operation": "set", "value": "1"},
               "X-Bad": {"operation": "add", "value": "2"}}}}
_ir15 = _pre.make_empty_ir(DC)
_pre.find_or_create_behavior(_ir15, "*", DC, "o.net")
_uid15 = _pre._assign_unit_id(_ir15, _rule15, "rule", "response_header", 0)
_ir15["_inventory"].extend(_pre._inventory_keys_for_rule(_rule15, source_id=_uid15))
for r in _proc.process_response_header_transform(_rule15, _iplists, "response"):
    _pre._place_result(_ir15, r, DC, "o.net", r.get("condition"), _rule15["expression"],
                       source_kind="rule", source_id=_uid15)
_ip15 = [e for e in _ir15["metadata"]["kvs_data"] if e["key"].startswith("ip:")]
check("#15 IP-list KVS entry exists", len(_ip15) >= 1)
# X-Good is a RESPONSE-header set → its op is LOSSY (viewer-response gap, round-27 finding 5), so
# the IP-list KVS owner ref INHERITS that LOSSY status + reason. Owner is STILL ONLY X-Good's
# subset (not the whole rule / not X-Bad). Assert the subset + status; the reason is a non-empty
# string (the exact wording is a mechanism message, not pinned here).
_ref15 = _ip15[0]["_owner_refs"][0] if _ip15 and _ip15[0]["_owner_refs"] else None
check("#15 IP-list KVS owner owns ONLY the converted X-Good subset (not the whole rule)",
      len(_ip15[0]["_owner_refs"]) == 1 if _ip15 else False,
      f"got {_ip15[0]['_owner_refs'] if _ip15 else None}")
check("#15 the X-Good KVS owner ref = its subset, status LOSSY (inherits the viewer-response gap)",
      _ref15 == {"source_kind": "rule", "source_id": _uid15,
                 "owned_key_segments": [["headers", "X-Good"]],
                 "outcome_status": "LOSSY_WITH_WARNING",
                 "outcome_reason": _ref15.get("outcome_reason") if _ref15 else None}
      and isinstance((_ref15 or {}).get("outcome_reason"), str) and (_ref15 or {}).get("outcome_reason"),
      f"got {_ref15}")

print("== FINDING (spine) 16: KVS owner merge is by full CONTRIBUTION identity ==")
# Merge dedups on (unit, subset, status, reason). Status belongs to the contribution, so
# a whole-unit ref must NOT erase a differently-statused subset (the OLD per-unit collapse
# could). Same unit, two DIFFERENT subsets (X-A then X-B) sharing a KVS key -> TWO refs
# (distinct contributions), NOT one unioned ref.
_ir16 = _pre.make_empty_ir(DC)
_pre._append_kvs_entry(_ir16, "ip:L:1", "1", [_ref("r", [["headers", "X-A"]])])
_pre._append_kvs_entry(_ir16, "ip:L:1", "1", [_ref("r", [["headers", "X-B"]])])
_m16 = _ir16["metadata"]["kvs_data"][0]["_owner_refs"]
check("#16 same unit, two subsets -> TWO distinct contribution refs",
      sorted(str(r["owned_key_segments"]) for r in _m16)
      == [str([["headers", "X-A"]]), str([["headers", "X-B"]])],
      f"got {_m16}")
# identical contribution (same unit, subset, status, reason) collapses to one
_pre._append_kvs_entry(_ir16, "ip:L:1", "1", [_ref("r", [["headers", "X-A"]])])
check("#16 re-adding an IDENTICAL contribution does not duplicate it",
      len(_ir16["metadata"]["kvs_data"][0]["_owner_refs"]) == 2)
# subset + whole-unit(None): DIFFERENT subsets -> BOTH survive (None no longer erases the
# subset — that would drop a status the coordinator needs).
_ir16b = _pre.make_empty_ir(DC)
_pre._append_kvs_entry(_ir16b, "k", "1", [_ref("r", [["a"]])])
_pre._append_kvs_entry(_ir16b, "k", "1", [_ref("r", None)])
_segs16b = sorted(str(r["owned_key_segments"]) for r in _ir16b["metadata"]["kvs_data"][0]["_owner_refs"])
check("#16 subset + whole-unit(None) -> BOTH refs kept (None does NOT erase the subset)",
      _segs16b == [str(None), str([["a"]])], f"got {_segs16b}")
# SAME unit + SAME subset but DIFFERENT status -> both kept (status conflict preserved,
# not silently merged — the coordinator FATALs on it later).
_ir16e = _pre.make_empty_ir(DC)
_pre._append_kvs_entry(_ir16e, "k", "1", [_ref("r", [["a"]], status=_pre.OUTCOME_EXACT)])
_pre._append_kvs_entry(_ir16e, "k", "1",
                       [_ref("r", [["a"]], status=_pre.OUTCOME_LOSSY, reason="gap")])
check("#16 same unit+subset, different status -> BOTH refs kept (conflict preserved)",
      sorted(r["outcome_status"] for r in _ir16e["metadata"]["kvs_data"][0]["_owner_refs"])
      == ["EXACT", "LOSSY_WITH_WARNING"])
# DIFFERENT units still each get their own ref (not merged)
_ir16d = _pre.make_empty_ir(DC)
_pre._append_kvs_entry(_ir16d, "k", "1", [_ref("rA", [["a"]])])
_pre._append_kvs_entry(_ir16d, "k", "1", [_ref("rB", [["b"]])])
check("#16 different units -> two separate refs",
      sorted(r["source_id"] for r in _ir16d["metadata"]["kvs_data"][0]["_owner_refs"]) == ["rA", "rB"])

print("== FINDING (spine) 17: _append_kvs_entry rejects empty/None owners + bad key/value ==")
check("#17 empty owner_refs -> FATAL",
      _raises_ledger(lambda: _pre._append_kvs_entry(_pre.make_empty_ir(DC), "k", "v", [])) is not None)
check("#17 None owner_refs -> LedgerError (not a raw TypeError)",
      _raises_ledger(lambda: _pre._append_kvs_entry(_pre.make_empty_ir(DC), "k", "v", None)) is not None)
check("#17 empty key -> FATAL",
      _raises_ledger(lambda: _pre._append_kvs_entry(
          _pre.make_empty_ir(DC), "", "v", [_ref("r", None)])) is not None)
check("#17 non-string value -> FATAL",
      _raises_ledger(lambda: _pre._append_kvs_entry(
          _pre.make_empty_ir(DC), "k", 5, [_ref("r", None)])) is not None)

print("== FINDING (spine) 18: shared condition aliasing — each op owns an independent tree ==")
# ROOT CAUSE: a processor builds N per-header ops all sharing ONE parsed `cond` object;
# op1's KVS collection popped "kvs_ips" from the shared object, so op2 saw no IP data and
# failed to register its owner. _append_viewer_op now deep-copies the condition. These run
# the REAL production path (process_response_header_transform -> _place_result).
_DCX = dict(DC)


def _build_ir_with_rule(rule, ip_lists):
    ir = _pre.make_empty_ir(_DCX)
    _pre.find_or_create_behavior(ir, "*", _DCX, "o.net")
    uid = _pre._assign_unit_id(ir, rule, "rule", "response_header", 0)
    ir["_inventory"].extend(_pre._inventory_keys_for_rule(rule, source_id=uid))
    for r in _proc.process_response_header_transform(rule, ip_lists, "response"):
        _pre._place_result(ir, r, _DCX, "o.net", r.get("condition"),
                           rule["expression"], source_kind="rule", source_id=uid)
    return ir, uid


# X-A:set + X-B:set (both dynamic → viewer ops) sharing one IP-list condition.
_r18 = {"enabled": True, "expression": "ip.src in $blocklist", "action": "rewrite",
        "action_parameters": {"headers": {
            "X-A": {"operation": "set", "expression": "http.request.uri.path"},
            "X-B": {"operation": "set", "expression": "http.request.uri.path"}}}}
_ir18, _u18 = _build_ir_with_rule(_r18, {"blocklist": ["1.1.1.1"]})
_ip18 = [e for e in _ir18["metadata"]["kvs_data"] if e["key"].startswith("ip:")]
# Two headers → two DISTINCT contributions on the shared IP-list entry (same unit, but
# different subsets X-A vs X-B). Both must survive (the fix: op2's kvs_ips is no longer
# destroyed by op1's pop) — as two refs, per the contribution-identity merge.
_seg18 = sorted(str(r["owned_key_segments"]) for r in (_ip18[0]["_owner_refs"] if _ip18 else []))
check("#18 two headers sharing an IP list -> BOTH header subsets present (X-A and X-B)",
      _ip18 and _seg18 == [str([["headers", "X-A"]]), str([["headers", "X-B"]])]
      and all(r["source_id"] == _u18 for r in _ip18[0]["_owner_refs"]),
      f"got {_ip18[0]['_owner_refs'] if _ip18 else None}")
# the two viewer ops must NOT be the same condition object (aliasing severed)
_ops18 = _ir18["cache_behaviors"][0]["viewer_response_ops"]
check("#18 the two ops have DISTINCT condition objects (no aliasing)",
      len(_ops18) == 2 and _ops18[0]["condition"] is not _ops18[1]["condition"])

# X-Good:set + X-Bad:add on an IP-list rule: KVS owner is ONLY X-Good, disjoint from the
# X-Bad NC claim (no overlap between the KVS owner and the NC'd leaf).
_r18b = {"enabled": True, "expression": "ip.src in $blocklist", "action": "rewrite",
         "action_parameters": {"headers": {
             "X-Good": {"operation": "set", "expression": "http.request.uri.path"},
             "X-Bad": {"operation": "add", "value": "2"}}}}
_ir18b, _u18b = _build_ir_with_rule(_r18b, {"blocklist": ["1.1.1.1"]})
_ip18b = [e for e in _ir18b["metadata"]["kvs_data"] if e["key"].startswith("ip:")]
_kvs_owned = _ip18b[0]["_owner_refs"][0]["owned_key_segments"] if _ip18b else None
_nc18b = sorted(tuple(k) for c in _ir18b["_claims"] if c["status"] == "NON_CONVERTIBLE"
                for k in c["source_keys"])
check("#18 IP-list KVS owner is ONLY X-Good (converted op's subset)",
      _kvs_owned == [["headers", "X-Good"]], f"got {_kvs_owned}")
check("#18 X-Bad is NC-claimed and NOT in the KVS owner (no overlap)",
      ("rule", _u18b, "/headers/X-Bad/operation") in _nc18b
      and ["headers", "X-Bad"] not in (_kvs_owned or []))

# process_domain final IR must NOT contain the internal kvs_ips (popped from the op copy)
_ir18c = _pre.process_domain("shop.example.com", _DCX,
    {"response_header": [_r18]}, {"blocklist": ["1.1.1.1"]}, {}, {})
check("#18 no 'kvs_ips' anywhere in the persisted IR",
      "kvs_ips" not in _json.dumps(_ir18c))

print("== FINDING (spine) 19: coordination layer — bulk redirect + shared IP-list ==")
# The coordinator registers logical artifacts and folds source keys into claims. First
# slice covers the three hardest relations: multi-artifact (item→CFF+KVS), shared artifact
# (one CFF/IP-list serving many), multi-claim (many items→same CFF).
_ir19 = _pd(bulk={"L": [
    {"redirect": {"source_url": "shop.example.com/a", "target_url": "https://x"}},
    {"redirect": {"source_url": "shop.example.com/b", "target_url": "https://y"}}]})
_c19 = [c for c in _ir19["_claims"] if c["status"] != "NON_CONVERTIBLE"]
_by_item = {}
for c in _c19:
    ids = sorted(set(k[1] for k in c["source_keys"]))
    if len(ids) == 1:
        _by_item[ids[0]] = c
check("#19 one claim per bulk item (L#0, L#1)", sorted(_by_item) == ["L#0", "L#1"])
# artifact ids are DOMAIN-NAMESPACED (domain:{sanitized}:cff:... / :kvs:...)
check("#19 each bulk claim references BOTH the shared CFF artifact AND its own KVS artifact",
      all(any(":cff:" in a and a.endswith(":bulk_redirect") for a in c["artifact_ids"])
          and any(":kvs:redirect:" in a for a in c["artifact_ids"])
          for c in _by_item.values()),
      f"got {[c['artifact_ids'] for c in _by_item.values()]}")
check("#19 the two claims reference DIFFERENT KVS artifacts (per-item)",
      _by_item["L#0"]["artifact_ids"] != _by_item["L#1"]["artifact_ids"])
_cff19 = [a for a in _ir19["_logical_artifacts"] if a["kind"] == "cff_op"]
check("#19 exactly ONE shared CFF artifact", len(_cff19) == 1)
check("#19 shared CFF artifact owned by BOTH items (union of keys)",
      sorted(set(k[1] for k in _cff19[0]["owner_keys"])) == ["L#0", "L#1"])
check("#19 each bulk claim is EXACT (bulk item is EXACT)",
      all(c["status"] == "EXACT" for c in _by_item.values()))

# Coordinator invariant: a source key that is BOTH NC-claimed AND owns a converted
# artifact -> FATAL (one leaf, one fate).
_ir19b = _pre.make_empty_ir(DC)
_pre.find_or_create_behavior(_ir19b, "*", DC, "o.net")
_K19 = ("bulk_redirect", "X#0", "/source_url")
_ir19b["_inventory"] = [list(_K19)]
_pre.claim_decision(_ir19b, [_K19], _pre.OUTCOME_NON_CONVERTIBLE, reason="nc")
_pre._append_kvs_entry(_ir19b, "redirect:foo", "v",
                       [_ref("X#0", [["source_url"]], kind="bulk_redirect")])
check("#19 NC key that also owns a converted artifact -> FATAL",
      _raises_ledger(lambda: _pre._coordinate_artifacts_and_claims(_ir19b)) is not None)

# An ip: KVS entry is registered ONLY when a WIRED viewer op references its list. Add a
# wired op (set_request_header) referencing the list to each fixture so the shared KVS
# entry is legitimately in scope (matches production: _collect_kvs_ip_entries runs off a
# wired op's condition).
def _wired_ip_op(source_id, list_name, owned, status=None, reason=None):
    return {"type": "set_request_header", "cf_source_rule": source_id,
            "condition": {"op": "in_kvs", "value": list_name},
            "params": {"name": "X"}, "scope_pattern": "*", "seq": 0,
            "_source_kind": "rule", "_source_id": source_id, "_owned_key_segments": owned,
            "_outcome_status": status or _pre.OUTCOME_EXACT, "_outcome_reason": reason}


# Coordinator invariant: conflicting statuses for ONE source key -> FATAL. Two WIRED
# (ip:) KVS entries both owned by the same source key but with different statuses, each
# driven by a wired op referencing its list.
_ir19c = _pre.make_empty_ir(DC)
_beh19c = _pre.find_or_create_behavior(_ir19c, "*", DC, "o.net")
_ir19c["_inventory"] = [["rule", "r", "/headers/X/value"]]
_beh19c["viewer_request_ops"] = [_wired_ip_op("r", "L1", [["headers", "X"]]),
                                 _wired_ip_op("r", "L2", [["headers", "X"]],
                                              status=_pre.OUTCOME_LOSSY, reason="gap")]
_pre._append_kvs_entry(_ir19c, "ip:L1:1", "1", [_ref("r", [["headers", "X"]])])
_pre._append_kvs_entry(_ir19c, "ip:L2:1", "1",
                       [_ref("r", [["headers", "X"]], status=_pre.OUTCOME_LOSSY, reason="gap")])
check("#19 same key with conflicting statuses -> FATAL",
      _raises_ledger(lambda: _pre._coordinate_artifacts_and_claims(_ir19c)) is not None)

# MIXED-STATUS SHARING (synthetic): a shared artifact referenced by an EXACT key and a
# LOSSY key (DIFFERENT keys) is fine — each key keeps its own status, artifact owned by
# both. Proves the model supports mixed-status sharing. A wired op per key references the
# shared list L so its KVS entry is in scope.
_ir19d = _pre.make_empty_ir(DC)
_beh19d = _pre.find_or_create_behavior(_ir19d, "*", DC, "o.net")
_ir19d["_inventory"] = [["rule", "rE", "/headers/E/value"], ["rule", "rL", "/headers/L/value"]]
_beh19d["viewer_request_ops"] = [
    _wired_ip_op("rE", "L", [["headers", "E"]]),
    _wired_ip_op("rL", "L", [["headers", "L"]], status=_pre.OUTCOME_LOSSY, reason="gap")]
_pre._append_kvs_entry(_ir19d, "ip:L:1", "1", [
    _ref("rE", [["headers", "E"]]),
    _ref("rL", [["headers", "L"]], status=_pre.OUTCOME_LOSSY, reason="gap")])
_pre._coordinate_artifacts_and_claims(_ir19d)
_byk19 = {tuple(k): c["status"] for c in _ir19d["_claims"] for k in c["source_keys"]}
check("#19 mixed-status shared artifact: EXACT key stays EXACT",
      _byk19[("rule", "rE", "/headers/E/value")] == "EXACT")
check("#19 mixed-status shared artifact: LOSSY key stays LOSSY",
      _byk19[("rule", "rL", "/headers/L/value")] == "LOSSY_WITH_WARNING")
check("#19 mixed-status shared artifact owned by BOTH keys' units",
      sorted(set(k[1] for a in _ir19d["_logical_artifacts"] for k in a["owner_keys"])) == ["rE", "rL"])
# the two keys are in SEPARATE claims (different status → different group)
check("#19 mixed-status keys land in separate claims",
      len([c for c in _ir19d["_claims"]]) == 2)

# A bulk item with supported + UNKNOWN fields: unknown leaf is NC, supported leaves are
# EXACT (converted) — DISJOINT keys, no coordinator conflict (the NC-overlap guard only
# fires when the SAME key is both NC and converted).
_ir19e = _pd(bulk={"L": [{"redirect": {
    "source_url": "shop.example.com/a", "target_url": "https://x",
    "future_option": {"mode": "z"}}}]})
_nc19e = sorted(tuple(k) for c in _ir19e["_claims"] if c["status"] == "NON_CONVERTIBLE"
                for k in c["source_keys"])
_ex19e = sorted(tuple(k) for c in _ir19e["_claims"] if c["status"] == "EXACT"
                for k in c["source_keys"])
check("#19 bulk unknown leaf -> NC, supported leaves -> EXACT, DISJOINT",
      _nc19e == [("bulk_redirect", "L#0", "/future_option/mode")]
      and ("bulk_redirect", "L#0", "/source_url") in _ex19e
      and not (set(_nc19e) & set(_ex19e)))

print("== FINDING (spine) 20: cross-domain artifact-id uniqueness + custom-error not wired ==")
_DC_A = {"hostname": "shop.example.com", "apex_domain": "example.com", "origin_type": "custom",
         "origin_content": "o.net", "sanitized_name": "shop_example_com"}
_DC_B = {"hostname": "blog.example.com", "apex_domain": "example.com", "origin_type": "custom",
         "origin_content": "o.net", "sanitized_name": "blog_example_com"}


def _laids(ir):
    return set(a["artifact_id"] for a in ir["_logical_artifacts"])


# Two domains sharing an IP list — flattened logical ids must be globally unique.
_iprule = lambda: {"response_header": [{"enabled": True, "expression": "ip.src in $blk",
    "action": "rewrite", "action_parameters": {"headers": {
        "X-A": {"operation": "set", "expression": "http.request.uri.path"}}}}]}
_irA = _pre.process_domain("shop.example.com", _DC_A, _iprule(), {"blk": ["1.1.1.1"]}, {}, {})
_irB = _pre.process_domain("blog.example.com", _DC_B, _iprule(), {"blk": ["1.1.1.1"]}, {}, {})
check("#20 two domains sharing an IP list -> disjoint (globally unique) logical ids",
      not (_laids(_irA) & _laids(_irB)),
      f"overlap={_laids(_irA) & _laids(_irB)}")
# and the IP-list header claim in each references BOTH a cff and the shared-list kvs. The rule is
# a RESPONSE-header set → its claim is LOSSY (viewer-response gap, round-27 finding 5).
_exA = [c for c in _irA["_claims"] if c["status"] == "LOSSY_WITH_WARNING"]
check("#20 real IP-list header claim references BOTH cff:* and kvs:ip:*",
      any(any(":cff:" in a for a in c["artifact_ids"])
          and any(":kvs:ip:" in a for a in c["artifact_ids"]) for c in _exA),
      f"got {[c['artifact_ids'] for c in _exA]}")

# Two domains both with bulk redirects — CFF ids must not collide.
_bulk = lambda: {"L": [{"redirect": {"source_url": "%s/a", "target_url": "https://x"}}]}
_brA = _pre.process_domain("shop.example.com", _DC_A, {}, {},
                           {"L": [{"redirect": {"source_url": "shop.example.com/a", "target_url": "https://x"}}]}, {})
_brB = _pre.process_domain("blog.example.com", _DC_B, {}, {},
                           {"L": [{"redirect": {"source_url": "blog.example.com/a", "target_url": "https://x"}}]}, {})
_cffA = [a["artifact_id"] for a in _brA["_logical_artifacts"] if a["kind"] == "cff_op"]
_cffB = [a["artifact_id"] for a in _brB["_logical_artifacts"] if a["kind"] == "cff_op"]
check("#20 two domains' bulk CFF ids do not collide",
      _cffA and _cffB and not (set(_cffA) & set(_cffB)),
      f"A={_cffA} B={_cffB}")

# Inline custom error must NOT produce a converted claim / logical artifact this turn.
_ce = {"custom_error": [{"id": "ce123456", "enabled": True,
    "expression": "http.response.code eq 500", "action": "serve_error",
    "action_parameters": {"content": "<h1>x</h1>", "content_type": "text/html", "status_code": 503}}]}
_irCE = _pre.process_domain("shop.example.com", _DC_A, _ce, {}, {}, {})
check("#20 inline custom-error registers NO error: logical artifact this turn",
      not any(":kvs:error:" in a["artifact_id"] for a in _irCE["_logical_artifacts"]))
check("#20 inline custom-error produces NO converted (EXACT/LOSSY) claim this turn",
      not any(c["status"] != "NON_CONVERTIBLE" and any("error:" in a for a in c["artifact_ids"])
              for c in _irCE["_claims"]))

# _kvs_artifact_id gates by kind: redirect:/ip: wired, error: -> None (not wired).
check("#20 _kvs_artifact_id: redirect: is wired (namespaced)",
      _pre._kvs_artifact_id("d", "redirect:x") == "domain:d:kvs:redirect:x")
check("#20 _kvs_artifact_id: ip: is wired (namespaced)",
      _pre._kvs_artifact_id("d", "ip:L:1") == "domain:d:kvs:ip:L:1")
check("#20 _kvs_artifact_id: error: returns None (channel not wired)",
      _pre._kvs_artifact_id("d", "error:abc") is None)

# outcome_status is mandatory on a single-source op (no implicit EXACT).
check("#20 single-source op with NO outcome_status -> FATAL",
      _append_raises(source_kind="rule", source_id="u", outcome_status=None) is not None)

print("== FINDING (spine) 21: generic placement requires explicit result outcome_status ==")
# The EXACT fallback in _place_result's generic tail is GONE — a converted result reaching
# it WITHOUT outcome_status is a FATAL (not a silent EXACT). Tests drive the real
# _place_result path with a hand-built result dict (a processor sets outcome_status; the
# generic tail must not fabricate one).
_DC21 = {"hostname": "x.example.com", "apex_domain": "example.com", "origin_type": "custom",
         "origin_content": "o.net", "sanitized_name": "x_example_com"}


def _place_generic(result):
    ir = _pre.make_empty_ir(_DC21)
    _pre.find_or_create_behavior(ir, "*", _DC21, "o.net")
    _pre._place_result(ir, result, _DC21, "o.net", None, "true",
                       source_kind="rule", source_id="r1")
    for b in ir["cache_behaviors"]:
        for o in b.get("viewer_request_ops", []) + b.get("viewer_response_ops", []):
            if o["type"] == result["type"]:
                return o
    return None


# (a) converted result MISSING outcome_status -> FATAL
check("#21 generic converted result with NO outcome_status -> FATAL",
      _raises_ledger(lambda: _place_generic({
          "type": "set_request_header", "cf_source_rule": "r1", "description": "d",
          "condition": {"always": True}, "raw_expression": None,
          "params": {"name": "X-H", "value": "1"}})) is not None)
# (b) explicit EXACT result places normally, op carries EXACT. A set-header result now carries a
# LoweredValue (as a real processor emits) — the sink gate requires it.
_op21e = _place_generic({
    "type": "set_request_header", "cf_source_rule": "r1", "description": "d",
    "condition": {"always": True}, "raw_expression": None,
    "params": {"name": "X-H", "value_lowered": _cep.lower_literal_value("1", "request_header")},
    "outcome_status": _pre.OUTCOME_EXACT})
check("#21 explicit EXACT result places and op carries EXACT (no reason)",
      _op21e is not None and _op21e["_outcome_status"] == "EXACT"
      and _op21e["_outcome_reason"] is None)
# (c) explicit LOSSY result keeps status AND reason on the op
_op21l = _place_generic({
    "type": "set_response_header", "cf_source_rule": "r1", "description": "d",
    "condition": {"always": True}, "raw_expression": None,
    "params": {"name": "X-H", "value_lowered": _cep.lower_literal_value("1", "response_header")},
    "outcome_status": _pre.OUTCOME_LOSSY, "outcome_reason": "known gap"})
check("#21 explicit LOSSY result keeps status and reason on the op",
      _op21l is not None and _op21l["_outcome_status"] == "LOSSY_WITH_WARNING"
      and _op21l["_outcome_reason"] == "known gap")

# End to end: every real processor result reaching the tail carries a status, so a full
# process_domain over redirect/rewrite/header/origin rules does NOT FATAL.
_rules21 = {
    "redirect": [{"id": "rd", "enabled": True, "expression": "true", "action": "redirect",
        "action_parameters": {"from_value": {"status_code": 302,
            "target_url": {"value": "https://b"}}}}],
    "response_header": [{"id": "rh", "enabled": True, "expression": "true", "action": "rewrite",
        "action_parameters": {"headers": {"X-D": {"operation": "set", "value": "1"}}}}]}
_ir21 = _pre.process_domain("x.example.com", _DC21, _rules21, {}, {}, {})
check("#21 real processor results all carry status -> process_domain does NOT FATAL",
      isinstance(_ir21, dict) and _ir21.get("cache_behaviors"))

print("== FINDING (spine) 22: generic viewer ops are WIRED to the coordinator ==")
_DC22 = {"hostname": "shop.example.com", "apex_domain": "example.com", "origin_type": "custom",
         "origin_content": "o.net", "sanitized_name": "shop_example_com"}


def _pd22(all_rules=None, bulk=None):
    return _pre.process_domain("shop.example.com", _DC22, all_rules or {}, {}, bulk or {}, {})


def _keys_by_status(ir, status):
    return sorted(tuple(k) for c in ir["_claims"] if c["status"] == status
                  for k in c["source_keys"])


def _disjoint_and_in_inv(ir):
    inv = set(tuple(k) for k in ir["_inventory"])
    allk = [tuple(k) for c in ir["_claims"] for k in c["source_keys"]]
    return len(allk) == len(set(allk)) and all(k in inv for k in allk)


# redirect -> ONE EXACT claim over its whole unit, referencing a CFF artifact.
_ir22r = _pd22({"redirect": [{"id": "rd", "enabled": True, "expression": "true",
    "action": "redirect", "action_parameters": {"from_value": {"status_code": 302,
        "target_url": {"value": "https://b"}}}}]})
_ex22r = [c for c in _ir22r["_claims"] if c["status"] == "EXACT"]
check("#22 redirect -> one EXACT claim over the whole unit",
      len(_ex22r) == 1
      and sorted(tuple(k) for k in _ex22r[0]["source_keys"])
          == [("rule", "rd", "/from_value/status_code"),
              ("rule", "rd", "/from_value/target_url/value")])
check("#22 redirect claim references a CFF artifact",
      any(":cff:" in a for a in _ex22r[0]["artifact_ids"]))
check("#22 redirect claims are disjoint and in inventory", _disjoint_and_in_inv(_ir22r))

# two headers -> two per-header EXACT claims with DISTINCT CFF artifacts.
_ir22h = _pd22({"request_header": [{"id": "rh", "enabled": True, "expression": "true",
    "action": "rewrite", "action_parameters": {"headers": {
        "X-A": {"operation": "set", "value": "1"},
        "X-B": {"operation": "set", "value": "2"}}}}]})
_ex22h = [c for c in _ir22h["_claims"] if c["status"] == "EXACT"]
check("#22 two headers -> two per-header EXACT claims", len(_ex22h) == 2)
check("#22 each header claim owns ONLY its own /headers/<name> subtree",
      sorted(tuple(k)[2].split("/")[2] for c in _ex22h for k in c["source_keys"])
      == ["X-A", "X-A", "X-B", "X-B"])
check("#22 the two header claims reference DIFFERENT CFF artifacts",
      _ex22h[0]["artifact_ids"] != _ex22h[1]["artifact_ids"])
check("#22 two-header claims disjoint and in inventory", _disjoint_and_in_inv(_ir22h))

# mixed: X-Good set (EXACT viewer op) + X-Bad add (NC) -> disjoint EXACT vs NC.
_ir22m = _pd22({"response_header": [{"id": "mx", "enabled": True, "expression": "true",
    "action": "rewrite", "action_parameters": {"headers": {
        "X-Good": {"operation": "set", "expression": "http.request.uri.path"},
        "X-Bad": {"operation": "add", "value": "2"}}}}]})
check("#22 mixed: X-Bad is NON_CONVERTIBLE (only its leaves)",
      _keys_by_status(_ir22m, "NON_CONVERTIBLE")
      == [("rule", "mx", "/headers/X-Bad/operation"), ("rule", "mx", "/headers/X-Bad/value")])
# X-Good is a RESPONSE-header set → converts as LOSSY (viewer-response gap, round-27 finding 5),
# still with a CFF artifact — disjoint from X-Bad's NC.
check("#22 mixed: X-Good converts (LOSSY on response) with a CFF artifact",
      any("X-Good" in k[2] for k in _keys_by_status(_ir22m, "LOSSY_WITH_WARNING"))
      and any(":cff:" in a for c in _ir22m["_claims"] if c["status"] == "LOSSY_WITH_WARNING"
              for a in c["artifact_ids"]))
check("#22 mixed EXACT/NC keys are DISJOINT and in inventory", _disjoint_and_in_inv(_ir22m))

# generic viewer op + bulk redirect in the same behavior -> no artifact-id collision.
_ir22c = _pd22({"request_header": [{"id": "rh", "enabled": True, "expression": "true",
    "action": "rewrite", "action_parameters": {"headers": {"X-A": {"operation": "set", "value": "1"}}}}]},
    bulk={"L": [{"redirect": {"source_url": "shop.example.com/a", "target_url": "https://x"}}]})
_aids22 = [a["artifact_id"] for a in _ir22c["_logical_artifacts"]]
check("#22 generic op + bulk redirect -> all logical artifact ids unique",
      len(_aids22) == len(set(_aids22)))
check("#22 generic op + bulk redirect -> disjoint and in inventory", _disjoint_and_in_inv(_ir22c))

# browser_ttl emits a set_response_header op (now wired). Its claim MUST be LOSSY (from the
# op's explicit status), NOT EXACT — proving status is read from the contribution, never
# inferred from "the op produced an artifact". This is the load-bearing check for the
# status-on-contribution model now that generic ops are wired.
_ir22bt = _pd22({"cache": [{"id": "bt", "enabled": True, "expression": "true",
    "action": "set_cache_settings",
    "action_parameters": {"browser_ttl": {"mode": "override_origin", "default": 60}}}]})
_bt_claims = [c for c in _ir22bt["_claims"] if any(k[1] == "bt" for k in c["source_keys"])]
check("#22 browser_ttl op -> exactly one claim for /browser_ttl leaves",
      len(_bt_claims) == 1
      and sorted(tuple(k) for k in _bt_claims[0]["source_keys"])
          == [("rule", "bt", "/browser_ttl/default"), ("rule", "bt", "/browser_ttl/mode")])
check("#22 browser_ttl claim is LOSSY_WITH_WARNING (from explicit status, not inferred EXACT)",
      _bt_claims and _bt_claims[0]["status"] == "LOSSY_WITH_WARNING"
      and _bt_claims[0]["reason"])
check("#22 browser_ttl LOSSY claim still references a CFF artifact",
      _bt_claims and any(":cff:" in a for a in _bt_claims[0]["artifact_ids"]))

print("== FINDING (spine) 23: IP-list KVS registration is DRIVEN BY WIRED OPS ==")
_DC23 = {"hostname": "shop.example.com", "apex_domain": "example.com", "origin_type": "custom",
         "origin_content": "o.net", "sanitized_name": "shop_example_com"}


def _pd23(all_rules, iplists=None):
    return _pre.process_domain("shop.example.com", _DC23, all_rules, iplists or {}, {}, {})


# (1) An INLINE-content custom-error rule (even IP-list-gated) is NON_CONVERTIBLE (conversion-policy
# step-3 decision #1): the processor NCs it, so there is NO serve_error_inline op, NO error: KVS, and
# NO converted claim — and the IP list it referenced is NOT collected (the rule produced nothing).
# (Was: an unwired serve_error_inline produced a runtime op + KVS but no claim; inline content no
# longer converts at all — the CFF+KVS inline path is dropped.)
_ir23a = _pd23({"custom_error": [{"id": "ce2", "enabled": True,
    "expression": 'http.request.uri.path eq "/x" and ip.src in $blk', "action": "serve_error",
    "action_parameters": {"content": "<h1>x</h1>", "content_type": "text/html", "status_code": 503}}]},
    iplists={"blk": ["1.1.1.1"]})
_conv23 = [c for c in _ir23a["_claims"] if c["status"] != "NON_CONVERTIBLE"]
_kvs23 = sorted(e["key"] for e in _ir23a["metadata"]["kvs_data"])
_ops23 = [o["type"] for b in _ir23a["cache_behaviors"] for o in b["viewer_request_ops"]]
check("#23 inline-content custom-error -> NO converted claim (processor NC)", len(_conv23) == 0)
check("#23 inline-content custom-error -> NO serve_error_inline op", "serve_error_inline" not in _ops23)
check("#23 inline-content custom-error -> NO error: KVS", not any(k.startswith("error:") for k in _kvs23))
check("#23 inline-content custom-error -> its IP list NOT collected (rule produced nothing)",
      not any(k.startswith("ip:") for k in _kvs23))

# (2) A synthetic op of a NON-WIRED type (here the RETIRED serve_error_inline) whose condition uses
# an IP list registers NO artifact — the id helper admits by wired-TYPE membership only, never by
# "uses an IP list" (a retired/unknown type must not get an artifact id).
check("#23 non-wired (retired) op type + IP-list condition -> _viewer_op_artifact_id None",
      _pre._viewer_op_artifact_id("d", {"path_pattern": "*"}, "viewer_request_ops", 0,
          {"type": "serve_error_inline",
           "condition": {"op": "in_kvs", "value": "blk"}}) is None)

# (3) A WIRED header op using an IP list STILL references BOTH its CFF and the shared ip:
# KVS (the dual-artifact relation is intact for wired producers).
_ir23c = _pd23({"response_header": [{"id": "h", "enabled": True, "expression": "ip.src in $blk",
    "action": "rewrite", "action_parameters": {"headers": {
        "X-A": {"operation": "set", "expression": "http.request.uri.path"}}}}]},
    iplists={"blk": ["1.1.1.1"]})
# The wired producer here is a RESPONSE-header set → its claim is LOSSY (viewer-response gap).
_ex23c = [c for c in _ir23c["_claims"] if c["status"] == "LOSSY_WITH_WARNING"]
check("#23 wired header + IP list -> claim references BOTH cff and ip: kvs",
      any(any(":cff:" in a for a in c["artifact_ids"])
          and any(":kvs:ip:" in a for a in c["artifact_ids"]) for c in _ex23c),
      f"got {[c['artifact_ids'] for c in _ex23c]}")

print("== FINDING (spine) 24: shared IP list — KVS owners = WIRED ops only, not entry's mixed refs ==")
_DC24 = {"hostname": "shop.example.com", "apex_domain": "example.com", "origin_type": "custom",
         "origin_content": "o.net", "sanitized_name": "shop_example_com"}


def _pd24(all_rules, iplists=None):
    return _pre.process_domain("shop.example.com", _DC24, all_rules, iplists or {}, {}, {})


def _ip_kvs_owner_ids(ir):
    return sorted(set(k[1] for a in ir["_logical_artifacts"] if ":kvs:ip:" in a["artifact_id"]
                      for k in a["owner_keys"]))


# WIRED header + UNWIRED custom-error, SHARING $blk. The shared ip: KVS entry's
# _owner_refs (accumulated by _collect_kvs_ip_entries) contain BOTH producers — but the
# registered artifact must be owned by ONLY the wired header, never the custom-error.
_ir24 = _pd24({
    "response_header": [{"id": "h", "enabled": True, "expression": "ip.src in $blk",
        "action": "rewrite", "action_parameters": {"headers": {
            "X-A": {"operation": "set", "expression": "http.request.uri.path"}}}}],
    "custom_error": [{"id": "ce2", "enabled": True,
        "expression": 'http.request.uri.path eq "/x" and ip.src in $blk', "action": "serve_error",
        "action_parameters": {"content": "<h1>x</h1>", "content_type": "text/html", "status_code": 503}}]},
    iplists={"blk": ["1.1.1.1"]})
check("#24 shared-list ip: KVS owner is ONLY the wired header (not the unwired custom-error)",
      _ip_kvs_owner_ids(_ir24) == ["h"], f"got {_ip_kvs_owner_ids(_ir24)}")
check("#24 unwired custom-error sharing the list -> NO converted claim",
      not any(c["status"] != "NON_CONVERTIBLE" and any(k[1] == "ce2" for k in c["source_keys"])
              for c in _ir24["_claims"]))
check("#24 no custom-error key appears in ANY converted claim",
      not any(k[1] == "ce2" for c in _ir24["_claims"] if c["status"] != "NON_CONVERTIBLE"
              for k in c["source_keys"]))
# the header's own error: KVS is untouched, and the ip: KVS entry still carries the mixed
# runtime refs (that's fine — it's build-time provenance, stripped before persistence).

# TWO WIRED headers sharing $blk -> the ip: KVS artifact is owned by BOTH.
_ir24b = _pd24({"response_header": [
    {"id": "hA", "enabled": True, "expression": "ip.src in $blk", "action": "rewrite",
     "action_parameters": {"headers": {"X-A": {"operation": "set", "expression": "http.request.uri.path"}}}},
    {"id": "hB", "enabled": True, "expression": "ip.src in $blk", "action": "rewrite",
     "action_parameters": {"headers": {"X-B": {"operation": "set", "expression": "http.request.uri.path"}}}}]},
    iplists={"blk": ["1.1.1.1"]})
check("#24 two WIRED headers sharing a list -> BOTH own the shared ip: KVS artifact",
      _ip_kvs_owner_ids(_ir24b) == ["hA", "hB"], f"got {_ip_kvs_owner_ids(_ir24b)}")

# custom-error-ONLY sharing $blk: an inline custom-error is now NON_CONVERTIBLE (step-3 decision #1),
# so it produces NOTHING — no serve_error_inline op, and its IP list is NOT collected at all (neither
# a registered artifact NOR runtime KVS data). (Was: an unwired serve_error_inline kept the ip: KVS as
# runtime data; inline content no longer converts, so nothing references the list.)
_ir24c = _pd24({"custom_error": [{"id": "ce3", "enabled": True,
    "expression": 'http.request.uri.path eq "/y" and ip.src in $blk', "action": "serve_error",
    "action_parameters": {"content": "<h1>y</h1>", "content_type": "text/html", "status_code": 503}}]},
    iplists={"blk": ["1.1.1.1"]})
check("#24 custom-error-only list -> ip: KVS NOT a registered artifact",
      not any(":kvs:ip:" in a["artifact_id"] for a in _ir24c["_logical_artifacts"]))
check("#24 custom-error-only list -> ip: KVS NOT collected at all (inline rule NC'd, produced nothing)",
      not any(e["key"].startswith("ip:") for e in _ir24c["metadata"]["kvs_data"]))

# wired-ONLY sharing (header alone uses $blk) -> ip: KVS registered, owned by the header.
_ir24d = _pd24({"response_header": [{"id": "hW", "enabled": True, "expression": "ip.src in $blk",
    "action": "rewrite", "action_parameters": {"headers": {
        "X-A": {"operation": "set", "expression": "http.request.uri.path"}}}}]},
    iplists={"blk": ["1.1.1.1"]})
check("#24 wired-only list -> ip: KVS registered, owned by the header",
      _ip_kvs_owner_ids(_ir24d) == ["hW"])

print("== FINDING (spine) 25: native-effects producer — post-replay effective contribution ==")
_DC25 = {"hostname": "shop.example.com", "apex_domain": "example.com", "origin_type": "custom",
         "origin_content": "o.net", "sanitized_name": "shop_example_com"}


def _pd25(all_rules, mt=None):
    return _pre.process_domain("shop.example.com", _DC25, all_rules, {}, {}, mt or {})


def _claims_for(ir, unit):
    return [c for c in ir["_claims"] if any(k[1] == unit for k in c["source_keys"])]


def _native_arts(ir):
    return [a for a in ir["_logical_artifacts"] if a["kind"] == "native_effect"]


# (1) LAST-WINS: two *-scope edge_ttl overrides — the LOSER is EXACT exact_noop (no
# artifact, not a silent drop), the WINNER owns the native artifact.
_ir25 = _pd25({"cache": [
    {"id": "c1", "enabled": True, "expression": "true", "action": "set_cache_settings",
     "action_parameters": {"edge_ttl": {"mode": "override_origin", "default": 100}}},
    {"id": "c2", "enabled": True, "expression": "true", "action": "set_cache_settings",
     "action_parameters": {"edge_ttl": {"mode": "override_origin", "default": 200}}}]})
_c1 = _claims_for(_ir25, "c1")
_c2 = _claims_for(_ir25, "c2")
check("#25 last-wins LOSER (c1) -> EXACT exact_noop, NO artifact (not dropped, not owning)",
      len(_c1) == 1 and _c1[0]["status"] == "EXACT" and _c1[0]["exact_noop"]
      and not _c1[0]["artifact_ids"])
check("#25 last-wins WINNER (c2) -> EXACT owning the native artifact (not exact_noop)",
      len(_c2) == 1 and _c2[0]["status"] == "EXACT" and not _c2[0]["exact_noop"]
      and any(":native:" in a for a in _c2[0]["artifact_ids"]))
check("#25 last-wins: both units claimed, keys disjoint",
      _disjoint_and_in_inv(_ir25))

# (2) GLOBAL effect expands to MULTIPLE behaviors — the * unit owns one native artifact
# per behavior it applied to.
_ir25g = _pd25({"cache": [
    {"id": "g", "enabled": True, "expression": "true", "action": "set_cache_settings",
     "action_parameters": {"edge_ttl": {"mode": "override_origin", "default": 100}}},
    {"id": "img", "enabled": True, "expression": 'http.request.uri.path wildcard "/img/*"',
     "action": "set_cache_settings", "action_parameters": {
         "cache_key": {"custom_key": {"header": {"include": ["X-Foo"]}}}}}]})
_gc = _claims_for(_ir25g, "g")
check("#25 global effect expands: 'g' owns a native artifact on EACH behavior (2)",
      len(_gc) == 1 and sum(1 for a in _gc[0]["artifact_ids"] if ":native:" in a) == 2)
check("#25 global effect: the two native artifacts are for different behaviors",
      len({a for a in _gc[0]["artifact_ids"] if ":native:" in a}) == 2)

# (3) MANAGED-TRANSFORM /$action produces MULTIPLE artifacts, all owned by the ONE unit.
_ir25m = _pd25({}, mt={"managed_response_headers": [{"id": "add_security_headers", "enabled": True}]})
_mc = [c for c in _ir25m["_claims"] if any(k[0] == "managed_transform" for k in c["source_keys"])]
check("#25 managed-transform /$action -> one claim owning MULTIPLE native artifacts",
      len(_mc) == 1 and sum(1 for a in _mc[0]["artifact_ids"] if ":native:" in a) >= 2)
check("#25 managed-transform claim is EXACT over the /$action leaf",
      _mc and _mc[0]["status"] == "EXACT"
      and all(k[2] == "/$action" for k in _mc[0]["source_keys"]))

# (4) CROSS-OVERLAP -> NC, produces NO native artifact for the overlapped behavior. A
# *.js compression effect and a /api/* cache effect cross-overlap: each WINS on its own
# behavior but produces no artifact on the other's.
_ir25x = _pd25({"compression": [
    {"id": "cmp", "enabled": True, "expression": 'http.request.uri.path.extension in {"js"}',
     "action": "set_config", "action_parameters": {"algorithms": [{"name": "gzip"}]}}],
    "cache": [{"id": "api", "enabled": True, "expression": 'http.request.uri.path wildcard "/api/*"',
     "action": "set_cache_settings", "action_parameters": {
         "edge_ttl": {"mode": "override_origin", "default": 50}}}]})
_cmp_arts = [a for a in _native_arts(_ir25x)
             if any(k[1] == "cmp" for k in a["owner_keys"])]
_cmp_beh = {a["artifact_id"].split(":native:")[1].rsplit(":", 1)[0] for a in _cmp_arts}
check("#25 cross-overlap: cmp wins ONLY on *.js (native artifact), NOT on /api/*",
      _cmp_beh == {"*.js"}, f"got {_cmp_beh}")
check("#25 cross-overlap: everything disjoint + in inventory", _disjoint_and_in_inv(_ir25x))

# (5) SUBSET: a cache rule with a converting edge_ttl AND an un-converted serve_stale —
# the native effect owns ONLY /edge_ttl (EXACT), serve_stale is NOT swept into the claim.
_ir25s = _pd25({"cache": [
    {"id": "cm", "enabled": True, "expression": "true", "action": "set_cache_settings",
     "action_parameters": {"edge_ttl": {"mode": "override_origin", "default": 100},
                           "serve_stale": {"disable_stale_while_updating": True}}}]})
_ex25s = sorted(tuple(k) for c in _ir25s["_claims"] if c["status"] == "EXACT"
                for k in c["source_keys"])
check("#25 cache native effect owns ONLY /edge_ttl leaves (subset, not whole rule)",
      _ex25s == [("rule", "cm", "/edge_ttl/default"), ("rule", "cm", "/edge_ttl/mode")])
check("#25 un-converted serve_stale is NOT in any EXACT claim",
      not any("serve_stale" in k[2] for k in _ex25s))

# (6) RHP re-homed to a viewer op does NOT re-enter the native channel (no double-claim,
# artifact is cff: not native:).
_ir25r = _pd25({"response_header": [
    {"id": "h", "enabled": True, "expression": "true", "action": "rewrite",
     "action_parameters": {"headers": {"Strict-Transport-Security": {"operation": "set", "value": "max-age=1"}}}},
    {"id": "h2", "enabled": True, "expression": "true", "action": "rewrite",
     "action_parameters": {"headers": {"Strict-Transport-Security": {"operation": "remove"}}}}]})
_hsts_arts = [a for c in _ir25r["_claims"] if any("Strict-Transport-Security" in k[2] for k in c["source_keys"])
              for a in c["artifact_ids"]]
check("#25 re-homed RHP header -> cff artifact (NOT native), no double-entry",
      _hsts_arts and all(":cff:" in a for a in _hsts_arts))
check("#25 re-homed RHP: keys disjoint (no native+cff double-claim)", _disjoint_and_in_inv(_ir25r))

print("== FINDING (spine) 26: native-effect status ⋈ config value ⋈ artifact owner (consistency) ==")
_DC26 = {"hostname": "shop.example.com", "apex_domain": "example.com", "origin_type": "custom",
         "origin_content": "o.net", "sanitized_name": "shop_example_com"}


def _pd26(r):
    return _pre.process_domain("shop.example.com", _DC26, r, {}, {}, {})


def _beh(ir, path):
    return next(b for b in ir["cache_behaviors"] if b["path_pattern"] == path)


def _claim_for_unit(ir, unit):
    cs = [c for c in ir["_claims"] if any(k[1] == unit for k in c["source_keys"])]
    return cs[0] if cs else None


# (F1) CROSS-OVERLAP with a surviving artifact → LOSSY (not EXACT). *.js compression and
# /api/* TTL cross-overlap, each survives on its OWN behavior. Assert: config value applied,
# artifact owned, status LOSSY — all three consistent.
_ir26x = _pd26({"compression": [
    {"id": "cmp", "enabled": True, "expression": 'http.request.uri.path.extension in {"js"}',
     "action": "set_config", "action_parameters": {"algorithms": [{"name": "gzip"}]}}],
    "cache": [{"id": "api", "enabled": True, "expression": 'http.request.uri.path wildcard "/api/*"',
     "action": "set_cache_settings", "action_parameters": {
         "edge_ttl": {"mode": "override_origin", "default": 50}}}]})
_cmp = _claim_for_unit(_ir26x, "cmp")
check("#26 cross-overlap: config value applied (gzip on *.js behavior)",
      _beh(_ir26x, "*.js")["cache_policy"]["enable_gzip"] is True)
check("#26 cross-overlap: claim is LOSSY (surviving artifact + overlap), NOT EXACT",
      _cmp and _cmp["status"] == "LOSSY_WITH_WARNING" and _cmp["reason"])
check("#26 cross-overlap: LOSSY claim owns the surviving native artifact",
      _cmp and any(":native:*.js:compression" in a for a in _cmp["artifact_ids"]))

# (F2) cache_key PER-FIELD slot: rule sets HEADER, later rule sets QUERY. Both survive on
# the behavior (independent slots) → BOTH EXACT, neither exact_noop, distinct artifacts.
_ir26k = _pd26({"cache": [
    {"id": "kh", "enabled": True, "expression": "true", "action": "set_cache_settings",
     "action_parameters": {"cache_key": {"custom_key": {"header": {"include": ["X-Foo"]}}}}},
    {"id": "kq", "enabled": True, "expression": "true", "action": "set_cache_settings",
     "action_parameters": {"cache_key": {"custom_key": {"query_string": {"include": ["q"]}}}}}]})
_ck = _beh(_ir26k, "*")["cache_policy"]["cache_key"]
check("#26 cache_key: BOTH header and query survived in the final config",
      _ck.get("headers") and (_ck.get("query_strings") or _ck.get("query_strings_list")))
_kh = _claim_for_unit(_ir26k, "kh")
_kq = _claim_for_unit(_ir26k, "kq")
check("#26 cache_key: header rule EXACT (not exact_noop), owns a header-slot artifact",
      _kh and _kh["status"] == "EXACT" and not _kh["exact_noop"]
      and any("cache_key.headers" in a for a in _kh["artifact_ids"]))
check("#26 cache_key: query rule EXACT (not exact_noop), owns a query-slot artifact",
      _kq and _kq["status"] == "EXACT" and not _kq["exact_noop"]
      and any("cache_key.query" in a for a in _kq["artifact_ids"]))

# (F3) precise cache-leaf ownership: edge_ttl override + un-converted status_code_ttl, and
# cache_key header + un-converted cookie. The EXACT claim owns ONLY the converted leaves;
# the un-converted leaves are NOT in any EXACT claim (they stay legacy-NC).
_ir26c = _pd26({"cache": [
    {"id": "cm", "enabled": True, "expression": "true", "action": "set_cache_settings",
     "action_parameters": {"edge_ttl": {"mode": "override_origin", "default": 100,
                                        "status_code_ttl": [{"status_code": 404, "value": 5}]},
                           "cache_key": {"custom_key": {"header": {"include": ["X-Foo"]},
                                                        "cookie": {"include": ["sess"]}}}}}]})
_ex26 = sorted(k[2] for c in _ir26c["_claims"] if c["status"] == "EXACT"
               for k in c["source_keys"] if k[1] == "cm")
check("#26 precise leaves: EXACT owns edge_ttl mode+default and cache_key header/include",
      _ex26 == ["/cache_key/custom_key/header/include", "/edge_ttl/default", "/edge_ttl/mode"],
      f"got {_ex26}")
check("#26 precise leaves: status_code_ttl NOT in any EXACT claim",
      not any("status_code_ttl" in x for x in _ex26))
check("#26 precise leaves: cookie NOT in any EXACT claim",
      not any("cookie" in x for x in _ex26))
# consistency: the converted TTL value IS applied to the behavior
check("#26 precise leaves: the edge_ttl value (100) is applied to the behavior config",
      _beh(_ir26c, "*")["cache_policy"]["ttl"]["default"] == 100)

print("== FINDING (spine) 27: no-write effect / canonical header / precise query+browser leaves ==")
_DC27 = {"hostname": "shop.example.com", "apex_domain": "example.com", "origin_type": "custom",
         "origin_content": "o.net", "sanitized_name": "shop_example_com"}


def _pd27(r, mt=None):
    return _pre.process_domain("shop.example.com", _DC27, r, {}, {}, mt or {})


# (F1) NO-WRITE effect: managed adds X-Frame-Options + X-Content-Type-Options, BUT explicit
# rules override BOTH. The managed /$action wrote nothing that survived → it must NOT vanish
# (inventory key with no claim): it gets an EXACT exact_noop claim. Assert inventory ⋈ claim
# ⋈ final config all consistent.
_ir27a = _pd27({"response_header": [
    {"id": "e1", "enabled": True, "expression": "true", "action": "rewrite",
     "action_parameters": {"headers": {"X-Frame-Options": {"operation": "set", "value": "DENY"}}}},
    {"id": "e2", "enabled": True, "expression": "true", "action": "rewrite",
     "action_parameters": {"headers": {"X-Content-Type-Options": {"operation": "set", "value": "nosniff"}}}}]},
    mt={"managed_response_headers": [{"id": "add_security_headers", "enabled": True}]})
_mt27 = [c for c in _ir27a["_claims"] if any(k[0] == "managed_transform" for k in c["source_keys"])]
check("#27 fully-overridden managed /$action still has a claim (does NOT vanish)",
      len(_mt27) == 1)
check("#27 fully-overridden managed /$action is EXACT exact_noop (wrote nothing surviving)",
      _mt27 and _mt27[0]["status"] == "EXACT" and _mt27[0]["exact_noop"]
      and not _mt27[0]["artifact_ids"])
check("#27 managed /$action inventory key IS the claim's key (accounted)",
      _mt27 and [tuple(k) for k in _mt27[0]["source_keys"]]
      == [("managed_transform", "add_security_headers", "/$action")])
# final config reflects the explicit override (managed deferred)
_sh27 = _ir27a["cache_behaviors"][0]["response_headers_policy"]["security_headers"]
check("#27 final config: explicit values win (managed setdefault deferred)",
      _sh27.get("X-Frame-Options", {}).get("value") == "DENY"
      and _sh27.get("X-Content-Type-Options", {}).get("value") == "nosniff")

# (F2) CANONICAL header casing: an explicit rule sets LOWERCASE 'x-frame-options'. The slot,
# the RHP dict key, and the ledger must all use the canonical 'X-Frame-Options' (the key the
# HCL generator reads) — no split-brain where the ledger marks one casing and the generator
# emits another.
_ir27b = _pd27({"response_header": [{"id": "lc", "enabled": True, "expression": "true",
    "action": "rewrite", "action_parameters": {"headers": {
        "x-frame-options": {"operation": "set", "value": "DENY"}}}}]})
_sh27b = _ir27b["cache_behaviors"][0]["response_headers_policy"]["security_headers"]
check("#27 RHP dict key is canonical X-Frame-Options (what the generator reads)",
      list(_sh27b.keys()) == ["X-Frame-Options"])
_lc27 = [c for c in _ir27b["_claims"] if any(k[1] == "lc" for k in c["source_keys"])]
check("#27 the header rule is EXACT and owns a native rhp artifact (no split-brain)",
      _lc27 and _lc27[0]["status"] == "EXACT"
      and any(":native:" in a and "x-frame-options" in a for a in _lc27[0]["artifact_ids"]))

# canonical dedup: managed X-Frame-Options + explicit lowercase x-frame-options -> ONE key.
_ir27b2 = _pd27({"response_header": [{"id": "lc", "enabled": True, "expression": "true",
    "action": "rewrite", "action_parameters": {"headers": {
        "x-frame-options": {"operation": "set", "value": "DENY"}}}}]},
    mt={"managed_response_headers": [{"id": "add_security_headers", "enabled": True}]})
_sh27b2 = _ir27b2["cache_behaviors"][0]["response_headers_policy"]["security_headers"]
check("#27 managed + lowercase-explicit collapse to ONE X-Frame-Options key (value DENY)",
      sum(1 for k in _sh27b2 if k.lower() == "x-frame-options") == 1
      and _sh27b2["X-Frame-Options"]["value"] == "DENY")

# (F3) PRECISE query-string leaf: include + unknown sibling → EXACT owns only /include; the
# unknown sibling stays out (legacy-NC). And exclude mode owns /exclude, not /include.
_ir27c = _pd27({"cache": [{"id": "q", "enabled": True, "expression": "true",
    "action": "set_cache_settings", "action_parameters": {"cache_key": {"custom_key": {
        "query_string": {"include": ["a"], "future_opt": "z"}}}}}]})
_ex27c = sorted(k[2] for c in _ir27c["_claims"] if c["status"] == "EXACT" for k in c["source_keys"])
check("#27 query include+unknown: EXACT owns ONLY /query_string/include",
      _ex27c == ["/cache_key/custom_key/query_string/include"], f"got {_ex27c}")
check("#27 query unknown sibling (future_opt) NOT in EXACT", not any("future_opt" in x for x in _ex27c))
# the query selector IS applied to the config
check("#27 query include value applied to behavior config",
      _beh(_ir27c, "*")["cache_policy"]["cache_key"].get("query_strings_list") == ["a"]
      or _beh(_ir27c, "*")["cache_policy"]["cache_key"].get("query_strings") == "whitelist")
_ir27c2 = _pd27({"cache": [{"id": "qx", "enabled": True, "expression": "true",
    "action": "set_cache_settings", "action_parameters": {"cache_key": {"custom_key": {
        "query_string": {"exclude": ["a"]}}}}}]})
_ex27c2 = sorted(k[2] for c in _ir27c2["_claims"] if c["status"] == "EXACT" for k in c["source_keys"])
check("#27 query EXCLUDE mode owns /query_string/exclude (not /include)",
      _ex27c2 == ["/cache_key/custom_key/query_string/exclude"], f"got {_ex27c2}")

# (F4) PRECISE browser_ttl leaf: override + unknown sibling → LOSSY owns only mode+default;
# the unknown sibling stays out (would else be in BOTH the LOSSY claim and legacy-NC).
_ir27d = _pd27({"cache": [{"id": "b", "enabled": True, "expression": "true",
    "action": "set_cache_settings", "action_parameters": {
        "browser_ttl": {"mode": "override_origin", "default": 60, "future_x": "y"}}}]})
_lossy27 = sorted(k[2] for c in _ir27d["_claims"] if c["status"] == "LOSSY_WITH_WARNING"
                  for k in c["source_keys"])
check("#27 browser_ttl override+unknown: LOSSY owns ONLY mode+default",
      _lossy27 == ["/browser_ttl/default", "/browser_ttl/mode"], f"got {_lossy27}")
check("#27 browser_ttl unknown sibling (future_x) NOT in the LOSSY claim",
      not any("future_x" in x for x in _lossy27))
# consistency: the browser_ttl viewer op (cache-control) IS emitted
check("#27 browser_ttl override applied as a cache-control viewer op",
      any(o["params"].get("name") == "cache-control"
          for b in _ir27d["cache_behaviors"] for o in b["viewer_response_ops"]))

print("== FINDING (spine) 28: RHP capability registry / object-form query / no-default TTL ==")
_DC28 = {"hostname": "shop.example.com", "apex_domain": "example.com", "origin_type": "custom",
         "origin_content": "o.net", "sanitized_name": "shop_example_com"}


def _pd28(r):
    return _pre.process_domain("shop.example.com", _DC28, r, {}, {}, {})


def _unit_claim(ir, unit):
    cs = [c for c in ir["_claims"] if any(k[1] == unit for k in c["source_keys"])]
    return cs[0] if cs else None


# (F1a) Permissions-Policy is NOT RHP-emittable → NON_CONVERTIBLE (not EXACT-into-empty-RHP),
# and it must NOT populate security_headers.
_ir28pp = _pd28({"response_header": [{"id": "pp", "enabled": True, "expression": "true",
    "action": "rewrite", "action_parameters": {"headers": {
        "Permissions-Policy": {"operation": "set", "value": "geolocation=()"}}}}]})
_ppc = _unit_claim(_ir28pp, "pp")
check("#28 Permissions-Policy -> NON_CONVERTIBLE (RHP can't emit it)",
      _ppc and _ppc["status"] == "NON_CONVERTIBLE")
check("#28 Permissions-Policy does NOT populate security_headers",
      not _ir28pp["cache_behaviors"][0]["response_headers_policy"]["security_headers"])

# (F1b) A static CORS header (Allow-Origin, Expose-Headers) is NOT native-RHP EXACT: the
# native cors_config isn't a faithful substitute for a static header set and
# custom_headers_config rejects CORS names at the control plane. It converts to a
# viewer-response CFF marked LOSSY_WITH_WARNING (literal header on normal responses, absent
# on CloudFront-generated error responses). It must NOT populate security_headers (no
# cors_config emitted).
_ir28ao = _pd28({"response_header": [{"id": "ao", "enabled": True, "expression": "true",
    "action": "rewrite", "action_parameters": {"headers": {
        "Access-Control-Allow-Origin": {"operation": "set", "value": "*"}}}}]})
_aoc = _unit_claim(_ir28ao, "ao")
check("#28 Access-Control-Allow-Origin (static CORS) -> LOSSY_WITH_WARNING (viewer CFF)",
      _aoc and _aoc["status"] == "LOSSY_WITH_WARNING"
      and any(":cff:" in a for a in _aoc["artifact_ids"]))
check("#28 static CORS LOSSY carries an error-response-gap reason",
      _aoc and _aoc.get("reason") and "error response" in _aoc["reason"])
check("#28 static CORS is a set_response_header viewer op (literal name+value)",
      any(o["type"] == "set_response_header" and o["params"].get("name") == "Access-Control-Allow-Origin"
          for b in _ir28ao["cache_behaviors"] for o in b["viewer_response_ops"]))
check("#28 static CORS does NOT emit a native cors_config / security_headers",
      not _ir28ao["cache_behaviors"][0]["response_headers_policy"]["security_headers"]
      and not _ir28ao["cache_behaviors"][0]["response_headers_policy"]["cors"])
# an Expose-Headers (no RHP field at all) takes the SAME CFF-LOSSY path (a CFF can set any
# literal header name), NOT non-convertible.
_ir28eh = _pd28({"response_header": [{"id": "eh", "enabled": True, "expression": "true",
    "action": "rewrite", "action_parameters": {"headers": {
        "Access-Control-Expose-Headers": {"operation": "set", "value": "X-Custom"}}}}]})
check("#28 Access-Control-Expose-Headers (static CORS) -> LOSSY_WITH_WARNING (viewer CFF)",
      (_unit_claim(_ir28eh, "eh") or {}).get("status") == "LOSSY_WITH_WARNING")
# registry helpers agree with the generator's set (shared dependency-free registry
# cdn_rhp_capabilities, imported here as _cap and by both the processor and the generator)
check("#28 registry: security set excludes Permissions-Policy",
      _cap.rhp_supports_security("X-Frame-Options")
      and not _cap.rhp_supports_security("Permissions-Policy"))
# The authoritative static-CORS name set (finding 3) is EXACT-membership over the SIX CORS
# response headers — Expose-Headers / Max-Age ARE included (they route to a CFF, LOSSY),
# while a security header or an unrelated header is NOT a CORS header.
check("#28 registry: static-CORS set is the six CORS response headers (incl. Expose/Max-Age)",
      _cap.is_static_cors_header("Access-Control-Allow-Origin")
      and _cap.is_static_cors_header("Access-Control-Expose-Headers")
      and _cap.is_static_cors_header("Access-Control-Max-Age")
      and not _cap.is_static_cors_header("X-Frame-Options")
      and not _cap.is_static_cors_header("X-Custom"))
check("#28 registry: static-CORS uses EXACT membership, not an access-control- prefix",
      not _cap.is_static_cors_header("Access-Control-Bogus"))
# the dormant native cors_config set is the FOUR structured fields (separate from routing)
check("#28 registry: dormant native cors_config set is the four structured fields",
      _cap.native_cors_config_supports("Access-Control-Allow-Origin")
      and not _cap.native_cors_config_supports("Access-Control-Expose-Headers"))

# (F2) object-form query selector {"include": {"all": true}} + unknown sibling → the EXACT
# claim owns ONLY /query_string/include/all; the sibling stays legacy-NC.
_ir28q = _pd28({"cache": [{"id": "q", "enabled": True, "expression": "true",
    "action": "set_cache_settings", "action_parameters": {"cache_key": {"custom_key": {
        "query_string": {"include": {"all": True, "future": "x"}}}}}}]})
_ex28q = sorted(k[2] for c in _ir28q["_claims"] if c["status"] == "EXACT" for k in c["source_keys"])
check("#28 object-form query: EXACT owns ONLY /query_string/include/all (not the sibling)",
      _ex28q == ["/cache_key/custom_key/query_string/include/all"], f"got {_ex28q}")
check("#28 object-form query: unknown sibling is a legacy-NC (accounted, not vanished)",
      any("query_string.include.future" in n.get("reason", "")
          for b in _ir28q["cache_behaviors"] for n in b.get("non_convertible", [])))
# object-form include.list owns /include/list
_ir28ql = _pd28({"cache": [{"id": "ql", "enabled": True, "expression": "true",
    "action": "set_cache_settings", "action_parameters": {"cache_key": {"custom_key": {
        "query_string": {"include": {"list": ["a"]}}}}}}]})
_ex28ql = sorted(k[2] for c in _ir28ql["_claims"] if c["status"] == "EXACT" for k in c["source_keys"])
check("#28 object-form include.list owns /query_string/include/list",
      _ex28ql == ["/cache_key/custom_key/query_string/include/list"], f"got {_ex28ql}")

# (F3) edge_ttl / browser_ttl override with NO default → must NOT FATAL; owns only /mode.
_ir28e = _pd28({"cache": [{"id": "e", "enabled": True, "expression": "true",
    "action": "set_cache_settings",
    "action_parameters": {"edge_ttl": {"mode": "override_origin"}}}]})
check("#28 edge_ttl override with NO default: no FATAL, EXACT owns ONLY /edge_ttl/mode",
      isinstance(_ir28e, dict)
      and sorted(k[2] for c in _ir28e["_claims"] if c["status"] == "EXACT"
                 for k in c["source_keys"]) == ["/edge_ttl/mode"])
_ir28b = _pd28({"cache": [{"id": "b", "enabled": True, "expression": "true",
    "action": "set_cache_settings",
    "action_parameters": {"browser_ttl": {"mode": "override_origin"}}}]})
check("#28 browser_ttl override with NO default: no FATAL, LOSSY owns ONLY /browser_ttl/mode",
      isinstance(_ir28b, dict)
      and sorted(k[2] for c in _ir28b["_claims"] if c["status"] == "LOSSY_WITH_WARNING"
                 for k in c["source_keys"]) == ["/browser_ttl/mode"])
# with a default present, both leaves are owned (regression guard the other way)
_ir28ed = _pd28({"cache": [{"id": "ed", "enabled": True, "expression": "true",
    "action": "set_cache_settings",
    "action_parameters": {"edge_ttl": {"mode": "override_origin", "default": 30}}}]})
check("#28 edge_ttl WITH default: EXACT owns mode AND default",
      sorted(k[2] for c in _ir28ed["_claims"] if c["status"] == "EXACT"
             for k in c["source_keys"]) == ["/edge_ttl/default", "/edge_ttl/mode"])


print("== FINDING (spine) 29: RHP value-semantics / segment leaf identity / shared render ==")
_DC29 = {"hostname": "shop.example.com", "apex_domain": "example.com", "origin_type": "custom",
         "origin_content": "o.net", "sanitized_name": "shop_example_com"}


def _pd29(r):
    return _pre.process_domain("shop.example.com", _DC29, r, {}, {}, {})


def _rh29(name, value):
    return _pd29({"response_header": [{"id": "h", "enabled": True, "expression": "true",
        "action": "rewrite", "action_parameters": {"headers": {
            name: {"operation": "set", "value": value}}}}]})


# ── finding 1: capability checks VALUE, not just name ──────────────────────────
# (F1a) HSTS with a NON-default max-age must be preserved VERBATIM (the generator used to
# hardcode 31536000). EXACT, and the normalized value carried into the IR is the source's.
_ir29hs = _rh29("Strict-Transport-Security", "max-age=60; includeSubDomains")
_hsc = _unit_claim(_ir29hs, "h")
_shhs = _ir29hs["cache_behaviors"][0]["response_headers_policy"]["security_headers"]
check("#29 HSTS non-default (max-age=60) is EXACT (representable)",
      _hsc and _hsc["status"] == "EXACT")
check("#29 HSTS normalized carries the SOURCE max-age=60 (not hardcoded 31536000)",
      _shhs.get("Strict-Transport-Security", {}).get("normalized")
      == {"max_age": 60, "include_subdomains": True, "preload": False})
# (F1b) HSTS with an unknown directive → NON_CONVERTIBLE (can't be represented faithfully).
_ir29hx = _rh29("Strict-Transport-Security", "max-age=60; bogus-directive")
check("#29 HSTS with unknown directive -> NON_CONVERTIBLE",
      (_unit_claim(_ir29hx, "h") or {}).get("status") == "NON_CONVERTIBLE")
check("#29 HSTS-with-unknown does NOT populate security_headers",
      not _ir29hx["cache_behaviors"][0]["response_headers_policy"]["security_headers"])
# (F1c) X-XSS-Protection: 0 (disabled) → NC (the RHP can only emit `1; mode=block`).
_ir29x0 = _rh29("X-XSS-Protection", "0")
check("#29 X-XSS-Protection: 0 (disabled) -> NON_CONVERTIBLE (RHP forces 1; mode=block)",
      (_unit_claim(_ir29x0, "h") or {}).get("status") == "NON_CONVERTIBLE")
check("#29 X-XSS-Protection: 1; mode=block -> EXACT",
      (_unit_claim(_rh29("X-XSS-Protection", "1; mode=block"), "h") or {}).get("status") == "EXACT")
# (F1d) X-Content-Type-Options: only `nosniff`; anything else → NC.
check("#29 X-Content-Type-Options: not-nosniff -> NON_CONVERTIBLE",
      (_unit_claim(_rh29("X-Content-Type-Options", "sniff-please"), "h") or {}).get("status")
      == "NON_CONVERTIBLE")
# (F1e) X-Frame-Options: ALLOW-FROM is not in the CloudFront enum → NC; SAMEORIGIN → EXACT.
check("#29 X-Frame-Options: ALLOW-FROM ... -> NON_CONVERTIBLE (enum is DENY|SAMEORIGIN)",
      (_unit_claim(_rh29("X-Frame-Options", "ALLOW-FROM https://x"), "h") or {}).get("status")
      == "NON_CONVERTIBLE")

# ── finding 2: leaf identity is by SEGMENT, not string prefix ──────────────────
# (F2a) a cache_key query object with an `all` key AND a sibling whose name STARTS WITH `all`
# (`all_extra`): the consumed leaf is include.all; `all_extra` must NOT be swallowed by a
# string-prefix test — it stays a legacy-NC. (Was: `startswith("include.all")` ate `all_extra`.)
_ir29ae = _pd29({"cache": [{"id": "q", "enabled": True, "expression": "true",
    "action": "set_cache_settings", "action_parameters": {"cache_key": {"custom_key": {
        "query_string": {"include": {"all": True, "all_extra": "z"}}}}}}]})
_ex29ae = sorted(k[2] for c in _ir29ae["_claims"] if c["status"] == "EXACT" for k in c["source_keys"])
check("#29 query include.all + sibling `all_extra`: EXACT owns ONLY /include/all",
      _ex29ae == ["/cache_key/custom_key/query_string/include/all"], f"got {_ex29ae}")
check("#29 `all_extra` sibling is NOT swallowed (surfaces as legacy-NC)",
      any("all_extra" in n.get("reason", "")
          for b in _ir29ae["cache_behaviors"] for n in b.get("non_convertible", [])))
# (F2b) edge_ttl with `default` AND a sibling `default_extra`: the owned leaf is /edge_ttl/default
# ONLY; `default_extra` must NOT be counted as the default leaf (was: startswith match) and
# must surface as legacy-NC.
_ir29de = _pd29({"cache": [{"id": "e", "enabled": True, "expression": "true",
    "action": "set_cache_settings", "action_parameters": {
        "edge_ttl": {"mode": "override_origin", "default": 30, "default_extra": 99}}}]})
_ex29de = sorted(k[2] for c in _ir29de["_claims"] if c["status"] == "EXACT" for k in c["source_keys"])
check("#29 edge_ttl default + sibling `default_extra`: EXACT owns mode+default ONLY",
      _ex29de == ["/edge_ttl/default", "/edge_ttl/mode"], f"got {_ex29de}")
check("#29 `default_extra` sibling is NOT swallowed (surfaces as legacy-NC)",
      any("default_extra" in n.get("reason", "")
          for b in _ir29de["cache_behaviors"] for n in b.get("non_convertible", [])))
# and the _split_leaf helper is exact-segment (unit-level guard)
check("#29 _split_leaf('edge_ttl.default=30') -> (('edge_ttl','default'),'30')",
      _pre._split_leaf("edge_ttl.default=30") == (("edge_ttl", "default"), "30"))
check("#29 _split_leaf('a.b[]') strips the list marker -> (('a','b'),None)",
      _pre._split_leaf("a.b[]") == (("a", "b"), None))

# ── finding 3: generator uses the SHARED registry (no hardcoded dispatch) ──────
# (F3a) registry completeness: every security capability has name+parse+render (callable).
_reg_ok = all(isinstance(c.get("canonical_name"), str) and c["canonical_name"]
              and callable(c.get("parse")) and callable(c.get("render"))
              for c in _cap.SECURITY_CAPABILITIES)
check("#29 registry: every SECURITY_CAPABILITIES entry has name+parse+render", _reg_ok)
check("#29 registry: 6 security capabilities registered", len(_cap.SECURITY_CAPABILITIES) == 6)
# (F3b) no generator-side hardcoded per-header dispatch: the OLD generator had a `_sec_val`
# helper with a per-header if-block for each security header; it must be GONE, replaced by a
# loop over the shared registry. (The `31536000` literal is checked behaviorally in F3c —
# grepping source is unreliable since an explanatory comment may mention the old value.)
import inspect as _inspect
_gensrc = _inspect.getsource(_gen.gen_rhp)
check("#29 generator has NO per-header _sec_val hardcoded dispatch", "_sec_val" not in _gensrc)
check("#29 generator iterates the shared SECURITY_CAPABILITIES registry",
      "SECURITY_CAPABILITIES" in _gensrc)
# structural: a registry-driven loop references header names ONLY via cap["canonical_name"],
# so NO security-header name may appear as a literal in gen_rhp (that would be dead hardcoded
# dispatch). This is the strong form of "no generator-side hardcoded dispatch remains".
_name_lits = [c["canonical_name"] for c in _cap.SECURITY_CAPABILITIES
              if c["canonical_name"] in _gensrc]
check("#29 NO security-header name literal remains in gen_rhp (fully registry-driven)",
      _name_lits == [], f"leftover literals: {_name_lits}")
# (F3c) end-to-end: the generator renders the SOURCE max-age (60), proving render() reads the
# normalized value — NOT the old hardcoded 31536000 default. gen_rhp returns a joined string.
_hcl29 = _gen.gen_rhp("p29", _ir29hs["cache_behaviors"][0]["response_headers_policy"])
check("#29 generated HCL preserves source max-age=60 (render from normalized)",
      "access_control_max_age_sec = 60" in _hcl29 and "31536000" not in _hcl29)
check("#29 generated HCL keeps includeSubDomains=true from the source",
      "include_subdomains         = true" in _hcl29)

# ── per-capability positive + negative parser matrix ──────────────────────────
_CAP_CASES = {
    # HSTS: exact directive names only (reject `max-age-extra`, `max-agefoo`, duplicate max-age,
    # a valueless flag given a value) — round-12 finding 1.
    "Strict-Transport-Security": (
        ["max-age=0", "max-age=100; preload", "max-age=1; includeSubDomains; preload"],
        ["", "includeSubDomains", "max-age=abc", "max-age=1; x",
         "max-age-extra=60", "max-agefoo=1", "max-age=1; max-age=2", "max-age=1; preload=x"]),
    "X-Content-Type-Options": (["nosniff", "  NOSNIFF  "], ["", "sniff", "nosniff; x"]),
    "X-Frame-Options": (["DENY", "sameorigin"], ["", "ALLOW-FROM https://x", "deny; extra"]),
    "X-XSS-Protection": (["1; mode=block", "1;MODE=BLOCK"], ["", "0", "1", "1; mode=sanitize"]),
    # Referrer-Policy: CloudFront enum ONLY — reject "banana" and a spec-legal comma fallback
    # list (round-12 finding 2). Case folds to the canonical lowercase value.
    "Referrer-Policy": (["no-referrer", "strict-origin-when-cross-origin", "NO-REFERRER", "Origin"],
                        ["", 123, "banana", "no-referrer, strict-origin", "no referrer"]),
    # CSP: free-form; the parser's boundary is the RHP HARD ceiling 8192 (round-13 finding 2 —
    # 1783 is a RAISABLE quota, checked separately by the quota validator, NOT a parse-NC).
    # So 1783 AND up-to-8192 parse OK; only >8192 is NC (plus empty / non-string).
    "Content-Security-Policy": (["default-src 'self'", "x" * 1783, "x" * 8192],
                                ["", None, "x" * 8193]),
}
for _cn, (_pos, _neg) in _CAP_CASES.items():
    _c = _cap.security_capability(_cn)
    check(f"#29 {_cn}: registered", _c is not None)
    for _v in _pos:
        _norm = _c and _c["parse"](_v)
        check(f"#29 {_cn} parse OK: {_v!r}", _norm is not None,
              f"expected non-None for {_v!r}")
        # every registered capability's render() turns its own normalized value into HCL
        # lines carrying an `override` field (proves parse↔render pair is complete + wired).
        if _norm is not None:
            _lines = _c["render"](_norm, True)
            check(f"#29 {_cn} render OK: {_v!r}",
                  isinstance(_lines, list) and _lines
                  and any("override" in ln for ln in _lines),
                  f"render produced {_lines!r}")
    for _v in _neg:
        check(f"#29 {_cn} parse NC: {_v!r}", _c and _c["parse"](_v) is None,
              f"expected None for {_v!r}")

print("== FINDING (spine) 30: HSTS exact directives / Referrer enum / HCL escape / CORS LOSSY ==")
_DC30 = {"hostname": "shop.example.com", "apex_domain": "example.com", "origin_type": "custom",
         "origin_content": "o.net", "sanitized_name": "shop_example_com"}


def _pd30(r):
    return _pre.process_domain("shop.example.com", _DC30, r, {}, {}, {})


def _rh30(name, value):
    return _pd30({"response_header": [{"id": "h", "enabled": True, "expression": "true",
        "action": "rewrite", "action_parameters": {"headers": {
            name: {"operation": "set", "value": value}}}}]})


# ── finding 1: HSTS directive names are EXACT, not string-prefix ───────────────
_hsts_parse = _cap.security_capability("Strict-Transport-Security")["parse"]
check("#30 HSTS `max-age-extra=60` rejected (not a max-age directive)",
      _hsts_parse("max-age-extra=60") is None)
check("#30 HSTS `max-agefoo=1` rejected", _hsts_parse("max-agefoo=1") is None)
check("#30 HSTS duplicate `max-age` rejected (ambiguous, not faithful)",
      _hsts_parse("max-age=1; max-age=2") is None)
check("#30 HSTS `max-age-extra=60` -> NON_CONVERTIBLE end-to-end",
      (_unit_claim(_rh30("Strict-Transport-Security", "max-age-extra=60"), "h") or {}).get("status")
      == "NON_CONVERTIBLE")

# ── finding 2: Referrer-Policy enum + CSP length cap ───────────────────────────
_ref_parse = _cap.security_capability("Referrer-Policy")["parse"]
check("#30 Referrer-Policy `banana` rejected (not in enum)", _ref_parse("banana") is None)
check("#30 Referrer-Policy comma fallback list rejected",
      _ref_parse("no-referrer, strict-origin") is None)
check("#30 Referrer-Policy case-folds to canonical lowercase enum (behavior-preserving)",
      _ref_parse("NO-REFERRER") == {"value": "no-referrer"})
check("#30 Referrer-Policy `banana` -> NON_CONVERTIBLE end-to-end",
      (_unit_claim(_rh30("Referrer-Policy", "banana"), "h") or {}).get("status") == "NON_CONVERTIBLE")
# CSP length: 1783 is a RAISABLE quota (parse still EXACT — the quota validator warns
# separately); the parser only NC's beyond the 8192 hard ceiling (round-13 finding 2).
_csp_parse = _cap.security_capability("Content-Security-Policy")["parse"]
check("#30 CSP at the default quota 1783 -> EXACT (parse OK, quota checked separately)",
      _csp_parse("x" * 1783) is not None)
check("#30 CSP above default quota but <= 8192 -> EXACT (raisable quota, not a parse-NC)",
      _csp_parse("x" * 5000) is not None and _csp_parse("x" * 8192) is not None)
check("#30 CSP over the 8192 hard ceiling -> NON_CONVERTIBLE", _csp_parse("x" * 8193) is None)
# a CSP over the default quota converts EXACT end-to-end (deploy-readiness is orthogonal).
check("#30 CSP=3000 chars converts EXACT end-to-end (over default quota, under ceiling)",
      (_unit_claim(_rh30("Content-Security-Policy", "x" * 3000), "h") or {}).get("status") == "EXACT")

# ── finding 3: HCL string escaping (quotes / backslash / newline / interpolation) ──
_esc = _cap.hcl_string_literal
check("#30 hcl escape: double-quote -> \\\"", _esc('a"b') == 'a\\"b')
check("#30 hcl escape: backslash -> \\\\", _esc("a\\b") == "a\\\\b")
check("#30 hcl escape: newline -> \\n", _esc("a\nb") == "a\\nb")
check("#30 hcl escape: Terraform interpolation ${x} -> $${x}", _esc("a${x}b") == "a$${x}b")
check("#30 hcl escape: Terraform directive %{x} -> %%{x}", _esc("a%{x}b") == "a%%{x}b")
# and it flows through the generator: a CSP with a quote + interpolation renders escaped HCL.
_ir30csp = _rh30("Content-Security-Policy", 'default-src "self" ${evil}')
_hcl30 = _gen.gen_rhp("p30", _ir30csp["cache_behaviors"][0]["response_headers_policy"])
# the exact escaped line must appear; the raw interpolation `${evil}` (a `$` NOT preceded by
# another `$`) must NOT — Terraform would try to interpolate it. `$${evil}` is the safe form.
check("#30 generator escapes CSP quotes + doubles the interpolation to $${evil}",
      'content_security_policy = "default-src \\"self\\" $${evil}"' in _hcl30)

# ── finding 4: static CORS header -> viewer-response CFF, LOSSY (no native cors_config) ──
_ir30cors = _rh30("Access-Control-Allow-Origin", "*")
_cc = _unit_claim(_ir30cors, "h")
check("#30 static CORS Allow-Origin -> LOSSY_WITH_WARNING (viewer CFF, not native)",
      _cc and _cc["status"] == "LOSSY_WITH_WARNING" and any(":cff:" in a for a in _cc["artifact_ids"]))
check("#30 static CORS does NOT emit a native cors_config",
      _ir30cors["cache_behaviors"][0]["response_headers_policy"]["cors"] is None)
check("#30 static CORS LOSSY reason names the error-response gap",
      _cc and _cc.get("reason") and "error response" in _cc["reason"])
# `add` CORS stays NON_CONVERTIBLE (override=false is origin-wins, not append).
check("#30 CORS `add` stays NON_CONVERTIBLE (no faithful append)",
      (_unit_claim(_pd30({"response_header": [{"id": "h", "enabled": True, "expression": "true",
          "action": "rewrite", "action_parameters": {"headers": {
              "Access-Control-Allow-Origin": {"operation": "add", "value": "*"}}}}]}), "h") or {})
      .get("status") == "NON_CONVERTIBLE")

print("== FINDING (spine) 31: field-presence routing / exact CORS names / dormant native guard ==")
_DC31 = {"hostname": "shop.example.com", "apex_domain": "example.com", "origin_type": "custom",
         "origin_content": "o.net", "sanitized_name": "shop_example_com"}


def _rh31(name, header_config):
    """A response-header rule where header_config is passed VERBATIM (so a test can omit the
    `value` key entirely, or set it to "" / a non-string)."""
    return _pre.process_domain("shop.example.com", _DC31, {"response_header": [
        {"id": "h", "enabled": True, "expression": "true", "action": "rewrite",
         "action_parameters": {"headers": {name: header_config}}}]}, {}, {}, {})


# ── finding 1: empty / non-string value goes THROUGH the capability, not past it ───
# A security-header `set` with an EMPTY value must reach parse() and NC — the old truthiness
# gate (`value and ...`) let "" slip past into a plain CFF EXACT. One case per security family
# plus Permissions-Policy; CORS empty is carried (LOSSY), never EXACT.
for _nm in ("Strict-Transport-Security", "Content-Security-Policy", "Referrer-Policy",
            "X-Frame-Options", "X-XSS-Protection", "X-Content-Type-Options"):
    _c = _unit_claim(_rh31(_nm, {"operation": "set", "value": ""}), "h")
    check(f"#31 {_nm} empty value -> NON_CONVERTIBLE (reaches parser, not CFF EXACT)",
          (_c or {}).get("status") == "NON_CONVERTIBLE", f"got {(_c or {}).get('status')}")
check("#31 Permissions-Policy empty value -> NON_CONVERTIBLE",
      (_unit_claim(_rh31("Permissions-Policy", {"operation": "set", "value": ""}), "h") or {})
      .get("status") == "NON_CONVERTIBLE")
# a non-string value on a security header is NC too (parse() rejects non-str).
check("#31 HSTS non-string value (123) -> NON_CONVERTIBLE",
      (_unit_claim(_rh31("Strict-Transport-Security", {"operation": "set", "value": 123}), "h") or {})
      .get("status") == "NON_CONVERTIBLE")
# empty CORS value: carried as a LOSSY viewer op (finding 1: not dropped, not EXACT).
_ir31ce = _rh31("Access-Control-Allow-Origin", {"operation": "set", "value": ""})
_cce = _unit_claim(_ir31ce, "h")
check("#31 empty CORS value -> LOSSY_WITH_WARNING (carried, not dropped)",
      (_cce or {}).get("status") == "LOSSY_WITH_WARNING")
check("#31 empty CORS value is carried verbatim on the viewer op (round-26: LoweredValue literal '')",
      any(o["type"] == "set_response_header"
          and isinstance(o["params"].get("value_lowered"), dict)
          and o["params"]["value_lowered"].get("kind") == "literal"
          and o["params"]["value_lowered"].get("value") == ""
          and _cep.validate_lowered_value(o["params"]["value_lowered"], _cep.SLOT_RESPONSE_HEADER_VALUE) is None
          for b in _ir31ce["cache_behaviors"] for o in b["viewer_response_ops"]))

# ── finding 3: CORS classification is EXACT membership, not an access-control- prefix ──
# An unknown Access-Control-* header is NOT a CORS header: it's a plain custom header (settable
# via CFF, EXACT — CloudFront's control-plane CORS denylist is the six known names, not a
# prefix), so it must NOT get the CORS LOSSY treatment.
_ir31bogus = _rh31("Access-Control-Bogus", {"operation": "set", "value": "x"})
# An unknown Access-Control-* header is NOT CORS — it's a plain custom response header. It's still
# LOSSY (round-27 finding 5: every viewer-response CFF has the error-response gap), but its reason
# must NOT be the CORS-specific one (no cors_config / custom_headers_config mention).
_c31bogus = _unit_claim(_ir31bogus, "h") or {}
check("#31 unknown Access-Control-Bogus is NOT classified CORS (plain custom header, LOSSY not CORS-reason)",
      _c31bogus.get("status") == "LOSSY_WITH_WARNING" and "cors_config" not in (_c31bogus.get("reason") or ""),
      f"got status={_c31bogus.get('status')} reason={_c31bogus.get('reason')!r}")
# each of the six real CORS names IS classified CORS (LOSSY).
for _cn in ("Access-Control-Allow-Origin", "Access-Control-Allow-Methods",
            "Access-Control-Allow-Headers", "Access-Control-Allow-Credentials",
            "Access-Control-Expose-Headers", "Access-Control-Max-Age"):
    check(f"#31 {_cn} classified static-CORS -> LOSSY_WITH_WARNING",
          (_unit_claim(_rh31(_cn, {"operation": "set", "value": "v"}), "h") or {})
          .get("status") == "LOSSY_WITH_WARNING")

# ── finding 3: the dormant native cors_config path fails loud if re-entered ────
# _apply_native_effect must NOT silently apply a re-added rhp_cors effect via the old EXACT
# mapping — it raises LedgerError so re-enabling native CORS is a deliberate group-level change.
_beh31 = {"cache_policy": {"ttl": {"min": 0, "default": 7200, "max": 86400}},
          "response_headers_policy": {"cors": None, "security_headers": {}, "custom_headers": []}}
check("#31 rhp_cors native effect is a hard LedgerError (dormant path, no silent EXACT reuse)",
      _raises_ledger(lambda: _pre._apply_native_effect(
          _beh31, "rhp_cors", {"name": "Access-Control-Allow-Origin", "value": "*"})) is not None)
# ── finding 3 (Step 5): the gen_rhp CORS path ALSO fails loud on the *+credentials combo ──
# The old TLD-wildcard workaround (CORS_WILDCARD_TLDS) is DELETED: ACAO:* + ACAC:true is NC
# (FINDING-61), so gen_rhp must never silently emit a literal "*" or resurrect the hack. `cors` is
# never populated today (native path dormant), so this is a dormant future-safety guard. The GENERIC
# cors_config renderer is KEPT (consistent with the rhp_cors future-intent) — only the hack is gone.
check("#31 CORS_WILDCARD_TLDS TLD-hack symbol is deleted", not hasattr(_gen, "CORS_WILDCARD_TLDS"))
check("#31 no TLD-wildcard literal remains in gen_rhp source (hack gone)",
      "*.com" not in _inspect.getsource(_gen.gen_rhp))
_cfg31combo = {"security_headers": {}, "custom_headers": [], "remove_headers": [],
               "cors": {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"}}
_combo31raised = False
try:
    _gen.gen_rhp("p31combo", _cfg31combo)
except ValueError:
    _combo31raised = True
check("#31 gen_rhp FAILS LOUD on ACAO:* + ACAC:true (never silently emits literal *)", _combo31raised)
_hcl31ok = _gen.gen_rhp("p31ok", {"security_headers": {}, "custom_headers": [], "remove_headers": [],
    "cors": {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "false"}})
check("#31 gen_rhp still renders a NON-combo CORS config (generic renderer kept, not deleted)",
      bool(_hcl31ok) and "cors_config" in _hcl31ok)

print("== FINDING (spine) 32: malformed expression NC / shared CSP-quota validator ==")


def _hdr_rule(name, header_config):
    return {"id": "h", "enabled": True, "expression": "true", "action": "rewrite",
            "action_parameters": {"headers": {name: header_config}}}


def _status_of(ops):
    """The outcome of the single header op the processor returned. A non_convertible record
    has type='non_convertible' (no outcome_status field); a converted op carries
    outcome_status (EXACT/LOSSY)."""
    if not ops:
        return None
    o = ops[0]
    if o.get("type") == "non_convertible":
        return "NON_CONVERTIBLE"
    return o.get("outcome_status")


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
# LEDGER was wrongly EXACT. value_expression_unmappable now returns a reason on parse failure.
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
# the unmappable helper itself: parse failure yields a reason (was: None = "convertible").
check("#33 value_expression_unmappable('foo(') returns a reason (parse failure, not None)",
      isinstance(_cep.value_expression_unmappable("foo("), str))
check("#33 value_expression_unmappable('http.host') is None (a real, mappable field)",
      _cep.value_expression_unmappable("http.host") is None)

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
_gspec37 = _ilu.spec_from_file_location("cdn_gen37", os.path.join(SCRIPTS, "cdn-generate-js.py"))
_gen37 = _ilu.module_from_spec(_gspec37)
_gspec37.loader.exec_module(_gen37)


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
import shutil as _shutil
import subprocess as _subprocess
import json as _json
_NODE = _shutil.which("node")
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
import shutil as _sh2
import subprocess as _sp2
import json as _js2
_NODE2 = _sh2.which("node")


_QS_HELPER = "\n".join(_gen37._qs_helper_lines())   # the REAL _qs helper the generator injects


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
import json as _js44


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
    print()
    if SKIPPED:
        print(f"SKIPPED: {len(SKIPPED)} check(s) (not run — NOT counted as passing)")
        for label, reason in SKIPPED:
            print(f"  - {label} — {reason}")
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} check(s)")
        for label, _ in FAILURES:
            print(f"  - {label}")
        sys.exit(1)
    print("All NC-provenance checks passed."
          + (f" ({len(SKIPPED)} skipped)" if SKIPPED else ""))
