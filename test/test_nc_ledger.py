#!/usr/bin/env python3
"""Split from test_nc_provenance.py (round-2 test-split; behavior-preserving).
Shared setup + helpers live in test_nc_common."""
from test_nc_common import *  # noqa: F401,F403

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
# add_visitor_location_headers (an enabled MT with no CloudFront equivalent) must NOT silently vanish:
# an NC claim on its /$action leaf AND a non_convertible report entry (bucket-B silent-drop fix).
_irVL = _pd(mt={"managed_request_headers": [{"id": "add_visitor_location_headers", "enabled": True}]})
_vlC = [c for c in _irVL["_claims"] if c["status"] == "NON_CONVERTIBLE"
        and any(k[1] == "add_visitor_location_headers" for k in c["source_keys"])]
_vlR = [e for b in _irVL["cache_behaviors"] for e in b.get("non_convertible", [])
        if e.get("cf_source_rule") == "add_visitor_location_headers"]
check("#8 add_visitor_location_headers -> ONE NC claim on its /$action leaf (not a silent drop)",
      len(_vlC) == 1 and [list(k) for k in _vlC[0]["source_keys"]]
      == [["managed_transform", "add_visitor_location_headers", "/$action"]])
check("#8 add_visitor_location_headers -> non_convertible report entry (surfaced to the user)",
      len(_vlR) == 1 and "no CloudFront-equivalent" in (_vlR[0].get("reason") or ""))

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
_cff19 = _owned_artifacts(_ir19, ":cff:")
check("#19 exactly ONE shared CFF artifact", len(_cff19) == 1)
check("#19 shared CFF artifact owned by BOTH items (union of keys)",
      sorted(set(k[1] for k in next(iter(_cff19.values())))) == ["L#0", "L#1"])
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

# 2c dedup (bucket B): a rule applied to N behaviors records N cross-overlap-only effect OBJECTS for
# the SAME source leaf; the coordinator must mint ONE NC claim per leaf, not one per object.
_ir2cd = _pre.make_empty_ir(DC)
_pre.find_or_create_behavior(_ir2cd, "*", DC, "o.net")
_ir2cd["_inventory"] = [["rule", "rN", "/edge_ttl/mode"]]
_mk2cd = lambda: {"kind": "ttl_respect_origin", "_source_kind": "rule", "_source_id": "rN",
                  "_owned_key_segments": [["edge_ttl", "mode"]]}
_ir2cd["_native_overlap_nc"] = [{"effect": _mk2cd(), "behavior": "*a"},
                                {"effect": _mk2cd(), "behavior": "*b"}]
_ir2cd["_native_applied"] = []
_pre._coordinate_artifacts_and_claims(_ir2cd)
_nc2cd = [c for c in _ir2cd["_claims"] if c["status"] == "NON_CONVERTIBLE"
          and any(k[1] == "rN" for k in c["source_keys"])]
check("2c dedup: 2 cross-overlap effects on ONE source leaf -> exactly ONE NC claim",
      len(_nc2cd) == 1, f"got {len(_nc2cd)}")
check("2c dedup: the single NC claim owns exactly that source leaf",
      bool(_nc2cd) and sorted(tuple(k) for k in _nc2cd[0]["source_keys"]) == [("rule", "rN", "/edge_ttl/mode")])

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
      sorted(set(k[1] for owners in _owned_artifacts(_ir19d).values() for k in owners)) == ["rE", "rL"])
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
    return set(_owned_artifacts(ir))   # all artifact ids, from the ledger


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
_cffA = list(_owned_artifacts(_brA, ":cff:"))
_cffB = list(_owned_artifacts(_brB, ":cff:"))
check("#20 two domains' bulk CFF ids do not collide",
      _cffA and _cffB and not (set(_cffA) & set(_cffB)),
      f"A={_cffA} B={_cffB}")

# Inline custom error must NOT produce a converted claim / logical artifact this turn.
_ce = {"custom_error": [{"id": "ce123456", "enabled": True,
    "expression": "http.response.code eq 500", "action": "serve_error",
    "action_parameters": {"content": "<h1>x</h1>", "content_type": "text/html", "status_code": 503}}]}
_irCE = _pre.process_domain("shop.example.com", _DC_A, _ce, {}, {}, {})
check("#20 inline custom-error registers NO error: logical artifact this turn",
      not _owned_artifacts(_irCE, ":kvs:error:"))
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
_aids22 = sorted(_owned_artifacts(_ir22c))   # distinct artifact ids referenced by claims
check("#22 generic op + bulk redirect -> all artifact ids distinct, no collision",
      len(_aids22) == len(set(_aids22)) and len(_aids22) >= 2, f"got {_aids22}")
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
    return sorted(set(k[1] for owners in _owned_artifacts(ir, ":kvs:ip:").values()
                      for k in owners))


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
      not _owned_artifacts(_ir24c, ":kvs:ip:"))
check("#24 custom-error-only list -> ip: KVS NOT collected at all (inline rule NC'd, produced nothing)",
      not any(e["key"].startswith("ip:") for e in _ir24c["metadata"]["kvs_data"]))

# wired-ONLY sharing (header alone uses $blk) -> ip: KVS registered, owned by the header.
_ir24d = _pd24({"response_header": [{"id": "hW", "enabled": True, "expression": "ip.src in $blk",
    "action": "rewrite", "action_parameters": {"headers": {
        "X-A": {"operation": "set", "expression": "http.request.uri.path"}}}}]},
    iplists={"blk": ["1.1.1.1"]})
check("#24 wired-only list -> ip: KVS registered, owned by the header",
      _ip_kvs_owner_ids(_ir24d) == ["hW"])


if __name__ == "__main__":
    report()
