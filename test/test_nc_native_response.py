#!/usr/bin/env python3
"""Split from test_nc_provenance.py (round-2 test-split; behavior-preserving).
Shared setup + helpers live in test_nc_common."""
from test_nc_common import *  # noqa: F401,F403

print("== FINDING (spine) 25: native-effects producer — post-replay effective contribution ==")
_DC25 = {"hostname": "shop.example.com", "apex_domain": "example.com", "origin_type": "custom",
         "origin_content": "o.net", "sanitized_name": "shop_example_com"}


def _pd25(all_rules, mt=None):
    return _pre.process_domain("shop.example.com", _DC25, all_rules, {}, {}, mt or {})


def _claims_for(ir, unit):
    return [c for c in ir["_claims"] if any(k[1] == unit for k in c["source_keys"])]


def _native_arts(ir):
    # rebuild {artifact_id, owner_keys} native-effect artifacts from the ledger
    return [{"artifact_id": aid, "owner_keys": [list(k) for k in owners]}
            for aid, owners in _owned_artifacts(ir, ":native:").items()]


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


if __name__ == "__main__":
    report()
