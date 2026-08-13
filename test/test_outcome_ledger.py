#!/usr/bin/env python3
"""Unit tests for the L2 outcome-ledger core (three-layer model + hard reconciler).

The ledger is the Phase-1 safety gate: every source-config leaf must end with exactly
one EXACT/LOSSY_WITH_WARNING/NON_CONVERTIBLE outcome, artifacts must trace back to a
non-NC owner, and any integrity breach is a CONVERTER BUG → LedgerError → FATAL. This
tests the reconciler's invariants directly (no full pipeline), so a breach can't slip
through before channel wiring builds on it.

Run: python3 test_outcome_ledger.py   (exit 0 = all pass). Pure; no deps.
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

FAILURES = []


def check(label, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")
    if not cond:
        FAILURES.append((label, detail))
        if detail:
            print(f"           {detail}")


def _ir(inv):
    return {"cache_behaviors": [{"non_convertible": []}],
            "_inventory": [list(k) for k in inv],
            "_claims": [], "_logical_artifacts": [], "_logical_index": {},
            "_physical_artifacts": []}


def _reconcile_raises(ir):
    try:
        _pre._reconcile_ledger(ir)
        return None
    except _pre.LedgerError as e:
        return str(e)


K_A = ("rule", "r", "/a")
K_B = ("rule", "r", "/b")

print("== reconciler: happy paths ==")
ir = _ir([K_A])
_pre.emit_artifact(ir, "art1", "redirect", [K_A])
_pre.claim_decision(ir, [K_A], _pre.OUTCOME_EXACT, artifact_ids=["art1"])
_led = _pre._reconcile_ledger(ir)
check("EXACT with owned artifact -> ledger row", len(_led) == 1 and _led[0]["status"] == "EXACT")

ir = _ir([K_A])
_pre.claim_decision(ir, [K_A], _pre.OUTCOME_EXACT, exact_noop=True)
check("EXACT exact_noop (no artifact) -> ok", len(_pre._reconcile_ledger(ir)) == 1)

ir = _ir([K_A])
_pre.emit_non_convertible(ir, [K_A], "no CloudFront equivalent")
check("NON_CONVERTIBLE via emit_non_convertible -> ok", len(_pre._reconcile_ledger(ir)) == 1)
check("emit_non_convertible mirrors to legacy non_convertible list (#3)",
      len(ir["cache_behaviors"][0]["non_convertible"]) == 1
      and ir["cache_behaviors"][0]["non_convertible"][0]["outcome"] == "NON_CONVERTIBLE")

# a claim over TWO keys sharing one artifact (both co-own) — the multi-key model
ir = _ir([K_A, K_B])
_pre.emit_artifact(ir, "shared", "cff_op", [K_A, K_B])
_pre.claim_decision(ir, [K_A, K_B], _pre.OUTCOME_EXACT, artifact_ids=["shared"])
check("one claim over 2 keys sharing an artifact (both own) -> ok",
      len(_pre._reconcile_ledger(ir)) == 2)

print("== reconciler: integrity breaches all FATAL (LedgerError) ==")
check("inventory key with no claim -> FATAL",
      _reconcile_raises(_ir([K_A])) is not None)

ir = _ir([K_A])
_pre.claim_decision(ir, [K_A], _pre.OUTCOME_EXACT, exact_noop=True)
_pre.claim_decision(ir, [K_A], _pre.OUTCOME_EXACT, exact_noop=True)
check("same key covered by 2 claims -> FATAL", _reconcile_raises(ir) is not None)

ir = _ir([K_A])
_pre.emit_artifact(ir, "x", "k", [K_A])
_pre.claim_decision(ir, [K_A], _pre.OUTCOME_NON_CONVERTIBLE, reason="no", artifact_ids=["x"])
check("NON_CONVERTIBLE referencing an artifact -> FATAL", _reconcile_raises(ir) is not None)

ir = _ir([K_A])
_pre.emit_artifact(ir, "orphan", "k", [K_A])
_pre.claim_decision(ir, [K_A], _pre.OUTCOME_EXACT, exact_noop=True)
check("owned artifact no claim references (orphan) -> FATAL", _reconcile_raises(ir) is not None)

# #1 the subtle one: claim over [/a,/b] but artifact owned only by /a
ir = _ir([K_A, K_B])
_pre.emit_artifact(ir, "art", "k", [K_A])
_pre.claim_decision(ir, [K_A, K_B], _pre.OUTCOME_EXACT, artifact_ids=["art"])
check("#1 ownership mismatch (claim keys != artifact owners) -> FATAL",
      _reconcile_raises(ir) is not None, "must require set EQUALITY, not subset")

ir = _ir([K_A])
_pre.emit_artifact(ir, "a", "k", [("rule", "OTHER", "/z")])  # owner not in inventory
_pre.claim_decision(ir, [K_A], _pre.OUTCOME_EXACT, artifact_ids=["a"])
check("artifact owner not in inventory -> FATAL", _reconcile_raises(ir) is not None)

ir = {"cache_behaviors": [{"non_convertible": []}],
      "_inventory": [list(K_A), list(K_A)],  # duplicate
      "_claims": [], "_logical_artifacts": [], "_logical_index": {}, "_physical_artifacts": []}
_pre.claim_decision(ir, [K_A], _pre.OUTCOME_EXACT, exact_noop=True)
check("duplicate inventory key -> FATAL", _reconcile_raises(ir) is not None)

ir = _ir([K_A])
_pre.emit_artifact(ir, "a", "k", [K_A])
_pre.claim_decision(ir, [K_A], _pre.OUTCOME_EXACT, artifact_ids=["missing-id"])
check("claim references unknown logical artifact -> FATAL", _reconcile_raises(ir) is not None)

print("== API-level contract rejections (ValueError) ==")


def _valueerror(fn):
    try:
        fn()
        return False
    except ValueError:
        return True


check("exact_noop only valid with EXACT (#4)",
      _valueerror(lambda: _pre.claim_decision(_ir([K_A]), [K_A],
                  _pre.OUTCOME_NON_CONVERTIBLE, reason="x", exact_noop=True)))
check("LOSSY + exact_noop rejected",
      _valueerror(lambda: _pre.claim_decision(_ir([K_A]), [K_A],
                  _pre.OUTCOME_LOSSY, reason="x", exact_noop=True)))
_ir_k = _ir([K_A])
_pre.emit_artifact(_ir_k, "dup", "kindA", [K_A])
check("emit_artifact re-emit with different kind rejected",
      _valueerror(lambda: _pre.emit_artifact(_ir_k, "dup", "kindB", [K_A])))
check("bad status rejected",
      _valueerror(lambda: _pre.claim_decision(_ir([K_A]), [K_A], "WHATEVER")))

print("== LOSSY/NC reason required (via reconcile) ==")
ir = _ir([K_A])
_pre.emit_artifact(ir, "la", "cff", [K_A])
ir["_claims"].append({"source_keys": [list(K_A)], "status": "LOSSY_WITH_WARNING",
                      "reason": None, "exact_noop": False, "artifact_ids": ["la"]})
check("LOSSY without reason -> FATAL", _reconcile_raises(ir) is not None)

print("== physical-layer validation (finalize stage) ==")


def _la(artifact_id, kind, owner=K_A):
    # A raw logical-artifact dict, the LOSSLESS shape validate_physical_artifacts now
    # takes (it builds its own id->kind index internally — callers never pass a map).
    return {"artifact_id": artifact_id, "kind": kind, "owner_keys": [list(owner)]}


def _phys_raises(logical_artifacts, phys):
    try:
        _pre.validate_physical_artifacts(logical_artifacts, phys)
        return None
    except _pre.LedgerError as e:
        return str(e)


check("physical references ghost logical id -> FATAL",
      _phys_raises([_la("real", "rhp")], [{"artifact_id": "p", "baseline": False,
                               "logical_artifact_ids": ["ghost"], "kind": "rhp"}]) is not None)
check("logical artifact mapped to no physical -> FATAL",
      _phys_raises([_la("orphan", "rhp")], []) is not None)
check("duplicate physical id -> FATAL",
      _phys_raises([_la("l", "rhp")], [{"artifact_id": "p", "baseline": False, "logical_artifact_ids": ["l"], "kind": "rhp"},
                           {"artifact_id": "p", "baseline": True, "kind": "dns", "baseline_reason": "x"}]) is not None)
check("non-baseline physical with no logical ids -> FATAL",
      _phys_raises([], [{"artifact_id": "p", "baseline": False, "logical_artifact_ids": [], "kind": "rhp"}]) is not None)
check("baseline with logical ids -> FATAL",
      _phys_raises([], [{"artifact_id": "p", "baseline": True, "kind": "dns",
                         "baseline_reason": "x", "logical_artifact_ids": ["l"]}]) is not None)
check("baseline bad kind -> FATAL (allowlist)",
      _phys_raises([], [{"artifact_id": "p", "baseline": True, "kind": "not_allowed",
                         "baseline_reason": "x", "logical_artifact_ids": []}]) is not None)
check("valid physical mapping -> ok",
      _phys_raises([_la("l1", "rhp")], [{"artifact_id": "p", "baseline": False,
                             "logical_artifact_ids": ["l1"], "kind": "rhp"}]) is None)
check("physical artifact empty id -> FATAL",
      _phys_raises([_la("l1", "rhp")], [{"artifact_id": "", "baseline": False,
                   "logical_artifact_ids": ["l1"], "kind": "rhp"}]) is not None)
check("baseline artifact empty id -> FATAL",
      _phys_raises([], [{"artifact_id": None, "baseline": True, "kind": "dns",
                   "baseline_reason": "x", "logical_artifact_ids": []}]) is not None)
check("emit_baseline bad kind rejected (ValueError)",
      _valueerror(lambda: _pre.emit_baseline(_ir([]), "b", "nope", "reason")))
check("emit_baseline empty id rejected (ValueError)",
      _valueerror(lambda: _pre.emit_baseline(_ir([]), "", "dns", "reason")))
check("emit_physical_artifact empty id rejected (ValueError)",
      _valueerror(lambda: _pre.emit_physical_artifact(_ir([]), "", "rhp", ["l"])))
check("emit_physical_artifact empty kind rejected (ValueError)",
      _valueerror(lambda: _pre.emit_physical_artifact(_ir([]), "p", "", ["l"])))

print("== FINDING 1 (P1): validator builds its own index; kind check unbypassable ==")
# The validator takes the LOSSLESS raw logical-artifact list; there is no set/map input
# and no unknown-kind branch, so the kind check can't be dropped at the interface.
check("#1 physical kind != collapsed logical kind (cff_op -> rhp) -> FATAL",
      _phys_raises([_la("lg", "cff_op")], [{"artifact_id": "p", "baseline": False,
                   "logical_artifact_ids": ["lg"], "kind": "rhp"}]) is not None,
      "physical must be kind-homogeneous with the logicals it collapses")
check("#1 same-kind collapse (two cff_op logicals -> one cff_op physical) -> ok",
      _phys_raises([_la("a", "cff_op"), _la("b", "cff_op", K_B)],
                   [{"artifact_id": "p", "baseline": False,
                     "logical_artifact_ids": ["a", "b"], "kind": "cff_op"}]) is None)
check("#1 non-baseline physical with empty kind -> FATAL",
      _phys_raises([_la("l", "rhp")], [{"artifact_id": "p", "baseline": False,
                   "logical_artifact_ids": ["l"], "kind": ""}]) is not None)
check("#1 logical artifact missing/empty kind -> FATAL",
      _phys_raises([{"artifact_id": "l", "kind": "", "owner_keys": [list(K_A)]}],
                   [{"artifact_id": "p", "baseline": False,
                     "logical_artifact_ids": ["l"], "kind": "rhp"}]) is not None)
check("#1 duplicate logical id across domains -> FATAL (no silent overwrite)",
      _phys_raises([_la("dup", "cff_op"), _la("dup", "rhp")],
                   [{"artifact_id": "p", "baseline": False,
                     "logical_artifact_ids": ["dup"], "kind": "rhp"}]) is not None)
check("#1 bare set of ids rejected (no compat mode)",
      _phys_raises({"l"}, [{"artifact_id": "p", "baseline": False,
                   "logical_artifact_ids": ["l"], "kind": "rhp"}]) is not None,
      "a set element is a str, not a logical-artifact dict -> must fail")

print("== FINDING 2 (P1): duplicate logical artifact id not silently overwritten ==")
# The API merges a re-emit, so a duplicate can only arrive via a hand-built /
# round-tripped IR. Two entries with the SAME id but DIFFERENT kind must be rejected by
# the reconciler (a dict comprehension would silently keep the last and pass).
ir = _ir([K_A])
ir["_logical_artifacts"] = [
    {"artifact_id": "dup", "kind": "cff_op", "owner_keys": [list(K_A)]},
    {"artifact_id": "dup", "kind": "rhp", "owner_keys": [list(K_A)]},
]
_pre.claim_decision(ir, [K_A], _pre.OUTCOME_EXACT, artifact_ids=["dup"])
check("#2 duplicate logical id (diff kind) in _logical_artifacts -> FATAL",
      _reconcile_raises(ir) is not None, "reconciler must not silently keep the last")

print("== FINDING 3 (P2): exact_noop is mutually exclusive with artifacts ==")
check("exact_noop + artifact_ids rejected at API (ValueError)",
      _valueerror(lambda: _pre.claim_decision(_ir([K_A]), [K_A], _pre.OUTCOME_EXACT,
                  exact_noop=True, artifact_ids=["x"])))
# Hand-built claim bypassing the API: EXACT + exact_noop + artifact must still FATAL.
ir = _ir([K_A])
_pre.emit_artifact(ir, "a", "cff_op", [K_A])
ir["_claims"].append({"source_keys": [list(K_A)], "status": "EXACT",
                      "reason": None, "exact_noop": True, "artifact_ids": ["a"]})
check("#3 EXACT + exact_noop + artifact (hand-built) -> FATAL", _reconcile_raises(ir) is not None)
# LOSSY + exact_noop hand-built (API blocks it; reconciler must too).
ir = _ir([K_A])
_pre.emit_artifact(ir, "a", "cff_op", [K_A])
ir["_claims"].append({"source_keys": [list(K_A)], "status": "LOSSY_WITH_WARNING",
                      "reason": "r", "exact_noop": True, "artifact_ids": ["a"]})
check("#3 LOSSY + exact_noop (hand-built) -> FATAL", _reconcile_raises(ir) is not None)

print("== FINDING 3b (P2): source key must be a (kind, id, pointer) TRIPLE ==")
K2 = ("rule", "/a")            # two-element key — the reviewer's counterexample
K_EMPTY_KIND = ("", "r", "/a")
K_EMPTY_PTR = ("rule", "r", "")
K_EMPTY_ID = ("rule", "", "/a")   # LEGAL — a rule may have no id
# API rejects a malformed claim key.
check("claim_decision 2-element key rejected (ValueError)",
      _valueerror(lambda: _pre.claim_decision(_ir([K_A]), [K2], _pre.OUTCOME_EXACT, exact_noop=True)))
check("claim_decision empty-kind key rejected (ValueError)",
      _valueerror(lambda: _pre.claim_decision(_ir([K_A]), [K_EMPTY_KIND], _pre.OUTCOME_EXACT, exact_noop=True)))
check("claim_decision empty-pointer key rejected (ValueError)",
      _valueerror(lambda: _pre.claim_decision(_ir([K_A]), [K_EMPTY_PTR], _pre.OUTCOME_EXACT, exact_noop=True)))
# An EMPTY id is legal (a rule without an id) — must NOT be rejected (guard vs over-reject).
_ir_eid = _ir([K_EMPTY_ID])
_pre.claim_decision(_ir_eid, [K_EMPTY_ID], _pre.OUTCOME_EXACT, exact_noop=True)
check("empty source id is LEGAL (rule w/o id) -> ok", len(_pre._reconcile_ledger(_ir_eid)) == 1)
# API rejects a malformed OWNER key.
check("emit_artifact 2-element owner key rejected (ValueError)",
      _valueerror(lambda: _pre.emit_artifact(_ir([K_A]), "a", "cff_op", [K2])))
# Reconciler gate: hand-built 2-element inventory key -> FATAL (would become a 2-tuple).
ir = {"cache_behaviors": [{"non_convertible": []}], "_inventory": [list(K2)],
      "_claims": [], "_logical_artifacts": [], "_logical_index": {}, "_physical_artifacts": []}
ir["_claims"].append({"source_keys": [list(K2)], "status": "EXACT",
                      "reason": None, "exact_noop": True, "artifact_ids": []})
check("#3b 2-element inventory key (hand-built) -> FATAL", _reconcile_raises(ir) is not None)
# Reconciler gate: hand-built 2-element claim key with a valid inventory -> FATAL.
ir = _ir([K_A])
ir["_claims"].append({"source_keys": [list(K2)], "status": "EXACT",
                      "reason": None, "exact_noop": True, "artifact_ids": []})
check("#3b 2-element claim key (hand-built) -> FATAL", _reconcile_raises(ir) is not None)
# Reconciler gate: hand-built 2-element OWNER key -> FATAL.
ir = _ir([K_A])
ir["_logical_artifacts"] = [{"artifact_id": "a", "kind": "cff_op", "owner_keys": [list(K2)]}]
_pre.claim_decision(ir, [K_A], _pre.OUTCOME_EXACT, artifact_ids=["a"])
check("#3b 2-element owner key (hand-built) -> FATAL", _reconcile_raises(ir) is not None)

print("== FINDING 5 (P2): artifact identity + non-empty claim keys ==")
check("emit_artifact empty id rejected (ValueError)",
      _valueerror(lambda: _pre.emit_artifact(_ir([K_A]), "", "cff_op", [K_A])))
check("emit_artifact None id rejected (ValueError)",
      _valueerror(lambda: _pre.emit_artifact(_ir([K_A]), None, "cff_op", [K_A])))
check("emit_artifact empty kind rejected (ValueError)",
      _valueerror(lambda: _pre.emit_artifact(_ir([K_A]), "a", "", [K_A])))
check("emit_artifact no owner rejected (ValueError)",
      _valueerror(lambda: _pre.emit_artifact(_ir([K_A]), "a", "cff_op", [])))
check("claim_decision with no source key rejected (ValueError)",
      _valueerror(lambda: _pre.claim_decision(_ir([K_A]), [], _pre.OUTCOME_EXACT, exact_noop=True)))
# Hand-built breaches at the reconciler gate.
ir = _ir([K_A])
ir["_logical_artifacts"] = [{"artifact_id": "", "kind": "cff_op", "owner_keys": [list(K_A)]}]
_pre.claim_decision(ir, [K_A], _pre.OUTCOME_EXACT, exact_noop=True)
check("#5 logical artifact empty id (hand-built) -> FATAL", _reconcile_raises(ir) is not None)
ir = _ir([K_A])
ir["_logical_artifacts"] = [{"artifact_id": "a", "kind": "", "owner_keys": [list(K_A)]}]
_pre.claim_decision(ir, [K_A], _pre.OUTCOME_EXACT, exact_noop=True)
check("#5 logical artifact empty kind (hand-built) -> FATAL", _reconcile_raises(ir) is not None)
ir = _ir([K_A])
ir["_claims"].append({"source_keys": [], "status": "EXACT",
                      "reason": None, "exact_noop": True, "artifact_ids": []})
check("#5 claim with empty source_keys (hand-built) -> FATAL", _reconcile_raises(ir) is not None)

print("== FINDING 4 (P2): _logical_index stripped from written IR ==")
_ir4 = _ir([K_A])
_pre.emit_artifact(_ir4, "a", "cff_op", [K_A])
check("emit_artifact populates _logical_index (build time)", "_logical_index" in _ir4 and _ir4["_logical_index"])
_pre._strip_build_internals(_ir4)
check("#4 _logical_index dropped by _strip_build_internals", "_logical_index" not in _ir4)
check("#4 _logical_artifacts KEPT after strip", _ir4.get("_logical_artifacts"))
check("#4 ledger lists kept after strip",
      "_claims" in _ir4 and "_physical_artifacts" in _ir4 and "_inventory" in _ir4)

print("== FINDING 6 (P2): validate RAW type before normalizing to list ==")
# Root cause: list(k) ran BEFORE _bad_source_key, so a bare string "abc" became a
# legal-looking ["a","b","c"] triple. A source key must be validated in its RAW form.
check("#6 claim_decision bare-string key ['abc'] rejected (ValueError)",
      _valueerror(lambda: _pre.claim_decision(_ir([K_A]), ["abc"], _pre.OUTCOME_EXACT, exact_noop=True)))
check("#6 emit_artifact bare-string owner ['abc'] rejected (ValueError)",
      _valueerror(lambda: _pre.emit_artifact(_ir([K_A]), "a", "cff_op", ["abc"])))
# A well-formed key still works (no over-reject from the raw-first check).
_ir6 = _ir([K_A])
_pre.claim_decision(_ir6, [K_A], _pre.OUTCOME_EXACT, exact_noop=True)
check("#6 well-formed triple still accepted (no over-reject)", len(_pre._reconcile_ledger(_ir6)) == 1)

# emit_physical_artifact: logical_artifact_ids must be a list of non-empty strings, and
# there must be NO str() coercion (None must NOT become the string "None").
check("#6 emit_physical [None] rejected (ValueError)",
      _valueerror(lambda: _pre.emit_physical_artifact(_ir([]), "p", "rhp", [None])))
check("#6 emit_physical [''] rejected (ValueError)",
      _valueerror(lambda: _pre.emit_physical_artifact(_ir([]), "p", "rhp", [""])))
check("#6 emit_physical bare-string 'abc' rejected (ValueError)",
      _valueerror(lambda: _pre.emit_physical_artifact(_ir([]), "p", "rhp", "abc")))
check("#6 emit_physical empty list rejected (ValueError)",
      _valueerror(lambda: _pre.emit_physical_artifact(_ir([]), "p", "rhp", [])))
# Verbatim storage: a real id list is stored WITHOUT coercion.
_ir6b = _ir([])
_pre.emit_physical_artifact(_ir6b, "p", "cff_op", ["x", "y"])
check("#6 emit_physical stores ids verbatim (no str() coercion)",
      _ir6b["_physical_artifacts"][0]["logical_artifact_ids"] == ["x", "y"])

# Hand-built persisted physical with logical_artifact_ids="abc" must FATAL at the gate
# (a bare string would otherwise iterate as three ids 'a','b','c').
check("#6 gate: persisted logical_artifact_ids='abc' -> FATAL",
      _phys_raises([_la("a", "rhp"), _la("b", "rhp"), _la("c", "rhp")],
                   [{"artifact_id": "p", "baseline": False,
                     "logical_artifact_ids": "abc", "kind": "rhp"}]) is not None)
check("#6 gate: persisted logical_artifact_ids=[None] -> FATAL",
      _phys_raises([_la("l", "rhp")],
                   [{"artifact_id": "p", "baseline": False,
                     "logical_artifact_ids": [None], "kind": "rhp"}]) is not None)
# No over-reject: a genuine id literally named "None" round-trips fine.
check("#6 real id 'None' (genuine string) still works (no over-reject)",
      _phys_raises([_la("None", "rhp")],
                   [{"artifact_id": "p", "baseline": False,
                     "logical_artifact_ids": ["None"], "kind": "rhp"}]) is None)

print("== FINDING 7 (P2): emit_non_convertible must not double-consume a generator ==")
# claim_decision consumes source_keys internally; a GENERATOR would be exhausted before
# the report id-extraction ran, silently emptying cf_source_rule. Both the claim key AND
# the legacy cf_source_rule must be correct when passed a single-use iterator. Use TWO
# keys with DISTINCT source ids (K_A id 'r', K_D id 'r2') so cf_source_rule joins both —
# a double-consumed generator would collapse it to '' (the `or [""]` fallback).
K_D = ("rule", "r2", "/d")
ir = _ir([K_A, K_D])
_pre.emit_non_convertible(ir, (k for k in [K_A, K_D]), "no CF equivalent", "d")
check("#7 generator: claim source_keys correct",
      ir["_claims"][0]["source_keys"] == [list(K_A), list(K_D)])
check("#7 generator: cf_source_rule not emptied (both ids)",
      ir["cache_behaviors"][0]["non_convertible"][0]["cf_source_rule"] == "r,r2",
      "double-consumed generator would give ''")
ir = _ir([K_A])
_pre.emit_non_convertible(ir, (k for k in [K_A]), "x")
check("#7 single-key generator: cf_source_rule == 'r'",
      ir["cache_behaviors"][0]["non_convertible"][0]["cf_source_rule"] == "r")
# A plain list still works (no regression).
ir = _ir([K_A, K_D])
_pre.emit_non_convertible(ir, [K_A, K_D], "y")
check("#7 list input still correct (both claim + cf_source_rule)",
      ir["_claims"][0]["source_keys"] == [list(K_A), list(K_D)]
      and ir["cache_behaviors"][0]["non_convertible"][0]["cf_source_rule"] == "r,r2")

print("== FINDING 8 (P2): baseline gate is schema (real bool + strict []), not truthiness ==")
check("#8 baseline='false' (string) -> FATAL",
      _phys_raises([], [{"artifact_id": "p", "baseline": "false", "kind": "dns",
                   "baseline_reason": "x", "logical_artifact_ids": []}]) is not None,
      "truthiness would treat 'false' as baseline")
check("#8 missing baseline key -> FATAL",
      _phys_raises([_la("l", "rhp")], [{"artifact_id": "p", "kind": "rhp",
                   "logical_artifact_ids": ["l"]}]) is not None)
check("#8 baseline=1 (int) -> FATAL",
      _phys_raises([], [{"artifact_id": "p", "baseline": 1, "kind": "dns",
                   "baseline_reason": "x", "logical_artifact_ids": []}]) is not None)
check("#8 baseline logical_artifact_ids=None -> FATAL",
      _phys_raises([], [{"artifact_id": "p", "baseline": True, "kind": "dns",
                   "baseline_reason": "x", "logical_artifact_ids": None}]) is not None)
check("#8 baseline logical_artifact_ids='' -> FATAL",
      _phys_raises([], [{"artifact_id": "p", "baseline": True, "kind": "dns",
                   "baseline_reason": "x", "logical_artifact_ids": ""}]) is not None)
check("#8 baseline logical_artifact_ids=() (empty tuple) -> FATAL",
      _phys_raises([], [{"artifact_id": "p", "baseline": True, "kind": "dns",
                   "baseline_reason": "x", "logical_artifact_ids": ()}]) is not None)
check("#8 non-baseline logical_artifact_ids=tuple (persisted) -> FATAL",
      _phys_raises([_la("l", "rhp")], [{"artifact_id": "p", "baseline": False,
                   "kind": "rhp", "logical_artifact_ids": ("l",)}]) is not None,
      "JSON never yields tuples; persisted gate requires a strict list")
# CONTROL group: the legitimate shapes must still pass (no over-reject).
check("#8 CONTROL baseline=True + [] -> ok",
      _phys_raises([], [{"artifact_id": "p", "baseline": True, "kind": "dns",
                   "baseline_reason": "x", "logical_artifact_ids": []}]) is None)
check("#8 CONTROL non-baseline=False + ['l'] -> ok",
      _phys_raises([_la("l", "rhp")], [{"artifact_id": "p", "baseline": False,
                   "kind": "rhp", "logical_artifact_ids": ["l"]}]) is None)
# CONTROL: the emitters themselves produce schema-valid persisted artifacts.
_ir8 = _ir([])
_pre.emit_baseline(_ir8, "b", "dns", "r")
_pre.emit_physical_artifact(_ir8, "pp", "rhp", ["l1"])
check("#8 CONTROL emitters produce gate-valid artifacts",
      _phys_raises([_la("l1", "rhp")], _ir8["_physical_artifacts"]) is None)


if __name__ == "__main__":
    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} check(s)")
        for label, _ in FAILURES:
            print(f"  - {label}")
        sys.exit(1)
    print("All outcome-ledger checks passed.")
