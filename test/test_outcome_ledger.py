#!/usr/bin/env python3
"""Unit tests for the L2 claim layer's write-side API (`claim_decision` / `claim_non_convertible`).

After the round-2 bucket-B cleanup the artifact/physical/reconciler layer was removed; the system
runs on `_claims` + the finalize ledger gate (the gate's invariants — status, key shape,
duplicate-inventory, one-leaf-one-claim/disjointness, no-silent-drop, hidden NC/LOSSY — are tested in
test_dynamic_values.py). This file retains the WRITE-side contract of the two live ledger channels:
`claim_decision` (status / exact_noop / source-key shape guards) and `claim_non_convertible`, plus the
build-time strip contract. The old reconciler / logical-artifact / physical-artifact / baseline /
`emit_non_convertible` tests were deleted with that layer.

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
            "_inventory": [list(k) for k in inv], "_claims": []}


def _valueerror(fn):
    try:
        fn()
        return False
    except ValueError:
        return True


K_A = ("rule", "r", "/a")
K2 = ("rule", "/a")               # two-element key — malformed
K_EMPTY_KIND = ("", "r", "/a")
K_EMPTY_PTR = ("rule", "r", "")
K_EMPTY_ID = ("rule", "", "/a")   # LEGAL — a rule may have no id

print("== claim_decision: status / exact_noop contract (ValueError) ==")
check("exact_noop only valid with EXACT",
      _valueerror(lambda: _pre.claim_decision(_ir([K_A]), [K_A],
                  _pre.OUTCOME_NON_CONVERTIBLE, reason="x", exact_noop=True)))
check("LOSSY + exact_noop rejected",
      _valueerror(lambda: _pre.claim_decision(_ir([K_A]), [K_A],
                  _pre.OUTCOME_LOSSY, reason="x", exact_noop=True)))
check("bad status rejected",
      _valueerror(lambda: _pre.claim_decision(_ir([K_A]), [K_A], "WHATEVER")))
check("exact_noop + artifact_ids rejected (exact_noop is artifact-less)",
      _valueerror(lambda: _pre.claim_decision(_ir([K_A]), [K_A], _pre.OUTCOME_EXACT,
                  exact_noop=True, artifact_ids=["x"])))

print("== claim_decision: source-key shape contract (ValueError) ==")
check("2-element key rejected",
      _valueerror(lambda: _pre.claim_decision(_ir([K_A]), [K2], _pre.OUTCOME_EXACT, exact_noop=True)))
check("empty-kind key rejected",
      _valueerror(lambda: _pre.claim_decision(_ir([K_A]), [K_EMPTY_KIND], _pre.OUTCOME_EXACT, exact_noop=True)))
check("empty-pointer key rejected",
      _valueerror(lambda: _pre.claim_decision(_ir([K_A]), [K_EMPTY_PTR], _pre.OUTCOME_EXACT, exact_noop=True)))
check("no source key rejected",
      _valueerror(lambda: _pre.claim_decision(_ir([K_A]), [], _pre.OUTCOME_EXACT, exact_noop=True)))
check("bare-string key ['abc'] rejected (RAW key validated before list())",
      _valueerror(lambda: _pre.claim_decision(_ir([K_A]), ["abc"], _pre.OUTCOME_EXACT, exact_noop=True)))

print("== claim_decision: no over-reject (records the claim on _claims) ==")
_ir_eid = _ir([K_EMPTY_ID])
_pre.claim_decision(_ir_eid, [K_EMPTY_ID], _pre.OUTCOME_EXACT, exact_noop=True)
check("empty source id is LEGAL (rule w/o id) -> claim recorded",
      len(_ir_eid["_claims"]) == 1 and _ir_eid["_claims"][0]["source_keys"] == [list(K_EMPTY_ID)])
_ir6 = _ir([K_A])
_pre.claim_decision(_ir6, [K_A], _pre.OUTCOME_EXACT, exact_noop=True)
check("well-formed triple accepted (no over-reject)", len(_ir6["_claims"]) == 1)

print("== claim_non_convertible: whole-unit NC claim + legacy report entry ==")
_ir_nc = _ir([K_A])
_pre.claim_non_convertible(_ir_nc, "rule", "r", "no CloudFront equivalent", description="d")
check("claim_non_convertible records ONE NC claim over the unit's inventory keys",
      len(_ir_nc["_claims"]) == 1 and _ir_nc["_claims"][0]["status"] == "NON_CONVERTIBLE"
      and _ir_nc["_claims"][0]["source_keys"] == [list(K_A)])
check("claim_non_convertible writes the legacy non_convertible report entry (user-visible)",
      len(_ir_nc["cache_behaviors"][0]["non_convertible"]) == 1
      and _ir_nc["cache_behaviors"][0]["non_convertible"][0]["cf_source_rule"] == "r"
      and _ir_nc["cache_behaviors"][0]["non_convertible"][0]["outcome"] == "NON_CONVERTIBLE")

print("== build-time strip keeps the ledger keys the finalize gate reads ==")
_ir_s = _ir([K_A])
_pre.claim_decision(_ir_s, [K_A], _pre.OUTCOME_EXACT, exact_noop=True)
_pre._strip_build_internals(_ir_s)
check("_strip_build_internals keeps _claims + _inventory (the finalize gate reads them)",
      "_claims" in _ir_s and "_inventory" in _ir_s)
check("_strip_build_internals leaves NO removed artifact/reconciler key",
      not any(k in _ir_s for k in ("_logical_artifacts", "_physical_artifacts", "_ledger", "_logical_index")))


if __name__ == "__main__":
    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} check(s)")
        for label, _ in FAILURES:
            print(f"  - {label}")
        sys.exit(1)
    print("All outcome-ledger checks passed.")
