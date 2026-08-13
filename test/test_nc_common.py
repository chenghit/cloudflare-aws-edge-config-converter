#!/usr/bin/env python3
"""Shared setup + helpers for the split test_nc_* suites (ledger / native_response / dynamic_value /
op_condition / regression), extracted from the former test_nc_provenance.py (round-2 test-split).

Loads the converter modules, defines check / skip / report + the cross-theme helpers, and exports
them for `from test_nc_common import *`. This module has NO checks of its own — run the themed test
files directly, e.g. `python3 test/test_nc_ledger.py`.
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


def _owned_artifacts(ir, id_substr=None):
    """Reconstruct the (removed) _logical_artifacts view {artifact_id -> owner source-key tuples}
    from the LEDGER: a claim's source_keys own its artifact_ids (the coordinator populates the two
    together from the same resolved keys, so their union is the artifact's owner set). `id_substr` selects a KIND
    via the id string — ':cff:' (cff_op), ':kvs:ip:' / ':kvs:error:' / ':kvs:redirect:' (kvs),
    ':native:' (native_effect). Ownership now lives on the claim; this is the authoritative view."""
    owners = {}
    for c in ir.get("_claims", []):
        for a in c.get("artifact_ids", []):
            if id_substr is None or id_substr in a:
                owners.setdefault(a, set()).update(tuple(k) for k in c["source_keys"])
    return owners




def _nc_keys(ir, unit_id):
    return sorted(tuple(k) for c in ir["_claims"] if c["status"] == "NON_CONVERTIBLE"
                  for k in c["source_keys"] if k[1] == unit_id)


def _unit_leaves(ir, unit_id):
    return sorted(tuple(k) for k in ir["_inventory"] if k[1] == unit_id)


def _disjoint_and_in_inv(ir):
    inv = set(tuple(k) for k in ir["_inventory"])
    allk = [tuple(k) for c in ir["_claims"] for k in c["source_keys"]]
    return len(allk) == len(set(allk)) and all(k in inv for k in allk)


def _unit_claim(ir, unit):
    cs = [c for c in ir["_claims"] if any(k[1] == unit for k in c["source_keys"])]
    return cs[0] if cs else None


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


_DC31 = {"hostname": "shop.example.com", "apex_domain": "example.com", "origin_type": "custom",
         "origin_content": "o.net", "sanitized_name": "shop_example_com"}


def _rh31(name, header_config):
    """A response-header rule where header_config is passed VERBATIM (so a test can omit the
    `value` key entirely, or set it to "" / a non-string)."""
    return _pre.process_domain("shop.example.com", _DC31, {"response_header": [
        {"id": "h", "enabled": True, "expression": "true", "action": "rewrite",
         "action_parameters": {"headers": {name: header_config}}}]}, {}, {}, {})


_gspec37 = _ilu.spec_from_file_location("cdn_gen37", os.path.join(SCRIPTS, "cdn-generate-js.py"))
_gen37 = _ilu.module_from_spec(_gspec37)
_gspec37.loader.exec_module(_gen37)


import shutil as _shutil
import subprocess as _subprocess
import json as _json
_NODE = _shutil.which("node")


import shutil as _sh2
import subprocess as _sp2
import json as _js2
_NODE2 = _sh2.which("node")


_QS_HELPER = "\n".join(_gen37._qs_helper_lines())   # the REAL _qs helper the generator injects


import json as _js44   # hoisted (finding 44 + op-condition round-trip)

def report():
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
    print("All checks passed." + (f" ({len(SKIPPED)} skipped)" if SKIPPED else ""))


__all__ = [_n for _n in dir() if not _n.startswith("__")]

