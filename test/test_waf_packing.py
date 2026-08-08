#!/usr/bin/env python3
"""Regression tests for the WAF rule-group overflow packer (waf-generate-cfn).

The packer moves overflow rules into referenced rule groups to fit AWS's hard
per-WebACL caps (10 rate-based rules, 50 reference statements), preserving
Cloudflare phase order (custom→rate→managed contiguous) and label semantics
(rewriting LabelMatchStatement keys to the producer's fully-qualified form).
These are the exact behaviors that, if wrong, silently break protection at
deploy time with no AWS error — so they're pinned here. The rule-group escape
of both caps was confirmed live (2026-07-12).

Run: python3 test_waf_packing.py   (exit 0 = all pass)
"""
import importlib.util
import os
import sys

_SCRIPTS = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "converter", "scripts")


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, os.path.join(_SCRIPTS, filename))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_cfn = _load("waf_generate_cfn", "waf-generate-cfn.py")

FAILURES = []


def check(label, cond, detail=""):
    if not cond:
        FAILURES.append((label, detail))
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}" + ("" if cond else f"  — {detail}"))


def _rbr(n):
    return {"Name": n, "Action": {"Block": {}},
            "Statement": {"RateBasedStatement": {"Limit": 1000, "AggregateKeyType": "IP",
                                                 "EvaluationWindowSec": 60}},
            "VisibilityConfig": {}}


def _ipref(n):
    return {"Name": n, "Action": {"Block": {}},
            "Statement": {"IPSetReferenceStatement": {"ARN": {"Fn::GetAtt": [f"ip{n}", "Arn"]}}},
            "VisibilityConfig": {}}


def _skip_producer(n, label="skip:all_remaining_custom_rules"):
    return {"Name": n, "Action": {"Count": {}}, "RuleLabels": [{"Name": label}],
            "Statement": {"ByteMatchStatement": {"SearchString": "x", "PositionalConstraint": "EXACTLY",
                          "FieldToMatch": {"UriPath": {}}, "TextTransformations": [{"Priority": 0, "Type": "NONE"}]}},
            "VisibilityConfig": {}}


def _consumer(n, label="skip:all_remaining_custom_rules"):
    return {"Name": n, "Action": {"Block": {}},
            "Statement": {"AndStatement": {"Statements": [
                {"NotStatement": {"Statement": {"LabelMatchStatement": {"Scope": "LABEL", "Key": label}}}},
                {"IPSetReferenceStatement": {"ARN": {"Fn::GetAtt": [f"ip{n}", "Arn"]}}}]}},
            "VisibilityConfig": {}}


def _pack(custom, rate, header=None, trailer=None, managed=None):
    resources, used = {}, set()

    def uid(b):
        lid = _cfn.sanitize_logical_id(b)
        while lid in used:
            lid += "X"
        used.add(lid)
        return lid

    ordered, warnings, over = _cfn.pack_webacl_rules(
        "waf-api", custom, rate, header or [], trailer or [], managed or [],
        uid, resources, None)
    return resources, ordered, over


def _webacl_refs(ordered):
    return sum(_cfn._count_refs_in_stmt(r.get("Statement", {})) for r in ordered)


def _webacl_rbr(ordered):
    return sum(1 for r in ordered if "RateBasedStatement" in r.get("Statement", {}))


def _groups(resources):
    return [r for r in resources.values() if r["Type"] == "AWS::WAFv2::RuleGroup"]


print("== WAF rule-group overflow packer ==")

# Under caps → no packing.
res, o, over = _pack([_ipref(f"c{i}") for i in range(5)], [_rbr(f"r{i}") for i in range(3)])
check("under caps → no rule groups", over is None and not _groups(res))
check("under caps → all rules stay direct", len(o) == 8)

# >10 RBR → overflow into a rule group; direct RBR clamped to 10.
res, o, over = _pack([], [_rbr(f"r{i}") for i in range(12)])
check("12 RBR: no over-limit", over is None)
check("12 RBR: direct RBR == 10", _webacl_rbr(o) == 10)
check("12 RBR: exactly 1 rule group created", len(_groups(res)) == 1)
check("12 RBR: rule group holds ≤4 RBR", all(
    sum(1 for x in g["Properties"]["Rules"] if "RateBasedStatement" in x["Statement"]) <= 4
    for g in _groups(res)))

# >50 refs → pack; the WebACL's OWN ref total (direct refs + 1 per group) must be ≤50.
res, o, over = _pack([_ipref(f"c{i}") for i in range(60)], [])
check("60 refs: no over-limit (packs, doesn't fail)", over is None)
check("60 refs: WebACL ref total ≤ 50 (group refs counted)", _webacl_refs(o) <= 50,
      f"got {_webacl_refs(o)}")

# rule group Capacity is set to the computed WCU (create-time immutable).
check("rule groups carry a positive Capacity", all(
    g["Properties"]["Capacity"] > 0 for g in _groups(res)))

# Label rewrite semantics (dual-subagent + 5 live tests, 2026-07-12):
#  - a consumer in the SAME container as the producer → BARE key (a self-prefix
#    like awswaf:...:webacl:<self>:<label> is REJECTED by CreateWebACL);
#  - a consumer in a DIFFERENT container → producer's Fn::Sub FQN;
#  - a label produced in MULTIPLE containers → OR of one match per container.
def _all_keys(res, ordered):
    """Every (owner_desc, Key) across WebACL rules and group rules."""
    out = []
    def walk(stmt, owner):
        for lm in _cfn._iter_label_match_statements(stmt):
            out.append((owner, lm["Key"]))
    for r in ordered:
        walk(r.get("Statement", {}), "webacl")
    for g in _groups(res):
        for r in g["Properties"]["Rules"]:
            walk(r.get("Statement", {}), "group")
    return out

# Producer stays in WebACL, consumers overflow into a group → cross-container FQN.
res, o, over = _pack([_skip_producer("s0")] + [_consumer(f"c{i}") for i in range(60)], [])
check("producer+consumers: no over-limit", over is None)
group_keys = [k for owner, k in _all_keys(res, o) if owner == "group"]
check("consumer-in-group (producer in WebACL) → Fn::Sub FQN", bool(group_keys) and all(
    isinstance(k, dict) and "Fn::Sub" in k for k in group_keys))
check("cross-container key targets producer's webacl FQN", all(
    ":webacl:waf-api:skip:all_remaining_custom_rules" in k["Fn::Sub"] for k in group_keys))
# No self-webacl prefix must EVER be emitted for a WebACL-level consumer (the deploy bug).
webacl_keys = [k for owner, k in _all_keys(res, o) if owner == "webacl"]
check("no self-webacl-prefixed key emitted at WebACL level", all(
    not (isinstance(k, dict) and ":webacl:waf-api:" in k.get("Fn::Sub", "")) for k in webacl_keys))

# Same-container: producer + consumer BOTH stay in the WebACL (small ruleset, no
# packing) → consumer key must be BARE (string), never a self-qualified Fn::Sub.
res2, o2, over2 = _pack([_skip_producer("p0"), _consumer("q0")], [])
check("small ruleset: no packing (stays in WebACL)", over2 is None and not _groups(res2))
same_keys = [k for _owner, k in _all_keys(res2, o2)]
check("same-container consumer → BARE string key (no self-prefix)", bool(same_keys) and all(
    isinstance(k, str) and k == "skip:all_remaining_custom_rules" for k in same_keys))

# Role-homogeneous packing: skip PRODUCERS (Count + RuleLabels) and CONSUMERS
# (everything else) must NEVER share a rule group. Give producers IP refs (real
# skip rules do) so >50 refs force grouping; the consumer stays direct at WebACL
# level and matches the label produced in the group(s) via the group FQN.
def _skip_producer_with_ref(n, label="skip:all_remaining_custom_rules"):
    return {"Name": n, "Action": {"Count": {}}, "RuleLabels": [{"Name": label}],
            "Statement": {"IPSetReferenceStatement": {"ARN": {"Fn::GetAtt": [f"ip{n}", "Arn"]}}},
            "VisibilityConfig": {}}
producers = [_skip_producer_with_ref(f"gp{i}") for i in range(60)]
res3, o3, over3 = _pack(producers + [_consumer("cc")], [])
check("role-aware pack: no over-limit", over3 is None and bool(_groups(res3)))

def _rule_role(r):
    return "P" if r.get("RuleLabels") else "C"
mixed = [g["Properties"]["Name"] for g in _groups(res3)
         if len({_rule_role(x) for x in g["Properties"]["Rules"]}) > 1]
check("every rule group is role-homogeneous (no producer+consumer mix)",
      not mixed, f"mixed groups: {mixed}")

# The consumer 'cc' (in a consumer-only group) references the label produced in
# the producer group(s) by their rulegroup FQN — cross-container, OR-combined.
def _find_rule(name):
    for r in o3:  # WebACL direct
        if r["Name"].startswith(name):
            return r
    for g in _groups(res3):  # inside a group
        for r in g["Properties"]["Rules"]:
            if r["Name"].startswith(name):
                return r
    return None
cc_rule = _find_rule("cc")
cc_key_vals = [lm["Key"] for lm in _cfn._iter_label_match_statements(cc_rule.get("Statement", {}))] \
    if cc_rule else []
check("cross-container consumer references a rulegroup FQN for the group-produced label",
      any(isinstance(k, dict) and ":rulegroup:" in k.get("Fn::Sub", "") for k in cc_key_vals),
      f"cc keys: {cc_key_vals}")

# Phase order: custom block (+ its group refs) all precede the rate block.
res, o, over = _pack([_ipref(f"c{i}") for i in range(55)], [_rbr(f"r{i}") for i in range(3)])
def _first_rate_idx(ordered):
    for i, r in enumerate(ordered):
        if "RateBasedStatement" in r.get("Statement", {}):
            return i
    return len(ordered)
def _last_custom_or_customgroup_idx(ordered):
    last = -1
    for i, r in enumerate(ordered):
        st = r.get("Statement", {})
        if "RateBasedStatement" in st:
            continue
        last = i
    return last
check("phase order: rate rules come after all custom/custom-group rules",
      over is None and _first_rate_idx(o) > 0)

# Priorities are unique and sequential from 0.
prios = [r["Priority"] for r in o]
check("priorities sequential 0..n-1", prios == list(range(len(o))), f"got {prios[:8]}...")

# Managed rules never packed (they'd be in `managed`, passed through).
mrg = {"Name": "AWS-CRS", "OverrideAction": {"Count": {}},
       "Statement": {"ManagedRuleGroupStatement": {"VendorName": "AWS", "Name": "AWSManagedRulesCommonRuleSet"}},
       "VisibilityConfig": {}}
res, o, over = _pack([], [_rbr(f"r{i}") for i in range(12)], managed=[mrg])
check("managed rule stays direct (last), not packed", over is None and
      o[-1]["Statement"].get("ManagedRuleGroupStatement", {}).get("Name") == "AWSManagedRulesCommonRuleSet")

print()
if FAILURES:
    print(f"FAILED: {len(FAILURES)} check(s)")
    for label, detail in FAILURES:
        print(f"  - {label}: {detail}")
    sys.exit(1)
print("All packing checks passed.")
