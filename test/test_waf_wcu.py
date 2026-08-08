#!/usr/bin/env python3
"""Regression tests for the WAF WCU calculator (waf-generate-cfn.compute_statement_wcu).

The WCU total is what the rule-group packer uses to stay under AWS's hard 5000-WCU
ceiling per WebACL / rule group, so a wrong number = a deploy that fails at
`create-web-acl` time. These pin the calculator to AWS's authoritative per-statement
WCU model, verified three ways: the AWS Developer Guide worked example (CheckCapacity
returned 15), a per-statement table (dual-subagent + internal-wiki confirmed), and a
mixed ruleset that CheckCapacity returned 727 for on a real account (2026-07-12).

Run: python3 test_waf_wcu.py   (exit 0 = all pass)
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
wcu = _cfn.compute_statement_wcu

FAILURES = []


def check(label, got, expect):
    ok = got == expect
    if not ok:
        FAILURES.append((label, got, expect))
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}: got {got}, expect {expect}")


def _bm(pc, ftm=None, tts=None):
    return {"ByteMatchStatement": {
        "SearchString": "x", "PositionalConstraint": pc,
        "FieldToMatch": ftm or {"UriPath": {}},
        "TextTransformations": tts or [{"Priority": 0, "Type": "NONE"}]}}


print("== WAF WCU calculator ==")

# ── AWS Developer Guide worked example (CheckCapacity == 15) ──
r1 = {"AndStatement": {"Statements": [
    _bm("EXACTLY", {"SingleHeader": {"Name": "host"}}, [{"Priority": 0, "Type": "LOWERCASE"}]),  # 2+10
    {"GeoMatchStatement": {"CountryCodes": ["US", "IN"]}},                                        # 1
]}}
r2 = {"RateBasedStatement": {"Limit": 1000, "AggregateKeyType": "IP"}}                            # 2
check("worked-example rule 1 (AND: bytematch+transform + geo)", wcu(r1), 13)
check("worked-example rule 2 (rate IP)", wcu(r2), 2)
check("worked-example total == AWS CheckCapacity 15", wcu(r1) + wcu(r2), 15)

# ── per-statement table (dual-source + internal wiki confirmed) ──
check("ByteMatch EXACTLY", wcu(_bm("EXACTLY")), 2)
check("ByteMatch STARTS_WITH", wcu(_bm("STARTS_WITH")), 2)
check("ByteMatch ENDS_WITH", wcu(_bm("ENDS_WITH")), 2)
check("ByteMatch CONTAINS", wcu(_bm("CONTAINS")), 10)
check("ByteMatch CONTAINS_WORD", wcu(_bm("CONTAINS_WORD")), 10)
check("RegexMatch", wcu({"RegexMatchStatement": {"RegexString": "a", "FieldToMatch": {"UriPath": {}}, "TextTransformations": [{"Priority": 0, "Type": "NONE"}]}}), 3)
check("RegexPatternSetRef (flat 25)", wcu({"RegexPatternSetReferenceStatement": {"ARN": "x", "FieldToMatch": {"UriPath": {}}, "TextTransformations": [{"Priority": 0, "Type": "NONE"}]}}), 25)
check("SizeConstraint", wcu({"SizeConstraintStatement": {"ComparisonOperator": "GT", "Size": 8, "FieldToMatch": {"UriPath": {}}, "TextTransformations": [{"Priority": 0, "Type": "NONE"}]}}), 1)
check("Geo flat (5 countries != 5 WCU)", wcu({"GeoMatchStatement": {"CountryCodes": ["US", "IN", "CN", "JP", "DE"]}}), 1)
check("Label", wcu({"LabelMatchStatement": {"Scope": "LABEL", "Key": "x"}}), 1)
check("Asn flat (5 asns != 5 WCU)", wcu({"AsnMatchStatement": {"AsnList": [1, 2, 3, 4, 5]}}), 1)
check("IPSet", wcu({"IPSetReferenceStatement": {"ARN": "x"}}), 1)
check("IPSet fwd-IP FIRST (no surcharge)", wcu({"IPSetReferenceStatement": {"ARN": "x", "IPSetForwardedIPConfig": {"Position": "FIRST", "HeaderName": "X-Forwarded-For", "FallbackBehavior": "MATCH"}}}), 1)
check("IPSet fwd-IP ANY (+4)", wcu({"IPSetReferenceStatement": {"ARN": "x", "IPSetForwardedIPConfig": {"Position": "ANY", "HeaderName": "X-Forwarded-For", "FallbackBehavior": "MATCH"}}}), 5)
check("SQLi LOW", wcu({"SqliMatchStatement": {"SensitivityLevel": "LOW", "FieldToMatch": {"Body": {}}, "TextTransformations": [{"Priority": 0, "Type": "NONE"}]}}), 20)
check("SQLi HIGH", wcu({"SqliMatchStatement": {"SensitivityLevel": "HIGH", "FieldToMatch": {"Body": {}}, "TextTransformations": [{"Priority": 0, "Type": "NONE"}]}}), 30)
check("XSS", wcu({"XssMatchStatement": {"FieldToMatch": {"Body": {}}, "TextTransformations": [{"Priority": 0, "Type": "NONE"}]}}), 40)

# ── modifiers ──
check("TextTransform: 1 non-NONE = +10", wcu(_bm("EXACTLY", None, [{"Priority": 0, "Type": "LOWERCASE"}])), 12)
check("TextTransform: 2 non-NONE = +20", wcu(_bm("EXACTLY", None, [{"Priority": 0, "Type": "LOWERCASE"}, {"Priority": 1, "Type": "URL_DECODE"}])), 22)
check("TextTransform: NONE = 0", wcu(_bm("EXACTLY", None, [{"Priority": 0, "Type": "NONE"}])), 2)
check("FieldToMatch AllQueryArguments +10", wcu(_bm("EXACTLY", {"AllQueryArguments": {}})), 12)
check("FieldToMatch JsonBody x2 base", wcu({"SizeConstraintStatement": {"ComparisonOperator": "GT", "Size": 8, "FieldToMatch": {"JsonBody": {}}, "TextTransformations": [{"Priority": 0, "Type": "NONE"}]}}), 2)
check("FieldToMatch Cookies = no surcharge", wcu(_bm("EXACTLY", {"Cookies": {"MatchPattern": {"All": {}}, "MatchScope": "ALL", "OversizeHandling": "NO_MATCH"}})), 2)

# ── rate-based / managed / containers ──
check("RBR CUSTOM_KEYS 2 keys = 2 + 30*2", wcu({"RateBasedStatement": {"AggregateKeyType": "CUSTOM_KEYS", "CustomKeys": [{"IP": {}}, {"Header": {"Name": "x", "TextTransformations": [{"Priority": 0, "Type": "NONE"}]}}]}}), 62)
check("RBR IP + scope-down recurses", wcu({"RateBasedStatement": {"AggregateKeyType": "IP", "ScopeDownStatement": _bm("CONTAINS")}}), 12)
check("ManagedRG CRS = 700", wcu({"ManagedRuleGroupStatement": {"VendorName": "AWS", "Name": "AWSManagedRulesCommonRuleSet"}}), 700)
check("ManagedRG AntiDDoS = 50", wcu({"ManagedRuleGroupStatement": {"VendorName": "AWS", "Name": "AWSManagedRulesAntiDDoSRuleSet"}}), 50)
check("AND container adds 0", wcu({"AndStatement": {"Statements": [_bm("CONTAINS"), {"GeoMatchStatement": {"CountryCodes": ["IR"]}}]}}), 11)
check("OR container adds 0", wcu({"OrStatement": {"Statements": [_bm("EXACTLY"), _bm("EXACTLY")]}}), 4)
check("NOT container adds 0", wcu({"NotStatement": {"Statement": {"GeoMatchStatement": {"CountryCodes": ["IR"]}}}}), 1)

# ── RuleLabels cost (compute_rule_wcu adds ceil(num_labels/5)) ──
# Empirically confirmed live via CheckCapacity (2026-07-12): a base GeoMatch rule
# (statement WCU 1) measured 2 with 1-5 labels, 3 with 6-10, 4 with 11-15. Omitting
# this under-counts a rule group's Capacity → CreateRuleGroup rejects it at deploy.
def _rule_with_labels(n):
    return {"Statement": {"GeoMatchStatement": {"CountryCodes": ["US"]}},
            "RuleLabels": [{"Name": f"lbl{i}"} for i in range(n)]}
check("0 labels: no surcharge (geo=1)", _cfn.compute_rule_wcu(_rule_with_labels(0)), 1)
check("1 label: +1 (matches CheckCapacity 2)", _cfn.compute_rule_wcu(_rule_with_labels(1)), 2)
check("5 labels: +1 (batch boundary)", _cfn.compute_rule_wcu(_rule_with_labels(5)), 2)
check("6 labels: +2 (matches CheckCapacity 3)", _cfn.compute_rule_wcu(_rule_with_labels(6)), 3)
check("10 labels: +2 (matches CheckCapacity 3)", _cfn.compute_rule_wcu(_rule_with_labels(10)), 3)
check("11 labels: +3 (matches CheckCapacity 4)", _cfn.compute_rule_wcu(_rule_with_labels(11)), 4)

# ── the mixed ruleset that real CheckCapacity returned 727 for (2026-07-12) ──
mixed = [
    {"Statement": {"AndStatement": {"Statements": [
        _bm("CONTAINS", {"UriPath": {}}, [{"Priority": 0, "Type": "LOWERCASE"}]),  # 10+10=20
        {"GeoMatchStatement": {"CountryCodes": ["IR", "KP"]}},                      # 1  -> 21
    ]}}},
    {"Statement": {"RateBasedStatement": {"Limit": 2000, "AggregateKeyType": "IP", "EvaluationWindowSec": 300,
        "ScopeDownStatement": _bm("STARTS_WITH")}}},                               # 2+2=4
    {"Statement": {"ManagedRuleGroupStatement": {"VendorName": "AWS", "Name": "AWSManagedRulesCommonRuleSet"}}},  # 700
    {"Statement": {"SizeConstraintStatement": {"ComparisonOperator": "GT", "Size": 8192,
        "FieldToMatch": {"JsonBody": {}}, "TextTransformations": [{"Priority": 0, "Type": "NONE"}]}}},           # 1*2=2
]
check("mixed ruleset total == AWS CheckCapacity 727", sum(_cfn.compute_rule_wcu(r) for r in mixed), 727)

print()
if FAILURES:
    print(f"FAILED: {len(FAILURES)} check(s)")
    for label, got, expect in FAILURES:
        print(f"  - {label}: {got} != {expect}")
    sys.exit(1)
print("All WCU checks passed.")
