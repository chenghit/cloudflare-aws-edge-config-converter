#!/usr/bin/env python3
"""Regression tests for WAF named-list handling — the bugs a real customer config exposed.

Four distinct defects, each of which silently produced a WAF that matched the
WRONG thing (or nothing) at deploy time:

  1. `ip.src in $cf.open_proxies` (a Cloudflare MANAGED list) was treated as a
     missing CUSTOM list → a `MISSING_IP_LIST` ByteMatch that never matches.
     Now: the leaf is non-convertible; the rule is pruned/partial and reported,
     and the protection is covered by the IP Reputation AMR on the WebACL.
  2. `http.host in $namedlist` (hostname list) was emitted as a ByteMatch for the
     literal string "$namedlist" — never matches. Now: an OR of EXACTLY host-header
     matches over the list's hostnames.
  3. IP-access whitelist rules (`ip.src in {1.2.3.4}`) lost their inline IP set
     because the hand-built condition wasn't annotated with `_ip_set_names` →
     `MISSING_INLINE_IP`. Now: annotated, so the generator emits a real ref.
  4. A `partial` rule was emitted from its UNPRUNED `conditions`, leaking the
     non-convertible branch. Now: partial rules use `convertible_conditions`.

Run: python3 test_waf_named_lists.py   (exit 0 = all pass)
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
    sys.modules[name] = mod  # waf-generate-cfn imports waf_expr_parser / waf_common
    spec.loader.exec_module(mod)
    return mod


_wc = _load("waf_common", "waf_common.py")
_cfn = _load("waf_generate_cfn", "waf-generate-cfn.py")

FAILURES = []


def check(label, cond, detail=""):
    if not cond:
        FAILURES.append((label, detail))
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}" + ("" if cond else f"  — {detail}"))


def _find(stmt, key):
    """Collect every dict node that has `key` anywhere in the statement tree."""
    out = []
    def rec(o):
        if isinstance(o, dict):
            if key in o:
                out.append(o[key])
            for v in o.values():
                rec(v)
        elif isinstance(o, list):
            for v in o:
                rec(v)
    rec(stmt)
    return out


def _ctx(**over):
    c = {"refs": _cfn.RefCounter(), "warnings": [], "rule_name": "t",
         "ip_list_map": {}, "asn_lists": {}, "hostname_lists": {},
         "inline_ip_set_ids": {}, "current_rule_ip_sets": []}
    c.update(over)
    return c


print("== WAF named-list handling ==")

# ── 1. Managed list ($cf.*) is non-convertible ──
check("is_managed_list_value: $cf.open_proxies → True",
      _wc.is_managed_list_value("$cf.open_proxies") is True)
check("is_managed_list_value: $block_list_1 (custom) → False",
      _wc.is_managed_list_value("$block_list_1") is False)

# A leaf whose only condition is a managed list: nothing convertible remains
# (pruned tree is None) and the list token is reported. classify_convertibility
# returns "partial" with pruned=None here — the rate analyzer then keeps the rate
# limit and drops the scope-down (an unconditional rate limit), which is correct.
leaf = {"field": "ip.src", "operator": "in", "value": "$cf.open_proxies"}
conv, pruned, removed = _wc.classify_convertibility(leaf)
check("managed-list-only leaf → nothing convertible remains (pruned is None)",
      pruned is None and conv != "yes")
check("managed-list token reported in removed", "$cf.open_proxies" in removed)

# In an AND with a convertible sibling → partial, managed branch dropped.
and_cond = {"op": "and", "items": [
    {"field": "http.request.uri.path", "operator": "contains", "value": "/x"},
    {"field": "ip.src", "operator": "in", "value": "$cf.open_proxies"}]}
conv, pruned, removed = _wc.classify_convertibility(and_cond)
check("managed list in AND → partial", conv == "partial")
check("pruned tree drops the managed-list branch",
      "$cf.open_proxies" not in str(pruned) and "/x" in str(pruned))

# ── 2. Hostname list → OR of EXACTLY host-header matches ──
ctx = _ctx(hostname_lists={"domain_name": ["www.example.com", "api.example.com"]})
stmt = _cfn.conditions_to_statement(
    {"field": "http.host", "operator": "in", "value": "$domain_name"}, ctx)
searchstrings = _find(stmt, "SearchString")
check("hostname list → matches actual hostnames (not the literal $name)",
      set(searchstrings) == {"www.example.com", "api.example.com"},
      f"got {searchstrings}")
bms = _find(stmt, "ByteMatchStatement")
check("hostname matches are EXACTLY on the host header", bms and all(
    b["PositionalConstraint"] == "EXACTLY"
    and b["FieldToMatch"] == {"SingleHeader": {"Name": "host"}} for b in bms))
check("no MISSING_HOSTNAME_LIST when the list resolves",
      "MISSING_HOSTNAME_LIST" not in str(stmt))

# Unknown hostname list → explicit MISSING marker (a warning, not a silent literal).
ctx2 = _ctx()
stmt2 = _cfn.conditions_to_statement(
    {"field": "http.host", "operator": "in", "value": "$nope"}, ctx2)
check("unknown hostname list → MISSING_HOSTNAME_LIST marker + warning",
      "MISSING_HOSTNAME_LIST" in str(stmt2) and any("not found" in w for w in ctx2["warnings"]))

# ── 3. Inline IP-access set resolves via _ip_set_names annotation ──
ctx3 = _ctx(inline_ip_set_ids={"wl-ipv4": "IpsetWlIpv4"})
inline = {"field": "ip.src", "operator": "in", "value": "{192.0.2.8/32}",
          "_ip_set_names": ["wl-ipv4"]}
stmt3 = _cfn.conditions_to_statement(inline, ctx3)
check("annotated inline IP set → real IPSetReferenceStatement (not MISSING_INLINE_IP)",
      _find(stmt3, "IPSetReferenceStatement") and "MISSING_INLINE_IP" not in str(stmt3))

# ── 4. Partial rule emits its PRUNED conditions, not the original ──
partial_rule = {
    "name": "r", "convertibility": "partial",
    "conditions": {"op": "and", "items": [  # original (unpruned) — must NOT be used
        {"field": "ip.src", "operator": "in", "value": "$cf.open_proxies"},
        {"field": "http.request.uri.path", "operator": "contains", "value": "/x"}]},
    "convertible_conditions": {"field": "http.request.uri.path", "operator": "contains", "value": "/x"}}
check("rule_conditions(partial) returns the pruned tree",
      _cfn.rule_conditions(partial_rule) == partial_rule["convertible_conditions"])
yes_rule = {"name": "r", "convertibility": "yes",
            "conditions": {"field": "ip.src", "operator": "in", "value": "{1.2.3.4/32}"}}
check("rule_conditions(yes) returns conditions",
      _cfn.rule_conditions(yes_rule) == yes_rule["conditions"])

# ── 5. Inline-set names are globally unique across rules (no cross-rule collision) ──
# The bug: rule "biz_callback_skip" branch #2 minted "biz_callback_skip_2-ipv4",
# identical to rule "biz_callback_skip_2" branch #0 — same name, different IPs →
# one set's addresses silently dropped, its rule pointed at the other's IPs.
# extract_ip_sets now takes a globally-unique scope_tag per rule.
_parser = _load("waf_expr_parser", "waf_expr_parser.py")
_ex = _parser.extract_ip_sets

def _leaf(ips):
    return {"field": "ip.src", "operator": "in", "value": "{" + " ".join(ips) + "}"}

# rule A ("biz_callback_skip"): 3 branches → its 3rd branch would be "..._2"
condA = {"op": "or", "items": [_leaf(["1.1.1.1"]), _leaf(["2.2.2.2"]), _leaf(["3.3.3.3"])]}
setsA = _ex(condA, "biz-callback-skip", 1, scope_tag="c1")
# rule B ("biz_callback_skip_2"): 1 branch → base name "biz_callback_skip_2"
condB = {"op": "or", "items": [_leaf(["4.4.4.4"])]}
setsB = _ex(condB, "biz-callback-skip-2", 3, scope_tag="c3")

namesA = {s["name"] for s in setsA}
namesB = {s["name"] for s in setsB}
check("cross-rule inline-set names disjoint (no collision)",
      namesA.isdisjoint(namesB), f"A={namesA} B={namesB}")
# and after logical-id sanitization they must STILL be distinct (sanitize strips _/-/.)
lidsA = {_cfn.sanitize_logical_id("IPSet" + n) for n in namesA}
lidsB = {_cfn.sanitize_logical_id("IPSet" + n) for n in namesB}
check("cross-rule logical IDs disjoint after sanitization",
      lidsA.isdisjoint(lidsB), f"A={lidsA} B={lidsB}")

# ── 6. No AWS-invalid statement shapes (same-type-direct-child, or <2-child AND/OR) ──
# AWS WAFv2 rejects an AndStatement whose Statements directly contain another
# AndStatement (and OR-in-OR), and requires >=2 statements per AND/OR — verified
# live via CheckCapacity + the Goku control-plane source (2026-07-12). Two
# generation paths build these containers: conditions_to_statement (guarded by
# _flatten_statements) and _rewrite_stmt (label-key rewrite — the OR-expansion of
# a multi-producer label could land directly inside an OR → OR-in-OR). Fuzz both.
import random as _random

def _aws_invalid(stmt):
    """Return the set of AWS-invalid shapes in a statement tree."""
    bad = set()
    def rec(s):
        if not isinstance(s, dict):
            return
        for k in ("AndStatement", "OrStatement"):
            if k in s:
                sts = s[k]["Statements"]
                if len(sts) < 2:
                    bad.add(f"{k}-<2-children")
                for c in sts:
                    if isinstance(c, dict) and k in c:
                        bad.add(f"{k}-direct-{k}")
                    rec(c)
        if "NotStatement" in s:
            rec(s["NotStatement"]["Statement"])
        for w in ("RateBasedStatement", "ManagedRuleGroupStatement"):
            if w in s and "ScopeDownStatement" in s[w]:
                rec(s[w]["ScopeDownStatement"])
    rec(stmt)
    return bad

_rng = _random.Random(20260712)

# 6a. conditions_to_statement over random Cloudflare expression trees.
_LEAVES = ['http.host eq "a"', 'http.request.uri contains "/x"',
           'ip.src in {1.1.1.1}', 'ip.src.country eq "US"']
def _gen_expr(d):
    if d <= 0 or _rng.random() < 0.4:
        return _rng.choice(_LEAVES)
    r = _rng.random()
    if r < 0.4:
        return "(" + " and ".join(_gen_expr(d - 1) for _ in range(_rng.randint(2, 3))) + ")"
    if r < 0.8:
        return "(" + " or ".join(_gen_expr(d - 1) for _ in range(_rng.randint(2, 3))) + ")"
    return f"not ({_gen_expr(d - 1)})"

_ctx = lambda: {"refs": _cfn.RefCounter(), "warnings": [], "rule_name": "t",
                "ip_list_map": {}, "asn_lists": {}, "hostname_lists": {},
                "inline_ip_set_ids": {}, "current_rule_ip_sets": []}
_bad1 = set()
for _ in range(2000):
    try:
        tree = _parser.parse(_gen_expr(_rng.randint(1, 6)).strip("()") or _LEAVES[0])
        _bad1 |= _aws_invalid(_cfn.conditions_to_statement(tree, _ctx()))
    except Exception:
        pass
check("conditions_to_statement: no same-type-nesting / <2-child (2000 fuzzed trees)",
      not _bad1, str(_bad1))

# 6b. _rewrite_stmt with a multi-producer label (the OR-expansion path).
_producers = {"skip:x": {("webacl", "w"), ("rulegroup", "g"), ("rulegroup", "g2")}}
_LEAFN = [{"IPSetReferenceStatement": {"ARN": "x"}},
          {"GeoMatchStatement": {"CountryCodes": ["US"]}},
          {"LabelMatchStatement": {"Scope": "LABEL", "Key": "skip:x"}}]
def _gen_stmt(d):
    if d <= 0 or _rng.random() < 0.4:
        return _rng.choice(_LEAFN)
    op = _rng.choice(["AndStatement", "OrStatement", "NotStatement"])
    if op == "NotStatement":
        return {"NotStatement": {"Statement": _gen_stmt(d - 1)}}
    return {op: {"Statements": [_gen_stmt(d - 1) for _ in range(_rng.randint(2, 3))]}}
_bad2 = set()
for _ in range(3000):
    _bad2 |= _aws_invalid(_cfn._rewrite_stmt(_gen_stmt(_rng.randint(1, 6)),
                                             _producers, ("webacl", "w")))
check("_rewrite_stmt (multi-producer label): no same-type-nesting / <2-child (3000 fuzzed)",
      not _bad2, str(_bad2))

print()
if FAILURES:
    print(f"FAILED: {len(FAILURES)} check(s)")
    for label, detail in FAILURES:
        print(f"  - {label}: {detail}")
    sys.exit(1)
print("All named-list checks passed.")
