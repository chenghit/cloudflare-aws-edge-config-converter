#!/usr/bin/env python3
"""waf-generate-cfn.py — WAF Stage 3: Generate CloudFormation template.

Reads waf_ir.json and outputs a CloudFormation JSON template containing
IP sets, regex pattern sets, and two WebACL resources.

Usage:
    python3 waf-generate-cfn.py <output_dir> [--split | --force-no-split]

The rule-group overflow packer keeps each WebACL under AWS's hard caps (10
rate-based rules, 50 reference statements) by offloading overflow into referenced
rule groups, so the 50-ref limit no longer forces a per-host split. A config can
still be undeployable if a WebACL's WCU exceeds 5000 or a single rule is too big
to fit one rule group — those are reported as STATUS: BLOCKED (the template is
still written so the user can inspect it, then simplify + re-run).

Exit codes: 0 = OK or BLOCKED (template written either way), 2 = fatal (no
deliverable, e.g. stack exceeds the CloudFormation resource limit).
"""
import copy, json, sys, os, re, math

# ── Constants ────────────────────────────────────────────────────────────────

MAX_WCU = 5000
WARN_WCU = 1500
MAX_REF_STATEMENTS = 50
MAX_RATE_RULES = 10
MAX_IP_SET_SIZE = 10000
MAX_ASN_PER_STATEMENT = 100
MAX_STACK_RESOURCES = 500
MAX_REGEX_LEN = 200
MAX_STRING_MATCH_LEN = 200
STRING_SET_REGEX_THRESHOLD = 3


# ── Helpers ──────────────────────────────────────────────────────────────────

def sanitize_logical_id(name):
    """Convert a name to a valid CloudFormation logical ID (alphanumeric only)."""
    parts = re.split(r'[-_.\s]+', name)
    result = ''.join(p.capitalize() for p in parts if p)
    result = re.sub(r'[^A-Za-z0-9]', '', result)
    if not result or result[0].isdigit():
        result = 'R' + result
    return result[:64]


def sanitize_rule_name(name):
    """Convert to valid AWS WAF rule name: a-zA-Z0-9_- only, max 128 chars."""
    result = re.sub(r'[^a-zA-Z0-9_-]', '_', name)
    # Collapse multiple underscores
    result = re.sub(r'_+', '_', result).strip('_')
    if not result or result[0].isdigit():
        result = 'R' + result
    return result[:128]


def glob_to_regex(pattern, case_insensitive=True):
    """Convert a Cloudflare wildcard pattern to a regex."""
    # Escape regex metacharacters except *
    escaped = ''
    for ch in pattern:
        if ch == '*':
            escaped += '.*'
        elif ch in r'\.+?^${}()|[]':
            escaped += '\\' + ch
        else:
            escaped += ch
    regex = f'^{escaped}$'
    if case_insensitive:
        regex = f'(?i){regex}'
    return regex


def is_ipv6(addr):
    return ':' in addr.split('/')[0]


# ── WCU calculation ───────────────────────────────────────────────────────────
# Authoritative per-statement WCU model (AWS WAF Developer Guide, dual-source +
# internal-wiki confirmed, cross-checked against a real CheckCapacity example =
# 15 WCU). A local per-statement sum is a SAFE UPPER BOUND: AWS may charge once
# for a text transformation shared across rules in the same WebACL/rule group,
# so the real (CheckCapacity) total is ≤ this sum. Over-estimating never fails a
# deploy — which is exactly what we want for packing under the 5000 ceiling.
# Verify the final packed rulesets with `aws wafv2 check-capacity` (see the
# WCU-verification RESULT protocol) for the tightest numbers.

# ByteMatch base cost by PositionalConstraint.
_BYTEMATCH_WCU = {"EXACTLY": 2, "STARTS_WITH": 2, "ENDS_WITH": 2,
                  "CONTAINS": 10, "CONTAINS_WORD": 10}

# Fixed Capacity of AWS managed rule groups we emit. These are version-dependent
# — prefer a live DescribeManagedRuleGroup when an AWS profile is available; this
# table is the zero-credential default. (AWS docs / DescribeManagedRuleGroup.)
MANAGED_RULE_GROUP_WCU = {
    "AWSManagedRulesCommonRuleSet": 700,
    "AWSManagedRulesKnownBadInputsRuleSet": 200,
    "AWSManagedRulesSQLiRuleSet": 200,
    "AWSManagedRulesAmazonIpReputationList": 25,
    "AWSManagedRulesAnonymousIpList": 50,
    "AWSManagedRulesAntiDDoSRuleSet": 50,
    "AWSManagedRulesBotControlRuleSet": 50,
    "AWSManagedRulesATPRuleSet": 50,
    "AWSManagedRulesACFPRuleSet": 50,
    "AWSManagedRulesAdminProtectionRuleSet": 100,
    "AWSManagedRulesPHPRuleSet": 100,
    "AWSManagedRulesWordPressRuleSet": 100,
    "AWSManagedRulesUnixRuleSet": 200,
    "AWSManagedRulesLinuxRuleSet": 200,
    "AWSManagedRulesWindowsRuleSet": 200,
}
DEFAULT_MANAGED_RULE_GROUP_WCU = 200  # conservative fallback for an unknown group


def _text_transform_wcu(field_to_match_owner):
    """10 WCU per non-NONE text transformation entry on a statement (NONE = 0)."""
    tts = field_to_match_owner.get("TextTransformations", [])
    return 10 * sum(1 for t in tts if t.get("Type") != "NONE")


def _field_to_match_wcu(stmt_body):
    """FieldToMatch surcharge: AllQueryArguments +10 (flat), JsonBody ×2 on base.
    Returns (flat_add, base_multiplier). Every other component adds nothing."""
    ftm = stmt_body.get("FieldToMatch", {})
    if "AllQueryArguments" in ftm:
        return 10, 1
    if "JsonBody" in ftm:
        return 0, 2
    return 0, 1


def compute_statement_wcu(stmt, managed_wcu=None):
    """Compute the WCU of one emitted AWS WAF Statement (dict), recursively.

    Walks the generated statement JSON (not the Cloudflare condition), so the
    number reflects exactly what gets deployed and is unit-testable against the
    CheckCapacity API. `managed_wcu` optionally overrides MANAGED_RULE_GROUP_WCU
    (e.g. from a live DescribeManagedRuleGroup lookup)."""
    mwcu = managed_wcu or MANAGED_RULE_GROUP_WCU

    # ── Logical containers: sum children, container itself costs 0 ──
    if "AndStatement" in stmt:
        return sum(compute_statement_wcu(s, managed_wcu) for s in stmt["AndStatement"]["Statements"])
    if "OrStatement" in stmt:
        return sum(compute_statement_wcu(s, managed_wcu) for s in stmt["OrStatement"]["Statements"])
    if "NotStatement" in stmt:
        return compute_statement_wcu(stmt["NotStatement"]["Statement"], managed_wcu)

    # ── Component-inspecting statements (base × JsonBody + AllQueryArgs + transforms) ──
    if "ByteMatchStatement" in stmt:
        b = stmt["ByteMatchStatement"]
        base = _BYTEMATCH_WCU.get(b.get("PositionalConstraint", "EXACTLY"), 10)
        add, mult = _field_to_match_wcu(b)
        return base * mult + add + _text_transform_wcu(b)
    if "RegexMatchStatement" in stmt:
        b = stmt["RegexMatchStatement"]
        add, mult = _field_to_match_wcu(b)
        return 3 * mult + add + _text_transform_wcu(b)
    if "RegexPatternSetReferenceStatement" in stmt:
        b = stmt["RegexPatternSetReferenceStatement"]
        add, mult = _field_to_match_wcu(b)
        return 25 * mult + add + _text_transform_wcu(b)
    if "SizeConstraintStatement" in stmt:
        b = stmt["SizeConstraintStatement"]
        add, mult = _field_to_match_wcu(b)
        return 1 * mult + add + _text_transform_wcu(b)
    if "SqliMatchStatement" in stmt:
        b = stmt["SqliMatchStatement"]
        base = 30 if b.get("SensitivityLevel") == "HIGH" else 20
        add, mult = _field_to_match_wcu(b)
        return base * mult + add + _text_transform_wcu(b)
    if "XssMatchStatement" in stmt:
        b = stmt["XssMatchStatement"]
        add, mult = _field_to_match_wcu(b)
        return 40 * mult + add + _text_transform_wcu(b)

    # ── Flat-cost statements (no FieldToMatch / transforms) ──
    if "GeoMatchStatement" in stmt:
        return 1  # flat, not per country
    if "LabelMatchStatement" in stmt:
        return 1
    if "AsnMatchStatement" in stmt:
        return 1  # flat, not per ASN
    if "IPSetReferenceStatement" in stmt:
        b = stmt["IPSetReferenceStatement"]
        fwd = b.get("IPSetForwardedIPConfig", {})
        return 5 if fwd.get("Position") == "ANY" else 1

    # ── Special statements ──
    if "RateBasedStatement" in stmt:
        b = stmt["RateBasedStatement"]
        wcu = 2
        if b.get("AggregateKeyType") == "CUSTOM_KEYS":
            wcu += 30 * len(b.get("CustomKeys", []))
        if "ScopeDownStatement" in b:
            wcu += compute_statement_wcu(b["ScopeDownStatement"], managed_wcu)
        return wcu
    if "ManagedRuleGroupStatement" in stmt:
        b = stmt["ManagedRuleGroupStatement"]
        wcu = mwcu.get(b.get("Name", ""), DEFAULT_MANAGED_RULE_GROUP_WCU)
        if "ScopeDownStatement" in b:
            wcu += compute_statement_wcu(b["ScopeDownStatement"], managed_wcu)
        return wcu
    if "RuleGroupReferenceStatement" in stmt:
        # A reference to our OWN rule group: the WebACL is charged the group's
        # capacity. Caller supplies it out-of-band (we know it — we built it);
        # a bare reference with no known capacity contributes 0 here and is
        # accounted where the rule group is built.
        return 0

    # Unknown statement type — conservative nonzero so we never under-count.
    return 1


def _label_wcu(n_labels):
    """WCU that defining `n_labels` RuleLabels adds. AWS pools this per WebACL /
    per rule group: 1 WCU for every 5 labels defined across the container's rules
    (docs: waf-rule-label-add.html). Confirmed live via CheckCapacity (2026-07-12):
    a base rule measured +1 with 1-5 labels, +2 with 6-10, +3 with 11-15."""
    return -(-n_labels // 5)  # ceil(n_labels / 5)


def compute_rule_wcu(rule, managed_wcu=None):
    """WCU of a full emitted Rule dict EVALUATED ALONE: its statement + its own
    RuleLabels cost. Matches CheckCapacity on a single rule. NOTE: label cost is
    pooled at the container level, so summing this over a group OVER-counts the
    label part — use compute_rules_wcu() for a group/WebACL total (accurate)."""
    return (compute_statement_wcu(rule.get("Statement", {}), managed_wcu)
            + _label_wcu(len(rule.get("RuleLabels", []))))


def compute_rules_wcu(rules, managed_wcu=None):
    """Accurate WCU of a SET of rules evaluated together in one container (rule
    group or WebACL): sum of each rule's statement WCU PLUS the pooled label cost
    ceil(total_labels / 5). This is what CheckCapacity returns for the container,
    and what a rule group's declared Capacity must be (>= actual, so deploy is
    accepted). Cheaper than summing compute_rule_wcu when labels don't divide
    evenly across rules."""
    stmt = sum(compute_statement_wcu(r.get("Statement", {}), managed_wcu) for r in rules)
    labels = sum(len(r.get("RuleLabels", [])) for r in rules)
    return stmt + _label_wcu(labels)


# ── Rule-group overflow packing ───────────────────────────────────────────────
# AWS WAF WebACL hard caps: 10 rate-based rules and 50 reference statements
# (IP-set / regex-set / rule-group refs) DIRECTLY in a WebACL — both
# non-adjustable. EMPIRICALLY CONFIRMED (live, 2026-07-12): moving overflow rules
# into a referenced custom RuleGroup escapes BOTH caps — RBR-in-group don't count
# against the WebACL's 10, IP-set-refs-in-group don't count against the 50; the
# WebACL only pays 1 reference slot per rule-group reference. A rule group holds
# ≤4 RBR, ≤50 refs, ≤5000 WCU. So a rule group is a general OVERFLOW CONTAINER.
#
# Correctness rules the packer must preserve:
#  1. CLOUDFLARE PHASE ORDER: custom-rule → rate-rule → managed-rule blocks stay
#     contiguous and in that order (Cloudflare evaluates the phases in that order;
#     interleaving would change semantics). We pack WITHIN a single block, and a
#     block's overflow rule-group references are placed right after that block's
#     direct rules — so the whole block (direct rules + its rule groups) still
#     evaluates before the next block. Order within a block is preserved.
#  2. LABELS: nearly every rule touches a label (skip rules PRODUCE
#     skip:{phase}/skip:all_remaining_custom_rules; custom/rate/managed rules
#     CONSUME them via NOT-LabelMatch), so we can't avoid packing label rules.
#     Instead: a label's fully-qualified name bakes in its PRODUCER's container
#     (awswaf:<acct>:webacl:<name>:<label> vs :rulegroup:<name>:<label>), and an
#     unqualified LabelMatchStatement.Key resolves against the CONSUMER's own
#     container. So after packing we REWRITE every LabelMatchStatement.Key to the
#     producer's fully-qualified form via Fn::Sub with ${AWS::AccountId}
#     (confirmed live: CloudFormation substitutes the real account id, template
#     stays portable). Producer-before-consumer evaluation order is preserved
#     because a block's rule groups sit after that block's direct producers.

RULE_GROUP_MAX_RBR = 4          # AWS hard cap: rate-based rules per rule group
RULE_GROUP_MAX_REFS = 50        # AWS hard cap: reference statements per rule group
RULE_GROUP_WCU_BUDGET = 4500    # 5000 ceiling minus safety margin (user decision)


def _rule_is_rbr(rule):
    return "RateBasedStatement" in rule.get("Statement", {})


def _iter_label_match_statements(stmt):
    """Yield every LabelMatchStatement dict in a statement tree (for key rewrite)."""
    if not isinstance(stmt, dict):
        return
    if "LabelMatchStatement" in stmt:
        yield stmt["LabelMatchStatement"]
    if "AndStatement" in stmt:
        for s in stmt["AndStatement"]["Statements"]:
            yield from _iter_label_match_statements(s)
    if "OrStatement" in stmt:
        for s in stmt["OrStatement"]["Statements"]:
            yield from _iter_label_match_statements(s)
    if "NotStatement" in stmt:
        yield from _iter_label_match_statements(stmt["NotStatement"]["Statement"])
    if "RateBasedStatement" in stmt and "ScopeDownStatement" in stmt["RateBasedStatement"]:
        yield from _iter_label_match_statements(stmt["RateBasedStatement"]["ScopeDownStatement"])
    if "ManagedRuleGroupStatement" in stmt and "ScopeDownStatement" in stmt["ManagedRuleGroupStatement"]:
        yield from _iter_label_match_statements(stmt["ManagedRuleGroupStatement"]["ScopeDownStatement"])


def _rule_produced_labels(rule):
    """Custom label names a rule ADDS (RuleLabels). Empty for non-producers."""
    return [l["Name"] for l in rule.get("RuleLabels", [])]


def _count_refs_in_stmt(stmt):
    """Count reference statements toward the WebACL's 50-ref cap. AWS counts, per
    WebACL: IPSetReference + RegexPatternSetReference + your-own-RuleGroupReference
    + AWS-MANAGED-RuleGroup references — ALL four types (EMPIRICALLY CONFIRMED live
    2026-07-12: 45 IP refs + 5 AWS managed rule groups = 50 → accepted; 46 + 5 = 51
    → NUM_REFERENCED_STATEMENT_IN_CONTAINER. So managed groups are NOT free against
    this cap, contrary to earlier belief). A ManagedRuleGroupStatement's own
    scope-down refs count too."""
    if not isinstance(stmt, dict):
        return 0
    if "IPSetReferenceStatement" in stmt or "RegexPatternSetReferenceStatement" in stmt:
        return 1
    if "RuleGroupReferenceStatement" in stmt:
        return 1
    if "AndStatement" in stmt:
        return sum(_count_refs_in_stmt(s) for s in stmt["AndStatement"]["Statements"])
    if "OrStatement" in stmt:
        return sum(_count_refs_in_stmt(s) for s in stmt["OrStatement"]["Statements"])
    if "NotStatement" in stmt:
        return _count_refs_in_stmt(stmt["NotStatement"]["Statement"])
    if "RateBasedStatement" in stmt and "ScopeDownStatement" in stmt["RateBasedStatement"]:
        return _count_refs_in_stmt(stmt["RateBasedStatement"]["ScopeDownStatement"])
    if "ManagedRuleGroupStatement" in stmt:
        n = 1  # the managed group reference itself consumes 1
        if "ScopeDownStatement" in stmt["ManagedRuleGroupStatement"]:
            n += _count_refs_in_stmt(stmt["ManagedRuleGroupStatement"]["ScopeDownStatement"])
        return n
    return 0


def _pack_block(rules, direct_rbr_budget, direct_ref_budget, managed_wcu):
    """Split ONE ordered rule block into (direct, [groups]) so the block's direct
    RBR ≤ direct_rbr_budget and direct refs ≤ direct_ref_budget.

    Peels a contiguous TAIL of the block into rule groups (order preserved: the
    peeled rules keep their relative order and the groups sit after the block's
    direct rules). Each group ≤4 RBR, ≤50 refs, ≤WCU budget. Returns
    (direct_rules, [group_rule_lists], over_reason|None). `over_reason` is set if
    a single rule alone exceeds a group cap (can't be split further).
    """
    def _binpack(overflow):
        """Pack an ordered overflow list into groups (≤4 RBR, ≤50 refs, ≤WCU).
        Returns (groups, over_reason|None)."""
        groups, cur, c_rbr, c_refs, c_wcu = [], [], 0, 0, 0
        for r in overflow:
            r_rbr = 1 if _rule_is_rbr(r) else 0
            r_refs = _count_refs_in_stmt(r.get("Statement", {}))
            r_wcu = compute_rule_wcu(r, managed_wcu)
            if r_rbr > RULE_GROUP_MAX_RBR or r_refs > RULE_GROUP_MAX_REFS or r_wcu > 5000:
                return None, "a single rule exceeds a rule group's own caps"
            if cur and (c_rbr + r_rbr > RULE_GROUP_MAX_RBR
                        or c_refs + r_refs > RULE_GROUP_MAX_REFS
                        or c_wcu + r_wcu > RULE_GROUP_WCU_BUDGET):
                groups.append(cur)
                cur, c_rbr, c_refs, c_wcu = [], 0, 0, 0
            cur.append(r)
            c_rbr += r_rbr; c_refs += r_refs; c_wcu += r_wcu
        if cur:
            groups.append(cur)
        return groups, None

    rbr_total = sum(1 for r in rules if _rule_is_rbr(r))
    ref_total = sum(_count_refs_in_stmt(r.get("Statement", {})) for r in rules)
    if rbr_total <= direct_rbr_budget and ref_total <= direct_ref_budget:
        return rules, [], None

    # Peel a contiguous tail into rule groups. This is chicken-and-egg for refs:
    # each rule group we create ALSO consumes 1 of the block's direct ref budget,
    # so peeling more can create another group and shift the target. Converge by
    # peeling one more rule at a time until the DIRECT side fits BOTH:
    #   direct_rbr ≤ direct_rbr_budget
    #   direct_refs + num_groups ≤ direct_ref_budget   (group refs counted)
    split = len(rules)
    groups = []
    while split > 0:
        rem = rules[:split]
        overflow = rules[split:]
        rem_rbr = sum(1 for r in rem if _rule_is_rbr(r))
        rem_refs = sum(_count_refs_in_stmt(r.get("Statement", {})) for r in rem)
        if overflow:
            groups, over = _binpack(overflow)
            if over:
                return rem, [], over
        else:
            groups = []
        if (rem_rbr <= direct_rbr_budget
                and rem_refs + len(groups) <= direct_ref_budget):
            return rem, groups, None
        split -= 1

    return [], [], "cannot peel enough rules to fit direct caps"


def pack_webacl_rules(webacl_name, custom_block, rate_block, header_rules,
                      trailer_rules, managed_rules, unique_id, resources,
                      managed_wcu=None):
    """Assemble one WebACL's final ordered rule list, packing per-block overflow
    into referenced rule groups, preserving Cloudflare phase order and label
    semantics.

    Blocks (in Cloudflare phase order):
      header_rules   – injected, run first (anti-DDoS, search-engine), never packed
      custom_block   – converted custom rules (http_request_firewall_custom)
      rate_block     – converted rate rules (http_ratelimit)
      trailer_rules  – injected (always-on-challenge), never packed
      managed_rules  – managed rule groups (http_request_firewall_managed), never packed

    Returns (ordered_rules, warnings, over_limit). ordered_rules have final
    Priorities assigned. Rule group resources are added to `resources`; every
    LabelMatchStatement.Key across the whole WebACL is rewritten to its producer's
    fully-qualified form. over_limit is None or a dict {reason, ...}.
    """
    warnings = []

    # The 50-ref budget counts IP-set + regex-set + our-own-rule-group + AWS-MANAGED
    # rule-group references (all four — confirmed live 2026-07-12). RBR consume the
    # separate 10-RBR budget. Injected header/trailer + managed rules are never
    # packed — count what they consume up front (managed groups are NOT free here).
    fixed_refs = sum(_count_refs_in_stmt(r.get("Statement", {}))
                     for r in header_rules + trailer_rules + managed_rules)
    fixed_rbr = sum(1 for r in header_rules + trailer_rules + managed_rules if _rule_is_rbr(r))

    rbr_budget = MAX_RATE_RULES - fixed_rbr       # RBR only ever come from rate rules
    ref_budget = MAX_REF_STATEMENTS - fixed_refs  # shared across custom + rate blocks

    # Pack the custom block first (custom rules aren't RBR, so give it 0 RBR
    # budget — it never needs any — and the full ref budget). _pack_block already
    # accounts for each rule group costing 1 ref, so its result fits ref_budget.
    cd, cg, cover = _pack_block(custom_block, 0, ref_budget, managed_wcu)
    if cover:
        return (_finalize(header_rules, cd, cg, [], [], trailer_rules,
                          managed_rules, webacl_name, unique_id, resources, warnings),
                warnings, {"reason": cover, "webacl": webacl_name})

    # Rate block gets the RBR budget and the ref budget left after the custom
    # block's direct refs + its rule-group refs.
    custom_used_refs = (sum(_count_refs_in_stmt(r.get("Statement", {})) for r in cd)
                        + len(cg))
    rate_ref_budget = ref_budget - custom_used_refs
    rd, rg, rover = _pack_block(rate_block, rbr_budget, rate_ref_budget, managed_wcu)
    if rover:
        return (_finalize(header_rules, cd, cg, rd, rg, trailer_rules, managed_rules,
                          webacl_name, unique_id, resources, warnings),
                warnings, {"reason": rover, "webacl": webacl_name})

    if cg or rg:
        moved = sum(len(g) for g in cg) + sum(len(g) for g in rg)
        warnings.append(
            f"WebACL '{webacl_name}': moved {moved} overflow rule(s) into "
            f"{len(cg) + len(rg)} rule group(s) to fit the 10-RBR / 50-ref direct caps")

    ordered = _finalize(header_rules, cd, cg, rd, rg, trailer_rules, managed_rules,
                        webacl_name, unique_id, resources, warnings)
    return ordered, warnings, None


def _make_rule_group(block_name, gi, group_rules, unique_id, resources, managed_wcu):
    """Create an AWS::WAFv2::RuleGroup resource for a packed group; return
    (logical_id, rule_group_name, reference_rule). Rules are re-prioritized
    from 0 within the group (order preserved)."""
    base = f"{block_name}-overflow-{gi}"
    rg_name = sanitize_rule_name(base)
    lid = unique_id(f"RG{sanitize_logical_id(base)}")
    g_rules = []
    for pi, r in enumerate(group_rules):
        rc = copy.deepcopy(r)
        rc["Priority"] = pi
        g_rules.append(rc)
    capacity = compute_rules_wcu(group_rules, managed_wcu)
    resources[lid] = {"Type": "AWS::WAFv2::RuleGroup", "Properties": {
        "Name": rg_name, "Scope": "CLOUDFRONT", "Capacity": capacity,
        "Rules": g_rules,
        "VisibilityConfig": {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True,
                             "MetricName": rg_name}}}
    ref_rule = {
        "Name": sanitize_rule_name(f"{base}-ref"),
        "OverrideAction": {"None": {}},
        "Statement": {"RuleGroupReferenceStatement": {"ARN": {"Fn::GetAtt": [lid, "Arn"]}}},
        "VisibilityConfig": {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True,
                             "MetricName": sanitize_rule_name(f"{base}ref")}}
    return lid, rg_name, ref_rule


def _label_match_node(label, producers, own):
    """The statement node that matches `label` from a consumer in container
    `own` = (kind, name). AWS label-key rules (dual-subagent + 5 live tests,
    2026-07-12): a BARE key resolves ONLY against the matching rule's own
    container; a cross-container match needs the producer's fully-qualified
    prefix awswaf:<acct>:<rulegroup|webacl>:<name>:<label>; writing your OWN
    container's prefix is REJECTED ("parameter value isn't supported"). A label
    can be produced in SEVERAL containers, so we OR one LabelMatch per producing
    container — bare for `own`, Fn::Sub FQN for each other (portable: CFN fills
    the account id). Matching a not-yet-set label is simply false, so OR-ing all
    producers is always safe."""
    def sort_key(p):
        return (0 if p == own else 1, p[0], p[1])  # own (bare) first, then by container

    nodes = []
    for pkind, pname in sorted(producers, key=sort_key):
        if (pkind, pname) == own:
            key = label  # same container → bare (a self-prefix would be rejected)
        else:
            key = {"Fn::Sub": f"awswaf:${{AWS::AccountId}}:{pkind}:{pname}:{label}"}
        nodes.append({"LabelMatchStatement": {"Scope": "LABEL", "Key": key}})
    return nodes[0] if len(nodes) == 1 else {"OrStatement": {"Statements": nodes}}


def _rewrite_stmt(stmt, producers, own):
    """Return `stmt` with every Scope==LABEL LabelMatchStatement replaced by the
    correct bare/FQN/OR match node for a consumer in container `own`. Pure
    transform: a replacement node is TERMINAL — we never recurse into freshly
    created LabelMatch/OR nodes (which would re-expand a bare key forever)."""
    if not isinstance(stmt, dict):
        return stmt
    if "LabelMatchStatement" in stmt:
        lm = stmt["LabelMatchStatement"]
        key = lm.get("Key")
        if lm.get("Scope") != "LABEL" or not isinstance(key, str):
            return stmt  # NAMESPACE scope or already-rewritten dict key — leave
        prods = producers.get(key)
        if not prods:
            return stmt  # no known producer (external/managed label) — leave bare
        return _label_match_node(key, prods, own)  # terminal
    for cont in ("AndStatement", "OrStatement"):
        if cont in stmt:
            children = [_rewrite_stmt(s, producers, own)
                        for s in stmt[cont]["Statements"]]
            # A rewritten child may itself be a same-type container: a bare
            # LabelMatch with multiple producing containers expands to an OR, and
            # if it sat directly inside an OR that would be OR-in-OR — which AWS
            # REJECTS at deploy (INVALID_NESTED_STATEMENT). Flatten same-type
            # direct children back to siblings (same rule as _flatten_statements).
            children = _flatten_statements(children, cont)
            return {cont: {"Statements": children}}
    if "NotStatement" in stmt:
        return {"NotStatement": {"Statement": _rewrite_stmt(
            stmt["NotStatement"]["Statement"], producers, own)}}
    for wrap in ("RateBasedStatement", "ManagedRuleGroupStatement"):
        if wrap in stmt and "ScopeDownStatement" in stmt[wrap]:
            out = copy.deepcopy(stmt)
            out[wrap]["ScopeDownStatement"] = _rewrite_stmt(
                stmt[wrap]["ScopeDownStatement"], producers, own)
            return out
    return stmt


def _rewrite_label_keys(all_placements, webacl_name):
    """Rewrite every consumer's Scope==LABEL LabelMatchStatement to the correct
    bare/FQN/OR form given where each label is PRODUCED. `all_placements` is a
    list of (rule, container_kind, container_name) with kind 'webacl'/'rulegroup'.
    A label may have producers in multiple containers; each consumer OR-matches
    them all (see _label_match_node). Mutates each rule's Statement in place."""
    producers = {}
    for rule, kind, cname in all_placements:
        for lbl in _rule_produced_labels(rule):
            producers.setdefault(lbl, set()).add((kind, cname))

    for rule, kind, cname in all_placements:
        rule["Statement"] = _rewrite_stmt(rule.get("Statement", {}), producers, (kind, cname))


def _finalize(header_rules, custom_direct, custom_groups, rate_direct, rate_groups,
              trailer_rules, managed_rules, webacl_name, unique_id, resources, warnings):
    """Materialize rule groups, rewrite label keys to fully-qualified producer
    form, assemble the final ordered rule list, and assign sequential priorities.
    Order: header → custom-direct → custom-group-refs → rate-direct →
    rate-group-refs → trailer → managed (Cloudflare phase order preserved)."""
    # Build rule group resources; collect (rule, container_kind, container_name)
    # placements for label rewrite BEFORE priorities are stamped.
    placements = []
    for r in header_rules:
        placements.append((r, "webacl", webacl_name))
    for r in custom_direct:
        placements.append((r, "webacl", webacl_name))

    custom_refs, rate_refs = [], []
    for gi, g in enumerate(custom_groups, 1):
        lid, rg_name, ref = _make_rule_group(f"{webacl_name}-custom", gi, g,
                                             unique_id, resources, None)
        custom_refs.append(ref)
        for r in resources[lid]["Properties"]["Rules"]:
            placements.append((r, "rulegroup", rg_name))
    for r in rate_direct:
        placements.append((r, "webacl", webacl_name))
    for gi, g in enumerate(rate_groups, 1):
        lid, rg_name, ref = _make_rule_group(f"{webacl_name}-rate", gi, g,
                                             unique_id, resources, None)
        rate_refs.append(ref)
        for r in resources[lid]["Properties"]["Rules"]:
            placements.append((r, "rulegroup", rg_name))
    for r in trailer_rules + managed_rules:
        placements.append((r, "webacl", webacl_name))

    # Rewrite label keys in place across every placement (WebACL rules AND rules
    # now living inside rule groups). This may OR-expand a LabelMatch into several
    # (one per producing container), which ADDS WCU — so recompute each rule
    # group's Capacity afterward (Capacity is immutable at create; a stale value
    # lower than actual gets rejected at deploy).
    _rewrite_label_keys(placements, webacl_name)
    for res in resources.values():
        if res["Type"] == "AWS::WAFv2::RuleGroup":
            res["Properties"]["Capacity"] = compute_rules_wcu(
                res["Properties"]["Rules"], None)

    # Assemble final order + assign WebACL-level priorities.
    ordered = (list(header_rules) + list(custom_direct) + custom_refs
               + list(rate_direct) + rate_refs + list(trailer_rules) + list(managed_rules))
    for p, r in enumerate(ordered):
        r["Priority"] = p
    return ordered


def webacl_effective_wcu(resources, managed_wcu=None):
    """Return {webacl_name: effective_wcu} for every WebACL in `resources`. A
    WebACL's effective WCU = the WCU of its direct rules PLUS the Capacity of each
    rule group it references (AWS charges the group's fixed capacity to the
    referencing WebACL). This is the number that must stay ≤ 5000."""
    # logical-id → rule group Capacity, for resolving RuleGroupReferenceStatement.
    rg_capacity = {}
    for lid, res in resources.items():
        if res["Type"] == "AWS::WAFv2::RuleGroup":
            rg_capacity[lid] = res["Properties"]["Capacity"]

    def _group_ref_capacity(rule):
        """If `rule` is a rule-group reference, return the group's charged
        Capacity; else None (a direct rule, priced with the pooled batch)."""
        ref = rule.get("Statement", {}).get("RuleGroupReferenceStatement")
        if not ref:
            return None
        arn = ref.get("ARN", {})
        # our own groups reference via {"Fn::GetAtt": [lid, "Arn"]}
        if isinstance(arn, dict) and "Fn::GetAtt" in arn:
            return rg_capacity.get(arn["Fn::GetAtt"][0], 0)
        return 0

    out = {}
    for res in resources.values():
        if res["Type"] != "AWS::WAFv2::WebACL":
            continue
        name = res["Properties"]["Name"]
        # Referenced rule groups are charged at their fixed Capacity; the WebACL's
        # OWN direct rules are priced together (labels pooled across them).
        direct, total = [], 0
        for r in res["Properties"]["Rules"]:
            cap = _group_ref_capacity(r)
            if cap is None:
                direct.append(r)
            else:
                total += cap
        out[name] = total + compute_rules_wcu(direct, managed_wcu)
    return out


class RefCounter:
    """Count reference statements and track which IP set logical IDs are referenced.
    AWS WAF hard limit: 50 reference statements per WebACL.
    In legacy mode both WebACLs share identical rules, so global count = per-WebACL count."""
    def __init__(self):
        self.count = 0
        self.referenced_ids = set()
        self.referenced_asn_lists = set()

    def add(self, logical_id=None):
        self.count += 1
        if logical_id:
            self.referenced_ids.add(logical_id)

    def add_asn(self, list_name):
        self.referenced_asn_lists.add(list_name)


# ── Condition → Statement conversion ─────────────────────────────────────────

FIELD_TO_MATCH = {
    "http.request.uri.path": {"UriPath": {}},
    "http.request.uri": {"UriPath": {}},
    "http.request.uri.query": {"QueryString": {}},
    "http.host": {"SingleHeader": {"Name": "host"}},
    "http.user_agent": {"SingleHeader": {"Name": "user-agent"}},
    "http.referer": {"SingleHeader": {"Name": "referer"}},
    "http.request.method": {"Method": {}},
    "http.cookie": {"Cookies": {"MatchPattern": {"All": {}}, "MatchScope": "ALL", "OversizeHandling": "NO_MATCH"}},
    "http.request.full_uri": {"UriPath": {}},
    "http.request.body": {"Body": {"OversizeHandling": "NO_MATCH"}},
}

POSITIONAL_CONSTRAINT = {
    "eq": "EXACTLY",
    "contains": "CONTAINS",
    "starts_with": "STARTS_WITH",
    "ends_with": "ENDS_WITH",
}


def _flatten_statements(stmts, key):
    """Flatten same-type compound statements. E.g., OR containing OR → siblings.
    AWS WAF does not allow AND-in-AND or OR-in-OR."""
    flat = []
    for s in stmts:
        if key in s:
            # Same type nested — lift children up
            flat.extend(s[key].get("Statements", []))
        else:
            flat.append(s)
    return flat


def rule_conditions(rule):
    """The condition tree to actually emit for a rule.

    For a `partial` rule, `conditions` still holds the ORIGINAL (unpruned) tree
    and `convertible_conditions` holds the pruned one — so we MUST use the pruned
    tree, or non-convertible branches (e.g. `ip.src in $cf.open_proxies`, a
    managed list) leak into the generated WAF. For `yes` rules there is no
    pruned tree, so use `conditions`. (`no` rules are filtered out before here.)
    A rate rule whose whole condition pruned away → None → unconditional rate
    limit, which is the correct outcome."""
    if rule.get("convertibility") == "partial":
        return rule.get("convertible_conditions")
    return rule.get("conditions")


def conditions_to_statement(cond, ctx):
    """Recursively convert conditions tree to AWS WAF Statement JSON."""
    if "op" in cond:
        op = cond["op"]
        if op == "and":
            stmts = [conditions_to_statement(c, ctx) for c in cond["items"]]
            stmts = _flatten_statements(stmts, "AndStatement")
            return stmts[0] if len(stmts) == 1 else {"AndStatement": {"Statements": stmts}}
        if op == "or":
            stmts = [conditions_to_statement(c, ctx) for c in cond["items"]]
            stmts = _flatten_statements(stmts, "OrStatement")
            return stmts[0] if len(stmts) == 1 else {"OrStatement": {"Statements": stmts}}
        if op == "not":
            inner = conditions_to_statement(cond["item"], ctx)
            # Flatten NOT(NOT(X)) → X
            if "NotStatement" in inner:
                return inner["NotStatement"]["Statement"]
            return {"NotStatement": {"Statement": inner}}

    # Leaf condition
    field = cond.get("field", "")
    operator = cond.get("operator", "")
    value = cond.get("value")
    transform = cond.get("transform")

    text_transforms = [{"Priority": 0, "Type": "LOWERCASE" if transform == "lowercase" else "NONE"}]

    # IP set reference
    if field == "ip.src" and operator in ("in", "not_in"):
        return _build_ip_statement(value, ctx, cond)

    # Named hostname list: `http.host in $name` → OR of exact host-header matches
    # (same semantics as an inline `http.host in {"a" "b"}`). Custom lists only;
    # `$cf.*` managed lists were already pruned as non-convertible upstream.
    if field == "http.host" and operator in ("in", "not_in") \
            and isinstance(value, str) and value.startswith("$"):
        hostnames = ctx.get("hostname_lists", {}).get(value[1:])
        if hostnames is not None:
            if not hostnames:
                ctx["warnings"].append(f"Hostname list '{value}' is empty — rule matches nothing")
                return {"ByteMatchStatement": {
                    "SearchString": "MISSING_HOSTNAME_LIST", "PositionalConstraint": "EXACTLY",
                    "FieldToMatch": {"SingleHeader": {"Name": "host"}},
                    "TextTransformations": [{"Priority": 0, "Type": "NONE"}]}}
            stmt = _build_string_set_statement("http.host", hostnames,
                                               [{"Priority": 0, "Type": "NONE"}], ctx)
            if operator == "not_in":
                return {"NotStatement": {"Statement": stmt}}
            return stmt
        ctx["warnings"].append(f"Hostname list '{value}' not found in ip_lists")
        return {"ByteMatchStatement": {
            "SearchString": "MISSING_HOSTNAME_LIST", "PositionalConstraint": "EXACTLY",
            "FieldToMatch": {"SingleHeader": {"Name": "host"}},
            "TextTransformations": [{"Priority": 0, "Type": "NONE"}]}}

    # Country match
    if field == "ip.src.country":
        if operator == "in" and isinstance(value, str) and value.startswith("{"):
            codes = [c.strip().strip('"').upper() for c in value[1:-1].split()]
        elif operator == "eq":
            codes = [str(value).upper()]
        elif operator == "ne":
            return {"NotStatement": {"Statement": {
                "GeoMatchStatement": {"CountryCodes": [str(value).upper()]}}}}
        else:
            codes = [str(value).upper()]
        return {"GeoMatchStatement": {"CountryCodes": codes}}

    # ASN match
    if field in ("ip.geoip.asnum", "ip.src.asnum") and operator == "in":
        return _build_asn_statement(value, ctx)

    # Bare boolean field
    if operator == "eq" and value is True:
        # Non-convertible bare boolean — should have been caught by convertibility check
        ctx["warnings"].append(f"Bare boolean field '{field}' in statement — may not convert correctly")
        return {"ByteMatchStatement": {
            "SearchString": "1", "PositionalConstraint": "EXACTLY",
            "FieldToMatch": {"SingleHeader": {"Name": field.replace(".", "-")}},
            "TextTransformations": [{"Priority": 0, "Type": "NONE"}]}}

    # Wildcard → regex
    if operator in ("wildcard", "strict_wildcard"):
        regex = glob_to_regex(str(value), case_insensitive=(operator == "wildcard"))
        if len(regex) > MAX_REGEX_LEN:
            ctx["warnings"].append(f"Regex pattern exceeds {MAX_REGEX_LEN} chars for field '{field}'")
        ftm = FIELD_TO_MATCH.get(field, {"UriPath": {}})
        return {"RegexMatchStatement": {
            "RegexString": regex,
            "FieldToMatch": ftm,
            "TextTransformations": [{"Priority": 0, "Type": "NONE"}]}}

    # Regex match
    if operator == "matches":
        ftm = FIELD_TO_MATCH.get(field, {"UriPath": {}})
        return {"RegexMatchStatement": {
            "RegexString": str(value),
            "FieldToMatch": ftm,
            "TextTransformations": text_transforms}}

    # String set → OR of ByteMatch or regex optimization
    if operator == "in" and isinstance(value, str) and value.startswith("{"):
        inner = value[1:-1]
        # Extract quoted strings, or fall back to whitespace split
        items = re.findall(r'"([^"]*)"', inner)
        if not items:
            items = [v.strip() for v in inner.split() if v.strip()]
        return _build_string_set_statement(field, items, text_transforms, ctx)

    # Size constraint
    if operator in ("gt", "lt", "ge", "le") and cond.get("size_check"):
        comp_map = {"gt": "GT", "lt": "LT", "ge": "GE", "le": "LE"}
        ftm = FIELD_TO_MATCH.get(field, {"UriPath": {}})
        return {"SizeConstraintStatement": {
            "ComparisonOperator": comp_map[operator],
            "Size": int(value),
            "FieldToMatch": ftm,
            "TextTransformations": [{"Priority": 0, "Type": "NONE"}]}}

    # Standard byte match
    if operator in POSITIONAL_CONSTRAINT:
        pc = POSITIONAL_CONSTRAINT[operator]
        search = str(value)
        if len(search) > MAX_STRING_MATCH_LEN:
            ctx["warnings"].append(f"String match exceeds {MAX_STRING_MATCH_LEN} chars for '{field}'")
        ftm = FIELD_TO_MATCH.get(field, {"SingleHeader": {"Name": field.split(".")[-1]}})
        return {"ByteMatchStatement": {
            "SearchString": search,
            "PositionalConstraint": pc,
            "FieldToMatch": ftm,
            "TextTransformations": text_transforms}}

    # ne → NOT + EXACTLY
    if operator == "ne":
        ftm = FIELD_TO_MATCH.get(field, {"SingleHeader": {"Name": field.split(".")[-1]}})
        return {"NotStatement": {"Statement": {"ByteMatchStatement": {
            "SearchString": str(value),
            "PositionalConstraint": "EXACTLY",
            "FieldToMatch": ftm,
            "TextTransformations": text_transforms}}}}

    # Fallback — unknown field/operator
    ctx["warnings"].append(f"Unknown field/operator: {field} {operator} — generating placeholder")
    return {"ByteMatchStatement": {
        "SearchString": str(value) if value else "PLACEHOLDER",
        "PositionalConstraint": "CONTAINS",
        "FieldToMatch": {"UriPath": {}},
        "TextTransformations": [{"Priority": 0, "Type": "NONE"}]}}


def _build_ip_statement(value, ctx, cond=None):
    """Build IPSetReferenceStatement(s) for ip.src in ... conditions."""
    value_str = str(value)

    # Named list: $list_name
    if value_str.startswith("$"):
        list_name = value_str[1:]
        ipv4_id = ctx["ip_list_map"].get(f"{list_name}-ipv4")
        ipv6_id = ctx["ip_list_map"].get(f"{list_name}-ipv6")
        if ipv4_id and ipv6_id:
            ctx["refs"].add(ipv4_id)
            ctx["refs"].add(ipv6_id)
            return {"OrStatement": {"Statements": [
                {"IPSetReferenceStatement": {"ARN": {"Fn::GetAtt": [ipv4_id, "Arn"]}}},
                {"IPSetReferenceStatement": {"ARN": {"Fn::GetAtt": [ipv6_id, "Arn"]}}},
            ]}}
        elif ipv4_id:
            ctx["refs"].add(ipv4_id)
            return {"IPSetReferenceStatement": {"ARN": {"Fn::GetAtt": [ipv4_id, "Arn"]}}}
        elif ipv6_id:
            ctx["refs"].add(ipv6_id)
            return {"IPSetReferenceStatement": {"ARN": {"Fn::GetAtt": [ipv6_id, "Arn"]}}}
        # ASN list referenced as $name
        asn_id = ctx["ip_list_map"].get(list_name)
        if asn_id == "__asn__":
            ctx["refs"].add_asn(list_name)
            asns = ctx["asn_lists"].get(list_name, [])
            return _build_asn_from_list(asns, ctx)
        ctx["warnings"].append(f"IP list '${list_name}' not found in ip_lists")
        return {"ByteMatchStatement": {"SearchString": "MISSING_IP_LIST", "PositionalConstraint": "EXACTLY",
                "FieldToMatch": {"UriPath": {}}, "TextTransformations": [{"Priority": 0, "Type": "NONE"}]}}

    # Inline IP set: {addr1 addr2 ...}
    # Use _ip_set_names annotation from extract_ip_sets for precise matching
    ip_set_names = cond.get("_ip_set_names", [])
    stmts = []
    for name in ip_set_names:
        lid = ctx["inline_ip_set_ids"].get(name)
        if lid:
            ctx["refs"].add(lid)
            stmts.append({"IPSetReferenceStatement": {"ARN": {"Fn::GetAtt": [lid, "Arn"]}}})

    if not stmts:
        ctx["warnings"].append(f"No IP sets found for inline set in rule '{ctx['rule_name']}'")
        return {"ByteMatchStatement": {"SearchString": "MISSING_INLINE_IP", "PositionalConstraint": "EXACTLY",
                "FieldToMatch": {"UriPath": {}}, "TextTransformations": [{"Priority": 0, "Type": "NONE"}]}}
    if len(stmts) == 1:
        return stmts[0]
    return {"OrStatement": {"Statements": stmts}}


def _build_asn_statement(value, ctx):
    """Build AsnMatchStatement, splitting if >100 ASNs."""
    value_str = str(value)
    if value_str.startswith("$"):
        list_name = value_str[1:]
        ctx["refs"].add_asn(list_name)
        asns = ctx["asn_lists"].get(list_name, [])
    elif value_str.startswith("{"):
        asns = [int(x) for x in value_str[1:-1].split() if x.strip()]
    else:
        asns = [int(value_str)] if value_str.isdigit() else []
    return _build_asn_from_list(asns, ctx)


def _build_asn_from_list(asns, ctx):
    if not asns:
        ctx["warnings"].append("Empty ASN list")
        return {"AsnMatchStatement": {"AsnList": [0]}}
    chunks = [asns[i:i+MAX_ASN_PER_STATEMENT] for i in range(0, len(asns), MAX_ASN_PER_STATEMENT)]
    stmts = [{"AsnMatchStatement": {"AsnList": chunk}} for chunk in chunks]
    return stmts[0] if len(stmts) == 1 else {"OrStatement": {"Statements": stmts}}


def _build_string_set_statement(field, items, text_transforms, ctx):
    """Build statement for string set (in operator with string values)."""
    ftm = FIELD_TO_MATCH.get(field, {"SingleHeader": {"Name": field.split(".")[-1]}})

    if len(items) <= STRING_SET_REGEX_THRESHOLD:
        stmts = [{"ByteMatchStatement": {
            "SearchString": item, "PositionalConstraint": "EXACTLY",
            "FieldToMatch": ftm, "TextTransformations": text_transforms}} for item in items]
        return stmts[0] if len(stmts) == 1 else {"OrStatement": {"Statements": stmts}}

    # Optimize: combine into regex
    escaped = [re.escape(item) for item in items]
    regex = "^(" + "|".join(escaped) + ")$"
    if len(regex) <= MAX_REGEX_LEN:
        return {"RegexMatchStatement": {"RegexString": regex, "FieldToMatch": ftm,
                "TextTransformations": text_transforms}}

    # Split into multiple regex
    stmts = []
    batch = []
    current_len = 4  # ^()$
    for e in escaped:
        if current_len + len(e) + 1 > MAX_REGEX_LEN - 4:
            r = "^(" + "|".join(batch) + ")$"
            stmts.append({"RegexMatchStatement": {"RegexString": r, "FieldToMatch": ftm,
                          "TextTransformations": text_transforms}})
            batch = [e]
            current_len = 4 + len(e)
        else:
            batch.append(e)
            current_len += len(e) + 1
    if batch:
        r = "^(" + "|".join(batch) + ")$"
        stmts.append({"RegexMatchStatement": {"RegexString": r, "FieldToMatch": ftm,
                      "TextTransformations": text_transforms}})
    return stmts[0] if len(stmts) == 1 else {"OrStatement": {"Statements": stmts}}


# ── Template assembly ────────────────────────────────────────────────────────

ACTION_MAP = {
    "block": {"Block": {}},
    "allow": {"Allow": {}},
    "whitelist": {"Allow": {}},
    "challenge": {"Challenge": {}},
    "js_challenge": {"Challenge": {}},
    "managed_challenge": {"Challenge": {}},
    "interactive_challenge": {"Captcha": {}},
    "captcha": {"Captcha": {}},
    "count": {"Count": {}},
}


def build_managed_rules(priority_start, skip_labels_present):
    """Build the managed rule group rules (WCU is computed later from the
    assembled template by webacl_effective_wcu, not tracked here)."""
    rules = []
    p = priority_start

    # Anti-DDoS (placeholder — actual config differs per WebACL, handled in build_webacl)
    # IP Reputation
    ip_rep = {
        "Name": "AWS-AWSManagedRulesAmazonIpReputationList", "Priority": p,
        "OverrideAction": {"Count": {}},
        "Statement": {"ManagedRuleGroupStatement": {"VendorName": "AWS",
                       "Name": "AWSManagedRulesAmazonIpReputationList"}},
        "VisibilityConfig": {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True,
                             "MetricName": "AWS-AWSManagedRulesAmazonIpReputationList"},
    }
    if skip_labels_present.get("http_request_firewall_managed"):
        ip_rep["Statement"]["ManagedRuleGroupStatement"]["ScopeDownStatement"] = {
            "NotStatement": {"Statement": {"LabelMatchStatement": {
                "Scope": "LABEL", "Key": "skip:http_request_firewall_managed"}}}}
    rules.append(ip_rep)
    p += 1

    # Common Rule Set
    crs = {
        "Name": "AWS-AWSManagedRulesCommonRuleSet", "Priority": p,
        "OverrideAction": {"Count": {}},
        "Statement": {"ManagedRuleGroupStatement": {"VendorName": "AWS",
                       "Name": "AWSManagedRulesCommonRuleSet",
                       "RuleActionOverrides": [{"Name": "SizeRestrictions_BODY",
                                                "ActionToUse": {"Count": {}}}]}},
        "VisibilityConfig": {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True,
                             "MetricName": "AWS-AWSManagedRulesCommonRuleSet"},
    }
    if skip_labels_present.get("http_request_firewall_managed"):
        crs["Statement"]["ManagedRuleGroupStatement"]["ScopeDownStatement"] = {
            "NotStatement": {"Statement": {"LabelMatchStatement": {
                "Scope": "LABEL", "Key": "skip:http_request_firewall_managed"}}}}
    rules.append(crs)
    p += 1

    # Known Bad Inputs
    kbi = {
        "Name": "AWS-AWSManagedRulesKnownBadInputsRuleSet", "Priority": p,
        "OverrideAction": {"Count": {}},
        "Statement": {"ManagedRuleGroupStatement": {"VendorName": "AWS",
                       "Name": "AWSManagedRulesKnownBadInputsRuleSet"}},
        "VisibilityConfig": {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True,
                             "MetricName": "AWS-AWSManagedRulesKnownBadInputsRuleSet"},
    }
    if skip_labels_present.get("http_request_firewall_managed"):
        kbi["Statement"]["ManagedRuleGroupStatement"]["ScopeDownStatement"] = {
            "NotStatement": {"Statement": {"LabelMatchStatement": {
                "Scope": "LABEL", "Key": "skip:http_request_firewall_managed"}}}}
    rules.append(kbi)
    p += 1

    # SQLi
    sqli = {
        "Name": "AWS-AWSManagedRulesSQLiRuleSet", "Priority": p,
        "OverrideAction": {"Count": {}},
        "Statement": {"ManagedRuleGroupStatement": {"VendorName": "AWS",
                       "Name": "AWSManagedRulesSQLiRuleSet", "Version": "Version_2.0"}},
        "VisibilityConfig": {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True,
                             "MetricName": "AWS-AWSManagedRulesSQLiRuleSet"},
    }
    if skip_labels_present.get("http_request_firewall_managed"):
        sqli["Statement"]["ManagedRuleGroupStatement"]["ScopeDownStatement"] = {
            "NotStatement": {"Statement": {"LabelMatchStatement": {
                "Scope": "LABEL", "Key": "skip:http_request_firewall_managed"}}}}
    rules.append(sqli)
    p += 1

    return rules, p


def build_anti_ddos_rule(priority, advanced=False, scope_down_exclude_labels=None):
    """Build Anti-DDoS managed rule."""
    rule = {
        "Name": "AWS-AWSManagedRulesAntiDDoSRuleSet", "Priority": priority,
        "OverrideAction": {"Count": {}},
        "Statement": {"ManagedRuleGroupStatement": {"VendorName": "AWS",
                       "Name": "AWSManagedRulesAntiDDoSRuleSet"}},
        "VisibilityConfig": {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True,
                             "MetricName": "AWS-AWSManagedRulesAntiDDoSRuleSet"},
    }
    mrg = rule["Statement"]["ManagedRuleGroupStatement"]
    if advanced:
        mrg["ManagedRuleGroupConfigs"] = [{
            "AWSManagedRulesAntiDDoSRuleSet": {
                "ClientSideActionConfig": {"Challenge": {"UsageOfAction": "DISABLED"}},
                "SensitivityToBlock": "MEDIUM"}}]
    else:
        mrg["ManagedRuleGroupConfigs"] = [{
            "AWSManagedRulesAntiDDoSRuleSet": {
                "ClientSideActionConfig": {"Challenge": {
                    "UsageOfAction": "ENABLED", "Sensitivity": "HIGH",
                    "ExemptUriRegularExpressions": [
                        {"RegexString": "\\/api\\/|\\.(acc|avi|css|gif|jpe?g|js|mp[34]|ogg|otf|pdf|png|tiff?|ttf|webm|webp|woff2?)$"}
                    ]}},
                "SensitivityToBlock": "LOW"}}]
    if scope_down_exclude_labels:
        if len(scope_down_exclude_labels) == 1:
            mrg["ScopeDownStatement"] = {"NotStatement": {"Statement": {
                "LabelMatchStatement": {"Scope": "LABEL", "Key": scope_down_exclude_labels[0]}}}}
        else:
            mrg["ScopeDownStatement"] = {"AndStatement": {"Statements": [
                {"NotStatement": {"Statement": {"LabelMatchStatement": {
                    "Scope": "LABEL", "Key": lbl}}}} for lbl in scope_down_exclude_labels]}}
    return rule


def build_search_engine_label_rule(priority):
    """Build search engine labeling rule (Count + label)."""
    bots = [
        ("Googlebot", [15169]),
        ("bingbot", [8075]),
        ("YandexBot", [13238]),
    ]
    stmts = []
    for ua, asns in bots:
        stmts.append({"AndStatement": {"Statements": [
            {"ByteMatchStatement": {
                "SearchString": ua, "PositionalConstraint": "CONTAINS",
                "FieldToMatch": {"SingleHeader": {"Name": "user-agent"}},
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}]}},
            {"AsnMatchStatement": {"AsnList": asns}},
        ]}})
    return {
        "Name": "search-engine-label", "Priority": priority,
        "Action": {"Count": {}},
        "Statement": {"OrStatement": {"Statements": stmts}},
        "RuleLabels": [{"Name": "custom:search-engine"}],
        "VisibilityConfig": {"SampledRequestsEnabled": True,
                             "CloudWatchMetricsEnabled": True,
                             "MetricName": "search-engine-label"},
    }


def build_always_on_challenge_rule(priority):
    """Build always-on challenge rule (Count action — user changes to Challenge after review).
    Excludes requests labeled custom:search-engine to avoid impacting SEO."""
    uris = ["/", "/login", "/signup"]
    uri_stmts = [{"ByteMatchStatement": {
        "SearchString": uri, "PositionalConstraint": "EXACTLY",
        "FieldToMatch": {"UriPath": {}},
        "TextTransformations": [{"Priority": 0, "Type": "NONE"}]}} for uri in uris]
    uri_match = {"OrStatement": {"Statements": uri_stmts}}
    not_search_engine = {"NotStatement": {"Statement": {
        "LabelMatchStatement": {"Scope": "LABEL", "Key": "custom:search-engine"}}}}
    return {
        "Name": "always-on-challenge", "Priority": priority,
        "Action": {"Count": {}},
        "Statement": {"AndStatement": {"Statements": [uri_match, not_search_engine]}},
        "VisibilityConfig": {"SampledRequestsEnabled": True,
                             "CloudWatchMetricsEnabled": True,
                             "MetricName": "always-on-challenge"},
    }


def sanitize_webacl_name(hostname):
    """Convert hostname to valid AWS WAF Name: dots → underscores."""
    return hostname.replace('.', '_')


# ── Main generation logic ────────────────────────────────────────────────────

def generate(ir):
    """Generate CloudFormation template from IR JSON."""
    resources = {}
    warnings = []
    refs = RefCounter()

    # ── Build IP set resources ───────────────────────────────────────────────

    ip_list_map = {}   # list_name → logical_id (for named lists)
    asn_lists = {}     # list_name → [asn_numbers] (for ASN lists)
    hostname_lists = {}  # list_name → [hostnames] (for hostname lists)
    inline_ip_set_ids = {}  # ip_set_name → logical_id
    used_ids = set()

    def unique_id(base):
        lid = sanitize_logical_id(base)
        if lid in used_ids:
            i = 2
            while f"{lid}{i}" in used_ids:
                i += 1
            lid = f"{lid}{i}"
        used_ids.add(lid)
        return lid

    # Named IP lists
    for lst in ir.get("ip_lists", []):
        name = lst.get("name", "")
        conv = lst.get("conversion", "")
        if conv == "hostname_set":
            hostname_lists[name] = lst.get("items", [])
        if conv == "ip_set":
            v4 = lst.get("items_ipv4", [])
            v6 = lst.get("items_ipv6", [])
            if v4:
                lid = unique_id(f"IPSet{name}Ipv4")
                resources[lid] = {"Type": "AWS::WAFv2::IPSet", "Properties": {
                    "Name": f"{name}-ipv4", "Scope": "CLOUDFRONT",
                    "IPAddressVersion": "IPV4", "Addresses": v4}}
                ip_list_map[f"{name}-ipv4"] = lid
            if v6:
                lid = unique_id(f"IPSet{name}Ipv6")
                resources[lid] = {"Type": "AWS::WAFv2::IPSet", "Properties": {
                    "Name": f"{name}-ipv6", "Scope": "CLOUDFRONT",
                    "IPAddressVersion": "IPV6", "Addresses": v6}}
                ip_list_map[f"{name}-ipv6"] = lid
            if not v4 and not v6:
                ip_list_map[f"{name}-ipv4"] = None
                ip_list_map[f"{name}-ipv6"] = None
        elif conv == "asn_inline":
            asn_lists[name] = lst.get("items", [])
            ip_list_map[name] = "__asn__"

    # Inline IP sets from rules
    for section_key in ("ip_access_rules", "custom_rules", "rate_limiting_rules"):
        section = ir.get(section_key, {})
        for rule in section.get("rules", []):
            for ipset in rule.get("ip_sets", []):
                ipset_name = ipset["name"]
                addrs = ipset.get("addresses", [])
                if not addrs:
                    continue
                is_v6 = any(is_ipv6(a) for a in addrs)
                lid = unique_id(f"IPSet{ipset_name}")
                resources[lid] = {"Type": "AWS::WAFv2::IPSet", "Properties": {
                    "Name": ipset_name, "Scope": "CLOUDFRONT",
                    "IPAddressVersion": "IPV6" if is_v6 else "IPV4",
                    "Addresses": addrs}}
                inline_ip_set_ids[ipset_name] = lid
                if len(addrs) > MAX_IP_SET_SIZE:
                    warnings.append(f"IP set '{ipset_name}' has {len(addrs)} addresses (max {MAX_IP_SET_SIZE})")

    # ── Build rules ──────────────────────────────────────────────────────────

    # Rules are built into two ordered blocks matching Cloudflare's phase order:
    #   custom_block = IP-access + custom rules (http_request_firewall_custom phase)
    #   rate_block   = rate-limiting rules       (http_ratelimit phase)
    # managed rules are the http_request_firewall_managed phase (built separately).
    # The packer keeps these blocks contiguous/ordered and offloads per-block
    # overflow into rule groups. Priorities are assigned by the packer, so the
    # rules here carry no meaningful Priority yet.
    custom_block = []
    rate_block = []
    used_rule_names = set()

    def unique_rule_name(raw_name):
        """Sanitize and deduplicate rule names for AWS WAF."""
        name = sanitize_rule_name(raw_name)
        if name not in used_rule_names:
            used_rule_names.add(name)
            return name
        i = 2
        while f"{name}-{i}" in used_rule_names:
            i += 1
        deduped = f"{name}-{i}"[:128]
        used_rule_names.add(deduped)
        return deduped

    # IP Access Rules (part of the custom phase, evaluated first)
    for rule in ir.get("ip_access_rules", {}).get("rules", []):
        if rule.get("convertibility") == "no":
            continue
        cond = rule.get("conditions")
        if not cond:
            continue
        ctx = {"refs": refs, "warnings": warnings,
               "rule_name": rule["name"], "ip_list_map": ip_list_map,
               "asn_lists": asn_lists, "hostname_lists": hostname_lists,
               "inline_ip_set_ids": inline_ip_set_ids,
               "current_rule_ip_sets": rule.get("ip_sets", [])}
        stmt = conditions_to_statement(cond, ctx)
        aws_action = ACTION_MAP.get(rule.get("mode", "block"), {"Block": {}})
        rn = unique_rule_name(rule["name"])
        custom_block.append({
            "Name": rn, "Action": aws_action, "Statement": stmt,
            "VisibilityConfig": {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True,
                                 "MetricName": rn},
        })

    # Custom Rules
    skip_labels_present = ir.get("custom_rules", {}).get("skip_labels_present", {})
    for rule in ir.get("custom_rules", {}).get("rules", []):
        if rule.get("convertibility") == "no":
            continue
        cond = rule_conditions(rule)
        if not cond:
            continue
        ctx = {"refs": refs, "warnings": warnings,
               "rule_name": rule["name"], "ip_list_map": ip_list_map,
               "asn_lists": asn_lists, "hostname_lists": hostname_lists,
               "inline_ip_set_ids": inline_ip_set_ids,
               "current_rule_ip_sets": rule.get("ip_sets", [])}
        stmt = conditions_to_statement(cond, ctx)

        # Scope-down: wrap in AND with NOT label_match
        if rule.get("scope_down", {}).get("skip_all_remaining_custom_rules"):
            not_label = {"NotStatement": {"Statement": {"LabelMatchStatement": {
                "Scope": "LABEL", "Key": "skip:all_remaining_custom_rules"}}}}
            # Flatten: if stmt is already AndStatement, add as sibling instead of nesting
            if "AndStatement" in stmt:
                stmt["AndStatement"]["Statements"].insert(0, not_label)
            else:
                stmt = {"AndStatement": {"Statements": [not_label, stmt]}}

        # Determine action
        action = rule.get("action", "block")
        if action == "skip":
            aws_action = {"Count": {}}
        else:
            aws_act = rule.get("aws_action", action)
            aws_action = ACTION_MAP.get(aws_act, {"Block": {}})

        rn = unique_rule_name(rule["name"])
        waf_rule = {
            "Name": rn, "Action": aws_action, "Statement": stmt,
            "VisibilityConfig": {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True,
                                 "MetricName": rn},
        }

        # Skip rule labels
        if action == "skip" and rule.get("labels"):
            waf_rule["RuleLabels"] = [{"Name": l} for l in rule["labels"]]

        custom_block.append(waf_rule)

    # Rate-Limiting Rules
    for rule in ir.get("rate_limiting_rules", {}).get("rules", []):
        if rule.get("convertibility") == "no":
            continue
        cond = rule_conditions(rule)

        ctx = {"refs": refs, "warnings": warnings,
               "rule_name": rule["name"], "ip_list_map": ip_list_map,
               "asn_lists": asn_lists, "hostname_lists": hostname_lists,
               "inline_ip_set_ids": inline_ip_set_ids,
               "current_rule_ip_sets": rule.get("ip_sets", [])}

        rate_stmt = {
            "RateBasedStatement": {
                "Limit": rule.get("aws_limit", 100),
                "AggregateKeyType": "IP",
                "EvaluationWindowSec": rule.get("aws_evaluation_window_sec", 60),
            }
        }

        # Build scope-down
        scope_parts = []
        if rule.get("scope_down", {}).get("skip_http_ratelimit"):
            scope_parts.append({"NotStatement": {"Statement": {"LabelMatchStatement": {
                "Scope": "LABEL", "Key": "skip:http_ratelimit"}}}})
        if cond:
            cond_stmt = conditions_to_statement(cond, ctx)
            # Flatten: if cond_stmt is AndStatement and we're building an AndStatement, merge
            if scope_parts and "AndStatement" in cond_stmt:
                scope_parts.extend(cond_stmt["AndStatement"]["Statements"])
            else:
                scope_parts.append(cond_stmt)

        if scope_parts:
            if len(scope_parts) == 1:
                rate_stmt["RateBasedStatement"]["ScopeDownStatement"] = scope_parts[0]
            else:
                rate_stmt["RateBasedStatement"]["ScopeDownStatement"] = {
                    "AndStatement": {"Statements": scope_parts}}

        aws_action = ACTION_MAP.get(rule.get("action", "block"), {"Block": {}})
        rn = unique_rule_name(rule["name"])
        rate_block.append({
            "Name": rn, "Action": aws_action, "Statement": rate_stmt,
            "VisibilityConfig": {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True,
                                 "MetricName": rn},
        })

    # Managed rules (built separately, added per-WebACL, never packed)
    managed_rules, _ = build_managed_rules(0, skip_labels_present)

    # ── Build WebACLs ────────────────────────────────────────────────────────

    def build_webacl(name, acl_rules):
        return {
            "Type": "AWS::WAFv2::WebACL",
            "Properties": {
                "Name": name, "Scope": "CLOUDFRONT",
                "DefaultAction": {"Allow": {}},
                "Rules": acl_rules,
                "VisibilityConfig": {"SampledRequestsEnabled": True,
                                     "CloudWatchMetricsEnabled": True,
                                     "MetricName": sanitize_rule_name(name)},
            }
        }

    # Legacy mode: 2 WebACLs (website + api). Each gets the SAME custom_block +
    # rate_block, packed independently into its own rule groups (rule groups are
    # per-WebACL so counters/labels stay isolated per WebACL). Injected rules:
    #   website: header = [search-engine, anti-DDoS(challenge on)], trailer = [always-on-challenge]
    #   api:     header = [anti-DDoS(challenge off/advanced)],       trailer = []
    over_limits = []

    def build_one_webacl(logical_id, name, header, trailer):
        # Deep-copy the shared blocks so each WebACL's packing (label rewrites,
        # priorities, rule-group materialization) is independent.
        cust = copy.deepcopy(custom_block)
        rate = copy.deepcopy(rate_block)
        mgd = copy.deepcopy(managed_rules)
        ordered, warns, over = pack_webacl_rules(
            name, cust, rate, header, trailer, mgd, unique_id, resources)
        warnings.extend(warns)
        if over:
            over_limits.append(over)
        resources[logical_id] = build_webacl(name, ordered)

    build_one_webacl(
        "WebACLWebsite", "waf-website",
        header=[build_search_engine_label_rule(0),
                build_anti_ddos_rule(0, advanced=False,
                                     scope_down_exclude_labels=["custom:search-engine"])],
        trailer=[build_always_on_challenge_rule(0)])

    build_one_webacl(
        "WebACLApiFile", "waf-api-file",
        header=[build_anti_ddos_rule(0, advanced=True)],
        trailer=[])

    # ── Clean up unreferenced IP sets ────────────────────────────────────────

    unreferenced = [lid for lid, res in resources.items()
                    if res["Type"] == "AWS::WAFv2::IPSet" and lid not in refs.referenced_ids]
    for lid in unreferenced:
        name = resources[lid]["Properties"]["Name"]
        del resources[lid]
        warnings.append(f"IP set '{name}' not referenced by any rule — removed")

    for name in asn_lists:
        if name not in refs.referenced_asn_lists:
            warnings.append(f"ASN list '{name}' not referenced by any rule")

    # ── Quota validation ─────────────────────────────────────────────────────
    # WCU and ref counts are computed from the FINAL assembled resources (each
    # WebACL's own effective WCU = its direct rules + the capacity of every rule
    # group it references). The packer already fit RBR/refs under the per-WebACL
    # caps (rule-group overflow) or reported over_limits; the 50-ref cap can no
    # longer be exceeded here. We split findings into:
    #   errors        — FATAL: no point delivering (stack too big to even write)
    #   blocked       — deliver the CFN, but it WON'T deploy as-is (WCU>5000, or a
    #                   single rule too big to split); user must simplify + re-run
    # This matches the decision: always deliver + signal loudly, never silently
    # succeed and never hard-fail-without-output for an over-limit the user can act on.

    errors = []
    blocked = []
    max_wcu_total = 0
    for wl, wr in webacl_effective_wcu(resources).items():
        max_wcu_total = max(max_wcu_total, wr)
        if wr > MAX_WCU:
            blocked.append(f"WebACL {wl}: WCU {wr} exceeds the {MAX_WCU} hard cap — "
                           f"cannot deploy. Reduce rule complexity in this WebACL's "
                           f"source rules, then re-run.")
        elif wr > WARN_WCU:
            warnings.append(f"WebACL {wl}: WCU {wr} exceeds {WARN_WCU} (extra charges apply)")
    for over in over_limits:
        blocked.append(f"WebACL {over.get('webacl','?')}: {over['reason']} — cannot "
                       f"deploy. Simplify the offending rule, then re-run.")
    if len(resources) > MAX_STACK_RESOURCES:
        errors.append(f"Stack resources {len(resources)} exceeds maximum {MAX_STACK_RESOURCES}")

    # ── Assemble template ────────────────────────────────────────────────────

    outputs = {}
    for lid, res in resources.items():
        if res["Type"] == "AWS::WAFv2::WebACL":
            name = res["Properties"]["Name"]
            outputs[f"{lid}Arn"] = {"Description": f"{name} WebACL ARN",
                                    "Value": {"Fn::GetAtt": [lid, "Arn"]}}

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "AWS WAF configuration — converted from Cloudflare",
        "Resources": resources,
        "Outputs": outputs,
    }

    # max_wcu_total = the highest per-WebACL effective WCU (computed from the
    # assembled template, not tracked during rule building).
    return template, max_wcu_total, refs, warnings, errors, blocked


def generate_split(split_ir):
    """Generate CloudFormation template with per-domain WebACLs."""
    resources = {}
    warnings = []
    used_ids = set()

    def unique_id(base):
        lid = sanitize_logical_id(base)
        if lid in used_ids:
            i = 2
            while f"{lid}{i}" in used_ids:
                i += 1
            lid = f"{lid}{i}"
        used_ids.add(lid)
        return lid

    # ── Build named IP set resources ─────────────────────────────────────────

    ip_list_map = {}
    asn_lists = {}
    hostname_lists = {}

    for lst in split_ir.get("ip_lists", []):
        name = lst.get("name", "")
        conv = lst.get("conversion", "")
        if conv == "hostname_set":
            hostname_lists[name] = lst.get("items", [])
        if conv == "ip_set":
            v4 = lst.get("items_ipv4", [])
            v6 = lst.get("items_ipv6", [])
            if v4:
                lid = unique_id(f"IPSet{name}Ipv4")
                resources[lid] = {"Type": "AWS::WAFv2::IPSet", "Properties": {
                    "Name": f"{name}-ipv4", "Scope": "CLOUDFRONT",
                    "IPAddressVersion": "IPV4", "Addresses": v4}}
                ip_list_map[f"{name}-ipv4"] = lid
            if v6:
                lid = unique_id(f"IPSet{name}Ipv6")
                resources[lid] = {"Type": "AWS::WAFv2::IPSet", "Properties": {
                    "Name": f"{name}-ipv6", "Scope": "CLOUDFRONT",
                    "IPAddressVersion": "IPV6", "Addresses": v6}}
                ip_list_map[f"{name}-ipv6"] = lid
            if not v4 and not v6:
                ip_list_map[f"{name}-ipv4"] = None
                ip_list_map[f"{name}-ipv6"] = None
        elif conv == "asn_inline":
            asn_lists[name] = lst.get("items", [])
            ip_list_map[name] = "__asn__"

    # ── Build inline IP sets (auto-dedup if >100 unique) ─────────────────────

    # Step 1: scan to decide dedup
    content_keys = set()
    for domain_data in split_ir.get("domains", {}).values():
        for section in ("ip_access_rules", "custom_rules", "rate_limiting_rules"):
            for rule in domain_data.get(section, []):
                for ipset in rule.get("ip_sets", []):
                    addrs = ipset.get("addresses", [])
                    if not addrs:
                        continue
                    is_v6 = any(is_ipv6(a) for a in addrs)
                    content_keys.add(("IPV6" if is_v6 else "IPV4", tuple(sorted(addrs))))
    dedup = len(content_keys) > 100

    # Step 2: create resources
    inline_ip_set_ids = {}
    if dedup:
        content_to_id = {}
        for domain_data in split_ir.get("domains", {}).values():
            for section in ("ip_access_rules", "custom_rules", "rate_limiting_rules"):
                for rule in domain_data.get(section, []):
                    for ipset in rule.get("ip_sets", []):
                        name = ipset["name"]
                        addrs = ipset.get("addresses", [])
                        if not addrs:
                            continue
                        is_v6 = any(is_ipv6(a) for a in addrs)
                        key = (("IPV6" if is_v6 else "IPV4"), tuple(sorted(addrs)))
                        if key in content_to_id:
                            inline_ip_set_ids[name] = content_to_id[key]
                        else:
                            lid = unique_id(f"IPSet{name}")
                            content_to_id[key] = lid
                            inline_ip_set_ids[name] = lid
                            resources[lid] = {"Type": "AWS::WAFv2::IPSet", "Properties": {
                                "Name": name, "Scope": "CLOUDFRONT",
                                "IPAddressVersion": key[0], "Addresses": addrs}}
    else:
        seen_names = set()
        for domain_data in split_ir.get("domains", {}).values():
            for section in ("ip_access_rules", "custom_rules", "rate_limiting_rules"):
                for rule in domain_data.get(section, []):
                    for ipset in rule.get("ip_sets", []):
                        name = ipset["name"]
                        if name in seen_names:
                            continue
                        seen_names.add(name)
                        addrs = ipset.get("addresses", [])
                        if not addrs:
                            continue
                        is_v6 = any(is_ipv6(a) for a in addrs)
                        lid = unique_id(f"IPSet{name}")
                        inline_ip_set_ids[name] = lid
                        resources[lid] = {"Type": "AWS::WAFv2::IPSet", "Properties": {
                            "Name": name, "Scope": "CLOUDFRONT",
                            "IPAddressVersion": "IPV6" if is_v6 else "IPV4",
                            "Addresses": addrs}}

    # ── Build per-domain WebACLs ─────────────────────────────────────────────

    skip_labels_present = split_ir.get("skip_labels_present", {})
    total_rules = 0
    max_wcu = 0
    max_wcu_domain = ""
    seen_warnings = set()
    all_referenced_ids = set()
    all_referenced_asn_lists = set()
    exceeded_domains = []
    domain_ref_counts = {}  # domain → ref count for quota reporting
    over_limits = []        # packer over-limit reports (per domain)
    blocked = []            # deliverable-but-won't-deploy findings (WCU>5000, etc.)

    for domain, domain_data in split_ir.get("domains", {}).items():
        # `refs` feeds unreferenced-IP-set cleanup; the authoritative WCU + ref
        # counts come from the packed resources below (webacl_effective_wcu).
        refs = RefCounter()
        used_rule_names = set()

        def unique_rule_name(raw_name):
            name = sanitize_rule_name(raw_name)
            if name not in used_rule_names:
                used_rule_names.add(name)
                return name
            i = 2
            while f"{name}-{i}" in used_rule_names:
                i += 1
            deduped = f"{name}-{i}"[:128]
            used_rule_names.add(deduped)
            return deduped

        # Build the two ordered phase blocks (no Priority/WCU here — the packer
        # assigns priorities, offloads overflow into rule groups, and rewrites
        # label keys; WCU/refs are then read back from the assembled resources).
        custom_block = []
        rate_block = []

        # IP Access Rules (custom phase, first)
        for rule in domain_data.get("ip_access_rules", []):
            if rule.get("convertibility") == "no":
                continue
            cond = rule.get("conditions")
            if not cond:
                continue
            ctx = {"refs": refs, "warnings": warnings,
                   "rule_name": rule["name"], "ip_list_map": ip_list_map,
                   "asn_lists": asn_lists, "hostname_lists": hostname_lists,
               "inline_ip_set_ids": inline_ip_set_ids,
                   "current_rule_ip_sets": rule.get("ip_sets", [])}
            stmt = conditions_to_statement(cond, ctx)
            aws_action = ACTION_MAP.get(rule.get("mode", "block"), {"Block": {}})
            rn = unique_rule_name(rule["name"])
            custom_block.append({
                "Name": rn, "Action": aws_action, "Statement": stmt,
                "VisibilityConfig": {"SampledRequestsEnabled": True,
                                     "CloudWatchMetricsEnabled": True, "MetricName": rn},
            })

        # Custom Rules
        for rule in domain_data.get("custom_rules", []):
            if rule.get("convertibility") == "no":
                continue
            cond = rule_conditions(rule)
            if not cond:
                continue
            ctx = {"refs": refs, "warnings": warnings,
                   "rule_name": rule["name"], "ip_list_map": ip_list_map,
                   "asn_lists": asn_lists, "hostname_lists": hostname_lists,
               "inline_ip_set_ids": inline_ip_set_ids,
                   "current_rule_ip_sets": rule.get("ip_sets", [])}
            stmt = conditions_to_statement(cond, ctx)

            if rule.get("scope_down", {}).get("skip_all_remaining_custom_rules"):
                not_label = {"NotStatement": {"Statement": {"LabelMatchStatement": {
                    "Scope": "LABEL", "Key": "skip:all_remaining_custom_rules"}}}}
                if "AndStatement" in stmt:
                    stmt["AndStatement"]["Statements"].insert(0, not_label)
                else:
                    stmt = {"AndStatement": {"Statements": [not_label, stmt]}}

            action = rule.get("action", "block")
            if action == "skip":
                aws_action = {"Count": {}}
            else:
                aws_act = rule.get("aws_action", action)
                aws_action = ACTION_MAP.get(aws_act, {"Block": {}})

            rn = unique_rule_name(rule["name"])
            waf_rule = {
                "Name": rn, "Action": aws_action, "Statement": stmt,
                "VisibilityConfig": {"SampledRequestsEnabled": True,
                                     "CloudWatchMetricsEnabled": True, "MetricName": rn},
            }
            if action == "skip" and rule.get("labels"):
                waf_rule["RuleLabels"] = [{"Name": l} for l in rule["labels"]]
            custom_block.append(waf_rule)

        # Rate-Limiting Rules
        for rule in domain_data.get("rate_limiting_rules", []):
            if rule.get("convertibility") == "no":
                continue
            cond = rule_conditions(rule)
            ctx = {"refs": refs, "warnings": warnings,
                   "rule_name": rule["name"], "ip_list_map": ip_list_map,
                   "asn_lists": asn_lists, "hostname_lists": hostname_lists,
               "inline_ip_set_ids": inline_ip_set_ids,
                   "current_rule_ip_sets": rule.get("ip_sets", [])}
            rate_stmt = {"RateBasedStatement": {
                "Limit": rule.get("aws_limit", 100),
                "AggregateKeyType": "IP",
                "EvaluationWindowSec": rule.get("aws_evaluation_window_sec", 60),
            }}
            scope_parts = []
            if rule.get("scope_down", {}).get("skip_http_ratelimit"):
                scope_parts.append({"NotStatement": {"Statement": {"LabelMatchStatement": {
                    "Scope": "LABEL", "Key": "skip:http_ratelimit"}}}})
            if cond:
                cond_stmt = conditions_to_statement(cond, ctx)
                if scope_parts and "AndStatement" in cond_stmt:
                    scope_parts.extend(cond_stmt["AndStatement"]["Statements"])
                else:
                    scope_parts.append(cond_stmt)
            if scope_parts:
                if len(scope_parts) == 1:
                    rate_stmt["RateBasedStatement"]["ScopeDownStatement"] = scope_parts[0]
                else:
                    rate_stmt["RateBasedStatement"]["ScopeDownStatement"] = {
                        "AndStatement": {"Statements": scope_parts}}
            aws_action = ACTION_MAP.get(rule.get("action", "block"), {"Block": {}})
            rn = unique_rule_name(rule["name"])
            rate_block.append({
                "Name": rn, "Action": aws_action, "Statement": rate_stmt,
                "VisibilityConfig": {"SampledRequestsEnabled": True,
                                     "CloudWatchMetricsEnabled": True, "MetricName": rn},
            })

        # Managed rules (never packed)
        managed_rules, _ = build_managed_rules(0, skip_labels_present)

        # Pack the domain's blocks into a WebACL. Per-domain WebACLs each carry
        # the same injected header/trailer as legacy mode's website variant
        # (search-engine label + anti-DDoS challenge-on, always-on-challenge).
        webacl_name = sanitize_webacl_name(domain)
        lid_unique = unique_id(f"WebACL{sanitize_logical_id(domain)}")
        header = [build_search_engine_label_rule(0),
                  build_anti_ddos_rule(0, advanced=False,
                                       scope_down_exclude_labels=["custom:search-engine"])]
        trailer = [build_always_on_challenge_rule(0)]
        ordered, warns, over = pack_webacl_rules(
            webacl_name, custom_block, rate_block, header, trailer,
            managed_rules, unique_id, resources)
        warnings.extend(warns)

        resources[lid_unique] = {
            "Type": "AWS::WAFv2::WebACL",
            "Properties": {
                "Name": webacl_name, "Scope": "CLOUDFRONT",
                "DefaultAction": {"Allow": {}},
                "Rules": ordered,
                "VisibilityConfig": {"SampledRequestsEnabled": True,
                                     "CloudWatchMetricsEnabled": True,
                                     "MetricName": sanitize_rule_name(webacl_name)},
            }
        }
        total_rules += len(ordered)

        # Authoritative WCU + ref count read back from the assembled WebACL.
        domain_total_wcu = webacl_effective_wcu(resources).get(webacl_name, 0)
        webacl_refs = sum(_count_refs_in_stmt(r.get("Statement", {}))
                          for r in ordered)
        domain_ref_counts[domain] = webacl_refs
        all_referenced_ids |= refs.referenced_ids
        all_referenced_asn_lists |= refs.referenced_asn_lists

        if domain_total_wcu > max_wcu:
            max_wcu = domain_total_wcu
            max_wcu_domain = domain
        if domain_total_wcu > MAX_WCU:
            warnings.append(f"Domain {domain}: WCU {domain_total_wcu} exceeds {MAX_WCU}")
        elif domain_total_wcu > WARN_WCU:
            w = f"WCU {domain_total_wcu} exceeds {WARN_WCU} (extra charges apply)"
            if w not in seen_warnings:
                seen_warnings.add(w)
                warnings.append(f"Domain {domain}: {w}")

        # WCU over the hard cap → deliverable but blocked (user must simplify).
        if domain_total_wcu > MAX_WCU:
            blocked.append(f"Domain {domain}: WCU {domain_total_wcu} exceeds the "
                           f"{MAX_WCU} hard cap — cannot deploy. Simplify this "
                           f"domain's rules, then re-run.")
        # The packer offloads RBR/ref overflow into rule groups; a residual
        # over-limit (a single rule too big to split) blocks that domain.
        if over:
            over["domain"] = domain
            over_limits.append(over)
            blocked.append(f"Domain {domain}: {over['reason']} — cannot deploy. "
                           f"Simplify the offending rule, then re-run.")
            exceeded_domains.append(f"{domain}: {over['reason']}")

    # ── Clean up unreferenced IP sets ────────────────────────────────────────

    unreferenced = [lid for lid, res in resources.items()
                    if res["Type"] == "AWS::WAFv2::IPSet" and lid not in all_referenced_ids]
    for lid in unreferenced:
        name = resources[lid]["Properties"]["Name"]
        del resources[lid]
        warnings.append(f"IP set '{name}' not referenced by any rule — removed")

    for name in asn_lists:
        if name not in all_referenced_asn_lists:
            warnings.append(f"ASN list '{name}' not referenced by any rule")

    # ── Quota validation ─────────────────────────────────────────────────────

    errors = []
    num_webacls = sum(1 for r in resources.values() if r["Type"] == "AWS::WAFv2::WebACL")
    num_ip_sets = sum(1 for r in resources.values() if r["Type"] == "AWS::WAFv2::IPSet")
    if num_webacls > 80:
        warnings.append(f"{num_webacls} WebACLs approaching 100 per-region limit")
    if num_ip_sets > 80:
        warnings.append(f"{num_ip_sets} IP sets approaching 100 per-region limit")
    if len(resources) > MAX_STACK_RESOURCES:
        errors.append(f"Stack resources {len(resources)} exceeds maximum {MAX_STACK_RESOURCES}")

    # ── Assemble template ────────────────────────────────────────────────────

    outputs = {}
    for lid, res in resources.items():
        if res["Type"] == "AWS::WAFv2::WebACL":
            name = res["Properties"]["Name"]
            outputs[f"{lid}Arn"] = {"Description": f"{name} WebACL ARN",
                                    "Value": {"Fn::GetAtt": [lid, "Arn"]}}

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "AWS WAF configuration — converted from Cloudflare (per-domain WebACLs)",
        "Resources": resources,
        "Outputs": outputs,
    }

    return (template, max_wcu, max_wcu_domain, warnings, errors, exceeded_domains,
            dedup, domain_ref_counts, blocked)


# ── WAFv2 API throttle mitigation ─────────────────────────────────────────────

def _add_throttle_chains(template):
    """Add DependsOn chains to WAFv2 resources to avoid API throttling.

    WAFv2 write API limit is 1 TPS (fixed, non-adjustable). CloudFormation
    creates resources in parallel by default, causing ThrottlingException
    when many IP sets are created simultaneously.

    Strategy: a FULLY SERIAL chain per resource type — each resource DependsOn
    the previous one, so CloudFormation creates them strictly one at a time.
    An earlier "batches of 5 in parallel, rely on CFN retries" strategy still
    throttled at deploy (EMPIRICALLY: 55 IP sets → repeated ThrottlingException
    + rollback), because 5 concurrent creates is 5x the 1 TPS ceiling and CFN's
    retry budget is exhausted under sustained back-to-back batches. Serial is
    the only rate that reliably stays under 1 TPS. IP set creation is fast
    (~1s each), so 55 sets ≈ 1 min of serial creation — acceptable.
    """
    resources = template.get("Resources", {})

    for rtype in ("AWS::WAFv2::IPSet", "AWS::WAFv2::WebACL"):
        lids = [lid for lid, res in resources.items() if res["Type"] == rtype]
        # Serial chain: resource i depends on resource i-1.
        for prev, cur in zip(lids, lids[1:]):
            res = resources[cur]
            deps = res.get("DependsOn", [])
            if isinstance(deps, str):
                deps = [deps]
            if prev not in deps:
                deps.append(prev)
            res["DependsOn"] = deps


# ── Template writing (compact + split if needed) ─────────────────────────────

CFN_S3_LIMIT = 1_048_576  # 1 MB
SPLIT_TARGET = 900_000    # 900 KB per stack (leave margin)


def _write_templates(template, output_dir):
    """Write CloudFormation template(s). Returns dict with file info.

    - Adds DependsOn chains to avoid WAFv2 API throttling (1 TPS limit).
    - Always writes compact JSON for deployment + indented for reading.
    - If compact > 1MB, splits into IP set stack + WebACL batch stacks
      using Export/Fn::ImportValue for cross-stack references.
    """
    # Always write readable version (full template, indented — no throttle chains, for human reading)
    readable_path = os.path.join(output_dir, "waf-cloudformation.readable.json")
    with open(readable_path, "w") as f:
        json.dump(template, f, indent=2, ensure_ascii=False)

    # Check if split is needed (before adding throttle chains)
    compact_check = json.dumps(template, separators=(",", ":"), ensure_ascii=False)
    compact_size = len(compact_check.encode("utf-8"))

    if compact_size <= CFN_S3_LIMIT:
        # Single file — add throttle chains to the whole template
        _add_throttle_chains(template)
        compact = json.dumps(template, separators=(",", ":"), ensure_ascii=False)
        compact_size = len(compact.encode("utf-8"))
        out_path = os.path.join(output_dir, "waf-cloudformation.json")
        with open(out_path, "w") as f:
            f.write(compact)
        return {"count": 1, "files": ["waf-cloudformation.json"], "compact_size": compact_size}

    # Split: IP sets → one stack, WebACLs → batched stacks
    resources = template["Resources"]
    ipset_resources = {k: v for k, v in resources.items() if v["Type"] == "AWS::WAFv2::IPSet"}
    webacl_resources = {k: v for k, v in resources.items() if v["Type"] == "AWS::WAFv2::WebACL"}

    # Build IP set stack with Exports
    ipset_outputs = {}
    for lid in ipset_resources:
        export_name = f"waf-ipsets-{lid}-Arn"
        ipset_outputs[f"{lid}Arn"] = {
            "Value": {"Fn::GetAtt": [lid, "Arn"]},
            "Export": {"Name": export_name},
        }
    ipset_template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "AWS WAF IP sets — converted from Cloudflare",
        "Resources": ipset_resources,
        "Outputs": ipset_outputs,
    }
    _add_throttle_chains(ipset_template)
    ipset_path = os.path.join(output_dir, "waf-cloudformation-ipsets.json")
    with open(ipset_path, "w") as f:
        json.dump(ipset_template, f, separators=(",", ":"), ensure_ascii=False)

    # Build mapping: logical_id → export name (for Fn::ImportValue replacement)
    lid_to_export = {lid: f"waf-ipsets-{lid}-Arn" for lid in ipset_resources}

    # Batch WebACLs into stacks ≤ SPLIT_TARGET
    batches = []
    current_batch = {}
    current_size = 200  # boilerplate overhead estimate

    for lid, res in webacl_resources.items():
        # Replace Fn::GetAtt with Fn::ImportValue in this WebACL
        res_json = json.dumps(res, separators=(",", ":"))
        for ip_lid, export_name in lid_to_export.items():
            old = json.dumps({"Fn::GetAtt": [ip_lid, "Arn"]}, separators=(",", ":"))
            new = json.dumps({"Fn::ImportValue": export_name}, separators=(",", ":"))
            res_json = res_json.replace(old, new)
        res_replaced = json.loads(res_json)
        res_size = len(res_json.encode("utf-8"))

        if current_size + res_size > SPLIT_TARGET and current_batch:
            batches.append(current_batch)
            current_batch = {}
            current_size = 200
        current_batch[lid] = res_replaced
        current_size += res_size

    if current_batch:
        batches.append(current_batch)

    # Write WebACL batch stacks
    files = ["waf-cloudformation-ipsets.json"]
    for i, batch in enumerate(batches, 1):
        outputs = {}
        for lid, res in batch.items():
            name = res["Properties"]["Name"]
            outputs[f"{lid}Arn"] = {"Description": f"{name} WebACL ARN",
                                    "Value": {"Fn::GetAtt": [lid, "Arn"]}}
        batch_template = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Description": f"AWS WAF WebACLs batch {i} — converted from Cloudflare",
            "Resources": batch,
            "Outputs": outputs,
        }
        _add_throttle_chains(batch_template)
        fname = f"waf-cloudformation-webacls-{i}.json"
        batch_path = os.path.join(output_dir, fname)
        with open(batch_path, "w") as f:
            json.dump(batch_template, f, separators=(",", ":"), ensure_ascii=False)
        files.append(fname)

    return {"count": len(files), "files": files, "compact_size": compact_size}


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Usage: waf-generate-cfn.py <output_dir> [--split] [--force-no-split]", file=sys.stderr)
        sys.exit(1)

    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    output_dir = os.path.expanduser(args[0])
    mode = "split" if "--split" in sys.argv else "legacy"
    force_no_split = "--force-no-split" in sys.argv

    if mode == "split":
        split_path = os.path.join(output_dir, "waf_ir_split.json")
        if not os.path.exists(split_path):
            print(f"ERROR: {split_path} not found (split mode requires waf-split-by-host.py)", file=sys.stderr)
            sys.exit(1)
        with open(split_path) as f:
            split_ir = json.load(f)
        (template, max_wcu_val, max_wcu_domain, warnings, errors, exceeded_domains,
         dedup, domain_ref_counts, blocked) = generate_split(split_ir)
        wcu_display = f"WCU={max_wcu_val} (max, {max_wcu_domain})"
    else:
        ir_path = os.path.join(output_dir, "waf_ir.json")
        if not os.path.exists(ir_path):
            print(f"ERROR: {ir_path} not found", file=sys.stderr)
            sys.exit(1)
        with open(ir_path) as f:
            ir = json.load(f)
        template, max_wcu_val, refs, warnings, errors, blocked = generate(ir)
        wcu_display = f"WCU={max_wcu_val}"
        exceeded_domains = []
        dedup = False
        domain_ref_counts = {}

    # Count resources for metadata
    num_ip_sets = sum(1 for r in template["Resources"].values() if r["Type"] == "AWS::WAFv2::IPSet")

    # Write metadata for downstream scripts (readme). Ref counts are the ACTUAL
    # post-pack WebACL reference-statement totals (direct IP/regex/rule-group refs
    # that count against the 50 cap) read from the assembled template — NOT the
    # pre-pack raw count, which the packer offloads into rule groups. These are
    # always ≤50 now; the 50-ref cap can no longer force a split.
    webacl_ref_counts = {
        r["Properties"]["Name"]: sum(_count_refs_in_stmt(x.get("Statement", {}))
                                     for x in r["Properties"]["Rules"])
        for r in template["Resources"].values()
        if r["Type"] == "AWS::WAFv2::WebACL"}
    meta = {"mode": mode, "dedup": dedup, "ip_sets_total": num_ip_sets,
            "ref_counts_per_webacl": webacl_ref_counts,
            "max_ref_per_webacl": max(webacl_ref_counts.values(), default=0),
            "blocked_count": len(blocked), "blocked_items": blocked}
    if mode != "legacy":
        meta["ref_counts_per_domain"] = domain_ref_counts
    meta_path = os.path.join(output_dir, "waf_metadata.json")
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)

    # Write template(s)
    template_files = _write_templates(template, output_dir)
    compact_size = template_files["compact_size"]

    # Update metadata with template info
    meta["template_count"] = template_files["count"]
    meta["template_files"] = template_files["files"]
    meta["compact_size"] = compact_size
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)

    # Report
    num_resources = len(template["Resources"])
    num_webacls = sum(1 for r in template["Resources"].values() if r["Type"] == "AWS::WAFv2::WebACL")
    num_ip_sets = sum(1 for r in template["Resources"].values() if r["Type"] == "AWS::WAFv2::IPSet")

    seen = set()
    for w in warnings:
        if w not in seen:
            seen.add(w)
            print(f"  WARN: {w}", file=sys.stderr)

    # Fatal errors (e.g. stack too big to even write) — no deliverable, stop.
    if errors:
        for e in errors:
            print(f"  ERROR: {e}", file=sys.stderr)
        print(f"\n---RESULT---\nSPEC: 1\nSTATUS: FATAL\nACTION: FIX\n"
              f"ERRORS: {len(errors)}\n"
              f"CONTEXT: {'; '.join(errors)}")
        sys.exit(2)

    # The template is written either way. `blocked` = findings that make it
    # UNDEPLOYABLE as-is but that the user can fix (WCU>5000, a single rule too
    # big to split). We still deliver the CFN + a loud BLOCKED signal so the user
    # can inspect it, clean up the source, and re-run — never silently succeed,
    # never hard-fail-without-output. `common_tail` carries the artifact facts
    # shared by every terminal status.
    common_tail = (f"TEMPLATE_COUNT: {template_files['count']}\n"
                   f"TEMPLATES: {','.join(template_files['files'])}\n"
                   f"TEMPLATE_SIZE: {compact_size}\n"
                   f"RESOURCES: {num_resources}\nWEBACLS: {num_webacls}\n"
                   f"IP_SETS: {num_ip_sets}\nWCU: {max_wcu_val}\nMODE: {mode}")

    if blocked:
        for b in blocked:
            print(f"  BLOCKED: {b}", file=sys.stderr)
        items = "\n".join(f"  {b}" for b in blocked)
        print(f"BLOCKED: {num_resources} resources, {num_webacls} WebACLs, "
              f"{num_ip_sets} IP sets, {wcu_display} — template written but NOT deployable as-is")
        print(f"\n---RESULT---\nSPEC: 1\nSTATUS: BLOCKED\n{common_tail}\n"
              f"BLOCKED_COUNT: {len(blocked)}\nBLOCKED_ITEMS:\n{items}\n"
              f"ACTION: FIX\n"
              f"CONTEXT: The CloudFormation was generated but will be REJECTED at "
              f"deploy time by the item(s) above (AWS hard caps). Do NOT deploy as-is. "
              f"Reduce the offending WebACL/rule complexity in the source Cloudflare "
              f"config (or split affected hosts), then re-run the pipeline.")
        return  # exit 0 — pipeline completes; BLOCKED status carries the signal

    print(f"OK: {num_resources} resources, {num_webacls} WebACLs, "
          f"{num_ip_sets} IP sets, {wcu_display}")
    # WCU is computed by a calculator proven exact vs CheckCapacity, so this is a
    # safety-net note, not a required step. VERIFY_WCU_CMD lets an agent/user
    # optionally reconcile rule-group Capacity against AWS before deploying.
    print(f"\n---RESULT---\nSPEC: 1\nSTATUS: OK\n{common_tail}\n"
          f"VERIFY_WCU_CMD: python3 {os.path.join(os.path.dirname(os.path.abspath(__file__)), 'waf-verify-wcu.py')} {output_dir} --profile <aws-profile>\n"
          f"VERIFY_WCU_NOTE: Optional pre-deploy check. Local WCU is calculator-exact; "
          f"run this only to reconcile rule-group Capacity against AWS CheckCapacity "
          f"(needs an AWS profile). Without a profile, deploy as-is — Capacity can "
          f"only ever be slightly high, which still deploys.")


if __name__ == "__main__":
    main()
