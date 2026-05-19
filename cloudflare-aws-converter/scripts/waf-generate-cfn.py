#!/usr/bin/env python3
"""waf-generate-cfn.py — WAF Stage 3: Generate CloudFormation template.

Reads waf_ir.json and outputs a CloudFormation JSON template containing
IP sets, regex pattern sets, and two WebACL resources.

Usage:
    python3 waf-generate-cfn.py <output_dir>

Exit codes: 0 = OK, 2 = fatal error, 3 = ref count exceeded (auto fallback to split).
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


class WCUTracker:
    def __init__(self):
        self.total = 0
        self.per_rule = {}

    def add(self, rule_name, wcu):
        self.total += wcu
        self.per_rule[rule_name] = self.per_rule.get(rule_name, 0) + wcu


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
    if transform == "lowercase":
        ctx["wcu"].add(ctx["rule_name"], 10)

    # IP set reference
    if field == "ip.src" and operator in ("in", "not_in"):
        return _build_ip_statement(value, ctx, cond)

    # Country match
    if field == "ip.src.country":
        if operator == "in" and isinstance(value, str) and value.startswith("{"):
            codes = [c.strip().strip('"').upper() for c in value[1:-1].split()]
        elif operator == "eq":
            codes = [str(value).upper()]
        elif operator == "ne":
            ctx["wcu"].add(ctx["rule_name"], 1)
            return {"NotStatement": {"Statement": {
                "GeoMatchStatement": {"CountryCodes": [str(value).upper()]}}}}
        else:
            codes = [str(value).upper()]
        ctx["wcu"].add(ctx["rule_name"], 1)
        return {"GeoMatchStatement": {"CountryCodes": codes}}

    # ASN match
    if field in ("ip.geoip.asnum", "ip.src.asnum") and operator == "in":
        return _build_asn_statement(value, ctx)

    # Bare boolean field
    if operator == "eq" and value is True:
        # Non-convertible bare boolean — should have been caught by convertibility check
        ctx["warnings"].append(f"Bare boolean field '{field}' in statement — may not convert correctly")
        ctx["wcu"].add(ctx["rule_name"], 1)
        return {"ByteMatchStatement": {
            "SearchString": "1", "PositionalConstraint": "EXACTLY",
            "FieldToMatch": {"SingleHeader": {"Name": field.replace(".", "-")}},
            "TextTransformations": [{"Priority": 0, "Type": "NONE"}]}}

    # Wildcard → regex
    if operator in ("wildcard", "strict_wildcard"):
        regex = glob_to_regex(str(value), case_insensitive=(operator == "wildcard"))
        if len(regex) > MAX_REGEX_LEN:
            ctx["warnings"].append(f"Regex pattern exceeds {MAX_REGEX_LEN} chars for field '{field}'")
        ctx["wcu"].add(ctx["rule_name"], 3)
        ftm = FIELD_TO_MATCH.get(field, {"UriPath": {}})
        return {"RegexMatchStatement": {
            "RegexString": regex,
            "FieldToMatch": ftm,
            "TextTransformations": [{"Priority": 0, "Type": "NONE"}]}}

    # Regex match
    if operator == "matches":
        ctx["wcu"].add(ctx["rule_name"], 3)
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
        ctx["wcu"].add(ctx["rule_name"], 1)
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
        ctx["wcu"].add(ctx["rule_name"], 1)
        ftm = FIELD_TO_MATCH.get(field, {"SingleHeader": {"Name": field.split(".")[-1]}})
        return {"ByteMatchStatement": {
            "SearchString": search,
            "PositionalConstraint": pc,
            "FieldToMatch": ftm,
            "TextTransformations": text_transforms}}

    # ne → NOT + EXACTLY
    if operator == "ne":
        ctx["wcu"].add(ctx["rule_name"], 1)
        ftm = FIELD_TO_MATCH.get(field, {"SingleHeader": {"Name": field.split(".")[-1]}})
        return {"NotStatement": {"Statement": {"ByteMatchStatement": {
            "SearchString": str(value),
            "PositionalConstraint": "EXACTLY",
            "FieldToMatch": ftm,
            "TextTransformations": text_transforms}}}}

    # Fallback — unknown field/operator
    ctx["warnings"].append(f"Unknown field/operator: {field} {operator} — generating placeholder")
    ctx["wcu"].add(ctx["rule_name"], 1)
    return {"ByteMatchStatement": {
        "SearchString": str(value) if value else "PLACEHOLDER",
        "PositionalConstraint": "CONTAINS",
        "FieldToMatch": {"UriPath": {}},
        "TextTransformations": [{"Priority": 0, "Type": "NONE"}]}}


def _build_ip_statement(value, ctx, cond=None):
    """Build IPSetReferenceStatement(s) for ip.src in ... conditions."""
    ctx["wcu"].add(ctx["rule_name"], 1)
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
    stmts = []
    for chunk in chunks:
        ctx["wcu"].add(ctx["rule_name"], 1)
        stmts.append({"AsnMatchStatement": {"AsnList": chunk}})
    return stmts[0] if len(stmts) == 1 else {"OrStatement": {"Statements": stmts}}


def _build_string_set_statement(field, items, text_transforms, ctx):
    """Build statement for string set (in operator with string values)."""
    ftm = FIELD_TO_MATCH.get(field, {"SingleHeader": {"Name": field.split(".")[-1]}})

    if len(items) <= STRING_SET_REGEX_THRESHOLD:
        stmts = []
        for item in items:
            ctx["wcu"].add(ctx["rule_name"], 1)
            stmts.append({"ByteMatchStatement": {
                "SearchString": item, "PositionalConstraint": "EXACTLY",
                "FieldToMatch": ftm, "TextTransformations": text_transforms}})
        return stmts[0] if len(stmts) == 1 else {"OrStatement": {"Statements": stmts}}

    # Optimize: combine into regex
    escaped = [re.escape(item) for item in items]
    regex = "^(" + "|".join(escaped) + ")$"
    if len(regex) <= MAX_REGEX_LEN:
        ctx["wcu"].add(ctx["rule_name"], 3)
        return {"RegexMatchStatement": {"RegexString": regex, "FieldToMatch": ftm,
                "TextTransformations": text_transforms}}

    # Split into multiple regex
    stmts = []
    batch = []
    current_len = 4  # ^()$
    for e in escaped:
        if current_len + len(e) + 1 > MAX_REGEX_LEN - 4:
            r = "^(" + "|".join(batch) + ")$"
            ctx["wcu"].add(ctx["rule_name"], 3)
            stmts.append({"RegexMatchStatement": {"RegexString": r, "FieldToMatch": ftm,
                          "TextTransformations": text_transforms}})
            batch = [e]
            current_len = 4 + len(e)
        else:
            batch.append(e)
            current_len += len(e) + 1
    if batch:
        r = "^(" + "|".join(batch) + ")$"
        ctx["wcu"].add(ctx["rule_name"], 3)
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


def build_managed_rules(priority_start, skip_labels_present, wcu):
    """Build the 5 managed rule group rules."""
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
    wcu.add("AWS-IpReputation", 25)
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
    wcu.add("AWS-CRS", 700)
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
    wcu.add("AWS-KBI", 200)
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
    wcu.add("AWS-SQLi", 200)
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
    wcu = WCUTracker()
    refs = RefCounter()

    # ── Build IP set resources ───────────────────────────────────────────────

    ip_list_map = {}   # list_name → logical_id (for named lists)
    asn_lists = {}     # list_name → [asn_numbers] (for ASN lists)
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

    all_rules = []
    priority = 0
    rate_rule_count = 0
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

    # Anti-DDoS at priority 0 (added per-WebACL later)
    priority = 1

    # IP Access Rules
    for rule in ir.get("ip_access_rules", {}).get("rules", []):
        if rule.get("convertibility") == "no":
            continue
        cond = rule.get("conditions")
        if not cond:
            continue
        ctx = {"wcu": wcu, "refs": refs, "warnings": warnings,
               "rule_name": rule["name"], "ip_list_map": ip_list_map,
               "asn_lists": asn_lists, "inline_ip_set_ids": inline_ip_set_ids,
               "current_rule_ip_sets": rule.get("ip_sets", [])}
        stmt = conditions_to_statement(cond, ctx)
        aws_action = ACTION_MAP.get(rule.get("mode", "block"), {"Block": {}})
        rn = unique_rule_name(rule["name"])
        all_rules.append({
            "Name": rn, "Priority": priority,
            "Action": aws_action, "Statement": stmt,
            "VisibilityConfig": {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True,
                                 "MetricName": rn},
        })
        priority += 1

    # Custom Rules
    skip_labels_present = ir.get("custom_rules", {}).get("skip_labels_present", {})
    for rule in ir.get("custom_rules", {}).get("rules", []):
        if rule.get("convertibility") == "no":
            continue
        cond = rule.get("conditions") or rule.get("convertible_conditions")
        if not cond:
            continue
        ctx = {"wcu": wcu, "refs": refs, "warnings": warnings,
               "rule_name": rule["name"], "ip_list_map": ip_list_map,
               "asn_lists": asn_lists, "inline_ip_set_ids": inline_ip_set_ids,
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
            wcu.add(rule["name"], 1)

        # Determine action
        action = rule.get("action", "block")
        if action == "skip":
            aws_action = {"Count": {}}
        else:
            aws_act = rule.get("aws_action", action)
            aws_action = ACTION_MAP.get(aws_act, {"Block": {}})

        rn = unique_rule_name(rule["name"])
        waf_rule = {
            "Name": rn, "Priority": priority,
            "Action": aws_action, "Statement": stmt,
            "VisibilityConfig": {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True,
                                 "MetricName": rn},
        }

        # Skip rule labels
        if action == "skip" and rule.get("labels"):
            waf_rule["RuleLabels"] = [{"Name": l} for l in rule["labels"]]

        all_rules.append(waf_rule)
        priority += 1

    # Rate-Limiting Rules
    for rule in ir.get("rate_limiting_rules", {}).get("rules", []):
        if rule.get("convertibility") == "no":
            continue
        rate_rule_count += 1
        cond = rule.get("conditions") or rule.get("convertible_conditions")

        ctx = {"wcu": wcu, "refs": refs, "warnings": warnings,
               "rule_name": rule["name"], "ip_list_map": ip_list_map,
               "asn_lists": asn_lists, "inline_ip_set_ids": inline_ip_set_ids,
               "current_rule_ip_sets": rule.get("ip_sets", [])}

        rate_stmt = {
            "RateBasedStatement": {
                "Limit": rule.get("aws_limit", 100),
                "AggregateKeyType": "IP",
                "EvaluationWindowSec": rule.get("aws_evaluation_window_sec", 60),
            }
        }
        wcu.add(rule["name"], 2)

        # Build scope-down
        scope_parts = []
        if rule.get("scope_down", {}).get("skip_http_ratelimit"):
            scope_parts.append({"NotStatement": {"Statement": {"LabelMatchStatement": {
                "Scope": "LABEL", "Key": "skip:http_ratelimit"}}}})
            wcu.add(rule["name"], 1)
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
        all_rules.append({
            "Name": rn, "Priority": priority,
            "Action": aws_action, "Statement": rate_stmt,
            "VisibilityConfig": {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True,
                                 "MetricName": rn},
        })
        priority += 1

    # Managed rules (built separately, added per-WebACL)
    managed_rules, _ = build_managed_rules(priority, skip_labels_present, wcu)

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

    # Legacy mode: 2 WebACLs
    # Website WebACL: search engine label + Anti-DDoS with scope-down + customer rules + always-on challenge + managed
    se_rule = build_search_engine_label_rule(0)
    wcu.add("search-engine-label", 6)
    ddos_website = build_anti_ddos_rule(1, advanced=False,
                                         scope_down_exclude_labels=["custom:search-engine"])
    wcu.add("AntiDDoS-website", 250)

    # Find where rate rules end to insert always-on challenge
    rate_end_idx = len(all_rules)
    for idx, r in enumerate(all_rules):
        if "RateBasedStatement" not in r.get("Statement", {}):
            if idx > 0 and "RateBasedStatement" in all_rules[idx - 1].get("Statement", {}):
                rate_end_idx = idx
                break

    aoc_rule = build_always_on_challenge_rule(0)  # priority reassigned below
    wcu.add("always-on-challenge", 3)

    # Reassign priorities for website WebACL
    website_rules = [se_rule, ddos_website]
    p = 2
    for r in all_rules[:rate_end_idx]:
        r_copy = copy.deepcopy(r)
        r_copy["Priority"] = p
        website_rules.append(r_copy)
        p += 1
    aoc_rule["Priority"] = p
    website_rules.append(aoc_rule)
    p += 1
    for r in all_rules[rate_end_idx:]:
        r_copy = copy.deepcopy(r)
        r_copy["Priority"] = p
        website_rules.append(r_copy)
        p += 1
    for mr in managed_rules:
        mr_copy = copy.deepcopy(mr)
        mr_copy["Priority"] = p
        website_rules.append(mr_copy)
        p += 1

    resources["WebACLWebsite"] = build_webacl("waf-website", website_rules)

    # API/File WebACL: Anti-DDoS (challenge disabled) + customer rules + managed
    ddos_api = build_anti_ddos_rule(0, advanced=True)
    wcu.add("AntiDDoS-api", 250)
    api_rules = [ddos_api]
    p = 1
    for r in all_rules:
        r_copy = copy.deepcopy(r)
        r_copy["Priority"] = p
        api_rules.append(r_copy)
        p += 1
    for mr in managed_rules:
        mr_copy = copy.deepcopy(mr)
        mr_copy["Priority"] = p
        api_rules.append(mr_copy)
        p += 1

    resources["WebACLApiFile"] = build_webacl("waf-api-file", api_rules)

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

    errors = []
    if wcu.total > MAX_WCU:
        errors.append(f"WCU total {wcu.total} exceeds maximum {MAX_WCU}")
    elif wcu.total > WARN_WCU:
        warnings.append(f"WCU total {wcu.total} exceeds {WARN_WCU} (extra charges apply)")
    if refs.count > MAX_REF_STATEMENTS:
        errors.append(f"Reference statements {refs.count} exceeds maximum {MAX_REF_STATEMENTS} per WebACL")
    if rate_rule_count > MAX_RATE_RULES:
        errors.append(f"Rate-based rules {rate_rule_count} exceeds maximum {MAX_RATE_RULES}")
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

    return template, wcu, refs, warnings, errors


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

    for lst in split_ir.get("ip_lists", []):
        name = lst.get("name", "")
        conv = lst.get("conversion", "")
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

    for domain, domain_data in split_ir.get("domains", {}).items():
        domain_wcu = WCUTracker()
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

        acl_rules = []
        p = 0

        # Injected: search engine label
        acl_rules.append(build_search_engine_label_rule(p))
        domain_wcu.add("search-engine-label", 6)
        p += 1

        # Injected: Anti-DDoS with scope-down
        acl_rules.append(build_anti_ddos_rule(p, advanced=False,
                                               scope_down_exclude_labels=["custom:search-engine"]))
        domain_wcu.add("AntiDDoS", 250)
        p += 1

        # IP Access Rules
        for rule in domain_data.get("ip_access_rules", []):
            if rule.get("convertibility") == "no":
                continue
            cond = rule.get("conditions")
            if not cond:
                continue
            ctx = {"wcu": domain_wcu, "refs": refs, "warnings": warnings,
                   "rule_name": rule["name"], "ip_list_map": ip_list_map,
                   "asn_lists": asn_lists, "inline_ip_set_ids": inline_ip_set_ids,
                   "current_rule_ip_sets": rule.get("ip_sets", [])}
            stmt = conditions_to_statement(cond, ctx)
            aws_action = ACTION_MAP.get(rule.get("mode", "block"), {"Block": {}})
            rn = unique_rule_name(rule["name"])
            acl_rules.append({
                "Name": rn, "Priority": p,
                "Action": aws_action, "Statement": stmt,
                "VisibilityConfig": {"SampledRequestsEnabled": True,
                                     "CloudWatchMetricsEnabled": True, "MetricName": rn},
            })
            p += 1

        # Custom Rules
        for rule in domain_data.get("custom_rules", []):
            if rule.get("convertibility") == "no":
                continue
            cond = rule.get("conditions") or rule.get("convertible_conditions")
            if not cond:
                continue
            ctx = {"wcu": domain_wcu, "refs": refs, "warnings": warnings,
                   "rule_name": rule["name"], "ip_list_map": ip_list_map,
                   "asn_lists": asn_lists, "inline_ip_set_ids": inline_ip_set_ids,
                   "current_rule_ip_sets": rule.get("ip_sets", [])}
            stmt = conditions_to_statement(cond, ctx)

            if rule.get("scope_down", {}).get("skip_all_remaining_custom_rules"):
                not_label = {"NotStatement": {"Statement": {"LabelMatchStatement": {
                    "Scope": "LABEL", "Key": "skip:all_remaining_custom_rules"}}}}
                if "AndStatement" in stmt:
                    stmt["AndStatement"]["Statements"].insert(0, not_label)
                else:
                    stmt = {"AndStatement": {"Statements": [not_label, stmt]}}
                domain_wcu.add(rule["name"], 1)

            action = rule.get("action", "block")
            if action == "skip":
                aws_action = {"Count": {}}
            else:
                aws_act = rule.get("aws_action", action)
                aws_action = ACTION_MAP.get(aws_act, {"Block": {}})

            rn = unique_rule_name(rule["name"])
            waf_rule = {
                "Name": rn, "Priority": p,
                "Action": aws_action, "Statement": stmt,
                "VisibilityConfig": {"SampledRequestsEnabled": True,
                                     "CloudWatchMetricsEnabled": True, "MetricName": rn},
            }
            if action == "skip" and rule.get("labels"):
                waf_rule["RuleLabels"] = [{"Name": l} for l in rule["labels"]]
            acl_rules.append(waf_rule)
            p += 1

        # Rate-Limiting Rules
        for rule in domain_data.get("rate_limiting_rules", []):
            if rule.get("convertibility") == "no":
                continue
            cond = rule.get("conditions") or rule.get("convertible_conditions")
            ctx = {"wcu": domain_wcu, "refs": refs, "warnings": warnings,
                   "rule_name": rule["name"], "ip_list_map": ip_list_map,
                   "asn_lists": asn_lists, "inline_ip_set_ids": inline_ip_set_ids,
                   "current_rule_ip_sets": rule.get("ip_sets", [])}
            rate_stmt = {"RateBasedStatement": {
                "Limit": rule.get("aws_limit", 100),
                "AggregateKeyType": "IP",
                "EvaluationWindowSec": rule.get("aws_evaluation_window_sec", 60),
            }}
            domain_wcu.add(rule["name"], 2)
            scope_parts = []
            if rule.get("scope_down", {}).get("skip_http_ratelimit"):
                scope_parts.append({"NotStatement": {"Statement": {"LabelMatchStatement": {
                    "Scope": "LABEL", "Key": "skip:http_ratelimit"}}}})
                domain_wcu.add(rule["name"], 1)
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
            acl_rules.append({
                "Name": rn, "Priority": p,
                "Action": aws_action, "Statement": rate_stmt,
                "VisibilityConfig": {"SampledRequestsEnabled": True,
                                     "CloudWatchMetricsEnabled": True, "MetricName": rn},
            })
            p += 1

        # Injected: always-on challenge (after rate rules, before managed)
        acl_rules.append(build_always_on_challenge_rule(p))
        domain_wcu.add("always-on-challenge", 3)
        p += 1

        # Managed rules
        managed, p = build_managed_rules(p, skip_labels_present, domain_wcu)
        acl_rules.extend(managed)

        total_rules += len(acl_rules)

        # Track max WCU
        if domain_wcu.total > max_wcu:
            max_wcu = domain_wcu.total
            max_wcu_domain = domain
        if domain_wcu.total > MAX_WCU:
            warnings.append(f"Domain {domain}: WCU {domain_wcu.total} exceeds {MAX_WCU}")
        elif domain_wcu.total > WARN_WCU:
            w = f"WCU {domain_wcu.total} exceeds {WARN_WCU} (extra charges apply)"
            if w not in seen_warnings:
                seen_warnings.add(w)
                warnings.append(f"Domain {domain}: {w}")

        # Check per-WebACL IP set refs (hard limit: 50)
        if refs.count > MAX_REF_STATEMENTS:
            exceeded_domains.append(f"{domain}: {refs.count} refs > {MAX_REF_STATEMENTS}")
            domain_ref_counts[domain] = refs.count
            # Don't merge referenced_ids — avoid orphan IP sets in template
            continue

        domain_ref_counts[domain] = refs.count
        all_referenced_ids |= refs.referenced_ids
        all_referenced_asn_lists |= refs.referenced_asn_lists

        # Deduplicate warnings
        for w in list(warnings):
            if w in seen_warnings:
                continue
            seen_warnings.add(w)

        webacl_name = sanitize_webacl_name(domain)
        lid = f"WebACL{sanitize_logical_id(domain)}"
        lid_unique = unique_id(lid)
        resources[lid_unique] = {
            "Type": "AWS::WAFv2::WebACL",
            "Properties": {
                "Name": webacl_name, "Scope": "CLOUDFRONT",
                "DefaultAction": {"Allow": {}},
                "Rules": acl_rules,
                "VisibilityConfig": {"SampledRequestsEnabled": True,
                                     "CloudWatchMetricsEnabled": True,
                                     "MetricName": sanitize_rule_name(webacl_name)},
            }
        }

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

    # All domains exceeded — fatal
    if exceeded_domains and len(exceeded_domains) == len(split_ir.get("domains", {})):
        errors = [f"All {len(exceeded_domains)} domains exceed {MAX_REF_STATEMENTS} ref statement limit"]
    else:
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

    return template, max_wcu, max_wcu_domain, warnings, errors, exceeded_domains, dedup, domain_ref_counts


# ── WAFv2 API throttle mitigation ─────────────────────────────────────────────

THROTTLE_BATCH_SIZE = 5  # WAFv2 Create/Update = 1 TPS; batches of 5 with retry


def _add_throttle_chains(template):
    """Add DependsOn chains to WAFv2 resources to avoid API throttling.

    WAFv2 write API limit is 1 TPS (fixed, non-adjustable). CloudFormation
    creates resources in parallel by default, causing ThrottlingException
    when many IP sets or WebACLs are created simultaneously.

    Strategy: chain resources of the same type in batches. Each batch of N
    resources depends on the previous batch's last resource, forcing serial
    batch execution. Within a batch, resources are created in parallel
    (CloudFormation retries handle the 1 TPS limit for small batches).
    """
    resources = template.get("Resources", {})

    for rtype in ("AWS::WAFv2::IPSet", "AWS::WAFv2::WebACL"):
        lids = [lid for lid, res in resources.items() if res["Type"] == rtype]
        if len(lids) <= THROTTLE_BATCH_SIZE:
            continue
        # Chain: batch N depends on last resource of batch N-1
        for i in range(THROTTLE_BATCH_SIZE, len(lids), THROTTLE_BATCH_SIZE):
            anchor = lids[i - 1]  # last resource of previous batch
            batch_end = min(i + THROTTLE_BATCH_SIZE, len(lids))
            for j in range(i, batch_end):
                res = resources[lids[j]]
                deps = res.get("DependsOn", [])
                if isinstance(deps, str):
                    deps = [deps]
                if anchor not in deps:
                    deps.append(anchor)
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
        template, max_wcu_val, max_wcu_domain, warnings, errors, exceeded_domains, dedup, domain_ref_counts = generate_split(split_ir)
        wcu_display = f"WCU={max_wcu_val} (max, {max_wcu_domain})"
    else:
        ir_path = os.path.join(output_dir, "waf_ir.json")
        if not os.path.exists(ir_path):
            print(f"ERROR: {ir_path} not found", file=sys.stderr)
            sys.exit(1)
        with open(ir_path) as f:
            ir = json.load(f)
        template, wcu, refs, warnings, errors = generate(ir)
        max_wcu_val = wcu.total
        wcu_display = f"WCU={wcu.total}"
        exceeded_domains = []
        dedup = False
        domain_ref_counts = {}

    # Count resources for metadata
    num_ip_sets = sum(1 for r in template["Resources"].values() if r["Type"] == "AWS::WAFv2::IPSet")

    # Write metadata for downstream scripts (readme)
    meta = {"mode": mode, "dedup": dedup, "ip_sets_total": num_ip_sets}
    if mode == "legacy":
        meta["ref_count_per_webacl"] = refs.count
    else:
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

    # Handle ref count exceeded in legacy mode
    ref_exceeded = any("Reference statements" in e for e in errors)
    if ref_exceeded and mode == "legacy":
        if force_no_split:
            # Default behavior — downgrade to warning, add POST_ACTION for LLM
            ref_count = next((int(e.split()[2]) for e in errors if "Reference statements" in e), 0)
            for e in errors:
                if "Reference statements" in e:
                    print(f"  WARN: {e}", file=sys.stderr)
            errors = [e for e in errors if "Reference statements" not in e]
            # Store for POST_ACTION output
            meta["ref_exceeded"] = ref_count
        else:
            # --split mode would have been used; this path shouldn't be reached
            ref_count = next((int(e.split()[2]) for e in errors if "Reference statements" in e), 0)
            print(f"\n---RESULT---\nSPEC: 1\nSTATUS: PARTIAL\n"
                  f"REF_COUNT: {ref_count}\nREF_LIMIT: {MAX_REF_STATEMENTS}")
            sys.exit(3)

    if errors:
        for e in errors:
            print(f"  ERROR: {e}", file=sys.stderr)
        print(f"\n---RESULT---\nSPEC: 1\nSTATUS: ERROR\nERRORS: {len(errors)}")
        sys.exit(2)

    # Handle split mode partial (some domains exceeded ref limit).
    # Exit 0 so pipeline.sh run_step doesn't treat it as failure.
    # PARTIAL status in ---RESULT--- tells orchestrator about skipped domains.
    if exceeded_domains:
        failed_items = "\n".join(f"  {d}" for d in exceeded_domains)
        print(f"OK (partial): {num_resources} resources, {num_webacls} WebACLs, "
              f"{num_ip_sets} IP sets, {wcu_display}")
        print(f"\n---RESULT---\nSPEC: 1\nSTATUS: PARTIAL\n"
              f"TEMPLATE_COUNT: {template_files['count']}\nTEMPLATES: {','.join(template_files['files'])}\n"
              f"TEMPLATE_SIZE: {compact_size}\n"
              f"RESOURCES: {num_resources}\nWEBACLS: {num_webacls}\n"
              f"IP_SETS: {num_ip_sets}\nWCU: {max_wcu_val}\nMODE: {mode}\n"
              f"SUCCEEDED: {num_webacls}\nFAILED: {len(exceeded_domains)}\n"
              f"FAILED_ITEMS:\n{failed_items}")
        return  # exit 0

    print(f"OK: {num_resources} resources, {num_webacls} WebACLs, "
          f"{num_ip_sets} IP sets, {wcu_display}")
    result_block = (f"\n---RESULT---\nSPEC: 1\nSTATUS: OK\n"
          f"TEMPLATE_COUNT: {template_files['count']}\nTEMPLATES: {','.join(template_files['files'])}\n"
          f"TEMPLATE_SIZE: {compact_size}\n"
          f"RESOURCES: {num_resources}\nWEBACLS: {num_webacls}\n"
          f"IP_SETS: {num_ip_sets}\nWCU: {max_wcu_val}\nMODE: {mode}")
    print(result_block)


if __name__ == "__main__":
    main()
