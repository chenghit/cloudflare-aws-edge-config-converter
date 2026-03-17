"""Cloudflare expression parser — Phase 1 (regex + string ops, no AST).

Parses simple Cloudflare rule expressions into structured conditions.
Complex expressions are left as raw_expression for LLM (Stage 8 tf-domain).

Returns (condition, raw_expression) — exactly one is non-None.
"""
import re

# ── helpers ──────────────────────────────────────────────────────────────────

def _strip_outer_parens(expr):
    """Remove one layer of wrapping parentheses if balanced."""
    e = expr.strip()
    if e.startswith("(") and e.endswith(")"):
        depth, i = 0, 0
        for ch in e:
            if ch == "(": depth += 1
            elif ch == ")": depth -= 1
            if depth == 0 and i < len(e) - 1:
                return e  # closing paren is not the last char
            i += 1
        return e[1:-1].strip()
    return e


def _parse_in_set(raw):
    """Parse '{\"a\" \"b\" \"c\"}' or '{1.2.3.4 5.6.7.8}' into a list."""
    inner = raw.strip().strip("{}")
    # Quoted strings: "val1" "val2"
    quoted = re.findall(r'"([^"]*)"', inner)
    if quoted:
        return quoted
    # Unquoted tokens (IPs, numbers)
    return inner.split()


def _parse_full_uri_wildcard(pattern):
    """Split full_uri wildcard pattern into (host_pattern, path_pattern).

    e.g. 'https://*.c.example.com/files/*' → ('*.c.example.com', '/files/*')
         'https://cdn.c.example.com/host/*' → ('cdn.c.example.com', '/host/*')
    """
    # Strip optional r prefix and quotes
    p = pattern.strip()
    if p.startswith('r"') or p.startswith("r'"):
        p = p[2:-1]
    elif p.startswith('"') or p.startswith("'"):
        p = p[1:-1]

    m = re.match(r'https?://([^/]+)(/.*)$', p)
    if m:
        return m.group(1), m.group(2)
    return None, None


# ── field → condition field mapping ──────────────────────────────────────────

CF_FIELD_MAP = {
    "http.request.uri.path": "uri.path",
    "http.request.uri": "uri",
    "http.request.uri.query": "uri.query",
    "http.request.uri.path.extension": "uri.path.extension",
    "http.host": "host",
    "http.user_agent": "user_agent",
    "http.referer": "referer",
    "http.request.method": "method",
    "http.request.version": "http_version",
    "http.request.full_uri": "full_uri",
    "ip.src": "ip.src",
    "ip.src.country": "country",
    "ip.src.continent": "continent",
    "ip.src.city": "city",
    "ip.src.region": "region",
    "ip.src.region_code": "region_code",
    "ip.src.lat": "latitude",
    "ip.src.lon": "longitude",
    "ip.src.postal_code": "postal_code",
    "ip.src.metro_code": "metro_code",
    "ip.src.timezone.name": "timezone",
    "ip.src.asnum": "asnum",
    "ip.src.is_in_european_union": "is_eu",
    "ip.src.subdivision_1_iso_code": "subdivision_1",
    "http.response.code": "response_code",
}

# Fields that need ORP headers
FIELD_TO_ORP_HEADERS = {
    "country": ["CloudFront-Viewer-Country"],
    "continent": ["CloudFront-Viewer-Country"],  # + KVS
    "is_eu": ["CloudFront-Viewer-Country"],       # + KVS
    "city": ["CloudFront-Viewer-City"],
    "region": ["CloudFront-Viewer-Country-Region-Name"],
    "region_code": ["CloudFront-Viewer-Country-Region"],
    "subdivision_1": ["CloudFront-Viewer-Country", "CloudFront-Viewer-Country-Region"],
    "latitude": ["CloudFront-Viewer-Latitude"],
    "longitude": ["CloudFront-Viewer-Longitude"],
    "postal_code": ["CloudFront-Viewer-Postal-Code"],
    "metro_code": ["CloudFront-Viewer-Metro-Code"],
    "timezone": ["CloudFront-Viewer-Time-Zone"],
    "asnum": ["CloudFront-Viewer-ASN"],
    "http_version": ["CloudFront-Viewer-Http-Version"],
}

# Fields that trigger KVS requirements
FIELD_KVS_TRIGGERS = {
    "continent": "needs_continent",
    "is_eu": "needs_eu",
}


# ── single-condition parsers ─────────────────────────────────────────────────

# Order matters: longer field names first to avoid partial matches
_FIELD_PATTERN = "|".join(
    re.escape(f) for f in sorted(CF_FIELD_MAP.keys(), key=len, reverse=True)
)

# Pattern: field op value
_RE_EQ = re.compile(
    rf'({_FIELD_PATTERN})\s+(eq|ne|gt|ge|lt|le)\s+"([^"]*)"'
)
_RE_EQ_NUM = re.compile(
    rf'({_FIELD_PATTERN})\s+(eq|ne|gt|ge|lt|le)\s+(\d+)'
)
_RE_WILDCARD = re.compile(
    rf'({_FIELD_PATTERN})\s+wildcard\s+r?"([^"]*)"'
)
_RE_MATCHES = re.compile(
    rf'({_FIELD_PATTERN})\s+matches\s+r?"([^"]*)"'
)
_RE_CONTAINS = re.compile(
    rf'({_FIELD_PATTERN})\s+contains\s+"([^"]*)"'
)
_RE_IN_SET = re.compile(
    rf'({_FIELD_PATTERN})\s+in\s+(\{{[^}}]*\}})'
)
_RE_IN_LIST = re.compile(
    rf'({_FIELD_PATTERN})\s+in\s+\$(\w+)'
)
_RE_STARTS_WITH = re.compile(
    rf'starts_with\(({_FIELD_PATTERN}),\s*"([^"]*)"\)'
)
_RE_ENDS_WITH = re.compile(
    rf'ends_with\(({_FIELD_PATTERN}),\s*"([^"]*)"\)'
)
# Boolean field (no operator): ip.src.is_in_european_union
_RE_BOOL_FIELD = re.compile(
    r'^(ip\.src\.is_in_european_union)$'
)


def _try_simple_regex_to_wildcard(regex_str):
    """Convert trivial regex to wildcard. Returns wildcard string or None."""
    # ^/literal-prefix/(.*)  → /literal-prefix/*
    m = re.match(r'^\^(/[^()\[\]{}|+?*\\]+)/\(\.\*\)$', regex_str)
    if m:
        return m.group(1) + "/*"
    # ^/literal$  → /literal (exact)
    m = re.match(r'^\^(/[^()\[\]{}|+?*\\]+)\$$', regex_str)
    if m:
        return m.group(1)
    return None


def _parse_single_condition(expr):
    """Try to parse a single atomic condition. Returns condition dict or None."""
    e = expr.strip()

    # Boolean field
    m = _RE_BOOL_FIELD.match(e)
    if m:
        mapped = CF_FIELD_MAP.get(m.group(1))
        if mapped:
            return {"field": mapped, "op": "eq", "value": True}

    # not <expr>
    if e.startswith("not "):
        inner = _parse_single_condition(e[4:].strip())
        if inner:
            inner["op"] = "not_" + inner["op"]
            return inner
        return None

    # starts_with(field, "value")
    m = _RE_STARTS_WITH.search(e)
    if m:
        mapped = CF_FIELD_MAP.get(m.group(1))
        if mapped:
            return {"field": mapped, "op": "starts_with", "value": m.group(2)}

    # ends_with(field, "value")
    m = _RE_ENDS_WITH.search(e)
    if m:
        mapped = CF_FIELD_MAP.get(m.group(1))
        if mapped:
            return {"field": mapped, "op": "ends_with", "value": m.group(2)}

    # field in $list_name
    m = _RE_IN_LIST.search(e)
    if m:
        mapped = CF_FIELD_MAP.get(m.group(1))
        if mapped:
            return {"field": mapped, "op": "in_list", "value": "$" + m.group(2)}

    # field in {set}
    m = _RE_IN_SET.search(e)
    if m:
        mapped = CF_FIELD_MAP.get(m.group(1))
        if mapped:
            return {"field": mapped, "op": "in", "value": _parse_in_set(m.group(2))}

    # field wildcard "pattern"
    m = _RE_WILDCARD.search(e)
    if m:
        field_name = m.group(1)
        pattern = m.group(2)
        mapped = CF_FIELD_MAP.get(field_name)
        if mapped == "full_uri":
            host_pat, path_pat = _parse_full_uri_wildcard(pattern)
            if host_pat and path_pat:
                return {
                    "field": "full_uri", "op": "wildcard", "value": pattern,
                    "host_pattern": host_pat, "path_pattern": path_pat,
                }
        if mapped:
            return {"field": mapped, "op": "wildcard", "value": pattern}

    # field matches "regex"
    m = _RE_MATCHES.search(e)
    if m:
        mapped = CF_FIELD_MAP.get(m.group(1))
        regex_str = m.group(2)
        if mapped:
            wc = _try_simple_regex_to_wildcard(regex_str)
            if wc:
                return {"field": mapped, "op": "wildcard", "value": wc}
            # Complex regex → cannot parse
            return None

    # field contains "value"
    m = _RE_CONTAINS.search(e)
    if m:
        mapped = CF_FIELD_MAP.get(m.group(1))
        if mapped:
            return {"field": mapped, "op": "contains", "value": m.group(2)}

    # field eq/ne/gt/ge/lt/le "string"
    m = _RE_EQ.search(e)
    if m:
        mapped = CF_FIELD_MAP.get(m.group(1))
        if mapped:
            return {"field": mapped, "op": m.group(2), "value": m.group(3)}

    # field eq/ne/gt/ge/lt/le number
    m = _RE_EQ_NUM.search(e)
    if m:
        mapped = CF_FIELD_MAP.get(m.group(1))
        if mapped:
            return {"field": mapped, "op": m.group(2), "value": int(m.group(3))}

    return None


# ── top-level parser ─────────────────────────────────────────────────────────

def _split_and(expr):
    """Split 'A and B' at the top level (not inside parens)."""
    depth = 0
    tokens = []
    current = []
    for ch in expr:
        if ch == "(":
            depth += 1
            current.append(ch)
        elif ch == ")":
            depth -= 1
            current.append(ch)
        else:
            current.append(ch)
        # Check for ' and ' at depth 0
        s = "".join(current)
        if depth == 0 and s.endswith(" and "):
            tokens.append(s[:-5].strip())
            current = []
    tokens.append("".join(current).strip())
    return [t for t in tokens if t]


def _has_or(expr):
    """Check if expression contains top-level OR."""
    depth = 0
    for i, ch in enumerate(expr):
        if ch == "(": depth += 1
        elif ch == ")": depth -= 1
        if depth == 0 and expr[i:i+4] == " or ":
            return True
    return False


def parse_expression(expression):
    """Parse a Cloudflare expression string.

    Returns:
        (condition, raw_expression): exactly one is non-None.
        condition can be:
          - {"always": True}
          - {"field": ..., "op": ..., "value": ...}
          - {"logic": "and", "parts": [...]}
    """
    expr = expression.strip()

    # Unconditional
    if expr == "true":
        return {"always": True}, None

    # Contains OR → too complex
    if _has_or(expr):
        return None, expression

    # Strip outer parens
    expr = _strip_outer_parens(expr)

    # Try dual AND first (before single, to avoid partial matches)
    # 3+ AND conditions: _split_and returns 3+ parts, falls through to raw_expression
    parts = _split_and(expr)
    if len(parts) == 2:
        c1 = _parse_single_condition(_strip_outer_parens(parts[0]))
        c2 = _parse_single_condition(_strip_outer_parens(parts[1]))
        if c1 and c2:
            return {"logic": "and", "parts": [c1, c2]}, None

    # Try single condition (only if not an AND expression)
    if len(parts) == 1:
        cond = _parse_single_condition(expr)
        if cond:
            return cond, None

    # Cannot parse
    return None, expression


def extract_orp_headers(condition):
    """Extract required ORP headers from a parsed condition."""
    if condition is None:
        return []
    headers = set()
    _collect_orp(condition, headers)
    return sorted(headers)


def extract_orp_headers_from_raw(raw_expression):
    """Extract required ORP headers by scanning a raw expression string for field names."""
    if not raw_expression:
        return []
    headers = set()
    # Scan for known field names that need ORP headers
    for cf_field, mapped_field in CF_FIELD_MAP.items():
        if cf_field in raw_expression and mapped_field in FIELD_TO_ORP_HEADERS:
            for h in FIELD_TO_ORP_HEADERS[mapped_field]:
                headers.add(h)
    return sorted(headers)


def _collect_orp(cond, headers):
    if "logic" in cond:
        for p in cond.get("parts", []):
            _collect_orp(p, headers)
    elif "field" in cond:
        for h in FIELD_TO_ORP_HEADERS.get(cond["field"], []):
            headers.add(h)


def extract_kvs_triggers(condition):
    """Return set of kvs requirement keys triggered by this condition."""
    if condition is None:
        return set()
    triggers = set()
    _collect_kvs(condition, triggers)
    return triggers


def _collect_kvs(cond, triggers):
    if "logic" in cond:
        for p in cond.get("parts", []):
            _collect_kvs(p, triggers)
    elif "field" in cond:
        t = FIELD_KVS_TRIGGERS.get(cond["field"])
        if t:
            triggers.add(t)


def extract_host_filter(condition, expression):
    """Determine which hostnames this rule applies to.

    Returns:
        list of hostnames, or None if global (applies to all).
    """
    if condition is None:
        # raw_expression — scan the original expression for http.host
        return _scan_host_from_expression(expression)
    if condition.get("always"):
        return None  # global
    return _scan_host_from_condition(condition)


def _scan_host_from_condition(cond):
    """Extract host filter from parsed condition."""
    if "logic" in cond:
        for p in cond.get("parts", []):
            hosts = _scan_host_from_condition(p)
            if hosts is not None:
                return hosts
        return None
    field = cond.get("field", "")
    if field == "host":
        op = cond.get("op", "")
        val = cond.get("value")
        if op == "eq" and isinstance(val, str):
            return [val]
        if op == "in" and isinstance(val, list):
            return val
    if field == "full_uri":
        hp = cond.get("host_pattern")
        if hp:
            return [hp]  # may contain wildcard
    return None


def _scan_host_from_expression(expr):
    """Regex scan for http.host references in raw expression."""
    if not expr:
        return None
    # http.host eq "X"
    m = re.search(r'http\.host\s+eq\s+"([^"]*)"', expr)
    if m:
        return [m.group(1)]
    # http.host in {"X" "Y"}
    m = re.search(r'http\.host\s+in\s+(\{[^}]*\})', expr)
    if m:
        return _parse_in_set(m.group(1))
    # full_uri wildcard with host
    m = re.search(r'http\.request\.full_uri\s+wildcard\s+r?"([^"]*)"', expr)
    if m:
        host, _ = _parse_full_uri_wildcard(m.group(1))
        if host:
            return [host]
    return None


# ── path pattern extraction ──────────────────────────────────────────────────

def extract_path_pattern_single(cond):
    """Extract a CloudFront path pattern from a single condition."""
    field = cond.get("field", "")
    op = cond.get("op", "")
    val = cond.get("value", "")
    if field in ("uri.path", "uri"):
        if op == "wildcard":
            return val
        if op == "eq":
            return val
        if op == "starts_with":
            return val + "*" if not val.endswith("*") else val
        if op == "ends_with":
            return "*" + val
    if field == "uri.path.extension":
        if op == "in" and isinstance(val, list):
            if len(val) == 1:
                return f"*.{val[0]}"
            # Multiple extensions: create individual behaviors for bypass/TTL rules
            # but for viewer_request_ops, use default behavior
            return "*"
    if field == "full_uri":
        pp = cond.get("path_pattern")
        if pp:
            return pp
    return "*"
