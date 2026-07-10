"""Cloudflare expression parser — Phase 1 (regex + string ops, no AST).

Parses simple Cloudflare rule expressions into structured conditions.
Complex expressions are left as raw_expression for cdn-generate-js.py
(which generates JS condition code or a // TODO comment).

Returns (condition, raw_expression) — exactly one is non-None.
"""
import re

# ── helpers ──────────────────────────────────────────────────────────────────

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
    "ip.src.subdivision_2_iso_code": "subdivision_2",
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

# Short field names (post CF_FIELD_MAP) that have NO CloudFront source and
# cannot be evaluated in a CloudFront Function or Lambda@Edge. A rule (or the
# single header op) that references one of these — as a match condition field
# or as an action value — is non-convertible and must be reported, not emitted
# as a bare JS identifier (which would throw ReferenceError at runtime).
UNMAPPABLE_FIELDS = {
    # ip.src.subdivision_2_iso_code — CloudFront exposes only the first-level
    # subdivision (CloudFront-Viewer-Country-Region); there is no header for the
    # second-level (county/district) subdivision. subdivision_1 IS convertible
    # and is intentionally NOT listed here.
    "subdivision_2",
}

# Short field names sourceable ONLY in the viewer-response phase. In a
# request-phase context (redirect/rewrite/query action values, viewer-request
# conditions) they have no source and are non-convertible.
RESPONSE_ONLY_FIELDS = {
    "response_code",  # http.response.code — only available as response.statusCode
}


def field_convertibility(cf_field, target="cff"):
    """Classify a raw Cloudflare field name for CDN (CFF/Lambda) conversion.

    Returns (convertible: bool, reason: str). A field is non-convertible when
    Cloudflare exposes it but CloudFront has no way to source it at the edge
    (bot/WAF scores, TLS details, ray id, JWT claims, geo subdivisions, ...).

    ``target`` is the phase the field is used in — "cff"/"lambda" mean
    viewer-request (or a request-phase action value), "response" means
    viewer-response. A response-only field (http.response.code) is convertible
    only when target == "response"; used in a request-phase value it has no
    source and must be reported, not emitted as a leaked marker.
    """
    short = CF_FIELD_MAP.get(cf_field)
    if short is None:
        return False, f"Cloudflare field '{cf_field}' has no CloudFront equivalent"
    if short in UNMAPPABLE_FIELDS:
        return False, f"Cloudflare field '{cf_field}' has no CloudFront edge source"
    if short in RESPONSE_ONLY_FIELDS and target != "response":
        return False, f"Cloudflare field '{cf_field}' is only available in the response phase"
    return True, ""


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

def split_or(expr):
    """Split 'A or B or C' at the top level (not inside parens).

    Exported for use by preprocess (cache rule OR path splitting).
    """
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
        s = "".join(current)
        if depth == 0 and s.endswith(" or "):
            tokens.append(s[:-4].strip())
            current = []
    tokens.append("".join(current).strip())
    return [t for t in tokens if t]


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

    # Everything else goes through the full recursive-descent parser, which
    # produces a proper structured {"logic": "or"/"and"/"not", ...} tree for OR,
    # AND, nested groups, and NOT alike. The old hand-rolled AND/single-condition
    # path here was OR-blind — `A and (B or C)` split on the top-level AND and
    # then parsed `(B or C)` with a single-condition regex that silently dropped
    # the OR branch. The full parser handles all of these correctly; we only
    # defer to raw_expression when it genuinely cannot parse the text.
    try:
        return parse_expression_full(expr), None
    except (_ParseError, RecursionError):
        return None, expression


def iter_condition_children(cond):
    """Yield the direct child condition nodes of a logic node.

    A condition tree has two logic shapes: AND/OR store children under "parts",
    NOT stores its single child under "item". Every tree walker MUST descend
    through both, or it silently skips whatever sits under a NOT — the bug class
    that surfaced when parse_expression started structuring OR/NOT instead of
    deferring to raw text. Route all walkers through this so none can forget.
    """
    if not isinstance(cond, dict):
        return
    for p in cond.get("parts", []):
        yield p
    if "item" in cond:
        yield cond["item"]


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
        for child in iter_condition_children(cond):
            _collect_orp(child, headers)
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
        for child in iter_condition_children(cond):
            _collect_kvs(child, triggers)
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
        # Deliberately do NOT descend into a NOT node's "item": a host inside a
        # negation ("not http.host eq x") is an EXCLUSION, not a positive scope —
        # returning it as the host filter would scope the rule to exactly the
        # host it excludes. A negated host condition means "applies globally".
        if cond.get("logic") == "not":
            return None
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


# ── Full recursive descent parser (Phase 2) ─────────────────────────────────
# Handles OR, nested AND/OR, NOT — eliminates raw_expression fallback.
# Output format matches Phase 1: {"field": "uri.path", "op": "eq", "value": "/api"}

class _ParseError(Exception):
    pass


class _Token:
    __slots__ = ("type", "value", "pos")
    def __init__(self, type, value, pos):
        self.type = type
        self.value = value
        self.pos = pos


# Token types
_TT_FIELD = 1
_TT_STRING = 2
_TT_NUMBER = 3
_TT_LBRACE = 4
_TT_RBRACE = 5
_TT_LPAREN = 6
_TT_RPAREN = 7
_TT_COMMA = 8
_TT_DOLLAR = 9
_TT_AND = 10
_TT_OR = 11
_TT_NOT = 12
_TT_OP = 13
_TT_EOF = 14

_OPS = {"eq", "ne", "contains", "matches", "wildcard", "in", "gt", "lt", "ge", "le"}
_OP_CLIKE = {"==": "eq", "!=": "ne", "~": "matches", ">": "gt", "<": "lt", ">=": "ge", "<=": "le"}
_FUNC_OPS = {"starts_with", "ends_with", "lower", "upper", "len"}


def _tokenize_cdn(expr):
    tokens = []
    i = 0
    n = len(expr)
    while i < n:
        if expr[i].isspace():
            i += 1
            continue
        pos = i
        ch = expr[i]
        if ch == '(':
            tokens.append(_Token(_TT_LPAREN, '(', pos)); i += 1
        elif ch == ')':
            tokens.append(_Token(_TT_RPAREN, ')', pos)); i += 1
        elif ch == '{':
            tokens.append(_Token(_TT_LBRACE, '{', pos)); i += 1
        elif ch == '}':
            tokens.append(_Token(_TT_RBRACE, '}', pos)); i += 1
        elif ch == ',':
            tokens.append(_Token(_TT_COMMA, ',', pos)); i += 1
        elif ch == '$':
            tokens.append(_Token(_TT_DOLLAR, '$', pos)); i += 1
        elif expr[i:i+2] in ('==', '!=', '>=', '<='):
            tokens.append(_Token(_TT_OP, _OP_CLIKE[expr[i:i+2]], pos)); i += 2
        elif ch in ('>', '<'):
            tokens.append(_Token(_TT_OP, _OP_CLIKE[ch], pos)); i += 1
        elif ch == '~':
            tokens.append(_Token(_TT_OP, "matches", pos)); i += 1
        elif ch == '"' or (ch == 'r' and i + 1 < n and expr[i+1] == '"'):
            raw = ch == 'r'
            if raw:
                i += 1
            i += 1  # skip "
            start = i
            while i < n and expr[i] != '"':
                if not raw and expr[i] == '\\':
                    i += 2
                else:
                    i += 1
            val = expr[start:i]
            if i < n:
                i += 1
            tokens.append(_Token(_TT_STRING, val, pos))
        elif ch.isdigit() or (ch == '-' and i + 1 < n and expr[i+1].isdigit()):
            start = i
            if ch == '-':
                i += 1
            while i < n and (expr[i].isalnum() or expr[i] in '.:/'):
                i += 1
            val = expr[start:i]
            if re.fullmatch(r'-?\d+', val):
                tokens.append(_Token(_TT_NUMBER, int(val), pos))
            elif re.fullmatch(r'-?\d+\.\d+', val):
                tokens.append(_Token(_TT_NUMBER, float(val), pos))
            else:
                tokens.append(_Token(_TT_FIELD, val, pos))
        elif ch.isalpha() or ch == '_':
            start = i
            while i < n and (expr[i].isalnum() or expr[i] in '._'):
                i += 1
            word = expr[start:i]
            if word == "strict":
                j = i
                while j < n and expr[j].isspace():
                    j += 1
                if expr[j:j+8] == "wildcard":
                    tokens.append(_Token(_TT_OP, "strict_wildcard", pos)); i = j + 8; continue
            if word == "and":
                tokens.append(_Token(_TT_AND, "and", pos))
            elif word == "or":
                tokens.append(_Token(_TT_OR, "or", pos))
            elif word == "not":
                tokens.append(_Token(_TT_NOT, "not", pos))
            elif word in _OPS:
                tokens.append(_Token(_TT_OP, word, pos))
            else:
                tokens.append(_Token(_TT_FIELD, word, pos))
        else:
            raise _ParseError(f"Unexpected character: {ch!r} at position {pos}")
    tokens.append(_Token(_TT_EOF, None, len(expr)))
    return tokens


class _CDNParser:
    """Recursive descent parser producing CDN-format condition trees."""

    def __init__(self, tokens, expr):
        self.tokens = tokens
        self.expr = expr
        self.pos = 0

    def peek(self):
        return self.tokens[self.pos]

    def advance(self):
        t = self.tokens[self.pos]
        self.pos += 1
        return t

    def expect(self, tt):
        t = self.advance()
        if t.type != tt:
            raise _ParseError(f"Expected token type {tt}, got {t.type} ({t.value!r}) at pos {t.pos}")
        return t

    def parse(self):
        result = self._or_expr()
        if self.peek().type != _TT_EOF:
            t = self.peek()
            raise _ParseError(f"Unexpected token after expression: {t.value!r} at pos {t.pos}")
        return result

    def _or_expr(self):
        left = self._and_expr()
        items = [left]
        while self.peek().type == _TT_OR:
            self.advance()
            items.append(self._and_expr())
        if len(items) == 1:
            return items[0]
        return {"logic": "or", "parts": items}

    def _and_expr(self):
        left = self._not_expr()
        items = [left]
        while self.peek().type == _TT_AND:
            self.advance()
            items.append(self._not_expr())
        if len(items) == 1:
            return items[0]
        return {"logic": "and", "parts": items}

    def _not_expr(self):
        if self.peek().type == _TT_NOT:
            self.advance()
            inner = self._not_expr()
            # Flatten not into op: not {field, op: eq} → {field, op: not_eq}
            if "field" in inner and "op" in inner:
                inner["op"] = "not_" + inner["op"]
                return inner
            # not (logic expr) → wrap
            return {"logic": "not", "item": inner}
        return self._atom()

    def _atom(self):
        t = self.peek()
        if t.type == _TT_LPAREN:
            self.advance()
            result = self._or_expr()
            self.expect(_TT_RPAREN)
            return result
        if t.type == _TT_FIELD and t.value in _FUNC_OPS:
            return self._func_call()
        if t.type == _TT_FIELD:
            return self._field_expr()
        raise _ParseError(f"Unexpected token: {t.value!r} at pos {t.pos}")

    def _func_call(self):
        func_tok = self.advance()
        name = func_tok.value
        if name in ("lower", "upper"):
            self.expect(_TT_LPAREN)
            field = self.expect(_TT_FIELD).value
            self.expect(_TT_RPAREN)
            op = self._read_op()
            value = self._read_value()
            mapped = CF_FIELD_MAP.get(field, field)
            result = {"field": mapped, "op": op, "value": value}
            if name == "lower":
                result["transform"] = "lowercase"
            elif name == "upper":
                result["transform"] = "uppercase"
            return result
        if name in ("starts_with", "ends_with"):
            self.expect(_TT_LPAREN)
            field = self.expect(_TT_FIELD).value
            self.expect(_TT_COMMA)
            value = self._read_value()
            self.expect(_TT_RPAREN)
            mapped = CF_FIELD_MAP.get(field, field)
            return {"field": mapped, "op": name, "value": value}
        if name == "len":
            self.expect(_TT_LPAREN)
            field = self.expect(_TT_FIELD).value
            self.expect(_TT_RPAREN)
            op = self._read_op()
            value = self._read_value()
            mapped = CF_FIELD_MAP.get(field, field)
            return {"field": mapped, "op": op, "value": value, "size_check": True}
        raise _ParseError(f"Unknown function: {name}")

    def _field_expr(self):
        field_tok = self.advance()
        field = field_tok.value
        mapped = CF_FIELD_MAP.get(field, field)

        # Bare boolean field (no operator follows)
        if self.peek().type not in (_TT_OP,):
            return {"field": mapped, "op": "eq", "value": True}

        op_tok = self.advance()
        op = op_tok.value

        # "in" can be followed by $list or {set}
        if op == "in":
            t = self.peek()
            if t.type == _TT_DOLLAR:
                self.advance()
                list_name = self.expect(_TT_FIELD).value
                return {"field": mapped, "op": "in_list", "value": "$" + list_name}
            if t.type == _TT_LBRACE:
                values = self._read_set()
                return {"field": mapped, "op": "in", "value": values}
            raise _ParseError(f"Expected $ or {{ after 'in', got {t.value!r}")

        # wildcard / strict_wildcard with full_uri special handling
        if op in ("wildcard", "strict_wildcard"):
            value = self._read_value()
            if mapped == "full_uri":
                host_pat, path_pat = _parse_full_uri_wildcard(value)
                if host_pat and path_pat:
                    return {"field": "full_uri", "op": "wildcard", "value": value,
                            "host_pattern": host_pat, "path_pattern": path_pat}
            return {"field": mapped, "op": "wildcard" if op == "wildcard" else "strict_wildcard", "value": value}

        # matches — keep regex as-is, try simple wildcard conversion
        if op == "matches":
            value = self._read_value()
            wc = _try_simple_regex_to_wildcard(value)
            if wc:
                return {"field": mapped, "op": "wildcard", "value": wc}
            return {"field": mapped, "op": "matches", "value": value}

        # Standard comparison: eq, ne, contains, gt, lt, ge, le
        value = self._read_value()
        return {"field": mapped, "op": op, "value": value}

    def _read_op(self):
        t = self.expect(_TT_OP)
        return _OP_CLIKE.get(t.value, t.value) if t.value in _OP_CLIKE else t.value

    def _read_value(self):
        t = self.peek()
        if t.type == _TT_STRING:
            self.advance()
            return t.value
        if t.type == _TT_NUMBER:
            self.advance()
            return t.value
        if t.type == _TT_DOLLAR:
            self.advance()
            name = self.expect(_TT_FIELD).value
            return "$" + name
        if t.type == _TT_LBRACE:
            return self._read_set()
        raise _ParseError(f"Expected value, got {t.type} ({t.value!r}) at pos {t.pos}")

    def _read_set(self):
        self.expect(_TT_LBRACE)
        items = []
        while self.peek().type != _TT_RBRACE:
            t = self.peek()
            if t.type == _TT_STRING:
                self.advance()
                items.append(t.value)
            elif t.type == _TT_NUMBER:
                self.advance()
                items.append(t.value)
            elif t.type == _TT_FIELD:
                self.advance()
                items.append(t.value)
            else:
                raise _ParseError(f"Unexpected token in set: {t.value!r}")
        self.expect(_TT_RBRACE)
        return items


def parse_expression_full(expression):
    """Full recursive descent parse of a Cloudflare expression.

    Returns a conditions tree in CDN format (same as parse_expression() conditions).
    Raises _ParseError on failure — never returns raw_expression.

    Examples:
        parse_expression_full('http.request.uri.path eq "/api"')
        → {"field": "uri.path", "op": "eq", "value": "/api"}

        parse_expression_full('(A eq "1") or (B eq "2")')
        → {"logic": "or", "parts": [...]}
    """
    expr = expression.strip()
    if expr == "true":
        return {"always": True}
    tokens = _tokenize_cdn(expr)
    parser = _CDNParser(tokens, expr)
    return parser.parse()


# ── Dynamic expression parser ────────────────────────────────────────────────
# Parses Cloudflare action expressions: concat(), regex_replace(),
# wildcard_replace(), lower(), upper(), etc.

def parse_dynamic_expression(expr):
    """Parse a Cloudflare dynamic expression (used in action params).

    Returns a structured representation:
        {"func": "concat", "args": [{"type": "literal", "value": "/eu"}, ...]}
        {"type": "field", "value": "http.request.uri.path"}
        {"type": "literal", "value": "/static"}
    """
    expr = expr.strip()
    tokens = _tokenize_cdn(expr)
    parser = _DynExprParser(tokens, expr)
    result = parser.parse()
    return result


def _dyn_tree_fields(node):
    """Collect all field references (raw CF names) from a dynamic-expr tree.

    Recurses through every child of every node rather than white-listing known
    node types, so a field reference nested under a node shape this walker does
    not specifically know about is still surfaced (an unknown-but-field-bearing
    node must not slip past the unmappable-field screen). Only ``field`` nodes
    contribute a name; ``literal`` nodes contribute nothing.
    """
    if isinstance(node, list):
        out = []
        for item in node:
            out.extend(_dyn_tree_fields(item))
        return out
    if not isinstance(node, dict):
        return []
    if node.get("type") == "field":
        return [node["value"]]
    out = []
    for key, value in node.items():
        if key == "type":
            continue
        out.extend(_dyn_tree_fields(value))
    return out


def value_expression_unmappable(expr, target="cff"):
    """Given a header/redirect/rewrite dynamic action value expression, return
    a reason string if it references any non-convertible Cloudflare field, else
    None. Parse failures are treated as convertible here (the generator has its
    own fallback); this only flags fields with no CloudFront source.

    ``target`` is the phase the value is emitted in so response-only fields
    (http.response.code) are flagged when used in a request-phase value
    (redirect target, rewrite path/query) — matching the generator's
    target-aware _field_is_mappable.
    """
    try:
        tree = parse_dynamic_expression(expr)
    except Exception:
        return None
    for f in _dyn_tree_fields(tree):
        ok, reason = field_convertibility(f, target)
        if not ok:
            return reason
    return None


def condition_unmappable_fields(cond, target="cff"):
    """Walk a parsed condition tree; return list of (short_field, reason) for
    any field that has no CloudFront equivalent. The condition tree stores
    already-mapped short names for known fields and raw dotted names for
    unknown ones, so we check both forms against the convertibility rules.

    ``target`` is the phase the condition is evaluated in. A response-only field
    (response_code) in a request-phase condition ("cff"/"lambda") is unmappable
    — matching the generator, which would otherwise dead-code it to if(false)
    with no non_convertible report.
    """
    if not isinstance(cond, dict):
        return []
    if "logic" in cond:
        out = []
        for child in iter_condition_children(cond):
            out.extend(condition_unmappable_fields(child, target))
        return out
    field = cond.get("field")
    if field is None:
        return []
    # Known short names (values of CF_FIELD_MAP) are convertible unless listed
    # in UNMAPPABLE_FIELDS. A raw dotted name that never got mapped is unknown.
    if field in CF_FIELD_MAP.values():
        if field in UNMAPPABLE_FIELDS:
            return [(field, f"condition field '{field}' has no CloudFront edge source")]
        if field in RESPONSE_ONLY_FIELDS and target != "response":
            return [(field, f"condition field '{field}' is only available in the response phase")]
        return []
    if "." in field or field in UNMAPPABLE_FIELDS:
        return [(field, f"condition field '{field}' has no CloudFront equivalent")]
    return []


_DYN_FUNCS = {
    "concat", "regex_replace", "wildcard_replace", "lower", "upper",
    "to_string", "substring", "len", "url_decode", "encode_base64",
    "decode_base64", "lookup_json_string", "lookup_json_integer",
    "sha256", "split", "join", "remove_query_args", "remove_bytes",
    "uuidv4",
}


class _DynExprParser:
    """Parser for Cloudflare dynamic expressions (action values)."""

    def __init__(self, tokens, expr):
        self.tokens = tokens
        self.expr = expr
        self.pos = 0

    def peek(self):
        return self.tokens[self.pos]

    def advance(self):
        t = self.tokens[self.pos]
        self.pos += 1
        return t

    def expect(self, tt):
        t = self.advance()
        if t.type != tt:
            raise _ParseError(f"Expected {tt}, got {t.type} ({t.value!r}) at pos {t.pos}")
        return t

    def parse(self):
        result = self._dyn_expr()
        if self.peek().type != _TT_EOF:
            t = self.peek()
            raise _ParseError(f"Unexpected token: {t.value!r} at pos {t.pos}")
        return result

    def _dyn_expr(self):
        t = self.peek()
        # Function call
        if t.type == _TT_FIELD and t.value in _DYN_FUNCS:
            return self._func_call()
        # String literal
        if t.type == _TT_STRING:
            self.advance()
            return {"type": "literal", "value": t.value}
        # Number
        if t.type == _TT_NUMBER:
            self.advance()
            return {"type": "literal", "value": t.value}
        # Field reference (e.g., http.request.uri.path)
        if t.type == _TT_FIELD:
            self.advance()
            return {"type": "field", "value": t.value}
        raise _ParseError(f"Unexpected token in dynamic expression: {t.value!r} at pos {t.pos}")

    def _func_call(self):
        name_tok = self.advance()
        name = name_tok.value
        self.expect(_TT_LPAREN)
        args = []
        if self.peek().type != _TT_RPAREN:
            args.append(self._dyn_expr())
            while self.peek().type == _TT_COMMA:
                self.advance()
                args.append(self._dyn_expr())
        self.expect(_TT_RPAREN)
        return {"type": "func_call", "func": name, "args": args}
