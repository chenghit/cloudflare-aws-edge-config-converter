"""Cloudflare expression parser — Phase 1 (regex + string ops, no AST).

Parses simple Cloudflare rule expressions into structured conditions.
Complex expressions are left as raw_expression for cdn-generate-js.py
(which generates JS condition code or a // TODO comment).

Returns (condition, raw_expression) — exactly one is non-None.
"""
import hashlib
import re

# (Quota tags + cdn_summary.json loader moved to cdn_common.py — file-IO and the
# result contract don't belong in the expression parser.)

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
    """Split full_uri wildcard pattern into (host_pattern, path_pattern, scheme).

    e.g. 'https://*.c.example.com/files/*' → ('*.c.example.com', '/files/*', 'https')
         'http://cdn.c.example.com/host/*' → ('cdn.c.example.com', '/host/*', 'http')
         '*://host/p'                       → ('host', '/p', None)  (scheme wildcard)

    `scheme` is 'http' or 'https' when the pattern pins ONE scheme, else None (a
    `*://` or scheme-wildcard prefix). A pinned scheme can't be represented by a
    CloudFront path pattern (a behavior serves both schemes), so the caller treats
    a scheme-pinned full_uri as NOT single-path — see _cache_cond_is_single_path.
    """
    # Strip optional r prefix and quotes
    p = pattern.strip()
    if p.startswith('r"') or p.startswith("r'"):
        p = p[2:-1]
    elif p.startswith('"') or p.startswith("'"):
        p = p[1:-1]

    m = re.match(r'(https?)://([^/]+)(/.*)$', p)
    if m:
        return m.group(2), m.group(3), m.group(1)
    # A non-scheme-specific prefix (e.g. '*://' or '*') still yields host/path.
    m2 = re.match(r'[^/]*://([^/]+)(/.*)$', p)
    if m2:
        return m2.group(1), m2.group(2), None
    return None, None, None


# Header injected by the conditional cache-bypass CFF to force a guaranteed
# cache MISS. It carries a per-request-unique value and MUST be part of the
# behavior's cache-key (whitelisted in the cache policy) for the miss to happen.
# SINGLE SOURCE OF TRUTH: both the CFF codegen (cdn-generate-js) and the
# cache-policy whitelist (cdn-preprocess / cdn-generate-shared-policies) import
# this — the header the CFF writes and the header the cache key includes can
# never drift apart (the ORP split-brain lesson). Lowercase: CFF header keys are
# lowercased, and cache-policy header matching is case-insensitive.
CACHE_BYPASS_HEADER = "x-cf-cache-bypass"

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
    "http.cookie": "cookie",  # the entire Cookie header as a string
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

# Indexed (named) Cloudflare fields: cookies / headers / query-string args, each
# a Map keyed by name. We support the leaf forms a rule actually uses to gate a
# cache bypass: EXISTENCE (the bare indexed field as a boolean, "this name is
# present") and a scalar VALUE comparison (eq/ne/contains/…), both mapped to a
# synthetic short field carrying the name. The multi-value form
# any(field["k"][*] == "v") parses to a raw expression (the any() wrapper is
# unsupported) → reported non-convertible, never silently converted.
#   cookies → request.cookies (name as-is)
#   headers → request.headers (name LOWERCASED at render — CFF header keys are
#             ASCII-lowercase; the Cookie header is excluded, it lives in cookies)
#   uri.args → request.querystring (name case-sensitive, as-is)
_RE_INDEXED_FIELD = re.compile(
    r'^http\.request\.(cookies|headers|uri\.args)\["((?:[^"\\]|\\.)*)"\]$')
_INDEXED_SHORT = {"cookies": "cookie_named", "headers": "header_named",
                  "uri.args": "arg_named"}


# Short field names synthesized by _map_field that are NOT CF_FIELD_MAP values
# but ARE convertible (so the unmappable screen doesn't reject them).
_SYNTHETIC_CONVERTIBLE_FIELDS = {"cookie_named", "header_named", "arg_named"}
# The extra-dict key each synthetic field uses to carry its name.
_SYNTHETIC_NAME_KEY = {"cookie_named": "cookie_name", "header_named": "header_name",
                       "arg_named": "arg_name"}


def _map_field(field):
    """Map a raw Cloudflare field token to (short_field, extra) for a leaf.

    Returns (mapped_field, extra_dict). extra_dict carries leaf attributes that
    depend on the field shape — for an indexed cookie/header/arg field it's the
    structured name. For a plain field it's the CF_FIELD_MAP lookup (or the
    field unchanged), no extras.
    """
    m = _RE_INDEXED_FIELD.match(field)
    if m:
        short = _INDEXED_SHORT[m.group(1)]
        return short, {_SYNTHETIC_NAME_KEY[short]: m.group(2)}
    return CF_FIELD_MAP.get(field, field), {}

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


# ── top-level parser ─────────────────────────────────────────────────────────

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


def orp_header_union(ir):
    """The sorted UNION of required_orp_headers across ALL of a domain's cache
    behaviors — i.e. the exact header set the domain's shared custom ORP resource
    forwards. Single source of truth for the call sites that MUST agree or the
    pipeline breaks: the shared-ORP resource (cdn-generate-shared-policies), the
    per-behavior ORP reference (cdn-generate-tf-scaffold), and the ORP-header
    quota check (cdn-finalize). Per-behavior counts do NOT match the real
    resource — a domain can stay under 10 on each behavior yet exceed 10 in the
    union, which is what AWS actually validates."""
    headers = set()
    for b in ir.get("cache_behaviors", []):
        headers.update(b.get("required_orp_headers", []))
    return sorted(headers)


def custom_orp_hash(headers):
    """Stable 8-char id for a custom-ORP header set. The shared-ORP RESOURCE name
    (cdn-generate-shared-policies) and the per-domain DATA-SOURCE name (cdn-
    generate-tf-scaffold) both derive from this, so they MUST use one function.
    Sorted so header order can't change the hash."""
    key = ",".join(sorted(headers))
    return hashlib.sha256(key.encode()).hexdigest()[:8]


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
    """Determine which distributions a rule applies to, as a HOST FILTER that
    ``host_filter_applies(filter, hostname)`` evaluates against a CONCRETE
    distribution hostname (one per proxied CNAME, from DNS).

    Returns one of:
      - None                          -> global (applies to every distribution)
      - {"tree": <host-condition>}    -> evaluate the (host-only) condition tree
                                         against each concrete hostname

    Why a tree, not an include/exclude set: host values can carry a zone
    wildcard (``*.example.com`` from a full_uri pattern or ``host in {*.x}``),
    and abstract set intersect/union over wildcards is unsound — that produced
    fail-opens and silent drops. Evaluating the tree against the REAL
    distribution hostnames (via hostname_matches, which already handles
    wildcards) sidesteps set algebra entirely: ``*.example.com`` simply matches
    every real subdomain in the zone. The tree keeps ONLY host / full_uri leaves
    (a non-host leaf like uri.path is dropped to "unconstrained"), so what
    survives is purely the host scope. OR is expected to have been split into
    independent rules upstream, but the evaluator handles it correctly anyway.
    """
    if condition is None:
        # raw_expression -- scan the original expression for http.host
        hosts = _scan_host_from_expression(expression)
        return {"tree": _hosts_to_tree(hosts)} if hosts else None
    if condition.get("always"):
        return None  # global
    tree = _host_scope_tree(condition)
    return None if tree is None else {"tree": tree}


# ── Host-scope tree ──────────────────────────────────────────────────────────
# A pruned copy of the condition holding only the host-constraining parts
# (host leaves, full_uri leaves — which bind host AND path atomically — and the
# logic nodes joining them). Non-host leaves become None ("this branch imposes
# no host constraint"). host_filter_applies() walks it against a concrete
# hostname. None anywhere means "no host constraint from here" (global for that
# subtree), combined per the surrounding logic.


def _host_scope_tree(cond, negate=False):
    """Build the host-scope tree from a condition, or None if it imposes no host
    constraint (a rule with no host test applies to every distribution).

    INVARIANT: the pruned tree must never be MORE restrictive than the real
    condition's host-satisfiability — it may say "applies" where the truth is
    "no" (the rule runs on an extra distribution and the full condition gates it
    out at request time: wasteful but correct), but must NEVER say "doesn't
    apply" where the truth is "yes" (that silently drops the rule).

    Dropping a non-host leaf must therefore always WIDEN the matched-host set.
    That holds under positive (AND) polarity but NOT under negation: dropping B
    from `not(A and B)` turns the real `not A or not B` (fires on host-of-A when
    B is false) into `not A` (never fires there) — strictly narrower, a silent
    drop. So `negate` is tracked; a non-host leaf reached under ODD negation
    can't be dropped safely, and its enclosing negated subtree collapses to
    "no host constraint" (None → applies everywhere, the safe/permissive side).
    """
    if not isinstance(cond, dict):
        return None
    if "logic" in cond:
        logic = cond["logic"]
        if logic == "not":
            inner = _host_scope_tree(cond.get("item"), not negate)
            return None if inner is None else {"logic": "not", "item": inner}
        kids_raw = cond.get("parts", [])
        kids = [_host_scope_tree(p, negate) for p in kids_raw]
        # A conjunct/disjunct dropped to None *because it held a non-host leaf*
        # is the unsafe case — record it. (A branch that was None purely because
        # it had no host test is a safe drop.)
        dropped_nonhost = any(
            k is None and _has_nonhost_leaf(p) for k, p in zip(kids, kids_raw))
        # Under negation, AND/OR swap roles (De Morgan) for the DROP-SAFETY test
        # only — the emitted node keeps the REAL operator so the evaluator (which
        # applies the enclosing NOT itself) negates the true structure. Applying
        # De Morgan to the output too would double-negate.
        effective = ("or" if logic == "and" else "and") if negate else logic
        if effective == "and":
            # Effective-AND: dropping a non-host conjunct WIDENS the host set →
            # safe. Keep the host-constraining children under the REAL operator.
            kept = [k for k in kids if k is not None]
            if not kept:
                return None
            if len(kept) == 1 and len(kids_raw) == 1:
                return kept[0]
            return {"logic": logic, "parts": kept}
        # Effective-OR: if any branch imposes no host constraint (None), or a
        # branch was dropped only because it contained a non-host leaf under this
        # polarity, the disjunction can fire on any host → None (permissive-safe).
        if not kids or any(k is None for k in kids) or dropped_nonhost:
            return None
        return {"logic": logic, "parts": kids}
    field = cond.get("field", "")
    op = cond.get("op", "")
    if field == "full_uri":
        # full_uri binds host AND path atomically: it matches iff host~host_pattern
        # AND path~path_pattern. As a HOST-scope constraint that only holds under
        # POSITIVE polarity (host must match). Negated — `not(host~hp AND path~pp)`
        # — it fires on hp too (whenever path≠pp), so it imposes NO sound host
        # exclusion; drop to None (unconstrained → applies everywhere; the path
        # exclusion is realized at behavior placement, not as a host filter).
        # `op` already carries any inline `not_` (a flattened single leaf); an
        # enclosing NOT node is captured by `negate`.
        negated_here = negate ^ op.startswith("not_")
        if negated_here:
            return None
        leaf = dict(cond)
        if op.startswith("not_"):  # normalize to the positive op for the evaluator
            leaf["op"] = op[len("not_"):]
        return leaf
    if field == "host":
        # A host leaf constrains the host; keep as-is (the evaluator honors its op
        # and the surrounding NOT nodes).
        return dict(cond)
    return None  # non-host leaf: no host constraint


def _has_nonhost_leaf(cond):
    """True if the condition subtree contains any non-host, non-full_uri leaf —
    i.e. a leaf whose removal from the host-scope tree could change semantics."""
    if not isinstance(cond, dict):
        return False
    if "logic" in cond:
        return any(_has_nonhost_leaf(c) for c in iter_condition_children(cond))
    return cond.get("field") not in ("host", "full_uri")


def _hosts_to_tree(hosts):
    """Wrap a flat host list (from the raw-expression scan) as an OR of host-eq
    leaves, so host_filter_applies can evaluate it uniformly."""
    leaves = [{"field": "host", "op": "eq", "value": h} for h in hosts]
    if len(leaves) == 1:
        return leaves[0]
    return {"logic": "or", "parts": leaves}


def host_filter_applies(host_filter, hostname, host_matches):
    """Evaluate a host filter (from extract_host_filter) against a concrete
    distribution hostname. ``host_matches(hostname, pattern)`` is the caller's
    wildcard-aware matcher (cdn-preprocess.hostname_matches). None filter =
    global = applies. See rule_applies_to_domain for the wrapper used in-tree."""
    if host_filter is None:
        return True
    return _eval_host_tree(host_filter["tree"], hostname, host_matches)


def _eval_host_tree(node, hostname, host_matches):
    """Boolean-evaluate a host-scope tree node against one concrete hostname."""
    if "logic" in node:
        logic = node["logic"]
        if logic == "not":
            return not _eval_host_tree(node["item"], hostname, host_matches)
        if logic == "and":
            return all(_eval_host_tree(p, hostname, host_matches) for p in node["parts"])
        return any(_eval_host_tree(p, hostname, host_matches) for p in node["parts"])
    field = node.get("field", "")
    op = node.get("op", "")
    if field == "full_uri":
        # Only POSITIVE full_uri leaves reach the tree (_host_scope_tree drops a
        # negated full_uri to None, since negating host∧path imposes no sound
        # host exclusion). For the host-scope decision, test only the host part
        # (host_pattern); the path part is applied at behavior placement.
        hp = node.get("host_pattern")
        if not hp:
            return True  # no host pinned -> unconstrained
        return host_matches(hostname, hp)
    if field == "host":
        return _eval_host_leaf(op, node.get("value"), hostname, host_matches)
    return True  # non-host leaf: no host constraint -> matches


def _eval_host_leaf(op, val, hostname, host_matches):
    """Evaluate a single host leaf against a concrete hostname."""
    if op == "eq":
        return isinstance(val, str) and host_matches(hostname, val)
    if op == "in":
        return isinstance(val, list) and any(host_matches(hostname, v) for v in val)
    if op in ("ne", "not_eq"):
        return not (isinstance(val, str) and host_matches(hostname, val))
    if op == "not_in":
        return not (isinstance(val, list) and any(host_matches(hostname, v) for v in val))
    if op == "not_ne":  # double negation: not(host ne x) == host eq x
        return isinstance(val, str) and host_matches(hostname, val)
    if op in ("wildcard", "strict_wildcard"):
        return isinstance(val, str) and host_matches(hostname, val)
    if op in ("not_wildcard",):
        return not (isinstance(val, str) and host_matches(hostname, val))
    # in_list / contains / unknown: can't pin to a host set -> no constraint
    # (the processor rejects a named $list separately). Applies (global-ish).
    return True


# Host-leaf ops the ROUTER consumes to scope a rule to distributions. A leaf
# with one of these is redundant once the rule is placed on a matched
# distribution and may be stripped; any OTHER op on `host` (contains, matches,
# gt via size_check/len, …) is a LIVE predicate that does NOT route and must be
# kept and gated at request time. Single source of truth for both the
# host-strip in cdn-preprocess and the custom-error code gate.
_HOST_ROUTING_OPS = frozenset({
    "eq", "in", "ne", "not_eq", "not_in", "not_ne",
    "wildcard", "strict_wildcard", "not_wildcard",
})


def host_leaf_is_routing(cond):
    """True if `cond` is a `host` leaf whose op the router consumes for
    distribution scoping (see _HOST_ROUTING_OPS). A full_uri leaf is NOT a plain
    host leaf (its path part matters) and returns False here."""
    return (isinstance(cond, dict) and cond.get("field") == "host"
            and not cond.get("size_check")
            and cond.get("op") in _HOST_ROUTING_OPS)


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
        host, _, _ = _parse_full_uri_wildcard(m.group(1))
        if host:
            return [host]
    return None


# ── path pattern extraction ──────────────────────────────────────────────────

_PATH_FIELDS = {"uri", "uri.path", "uri.path.extension", "full_uri"}


def condition_has_path_field(cond):
    """True if the condition references any URI/path field anywhere in the tree
    (uri, uri.path, uri.path.extension, full_uri) — regardless of operator or
    negation. Used to tell a genuinely zone-wide rule (no path field → scope
    'all', runs on every behavior) apart from a rule that DID scope by path but
    whose path couldn't reduce to a single CloudFront pattern (has a path field
    → scope 'default_only', runs on the default behavior only). Descends both
    AND/OR parts and a NOT item via iter_condition_children."""
    if not isinstance(cond, dict):
        return False
    if "logic" in cond:
        return any(condition_has_path_field(c) for c in iter_condition_children(cond))
    return cond.get("field") in _PATH_FIELDS


def extract_path_pattern_single(cond):
    """Extract a CloudFront path pattern from a single condition."""
    field = cond.get("field", "")
    op = cond.get("op", "")
    val = cond.get("value", "")
    # A NEGATED path/full_uri leaf ("path is anything BUT /x", "full_uri does
    # not match .../admin/*") is not expressible as a single CloudFront path
    # pattern — the matching set is the complement. Return "*" (default behavior)
    # rather than the pattern being excluded, which would place the rule on
    # exactly the path it must NOT scope to. (The full_uri branch below reads
    # path_pattern regardless of op, so this guard is what stops that leak.)
    if op.startswith("not_"):
        return "*"
    if field in ("uri.path", "uri"):
        if op in ("wildcard", "strict_wildcard"):
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
# A ["quoted key"] subscript following a field name (cookies/headers maps). The
# tokenizer absorbs it into the field token; an optional [*] array-expansion
# after it (any(cookies["x"][*] == ...)) is captured so the field layer can
# reject value-comparison forms cleanly instead of the parser choking on `[`.
_RE_FIELD_SUBSCRIPT = re.compile(r'\[\s*"(?:[^"\\]|\\.)*"\s*\](?:\[\*\])?')


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
            # A ["key"] subscript directly after a field name (e.g.
            # http.request.cookies["session"] / http.request.headers["x"]) is
            # part of the field, not a separate token. Absorb it into the field
            # token so the field-map layer sees the whole indexed name; the bare
            # `[` would otherwise hit the "Unexpected character" error below.
            m = _RE_FIELD_SUBSCRIPT.match(expr, i)
            if m:
                word = expr[start:m.end()]
                i = m.end()
                tokens.append(_Token(_TT_FIELD, word, pos)); continue
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
            # Flatten not into op: not {field, op: eq} → {field, op: not_eq}.
            # Double negation cancels: not(not_eq) → eq (NOT not_not_eq, which is
            # an unknown op that would render as `false` — rule never fires).
            if "field" in inner and "op" in inner:
                op = inner["op"]
                inner["op"] = op[4:] if op.startswith("not_") else "not_" + op
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
        # All three func branches map the field through _map_field (NOT the bare
        # CF_FIELD_MAP.get), so an INDEXED cookie/header/arg — cookies["x"],
        # headers["x"], uri.args["x"] — wrapped in len()/lower()/upper()/
        # starts_with()/ends_with() resolves to its synthetic field + name (extra),
        # exactly like a bare indexed field does via _field_expr. Without this the
        # indexed name leaked through as a raw string and was later screened
        # "unmappable" → rendered `false`, silently killing e.g. a
        # `len(http.request.headers["rsc"]) > 0` cache-bypass gate.
        if name in ("lower", "upper"):
            self.expect(_TT_LPAREN)
            field = self.expect(_TT_FIELD).value
            self.expect(_TT_RPAREN)
            op = self._read_op()
            value = self._read_value()
            mapped, extra = _map_field(field)
            result = {"field": mapped, "op": op, "value": value, **extra}
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
            mapped, extra = _map_field(field)
            return {"field": mapped, "op": name, "value": value, **extra}
        if name == "len":
            self.expect(_TT_LPAREN)
            field = self.expect(_TT_FIELD).value
            self.expect(_TT_RPAREN)
            op = self._read_op()
            value = self._read_value()
            mapped, extra = _map_field(field)
            return {"field": mapped, "op": op, "value": value, "size_check": True, **extra}
        raise _ParseError(f"Unknown function: {name}")

    def _field_expr(self):
        field_tok = self.advance()
        field = field_tok.value
        mapped, extra = _map_field(field)

        # Bare boolean field (no operator follows). For an indexed cookie this is
        # the existence check (http.request.cookies["x"] → "x" is present).
        if self.peek().type not in (_TT_OP,):
            return {"field": mapped, "op": "eq", "value": True, **extra}

        op_tok = self.advance()
        op = op_tok.value

        # "in" can be followed by $list or {set}. BOTH returns must carry **extra:
        # for an indexed field (cookies["x"] in {…}) the synthetic short name is in
        # `mapped` but the actual key lives in `extra` — dropping it renders
        # `request.cookies[''] ...` (empty-string key → silently never matches, and
        # it evades both the unmappable screen and cdn-validate-js). Same class as
        # the _func_call bug; keep every _field_expr return path consistent.
        if op == "in":
            t = self.peek()
            if t.type == _TT_DOLLAR:
                self.advance()
                list_name = self.expect(_TT_FIELD).value
                return {"field": mapped, "op": "in_list", "value": "$" + list_name, **extra}
            if t.type == _TT_LBRACE:
                values = self._read_set()
                return {"field": mapped, "op": "in", "value": values, **extra}
            raise _ParseError(f"Expected $ or {{ after 'in', got {t.value!r}")

        # wildcard / strict_wildcard with full_uri special handling
        if op in ("wildcard", "strict_wildcard"):
            value = self._read_value()
            if mapped == "full_uri":
                host_pat, path_pat, scheme = _parse_full_uri_wildcard(value)
                if host_pat and path_pat:
                    # Preserve the ORIGINAL op — a full_uri STRICT wildcard is
                    # case-sensitive; collapsing it to "wildcard" would render a
                    # case-insensitive match and wrongly match case variants.
                    return {"field": "full_uri", "op": op, "value": value,
                            "host_pattern": host_pat, "path_pattern": path_pat,
                            "scheme": scheme}
            return {"field": mapped, "op": "wildcard" if op == "wildcard" else "strict_wildcard", "value": value, **extra}

        # matches — keep regex as-is, try simple wildcard conversion
        if op == "matches":
            value = self._read_value()
            wc = _try_simple_regex_to_wildcard(value)
            if wc:
                return {"field": mapped, "op": "wildcard", "value": wc, **extra}
            return {"field": mapped, "op": "matches", "value": value, **extra}

        # Standard comparison: eq, ne, contains, gt, lt, ge, le
        value = self._read_value()
        return {"field": mapped, "op": op, "value": value, **extra}

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
    # Synthetic short names not in CF_FIELD_MAP but produced by _map_field
    # (structured cookie existence) are convertible.
    if field in _SYNTHETIC_CONVERTIBLE_FIELDS:
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
