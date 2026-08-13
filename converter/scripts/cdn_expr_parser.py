"""Cloudflare expression parser — Phase 1 (regex + string ops, no AST).

Parses simple Cloudflare rule expressions into structured conditions.
Complex expressions are left as raw_expression for cdn-generate-js.py
(which generates JS condition code or a // TODO comment).

Returns (condition, raw_expression) — exactly one is non-None.
"""
import hashlib
import re

# (Quota tags + cdn_summary.json loader moved to cdn_common.py — file-IO and the
# result contract don't belong in the expression parser. The RHP capability registry —
# name + value parser + renderer — lives in its own dependency-free module
# cdn_rhp_capabilities.py so the processor, preprocess, and the HCL generator share ONE
# source of truth for both the supported set AND the value semantics.)

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
        # Unquoted boolean literal (wirefilter) as a comparison operand, e.g.
        # `ip.src.is_in_european_union eq true` / `ip.src.is_in_european_union ne false`. The
        # tokenizer emits bare true/false as a _TT_FIELD (they are not ops/keywords); only in a
        # VALUE position are they the boolean literal. A quoted "true" is a _TT_STRING (handled
        # above) and stays a string. This yields value=True/False, the SAME shape a bare boolean
        # field (`ip.src.is_in_european_union`) produces, so it renders/validates identically.
        if t.type == _TT_FIELD and t.value in ("true", "false"):
            self.advance()
            return t.value == "true"
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


# ── Dynamic-expression TYPE registry (round-20: the SINGLE source of expression result types) ──
# A header value must be a STRING. CloudFront Functions have NO implicit coercion for a header
# value, so a non-string result (number/array/bytes) is NOT a faithful conversion — it must be
# explicitly converted in the source (to_string / join / encode_base64) before it can be EXACT.
# `unknown` fails closed (NC), never optimistically string. This replaces the old number-only
# guess where everything else defaulted to string and String() masked the mismatch.
_TYPE_STRING, _TYPE_NUMBER, _TYPE_ARRAY, _TYPE_BYTES, _TYPE_BOOL, _TYPE_IP, _TYPE_UNKNOWN = (
    "string", "number", "array", "bytes", "boolean", "ip", "unknown")

# ── FUNCTION CONTRACT registry (round-21: signatures, not just return types) ──
# A return-type table alone let signature-illegal expressions pass (lower(len(...)),
# join(http.host,...), to_string(sha256(...))). Each contract carries what Cloudflare's
# Functions reference actually specifies, so type-checking VALIDATES the whole call, recursively:
#   result:   result type.
#   args:     tuple of accepted-type SETS, positional. A `None` arg slot = any type (rare).
#   variadic: the LAST args entry repeats (concat/remove_query_args/lookup_json_* trailing keys).
#   min_arity/max_arity: inclusive arg-count bounds (max None = unbounded, needs variadic).
#   contexts: the emit CONTEXTS this function is allowed in (round-22 — replaces the coarse
#             request/response phase). Cloudflare restricts many functions to specific rule
#             types; we track the ones we can emit into: request_header, response_header,
#             url_rewrite, redirect, custom_error. None = allowed everywhere we emit. The header
#             producers pass request_header/response_header, so a rewrite-only function
#             (regex_replace/wildcard_replace/remove_query_args/uuidv4/sha256) is rejected there.
#   literal:  optional callable(args_nodes)->reason|None for NODE-SHAPE / literal-value
#             constraints beyond arg TYPES (split's non-empty literal separator + 1..128 limit,
#             decode_base64's field-only source, encode_base64's flags, …).
# concat is POLYMORPHIC (result depends on args) — handled specially, not via a fixed result.
class _FC:
    __slots__ = ("result", "args", "variadic", "min_arity", "max_arity", "contexts", "literal")

    def __init__(self, result, args, min_arity, max_arity, variadic=False,
                 contexts=None, literal=None):
        self.result, self.args = result, args
        self.min_arity, self.max_arity, self.variadic = min_arity, max_arity, variadic
        self.contexts, self.literal = contexts, literal


_ANY_STRINGLIKE = frozenset({_TYPE_STRING, _TYPE_BYTES})

# The emit contexts we convert into. Header producers pass a *_header context; redirect/rewrite
# use their own. A function's `contexts` (when set) lists where Cloudflare permits it.
_CTX_REQUEST_HEADER = "request_header"
_CTX_RESPONSE_HEADER = "response_header"
_CTX_URL_REWRITE = "url_rewrite"
_CTX_REDIRECT = "redirect"
_CTX_CUSTOM_ERROR = "custom_error"
# Cloudflare "rewrite expression" scope = url_rewrite + the target-URL of redirects. These
# functions are documented rewrite-only and must NOT appear in a header transform.
_REWRITE_CTXS = frozenset({_CTX_URL_REWRITE, _CTX_REDIRECT})


def _is_literal_str(node):
    return isinstance(node, dict) and node.get("type") == "literal" \
        and isinstance(node.get("value"), str)


def _is_field(node):
    return isinstance(node, dict) and node.get("type") == "field"


def _split_shape_ok(arg_nodes):
    # split(input, separator, limit): separator a NON-EMPTY LITERAL string (Cloudflare: "The
    # separator must be a non-empty literal string"); limit MANDATORY literal integer 1..128.
    if len(arg_nodes) >= 2:
        sep = arg_nodes[1]
        if not _is_literal_str(sep):
            return "split() `separator` must be a literal string (not a dynamic field)"
        if sep.get("value") == "":
            return "split() `separator` must be a non-empty literal string"
    if len(arg_nodes) < 3:
        return "split() requires a mandatory `limit` argument (a literal integer 1..128)"
    lim = arg_nodes[2]
    if not (isinstance(lim, dict) and lim.get("type") == "literal"
            and isinstance(lim.get("value"), int) and not isinstance(lim.get("value"), bool)):
        return "split() `limit` must be a literal integer"
    if not (1 <= lim["value"] <= 128):
        return f"split() `limit` must be between 1 and 128, got {lim['value']}"
    return None


def _decode_base64_shape_ok(arg_nodes):
    # decode_base64(source): source must be a FIELD (Cloudflare: "source must be a field, it
    # cannot be a literal String") — else the generator's atob() runs on a build-time constant.
    if arg_nodes and not _is_field(arg_nodes[0]):
        return "decode_base64() source must be a field, not a literal"
    return None


def _url_decode_shape_ok(arg_nodes):
    # url_decode(source, options?): source must be a field; options (if present) a literal
    # containing only r/u.
    if arg_nodes and not _is_field(arg_nodes[0]):
        return "url_decode() source must be a field, not a literal"
    if len(arg_nodes) > 1:
        opt = arg_nodes[1]
        if not _is_literal_str(opt) or any(c not in "ru" for c in opt.get("value", "")):
            return "url_decode() options must be a literal containing only 'r'/'u'"
    return None


def _encode_base64_shape_ok(arg_nodes):
    # encode_base64(input, flags?): flags (if present) a literal string of only u/p.
    if len(arg_nodes) > 1:
        fl = arg_nodes[1]
        if not _is_literal_str(fl) or any(c not in "up" for c in fl.get("value", "")):
            return "encode_base64() flags must be a literal containing only 'u'/'p'"
    return None


def _remove_query_args_shape_ok(arg_nodes):
    # remove_query_args(field, name...): field must be the URI query field (raw or normal), not
    # a literal or arbitrary field; the removed names must be literal strings.
    if arg_nodes:
        f0 = arg_nodes[0]
        allowed = {"http.request.uri.query", "raw.http.request.uri.query"}
        if not (_is_field(f0) and f0.get("value") in allowed):
            return ("remove_query_args() first argument must be the http.request.uri.query "
                    "field (or its raw form)")
    for nm in arg_nodes[1:]:
        if not _is_literal_str(nm):
            return "remove_query_args() query-parameter names must be literal strings"
    return None


def _regex_replace_shape_ok(arg_nodes):
    # regex_replace(source, regex, replacement): regex + replacement literal strings.
    for i in (1, 2):
        if len(arg_nodes) > i and not _is_literal_str(arg_nodes[i]):
            return f"regex_replace() argument {i + 1} must be a literal string"
    return None


def _wildcard_replace_shape_ok(arg_nodes):
    # wildcard_replace(source, pattern, replacement, flags?): pattern + replacement literal
    # strings; the optional flags a literal containing only 's' (case-sensitive). The generator
    # reads pattern/replacement/flags as literals (args[n]["value"]), so a dynamic one would be
    # mis-emitted (round-22 finding 5 — must be constrained before the rewrite context is wired).
    for i in (1, 2):
        if len(arg_nodes) > i and not _is_literal_str(arg_nodes[i]):
            return f"wildcard_replace() argument {i + 1} must be a literal string"
    if len(arg_nodes) > 3:
        fl = arg_nodes[3]
        if not _is_literal_str(fl) or any(c not in "s" for c in fl.get("value", "")):
            return "wildcard_replace() flags must be a literal containing only 's'"
    return None


def _substring_shape_ok(arg_nodes):
    # substring(field, start, end?): Cloudflare allows NEGATIVE indices (count from the end), but
    # the JS renderer emits String.substring(), which clamps a negative to 0 — a DIFFERENT result.
    # Until the renderer uses a negative-aware slice, ONLY a PROVABLY-NON-NEGATIVE index converts
    # (round-26 finding 3). So each index MUST be a literal integer >= 0; a DYNAMIC index (e.g.
    # lookup_json_integer(...), which can be negative at runtime and would then clamp) is NOT
    # provably non-negative → NC. (Was: only literal-negative rejected, letting a dynamic
    # possibly-negative index through.)
    for i in (1, 2):
        if len(arg_nodes) > i:
            n = arg_nodes[i]
            if not (isinstance(n, dict) and n.get("type") == "literal"
                    and isinstance(n.get("value"), int) and not isinstance(n.get("value"), bool)):
                return (f"substring() index (argument {i + 1}) must be a literal non-negative "
                        "integer — a dynamic index can be negative at runtime, which JS "
                        ".substring() clamps to 0 (a different result); not converted")
            if n["value"] < 0:
                return ("substring() with a negative index has no faithful CloudFront Functions "
                        "renderer (JS .substring() clamps negatives to 0) — not converted")
    return None


def _lookup_json_shape_ok(arg_nodes):
    # lookup_json_string/integer(field, key, key...): the renderer reads each KEY as a STATIC
    # node (js_string(a["value"]) / int index), so every key MUST be a literal string or integer
    # — a dynamic key (http.host, lower(...)) would render as a fixed wrong key or KeyError
    # (round-24 finding 3). The field (arg 0) may be dynamic.
    for k in arg_nodes[1:]:
        if not (isinstance(k, dict) and k.get("type") == "literal"
                and isinstance(k.get("value"), (str, int)) and not isinstance(k.get("value"), bool)):
            return ("lookup_json_*() keys must be literal strings or integers (the generator "
                    "reads them statically) — a dynamic key can't be converted")
    return None


# Grounded in developers.cloudflare.com/ruleset-engine/rules-language/functions/ (fetched 2026-08).
# `contexts` names where Cloudflare PERMITS each function (None = all our emit contexts). The
# rewrite-only set (regex_replace/wildcard_replace/remove_query_args/uuidv4/sha256) therefore
# never validates inside a *_header context.
_HDR_CTXS = frozenset({_CTX_REQUEST_HEADER, _CTX_RESPONSE_HEADER})
_TRANSFORM_ALL = frozenset({_CTX_REQUEST_HEADER, _CTX_RESPONSE_HEADER, _CTX_URL_REWRITE,
                            _CTX_REDIRECT, _CTX_CUSTOM_ERROR})
_DYN_FUNC_CONTRACT = {
    # string result
    "lower":        _FC(_TYPE_STRING, (frozenset({_TYPE_STRING}),), 1, 1),
    "upper":        _FC(_TYPE_STRING, (frozenset({_TYPE_STRING}),), 1, 1),
    "to_string":    _FC(_TYPE_STRING, (frozenset({_TYPE_NUMBER, _TYPE_BOOL, _TYPE_IP}),), 1, 1,
                        contexts=frozenset({_CTX_URL_REWRITE, _CTX_REDIRECT, _CTX_REQUEST_HEADER,
                                            _CTX_RESPONSE_HEADER})),
    "substring":    _FC(_TYPE_STRING, (_ANY_STRINGLIKE, frozenset({_TYPE_NUMBER}),
                                       frozenset({_TYPE_NUMBER})), 2, 3,
                        literal=_substring_shape_ok),
    # rewrite-only (regex/wildcard replace, uuidv4, remove_query_args, sha256)
    "regex_replace": _FC(_TYPE_STRING, (frozenset({_TYPE_STRING}), frozenset({_TYPE_STRING}),
                                        frozenset({_TYPE_STRING})), 3, 3,
                         contexts=_REWRITE_CTXS, literal=_regex_replace_shape_ok),
    "wildcard_replace": _FC(_TYPE_STRING, (_ANY_STRINGLIKE, _ANY_STRINGLIKE, _ANY_STRINGLIKE,
                                           _ANY_STRINGLIKE), 3, 4, contexts=_REWRITE_CTXS,
                            literal=_wildcard_replace_shape_ok),
    "url_decode":   _FC(_TYPE_STRING, (frozenset({_TYPE_STRING}), frozenset({_TYPE_STRING})), 1, 2,
                        literal=_url_decode_shape_ok),
    "join":         _FC(_TYPE_STRING, (frozenset({_TYPE_ARRAY}), frozenset({_TYPE_STRING})), 2, 2,
                        contexts=frozenset({_CTX_REQUEST_HEADER, _CTX_RESPONSE_HEADER,
                                            _CTX_CUSTOM_ERROR})),
    "lookup_json_string": _FC(_TYPE_STRING, (frozenset({_TYPE_STRING}),
                                             frozenset({_TYPE_STRING, _TYPE_NUMBER})), 2, None,
                              variadic=True, literal=_lookup_json_shape_ok),
    "remove_query_args": _FC(_TYPE_STRING, (frozenset({_TYPE_STRING}), frozenset({_TYPE_STRING})),
                             2, None, variadic=True, contexts=frozenset({_CTX_URL_REWRITE}),
                             literal=_remove_query_args_shape_ok),
    "encode_base64": _FC(_TYPE_STRING, (_ANY_STRINGLIKE, frozenset({_TYPE_STRING})), 1, 2,
                         contexts=_HDR_CTXS, literal=_encode_base64_shape_ok),
    # uuidv4(source Bytes) → TARGET-UNSUPPORTED in EVERY context (round-22 finding 2): the
    # generator's uuidv4 renderer uses Math.random() and IGNORES the source-of-randomness bytes,
    # so it does NOT reproduce Cloudflare's deterministic-from-source UUID. Until a faithful
    # renderer exists, uuidv4 is NC everywhere — do NOT rely on the source field merely happening
    # to be unmappable. contexts=frozenset() (empty) → the context check rejects it in all contexts.
    "uuidv4":       _FC(_TYPE_STRING, (frozenset({_TYPE_BYTES}),), 1, 1, contexts=frozenset()),
    "decode_base64": _FC(_TYPE_STRING, (frozenset({_TYPE_STRING}),), 1, 1,   # String→String (not bytes)
                         literal=_decode_base64_shape_ok),
    # number result
    "len":          _FC(_TYPE_NUMBER, (frozenset({_TYPE_STRING, _TYPE_BYTES, _TYPE_ARRAY}),), 1, 1),
    "lookup_json_integer": _FC(_TYPE_NUMBER, (frozenset({_TYPE_STRING}),
                                              frozenset({_TYPE_STRING, _TYPE_NUMBER})), 2, None,
                               variadic=True, literal=_lookup_json_shape_ok),
    # array result — split is RESPONSE-header + custom-error only.
    "split":        _FC(_TYPE_ARRAY, (frozenset({_TYPE_STRING}), frozenset({_TYPE_STRING}),
                                      frozenset({_TYPE_NUMBER})), 3, 3,
                        contexts=frozenset({_CTX_RESPONSE_HEADER, _CTX_CUSTOM_ERROR}),
                        literal=_split_shape_ok),
    # bytes result. sha256 has NO context restriction: Cloudflare's own docs contradict
    # themselves (the standalone note says rewrite-only, but the encode_base64 signed-header
    # example nests sha256 inside a header transform). The BYTES result type already makes a
    # bare sha256 header NC, while encode_base64(sha256(...)) → string → EXACT (the documented
    # use). So the type gate, not a context flag, is the correct guard here.
    "sha256":       _FC(_TYPE_BYTES, (_ANY_STRINGLIKE,), 1, 1),
    # remove_bytes → TARGET-UNSUPPORTED this round (round-24 finding 4): its renderer calls
    # string .replace() on the arg, but remove_bytes operates on BYTES (its own sha256/bytes
    # input is a Buffer → runtime `replace is not a function`), and it allows a dynamic 2nd arg
    # the renderer reads as a static literal. contexts=frozenset() → NC everywhere until a
    # Buffer-safe byte-filter renderer exists.
    "remove_bytes": _FC(_TYPE_BYTES, (_ANY_STRINGLIKE, _ANY_STRINGLIKE), 2, 2, contexts=frozenset()),
}

# Field → result type. EXPLICIT registry (round-20/21): a field is NOT unconditionally a string.
# Keyed by SHORT name (post CF_FIELD_MAP). Numeric/boolean/IP ones named; else string (routable
# text) or unknown (fail closed).
_FIELD_RESULT_TYPE = {
    "response_code": _TYPE_NUMBER, "asnum": _TYPE_NUMBER, "latitude": _TYPE_NUMBER,
    "longitude": _TYPE_NUMBER, "metro_code": _TYPE_NUMBER,
    "is_eu": _TYPE_BOOL,            # ip.src.is_in_european_union is a Boolean (round-21 finding 4)
    "ip.src": _TYPE_IP,            # to_string(ip.src) is the legal way to use it as a string
}
_FIELD_STRING = frozenset({
    "uri.path", "uri", "uri.query", "uri.path.extension", "host", "user_agent", "referer",
    "method", "http_version", "full_uri", "cookie", "country", "continent", "city",
    "region", "region_code", "postal_code", "timezone", "subdivision_1", "subdivision_2",
    "cookie_named", "header_named", "arg_named",
})


def dynamic_expression_result_type(node):
    """The STATIC result type of a parsed dynamic-expr tree ∈ {string, number, array, bytes,
    boolean, ip, unknown}. The SINGLE authority the value-type gate + generator consult. Fails
    CLOSED (unrecognized node/func/field → unknown). NOTE: this reports the result type ASSUMING
    the call is well-formed; check_dynamic_expression_signature validates the args — a caller
    that needs faithfulness must run BOTH (value_expression_type_unconvertible does)."""
    if not isinstance(node, dict):
        return _TYPE_UNKNOWN
    ntype = node.get("type")
    if ntype == "literal":
        v = node.get("value")
        if isinstance(v, bool):
            return _TYPE_BOOL
        if isinstance(v, (int, float)):
            return _TYPE_NUMBER
        # A literal is String ONLY if it is genuinely a string. A dict/list/None literal has NO
        # faithful source-expression meaning (the Cloudflare grammar has no such literal) — fail
        # CLOSED to unknown so it can't ride the string contract and get str()-ified by the
        # generator (round-27 finding 3). validate_ast_node_schema rejects it outright too.
        return _TYPE_STRING if isinstance(v, str) else _TYPE_UNKNOWN
    if ntype == "field":
        short = CF_FIELD_MAP.get(node.get("value"), node.get("value"))
        if short in _FIELD_RESULT_TYPE:
            return _FIELD_RESULT_TYPE[short]
        return _TYPE_STRING if short in _FIELD_STRING else _TYPE_UNKNOWN
    if ntype == "func_call" or "func" in node:
        func = node.get("func")
        if func == "concat":
            # POLYMORPHIC but HOMOGENEOUS: String iff EVERY arg is String; Array iff EVERY arg
            # is Array; ANY MIXTURE (string+array, or a bytes/number/unknown arg) → unknown →
            # NC (round-24 finding 1). A mixed string+array previously resolved to array, which
            # generated `str.concat(arr).join(...)` → runtime `join is not a function` when the
            # mixed concat was nested inside join(). Cloudflare's concat is same-type only.
            arg_types = [dynamic_expression_result_type(a) for a in node.get("args", [])]
            if arg_types and all(t == _TYPE_STRING for t in arg_types):
                return _TYPE_STRING
            if arg_types and all(t == _TYPE_ARRAY for t in arg_types):
                return _TYPE_ARRAY
            return _TYPE_UNKNOWN
        fc = _DYN_FUNC_CONTRACT.get(func)
        return fc.result if fc else _TYPE_UNKNOWN
    return _TYPE_UNKNOWN


def check_dynamic_expression_signature(node, context=None):
    """Recursively validate a parsed dynamic-expr tree against the FUNCTION CONTRACT registry.
    Returns a reason string on the FIRST violation (unknown function, wrong arity, an arg whose
    result type isn't accepted, a CONTEXT restriction, a node-shape/literal constraint), else
    None. `context` ∈ {request_header, response_header, url_rewrite, redirect, custom_error,
    None}; None skips the context check.

    This turns the return-type table into a real signature proof (round-21/22): lower(len(...))
    is rejected on arg type; a header context rejects a rewrite-only function; split's separator
    must be a non-empty literal; decode_base64's source must be a field. Validates depth-first so
    the innermost bad call is reported."""
    if not isinstance(node, dict):
        return None
    ntype = node.get("type")
    if ntype in (None, "literal", "field"):
        return None
    if ntype == "func_call" or "func" in node:
        func = node.get("func")
        args = node.get("args", [])
        # validate children first (innermost error wins, and their types must be known to check us)
        for a in args:
            child = check_dynamic_expression_signature(a, context)
            if child:
                return child
        if func == "concat":
            # concat is HOMOGENEOUS: all-String or all-Array only (round-24 finding 1). Give a
            # CLEAR reason at the signature layer for a mixed/unsupported-type concat rather than
            # relying on the result-type collapsing to unknown (which produces a vaguer message).
            if not args:
                return "concat() requires at least one argument"
            at = [dynamic_expression_result_type(a) for a in args]
            if not (all(t == _TYPE_STRING for t in at) or all(t == _TYPE_ARRAY for t in at)):
                return (f"concat() arguments must be ALL string or ALL array (got {at}); "
                        "CloudFront has no mixed-type concat")
            return None
        # PURE low-level signature contract (SOURCE-AGNOSTIC): an unknown function (not in the
        # capability table) has no faithful conversion. The SOURCE-policy narrow (a USER value may use
        # ONLY SOURCE_CONVERTIBLE_FUNCTIONS) lives ONE layer up in validate_dynamic_tree(source=True) —
        # so this checker keeps validating EVERY function's signature for the renderer/contract tests
        # AND the internal producers (source=False, e.g. True-Client-IP's to_string). concat handled above.
        fc = _DYN_FUNC_CONTRACT.get(func)
        if fc is None:
            return f"unknown function {func!r} — no CloudFront-faithful conversion"
        n = len(args)
        if n < fc.min_arity or (fc.max_arity is not None and n > fc.max_arity):
            bound = f"{fc.min_arity}" if fc.max_arity == fc.min_arity else \
                (f"{fc.min_arity}+" if fc.max_arity is None else f"{fc.min_arity}..{fc.max_arity}")
            return f"{func}() takes {bound} argument(s), got {n}"
        # per-arg type check; a variadic function repeats its LAST declared arg type.
        for i, a in enumerate(args):
            slot = fc.args[i] if i < len(fc.args) else (fc.args[-1] if fc.variadic else None)
            if slot is None:
                continue
            at = dynamic_expression_result_type(a)
            if at == _TYPE_UNKNOWN:
                return (f"{func}() argument {i + 1} has an undetermined type — no faithful "
                        "conversion")
            if at not in slot:
                return (f"{func}() argument {i + 1} is {at}, expected one of "
                        f"{sorted(slot)}")
        # NODE-SHAPE / literal constraints (field-only, non-empty literal, valid flags, …).
        if fc.literal:
            lit = fc.literal(args)
            if lit:
                return lit
        # CONTEXT restriction. An EMPTY contexts set = TARGET-UNSUPPORTED everywhere (e.g.
        # uuidv4 — no faithful renderer): reject regardless of the caller's context, so it can't
        # slip through when a caller passes context=None. A non-empty set restricts to those
        # contexts (only checked when the caller names one).
        if fc.contexts is not None and not fc.contexts:
            return f"{func}() has no faithful CloudFront conversion (target-unsupported)"
        if context is not None and fc.contexts is not None and context not in fc.contexts:
            return (f"{func}() is not available in the {context} context "
                    f"(allowed: {sorted(fc.contexts)})")
        return None
    return None


def value_expression_type_unconvertible(expr, context=None):
    """Return a reason if a dynamic value expression is not a FAITHFUL string conversion for the
    given emit `context`, else None. TWO proofs (round-21/22): (1) the whole call tree passes
    signature validation (arity / arg-types / context / node-shape+literal constraints); (2) the
    result type is exactly `string` (a header value must be a string; number/array/bytes/boolean/
    ip/unknown → NC unless explicitly converted via to_string / join / encode_base64). Parse
    failures are handled by value_expression_unmappable, so a parse failure returns None here
    (no double-report). `context` is the emit context (e.g. request_header / response_header)."""
    try:
        tree = parse_dynamic_expression(expr)
    except Exception:
        return None
    sig = check_dynamic_expression_signature(tree, context)
    if sig:
        return f"dynamic value expression {expr!r}: {sig}"
    rtype = dynamic_expression_result_type(tree)
    if rtype != _TYPE_STRING:
        return (f"dynamic value expression {expr!r} has a non-string result type ({rtype}); a "
                "header value must be a string — convert it explicitly (to_string / join / "
                "encode_base64) to make the conversion faithful")
    return None


# ── TYPED LOWERING (round-26): the ONE data boundary between processor and generator ──
# LoweredValue is a JSON-SAFE, VERSIONED tagged union stored IN THE IR. The processor lowers a
# source action value EXACTLY ONCE (parse the tree, then run the full proof ON that tree); the
# generator renders ONLY the stored `ast` and never re-parses. The persisted IR is INDEPENDENTLY
# re-verified by validate_lowered_value (deep: re-derives the type from the AST, re-runs the
# contract, checks context↔empty_behavior) so a hand-built/JSON-reloaded IR can't sneak a wrong
# claim past a shallow shape check. `raw` is DIAGNOSTIC ONLY.
#   Literal : {schema_version:1, kind:"literal", context, value:<str>, empty_behavior}
#   Dynamic : {schema_version:1, kind:"dynamic", context, ast:<tree>, result_type:"string",
#              empty_behavior, raw:<expr>}
# empty_behavior ∈ {none, delete_header, clear_query} — a per-value policy: a dynamic header
# empty→delete_header; a static rewrite query ""→clear_query (a distinct literal, see below);
# everything else `none`. Carried ON the value so the gate can check the context↔behavior combo.
LOWERED_SCHEMA_VERSION = 1
LOWERED_EMPTY_NONE = "none"
LOWERED_EMPTY_DELETE_HEADER = "delete_header"
LOWERED_EMPTY_CLEAR_QUERY = "clear_query"
_LOWERED_EMPTY_BEHAVIORS = frozenset({LOWERED_EMPTY_NONE, LOWERED_EMPTY_DELETE_HEADER,
                                      LOWERED_EMPTY_CLEAR_QUERY})
# (round-27: the coarse _LOWERED_CONTEXTS / _CONTEXT_EMPTY_OK maps were REPLACED by the SLOT model
# below + _slot_empty_behavior_ok — context alone couldn't tell a path from a query or a header
# literal from a dynamic, so the empty_behavior legality is now decided per (slot, kind).)

# ── SLOTS (round-27 finding 1): the SPECIFIC place a LoweredValue is used ──
# context alone was too coarse — path and query share context "url_rewrite", and a header literal
# vs dynamic share "request_header", so the coarse gate let literal-header+delete_header (deletes
# a static empty header), dynamic-header+none (keeps a runtime-empty value), empty-literal rewrite
# path (request.uri=''), and dynamic query+clear_query (AST ignored, query blindly cleared) all
# pass. A SLOT pins down (context, kind-legality, empty_behavior-legality per kind) exactly.
SLOT_REQUEST_HEADER_VALUE = "request_header_value"
SLOT_RESPONSE_HEADER_VALUE = "response_header_value"
SLOT_REWRITE_PATH = "rewrite_path"
SLOT_REWRITE_QUERY = "rewrite_query"
SLOT_REDIRECT_TARGET = "redirect_target"
# Each slot → its underlying context (what field-sourcing/signature the AST is checked against).
_SLOT_CONTEXT = {
    SLOT_REQUEST_HEADER_VALUE: "request_header",
    SLOT_RESPONSE_HEADER_VALUE: "response_header",
    SLOT_REWRITE_PATH: "url_rewrite",
    SLOT_REWRITE_QUERY: "url_rewrite",
    SLOT_REDIRECT_TARGET: "redirect",
}
_LOWERED_SLOTS = frozenset(_SLOT_CONTEXT)

# THE single reason string for the viewer-response CFF error-response gap (round-27 finding 5 →
# review 2 finding 1). EVERY response-CFF producer — the response-header processor tail AND the
# native-RHP→CFF rehome in cdn-preprocess — uses this so the two can't drift (a rehomed static
# security header and a dynamic set of the SAME header both run in the one viewer-response function
# and share the same gap → both LOSSY). AWS-confirmed: a viewer-response function does NOT run on
# CloudFront-generated error responses (origin 4xx/5xx, custom error pages, WAF blocks).
VIEWER_RESPONSE_GAP_REASON = (
    "converted to a viewer-response CloudFront Function: it applies on normal responses, but a "
    "viewer-response function does not run on CloudFront-generated error responses (origin "
    "4xx/5xx, custom error pages, WAF blocks), so the header is absent/unmodified there.")


def lower_literal_value(value, context, empty_behavior=LOWERED_EMPTY_NONE):
    """A static string value → a versioned LiteralValue node. Caller pre-validates the string
    shape (validate_action_value); this stamps the version/context/empty_behavior."""
    return {"schema_version": LOWERED_SCHEMA_VERSION, "kind": "literal", "context": context,
            "value": value, "empty_behavior": empty_behavior}


def lower_dynamic_value(expr, context, empty_behavior=LOWERED_EMPTY_NONE, source=True):
    """Lower a DYNAMIC action-value expression to a versioned DynamicValue node, or return an NC
    reason string. Parses ONCE, then runs the full faithful-conversion proof on that tree
    (validate_dynamic_tree). Stores the JSON-safe AST so the generator never re-parses.
    `source` marks provenance: True = a USER Cloudflare value (gated by SOURCE_CONVERTIBLE_FUNCTIONS);
    False = an INTERNAL producer intrinsic (e.g. True-Client-IP's to_string(ip.src)) that bypasses the
    source allowlist and validates against the low-level _DYN_FUNC_CONTRACT. Provenance is STAMPED as
    `origin` so the persisted-IR re-validator (validate_lowered_value) applies the same mode post
    round-trip — else a persisted internal op would falsely fail the narrow source gate at the sink."""
    try:
        tree = parse_dynamic_expression(expr)
    except Exception as e:
        return f"dynamic value expression {expr!r} could not be parsed ({e})"
    bad = validate_dynamic_tree(tree, context, context_target(context), source)
    if bad:
        return bad
    return {"schema_version": LOWERED_SCHEMA_VERSION, "kind": "dynamic", "context": context,
            "ast": tree, "result_type": dynamic_expression_result_type(tree),
            "empty_behavior": empty_behavior, "raw": expr,
            "origin": "source" if source else "internal"}


def _slot_empty_behavior_ok(slot, kind, eb, value_is_empty):
    """Per-SLOT empty_behavior legality (round-27 finding 1). Returns a reason or None. This is the
    precision the coarse context check lacked — it pins the LEGAL empty_behavior to the (slot,kind)
    pair, and requires clear_query to line up with an actual empty query literal:
      - header literal  → only `none` (a static "" is an empty header; delete_header would delete
                          a value the source set, which is wrong).
      - header dynamic  → MUST be `delete_header` (Cloudflare deletes the header on an empty/
                          undefined dynamic result; `none` would keep a stray empty header).
      - rewrite path    → only `none` (both kinds; an empty path literal is rejected separately).
      - rewrite query literal  → `clear_query` IFF the value is "" (clear the query); else `none`.
      - rewrite query dynamic  → only `none`. clear_query on a dynamic value would drop the AST and
                          unconditionally clear — no runtime-empty branch is implemented.
      - redirect        → only `none` (both kinds; empty literal rejected separately)."""
    if slot in (SLOT_REQUEST_HEADER_VALUE, SLOT_RESPONSE_HEADER_VALUE):
        if kind == "literal":
            if eb != LOWERED_EMPTY_NONE:
                return f"header literal must have empty_behavior=none, got {eb!r}"
        else:  # dynamic
            if eb != LOWERED_EMPTY_DELETE_HEADER:
                return (f"header dynamic value must have empty_behavior=delete_header (Cloudflare "
                        f"deletes the header on an empty result), got {eb!r}")
        return None
    if slot == SLOT_REWRITE_PATH:
        if eb != LOWERED_EMPTY_NONE:
            return f"rewrite path must have empty_behavior=none, got {eb!r}"
        return None
    if slot == SLOT_REWRITE_QUERY:
        if kind == "literal":
            if value_is_empty and eb != LOWERED_EMPTY_CLEAR_QUERY:
                return "an empty rewrite query literal must have empty_behavior=clear_query"
            if not value_is_empty and eb != LOWERED_EMPTY_NONE:
                return f"a non-empty rewrite query literal must have empty_behavior=none, got {eb!r}"
        else:  # dynamic
            if eb != LOWERED_EMPTY_NONE:
                return (f"a dynamic rewrite query must have empty_behavior=none (clear_query would "
                        f"discard the expression and blindly clear the query), got {eb!r}")
        return None
    if slot == SLOT_REDIRECT_TARGET:
        if eb != LOWERED_EMPTY_NONE:
            return f"redirect target must have empty_behavior=none, got {eb!r}"
        return None
    return f"unknown slot {slot!r}"


def validate_lowered_value(value, expected_slot):
    """THE deep, independent hard-gate verifier for a persisted LoweredValue (round-26 finding 2;
    round-27 finding 1 made it SLOT-specific). Returns a reason if `value` is not a fully-valid
    LoweredValue for `expected_slot` (one of the SLOT_* constants), else None. Re-verifies
    JSON-reloaded data from scratch — does NOT trust stored fields:
      - strict allowed field set + schema_version + kind;
      - context == the slot's underlying context (a response value can't fill a request slot,
        a path value can't fill a query slot even though both are url_rewrite);
      - empty_behavior legal for the (slot, kind, empty?) triple (_slot_empty_behavior_ok);
      - literal: value is a string; an empty literal is rejected for path/redirect, and for a
        header/query only in the exact shape the slot allows (empty query literal must be
        clear_query — enforced above);
      - dynamic: the AST passes validate_dynamic_tree (STRICT NODE SCHEMA + field-source +
        signature + context + string result), AND result_type RE-DERIVED from the AST == the
        stored result_type == "string" (a lie like ast=len(...) + result_type="string" is caught)."""
    if expected_slot not in _LOWERED_SLOTS:
        return f"unknown expected_slot {expected_slot!r} (must be one of {sorted(_LOWERED_SLOTS)})"
    expected_context = _SLOT_CONTEXT[expected_slot]
    if not isinstance(value, dict):
        return f"LoweredValue must be an object, got {type(value).__name__}"
    if value.get("schema_version") != LOWERED_SCHEMA_VERSION:
        return f"LoweredValue schema_version must be {LOWERED_SCHEMA_VERSION}, got {value.get('schema_version')!r}"
    kind = value.get("kind")
    ctx = value.get("context")
    eb = value.get("empty_behavior")
    if ctx != expected_context:
        return f"LoweredValue context {ctx!r} != {expected_context!r} required by slot {expected_slot!r}"
    if eb not in _LOWERED_EMPTY_BEHAVIORS:
        return f"LoweredValue has unknown empty_behavior {eb!r}"
    if kind == "literal":
        allowed = {"schema_version", "kind", "context", "value", "empty_behavior"}
        extra = set(value) - allowed
        if extra:
            return f"literal LoweredValue has unknown field(s) {sorted(extra)}"
        v = value.get("value")
        if not isinstance(v, str):
            return f"literal value must be a string, got {v!r}"
        # An empty literal is only meaningful as a cleared query; every other slot rejects it.
        if v == "" and expected_slot in (SLOT_REDIRECT_TARGET, SLOT_REWRITE_PATH):
            return f"empty literal has no faithful meaning in slot {expected_slot!r}"
        eb_bad = _slot_empty_behavior_ok(expected_slot, "literal", eb, v == "")
        if eb_bad:
            return eb_bad
        return None
    if kind == "dynamic":
        allowed = {"schema_version", "kind", "context", "ast", "result_type", "empty_behavior",
                   "raw", "origin"}
        extra = set(value) - allowed
        if extra:
            return f"dynamic LoweredValue has unknown field(s) {sorted(extra)}"
        ast = value.get("ast")
        if not isinstance(ast, dict):
            return f"dynamic LoweredValue ast must be an object, got {type(ast).__name__}"
        # RE-DERIVE + RE-VALIDATE from the AST — do not trust the stored result_type. Honor the
        # persisted `origin`: a source value re-validates against the narrow SOURCE_CONVERTIBLE_FUNCTIONS
        # allowlist; an internal producer's value (origin="internal", e.g. True-Client-IP) against the
        # low-level contract — else a persisted internal op would falsely fail the source gate here.
        _src = value.get("origin", "source") == "source"
        bad = validate_dynamic_tree(ast, ctx, context_target(ctx), _src)
        if bad:
            return f"dynamic LoweredValue ast fails the contract: {bad}"
        derived = dynamic_expression_result_type(ast)
        if derived != value.get("result_type"):
            return (f"dynamic LoweredValue result_type {value.get('result_type')!r} != the type "
                    f"re-derived from the ast ({derived!r})")
        eb_bad = _slot_empty_behavior_ok(expected_slot, "dynamic", eb, False)
        if eb_bad:
            return eb_bad
        return None
    return f"LoweredValue has unknown kind {kind!r}"


# (round-27: is_lowered_value — the shallow shape check — was DELETED. It let a JSON-reloaded
# value with a lying result_type or a wrong context pass as "valid". Every consumer (chunk gate,
# generator) now calls validate_lowered_value, which re-derives the AST type and re-runs the
# contract against the expected context. There is no shallow fast-path anymore — a LoweredValue
# is only "valid" if it fully re-verifies.)


# ── VIEWER OP CONTRACTS (round-27 finding 2): the ONE authoritative op-shape registry ──
# The chunk hard gate previously only checked op["type"] presence + forbidden `add` + the lowered
# params — so a persisted op with an unknown type, a bad redirect status_code, a non-bool
# preserve_query_string, or a LEFTOVER legacy raw field (target_expression beside a valid target,
# value_expression beside value_lowered) sailed through and could be claimed as a converted
# artifact (the generator then emits a bare `// TODO` for an unknown type). This registry is the
# single definition the chunk validator (and the _append_viewer_op sink) enforce so no such op
# reaches codegen / the ledger. Each entry:
#   phase           : "request" | "response" | None(=either; e.g. bulk_redirect placement)
#   lowered         : {param_name: SLOT_*}  — each MUST be a valid LoweredValue for that slot
#   lowered_optional: subset of `lowered` keys that MAY be absent (rewrite path/query), with a
#                     require_one rule enforced separately; everything else in `lowered` is required
#   required        : {param_name: predicate(value)->bool}  — scalar params that MUST be present+valid
#   optional        : {param_name: predicate(value)->bool}  — scalar params that MAY be present
#   name_param      : the header-name param, validated as a non-empty header token, if set
# ANY param on the op not covered by lowered/required/optional/name_param is UNKNOWN → rejected.
# The op MUST NOT carry any _LEGACY_RAW_VALUE_FIELDS key (a pre-lowering raw string that must never
# coexist with a LoweredValue).
_REDIRECT_STATUS_CODES_SET = frozenset({301, 302, 303, 307, 308})
_LEGACY_RAW_VALUE_FIELDS = frozenset({"target_expression", "value_expression", "path_expression",
                                      "query_expression", "target_url", "value", "expression"})
# A header field-name token per RFC 7230 (what CloudFront/CFF will accept as a header key).
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


def header_name_is_valid(v):
    """True if `v` is a syntactically valid HTTP header field-name (RFC 7230 token). The SINGLE
    definition the header processors (to NC a malformed SOURCE name) and the viewer-op contract
    (to backstop an internal-producer bug) both use."""
    return isinstance(v, str) and bool(_HEADER_NAME_RE.match(v))


# ── CloudFront Functions header-mutation CAPABILITY (round-27 review-2 finding 2) ──
# Beyond RFC-token SYNTAX, a CFF cannot add/modify/delete certain headers: it fails CloudFront's
# post-execution validation and returns HTTP 502 to the viewer at RUNTIME (not at deploy, not in
# the console test tool). AWS-confirmed (3 subagents + docs edge-function-restrictions-all.html):
#   - DISALLOWED (not exposed to ANY edge function; a function can't add them) — both phases, incl.
#     the two PREFIX families X-Amz-Cf-* and X-Edge-*.
#   - READ-ONLY per event: viewer-request {CDN-Loop, Content-Length, Host, Transfer-Encoding, Via};
#     viewer-response {Warning, Via}. (Content-Length/Encoding/Transfer-Encoding are writable in a
#     CFF viewer-response — they're read-only only for Lambda@Edge, which this tool never emits.)
# All names lower-cased; matched case-insensitively. A Cloudflare header transform whose target is
# one of these has NO faithful CFF conversion → NON_CONVERTIBLE at the source; the persisted op
# contract also FATALs it as a backstop (an internal producer must never emit one).
_CFF_DISALLOWED_HEADERS = frozenset({
    "connection", "expect", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "proxy-connection", "trailer", "upgrade",
    "x-accel-buffering", "x-accel-charset", "x-accel-limit-rate", "x-accel-redirect",
    "x-amzn-auth", "x-amzn-cf-billing", "x-amzn-cf-id", "x-amzn-cf-xff", "x-amzn-errortype",
    "x-amzn-fle-profile", "x-amzn-header-count", "x-amzn-header-order",
    "x-amzn-lambda-integration-tag", "x-amzn-requestid",
    "x-cache", "x-forwarded-proto", "x-real-ip",
    "cloudfront-viewer-cert-pem", "client-cert", "client-cert-chain",
})
_CFF_DISALLOWED_PREFIXES = ("x-amz-cf-", "x-edge-")
_CFF_READONLY_REQUEST = frozenset({"cdn-loop", "content-length", "host", "transfer-encoding", "via"})
_CFF_READONLY_RESPONSE = frozenset({"warning", "via"})


def header_mutation_capability_reason(name, phase):
    """Return a reason if a CloudFront Function in `phase` (request|response|request_header|
    response_header) CANNOT faithfully add/modify/delete the header `name`, else None (round-27
    review-2 finding 2). Checks the DISALLOWED list + prefix families (both phases) and the
    phase-scoped READ-ONLY list. Case-insensitive. `name` must already be a valid token (caller
    checks header_name_is_valid first). This is the SINGLE capability authority the processors (to
    NC a source input) and the viewer-op contract (to reject an internal-producer bug) both use."""
    if not isinstance(name, str):
        return f"header name must be a string, got {type(name).__name__}"
    low = name.lower()
    if low in _CFF_DISALLOWED_HEADERS or low.startswith(_CFF_DISALLOWED_PREFIXES):
        return (f"header {name!r} is DISALLOWED in a CloudFront Function (not exposed; adding it "
                "fails CloudFront validation → HTTP 502 at runtime) — no faithful conversion")
    is_response = phase in ("response", "response_header")
    readonly = _CFF_READONLY_RESPONSE if is_response else _CFF_READONLY_REQUEST
    if low in readonly:
        return (f"header {name!r} is READ-ONLY in a viewer-{'response' if is_response else 'request'} "
                "CloudFront Function (add/modify/delete → HTTP 502 at runtime) — no faithful conversion")
    return None


_is_header_name = header_name_is_valid  # local alias for the contract predicate table


def _is_bool(v):
    return isinstance(v, bool)


def _is_redirect_status(v):
    return v in _REDIRECT_STATUS_CODES_SET


def _is_nonneg_int(v):
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


def _is_tcp_port(v):
    # A valid TCP port 1..65535 (round-27 review-2 finding 4: 0 and 65536 are not ports).
    return isinstance(v, int) and not isinstance(v, bool) and 1 <= v <= 65535


def _is_nonempty_str(v):
    return isinstance(v, str) and v != ""


def _is_str(v):
    return isinstance(v, str)


VIEWER_OP_CONTRACTS = {
    "redirect": {
        "phase": "request",
        "lowered": {"target": SLOT_REDIRECT_TARGET},
        "required": {"status_code": _is_redirect_status, "preserve_query_string": _is_bool},
    },
    "rewrite": {
        "phase": "request",
        "lowered": {"path_lowered": SLOT_REWRITE_PATH, "query_lowered": SLOT_REWRITE_QUERY},
        "lowered_optional": {"path_lowered", "query_lowered"},  # ≥1 required (require_one)
        "require_one": ("path_lowered", "query_lowered"),
    },
    "set_request_header": {
        "phase": "request", "name_param": "name",
        "lowered": {"value_lowered": SLOT_REQUEST_HEADER_VALUE},
    },
    "set_response_header": {
        "phase": "response", "name_param": "name",
        "lowered": {"value_lowered": SLOT_RESPONSE_HEADER_VALUE},
    },
    "remove_request_header": {"phase": "request", "name_param": "name"},
    "remove_response_header": {"phase": "response", "name_param": "name"},
    # origin_override: ≥1 real override (require_one), each a valid type — host/host_header/sni
    # NON-EMPTY strings, port a valid TCP port 1..65535 (round-27 review-2 finding 4; was: int host
    # accepted, port 0/65536 accepted, empty host accepted, no-override op marked EXACT then dropped).
    "origin_override": {
        "phase": "request",
        "optional": {"origin_host": _is_nonempty_str, "host_header": _is_nonempty_str,
                     "origin_port": _is_tcp_port, "sni": _is_nonempty_str},
        "require_one": ("origin_host", "host_header", "origin_port", "sni"),
    },
    "cache_bypass": {"phase": "request"},
    # bulk_redirect is KVS-driven (a fixed template block, not per-op codegen); entry_count is a
    # descriptive count of the KVS entries it serves.
    "bulk_redirect": {"phase": "request", "optional": {"entry_count": _is_nonneg_int}},
}


# ── CONVERSION-POLICY AUTHORITY (docs/conversion-policy.md) — the SINGLE source ─────────────────
# ONE place for the convertible allow-lists so the processor, chunk validator, generator and
# preprocess can't drift into disagreeing lists. STEP 1 initializes these to the CURRENT values (a
# behavior-preserving consolidation — NC counts / ledger claims / generated JS+HCL must NOT change).
# STEP 3 NARROWS them (functions → the core set; response header `add` → NC; numeric geo → NC).
# Do NOT narrow here.

# Header operations ACCEPTED FOR STRUCTURAL VALIDATION, PER PHASE (validate_header_input). NOT an
# "is convertible" list: Cloudflare's Request Header Transform has no `add`; the response phase still
# ACCEPTS `add` here so the response processor's dedicated block can NC it with a SPECIFIC reason (a
# native RHP can't append) instead of a generic "unsupported operation" — `add` is NON-convertible in
# both phases regardless. ORDERED tuples, not sets: the order is surfaced verbatim in the NC reason
# (validate_header_input's ", ".join), so it must stay stable for a zero-diff conversion report.
HEADER_OPS_ACCEPTED_FOR_VALIDATION_BY_PHASE = {
    "request": ("set", "remove"),
    "response": ("set", "add", "remove"),
}

# SOURCE allowlist: the dynamic-value functions a USER's Cloudflare rule value may auto-convert (the
# narrowed policy core). SEPARATE from _DYN_FUNC_CONTRACT (the low-level renderer/capability table,
# KEPT for internal producers + Step-5 reachability). `concat` is polymorphic and handled on its own
# codegen path (not in _DYN_FUNC_CONTRACT); it is listed here to document the source core. INTERNAL
# producers (lower_dynamic_value source=False, e.g. True-Client-IP's to_string(ip.src)) bypass this
# allowlist and validate against _DYN_FUNC_CONTRACT directly.
SOURCE_CONVERTIBLE_FUNCTIONS = frozenset({"concat", "lower", "upper", "regex_replace", "wildcard_replace"})

# Condition-leaf short fields that are NON-convertible (checked by validate_condition_semantics, via
# the shared processor-side _screen_condition_semantics in cdn_rule_processors). The NUMERIC geo
# fields: CloudFront delivers them as header TEXT, so a faithful numeric comparison needs a parse the
# narrowed policy declines to emit, and they don't occur in real configs. The STRING / BOOLEAN geo
# fields (country, city, region, region_code, postal_code, timezone, continent, is_eu) stay
# convertible — they are NOT in this set.
NON_CONVERTIBLE_CONDITION_FIELDS = frozenset({"asnum", "latitude", "longitude", "metro_code"})

# Header-`add` op types no producer may ever emit — an independent historical/error defense line for
# the chunk validator's Check3. NOT derived from VIEWER_OP_CONTRACTS: add_*_header is not a legal
# viewer op type at all (the complement of the allowlist, never a member). Pairs with
# HEADER_OPS_ACCEPTED_FOR_VALIDATION_BY_PHASE — `add` is accepted there only for a better NC reason.
FORBIDDEN_HEADER_ADD_OP_TYPES = frozenset({"add_request_header", "add_response_header", "add_header"})

# Viewer-op contract types NOT routed through the GENERIC viewer-op artifact channel, so preprocess
# derives _WIRED_VIEWER_OP_TYPES = VIEWER_OP_CONTRACTS − this set. `bulk_redirect` IS wired, but via
# its OWN shared-artifact branch (special-cased before the generic set is consulted — deleting that
# branch would silently drop bulk redirects). (serve_error_inline was RETIRED in Step 5: inline
# custom-error is permanently NON_CONVERTIBLE, so the op type no longer exists in VIEWER_OP_CONTRACTS
# and a stray op fails loud as an unknown type at the sink / generator / chunk gate.)
VIEWER_OP_CONTRACT_NOT_GENERIC_WIRED = frozenset({"bulk_redirect"})


def validate_viewer_op_contract(op, phase=None):
    """Validate a persisted viewer op against VIEWER_OP_CONTRACTS (round-27 finding 2). Returns a
    reason on the FIRST violation, else None. Enforces: known op type; op phase matches (if the
    caller names one AND the contract pins a phase); every declared lowered param is a valid
    LoweredValue for its SLOT (via validate_lowered_value); require_one for rewrite; scalar
    required present+valid / optional valid-if-present; header name_param a valid token; NO unknown
    param; NO leftover legacy raw-value field. This is the single op-shape authority the chunk
    validator and the _append_viewer_op sink both call — no separate, drifting allow-lists."""
    if not isinstance(op, dict):
        return f"op must be an object, got {type(op).__name__}"
    t = op.get("type")
    spec = VIEWER_OP_CONTRACTS.get(t)
    if spec is None:
        return f"unknown op type {t!r} — not in VIEWER_OP_CONTRACTS (a converter bug or drift)"
    want_phase = spec.get("phase")
    if phase is not None and want_phase is not None and phase != want_phase:
        return f"op type {t!r} is a {want_phase}-phase op but appears in the {phase} phase"
    params = op.get("params", {})
    if not isinstance(params, dict):
        return f"op {t!r} params must be an object, got {type(params).__name__}"
    # No leftover pre-lowering raw value field may coexist with (or stand in for) a LoweredValue.
    raw_leftover = set(params) & _LEGACY_RAW_VALUE_FIELDS
    if raw_leftover:
        return (f"op {t!r} carries legacy raw value field(s) {sorted(raw_leftover)} — a raw "
                "expression/value must never reach the persisted IR; only lowered params are valid")
    lowered_spec = spec.get("lowered", {})
    lowered_optional = spec.get("lowered_optional", set())
    required = spec.get("required", {})
    optional = spec.get("optional", {})
    name_param = spec.get("name_param")
    known = set(lowered_spec) | set(required) | set(optional)
    if name_param:
        known.add(name_param)
    unknown = set(params) - known
    if unknown:
        return f"op {t!r} has unknown param(s) {sorted(unknown)}"
    # lowered params (each validated against its slot)
    for pkey, slot in lowered_spec.items():
        if pkey not in params:
            if pkey not in lowered_optional:
                return f"op {t!r} missing lowered param {pkey!r}"
            continue
        reason = validate_lowered_value(params.get(pkey), slot)
        if reason:
            return f"op {t!r} param {pkey!r} is not a valid LoweredValue: {reason}"
    if "require_one" in spec and not any(k in params for k in spec["require_one"]):
        return f"op {t!r} must carry at least one of {list(spec['require_one'])}"
    # scalar params
    for pkey, pred in required.items():
        if pkey not in params:
            return f"op {t!r} missing required param {pkey!r}"
        if not pred(params[pkey]):
            return f"op {t!r} param {pkey!r} has an invalid value {params[pkey]!r}"
    for pkey, pred in optional.items():
        if pkey in params and not pred(params[pkey]):
            return f"op {t!r} param {pkey!r} has an invalid value {params[pkey]!r}"
    if name_param:
        if name_param not in params:
            return f"op {t!r} missing header name param {name_param!r}"
        if not _is_header_name(params[name_param]):
            return f"op {t!r} param {name_param!r} is not a valid header name: {params[name_param]!r}"
        # CAPABILITY backstop (round-27 review-2 finding 2): a header op must not target a header a
        # CloudFront Function can't set/remove (Host / Via / Content-Length / … → 502). The
        # processor NCs such a SOURCE header; this catches an internal-producer bug that hand-built
        # one. Phase from the op type (set_request_header→request, set_response_header→response).
        _hphase = "response" if "response" in t else "request"
        cap = header_mutation_capability_reason(params[name_param], _hphase)
        if cap:
            return f"op {t!r} {cap}"
    return None


# The condition-leaf value types the tree may carry: a scalar str/int/bool, or a list of scalars
# for an `in`-set. float is NOT a valid CF condition value.
def _is_condition_scalar(v):
    return isinstance(v, (str, bool)) or (isinstance(v, int) and not isinstance(v, bool))


def _is_condition_value(v):
    if isinstance(v, list):
        return all(_is_condition_scalar(x) for x in v)
    return _is_condition_scalar(v)


def validate_condition_tree(cond, _depth=0):
    """STRICT structural schema for a parsed condition tree (round-27 review-2 finding 3). Returns a
    reason for the FIRST malformed node, else None. The op contract validated type+params but NOT
    the condition, so a persisted op could carry condition [] / "x" (→ generator AttributeError) or
    {"future":"x"} / {"field":"host"} with no op (→ silently `if(false)` while the ledger still
    claims the op converted). Every node must be EXACTLY one of:
      - None                                   (unconditional; the op fires always)
      - {"always": true}                       (unconditional)
      - leaf   {"field": nonempty-str, "op": nonempty-str, "value": <str|int|bool|list>,
                optional "size_check": bool, optional "transform": str}
      - logic  {"logic": "and"|"or", "parts": [ <node>, ... ]}   (parts a list, ≥1, each recursed)
      - logic  {"logic": "not", "item": <node>}                  (item recursed)
    Unknown keys / wrong types / unknown logic / a leaf missing field-or-op → a reason. Bounded
    recursion depth guards a pathological/cyclic reload."""
    if _depth > 64:
        return "condition tree is too deep (possible cycle or malformed reload)"
    if cond is None:
        return None
    if not isinstance(cond, dict):
        return f"condition must be an object or null, got {type(cond).__name__}"
    if cond.get("always") is True:
        if set(cond) != {"always"}:
            return f"unconditional condition must be exactly {{'always': true}}, got keys {sorted(cond)}"
        return None
    if "logic" in cond:
        logic = cond.get("logic")
        if logic in ("and", "or"):
            extra = set(cond) - {"logic", "parts"}
            if extra:
                return f"{logic} node has unknown field(s) {sorted(extra)}"
            parts = cond.get("parts")
            if not isinstance(parts, list) or not parts:
                return f"{logic} node `parts` must be a non-empty list, got {parts!r}"
            for p in parts:
                bad = validate_condition_tree(p, _depth + 1)
                if bad:
                    return bad
            return None
        if logic == "not":
            extra = set(cond) - {"logic", "item"}
            if extra:
                return f"not node has unknown field(s) {sorted(extra)}"
            if "item" not in cond:
                return "not node missing `item`"
            return validate_condition_tree(cond.get("item"), _depth + 1)
        return f"unknown logic operator {logic!r}"
    # leaf. Base keys + per-field extras:
    #  - a synthetic indexed field carries its NAME key (header_named→header_name, etc.);
    #  - `kvs_ips`, a BUILD-TIME transient on in_kvs/not_in_kvs (resolved IP rows, popped into KVS
    #    and stripped before persist — valid ON the op at the sink, gone by the chunk gate);
    #  - a `full_uri` + wildcard/strict_wildcard leaf carries DERIVED host_pattern/path_pattern/
    #    scheme (parser splits the absolute-URL wildcard so the renderer matches host and path
    #    separately — round-27 review-4 finding 2). These are allowed ONLY on that exact shape.
    field = cond.get("field")
    op = cond.get("op")
    base_op = op[4:] if isinstance(op, str) and op.startswith("not_") else op
    allowed_leaf = {"field", "op", "value", "size_check", "transform"}
    name_key = _SYNTHETIC_NAME_KEY.get(field)
    if name_key:
        allowed_leaf.add(name_key)
    if base_op in ("in_kvs", "not_in_kvs"):
        allowed_leaf.add("kvs_ips")
    is_full_uri_wildcard = field == "full_uri" and base_op in ("wildcard", "strict_wildcard")
    if is_full_uri_wildcard:
        allowed_leaf |= {"host_pattern", "path_pattern", "scheme"}
    extra = set(cond) - allowed_leaf
    if extra:
        return f"condition leaf has unknown field(s) {sorted(extra)}"
    if not _is_nonempty_str(field):
        return f"condition leaf `field` must be a non-empty string, got {field!r}"
    if not _is_nonempty_str(op):
        return f"condition leaf `op` must be a non-empty string, got {op!r}"
    if "value" in cond and not _is_condition_value(cond.get("value")):
        return f"condition leaf `value` has an invalid type: {cond.get('value')!r}"
    if "size_check" in cond and not isinstance(cond.get("size_check"), bool):
        return f"condition leaf `size_check` must be a boolean, got {cond.get('size_check')!r}"
    if "transform" in cond and not _is_nonempty_str(cond.get("transform")):
        return f"condition leaf `transform` must be a non-empty string, got {cond.get('transform')!r}"
    # a synthetic indexed field's name key must be a non-empty string when present.
    if name_key and name_key in cond and not _is_nonempty_str(cond.get(name_key)):
        return f"condition leaf `{name_key}` must be a non-empty string, got {cond.get(name_key)!r}"
    # full_uri wildcard comes in TWO legit shapes: (a) ABSOLUTE-URL wildcard (https://host/path*,
    # *://host/path*) — the parser splits it into host_pattern/path_pattern(/scheme) derived fields and
    # the generator matches host+path (cdn-generate-js ~397); (b) SCHEME/HOST-LESS wildcard (e.g.
    # */admin/*) — NO derived fields, and the generator RECONSTRUCTS the absolute URL and matches the
    # whole thing (cdn-generate-js ~408). Only shape (a) carries + requires derived fields; requiring
    # them on shape (b) makes this validator reject a legal */admin/* at the sink (this shape has
    # previously failed here under the full validator). So enforce ONLY when the leaf HAS derived
    # fields or its value is an absolute-URL wildcard that SHOULD have them; otherwise pass it through
    # to the generator's reconstruct branch.
    if is_full_uri_wildcard:
        v = cond.get("value")
        if not _is_nonempty_str(v):
            return f"full_uri wildcard leaf `value` must be a non-empty string, got {v!r}"
        reparsed = _parse_full_uri_wildcard(v)
        has_derived = any(k in cond for k in ("host_pattern", "path_pattern", "scheme"))
        if has_derived or reparsed[0] or reparsed[1]:
            hp, pp = cond.get("host_pattern"), cond.get("path_pattern")
            if not _is_nonempty_str(hp) or not _is_nonempty_str(pp):
                return ("full_uri absolute-URL wildcard leaf must carry BOTH a non-empty host_pattern "
                        f"and path_pattern, got host_pattern={hp!r}, path_pattern={pp!r}")
            if cond.get("scheme") not in ("http", "https", None):
                return (f"full_uri wildcard `scheme` must be 'http', 'https', or None, got "
                        f"{cond.get('scheme')!r}")
            if reparsed != (hp, pp, cond.get("scheme")):
                return (f"full_uri wildcard derived fields disagree with a fresh parse of value {v!r}: "
                        f"{reparsed!r} vs {(hp, pp, cond.get('scheme'))!r}")
    return None


# ── CONDITION SEMANTICS (round-27 review-3 finding 1): the leaf must be EXECUTABLE, not just
# structurally well-formed. The renderer (_op_to_js / _apply_leaf_modifiers / _get_accessor in
# cdn-generate-js) can only emit a bounded set of operators, transforms, and fields; a leaf outside
# them renders to `false` / compares against 'None' / queries an empty header name / silently drops
# the transform — while the ledger still claims the op converted. These sets are the renderer's
# actual capability; the generator has a completeness relationship to them (a field here must have
# an accessor there). ──
# The condition-leaf short field-names that DO have a CloudFront edge source (derived from the
# authoritative CF_FIELD_MAP minus the unmappable set) + the synthetic indexed fields. A persisted
# leaf carries the SHORT name (host, country, uri.path, header_named, …), not the raw CF name.
_MAPPABLE_SHORT_FIELDS = (set(CF_FIELD_MAP.values()) - UNMAPPABLE_FIELDS) | _SYNTHETIC_CONVERTIBLE_FIELDS
_TRANSFORMS = frozenset({"lowercase", "uppercase"})

# ── TYPED CONDITION CONTRACT (round-27 review-4 finding 1): a leaf is executable only if FIELD ×
# OPERATOR × VALUE agree. Checking them independently let host eq [list] / is_eu contains x /
# host matches 123 / ip.src in_kvs 123 pass → wrong string compare, .includes() on a boolean, and
# a generator crash on an int regex. Group operators by the value type they render correctly. ──
# String comparisons/substring/pattern ops (render `x === s` / x.includes(s) / regex / wildcard).
_STRING_OPS = frozenset({"eq", "ne", "contains", "starts_with", "ends_with", "matches",
                         "wildcard", "strict_wildcard"})
# Numeric comparisons (render `x OP n`). eq/ne are shared with string (a numeric eq/ne is fine).
_NUMERIC_OPS = frozenset({"eq", "ne", "gt", "ge", "lt", "le"})
# Boolean ops (is_eu eq/ne true|false).
_BOOLEAN_OPS = frozenset({"eq", "ne"})
# All renderer operators (a `not_` prefix wraps any). in_list is DELIBERATELY absent — an
# unresolved named list renders to _NEVER (false); it must be resolved to in_kvs (or NC'd).
_RENDERABLE_OPS = _STRING_OPS | _NUMERIC_OPS | frozenset({"in", "in_kvs"})
# Field short-name → value TYPE for the condition contract. Reuses _FIELD_RESULT_TYPE (the single
# field-type authority; its _TYPE_* values ARE "number"/"boolean"/"ip"/"string") so the two can't
# drift. A field absent from it ⇒ string (host, uri.path, country, full_uri, referer, …).
# size_check turns ANY field into a NUMBER length comparison, so it overrides the base type.
def _condition_field_type(field):
    return _FIELD_RESULT_TYPE.get(field, _TYPE_STRING)


def _condition_leaf_semantics(cond, phase):
    """The TYPED field × operator × value contract for ONE condition leaf (round-27 review-4
    finding 1). Returns a reason on the first violation, else None. This is where field, operator
    and value are checked TOGETHER — checking them independently let host eq [list] (list value on
    a scalar op), is_eu contains x (.includes on a boolean), host matches 123 (int regex → generator
    crash), ip.src in_kvs 123 (non-string list name) all pass. The type is: size_check ⇒ number
    (len is a count); else _condition_field_type(field) (number/boolean/ip); else string. full_uri
    is string-typed with a wildcard host/path special (validated in the leaf schema)."""
    field = cond.get("field")
    op = cond.get("op", "")
    base_op = op[4:] if op.startswith("not_") else op
    value = cond.get("value")
    name_key = _SYNTHETIC_NAME_KEY.get(field)
    has_value = "value" in cond
    size_check = bool(cond.get("size_check"))

    # FIELD source + phase.
    if field != "full_uri" and field not in _MAPPABLE_SHORT_FIELDS:
        return (f"field {field!r} has no CloudFront edge source — the renderer would emit `false` "
                "while the ledger claims the op converted")
    if field in RESPONSE_ONLY_FIELDS and phase != "response":
        return f"field {field!r} is response-only but used in the {phase} phase"
    # OPERATOR must be renderable; in_list (unresolved) must never persist.
    if base_op == "in_list":
        return ("uses an UNRESOLVED named list (in_list) — it renders to `false`; resolve it to "
                "in_kvs or mark the rule non-convertible before persisting")
    if base_op not in _RENDERABLE_OPS:
        return f"operator {op!r} is not renderer-supported (renders to `false`)"
    # INDEXED field must carry a non-empty name.
    if name_key and not _is_nonempty_str(cond.get(name_key)):
        return f"indexed field {field!r} is missing its {name_key!r}"
    # in_kvs is an IP-list membership test: only on ip.src, value a non-empty list NAME (string).
    if base_op == "in_kvs":
        if field != "ip.src":
            return f"in_kvs is only valid on ip.src (IP-list membership), not field {field!r}"
        if not _is_nonempty_str(value):
            return f"in_kvs value must be a non-empty list name (string), got {value!r}"
        return None
    # TRANSFORM (lower/upper) is a STRING operation — only on a string-typed leaf (not a
    # number/boolean/ip/size_check leaf), and must be renderer-supported.
    transform = cond.get("transform")
    # EFFECTIVE type: len(x) is a NUMBER count (overrides base); an indexed field's value is a
    # string; else the field's declared type (string default).
    if size_check:
        eff_type = _TYPE_NUMBER
    elif name_key:
        eff_type = _TYPE_STRING
    else:
        eff_type = _condition_field_type(field)
    if transform is not None:
        if transform not in _TRANSFORMS:
            return f"transform {transform!r} is not renderer-supported (silently ignored)"
        if eff_type != _TYPE_STRING:
            return f"transform {transform!r} is only valid on a string field, not {eff_type} {field!r}"
    # VALUE presence.
    if not has_value:
        return f"leaf (field {field!r}, op {op!r}) is missing `value`"
    # EXISTENCE form: value is True is the "name present" check — ONLY on an indexed field, and
    # only with eq (the renderer treats value=True as existence regardless of op, so pin it to eq).
    if value is True and name_key and not size_check:
        if base_op != "eq":
            return f"indexed existence check (value=true) must use eq, not {op!r}"
        return None
    # `in` set-membership: a non-empty homogeneous list on a STRING field (the renderer emits
    # js_array(value).includes(accessor) — only sound for string values / string field).
    if base_op == "in":
        if not isinstance(value, list) or not value:
            return f"`in` needs a non-empty list value, got {value!r}"
        if not all(isinstance(x, str) for x in value):
            return f"`in` list must be all strings, got {value!r}"
        if eff_type != _TYPE_STRING:
            return f"`in` is only valid on a string field, not {eff_type} {field!r}"
        return None
    # a list value is ONLY valid with `in` (handled above); any other op with a list is wrong.
    if isinstance(value, list):
        return f"operator {op!r} does not take a list value, got {value!r}"
    # TYPED scalar compare: pick the operator set for the effective type.
    if eff_type == _TYPE_NUMBER:
        if base_op not in _NUMERIC_OPS:
            return f"operator {op!r} is not valid on a numeric field/len ({field!r})"
        if not (isinstance(value, int) and not isinstance(value, bool)):
            return f"numeric comparison on {field!r} needs an integer value, got {value!r}"
        return None
    if eff_type == _TYPE_BOOL:
        if base_op not in _BOOLEAN_OPS:
            return f"operator {op!r} is not valid on the boolean field {field!r} (use eq/ne)"
        if not isinstance(value, bool):
            return f"boolean field {field!r} needs a true/false value, got {value!r}"
        return None
    if eff_type == _TYPE_IP:
        # ip.src as a scalar leaf has no string/number compare the renderer emits (only in_kvs,
        # handled above). A bare ip.src eq/contains/… is not convertible.
        return (f"field 'ip.src' has no scalar comparison at the edge — only an in_kvs IP-list "
                "membership test is convertible")
    # string field: a string-op with a string value.
    if base_op not in _STRING_OPS:
        return f"operator {op!r} is not valid on the string field {field!r}"
    if not isinstance(value, str):
        return f"string comparison on {field!r} needs a string value, got {value!r}"
    return None


def _continent_value_mentions_t1(value):
    """True if a `continent` condition value references Cloudflare's Tor pseudo-continent "T1"
    — a bare "T1" (eq/ne) or "T1" among an in-{set}. Case-insensitive, whitespace-tolerant."""
    if isinstance(value, str):
        return value.strip().upper() == "T1"
    if isinstance(value, (list, tuple)):
        return any(isinstance(v, str) and v.strip().upper() == "T1" for v in value)
    return False


def validate_condition_semantics(cond, phase, _depth=0):
    """Prove a condition is EXECUTABLE for `phase` ("request"|"response") — the TYPED field ×
    operator × value contract, applied to every leaf (round-27 review-3 finding 1 → review-4
    finding 1). Returns a reason on the FIRST violation, else None. Assumes validate_condition_tree
    already passed (shape valid). Recurses logic nodes; each leaf goes through
    _condition_leaf_semantics."""
    if _depth > 64:
        return "condition tree too deep"
    if cond is None or cond.get("always") is True:
        return None
    if "logic" in cond:
        if cond["logic"] == "not":
            return validate_condition_semantics(cond.get("item"), phase, _depth + 1)
        for p in cond.get("parts", []):
            bad = validate_condition_semantics(p, phase, _depth + 1)
            if bad:
                return bad
        return None
    field = cond.get("field")
    if field in NON_CONVERTIBLE_CONDITION_FIELDS:
        return f"condition leaf: field {field!r} is non-convertible per conversion policy"
    # VALUE-level NC (conversion-policy geo decision): a `continent` condition mentioning
    # Cloudflare's Tor pseudo-continent "T1" is non-convertible in EVERY form. CloudFront's continent
    # is DERIVED from the country code (the continent KVS maps ISO country → NA/EU/AS/AF/SA/OC/AN) and
    # can NEVER be T1, so eq "T1" would render a never-matching branch and ne "T1" an always-true one —
    # both silent wrong conversions. Op-agnostic (eq/ne/in/not-in/outer-not all fail the same way).
    if field == "continent" and _continent_value_mentions_t1(cond.get("value")):
        return ("condition leaf: continent value 'T1' is non-convertible — Cloudflare's T1 is the "
                "Tor pseudo-continent and cannot be derived from a CloudFront country code")
    bad = _condition_leaf_semantics(cond, phase)
    return f"condition leaf: {bad}" if bad else None


def validate_viewer_op(op, phase=None):
    """THE full persisted-op validator (round-27 review-2 finding 3 → review-3 finding 1): the
    op-shape CONTRACT (validate_viewer_op_contract) PLUS the condition gate. Returns a reason on the
    first violation, else None. This is what _append_viewer_op, the chunk validator, AND the
    generator all call so no drifting per-caller checks exist. On top of the contract it enforces:
      - a CONVERTED op MUST carry a STRUCTURED `condition` — NEVER `raw_expression` (review-3: raw
        is only an NC diagnostic; the generator must not re-parse it, closing the last raw-drives-
        codegen seam). An op with raw_expression set is rejected; an op with no condition is rejected;
      - the condition is structurally valid (validate_condition_tree) — a list/string condition
        would AttributeError in the generator, an unknown-key dict would silently render `if(false)`;
      - the condition is SEMANTICALLY executable for `phase` (validate_condition_semantics) — every
        field has a CloudFront source + is phase-legal, every operator/transform is renderer-
        supported, values are present and well-typed, indexed fields carry their name. Without this
        a bogus-but-well-formed leaf (op 'bogus', field 'future', missing value, unknown transform)
        renders to `false`/'None'/an empty-name lookup while the ledger claims the op converted.
    `phase` ("request"|"response") is required for the semantic check; when None (the generator's
    phase-agnostic call) the field-source/phase checks that need it are still run against the
    stricter 'request' rules is NOT assumed — instead the semantic check is run with the op-derived
    phase when determinable, else skipped for the phase-only rules (structure + operator + value +
    transform still apply)."""
    contract = validate_viewer_op_contract(op, phase)
    if contract:
        return contract
    cond = op.get("condition")
    raw = op.get("raw_expression")
    if raw is not None:
        return ("op carries a raw_expression — a converted op must have a STRUCTURED condition; "
                "raw_expression is an NC diagnostic only and must not drive codegen")
    if cond is None:
        return "op has no condition (a converted op needs a structured condition gate)"
    bad = validate_condition_tree(cond)
    if bad:
        return f"op condition is malformed: {bad}"
    # SEMANTIC executability. Phase for the field-source/response-only rule: the caller's phase if
    # given, else derive from the op type (set_response_header/… → response; else request).
    sem_phase = phase if phase in ("request", "response") else (
        "response" if "response" in (op.get("type") or "") else "request")
    bad = validate_condition_semantics(cond, sem_phase)
    if bad:
        return f"op condition is not executable: {bad}"
    return None


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


# ── AST-NATIVE validation cores (round-26 finding 4: parse ONCE, pass the tree) ──
# The context→emit-target map (redirect/rewrite/header values are all request-phase; only a
# response header can source response-only fields like http.response.code).
_CONTEXT_TARGET = {"response_header": "response"}


def context_target(context):
    """The field-source `target` phase for an emit context (round-26)."""
    return _CONTEXT_TARGET.get(context, "cff")


def find_unmappable_fields(tree, target="cff"):
    """AST-native: return a reason for the FIRST field in `tree` with no CloudFront source, else
    None. The tree-native core of value_expression_unmappable — callers that already parsed pass
    the tree so there's no re-parse (round-26 finding 4)."""
    for f in _dyn_tree_fields(tree):
        ok, reason = field_convertibility(f, target)
        if not ok:
            return reason
    return None


def validate_ast_node_schema(node):
    """STRICT structural schema for a parsed dynamic-expr AST node (round-27 finding 3). Returns a
    reason for the FIRST malformed node, else None. This is the shape gate the result-type and
    signature checks ASSUME but never enforced — a persisted/hand-built/JSON-reloaded AST could
    carry a literal dict/list/None (str()-ified by the generator into a Python-repr string), a
    field with a non-string/empty value, or a func_call whose args isn't a list, and still pass the
    old checks. Every node must be EXACTLY one of:
      - literal   : {type:"literal", value: str|int|float|bool}  (NO dict/list/None value)
      - field     : {type:"field",   value: non-empty str}
      - func_call : {type:"func_call", func: non-empty str, args: list}  (recurse into args)
    Unknown `type`, unknown extra keys, or a wrong value type → a reason. Recurses func_call args.
    NOTE: bool is a subclass of int — a boolean literal is allowed here (it's a real CF type)."""
    if not isinstance(node, dict):
        return f"AST node must be an object, got {type(node).__name__}"
    ntype = node.get("type")
    if ntype == "literal":
        extra = set(node) - {"type", "value"}
        if extra:
            return f"literal node has unknown field(s) {sorted(extra)}"
        v = node.get("value")
        # bool is intentionally allowed (isinstance(True, int) is True, but a boolean literal is a
        # legal Cloudflare type). Reject dict/list/None and anything else.
        if not isinstance(v, (str, int, float, bool)):
            return (f"literal value must be a string, number, or boolean, got "
                    f"{type(v).__name__} ({v!r}) — not a source-expressible literal")
        return None
    if ntype == "field":
        extra = set(node) - {"type", "value"}
        if extra:
            return f"field node has unknown field(s) {sorted(extra)}"
        v = node.get("value")
        if not (isinstance(v, str) and v != ""):
            return f"field node value must be a non-empty string, got {v!r}"
        return None
    if ntype == "func_call":
        extra = set(node) - {"type", "func", "args"}
        if extra:
            return f"func_call node has unknown field(s) {sorted(extra)}"
        func = node.get("func")
        if not (isinstance(func, str) and func != ""):
            return f"func_call node func must be a non-empty string, got {func!r}"
        args = node.get("args")
        if not isinstance(args, list):
            return f"func_call node args must be a list, got {type(args).__name__}"
        for a in args:
            bad = validate_ast_node_schema(a)
            if bad:
                return bad
        return None
    return f"AST node has unknown or missing type {ntype!r}"


def _ast_func_names(node):
    """Collect every function name used ANYWHERE in a parsed dynamic-expr AST (recursive). The
    SOURCE-policy narrow must see NESTED funcs (e.g. the `len` in lower(len(...))), not just the
    outermost call."""
    names = set()
    if isinstance(node, dict):
        if (node.get("type") == "func_call" or "func" in node) and node.get("func"):
            names.add(node["func"])
        for _v in node.values():
            names |= _ast_func_names(_v)
    elif isinstance(node, list):
        for _it in node:
            names |= _ast_func_names(_it)
    return names


def validate_dynamic_tree(tree, context, target="cff", source=True):
    """AST-native: the FULL faithful-conversion proof on an already-parsed tree. Returns a reason
    on the first failure, else None. Runs (in order) the STRICT NODE SCHEMA, the field-source
    screen, the signature/context/node-shape contract, and the string-result-type requirement — the
    proofs that were spread across value_expression_unmappable + value_expression_type_unconvertible,
    but on ONE tree (round-26 finding 4). Used by lower_dynamic_value AND the hard-gate re-verifier.
    The node-schema runs FIRST so a structurally-bogus reloaded AST (literal dict/None, field with
    no value) is rejected before any type inference trusts it (round-27 finding 3)."""
    schema_bad = validate_ast_node_schema(tree)
    if schema_bad:
        return schema_bad
    unmap = find_unmappable_fields(tree, target)
    if unmap:
        return unmap
    sig = check_dynamic_expression_signature(tree, context)
    if sig:
        return sig
    # SOURCE-policy narrow (conversion-policy authority): a USER value (source=True) may use ONLY the
    # SOURCE_CONVERTIBLE_FUNCTIONS core. SEPARATE from the source-agnostic signature contract above, so
    # the renderer/contract tests keep exercising every function. INTERNAL producers (source=False,
    # e.g. True-Client-IP's to_string) skip this; a genuinely-unknown token was already caught above.
    if source:
        for _fn in _ast_func_names(tree):
            if _fn in _DYN_FUNC_CONTRACT and _fn not in SOURCE_CONVERTIBLE_FUNCTIONS:
                return f"function {_fn!r} is unsupported by conversion policy"
    rtype = dynamic_expression_result_type(tree)
    if rtype != _TYPE_STRING:
        return (f"non-string result type ({rtype}); a value must be a string — convert it "
                "explicitly (to_string / join / encode_base64)")
    return None


def value_expression_unmappable(expr, target="cff"):
    """String-input wrapper around find_unmappable_fields (kept for compat/tests + the redirect/
    rewrite/condition callers that still hold a string). Parse failure → a reason (round-15).
    PRODUCTION lowering uses the tree-native API; do not add new string-input callers."""
    try:
        tree = parse_dynamic_expression(expr)
    except Exception as e:
        return (f"dynamic value expression {expr!r} could not be parsed ({e}); "
                f"CloudFront has no faithful equivalent")
    return find_unmappable_fields(tree, target)


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
