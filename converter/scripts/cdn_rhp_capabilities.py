"""RHP capability registry — the SINGLE source of truth for which response headers a
native CloudFront Response Headers Policy can faithfully emit, AND for the value semantics.

A capability is (canonical_name, parse, render):
  - parse(raw_value) -> a NORMALIZED dict the RHP can faithfully represent, or None if the
    value is unsupported / malformed / only partially representable (→ NON_CONVERTIBLE).
    "Faithful" means the generated HCL preserves the SOURCE behavior — the generator used
    to hardcode HSTS max-age=31536000 / force X-Content-Type-Options / force X-XSS-Protection
    on, silently changing the value; parse() rejects any value the render() can't reproduce.
  - render(normalized, override) -> the list of HCL lines for this header's block.

The processor calls parse() to decide EXACT-vs-NC and stores the NORMALIZED value in the IR;
the generator calls the SAME capability's render() on that normalized value — it must NOT
re-parse the raw header value independently (that's how the two support sets drifted). This
module is DEPENDENCY-FREE (no import of preprocess / processors / generator) so all three can
import it without a cycle.
"""


# ── HCL string escaping ───────────────────────────────────────────────────────

def hcl_string_literal(s):
    """Escape `s` for insertion inside a double-quoted Terraform HCL string. A raw Cloudflare
    header value can contain a double-quote, backslash, newline, or a literal `${...}` / `%{...}`
    — inserted verbatim these break the generated HCL or get interpreted as a Terraform
    interpolation/directive. Escapes, in a single left-to-right pass (so escapes we ADD aren't
    re-escaped): backslash → \\\\, `"` → \\", the control chars (newline/CR/tab, others → \\uXXXX),
    then Terraform's `${` → `$${` and `%{` → `%%{`. Returns the escaped body WITHOUT the
    surrounding quotes (callers wrap in `"..."`)."""
    if not isinstance(s, str):
        s = str(s)
    out = []
    for ch in s:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif ord(ch) < 0x20:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    # ${ and %{ are disjoint Terraform triggers; str.replace scans left-to-right so
    # `$${` (source) → `$$${` renders back to the literal `$${` (Terraform's doubling rule).
    return "".join(out).replace("${", "$${").replace("%{", "%%{")


# ── Security-header value parsers (strict — NC on any inexactness) ─────────────

def _parse_hsts(raw):
    """Strict-Transport-Security → {max_age, include_subdomains, preload}. Each directive is
    matched as an EXACT name (RFC 6797: `max-age=<digits>`, valueless `includeSubDomains` /
    `preload`) — NOT by string prefix, so `max-age-extra=60` / `max-agefoo=1` are rejected.
    A REPEATED directive is rejected (the RHP can carry only one value → picking one wouldn't
    be faithful). NC if max-age is absent/non-integer, a valueless directive is given a value,
    or an unknown directive appears."""
    if not isinstance(raw, str):
        return None
    max_age = None
    include_subdomains = False
    preload = False
    seen = set()
    for part in raw.split(";"):
        tok = part.strip()
        if not tok:
            continue
        name, sep, value = tok.partition("=")
        name = name.strip().lower()
        if name in seen:
            return None          # duplicate directive → ambiguous, not faithful
        seen.add(name)
        if name == "max-age":
            num = value.strip()
            if not sep or not num.isdigit():   # requires `=<non-negative int>`
                return None
            max_age = int(num)
        elif name in ("includesubdomains", "preload"):
            if sep:                            # valueless flag given a value → malformed
                return None
            if name == "includesubdomains":
                include_subdomains = True
            else:
                preload = True
        else:
            return None          # unknown directive → can't faithfully represent
    if max_age is None:
        return None              # RHP's strict_transport_security REQUIRES a max-age
    return {"max_age": max_age, "include_subdomains": include_subdomains,
            "preload": preload}


def _render_hsts(n, override):
    return [
        "    strict_transport_security {",
        f"      access_control_max_age_sec = {n['max_age']}",
        f"      include_subdomains         = {'true' if n['include_subdomains'] else 'false'}",
        f"      preload                    = {'true' if n['preload'] else 'false'}",
        f"      override                   = {'true' if override else 'false'}",
        "    }",
    ]


def _parse_xcto(raw):
    """X-Content-Type-Options → the ONLY value CloudFront's content_type_options can emit is
    `nosniff`. Any other value is NON_CONVERTIBLE (the generator would silently force nosniff)."""
    if isinstance(raw, str) and raw.strip().lower() == "nosniff":
        return {}
    return None


def _render_xcto(n, override):
    return [f"    content_type_options {{ override = {'true' if override else 'false'} }}"]


def _parse_xfo(raw):
    """X-Frame-Options → CloudFront's frame_options enum is DENY | SAMEORIGIN ONLY. Any other
    value (e.g. ALLOW-FROM https://x) is NON_CONVERTIBLE."""
    if isinstance(raw, str) and raw.strip().upper() in ("DENY", "SAMEORIGIN"):
        return {"frame_option": raw.strip().upper()}
    return None


def _render_xfo(n, override):
    return [
        "    frame_options {",
        f"      frame_option = \"{n['frame_option']}\"",
        f"      override     = {'true' if override else 'false'}",
        "    }",
    ]


def _parse_xss(raw):
    """X-XSS-Protection → CloudFront's xss_protection can ONLY emit `1; mode=block` (protection
    on + mode_block). So the source value must be exactly that (modulo whitespace/case). `0`
    (disabled) and every other variant are NON_CONVERTIBLE — the generator can't emit them."""
    if not isinstance(raw, str):
        return None
    parts = [p.strip().lower() for p in raw.split(";") if p.strip()]
    if parts == ["1", "mode=block"]:
        return {}
    return None


def _render_xss(n, override):
    return [
        "    xss_protection {",
        "      mode_block  = true",
        f"      override    = {'true' if override else 'false'}",
        "      protection  = true",
        "    }",
    ]


# CloudFront's referrer_policy is a STRICT enum (anchored regex, case-sensitive, no
# case-insensitivity flag — confirmed vs the CloudFront service model / CFN schema). A
# value outside this set (e.g. "banana", or a spec-legal comma-separated fallback list like
# "no-referrer, strict-origin") is rejected at deploy → NON_CONVERTIBLE, not EXACT.
_REFERRER_POLICY_ENUM = frozenset((
    "no-referrer", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin",
    "same-origin", "strict-origin", "strict-origin-when-cross-origin", "unsafe-url",
))
# Content-Security-Policy length limits. The 1783-char figure (Developer Guide /
# TooLongCSPInResponseHeadersPolicy) is the DEFAULT ACCOUNT QUOTA, which is RAISABLE — it is
# NOT a fixed semantic cap. So the parser only rejects a CSP that no account can carry:
#   len <= CSP_MAX_LEN (8192, the maximum the quota can be raised to) → EXACT (verbatim).
#   len  > CSP_MAX_LEN                                                → NON_CONVERTIBLE.
# The DEFAULT-quota gate (1783, raisable) is a DEPLOY-READINESS check, reported as a
# QUOTA-RAISE by the central quota validator (cdn-finalize) — NOT a conversion outcome (the
# CSP content is neither modified nor dropped, so it stays EXACT). Keeping the two separate is
# the point: a CSP between the default quota and 8192 converts EXACT and deploys once the
# account quota is raised (or an effective quota is declared).
CSP_MAX_LEN = 8192          # hard ceiling — RHP cannot carry more even with a raised quota
CSP_DEFAULT_QUOTA = 1783    # default account CSP quota (raisable up to CSP_MAX_LEN)
# (The 1783 limit on a native custom-header value / cors_config Allow-Origin value is NOT
# modeled here: those native paths are dormant — plain custom headers route to a CFF, which
# carries its own code/response-size limits, and native cors_config raises. Re-enabling a
# native path must add its own value-length check at that point, treated as HARD.)


def validate_csp_quota(value):
    """Validate a user-declared EFFECTIVE Content-Security-Policy length quota. Returns the
    int unchanged, or raises ValueError with a user-facing message. THE single validator both
    the CLI (cdn-finalize --csp-quota) and generate_report() use, so a bad value is rejected
    identically everywhere (round-14 finding 3). Valid range: a positive integer up to the
    8192 hard ceiling. NOT clamped — an out-of-range value is REJECTED, never silently
    changed, so the report can never misrepresent the quota the user actually declared."""
    # Accept an int or an integer-valued string (the CLI passes strings); REJECT a bool
    # (int(True)==1) and a non-integer float (int(1.5)==1 would SILENTLY truncate the user's
    # value — the exact "don't modify the declared value" failure this validator prevents).
    if isinstance(value, bool):
        raise ValueError(f"CSP quota must be an integer, got {value!r}")
    if isinstance(value, float):
        raise ValueError(f"CSP quota must be a whole integer, got {value!r}")
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"CSP quota must be an integer, got {value!r}")
    if n <= 0:
        raise ValueError(f"CSP quota must be a positive integer, got {n}")
    if n > CSP_MAX_LEN:
        raise ValueError(
            f"CSP quota {n} exceeds the {CSP_MAX_LEN}-char hard ceiling — CloudFront cannot "
            f"carry a larger Content-Security-Policy even with a raised account quota")
    return n


def _parse_referrer(raw):
    """Referrer-Policy → CloudFront's referrer_policy enum ONLY. The header token is ASCII
    case-insensitive per spec (a browser folds case), so match case-insensitively and emit
    the canonical lowercase value CloudFront requires — behavior-preserving, so still EXACT.
    A comma-separated fallback list / unknown token / empty → NC (the enum has no such value)."""
    if not isinstance(raw, str):
        return None
    tok = raw.strip().lower()
    if tok in _REFERRER_POLICY_ENUM:
        return {"value": tok}
    return None


def _parse_csp(raw):
    """Content-Security-Policy → free-form string field, emitted VERBATIM, so any non-empty
    value is faithful up to the RHP hard ceiling (CSP_MAX_LEN=8192, the most a raised quota
    allows). Over that → NON_CONVERTIBLE (no account can carry it). The DEFAULT quota (1783)
    is NOT enforced here — it's a raisable deploy-readiness gate reported by the quota
    validator, not a conversion boundary (the content is unchanged → still EXACT)."""
    if isinstance(raw, str) and raw != "" and len(raw) <= CSP_MAX_LEN:
        return {"value": raw}
    return None


def _render_referrer(n, override):
    return [
        "    referrer_policy {",
        f"      referrer_policy = \"{hcl_string_literal(n['value'])}\"",
        f"      override        = {'true' if override else 'false'}",
        "    }",
    ]


def _render_csp(n, override):
    # CSP is a free-form string field (confirmed vs AWS service model) → any value is
    # faithful, but it MUST be HCL-escaped (quotes/backslashes/`${`/`%{` in a CSP would
    # otherwise break the HCL or trigger a Terraform interpolation).
    return [
        "    content_security_policy {",
        f"      content_security_policy = \"{hcl_string_literal(n['value'])}\"",
        f"      override                = {'true' if override else 'false'}",
        "    }",
    ]


# ── Registry ───────────────────────────────────────────────────────────────
# Ordered so the generated security_headers_config block is deterministic. Each entry:
# canonical_name (generator-expected casing), parse (raw->normalized|None), render
# (normalized,override->HCL lines).
SECURITY_CAPABILITIES = (
    {"canonical_name": "Strict-Transport-Security", "parse": _parse_hsts, "render": _render_hsts},
    {"canonical_name": "X-Content-Type-Options", "parse": _parse_xcto, "render": _render_xcto},
    {"canonical_name": "X-Frame-Options", "parse": _parse_xfo, "render": _render_xfo},
    {"canonical_name": "X-XSS-Protection", "parse": _parse_xss, "render": _render_xss},
    {"canonical_name": "Referrer-Policy", "parse": _parse_referrer, "render": _render_referrer},
    {"canonical_name": "Content-Security-Policy", "parse": _parse_csp, "render": _render_csp},
)

# The SIX CORS RESPONSE headers, canonical casing. This is the ONE authoritative set of CORS
# names (finding 3: the processor must NOT use a loose `access-control-` prefix, which would
# misclassify an unknown Access-Control-* header as CORS). A static Cloudflare `set` of any of
# these converts to a viewer-response CFF marked LOSSY (see the processor / memory
# cdn-response-header-mechanism-facts) — NOT to a native cors_config. The set is EXHAUSTIVE:
# Access-Control-Request-* are REQUEST headers (never a response transform) and are absent.
STATIC_CORS_HEADER_NAMES = (
    "Access-Control-Allow-Origin", "Access-Control-Allow-Methods",
    "Access-Control-Allow-Headers", "Access-Control-Allow-Credentials",
    "Access-Control-Expose-Headers", "Access-Control-Max-Age",
)
# Names the DORMANT native cors_config path (structured, group-level) could emit. Kept
# separate from the CFF-routed set above so re-enabling the native path is a DELIBERATE
# group-level decision (finding 3), never an implicit inheritance of a per-header status.
_NATIVE_CORS_CONFIG_NAMES = (
    "Access-Control-Allow-Origin", "Access-Control-Allow-Methods",
    "Access-Control-Allow-Headers", "Access-Control-Allow-Credentials",
)

_SECURITY_BY_LOWER = {c["canonical_name"].lower(): c for c in SECURITY_CAPABILITIES}
_STATIC_CORS_LOWER = frozenset(h.lower() for h in STATIC_CORS_HEADER_NAMES)
_NATIVE_CORS_LOWER = frozenset(h.lower() for h in _NATIVE_CORS_CONFIG_NAMES)
_CANONICAL = {c["canonical_name"].lower(): c["canonical_name"] for c in SECURITY_CAPABILITIES}
_CANONICAL.update({h.lower(): h for h in STATIC_CORS_HEADER_NAMES})


def security_capability(name):
    """The security capability for `name` (any casing), or None if the RHP has no field."""
    return _SECURITY_BY_LOWER.get(name.lower())


def rhp_supports_security(name):
    """True if the RHP has a field for this security header (name-level check)."""
    return name.lower() in _SECURITY_BY_LOWER


def is_static_cors_header(name):
    """True if `name` is one of the SIX CORS response headers a static Cloudflare `set`
    routes to a viewer-response CFF (LOSSY). This is the processor's routing predicate —
    an EXACT-membership check, never a loose `access-control-` prefix (finding 3)."""
    return name.lower() in _STATIC_CORS_LOWER


def native_cors_config_supports(name):
    """True if the DORMANT native cors_config path could emit this header. Separate from
    is_static_cors_header on purpose: re-enabling the native path is a deliberate
    group-level decision, not an implicit reuse of the CFF routing set (finding 3)."""
    return name.lower() in _NATIVE_CORS_LOWER


def canonical_header(name):
    """Canonical (generator-expected) casing for a registered RHP header; unchanged if not
    in the registry (a header the processor NC's never reaches the canonicalizer)."""
    return _CANONICAL.get(name.lower(), name)
