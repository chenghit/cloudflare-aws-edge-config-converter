"""Shared CDN-pipeline helpers — SCRIPT_STANDARDS result emitting, the
cdn_summary.json loader, and the quota action-tag constants.

Split out (mirroring waf_common.py) so file-IO / result-contract logic doesn't
live in the expression parser. The single most important piece is emit_result:
every CDN stage MUST emit its ---RESULT--- through it rather than hand-writing
`print(f"...---RESULT---...")`, because hand-written blocks have repeatedly
shipped bugs the agent then can't parse — a FATAL sent to stderr instead of
stdout, a non-indented continuation line that splits into a garbage key, a
CONTEXT string assembled into self-contradiction. Centralizing the envelope
(stream, SPEC line, field order, multi-line indentation, STATUS→exit mapping)
fixes all of those in one place and stops the next one.
"""
import json
import os
import sys

# ── Quota action tags ─────────────────────────────────────────────────────────
# The machine-readable prefix on each over-limit warning so the final
# ---RESULT--- (and the agent) know what to DO:
#   QUOTA-RAISE    — SOFT limit: config is correct, deploy is blocked only until
#                    the quota is raised, then deploys unchanged.
#   QUOTA-REDESIGN — HARD limit: no increase path; cdn-validate-js escalates to
#                    STATUS: BLOCKED and the source must be reduced/redesigned.
# Single source of truth: producers prefix with these, consumers test membership
# against QUOTA_TAGS, so a typo in one literal can't silently disable a path.
QUOTA_RAISE = "QUOTA-RAISE"
QUOTA_REDESIGN = "QUOTA-REDESIGN"
QUOTA_TAGS = (QUOTA_RAISE, QUOTA_REDESIGN)

# ── ACM certificate coverage (SNI / CloudFront alternate-domain matching) ──────
# CloudFront checks a distribution's alternate domain name against the attached
# certificate's SAN field: it is covered by an EXACT SAN entry, or by a wildcard
# SAN "at the same level" (one wildcard label, leftmost only). A wildcard covers
# exactly ONE DNS label — `*.example.com` covers `a.example.com` but NOT the apex
# `example.com` (zero labels) NOR a two-label host `a.b.example.com`. This is the
# TLS/RFC-6125 rule AWS enforces; VERIFIED LIVE (2026-08): a distribution with
# alias `app.eu.a.letsmakeit.link` and a cert whose SANs were `*.a.letsmakeit.link`
# + `*.eu.a.letsmakeit.link` served HTTPS 200 with tls_verify=0 — the request host
# matched ONLY via the `*.eu…` SAN, since the `*.a…` SAN (one level up) does not
# cover a two-label-deeper host.
#
# NOTE the split of responsibilities that this whole cert rework rests on, also
# verified live the same day:
#   - CloudFront matches an alias against a cert by SAN COVERAGE (cert_covers).
#   - The Terraform `aws_acm_certificate` DATA SOURCE `domain=` filter matches a
#     cert ONLY by its primary DomainName (CN) with exact string equality — it
#     does NOT search SANs. So `domain = "*.eu.example.com"` finds a cert only if
#     that string is the cert's CN; a merged cert (CN `*.example.com`, SAN
#     `*.eu.example.com`) is NOT found and `terraform plan` errors "no matching
#     ACM Certificate". That mismatch is exactly why cert discovery cannot be a
#     domain-guess data source and moves to explicit ARNs + a SAN-coverage
#     resolver (resolve-certs.py) that mirrors cert_covers.


def derive_cert_domain(hostname, zone_name=None):
    """The SAME-LEVEL wildcard that must appear in a certificate's SAN to cover
    `hostname` on CloudFront — i.e. the coverage a user needs to provision.

      zone example.com:
        app.eu.example.com → *.eu.example.com   (wildcard replaces `app`)
        www.example.com    → *.example.com
        example.com        → example.com        (apex: a wildcard one level up
                                                 does NOT cover the apex — it
                                                 needs an exact SAN of itself)
      zone a.letsmakeit.link (a delegated/registered zone whose apex has 3+
      labels — a plain label count can't spot it):
        a.letsmakeit.link     → a.letsmakeit.link   (apex → exact self, NOT
                                                     *.letsmakeit.link, which is a
                                                     different registrable domain)
        www.a.letsmakeit.link → *.a.letsmakeit.link
      *.example.com → *.example.com (already a wildcard: unchanged)

    Apex detection is by `hostname == zone_name`, NOT by label count — a zone
    apex can have any number of labels (example.co.uk, a.letsmakeit.link), and
    label-counting mis-derived those to a public-suffix wildcard (*.co.uk /
    *.letsmakeit.link) that ACM won't issue and that would span other zones.
    `zone_name` is the Cloudflare zone the host lives in (its apex); pass it
    whenever known. Without it, fall back to "2-label host = apex", correct for
    the common example.com case but blind to multi-label apexes."""
    if hostname.startswith("*."):
        return hostname
    zone = (zone_name or "").lstrip(".")
    if zone and hostname == zone:
        return hostname  # apex → exact self
    if not zone and hostname.count(".") <= 1:
        return hostname  # no zone hint: treat a 2-label host as the apex
    # A subdomain: replace the leftmost label with `*` (its same-level wildcard).
    # host must have a label to strip; a bare single label has none → exact self.
    return "*." + hostname.split(".", 1)[1] if "." in hostname else hostname


def cert_covers(cert_names, hostname):
    """True if a certificate whose SAN/name set is `cert_names` covers `hostname`
    under CloudFront's alternate-domain matching rule. `cert_names` is the list
    of names on the cert (its DomainName plus every SubjectAlternativeName — ACM
    folds the primary name into the SAN list too). Matching per name:

      - exact, case-insensitive:            `app.example.com` == `app.example.com`
      - same-level wildcard `*.parent`:     covers exactly one label under parent,
                                            `*.example.com` ⊇ `app.example.com`
                                            but NOT the apex and NOT two-deep.

    Mirrors derive_cert_domain (a cert containing derive_cert_domain(h) as a SAN
    always covers h) AND CloudFront's live behavior. resolve-certs.py uses this to
    pick the cert whose coverage CloudFront will actually accept — so a cert it
    selects can never fail the distribution's viewer-certificate check."""
    host = hostname.lower().rstrip(".")
    for name in cert_names:
        n = str(name).lower().rstrip(".")
        if n == host:
            return True
        if n.startswith("*."):
            suffix = n[1:]  # ".parent"
            if not host.endswith(suffix):
                continue
            # exactly one label before the matched suffix (no extra dots)
            label = host[: -len(suffix)]
            if label and "." not in label:
                return True
    return False


# ── CloudFront PathPattern algebra ─────────────────────────────────────────────
# CloudFront selects the ONE cache behavior to serve a request by first-match in
# list order (default `*` last); overlapping patterns do NOT merge, and a behavior
# inherits NOTHING from the default. VERIFIED vs AWS docs by dual subagents
# (2026-08): the only wildcards are `*` (0+ chars, CROSSES `/`) and `?` (exactly 1
# char); matching is against the URI path only (query string excluded).
#
# Two primitives the placement/scaffold logic rests on:
#   pattern_contains(outer, inner) — SOUND: True only when every path matching
#     `inner` also matches `outer` (P_inner ⊆ P_outer). Used to decide whether a
#     native effect scoped to `outer` must be replayed onto behavior `inner`. When
#     unsure it returns False (never over-claim coverage — that would widen).
#   patterns_overlap(a, b) — True when SOME path matches both (P_a ∩ P_b ≠ ∅).
#     Used to decide which behaviors a shared viewer CFF must attach to (attach on
#     any overlap — over-attach is only cost, a miss is a silent drop) and to spot
#     cross-overlap (overlap but neither contains the other), whose intersection is
#     not expressible as one CloudFront behavior → caller reports non-convertible.
# Both are exact for the `*`/`?` glob language via a standard two-pointer / DP glob
# matcher, plus a symbolic emptiness check for pattern∩pattern.


def _glob_closure(pattern, states):
    """ε-closure: a `*` can be skipped entirely (match empty), so from a position
    on a `*` you may also stand just past it. Returns the closed frozenset."""
    out = set(states)
    changed = True
    while changed:
        changed = False
        for i in list(out):
            if i < len(pattern) and pattern[i] == "*" and (i + 1) not in out:
                out.add(i + 1)
                changed = True
    return frozenset(out)


def _glob_step(pattern, states, ch):
    """Advance an NFA position-set by consuming one character `ch`."""
    nxt = set()
    for i in _glob_closure(pattern, states):
        if i >= len(pattern):
            continue
        c = pattern[i]
        if c == "*":
            nxt.add(i)                      # `*` absorbs the char, stay put
        elif c == "?" or c == ch:
            nxt.add(i + 1)                  # `?` or matching literal advances
    return _glob_closure(pattern, nxt)


def _glob_accepts(pattern, states):
    return len(pattern) in _glob_closure(pattern, states)


def pattern_contains(outer, inner):
    """True iff EVERY path matching glob `inner` also matches glob `outer`
    (language containment P_inner ⊆ P_outer). Patterns are over the CloudFront glob
    language (`*` = 0+ chars including `/`, `?` = exactly 1 char). EXACT — decided
    by NFA language containment (validated exhaustively vs a brute-force oracle in
    the test suite), NOT a token heuristic: outer's leading `*` and its trailing
    tokens interact non-locally (e.g. `*?` ⊇ `a*`), which a positional DP gets
    wrong.

    Method: containment fails iff some string is matched by `inner` but NOT by
    `outer`. Simulate `inner` and `outer` as position-set NFAs in lockstep over the
    product of their reachable state-sets; a product state where inner accepts but
    outer does not is a counterexample. The alphabet need only distinguish the
    literal characters appearing in either pattern plus ONE sentinel standing for
    "every other character" (all such chars behave identically under `*`/`?`/literal
    transitions), so the search is finite and small."""
    alphabet = set(c for c in outer + inner if c not in ("*", "?"))
    alphabet.add("\x00")                    # sentinel: any char not a named literal
    start = (_glob_closure(inner, {0}), _glob_closure(outer, {0}))
    seen = {start}
    stack = [start]
    while stack:
        istates, ostates = stack.pop()
        if _glob_accepts(inner, istates) and not _glob_accepts(outer, ostates):
            return False                    # a string in inner that outer rejects
        for ch in alphabet:
            nxt = (_glob_step(inner, istates, ch), _glob_step(outer, ostates, ch))
            if nxt not in seen:
                seen.add(nxt)
                stack.append(nxt)
    return True


def patterns_overlap(a, b):
    """True iff SOME path matches BOTH glob patterns (P_a ∩ P_b ≠ ∅). EXACT for the
    `*`/`?` language (validated vs brute force in the test suite). Used to decide
    which behaviors a shared viewer CFF attaches to (attach on any overlap — a miss
    is a silent drop, an extra attach is only cost) and to detect cross-overlap
    (overlap with neither pattern containing the other → their intersection is not
    one CloudFront behavior → caller reports non-convertible)."""
    memo = {}

    def go(i, j):
        key = (i, j)
        if key in memo:
            return memo[key]
        la, lb = len(a), len(b)
        if i == la and j == lb:
            r = True                         # both consumed by a common string
        elif i < la and a[i] == "*":
            r = go(i + 1, j) or (j < lb and go(i, j + 1))
        elif j < lb and b[j] == "*":
            r = go(i, j + 1) or (i < la and go(i + 1, j))
        elif i == la or j == lb:
            r = False                        # one side has a real token, other empty
        elif a[i] == "?" or b[j] == "?" or a[i] == b[j]:
            r = go(i + 1, j + 1)             # one common char satisfies both tokens
        else:
            r = False
        memo[key] = r
        return r

    return go(0, 0)


def _bad_source_key(k):
    """Return a human reason string if `k` is NOT a well-formed source key, else None.
    The contract (see make_empty_ir) is a (kind, id, pointer) TRIPLE: `kind` and
    `pointer` are non-empty strings; `id` is a string but MAY be empty — a rule without
    an id is legal (two empty-id units collide and are caught by the duplicate check,
    not here). Exception-agnostic and SHARED so the write-side API (ValueError) and the
    finalize ledger gate enforce the SAME shape from one definition."""
    if not isinstance(k, (list, tuple)):
        return f"source key must be a list/tuple, got {type(k).__name__}: {k!r}"
    if len(k) != 3:
        return f"source key must be a (kind, id, pointer) triple, got {len(k)} parts: {k!r}"
    kind, sid, ptr = k
    if not kind or not isinstance(kind, str):
        return f"source key kind must be a non-empty string, got {kind!r}"
    if not isinstance(sid, str):
        return f"source key id must be a string, got {sid!r}"
    if not ptr or not isinstance(ptr, str):
        return f"source key pointer must be a non-empty string, got {ptr!r}"
    return None


# STATUS → exit code (SCRIPT_STANDARDS). BLOCKED is a completed run with an
# undeployable artifact, not a script failure → exit 0 (the block carries the
# don't-deploy signal). OK also 0; ERROR 1; FATAL 2; PARTIAL 3.
_STATUS_EXIT = {"OK": 0, "BLOCKED": 0, "ERROR": 1, "FATAL": 2, "PARTIAL": 3}


def emit_result(status, *, exit_after=True, exit_code=None, **fields):
    """Print a SCRIPT_STANDARDS ---RESULT--- block to STDOUT (never stderr — the
    agent parses only stdout) and, by default, exit with the STATUS's code.

    fields are emitted in the order given (kwargs preserve order). A field value
    is rendered by TYPE, so callers never hand-format continuation lines (the
    exact source of the "non-indented line becomes a garbage key" bugs this
    module exists to kill):
      - scalar (str/int/…)  → `KEY: value`; a single-line value stays on one
                              line, and a value that itself spans multiple lines
                              (e.g. a multi-line POST_ACTION directive) has every
                              continuation two-space indented.
      - list/tuple of str   → `KEY:` then each item as a two-space-indented
                              continuation line (FAILED_ITEMS, BLOCKED_ITEMS,
                              DEPLOY_SUMMARY). emit_result owns the newline and
                              the indent; the caller just passes the items.
    Either way every physical line after `KEY:` is indented, so no caller input
    (including an embedded '\n') can produce a line the agent misreads as a key.

    exit_after=False emits but returns (OK paths that keep running). exit_code
    overrides the STATUS→code mapping when a caller needs a specific code.
    """
    def _indent_continuations(text):
        # Every physical line after the first must be two-space indented, or the
        # agent reads it as a new key (a value/item with an embedded '\n' — e.g.
        # an agent-authored skipped-domain reason — is the recurring garbage-key
        # bug). Enforce it here so NO caller input can break the contract.
        first, *rest = str(text).split("\n")
        return "\n".join([first, *(f"  {r}" for r in rest)])

    lines = ["", "---RESULT---", "SPEC: 1", f"STATUS: {status}"]
    for key, value in fields.items():
        if isinstance(value, (list, tuple)):
            lines.append(f"{key}:")
            lines.extend(f"  {_indent_continuations(item)}" for item in value)
        else:
            lines.append(f"{key}: {_indent_continuations(value)}")
    print("\n".join(lines))
    if exit_after:
        code = exit_code if exit_code is not None else _STATUS_EXIT.get(status, 1)
        sys.exit(code)


def load_summary_or_fatal(output_dir):
    """Load cdn_summary.json, returning (summary_dict, None) on success or
    (None, context_str) on any problem so the caller can emit its own
    ---RESULT--- STATUS: FATAL and exit.

    Both readers of this file — cdn-generate-js (Stage 8, which reads FIRST and
    writes back) and cdn-validate-js (Stage 9) — must go through here, and both
    the top-level shape AND the `warnings` value are validated:
      - missing/unreadable/invalid JSON → fatal (a truncated or absent file)
      - not a JSON object (null/list/str/number) → fatal (Stage 8 would crash on
        item assignment; Stage 9 would crash on _s.get)
      - `warnings` present but not a list OF STRINGS → fatal (a string value
        would be iterated char-by-char, exploding into garbage on write-back and
        silently dropping a QUOTA-REDESIGN blocker; a null would raise on
        iteration; a non-string element would crash the readers' w.startswith)
    Guarding shape here, once, is why neither stage can fail-open on a malformed
    summary and hide a deploy blocker. expanduser matches the writer
    (cdn-finalize), so a `~`-prefixed output_dir doesn't misfire a FATAL."""
    path = os.path.join(os.path.expanduser(output_dir), "cdn_summary.json")
    try:
        with open(path) as f:
            summary = json.load(f)
    except Exception as e:
        return None, f"cdn_summary.json missing or unreadable ({e})"
    if not isinstance(summary, dict):
        return None, (f"cdn_summary.json is not a JSON object "
                      f"(got {type(summary).__name__})")
    # The list-of-string fields the readers iterate or ', '.join — validate every
    # one, so a malformed element can't crash a reader with no ---RESULT--- block.
    # Gate on presence, NOT on `is not None`: an explicit null is exactly the
    # malformed case to reject (it would crash list()/for-in/join), not a value
    # to wave through.
    for field in ("warnings", "skipped_domains"):
        if field in summary:
            value = summary[field]
            if not (isinstance(value, list) and all(isinstance(x, str) for x in value)):
                return None, (f"cdn_summary.json '{field}' must be a list of strings "
                              f"(a malformed value can crash the reader / hide a blocker)")
    return summary, None
