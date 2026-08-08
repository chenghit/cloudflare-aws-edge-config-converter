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


def derive_cert_domain(hostname):
    """The SAME-LEVEL wildcard that must appear in a certificate's SAN to cover
    `hostname` on CloudFront — i.e. the coverage a user needs to provision.

      app.eu.example.com → *.eu.example.com   (wildcard replaces `app`)
      www.example.com    → *.example.com
      example.com        → example.com        (apex: a wildcard one level up does
                                               NOT cover the apex, so it needs an
                                               exact SAN of itself)
      *.example.com      → *.example.com       (already a wildcard: unchanged)

    A wildcard host keeps its own value (Cloudflare `*.x` → one CloudFront
    distribution whose alias is `*.x`, covered by a `*.x` SAN). A bare host with
    only one label left (a TLD-like `localhost`, or the apex itself) can't be
    wildcarded a level up soundly, so it maps to an exact-self SAN."""
    if hostname.startswith("*."):
        return hostname
    labels = hostname.split(".")
    # Need at least 3 labels (a.b.c) to replace the leftmost with `*` and still
    # leave a real registrable parent. `example.com` (2 labels) is the apex →
    # exact self; a single label → exact self.
    if len(labels) >= 3:
        return "*." + ".".join(labels[1:])
    return hostname


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
