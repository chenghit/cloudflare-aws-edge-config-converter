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
      - scalar (str/int/…)  → `KEY: value` on one line.
      - list/tuple of str   → `KEY:` then each item as a two-space-indented
                              continuation line (FAILED_ITEMS, BLOCKED_ITEMS,
                              DEPLOY_SUMMARY). emit_result owns the newline and
                              the indent; the caller just passes the items.

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
    # `warnings` is optional, but if the KEY is present its value must be a list
    # of strings. Gate on presence (`"warnings" in summary`), NOT on `is not
    # None` — an explicit null is exactly the malformed case to reject (it would
    # crash the readers' list()/for-in), not a value to wave through.
    if "warnings" in summary:
        warnings = summary["warnings"]
        if not (isinstance(warnings, list) and all(isinstance(w, str) for w in warnings)):
            return None, ("cdn_summary.json 'warnings' must be a list of strings "
                          "(a malformed value can hide a deploy blocker)")
    return summary, None
