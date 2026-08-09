#!/usr/bin/env python3
"""Exhaustive validation of the CloudFront PathPattern algebra in cdn_common.

pattern_contains / patterns_overlap are the FOUNDATION of the native-effect
placement refactor: a native rule scoped to pattern `outer` is replayed onto
behavior `inner` iff pattern_contains(outer, inner); a shared viewer CFF attaches
to every behavior whose pattern overlaps the op's scope; a cross-overlap (overlap
with neither containing the other) is non-convertible. If either primitive is
wrong, effects silently widen or drop. So this checks them EXACTLY against a
brute-force language oracle over a bounded alphabet — not a few hand cases.

CloudFront glob: `*` = 0+ chars INCLUDING `/`, `?` = exactly 1 char (verified vs
AWS docs by dual subagents, 2026-08). See memory cloudfront-behavior-matching-
semantics.

Run: python3 test_pattern_algebra.py  (exit 0 = all pass). Pure; no deps.
"""
import itertools
import os
import re
import sys

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "converter", "scripts"))
from cdn_common import pattern_contains, patterns_overlap  # noqa: E402

FAILURES = []


def check(label, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")
    if not cond:
        FAILURES.append((label, detail))
        if detail:
            print(f"           {detail}")


# ── Exhaustive oracle ──────────────────────────────────────────────────────────
# Alphabet includes `/` so we exercise the "* crosses separators" rule. The oracle
# is the ground-truth language of each pattern over all strings up to length NT;
# comparison is sound because every test pattern's minimum match length is < NT, so
# any subset/overlap divergence is realized within the bounded universe.
_A = list("ab/")
_PA = list("ab/*?")
_NT = 7
_NP = 4


def _glob_re(pat):
    return re.compile("^" + "".join(
        "[\\s\\S]*" if c == "*" else "[\\s\\S]" if c == "?" else re.escape(c)
        for c in pat) + "$")


def _run_exhaustive():
    universe = [""]
    for L in range(1, _NT + 1):
        universe += ["".join(p) for p in itertools.product(_A, repeat=L)]
    pats = [""]
    for L in range(1, _NP + 1):
        pats += ["".join(p) for p in itertools.product(_PA, repeat=L)]

    def minlen(p):
        return sum(1 for c in p if c != "*")

    langs = {p: frozenset(s for s in universe if _glob_re(p).match(s))
             for p in pats if minlen(p) <= _NT - 1}
    keys = list(langs)
    cm = om = tot = 0
    for p in keys:
        Lp = langs[p]
        for q in keys:
            tot += 1
            Lq = langs[q]
            if Lq.issubset(Lp) != pattern_contains(p, q):
                cm += 1
            if bool(Lp & Lq) != patterns_overlap(p, q):
                om += 1
    check(f"pattern_contains exact over {tot} pairs (|pat|<={_NP}, text<={_NT})", cm == 0,
          f"{cm} mismatches")
    check(f"patterns_overlap exact over {tot} pairs", om == 0, f"{om} mismatches")


print("== exhaustive vs brute-force language oracle ==")
_run_exhaustive()

# ── Named cases that pin the CloudFront-specific semantics ─────────────────────
print("== containment: the cases the refactor depends on ==")
check("* contains everything", pattern_contains("*", "/api/private/*")
      and pattern_contains("*", "/x") and pattern_contains("*", "*"))
check("/api/* contains /api/private/* (* crosses /)", pattern_contains("/api/*", "/api/private/*"))
check("/api/private/* does NOT contain /api/*", not pattern_contains("/api/private/*", "/api/*"))
check("/api/* does NOT contain /other/*", not pattern_contains("/api/*", "/other/*"))
check("exact contains only itself", pattern_contains("/a", "/a") and not pattern_contains("/a", "/b"))
check("/api/* contains the exact /api/test", pattern_contains("/api/*", "/api/test"))
check("*.js contains /a/b.js (* crosses /)", pattern_contains("*.js", "/a/b.js"))
check("prefix* contains longer prefix*", pattern_contains("/img*", "/imgs/*"))
check("/api/t?st contains /api/test (? matches the 'e')", pattern_contains("/api/t?st", "/api/test"))
check("/api/t?st contains /api/txst (? = any one literal)", pattern_contains("/api/t?st", "/api/txst"))
check("/api/t?st does NOT contain /api/txxst (? is exactly one, not two)",
      not pattern_contains("/api/t?st", "/api/txxst"))
check("/api/test (exact) does NOT contain /api/t?st (? ranges wider)",
      not pattern_contains("/api/test", "/api/t?st"))
check("*? (>=1 char) contains a* (>=1 char)", pattern_contains("*?", "a*"))
check("*? does NOT contain * (empty string)", not pattern_contains("*?", "*"))

print("== overlap / cross-overlap ==")
check("/api/* overlaps /api/private/* (nested)", patterns_overlap("/api/*", "/api/private/*"))
check("/a/* and /b/* are disjoint", not patterns_overlap("/a/*", "/b/*"))
check("*.js and /api/* cross-overlap (/api/x.js in both)", patterns_overlap("*.js", "/api/*"))
check("cross-overlap: neither contains the other", patterns_overlap("*.js", "/api/*")
      and not pattern_contains("*.js", "/api/*") and not pattern_contains("/api/*", "*.js"))
check("exact /a overlaps /a*", patterns_overlap("/a", "/a*"))
check("/a?c and /abc overlap", patterns_overlap("/a?c", "/abc"))
check("/a?c and /axyc disjoint (? one char)", not patterns_overlap("/a?c", "/axyc"))


if __name__ == "__main__":
    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} check(s)")
        for label, _ in FAILURES:
            print(f"  - {label}")
        sys.exit(1)
    print("All pattern-algebra checks passed.")
