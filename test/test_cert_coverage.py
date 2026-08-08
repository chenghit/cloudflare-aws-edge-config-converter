#!/usr/bin/env python3
"""Regression test for multi-level-subdomain certificate handling.

Root cause this locks down: the pipeline used to look up every distribution's
ACM cert with `data "aws_acm_certificate" { domain = "*.<zone-apex>" }`. That is
wrong two ways, both verified LIVE against a real AWS account (2026-08):

  1. CloudFront covers an alias by SAN at the SAME LEVEL only. `*.example.com`
     does NOT cover a 4-level host `app.eu.example.com` — that needs
     `*.eu.example.com`. (Verified live on a real account: a cert whose SANs were
     `*.<zone>` + `*.eu.<zone>` served HTTPS 200 for `app.eu.<zone>`, matching
     ONLY via the deeper `*.eu…` SAN.)
  2. The Terraform data source `domain=` matches a cert's PRIMARY DomainName
     (CN) only, never its SANs. (Live: looking up a value that was a SAN but not
     the CN errored "empty result"; the CN value matched.)

So cert discovery moved to per-distribution ARN variables filled by
resolve-certs.py (SAN-coverage match, mirroring CloudFront). This test asserts:
  - derive_cert_domain / cert_covers behave per the CloudFront rule
  - a zone with hosts at 2/3/4 label depths splits into the correct cert groups
  - each generated main.tf reads its cert from a cert_arn_<san> variable whose
    validation names the correct same-level SAN — NOT a *.apex data source
  - resolve-certs.py is generated, parses, and its inlined cert_covers agrees

Run: python3 test_cert_coverage.py   (exit 0 = all pass). No terraform/AWS needed.
"""
import importlib.util as _ilu
import ast
import json
import os
import shutil
import subprocess
import sys
import tempfile

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(_REPO, "converter", "scripts")

sys.path.insert(0, SCRIPTS)
from cdn_common import derive_cert_domain, cert_covers  # noqa: E402


def _load(name, filename):
    spec = _ilu.spec_from_file_location(name, os.path.join(SCRIPTS, filename))
    m = _ilu.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


_scaf = _load("cdn_scaffold", "cdn-generate-tf-scaffold.py")

FAILURES = []


def check(label, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")
    if not cond:
        FAILURES.append((label, detail))
        if detail:
            print(f"           {detail}")


def run(script, *args):
    p = subprocess.run([sys.executable, os.path.join(SCRIPTS, script), *args],
                       capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr


# ── Unit: the two pure functions vs the CloudFront same-level rule ─────────────

def test_pure_functions():
    print("== derive_cert_domain / cert_covers ==")
    # (hostname, zone_name, want)
    for host, zone, want in [
        ("www.example.com", "example.com", "*.example.com"),
        ("app.eu.example.com", "example.com", "*.eu.example.com"),  # 4-level → deeper wildcard
        ("a.b.c.example.com", "example.com", "*.b.c.example.com"),
        ("example.com", "example.com", "example.com"),              # apex → exact self
        ("*.example.com", "example.com", "*.example.com"),          # already wildcard
        # Multi-label apex — the label-count heuristic mis-derived these to a
        # public-suffix wildcard. Apex is detected by hostname == zone_name.
        ("example.co.uk", "example.co.uk", "example.co.uk"),        # NOT *.co.uk
        ("www.example.co.uk", "example.co.uk", "*.example.co.uk"),
        ("app.eu.example.co.uk", "example.co.uk", "*.eu.example.co.uk"),
        ("shop.acme.co", "shop.acme.co", "shop.acme.co"),           # delegated-zone apex, NOT *.acme.co
        ("www.shop.acme.co", "shop.acme.co", "*.shop.acme.co"),
        # No zone hint (older domain_scope.json): fall back to 2-label = apex.
        ("www.example.com", None, "*.example.com"),
        ("example.com", None, "example.com"),
    ]:
        got = derive_cert_domain(host, zone)
        check(f"derive_cert_domain({host}, zone={zone}) == {want}", got == want, f"got {got}")

    # CloudFront coverage rule: exact, or same-level wildcard (one label).
    for names, host, want in [
        (["*.example.com"], "www.example.com", True),
        (["*.example.com"], "example.com", False),        # apex not covered by *.
        (["*.example.com"], "app.eu.example.com", False),  # 4-level not covered
        (["*.eu.example.com"], "app.eu.example.com", True),
        (["example.com"], "example.com", True),
        # The shape verified live on a real account: a merged cert (CN + deeper
        # SAN) — only the deeper SAN covers the 4-level host.
        (["*.example.net", "*.eu.example.net"], "app.eu.example.net", True),
        (["*.example.net"], "app.eu.example.net", False),
    ]:
        got = cert_covers(names, host)
        check(f"cert_covers({names}, {host}) == {want}", got == want, f"got {got}")

    # Invariant the whole design leans on: a cert carrying derive_cert_domain(h)
    # as a SAN always covers h — across simple, deep, and multi-label-apex zones.
    for h, z in [("www.example.com", "example.com"),
                 ("app.eu.example.com", "example.com"),
                 ("a.b.c.example.com", "example.com"),
                 ("example.com", "example.com"),
                 ("*.example.com", "example.com"),
                 ("example.co.uk", "example.co.uk"),
                 ("app.eu.example.co.uk", "example.co.uk"),
                 ("shop.acme.co", "shop.acme.co")]:
        check(f"invariant: cert_covers([derive({h}, {z})], {h})",
              cert_covers([derive_cert_domain(h, z)], h))


# ── E2E: mixed-depth zone through the real parse-dns + scaffold ────────────────

DNS = {"result": [
    {"name": "www.example.com", "type": "CNAME", "content": "o1.net", "proxied": True},
    {"name": "app.eu.example.com", "type": "CNAME", "content": "o2.net", "proxied": True},
    {"name": "api.eu.example.com", "type": "CNAME", "content": "o3.net", "proxied": True},
    {"name": "deep.a.b.example.com", "type": "CNAME", "content": "o4.net", "proxied": True},
]}


def test_end_to_end():
    print("== parse-dns cert grouping (mixed 3/4/5-label zone) ==")
    tmp = tempfile.mkdtemp(prefix="cert_e2e_")
    try:
        cfg = os.path.join(tmp, "backup", "example.com", "20260808")
        os.makedirs(cfg)
        with open(os.path.join(cfg, "DNS.txt"), "w") as f:
            json.dump(DNS, f)
        out = os.path.join(tmp, "out")

        rc, log = run("cdn-parse-dns.py", os.path.join(tmp, "backup"), out)
        check("parse-dns OK", "STATUS: OK" in log, log[-400:])

        scope = json.load(open(os.path.join(out, "domain_scope.json")))

        # Correct per-depth grouping — NOT one *.example.com bucket. The
        # 5-label host's same-level wildcard replaces its LEFTMOST label only:
        # deep.a.b.example.com → *.a.b.example.com (that SAN covers it; *.b… would
        # not, it's a label short).
        groups = scope["cert_groups"]
        want_groups = {"*.example.com", "*.eu.example.com", "*.a.b.example.com"}
        check("cert_groups keyed by same-level coverage",
              set(groups) == want_groups, f"got {set(groups)}")
        check("*.eu.example.com group has both eu hosts",
              sorted(groups.get("*.eu.example.com", {}).get("hostnames", []))
              == ["api.eu.example.com", "app.eu.example.com"],
              json.dumps(groups.get("*.eu.example.com")))

        # Per-domain cert_domain + resolve mode.
        by_host = {d["hostname"]: d for d in scope["domains"]}
        check("www → *.example.com", by_host["www.example.com"]["cert_domain"] == "*.example.com")
        check("app.eu → *.eu.example.com", by_host["app.eu.example.com"]["cert_domain"] == "*.eu.example.com")
        check("deep.a.b → *.a.b.example.com", by_host["deep.a.b.example.com"]["cert_domain"] == "*.a.b.example.com")
        check("cert_arn_mode == resolve (not data_source)",
              all(d["cert_arn_mode"] == "resolve" for d in scope["domains"]))
        check("old apex_cert_groups key is gone", "apex_cert_groups" not in scope)

        # Run the rest of the pipeline so we can assert the generated main.tf.
        for stage in ("cdn-preprocess.py", "cdn-validate-chunk.py", "cdn-finalize.py",
                      "cdn-validate-final.py", "cdn-generate-shared-policies.py",
                      "cdn-generate-tf-scaffold.py"):
            rc, log = run(stage, out if stage != "cdn-preprocess.py" else os.path.join(tmp, "backup"),
                          *([out] if stage == "cdn-preprocess.py" else []))
            check(f"{stage} exit 0", rc == 0, log[-600:])

        cdn = out
        tf_domains = os.path.join(cdn, "terraform", "domains")

        # main.tf for the 4-level host: variable with a validation naming the
        # DEEPER wildcard, and NO leftover *.apex data source.
        app_main = open(os.path.join(tf_domains, "app_eu_example_com", "main.tf")).read()
        check("4-level main.tf declares cert_arn variable",
              'variable "cert_arn_app_eu_example_com"' in app_main)
        check("4-level validation names *.eu.example.com",
              "*.eu.example.com" in app_main)
        check("4-level main.tf does NOT guess *.example.com",
              '"*.example.com"' not in app_main, "stale apex guess leaked")
        check("no aws_acm_certificate data source anywhere in main.tf",
              "data \"aws_acm_certificate\"" not in app_main)
        check("cert ref uses the variable",
              "var.cert_arn_app_eu_example_com" in app_main)

        # resolve-certs.py exists, parses, and its inlined cert_covers is correct.
        resolver = os.path.join(cdn, "terraform", "resolve-certs.py")
        check("resolve-certs.py generated", os.path.exists(resolver))
        src = open(resolver).read()
        tree = ast.parse(src)  # raises on syntax error
        ns = {}
        exec(compile(tree, resolver, "exec"), ns)  # defines cert_covers + DOMAINS; main() not called
        rc_covers = ns["cert_covers"]
        check("resolver cert_covers: *.eu covers 4-level",
              rc_covers(["*.eu.example.com"], "app.eu.example.com"))
        check("resolver cert_covers: *.apex does NOT cover 4-level",
              not rc_covers(["*.example.com"], "app.eu.example.com"))
        sans_by_host = {d["hostname"]: d["cert_domain"] for d in ns["DOMAINS"]}
        check("resolver DOMAINS carries all 4 hosts", len(sans_by_host) == 4)

        # F2: the resolver must request ALL key types — list_certificates defaults
        # to RSA-1024/2048 only, hiding every ECDSA / RSA-3072+ cert.
        check("resolver passes Includes.keyTypes (not default RSA-only)",
              "keyTypes" in src and "EC_prime256v1" in src, "no keyTypes filter")

        # F4: multiple covering certs are chosen deterministically (latest expiry,
        # ARN tiebreak) — assert the resolver sorts by (-not_after, arn).
        check("F4: resolver sorts matches deterministically (expiry then ARN)",
              "not_after" in src and "-c[\"not_after\"]" in src.replace("'", '"'),
              "no deterministic sort key")

        # R2-F1: CloudFront-managed certs (ManagedBy=CLOUDFRONT) must be EXCLUDED —
        # they are locked to their managed distribution/tenant and can't be attached
        # to a standard distribution. They routinely share a host's SAN and can be
        # the newest, so a missing filter would pick one and write an undeployable
        # var. Assert the resolver skips them on the exact string ManagedBy carries.
        check("R2-F1: resolver excludes ManagedBy=CLOUDFRONT certs",
              'ManagedBy") == "CLOUDFRONT"' in src or "ManagedBy') == 'CLOUDFRONT'" in src,
              "no ManagedBy=CLOUDFRONT filter in resolver")

        # R4: storage is a tool-owned per-domain JSON (certs.auto.tfvars.json),
        # NOT spliced into user-authored HCL. This retires the whole class of
        # comment/heredoc misreads (rounds 2 & 3): there is no HCL parsing left.
        # The JSON MUST live in each domain's own Terraform root — Terraform
        # auto-loads *.auto.tfvars.json only from the root it runs in, not a parent
        # (verified live). read_existing/write_arn use only json.load/json.dump.
        check("R4: resolver has NO HCL comment/heredoc parsing",
              "_blank_hcl_comments" not in src and "_assign_re" not in src
              and "<<" not in src,
              "leftover HCL-parsing machinery in resolver")
        check("R4: resolver writes certs.auto.tfvars.json (Terraform auto-loads it)",
              "certs.auto.tfvars.json" in src)
        check("R4: JSON path is per-domain (domains/<san>/), not a shared parent file",
              'domains", san' in src or "domains', san" in src,
              "resolver must write into each domain's own root")

        # R4 behavior: json.load/dump round-trip, and a non-empty prior value is
        # KEPT (never overwritten). Point the resolver's _HERE at a temp tree and
        # exercise write_arn/read_existing directly.
        rd, wa = ns["read_existing"], ns["write_arn"]
        ns["_HERE"] = tmp  # tfvars_path(san) -> tmp/domains/<san>/certs.auto.tfvars.json
        check("R4: read_existing on a missing file -> None", rd("s1") is None)
        wa("s1", "CERT-ARN-PLACEHOLDER-1")
        jpath = os.path.join(tmp, "domains", "s1", "certs.auto.tfvars.json")
        blob = json.load(open(jpath))
        check("R4: write_arn produces valid JSON with the right key",
              blob == {"cert_arn_s1": "CERT-ARN-PLACEHOLDER-1"}, blob)
        check("R4: read_existing reads back the written value",
              rd("s1") == "CERT-ARN-PLACEHOLDER-1", f"got {rd('s1')!r}")
        # a malformed JSON must not crash the reader (treated as absent)
        with open(jpath, "w") as f:
            f.write("not valid json {")
        check("R4: malformed JSON -> None (no crash)", rd("s1") is None)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    test_pure_functions()
    test_end_to_end()
    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} check(s)")
        for label, _ in FAILURES:
            print(f"  - {label}")
        sys.exit(1)
    print("All cert-coverage checks passed.")
