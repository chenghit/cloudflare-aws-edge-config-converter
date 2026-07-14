#!/usr/bin/env python3
"""cdn-finalize.py — Stage 5: Sort, dedup, and finalize IR.

Usage:
    python3 cdn-finalize.py <output_dir> [skipped_domains_json]

Exit codes: 0 = OK, 1 = error.
"""
import json, sys, os, hashlib, copy, re
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cdn_expr_parser import orp_header_union
from cdn_common import QUOTA_RAISE, QUOTA_REDESIGN


def _nbytes(v):
    """UTF-8 byte length of a value. str()-coerces first so a non-str (a KVS
    value should be str after coercion at the store point, but be defensive)
    can't raise AttributeError on .encode()."""
    return len(str(v).encode("utf-8"))


def _combined_name_len(*name_lists):
    """Total character length of all query-string / header / cookie NAMES in a
    policy — CloudFront caps this at 1024 (a HARD limit). Each arg is a list of
    names (str) or, for headers stored as dicts, entries with a 'name'/'key'."""
    total = 0
    for names in name_lists:
        for n in names or []:
            if isinstance(n, str):
                total += len(n)
            elif isinstance(n, dict):
                total += len(n.get("name") or n.get("key") or "")
    return total


def specificity_score(pattern):
    """Compute specificity score for a CloudFront path pattern."""
    if pattern == "*":
        return 0
    if pattern == "/*":
        return 1
    # Extension pattern: *.jpg, *.css (no slash)
    if pattern.startswith("*.") and "/" not in pattern:
        return 5
    # Find first wildcard
    wc_pos = -1
    for i, ch in enumerate(pattern):
        if ch in ("*", "?"):
            wc_pos = i
            break
    if wc_pos == -1:
        # Exact match
        return len(pattern) * 10 + 100
    return wc_pos * 10


def sort_behaviors(behaviors):
    """Sort cache behaviors by specificity (descending) and assign precedence."""
    # Separate default from rest
    default = None
    rest = []
    for b in behaviors:
        if b["path_pattern"] == "*":
            default = b
        else:
            rest.append(b)

    # Sort by score descending, then lexicographic ascending for ties
    rest.sort(key=lambda b: (-specificity_score(b["path_pattern"]), b["path_pattern"]))

    # Assign precedence
    for i, b in enumerate(rest):
        b["precedence"] = i + 1

    if default:
        default["precedence"] = 999
        rest.append(default)

    return rest


def detect_shadows(behaviors):
    """Detect shadowed rules. Returns list of warning strings."""
    warnings = []
    for i, a in enumerate(behaviors):
        for j, b in enumerate(behaviors):
            if i >= j:
                continue
            if a["precedence"] >= b["precedence"]:
                continue
            # Check if A's path_pattern covers B's
            a_types = {op["type"] for op in a.get("viewer_request_ops", [])}
            b_types = {op["type"] for op in b.get("viewer_request_ops", [])}
            shadow_types = {"redirect", "origin_override"}
            if not (a_types & shadow_types) or not (b_types & shadow_types):
                continue
            if _path_covers(a["path_pattern"], b["path_pattern"]):
                b["shadowed"] = True
                b.setdefault("non_convertible", []).append({
                    "type": "shadowed_rule",
                    "reason": (
                        f"Rule potentially shadowed by cache_behavior with "
                        f"path_pattern='{a['path_pattern']}' (precedence={a['precedence']}). "
                        f"This rule may never be evaluated in CloudFront. Review manually."
                    ),
                    "cf_source_rule": "",
                    "description": f"Shadowed by {a['path_pattern']}",
                })
                warnings.append(
                    f"{b['path_pattern']} potentially shadowed by {a['path_pattern']}"
                )
    return warnings


def _path_covers(a_pat, b_pat):
    """Check if path pattern A covers (is superset of) B."""
    if a_pat in ("*", "/*"):
        return True
    # A is prefix wildcard covering B: /api/* covers /api/v2/*
    if a_pat.endswith("/*"):
        prefix = a_pat[:-1]  # "/api/"
        return b_pat.startswith(prefix)
    return False


def normalize_policy(policy):
    """Normalize a policy object for hashing."""
    def _normalize(obj):
        if isinstance(obj, float) and obj == int(obj):
            return int(obj)
        if isinstance(obj, dict):
            return {k: _normalize(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [_normalize(v) for v in obj]
        return obj
    return _normalize(policy)


def dedup_policies(all_irs):
    """Deduplicate policies across all domains.

    Returns (dedup_manifest, updated_irs).
    """
    manifest = {}  # policy_id → {hash, type, count, sample_hostname, config}
    hash_to_id = {}  # full_hash → policy_id
    prefix_counts = {}  # 8-char prefix → count (for collision handling)

    policy_keys = [
        ("cache_policy", "cache_policy_id"),
        ("origin_request_policy", "origin_request_policy_id"),
        ("response_headers_policy", "response_headers_policy_id"),
    ]

    for ir in all_irs:
        hostname = ir["metadata"]["hostname"]
        for beh in ir["cache_behaviors"]:
            for orig_key, ref_key in policy_keys:
                if orig_key not in beh:
                    continue
                policy = normalize_policy(beh[orig_key])

                # Skip empty RHP — no Terraform resource needed
                if orig_key == "response_headers_policy":
                    if (not policy.get("security_headers") and
                        not policy.get("custom_headers") and
                        not policy.get("cors") and
                        not policy.get("remove_headers")):
                        del beh[orig_key]
                        beh[ref_key] = None
                        continue

                # Skip all-none ORP — omitting ORP is equivalent
                if orig_key == "origin_request_policy":
                    fwd = policy.get("forward", {})
                    if (fwd.get("headers") == "none" and
                        fwd.get("cookies") == "none" and
                        fwd.get("query_strings") == "none"):
                        del beh[orig_key]
                        beh[ref_key] = None
                        continue

                policy_json = json.dumps(policy, sort_keys=True, separators=(",", ":"))
                full_hash = hashlib.sha256(policy_json.encode()).hexdigest()

                if full_hash in hash_to_id:
                    pid = hash_to_id[full_hash]
                    manifest[pid]["count"] += 1
                    if hostname not in manifest[pid]["used_by"]:
                        manifest[pid]["used_by"].append(hostname)
                else:
                    prefix = full_hash[:8]
                    if prefix in prefix_counts:
                        prefix_counts[prefix] += 1
                        pid = f"policy-{prefix}-{prefix_counts[prefix]}"
                    else:
                        prefix_counts[prefix] = 1
                        pid = f"policy-{prefix}"
                    hash_to_id[full_hash] = pid
                    manifest[pid] = {
                        "hash": full_hash,
                        "type": orig_key,
                        "count": 1,
                        "sample_hostname": hostname,
                        "used_by": [hostname],
                        "config": policy,
                    }

                # Replace inline policy with reference
                del beh[orig_key]
                beh[ref_key] = pid

    return manifest, all_irs


def generate_report(all_irs, manifest, shadow_warnings, skipped_domains):
    """Generate conversion_report.md content."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    total_behaviors = sum(len(ir["cache_behaviors"]) for ir in all_irs)
    # Detect S3 the SAME way the scaffold decides to generate an OAC: any
    # behavior whose origin is S3 (origin['s3_origin']). Keying on the
    # domain-level origin_type=='s3' alone would miss a Cloud-Connector→S3
    # origin (set per-behavior), leaving that OAC without the bucket-policy
    # guidance below.
    has_s3 = any(
        b.get("origin", {}).get("s3_origin")
        for ir in all_irs for b in ir.get("cache_behaviors", [])
    )

    lines = [
        "# Cloudflare → CloudFront Conversion Report",
        "",
        f"Generated: {now}",
        f"Domains processed: {len(all_irs)}",
        f"Total cache behaviors: {total_behaviors}",
        f"Total unique policies: {len(manifest)}",
        "",
        "---",
        "",
        "## Overlapping Cache Behaviors",
        "",
        "When two cache behaviors have overlapping path patterns (e.g., `/api/*` and `/api/v1/*`), "
        "the more specific pattern may be unreachable because CloudFront evaluates behaviors "
        "in order. These are flagged below.",
        "",
    ]

    if shadow_warnings:
        lines.append("| Domain | Path Pattern | Shadowed By | Rule Type |")
        lines.append("|--------|-------------|-------------|-----------|")
        for ir in all_irs:
            for beh in ir["cache_behaviors"]:
                if beh.get("shadowed"):
                    for nc in beh.get("non_convertible", []):
                        if nc.get("type") == "shadowed_rule":
                            lines.append(
                                f"| {ir['metadata']['hostname']} | "
                                f"`{beh['path_pattern']}` | "
                                f"{nc['reason'][:60]}... | shadowed |"
                            )
    else:
        lines.append("No overlapping cache behaviors detected.")

    lines += ["", "---", "", "## Domain Summary", ""]
    lines.append("| Domain | Behaviors | Ops | Non-Convertible | Overlapping | Status |")
    lines.append("|--------|-----------|-----|-----------------|-------------|--------|")
    for ir in all_irs:
        h = ir["metadata"]["hostname"]
        nb = len(ir["cache_behaviors"])
        nops = sum(len(b.get("viewer_request_ops", [])) + len(b.get("viewer_response_ops", []))
                   for b in ir["cache_behaviors"])
        nnc = sum(len(b.get("non_convertible", [])) for b in ir["cache_behaviors"])
        nsh = sum(1 for b in ir["cache_behaviors"] if b.get("shadowed"))
        lines.append(f"| {h} | {nb} | {nops} | {nnc} | {nsh} | ✅ |")
    for sd in skipped_domains:
        lines.append(f"| {sd.get('hostname', '?')} | — | — | — | — | ⏭ SKIPPED: {sd.get('reason', '?')[:40]} |")

    lines += ["", "---", "", "## Non-Convertible Items", ""]

    nc_rows = []
    for ir in all_irs:
        hostname = ir["metadata"]["hostname"]
        for beh in ir["cache_behaviors"]:
            for nc in beh.get("non_convertible", []):
                if nc.get("type") == "shadowed_rule":
                    continue
                nc_rows.append((hostname, beh["path_pattern"], nc.get("description", ""), nc.get("reason", "")))

    if nc_rows:
        # Group: items that appear for ALL domains vs domain-specific
        all_hostnames = set(ir["metadata"]["hostname"] for ir in all_irs)
        # Group by (description, reason) → set of hostnames
        from collections import defaultdict
        nc_groups = defaultdict(set)
        for hostname, pp, desc, reason in nc_rows:
            nc_groups[(pp, desc, reason)].add(hostname)

        global_nc = [(pp, desc, reason) for (pp, desc, reason), hosts in nc_groups.items()
                     if hosts == all_hostnames]
        domain_nc = [(hostname, pp, desc, reason) for hostname, pp, desc, reason in nc_rows
                     if (pp, desc, reason) not in [(p, d, r) for p, d, r in global_nc]]

        if global_nc:
            lines.append(f"**Affects all {len(all_hostnames)} domains:**")
            lines.append("")
            lines.append("| Cache Behavior | Description | Reason |")
            lines.append("|---------------|-------------|--------|")
            for pp, desc, reason in global_nc:
                lines.append(f"| `{pp}` | {desc} | {reason} |")
            lines.append("")

        if domain_nc:
            lines.append("**Domain-specific:**")
            lines.append("")
            lines.append("| Domain | Cache Behavior | Description | Reason |")
            lines.append("|--------|---------------|-------------|--------|")
            for hostname, pp, desc, reason in domain_nc:
                lines.append(f"| {hostname} | `{pp}` | {desc} | {reason} |")
    else:
        lines.append("No non-convertible items.")

    lines += ["", "---", "", "## Policy Deduplication Summary", ""]
    shared = {pid: v for pid, v in manifest.items() if v["count"] > 1}
    if shared:
        lines.append("| Policy ID | Type | Cache Behaviors | Sample Domain |")
        lines.append("|-----------|------|-----------------|---------------|")
        for pid in sorted(shared):
            v = shared[pid]
            lines.append(f"| `{pid}` | {v['type']} | {v['count']} | {v['sample_hostname']} |")
    else:
        lines.append("No shared policies (all policies are domain-unique).")

    lines += ["", "---", "", "## Warnings", ""]
    all_warnings = list(shadow_warnings)
    if skipped_domains:
        for sd in skipped_domains:
            all_warnings.append(f"Domain skipped: {sd.get('hostname', '?')} — {sd.get('reason', '?')}")

    # KVS size estimation per domain
    for ir in all_irs:
        hostname = ir["metadata"]["hostname"]
        kvs_data = ir["metadata"].get("kvs_data", [])
        if not kvs_data and not ir["metadata"].get("kvs_requirements", {}).get("needs_continent"):
            continue
        # Estimate: each entry = key bytes + value bytes + ~20 bytes overhead.
        # AWS measures the store size in BYTES (_nbytes encodes to UTF-8) — a char
        # count under-reports multi-byte content (IDN hosts, non-Latin paths),
        # which could let a real >5 MB store slip under the HARD-limit gate below.
        total_bytes = sum(_nbytes(e.get("key", "")) + _nbytes(e.get("value", "")) + 20
                          for e in kvs_data)
        # Continent/EU mappings add ~3KB
        kvs_req = ir["metadata"].get("kvs_requirements", {})
        if kvs_req.get("needs_continent"):
            total_bytes += 3000
        if kvs_req.get("needs_eu"):
            total_bytes += 300
        # The 5 MB per-store size is a HARD CloudFront limit — NOT adjustable via
        # Service Quotas or a Support case (verified: it has no increase path;
        # writes past 5 MB fail with EntitySizeLimitExceeded). So >5 MB is a
        # QUOTA-REDESIGN blocker (the data must be split across stores or shrunk),
        # NOT a "request a quota increase". The estimate is approximate, so a
        # 4–5 MB store is flagged as approaching (it may cross 5 MB once seeded).
        # Display FLOORS to 2 decimals (integer math, no round-up): a store BELOW
        # 5 MB never rounds UP to "5.00 MB" in the "approaching" tier the way a
        # plain :.2f would (4,996,000 B → "4.99 MB", not "5.00"). Exactly
        # 5,000,000 B does show "5.00 MB", but that's honest — it is exactly at
        # (not over) the 5 MB cap, which is why it's still in the approaching
        # tier (the blocker gate is > 5,000,000, and 5 MB itself is allowed).
        est_mb = (total_bytes // 10_000) / 100
        if total_bytes > 5_000_000:
            all_warnings.append(
                f"{QUOTA_REDESIGN} — KVS for {hostname}: estimated {est_mb:.2f} MB exceeds the "
                f"5 MB HARD per-store limit, NOT adjustable via Service Quotas/Support. "
                f"Deploy/seeding will be rejected (EntitySizeLimitExceeded). Split the data "
                f"across multiple key value stores (a domain's error pages, bulk redirects, "
                f"and IP/geo lists can each use a separate store) or shrink it before deploying."
            )
        elif total_bytes > 4_000_000:
            all_warnings.append(
                f"KVS for {hostname}: estimated {est_mb:.2f} MB (5 MB is a HARD, non-raisable "
                f"limit). Close to the cap — the estimate is approximate, so verify after "
                f"seeding; if it crosses 5 MB, split the data across multiple stores."
            )
        elif total_bytes > 3_000_000:
            all_warnings.append(
                f"KVS for {hostname}: estimated {est_mb:.2f} MB (HARD limit 5 MB). "
                f"Approaching limit — monitor after deployment."
            )

    # ── CloudFront quota checks (soft vs hard) ────────────────────────────────
    # SOFT quotas carry "Request a higher quota" in the AWS docs — the user can
    # raise them via Service Quotas. HARD quotas cannot be raised, so exceeding
    # one means the config must be redesigned before it can deploy. The messages
    # say which, so the user doesn't waste a Support request on an unraisable
    # limit. See _quota_warn.
    def _quota_warn(count, limit, hard, subject, raise_via="Service Quotas"):
        """Append a soft/hard quota warning if count exceeds (or nears) limit.

        Each over-limit warning starts with a machine-readable tag so the final
        ---RESULT--- and the agent know what to DO, not just that a number was
        exceeded:
          QUOTA-REDESIGN — HARD limit, not adjustable. Deploy WILL be rejected
                           forever as-is; the source must be shrunk/redesigned.
          QUOTA-RAISE    — SOFT limit, adjustable. Config is correct; deploy is
                           blocked only until the quota is raised, then deploys
                           unchanged (the tool has already minimized usage via
                           dedup — there is no further code-side lever).
        `raise_via` names where to request the increase (some quotas are
        Support-only, not in the Service Quotas console)."""
        if count > limit:
            if hard:
                all_warnings.append(
                    f"{QUOTA_REDESIGN} — {subject}: {count} exceeds the HARD limit of "
                    f"{limit}, NOT adjustable via Service Quotas/AWS Support. Deploy will "
                    f"be rejected as-is — reduce/redesign the source before deploying.")
            else:
                all_warnings.append(
                    f"{QUOTA_RAISE} — {subject}: {count} exceeds the default quota of "
                    f"{limit} (SOFT). The conversion is correct; request an increase via "
                    f"{raise_via}, then deploy unchanged. Deploy is blocked until raised.")
        elif not hard and count > limit * 0.8:
            all_warnings.append(
                f"{subject}: {count} approaching the default quota of {limit} (SOFT).")

    # Per-account custom policy counts (SOFT: 20 each).
    policy_counts = {"cache_policy": 0, "origin_request_policy": 0, "response_headers_policy": 0}
    for entry in manifest.values():
        t = entry["type"]
        if t in policy_counts:
            policy_counts[t] += 1
    # Shared custom ORPs (native CloudFront-* header forwarding) are ALSO
    # aws_cloudfront_origin_request_policy resources and count against the same
    # 20/account quota. They're generated in cdn-generate-shared-policies (deduped
    # by header set), not in the manifest — count distinct header sets here so the
    # quota check (and the final ---RESULT--- warning) reflects the real total.
    # Was a bug: 54 hosts each got an identical custom ORP → hit the 20 cap.
    custom_orp_sets = {tuple(orp_header_union(ir)) for ir in all_irs}
    custom_orp_sets.discard(())  # domains with no native-header need
    policy_counts["origin_request_policy"] += len(custom_orp_sets)
    for ptype, label in [
        ("cache_policy", "Custom cache policies per account"),
        ("origin_request_policy", "Custom origin request policies per account (incl. shared custom ORPs)"),
        ("response_headers_policy", "Custom response headers policies per account"),
    ]:
        _quota_warn(policy_counts[ptype], 20, False, label)

    # Per-policy item quotas. Counts (query/header/cookie ≤ 10) are SOFT; the
    # combined name length (≤ 1024) is HARD.
    for pid, entry in manifest.items():
        cfg = entry["config"]
        used = ", ".join(entry.get("used_by", [entry.get("sample_hostname", "?")]))
        if entry["type"] == "cache_policy":
            ck = cfg.get("cache_key", cfg)
            qs = ck.get("query_strings_list", ck.get("query_strings", []))
            hd = ck.get("headers", [])
            co = ck.get("cookies", [])
            qs = qs if isinstance(qs, list) else []
            _quota_warn(len(qs), 10, False, f"Cache policy {pid} (used by {used}) query strings")
            _quota_warn(len(hd) if isinstance(hd, list) else 0, 10, False, f"Cache policy {pid} (used by {used}) headers")
            _quota_warn(len(co) if isinstance(co, list) else 0, 10, False, f"Cache policy {pid} (used by {used}) cookies")
            _quota_warn(_combined_name_len(qs, hd, co), 1024, True,
                        f"Cache policy {pid} (used by {used}) combined query/header/cookie name length")
        elif entry["type"] == "origin_request_policy":
            fwd = cfg.get("forward", {})
            qs = fwd.get("query_strings_list", []) if isinstance(fwd.get("query_strings_list"), list) else []
            hd = cfg.get("headers", []) if isinstance(cfg.get("headers"), list) else []
            co = fwd.get("cookies_list", []) if isinstance(fwd.get("cookies_list"), list) else []
            _quota_warn(_combined_name_len(qs, hd, co), 1024, True,
                        f"Origin request policy {pid} (used by {used}) combined name length")
        elif entry["type"] == "response_headers_policy":
            ch = cfg.get("custom_headers", [])
            _quota_warn(len(ch) if isinstance(ch, list) else 0, 10, False,
                        f"Response headers policy {pid} (used by {used}) custom headers")

    # Per-distribution quotas (all keyed on the domain's own IR).
    for ir in all_irs:
        hostname = ir["metadata"]["hostname"]
        # Cache behaviors per distribution (SOFT: 75).
        _quota_warn(len(ir["cache_behaviors"]), 75, False, f"{hostname}: cache behaviors")

        # Custom ORP header whitelist (SOFT: 10). The shared custom ORP forwards
        # the UNION of required_orp_headers across all of the domain's behaviors
        # (orp_header_union — the SAME helper the resource and reference use).
        # Checking per-behavior would miss a domain that stays <10 on each
        # behavior but exceeds 10 in the union — the real ORP resource is what
        # AWS validates. Header NAME length also counts toward the 1024
        # combined-name HARD limit.
        orp_union = orp_header_union(ir)
        if orp_union:
            _quota_warn(len(orp_union), 10, False,
                        f"{hostname}: custom ORP forwarded headers (union across behaviors)")
            _quota_warn(sum(len(h) for h in orp_union), 1024, True,
                        f"{hostname}: custom ORP combined header-name length")

        # Origins per distribution (SOFT: 100). Origins are deduped by domain in
        # collect_origins, so count distinct origin domains across behaviors —
        # this matches the number of origin blocks the scaffold emits.
        origin_domains = {b.get("origin", {}).get("domain")
                          for b in ir["cache_behaviors"]
                          if b.get("origin", {}).get("domain")}
        _quota_warn(len(origin_domains), 100, False, f"{hostname}: origins per distribution")

    # Per-account totals the pipeline can know here: one distribution per proxied
    # host (SOFT: 500). NOTE: the KVS-store quota is NOT checked here — KVS is
    # content-hash DEDUPED in Stage 8 (cdn-generate-js), so the real store count
    # (shared groups + standalone) is only known there, and that's where the 50
    # SOFT quota is checked. Counting per-host here (one KVS per host needing it)
    # would grossly over-report (e.g. 54 hosts → 2 actual stores) — a false alarm.
    _quota_warn(len(all_irs), 500, False, "Distributions per account (one per proxied host)")

    # CFF count quota (default 100) is checked post-dedup in Stage 8 (generate-js),
    # which reports the actual deduped CFF_TOTAL. This quota is NOT in Service
    # Quotas — it's raised via an AWS Support case, not self-service (that's what
    # the Stage-8 runtime message says). The CFF SIZE limit (10 KB) is HARD and
    # enforced there too.
    cff_warning = None

    # CORS credentials + wildcard check
    for pid, entry in manifest.items():
        if entry["type"] != "response_headers_policy":
            continue
        cors = entry["config"].get("cors")
        if not cors or not isinstance(cors, dict):
            continue
        if cors.get("Access-Control-Allow-Credentials") == "true":
            origins = cors.get("Access-Control-Allow-Origin", "")
            headers = cors.get("Access-Control-Allow-Headers", "")
            used = ", ".join(entry.get("used_by", [entry.get("sample_hostname", "?")]))
            if "*" in origins:
                all_warnings.append(
                    f"CORS policy {pid} (used by {used}): credentials=true with wildcard "
                    f"origin. Converted using TLD wildcard patterns (*.com, *.net, etc.) "
                    f"which cover ~60 common TLDs. CloudFront echoes back the exact "
                    f"request Origin value. Limitations: (1) Origins on unlisted TLDs "
                    f"will not match — add patterns to policies.tf as needed. "
                    f"(2) Origins with non-standard ports are not matched by scheme-less "
                    f"wildcards. CloudFront only serves on ports 80/443, so this only "
                    f"affects cross-origin requests FROM non-standard-port origins."
                )
            if "*" in origins and not cors.get("_origin_override", True):
                all_warnings.append(
                    f"CORS policy {pid} (used by {used}): Cloudflare operation was 'add' "
                    f"(not 'set'). CloudFront cors_config with origin_override=false will "
                    f"not add CORS headers when the request has no Origin header. This "
                    f"differs from Cloudflare which adds headers unconditionally. Only "
                    f"affects non-browser clients (curl, SDKs) — browsers always send "
                    f"Origin for cross-origin requests."
                )
            if "*" in headers:
                all_warnings.append(
                    f"CORS policy {pid} (used by {used}): credentials=true with wildcard "
                    f"headers. Replaced with common header set (Authorization, Content-Type, "
                    f"Origin, Accept, X-Requested-With). Add additional headers in policies.tf "
                    f"if your application requires them."
                )

    # Op-less behaviors that STILL carry the CFF because the domain has a
    # zone-wide op (no path condition) — those must run on every behavior to
    # match Cloudflare's zone scope, so the tool keeps them. (Op-less behaviors
    # in a domain with NO zone-wide op are dropped automatically by the scaffold
    # — inv: _behavior_needs_cff — and are NOT flagged.) This is a cost note, not
    # an action item; the drop is already automatic where it's safe.
    cff_no_ops = []
    for ir in all_irs:
        hostname = ir["metadata"]["hostname"]
        has_zonewide = any(op.get("scope") == "all"
                           for b in ir["cache_behaviors"]
                           for op in b.get("viewer_request_ops", []) + b.get("viewer_response_ops", []))
        if not has_zonewide:
            continue
        no_ops_behs = [b["path_pattern"] for b in ir["cache_behaviors"]
                       if not b.get("viewer_request_ops") and not b.get("viewer_response_ops")
                       and b["path_pattern"] not in ("default", "*")]
        if no_ops_behs:
            cff_no_ops.append((hostname, no_ops_behs))
    if cff_no_ops:
        domains_str = ", ".join(h for h, _ in cff_no_ops)
        # Show sample paths from first domain
        sample = cff_no_ops[0][1]
        paths = ", ".join(f"`{p}`" for p in sample[:5])
        if len(sample) > 5:
            paths += f" (+{len(sample) - 5} more)"
        all_warnings.append(
            f"CFF zone-wide association ({len(cff_no_ops)} domains): these domains have a "
            f"zone-wide rule (no path condition — bulk redirects / header transforms), so the "
            f"shared CFF is attached to every behavior, including path behaviors with no rule of "
            f"their own (e.g. {paths}). This is required to replicate Cloudflare's zone-wide scope "
            f"and adds CFF invocation cost ($0.10/million requests) on those paths. Behaviors NOT "
            f"covered by a zone-wide rule already carry no CFF. To trim further, delete a "
            f"behavior's function_associations block in main.tf — but the zone-wide redirects / "
            f"header mutations will then no longer apply to that path."
        )

    if cff_warning:
        lines.append(cff_warning)
        lines.append("")

    if all_warnings:
        for w in all_warnings:
            lines.append(f"- {w}")
    else:
        lines.append("No warnings.")

    lines += [
        "", "---", "",
        "## Caveats",
        "",
        "- Response Header Transform rules converted to CFF viewer-response will NOT execute "
        "when origin returns HTTP 400+. This differs from Cloudflare where Response Header "
        "Transform runs on all responses. Use Lambda@Edge origin-response if needed.",
        "- Lambda@Edge viewer-response also does NOT execute on 4xx+ origin responses. "
        "Only Lambda@Edge origin-response runs on all origin responses.",
        "- If your rules use more than 10 geo/device headers per cache behavior, "
        "request a CloudFront ORP headers quota increase via AWS Support.",
        "- **Geolocation data source differs.** Cloudflare now sources IP geolocation "
        "from IPinfo, while CloudFront uses MaxMind. Any rule that matches on a geo field "
        "(country, region/subdivision, city, or the derived continent / EU-membership "
        "lookups) is converted faithfully in logic, but the *value* for a given IP may "
        "differ between the two providers — a request judged `US-CA` by Cloudflare could "
        "resolve differently under CloudFront, especially near country/region borders or "
        "for ranges the two providers disagree on. After cutover, spot-check geo-sensitive "
        "rules with representative and boundary IPs before relying on them.",
        "- `http.request.full_uri` is reconstructed as `https://<host><path>[?<query>]`. "
        "CloudFront edge functions do not expose the request scheme, so the scheme is "
        "assumed to be **https**; a rule that matched on an `http://` full URI will behave "
        "as if the request were https.",
        "- Second-level geo subdivisions (`ip.src.subdivision_2_iso_code`) are non-convertible: "
        "CloudFront exposes only the first-level subdivision (`CloudFront-Viewer-Country-Region`). "
        "First-level subdivisions (`ip.src.subdivision_1_iso_code`) convert normally.",
    ]

    # WAF + Custom Header pattern guidance (if CIDR-related non_convertible items exist)
    has_cidr_nc = any("CIDR" in reason for _, _, _, reason in nc_rows)
    if has_cidr_nc:
        lines += [
            "", "---", "",
            "## WAF + Custom Header Pattern",
            "",
            "Some rules reference IP lists with CIDR ranges, which CloudFront Functions "
            "cannot match (CFF only has access to the viewer's single IP address via "
            "`event.viewer.ip`). Use this pattern to handle CIDR-based IP matching:",
            "",
            "1. Create an AWS WAF IP set containing the CIDR ranges",
            "2. Create a WAF rule with **Count** action that matches the IP set "
            "and adds a custom header (e.g., `x-waf-ip-match: blocklist1`)",
            "3. Associate the WAF Web ACL with the CloudFront distribution",
            "4. In the CloudFront Function, check `request.headers['x-waf-ip-match']` "
            "and execute the corresponding logic (redirect, block, etc.)",
            "",
            "WAF evaluates before CloudFront Functions, so the custom header is "
            "available when the CFF runs. The Count action ensures the request is "
            "not terminated by WAF — it only labels the request for CFF to act on.",
            "",
            "This pattern also supports IPv4/IPv6 mixed lists and CIDR notation, "
            "which are native to AWS WAF IP sets (up to 10,000 entries per set).",
        ]

    # Deployment steps
    domains_with_kvs = [ir["metadata"]["hostname"] for ir in all_irs
                        if any(ir["metadata"].get("kvs_requirements", {}).values())]
    domains_with_le = [ir["metadata"]["hostname"] for ir in all_irs
                       if ir["metadata"].get("lambda_edge", {}).get("origin_response")]
    domain_list = [ir["metadata"] for ir in all_irs]

    lines += [
        "", "---", "",
        "## Deployment Steps",
        "",
        "### 1. Set AWS credentials",
        "",
        "You need an AWS IAM user or role with permissions for CloudFront, Lambda, IAM, "
        "ACM, and CloudFront KeyValueStore. Configure credentials using one of:",
        "",
        "```bash",
        "# Option A: Named profile (recommended)",
        "export AWS_PROFILE=<your-profile-name>",
        "",
        "# Option B: Environment variables",
        "export AWS_ACCESS_KEY_ID=<your-access-key>",
        "export AWS_SECRET_ACCESS_KEY=<your-secret-key>",
        "export AWS_DEFAULT_REGION=us-east-1",
        "```",
        "",
        "Verify credentials work: `aws sts get-caller-identity`",
        "",
        "### 2. Prerequisite — ACM certificates (REQUIRED before any apply)",
        "",
        "Every distribution's `viewer_certificate` is resolved from an ACM certificate "
        "via a Terraform `data` source. The certificate MUST already exist and be "
        "**ISSUED** before you run `terraform apply`, or `terraform plan` fails immediately.",
        "",
        "- **Region: us-east-1 (N. Virginia)** — CloudFront only accepts certs from there, "
        "regardless of where your origins live.",
        "- One cert must cover **every** custom domain being deployed. A `*.<apex>` wildcard "
        "(e.g. `*.example.com`) covers all subdomains; add the apex itself as a SAN if you "
        "deploy the apex too.",
        "- The cert must be validated (DNS or email) to reach status ISSUED — a PENDING "
        "cert will NOT be found by the data source.",
        "",
        "Check what you have:",
        "```bash",
        "aws acm list-certificates --region us-east-1 \\",
        "  --query \"CertificateSummaryList[].{Domain:DomainName,Status:Status}\" --output table",
        "```",
        "",
        "### 3. One-time — enable the Terraform provider plugin cache",
        "",
        "Each domain is a separate Terraform root. WITHOUT a shared plugin cache, every "
        "`terraform init` re-downloads the ~800 MB AWS provider — for dozens of domains "
        "that is hours of wasted download and disk. Enable the cache with the "
        "`TF_PLUGIN_CACHE_DIR` environment variable (the shell expands the path before "
        "Terraform sees it):",
        "```bash",
        'export TF_PLUGIN_CACHE_DIR="$HOME/.terraform.d/plugin-cache"',
        'mkdir -p "$TF_PLUGIN_CACHE_DIR"   # Terraform will NOT create it; it must exist',
        "```",
        "Keep that `export` in the same shell for all the `terraform` commands below (add "
        "it to `~/.bashrc` / `~/.zshrc` to persist).",
        "",
        "**Do NOT** put `plugin_cache_dir = \"$HOME/…\"` in `~/.terraformrc` instead: "
        "Terraform only env-expands that value when `HOME` happens to be set in its "
        "process, and on a shell/CI where it isn't, it silently creates a literal `$HOME` "
        "directory and the cache quietly does nothing. If you prefer the config-file form, "
        "write a fully-resolved absolute path (e.g. `plugin_cache_dir = \"/home/you/"
        ".terraform.d/plugin-cache\"`), not `$HOME` or `~`.",
        "",
        "### 4. Deploy shared policies",
        "",
        "Shared policies (cache / origin-request / response-headers, incl. the shared "
        "custom ORP) MUST be applied FIRST — each domain looks them up by name via a data "
        "source, so they must exist before any domain applies.",
        "```bash",
        "cd cloudflare-to-aws-cdn/terraform/shared",
        "terraform init && terraform apply",
        "```",
        "",
        "### 5. Deploy each domain",
        "",
        "With the plugin cache enabled (step 3), plain `terraform init` reuses the cached "
        "provider. Do NOT use `-upgrade` in the per-domain loop — it forces a network "
        "re-check of the registry on every domain and is the usual cause of init hangs on "
        "a slow connection. The committed `.terraform.lock.hcl` already pins the version.",
        "",
        "To deploy **all** domains:",
        "```bash",
        "for d in cloudflare-to-aws-cdn/terraform/domains/*/; do",
        '  echo "Deploying $(basename $d)..."',
        "  (cd \"$d\" && terraform init && terraform apply -auto-approve)",
        "done",
        "```",
        "",
        "To deploy **specific** domains only (e.g., when CFF quota limits apply):",
        "```bash",
        "for d in cdn_example_com api_example_com; do",
        '  echo "Deploying $d..."',
        "  (cd \"cloudflare-to-aws-cdn/terraform/domains/$d\" && terraform init && terraform apply -auto-approve)",
        "done",
        "```",
        "",
    ]

    if domains_with_kvs:
        step_kvs = 6
        lines += [
            f"### {step_kvs}. Seed KVS data",
            "",
            "**Requires `boto3` with the CRT extra**: `pip install 'boto3[crt]'` "
            "(quote it — the brackets are shell globs otherwise). The CloudFront "
            "KeyValueStore data-plane API requires SigV4a signing, which needs the "
            "`botocore[crt]` (AWS Common Runtime) dependency the CRT extra pulls in. "
            "Plain `pip install boto3` will fail seeding with a signing/credential error.",
            "",
            "Run `seed-kvs.py` for each domain **after its `terraform apply` succeeds**. "
            "The script reads the KVS ARN from `terraform output` — it will fail if "
            "`terraform apply` has not completed.",
            "",
            "```bash",
            "for d in cloudflare-to-aws-cdn/terraform/domains/*/; do",
            '  [ -f "$d/seed-kvs.py" ] && (cd "$d" && python3 seed-kvs.py)',
            "done",
            "```",
            "",
        ]

    step_n = 7 if domains_with_kvs else 6
    lines += [
        f"### {step_n}. Validate deployment",
        "",
        "Each domain has a `test-cdn-rules.py` script for post-deployment validation.",
        "Run it against the CloudFront distribution domain name:",
        "",
        "```bash",
        "for d in cloudflare-to-aws-cdn/terraform/domains/*/; do",
        '  DIST=$(cd "$d" && terraform output -raw distribution_domain_name 2>/dev/null)',
        '  [ -n "$DIST" ] && (cd "$d" && python3 test-cdn-rules.py "$DIST")',
        "done",
        "```",
        "",
        "The script tests redirects, error pages, bulk redirects, and response headers "
        "using curl. Items requiring manual testing (IP-based rules, geo conditions, "
        "origin overrides) are listed as SKIP with instructions.",
        "",
    ]

    step_n += 1
    lines += [
        f"### {step_n}. DNS cutover (you do this, at your own pace)",
        "",
        f"The tool does NOT touch DNS. When you're ready, point each of the "
        f"{len(domain_list)} domains at its CloudFront distribution domain name "
        "(a CNAME, or an ALIAS/ANAME at the apex). Do this on your own schedule — "
        "there's no rush, and you'll likely want to run your own canary / staged "
        "rollout first. Nothing above requires DNS to be switched.",
        "",
        "Get each distribution's domain name:",
        "```bash",
        "for d in cloudflare-to-aws-cdn/terraform/domains/*/; do",
        '  echo "$(basename $d): $(cd "$d" && terraform output -raw distribution_domain_name 2>/dev/null)"',
        "done",
        "```",
        "",
        "**Test before you cut over** — no DNS change needed. Hit the distribution "
        "domain directly and spoof the Host header, which is exactly what the "
        "generated `test-cdn-rules.py` does:",
        "```bash",
        "curl -sI -H 'Host: www.example.com' https://<distribution-domain>/some/path",
        "```",
        "This exercises the real behaviors, functions, and origins on CloudFront "
        "while your live traffic still flows through Cloudflare, so you can validate "
        "and canary safely, then switch DNS when you're satisfied.",
        "",
    ]

    if has_s3:
        lines += [
            "", "---", "",
            "## Post-Deployment: S3 Bucket Policy",
            "",
            "After deploying CloudFront distributions, update each S3 bucket policy to "
            "allow access via Origin Access Control (OAC). Replace placeholders with "
            "actual values from `terraform output`.",
            "",
            "```json",
            '{',
            '  "Version": "2012-10-17",',
            '  "Statement": [{',
            '    "Sid": "AllowCloudFrontOAC",',
            '    "Effect": "Allow",',
            '    "Principal": {"Service": "cloudfront.amazonaws.com"},',
            '    "Action": "s3:GetObject",',
            '    "Resource": "<BUCKET_ARN>/*",',
            '    "Condition": {',
            '      "StringEquals": {',
            '        "AWS:SourceArn": "<DISTRIBUTION_ARN>"',
            '      }',
            '    }',
            '  }]',
            '}',
            "```",
        ]

    lines += [
        "", "---", "",
        "## Troubleshooting",
        "",
        "### `terraform init` fails with provider checksum mismatch",
        "",
        "```",
        "Error: the cached package for registry.terraform.io/hashicorp/aws does not match any of the checksums recorded in the dependency lock file",
        "```",
        "",
        "Fix (once): `terraform init -upgrade` in that one domain to re-record the lock, "
        "then go back to plain `terraform init` for the rest. Do NOT put `-upgrade` in the "
        "deploy loop — with the plugin cache enabled (deploy step 3) it forces a registry "
        "re-check on every domain and is the usual cause of init hangs.",
        "",
        "### `terraform init` hangs for minutes on each domain",
        "",
        "Almost always `-upgrade` in the loop (a network registry re-check per domain) "
        "and/or a missing plugin cache re-downloading the ~800 MB provider each time. "
        "Fix: enable the plugin cache (deploy step 3) and drop `-upgrade` from the loop.",
        "",
        "### `seed-kvs.py` fails with a signing / NoCredentialProviders / SigV4a error",
        "",
        "The CloudFront KeyValueStore data API needs SigV4a signing (AWS Common Runtime). "
        "Fix: `pip install 'boto3[crt]'` (quote it). Plain `boto3` lacks the CRT signer.",
        "",
        "### `seed-kvs.py` fails with `KVS ARN must be a valid ARN`",
        "",
        "This means `terraform apply` did not complete successfully for this domain. "
        "The KVS resource was not created, so `terraform output` returns an empty ARN. "
        "Fix: re-run `terraform apply` for the domain, then re-run `seed-kvs.py`.",
        "",
        "### `terraform apply` fails with `ResourceNotFoundException` for Lambda@Edge",
        "",
        "Lambda@Edge functions replicate globally and take time to delete. If you're "
        "re-deploying after a `terraform destroy`, wait 15–30 minutes for replicas to "
        "be cleaned up, then retry.",
        "",
    ]

    # Cloudflare default caching note
    lines += [
        "---", "",
        "## Cloudflare Default Caching Behavior (Not Migrated)",
        "",
        "Cloudflare automatically caches responses for the following ~70 file extensions "
        "with a default TTL of 2 hours. This behavior applies to **all** proxied domains "
        "and is NOT part of Cache Rules — it is a platform default.",
        "",
        "**This default caching behavior is not automatically migrated to CloudFront.** "
        "CloudFront does not have an equivalent built-in feature. If your domains rely on "
        "this behavior, you need to add a Lambda@Edge origin-response function to replicate it.",
        "",
        "### Cached file extensions",
        "",
        "```",
        "7z, avif, bmp, bz2, css, csv, doc, docx, eot, eps, gif, gz, ico, jar, jpeg, jpg,",
        "js, json, mid, midi, mp3, mp4, ogg, otf, pdf, pict, pls, png, ppt, pptx, ps,",
        "rar, svg, svgz, swf, tar, tif, tiff, ttf, webm, webp, woff, woff2, xls, xlsx,",
        "xml, zip, zst, class, dmg, ejs, exe, flv, gzip, m4v, mov, ogv, pps, ppsx, tgz,",
        "wmv, avi, bin, cab, dat, iso, msi, pkg, qt, rss, tsv, wav",
        "```",
        "",
        "### Example Lambda@Edge origin-response function",
        "",
        "Associate this function with the `origin-response` event on distributions that "
        "need Cloudflare-equivalent default caching.",
        "",
        "```javascript",
        "'use strict';",
        "",
        "const CACHED_EXTENSIONS = new Set([",
        "  '7z','avif','bmp','bz2','css','csv','doc','docx','eot','eps','gif','gz','ico',",
        "  'jar','jpeg','jpg','js','json','mid','midi','mp3','mp4','ogg','otf','pdf',",
        "  'pict','pls','png','ppt','pptx','ps','rar','svg','svgz','swf','tar','tif',",
        "  'tiff','ttf','webm','webp','woff','woff2','xls','xlsx','xml','zip','zst',",
        "  'class','dmg','ejs','exe','flv','gzip','m4v','mov','ogv','pps','ppsx','tgz',",
        "  'wmv','avi','bin','cab','dat','iso','msi','pkg','qt','rss','tsv','wav',",
        "]);",
        "",
        "exports.handler = (event, context, callback) => {",
        "  const response = event.Records[0].cf.response;",
        "  const request = event.Records[0].cf.request;",
        "  const uri = request.uri;",
        "  const ext = uri.includes('.') ? uri.split('.').pop().toLowerCase() : '';",
        "",
        "  // Only add cache header if origin didn't set one and extension matches",
        "  const cc = response.headers['cache-control'];",
        "  if (!cc && CACHED_EXTENSIONS.has(ext)) {",
        "    response.headers['cache-control'] = [{",
        "      key: 'Cache-Control',",
        "      value: 'public, max-age=7200'  // 2 hours, matching Cloudflare default",
        "    }];",
        "  }",
        "",
        "  callback(null, response);",
        "};",
        "```",
        "",
    ]

    # Summary facts for the pipeline's final ---RESULT--- (the last step,
    # cdn-validate-js, reads cdn_summary.json and surfaces these to the user, so
    # deploy concerns aren't buried in the report / diluted by later steps).
    total_nc = sum(len(b.get("non_convertible", []))
                   for ir in all_irs for b in ir.get("cache_behaviors", []))
    summary = {
        "domains": len(all_irs),
        "total_policies": len(manifest),
        "non_convertible_items": total_nc,
        "warnings": all_warnings,               # quota + shadow + limit warnings
        "s3_oac_bucket_policy_required": has_s3,  # every S3 origin needs a manual bucket policy
        "skipped_domains": [sd.get("hostname", "?") for sd in skipped_domains],
    }
    return "\n".join(lines) + "\n", summary


def main():
    if len(sys.argv) < 2:
        print("Usage: cdn-finalize.py <output_dir> [skipped_domains_json]", file=sys.stderr)
        sys.exit(1)

    output_dir = os.path.expanduser(sys.argv[1])
    skipped_domains = []
    if len(sys.argv) >= 3 and os.path.exists(sys.argv[2]):
        with open(sys.argv[2]) as f:
            skipped_domains = json.load(f)

    acc_dir = os.path.join(output_dir, "ir", "accumulator")
    val_dir = os.path.join(output_dir, "ir", "validation", "chunk")
    final_dir = os.path.join(output_dir, "ir", "final")
    shared_dir = os.path.join(output_dir, "shared")
    os.makedirs(final_dir, exist_ok=True)
    os.makedirs(shared_dir, exist_ok=True)

    # Step 1: Verify all accumulators have V1 PASS
    json_files = sorted(f for f in os.listdir(acc_dir) if f.endswith(".json") and not f.endswith(".error.json"))
    for filename in json_files:
        hostname = filename.replace(".json", "")
        v1_path = os.path.join(val_dir, f"{hostname}-v1.json")
        if not os.path.exists(v1_path):
            print(f"ERROR: V1 validation report not found for {hostname}", file=sys.stderr)
            sys.exit(1)
        with open(v1_path) as f:
            v1 = json.load(f)
        if v1.get("status") != "PASS":
            print(f"ERROR: {hostname} did not pass V1 validation", file=sys.stderr)
            sys.exit(1)

    # Step 2: Load all IRs
    all_irs = []
    for filename in json_files:
        with open(os.path.join(acc_dir, filename)) as f:
            all_irs.append(json.load(f))

    # Step 3: Sort cache behaviors and detect shadows
    all_shadow_warnings = []
    for ir in all_irs:
        ir["cache_behaviors"] = sort_behaviors(ir["cache_behaviors"])
        warnings = detect_shadows(ir["cache_behaviors"])
        all_shadow_warnings.extend(
            f"{ir['metadata']['hostname']}: {w}" for w in warnings
        )

    # Step 4: Policy deduplication
    manifest, all_irs = dedup_policies(all_irs)

    # Step 5: Write finalized IR files
    for ir in all_irs:
        hostname = ir["metadata"]["hostname"]
        ir["metadata"]["finalized_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        out_path = os.path.join(final_dir, f"{hostname}.json")
        with open(out_path, "w") as f:
            json.dump(ir, f, indent=2, ensure_ascii=False)
        print(f"OK: {hostname} → {len(ir['cache_behaviors'])} behaviors")

    # Step 6: Write dedup manifest
    manifest_out = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total_policies": len(manifest),
        "policies": dict(sorted(manifest.items())),
    }
    manifest_path = os.path.join(shared_dir, "dedup_manifest.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest_out, f, indent=2, ensure_ascii=False)
    print(f"OK: dedup_manifest.json → {len(manifest)} unique policies")

    # Step 7: Write conversion report + machine-readable deploy summary
    report, summary = generate_report(all_irs, manifest, all_shadow_warnings, skipped_domains)
    report_path = os.path.join(output_dir, "conversion_report.md")
    with open(report_path, "w") as f:
        f.write(report)
    print(f"OK: conversion_report.md written")
    # cdn-generate-js (Stage 8) augments this with post-dedup CFF/KVS counts;
    # cdn-validate-js (last step) reads it for the final summary ---RESULT---.
    summary_path = os.path.join(output_dir, "cdn_summary.json")
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    print(f"OK: cdn_summary.json written")

    # Summary
    shared_count = sum(1 for v in manifest.values() if v["count"] > 1)
    print(f"\n{'='*60}")
    print(f"Finalized {len(all_irs)} domains, {len(manifest)} unique policies ({shared_count} shared)")
    if all_shadow_warnings:
        print(f"⚠ {len(all_shadow_warnings)} shadowed rule warnings")
    if skipped_domains:
        print(f"⚠ {len(skipped_domains)} domains skipped")


if __name__ == "__main__":
    main()
