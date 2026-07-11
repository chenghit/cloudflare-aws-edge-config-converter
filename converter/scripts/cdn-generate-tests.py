#!/usr/bin/env python3
"""cdn-generate-tests.py — Generate post-deployment validation scripts.

Reads final IR for each domain and generates a test script that uses curl
to verify redirect rules, bulk redirects, inline error pages, cache behaviors,
and response headers. Untestable rules (ip.src, geo, raw_expression) are
listed as SKIP items with manual testing instructions.

Usage:
    python3 cdn-generate-tests.py <output_dir>

Exit codes: 0 = OK, 1 = error.
"""
import json, sys, os, glob as globmod

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cdn_expr_parser import iter_condition_children


# Max bulk redirect tests (first N + last 1)
MAX_BULK_REDIRECT_TESTS = 10


def generate_test_script(ir):
    """Generate test script content for a single domain."""
    meta = ir["metadata"]
    hostname = meta["hostname"]
    san = meta["sanitized_name"]
    behaviors = ir["cache_behaviors"]

    tests = []      # {"name", "curl_args", "expect_status", "expect_header", ...}
    skips = []      # {"name", "note"}
    manual = []     # {"name", "note"}

    for beh in behaviors:
        pp = beh["path_pattern"]

        # viewer_request_ops
        for op in beh.get("viewer_request_ops", []):
            otype = op["type"]
            desc = op.get("description", "")
            cond = op.get("condition")
            raw = op.get("raw_expression")
            params = op.get("params", {})

            # Skip if condition is untestable
            if raw:
                skips.append({"name": f"{otype}: {desc}",
                              "note": f"Complex expression — test manually: {raw[:80]}"})
                continue
            if cond and _condition_untestable(cond):
                skips.append({"name": f"{otype}: {desc}",
                              "note": _skip_reason(cond)})
                continue

            test_path = _derive_test_path(cond, pp)

            if otype == "redirect":
                target = params.get("target_url", "")
                status = params.get("status_code", 302)
                tests.append({
                    "name": f"redirect: {desc or test_path}",
                    "path": test_path,
                    "expect_status": status,
                    "expect_location": target,
                })

            elif otype == "serve_error_inline":
                status = params.get("status_code", 500)
                ct = params.get("content_type", "text/plain")
                tests.append({
                    "name": f"error page: {desc or test_path}",
                    "path": test_path,
                    "expect_status": status,
                    "expect_content_type": ct,
                })

            elif otype == "bulk_redirect":
                # Tested separately from kvs_data
                pass

            elif otype in ("set_request_header", "remove_request_header"):
                manual.append({
                    "name": f"request header: {desc}",
                    "note": "Verify origin receives correct headers (requires origin-side logging)",
                })

            elif otype == "rewrite":
                manual.append({
                    "name": f"rewrite: {desc or test_path}",
                    "note": f"Verify origin receives rewritten path (requires origin echo or logging)",
                })

            elif otype == "origin_override":
                manual.append({
                    "name": f"origin override: {desc}",
                    "note": "Verify response comes from expected origin backend",
                })

        # viewer_response_ops
        for op in beh.get("viewer_response_ops", []):
            otype = op["type"]
            desc = op.get("description", "")
            cond = op.get("condition")
            raw = op.get("raw_expression")
            params = op.get("params", {})

            if raw or (cond and _condition_untestable(cond)):
                skips.append({"name": f"response header: {desc}",
                              "note": _skip_reason(cond) if cond else f"Complex expression"})
                continue

            test_path = _derive_test_path(cond, pp)

            if otype == "set_response_header":
                tests.append({
                    "name": f"response header set: {params.get('name', '')}",
                    "path": test_path,
                    "expect_response_header": params.get("name", ""),
                })
            elif otype == "remove_response_header":
                tests.append({
                    "name": f"response header removed: {params.get('name', '')}",
                    "path": test_path,
                    "expect_no_response_header": params.get("name", ""),
                })

        # Cache behavior path pattern test (basic reachability)
        if pp != "*":
            cp = beh.get("cache_policy", {})
            ttl = cp.get("ttl", {})
            if cp.get("bypass"):
                tests.append({
                    "name": f"cache bypass: {pp}",
                    "path": _path_from_pattern(pp),
                    "expect_cache_control_no_store": True,
                })

    # Bulk redirect tests (sample)
    kvs_data = meta.get("kvs_data", [])
    redirect_entries = [e for e in kvs_data if e["key"].startswith("redirect:")]
    if redirect_entries:
        sample = redirect_entries[:MAX_BULK_REDIRECT_TESTS]
        if len(redirect_entries) > MAX_BULK_REDIRECT_TESTS + 1:
            sample.append(redirect_entries[-1])  # last entry as boundary test
        remaining = len(redirect_entries) - len(sample)

        for entry in sample:
            key = entry["key"]  # redirect:host/path
            value = entry["value"]  # 301|0|https://target
            parts = value.split("|", 2)
            if len(parts) == 3:
                status = int(parts[0])
                target = parts[2]
                path = "/" + key.split("/", 1)[1] if "/" in key else "/"
                tests.append({
                    "name": f"bulk redirect: {path}",
                    "path": path,
                    "expect_status": status,
                    "expect_location": target,
                })

        if remaining > 0:
            skips.append({
                "name": f"bulk redirects: {remaining} more entries",
                "note": f"Only first {MAX_BULK_REDIRECT_TESTS} + last 1 tested. "
                        f"Verify remaining {remaining} manually or extend this script.",
            })

    # Non-convertible items as info
    for nc in beh.get("non_convertible", []):
        manual.append({
            "name": f"non-convertible: {nc.get('description', '')}",
            "note": nc.get("reason", "")[:100],
        })

    return _render_script(hostname, san, tests, skips, manual)


def _condition_untestable(cond):
    """Check if a condition requires special environment to test."""
    if cond is None:
        return False
    if cond.get("always"):
        return False
    field = cond.get("field", "")
    # The condition tree stores SHORT field names (post CF_FIELD_MAP), not the
    # raw dotted Cloudflare names — matching on `ip.src.country` etc. never fired
    # for geo leaves (stored as `country`, `continent`, …), so geo-gated rules
    # were emitted as tests that can't pass without a request from that geo.
    if field in ("ip.src", "country", "continent", "is_eu", "asnum",
                 "city", "region", "region_code", "subdivision_1",
                 "latitude", "longitude", "postal_code", "metro_code", "timezone"):
        return True
    if cond.get("op") in ("in_kvs", "not_in_kvs"):
        return True
    if "logic" in cond:
        # Descend parts AND a NOT node's item (via the shared walker) — a negated
        # untestable condition (e.g. `not ip.src eq x`) is still untestable.
        return any(_condition_untestable(p) for p in iter_condition_children(cond))
    return False


def _skip_reason(cond):
    if cond is None:
        return "Complex expression"
    field = cond.get("field", "")
    # Short field names (post CF_FIELD_MAP), matching _condition_untestable.
    if field == "ip.src":
        return "Requires request from specific IP address"
    if field == "country":
        return f"Requires request from country {cond.get('value', '?')}"
    if field == "continent":
        return "Requires request from specific continent"
    if field == "is_eu":
        return "Requires request from EU country"
    if field == "asnum":
        return f"Requires request from ASN {cond.get('value', '?')}"
    if field in ("city", "region", "region_code", "subdivision_1",
                 "latitude", "longitude", "postal_code", "metro_code", "timezone"):
        return f"Requires request from a specific geo ({field})"
    if cond.get("op") in ("in_kvs", "not_in_kvs"):
        return "Requires request from IP in KVS list"
    if "logic" in cond:
        for p in iter_condition_children(cond):
            if _condition_untestable(p):
                return _skip_reason(p)
    return "Complex condition — test manually"


def _derive_test_path(cond, path_pattern):
    """Derive a test URL path from condition or path pattern."""
    if cond:
        field = cond.get("field", "")
        op = cond.get("op", "")
        value = cond.get("value", "")
        if field in ("uri.path", "uri") and isinstance(value, str):
            if op in ("eq", "wildcard"):
                return value.replace("*", "test")
            if op == "starts_with":
                return value + "test"
            if op == "ends_with":
                return "/test/" + value.lstrip("/")
    return _path_from_pattern(path_pattern)


def _path_from_pattern(pp):
    """Convert a CloudFront path pattern to a test path."""
    if pp == "*":
        return "/"
    return pp.replace("*", "test")


def _render_script(hostname, san, tests, skips, manual):
    """Render the test script as a Python file."""
    lines = [
        '#!/usr/bin/env python3',
        f'"""Post-deployment validation for {hostname}',
        '',
        'Usage:',
        f'    python3 test-cdn-rules.py <cloudfront-distribution-domain>',
        f'    python3 test-cdn-rules.py d111111abcdef8.cloudfront.net',
        '',
        'Tests redirect rules, error pages, response headers, and bulk redirects',
        'using curl. No third-party dependencies required.',
        '"""',
        'import subprocess, sys, json',
        '',
        f'HOSTNAME = "{hostname}"',
        '',
        '',
        'def curl(domain, path, method="GET"):',
        '    """Run curl and return (status_code, headers_dict, body)."""',
        '    url = f"https://{domain}{path}"',
        '    result = subprocess.run([',
        '        "curl", "-s", "-o", "/dev/null",',
        '        "-w", \'{"status":%{http_code},"redirect":"%{redirect_url}","content_type":"%{content_type}"}\',',
        '        "-H", f"Host: {HOSTNAME}",',
        '        "-X", method,',
        '        "--max-time", "10",',
        '        "--no-location",  # do not follow redirects',
        '        url,',
        '    ], capture_output=True, text=True)',
        '    try:',
        '        info = json.loads(result.stdout)',
        '    except json.JSONDecodeError:',
        '        info = {"status": 0, "redirect": "", "content_type": ""}',
        '    return info',
        '',
        '',
        'def curl_headers(domain, path):',
        '    """Run curl -I and return response headers as dict."""',
        '    url = f"https://{domain}{path}"',
        '    result = subprocess.run([',
        '        "curl", "-s", "-I",',
        '        "-H", f"Host: {HOSTNAME}",',
        '        "--max-time", "10",',
        '        url,',
        '    ], capture_output=True, text=True)',
        '    headers = {}',
        '    for line in result.stdout.splitlines():',
        '        if ": " in line:',
        '            k, v = line.split(": ", 1)',
        '            headers[k.lower()] = v.strip()',
        '    return headers',
        '',
        '',
        'def main():',
        '    if len(sys.argv) < 2:',
        '        print("Usage: python3 test-cdn-rules.py <cloudfront-domain>")',
        '        sys.exit(1)',
        '',
        '    domain = sys.argv[1]',
        '    passed = 0',
        '    failed = 0',
        '    skipped = 0',
        '',
    ]

    # Auto tests
    for t in tests:
        name = t["name"].replace('"', '\\"')
        path = t.get("path", "/")

        if "expect_location" in t:
            lines += [
                f'    # {name}',
                f'    info = curl(domain, "{path}")',
                f'    if info["status"] == {t["expect_status"]}:',
                f'        print(f"✓ PASS: {name} ({{info[\'status\']}})")',
                f'        passed += 1',
                f'    else:',
                f'        print(f"✗ FAIL: {name} (expected {t["expect_status"]}, got {{info[\'status\']}})")',
                f'        failed += 1',
                '',
            ]
        elif "expect_content_type" in t:
            lines += [
                f'    # {name}',
                f'    info = curl(domain, "{path}")',
                f'    if info["status"] == {t["expect_status"]}:',
                f'        print(f"✓ PASS: {name} ({{info[\'status\']}})")',
                f'        passed += 1',
                f'    else:',
                f'        print(f"✗ FAIL: {name} (expected {t["expect_status"]}, got {{info[\'status\']}})")',
                f'        failed += 1',
                '',
            ]
        elif "expect_response_header" in t:
            hdr = t["expect_response_header"].lower()
            lines += [
                f'    # {name}',
                f'    hdrs = curl_headers(domain, "{path}")',
                f'    if "{hdr}" in hdrs:',
                f'        print(f"✓ PASS: {name} ({{hdrs[\'{hdr}\']}})")',
                f'        passed += 1',
                f'    else:',
                f'        print(f"✗ FAIL: {name} (header \'{hdr}\' not found)")',
                f'        failed += 1',
                '',
            ]
        elif "expect_no_response_header" in t:
            hdr = t["expect_no_response_header"].lower()
            lines += [
                f'    # {name}',
                f'    hdrs = curl_headers(domain, "{path}")',
                f'    if "{hdr}" not in hdrs:',
                f'        print(f"✓ PASS: {name} (header removed)")',
                f'        passed += 1',
                f'    else:',
                f'        print(f"✗ FAIL: {name} (header \'{hdr}\' still present)")',
                f'        failed += 1',
                '',
            ]

    # Skips
    for s in skips:
        name = s["name"].replace('"', '\\"')
        note = s["note"].replace('"', '\\"')
        lines += [
            f'    print(f"⏭ SKIP: {name} — {note}")',
            f'    skipped += 1',
            '',
        ]

    # Manual items
    for m in manual:
        name = m["name"].replace('"', '\\"')
        note = m["note"].replace('"', '\\"')
        lines += [
            f'    print(f"⏭ SKIP: {name} — {note}")',
            f'    skipped += 1',
            '',
        ]

    lines += [
        '    print()',
        '    print(f"Results: {passed} passed, {failed} failed, {skipped} skipped")',
        '    sys.exit(1 if failed > 0 else 0)',
        '',
        '',
        'if __name__ == "__main__":',
        '    main()',
        '',
    ]

    return "\n".join(lines)


def main():
    if len(sys.argv) < 2:
        print("Usage: cdn-generate-tests.py <output_dir>", file=sys.stderr)
        sys.exit(1)

    output_dir = os.path.expanduser(sys.argv[1])
    final_dir = os.path.join(output_dir, "ir", "final")
    tf_dir = os.path.join(output_dir, "terraform", "domains")

    json_files = sorted(globmod.glob(os.path.join(final_dir, "*.json")))
    if not json_files:
        print(f"ERROR: no final IR files in {final_dir}", file=sys.stderr)
        sys.exit(1)

    for jf in json_files:
        with open(jf) as f:
            ir = json.load(f)
        san = ir["metadata"]["sanitized_name"]
        hostname = ir["metadata"]["hostname"]

        script = generate_test_script(ir)
        out_path = os.path.join(tf_dir, san, "test-cdn-rules.py")
        with open(out_path, "w") as f:
            f.write(script)

        print(f"OK: {hostname} → test-cdn-rules.py")

    print(f"\n{'='*60}")
    print(f"Generated test scripts for {len(json_files)} domains")


if __name__ == "__main__":
    main()
