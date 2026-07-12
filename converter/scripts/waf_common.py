"""Shared constants and utilities for WAF analysis scripts."""

# ── Non-convertible fields ───────────────────────────────────────────────────

NON_CONVERTIBLE_FIELDS = {
    # Bot detection
    "cf.verified_bot_category", "cf.bot_management.score",
    "cf.bot_management.ja3_hash", "cf.bot_management.js_detection.passed",
    "cf.bot_management.detection_ids", "cf.bot_management.verified_bot",
    # Attack scores
    "cf.waf.score", "cf.waf.score.sqli", "cf.waf.score.xss", "cf.waf.score.rce",
    # Fraud prevention
    "cf.waf.credential_check.password_leaked",
    "cf.waf.credential_check.username_leaked",
    "cf.waf.credential_check.similar_password_leaked",
    "cf.waf.credential_check.user_and_password_leaked",
    "cf.waf.credential_check.authentication_detected",
    "cf.waf.credential_check.disposable_email",
    # Connection / protocol
    "ssl", "http.request.version",
    # Geography (no AWS equivalent)
    "ip.src.continent",
    # Client cert
    "cf.tls_client_auth.cert_verified",
}

# AWS equivalents for non_convertible_notes
NON_CONVERTIBLE_AWS_EQUIV = {
    "cf.verified_bot_category": "AWS WAF Bot Control managed rule group",
    "cf.bot_management.score": "AWS WAF Bot Control managed rule group",
    "cf.waf.score": "AWS WAF Common Rule Set (already included)",
    "cf.waf.score.sqli": "AWS WAF SQLi Rule Set (already included)",
    "cf.waf.score.xss": "AWS WAF Common Rule Set (already included)",
    "cf.waf.credential_check.password_leaked": "AWS WAF Fraud Control ATP",
    "cf.waf.credential_check.username_leaked": "AWS WAF Fraud Control ATP",
    "ssl": "CloudFront viewer protocol policy",
    "http.request.version": "CloudFront Function",
    "ip.src.continent": "CloudFront Function with country-to-continent mapping",
    # Cloudflare MANAGED IP Lists (referenced as a VALUE like `ip.src in $cf.xxx`,
    # not a field). The full set per Cloudflare's Managed Lists doc — all 5 are IP
    # lists; there are no managed hostname/ASN lists. AWS has no importable
    # equivalent, so the closest AWS managed rule group is noted per list. Any
    # `$cf.*` value is still caught by is_managed_list_value() regardless of this
    # table, so an unlisted future name is treated as non-convertible too (it just
    # gets the generic "No direct equivalent" note).
    "$cf.open_proxies": "AWS WAF Amazon IP reputation list / Anonymous IP list managed rule group",
    "$cf.anonymizer": "AWS WAF Anonymous IP list managed rule group",
    "$cf.vpn": "AWS WAF Anonymous IP list managed rule group",
    "$cf.malware": "AWS WAF Amazon IP reputation list managed rule group",
    "$cf.botnetcc": "AWS WAF Amazon IP reputation list managed rule group",
}


def is_managed_list_value(value):
    """A Cloudflare MANAGED list, referenced as a VALUE (e.g. `ip.src in
    $cf.open_proxies`). These are Cloudflare-curated lists with no importable
    AWS equivalent — a rule using one is non-convertible (the closest AWS
    substitute is a managed rule group, surfaced via NON_CONVERTIBLE_AWS_EQUIV).
    Custom lists (`$block_list_1`) are convertible and are NOT matched here."""
    return isinstance(value, str) and value.startswith("$cf.")


def _extract_fields(cond):
    """Recursively extract all field names from a conditions tree."""
    fields = set()
    if "op" in cond:
        if cond["op"] in ("and", "or"):
            for item in cond["items"]:
                fields |= _extract_fields(item)
        elif cond["op"] == "not":
            fields |= _extract_fields(cond["item"])
    else:
        f = cond.get("field", "")
        if f:
            fields.add(f)
        # A managed-list VALUE (e.g. `ip.src in $cf.open_proxies`) makes the leaf
        # non-convertible even though its FIELD (ip.src) is fine. Surface the
        # list token as a pseudo-field so the prune/report machinery treats it
        # like any other non-convertible field (keyed in NON_CONVERTIBLE_AWS_EQUIV).
        if is_managed_list_value(cond.get("value")):
            fields.add(cond["value"])
    return fields


def is_non_convertible(field):
    """Check if a field (or managed-list pseudo-field like `$cf.open_proxies`)
    is non-convertible."""
    if field in NON_CONVERTIBLE_FIELDS:
        return True
    if is_managed_list_value(field):  # `$cf.*` managed list used as a value
        return True
    if field.startswith("cf.") and field not in NON_CONVERTIBLE_FIELDS:
        return True
    return False


def _prune_non_convertible(cond):
    """Prune non-convertible branches. Returns (pruned_tree_or_None, removed_fields)."""
    removed = set()

    if "op" in cond:
        op = cond["op"]
        if op == "or":
            kept = []
            for item in cond["items"]:
                pruned, rm = _prune_non_convertible(item)
                removed |= rm
                if pruned is not None:
                    kept.append(pruned)
            if not kept:
                return None, removed
            return (kept[0] if len(kept) == 1 else {"op": "or", "items": kept}), removed

        if op == "and":
            all_items_ok = True
            for item in cond["items"]:
                fields = _extract_fields(item)
                if any(is_non_convertible(f) for f in fields):
                    all_items_ok = False
                    removed |= {f for f in fields if is_non_convertible(f)}
            if not all_items_ok:
                kept = []
                for item in cond["items"]:
                    fields = _extract_fields(item)
                    if not any(is_non_convertible(f) for f in fields):
                        kept.append(item)
                if not kept:
                    return None, removed
                return (kept[0] if len(kept) == 1 else {"op": "and", "items": kept}), removed
            return cond, removed

        if op == "not":
            pruned, rm = _prune_non_convertible(cond["item"])
            removed |= rm
            if pruned is None:
                return None, removed
            return {"op": "not", "item": pruned}, removed

    field = cond.get("field", "")
    if is_non_convertible(field):
        return None, {field}
    # Leaf whose VALUE is a managed list (`ip.src in $cf.open_proxies`) — prune it
    # and report the list token (not the field, which is convertible on its own).
    if is_managed_list_value(cond.get("value")):
        return None, {cond["value"]}
    return cond, set()


# ── Host scope extraction ────────────────────────────────────────────────────

def _parse_host_in_value(value):
    """Parse host in {"d1" "d2"} value string into list of domains."""
    import re as _re
    return _re.findall(r'"([^"]+)"', value)


def _extract_branch_host(cond):
    """Extract host info from a single AND/leaf branch.
    Returns (host_value, host_op, non_host_condition) or (None, None, cond) if no host."""
    if "field" in cond and cond.get("field") == "http.host":
        return cond["value"], cond["operator"], None
    if cond.get("op") != "and":
        return None, None, cond
    host_val, host_op = None, None
    others = []
    for item in cond["items"]:
        if "field" in item and item.get("field") == "http.host":
            host_val = item["value"]
            host_op = item["operator"]
        else:
            others.append(item)
    if host_val is None:
        return None, None, cond
    if len(others) == 0:
        return host_val, host_op, None
    if len(others) == 1:
        return host_val, host_op, others[0]
    return host_val, host_op, {"op": "and", "items": others}


def extract_host_scope(cond):
    """Extract host scope from a parsed condition tree.

    Returns dict:
        {"type": "global"} — no host condition
        {"type": "single_host", "hosts": ["domain"]}
        {"type": "multi_host", "hosts": ["d1", "d2"]}
        {"type": "contains", "contains": ["keyword"]}
        {"type": "branched", "branches": [{"host": ..., "host_op": ..., "condition": ...}, ...]}
    """
    if cond is None:
        return {"type": "global"}

    # Leaf node
    if "field" in cond:
        if cond["field"] == "http.host":
            op = cond["operator"]
            if op == "eq":
                return {"type": "single_host", "hosts": [cond["value"]]}
            if op == "in":
                hosts = _parse_host_in_value(cond["value"])
                return {"type": "multi_host", "hosts": hosts}
            if op == "contains":
                return {"type": "contains", "contains": [cond["value"]]}
        return {"type": "global"}

    op = cond.get("op")

    # NOT — check inner
    if op == "not":
        inner_scope = extract_host_scope(cond.get("item"))
        # not(host ...) is unusual but treat as global to be safe
        if inner_scope["type"] != "global":
            return {"type": "global"}
        return {"type": "global"}

    # AND — look for host field among items
    if op == "and":
        host_val, host_op, _ = _extract_branch_host(cond)
        if host_val is None:
            return {"type": "global"}
        if host_op == "eq":
            return {"type": "single_host", "hosts": [host_val]}
        if host_op == "in":
            return {"type": "multi_host", "hosts": _parse_host_in_value(host_val)}
        if host_op == "contains":
            return {"type": "contains", "contains": [host_val]}
        return {"type": "global"}

    # OR — each branch may have different host
    if op == "or":
        branches = []
        all_global = True
        for item in cond["items"]:
            host_val, host_op, remainder = _extract_branch_host(item)
            if host_val is not None:
                all_global = False
                if host_op == "in":
                    # host in {d1 d2} inside an OR branch — expand to per-host
                    for h in _parse_host_in_value(host_val):
                        branches.append({"host": h, "host_op": "eq", "condition": remainder})
                else:
                    branches.append({"host": host_val, "host_op": host_op, "condition": remainder})
            else:
                branches.append({"host": None, "host_op": None, "condition": item})
        if all_global:
            return {"type": "global"}
        # If all branches have the same single host, simplify
        hosts = set(b["host"] for b in branches if b["host"] is not None)
        if len(hosts) == 1 and all(b["host"] is not None for b in branches):
            return {"type": "single_host", "hosts": [hosts.pop()]}
        return {"type": "branched", "branches": branches}

    return {"type": "global"}


def classify_convertibility(cond):
    """Determine convertibility of a conditions tree.
    Returns (convertibility, pruned_tree_or_None, non_convertible_fields)."""
    all_fields = _extract_fields(cond)
    non_conv = {f for f in all_fields if is_non_convertible(f)}

    if not non_conv:
        return "yes", cond, []
    if non_conv == all_fields:
        return "no", None, sorted(non_conv)

    pruned, _ = _prune_non_convertible(cond)
    return "partial", pruned, sorted(non_conv)
