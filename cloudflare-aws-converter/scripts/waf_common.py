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
}


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
    return fields


def is_non_convertible(field):
    """Check if a field is non-convertible."""
    if field in NON_CONVERTIBLE_FIELDS:
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
    return cond, set()


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
