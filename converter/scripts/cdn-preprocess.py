#!/usr/bin/env python3
"""cdn-preprocess.py — Stage 3: Convert Cloudflare CDN rules to IR JSON.

Usage:
    python3 cdn-preprocess.py <config_path> <output_dir> [--domain DOMAIN]

Exit codes: 0 = all OK, 1 = partial failure, 2 = total failure.
"""
import json, sys, os, re, glob as globmod, copy

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cdn_expr_parser import (
    parse_expression, extract_orp_headers, extract_orp_headers_from_raw,
    extract_kvs_triggers, extract_host_filter, extract_path_pattern_single,
    iter_condition_children, host_filter_applies, host_leaf_is_routing,
    CACHE_BYPASS_HEADER,
    lower_literal_value, lower_dynamic_value, validate_viewer_op,
    LOWERED_EMPTY_DELETE_HEADER, VIEWER_RESPONSE_GAP_REASON,
    VIEWER_OP_CONTRACTS, VIEWER_OP_CONTRACT_NOT_GENERIC_WIRED,
)
from cdn_rhp_capabilities import (
    canonical_header as _canonical_rhp_header, security_capability,
)
from cdn_common import (emit_result, derive_cert_domain,
                        pattern_contains, patterns_overlap, _bad_source_key)
from cdn_rule_processors import (
    process_redirect_rule, process_rewrite_rule, process_config_rule,
    process_origin_rule, process_cache_rule, process_request_header_transform,
    process_response_header_transform, process_custom_error_rule,
    process_cloud_connector,
    process_compression_rule,
    IP_SRC_NON_CONVERTIBLE_PHASES,
)


class LedgerError(Exception):
    """A ledger-integrity breach — a CONVERTER BUG (not a per-config issue). The
    caller turns this into a FATAL exit; it must never be swallowed."""


# ── file discovery ───────────────────────────────────────────────────────────

RULE_FILES = {
    "redirect": "Redirect-Rules.txt",
    "rewrite": "URL-Rewrite-Rules.txt",
    "config": "Configuration-Rules.txt",
    "origin": "Origin-Rules.txt",
    "cache": "Cache-Rules.txt",
    "request_header": "Request-Header-Transform.txt",
    "response_header": "Response-Header-Transform.txt",
    "custom_error": "Custom-Error-Rules.txt",
    "compression": "Compression-Rules.txt",
    "managed_transforms": "Managed-Transforms.txt",
}

CLOUD_CONNECTOR_FILE = "Cloud-Connector-Rules.txt"

PHASE_MAP = {
    "redirect": "http_request_dynamic_redirect",
    "rewrite": "http_request_transform",
    "config": "http_config_settings",
    "origin": "http_request_origin",
    "cache": "http_request_cache_settings",
    "request_header": "http_request_late_transform",
    "response_header": "http_response_headers_transform",
    "custom_error": "http_custom_errors",
    "compression": "http_request_compress",
}


def find_zone_dir(config_path):
    """Find the zone backup directory (contains DNS.txt).

    followlinks=True so a symlinked per-zone view (see SKILL.md multi-zone
    flow) is walked like the glob-based scripts, which follow symlinks.
    """
    for root, dirs, files in os.walk(config_path, followlinks=True):
        if "DNS.txt" in files and "account" not in root:
            return root
    return None


def load_json_file(path):
    """Load a Cloudflare backup JSON file, handling both ruleset and array formats."""
    if not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            data = json.load(f)
    except (json.JSONDecodeError, ValueError):
        print(f"  WARN: {path} is empty or invalid JSON, skipping", file=sys.stderr)
        return None
    if not data.get("success", True):
        return None
    result = data.get("result")
    if isinstance(result, dict) and "rules" in result:
        return result["rules"]
    if isinstance(result, list):
        return result
    return result


def latest_account_dir(config_path):
    """Newest account/<timestamp>/ dir (user may have backed up more than once)."""
    dirs = sorted(d for d in globmod.glob(os.path.join(config_path, "account", "*"))
                  if os.path.isdir(d))
    if not dirs:
        return None
    if len(dirs) > 1:
        print(f"WARNING: {len(dirs)} account backups found; using newest "
              f"({os.path.basename(dirs[-1])})", file=sys.stderr)
    return dirs[-1]


def load_ip_lists(config_path):
    """Load account-level IP lists → {list_name: [ip1, ip2, ...]}."""
    ip_lists = {}
    account_dir = latest_account_dir(config_path)
    if not account_dir:
        return ip_lists

    for f in globmod.glob(os.path.join(account_dir, "List-Items-ip-*.txt")):
        basename = os.path.basename(f)
        # Extract list name: List-Items-ip-<name>.txt
        m = re.match(r"List-Items-ip-(.+)\.txt$", basename)
        if not m:
            continue
        list_name = m.group(1)
        items = load_json_file(f)
        if items and isinstance(items, list):
            ip_lists[list_name] = [item.get("ip", "") for item in items if item.get("ip")]
    return ip_lists


def load_bulk_redirect_items(config_path):
    """Load account-level bulk redirect list items → {list_name: [items]}."""
    redirects = {}
    account_dir = latest_account_dir(config_path)
    if not account_dir:
        return redirects

    for f in globmod.glob(os.path.join(account_dir, "List-Items-redirect-*.txt")):
        basename = os.path.basename(f)
        m = re.match(r"List-Items-redirect-(.+)\.txt$", basename)
        if not m:
            continue
        list_name = m.group(1)
        items = load_json_file(f)
        if items and isinstance(items, list):
            redirects[list_name] = items
    return redirects


def load_managed_transforms(zone_dir):
    """Load Managed Transforms settings."""
    path = os.path.join(zone_dir, "Managed-Transforms.txt")
    if not os.path.exists(path):
        return {}
    try:
        with open(path) as f:
            data = json.load(f)
    except (json.JSONDecodeError, ValueError):
        print(f"  WARN: {path} is empty or invalid JSON, skipping", file=sys.stderr)
        return {}
    return data.get("result", {})


# ── ignored-feature scan (Step-6 Block 3) ───────────────────────────────────
# Files the CDN pipeline CONSUMES (reads + converts) — NEVER ignored. RULE_FILES + the cloud
# connector + the DNS marker (Managed-Transforms is already in RULE_FILES). Account-dir inputs
# (IP-list / bulk-redirect List-Items) are consumed too but live outside the zone dir.
_CDN_CONSUMED_ZONE_FILES = set(RULE_FILES.values()) | {CLOUD_CONNECTOR_FILE, "DNS.txt"}
_INACTIVE_SETTING_VALUES = ("off", "false", "0", "", "disabled", "none")

# CURATED policy (docs/conversion-policy.md "Explicitly not converted"): the SEMANTIC category of a
# present-but-unread zone file. Encoded here, NOT parsed from the markdown, so the report says WHICH
# real features aren't covered — not just which files exist. Separation of concerns: the active-state
# DETECTOR decides active/inactive/unknown; THIS mapping decides the output BUCKET. An UNMAPPED file
# that is ACTIVE falls to "unknown_active" (a review item) — FAIL CLOSED, so a NEW Cloudflare feature
# is surfaced for review, never silently dropped.
#   "waf"     → read by the companion WAF pipeline (waf-analyze-*.py); NOT a CDN gap.
#   "native"  → CloudFront provides an equivalent natively / no action needed; NOT a gap.
#   "abandon" → no faithful CloudFront equivalent; when ACTIVE this is the real IGNORED_FEATURES signal.
IGNORED_FEATURE_POLICY = {
    # companion WAF pipeline inputs (NOT CDN-ignored — the WAF report speaks for them)
    "WAF-Custom-Rules.txt": "waf", "WAF-Managed-Rules.txt": "waf",
    "Rate-limits.txt": "waf", "IP-Access-Rules.txt": "waf",
    # CloudFront-native / no action needed (CloudFront supports the protocol/behavior itself)
    "HTTP2.txt": "native", "HTTP3.txt": "native", "IPv6.txt": "native",
    "WebSockets.txt": "native", "TLS-1-3.txt": "native", "Zero-RTT.txt": "native",
    "URL-Normalization.txt": "native",
    # no faithful CloudFront equivalent → abandon (reported as IGNORED_FEATURES only when ACTIVE)
    "Always-Online.txt": "abandon", "Argo-Smart-Routing.txt": "abandon",
    "Browser-Check.txt": "abandon", "Cache-Reserve.txt": "abandon",
    "Challenge-TTL.txt": "abandon", "Ciphers.txt": "abandon",
    "Custom-Pages.txt": "abandon", "DNSSEC.txt": "abandon",
    "Development-Mode.txt": "abandon", "Early-Hints.txt": "abandon",
    "Hotlink-Protection.txt": "abandon", "Image-Resizing.txt": "abandon",
    "Load-Balancers.txt": "abandon", "Min-TLS-Version.txt": "abandon",
    "Opportunistic-Encryption.txt": "abandon", "Page_Shield.txt": "abandon",
    "SaaS-Fallback-Origin.txt": "abandon", "Security-level.txt": "abandon",
    "Server-Side-Excludes.txt": "abandon", "Smart-Tiered-Cache.txt": "abandon",
    "Snippet-Rules.txt": "abandon", "Snippets.txt": "abandon",
    "Tiered-Cache.txt": "abandon", "TLS-Client-Auth.txt": "abandon", "WebP.txt": "abandon",
}


def _feature_active_state(path):
    """Classify a Cloudflare feature-export file's STATE (Block 3) — active / inactive / unknown.
    Decides ONLY whether the feature is configured, NOT its semantics (the policy mapping does that).
      - inactive: an empty result ([]/{}/result.rules==[]), enabled:false, a value of off/false/0/
        empty, OR a `success:false` export (plan-unavailable / not-found / no-route → the feature is
        not provisioned on this account).
      - active:   a non-empty list/rules/snippets, enabled:true, or a real setting value.
      - unknown:  the file won't parse / has an unexpected shape. NEVER a CDN FATAL (a malformed
        companion file must not fail the conversion) and never silently dropped — surfaced for review."""
    try:
        with open(path) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError, ValueError):
        return "unknown"
    if not isinstance(data, dict):
        return "unknown"
    if not data.get("success", True):
        return "inactive"   # failed export = the feature is not provisioned/available on this account
    result = data.get("result")
    if result is None or result == [] or result == {}:
        return "inactive"
    if isinstance(result, list):
        return "active"
    if isinstance(result, dict):
        if "rules" in result:
            return "active" if result.get("rules") else "inactive"
        if "enabled" in result:
            return "active" if result.get("enabled") else "inactive"
        val = result.get("value")
        if isinstance(val, str) and val.strip().lower() in _INACTIVE_SETTING_VALUES:
            return "inactive"
        if val in (False, 0, None):
            return "inactive"
        return "active"
    return "unknown"


# Files that are DIFFERENT exports of the SAME user-facing feature — collapsed to one feature name so
# the report counts a single migration item (e.g. Snippets.txt + Snippet-Rules.txt = "Snippets", one
# feature) while both files stay as evidence in the summary breakdown. Avoids double-counting.
_FEATURE_NAME_OVERRIDE = {"Snippets.txt": "Snippets", "Snippet-Rules.txt": "Snippets"}


def _feature_name_from_file(filename):
    """Readable feature name from a backup filename: 'Always-Online.txt' -> 'Always Online'. Files
    that are facets of one feature collapse via _FEATURE_NAME_OVERRIDE (Snippet-Rules -> Snippets)."""
    if filename in _FEATURE_NAME_OVERRIDE:
        return _FEATURE_NAME_OVERRIDE[filename]
    stem = filename[:-4] if filename.endswith(".txt") else filename
    return stem.replace("-", " ").replace("_", " ").strip()


def scan_ignored_features(zone_dir):
    """Scan a zone backup dir for Cloudflare feature files the CDN pipeline does NOT read and bucket
    each (Block 3 — purely observational, reads nothing into the IR, NEVER raises). Buckets:
      - active_abandoned:       ACTIVE + policy 'abandon' — the real IGNORED_FEATURES signal (deduped
                                feature NAMES, so Snippets counts ONCE even across two files).
      - active_abandoned_files: the evidence FILES behind active_abandoned (Snippets = 2 files) — kept
                                so the summary can show files vs features without double-counting.
      - native_or_no_action:    ACTIVE + policy 'native' — CloudFront handles it; not a gap.
      - handled_or_reported_by_waf_pipeline: ACTIVE + policy 'waf' — the companion WAF pipeline reads /
                                REPLACES it (AWS managed rule groups, not a 1:1 port); NOT a CDN gap.
      - inactive:               present but off/empty/not-provisioned — not reported.
      - unknown_active:         active-but-UNMAPPED (a new feature) OR unparseable — a review item,
                                kept SEPARATE from abandoned (do not conflate a guess with a decision).
      - raw_scanned:            count of present-but-unread files considered (incl. inactive)."""
    abandoned, abandoned_files = set(), []
    native, waf, inactive, unknown = set(), set(), set(), set()
    raw = 0
    for path in sorted(globmod.glob(os.path.join(zone_dir, "*.txt"))):
        fn = os.path.basename(path)
        if fn in _CDN_CONSUMED_ZONE_FILES:
            continue
        raw += 1
        name = _feature_name_from_file(fn)
        state = _feature_active_state(path)
        if state == "inactive":
            inactive.add(name)
            continue
        if state == "unknown":
            unknown.add(name)   # unparseable → review, never silently dropped
            continue
        policy = IGNORED_FEATURE_POLICY.get(fn)    # state == "active"
        if policy == "waf":
            waf.add(name)
        elif policy == "native":
            native.add(name)
        elif policy == "abandon":
            abandoned.add(name)
            abandoned_files.append(fn)
        else:
            unknown.add(name)    # active but UNMAPPED → review (catch a new Cloudflare feature)
    return {
        "active_abandoned": sorted(abandoned),               # deduped feature names → IGNORED_FEATURES
        "active_abandoned_files": sorted(abandoned_files),   # evidence files (Snippets = 2 files)
        "native_or_no_action": sorted(native),
        "handled_or_reported_by_waf_pipeline": sorted(waf),
        "inactive": sorted(inactive),
        "unknown_active": sorted(unknown),
        "raw_scanned": raw,
    }


# An S3 host (REST endpoint `bucket.s3[.region].amazonaws.com` or website
# endpoint `bucket.s3-website[.-]region.amazonaws.com`). Mirrors the S3 patterns
# in cdn-parse-dns.classify_origin; used to spot a redundant S3 origin-override.
_RE_S3_HOST = re.compile(r"\.s3[.-]", re.I)


def _is_s3_host(host):
    return bool(host) and ".amazonaws.com" in host.lower() and bool(_RE_S3_HOST.search(host))


# ── domain matching ──────────────────────────────────────────────────────────

def hostname_matches(hostname, pattern):
    """Check if hostname matches a pattern (supports wildcard *)."""
    if pattern == hostname:
        return True
    if pattern.startswith("*."):
        suffix = pattern[1:]  # .example.com
        return hostname.endswith(suffix) or hostname == pattern[2:]
    return False


def rule_applies_to_domain(host_filter, hostname, apex_domain):
    """Check if a rule with the given host filter applies to this domain.

    The host filter is None (global) or a host-condition tree; it is evaluated
    against this CONCRETE distribution hostname via hostname_matches (which
    handles zone wildcards). See extract_host_filter / host_filter_applies —
    evaluating against real hostnames avoids the unsound wildcard set algebra
    the previous include/exclude representation used.
    """
    return host_filter_applies(host_filter, hostname, hostname_matches)


def _host_leaf_consumed_for_routing(cond):
    """True if this leaf is a host test the router consumed for distribution
    scoping (host eq/in/ne/not_in/wildcard) and is therefore redundant on the
    distribution the rule was routed to — safe to strip. A `host` leaf the
    router does NOT consume is a LIVE predicate that must be KEPT and rendered,
    not dropped: `len(http.host) gt 5` (size_check), `http.host contains "x"`.
    full_uri leaves carry a host_pattern but their PATH part still matters, so
    they are never stripped (host_leaf_is_routing guards on field == "host").
    Single source of truth: cdn_expr_parser.host_leaf_is_routing."""
    return host_leaf_is_routing(cond)


def _strip_host_condition(cond):
    """Remove the now-redundant host test once the rule is routed to a single
    host's distribution.

    The CDN pipeline builds one CloudFront distribution per proxied host, and
    rule_applies_to_domain() has ALREADY decided this rule belongs to this
    distribution (honoring include/exclude host filters). A host leaf the router
    consumed is redundant and always-true for this distribution — a positive
    `host eq x` (we ARE x) and, crucially, a negated `host ne x` / `not_eq x`
    too (an exclude-x rule only reaches a non-x distribution, where `host != x`
    holds). Strip ONLY those (see _host_leaf_consumed_for_routing); a live host
    predicate like `len(host) gt 5` is kept. If stripping empties the condition,
    return {"always": True} (NOT None — the op must keep a condition for
    validate-chunk Check11). Non-host leaves and OR/NOT (whose membership the
    classifier already resolved) are left as-is.
    """
    if cond is None:
        return None
    if "logic" not in cond:
        if _host_leaf_consumed_for_routing(cond):
            return {"always": True}  # router consumed it -> redundant here
        # Non-host leaf, live host predicate, or full_uri (path still matters).
        return cond
    if cond["logic"] == "and":
        kept = [p for p in cond.get("parts", [])
                if not _host_leaf_consumed_for_routing(p)]
        if not kept:
            return {"always": True}  # was only routing-host conjuncts -> unconditional
        if len(kept) == 1:
            return kept[0]
        return {**cond, "parts": kept}
    # OR / NOT: leave as-is (the classifier already resolved membership).
    return cond


def _strip_host_in_result(result):
    """Strip the redundant host test from a processor result's `condition`
    in place (the processor re-parsed the expression into its own condition)."""
    if isinstance(result, dict) and result.get("condition") is not None:
        result["condition"] = _strip_host_condition(result["condition"])


# ── IR assembly ──────────────────────────────────────────────────────────────

def make_empty_ir(domain_config):
    """Create empty IR structure for a domain."""
    hostname = domain_config["hostname"]
    sanitized = hostname.replace(".", "_").replace("-", "_")
    return {
        "metadata": {
            "hostname": hostname,
            "sanitized_name": sanitized,
            "apex_domain": domain_config.get("apex_domain", ""),
            # The same-level wildcard SAN this host needs a cert to cover (see
            # cdn_common.derive_cert_domain). Drives the report's per-coverage
            # cert list and the resolve-certs.py matcher. Fall back to deriving it
            # if an older domain_scope.json predates the field.
            "cert_domain": domain_config.get("cert_domain")
                or derive_cert_domain(hostname, domain_config.get("apex_domain", "")),
            "origin_type": domain_config.get("origin_type", "server"),
            "kvs_requirements": {
                "needs_redirects": False,
                "needs_continent": False,
                "needs_eu": False,
                "needs_ip_lists": False,
            },
            "kvs_data": [],
            "custom_error_responses": [],
            # Non-fatal conversion warnings surfaced in the report (e.g. a native
            # path behavior from a case-INSENSITIVE Cloudflare wildcard — CloudFront
            # PathPattern is case-sensitive, so case variants won't match).
            "conversion_warnings": [],
            "lambda_edge": {
                "origin_request": None,
                "origin_response": None,
            },
        },
        "cache_behaviors": [],
        # Ordered log of NATIVE effects (TTL/cache-key/compression/caching-disabled/
        # response-headers/origin) in SOURCE-RULE order. Native settings are NOT
        # written onto behaviors during the rule loop; they are recorded here and
        # replayed per behavior afterward (see _replay_native_effects). This is what
        # makes Cloudflare's rule-stacking correct on CloudFront: a behavior's
        # effective value = the LAST source-order rule whose scope CONTAINS that
        # behavior's path pattern (default `*` inherits nothing — every behavior is
        # computed independently). Dropped from the IR before it is written out.
        "_native_effects": [],
        # Rule-accounting sets for the every-rule-has-an-output invariant (both
        # internal, stripped before write): IDs that entered processing (passed the
        # host filter) vs IDs that produced any output.
        "_entered_rule_ids": set(),
        "_accounted_rule_ids": set(),
        # Monotonic source-order counter. Every viewer op and native effect is
        # stamped with `seq` in the order rules are PROCESSED (Cloudflare phase
        # order × in-phase file order). The JS generator emits ops sorted by seq —
        # NOT by cache-behavior order — so first-match redirects and last-wins
        # header transforms keep their true Cloudflare precedence regardless of how
        # behaviors are later sorted for CloudFront routing.
        "_seq": 0,
        # ── Outcome ledger (round-11 rebuild) ──────────────────────────────────
        # `_inventory`: every SOURCE KEY that MUST end up with exactly one outcome —
        # a (source_kind, source_id, json_pointer) TRIPLE per leaf of a config unit's
        # original parameters, captured at source-entry BEFORE any conversion decision,
        # covering ALL source kinds (rule / cloud_connector / bulk_redirect /
        # managed_transform). Duplicates are PRESERVED (not set-collapsed) so the finalize
        # gate can reject a repeated key. `_inventory` + `_claims` are KEPT in the written IR
        # (the finalize ledger gate reads them). L1 builds the inventory; sinks write outcomes
        # (claims) in L2/L3.
        "_inventory": [],
        # `_claims`: the DecisionClaims (the capability layer's verdict per source-key set) —
        # the ledger the system runs on (finalize gate + completeness read it). The
        # artifact/physical/reconciler layer (_logical_artifacts / _physical_artifacts /
        # _ledger) was removed in the round-2 bucket-B cleanup; only claims remain.
        "_claims": [],
    }


def _jp_escape(token):
    """RFC-6901 escape for one path token: ~ → ~0, / → ~1 (so a key like `x/y~z`
    doesn't produce an ambiguous pointer)."""
    return str(token).replace("~", "~0").replace("/", "~1")


def _json_pointer_leaves(obj, prefix=""):
    """VALUE-INDEPENDENT RFC-6901 leaf pointers for a config subtree, the ledger's
    per-setting source keys (stable regardless of value — so a key never drifts when
    only the value changes). A non-empty dict recurses (keys RFC-6901-escaped); a
    scalar or a LIST is an ATOMIC leaf (a list is one setting — if only part of it
    converts the WHOLE list must be one outcome, never split). A NESTED empty dict
    (prefix != "") is itself an atomic leaf. The ROOT being an empty dict (prefix ==
    "") yields NO leaf ([]) — a setting-less action; the caller substitutes /$action
    (see _inventory_keys_for)."""
    out = []
    if isinstance(obj, dict) and obj:
        for k, v in obj.items():
            out += _json_pointer_leaves(v, f"{prefix}/{_jp_escape(k)}")
    elif prefix == "" and isinstance(obj, dict):
        return []            # root empty dict → no leaf; caller uses /$action
    else:
        out.append(prefix)   # scalar, list (atomic), or NESTED empty dict → a leaf
    return sorted(set(out))


def _inventory_keys_for(source_kind, source_id, params):
    """Source keys (source_kind, source_id, json_pointer) a config UNIT contributes.

    `source_kind` distinguishes the config type (rule / cloud_connector /
    bulk_redirect / managed_transform) so the inventory covers EVERY source-owned
    artifact, not just phase rules — the reverse-ownership check needs all of them.
    One key per leaf of `params`. When `params` is an empty dict the action itself is
    the unit (`/$action` — e.g. a redirect with only a target elsewhere), NOT a
    fictional `/` leaf; a non-dict `params` is an input error the caller reports."""
    ptrs = _json_pointer_leaves(params) if isinstance(params, dict) else None
    if ptrs is None:
        return [(source_kind, source_id, "/$invalid")]
    if not ptrs:
        return [(source_kind, source_id, "/$action")]
    return [(source_kind, source_id, p) for p in ptrs]


def _register_unit_id(ir, source_kind, explicit_id, fallback):
    """Return a UNIQUE internal source-unit id and record it as seen. SHARED by EVERY
    source kind (phase rule, cloud connector, bulk redirect, managed transform) so the
    id contract is uniform, not per-kind.

    (source_kind, source_id) must reliably identify ONE config unit — the resolver groups
    inventory keys by that PAIR, so two units sharing BOTH kind and id would merge and a
    partial claim on one could bleed onto the other. Uniqueness is scoped PER
    (source_kind, source_id): different kinds may share a display id (→ different units),
    but two units of the SAME kind may not.
      - `explicit_id` a non-empty STRING: require (kind, id) unique — a duplicate SAME-KIND
        id → LedgerError (that domain FAILs, not a silent merge);
      - `explicit_id` None or "": synthesize the `fallback` (a stable per-kind string the
        caller supplies, e.g. 'cache#0', 'list#3', 'mt_req#1');
      - `explicit_id` a NON-STRING (int, etc.): a source-schema error → LedgerError at
        source-entry (uniform across ALL kinds — never a convertible path writing an
        illegal ['bulk_redirect', 123, ...] key while another path raises later)."""
    seen = ir.setdefault("_unit_ids", set())
    if explicit_id is not None and not isinstance(explicit_id, str):
        raise LedgerError(
            f"{source_kind} id {explicit_id!r} is a {type(explicit_id).__name__}, not a "
            f"string — a source id must be a string (or absent); fix the source config")
    unit_id = explicit_id if explicit_id else fallback
    key = (source_kind, unit_id)
    if key in seen:
        raise LedgerError(
            f"duplicate {source_kind} id {unit_id!r} within domain — a (kind, id) pair "
            f"must uniquely identify one config unit (two same-kind units sharing an id "
            f"would merge in the ledger); de-duplicate the source config")
    seen.add(key)
    return unit_id


def _assign_unit_id(ir, rule, source_kind, rule_type, index):
    """Unit id for a phase rule / cloud connector (thin wrapper over _register_unit_id).
    The synthetic fallback uses `rule_type` (redirect/cache/config/...) — NOT source_kind,
    which is just 'rule' for every phase rule — so an id-less config#0 stays distinct from
    an id-less redirect#0. The rule's original id stays the DISPLAY value (cf_source_rule);
    this never rewrites it."""
    return _register_unit_id(ir, source_kind, rule.get("id"), f"{rule_type}#{index}")


def _inventory_keys_for_rule(rule, source_id=None):
    """Inventory keys for a phase rule (source_kind 'rule', keyed on action_parameters).
    `source_id` is the internal unit id (from _assign_unit_id); defaults to the rule's
    own id for callers/tests that manage ids themselves."""
    sid = source_id if source_id is not None else rule.get("id", "")
    return _inventory_keys_for("rule", sid, rule.get("action_parameters", {}))


# ── Unit-provenance resolver (L2 channel wiring) ───────────────────────────────
# The ledger's source keys are the inventory's value-independent (kind, id, pointer)
# triples. A CONFIG UNIT is one (source_kind, source_id) pair; its inventory keys are
# the leaves recorded for it at source-entry. Sinks know a unit's (kind, id) and, for a
# split-capable action, WHICH json-pointer leaves a given outcome owns. This resolver is
# the ONLY place that maps (kind, id[, pointers]) → concrete source keys — always by
# reading the ALREADY-BUILT inventory (never re-deriving), so a claim's keys are exactly
# the inventory keys and the reconciler's `key in inventory` check can't be tripped by a
# scheme mismatch. Processors stay ledger-agnostic; they may expose an `owned_pointers`
# hint but never construct keys or call ledger APIs.


def _unit_inventory_keys(ir, source_kind, source_id):
    """The inventory source keys belonging to config unit (source_kind, source_id), as a
    list of (kind, id, pointer) tuples in inventory order. Empty if the unit contributed
    no inventory (a converter bug for a real unit — the caller decides how loud to be)."""
    return [tuple(k) for k in ir.get("_inventory", [])
            if len(k) == 3 and k[0] == source_kind and k[1] == source_id]


def _key_path_to_pointer(segments):
    """Build an RFC-6901 json-pointer from RAW dict-key segments, using the SAME escape
    as _json_pointer_leaves so a hint lines up with the inventory. `[]` (no segments)
    means the ACTION ROOT, which the inventory records as the literal `/$action` (see
    _inventory_keys_for) — NOT the empty string, which would `startswith("/")`-match
    EVERY leaf. Processors expose raw segments (scheme-agnostic); this is the ONE place
    that knows the pointer encoding."""
    if not segments:
        return "/$action"
    return "".join(f"/{_jp_escape(s)}" for s in segments)


def _result_owned_pointers(result):
    """Translate a processor result's `owned_key_segments` provenance hint into a list of
    json-pointers, or None for whole-unit ownership. Shared by every sink that turns a
    result into an NC claim (_place_result's NC branch AND _mark_result_non_convertible's
    placement-time reject) so a partial-result's subset provenance is preserved no matter
    which sink fires — a per-header result stays owning just its /headers/<name> subtree
    even when the reject happens after placement, not in the processor."""
    segs = result.get("owned_key_segments")
    if segs is None:
        return None
    return [_key_path_to_pointer(s) for s in segs]


def _resolve_owned_keys(ir, source_kind, source_id, owned_pointers=None):
    """Resolve the source keys an outcome owns within one config unit.

    owned_pointers is None → WHOLE-UNIT ownership: every inventory key of the unit. Use
                        ONLY for a proven atomic/all-or-nothing action (the whole unit
                        shares one fate).
    owned_pointers is a list → SUBSET ownership. Each entry is a json-pointer that either
                        EXACTLY names an inventory leaf of the unit OR is an ANCESTOR of
                        one or more leaves (a minimal subtree hint, e.g. `/headers/X-Foo`
                        owning `/headers/X-Foo/operation` + `/headers/X-Foo/value`). Every
                        entry MUST match at least one inventory key; a hint that matches
                        nothing is a converter bug (it drifted from the inventory scheme)
                        and raises LedgerError — NEVER a silent claim-all fallback.

    Returns a non-empty, de-duplicated list of (kind, id, pointer) tuples in inventory
    order. Raises LedgerError if the unit has no inventory, or a hint matches nothing."""
    unit_keys = _unit_inventory_keys(ir, source_kind, source_id)
    if not unit_keys:
        raise LedgerError(
            f"unit ({source_kind!r}, {source_id!r}) has no inventory keys — cannot "
            f"resolve provenance (the unit was not inventoried at source-entry)")
    if owned_pointers is None:
        return unit_keys
    # An empty subset list is a bug, NOT whole-unit (that's what None means) — a subset
    # claim must own at least one leaf. Reject rather than return [] (a claim with no
    # keys the API/reconciler would then reject with a less specific error).
    if not owned_pointers:
        raise LedgerError(
            f"empty owned_pointers for unit ({source_kind!r}, {source_id!r}) — a subset "
            f"claim must name at least one leaf; use owned_pointers=None for whole-unit")
    known = [k[2] for k in unit_keys]
    chosen = set()
    for hint in owned_pointers:
        # An empty-string hint would `startswith("/")`-match EVERY leaf — a silent
        # claim-all. Reject it: the action root is the explicit pointer "/$action"
        # (see _key_path_to_pointer), never "".
        if not hint or not isinstance(hint, str) or not hint.startswith("/"):
            raise LedgerError(
                f"invalid provenance hint {hint!r} for unit ({source_kind!r}, "
                f"{source_id!r}) — must be a non-empty json-pointer starting with '/' "
                f"(the action root is '/$action', not '')")
        # exact leaf, or an ancestor subtree (hint + "/" prefixes the leaf)
        matched = [p for p in known if p == hint or p.startswith(hint + "/")]
        if not matched:
            raise LedgerError(
                f"provenance hint {hint!r} matches no inventory key of unit "
                f"({source_kind!r}, {source_id!r}); known pointers: {sorted(known)} "
                f"(a processor owned-pointer hint drifted from the inventory scheme)")
        chosen.update(matched)
    # preserve inventory order, drop dups (overlapping hints are allowed)
    return [(source_kind, source_id, p) for p in known if p in chosen]


def make_default_behavior(domain_config, origin_content):
    """Create the default cache behavior."""
    hostname = domain_config["hostname"]
    sanitized = hostname.replace(".", "_").replace("-", "_")
    return {
        "path_pattern": "*",
        "precedence": 0,
        "distribution_settings": {
            "viewer_protocol_policy": "redirect-to-https",
            "minimum_protocol_version": "TLSv1.2_2021",
            "http_version": "http2and3",
            "is_ipv6_enabled": True,
            "price_class": "PriceClass_All",
            "waf_acl_arn": None,
            "geo_restriction_type": "none",
            "geo_restriction_locations": [],
        },
        "origin": {
            "id": f"origin_{sanitized}",
            "domain": origin_content or hostname,
            "protocol": "https",
            "port": 443,
            "host_header": None,
            "custom_origin_headers": [],
            "s3_origin": domain_config.get("origin_type") == "s3",
        },
        "cache_policy": {
            "caching_disabled": False,
            "ttl": {"min": 0, "default": 7200, "max": 86400},
            "cache_key": {"headers": [], "cookies": [], "query_strings": "none",
                         "query_strings_list": [], "query_strings_exclude": []},
            "enable_gzip": True,
            "enable_brotli": True,
        },
        "origin_request_policy": {
            "forward": {
                "headers": "none", "headers_list": [],
                "cookies": "none", "cookies_list": [],
                "query_strings": "none", "query_strings_list": [],
            },
        },
        "response_headers_policy": {
            "security_headers": {},
            "custom_headers": [],
            "cors": None,
            "remove_headers": [],
        },
        "required_orp_headers": [],
        "viewer_request_ops": [],
        "viewer_response_ops": [],
        "non_convertible": [],
    }


def find_or_create_behavior(ir, path_pattern, domain_config, origin_content):
    """Find existing behavior by path_pattern or create new one."""
    for b in ir["cache_behaviors"]:
        if b["path_pattern"] == path_pattern:
            return b
    # Create new
    b = make_default_behavior(domain_config, origin_content)
    b["path_pattern"] = path_pattern
    b["precedence"] = len(ir["cache_behaviors"]) + 1
    ir["cache_behaviors"].append(b)
    return b


# ── main processing ──────────────────────────────────────────────────────────

def process_domain(hostname, domain_config, all_rules, ip_lists,
                   bulk_redirects, managed_transforms):
    """Process all rules for a single domain, producing IR JSON."""
    apex = domain_config.get("apex_domain", "")
    origin_content = domain_config.get("origin_content", "")
    ir = make_empty_ir(domain_config)

    # Ensure default behavior exists
    default_beh = find_or_create_behavior(ir, "*", domain_config, origin_content)

    # Process rules in Cloudflare execution order
    rule_order = [
        ("redirect", process_redirect_rule),
        ("rewrite", process_rewrite_rule),
        ("config", process_config_rule),
        ("origin", process_origin_rule),
        ("cache", process_cache_rule),
        ("request_header", process_request_header_transform),
        ("response_header", process_response_header_transform),
        ("custom_error", process_custom_error_rule),
        ("compression", process_compression_rule),
    ]

    for rule_type, processor in rule_order:
        rules = all_rules.get(rule_type, [])
        phase = PHASE_MAP.get(rule_type, "")
        for index, rule in enumerate(rules):
            if not rule.get("enabled", True):
                continue

            expr = rule.get("expression", "true")
            cond, raw_expr = parse_expression(expr)
            hosts = extract_host_filter(cond, raw_expr or expr)

            if not rule_applies_to_domain(hosts, hostname, apex):
                continue

            # Assign the UNIQUE internal unit id (display id stays cf_source_rule). This
            # is the source_id for BOTH the inventory keys and the placement claims, so
            # (kind, id) reliably identifies one unit even for id-less / dup-id rules.
            # source_kind 'rule' scopes uniqueness; rule_type names the synthetic id.
            unit_id = _assign_unit_id(ir, rule, "rule", rule_type, index)
            if rule.get("id"):
                ir["_entered_rule_ids"].add(rule["id"])
            ir["_inventory"].extend(_inventory_keys_for_rule(rule, source_id=unit_id))
            ir["_seq"] += 1  # source-processing order for this rule
            result = processor(rule, ip_lists, phase)

            # This rule is now scoped to this host's distribution, so the host
            # test is redundant — strip it from both the loop cond and each
            # result's condition (the processor re-parsed the expr into its own
            # `condition`). This is what lets `host eq x AND uri.path eq /api`
            # reduce to the `/api` behavior instead of looking "compound".
            cond = _strip_host_condition(cond)
            # Handle list results (config rules, header transforms)
            if isinstance(result, list):
                for r in result:
                    _strip_host_in_result(r)
                    _place_result(ir, r, domain_config, origin_content, cond, expr,
                                  source_id=unit_id)
            else:
                _strip_host_in_result(result)
                _place_result(ir, result, domain_config, origin_content, cond, expr,
                              source_id=unit_id)

    # Process Cloud Connector rules
    for cc_index, rule in enumerate(all_rules.get("cloud_connector", [])):
        if not rule.get("enabled", True):
            continue
        expr = rule.get("expression", "true")
        cond, raw_expr = parse_expression(expr)
        hosts = extract_host_filter(cond, raw_expr or expr)
        if not rule_applies_to_domain(hosts, hostname, apex):
            continue
        unit_id = _assign_unit_id(ir, rule, "cloud_connector", "cloud_connector", cc_index)
        if rule.get("id"):
            ir["_entered_rule_ids"].add(rule["id"])
        # Cloud Connector's config unit spans BOTH the top-level `provider` AND
        # `parameters` (the processor reads both), so inventory a combined structure
        # — else `provider` is silently excluded from the outcome contract.
        ir["_inventory"].extend(
            _inventory_keys_for("cloud_connector", unit_id,
                                {"provider": rule.get("provider"),
                                 "parameters": rule.get("parameters", {})}))
        ir["_seq"] += 1
        result = process_cloud_connector(rule, ip_lists, "")
        cond = _strip_host_condition(cond)
        _strip_host_in_result(result)
        _place_result(ir, result, domain_config, origin_content, cond, expr,
                      source_kind="cloud_connector", source_id=unit_id)

    # Process bulk redirects
    _process_bulk_redirects(ir, hostname, apex, bulk_redirects, domain_config, origin_content)

    # Process managed transforms
    _process_managed_transforms(ir, managed_transforms, default_beh)

    # Process default cache behavior (Lambda@Edge origin-response)
    if domain_config.get("apply_default_cache_behavior"):
        _process_default_cache_behavior(ir, hostname, domain_config, origin_content, all_rules, apex)

    # Before replay: if a header name is handled by BOTH the RHP and the CFF, move
    # its RHP effects into the CFF so AWS's fixed RHP-then-CFF order can't reverse
    # the source (Cloudflare) order for that header.
    _reconcile_mixed_op_headers(ir, domain_config, origin_content)

    # Replay recorded NATIVE effects onto every behavior in source-rule order (F2).
    # MUST run after ALL effects are recorded (rules + cloud connector + managed
    # transforms) and after the behavior set is materialized, but BEFORE the ORP /
    # KVS scans below (they read the finished behaviors). This is what makes
    # Cloudflare rule-stacking correct on CloudFront's no-inheritance behaviors.
    _replay_native_effects(ir, domain_config, origin_content)

    # Collect ORP headers across all behaviors
    for beh in ir["cache_behaviors"]:
        orp_set = set()
        for op in beh["viewer_request_ops"] + beh["viewer_response_ops"]:
            c = op.get("condition")
            if c:
                for h in extract_orp_headers(c):
                    orp_set.add(h)
            raw = op.get("raw_expression")
            if raw:
                for h in extract_orp_headers_from_raw(raw):
                    orp_set.add(h)
        beh["required_orp_headers"] = sorted(orp_set)

    # Collect KVS requirements. Scan BOTH request and response ops — a
    # continent/is_eu condition on a response-header rule also needs the KVS
    # provisioned + associated + seeded, else the response CFF calls
    # kvsHandle.get('continent:'…) against a store that was never created and
    # cf.kvs() throws at init.
    for beh in ir["cache_behaviors"]:
        for op in beh["viewer_request_ops"] + beh["viewer_response_ops"]:
            c = op.get("condition")
            if c:
                for trigger in extract_kvs_triggers(c):
                    ir["metadata"]["kvs_requirements"][trigger] = True
            raw = op.get("raw_expression")
            if raw:
                # Scan raw expression for KVS triggers
                if "ip.src.continent" in raw:
                    ir["metadata"]["kvs_requirements"]["needs_continent"] = True
                if "ip.src.is_in_european_union" in raw:
                    ir["metadata"]["kvs_requirements"]["needs_eu"] = True

    # Cache-bypass: whitelist the buster header in the cache key. The viewer
    # request CFF is SHARED across all of a domain's behaviors, so a cache_bypass
    # op (even one scoped to a single path) may inject the buster on any behavior
    # the shared CFF runs on. The buster only forces a miss if it's part of that
    # behavior's cache key — so if ANY behavior carries a cache_bypass op, add the
    # header to EVERY behavior's cache-key header whitelist. Harmless where the
    # CFF never injects it (absent header = one shared empty value = normal
    # caching — verified live). Same constant the CFF codegen writes, so the
    # injected header and the cache-key header can't drift (avoids a split-brain).
    if any(op.get("type") == "cache_bypass"
           for beh in ir["cache_behaviors"]
           for op in beh["viewer_request_ops"]):
        for beh in ir["cache_behaviors"]:
            hdrs = beh["cache_policy"]["cache_key"]["headers"]
            if CACHE_BYPASS_HEADER not in hdrs:
                hdrs.append(CACHE_BYPASS_HEADER)

    # INVARIANT (reviewer's "every enabled rule must have an output"): every rule
    # that entered processing must leave a trace — a native effect, a viewer op, a
    # distribution setting, a custom-error entry, KVS data, or a non_convertible
    # record. A rule ID that produced NOTHING was silently dropped (the whole class
    # of bug this refactor targets). Surface any such orphan as non_convertible so
    # it lands in the report rather than vanishing. `_accounted_rule_ids` is
    # populated as outputs are produced; `_entered_rule_ids` as rules pass the host
    # filter. (Both internal, stripped below with _native_effects.)
    _enforce_every_rule_accounted(ir)

    # Coordination layer: group source keys by (artifact-id-label set, status, reason) and emit
    # one DecisionClaim per group (the artifact REGISTRY was removed in bucket B; the id labels
    # remain as stable claim grouping keys). MUST run before _strip_build_internals (which removes
    # the per-op / per-KVS provenance the coordinator reads).
    _coordinate_artifacts_and_claims(ir)

    # Drop build-time-only bookkeeping from the emitted IR (see _strip_build_internals).
    # (`seq` stays ON each op — the JS generator sorts by it; harmless persisted
    # metadata.) `_inventory` + `_claims` are DELIBERATELY KEPT: the finalize ledger gate
    # reads them from the written IR to enforce the no-silent-drop contract.
    _strip_build_internals(ir)
    return ir


# Build-time-only IR keys that must NOT reach the written IR. NB: `_inventory` and `_claims`
# are DELIBERATELY kept for the finalize ledger gate and are NOT in this set.
_BUILD_INTERNAL_KEYS = ("_native_effects", "_entered_rule_ids", "_accounted_rule_ids",
                        "_seq", "_unit_ids", "_kvs_index",
                        "_native_applied", "_native_overlap_nc")


def _strip_build_internals(ir):
    """Drop build-time-only bookkeeping from `ir` in place before it's written, and
    normalize `_inventory` to a list of [kind, id, pointer] triples (NOT de-duplicated:
    a duplicate source key is a real conflict the finalize validator must reject, so it
    must stay visible).

    Runs LAST in process_domain — AFTER every ledger channel has scanned the per-op /
    per-KVS-entry internal provenance. Each viewer op's `_source_*` / `_owner_refs` and
    each KVS entry's `_owner_refs` are build-time provenance for the (deferred) artifact
    channels; they must NOT reach the persisted IR (nested internal state, and a JSON
    round-trip would carry a stale copy), so strip them here — the top-level
    _BUILD_INTERNAL_KEYS pop only clears top-level keys, never nested ones."""
    ir["_inventory"] = [list(k) for k in ir.get("_inventory", [])]
    for k in _BUILD_INTERNAL_KEYS:
        ir.pop(k, None)
    for beh in ir.get("cache_behaviors", []):
        for phase in ("viewer_request_ops", "viewer_response_ops"):
            for op in beh.get(phase, []):
                for k in _VIEWER_OP_INTERNAL_KEYS:
                    op.pop(k, None)
    for entry in ir.get("metadata", {}).get("kvs_data", []):
        entry.pop("_owner_refs", None)


# Conversion outcome vocabulary (Phase-1 honesty model). Only EXACT counts as a
# successful conversion; LOSSY_WITH_WARNING is deployed but has a KNOWN behavioral
# gap the user must accept (surfaced in the report, NOT hidden behind nc=0);
# NON_CONVERTIBLE is not emitted at all. A single rule/leaf carries exactly one.
OUTCOME_EXACT = "EXACT"
OUTCOME_LOSSY = "LOSSY_WITH_WARNING"
OUTCOME_NON_CONVERTIBLE = "NON_CONVERTIBLE"
_OUTCOME_STATUSES = (OUTCOME_EXACT, OUTCOME_LOSSY, OUTCOME_NON_CONVERTIBLE)


# ── Unified outcome-channel API (L2, three-layer model) ────────────────────────
# The ~40 decision points do NOT call these directly one-by-one from scattered code
# paths; instead the finite set of OUTPUT CHANNELS routes through them. A source key
# is a (kind, id, pointer) triple (list, to stay JSON-safe).


def claim_decision(ir, source_keys, status, reason=None, exact_noop=False,
                   artifact_ids=None):
    """Record a DecisionClaim: the capability/decision layer's verdict for a SET of
    inventory source keys. status ∈ EXACT/LOSSY_WITH_WARNING/NON_CONVERTIBLE — the
    reconciler NEVER invents it. `artifact_ids` are the LOGICAL artifacts this claim
    produced; when present, EVERY source key of the claim co-owns them (the reconciler
    requires artifact-owner-set == claim-key-set — split the claim if some keys don't
    share the artifact). Omit/empty for NC; use exact_noop (EXACT ONLY) for a
    legitimately artifact-less EXACT. LOSSY/NC must carry a reason."""
    if status not in _OUTCOME_STATUSES:
        raise ValueError(f"bad decision status {status!r}")
    if artifact_ids is not None and not isinstance(artifact_ids, (list, tuple)):
        raise ValueError("artifact_ids must be a list/tuple")
    if exact_noop and status != OUTCOME_EXACT:
        raise ValueError(f"exact_noop is only valid with EXACT, not {status!r}")
    # Materialize the iterator ONLY (do NOT list(k) each key yet — list("abc") would
    # fabricate a legal-looking ["a","b","c"] triple). Validate the caller's RAW keys,
    # then convert to JSON-safe lists once they're confirmed well-formed.
    raw_keys = list(source_keys)
    if not raw_keys:
        raise ValueError("claim_decision requires at least one source key")
    for k in raw_keys:
        bad = _bad_source_key(k)
        if bad:
            raise ValueError(f"claim_decision: {bad}")
    keys = [list(k) for k in raw_keys]
    aids = list(artifact_ids or [])
    if exact_noop and aids:
        raise ValueError("exact_noop is an artifact-less EXACT — it must not "
                         f"reference artifacts (got {aids})")
    ir.setdefault("_claims", []).append({
        "source_keys": keys,
        "status": status,
        "reason": reason,
        "exact_noop": bool(exact_noop),
        "artifact_ids": aids,
    })


def claim_non_convertible(ir, source_kind, source_id, reason, description="",
                          owned_pointers=None, legacy_behavior=None,
                          legacy_cf_source_rule=None):
    """The single ledger-aware NON_CONVERTIBLE channel every NC sink routes through.

    Resolves the owned inventory source keys for config unit (source_kind, source_id)
    via the provenance resolver (whole-unit when owned_pointers is None, else the named
    json-pointer subset), records ONE NC DecisionClaim for exactly those keys, and writes
    the legacy cache_behaviors[*].non_convertible report entry so existing report/validate
    output is preserved. A source key gets AT MOST ONE claim — the caller must not claim
    the same leaves from two sinks (disjointness is a per-unit contract the tests check).

    `legacy_behavior` is the behavior dict the legacy entry lands on (defaults to the
    default behavior — the historical single sink for the report). `legacy_cf_source_rule`
    overrides the report id string ONLY (e.g. the literal "bulk_redirects"); the LEDGER
    claim always uses the real inventory keys, never this display string."""
    keys = _resolve_owned_keys(ir, source_kind, source_id, owned_pointers)
    claim_decision(ir, keys, OUTCOME_NON_CONVERTIBLE, reason=reason)
    beh = legacy_behavior if legacy_behavior is not None else ir["cache_behaviors"][0]
    beh.setdefault("non_convertible", []).append({
        "cf_source_rule": legacy_cf_source_rule if legacy_cf_source_rule is not None
        else source_id,
        "description": description,
        "outcome": OUTCOME_NON_CONVERTIBLE,
        "reason": reason,
    })


# ── Coordination layer (L2): artifact registration + decision aggregation ──────
# Artifact-producing channels (bulk-redirect CFF op + KVS entries, shared IP-list KVS)
# contribute an artifact-id LABEL owned by resolved source keys. The coordinator groups source
# keys by (artifact-id-set, status, reason) and emits EXACTLY ONE DecisionClaim per group.
# Status/reason live on the CONTRIBUTION (the owner ref), never inferred from "has an artifact".
# Generic — no bulk/IP-specific branches. (The artifact REGISTRY was removed in bucket B; the id
# labels remain as stable claim grouping keys.)


def _resolve_ref_to_keys(ir, ref):
    """Resolve ONE owner ref to its concrete inventory source keys (tuples), honoring the
    ref's owned_key_segments (None = whole-unit, else the named json-pointer subset). The
    ref is pre-validated. Raises LedgerError (via _resolve_owned_keys) if the unit has no
    inventory or a segment hint matches nothing."""
    pointers = (None if ref["owned_key_segments"] is None
                else [_key_path_to_pointer(s) for s in ref["owned_key_segments"]])
    return _resolve_owned_keys(ir, ref["source_kind"], ref["source_id"], pointers)


def _op_owner_refs(op_or_entry):
    """The list of owner refs for a viewer op OR a KVS entry, normalizing the single-source
    op shape (_source_kind/_source_id/_owned_key_segments/_outcome_status/_outcome_reason)
    to the same {source_kind, source_id, owned_key_segments, outcome_status, outcome_reason}
    ref shape the aggregation (_owner_refs) already uses. Returns [] if the item carries no
    provenance (a channel not yet wired — skipped, not claimed)."""
    if op_or_entry.get("_owner_refs") is not None:
        return op_or_entry["_owner_refs"]
    if op_or_entry.get("_source_id") is not None:
        return [{"source_kind": op_or_entry["_source_kind"],
                 "source_id": op_or_entry["_source_id"],
                 "owned_key_segments": op_or_entry["_owned_key_segments"],
                 "outcome_status": op_or_entry["_outcome_status"],
                 "outcome_reason": op_or_entry["_outcome_reason"]}]
    return []


def _register_artifact_contributions(ir, artifact_id, kind, refs, contributions):
    """Record each ref's contribution to `contributions[key]` for the coordinator to aggregate.
    `refs` are pre-validated owner refs. For each ref: resolve its source keys and append
    (key → artifact_id-label, status, reason). `artifact_id` is the stable grouping LABEL a claim
    carries (its `artifact_ids`); it no longer materializes a logical artifact (the registry was
    removed in bucket B). `kind` is now vestigial — kept to avoid churning the coordinator's call
    sites. NC status never reaches here (the validator forbids it on an artifact ref)."""
    for ref in refs:
        keys = _resolve_ref_to_keys(ir, ref)
        for k in keys:
            contributions.setdefault(k, []).append(
                (artifact_id, ref["outcome_status"], ref.get("outcome_reason")))


def _coordinate_artifacts_and_claims(ir):
    """THE coordination layer. Walks the WIRED artifact-producing sinks, registers logical
    artifacts, then emits ONE DecisionClaim per group of source keys that share the exact
    same (artifact-set, status, reason). Generic — the set of wired producers is data, not
    branches.

    Per source key it collects contributions (artifact_id, status, reason). Rules:
      - a key already carrying an NC claim must NOT also own a converted artifact → FATAL
        (an inventory leaf has exactly one fate);
      - all contributions to a key must agree on status AND reason → else FATAL (a source
        key can't be both EXACT and LOSSY);
      - keys with an IDENTICAL (sorted artifact-set, status, reason) fold into ONE claim.
    LOSSY only ever comes from a contribution that explicitly carried it (browser_ttl etc.),
    never inferred. Leaves with no contribution stay unclaimed (their channel isn't wired)."""
    # (1) NC keys already claimed — a converted artifact must not also own them.
    nc_keys = set()
    for c in ir.get("_claims", []):
        if c["status"] == OUTCOME_NON_CONVERTIBLE:
            nc_keys.update(tuple(k) for k in c["source_keys"])

    # Domain namespace — the artifact-id LABELS on claims are DOMAIN-NAMESPACED so two domains
    # sharing an IP list don't both mint `kvs:ip:blk:1.1.1.1` (or both `cff:*:bulk_redirect`).
    # The registry that once flattened these is gone (bucket B); the namespacing is kept as the
    # stable id scheme so a claim's artifact_ids stay distinct across domains.
    ns = ir["metadata"]["sanitized_name"]

    # (2) walk WIRED viewer-op producers, register their CFF artifacts, and accumulate —
    # PER IP-LIST NAME — the owner refs of ONLY the wired ops that reference each list. A
    # shared IP-list KVS entry carries owner refs from EVERY producer that referenced it
    # (wired AND unwired — _collect_kvs_ip_entries merges them all), so registering the
    # entry with its OWN refs would leak an unwired producer's owner (e.g. an unwired
    # custom-error sharing $blk with a wired header would get an IP-KVS-only claim, missing
    # its error: KVS). Instead register the ip: KVS artifact with wired_ip_refs_by_list —
    # the wired ops' refs only.
    contributions = {}   # source key (tuple) -> [(artifact_id, status, reason), ...]
    wired_ip_refs_by_list = {}   # list name -> [owner refs of WIRED ops referencing it]
    for beh in ir.get("cache_behaviors", []):
        for phase in ("viewer_request_ops", "viewer_response_ops"):
            for idx, op in enumerate(beh.get(phase, [])):
                aid = _viewer_op_artifact_id(ns, beh, phase, idx, op)
                if aid is None:
                    continue          # op type whose artifact channel isn't wired yet
                op_refs = _op_owner_refs(op)
                _register_artifact_contributions(
                    ir, aid, _viewer_op_artifact_kind(op), op_refs, contributions)
                for list_name in _condition_ip_list_names(op.get("condition")):
                    _merge_owner_refs_into(
                        wired_ip_refs_by_list.setdefault(list_name, []), op_refs)
    for entry in ir.get("metadata", {}).get("kvs_data", []):
        key = entry["key"]
        if key.startswith("ip:"):
            # Register ONLY with the WIRED ops' refs for this list — NOT the entry's own
            # mixed refs. A list no wired op referenced is skipped entirely (its producer
            # is unwired; the entry stays runtime data).
            list_name = key.split(":", 2)[1]
            refs = wired_ip_refs_by_list.get(list_name)
            if not refs:
                continue
        else:
            refs = entry.get("_owner_refs")
            if not refs:
                continue              # KVS entry whose channel isn't wired yet
        aid = _kvs_artifact_id(ns, key)
        if aid is None:
            continue                  # KVS kind whose channel isn't wired yet (error:)
        _register_artifact_contributions(ir, aid, "kvs", refs, contributions)

    # (2c) NATIVE EFFECTS — from the POST-REPLAY effective contribution. The STATUS of an
    # effect's source leaves depends on what actually survived (reviewer finding 1):
    #   - won ≥1 slot AND never cross-overlapped → EXACT, owns the winning slots' artifacts;
    #   - won ≥1 slot AND also cross-overlapped some behavior → LOSSY (deployed, but a
    #     cross-overlap region it can't cover — a known gap), owns the winning artifacts;
    #   - won NO slot but cross-overlapped → NON_CONVERTIBLE (no surviving artifact at all);
    #   - won NO slot, no cross-overlap (a PURE last-wins overwrite loser) → EXACT exact_noop
    #     (it converted but was fully overwritten — owns nothing).
    # Effects are identified by object identity (the SAME dict flows through applied/overlap).
    _native_won = {}     # id(effect) -> set of winning artifact ids (one per behavior+slot it
                         # won — a global effect wins the SAME slot on MULTIPLE behaviors, so
                         # key on the full artifact id, not the slot, or the behaviors clobber).
    for row in ir.get("_native_applied", []):
        if row["is_winner"]:
            _native_won.setdefault(id(row["effect"]), set()).add(
                _native_artifact_id(ns, row["behavior"], row["slot"]))
    _native_overlapped = {id(o["effect"]) for o in ir.get("_native_overlap_nc", [])}
    _native_effect_by_id = {}
    for row in ir.get("_native_applied", []):
        _native_effect_by_id[id(row["effect"])] = row["effect"]
    for o in ir.get("_native_overlap_nc", []):
        _native_effect_by_id[id(o["effect"])] = o["effect"]

    # A rule applied to N behaviors records N effect OBJECTS for the SAME source leaf; when they
    # cross-overlap only (win no slot), each would mint a DUPLICATE NC claim (and report line) for
    # that one leaf. The ledger contract is one claim per leaf, so dedup the cross-overlap NC by
    # NORMALIZED source identity (source_kind, source_id, owned_pointers) — NOT id(effect), which is
    # per-object. The winner/exact_noop paths need no such guard (their contributions fold by
    # grouping). Keep the first effect's reason (duplicates carry the same reason anyway).
    _claimed_nc_leaves = set()
    _winner_by_key = {}   # merge OR-split/*.ext branches: one source leaf → one native fate
    for eid, e in _native_effect_by_id.items():
        won = _native_won.get(eid, set())
        overlapped = eid in _native_overlapped
        if won:
            # An OR-split / *.ext rule records one effect OBJECT per branch, all sharing the SAME
            # owned key (the key ignores scope). Branches can land differently — one wins a slot
            # cleanly (EXACT), another also cross-overlaps a behavior it can't cover (LOSSY). Merge
            # per key so the leaf gets ONE native fate: LOSSY if ANY winning branch overlapped
            # (partial coverage), else EXACT; artifacts union. Registered after the loop. This
            # keeps the strict per-key aggregator (step 3) from seeing a spurious
            # one-leaf-two-fates conflict on a legal rule. (Only the SAME source unit can share a
            # key, so this merge is always intra-rule.)
            okey = (e["_source_kind"], e["_source_id"],
                    None if e["_owned_key_segments"] is None
                    else tuple(tuple(s) for s in e["_owned_key_segments"]))
            slot = _winner_by_key.setdefault(okey, {"aids": set(), "overlapped": False, "e": e})
            slot["aids"] |= won
            slot["overlapped"] = slot["overlapped"] or overlapped
        elif overlapped:
            # cross-overlap ONLY, nothing survived → NON_CONVERTIBLE (via the NC channel so
            # its keys are claimed NC, not left artifact-less-EXACT). The legacy
            # non_convertible report entry was already written at replay time.
            owned_pointers = (None if e["_owned_key_segments"] is None
                              else [_key_path_to_pointer(s) for s in e["_owned_key_segments"]])
            nc_leaf = (e["_source_kind"], e["_source_id"],
                       None if owned_pointers is None else tuple(owned_pointers))
            if nc_leaf not in _claimed_nc_leaves:
                _claimed_nc_leaves.add(nc_leaf)
                claim_non_convertible(
                    ir, e["_source_kind"], e["_source_id"],
                    reason=(f"native {e['kind']} cross-overlaps every behavior it could apply "
                            f"to and survives on none — no CloudFront equivalent"),
                    owned_pointers=owned_pointers)
        else:
            # PURE overwrite loser → EXACT exact_noop (sentinel None artifact_id).
            ref = {"source_kind": e["_source_kind"], "source_id": e["_source_id"],
                   "owned_key_segments": e["_owned_key_segments"],
                   "outcome_status": OUTCOME_EXACT, "outcome_reason": None}
            for k in _resolve_ref_to_keys(ir, ref):
                contributions.setdefault(k, []).append((None, OUTCOME_EXACT, None))

    # Register the merged winner contribution once per source leaf (OR-split / *.ext branches
    # folded to one native fate above, so the strict per-key aggregator never sees them split).
    for slot in _winner_by_key.values():
        e = slot["e"]
        status = OUTCOME_LOSSY if slot["overlapped"] else OUTCOME_EXACT
        reason = (f"native {e['kind']} converts where it contains a behavior but cross-overlaps "
                  f"another (partial coverage)") if slot["overlapped"] else None
        ref = {"source_kind": e["_source_kind"], "source_id": e["_source_id"],
               "owned_key_segments": e["_owned_key_segments"],
               "outcome_status": status, "outcome_reason": reason}
        for aid in sorted(slot["aids"]):
            _register_artifact_contributions(ir, aid, "native_effect", [ref], contributions)

    # (3) per key: forbid NC-overlap, require status/reason agreement, fold to one row.
    # Recompute nc_keys from the CURRENT _claims — step (2c) may have added NC claims
    # (cross-overlap-only native effects), so a converted-artifact contribution on one of
    # those same keys must still be caught as a one-leaf-two-fates conflict regardless of
    # the order the two arose.
    nc_keys = set()
    for c in ir.get("_claims", []):
        if c["status"] == OUTCOME_NON_CONVERTIBLE:
            nc_keys.update(tuple(k) for k in c["source_keys"])
    per_key = {}   # key -> (frozenset(artifact_ids), status, reason)
    for k, contribs in contributions.items():
        if k in nc_keys:
            raise LedgerError(
                f"source key {k} owns a converted artifact but is ALSO NON_CONVERTIBLE "
                f"— an inventory leaf has exactly one fate (converter bug)")
        statuses = {s for _, s, _ in contribs}
        reasons = {(r or None) for _, _, r in contribs}
        # STRICT: a leaf that reaches here with divergent statuses/reasons is a genuine
        # one-leaf-two-fates conflict (a converter bug). The ONE legitimate divergence — an
        # OR-split / *.ext native rule whose branches land EXACT on one slot and LOSSY on another
        # — is merged UPSTREAM in step (2c) into a single native fate per leaf, so it never
        # reaches here split. NC-vs-converted is caught above via nc_keys.
        if len(statuses) > 1 or len(reasons) > 1:
            raise LedgerError(
                f"source key {k} has conflicting contribution outcomes "
                f"(statuses={statuses}, reasons={reasons}) — one key, one decision")
        # None artifact_id is the exact_noop sentinel (an overwritten-loser contribution) —
        # drop it: if the SAME key also owns a real artifact (it won some other slot), that
        # artifact stands; if ALL its contributions are None, the empty set → exact_noop.
        per_key[k] = (frozenset(a for a, _, _ in contribs if a is not None),
                      next(iter(statuses)), next(iter(reasons)))

    # (4) group keys with identical (artifact-set, status, reason) into one claim.
    groups = {}   # (frozenset(artifact_ids), status, reason) -> [keys]
    for k, sig in per_key.items():
        groups.setdefault(sig, []).append(k)
    for (artifact_ids, status, reason), keys in groups.items():
        # An EXACT contribution with NO artifact is a VALIDATED exact_noop — the source
        # leaf converted but its output did not survive as a distinct artifact (a last-wins
        # overwritten native effect: the winning rule owns the setting, the overwritten one
        # legitimately produces nothing). LOSSY/NC always carry an artifact or go through
        # their own channel, so exact_noop applies to EXACT-only.
        exact_noop = (status == OUTCOME_EXACT and not artifact_ids)
        claim_decision(ir, sorted(keys), status, reason=reason,
                       artifact_ids=sorted(artifact_ids), exact_noop=exact_noop)


def _native_artifact_id(ns, behavior_path, slot):
    """Stable, DOMAIN-NAMESPACED logical-artifact id for a native effect's WINNING
    contribution to one (behavior, slot). The applied setting on the behavior carries no
    source back-ref, so the id is derived from behavior + slot (the last-wins winner is the
    sole owner). `slot` may be a tuple (e.g. ('rhp','x-frame-options')) — join stably."""
    slot_str = ":".join(str(s) for s in slot) if isinstance(slot, tuple) else str(slot)
    return f"domain:{ns}:native:{behavior_path}:{slot_str}"


def _condition_ip_list_names(condition):
    """The set of IP-list names an op's `condition` depends on (its in_kvs/not_in_kvs
    leaves' list names) — i.e. the shared IP-list KVS artifacts this op needs. Empty set
    if none. Mirrors _collect_kvs_ip_entries' walk; the list name is the leaf `value`."""
    names = set()
    if not isinstance(condition, dict):
        return names
    if "logic" in condition:
        for c in iter_condition_children(condition):
            names |= _condition_ip_list_names(c)
        return names
    if condition.get("op") in ("in_kvs", "not_in_kvs"):
        v = condition.get("value")
        if v:
            names.add(v)
    return names


def _kvs_artifact_id(ns, key):
    """Stable, DOMAIN-NAMESPACED logical-artifact id for a KVS entry, or None if this KVS
    KIND's channel isn't wired this turn. The KVS key namespaces by kind (`redirect:` /
    `ip:` / `error:`); THIS TURN only redirect: (bulk) and ip: (shared IP list) are wired —
    error: (inline custom error) returns None until the custom-error viewer-op channel is
    wired, else it would mint an EXACT claim referencing only the KVS, no viewer op."""
    if key.startswith("redirect:") or key.startswith("ip:"):
        return f"domain:{ns}:kvs:{key}"
    return None


# Viewer-op types whose CFF artifact channel is WIRED. Each is a converted output (one
# CFF statement) → its own logical artifact, keyed by stable domain/behavior/phase/op-index
# coordinates (NOT object identity). The bulk_redirect op is special-cased below (ONE
# shared id per behavior — all items reference the same CFF artifact). Everything else
# (a viewer-op type not listed, and not IP-list-conditioned) is a later increment → None.
# DERIVED from the ONE viewer-op-type authority (VIEWER_OP_CONTRACTS) so it can't drift into a
# separate hand-maintained list. "Wired" = a viewer op type preprocess may route through the GENERIC
# artifact channel today. ONE contract type is excluded (VIEWER_OP_CONTRACT_NOT_GENERIC_WIRED):
# bulk_redirect is wired but via its OWN shared-artifact branch (special-cased in
# _viewer_op_artifact_id BEFORE this set is consulted — do NOT delete that branch).
# (serve_error_inline was RETIRED in Step 5 — inline custom-error is permanently NC, so it no longer
# exists in VIEWER_OP_CONTRACTS.) Result = {redirect, rewrite, origin_override, cache_bypass,
# set/remove_{request,response}_header}. NO add_*_header (header `add` isn't a contract type at all).
_WIRED_VIEWER_OP_TYPES = frozenset(VIEWER_OP_CONTRACTS) - VIEWER_OP_CONTRACT_NOT_GENERIC_WIRED


def _viewer_op_artifact_id(ns, beh, phase, idx, op):
    """Stable, DOMAIN-NAMESPACED logical-artifact id for a viewer op, or None if this op's
    artifact channel isn't wired this turn. Wired ONLY by explicit op TYPE:
      - the bulk-redirect CFF op → ONE shared id per behavior (all items' claims reference
        the same CFF artifact);
      - a generic viewer op of a wired type (redirect / rewrite / origin_override /
        cache_bypass / {op}_request_header / {op}_response_header) → its OWN CFF artifact.
    Keyed by domain/behavior/phase/op-index (stable coordinates — the op list order is
    deterministic). An op of an UNWIRED type returns None EVEN IF its condition uses an IP
    list — "uses an IP list" must NOT admit a non-wired producer (an op type not in
    _WIRED_VIEWER_OP_TYPES), or its claim would be partial (CFF + IP-list KVS). The
    IP-list KVS dependency is registered separately, DRIVEN by the wired ops that actually
    reference each list (see the coordinator), not by op-condition admission here."""
    if op.get("type") == "bulk_redirect":
        return f"domain:{ns}:cff:{beh['path_pattern']}:bulk_redirect"
    if op.get("type") in _WIRED_VIEWER_OP_TYPES:
        return f"domain:{ns}:cff:{beh['path_pattern']}:{phase}:{idx}"
    return None


def _viewer_op_artifact_kind(op):
    return "cff_op"


def _mark_result_non_convertible(ir, result, reason, expr=None, source_kind="rule",
                                 source_id=None):
    """Record a native-mechanism result as non-convertible via the ledger channel.
    Used when native_placement() rejects a condition — so the rule lands in
    conversion_report.md instead of being silently applied to `*` (widening) or dropped.

    Preserves the RESULT's subset provenance: a conditional security header reaches here
    as a response_headers_policy result carrying owned_key_segments=[["headers", name]],
    so this NC must own ONLY that header — not the whole rule (which would collide with a
    sibling header's converted-op claim once the viewer-op channel is wired). A result
    with no hint (a genuinely whole-scope reject, e.g. a compression rule) claims the
    whole unit. `source_id` is the internal ledger unit id (defaults to the display id)."""
    if source_id is None:
        source_id = result.get("cf_source_rule", "")
    full_reason = f"{reason}. Scope: {result.get('raw_expression') or expr or '(complex)'}"
    claim_non_convertible(
        ir, source_kind, source_id,
        reason=full_reason, description=result.get("description", ""),
        owned_pointers=_result_owned_pointers(result),
        legacy_cf_source_rule=result.get("cf_source_rule", ""))


def _mark_result_lossy(ir, result, reason):
    """Record a LOSSY_WITH_WARNING outcome: the rule IS converted and deployed, but
    with a known behavioral gap (e.g. a viewer-response CFF header that AWS won't run
    on origin >=400 / custom-error / WAF-block responses, which the Cloudflare rule
    WOULD cover). Surfaced in the report's warnings so it is never counted as a clean
    (EXACT) success. Recorded on the default behavior's warnings sink."""
    ir["metadata"].setdefault("conversion_warnings", []).append(
        f"{OUTCOME_LOSSY} — rule {result.get('cf_source_rule', '')}"
        f"{(': ' + result.get('description', '')) if result.get('description') else ''}: {reason}")


# ── Native-effect engine (F2: replay in source-rule order per behavior) ────────
# A NATIVE effect is a CloudFront setting that lives ON a cache behavior (not in the
# shared viewer CFF): edge TTL, cache-key, compression, caching-disabled, response-
# headers policy entries, and the behavior's origin. Cloudflare rules STACK — a
# later same-phase rule overrides an earlier one for requests both match — but
# CloudFront picks ONE behavior per request and it inherits nothing from the
# default. So we can't write these settings as we see each rule; we record them in
# source order and, once the full behavior set is known, replay onto each behavior
# every effect whose SCOPE PATTERN contains that behavior's path (last write wins).


def _resolved_vpp(ir):
    """The distribution's resolved ViewerProtocolPolicy (from the default behavior).
    Config rules (phase 3) set it before cache rules (phase 5) are placed, so at
    placement time this is the effective value for the full_uri https-scheme check."""
    return ir["cache_behaviors"][0]["distribution_settings"].get(
        "viewer_protocol_policy", "redirect-to-https")


def _warn_case_insensitive_native(ir, condition, pattern, source):
    """Emit a non-fatal case-difference warning when a NATIVE path pattern is
    derived from a case-INSENSITIVE Cloudflare wildcard (per user's decision: still
    convert natively, but surface the divergence — CloudFront PathPattern is
    case-sensitive, so `/Admin/*` won't match a `/admin/x` request Cloudflare would).
    De-duplicated per (rule, pattern)."""
    if not isinstance(condition, dict) or "logic" in condition:
        return
    if not _pattern_case_insensitive_letters(condition, pattern):
        return
    rid = source.get("cf_source_rule", "")
    msg = (f"Rule {rid or '(cache)'}: path pattern '{pattern}' comes from a "
           f"case-INSENSITIVE Cloudflare `wildcard`, but the CloudFront cache "
           f"behavior is CASE-SENSITIVE — requests with different capitalization "
           f"(e.g. '{pattern.upper()}') that Cloudflare matched will NOT match this "
           f"behavior. If your paths can vary in case, switch the source rule to "
           f"`strict wildcard` or normalize case at the origin.")
    warns = ir["metadata"].setdefault("conversion_warnings", [])
    if msg not in warns:
        warns.append(msg)


def _validate_owned_key_segments(oks):
    """Validate the `owned_key_segments` shape used by BOTH single-source provenance and
    each owner ref: None (whole-unit) OR a NON-EMPTY list of paths, where each path is a
    list of string segments (an empty path [] is legal — it means the action root
    /$action, see _key_path_to_pointer). Raises LedgerError on breach."""
    if oks is None:
        return
    if not isinstance(oks, list) or not oks:
        raise LedgerError(f"owned_key_segments must be None or a non-empty list, got {oks!r}")
    for path in oks:
        if not isinstance(path, list):
            raise LedgerError(f"owned_key_segments path must be a list of segments, "
                              f"got {path!r}")
        for seg in path:
            if not isinstance(seg, str):
                raise LedgerError(f"owned_key_segments segment must be a string, got "
                                  f"{seg!r} in {path!r}")


def _validate_owner_ref(ref):
    """Validate ONE provenance owner ref (SHARED by the viewer-op and KVS gates, and by
    single-source ops via a synthesized ref): a dict with a NON-EMPTY STRING source_kind
    and source_id, a well-formed owned_key_segments (None or non-empty list of
    string-segment paths), and an EXPLICIT outcome_status.

    STATUS BELONGS TO THE SOURCE CONTRIBUTION, NOT THE ARTIFACT — a shared artifact (e.g.
    an IP-list KVS entry) can serve an EXACT header and a LOSSY op at once, so each ref
    carries its own status. Status is ALWAYS explicit (no implicit EXACT default):
    outcome_status ∈ {EXACT, LOSSY_WITH_WARNING}; NON_CONVERTIBLE never appears on an
    artifact-producing ref (NC keys own no artifact). EXACT requires NO reason; LOSSY
    requires a non-empty reason. Raises LedgerError on breach — a malformed ref must fail
    at construction, not when the coordinator finally consumes it."""
    if not isinstance(ref, dict):
        raise LedgerError(f"owner ref must be a dict, got {type(ref).__name__}: {ref!r}")
    for f in ("source_kind", "source_id"):
        v = ref.get(f)
        if not v or not isinstance(v, str):
            raise LedgerError(f"owner ref {f} must be a non-empty string, got {v!r}")
    _validate_owned_key_segments(ref.get("owned_key_segments"))
    status = ref.get("outcome_status")
    if status not in (OUTCOME_EXACT, OUTCOME_LOSSY):
        raise LedgerError(f"owner ref outcome_status must be EXACT or LOSSY_WITH_WARNING "
                          f"(explicit — no implicit default; NC never owns an artifact), "
                          f"got {status!r}")
    reason = ref.get("outcome_reason")
    if status == OUTCOME_EXACT and reason:
        raise LedgerError(f"EXACT owner ref must have no reason, got {reason!r}")
    if status == OUTCOME_LOSSY and not reason:
        raise LedgerError("LOSSY_WITH_WARNING owner ref requires a non-empty reason")


def _owner_ref_identity(ref):
    """The full CONTRIBUTION identity of an owner ref: (unit, subset, status, reason).
    Two refs are the SAME contribution only when ALL FOUR match — so a whole-unit ref
    does NOT subsume a differently-statused subset (that would erase a conflicting
    status). owned_key_segments is normalized to a hashable, order-independent form
    (None stays None; a list → a frozenset of segment-tuples)."""
    oks = ref.get("owned_key_segments")
    oks_key = None if oks is None else frozenset(tuple(p) for p in oks)
    return (ref["source_kind"], ref["source_id"], oks_key,
            ref.get("outcome_status"), ref.get("outcome_reason") or None)


def _merge_owner_refs_into(existing, incoming):
    """Merge `incoming` owner refs into the `existing` list, IN PLACE, de-duplicating on
    the FULL CONTRIBUTION identity (unit + subset + status + reason) — NOT just the unit.

    Status belongs to the source contribution, so a whole-unit EXACT ref and a subset
    LOSSY ref for the SAME unit are DIFFERENT contributions and BOTH survive (the old
    per-unit collapse could erase a conflicting status). Identical contributions (same
    unit, same subset, same status, same reason) collapse to one. The coordinator later
    resolves refs to source keys and FATALs if one key ends up with conflicting statuses.
    All refs are pre-validated by the caller."""
    have = {_owner_ref_identity(r) for r in existing}
    for r in incoming:
        ident = _owner_ref_identity(r)
        if ident in have:
            continue
        existing.append({
            "source_kind": r["source_kind"], "source_id": r["source_id"],
            "owned_key_segments": (None if r["owned_key_segments"] is None
                                   else [list(p) for p in r["owned_key_segments"]]),
            "outcome_status": r["outcome_status"],
            "outcome_reason": r.get("outcome_reason"),
        })
        have.add(ident)


def _append_kvs_entry(ir, key, value, owner_refs):
    """THE single constructor+sink for a KVS entry (ir.metadata.kvs_data). Attaches the
    INTERNAL provenance `_owner_refs` so the (deferred) KVS artifact channel can resolve
    each entry's source unit(s) — a KVS entry with no provenance can't be traced back,
    exactly the bulk / custom-error / IP-list gap the earlier rounds hit on viewer ops.

    DEDUP-MERGE: KVS keys are unique (the store is a map). When the SAME key is appended
    again (a shared IP-list entry referenced by several rules, or an identical redirect),
    the owner refs are MERGED PER UNIT via _merge_owner_refs_into — a later ref that names
    the same unit with a DIFFERENT subset unions its paths (X-A + X-B on one shared entry),
    and whole-unit subsumes a subset. The value must match on a re-append (same key,
    different value is a real conflict → FATAL). `owner_refs` must be a non-empty list; key
    a non-empty string; value a string. Returns the entry dict."""
    if not isinstance(owner_refs, list) or not owner_refs:
        raise LedgerError(f"_append_kvs_entry: owner_refs must be a non-empty list, got "
                          f"{owner_refs!r}")
    for r in owner_refs:
        _validate_owner_ref(r)
    if not key or not isinstance(key, str):
        raise LedgerError(f"_append_kvs_entry: key must be a non-empty string, got {key!r}")
    if not isinstance(value, str):
        raise LedgerError(f"_append_kvs_entry: value must be a string, got {value!r}")
    kvs = ir["metadata"].setdefault("kvs_data", [])
    # O(1) key lookup via an index (a large IP list re-referenced by many rules would be
    # O(n²) with a per-append linear scan). The index holds the SAME dict objects as the
    # list; it's a build-time accelerator stripped with the other internals.
    idx = ir.setdefault("_kvs_index", {})
    existing = idx.get(key)
    if existing is not None:
        if existing["value"] != value:
            raise LedgerError(f"KVS key {key!r} re-appended with a different value "
                              f"({existing['value']!r} != {value!r}) — a key must map to "
                              f"one value")
        _merge_owner_refs_into(existing["_owner_refs"], owner_refs)
        return existing
    # Normalize the seed refs through the same merge (into an empty list) so the stored
    # shape is canonical (own copies, per-unit deduped) even on first insert.
    seed = []
    _merge_owner_refs_into(seed, owner_refs)
    entry = {"key": key, "value": value, "_owner_refs": seed}
    kvs.append(entry)
    idx[key] = entry
    return entry


def _append_viewer_op(beh, phase, *, type, cf_source_rule, description, condition,
                      raw_expression, params, scope_pattern, seq,
                      source_kind="rule", source_id=None, owned_key_segments=None,
                      outcome_status=None, outcome_reason=None,
                      owner_refs=None, insert_index=None):
    """THE single constructor+sink for a viewer_request_ops / viewer_response_ops entry.
    EVERY op-append site (generic placement, browser_ttl, mixed-header rehome, managed
    transforms, bulk redirect) routes through here so the INTERNAL PROVENANCE
    (`_source_kind`, `_source_id`, `_owned_key_segments`) can never be forgotten — a
    viewer op with no provenance can't be resolved to its inventory unit by the
    (deferred) viewer-op artifact channel, silently dropping the outcome for an id-less
    rule (empty cf_source_rule).

    phase ∈ {"request","response"} selects the list. Provenance keys are `_`-prefixed and
    are stripped from the persisted op by _strip_build_internals AFTER the channels scan
    them. For a MULTI-UNIT AGGREGATION op (bulk redirect: one CFF op serving many redirect
    items), pass `owner_refs` — a list of {source_kind, source_id, owned_key_segments}
    dicts, one per owned unit — instead of a single source_id; the op then has no single
    _source_id (that would be a lie) and the channel unions the owner refs. `insert_index`
    inserts at a position (bulk redirect must land after redirect/rewrite/origin ops)
    instead of appending.

    ENFORCES the provenance contract at construction (a bad ref only fails when a future
    channel consumes it otherwise): phase must be request/response; SINGLE-source mode
    requires a non-empty source_kind AND source_id (NO cf_source_rule fallback — a display
    id, empty for id-less rules, is not a ledger unit); AGGREGATION mode requires a
    non-empty owner_refs list, each ref a dict with non-empty source_kind/source_id and an
    owned_key_segments that is None (whole-unit) or a list. Raises LedgerError on breach."""
    if phase not in ("request", "response"):
        raise LedgerError(f"_append_viewer_op: phase must be 'request' or 'response', "
                          f"got {phase!r}")
    # HARD GATE (round-19 finding 2): NO producer may emit an `add_*_header` viewer op — a
    # request `add` isn't a real Cloudflare operation and a response `add` (append-duplicate)
    # is non-convertible. The generator's add branch is dormant/legacy-only; a live IR reaching
    # it would get a spurious EXACT claim + CFF artifact. Fail loud instead of silently wiring.
    if type in ("add_request_header", "add_response_header", "add_header"):
        raise LedgerError(
            f"_append_viewer_op: op type {type!r} is not a valid conversion output — "
            "Cloudflare header `add` has no faithful CloudFront equivalent (request has no "
            "add; response add is append-duplicate → non-convertible). A producer must NC it, "
            "never emit an add viewer op.")
    # HARD GATE (round-27 finding 2 → review-2 finding 3): every op MUST satisfy the FULL SHARED
    # op validator at the single construction sink — the SAME validate_viewer_op the chunk
    # validator and generator enforce, so no producer (generic placement OR an internal one: RHP
    # rehome, browser_ttl, True-Client-IP) can build an op with an unknown type, wrong phase, bad
    # param, invalid header name, a leftover raw value field, a slot-illegal lowered value, OR a
    # malformed/absent condition (a list/str condition AttributeErrors in the generator; neither/
    # both condition+raw is ambiguous). The generator renders ONLY validated data, so anything
    # malformed here would FATAL downstream — catch it at the sink. A type absent from the registry
    # (a producer bug) is rejected outright.
    _op_bad = validate_viewer_op({"type": type, "params": params or {},
                                  "condition": condition, "raw_expression": raw_expression}, phase)
    if _op_bad:
        raise LedgerError(
            f"_append_viewer_op: op violates the shared viewer-op contract: {_op_bad}. "
            "Every producer must emit a registry-valid op (lowered values via lower_literal_value "
            "/ lower_dynamic_value) — a malformed op must never reach the persisted IR / generator.")
    if owner_refs is not None:
        if not owner_refs:
            raise LedgerError("_append_viewer_op: aggregation op has empty owner_refs "
                              "(an aggregate must own at least one unit)")
        for r in owner_refs:
            _validate_owner_ref(r)   # non-empty STRING kind/id, valid segments
    else:
        # Single-source: validate via the SAME ref validator (a synthesized ref) so int
        # source_kind/source_id, a string owned_key_segments, a bad status, or an empty
        # subset are all rejected here too — not just falsy checks. `outcome_status` has NO
        # default (was EXACT) — every caller MUST pass it explicitly; a missing status is
        # outcome_status=None, which the validator REJECTS (status must be explicit — the
        # design decision). EXACT callers pass OUTCOME_EXACT; a known-gap sink (browser_ttl)
        # passes LOSSY + reason.
        _validate_owner_ref({"source_kind": source_kind, "source_id": source_id,
                             "owned_key_segments": owned_key_segments,
                             "outcome_status": outcome_status,
                             "outcome_reason": outcome_reason})
    # DEEP-COPY the condition so each op owns an INDEPENDENT tree. A processor builds N
    # per-header ops all sharing ONE parsed `cond` object (parse_expression is called
    # once per rule); a destructive read on one op's condition (e.g. _collect_kvs_ip_
    # entries popping "kvs_ips") would otherwise mutate the SAME object the sibling ops
    # alias, so only the first op would see the IP data and later headers would fail to
    # register their KVS owner. Copying here severs the aliasing at the single sink.
    op = {
        "type": type, "cf_source_rule": cf_source_rule,
        "description": description,
        "condition": copy.deepcopy(condition), "raw_expression": raw_expression,
        "params": params, "scope_pattern": scope_pattern, "seq": seq,
    }
    if owner_refs is not None:
        op["_owner_refs"] = [dict(r) for r in owner_refs]
    else:
        op["_source_kind"] = source_kind
        op["_source_id"] = source_id
        op["_owned_key_segments"] = owned_key_segments
        op["_outcome_status"] = outcome_status
        op["_outcome_reason"] = outcome_reason
    lst = beh["viewer_response_ops"] if phase == "response" else beh["viewer_request_ops"]
    if insert_index is None:
        lst.append(op)
    else:
        lst.insert(insert_index, op)
    return op


# The per-op INTERNAL provenance keys _append_viewer_op writes — stripped from every
# persisted viewer op by _strip_build_internals once the ledger channels have consumed them.
_VIEWER_OP_INTERNAL_KEYS = ("_source_kind", "_source_id", "_owned_key_segments",
                            "_outcome_status", "_outcome_reason", "_owner_refs")


def _record_native_effect(ir, scope_pattern, kind, params, source,
                          source_kind="rule", source_id=None, owned_key_segments=None):
    """Append a native effect to the ordered replay log. `scope_pattern` is the
    CloudFront path pattern the effect applies to (`*` = whole distribution).
    `kind` selects the applier branch in _apply_native_effect; `source` carries
    cf_source_rule/description for non-convertible reporting. `condition` is the
    processor's SCREENED, host-stripped condition — kept so that if this effect is
    later re-homed to the CFF (mixed-op header reconciliation) it carries its
    authoritative runtime predicate, not the behavior association as a stand-in.

    INTERNAL PROVENANCE (`_source_kind`, `_source_id`, `_owned_key_segments`) is stored
    ALONGSIDE the display cf_source_rule so the native-effect / viewer-op artifact
    channels (and the mixed-header rehome) can resolve the correct inventory unit even
    for an id-less rule (whose cf_source_rule is empty but whose unit id is a synthesized
    {rule_type}#{index}). Provenance MUST come from the internal id, never be rebuilt
    from cf_source_rule (a display field). `source_id` defaults to the display id for
    callers/tests that don't thread a separate unit id.

    `owned_key_segments` is the SUBSET of the source unit this effect owns (its
    json-pointer leaves). A cache rule has SEVERAL independent settings (edge_ttl /
    cache_key / cache / ...), only some of which convert — so each cache effect owns ONLY
    its own leaves (edge_ttl → [["edge_ttl"]]), never the whole rule (which would falsely
    claim an un-converted sibling like serve_stale). An explicit arg overrides the source's
    hint; None falls back to the source's owned_key_segments (whole-unit for a single-
    concern rule like compression/origin, whose whole action IS the effect)."""
    if source_id is None:
        source_id = source.get("cf_source_rule", "")
    if owned_key_segments is None:
        owned_key_segments = source.get("owned_key_segments")
    ir["_native_effects"].append({
        "scope": scope_pattern, "kind": kind, "params": params,
        "cf_source_rule": source.get("cf_source_rule", ""),
        "description": source.get("description", ""),
        "condition": source.get("condition"),
        "raw_expression": source.get("raw_expression"),
        "seq": ir.get("_seq", 0),   # source order (replay is order-sensitive: last wins)
        "_source_kind": source_kind,
        "_source_id": source_id,
        "_owned_key_segments": owned_key_segments,
    })


# _canonical_rhp_header is imported from cdn_rhp_capabilities (the shared registry) — the
# canonical (generator-expected) casing for an RHP header, so the RHP dict key, the
# last-wins slot, and the generated output all use ONE name (no `x-frame-options` dict vs
# `X-Frame-Options` generator desync). An unsupported header never reaches the RHP branch.


def _apply_native_effect(beh, kind, params, seq=0):
    """Apply one native effect onto one behavior and RETURN THE SET OF LAST-WINS SLOTS it
    actually WROTE. Pure w.r.t. the behavior dict — the replay pass decides WHICH behaviors
    this runs on. Last-writer-wins is a property of replay ORDER, so each branch overwrites.

    The returned slots are the AUTHORITATIVE last-wins keys — two effects that write the
    SAME slot on the same behavior overwrite (only the later survives → the earlier is a
    pure-overwrite loser); effects writing DIFFERENT slots coexist (both survive). Returning
    the ACTUALLY-written slots (not a kind→slot guess) keeps the winner tracker in lockstep
    with real write semantics: cache_key writes PER FIELD (a query-selector rule and a
    headers rule don't collide), and a managed rhp_security setdefault that DIDN'T write
    (the header already exists) returns NO slot → no winner row for it."""
    cp = beh["cache_policy"]
    if kind == "ttl_override":
        # override_origin forces a fixed TTL — min=default=max is the only way
        # (a >max value would otherwise fail CloudFront's create API).
        ttl = params["ttl"]
        cp["ttl"]["min"] = cp["ttl"]["default"] = cp["ttl"]["max"] = ttl
        return {"ttl"}
    elif kind == "ttl_respect_origin":
        # RESET to factory TTL (CachingOptimized-like defaults) — undoes a prior
        # override at this scope. Must match make_default_behavior's ttl.
        cp["ttl"]["min"], cp["ttl"]["default"], cp["ttl"]["max"] = 0, 7200, 86400
        return {"ttl"}
    elif kind == "caching_enabled":
        cp["caching_disabled"] = False       # RESET: undoes a prior cache=false
        return {"caching"}
    elif kind == "cache_key":
        # cache_key updates PER FIELD — the query-string selector and the header list are
        # INDEPENDENT slots (a later query rule must not overwrite an earlier header rule).
        slots = set()
        for k in ("query_strings", "query_strings_list", "query_strings_exclude"):
            if k in params:
                cp["cache_key"][k] = params[k]
                slots.add("cache_key.query")
        if "headers" in params:
            cp["cache_key"]["headers"] = params["headers"]
            slots.add("cache_key.headers")
        return slots
    elif kind == "caching_disabled":
        cp["caching_disabled"] = True
        return {"caching"}
    elif kind == "compression":
        cp["enable_gzip"] = params.get("enable_gzip", True)
        cp["enable_brotli"] = params.get("enable_brotli", True)
        return {"compression"}
    elif kind == "rhp_security":
        sh = beh["response_headers_policy"]["security_headers"]
        # CANONICAL name for BOTH the dict key and the slot — must match what the HCL
        # generator reads, so the ledger winner and the emitted header can't disagree.
        cname = _canonical_rhp_header(params["name"])
        # Store the NORMALIZED value the processor's capability.parse() accepted — the
        # generator renders THIS via the same capability's render() (no independent
        # re-parse). Raw value kept for reference/report only. The managed-transform
        # producer doesn't pre-parse, so derive it here from the SAME registry (its two
        # hardcoded values, nosniff / SAMEORIGIN, always parse) — never leave it None on
        # a security header or the generator would emit nothing.
        normalized = params.get("normalized")
        if normalized is None:
            cap = security_capability(params["name"])
            normalized = cap["parse"](params["value"]) if cap else None
        entry = {"value": params["value"], "operation": params.get("operation", "set"),
                 "normalized": normalized}
        if params.get("_managed"):
            # managed default: only WRITES if the header isn't already set (explicit rule
            # wins). If it didn't write, it owns nothing → return NO slot.
            if cname in sh:
                return set()
            sh[cname] = entry
        else:
            sh[cname] = entry
        return {("rhp", cname.lower())}
    elif kind == "rhp_cors":
        # DORMANT (round-13 finding 3). No producer emits rhp_cors today — a static CORS
        # header routes to a viewer-response CFF (LOSSY), never here. The native cors_config
        # path is NOT a faithful substitute for a static header set (it synthesizes the
        # required Allow-Methods/Allow-Headers the source never set, Origin-matches instead of
        # emitting the literal value, and is preflight-only). Re-enabling it must go through a
        # NEW group-level semantic check that assigns the correct per-GROUP outcome (likely
        # LOSSY, not EXACT); it must NOT silently inherit the old per-header EXACT status. So
        # fail loud rather than let a re-added producer flow through the retired mapping.
        raise LedgerError(
            "rhp_cors native effect reached _apply_native_effect, but the native cors_config "
            "path is dormant: a static CORS header must route to a viewer-response CFF "
            "(LOSSY). Re-enabling native CORS requires a group-level semantic check + explicit "
            "outcome assignment (see cdn_rhp_capabilities.native_cors_config_supports) — do "
            "NOT reuse the old per-header EXACT path.")
    elif kind == "rhp_custom":
        beh["response_headers_policy"]["custom_headers"].append({
            "name": params["name"], "value": params["value"],
            "operation": params.get("operation", "set"),
        })
        return {("rhp_custom", seq)}   # APPEND semantics → unique slot, never overwritten
    elif kind == "origin":
        beh["origin"]["domain"] = params.get("origin_host", beh["origin"]["domain"])
        beh["origin"]["s3_origin"] = "s3." in (params.get("origin_host") or "")
        return {"origin"}
    return set()


def _replay_native_effects(ir, domain_config, origin_content):
    """Compute each behavior's EFFECTIVE native config by replaying every recorded
    effect, in source-rule order (last write wins — Cloudflare rule stacking), onto
    the behaviors it applies to. Effects that name a concrete path first MATERIALIZE
    that behavior, so `TTL on /files/*` creates the /files/* behavior.

    For each (effect scope S, behavior pattern B), exactly one of:
      - pattern_contains(S, B): every request routed to B matches S → APPLY.
      - pattern_contains(B, S) (B strictly broader): S is a sub-region of B that is
        served by ITS OWN (more-specific) behavior, so B never actually serves an
        S request → the effect does NOT apply to B and is NOT a conflict. (This is
        why an ordered `/img` effect doesn't touch — or flag — the default `*`.)
      - otherwise, if they still OVERLAP: a genuine cross-overlap (e.g. `*.js` vs
        `/api/*`) — some requests match both, route to whichever behavior is listed
        first, and the effect can't be scoped to just them. CloudFront can't express
        a native setting on part of a behavior's traffic → report non-convertible
        rather than widen or drop.
      - disjoint: nothing to do.
    """
    effects = ir.get("_native_effects", [])
    for e in effects:
        if e["scope"] != "*":
            find_or_create_behavior(ir, e["scope"], domain_config, origin_content)

    # Record the POST-REPLAY EFFECTIVE contribution for the native-effect artifact channel:
    # replay is the sole authority on last-wins / containment / cross-overlap, so it stamps
    # what actually survived rather than the coordinator re-deriving that logic. Build-time,
    # stripped before write.
    #   _native_applied: one row per (effect APPLIED to a behavior) — {behavior, slot, effect,
    #     is_winner}. is_winner = this effect is the LAST applied to that (behavior, slot), so
    #     its value survives on the behavior (→ owns the artifact); a loser was overwritten
    #     (→ a validated exact_noop, owns nothing).
    #   _native_overlap_nc: (effect, behavior) pairs that cross-overlapped → NC (never applied,
    #     so they must NOT become a native artifact — reviewer semantic #4).
    applied = ir.setdefault("_native_applied", [])
    overlap_nc = ir.setdefault("_native_overlap_nc", [])

    for beh in ir["cache_behaviors"]:
        bp = beh["path_pattern"]
        winner_by_slot = {}   # slot -> index into `applied` of the current winner for THIS beh
        for e in effects:
            scope = e["scope"]
            if pattern_contains(scope, bp):
                # _apply returns the slots it ACTUALLY wrote (cache_key = per field; a
                # managed setdefault that didn't write = no slot).
                wrote = _apply_native_effect(beh, e["kind"], e["params"], e["seq"])
                if not wrote:
                    # EVALUATED but wrote NOTHING (a managed setdefault the explicit rule
                    # already satisfied). Record a NO-WRITE row so the effect's source unit
                    # is still accounted — the coordinator emits exact_noop for it IF the
                    # unit has no other winner and no cross-overlap (else it vanishes:
                    # inventory key with no claim).
                    applied.append({"behavior": bp, "slot": None, "effect": e,
                                    "is_winner": False, "no_write": True})
                    continue
                for slot in wrote:
                    prev = winner_by_slot.get(slot)
                    if prev is not None:
                        applied[prev]["is_winner"] = False   # later effect wins this slot
                    applied.append({"behavior": bp, "slot": slot, "effect": e,
                                    "is_winner": True})
                    winner_by_slot[slot] = len(applied) - 1
            elif pattern_contains(bp, scope):
                continue                     # S is a narrower sibling behavior's job
            elif patterns_overlap(scope, bp):
                overlap_nc.append({"effect": e, "behavior": bp})
                beh["non_convertible"].append({
                    "cf_source_rule": e["cf_source_rule"],
                    "description": e["description"],
                    "reason": (f"native {e['kind']} scoped to '{scope}' cross-overlaps "
                               f"behavior '{bp}' (neither contains the other) — "
                               "CloudFront can't apply a native setting to only part "
                               "of a behavior's traffic; scope them so one path "
                               "contains the other, or apply it at the origin"),
                })


def _reconcile_mixed_op_headers(ir, domain_config, origin_content):
    """ONE AWS WRITER PER RESPONSE HEADER. A header is served by the RHP (native,
    which AWS runs BEFORE the viewer-response function) OR the CFF, never both — the
    fixed RHP-then-CFF order can't reproduce arbitrary Cloudflare source order
    (remove(1)+set(2) → RHP-set + CFF-remove → wrongly removed). When a header is
    touched by both, move all its RHP effects into the CFF, PRESERVING each effect's
    screened condition/raw/seq. Runs before replay so moved effects never reach RHP.

    Two move triggers:
    - PER NAME: the header already has a CFF response-header op (remove / dynamic /
      conditional), so unify it in the CFF.
    - WHOLE CORS GROUP: CloudFront's `origin_override` is ONE boolean for the ENTIRE
      CorsConfig, not per header. So if ANY mix of add/set exists ACROSS ALL the
      behavior's CORS headers (e.g. add Allow-Origin + set Allow-Methods — different
      names), the single flag can't encode it → move the ENTIRE CORS group to the
      CFF. (A pure-all-add or pure-all-set CORS group stays native.)
    """
    effects = ir.get("_native_effects", [])
    rhp_names = set()         # lowercased names with a (non-managed) RHP effect
    cors_ops = set()          # operations seen across ALL CORS RHP effects
    has_cors = False
    for e in effects:
        if e["kind"] in ("rhp_security", "rhp_cors") and not e["params"].get("_managed"):
            rhp_names.add(e["params"]["name"].lower())
            if e["kind"] == "rhp_cors":
                has_cors = True
                cors_ops.add(e["params"].get("operation", "set"))
    cff_names = set()         # names with an existing CFF response-header op
    for beh in ir["cache_behaviors"]:
        for op in beh.get("viewer_response_ops", []):
            if op.get("type", "").endswith("_response_header"):
                nm = op.get("params", {}).get("name")
                if nm:
                    cff_names.add(nm.lower())

    # CORS is one shared-flag group: mixed add/set anywhere in it → move it all.
    cors_mixed = has_cors and ("add" in cors_ops and any(o != "add" for o in cors_ops))

    def _must_move(e):
        nm = e["params"]["name"].lower()
        if nm in cff_names:
            return True
        if e["kind"] == "rhp_cors" and cors_mixed:
            return True
        return False

    if not any(e["kind"] in ("rhp_security", "rhp_cors")
               and not e["params"].get("_managed") and _must_move(e) for e in effects):
        return
    kept = []
    for e in effects:
        _is_hdr = e["kind"] in ("rhp_security", "rhp_cors") and not e["params"].get("_managed")
        if _is_hdr and _must_move(e):
            # A rehomed native RHP effect is always a `set` — response `add` is NC'd at the
            # processor before it can become a native effect (round-19 finding 2), so it never
            # reaches here. Guard rather than construct an `add_response_header` the hard gate
            # would reject anyway.
            if e["params"].get("operation") == "add":
                raise LedgerError(
                    "rehome: a native RHP effect with operation=add reached the CFF rehome — "
                    "response header `add` must be non-convertible at the processor, never a "
                    "native effect")
            op_type = "set_response_header"
            beh = find_or_create_behavior(ir, e["scope"], domain_config, origin_content)
            # CARRY the internal provenance across the rehome — this viewer op is the same
            # source unit's output as the native effect it replaces; the (id-less) unit id
            # must survive so the viewer-op artifact channel can resolve it. Rebuilding
            # from cf_source_rule (empty for id-less) would lose it.
            _append_viewer_op(
                beh, "response",
                type=op_type,
                cf_source_rule=e.get("cf_source_rule", ""),
                description=e.get("description", ""),
                # PRESERVE the effect's authoritative screened condition — a native RHP
                # effect scoped to a path was recorded with that condition, and dropping
                # it to `always` would fire the header on every path.
                condition=e.get("condition") if e.get("condition") is not None else {"always": True},
                raw_expression=e.get("raw_expression"),
                # LOWER the static header value ONCE (round-27) — a rehomed RHP effect's value is
                # always a literal string; the generator renders the stored LiteralValue AST.
                params={"name": e["params"]["name"],
                        "value_lowered": lower_literal_value(e["params"]["value"], "response_header")},
                # CFF-attach scope from the SAME single authority (case-insensitive
                # wildcard → all behaviors), not the native path scope e["scope"].
                scope_pattern=_compute_scope_pattern(e.get("condition")),
                seq=e.get("seq", 0),
                source_kind=e.get("_source_kind", "rule"),
                source_id=e.get("_source_id", e.get("cf_source_rule", "")),
                owned_key_segments=e.get("_owned_key_segments"),
                # A rehomed static security/CORS header now runs in the SAME viewer-response CFF as
                # a dynamic set of that header — so it shares the error-response gap and is
                # LOSSY_WITH_WARNING, NOT EXACT (round-27 review 2 finding 1). Uses the shared
                # VIEWER_RESPONSE_GAP_REASON so it can't drift from the processor's response tail.
                outcome_status=OUTCOME_LOSSY,
                outcome_reason=(f"response header '{e['params']['name']}' "
                                f"{VIEWER_RESPONSE_GAP_REASON}"))
        else:
            kept.append(e)
    ir["_native_effects"] = kept


def _enforce_every_rule_accounted(ir):
    """Every rule that entered processing (passed the host filter) must leave a
    trace: a native effect, a viewer op, a distribution/custom-error/KVS output, or
    a non_convertible record. A rule ID with NO trace was silently dropped — the
    exact failure class this refactor targets — so record it as non_convertible
    rather than letting it vanish. Scans all output sinks for cf_source_rule."""
    accounted = set(ir.get("_accounted_rule_ids", set()))
    for e in ir.get("_native_effects", []):
        accounted.add(e.get("cf_source_rule"))
    for beh in ir["cache_behaviors"]:
        for nc in beh.get("non_convertible", []):
            accounted.add(nc.get("cf_source_rule"))
        for op in beh.get("viewer_request_ops", []) + beh.get("viewer_response_ops", []):
            accounted.add(op.get("cf_source_rule"))
    # metadata sinks (custom errors, kvs data carry the source in their own ids;
    # distribution settings are recorded in _accounted_rule_ids at placement time).
    orphans = ir.get("_entered_rule_ids", set()) - accounted
    for rid in sorted(orphans):
        ir["cache_behaviors"][0]["non_convertible"].append({
            "cf_source_rule": rid,
            "description": "(rule produced no output)",
            "reason": ("INTERNAL: this enabled rule matched the domain but produced "
                       "no CloudFront output (native setting, function op, or "
                       "non-convertible record) — a silent drop. Reported so it is "
                       "never lost; please file it as a converter bug."),
        })


def _place_result(ir, result, domain_config, origin_content, cond, expr,
                  source_kind="rule", source_id=None):
    """Place a processed rule result into the appropriate IR location.

    `source_kind` is the config-unit kind of the rule that produced `result` ('rule' for
    phase rules, 'cloud_connector' for cloud connector). `source_id` is the INTERNAL unit
    id (from _assign_unit_id) — the ledger provenance key; it defaults to the result's
    display cf_source_rule for callers/tests that don't assign a separate unit id. The
    two differ only when a rule's display id is absent/duplicated, where source_id is a
    unique synthesized id. Both name the same unit's inventory keys."""
    if result is None:
        return

    rtype = result.get("type", "")
    if source_id is None:
        source_id = result.get("cf_source_rule", "")

    if rtype == "non_convertible":
        # Route through the ledger-aware NC channel. A processor that partially converts
        # exposes `owned_key_segments` (raw dict-key paths) so the NC outcome claims ONLY
        # its own leaves; without a hint the whole unit is non-convertible. The resolver
        # turns segments into json-pointers and validates them against the inventory. The
        # LEDGER unit is source_id; the legacy report still shows the display id.
        claim_non_convertible(
            ir, source_kind, source_id,
            reason=result.get("reason", ""),
            description=result.get("description", ""),
            owned_pointers=_result_owned_pointers(result),
            legacy_cf_source_rule=result.get("cf_source_rule", ""))
        return

    if rtype == "distribution_setting":
        default_beh = ir["cache_behaviors"][0]
        setting = result.get("setting", "")
        value = result.get("value")
        if setting in default_beh["distribution_settings"]:
            default_beh["distribution_settings"][setting] = value
        # LEDGER: this converted setting owns its SOURCE leaf (e.g. /ssl, /min_tls_version). Record an
        # EXACT claim (artifact-less native setting → exact_noop) so the leaf is NOT a silent drop the
        # finalize gate flags. owned_key_segments comes from the processor (a single setting's leaf);
        # None would mean whole-unit — a config rule can carry other settings with their own claims.
        claim_decision(ir, _resolve_owned_keys(ir, source_kind, source_id, _result_owned_pointers(result)),
                       OUTCOME_EXACT, exact_noop=True)
        # A directed-override note (e.g. min TLS floored to the 1.2 baseline) rides the result → the
        # report's conversion_warnings. NOT a claim (the setting IS converted) — informational only.
        if result.get("warning"):
            ir["metadata"].setdefault("conversion_warnings", []).append(result["warning"])
        if result.get("cf_source_rule"):
            ir.setdefault("_accounted_rule_ids", set()).add(result["cf_source_rule"])
        return

    if rtype == "custom_error_response":
        ir["metadata"]["custom_error_responses"].append(result["params"])
        # LEDGER: the native custom_error_response converts the rule's status_code leaf → EXACT claim
        # (artifact-less → exact_noop), so it is NOT a silent drop the finalize gate flags.
        claim_decision(ir, _resolve_owned_keys(ir, source_kind, source_id, _result_owned_pointers(result)),
                       OUTCOME_EXACT, exact_noop=True)
        if result.get("cf_source_rule"):
            ir.setdefault("_accounted_rule_ids", set()).add(result["cf_source_rule"])
        return

    if rtype == "compression_setting":
        # Compression is a cache-policy attribute (native). Record it as an ordered
        # native effect scoped to its path; the replay pass applies it to every
        # behavior that path contains (and reports a cross-overlap). A scope that
        # isn't a single pattern (raw / multi-path OR) can't be honored → report.
        scope, reason = native_placement(result.get("condition") or cond, _resolved_vpp(ir))
        if reason:
            _mark_result_non_convertible(ir, result, reason, expr, source_kind, source_id)
            return
        _warn_case_insensitive_native(ir, result.get("condition") or cond, scope, result)
        _record_native_effect(ir, scope, "compression", result.get("params", {}), result,
                              source_kind, source_id)
        return

    if rtype == "response_headers_policy":
        # A response-headers policy is native (per behavior) and — unlike a
        # viewer-response CFF — it applies to ERROR responses too (origin 4xx/5xx,
        # custom error pages), which a Cloudflare Response Header Transform also
        # covers (confirmed vs AWS docs, dual subagents — see memory
        # cdn-response-header-mechanism-facts). PHASE-1 NARROWING: RHP is faithful
        # ONLY for an UNCONDITIONAL/host-only STATIC set. A per-request condition
        # can't be carried by the RHP, and routing it to a viewer-response CFF
        # SILENTLY DROPS the header on all error responses / WAF blocks — that is a
        # known runtime gap, NOT an exact conversion. So report it (non-convertible)
        # instead of masking the gap as CFF success (reverses the round-9 fallback).
        # The processor emits this result type ONLY for a static SECURITY header (CORS
        # now routes to a viewer-response CFF marked LOSSY — cors_config isn't a faithful
        # static-set substitute and custom_headers_config rejects CORS names; the native
        # rhp_cors machinery stays for a FUTURE semantic CORS conversion, not this path).
        scope, reason = native_placement(result.get("condition"), _resolved_vpp(ir))
        if reason:
            _mark_result_non_convertible(
                ir, result,
                "a conditional/complex-scope response header can't be carried by a "
                "native Response Headers Policy, and a viewer-response CloudFront "
                "Function would silently NOT apply it to error responses (origin "
                "4xx/5xx, custom error pages, WAF blocks) that a Cloudflare rule "
                "covers — no faithful CloudFront equivalent",
                expr, source_kind, source_id)
            return
        _warn_case_insensitive_native(ir, result.get("condition"), scope, result)
        params = result["params"]
        _record_native_effect(ir, scope, "rhp_security", params, result, source_kind, source_id)
        return

    if rtype == "cache_setting":
        # status_code_ttl (per-status-code edge cache duration) has no CloudFront
        # equivalent — record it once, before the rule fans out to behaviors.
        if "status_code_ttl" in result.get("params", {}):
            _mark_status_code_ttl_non_convertible(ir, result, source_kind, source_id)
            result["params"].pop("status_code_ttl", None)

    if rtype == "cache_setting" and result.get("params", {}).get("bypass"):
        # Cache bypass = "don't serve this from cache; always go to origin".
        # CloudFront can't conditionally skip the cache at request time, so:
        #   - UNCONDITIONAL bypass (host-stripped condition is always/None) → the
        #     whole behavior never caches: use the managed CachingDisabled policy.
        #   - CONDITIONAL bypass (a real request-time predicate: cookie, path,
        #     query, …) → a viewer-request CFF forces a guaranteed cache MISS for
        #     matching requests by injecting a unique cache-buster header that is
        #     part of the cache key. Represented as a `cache_bypass` op so it runs
        #     through the normal viewer_request_ops placement + codegen.
        bcond = result.get("condition")
        # An UNPARSEABLE condition (raw_expression, no structured cond) must NOT
        # be treated as unconditional — that would disable caching for the WHOLE
        # behavior when the rule really only meant to bypass a specific subset
        # (e.g. any(uri.args["x"][*]=="v"), which we don't convert). Silent
        # over-bypass. Report it non-convertible instead.
        if result.get("raw_expression") and not bcond:
            _mark_cache_non_convertible(ir, result, expr, source_kind, source_id)
            return
        if bcond is None or bcond.get("always"):
            # Unconditional (after host-strip) → CachingDisabled on the scoped
            # behavior. Record as a native effect so it stacks in source order and
            # covers every behavior its path contains (a site-wide `*` bypass turns
            # caching off on every ordered behavior too — none inherit the default).
            path = _extract_path_from_result(result, cond, expr)
            _record_native_effect(ir, path, "caching_disabled", {}, result,
                                  source_kind, source_id, owned_key_segments=[["cache"]])
            return
        # Conditional → re-tag as a cache_bypass viewer-request op and fall
        # through to the generic viewer_request_ops placement below. This is re-tagged
        # HERE (not by a processor), so stamp the explicit EXACT status the generic tail
        # now requires — a conditional cache-buster CFF is a faithful conversion. CLEAR the
        # cache_setting params (bypass/ttl/…): the generator's cache_bypass branch reads NONE
        # of them (it injects the fixed cache-buster header), and the viewer-op contract rejects
        # any unknown param — a leftover `bypass` leaf would falsely ride the op (round-27
        # finding 2). The condition already carries what the CFF needs.
        result["type"] = "cache_bypass"
        result["params"] = {}
        result["outcome_status"] = OUTCOME_EXACT
        rtype = "cache_bypass"

    if rtype == "cache_setting":
        # OR cache rule: try to split into one behavior per path. OR is now a
        # structured {"logic":"or"} condition (no longer deferred to raw), so
        # read it from the condition. A raw_expression still means genuinely
        # unparseable — route that (and any non-splittable OR) to Lambda@Edge.
        result_cond = result.get("condition")
        if (result_cond and result_cond.get("logic") == "or") or \
           (result.get("raw_expression") and not result_cond):
            or_paths = _try_split_or_cache_paths(result_cond)
            if or_paths:
                # One native effect per path branch (each a single pattern); replay
                # stacks them in source order like any other cache effect.
                for path in or_paths:
                    _record_cache_effects(ir, path, result, domain_config, origin_content,
                                          source_kind, source_id)
                return
            # Non-splittable OR → can't be expressed as CloudFront path behaviors.
            _mark_cache_non_convertible(ir, result, expr, source_kind, source_id)
            return
        # Fan out to one *.ext effect per extension ONLY when the condition is
        # PURELY an extension set. A sibling scope (host eq x and ext in [...])
        # must NOT fan out — that would apply the cache setting to *.pdf on every
        # host, dropping the host scope. In that case fall through to the normal
        # single-path placement below (which keeps the host/path scope).
        result_cond = result.get("condition") or cond
        exts = _extract_extensions_from_condition(result_cond)
        if len(exts) > 1 and _condition_is_pure_extension(result_cond):
            for ext in exts:
                _record_cache_effects(ir, f"*.{ext}", result, domain_config, origin_content,
                                      source_kind, source_id)
            return
        # A cache setting is native (per behavior), so its condition MUST be
        # representable as a single path pattern. After host-stripping, a still-
        # compound scope (ip.src.country, a multi-field AND, a NOT) can't be —
        # applying it to `_extract_path_from_result`'s best-effort `*` would widen
        # it site-wide. Report non-convertible instead of silently dropping.
        if not _cache_cond_is_single_path(result_cond, _resolved_vpp(ir)):
            _mark_cache_non_convertible(ir, result, expr, source_kind, source_id)
            return
        path = _extract_path_from_result(result, cond, expr)
        _warn_case_insensitive_native(ir, result_cond, path, result)
        _record_cache_effects(ir, path, result, domain_config, origin_content,
                              source_kind, source_id)
        return

    if rtype == "cloud_connector":
        # A cloud connector switches the ORIGIN of a cache behavior (native).
        # Record as an ordered origin effect; replay re-points every behavior its
        # scope contains. A non-single-pattern scope → report (would re-point the
        # whole distribution or drop).
        scope, reason = native_placement(result.get("condition") or cond, _resolved_vpp(ir))
        if reason:
            _mark_result_non_convertible(ir, result, reason, expr, source_kind, source_id)
            return
        _warn_case_insensitive_native(ir, result.get("condition") or cond, scope, result)
        _record_native_effect(ir, scope, "origin", result.get("params", {}), result,
                              source_kind, source_id)
        return

    # Drop a redundant S3 origin-override. Cloudflare pointing at an S3 bucket
    # needs an Origin Rule that rewrites the Host header to the bucket name (S3
    # routes by Host). On CloudFront+OAC that handling is UNNECESSARY: OAC signs
    # the request (SigV4) and CloudFront sets Host to the origin (bucket) domain
    # automatically — re-setting it via cf.updateRequestOrigin is at best noise
    # and can interfere with signing. So for an S3 origin, drop an origin_override
    # that only re-points Host/origin at the bucket (no genuinely different,
    # non-S3 origin). A real cross-origin override (to a non-S3 host) is kept.
    if rtype == "origin_override" and domain_config.get("origin_type") == "s3":
        ov_origin = result.get("params", {}).get("origin_host") or ""
        if not ov_origin or _is_s3_host(ov_origin):
            # Redundant on CloudFront+OAC — the origin rule's intent (route to the S3 bucket with the
            # right Host) is achieved NATIVELY (OAC signs SigV4, CloudFront sets Host to the bucket
            # domain). So this is an EXACT NO-OP conversion, NOT an untracked drop: claim the whole
            # unit EXACT (exact_noop) so its source leaves aren't a silent drop the finalize gate flags.
            claim_decision(ir, _resolve_owned_keys(ir, source_kind, source_id, None),
                           OUTCOME_EXACT, exact_noop=True)
            return  # redundant on CloudFront+OAC — dropped (claimed EXACT no-op above)

    # Drop a no-op origin_override — an Origin Rule with no origin host, port,
    # host_header, or sni has nothing to convert. Keeping it would emit an empty
    # (no-op) CFF statement that then trips validate-js's origin_override
    # coverage check ("missing updateRequestOrigin").
    if rtype == "origin_override":
        p = result.get("params", {})
        if not (p.get("origin_host") or p.get("origin_port") or p.get("host_header") or p.get("sni")):
            return

    # viewer_request_ops or viewer_response_ops
    is_response = "response" in rtype
    path = _extract_path_from_result(result, cond, expr)
    beh = find_or_create_behavior(ir, path, domain_config, origin_content)

    # STATUS MUST BE EXPLICIT — NO fallback default (a `.get(..., EXACT)` here would be
    # the same implicit EXACT one layer up, and would silently mis-label a future LOSSY
    # processor as EXACT). Every artifact-producing result reaching this generic tail
    # MUST carry outcome_status from its processor; a missing one is a converter bug.
    if "outcome_status" not in result:
        raise LedgerError(
            f"converted result type {rtype!r} (rule {result.get('cf_source_rule')!r}) "
            f"reached generic viewer-op placement without an explicit outcome_status — "
            f"the processor must set it (EXACT, or LOSSY_WITH_WARNING + outcome_reason)")
    op_entry = _append_viewer_op(
        beh, "response" if is_response else "request",
        type=rtype,
        cf_source_rule=result.get("cf_source_rule", ""),
        description=result.get("description", ""),
        condition=result.get("condition"),
        raw_expression=result.get("raw_expression"),
        params=result.get("params", {}),
        scope_pattern=_compute_scope_pattern(result.get("condition")),
        seq=ir.get("_seq", 0),   # source-processing order (see make_empty_ir)
        source_kind=source_kind, source_id=source_id,
        owned_key_segments=result.get("owned_key_segments"),
        outcome_status=result["outcome_status"],
        outcome_reason=result.get("outcome_reason"))

    # Generate KVS entries for in_kvs conditions (IP list lookup). The IP-list KVS is a
    # SHARED artifact — several ops may test the same list — so pass THIS op's owner ref
    # (its REAL subset, not whole-unit: a partially-converted rule where only some headers
    # convert must not claim the un-converted leaves via its IP-list KVS entry). The op
    # carries its authoritative subset AND status; the IP-list contribution INHERITS the
    # referring op's status/reason (the shared entry itself has no global status — it can
    # serve an EXACT header and a LOSSY op at once). _append_kvs_entry merges by full
    # contribution so no referrer is lost and conflicting statuses both survive.
    _collect_kvs_ip_entries(ir, op_entry.get("condition"),
                            {"source_kind": op_entry["_source_kind"],
                             "source_id": op_entry["_source_id"],
                             "owned_key_segments": op_entry["_owned_key_segments"],
                             "outcome_status": op_entry["_outcome_status"],
                             "outcome_reason": op_entry["_outcome_reason"]})


def _collect_kvs_ip_entries(ir, condition, owner_ref):
    """Generate KVS entries for in_kvs conditions (IP list → KVS exists()). `owner_ref`
    is the source unit of the op whose condition this is; a shared IP-list entry
    accumulates every referring op's owner via _append_kvs_entry's dedup-merge."""
    if condition is None:
        return
    if "logic" in condition:
        for child in iter_condition_children(condition):
            _collect_kvs_ip_entries(ir, child, owner_ref)
        return
    if condition.get("op") in ("in_kvs", "not_in_kvs"):
        list_name = condition["value"]
        ips = condition.pop("kvs_ips", [])
        if not ips:
            return
        # A previously-collected list: MERGE this op's owner into the existing entries
        # (don't early-return, which would drop the later referrer's ownership), but do
        # NOT re-append the ip rows. _append_kvs_entry merges owners on a same key+value.
        ir["metadata"]["kvs_requirements"]["needs_ip_lists"] = True
        for ip in ips:
            _append_kvs_entry(ir, f"ip:{list_name}:{ip}", "1", [owner_ref])


def _try_split_or_cache_paths(condition):
    """Try to split a top-level OR condition into individual path patterns.

    Takes the STRUCTURED condition (OR is now parsed into {"logic":"or",...} —
    it is no longer deferred to raw text). Returns a list of CloudFront path
    patterns if the condition is an OR whose every branch is a single
    path-based leaf, or None otherwise (caller then routes to Lambda@Edge).
    """
    if not isinstance(condition, dict) or condition.get("logic") != "or":
        return None
    parts = condition.get("parts", [])
    if len(parts) < 2:
        return None
    paths = []
    for part in parts:
        # Each branch must be a single path leaf — a nested logic node or a
        # non-path field can't map to a per-path cache behavior.
        if "logic" in part:
            return None
        pp = extract_path_pattern_single(part)
        if not pp or pp == "*":
            return None  # branch doesn't yield a specific path
        paths.append(pp)
    return paths


def _extract_path_from_result(result, cond, expr):
    """Extract path pattern from a rule result's condition."""
    c = result.get("condition") or cond
    if c is None:
        return "*"
    if c.get("always"):
        return "*"
    if "logic" in c:
        # A top-level OR spans multiple paths — no single pattern represents it,
        # and picking the first branch would create a behavior at only one path
        # (a phantom scope). The shared CFF runs on the default behavior and
        # evaluates the full condition anyway, so use `*`. For AND, a path branch
        # IS the real scope (host eq x AND uri.path eq /a → /a), so keep the
        # first specific path. NOT has no "parts" (→ `*`).
        if c.get("logic") == "or":
            return "*"
        for p in c.get("parts", []):
            pp = extract_path_pattern_single(p)
            if pp and pp != "*":
                return pp
        return "*"
    return extract_path_pattern_single(c)


def _scope_leaf_is_case_insensitive_pattern(cond):
    """True if the SPECIFIC path-yielding leaf inside `cond` is a case-INSENSITIVE
    wildcard with cased letters. Recurses AND/OR/NOT so `uri.path wildcard /Admin/*
    AND header x==1` is caught (the wildcard leaf sits under an AND), which a
    top-level-only check misses."""
    if not isinstance(cond, dict):
        return False
    if "logic" in cond:
        return any(_scope_leaf_is_case_insensitive_pattern(c)
                   for c in iter_condition_children(cond))
    return _pattern_case_insensitive_letters(cond, extract_path_pattern_single(cond))


def _compute_scope_pattern(condition):
    """THE single source of truth for a viewer op / re-homed effect's CFF-ATTACH
    scope, computed ONCE from the full screened condition and stored on the op — no
    placement site may re-derive it (they drifted: the op tail, RHP re-home, and
    browser_ttl each computed scope differently, so a case-insensitive /Admin/*
    stayed /Admin/* on two of the three paths).

    Returns an EXACT CloudFront path pattern ONLY when the source match set equals
    that pattern's set — a case-SENSITIVE single path. Returns `"*"` (attach to
    EVERY behavior, the op self-gates in JS) when it can't prove that:
      - a case-INSENSITIVE `wildcard` with letters (CloudFront PathPattern is
        case-sensitive, so a `/admin/x` request routes to the default behavior, not
        the /Admin/* one — attaching only there silently drops it);
      - a top-level OR, a NOT, or any condition that doesn't reduce to one path
        (can still match requests served by ordered behaviors).
    """
    path = _extract_path_from_result({"condition": condition}, None, None)
    if path == "*":
        return "*"
    if _scope_leaf_is_case_insensitive_pattern(condition):
        return "*"
    return path


# The browser_ttl LOSSY reason — one constant so the op's _outcome_reason and the report
# warning (_mark_result_lossy) can't drift.
_BROWSER_TTL_LOSSY_REASON = (
    "browser_ttl (Cache-Control max-age to the viewer) is applied via a viewer-response "
    "function, which CloudFront does NOT run on origin 4xx/5xx, custom-error, or WAF-block "
    "responses — those responses will NOT carry the forced max-age that the Cloudflare "
    "rule would set")


def _split_leaf(leaf):
    """Split a `_configured` dotted leaf into (segments_tuple, value_or_None). The processor
    encodes a scalar leaf as `a.b.c=value`, a non-empty list as `a.b.c[]`, an empty container
    as bare `a.b.c` (cdn_rule_processors._leaf_paths). Comparing these by STRING prefix is
    wrong — `edge_ttl.default` startswith-matches `edge_ttl.default_extra`, and a consumed
    query path `include.all` matches `include.all_extra` — so leaf identity MUST be by SEGMENT.
    Value is split on the FIRST `=` (a value may itself contain `.`, so partition before
    splitting the path); segments never contain `=` (they're schema dict keys)."""
    core = leaf[:-2] if leaf.endswith("[]") else leaf
    path, eq, val = core.partition("=")
    segs = tuple(path.split(".")) if path else ()
    return segs, (val if eq else None)


def _ttl_owned_segments(result, family):
    """Owned leaf segments for an edge/browser TTL effect (`family` = 'edge_ttl' or
    'browser_ttl'): always [family, 'mode'], PLUS [family, 'default'] ONLY when the source
    actually carried a `default` leaf. The processor falls back to 0 for a missing default
    (cdn_rule_processors ~650), so an override_origin WITHOUT a default has NO
    /{family}/default inventory key — hinting it would FATAL. `_configured` records the
    present source leaves as dotted paths; match the `default` leaf by EXACT segments (a
    string-prefix test would spuriously fire on a hypothetical `{family}.default_*` sibling)."""
    segs = [[family, "mode"]]
    if any(_split_leaf(leaf)[0] == (family, "default")
           for leaf in result.get("_configured", [])):
        segs.append([family, "default"])
    return segs


def _record_cache_effects(ir, scope, result, domain_config, origin_content,
                          source_kind="rule", source_id=None):
    """Record a cache rule's NATIVE effects (edge TTL, cache-key) as ordered
    effects at `scope`, and emit its browser_ttl (a viewer-response op) directly.
    `source_kind`/`source_id` are the INTERNAL provenance forwarded to every native
    effect (so an id-less cache rule's effects still resolve to its {rule_type}#index
    unit — never rebuilt from the display cf_source_rule).

    Bypass is NOT handled here — _place_result intercepts every bypass cache rule
    (unconditional → caching_disabled effect; conditional → cache_bypass op), so
    only TTL / cache-key / browser_ttl reach here.
    """
    params = result.get("params", {})

    # A cache rule has SEVERAL independent settings; each native effect owns ONLY the EXACT
    # json-pointer LEAVES it converts — NOT the ancestor subtree, which would swallow an
    # un-converted sibling leaf (edge_ttl.status_code_ttl, cache_key.custom_key.cookie) that
    # the cache leaf-accounting reports NC. Precise leaves keep the EXACT claim honest.
    # edge_ttl owns mode + default WHEN PRESENT (an override_origin with no default falls
    # back to 0 and has NO /edge_ttl/default leaf — _ttl_owned_segments omits it, else the
    # hint would FATAL). Never status_code_ttl.
    if "edge_ttl_override" in params:
        _record_native_effect(ir, scope, "ttl_override",
                              {"ttl": params["edge_ttl_override"]}, result,
                              source_kind, source_id,
                              owned_key_segments=_ttl_owned_segments(result, "edge_ttl"))
    elif params.get("edge_ttl_respect_origin"):
        # respect_origin is a RESET back to factory TTL. It must be a real effect so
        # a LATER respect_origin rule overrides an EARLIER override_origin at the
        # same scope (Cloudflare last-match). Without this the earlier fixed TTL
        # would silently persist (reviewer F2). Owns ONLY /edge_ttl/mode (no default leaf).
        _record_native_effect(ir, scope, "ttl_respect_origin", {}, result,
                              source_kind, source_id, owned_key_segments=[["edge_ttl", "mode"]])

    # cache=true is a RESET of a prior cache=false at the same scope. bypass=True is
    # intercepted earlier (caching_disabled effect / cache_bypass op); an explicit
    # bypass=False here re-enables caching so a later cache=true beats an earlier
    # cache=false (reviewer F2 — was silently stuck disabled).
    if params.get("bypass") is False:
        _record_native_effect(ir, scope, "caching_enabled", {}, result,
                              source_kind, source_id, owned_key_segments=[["cache"]])

    # cache_key is TWO independent slots (per _apply_native_effect): the query-string
    # selector and the header list. Each owns ONLY the EXACT leaf it consumed — NOT the
    # whole query_string subtree (which would swallow an unknown sibling AND wrongly claim
    # the un-consumed include/exclude twin). The processor recorded the EXACT consumed path
    # (list-form → ["include"], object-form → ["include","all"]/["include","list"], …) in
    # cache_key_qs_consumed; own precisely that leaf.
    ck_query = {dst: params[src] for src, dst in (
        ("cache_key_qs", "query_strings"), ("cache_key_qs_list", "query_strings_list"),
        ("cache_key_qs_exclude", "query_strings_exclude")) if src in params}
    if ck_query:
        _record_native_effect(ir, scope, "cache_key", ck_query, result, source_kind,
                              source_id,
                              owned_key_segments=[["cache_key", "custom_key", "query_string"]
                                                  + params.get("cache_key_qs_consumed", [])])
    if "cache_key_headers" in params:
        _record_native_effect(ir, scope, "cache_key", {"headers": params["cache_key_headers"]},
                              result, source_kind, source_id,
                              owned_key_segments=[["cache_key", "custom_key", "header", "include"]])

    # browser_ttl (override_origin): Cloudflare forces the max-age in the
    # Cache-Control header sent to the VIEWER, independent of the edge TTL. A
    # viewer-response CFF replicates it for NORMAL (origin <400) responses — but that
    # function does NOT run on origin 4xx/5xx / custom-error / WAF-block responses,
    # whereas Cloudflare's rule would still set the header there. So this is a KNOWN
    # gap → LOSSY_WITH_WARNING (deployed, but not counted as a clean EXACT success),
    # NOT silently treated as faithful (Phase-1 honesty; mechanism-facts memory).
    if "browser_ttl_override" in params:
        beh = find_or_create_behavior(ir, scope, domain_config, origin_content)
        max_age = params["browser_ttl_override"]
        already = any(
            op.get("cf_source_rule") == result.get("cf_source_rule")
            and op.get("params", {}).get("name") == "cache-control"
            for op in beh["viewer_response_ops"]
        )
        if not already:
            _append_viewer_op(
                beh, "response",
                type="set_response_header",
                cf_source_rule=result.get("cf_source_rule", ""),
                description=f"{result.get('description', '')}: browser_ttl override",
                condition=result.get("condition"),
                raw_expression=result.get("raw_expression"),
                # LOWER the static Cache-Control value ONCE (round-27) — a fixed max-age literal.
                params={"name": "cache-control",
                        "value_lowered": lower_literal_value(f"max-age={max_age}", "response_header")},
                # Same single scope authority — a case-insensitive wildcard scope
                # must attach the browser_ttl CFF to all behaviors, not just `scope`.
                scope_pattern=_compute_scope_pattern(result.get("condition")),
                seq=ir.get("_seq", 0),
                # browser_ttl is a cache-rule leaf → owns just /browser_ttl (the rest of
                # the cache rule converts to native effects). source_id is the internal
                # unit id threaded from _place_result → _record_cache_effects. EXPLICIT
                # LOSSY status (the known viewer-response-CFF error-coverage gap below) —
                # this is decision metadata on the op, NOT inferred from "has artifact";
                # the coordinator will read it when the browser_ttl viewer-op channel is
                # wired (not this turn). Kept in sync with the _mark_result_lossy reason.
                source_kind=source_kind, source_id=source_id,
                # PRECISE leaves — mode (+ default WHEN PRESENT; an override with no default
                # falls back to 0 and has no /browser_ttl/default leaf). NOT the whole
                # browser_ttl subtree (would swallow an unknown sibling AND collide with the
                # cache leaf-accounting's NC). Mirrors edge_ttl via _ttl_owned_segments.
                owned_key_segments=_ttl_owned_segments(result, "browser_ttl"),
                outcome_status=OUTCOME_LOSSY,
                outcome_reason=_BROWSER_TTL_LOSSY_REASON)
            _mark_result_lossy(ir, result, _BROWSER_TTL_LOSSY_REASON)
    elif params.get("browser_ttl_respect_origin"):
        # A browser_ttl RESET back to the origin's Cache-Control. We can't faithfully
        # restore it: a viewer-response CFF would have to know the origin's original
        # value, but an earlier override CFF op / other AWS mechanism may already
        # have replaced it, and CloudFront gives no "unset to origin" primitive here.
        # Report rather than silently ignore the reset (round-9 #4).
        ir["cache_behaviors"][0]["non_convertible"].append({
            "cf_source_rule": result.get("cf_source_rule", ""),
            "description": result.get("description", ""),
            "reason": ("browser_ttl respect_origin (reset to the origin's Cache-Control) "
                       "has no faithful CloudFront equivalent — a viewer-response function "
                       "can't reliably restore the origin value once forced; apply the "
                       "browser cache policy at the origin instead."),
        })

    # EVERY-CONFIGURED-SETTING accounted, at LEAF granularity (round-10 #2). The
    # processor recorded every action_parameter LEAF path in `_configured`; a
    # top-level inventory would treat the whole cache_key/edge_ttl subtree as mapped
    # and hide a nested leaf the converter never consumed (cache_key.custom_key.
    # cookie.include, edge_ttl.mode=bypass_by_default). A leaf is accounted iff its
    # path starts with a prefix we ACTUALLY apply; anything else → non-convertible
    # with the exact leaf path, so a partially-dropped setting can't hide behind the
    # rule's other converted settings.
    # Each handled entry is (segments, required_value, subtree): match a `_configured` leaf
    # BY SEGMENT, never string prefix (`edge_ttl.default` must NOT swallow a hypothetical
    # `edge_ttl.default_extra`, and a consumed `include.all` must NOT swallow `include.all_extra`
    # — round-11 finding 2). required_value pins a mode discriminator (only override/respect_origin
    # are converted; `edge_ttl.mode=bypass_by_default` stays NC). subtree=True matches the leaf
    # AND its descendants (status_code_ttl is a list/subtree reported NC elsewhere; header.include
    # is a list leaf).
    _handled = [
        (("cache",), None, False),
        (("edge_ttl", "mode"), "override_origin", False),
        (("edge_ttl", "mode"), "respect_origin", False),
        (("edge_ttl", "default"), None, False),
        (("edge_ttl", "status_code_ttl"), None, True),   # already reported nc
        (("browser_ttl", "mode"), "override_origin", False),
        (("browser_ttl", "mode"), "respect_origin", False),
        (("browser_ttl", "default"), None, False),
        (("cache_key", "custom_key", "header", "include"), None, True),
    ]
    # query_string: mark ONLY the EXACT segment path the selector consumed as handled (as a
    # subtree, so the object-form scalar leaf under it counts) — NOT the whole query_string
    # subtree, so an unknown object-form sibling (query_string.include.future) still surfaces
    # as legacy-NC instead of silently vanishing.
    _qs_consumed = result.get("params", {}).get("cache_key_qs_consumed")
    if _qs_consumed:
        _handled.append(
            (("cache_key", "custom_key", "query_string") + tuple(_qs_consumed), None, True))
    def _accounted(leaf):
        segs, val = _split_leaf(leaf)
        for hsegs, hval, subtree in _handled:
            if hval is not None and val != hval:
                continue
            if segs == hsegs or (subtree and segs[:len(hsegs)] == hsegs):
                return True
        return False
    unhandled = sorted({leaf for leaf in result.get("_configured", []) if not _accounted(leaf)})
    if unhandled:
        ir["cache_behaviors"][0]["non_convertible"].append({
            "cf_source_rule": result.get("cf_source_rule", ""),
            "description": result.get("description", ""),
            "reason": (f"cache rule setting leaf(s) {unhandled} have no CloudFront "
                       "mapping and were not converted (other settings on the same "
                       "rule were)"),
        })


def _process_bulk_redirects(ir, hostname, apex, bulk_redirects, domain_config, origin_content):
    """Process bulk redirect items that match this domain."""
    kvs_entries = []
    owner_refs = []   # one per matching item — the shared CFF op is a MULTI-UNIT aggregate
    for list_name, items in bulk_redirects.items():
        for _idx, item in enumerate(items):
            rd = item.get("redirect", {})
            source = rd.get("source_url", "")
            include_subdomains = rd.get("include_subdomains", False)

            # Check if this redirect applies to this domain
            # source_url format: "hostname/path" (no scheme)
            source_host = source.split("/")[0] if "/" in source else source
            applies = False
            if source_host == hostname:
                applies = True
            elif include_subdomains and (
                hostname.endswith("." + source_host) or hostname == source_host
            ):
                applies = True

            if applies:
                # VALUE-INDEPENDENT source id via the uniform registrar: the item's own
                # id, else a stable list_name#index fallback — NOT the source_url (editing
                # the URL would change the id AND the /source_url leaf value). A non-string
                # id FATALs, a duplicate item id FATALs (same contract as every kind —
                # reviewer finding 2), rather than merging two items into one unit.
                item_id = _register_unit_id(ir, "bulk_redirect", item.get("id"),
                                            f"{list_name}#{_idx}")
                # Inventory: each matching redirect item is a source unit keyed on its
                # redirect params so L2 covers the bulk-redirect KVS artifacts too.
                ir.setdefault("_inventory", []).extend(
                    _inventory_keys_for("bulk_redirect", item_id, rd))

                # The CFF op reads ONLY these five fields; the shared op OWNS only those
                # (present ones), NOT the whole item — else an unknown leaf (e.g. a future
                # future_option.mode) would be falsely reported converted. Unknown leaves
                # are NC-claimed separately below. owned_key_segments hints are validated
                # against the inventory by the resolver, so only PRESENT supported fields.
                supported = ("source_url", "target_url", "status_code",
                             "preserve_query_string", "include_subdomains")
                owned_segs = [[f] for f in supported if f in rd]
                # Any leaf NOT under a supported field is non-convertible. Compare against
                # the item's actual inventory pointers (json-pointer scheme) so the split
                # is exact and value-independent.
                item_ptrs = [k[2] for k in _inventory_keys_for("bulk_redirect", item_id, rd)]
                supported_ptrs = {_key_path_to_pointer([f]) for f in supported}
                unknown_ptrs = [p for p in item_ptrs
                                if not any(p == s or p.startswith(s + "/")
                                           for s in supported_ptrs)]
                if unknown_ptrs:
                    claim_non_convertible(
                        ir, "bulk_redirect", item_id,
                        reason=("bulk redirect leaf(s) have no CloudFront equivalent "
                                "(only source_url/target_url/status_code/"
                                "preserve_query_string/include_subdomains convert)"),
                        description=f"bulk redirect item {item_id}",
                        owned_pointers=unknown_ptrs,
                        legacy_cf_source_rule="bulk_redirects")

                # If NOTHING converts (no supported field present), skip the KVS entry /
                # op ownership — the item's leaves are already NC-claimed above.
                if not owned_segs:
                    continue

                owner_refs.append({
                    "source_kind": "bulk_redirect", "source_id": item_id,
                    "owned_key_segments": owned_segs,   # ONLY the supported, present fields
                    "outcome_status": OUTCOME_EXACT, "outcome_reason": None})
                kvs_entries.append({
                    "source_url": source,
                    "target_url": rd.get("target_url", ""),
                    "status_code": rd.get("status_code", 301),
                    "preserve_query_string": rd.get("preserve_query_string", False),
                    "include_subdomains": include_subdomains,
                    "list_name": list_name,
                    "item_id": item_id,        # for the KVS entry's owner ref
                    "owned_segs": owned_segs,  # same supported fields as the CFF op ref
                })

    if kvs_entries:
        ir["metadata"]["kvs_requirements"]["needs_redirects"] = True
        # Convert to KVS key-value format: value="{status}|{preserve_qs}|{target}".
        # Key convention (must match the CFF lookup in cdn-generate-js):
        #   - exact:  "redirect:{source}"       matches only that exact host+path
        #   - wildcard: "redirect:.{source}"    (leading dot) matches that host
        #     AND any subdomain of it — written ONLY when include_subdomains=true.
        # The dot prefix is the include_subdomains marker: the CFF walks the
        # request host's parent suffixes against dotted keys, so a subdomain
        # request finds the ancestor's wildcard entry. Without this the flag was
        # silently dropped (key stored under the bare apex, never matched for a
        # subdomain request).
        for entry in kvs_entries:
            src = entry["source_url"]
            tgt = entry["target_url"]
            status = entry["status_code"]
            pqs = "1" if entry["preserve_query_string"] else "0"
            value = f"{status}|{pqs}|{tgt}"
            # This item's KVS entry (and its subdomain variant) are owned by the item's
            # unit — the SAME unit that owns the shared CFF op's owner ref above. Both are
            # artifacts of that one source key set; the future coordinator emits one claim
            # referencing both. owned_key_segments = the item's 5 supported fields.
            item_ref = {"source_kind": "bulk_redirect", "source_id": entry["item_id"],
                        "owned_key_segments": entry["owned_segs"],
                        "outcome_status": OUTCOME_EXACT, "outcome_reason": None}
            _append_kvs_entry(ir, f"redirect:{src}", value, [item_ref])
            if entry["include_subdomains"]:
                _append_kvs_entry(ir, f"redirect:.{src}", value, [item_ref])
        # Add bulk_redirect op after redirect/rewrite/origin ops (Cloudflare execution order)
        default_beh = ir["cache_behaviors"][0]
        # Find insertion point: after last redirect/rewrite/origin_override op
        insert_idx = 0
        for i, op in enumerate(default_beh["viewer_request_ops"]):
            if op["type"] in ("redirect", "rewrite", "origin_override"):
                insert_idx = i + 1
        # This ONE CFF op serves EVERY matching redirect item, so it's a MULTI-UNIT
        # aggregate: owner_refs carries one ref per item (not a single _source_id — that
        # would falsely attribute all items to one). The viewer-op artifact channel unions
        # them so each item's leaves trace to the shared op (the bulk-redirect aggregation
        # case). cf_source_rule stays the display "bulk_redirects".
        _append_viewer_op(
            default_beh, "request",
            type="bulk_redirect",
            cf_source_rule="bulk_redirects",
            description=f"Bulk redirects ({len(kvs_entries)} entries)",
            condition={"always": True},
            raw_expression=None,
            params={"entry_count": len(kvs_entries)},
            scope_pattern="*",  # unconditional zone-wide → overlaps every behavior
            seq=ir.get("_seq", 0) + 1,  # after all rules (Cloudflare runs bulk late)
            owner_refs=owner_refs,
            insert_index=insert_idx)


def _process_managed_transforms(ir, managed_transforms, default_beh):
    """Process Managed Transforms (True-Client-IP, security headers)."""
    req_headers = managed_transforms.get("managed_request_headers", [])
    resp_headers = managed_transforms.get("managed_response_headers", [])

    # Inventory EVERY enabled managed transform (kind 'managed_transform', unit =
    # /$action) FIRST — not just the two we know how to convert — so an unknown/future
    # enabled transform has a source key L2 can mark NC instead of silently vanishing.
    # Each id goes through _register_unit_id (uniform contract): a non-string id FATALs,
    # a missing/dup id gets a stable per-list `mt_req#{i}` / `mt_resp#{i}` fallback (so
    # two id-less or dup-id transforms don't merge — reviewer finding 2). Map each
    # enabled transform (by python identity) to its resolved unit id for the ops below.
    unit_of = {}
    for i, h in enumerate(req_headers):
        if h.get("enabled"):
            uid = _register_unit_id(ir, "managed_transform", h.get("id"), f"mt_req#{i}")
            unit_of[id(h)] = uid
            ir.setdefault("_inventory", []).append(("managed_transform", uid, "/$action"))
    for i, h in enumerate(resp_headers):
        if h.get("enabled"):
            uid = _register_unit_id(ir, "managed_transform", h.get("id"), f"mt_resp#{i}")
            unit_of[id(h)] = uid
            ir.setdefault("_inventory", []).append(("managed_transform", uid, "/$action"))

    for h in req_headers:
        if h.get("enabled") and h.get("id") == "add_true_client_ip_headers":
            # LOWER the viewer-IP value as a DYNAMIC intrinsic (round-27), NOT a `$viewer_ip`
            # string sentinel. `to_string(ip.src)` is the documented Cloudflare-legal way to
            # stringify the client IP; it goes through the SAME contract gate as any dynamic
            # value and the generator renders it to String(event.viewer.ip) (CFF) /
            # String(request.clientIp) (Lambda). A dynamic header value carries
            # empty_behavior=delete_header (the slot invariant; the IP is never empty so the
            # delete-on-empty guard never fires — same as any dynamic header). A reason string
            # here means the parser regressed on a hardcoded-good expression — fail loud.
            tci_lowered = lower_dynamic_value("to_string(ip.src)", "request_header",
                                              LOWERED_EMPTY_DELETE_HEADER, source=False)
            if not isinstance(tci_lowered, dict):
                raise LedgerError(
                    "True-Client-IP: lowering 'to_string(ip.src)' failed — the parser no longer "
                    f"accepts the viewer-IP intrinsic ({tci_lowered!r}). Fix the contract; the "
                    "producer must emit a valid LoweredValue.")
            _append_viewer_op(
                default_beh, "request",
                type="set_request_header",
                cf_source_rule="managed_transform_true_client_ip",
                description="Managed Transform: True-Client-IP",
                condition={"always": True},
                raw_expression=None,
                params={"name": "True-Client-IP", "value_lowered": tci_lowered},
                scope_pattern="*",  # unconditional zone-wide → overlaps every behavior
                seq=ir.get("_seq", 0) + 1,
                # provenance = the managed_transform unit (its /$action), not the display id
                source_kind="managed_transform", source_id=unit_of[id(h)],
                outcome_status=OUTCOME_EXACT)   # True-Client-IP is an EXACT conversion

    for h in resp_headers:
        if h.get("enabled") and h.get("id") == "add_security_headers":
            # Zone-wide managed security headers — record as `*`-scoped native
            # effects so replay applies them to EVERY behavior (ordered behaviors
            # don't inherit the default's RHP). Recorded at the head of the effect
            # log with operation="add" (setdefault semantics: a later explicit rule
            # for the same header still wins on replay order).
            src = {"cf_source_rule": "managed_transform_security_headers",
                   "description": "Managed Transform: security headers"}
            # Both effects share the one /$action unit — the "managed transform /$action
            # owns all effects it generates" aggregation. source_id = the registered unit.
            mt_id = unit_of[id(h)]
            _record_native_effect(ir, "*", "rhp_security",
                                  {"name": "X-Content-Type-Options", "value": "nosniff",
                                   "operation": "add", "_managed": True}, src,
                                  source_kind="managed_transform", source_id=mt_id)
            _record_native_effect(ir, "*", "rhp_security",
                                  {"name": "X-Frame-Options", "value": "SAMEORIGIN",
                                   "operation": "add", "_managed": True}, src,
                                  source_kind="managed_transform", source_id=mt_id)

    # Every OTHER enabled managed transform (e.g. add_visitor_location_headers) is inventoried above
    # but has NO CloudFront-equivalent managed transform — mark it NON_CONVERTIBLE (claim + report) so
    # it cannot silently vanish (the stated intent of inventorying every MT). The two ids handled
    # above already produce their own claims (True-Client-IP = EXACT viewer op; security headers =
    # native RHP effect), so skip them here.
    _HANDLED_MT_IDS = {"add_true_client_ip_headers", "add_security_headers"}
    for h in req_headers + resp_headers:
        if h.get("enabled") and h.get("id") not in _HANDLED_MT_IDS:
            claim_non_convertible(
                ir, "managed_transform", unit_of[id(h)],
                reason=(f"Cloudflare managed transform {h.get('id')!r} has no CloudFront-equivalent "
                        "managed transform; apply the equivalent request/response header logic "
                        "explicitly if needed"),
                description=f"Managed Transform: {h.get('id')}")


def _mark_cache_non_convertible(ir, result, expr=None, source_kind="rule", source_id=None):
    """Record a cache rule whose scope can't be expressed as a CloudFront path
    behavior (after host-stripping) as non-convertible, on the default behavior.

    CloudFront cache settings attach to a path-matched cache behavior; a scope
    like ip.src.country, a multi-field AND, or a NOT has no single path pattern.
    There is no working Lambda@Edge conditional-cache generator (the
    origin_response template only emits error pages), so we surface the rule in
    the conversion report instead of silently dropping it or mis-applying it
    site-wide.

    DEFERRED CHANNEL (next increment): still a DIRECT legacy-NC write — it does NOT yet
    route through claim_non_convertible. It ACCEPTS the internal provenance
    (`source_kind`/`source_id`) now so the cache-NC wiring can adopt it without
    re-plumbing every call site. A whole-scope reject is whole-unit (no owned_pointers).
    Not persisted yet — the params are threaded but unused until this channel wires."""
    del source_kind, source_id  # accepted for the next increment; not yet routed
    ir["cache_behaviors"][0]["non_convertible"].append({
        "cf_source_rule": result.get("cf_source_rule", ""),
        "description": result.get("description", ""),
        "reason": ("Cache rule condition cannot be expressed as a CloudFront "
                   "cache behavior (path-only). Scope: "
                   f"{result.get('raw_expression') or expr or '(complex)'}. "
                   "Apply the cache policy manually to the matching behavior, "
                   "or handle at the origin."),
    })


def _mark_status_code_ttl_non_convertible(ir, result, source_kind="rule", source_id=None):
    """Record status_code_ttl (per-status-code edge cache duration) as
    non-convertible. Recorded ONCE per rule on the default behavior.

    Cloudflare's edge_ttl.status_code_ttl sets different EDGE cache TTLs per HTTP
    status code / range (e.g. 200→1h, 404→1s, 5xx→0s). CloudFront can't:
    - a cache policy's min/default/max TTL is status-code-agnostic;
    - Custom Error Responses cover only 4xx/5xx, with a MINIMUM (not exact) TTL,
      and never 2xx.
    CFF can't help either — it controls response headers, not CloudFront's edge
    caching decision. So this is genuinely non-convertible.

    DEFERRED CHANNEL (next increment): still a DIRECT legacy-NC write; accepts internal
    provenance now (this is a SUB-LEAF NC — the next increment claims the
    /edge_ttl/status_code_ttl pointer, not the whole unit). Params threaded but unused."""
    del source_kind, source_id  # accepted for the next increment; not yet routed
    ir["cache_behaviors"][0]["non_convertible"].append({
        "cf_source_rule": result.get("cf_source_rule", ""),
        "description": f"{result.get('description', '')}: status_code_ttl",
        "reason": ("Cloudflare sets different edge cache TTLs per response status "
                   "code. CloudFront cache-policy TTL is status-code-agnostic, and "
                   "Custom Error Responses only cover 4xx/5xx with a minimum-TTL "
                   "(not exact, not 2xx). Handle per-status caching at the origin "
                   "via Cache-Control."),
    })


def _process_default_cache_behavior(ir, hostname, domain_config, origin_content, all_rules, apex):
    """Implement Cloudflare's implicit default cache behavior via Lambda@Edge origin-response.

    Three paths based on how many extensions have custom TTLs:
    - 0 custom TTL extensions → L@E with empty custom_ttl_map (uses default 7200s)
    - ≤20 custom TTL extensions → individual cache behaviors per extension + L@E (empty map)
    - >20 custom TTL extensions → L@E with custom_ttl_map (consolidated)
    """
    # Collect extension-based cache rules that apply to this domain
    custom_ttl_map = {}  # extension → ttl_seconds
    bypass_extensions = set()

    for rule in all_rules.get("cache", []):
        if not rule.get("enabled", True):
            continue
        expr = rule.get("expression", "true")
        cond, raw_expr = parse_expression(expr)
        hosts = extract_host_filter(cond, raw_expr or expr)
        if not rule_applies_to_domain(hosts, hostname, apex):
            continue

        # Only look at extension-based rules
        extensions = _extract_extensions_from_condition(cond)
        if not extensions:
            continue

        ap = rule.get("action_parameters", {})
        if not ap.get("cache", True):
            # Bypass cache for these extensions — they override default caching
            bypass_extensions.update(ext.lower() for ext in extensions)
            continue

        edge_ttl = ap.get("edge_ttl", {})
        if edge_ttl.get("mode") == "override_origin":
            ttl = edge_ttl.get("default", 7200)
            for ext in extensions:
                custom_ttl_map[ext.lower()] = ttl

    # Remove bypassed extensions from custom_ttl_map
    for ext in bypass_extensions:
        custom_ttl_map.pop(ext, None)

    # Determine path
    custom_count = len(custom_ttl_map)

    if custom_count <= 20:
        # Path 1 (0 custom) or Path 2 (≤20 custom):
        # Create individual cache behaviors for custom TTL extensions
        for ext, ttl in sorted(custom_ttl_map.items()):
            ext_path = f"*.{ext}"
            beh = find_or_create_behavior(ir, ext_path, domain_config, origin_content)
            # override_origin forces this exact TTL — min=default=max, same
            # reasoning as _apply_cache_setting (a >86400s value would otherwise
            # exceed the behavior's default max_ttl and fail CloudFront's API).
            beh["cache_policy"]["ttl"]["min"] = ttl
            beh["cache_policy"]["ttl"]["default"] = ttl
            beh["cache_policy"]["ttl"]["max"] = ttl

        # L@E with empty map — handles remaining ~70 extensions at default 7200s
        ir["metadata"]["lambda_edge"]["origin_response"] = {
            "type": "default_cache",
            "custom_ttl_map": {},
        }
    else:
        # Path 3 (>20 custom): consolidate into L@E custom_ttl_map
        ir["metadata"]["lambda_edge"]["origin_response"] = {
            "type": "default_cache",
            "custom_ttl_map": custom_ttl_map,
        }


def _extract_extensions_from_condition(condition):
    """Extract the file extensions a rule POSITIVELY matches, if extension-based.

    Collects from ALL positive branches — an `ext in {pdf} or ext in {jpg}` rule
    covers BOTH pdf and jpg, so returning only the first branch's `[pdf]` would
    drop jpg from the custom-TTL map. But a NEGATED set (`not (ext in {pdf})`,
    `ext not_in {pdf}`) matches everything EXCEPT those, so its extensions must
    NOT be collected — doing so would apply the TTL/bypass to exactly the
    extensions the rule excludes (a full inversion). So descend AND/OR `parts`
    only; do NOT descend a NOT node's `item`, and skip negated leaf ops.
    """
    if condition is None:
        return []
    if "logic" in condition:
        if condition["logic"] == "not":
            return []  # negated: matched set is the complement, not these exts
        exts = []
        for child in condition.get("parts", []):
            for e in _extract_extensions_from_condition(child):
                if e not in exts:
                    exts.append(e)
        return exts
    if condition.get("field") == "uri.path.extension":
        if condition.get("op") == "in":
            return list(condition.get("value", []))
        if condition.get("op") == "eq" and isinstance(condition.get("value"), str):
            return [condition["value"]]
    return []


def _cache_cond_is_single_path(condition, vpp=None):
    """True if a cache-rule condition can be represented by ONE specific
    CloudFront path pattern (so applying the setting to one behavior is faithful).
    `vpp` is the resolved viewer_protocol_policy for the scope (used only for the
    full_uri https-scheme check — see below); None = assume redirect-to-https.

    Unconditional (→ default `*` behavior) is fine. Otherwise the leaf must
    actually yield a SPECIFIC path pattern — verified by asking
    extract_path_pattern_single and rejecting `*`. This catches leaves that are
    "path-ish" but don't reduce to a concrete pattern, e.g.
    `uri.path.extension eq "pdf"` (only `in [one]` yields `*.pdf`; `eq` → `*`),
    which would otherwise be mis-applied site-wide. A logic node (AND/OR/NOT) or
    a non-path field is never single-path.
    """
    if condition is None or condition.get("always"):
        return True
    if "logic" in condition:
        return False
    # full_uri is included: a `full_uri wildcard "https://host/files/*"` leaf
    # reduces to the path pattern /files/* (extract_path_pattern_single reads its
    # path_pattern), so it IS a single-path scope for this host's distribution.
    if condition.get("field") not in ("uri.path", "uri", "uri.path.extension", "full_uri"):
        return False
    pattern = extract_path_pattern_single(condition)
    if pattern == "*":
        return False
    # A CloudFront path pattern matches ONLY the URI path — never the query string.
    # A full_uri that pins a query (`?`) can't be reduced to a path pattern (the `?`
    # would be a literal/path wildcard char, silently mis-matching), so reject it.
    # SCHEME (confirmed vs AWS docs by dual subagents): CloudFront selects the cache
    # behavior FIRST, then applies THAT behavior's ViewerProtocolPolicy. Scheme is
    # never a routing/matching key (no PathPattern or behavior setting keys off
    # http-vs-https) — it's only enforced by the VPP. So under redirect-to-https/
    # https-only, an http viewer request to a matched behavior gets a 301/redirect
    # instead of being served, i.e. every request the behavior actually SERVES is
    # https. Thus an `https://`-pinned full_uri reduces faithfully to a path pattern
    # (scheme already guaranteed — redundant), while an `http://`-pinned rule matches
    # ~no served traffic → a path pattern can't express it. (Caveat: under allow-all
    # VPP both schemes are served and a behavior can't distinguish them, so an https
    # rule mapped to path-only would widen to http — handled below.)
    if condition.get("field") == "full_uri":
        scheme = condition.get("scheme")
        # http-only is never a CloudFront path (scheme isn't a routing key; under
        # redirect-to-https http gets the redirect, not the behavior's content).
        if scheme == "http":
            return False
        # https-only is faithful ONLY when the effective VPP redirects/forces https
        # (then all served traffic is https — scheme redundant). Under allow-all,
        # http is served too, so dropping the scheme to a path would WIDEN the rule
        # to http traffic (reviewer F5). `vpp` is the resolved viewer_protocol_policy
        # for this scope; None means "not yet known" → assume the default
        # redirect-to-https (safe/common) rather than reject.
        if scheme == "https" and vpp == "allow-all":
            return False
        if "?" in (condition.get("path_pattern") or ""):
            return False
    if "?" in pattern:
        return False
    return True


def _pattern_case_insensitive_letters(condition, pattern):
    """True if this native path pattern comes from a CASE-INSENSITIVE Cloudflare
    match (`wildcard`, incl. full_uri wildcard) AND contains cased letters — so the
    case-SENSITIVE CloudFront behavior would miss case variants Cloudflare matched.
    Per Cloudflare docs `eq`/`starts_with`/`ends_with`/`strict wildcard` are already
    case-sensitive (faithful); only plain `wildcard` is case-insensitive. Used to
    emit a NON-fatal case-difference warning — the rule is still converted natively
    (user's call), the divergence is surfaced in the report, not silently dropped."""
    if condition.get("op") != "wildcard":
        return False
    return any(c.isalpha() for c in pattern or "")


def _is_pure_host_routing(condition):
    """True if `condition` is ENTIRELY host-routing leaves the router consumed —
    including an OR of them (`host eq a or host eq b`), which _strip_host_condition
    deliberately leaves intact (the classifier already routed it). After routing,
    such a condition is unconditional on each distribution it reached, so a native
    mechanism can honor it globally on that distribution. A full_uri leaf is NOT
    pure host-routing (its path part still matters). Fixes the pure-host-OR
    false-negative."""
    if condition is None or condition.get("always"):
        return True
    if "logic" in condition:
        if condition["logic"] == "not":
            return _is_pure_host_routing(condition.get("item"))
        parts = condition.get("parts", [])
        return bool(parts) and all(_is_pure_host_routing(p) for p in parts)
    return host_leaf_is_routing(condition)


def native_placement(condition, vpp=None):
    """The placement decision for a rule mapped to a NATIVE CloudFront mechanism
    (distribution setting / cache-behavior setting / response-headers policy /
    compression / cloud-connector origin) — mechanisms that can only be scoped by
    a single path pattern, NOT by a per-request predicate (header/cookie/geo/…).

    THE INVARIANT (was enforced only in the cache_setting branch; this generalizes
    it to every native mechanism): after host-routing is consumed, the condition
    must reduce to ONE CloudFront path pattern, else the mechanism can't carry it
    faithfully and it must be reported non-convertible — never silently placed on
    `*` (which widens a scoped setting site-wide) or dropped.

    Returns (path, None) when placeable — `path` is the pattern to attach to
    (`*` for unconditional / pure-host-routing) — or (None, reason) when the
    condition can't be represented, so the caller marks it non-convertible.
    `condition` must already be host-stripped (the caller strips before placing).
    `vpp` is the resolved viewer_protocol_policy (for the full_uri https check)."""
    if _is_pure_host_routing(condition):
        return "*", None
    if _cache_cond_is_single_path(condition, vpp):
        return extract_path_pattern_single(condition), None
    return None, ("condition cannot be scoped to a single CloudFront path pattern "
                  "(a native cache/behavior/header/compression/origin setting can't "
                  "be gated per-request on headers/cookies/geo or a multi-path OR)")


def _condition_is_pure_extension(condition):
    """True if the condition is ONLY a uri.path.extension test (a single leaf,
    or an OR of extension leaves) — with no sibling scope such as a host or path.

    Per-extension fan-out (one *.ext behavior each) is only safe when the whole
    condition is the extension set. If a host/path scope sits alongside it (an
    AND), fanning out would drop that scope and apply the setting site-wide.
    """
    if not isinstance(condition, dict):
        return False
    if "logic" in condition:
        # Only an OR of pure-extension branches stays pure; an AND has a sibling.
        if condition.get("logic") != "or":
            return False
        parts = condition.get("parts", [])
        return bool(parts) and all(_condition_is_pure_extension(p) for p in parts)
    return condition.get("field") == "uri.path.extension"


# ── main ─────────────────────────────────────────────────────────────────────

def _result(status, code, **fields):
    """Emit a ---RESULT--- via the shared cdn_common.emit_result, then exit.

    Keeps the positional `code` because this stage's PARTIAL maps to exit 1
    (retry-failed-domains), NOT the standard 3 — so the exit code is passed
    explicitly rather than derived from STATUS. Multi-line values (FAILED_ITEMS)
    are passed as a plain list; emit_result owns the indentation.
    """
    emit_result(status, exit_code=code, **fields)


def main():
    if len(sys.argv) < 3:
        print("Usage: cdn-preprocess.py <config_path> <output_dir> [--domain DOMAIN]",
              file=sys.stderr)
        _result("FATAL", 2, ACTION="FIX",
                CONTEXT="Usage: cdn-preprocess.py <config_path> <output_dir> [--domain DOMAIN]")

    config_path = os.path.expanduser(sys.argv[1])
    output_dir = os.path.expanduser(sys.argv[2])
    single_domain = None
    if "--domain" in sys.argv:
        idx = sys.argv.index("--domain")
        if idx + 1 < len(sys.argv):
            single_domain = sys.argv[idx + 1]

    # Load domain_scope.json
    scope_path = os.path.join(output_dir, "domain_scope.json")
    if not os.path.exists(scope_path):
        print(f"ERROR: {scope_path} not found", file=sys.stderr)
        _result("FATAL", 2, ACTION="FIX",
                CONTEXT=f"domain_scope.json not found at {scope_path}. Run Stage 1 "
                        "(cdn-parse-dns.py) first.")
    with open(scope_path) as f:
        domain_scope = json.load(f)

    domains = domain_scope.get("domains", [])
    if single_domain:
        domains = [d for d in domains if d["hostname"] == single_domain]
        if not domains:
            print(f"ERROR: domain {single_domain} not found in domain_scope.json",
                  file=sys.stderr)
            _result("FATAL", 2, ACTION="FIX",
                    CONTEXT=f"--domain {single_domain} is not in domain_scope.json")

    # Find zone directory
    zone_dir = find_zone_dir(config_path)
    if not zone_dir:
        print(f"ERROR: no zone directory with DNS.txt found under {config_path}",
              file=sys.stderr)
        _result("FATAL", 2, ACTION="FIX",
                CONTEXT=f"No zone directory with DNS.txt found under {config_path}")

    # Load all rule files (once)
    all_rules = {}
    for rule_type, filename in RULE_FILES.items():
        if rule_type == "managed_transforms":
            continue
        path = os.path.join(zone_dir, filename)
        rules = load_json_file(path)
        if rules and isinstance(rules, list):
            all_rules[rule_type] = rules
        else:
            all_rules[rule_type] = []

    # Cloud Connector (different JSON format)
    cc_path = os.path.join(zone_dir, CLOUD_CONNECTOR_FILE)
    cc_rules = load_json_file(cc_path)
    all_rules["cloud_connector"] = cc_rules if isinstance(cc_rules, list) else []

    # Load account-level data
    ip_lists = load_ip_lists(config_path)
    bulk_redirects = load_bulk_redirect_items(config_path)
    managed_transforms = load_managed_transforms(zone_dir)

    # Ignored-feature scan (Block 3): ONE observational pass over the zone backup for active
    # Cloudflare features the CDN pipeline doesn't read. Attached to each domain IR (zone-level, so
    # identical across this zone's domains) → finalize aggregates + de-dups by feature across domains
    # and, in a multi-zone run, across zones. Never raises; does NOT feed the ledger or completeness.
    ignored_features = scan_ignored_features(zone_dir)

    # Process each domain
    acc_dir = os.path.join(output_dir, "ir", "accumulator")
    os.makedirs(acc_dir, exist_ok=True)

    success = 0
    failed = []
    for domain_config in domains:
        hostname = domain_config["hostname"]
        try:
            ir = process_domain(
                hostname, domain_config, all_rules, ip_lists,
                bulk_redirects, managed_transforms,
            )
            ir["metadata"]["ignored_features"] = ignored_features
            out_path = os.path.join(acc_dir, f"{hostname}.json")
            with open(out_path, "w") as f:
                json.dump(ir, f, indent=2, ensure_ascii=False)
            beh_count = len(ir["cache_behaviors"])
            ops_count = sum(
                len(b["viewer_request_ops"]) + len(b["viewer_response_ops"])
                for b in ir["cache_behaviors"]
            )
            nc_count = sum(len(b["non_convertible"]) for b in ir["cache_behaviors"])
            print(f"OK: {hostname} → {beh_count} behaviors, {ops_count} ops, {nc_count} non-convertible")
            success += 1
        except Exception as e:
            err_path = os.path.join(acc_dir, f"{hostname}.error.json")
            with open(err_path, "w") as f:
                json.dump({"hostname": hostname, "error": str(e)}, f, indent=2)
            print(f"FAIL: {hostname} → {e}", file=sys.stderr)
            failed.append(hostname)

    # Summary
    total = len(domains)
    print(f"\n{'='*60}")
    print(f"Processed {success}/{total} domains successfully")
    if failed:
        print(f"Failed domains: {', '.join(failed)}")

    # FAILED_ITEMS is a list — emit_result indents each line (no hand "\n  ").
    failed_items = [f"{h}: see {h}.error.json" for h in failed]
    if success == 0:
        # Nothing converted — every domain raised. Each has a
        # {hostname}.error.json in the accumulator with the traceback.
        _result("FATAL", 2, ACTION="FIX", FAILED=len(failed),
                FAILED_ITEMS=failed_items,
                CONTEXT=f"All {total} domains failed preprocessing — likely a bad "
                        "config path or a pipeline bug, not a per-domain issue.")
    elif failed:
        # Retry command mirrors SKILL.md Stage 3: re-run with --domain for the
        # failed subset; if retry also fails, mark those SKIPPED and continue.
        retry_domains = ",".join(failed)
        _result("PARTIAL", 1, SUCCEEDED=success, FAILED=len(failed),
                FAILED_ITEMS=failed_items,
                ACTION="RETRY_FAILED",
                COMMAND=f'python3 cdn-preprocess.py "{config_path}" "{output_dir}" '
                        f'--domain {retry_domains}')
    else:
        _result("OK", 0, DOMAINS=total, PROCESSED=success,
                OUTPUT_DIR=acc_dir)


if __name__ == "__main__":
    main()
