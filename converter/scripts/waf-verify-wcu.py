#!/usr/bin/env python3
"""waf-verify-wcu.py — Reconcile rule-group Capacity against AWS CheckCapacity.

The pipeline generates the CloudFormation using a LOCAL WCU calculator that is
proven exact against CheckCapacity. This script is an OPTIONAL pre-deploy safety
net: given an AWS profile, it asks AWS for the authoritative WCU of every
referenced rule group and, if the declared `Capacity` differs, rewrites ONLY
that integer field. It NEVER touches a rule's `Rules`/`Statement` — a hash guard
over each group's Rules asserts zero logic change — so it cannot introduce a
behavioral bug. It also refreshes the managed-rule-group WCU reference numbers
via DescribeManagedRuleGroup (those only affect the informational per-WebACL WCU
total, never a declared field).

Why a rule group's Capacity matters: it is required and immutable at create time.
If declared < actual, CreateRuleGroup is rejected at deploy. If declared >
actual, deploy succeeds but the WebACL's WCU (and cost) is overstated. AWS does
not declare a WebACL capacity — AWS computes it — so only rule groups carry a
number we must get right.

Usage:
    python3 waf-verify-wcu.py <output_dir> --profile <aws-profile> [--region us-east-1]

Needs the AWS CLI on PATH and a profile with wafv2:CheckCapacity,
wafv2:DescribeManagedRuleGroup, and permission to create/delete a temporary IP
set + regex pattern set (used as stand-ins so CheckCapacity accepts the rules —
WCU depends on a statement's SHAPE, not the referenced ARN's contents).

Exit codes: 0 = verified (reconciled if needed), 2 = fatal (bad input / no
creds / AWS error), 3 = a rule group is over the 5000-WCU hard cap (cannot
deploy as-is). Follows ~/.claude/SCRIPT_STANDARDS.md.
"""
import base64
import copy
import hashlib
import json
import os
import subprocess
import sys

SCOPE = "CLOUDFRONT"
RULE_GROUP_WCU_CAP = 5000  # AWS hard cap per rule group

# Throwaway resources CheckCapacity can resolve (real ARNs required; a dummy ARN
# → WAFNonexistentItemException). WCU depends on statement shape, not contents.
_TMP_IPSET_NAME = "wafverify-tmp-ipset"
_TMP_REGEX_NAME = "wafverify-tmp-regex"


def _fail(context, action="FIX", command=""):
    """Emit a FATAL ---RESULT--- and exit 2."""
    print("\n---RESULT---\nSPEC: 1\nSTATUS: FATAL")
    print(f"ACTION: {action}")
    if command:
        print(f"COMMAND: {command}")
    print(f"CONTEXT: {context}")
    sys.exit(2)


def _aws(args, profile, region, check=True, parse_json=True):
    """Run an `aws` CLI command; return parsed JSON (or raw text)."""
    cmd = ["aws"] + args + ["--profile", profile, "--region", region]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError((r.stderr or r.stdout or "").strip())
    if not parse_json:
        return r.stdout
    try:
        return json.loads(r.stdout) if r.stdout.strip() else {}
    except json.JSONDecodeError:
        raise RuntimeError((r.stderr or r.stdout or "").strip())


# ── Template discovery ────────────────────────────────────────────────────────

def _load_templates(output_dir):
    """Return [(path, template_dict), ...] for every CFN file in output_dir.

    Handles both the single-file (waf-cloudformation.json) and the split layout
    (waf-cloudformation-ipsets.json + waf-cloudformation-webacls-N.json). The
    .readable.json is skipped — it's a pretty-printed copy of the same content.
    """
    single = os.path.join(output_dir, "waf-cloudformation.json")
    if os.path.exists(single):
        with open(single) as f:
            return [(single, json.load(f))]
    templates = []
    for fn in sorted(os.listdir(output_dir)):
        if fn.startswith("waf-cloudformation-") and fn.endswith(".json") \
                and not fn.endswith(".readable.json"):
            path = os.path.join(output_dir, fn)
            with open(path) as f:
                templates.append((path, json.load(f)))
    return templates


def _rules_hash(rules):
    """Stable hash of a rule group's Rules — used to prove we only touched
    Capacity, never the rules themselves."""
    return hashlib.sha256(
        json.dumps(rules, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


# ── CheckCapacity ─────────────────────────────────────────────────────────────

def _substitute_refs(rules, ipset_arn, regex_arn):
    """Deep-copy `rules`, replacing every ref ARN with a real throwaway ARN and
    base64-encoding ByteMatch SearchStrings (both required by the CLI). WCU
    depends on statement SHAPE, so the substituted values don't change the
    result. Label-match Fn::Sub keys are collapsed to a plain string (the WCU
    cost of a LabelMatch is 1 regardless of the key)."""
    def walk(o):
        if isinstance(o, dict):
            if "Fn::GetAtt" in o:
                lid = o["Fn::GetAtt"][0].lower()
                return regex_arn if "regex" in lid else ipset_arn
            if "Fn::Sub" in o:
                # Account segment is a non-numeric placeholder on purpose: a label
                # match's WCU is 1 regardless of the key, and CheckCapacity accepts
                # a non-12-digit account segment here (verified live) — so this
                # avoids embedding a 12-digit-account-id-shaped string that trips
                # secret scanners, with zero effect on the computed capacity.
                return "awswaf:PLACEHOLDER:webacl:x:label"
            out = {}
            for k, v in o.items():
                if k == "SearchString" and isinstance(v, str):
                    out[k] = base64.b64encode(v.encode()).decode()
                elif k == "ARN" and isinstance(v, str):
                    # a literal ARN ref (regex pattern set / ip set) → throwaway
                    out[k] = regex_arn if "regexpatternset" in v else ipset_arn
                else:
                    out[k] = walk(v)
            return out
        if isinstance(o, list):
            return [walk(x) for x in o]
        return o
    return walk(copy.deepcopy(rules))


def _check_capacity(rules, ipset_arn, regex_arn, profile, region):
    """Return AWS's authoritative WCU for `rules` (a rule group's rule list)."""
    subbed = _substitute_refs(rules, ipset_arn, regex_arn)
    tmp = f"/tmp/wafverify_cc_{os.getpid()}.json"
    with open(tmp, "w") as f:
        json.dump(subbed, f)
    try:
        out = _aws(["wafv2", "check-capacity", "--scope", SCOPE,
                    "--rules", f"file://{tmp}"], profile, region)
        return out["Capacity"]
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


# ── Throwaway resource lifecycle ──────────────────────────────────────────────

def _create_temp_resources(profile, region):
    """Create the throwaway IP set + regex pattern set; return (ip_arn, rgx_arn).

    Idempotent: a prior run killed mid-flight (e.g. by a timeout) may have left
    these behind, so delete any existing same-named resource first — otherwise
    CreateIPSet fails with WAFDuplicateItemException."""
    _delete_temp_resources(profile, region)
    ip = _aws(["wafv2", "create-ip-set", "--name", _TMP_IPSET_NAME, "--scope", SCOPE,
               "--ip-address-version", "IPV4", "--addresses", "203.0.113.0/24"],
              profile, region)
    rgx = _aws(["wafv2", "create-regex-pattern-set", "--name", _TMP_REGEX_NAME,
                "--scope", SCOPE, "--regular-expression-list", '[{"RegexString":"a"}]'],
               profile, region)
    return ip["Summary"]["ARN"], rgx["Summary"]["ARN"]


def _delete_temp_resources(profile, region):
    """Best-effort delete of the throwaway resources (needs id + lock token)."""
    for name, get_cmd, del_cmd, key in (
        (_TMP_IPSET_NAME, "get-ip-set", "delete-ip-set", "IPSet"),
        (_TMP_REGEX_NAME, "get-regex-pattern-set", "delete-regex-pattern-set", "RegexPatternSet"),
    ):
        try:
            lst = _aws(["wafv2", f"list-{'ip-sets' if key == 'IPSet' else 'regex-pattern-sets'}",
                        "--scope", SCOPE], profile, region)
            summaries = lst.get("IPSets" if key == "IPSet" else "RegexPatternSets", [])
            match = next((s for s in summaries if s["Name"] == name), None)
            if not match:
                continue
            got = _aws(["wafv2", get_cmd, "--name", name, "--scope", SCOPE,
                        "--id", match["Id"]], profile, region)
            _aws(["wafv2", del_cmd, "--name", name, "--scope", SCOPE,
                  "--id", match["Id"], "--lock-token", got["LockToken"]],
                 profile, region, parse_json=False)
        except RuntimeError:
            pass  # best-effort cleanup — leftover temp resource is harmless


# ── Managed rule group WCU refresh ────────────────────────────────────────────

def _refresh_managed_wcu(templates, profile, region):
    """DescribeManagedRuleGroup for every AWS managed rule group referenced, so
    the informational per-WebACL WCU total uses live numbers. Returns
    {group_name: wcu}. Managed groups are never packed into our rule groups, so
    this affects only reporting, never a declared Capacity."""
    names = set()
    for _p, t in templates:
        for res in t.get("Resources", {}).values():
            if res["Type"] != "AWS::WAFv2::WebACL":
                continue
            for rule in res["Properties"]["Rules"]:
                m = rule.get("Statement", {}).get("ManagedRuleGroupStatement")
                if m and m.get("VendorName") == "AWS":
                    names.add(m["Name"])
    live = {}
    for name in sorted(names):
        try:
            out = _aws(["wafv2", "describe-managed-rule-group", "--vendor-name", "AWS",
                        "--name", name, "--scope", SCOPE], profile, region)
            live[name] = out.get("Capacity")
        except RuntimeError:
            pass  # unknown/unavailable group — leave to the local constant
    return live


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not args:
        _fail("Usage: waf-verify-wcu.py <output_dir> --profile <p> [--region us-east-1]",
              action="ABORT")
    output_dir = os.path.expanduser(args[0])

    profile = None
    region = "us-east-1"
    for i, a in enumerate(sys.argv):
        if a == "--profile" and i + 1 < len(sys.argv):
            profile = sys.argv[i + 1]
        elif a.startswith("--profile="):
            profile = a.split("=", 1)[1]
        elif a == "--region" and i + 1 < len(sys.argv):
            region = sys.argv[i + 1]
        elif a.startswith("--region="):
            region = a.split("=", 1)[1]

    if not profile:
        _fail("No AWS profile given. Re-run with --profile <name> (an AWS profile "
              "is required to reach CheckCapacity). Without it, deploy on the local "
              "WCU numbers — they are calculator-exact; a rule group's Capacity can "
              "only ever be slightly high, which still deploys.",
              action="FIX",
              command=f"python3 waf-verify-wcu.py {output_dir} --profile <your-profile>")

    try:
        templates = _load_templates(output_dir)
    except (OSError, json.JSONDecodeError) as e:
        _fail(f"Could not read templates in {output_dir}: {e}", action="ABORT")
    if not templates:
        _fail(f"No waf-cloudformation*.json found in {output_dir}. Run the WAF "
              "pipeline first.", action="FIX")

    # Sanity: profile actually works.
    try:
        _aws(["sts", "get-caller-identity"], profile, region)
    except RuntimeError as e:
        _fail(f"AWS profile '{profile}' not usable: {e}", action="FIX",
              command="aws sts get-caller-identity --profile " + profile)

    # Collect all rule groups across all template files.
    groups = []  # (template_path, template, logical_id, resource)
    for path, t in templates:
        for lid, res in t.get("Resources", {}).items():
            if res["Type"] == "AWS::WAFv2::RuleGroup":
                groups.append((path, t, lid, res))

    print(f"Verifying {len(groups)} rule group(s) against CheckCapacity...", file=sys.stderr)

    reconciled = []      # (name, declared, actual)
    already_ok = []      # name
    over_cap = []        # (name, actual)
    dirty_paths = set()

    ip_arn = rgx_arn = None
    try:
        if groups:
            ip_arn, rgx_arn = _create_temp_resources(profile, region)
        for idx, (path, t, lid, res) in enumerate(groups, 1):
            props = res["Properties"]
            name = props["Name"]
            declared = props["Capacity"]
            before = _rules_hash(props["Rules"])
            actual = _check_capacity(props["Rules"], ip_arn, rgx_arn, profile, region)
            print(f"[PROGRESS] {idx}/{len(groups)} rule groups checked", file=sys.stderr)

            if actual > RULE_GROUP_WCU_CAP:
                over_cap.append((name, actual))
            if actual != declared:
                props["Capacity"] = actual          # ← the ONLY mutation
                assert _rules_hash(props["Rules"]) == before, \
                    f"Rules changed while reconciling {name} — aborting (bug guard)"
                reconciled.append((name, declared, actual))
                dirty_paths.add(path)
            else:
                already_ok.append(name)

        managed_live = _refresh_managed_wcu(templates, profile, region)
    except RuntimeError as e:
        _fail(f"AWS call failed during verification: {e}", action="RETRY",
              command=f"python3 waf-verify-wcu.py {output_dir} --profile {profile}")
    finally:
        if ip_arn or rgx_arn:
            _delete_temp_resources(profile, region)

    # Persist any Capacity corrections (compact, matching the generator's format).
    for path, t in templates:
        if path in dirty_paths:
            with open(path, "w") as f:
                json.dump(t, f, separators=(",", ":"), ensure_ascii=False)

    # ── Report ────────────────────────────────────────────────────────────────
    if over_cap:
        items = "\n".join(f"  {n}: {c} WCU > {RULE_GROUP_WCU_CAP}" for n, c in over_cap)
        print(f"\n{len(over_cap)} rule group(s) exceed the {RULE_GROUP_WCU_CAP}-WCU cap.",
              file=sys.stderr)
        print("\n---RESULT---\nSPEC: 1\nSTATUS: PARTIAL")
        print(f"CHECKED: {len(groups)}")
        print(f"RECONCILED: {len(reconciled)}")
        print(f"OVER_CAP: {len(over_cap)}")
        print(f"OVER_CAP_ITEMS:\n{items}")
        print("ACTION: FIX")
        print("CONTEXT: A rule group's true WCU exceeds the 5000 hard cap — it "
              "cannot be created. Reduce rule complexity (fewer text transforms / "
              "CONTAINS byte matches / regex-set refs) in the source Cloudflare "
              "rules feeding this group, then re-run the pipeline.")
        sys.exit(3)

    managed_note = ", ".join(f"{n}={w}" for n, w in sorted(managed_live.items())) or "none"
    verb = "reconciled" if reconciled else "already correct"
    print(f"WCU verification complete — {verb}.", file=sys.stderr)
    print("\n---RESULT---\nSPEC: 1\nSTATUS: OK")
    print(f"CHECKED: {len(groups)}")
    print(f"RECONCILED: {len(reconciled)}")
    if reconciled:
        detail = "\n".join(f"  {n}: {d} -> {a}" for n, d, a in reconciled)
        print(f"RECONCILED_ITEMS:\n{detail}")
    print(f"ALREADY_OK: {len(already_ok)}")
    print(f"MANAGED_WCU_LIVE: {managed_note}")
    if reconciled:
        print("NOTE: Rule-group Capacity values were corrected to AWS's computed "
              "WCU (only the Capacity integer changed; rule logic untouched). "
              "Re-deploy the updated template(s).")
    else:
        print("NOTE: All rule-group Capacity values already match AWS. Safe to deploy.")


if __name__ == "__main__":
    main()
