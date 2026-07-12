# WAF Pipeline

WAF conversion: Cloudflare security rules → IR JSON → AWS WAF CloudFormation.

All Python scripts output `---RESULT---` blocks per SCRIPT_STANDARDS.md. Parse STATUS and ACTION fields to decide next step.

## Single entry point

```bash
bash "$REPO/converter/scripts/waf-pipeline.sh" "$CONFIG_PATH" "$OUT/cloudflare-to-aws-waf"
```

Optional: `--force-split` flag to generate one WebACL per proxied domain instead of the default 2.

The pipeline runs all steps in sequence: analyze (IP / custom / rate) → merge → count-validate → IR-validate → generate CloudFormation → generate README. There is no auto-split step: a rule-group overflow packer keeps each WebACL under AWS's hard caps (10 rate-based rules, 50 reference statements) by offloading overflow into referenced rule groups, so exceeding 50 references never forces a split.

- `STATUS: OK` → report results (RESULT may include `VERIFY_WCU_CMD`, an optional pre-deploy WCU reconcile)
- `STATUS: BLOCKED` → the template was written but exceeds an AWS hard cap (WCU > 5000, or a rule too complex to fit one rule group); report `BLOCKED_ITEMS`, tell the user to simplify + re-run, do NOT present it as deployable
- `STATUS: FATAL` / `STATUS: ERROR` → report the `CONTEXT` field and stop

Zero LLM invocations. Fully deterministic.
