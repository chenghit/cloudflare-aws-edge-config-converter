# WAF Pipeline

WAF conversion: Cloudflare security rules → IR JSON → AWS WAF CloudFormation.

All Python scripts output `---RESULT---` blocks per SCRIPT_STANDARDS.md. Parse STATUS and ACTION fields to decide next step.

## Single entry point

```bash
bash ~/.kiro/skills/cloudflare-aws-converter/scripts/waf-pipeline.sh "{config_path}" "cloudflare-to-aws-waf"
```

Optional: `--force-split` flag to force per-domain WebACL mode for testing.

The pipeline runs all steps in sequence: analyze → merge → validate → check-split → (split if needed) → generate CloudFormation → generate README.

- `STATUS: OK` → report results
- `STATUS: ERROR` → report error and stop

Zero LLM invocations. Fully deterministic.
