[中文](./troubleshooting_CN.md)

# Troubleshooting

## Subagent Not Activating Properly

**Problem**: Subagent doesn't follow the skill's workflow when invoked automatically by the orchestrator

**Symptoms**:
- Agent generates ad-hoc analysis instead of following defined steps
- Output files are not created or have wrong names
- Agent doesn't read reference documents

**Solution**:
1. Try manual invocation first: `/agent swap cf-waf-analyzer` then give your instruction. If this works, the issue is with orchestrator routing, not the skill itself.
2. Verify installation: Check if `~/.kiro/agents/cf-waf-analyzer.json` exists
3. Restart Kiro CLI: Exit and start a new `kiro-cli chat` session
4. List available agents: Use `/agent list` to see installed subagents

## Skill Not Activating via Keywords

**Problem**: Orchestrator doesn't route to the correct subagent

**Solution**: Use specific keywords in your request:
- For WAF: say "convert **security rules**" or "convert to **AWS WAF**"
- For CloudFront Functions: say "convert **transformation rules**" or "convert to **CloudFront Functions**"
- For CDN: say "analyze **CDN configuration**" or "analyze **CDN config**"

**Example**:
- ❌ Vague: "analyze my cloudflare config files"
- ✅ Specific: "convert **security rules** in /path/to/config to **AWS WAF**"

## Conversion Results Don't Meet Expectations

**Problem**: Generated configuration doesn't match expectations

**Solution**:
1. Check if Cloudflare configuration files are complete
2. Try converting again in a new conversation
3. Consider converting complex configurations in batches

## Context Confusion

**Problem**: AI mixes different projects or different rule types

**Solution**:
1. Stop current conversation immediately
2. Start a new conversation
3. Convert only one type of rule for one project at a time

## CDN Python Script Errors

**Problem**: CDN Stages 3–6 (Python scripts) fail with an error

**Symptoms**:
- `cdn-preprocess.py` exits with code 1 (partial) or 2 (total failure)
- `cdn-validate-chunk.py` reports FAIL for one or more domains
- `cdn-finalize.py` or `cdn-validate-final.py` exits with error

**Solution**:
1. Check the error output — Python scripts print specific error messages to stderr
2. For preprocess failures: check `cloudflare-to-aws-cdn/ir/accumulator/<domain>.error.json` for details
3. For validation failures: check `cloudflare-to-aws-cdn/ir/validation/chunk/<domain>-v1.json` or `final/<domain>-v2.json`
4. Common causes:
   - `domain_scope.json` not found → run Stage 2 (Input Validator) first
   - JSON parse error in Cloudflare config → check if CloudflareBackup export is complete
   - Zone directory not found → verify the config path points to the CloudflareBackup root (containing `account/` and zone subdirectories)
5. To retry a single domain: `python3 cdn-preprocess.py <config_path> cloudflare-to-aws-cdn --domain <hostname>`
