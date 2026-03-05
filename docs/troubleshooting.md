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
