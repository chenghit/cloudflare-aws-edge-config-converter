[中文](./best-practices_CN.md)

# Best Practices

## ✅ Recommended

1. **Convert One Project at a Time**
   - After completing conversion for one domain, start a new chat session
   - Avoid mixing configurations from multiple projects

2. **Provide the CloudflareBackup Directory Path**
   - Example: `Convert security rules in /path/to/cloudflare-backup to AWS WAF`
   - Kiro will automatically locate the configuration files within the backup directory

3. **Use Specific Keywords**
   - For WAF: mention "security rules" or "AWS WAF"
   - For CloudFront Functions: mention "transformation rules" or "CloudFront Functions"
   - For CDN analysis: mention "CDN configuration" or "CDN config"

## ❌ Avoid

1. **Don't Mix Projects in One Conversation**
   - Causes context confusion and hallucination

2. **Don't Mix Rule Types in One Conversation**
   - Each rule type uses a different subagent with separate context. Mixing them in one conversation may cause the agent to lose track of previous work.

3. **Don't Use Vague Descriptions**
   - ❌ "Help me convert Cloudflare configuration"
   - ✅ "Convert Cloudflare security rules to AWS WAF configuration"
