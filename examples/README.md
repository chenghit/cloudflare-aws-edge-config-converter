# Examples

This directory contains example data for testing and demonstration purposes.

## Cloudflare Configurations

`cloudflare-configs/` contains sample Cloudflare configurations exported from real zones (with sensitive data removed).

These can be used to test the conversion skills:
- `account/` - Account-level configurations
- `example.com/` - Zone-level configurations for a sample domain

## Conversation History

`conversation-history/` contains complete conversation transcripts showing how to use each skill:
- `cloudflare-to-aws-waf.txt` - Example conversation for Skill 1 (WAF converter)
- `cloudflare-to-cloudfront-functions.txt` - Example conversation for Skill 2 (Functions converter)

These serve as:
- **Usage examples** for new users
- **Test cases** for validating skill behavior
- **Documentation** of expected workflows

## How to Use

### Testing Skills with Example Configs

```bash
# Start Kiro CLI
kiro-cli chat

# In the chat, reference the example configs:
"Convert Cloudflare security rules to AWS WAF using configs in ./examples/cloudflare-configs/example.com/"
```

### Learning from Conversation History

Read the conversation history files to understand:
- How to interact with each skill
- What inputs are required
- What outputs to expect
- Common workflows and best practices
