# Examples

This directory contains example data for testing and demonstration purposes.

## Cloudflare Configurations

`cloudflare-configs/` contains sample Cloudflare configurations exported from real zones (with sensitive data removed).

These can be used to test the conversion powers:
- `account/` - Account-level configurations
- `example.com/` - Zone-level configurations for a sample domain

## Conversation History

`conversation-history/` contains complete conversation transcripts showing how to use each power:
- `cloudflare-to-aws-waf.txt` - Example conversation for Power 1 (WAF converter)
- `cloudflare-to-cloudfront-functions.txt` - Example conversation for Power 2 (Functions converter)

These serve as:
- **Usage examples** for new users
- **Test cases** for validating power behavior
- **Documentation** of expected workflows

## How to Use

### Testing Powers with Example Configs

1. Open Kiro IDE
2. Open the workspace folder:
   - File → Open Folder
   - Select the root directory of this repository (or the folder containing your Cloudflare configs)
   - Important: Kiro IDE can only access files within the opened workspace
3. Start a new chat
4. Reference the example configs in your message:
   ```
   Convert Cloudflare security rules to AWS WAF using configs in ./examples/cloudflare-configs/example.com/
   ```

### Learning from Conversation History

Read the conversation history files to understand:
- How to interact with each power
- What inputs are required
- What outputs to expect
- Common workflows and best practices
