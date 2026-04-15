[中文](./troubleshooting_CN.md)

# Troubleshooting

## Subagent Not Activating Properly

**Problem**: Subagent doesn't follow the skill's workflow when invoked automatically by the orchestrator

**Symptoms**:
- Agent generates ad-hoc analysis instead of following defined steps
- Output files are not created or have wrong names
- Agent doesn't read reference documents

**Solution**:
1. Try manual invocation first: `/agent swap cf-cdn-dns-parser` then give your instruction. If this works, the issue is with orchestrator routing, not the skill itself.
2. Verify installation: Check if `~/.kiro/agents/cf-cdn-dns-parser.json` exists
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

## CloudFront Console Cannot Edit Cache Behavior

**Problem**: Clicking on a cache behavior in the CloudFront console shows "Your CloudFront distribution behavior configuration page failed to load"

**Cause**: The distribution status is still `InProgress` (deploying to edge locations). The console cannot load the behavior edit page until deployment completes.

**Solution**:
1. Check distribution status: `aws cloudfront get-distribution --id <DIST_ID> --query 'Distribution.Status'`
2. Wait for status to become `Deployed`. This typically takes 5–15 minutes, longer for distributions with many cache behaviors or Lambda@Edge associations.
3. Or wait with: `aws cloudfront wait distribution-deployed --id <DIST_ID>`

## Lambda@Edge Function Cannot Be Deleted During Destroy

**Problem**: `terraform destroy` fails with `InvalidParameterValueException: Lambda was unable to delete ... because it is a replicated function`

**Cause**: When a CloudFront distribution is deleted, Lambda@Edge replicas at edge locations are cleaned up asynchronously by AWS. Until all replicas are gone, the Lambda function itself cannot be deleted. This typically takes 30–60 minutes but can occasionally take several hours.

**Solution**:

1. **Wait and retry** (recommended): Wait 30–60 minutes, then re-run `terraform destroy`. The replicas will eventually be cleaned up automatically.

2. **Remove from state and clean up later**: If you don't want to wait:
   ```bash
   cd cloudflare-to-aws-cdn/terraform/domains/<sanitized_domain>

   # List remaining resources
   terraform state list

   # Remove Lambda functions from state (they'll be cleaned up by AWS automatically)
   terraform state rm 'aws_lambda_function.<resource_name>'

   # Destroy remaining resources
   terraform destroy -auto-approve
   ```
   The Lambda function will be automatically deleted by AWS once all replicas are cleaned up (no manual action needed).

3. **Check replica status**: You can monitor whether replicas still exist:
   ```bash
   aws lambda list-versions-by-function --function-name cfcdn-<sanitized_domain>-origin-response --query 'Versions[?Version!=`$LATEST`].[Version,State]'
   ```

**Note**: This is an AWS-side limitation, not a Terraform or tool bug. The same issue occurs with manual deletion via the AWS Console or CLI.

## Lambda@Edge IAM Role Not Destroyed

**Problem**: `terraform apply` fails with `EntityAlreadyExists: Role with name cfcdn-<domain>-lambda-edge already exists` after a previous `terraform destroy`

**Cause**: Lambda@Edge functions are replicated to CloudFront edge locations. When you destroy a distribution, AWS asynchronously cleans up these replicas — this can take several hours. The IAM role cannot be deleted while replicas still reference it, so `terraform destroy` may fail to delete the role (silently or with a timeout error).

**Solution**:
1. Import the existing role into Terraform state:
   ```bash
   cd cloudflare-to-aws-cdn/terraform/domains/<sanitized_domain>
   terraform import aws_iam_role.<sanitized_domain>_lambda_edge cfcdn-<sanitized_domain>-lambda-edge
   ```
   Where `<sanitized_domain>` is the directory name under `domains/` (dots and hyphens replaced with underscores, e.g., `ext_c_letsmakeit_link` for `ext.c.letsmakeit.link`).
   Then re-run `terraform apply`.
2. Or wait a few hours for replicas to be cleaned up, then manually delete:
   ```bash
   aws iam detach-role-policy --role-name cfcdn-<sanitized_domain>-lambda-edge --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
   aws iam delete-role --role-name cfcdn-<sanitized_domain>-lambda-edge
   ```
   Then re-run `terraform apply`.
