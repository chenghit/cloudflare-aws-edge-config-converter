[中文](./troubleshooting_CN.md)

# Troubleshooting

## Script Execution Errors

**Problem**: A pipeline script fails with an error

**Solution**:
1. Check the `---RESULT---` block in the output — it contains `STATUS`, `ACTION`, and `CONTEXT` fields
2. `STATUS: FATAL` means unrecoverable — check `CONTEXT` for the root cause
3. `STATUS: ERROR` with `ACTION: FIX` means user action needed (e.g., missing input file)
4. Restart Kiro CLI: Exit and start a new `kiro-cli chat` session if the orchestrator gets confused

## Skill Not Activating via Keywords

**Problem**: Orchestrator doesn't recognize the conversion request

**Solution**: Use specific keywords in your request:
- For WAF: say "convert **security rules**" or "convert to **AWS WAF**"
- For CDN: say "convert **CDN configuration**" or "convert to **CloudFront**"
- For both: say "convert **everything**" or "**full migration**"

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
   - `domain_scope.json` not found → run Stage 1 (cdn-parse-dns.py) first
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


## WAF CloudFormation "Duplicate Resource" Error

**Problem**: `aws cloudformation deploy` fails with `some resource in your request is a duplicate of an existing one`

**Cause**: A previous CloudFormation stack deployment failed and rolled back, but some resources (IP sets, WebACLs) were not fully cleaned up. CloudFormation cannot create resources with the same Name + Scope combination.

**Solution**:

1. Delete the failed stack:
   ```bash
   aws cloudformation delete-stack --stack-name cloudflare-waf-migration --region us-east-1
   aws cloudformation wait stack-delete-complete --stack-name cloudflare-waf-migration --region us-east-1
   ```

2. If residual resources remain after stack deletion, remove them manually:
   ```bash
   # List orphaned resources
   aws wafv2 list-ip-sets --scope CLOUDFRONT --region us-east-1
   aws wafv2 list-web-acls --scope CLOUDFRONT --region us-east-1

   # Delete each orphan (get Id and LockToken from the list output)
   aws wafv2 delete-ip-set --scope CLOUDFRONT --region us-east-1 \
     --name <name> --id <id> --lock-token <lock-token>
   aws wafv2 delete-web-acl --scope CLOUDFRONT --region us-east-1 \
     --name <name> --id <id> --lock-token <lock-token>
   ```

3. Re-deploy:
   ```bash
   aws cloudformation deploy \
     --template-file waf-cloudformation.json \
     --stack-name cloudflare-waf-migration \
     --region us-east-1
   ```

## WAF CloudFormation Stack Delete Fails with ThrottlingException

**Problem**: `aws cloudformation delete-stack` fails with `DELETE_FAILED` status. One or more WebACL or IP set resources fail to delete with `ThrottlingException`.

**Cause**: WAFv2 API write operations (including `DeleteWebACL`, `DeleteIPSet`) are limited to **1 request per second** per account per region. This is a fixed limit that cannot be increased. CloudFormation deletes resources in parallel, which can exceed this limit when the stack contains many WAFv2 resources (e.g., 50+ WebACLs).

**Solution**: Retry the delete. The second attempt only needs to delete the 1-2 remaining resources, which won't trigger throttling:

```bash
aws cloudformation delete-stack \
  --stack-name cloudflare-waf-migration \
  --region us-east-1
```

If the stack is stuck in `ROLLBACK_FAILED` (from a failed create), delete with `--retain-resources` for the stuck resources, then manually delete them:

```bash
# First, delete the stack and retain stuck resources
aws cloudformation delete-stack \
  --stack-name cloudflare-waf-migration \
  --retain-resources StuckResource1 StuckResource2 \
  --region us-east-1

# Then manually delete the retained IP sets via AWS Console or CLI
```
