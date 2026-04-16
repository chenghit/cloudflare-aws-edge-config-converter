[中文](./why-cloudformation_CN.md)

# Why CloudFormation Instead of Terraform for WAF?

The WAF pipeline generates a CloudFormation JSON template, not Terraform HCL. This is a deliberate choice — not a limitation. Here's why.

## The Terraform Provider Bug That Can't Be Fixed

The Terraform AWS provider hardcodes a **3-level nesting limit** for WAFv2 statement blocks ([hashicorp/terraform-provider-aws#14377](https://github.com/hashicorp/terraform-provider-aws/issues/14377)). This issue has been open since **July 2020** and remains unresolved as of 2026.

The AWS WAF API itself has no such limit — the [docs explicitly state](https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statements-logical.html) that statements can be nested at any depth. The restriction exists solely in the Terraform provider's schema.

### Why HashiCorp can't fix it

The root cause is in **Terraform Core**, not the AWS provider. Terraform's schema system uses static types — it doesn't support recursive type definitions. To represent WAFv2's recursive `Statement` structure, the provider must manually expand each nesting level into the schema. Expanding 3 levels already creates a massive schema object that causes significant performance degradation ([#14062](https://github.com/hashicorp/terraform-provider-aws/issues/14062)). Each additional level makes it exponentially worse.

A HashiCorp maintainer [confirmed in October 2024](https://github.com/hashicorp/terraform-provider-aws/issues/14377#issuecomment-2447427051): the upstream Terraform Core issue "is not likely to be resolved in the short term," and nesting beyond 3 levels results in "literal hours" of processing time.

### When you hit the limit

The 3-level limit is easy to hit with real-world WAF rules:

- **Skip rules with scope-down**: A rule with `AND(condition, condition)` gets wrapped in `AND(NOT(label_match), original_AND)` for scope-down — that's AND-in-AND, which Terraform rejects.
- **Rate-based rules**: `rate_based > scope_down > AND(NOT(label_match), original_conditions)` is already 3 levels before the original conditions add any nesting.
- **Complex expressions**: `(A OR B) AND (C OR D)` is 3 levels. Adding scope-down pushes it to 4+.

The error only surfaces at `terraform apply` — `terraform validate` doesn't catch it.

## What About `rule_json`?

Terraform provider v5.61.0 (July 2024) added a `rule_json` attribute as a workaround — you can pass raw JSON strings to bypass the schema nesting limit.

This solves the nesting problem but introduces a worse one: **no drift detection**. Terraform cannot inspect or diff the JSON content, so:

- Someone changes a WAF rule in the AWS Console → `terraform plan` shows no diff → the change persists silently
- You update the JSON in your `.tf` file → Terraform may not detect the change → you must `taint` or `replace` the resource manually

For security rules, silent drift is unacceptable. A WAF rule quietly disabled or modified could mean your application is unprotected without anyone knowing.

As one user [put it](https://github.com/hashicorp/terraform-provider-aws/issues/14377#issuecomment-2461405840): *"raw_json is not a practical workaround, since no drift for it, the terraform loses its meaning!"*

## Why CloudFormation Is Better Here

| | Terraform HCL | Terraform `rule_json` | CloudFormation |
|---|---|---|---|
| Nesting depth | ❌ 3-level limit | ✅ Unlimited | ✅ Unlimited |
| Drift detection | ✅ Full | ❌ None | ✅ Full (`detect-stack-drift`) |
| Deployment tool | Terraform CLI + provider | Terraform CLI + provider | AWS CLI or Console |
| Update/rollback | Partial apply possible | Partial apply possible | ✅ Atomic (auto-rollback on failure) |
| Install requirement | Terraform + ~300MB provider download | Same | AWS CLI (pre-installed on most systems) |

CloudFormation also supports deploying directly from the AWS Console — upload the JSON file and click deploy. No CLI installation needed.

## Beyond the Nesting Fix

Switching to CloudFormation was part of a larger architectural change. The entire WAF pipeline is now **deterministic Python** with zero LLM invocations:

| | Old pipeline | New pipeline |
|---|---|---|
| Expression parsing | LLM (non-deterministic) | Python recursive descent parser |
| Rule analysis | LLM subagents (2 batches) | Python scripts |
| Validation | LLM subagent (4 parallel batches) | Python round-trip validation |
| Code generation | LLM subagent → Terraform HCL | Python → CloudFormation JSON |
| Execution time | 15–30 minutes | < 1 second |
| API token cost | ~$2–5 per run | $0 |
| Reproducibility | Varies between runs | Identical every time |

The old pipeline used 3 LLM subagents with 16 reference documents to generate Terraform. The new pipeline is 7 Python scripts totaling ~1,500 lines. Same input always produces the same output.

## CDN Pipeline Still Uses Terraform

The CDN pipeline (CloudFront distributions, cache policies, CloudFront Functions) continues to generate Terraform. CloudFront resources don't have the recursive nesting problem, and Terraform's module system is genuinely useful for managing per-domain CloudFront distributions with shared policies.
