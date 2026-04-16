[English](./why-cloudformation.md)

# 为什么 WAF 用 CloudFormation 而不是 Terraform？

WAF pipeline 生成的是 CloudFormation JSON 模板，而不是 Terraform HCL。这是刻意的选择，不是限制。

## Terraform Provider 一个修不了的 Bug

Terraform AWS provider 对 WAFv2 的 statement 嵌套硬编码了 **3 层限制**（[hashicorp/terraform-provider-aws#14377](https://github.com/hashicorp/terraform-provider-aws/issues/14377)）。这个 issue 从 **2020 年 7 月**开到现在，至今未修复。

AWS WAF API 本身没有这个限制——[文档明确说明](https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statements-logical.html)语句可以嵌套到任意深度。限制完全来自 Terraform provider 的 schema。

### 为什么 HashiCorp 修不了

根因在 **Terraform Core**，不在 AWS provider。Terraform 的 schema 系统使用静态类型，不支持递归类型定义。为了表示 WAFv2 递归的 `Statement` 结构，provider 必须手动展开每一层嵌套。展开 3 层已经产生了巨大的 schema 对象，导致严重的性能问题（[#14062](https://github.com/hashicorp/terraform-provider-aws/issues/14062)）。每增加一层，性能指数级恶化。

HashiCorp 维护者在 [2024 年 10 月确认](https://github.com/hashicorp/terraform-provider-aws/issues/14377#issuecomment-2447427051)：上游 Terraform Core 问题"短期内不太可能解决"，嵌套超过 3 层会导致"数小时"的处理时间。

### 什么时候会触发限制

3 层限制在真实 WAF 规则中很容易触发：

- **带 scope-down 的 Skip 规则**：一条 `AND(条件A, 条件B)` 的规则被包裹成 `AND(NOT(label_match), 原始AND)` 来实现 scope-down——这就是 AND 嵌套 AND，Terraform 直接拒绝。
- **Rate-based 规则**：`rate_based > scope_down > AND(NOT(label_match), 原始条件)` 在原始条件加入任何嵌套之前就已经 3 层了。
- **复杂表达式**：`(A OR B) AND (C OR D)` 本身就是 3 层。加上 scope-down 就超过 4 层。

这个错误只在 `terraform apply` 时才会出现——`terraform validate` 检查不出来。

## `rule_json` Workaround 呢？

Terraform provider v5.61.0（2024 年 7 月）加了 `rule_json` 属性作为变通方案——可以传入原始 JSON 字符串绕过 schema 嵌套限制。

这解决了嵌套问题，但引入了更严重的问题：**没有 drift detection**。Terraform 无法检查或比较 JSON 内容，所以：

- 有人在 AWS Console 改了 WAF 规则 → `terraform plan` 看不到差异 → 改动悄悄保留
- 你更新了 `.tf` 文件中的 JSON → Terraform 可能检测不到变化 → 必须手动 `taint` 或 `replace` 资源

对安全规则来说，静默 drift 是不可接受的。一条 WAF 规则被悄悄禁用或修改，可能意味着应用在没有任何人知道的情况下失去了防护。

正如一位用户[所说](https://github.com/hashicorp/terraform-provider-aws/issues/14377#issuecomment-2461405840)：*"raw_json is not a practical workaround, since no drift for it, the terraform loses its meaning!"*

## 为什么 CloudFormation 更好

| | Terraform HCL | Terraform `rule_json` | CloudFormation |
|---|---|---|---|
| 嵌套深度 | ❌ 3 层限制 | ✅ 无限制 | ✅ 无限制 |
| Drift detection | ✅ 完整 | ❌ 没有 | ✅ 完整（`detect-stack-drift`） |
| 部署工具 | Terraform CLI + provider | Terraform CLI + provider | AWS CLI 或 Console |
| 更新/回滚 | 可能部分 apply | 可能部分 apply | ✅ 原子操作（失败自动回滚） |
| 安装要求 | Terraform + ~300MB provider 下载 | 同左 | AWS CLI（大多数系统预装） |

CloudFormation 还支持直接在 AWS Console 部署——上传 JSON 文件点击部署即可，不需要安装任何 CLI。

## 不只是修复嵌套问题

切换到 CloudFormation 是更大架构变更的一部分。整个 WAF pipeline 现在是**确定性 Python**，零 LLM 调用：

| | 旧 pipeline | 新 pipeline |
|---|---|---|
| 表达式解析 | LLM（不确定性） | Python 递归下降解析器 |
| 规则分析 | LLM 子代理（2 个批次） | Python 脚本 |
| 验证 | LLM 子代理（4 个并行批次） | Python round-trip 验证 |
| 代码生成 | LLM 子代理 → Terraform HCL | Python → CloudFormation JSON |
| 执行时间 | 15–30 分钟 | < 1 秒 |
| API token 成本 | 每次约 $2–5 | $0 |
| 可复现性 | 每次运行结果可能不同 | 每次完全相同 |

旧 pipeline 使用 3 个 LLM 子代理和 16 个参考文档来生成 Terraform。新 pipeline 是 7 个 Python 脚本共约 1,500 行代码。相同输入永远产生相同输出。

## CDN Pipeline 仍然使用 Terraform

CDN pipeline（CloudFront 分发、缓存策略、CloudFront Functions）继续生成 Terraform。CloudFront 资源没有递归嵌套问题，而且 Terraform 的模块系统对管理按域名划分的 CloudFront 分发和共享策略确实很有用。
