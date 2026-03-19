[English](./why-not-cf-terraforming.md)

# 为何不用 cf-terraforming？

[cf-terraforming](https://github.com/cloudflare/cf-terraforming) 是 Cloudflare 官方的 Terraform 导出工具。虽然它在 Terraform 管理 Cloudflare 方面很出色，但和本迁移工具根本不兼容。

## 核心问题：不可预测的文件结构

本工具的 AI skills 依赖**可预测的文件结构**——固定的目录布局、固定的文件名（`WAF-Custom-Rules.txt`、`Rate-limits.txt`、`IP-Lists.txt` 等）。Skills 通过这些已知路径触发工作流并定位配置数据。

cf-terraforming 要求用户**手动指定每种资源类型的输出文件名和路径**：

```bash
cf-terraforming generate --resource-type cloudflare_ruleset --zone $ZONE_ID > my-waf-rules.tf
cf-terraforming generate --resource-type cloudflare_list --account $ACCOUNT_ID > ip-lists.tf
cf-terraforming generate --resource-type cloudflare_rate_limit --zone $ZONE_ID > rate-limits.tf
# ... 用户可以选择任意文件名和位置
```

这意味着：
- **文件名是任意的**——一个用户可能叫 `waf.tf`，另一个叫 `my-rules.tf`
- **目录结构是任意的**——文件可能在一个目录、嵌套目录或分散各处
- **没有标准布局**——每个用户的导出结果都不一样

当文件结构不可预测时，AI skills 无法可靠地激活或定位配置数据。Skill 需要问"你把文件放哪了？"和"你给文件起了什么名？"——这就失去了自动化的意义。

**CloudflareBackup 解决了这个问题**，每次都生成固定、可预测的结构：

```
example.com/2026-01-12/
├── WAF-Custom-Rules.txt
├── Rate-limits.txt
├── IP-Lists.txt
├── IP-Access-Rules.txt
├── Redirect-Rules.txt
├── ...
```

一条命令，一种结构，每次都一样。Skills 准确知道每种配置类型在哪里。

## 次要问题：仍需 API 获取 Zone ID

cf-terraforming 无法从域名发现 zone ID——你必须先调用 Cloudflare API：

```bash
# cf-terraforming 做不到这个：
cf-terraforming generate --resource-type cloudflare_ruleset --domain example.com
# Error: unknown flag: --domain

# 你必须先调用 API：
ZONE_ID=$(curl -s "https://api.cloudflare.com/client/v4/zones?name=example.com" \
  -H "Authorization: Bearer $TOKEN" | jq -r '.result[0].id')

# 然后调用 cf-terraforming：
cf-terraforming generate --resource-type cloudflare_ruleset --zone $ZONE_ID
```

既然已经要调用 API 获取 zone ID，CloudflareBackup 可以一步到位获取 zone ID 和配置数据。

## 对比

| | cf-terraforming | CloudflareBackup |
|---|---|---|
| 文件结构 | 用户自定义（不可预测） | 固定（可预测） |
| 文件名 | 用户自定义（任意） | 标准化 |
| Zone ID 发现 | 需手动调用 API | 自动 |
| 所需命令数 | 多条（每种资源类型一条） | 一条 |
| AI skill 兼容性 | ❌ 无法可靠定位文件 | ✅ Skills 知道确切路径 |

## cf-terraforming 的实际用途

cf-terraforming 是为**用 Terraform 管理 Cloudflare** 设计的——不是为了从 Cloudflare 迁移走：

```
用途：用 Terraform 管理 Cloudflare（继续使用 Cloudflare）
不适用：从 Cloudflare 迁移到 AWS
```

## 数据格式依赖

除了文件发现之外，转换 pipeline 中有多个 Python 脚本（CDN pipeline 的 Stage 3–7.6，以及 WAF IP 分析）负责解析和转换配置数据。这些脚本完全针对 CloudflareBackup 产生的数据结构设计——即 Cloudflare REST API 的原始 JSON 响应格式。字段名、嵌套结构、表达式语法、数组结构都直接遵循 Cloudflare API schema。

Pipeline 没有针对 cf-terraforming 的 HCL 输出、Terraform state 文件或任何其他备份格式做设计或测试。支持不同的输入格式意味着需要重写预处理脚本（`cdn-preprocess.py`、`waf-analyze-ip.py`）中将 Cloudflare 原始数据解析为 pipeline 中间表示的部分。操作 IR 的下游脚本不需要改动。

## 总结

不兼容的原因不是 HCL 解析（AI 处理得很好）或数据质量。而是**文件结构的可预测性**和**数据格式的依赖**——这是基于 skill 的自动化工作流的基础。
