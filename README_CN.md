# Cloudflare 到 AWS 边缘服务迁移工具 | [English](./README.md)

**通过 AI 对话，自动将 Cloudflare 配置转换为 AWS 边缘服务配置**

---

## ⚠️ 重要：输入格式要求

**本工具仅支持由 [CloudflareBackup](https://github.com/chenghit/CloudflareBackup) 生成的配置备份文件。**

**❌ 不兼容 [cf-terraforming](https://github.com/cloudflare/cf-terraforming)** — cf-terraforming 需要用户手动指定输出文件名和路径，生成不可预测的文件结构，AI skills 无法可靠处理。详见 [为何不用 cf-terraforming？](./docs/why-not-cf-terraforming.md)

---

## 为什么使用这个工具

从 Cloudflare 迁移到 AWS 时，手动转换数百条规则既费时又容易出错。本工具借助 GenAI 能力，通过对话式交互实现批量配置转换自动化，将迁移时间从几天缩短到几小时。

## 功能列表

| Skill | 输入 | 输出 | 状态 |
|-------|------|------|------|
| **cf-waf-analyzer** | Cloudflare 安全规则（WAF、速率限制、IP 访问控制等） | 安全规则摘要及转换计划 | ✅ 可用 |
| **cf-waf-analyzer-validator** | 安全规则摘要 | 已校验摘要（就地修复错误） | ✅ 可用 |
| **cf-waf-terraform-generator** | 已校验安全规则摘要 | AWS WAF 配置（Terraform） | ✅ 可用 |
| **cf-cdn-dns-parser** | Cloudflare DNS 备份 | 域名清单 + 用户输入模板 CSV | ✅ 可用 |
| **cf-cdn-input-validator** | 用户确认后的域名 CSV | 已验证的域名范围 JSON | ✅ 可用 |
| **cf-cdn-per-domain-processor** | Cloudflare CDN 所有规则类型 | 每域名 CloudFront 原生 IR YAML | ✅ 可用 |
| **cf-cdn-ir-chunk-validator** | IR accumulator YAML | 验证报告（对抗性检查器） | ✅ 可用 |
| **cf-cdn-ir-finalizer** | 所有域名 IR | 排序后的最终 IR + 去重清单 + 转换报告 | ✅ 可用 |
| **cf-cdn-ir-final-validator** | 最终 IR YAML | 验证报告（对抗性检查器） | ✅ 可用 |
| **cf-cdn-tf-shared-policies** | 去重清单 | 共享 Terraform 策略（CachePolicy 等） | ✅ 可用 |
| **cf-cdn-tf-domain** | 每域名最终 IR | CloudFront Terraform + CloudFront Functions JS | ✅ 可用 |
| **cf-cdn-js-validator** | 生成的 JS 函数文件 | JS 验证报告（语法 + 运行时约束） | ✅ 可用 |

每个 skill 在独立的 Kiro subagent 中运行，拥有隔离的上下文。默认 agent 加载 `cloudflare-aws-converter` 编排 skill，自动调度到相应的 subagent。

```mermaid
flowchart TD
    User([用户]) -->|"转换 WAF / CDN / Functions / 全部"| Main["Kiro 默认 Agent\n(cloudflare-aws-converter)"]

    Main -->|WAF 意图| WAF_A["cf-waf-analyzer"]
    WAF_A --> WAF_V["cf-waf-analyzer-validator"]
    WAF_V -->|通过| WAF_G["cf-waf-terraform-generator"]
    WAF_G --> WAF_Done([WAF Terraform ✅])

    Main -->|CDN 完整流程| CDN1["cf-cdn-dns-parser"]
    CDN1 -->|user_input_template.csv| Pause[/"⏸ 用户填写 CSV\n（默认缓存 + 证书 ARN）"/]
    Pause --> CDN2["cf-cdn-input-validator"]
    CDN2 --> CDN3["cf-cdn-per-domain-processor × N\n（按域名并行）"]
    CDN3 --> CDN4["cf-cdn-ir-chunk-validator × N"]
    CDN4 -->|全部通过| CDN5["cf-cdn-ir-finalizer"]
    CDN5 --> CDN6["cf-cdn-ir-final-validator × N"]
    CDN6 -->|全部通过| CDN7["cf-cdn-tf-shared-policies"]
    CDN7 --> CDN8["cf-cdn-tf-domain × N\n（按域名并行）"]
    CDN8 --> CDN9["cf-cdn-js-validator × N"]
    CDN9 -->|全部通过| CDN_Done([CDN Terraform + JS ✅])

    style Main fill:#f9f,stroke:#333
    style Pause fill:#ff9,stroke:#f90
    style WAF_Done fill:#9f9,stroke:#333
    style CDN_Done fill:#9f9,stroke:#333
```

## CDN 完整流程：工作原理

CDN 流程将所有 Cloudflare CDN 配置（缓存规则、源站规则、重定向规则、URL 重写、请求头转换、批量重定向、压缩规则、自定义错误规则等）转换为可直接使用的 AWS CloudFront Terraform 文件。

**唯一的用户交互点：** 解析 DNS 记录后，工具生成一个 CSV 模板。你只需填写两列内容——是否为每个域名应用 Cloudflare 默认的 70+ 文件类型 2 小时缓存策略，以及可选的 ACM 证书 ARN。其余步骤完全自动化。

**输出目录结构：**
```
cloudflare-to-aws-cdn/
├── user_input_template.csv          # 填写后另存为 user_input.csv
├── dns_manifest.yaml
├── domain_scope.json
├── conversion_report.md             # 不可转换规则 + 警告信息
├── ir/
│   ├── accumulator/                 # 每域名 CloudFront 原生中间表示
│   ├── final/                       # 排序并去重后的中间表示
│   └── validation/                  # 验证报告（V1、V2、V3）
└── terraform/
    ├── modules/
    │   └── cloudfront_distribution/ # 共享模块（从 skill 复制而来）
    ├── shared/
    │   └── policies.tf              # 去重后的 CachePolicy 资源 + outputs
    └── domains/
        └── <域名>/
            ├── main.tf              # module call（约 50-80 行）
            ├── outputs.tf
            ├── functions.tf
            ├── kvs.tf               # KVS 存储（如有批量重定向）
            ├── functions/
            │   └── viewer_request.js
            └── lambda/              # Lambda@Edge（仅当 CF Function 超过大小限制时）
```

**ACM 证书：** 在 CSV 中填入证书 ARN，或留空——工具会生成 `data "aws_acm_certificate"` 数据源，在 `terraform plan` 时自动查找你已有的 ISSUED 证书。

**日志：** 本工具不配置 CloudFront 访问日志——这涉及 S3 桶 region、日志格式、共用桶还是每域名独立桶等与配置迁移无关的决策。如有需要，自行在生成的 `main.tf` 中添加 `logging_config` 块。

**设计目标：** 已测试最多 50 个代理域名。更大的 zone 也应该可以工作——每个 subagent 独立处理一个域名，orchestrator 的 context 消耗随域名数线性增长。主要约束是 CloudFront KVS 配额（默认 50 个/账号，软限制——如果你有超过 50 个使用 bulk redirect 的域名，请提前[申请提升配额](https://docs.aws.amazon.com/servicequotas/latest/userguide/request-quota-increase.html)）。每个域名一个独立 KVS，不跨域共享。

**单 zone 运行：** 本工具每次只转换一个 Cloudflare zone。如果备份目录包含多个 zone，编排器会检测到并要求你指定转换哪个 zone。每个 zone 需要单独运行一次。

**并行批次大小：** Pipeline 在 5 个阶段（处理、V1 验证、V2 验证、Terraform 生成、JS 验证）并行处理多个域名。默认批次大小为 **每次 2 个域名**——足够保守以避免大多数平台的 LLM API 限速（Anthropic API Tier 1: 50 RPM，AWS Bedrock 默认配额：新账号可能低至 2-10 RPM）。如果你的 API 配额更高，可以编辑 `cloudflare-aws-converter/SKILL.md` 中的"Parallel batch size"规则来增加批次大小。Anthropic Tier 2+（1,000+ RPM）或 Bedrock 已申请提额（200+ RPM）可以安全使用批次大小 4（Kiro CLI 最大值）。

**部署顺序：** 生成的 Terraform 使用独立的 root module。按以下顺序 apply：

```bash
# 1. 先部署共享策略（创建 CachePolicy、ORP、RHP 资源）
cd cloudflare-to-aws-cdn/terraform/shared
terraform init && terraform apply

# 2. 再逐个部署各域名（通过 data source 按名称查找共享策略）
cd cloudflare-to-aws-cdn/terraform/domains/cdn_example_com
terraform init && terraform apply
```

各域名可以在共享策略部署完成后独立 plan/apply。这样做的好处是爆炸半径小——修改一个域名不会影响其他域名。

## 快速开始

```bash
# 1. 安装 Kiro CLI
curl -fsSL https://cli.kiro.dev/install | bash

# 2. 备份 Cloudflare 配置
# 使用：https://github.com/chenghit/CloudflareBackup

# 3. 安装 skills
git clone https://github.com/chenghit/cloudflare-aws-edge-config-converter.git
cd cloudflare-aws-edge-config-converter
./install.sh

# 4. 开始转换
kiro-cli chat
```

然后描述你的需求：

```
将 /path/to/cloudflare-backup 中的 Cloudflare 安全规则转换为 AWS WAF
将 /path/to/cloudflare-backup 中的 CDN 配置转换为 CloudFront Terraform
将 /path/to/cloudflare-backup 中的全部 Cloudflare 配置转换到 AWS
```

如需在没有自己配置的情况下测试，可使用 `examples/cloudflare-configs/`。

## 前提条件

### ACM 证书（仅 CDN 流程需要）

CloudFront 要求 TLS 证书位于 **us-east-1**（弗吉尼亚北部）。运行 CDN 流程前，请先为你的域名申请通配符证书：

```bash
# 示例：为 *.example.com 申请通配符证书
aws acm request-certificate \
  --domain-name "*.example.com" \
  --validation-method DNS \
  --region us-east-1
```

完成 DNS 验证并等待状态变为 `ISSUED`。在流程中填写 CSV 模板时输入证书 ARN，或留空让 Terraform 自动按域名查找已签发的证书。

### Terraform

AWS WAF 和 CloudFront 输出需要 Terraform >= 1.8.0、AWS Provider >= 6.x。

```bash
terraform version
# 升级：https://developer.hashicorp.com/terraform/install
```

### Kiro CLI

- 安装文档：https://kiro.dev/docs/getting-started/installation/
- Skills 支持：自 1.24 版本起
- ⚠️ 不推荐使用 Kiro IDE——它不支持 subagent 中的 `skill://` 资源绑定，会破坏上下文隔离。

### 模型选择

> ⚠️ **最低要求模型：`claude-sonnet-4.6`**
>
> 旧版模型只能看到 skill 元数据，无法加载完整的 SKILL.md 内容，导致任务失败。

- `claude-sonnet-4.6` — 推荐用于 WAF 转换及小型 CDN 配置（< 10 个域名）
- `claude-sonnet-4.6-1m` — CDN 迁移域名较多（> 10 个）或规则量大时必须使用。在 Kiro 中通过 `/model` 切换。

## 安装

```bash
git clone https://github.com/chenghit/cloudflare-aws-edge-config-converter.git
cd cloudflare-aws-edge-config-converter
./install.sh    # 将 skills 复制到 ~/.kiro/skills/，subagent 配置复制到 ~/.kiro/agents/
```

更新：`git pull && ./install.sh`

> **使用其他 Agent 工具？** 安装脚本和所有 SKILL.md 文件默认使用 `~/.kiro/skills/` 作为 skill 安装目录（Kiro CLI 约定）。如需配合其他 agent 工具使用，需要：(1) 修改 `install.sh` / `uninstall.sh` 中的目标目录；(2) 在所有 SKILL.md 文件中将 `~/.kiro/skills/` 全局替换为你的 agent 工具的 skill 路径——subagent 之间通过绝对安装路径互相引用。

### 手动控制 Subagent

高级用户可通过 `/agent swap <subagent-name>` 单独运行各流程阶段。

可用 subagent：`cf-waf-analyzer`、`cf-waf-analyzer-validator`、`cf-waf-terraform-generator`、`cf-cdn-dns-parser`、`cf-cdn-input-validator`、`cf-cdn-per-domain-processor`、`cf-cdn-ir-chunk-validator`、`cf-cdn-ir-finalizer`、`cf-cdn-ir-final-validator`、`cf-cdn-tf-shared-policies`、`cf-cdn-tf-domain`、`cf-cdn-js-validator`。

## Subagent 权限与安全

大多数 subagent 只有文件读写和搜索权限（`fs_read`、`fs_write`、`glob`、`grep`）。只有一个 subagent 需要 shell 执行权限：

| Subagent | 有 `execute_bash` | 原因 |
|----------|-------------------|------|
| `cf-cdn-js-validator` | ✅ 有 | 运行 `node --check <file>` 做 JavaScript 语法检查，以及 `wc -c` 做文件大小检查。这是它唯一需要的两个命令——仅靠文件读写工具无法完成 JS 语法校验和精确的字节大小测量。 |
| 其他所有 subagent | ❌ 无 | 只需要读写文件和搜索文本。 |

**如果你的安全策略对 `execute_bash` 有告警：** 你可以查看该 validator 的 SKILL.md 确认它只运行 `node --check` 和 `wc -c`。从 `cf-cdn-js-validator.json` 中移除 `execute_bash` 会导致 JS 语法检查（CFF-01、LE-01）和精确文件大小校验（CFF-06、LE-03）被禁用——validator 会跳过这些检查并在输出 JSON 中标记为 `SKIP`。

**不要尝试用手动审批来替代。** Subagent 运行在编排器的上下文中——当主 agent 将任务分派给 subagent 时，你在聊天界面中看不到该 subagent 的具体工具调用。对 subagent 的工具调用无法逐个手动审批，因此移除权限后依赖交互式审批并不可行。

## 更多信息

- [最佳实践](./docs/best-practices.md)
- [限制与注意事项](./docs/limitations.md)
- [故障排除](./docs/troubleshooting.md)
- [为何不用 cf-terraforming？](./docs/why-not-cf-terraforming.md)
- [路线图](./docs/roadmap.md)

## 相关资源

- [Kiro 文档](https://kiro.dev/docs/)
- [Kiro CLI Agent Skills 支持](https://kiro.dev/changelog/cli/1-24/)
- [AWS WAF 文档](https://docs.aws.amazon.com/waf/)
- [CloudFront 开发者指南](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/)
- [CloudFront Functions Runtime 2.0](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/functions-javascript-runtime-20.html)

## 许可证

[MIT](./LICENSE)

## 反馈与贡献

如有问题或建议，欢迎提交 Issue 或 Pull Request。
