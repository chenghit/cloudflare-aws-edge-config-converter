# Cloudflare 到 AWS 边缘服务迁移工具 | [English](./README.md)

**通过 AI 对话，自动将 Cloudflare 配置转换为 AWS 边缘服务配置**

本工具读取 [CloudflareBackup](https://github.com/chenghit/CloudflareBackup) 导出的备份文件，生成可直接部署的 AWS WAF（CloudFormation）和 CloudFront（Terraform）配置——包括缓存策略、CloudFront Functions、Lambda@Edge 和 KVS 数据。

## 快速开始

无需安装。克隆仓库，然后让你的 AI agent（Claude Code、Kiro CLI、Codex、Cursor 等）来驱动它。

```bash
git clone https://github.com/chenghit/cloudflare-aws-edge-config-converter.git
```

然后告诉你的 agent：

```
阅读 /path/to/cloudflare-aws-edge-config-converter 里的 AGENTS.md，
然后把我在 /path/to/cloudflare-backup 的 Cloudflare 配置转换到 AWS。
```

agent 会读取 `AGENTS.md` → `converter/SKILL.md` 并为你运行流程。你可以指定范围：

```
将 /path/to/cloudflare-backup 中的 Cloudflare 安全规则转换为 AWS WAF
将 /path/to/cloudflare-backup 中的 CDN 配置转换为 CloudFront Terraform
将 /path/to/cloudflare-backup 中的全部 Cloudflare 配置转换到 AWS
```

还没有备份？`backup/` 目录里就是 CloudflareBackup 工具——agent 会指导你运行它（它不会看到你的 API 凭据，凭据由你自己配置）。详见下面的 [获取备份](#获取备份)。

请始终提供 **CloudflareBackup 的根目录**（包含 `account/` 和 zone 子目录如 `example.com/` 的那个目录）。**不要**提供子目录——WAF 和 CDN pipeline 都需要 `account/` 目录中的文件（WAF 需要 IP 列表，CDN 需要 bulk redirect 列表），这些文件位于 zone 目录之外。

如需在没有自己配置的情况下测试，可使用 `examples/cloudflare-configs/`。

## 前提条件

- **一个 AI 编码 agent** — Claude Code、Kiro CLI、Codex、Cursor，或任何能读取 markdown 文件并运行 shell 命令的 agent。agent 只需要理解用户意图、运行脚本，以及为非英文用户翻译部署文档。支持 Agent Skills 格式的工具（Kiro CLI、Claude Code）会自动发现 `converter/SKILL.md`；其他工具读取 `AGENTS.md`（很多工具会自动读取），或由你指给它。
- **Terraform** >= 1.8.0，AWS Provider >= 6.x — [安装 Terraform](https://developer.hashicorp.com/terraform/install)。仅 CDN pipeline 需要。WAF pipeline 使用 CloudFormation（不需要 Terraform）。
- **Python 3** — WAF 和 CDN pipeline 的脚本都需要。WAF pipeline 完全基于 Python（表达式解析、分析、验证、CloudFormation 生成）。CDN 用 Python 做规则预处理、IR 校验和合并（Stage 3–7.6）。macOS 和大多数 Linux 发行版已预装。转换流程无需第三方包（仅用标准库）。**部署阶段**：有 KVS 的 CDN 域名（批量重定向、IP 列表、错误页面）会生成 `seed-kvs.py` 脚本，需要 `boto3`——部署前运行 `pip install boto3` 安装。
- **模型**：转换 pipeline 本身无模型要求——所有脚本都是确定性 Python，零 LLM 调用。
- **备份步骤需要**：`bash`、`curl` 和 `jq`。详见 `backup/README.md`。
- **ACM 证书**（仅 CDN）：CloudFront 要求证书位于 us-east-1。运行前申请通配符证书（如 `*.example.com`），Terraform 会自动查找已签发的证书。
- **输入格式**：仅支持 [CloudflareBackup](https://github.com/chenghit/CloudflareBackup) 导出。不兼容 [cf-terraforming](https://github.com/cloudflare/cf-terraforming)——详见 [为何不用 cf-terraforming？](./docs/why-not-cf-terraforming.md)

## 转换范围

| Cloudflare | AWS 等价物 | 流程 |
|------------|-----------|------|
| WAF 规则、速率限制、IP 访问控制 | AWS WAF Web ACL (CloudFormation) | WAF |
| 缓存规则 | CloudFront 缓存策略 + 缓存行为 | CDN |
| 源站规则 | CloudFront Functions (`updateRequestOrigin`) 或缓存行为 | CDN |
| 重定向规则 | CloudFront Functions (viewer-request) | CDN |
| URL 重写规则 | CloudFront Functions (viewer-request) | CDN |
| 批量重定向 | KVS + CloudFront Functions | CDN |
| 请求头转换 | CloudFront Functions + Origin Request Policy | CDN |
| 响应头转换 | Response Headers Policy + CloudFront Functions | CDN |
| 压缩规则 | 缓存策略 `enable_gzip` / `enable_brotli` | CDN |
| 自定义错误规则 | CloudFront 自定义错误响应 | CDN |
| Cloud Connector 规则 | 独立缓存行为 + 独立源站 | CDN |

并非所有 Cloudflare 功能都有 CloudFront 等价物。无法转换的项目会记录在 `conversion_report.md` 中供人工审查——不会被静默丢弃。完整列表见 [限制与注意事项](./docs/limitations.md)。

## 工作原理

你的 AI agent 读取 `converter/SKILL.md`，作为编排器调度确定性 Python 脚本完成 WAF 和 CDN 两条 pipeline。

**WAF 流程**（全 Python，零 LLM）：分析 IP 列表 → 分析自定义规则 → 分析速率限制 → 合并 → 校验 → 生成 CloudFormation → **引用超限时自动回退为 per-domain 拆分**

WAF pipeline 首先尝试 legacy 模式（2 个 WebACL）。如果 IP set 引用语句超过每个 WebACL 的 hard limit（50），自动回退为 per-domain WebACL（每个 proxied 域名一个）。Per-domain 模式下，host-specific 规则只放到对应域名的 WebACL，host 条件被剥离（WebACL 只服务一个域名时冗余）。每个 WebACL 包含搜索引擎标签规则（Googlebot/Bingbot/YandexBot）、Anti-DDoS（排除搜索引擎）和 always-on challenge 规则（Count 模式——用户确认后手动改为 Challenge）。

**CDN 流程**（0 个 LLM 阶段 + 10 个 Python 脚本）：**🐍 解析 DNS + 生成域名配置** → **🐍 预处理规则** → **🐍 校验 IR** → **🐍 合并去重** → **🐍 校验最终 IR** → **🐍 生成共享策略** → **🐍 生成每域名 Terraform 骨架** → **🐍 生成每域名测试脚本** → **🐍 生成每域名 JS** → **🐍 校验 JS**

所有 CDN 阶段都是确定性 Python 脚本，零 LLM 调用，零用户交互。Stage 1 自动解析 DNS 并生成 `domain_scope.json`（所有域名使用 Terraform data source 自动查找 ACM 证书）。整个工具（WAF + CDN）完全不依赖模型。

```mermaid
flowchart TD
    User([用户]) -->|"转换 WAF / CDN / 全部"| Main["编排器"]

    Main -->|WAF| WAF_A1["🐍 IP 分析"] --> WAF_A2["🐍 自定义规则"] --> WAF_A3["🐍 速率限制"] --> WAF_M["🐍 合并 + 校验"] --> WAF_G["🐍 生成 CFN (legacy)"] --> WAF_C{引用超限?}
    WAF_C -->|"≤50"| WAF_Done([CloudFormation ✅])
    WAF_C -->|">50"| WAF_SP["🐍 按域名拆分"] --> WAF_GP["🐍 生成 CFN (per-domain)"] --> WAF_Done

    Main -->|CDN| CDN1["🐍 DNS 解析"] --> CDN3["🐍 预处理"]
    CDN3 --> CDN4["🐍 V1 校验"]
    CDN4 -->|通过| CDN5["🐍 合并"]
    CDN5 --> CDN6["🐍 V2 校验"]
    CDN6 -->|通过| CDN7["🐍 共享策略"]
    CDN7 --> CDN75["🐍 TF 骨架"]
    CDN75 --> CDN76["🐍 测试脚本"]
    CDN76 --> CDN8["TF 域名 × N"]
    CDN8 --> CDN9["🐍 JS 校验"]
    CDN9 -->|通过| CDN_Done([CDN Terraform + JS ✅])

    style Main fill:#f9f,stroke:#333
    style WAF_Done fill:#9f9,stroke:#333
    style CDN_Done fill:#9f9,stroke:#333
```

**全自动：** 无需用户交互。DNS 解析自动生成域名配置。ACM 证书通过 Terraform data source 自动查找。

## CDN 流程详情

<details>
<summary>输出目录结构</summary>

```
cloudflare-to-aws-cdn/
├── dns_manifest.yaml
├── domain_scope.json
├── conversion_report.md             # 不可转换规则 + 警告
├── ir/                              # 中间表示（仅调试用）
│   ├── accumulator/
│   ├── final/
│   └── validation/
└── terraform/
    ├── modules/
    │   └── cloudfront_distribution/ # 共享模块（勿编辑）
    ├── shared/
    │   └── policies.tf              # 去重后的 CachePolicy、ORP、RHP
    └── domains/
        └── <域名>/
            ├── main.tf              # Module call（约 50-80 行）
            ├── outputs.tf
            ├── functions.tf
            ├── kvs.tf               # 仅当有批量重定向时
            ├── functions/
            │   └── viewer_request.js
            └── lambda/              # 仅当 CF Function 超过 10KB 时
```

</details>

<details>
<summary>部署顺序</summary>

共享策略 → Lambda@Edge（如有）→ 各域名独立部署 → KVS 数据导入 → DNS 切换。详见 [部署指南](./docs/deployment-guide.md)。

</details>

<details>
<summary>扩展性与限速</summary>

- **设计目标：** 已测试最多 54 个代理域名。更大的 zone 也应该可以工作——Python 脚本在单次调用中处理所有域名。
- **每次转换一个 zone。** 如果备份含多个域名（很正常——`config.example` 自带两个），agent 会逐个转换到各自独立的输出目录，无需重新备份。
- **CFF 配额：** 默认 100 个/账号。Content-hash 去重自动共享相同 CFF（如 54 域名 → 5 CFF）。仅当大量域名有独立 CFF 逻辑时才需关注。
- **KVS 配额：** 默认 50 个/账号（软限制）。Content-hash 去重自动共享相同 KVS（如 54 域名 → 2 KVS）。去重后仍超限请[申请提额](https://docs.aws.amazon.com/servicequotas/latest/userguide/request-quota-increase.html)。

</details>

<details>
<summary>预计转换时间</summary>

转换时间取决于规则/域名数量。以下基准使用项目自带的 `examples/cloudflare-configs/`（1 个 zone、54 个代理域名、80+ 条 CDN 规则 + 20 条 WAF 规则，覆盖 12+ 种规则类型——包括正则表达式、OR 条件、地理路由、CORS、批量重定向、内联错误页面和 KV 存储数据）：

| 流程 | 时间 |
|------|------|
| WAF | <1 秒（全 Python，无 LLM） |
| CDN | <1 秒（全 Python，无 LLM，全自动） |

时间分布：
- **WAF**：全 Python pipeline，总计 <1 秒（无 LLM 调用）。
- **CDN**：全部 10 个 Python 阶段总计 <1 秒。全自动，无用户交互。

影响因素：
- **域名数量**不影响大部分阶段（Python 一次处理所有域名）。

</details>

<details>
<summary>ACM 证书</summary>

CloudFront 要求 TLS 证书位于 **us-east-1**。运行前申请：

```bash
aws acm request-certificate \
  --domain-name "*.example.com" \
  --validation-method DNS \
  --region us-east-1
```

工具会生成 `data "aws_acm_certificate"` 数据源，在 `terraform plan` 时自动查找已签发的证书。

</details>

<details>
<summary>本工具不配置的内容</summary>

- **CloudFront 访问日志** — 涉及 S3 桶决策，超出迁移范围。如需要，自行在 `main.tf` 中添加 `logging_config`。
- **DNS 切换** — 创建了 distribution 但不修改 DNS 记录。

</details>

<details>
<summary>需要了解的 AWS WAF 配额</summary>

- **每账号每区域 IP set 数量**：100（软限制，可通过 support case 申请提额）
- **每个 WebACL 的 IP set + regex set 引用数**：50（**硬限制**，不可通过 Service Quotas 提额）
- **每账号每区域 WebACL 数量**：100（软限制）

Pipeline 首先尝试 legacy 模式（2 个 WebACL）。如果引用语句超过每个 WebACL 的硬限制（50），自动回退为 per-domain WebACL；当 inline IP set 超过 100 时，启用跨规则 IP set 去重。生成的部署手册包含 Quota Usage 表格，显示实际使用量与限制的对比。详见 [为什么用 CloudFormation](./docs/why-cloudformation_CN.md)。

</details>

## 获取备份

如果你还没有 CloudflareBackup 导出，使用 `backup/` 里自带的工具：

```bash
cd backup
cp config.example config
# 编辑 config：填入你的 API Token（或 Global API Key）和域名——详见 backup/README.md
./cloudflare_backup.sh          # macOS/Linux；Windows 用户通过 WSL 运行
```

这会生成 `<zone>/<timestamp>/` 和 `account/<timestamp>/` 目录——那个父目录就是你要交给转换器的路径。你的凭据只存在本地 `config` 文件里，AI agent 绝不会读取或索取。

备份工具即 [chenghit/CloudflareBackup](https://github.com/chenghit/CloudflareBackup)，为方便使用随本仓库分发。

## 如何运行

**无需安装。** 脚本会自定位，从你克隆仓库的任何位置都能运行。

- **基于 skill 的 agent**（Kiro CLI、Claude Code）：会自动发现 `converter/SKILL.md`——直接开始对话、描述需求即可。
- **其他任何 agent**（Codex、Cursor 等）：让它读取 `AGENTS.md`（很多工具会自动读取）并按其操作。

agent 会建立三个路径——`$REPO`（克隆目录）、`$OUT`（你选定的输出工作目录）、`$CONFIG_PATH`（你的备份）——然后运行流程。输出写入 `$OUT`，绝不写进仓库内部。

高级用户可直接运行各流程阶段：都是 `converter/scripts/` 下的纯 Python/Bash 脚本。WAF pipeline 通过 `waf-pipeline.sh` 运行；CDN 各阶段是独立脚本。确切的调用顺序见 `converter/SKILL.md`。

## 更多信息

- [最佳实践](./docs/best-practices_CN.md)
- [部署指南](./docs/deployment-guide_CN.md)
- [限制与注意事项](./docs/limitations_CN.md)
- [故障排除](./docs/troubleshooting_CN.md)
- [为何不用 cf-terraforming？](./docs/why-not-cf-terraforming_CN.md)
- [为什么 WAF 用 CloudFormation 而不是 Terraform？](./docs/why-cloudformation_CN.md)

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
