# Cloudflare to AWS Edge 迁移工具 | [English](./README.md)

**通过 AI 对话自动将 Cloudflare 配置转换为 AWS 边缘服务配置**

---

## ⚠️ 重要：必需的输入格式

**此工具仅适用于由 [CloudflareBackup](https://github.com/chenghit/CloudflareBackup) 生成的配置文件。**

**❌ 不兼容 [cf-terraforming](https://github.com/cloudflare/cf-terraforming)（Cloudflare 官方工具）**

如果您提供由 cf-terraforming 生成的 Terraform HCL 文件（`.tf`），此工具的技能将不会激活。任何转换尝试都将仅依赖底层 LLM 的通用能力，而不会使用此工具中编码的专门转换逻辑、验证规则和最佳实践。结果将不可预测且不受支持。

**为什么需要 CloudflareBackup：**
- **可预测的文件结构**：CloudflareBackup 创建标准目录结构，具有固定文件名（`WAF-Custom-Rules.txt`、`Rate-limits.txt`、`IP-Lists.txt` 等）
- **一键备份**：在单次运行中备份所有配置，组织一致
- **技能优化**：文件位置和命名约定专为此工具的工作流程设计

**为什么不支持 cf-terraforming：**
- **仍需要 API 调用**：cf-terraforming 无法从域名发现区域 ID - 您必须调用 API
- **错误的输出格式**：生成用于管理 Cloudflare 的 Terraform HCL 代码，而不是用于迁移的配置数据
- **更多工作，而非更少**：需要多个手动命令 vs. 一个 CloudflareBackup 命令
- **没有实际好处**：如果您无论如何都要调用 API，CloudflareBackup 一步就能给您所需的一切

详见 [为什么不用 cf-terraforming？](#why-not-cf-terraforming) 的详细说明。

---

## 为什么使用此工具

从 Cloudflare 迁移到 AWS 时手动转换数百条规则既耗时又容易出错。此工具利用 GenAI 能力通过对话交互自动化批量配置转换，将迁移时间从数天缩短到数小时。

## 功能概述

此工具包含多个独立的代理技能，每个都专注于特定的配置转换：

| 技能 | 输入 | 输出 | 状态 |
|-------|-------|--------|--------|
| **cf-waf-converter** | Cloudflare 安全规则（WAF、速率限制、IP 访问等） | AWS WAF 配置（Terraform） | ✅ 可用 |
| **cf-functions-converter** | Cloudflare 转换规则（重定向、URL 重写、标头转换等） | CloudFront Functions（JavaScript） | ✅ 可用 |
| **cf-cdn-analyzer** | Cloudflare CDN 配置（缓存、源站、重定向等） | 基于主机名的配置摘要和用户决策模板 | ✅ 可用 |

**为什么使用子代理？** 每个技能在独立的 Kiro 子代理中运行，具有隔离的上下文。这防止了在处理复杂多步转换时的上下文污染，特别是对于即将推出的 CDN 迁移工作流程（技能 3-11），需要并行执行多个转换器技能。详见 [架构设计](./docs/architecture/)。

## 推荐配置

### 模型选择

- **默认配置**：`claude-sonnet-4.5`（Kiro 默认）
  - 使用场景：< 100 条规则
  - 适用于大多数迁移场景

- **大规模配置**：`claude-sonnet-4.5-1m`
  - 使用场景：> 100 条规则或具有复杂配置的多个域名
  - **推荐用于 CDN 迁移**：如果您有 10+ 个代理域名和各种规则，请使用此模型
  - 支持更大的上下文窗口
  - 配置：在 Kiro 中使用 `/model` 命令切换

**CDN 迁移注意事项**：CDN 配置分析（cf-cdn-analyzer）同时处理所有代理域名的所有规则。当域名和规则很多时，上下文大小会快速增长。使用 `claude-sonnet-4.5-1m` 确保足够的上下文窗口。

### 系统要求

- Kiro CLI 或 Kiro IDE
- 足够的磁盘空间用于 Cloudflare 配置备份

## 快速开始

### 使用 Kiro CLI

```bash
# 1. 安装 Kiro CLI
curl -fsSL https://cli.kiro.dev/install | bash

# 2. 备份 Cloudflare 配置
# 使用独立备份工具：https://github.com/chenghit/CloudflareBackup
# 按照该仓库的 README 进行安装和使用

# 3. 克隆此仓库并安装技能
git clone https://github.com/chenghit/cloudflare-aws-edge-config-converter.git
cd cloudflare-aws-edge-config-converter
./install.sh

# 4. 启动 Kiro CLI 聊天
kiro-cli chat

# 5. 切换到转换器子代理并开始转换
# 在聊天中，使用 /agent swap 命令：
/agent swap cf-waf-converter

# 然后提供您的 Cloudflare 配置路径：
# "Convert security rules in /path/to/cloudflare-config"

# 或者对于转换规则：
/agent swap cf-functions-converter
# "Convert transformation rules in /path/to/cloudflare-config"
```

### 使用 Kiro IDE

```bash
# 1. 安装 Kiro IDE 扩展到 VS Code
# 下载地址：https://kiro.dev/downloads/

# 2. 备份 Cloudflare 配置（与 CLI 相同）
# 使用独立备份工具：https://github.com/chenghit/CloudflareBackup

# 3. 克隆此仓库并安装技能
git clone https://github.com/chenghit/cloudflare-aws-edge-config-converter.git
cd cloudflare-aws-edge-config-converter
./install.sh

# 4. 在 VS Code 中打开您的项目（已安装 Kiro IDE）

# 5. 切换到转换器子代理
# 使用命令面板（Cmd/Ctrl+Shift+P）→ "Kiro: Switch Agent"
# 选择：cf-waf-converter、cf-functions-converter 或 cf-cdn-analyzer

# 6. 在 Kiro 聊天面板中开始对话
# "Convert security rules in /path/to/cloudflare-config"
```

## 前提条件

### 1. 安装 Terraform

此工具生成的 AWS WAF 配置需要 Terraform 1.8.0 或更高版本。

```bash
# 检查当前版本
terraform version

# 如果版本低于 1.8.0，请通过以下方式升级：
# https://developer.hashicorp.com/terraform/install
```

**重要**：AWS Provider 6.x 需要 Terraform >= 1.8.0。使用较低的 Terraform 版本会在 `terraform plan` 期间导致"Unrecognized remote plugin message"错误。

### 2. 安装 Kiro

选择 Kiro CLI 或 Kiro IDE：

**Kiro CLI**（命令行界面）：
- 安装：https://kiro.dev/docs/getting-started/installation/
- 技能支持：自 1.24 版本起

**Kiro IDE**（Visual Studio Code 扩展）：
- 安装：https://kiro.dev/downloads/
- 技能支持：自 0.9 版本起
- 技能在 CLI 和 IDE 中的工作方式相同

## 安装

运行安装脚本来安装技能和子代理配置：

```bash
git clone https://github.com/chenghit/cloudflare-aws-edge-config-converter.git
cd cloudflare-aws-edge-config-converter
./install.sh
```

这将：
- 将技能复制到 `~/.kiro/skills/cloudflare-aws-converter/`
- 将子代理配置复制到 `~/.kiro/agents/`

已安装的子代理：
- `cf-waf-converter` - 将 Cloudflare 安全规则转换为 AWS WAF
- `cf-functions-converter` - 将 Cloudflare 转换规则转换为 CloudFront Functions

### 更新技能

要更新到最新版本：

```bash
cd cloudflare-aws-edge-config-converter
git pull
./install.sh
```

安装脚本将自动用新版本替换旧技能。

## 使用指南

### 准备：备份 Cloudflare 配置

**推荐方法**（安全）：

使用独立备份工具：**[CloudflareBackup](https://github.com/chenghit/CloudflareBackup)**

按照该仓库的 README 完成 Cloudflare 配置备份，然后在 Kiro 中引用备份目录路径进行转换。

**为什么不在 Kiro 中提供 API 令牌？**

令牌会保留在对话历史中，存在安全风险。在本地使用独立备份工具更安全。

**使用示例配置**（用于测试）：

如果您想在不备份自己配置的情况下测试工具，可以使用提供的示例配置：
- 位置：`examples/cloudflare-configs/`
- 包含真实的 Cloudflare 配置结构
- 可直接用于测试转换功能

### 技能 1：将安全规则转换为 AWS WAF

**推荐用法**（主代理自动调用子代理）：

```
User: Convert Cloudflare security rules in /path/to/cloudflare-config to AWS WAF using cf-waf-converter

Kiro: [自动调用 cf-waf-converter 子代理]
      [读取配置文件，生成 Terraform 文件]
      ✅ 转换完成！生成的文件：
      - versions.tf
      - main.tf
      - variables.tf
      - terraform.tfvars
      - README_aws-waf-terraform-deployment.md
```

**备选用法**（手动切换子代理）：

```
User: /agent swap cf-waf-converter

User: Convert security rules in /path/to/cloudflare-config

Kiro: [生成 Terraform 配置文件]
```

**输出文件**：

- `versions.tf` - Terraform 和 AWS Provider 版本约束（需要 AWS Provider >= 6.4.0）
- `main.tf` - 两个 Web ACL 配置（website 和 api-and-file）
- `variables.tf` - 变量定义
- `terraform.tfvars` - 变量值
- `README_aws-waf-terraform-deployment.md` - 部署指南

**完整示例**：[examples/conversation-history/cloudflare-to-aws-waf.txt](examples/conversation-history/cloudflare-to-aws-waf.txt)

### 技能 2：将转换规则转换为 CloudFront Functions

**推荐用法**（主代理自动调用子代理）：

```
User: Convert Cloudflare transformation rules in /path/to/cloudflare-config to CloudFront Functions using cf-functions-converter

Kiro: [自动调用 cf-functions-converter 子代理]
      [读取配置文件，生成 JavaScript 代码]
      ✅ 转换完成！生成的文件：
      - cloudflare-transformation-rules-summary.md
      - viewer-request-function.js
      - viewer-request-function.min.js（如果需要）
      - key-value-store.json（如果需要）
      - README_function_and_kvs_deployment.md
```

**备选用法**（手动切换子代理）：

```
User: /agent swap cf-functions-converter

User: Convert transformation rules in /path/to/cloudflare-config

Kiro: [生成 JavaScript 代码和部署指南]
```

**输出文件**：

- `cloudflare-transformation-rules-summary.md` - 规则摘要
- `viewer-request-function.js` - CloudFront Function 代码
- `viewer-request-function.min.js` - 压缩版本（如需要）
- `key-value-store.json` - KVS 数据（如需要）
- `README_function_and_kvs_deployment.md` - 部署指南

**完整示例**：[examples/conversation-history/cloudflare-to-cloudfront-functions.txt](examples/conversation-history/cloudflare-to-cloudfront-functions.txt)

### 技能 3：分析 CDN 配置

**推荐用法**（主代理自动调用子代理）：

```
User: Analyze Cloudflare CDN configuration in /path/to/cloudflare-config using cf-cdn-analyzer

Kiro: [自动调用 cf-cdn-analyzer 子代理]
      [读取配置文件，检测 SaaS，按主机名分组规则]
      ✅ 分析完成！生成的文件：
      - hostname-based-config-summary.md
      - README_1_analyzer.md
```

**备选用法**（手动切换子代理）：

```
User: /agent swap cf-cdn-analyzer

User: Analyze CDN configuration in /path/to/cloudflare-config

Kiro: [生成配置摘要和下一步指南]
```

**输出文件**：

- `hostname-based-config-summary.md` - 按主机名分组的配置和用户决策模板
- `README_1_analyzer.md` - 下一步指南

**此技能的功能**：

- 检测 SaaS 配置（如发现则终止）
- 识别代理 DNS 记录（每个成为一个 CloudFront Distribution）
- 检测基于 IP 的源站（标记为不可转换）
- 按照 Cloudflare 执行顺序按主机名分组所有规则
- 识别隐式 Cloudflare 默认缓存行为
- 生成默认缓存行为的用户决策模板

**下一步**：编辑摘要文件并运行规划器技能（cf-cdn-planner）以确定 CloudFront 实现方法。

**注意**：这是多阶段 CDN 迁移工作流程（技能 3-11）的第一步。完整工作流程请参见 [架构设计](./docs/architecture/skill-3-11-design-EN.md)。

## 最佳实践

### ✅ 推荐做法

1. **为不同任务使用独立的子代理**
   - 使用 `/agent swap cf-waf-converter` 处理安全规则
   - 使用 `/agent swap cf-functions-converter` 处理转换规则
   - 使用 `/agent swap cf-cdn-analyzer` 进行 CDN 配置分析
   - 每个子代理都有隔离的上下文以避免混淆

2. **一次转换一个项目**
   - 完成一个域名的转换后，开始新的聊天会话
   - 避免混合多个项目的配置

3. **提供清晰的文件路径**
   - 始终指定 Cloudflare 配置目录的完整路径
   - 示例："Convert security rules in /Users/me/cloudflare-backup/example.com/2026-01-12"

4. **验证生成的摘要**
   - Kiro 会生成规则摘要供您确认
   - 仔细审查摘要以确保正确理解
   - 如发现问题请及时纠正

### ❌ 应避免的做法

1. **不要在同一对话中转换多个项目**
   - 会导致上下文混淆
   - AI 可能产生幻觉并混合不同项目的配置

2. **不要混合不同规则类型的转换**
   - 示例：在同一对话中同时转换 WAF 和 CloudFront Functions
   - 为不同的转换类型使用独立的子代理

3. **不要使用模糊的描述**
   - 避免："Help me convert Cloudflare configuration"（不清楚要转换什么）
   - 使用："Convert Cloudflare security rules to AWS WAF configuration"（具体且清晰）

## 限制和注意事项

### 不转换的内容

* **托管规则**
  - 原因：AWS WAF 不支持 Cloudflare 特定功能（如 API 滥用检测）
  - 替代方案：直接在 AWS WAF 中添加托管规则（反 DDoS、核心规则集、机器人控制等）
  - 这些标准化配置不需要 AI 转换，避免幻觉

* **页面规则（已弃用）**
  - 原因：Cloudflare 已弃用页面规则功能
  - 建议：首先在 Cloudflare 中迁移到现代规则类型（重定向规则、URL 重写规则等），然后使用此工具进行转换

* **Snippets 和 Workers**
  - 原因：这些是自定义 JavaScript/TypeScript 函数，而非配置规则
  - 建议：需要手动转换 - 审查逻辑并重写为 CloudFront Functions 或 Lambda@Edge
  - 注意：未来版本可能提供转换指导

* **SaaS 和 mTLS 配置**
  - 原因：复杂的多租户和证书管理配置需要手动架构设计
  - 注意：Cloudflare Custom Hostnames (SaaS) 和 CloudFront SaaS 的实现模型根本不同
  - 建议：需要仔细规划的手动迁移

* **图像优化和高级功能**
  - 原因：CloudFront 不原生支持 Cloudflare 的图像优化、Zaraz 等功能
  - 替代方案：部署 AWS 解决方案（例如 Dynamic Image Transformation for Amazon CloudFront）
  - 注意：这些需要单独的基础设施设置，超出简单配置转换范围

* **某些高级转换规则**
  - 原因：Cloudflare 和 CloudFront 功能不是一对一的
  - 注意：工具会在生成的文档中列出不可转换的规则和替代方案

### 大规模配置考虑

* **令牌消耗**
  - 超过 100 条规则时令牌消耗显著增加
  - 可能影响转换质量
  - 建议：使用 `claude-sonnet-4.5-1m` 模型，或分批转换

* **转换时间**
  - 规则越多 = 转换时间越长
  - 典型：50 条规则约 5-10 分钟

### 转换准确性

* **需要手动审查**
  - AI 生成的配置需要手动审查
  - 特别是复杂的条件逻辑和正则表达式
  - 建议先在测试环境中验证

* **边缘情况**
  - 某些复杂的嵌套条件可能需要手动调整
  - 工具会在文档中标记需要注意的区域

## 故障排除

### 子代理无法切换

**问题**：`/agent swap` 命令不起作用或找不到子代理

**解决方案**：
1. 验证安装：检查 `~/.kiro/agents/cf-waf-converter.json` 是否存在
2. 重启 Kiro CLI：退出并启动新的 `kiro-cli chat` 会话
3. 列出可用代理：使用 `/agent list` 查看已安装的子代理

### 转换结果不符合预期

**问题**：生成的配置不符合预期

**解决方案**：
1. 检查 Cloudflare 配置文件是否完整
2. 确认规则摘要阶段是否正确理解了配置
3. 尝试在新对话中重新转换
4. 考虑分批转换复杂配置

### 上下文混淆

**问题**：AI 混合了不同项目或不同规则类型

**解决方案**：
1. 立即停止当前对话
2. 使用 `/agent swap` 开始新对话到正确的子代理
3. 一次只转换一个项目的一种规则类型

### 技能未正确激活

**问题**：代理说"I will use [skill-name]"但不遵循技能的工作流程

**症状**：
- 代理生成临时分析而不是遵循定义的步骤
- 输出文件未创建或文件名错误
- 代理不读取参考文档

**解决方案**：
在请求中使用与技能描述匹配的特定关键词：
- 对于 cf-waf-converter：说"convert **security rules**"或"convert to **AWS WAF**"
- 对于 cf-functions-converter：说"convert **transformation rules**"或"convert to **CloudFront Functions**"
- 对于 cf-cdn-analyzer：说"analyze **CDN configuration**"或"analyze **CDN config**"

**示例**：
- ❌ 模糊："analyze my cloudflare config files"（技能可能不激活）
- ✅ 具体："analyze my cloudflare **CDN config**"（技能正确激活）

## 为什么不用 cf-terraforming？

[cf-terraforming](https://github.com/cloudflare/cf-terraforming) 是 Cloudflare 的官方工具，用于将配置导出到 Terraform。虽然它在基于 Terraform 的基础设施管理方面很出色，但它与此迁移工具根本不兼容。

### 致命缺陷：您仍然需要 API

**cf-terraforming 需要区域 ID 和账户 ID 作为输入** - 它无法从域名发现它们。

```bash
# cf-terraforming 需要区域 ID
cf-terraforming generate --resource-type cloudflare_dns_record --zone <ZONE_ID>

# 但您从哪里获得区域 ID？
# 您必须调用 Cloudflare API：
curl -s "https://api.cloudflare.com/client/v4/zones?name=example.com" \
  -H "Authorization: Bearer $TOKEN" | jq -r '.result[0].id'
```

**这意味着：**
1. 您配置域名：`example.com`、`api.example.com`
2. 您调用 API 获取区域 ID
3. 您使用这些区域 ID 调用 cf-terraforming
4. 您获得 Terraform HCL 代码
5. 您需要将 HCL 转换回配置数据进行迁移

**vs. CloudflareBackup：**
1. 您配置域名：`example.com`、`api.example.com`
2. CloudflareBackup 调用 API 获取区域 ID 和配置数据
3. 您获得准备迁移的配置数据

**当第 2 步已经给您所需的一切时，为什么要添加第 3-5 步？**

### "无意义绕道"问题

```
用户目标：从 Cloudflare 迁移到 AWS
              ↓
┌─────────────────────────────────────────────────────────────┐
│ 选项 1：cf-terraforming（绕远路）                           │
├─────────────────────────────────────────────────────────────┤
│ 1. 调用 API 获取区域 ID                                     │
│ 2. 调用 cf-terraforming 获取 Terraform HCL                 │
│ 3. 解析 HCL 提取配置数据                                    │
│ 4. 转换到 AWS                                               │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ 选项 2：CloudflareBackup（直接路径）                       │
├─────────────────────────────────────────────────────────────┤
│ 1. 调用 API 获取区域 ID 和配置数据                          │
│ 2. 转换到 AWS                                               │
└─────────────────────────────────────────────────────────────┘
```

**cf-terraforming 添加了两个不必要的步骤**（2 和 3），对迁移没有任何价值。

### cf-terraforming 实际做什么

cf-terraforming 本质上是一个包装器：
1. 调用 Cloudflare API（与 CloudflareBackup 相同）
2. 将 JSON 响应转换为 Terraform HCL 语法
3. 输出 Terraform 代码

**对于迁移，您需要第 1 步的数据，而不是第 3 步的代码。**

将 cf-terraforming 用于迁移就像：
- 翻译英语 → 法语 → 英语（而不是直接使用英语）
- 转换 JSON → HCL → JSON（而不是直接使用 JSON）
- 绕道经过另一个城市到达目的地

### "仍需要 API"示例

#### 示例 1：获取区域 ID
```bash
# cf-terraforming 无法做到这一点：
cf-terraforming generate --resource-type cloudflare_dns_record --domain example.com
# Error: unknown flag: --domain

# 您必须使用 API：
ZONE_ID=$(curl -s "https://api.cloudflare.com/client/v4/zones?name=example.com" \
  -H "Authorization: Bearer $TOKEN" | jq -r '.result[0].id')

# 然后调用 cf-terraforming：
cf-terraforming generate --resource-type cloudflare_dns_record --zone $ZONE_ID
```

#### 示例 2：获取列表项
```bash
# cf-terraforming 需要列表 ID：
cf-terraforming generate --resource-type cloudflare_list_item \
  --account $ACCOUNT_ID --resource-id "cloudflare_list_item=$LIST_ID"

# 您从哪里获得列表 ID？从 API：
curl -s "https://api.cloudflare.com/client/v4/accounts/$ACCOUNT_ID/rules/lists" \
  -H "Authorization: Bearer $TOKEN" | jq -r '.result[].id'
```

#### 示例 3：获取账户 ID
```bash
# cf-terraforming 需要账户 ID：
cf-terraforming generate --resource-type cloudflare_list --account $ACCOUNT_ID

# 您从哪里获得账户 ID？从 API：
curl -s "https://api.cloudflare.com/client/v4/zones/$ZONE_ID" \
  -H "Authorization: Bearer $TOKEN" | jq -r '.result.account.id'
```

**在每种情况下，您都已经在调用返回所需配置数据的 API。**

### 真实对比

| 步骤 | cf-terraforming 方法 | CloudflareBackup 方法 |
|------|-------------------------|---------------------------|
| 1. 获取区域 ID | 调用 API ✓ | 调用 API ✓ |
| 2. 获取配置数据 | 调用 cf-terraforming | 已从第 1 步获得 |
| 3. 解析 HCL | 解析 Terraform 语法 | 不适用 |
| 4. 提取配置 | 转换 HCL → JSON | 不适用 |
| 5. 迁移到 AWS | 使用转换工具 | 使用转换工具 |

**cf-terraforming 添加了 3 个额外步骤（2、3、4），对迁移毫无作用。**

### cf-terraforming 实际用途

cf-terraforming 是为完全不同的用例设计的：

**用例：采用 Terraform 管理 Cloudflare**
```
当前状态：通过仪表板/API 管理 Cloudflare
目标：通过 Terraform 管理 Cloudflare
解决方案：cf-terraforming 生成 Terraform 代码
结果：继续使用 Cloudflare，现在使用 IaC
```

**不适用于：从 Cloudflare 迁移到 AWS**
```
当前状态：使用 Cloudflare
目标：迁移到 AWS
解决方案：??? cf-terraforming 生成 Cloudflare Terraform 代码 ???
结果：您仍需要转换到 AWS（cf-terraforming 无法帮助）
```

### "但我已经使用 cf-terraforming"论点

**问：**"我已经使用 cf-terraforming 管理我的 Cloudflare 基础设施。我不能直接使用这些文件吗？"

**答：不能，因为：**

1. **您仍需要来自 API 的新数据**
   - 您的 `.tf` 文件可能已过时
   - 迁移需要当前配置
   - 您无论如何都需要重新运行 cf-terraforming

2. **cf-terraforming 输出是为 Terraform 而非迁移设计的**
   - 包含 Terraform 特定语法（变量、引用、函数）
   - 缺少转换所需的元数据（ID、时间戳、启用状态）
   - 为 Terraform 状态管理而非数据提取优化

3. **您仍需要调用 API**
   - 为 cf-terraforming 获取区域 ID
   - 为 cf-terraforming 获取账户 ID
   - 为列表项获取列表 ID
   - **此时您已经拥有 CloudflareBackup 会给您的数据**

**更好的方法：**
- 继续使用 cf-terraforming 管理 Cloudflare
- 为迁移运行一次 CloudflareBackup（5 分钟）
- 使用此工具迁移到 AWS
- 继续使用 cf-terraforming 管理 Cloudflare（如果您保留它）

### 设计决策：不走无意义的弯路

此工具拒绝支持 cf-terraforming，因为：

1. ❌ **无论如何都需要 API**：无法避免调用 API 获取区域/账户 ID
2. ❌ **增加复杂性**：HCL 解析、格式转换、错误处理
3. ❌ **没有好处**：API 已经返回我们需要的数据
4. ❌ **更多用户工作**：多个命令 vs. 一个命令
5. ❌ **维护负担**：需要支持和测试两种输入格式

vs. CloudflareBackup：

1. ✅ **一次 API 调用**：获取区域 ID 和配置数据
2. ✅ **简单格式**：来自 API 的 JSON，无需转换
3. ✅ **直接路径**：API → 迁移工具 → AWS
4. ✅ **一个命令**：用户运行一个脚本，完成
5. ✅ **单一格式**：只需支持和测试 JSON

**如果您无论如何都要调用 API（这是必须的），请以您实际需要的格式获取您实际需要的数据。**

### 底线

支持 cf-terraforming 就像：
- 建造一座通往无处的桥
- 添加一个收费但不提供服务的中间人
- 在美国时将美元转换为欧元再转换为美元

**这不仅仅是不必要的 - 它是适得其反的。**

## 相关资源

- [Kiro 文档](https://kiro.dev/docs/)
- [Kiro IDE：自定义子代理和技能](https://kiro.dev/blog/custom-subagents-skills-and-enterprise-controls/)
- [Kiro CLI 中的代理技能支持](https://kiro.dev/changelog/cli/1-24/)
- [AWS WAF 文档](https://docs.aws.amazon.com/waf/)
- [CloudFront Functions 文档](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/cloudfront-functions.html)

## 路线图

### 🚧 技能 3-11：完整的 CDN 配置迁移解决方案（架构设计阶段）

我们正在设计一个全面的 CDN 配置迁移解决方案，将当前的单一技能重构为多个专门的技能：

**架构设计文档：**
- [技能 3-11 架构设计（英文）](./docs/architecture/skill-3-11-design-EN.md)
- [技能 3-11 架构设计（中文）](./docs/architecture/skill-3-11-design-CN.md)
- [架构变更日志](./docs/architecture/CHANGELOG.md)

**计划的技能：**

| 技能 | 职责 | 输出 | 状态 |
|-------|---------------|--------|--------|
| **技能 3** | 配置分析器 - 解析 Cloudflare CDN 配置并按主机名分组 | 基于主机名的配置摘要 + 用户输入模板 | 🎨 架构设计 |
| **技能 4** | 实现规划器 - 确定 CloudFront 实现方法 | 实现计划 | 🎨 架构设计 |
| **技能 5** | 计划验证器 - 验证实现计划的正确性 | 验证报告（关键：错误计划 = 错误转换器） | 🎨 架构设计 |
| **技能 6** | 任务编排器 - 生成任务分配和执行指南 | 任务分配文件，执行指南 | 🎨 架构设计 |
| **技能 7** | Viewer Request Function 转换器 | CloudFront Function 代码（每个域名一个文件） | 📝 待设计 |
| **技能 8** | Viewer Response Function 转换器 | CloudFront Function 代码（每个域名一个文件） | 📝 待设计 |
| **技能 9** | Origin Request Lambda 转换器 | Lambda@Edge 代码 | 📝 待设计 |
| **技能 10** | Origin Response Lambda 转换器 | Lambda@Edge 代码 | 📝 待设计 |
| **技能 11** | CloudFront 配置生成器 | Terraform 配置，部署指南 | 📝 待设计 |

**关键改进：**
- ✅ **从第一天开始的子代理架构** - 所有技能（3-11）都作为具有隔离上下文的 Kiro 子代理实现
- ✅ **关注点分离** - 分析器（解析）、规划器（决策）、验证器（验证）、编排器（分配）
- ✅ **规划前的用户决策** - 业务上下文指导技术实现决策
- ✅ **计划验证** - 在转换器执行前捕获错误（转换后无法恢复）
- ✅ **基于域名的规则分组** - 满足 CloudFront Function 10KB 大小限制
- ✅ **基于实现的任务分配** - 不是按 Cloudflare 规则类型
- ✅ **多阶段转换工作流程** - 分析 → 决策 → 规划 → 验证 → 编排 → 转换 → 部署
- ✅ **成本感知设计** - 将高成本解决方案（Viewer Lambda@Edge）标记为不可转换
- ✅ **无状态工作流程** - 通过 Markdown 文件进行状态传输，支持批处理
- ✅ **自动化脚本** - 一键安装和配置

**实现后的影响：**

⚠️ **当技能 3-11 实现后，当前的 `cf-functions-converter` 将被弃用。**

原因：
- 技能 3-11 提供更完整的 CDN 配置转换（不仅仅是 Functions）
- 基于域名的分组更好地处理 Function 大小限制
- 支持更复杂的转换场景（Lambda@Edge、策略、缓存行为）
- 更清晰的工作流程和任务分配，带有验证

**时间表：**
- 2026 Q1：完成架构设计，实现技能 3（分析器）作为子代理原型
- 2026 Q2：实现技能 4-11 作为具有上下文隔离的子代理
  - 提供 Kiro 技能安装和子代理配置的自动化脚本
  - 弃用 `cf-functions-converter`
- 2026 Q3：优化子代理工作流程和用户体验
  - 并行子代理执行的性能调优
  - 基于反馈的增强错误处理和恢复机制
  - 用户体验改进

---

## 反馈和贡献

如有问题或建议，请提交 Issue 或 Pull Request。