# Cloudflare to AWS Edge 迁移工具 | [English](./README.md)

**通过AI对话，自动将Cloudflare配置转换为AWS边缘服务配置**

## How to clone this repo

Follow this guide: https://w.amazon.com/bin/view/Users/rayjwil/gitlab/

## 为什么需要这个工具

从Cloudflare迁移到AWS时，手工转换数百条规则既耗时又容易出错。本工具利用GenAI能力，通过对话式交互自动完成批量配置转换，将迁移时间从数天缩短到数小时。

## 功能概览

本工具包含多个独立的Kiro Powers，每个power专注于特定类型的配置转换：

| Power | 输入 | 输出 | 状态 |
|-------|------|------|------|
| **cloudflare-to-aws-waf-converter** | Cloudflare安全规则（WAF、Rate Limiting、IP Access等） | AWS WAF配置（Terraform） | ✅ 可用 |
| **cloudflare-to-cloudfront-functions-converter** | Cloudflare transformation规则（Redirect、URL Rewrite、Header Transform等） | CloudFront Functions（JavaScript） | ✅ 可用 |
| **cloudflare-to-cloudfront-config-converter** | Cloudflare CDN配置（Cache、Origin、SSL等） | CloudFront Distribution配置（Terraform） | 🚧 开发中 |

**重要**：每个power需要在独立的Kiro对话中使用，避免在同一对话中混合多种转换任务。

## 推荐配置

### 模型选择

- **默认配置**：`claude-sonnet-4.5`（Kiro默认）
  - 适用场景：规则数量 < 100条
  - 足够处理大多数迁移场景

- **大规模配置**：`claude-sonnet-4.5-1m`
  - 适用场景：规则数量 > 100条
  - 支持更大的context window
  - 配置方法：在Kiro中运行 `/model` 命令切换

### 系统要求

- Kiro IDE（桌面应用程序）
- 足够的磁盘空间存储Cloudflare配置备份

## 快速开始

```bash
# 1. 安装Kiro
# 下载地址：https://kiro.dev/downloads/

# 2. 备份Cloudflare配置
# 使用独立的备份工具：https://github.com/chenghit/CloudflareBackup
# 按照该repo的README安装和使用

# 3. 在Kiro中安装powers
# 打开Kiro → Powers面板（👻⚡ 图标）
# 点击"Add power from GitHub"
# 输入：https://github.com/chenghit/cloudflare-aws-edge-config-converter
# 选择并安装两个powers

# 4. 开始转换
# 在Kiro中打开新对话
# 输入："请将 /path/to/cloudflare-config 目录中的Cloudflare安全规则转换为AWS WAF配置"
```

## 前置条件

### 1. 安装Terraform

本工具生成的AWS WAF配置需要Terraform 1.8.0或更高版本。

```bash
# 检查当前版本
terraform version

# 如果版本低于1.8.0，请访问以下链接升级：
# https://developer.hashicorp.com/terraform/install
```

**重要**：AWS Provider 6.x要求Terraform >= 1.8.0。如果使用较低版本的Terraform，会在`terraform plan`时遇到"Unrecognized remote plugin message"错误。

### 2. 安装Kiro

按照官方文档安装：
- Kiro安装：https://kiro.dev/docs/getting-started/installation/

## 安装

### 从GitHub安装

1. 打开Kiro IDE
2. 点击Powers面板（👻⚡ 图标）
3. 点击"Add power from GitHub"
4. 输入仓库URL：`https://github.com/chenghit/cloudflare-aws-edge-config-converter`
5. 选择要安装的power：
   - `cloudflare-to-aws-waf-converter`
   - `cloudflare-to-cloudfront-functions-converter`

### 从本地路径安装（用于开发）

1. 克隆本仓库
2. 打开Kiro IDE
3. 点击Powers面板
4. 点击"Add power from Local Path"
5. 选择power目录

## 使用指南

### 准备工作：备份Cloudflare配置

**推荐方式**（安全）：

使用独立的备份工具：**[CloudflareBackup](https://github.com/chenghit/CloudflareBackup)**

按照该repo的README完成Cloudflare配置备份，然后在Kiro中引用备份目录路径进行转换。

**为什么不推荐在Kiro中提供API token？**

Token会保留在对话历史中，存在泄露风险。使用独立备份工具在本地运行更安全。

**使用示例配置**（用于测试）：

如果你想先测试工具而不备份自己的配置，可以使用项目提供的示例配置：
- 示例配置位置：`examples/cloudflare-configs/`
- 包含真实的Cloudflare配置结构
- 可直接用于测试转换功能

### Power 1: 转换安全规则到AWS WAF

**触发方式**：Power在你提到"Cloudflare"和"AWS WAF"或"安全规则"时自动激活

**示例对话**：

```
用户: 请将 ./cloudflare_config 目录中的Cloudflare安全规则转换为AWS WAF配置

Kiro: [读取配置文件，生成规则摘要]
      请确认以下规则摘要是否正确...

用户: 确认正确

Kiro: 请提供一个Web ACL名称用于部署

用户: my-web-acl

Kiro: [生成Terraform配置文件]
```

**输出文件**：

- `versions.tf` - Terraform和AWS Provider版本约束（要求AWS Provider >= 6.4.0）
- `main.tf` - 两个Web ACL配置（website和api-and-file）
- `variables.tf` - 变量定义
- `terraform.tfvars` - 变量值
- `README_aws-waf-terraform-deployment.md` - 部署指南

**完整示例**：[examples/conversation-history/cloudflare-to-aws-waf.txt](examples/conversation-history/cloudflare-to-aws-waf.txt)

### Power 2: 转换Transformation规则到CloudFront Functions

**触发方式**：Power在你提到"Cloudflare"和"CloudFront"或"transformation"或"redirect"时自动激活

**示例对话**：

```
用户: 请将 ./cloudflare_config 目录中的Cloudflare transformation规则转换为CloudFront Function

Kiro: [读取配置文件，生成规则摘要]
      请确认以下规则摘要是否正确...

用户: 确认正确

Kiro: 请提供一个CloudFront Function名称

用户: my-viewer-request-function

Kiro: [生成JavaScript代码和部署指南]
```

**输出文件**：

- `cloudflare-transformation-rules-summary.md` - 规则摘要
- `viewer-request-function.js` - CloudFront Function代码
- `viewer-request-function.min.js` - 压缩版本（如需要）
- `key-value-store.json` - KVS数据（如需要）
- `README_function_and_kvs_deployment.md` - 部署指南

**完整示例**：[examples/conversation-history/cloudflare-to-cloudfront-functions.txt](examples/conversation-history/cloudflare-to-cloudfront-functions.txt)

### Power 3: 转换CDN配置到CloudFront（开发中）

此功能计划在下一版本发布。

## 最佳实践

### ✅ 推荐做法

1. **一次转换一个项目**

   - 完成一个domain的转换后，新开对话
   - 避免多个项目的配置在同一对话中混淆

2. **分别转换不同类型的规则**

   - 在独立对话中转换安全规则
   - 在另一个对话中转换transformation规则
   - 不要在同一对话中混合转换

3. **使用清晰的描述**

   - 转换安全规则：提到"AWS WAF"或"安全规则"
   - 转换transformation规则：提到"CloudFront Function"或"redirect"
   - 帮助Kiro正确激活对应的power

4. **验证生成的摘要**

   - Kiro会生成规则摘要供你确认
   - 仔细检查摘要，确保理解正确
   - 发现问题及时纠正

### ❌ 避免的做法

1. **不要在同一对话中转换多个项目**

   - 会导致context混淆
   - AI可能产生幻觉，混淆不同项目的配置

2. **不要混合转换不同类型的规则**

   - 例如：在同一对话中既转换WAF又转换CloudFront Functions
   - 降低转换质量

3. **不要使用模糊的描述**

   - 避免："帮我转换Cloudflare配置"（不明确转换什么）
   - 使用："将Cloudflare安全规则转换为AWS WAF配置"（明确具体）

## 限制和注意事项

### 不转换的内容

* **托管规则（Managed Rules）**

  - 原因：AWS WAF不支持Cloudflare专有功能（如API Abuse Detection）
  - 替代方案：在AWS WAF中直接添加托管规则（Anti-DDoS、Core Rule Set、Bot Control等）
  - 这些标准化配置无需AI转换，避免幻觉

* **Page Rules（已弃用）**

  - 原因：Cloudflare已弃用Page Rules功能
  - 建议：先在Cloudflare上迁移到现代规则类型（Redirect Rules、URL Rewrite Rules等），再使用本工具转换

* **部分高级Transformation规则**

  - 原因：Cloudflare和CloudFront功能并非一一对应
  - 说明：工具会在生成的文档中列出无法转换的规则及替代方案

### 大规模配置的考虑

* **Token消耗**

  - 规则数量 > 100条时，token消耗显著增加
  - 可能影响转换质量
  - 建议：使用`claude-sonnet-4.5-1m`模型，或分批转换

* **转换时间**

  - 规则越多，转换时间越长
  - 通常：50条规则约需5-10分钟

### 转换准确性

* **需要人工审核**

  - AI生成的配置需要人工审核
  - 特别是复杂的条件逻辑和正则表达式
  - 建议在测试环境先验证

* **边界情况**

  - 某些复杂的嵌套条件可能需要手工调整
  - 工具会在文档中标注需要注意的地方

## 故障排除

### Power未激活

**问题**：Kiro没有激活对应的power进行转换

**解决方案**：

1. 检查对话中是否包含正确的关键词（如"Cloudflare" + "AWS WAF"）
2. 明确说明要转换的内容类型（安全规则 vs transformation规则）
3. 提供配置文件的完整路径

### 转换结果不符合预期

**问题**：生成的配置与预期不符

**解决方案**：

1. 检查Cloudflare配置文件是否完整
2. 确认规则摘要阶段是否正确理解了配置
3. 尝试在新对话中重新转换
4. 考虑分批转换复杂配置

### Context混淆

**问题**：AI混淆了不同项目或不同类型的规则

**解决方案**：

1. 立即停止当前对话
2. 新开一个对话
3. 一次只转换一个项目的一种类型规则

## 相关资源

- [Kiro文档](https://kiro.dev/docs/)
- [Kiro Powers](https://kiro.dev/powers/)
- [AWS WAF文档](https://docs.aws.amazon.com/waf/)
- [CloudFront Functions文档](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/cloudfront-functions.html)

## Roadmap

### 🚧 Powers 3-9: 完整的CDN配置迁移方案（架构设计中）

我们正在设计一套更完整的CDN配置迁移方案，将当前的单一power重构为多个专门的powers：

**架构设计文档：**
- [Power 3-4 Architecture Design (English)](./docs/architecture/power-3-4-design-EN.md)
- [Power 3-4 架构设计 (中文)](./docs/architecture/power-3-4-design-CN.md)

**计划中的Powers：**

| Power | 职责 | 输出 | 状态 |
|-------|-----|------|------|
| **Power 3** | 配置分析器 - 分析Cloudflare CDN配置，按域名分组，判断实现方式 | 分析报告、实施计划、用户决策模板 | 🎨 架构设计中 |
| **Power 4** | 任务编排器 - 生成任务分配和执行指南 | 任务分配文件、执行指南 | 🎨 架构设计中 |
| **Power 5** | Viewer Request Function转换器 | CloudFront Function代码（每域名一个文件） | 📝 待设计 |
| **Power 6** | Viewer Response Function转换器 | CloudFront Function代码（每域名一个文件） | 📝 待设计 |
| **Power 7** | Origin Request Lambda转换器 | Lambda@Edge代码 | 📝 待设计 |
| **Power 8** | Origin Response Lambda转换器 | Lambda@Edge代码 | 📝 待设计 |
| **Power 9** | CloudFront配置生成器 | Terraform配置、部署指南 | 📝 待设计 |

**核心改进：**
- ✅ **按域名分组规则** - 满足CloudFront Function 10KB大小限制
- ✅ **基于实现方式的任务分配** - 而非按Cloudflare规则类型
- ✅ **多阶段转换流程** - 分析→决策→编排→转换→部署
- ✅ **成本意识设计** - 标记高成本方案（Viewer Lambda@Edge）为不可转换
- ✅ **无状态工作流** - 通过Markdown文件传递状态，支持分批处理

**实施后的影响：**

⚠️ **当Powers 3-9实现后，当前的`cloudflare-to-cloudfront-functions-converter`将被废弃（deprecated）。**

原因：
- Powers 3-9提供更完整的CDN配置转换（不仅是Functions）
- 按域名分组，更好地处理Function大小限制
- 支持更复杂的转换场景（Lambda@Edge、Policies、Cache Behaviors）
- 更清晰的工作流和任务分配

**时间线：**
- 2026 Q1: 完成架构设计，实现Power 3原型
- 2026 Q2: 实现Powers 4-9
- 2026 Q2末: 废弃`cloudflare-to-cloudfront-functions-converter`
- 2026 Q3: 研究subagent架构以增强context隔离
  - 探索Kiro的subagent能力，将专门任务委托给独立的subagents
  - 设计让planner、orchestrator和converters作为隔离subagents运行的工作流
  - 目标：通过在单个对话中分离关注点来防止context混淆和幻觉

---

## 反馈和贡献

如有问题或建议，欢迎提交Issue或Pull Request。

---

**AWS内部用户**：可阅读[AI-powered Cloudflare-AWS conversion tool](https://quip-amazon.com/rJQHABEjIsUW)了解设计思想和架构细节。
