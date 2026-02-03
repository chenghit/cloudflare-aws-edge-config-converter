# Cloudflare to AWS Edge 迁移工具 | [English](./README.md)

**通过AI对话，自动将Cloudflare配置转换为AWS边缘服务配置**

---

## ⚠️ 重要：必需的输入格式

**本工具仅支持由 [CloudflareBackup](https://github.com/chenghit/CloudflareBackup) 生成的配置文件。**

**❌ 不兼容 [cf-terraforming](https://github.com/cloudflare/cf-terraforming)（Cloudflare官方工具）**

如果你提供由 cf-terraforming 生成的 Terraform HCL 文件（`.tf`），本工具的 Powers 将不会激活。任何转换尝试将仅依赖底层大语言模型的通用能力，而不会使用本工具中编码的专业转换逻辑、验证规则和最佳实践。转换结果将不可预测且不受支持。

**为什么必须使用 CloudflareBackup：**
- **可预测的文件结构**：CloudflareBackup 创建标准的目录结构，使用固定的文件名（`WAF-Custom-Rules.txt`、`Rate-limits.txt`、`IP-Lists.txt` 等）
- **一键备份**：一次运行即可备份所有配置，组织结构一致
- **Powers 优化**：文件位置和命名约定专为本工具的工作流设计

**为什么不支持 cf-terraforming：**
- **无标准输出结构**：cf-terraforming 输出到 stdout；用户必须手动重定向到任意命名的文件
- **需要手动执行多次**：每种资源类型（rulesets、lists、DNS records 等）都需要单独运行命令
- **不可预测的文件组织**：Powers 无法在没有标准结构的情况下可靠地定位配置文件

如果你更喜欢在 Terraform 工作流中使用 cf-terraforming，你需要手动重新组织其输出以匹配 CloudflareBackup 的结构，这违背了本工具的自动化目的。

详见 [为什么不支持 cf-terraforming？](#为什么不支持-cf-terraforming)

---

## 为什么需要这个工具

从Cloudflare迁移到AWS时，手工转换数百条规则既耗时又容易出错。本工具利用GenAI能力，通过对话式交互自动完成批量配置转换，将迁移时间从数天缩短到数小时。

## 功能概览

本工具包含多个独立的Kiro Powers，每个power专注于特定类型的配置转换：

| Skill | 输入 | 输出 | 状态 |
|-------|------|------|------|
| **cf-waf-converter** | Cloudflare安全规则（WAF、Rate Limiting、IP Access等） | AWS WAF配置（Terraform） | ✅ 可用 |
| **cf-functions-converter** | Cloudflare transformation规则（Redirect、URL Rewrite、Header Transform等） | CloudFront Functions（JavaScript） | ✅ 可用 |
| **cf-cdn-analyzer** | Cloudflare CDN配置（Cache、Origin、Redirect等） | 基于hostname的配置摘要及用户决策模板 | ✅ 可用 |

**重要**：每个skill需要在独立的Kiro对话中使用，避免在同一对话中混合多种转换任务。

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
# 点击"Add power from GitHub" → "Import power from GitHub"
# 安装WAF转换器：
#   输入：https://github.com/chenghit/cloudflare-aws-edge-config-converter/tree/main/cf-waf-converter
# 安装CloudFront Functions转换器：
#   输入：https://github.com/chenghit/cloudflare-aws-edge-config-converter/tree/main/cf-functions-converter

# 4. 在Kiro IDE中打开工作区
# 文件 → 打开文件夹 → 选择包含Cloudflare配置文件的文件夹
# 重要：Kiro IDE只能访问已打开工作区内的文件

# 5. 开始转换
# 在Kiro中打开新对话
# 输入："请将 ./cloudflare-config 目录中的Cloudflare安全规则转换为AWS WAF配置"
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
3. 点击"Add power from GitHub" → "Import power from GitHub"
4. 输入仓库URL及子目录路径：
   - WAF转换器：`https://github.com/chenghit/cloudflare-aws-edge-config-converter/tree/main/cf-waf-converter`
   - CloudFront Functions转换器：`https://github.com/chenghit/cloudflare-aws-edge-config-converter/tree/main/cf-functions-converter`
5. 点击"Install"

### 从本地路径安装（用于开发）

1. 克隆本仓库
2. 打开Kiro IDE
3. 点击Powers面板
4. 点击"Add power from GitHub" → "Import power from a folder"
5. 选择power目录：
   - `cf-waf-converter/`
   - `cf-functions-converter/`

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

### Skill 3: 分析CDN配置

**使用方法**：使用 `/agent swap cf-cdn-analyzer` 切换到CDN分析器子代理

**示例对话**：

```
用户: /agent swap cf-cdn-analyzer

Kiro: [切换到CDN分析器子代理]

用户: 分析 /path/to/cloudflare-config 中的Cloudflare CDN配置

Kiro: [读取配置文件，检测SaaS，按hostname分组规则]
      [生成 hostname-based-config-summary.md 和 README_1_analyzer.md]
      
      请编辑 hostname-based-config-summary.md 中的"Proxied Hostnames"表格，
      指示哪些hostname需要应用默认缓存行为...
```

**输出文件**：

- `hostname-based-config-summary.md` - 按hostname分组的配置摘要及用户决策模板
- `README_1_analyzer.md` - 下一步指南

**此Skill的功能**：

- 检测SaaS配置（如发现则终止）
- 识别代理DNS记录（每个记录将成为一个CloudFront Distribution）
- 检测基于IP的源站（标记为不可转换）
- 按hostname分组所有规则，遵循Cloudflare执行顺序
- 识别隐式的Cloudflare默认缓存行为
- 生成用户决策模板用于选择默认缓存行为

**下一步**：编辑摘要文件并运行Planner skill (cf-cdn-planner) 以确定CloudFront实现方法。

**注意**：这是多阶段CDN迁移工作流程（Skills 3-11）的第一步。完整工作流程见[架构设计](./docs/architecture/skill-3-11-design-CN.md)。

## 最佳实践

### ✅ 推荐做法

1. **使用独立的子代理处理不同任务**

   - 使用 `/agent swap cf-waf-converter` 转换安全规则
   - 使用 `/agent swap cf-functions-converter` 转换transformation规则
   - 使用 `/agent swap cf-cdn-analyzer` 分析CDN配置
   - 每个子代理有独立的上下文，避免混淆

2. **一次转换一个项目**

   - 完成一个domain的转换后，新开对话
   - 避免多个项目的配置在同一对话中混淆

3. **使用清晰的描述**

   - 转换安全规则：提到"AWS WAF"或"安全规则"
   - 转换transformation规则：提到"CloudFront Function"或"redirect"
   - 分析CDN配置：提到"CDN配置"或"analyze"

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

## 为什么不支持 cf-terraforming？

[cf-terraforming](https://github.com/cloudflare/cf-terraforming) 是 Cloudflare 的官方工具，用于将配置导出为 Terraform。虽然它非常适合基于 Terraform 的基础设施管理，但由于输出结构的根本差异，它与本转换工具不兼容。

### 输出结构对比

**CloudflareBackup（支持）**：
```
cloudflare_backup/
├── account/
│   └── 2026-01-31 10-00-00/
│       ├── IP-Lists.txt                    # 固定文件名
│       ├── List-Items-ip-block-list.txt    # 可预测的模式
│       └── Bulk-Redirect-Rules.txt         # 固定文件名
└── example.com/
    └── 2026-01-31 10-00-00/
        ├── WAF-Custom-Rules.txt            # 固定文件名
        ├── Rate-limits.txt                 # 固定文件名
        └── Redirect-Rules.txt              # 固定文件名
```

**cf-terraforming（不支持）**：
```bash
# 用户必须运行多个命令并手动命名文件：
cf-terraforming generate --resource-type cloudflare_ruleset --zone <ID> > 用户任意命名.tf
cf-terraforming generate --resource-type cloudflare_list --account <ID> > 另一个名字.tf
cf-terraforming generate --resource-type cloudflare_record --zone <ID> > dns.tf

# 结果：不可预测的结构
用户选择的目录/
├── 用户任意命名.tf      # 用户自定义名称
├── 另一个名字.tf         # 用户自定义名称
└── dns.tf               # 用户自定义名称
```

### 为什么这很重要

**CloudflareBackup 的可预测结构**允许 Powers：
1. **自动定位文件**：Powers 确切知道在哪里找到 `WAF-Custom-Rules.txt`
2. **验证完整性**：Powers 可以检查预期的文件是否存在
3. **处理关系**：Powers 知道 `List-Items-ip-<name>.txt` 对应 `IP-Lists.txt` 中的列表

**cf-terraforming 的灵活输出**造成问题：
1. **无法发现文件**：Powers 无法猜测用户如何命名文件
2. **无标准组织**：用户可能以任何目录结构组织文件
3. **需要手动协调**：用户需要告诉 Powers 每个文件的位置

### 用户体验示例

**使用 CloudflareBackup**：
```
用户："转换 ./cloudflare_backup/example.com/2026-01-31 10-00-00/ 中的 Cloudflare 安全规则"
Power：[自动找到 WAF-Custom-Rules.txt、Rate-limits.txt、IP-Lists.txt]
```

**使用 cf-terraforming**（假设）：
```
用户："转换 ./my_terraform/ 中的 Cloudflare 安全规则"
Power："我找不到标准配置文件。请指定：
        - WAF 规则在哪里？（文件名？）
        - Rate limits 在哪里？（文件名？）
        - IP 列表在哪里？（文件名？）
        - 列表项在哪里？（文件名？）"
用户：[必须手动指定每个文件位置]
```

### 设计决策

本工具优先考虑**自动化和可靠性**而非灵活性：
- **一条备份命令**（CloudflareBackup）vs. 多条手动命令（cf-terraforming）
- **可预测的文件位置** vs. 用户自定义组织
- **零配置** vs. 手动文件映射

如果你在 Terraform 工作流中使用 cf-terraforming，你需要手动重新组织其输出以匹配 CloudflareBackup 的结构（固定文件名、标准目录布局），这违背了本自动化工具的目的。

## 相关资源

- [Kiro文档](https://kiro.dev/docs/)
- [Kiro Powers](https://kiro.dev/powers/)
- [AWS WAF文档](https://docs.aws.amazon.com/waf/)
- [CloudFront Functions文档](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/cloudfront-functions.html)

## Roadmap

### 🚧 Powers 3-11: 完整的CDN配置迁移方案（架构设计中）

我们正在设计一套更完整的CDN配置迁移方案，将当前的单一power重构为多个专门的powers：

**架构设计文档：**
- [Power 3-11 Architecture Design (English)](./docs/architecture/power-3-11-design-EN.md)
- [Power 3-11 架构设计 (中文)](./docs/architecture/power-3-11-design-CN.md)
- [架构变更日志](./docs/architecture/CHANGELOG.md)

**计划中的Powers：**

| Power | 职责 | 输出 | 状态 |
|-------|-----|------|------|
| **Power 3** | 配置分析器 - 解析Cloudflare CDN配置并按hostname分组 | 基于hostname的配置汇总 + 用户输入模板 | 🎨 架构设计中 |
| **Power 4** | 实施规划器 - 确定CloudFront实现方法 | 实施计划 | 🎨 架构设计中 |
| **Power 5** | 计划验证器 - 验证实施计划正确性 | 验证报告（关键：错误的计划=错误的转换器） | 🎨 架构设计中 |
| **Power 6** | 任务编排器 - 生成任务分配和执行指南 | 任务分配文件、执行指南 | 🎨 架构设计中 |
| **Power 7** | Viewer Request Function转换器 | CloudFront Function代码（每域名一个文件） | 📝 待设计 |
| **Power 8** | Viewer Response Function转换器 | CloudFront Function代码（每域名一个文件） | 📝 待设计 |
| **Power 9** | Origin Request Lambda转换器 | Lambda@Edge代码 | 📝 待设计 |
| **Power 10** | Origin Response Lambda转换器 | Lambda@Edge代码 | 📝 待设计 |
| **Power 11** | CloudFront配置生成器 | Terraform配置、部署指南 | 📝 待设计 |

**核心改进：**
- ✅ **从一开始就采用subagent架构** - 所有Powers（3-11）都实现为Kiro subagents，具有隔离的context
- ✅ **关注点分离** - 分析器（解析）、规划器（决策）、验证器（验证）、编排器（分配）
- ✅ **规划前的用户决策** - 业务上下文指导技术实施决策
- ✅ **计划验证** - 在转换器执行前捕获错误（转换后无法恢复）
- ✅ **按域名分组规则** - 满足CloudFront Function 10KB大小限制
- ✅ **基于实现方式的任务分配** - 而非按Cloudflare规则类型
- ✅ **多阶段转换流程** - 分析→决策→规划→验证→编排→转换→部署
- ✅ **成本意识设计** - 标记高成本方案（Viewer Lambda@Edge）为不可转换
- ✅ **无状态工作流** - 通过Markdown文件传递状态，支持分批处理
- ✅ **自动化脚本** - 一键安装和配置

**实施后的影响：**

⚠️ **当Powers 3-11实现后，当前的`cf-functions-converter`将被废弃（deprecated）。**

原因：
- Powers 3-11提供更完整的CDN配置转换（不仅是Functions）
- 按域名分组，更好地处理Function大小限制
- 支持更复杂的转换场景（Lambda@Edge、Policies、Cache Behaviors）
- 更清晰的工作流和任务分配，包含验证步骤

**时间线：**
- 2026 Q1: 完成架构设计，实现Power 3（分析器）作为subagent原型
- 2026 Q2: 实现Powers 4-11作为subagents，实现context隔离
  - 提供自动化脚本用于Kiro Powers安装和subagent配置
  - 废弃`cf-functions-converter`
- 2026 Q3: 优化subagent工作流和用户体验
  - 并行subagent执行的性能调优
  - 增强错误处理和恢复机制
  - 基于反馈的用户体验改进

---

## 反馈和贡献

如有问题或建议，欢迎提交Issue或Pull Request。
