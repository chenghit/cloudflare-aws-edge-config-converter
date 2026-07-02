# CloudflareBackup

[English](README.md) | 简体中文

使用 curl 和 Cloudflare API 全面备份 Cloudflare 配置的 Bash 脚本。

> 来自 [chenghit/CloudflareBackup](https://github.com/chenghit/CloudflareBackup)（MIT-0，见 `LICENSE`），随转换器一起分发。它是转换器的输入来源——先运行它导出 Cloudflare 配置，再让转换器读取其输出。备份工具本身的更新或问题请见上游仓库。

## 环境要求

- `bash`（3.2+）
- `curl`
- `jq` — [安装说明](https://jqlang.github.io/jq/download/)
- `python3`（仅当 Workers KV 的键名包含特殊字符时才需要）
- 有效的 Cloudflare 凭据 —— 二选一：拥有读取权限的 **API Token**，或 **Global API Key** + 账户邮箱

## 配置

1. `cd backup/`（本目录，位于克隆下来的转换器仓库内）
2. 将 `config.example` 复制为 `config`
3. 编辑 `config`，填入你的凭据和域名

```bash
cd backup
cp config.example config
# 用你的编辑器编辑 config
```

**示例配置（API Token —— 推荐）：**

```
API_TOKEN=your_actual_cloudflare_api_token
DOMAIN1=example.com
DOMAIN2=example.org
DOMAIN3=example.net
```

**或使用 Global API Key（旧版）：** 将 `API_TOKEN` 留空，同时填写以下两项：

```
API_EMAIL=you@example.com
API_KEY=your_global_api_key
DOMAIN1=example.com
```

如果设置了 `API_TOKEN`，则优先使用它；否则脚本会回退到 Global API Key。

> ⚠️ Global API Key 拥有账户的完整权限且无法限定范围，安全性低于 API Token。建议优先使用 API Token。Global API Key 与 API Token 在[同一页面](https://dash.cloudflare.com/profile/api-tokens)，位于 **API Keys** 区块 → **Global API Key** → **View**。

域名数量没有上限 —— 按需添加 `DOMAIN4`、`DOMAIN5` 等即可。

## 运行

### macOS / Linux

```bash
chmod +x cloudflare_backup.sh
./cloudflare_backup.sh
```

### Windows（通过 WSL）

Windows 无法原生运行 bash，请使用 WSL（适用于 Linux 的 Windows 子系统）：

1. **安装 WSL**（一次性，需要管理员权限的 PowerShell）：

   ```powershell
   wsl --install
   ```

   出现提示时重启电脑。

2. **安装依赖**（一次性，在 WSL 终端内执行）：

   ```bash
   sudo apt update && sudo apt install -y jq curl
   ```

3. **运行脚本**：

   ```bash
   # 进入你的备份文件夹（Windows 盘符位于 /mnt/c/、/mnt/d/ 等）
   cd /mnt/c/Users/YourName/CloudflareBackup

   # 如有需要，修复换行符（在 Windows 上克隆后只需执行一次）
   sed -i 's/\r$//' cloudflare_backup.sh

   # 运行
   chmod +x cloudflare_backup.sh
   ./cloudflare_backup.sh
   ```

> **提示**：你也可以不进入 WSL，直接从 PowerShell 运行：
>
> ```powershell
> wsl -e bash -c "cd /mnt/c/Users/YourName/CloudflareBackup && ./cloudflare_backup.sh"
> ```

## 错误处理

脚本在开始前会先校验你的凭据。如果某次 API 调用失败，会把 **Cloudflare 的原始响应** 打印到屏幕，方便你看清具体出了什么问题。

常见错误：

- **Token IP 限制**：你的 API Token 设置了 IP 白名单，但当前 IP 变了
- **Token 过期/被吊销**：Token 已失效
- **权限不足**：Token 缺少所需的读取权限

遇到非致命错误后，脚本会继续备份其他资源，并在结束时报告错误数量。

## 备份内容

### 区域（Zone）级数据

| 类别 | 项目 |
|------|------|
| WAF | 自定义规则、托管规则 |
| 规则 | 速率限制、缓存、配置、重定向、源、压缩、URL 重写、请求/响应头转换、自定义错误、Cloud Connector |
| DNS | 所有记录（分页）、DNSSEC |
| 基础设施 | 负载均衡器、IP 访问规则（分页）、Page Shield、自定义页面、SaaS 回退源 |
| CDN/性能 | 智能分层缓存、缓存预留、Argo 智能路由、分层缓存、URL 规范化、托管转换 |
| TLS/安全 | TLS 1.3、最低 TLS 版本、加密套件、HTTP/3、HTTP/2、IPv6、0-RTT、WebSockets、Early Hints、安全级别、Challenge TTL、浏览器检查、机会性加密、TLS 客户端认证 |
| 其他设置 | 图片缩放、WebP、开发模式、Always Online、防盗链、服务端排除 |
| Snippets | Snippet 列表、路由规则及 JavaScript 源码 |

### 账户（Account）级数据

- IP 列表及所有列表项
- 批量重定向规则
- 负载均衡器源池（Pools）
- Workers KV 命名空间（所有键和值，分页）

## 输出结构

```
Backup Root/
├── example.com/
│   └── 2024-01-15 14-30-00/
│       ├── DNS.txt
│       ├── WAF-Custom-Rules.txt
│       ├── Cache-Rules.txt
│       ├── Snippets.txt
│       ├── Snippet-Rules.txt
│       ├── Snippet-my_snippet.js
│       └── ...
├── example.org/
│   └── 2024-01-15 14-30-00/
│       └── ...
└── account/
    └── 2024-01-15 14-30-00/
        ├── IP-Lists.txt
        ├── List-Items-ip-MyIPList.txt
        ├── Bulk-Redirect-Rules.txt
        ├── Load-Balancer-Pools.txt
        ├── KV-Namespaces.txt
        └── KV-My_Namespace/
            ├── keys-page-1.txt
            ├── value-config_key.txt
            └── ...
```

## API Token 权限

在 https://dash.cloudflare.com/profile/api-tokens 创建 Token，并赋予以下读取权限：

- Zone：DNS、Firewall Services、Zone Settings、Cache Rules、Config Rules、Dynamic Redirect、Origin Rules、Zone WAF、Page Shield、Load Balancers
- Account：Account Rulesets、Account Filter Lists、Load Balancing、Workers KV Storage

## 说明

- 本脚本仅备份**配置**，不包含账户设置（账单、团队成员等）
- 所有 API 响应均以 JSON 文件保存
- Zone ID 和 Account ID 会根据域名自动发现
- 对于因套餐未包含某功能而返回错误的端点，会被跳过并提示错误信息
