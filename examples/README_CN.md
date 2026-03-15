[English](./README.md)

# 示例

## Cloudflare 配置

`cloudflare-configs/` 包含从真实 zone 导出的示例 Cloudflare 配置（已移除敏感数据）。

- `account/` — 账号级配置（IP 列表等）
- `c.example.com/` — 示例域名的 zone 级配置
  > **注意**：这里用 `c.example.com` 作为 apex domain（测试时没有可用的真实 TLD）。在你自己的账号中，通常是 `example.com` 这样的域名。

可以用这些示例在没有自己 Cloudflare 备份的情况下测试转换。

## 对话历史

`conversation-history/` 包含完整的对话记录，展示各 skill 的使用方式：

- `cloudflare-to-aws-waf.txt` — WAF 转换（3 阶段 pipeline：分析 → 校验 → 生成）
- CDN 完整流程示例 — 即将补充

## 使用方法

```bash
kiro-cli chat
```

然后引用示例配置：

```
Convert Cloudflare security rules in ./examples/cloudflare-configs/ to AWS WAF
Convert CDN configuration in ./examples/cloudflare-configs/ to CloudFront Terraform
```
