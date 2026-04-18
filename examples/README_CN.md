# 示例

## Cloudflare 配置

`cloudflare-configs/` 包含用于测试迁移工具的 Cloudflare 示例配置。涵盖 54 个代理域名，CDN 规则（缓存、重定向、URL 重写、源站、请求/响应头转换、压缩、自定义错误、Cloud Connector、批量重定向）+ WAF 规则（自定义规则、速率限制、IP 访问），覆盖 12+ 种规则类型，包括正则表达式、OR 条件、地理路由、CORS、批量重定向、内联错误页面和 KV 存储数据。

- `account/` — 账号级配置（IP 列表、ASN 列表、主机名列表、批量重定向列表、KV 命名空间和数据）
- `example.com/` — Zone 级配置

所有域名、Cloudflare ID 和 IP 地址已脱敏。IP 地址使用 RFC 5737（`198.51.100.x`、`203.0.113.x`）和 RFC 3849（`2001:db8::x`）文档地址段。

## 使用方法

```bash
kiro-cli chat
```

然后引用示例配置：

```
Convert Cloudflare security rules in ./examples/cloudflare-configs/ to AWS WAF
Convert CDN configuration in ./examples/cloudflare-configs/ to CloudFront Terraform
Convert all Cloudflare configuration in ./examples/cloudflare-configs/ to AWS
```

## 部署前须知

示例配置使用 `example.com` 作为 zone 名称，子域名为 `cdn.example.com`、`www.example.com` 等。如果只是运行转换流程、查看生成的 Terraform/JS 输出，可以直接使用，无需修改。

但如果要将生成的 CloudFront 分配实际部署到 AWS，必须将域名替换为你拥有的真实公网域名：

1. 重命名 zone 目录并替换所有域名引用：
   ```bash
   cd examples/cloudflare-configs
   mv example.com yourdomain.com
   find . -name "*.txt" -exec sed -i '' 's/c\.example\.com/yourdomain.com/g' {} +
   find . -name "*.txt" -exec sed -i '' 's/example\.com/yourdomain.com/g' {} +
   ```
   Linux 上使用 `sed -i` 而不是 `sed -i ''`。
2. 确保在 `us-east-1` 有 `*.yourdomain.com` 的有效 ACM 证书。Terraform 会通过 data source 自动查找已签发的证书。

`account/` 目录包含引用域名的批量重定向列表——上面的 `find` 命令会一并更新。
