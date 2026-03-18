# 示例 Cloudflare 配置

本目录包含用于测试迁移工具的 Cloudflare 示例配置。涵盖 7 个代理域名、34 条 CDN 规则 + 8 条 WAF 规则，覆盖 12 种规则类型，包括正则表达式、OR 条件、地理路由、CORS、批量重定向和内联错误页面。

## 部署前须知

示例配置使用 `c.example.com` 作为 zone（顶级域名），子域名为 `cdn.c.example.com`、`www.c.example.com` 等。如果只是运行转换流程、查看生成的 Terraform/JS 输出，可以直接使用，无需修改。

但如果要将生成的 CloudFront 分配实际部署到 AWS，必须将域名替换为你拥有的真实公网域名：

1. 重命名 zone 目录并替换所有域名引用：
   ```bash
   cd examples/cloudflare-configs
   mv c.example.com c.yourdomain.com
   find c.yourdomain.com -name "*.txt" -exec sed -i '' 's/c\.example\.com/c.yourdomain.com/g' {} +
   ```
   Linux 上使用 `sed -i` 而不是 `sed -i ''`。
2. 确保在 `us-east-1` 有 `*.c.yourdomain.com` 的有效 ACM 证书，或在 CSV 中留空让 Terraform 自动查找。

`account/` 目录（IP 列表、批量重定向列表）不包含域名相关数据，无需修改。
