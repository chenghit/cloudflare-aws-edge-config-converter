[English](./deployment-guide.md)

# 部署指南

这篇文档说明各 pipeline 的输出结构和部署步骤。

## WAF Pipeline 输出

```
cloudflare-to-aws-waf/
├── cloudflare-security-rules-summary.md   # 分析摘要（generator 的输入）
├── versions.tf                             # Provider 版本约束
├── ip_sets.tf                              # 共享 IP sets（两个 ACL 都会引用）
├── main.tf                                 # Locals + 两个 module 调用（website + api-and-file）
├── modules/
│   └── waf/
│       ├── main.tf                         # Web ACL 资源定义
│       ├── variables.tf                    # Module 输入变量
│       └── outputs.tf                      # Module 输出
└── README_aws-waf-terraform-deployment.md  # 自动生成的部署说明
```

### WAF 部署

WAF 是单个 root module，一次 `terraform apply` 搞定：

```bash
cd cloudflare-to-aws-waf
terraform init
terraform plan    # 仔细看一下 plan
terraform apply
```

根目录的 `main.tf` 调用 `modules/waf/` 两次——一次给 website Web ACL，一次给 API/file Web ACL。共享 IP sets 在根级别定义，传给两个 module 调用。

### WAF 注意事项

- WAF 资源是区域性的。把 AWS provider region 设成你 ALB/API Gateway 所在的区域，或者用 `us-east-1`（如果是关联 CloudFront 的 WAF）。
- 检查 `ip_sets.tf`——Cloudflare 规则里的 IP 地址是直接转换过来的，确认下在 AWS 环境里还对不对。
- 看看 `README_aws-waf-terraform-deployment.md`（自动生成的），里面有转换过程中各规则的备注。

---

## CDN Pipeline 输出

```
cloudflare-to-aws-cdn/
├── user_input_template.csv          # 填好后另存为 user_input.csv
├── dns_manifest.yaml                # 解析后的 DNS 记录
├── domain_scope.json                # 验证后的域名配置
├── conversion_report.md             # 无法转换的规则 + 警告
├── ir/                              # 中间表示（仅调试用）
│   ├── accumulator/                 # 每个域名 finalization 前的 IR
│   ├── final/                       # 排序、去重后的 IR
│   └── validation/                  # V1, V2, V3 验证报告
└── terraform/
    ├── modules/
    │   └── cloudfront_distribution/ # 共享 module（别改）
    ├── shared/
    │   └── policies.tf              # 去重后的 CachePolicy, ORP, RHP 资源 + outputs
    └── domains/
        └── <sanitized_hostname>/
            ├── main.tf              # 调用 cloudfront_distribution module
            ├── outputs.tf           # distribution_id, domain_name, hosted_zone_id
            ├── functions.tf         # aws_cloudfront_function 资源
            ├── kvs.tf              # KVS store（仅在有 bulk redirects 时存在）
            ├── kvs-data.json       # KVS 种子数据（仅在有 bulk redirects 时存在）
            ├── functions/
            │   ├── <name>_viewer_request.js
            │   └── <name>_viewer_response.js   # 仅在有 response header 操作时存在
            └── lambda/             # 仅在 CloudFront Function 超过 10KB 时存在
                ├── origin_request_handler.js
                └── default_cache_origin_response.js
```

### CDN 部署顺序

CDN 输出使用独立的 Terraform root modules。**按这个顺序部署：**

#### 第 1 步：部署共享 policies

```bash
cd cloudflare-to-aws-cdn/terraform/shared
terraform init
terraform plan
terraform apply
```

这会创建所有去重后的 CloudFront cache policies、origin request policies 和 response headers policies。域名 module 通过 `data` source 按名称查找这些 policies——所以必须在部署任何域名之前先部署它们。

#### 第 2 步：部署 Lambda@Edge 函数（如果有的话）

如果某个域名有 `lambda/` 目录，你得先把那些 Lambda 函数部署到 AWS，**然后**再 apply 该域名的 Terraform。Lambda@Edge 有特殊要求：

- 必须部署在 **us-east-1**（Lambda@Edge 是全局服务，但函数必须在 N. Virginia 创建）
- Terraform 输出里用了 `REPLACE_WITH_DEPLOYED_LAMBDA_ARN` 占位符——部署完每个 Lambda 后，把 `main.tf` 里的占位符替换成实际 ARN（要带版本号，比如 `arn:aws:lambda:us-east-1:123456789:function:my-func:1`）

如果没有域名有 `lambda/` 目录，跳过这步。

#### 第 3 步：部署各域名

每个域名是独立的 root module，部署顺序随意：

```bash
cd cloudflare-to-aws-cdn/terraform/domains/cdn_example_com
terraform init
terraform plan    # 检查一下：origins、cache policies、function associations
terraform apply
```

每个域名重复上面的步骤。域名之间互相独立——部署或修改一个不影响其他的。

#### 第 4 步：灌入 KVS 数据（如果有的话）

如果某个域名有 `kvs-data.json`，KVS store 由 Terraform 创建，但数据需要单独灌入。用 AWS CLI：

```bash
# 对 kvs-data.json 里的每条记录：
aws cloudfront-keyvaluestore put-key \
  --kvs-arn <kvs_arn_from_terraform_output> \
  --key "redirect:example.com/old-path" \
  --value "301|0|https://example.com/new-path"
```

或者写个脚本遍历 `kvs-data.json` 里的条目。

#### 第 5 步：更新 DNS

确认每个 CloudFront distribution 正常工作后：

1. 从 Terraform output 拿到 distribution 域名（比如 `d111111abcdef8.cloudfront.net`）
2. 更新 DNS 记录指向 CloudFront distribution：
   - 根域名：Route 53 ALIAS 记录或 CNAME flattening
   - 子域名：CNAME 记录

### CDN 注意事项

- **部署前先看 `conversion_report.md`**。里面列了所有无法转换的规则，可能需要手动处理。
- **`ir/` 目录仅用于调试。** 部署不需要它。里面是转换过程中用到的中间表示和验证报告。
- **共享 module（`modules/cloudfront_distribution/`）别改。** 它是通用 wrapper——所有域名特定配置都在各域名的 `main.tf` 里。
- **CloudFront Functions 有 10KB 大小限制。** 超了的话，pipeline 会自动把逻辑升级到 Lambda@Edge。检查每个域名的 `lambda/` 目录。
- **CloudFront KVS 默认配额是每账户 50 个 store。** 如果超过 50 个域名用了 bulk redirects，部署前先[申请配额提升](https://docs.aws.amazon.com/servicequotas/latest/userguide/request-quota-increase.html)。
