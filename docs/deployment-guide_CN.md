[English](./deployment-guide.md)

# 部署指南

这篇文档说明各 pipeline 的输出结构和部署步骤。

## WAF Pipeline 输出

```
cloudflare-to-aws-waf/
├── waf_ir.json                             # 结构化 IR（generator 的输入）
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

#### 第 2 步：部署各域名

每个域名是独立的 root module，部署顺序随意：

```bash
cd cloudflare-to-aws-cdn/terraform/domains/cdn_example_com
terraform init
terraform plan    # 检查一下：origins、cache policies、function associations
terraform apply
```

每个域名重复上面的步骤。域名之间互相独立——部署或修改一个不影响其他的。

Lambda@Edge origin-response 函数（用于默认缓存 TTL 和条件性缓存规则）是全自动的——scaffold 生成了 IAM role、archive、Lambda 函数和 `main.tf` 中的 `qualified_arn` 引用。不需要手动替换 ARN。

Lambda@Edge origin-request 函数（少见——仅当 CFF 超过 10KB 且 origin_override 操作被拆分时）需要手动步骤：`terraform apply` 后，按 `origin_request_handler.js` 文件头部的注释将 origin-request association 添加到 `main.tf`。

#### 第 3 步：灌入 KVS 数据（如果有的话）

如果某个域名有 `kvs-data.json`，KVS store 由 Terraform 创建，但数据需要单独灌入。每个有 KVS 的域名都有生成好的 `seed-kvs.py` 脚本：

```bash
cd cloudflare-to-aws-cdn/terraform/domains/cdn_example_com
python3 seed-kvs.py
```

脚本读取 `kvs-data.json`，通过 `update-keys` API 按 50 条一批写入。需要 `boto3`（`pip install boto3`）和 AWS 凭证。

#### 第 4 步：验证部署

每个域名都有生成好的 `test-cdn-rules.py` 脚本用于部署后验证。用 CloudFront distribution 域名运行：

```bash
cd cloudflare-to-aws-cdn/terraform/domains/cdn_example_com
python3 test-cdn-rules.py d111111abcdef8.cloudfront.net
```

脚本使用 curl 测试重定向、错误页面、批量重定向和响应头。需要手动测试的项目（IP 规则、地理条件、origin 切换）会列为 SKIP 并附带说明。

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
- **CloudFront Functions 有 10KB 大小限制。** 超了的话，pipeline 会把 origin_override 逻辑拆到 Lambda@Edge origin-request。剩余 viewer 逻辑如果还是放不下，会标记为 non-convertible。检查每个域名的 `lambda/` 目录看有没有 origin event handler。
- **CloudFront KVS 默认配额是每账户 50 个 store。** 如果超过 50 个域名用了 bulk redirects，部署前先[申请配额提升](https://docs.aws.amazon.com/servicequotas/latest/userguide/request-quota-increase.html)。
- **Lambda@Edge IAM role 可能在 `terraform destroy` 后残留。** 边缘副本是异步清理的（可能需要几小时）。如果销毁后重新部署，可能需要 `terraform import` 已有 role。详见[故障排除](./troubleshooting_CN.md)。
