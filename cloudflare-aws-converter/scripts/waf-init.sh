#!/bin/bash
# Initialize WAF output directory with fixed Terraform files.
# Usage: bash waf-init.sh <working_directory>

set -e

WORK_DIR="${1:-.}"
WAF_DIR="$WORK_DIR/cloudflare-to-aws-waf"
MOD_DIR="$WAF_DIR/modules/waf"
CHUNKS_DIR="$WAF_DIR/chunks"

# Skip if all 3 pre-written files already exist
if [ -f "$WAF_DIR/versions.tf" ] && \
   [ -f "$MOD_DIR/variables.tf" ] && \
   [ -f "$MOD_DIR/outputs.tf" ]; then
  echo "WAF output directory already initialized — skipping."
  exit 0
fi

echo "Initializing WAF output directory at $WAF_DIR ..."

mkdir -p "$MOD_DIR"
mkdir -p "$CHUNKS_DIR"
mkdir -p "$WAF_DIR/validation"

# versions.tf — fixed
cat > "$WAF_DIR/versions.tf" << 'EOF'
terraform {
  required_version = ">= 1.8.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.2"
    }
  }
}
EOF

# modules/waf/variables.tf — fixed
cat > "$MOD_DIR/variables.tf" << 'EOF'
variable "web_acl_name" {
  type        = string
  description = "Name of the Web ACL"
}

variable "anti_ddos_use_advanced_config" {
  type        = bool
  description = "Whether to use advanced Anti-DDoS configuration (disable challenge, set block sensitivity)"
}

variable "anti_ddos_challenge_action" {
  type        = string
  description = "Challenge action usage for Anti-DDoS (ENABLED or DISABLED)"
  default     = "ENABLED"
}

variable "anti_ddos_block_sensitivity" {
  type        = string
  description = "Block sensitivity for Anti-DDoS (LOW, MEDIUM, HIGH)"
  default     = "LOW"
}

variable "ip_set_arns" {
  type        = map(string)
  description = "Map of IP set resource names to their ARNs"
  default     = {}
}
EOF

# modules/waf/outputs.tf — fixed
cat > "$MOD_DIR/outputs.tf" << 'EOF'
output "web_acl_arn" {
  description = "ARN of the Web ACL"
  value       = aws_wafv2_web_acl.main.arn
}

output "web_acl_id" {
  description = "ID of the Web ACL"
  value       = aws_wafv2_web_acl.main.id
}
EOF

echo "✅ WAF output directory initialized."
echo "  Pre-written: versions.tf, modules/waf/variables.tf, modules/waf/outputs.tf"
