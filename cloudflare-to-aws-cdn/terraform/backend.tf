# Configure your Terraform backend here.
# Example for S3 backend (recommended for team use):
#
# terraform {
#   backend "s3" {
#     bucket = "your-terraform-state-bucket"
#     key    = "cloudflare-aws-cdn/terraform.tfstate"
#     region = "us-east-1"
#   }
# }
#
# For local development, no backend configuration is needed.
# Run `terraform init` before `terraform plan` or `terraform apply`.
