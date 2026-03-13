variable "aws_region" {
  description = "Primary AWS region for resources"
  type        = string
  default     = "us-east-1"
}

variable "project_tags" {
  description = "Common tags applied to all resources"
  type        = map(string)
  default = {
    ManagedBy = "cloudflare-aws-converter"
    Tool      = "cf-cdn-terraform-generator"
  }
}
