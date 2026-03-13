variable "hostname" {
  description = "Primary hostname for this CloudFront distribution"
  type        = string
}

variable "aliases" {
  description = "List of domain aliases (alternate domain names)"
  type        = list(string)
  default     = []
}

variable "origins" {
  description = "List of origins for this distribution"
  type = list(object({
    origin_id   = string
    domain_name = string
    protocol_policy = string
    http_port   = number
    https_port  = number
    custom_origin_headers = list(object({
      name  = string
      value = string
    }))
  }))
}

variable "default_root_object" {
  type    = string
  default = ""
}

variable "price_class" {
  type    = string
  default = "PriceClass_All"
}

variable "http_version" {
  type    = string
  default = "http2and3"
}

variable "is_ipv6_enabled" {
  type    = bool
  default = true
}

variable "wait_for_deployment" {
  type    = bool
  default = false
}

variable "acm_certificate_arn" {
  description = "ACM certificate ARN (must be in us-east-1)"
  type        = string
}

variable "minimum_protocol_version" {
  type    = string
  default = "TLSv1.2_2021"
}

variable "web_acl_id" {
  description = "AWS WAF Web ACL ARN to associate with this distribution"
  type        = string
  default     = null
}

variable "tags" {
  type    = map(string)
  default = {}
}

# ── Default cache behavior ────────────────────────────────────────────────────

variable "default_target_origin_id" {
  type = string
}

variable "default_viewer_protocol_policy" {
  type    = string
  default = "redirect-to-https"
}

variable "default_compress" {
  type    = bool
  default = true
}

variable "default_cache_policy_id" {
  type    = string
  default = null
}

variable "default_origin_request_policy_id" {
  type    = string
  default = null
}

variable "default_response_headers_policy_id" {
  type    = string
  default = null
}

variable "default_function_associations" {
  description = "CloudFront Function associations for the default cache behavior"
  type = list(object({
    event_type   = string
    function_arn = string
  }))
  default = []
}

variable "default_lambda_function_associations" {
  description = "Lambda@Edge associations for the default cache behavior"
  type = list(object({
    event_type   = string
    lambda_arn   = string
    include_body = bool
  }))
  default = []
}

# ── Ordered cache behaviors ───────────────────────────────────────────────────

variable "ordered_cache_behaviors" {
  type = list(object({
    path_pattern               = string
    target_origin_id           = string
    viewer_protocol_policy     = string
    compress                   = bool
    cache_policy_id            = optional(string)
    origin_request_policy_id   = optional(string)
    response_headers_policy_id = optional(string)
    function_associations = optional(list(object({
      event_type   = string
      function_arn = string
    })), [])
    lambda_function_associations = optional(list(object({
      event_type   = string
      lambda_arn   = string
      include_body = bool
    })), [])
  }))
  default = []
}

# ── Geo restriction ───────────────────────────────────────────────────────────

variable "geo_restriction_type" {
  type    = string
  default = "none"
}

variable "geo_restriction_locations" {
  type    = list(string)
  default = []
}

variable "custom_error_responses" {
  description = "List of custom error response configurations"
  type = list(object({
    error_code            = number
    response_page_path    = string
    response_code         = number
    error_caching_min_ttl = number
  }))
  default = []
}
