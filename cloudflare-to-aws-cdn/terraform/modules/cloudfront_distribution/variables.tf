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
    origin_id            = string
    domain_name          = string
    protocol_policy      = string
    http_port            = number
    https_port           = number
    custom_origin_headers = list(object({
      name  = string
      value = string
    }))
  }))
}

variable "default_root_object" {
  description = "Default root object"
  type        = string
  default     = ""
}

variable "price_class" {
  description = "CloudFront price class"
  type        = string
  default     = "PriceClass_All"
}

variable "acm_certificate_arn" {
  description = "ACM certificate ARN (us-east-1)"
  type        = string
}

variable "minimum_protocol_version" {
  description = "Minimum TLS protocol version"
  type        = string
  default     = "TLSv1.2_2021"
}

variable "http_version" {
  description = "HTTP version (http1.1, http2, http2and3, http3)"
  type        = string
  default     = "http2and3"
}

variable "is_ipv6_enabled" {
  type    = bool
  default = true
}

variable "tags" {
  description = "Tags to apply to the distribution"
  type        = map(string)
  default     = {}
}

variable "default_cache_policy_id" {
  description = "CloudFront cache policy ID for the default cache behavior"
  type        = string
  default     = null
}

variable "default_origin_request_policy_id" {
  description = "CloudFront origin request policy ID for the default cache behavior"
  type        = string
  default     = null
}

variable "default_response_headers_policy_id" {
  description = "CloudFront response headers policy ID for the default cache behavior"
  type        = string
  default     = null
}

variable "default_target_origin_id" {
  description = "The origin ID to associate with the default cache behavior"
  type        = string
}

variable "default_viewer_protocol_policy" {
  description = "Viewer protocol policy for default cache behavior (allow-all, https-only, redirect-to-https)"
  type        = string
  default     = "redirect-to-https"
}

variable "default_compress" {
  description = "Whether to enable automatic compression for the default cache behavior"
  type        = bool
  default     = true
}

variable "ordered_cache_behaviors" {
  description = "List of ordered cache behaviors (path-based routing)"
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
  }))
  default = []
}

variable "default_function_associations" {
  description = "CloudFront Function associations for the default cache behavior"
  type = list(object({
    event_type   = string
    function_arn = string
  }))
  default = []
}

variable "geo_restriction_type" {
  description = "Geo restriction type: none, whitelist, or blacklist"
  type        = string
  default     = "none"
}

variable "geo_restriction_locations" {
  description = "ISO 3166-1 alpha-2 country codes for geo restriction"
  type        = list(string)
  default     = []
}

variable "web_acl_id" {
  description = "AWS WAF Web ACL ARN to associate with this distribution"
  type        = string
  default     = null
}
