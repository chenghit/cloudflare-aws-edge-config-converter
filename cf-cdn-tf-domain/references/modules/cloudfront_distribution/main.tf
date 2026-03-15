resource "aws_cloudfront_distribution" "this" {
  enabled             = true
  is_ipv6_enabled     = var.is_ipv6_enabled
  comment             = var.hostname
  default_root_object = var.default_root_object != "" ? var.default_root_object : null
  price_class         = var.price_class
  http_version        = var.http_version
  aliases             = concat([var.hostname], var.aliases)
  web_acl_id          = var.web_acl_id
  wait_for_deployment = var.wait_for_deployment

  # ── Origins ──────────────────────────────────────────────────────────────────
  dynamic "origin" {
    for_each = var.origins
    content {
      origin_id                = origin.value.origin_id
      domain_name              = origin.value.domain_name
      origin_access_control_id = origin.value.s3_origin ? origin.value.origin_access_control_id : null

      dynamic "custom_origin_config" {
        for_each = origin.value.s3_origin ? [] : [1]
        content {
          origin_protocol_policy = origin.value.protocol_policy
          http_port              = origin.value.http_port
          https_port             = origin.value.https_port
          origin_ssl_protocols   = ["TLSv1.2"]
        }
      }

      dynamic "custom_header" {
        for_each = origin.value.s3_origin ? [] : origin.value.custom_origin_headers
        content {
          name  = custom_header.value.name
          value = custom_header.value.value
        }
      }
    }
  }

  # ── Default Cache Behavior ────────────────────────────────────────────────────
  default_cache_behavior {
    target_origin_id           = var.default_target_origin_id
    viewer_protocol_policy     = var.default_viewer_protocol_policy
    compress                   = var.default_compress
    allowed_methods            = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods             = ["GET", "HEAD"]
    cache_policy_id            = var.default_cache_policy_id
    origin_request_policy_id   = var.default_origin_request_policy_id
    response_headers_policy_id = var.default_response_headers_policy_id

    dynamic "function_association" {
      for_each = var.default_function_associations
      content {
        event_type   = function_association.value.event_type
        function_arn = function_association.value.function_arn
      }
    }

    dynamic "lambda_function_association" {
      for_each = var.default_lambda_function_associations
      content {
        event_type   = lambda_function_association.value.event_type
        lambda_arn   = lambda_function_association.value.lambda_arn
        include_body = lambda_function_association.value.include_body
      }
    }
  }

  # ── Ordered Cache Behaviors ───────────────────────────────────────────────────
  dynamic "ordered_cache_behavior" {
    for_each = var.ordered_cache_behaviors
    content {
      path_pattern               = ordered_cache_behavior.value.path_pattern
      target_origin_id           = ordered_cache_behavior.value.target_origin_id
      viewer_protocol_policy     = ordered_cache_behavior.value.viewer_protocol_policy
      compress                   = ordered_cache_behavior.value.compress
      allowed_methods            = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
      cached_methods             = ["GET", "HEAD"]
      cache_policy_id            = ordered_cache_behavior.value.cache_policy_id
      origin_request_policy_id   = ordered_cache_behavior.value.origin_request_policy_id
      response_headers_policy_id = ordered_cache_behavior.value.response_headers_policy_id

      dynamic "function_association" {
        for_each = ordered_cache_behavior.value.function_associations
        content {
          event_type   = function_association.value.event_type
          function_arn = function_association.value.function_arn
        }
      }

      dynamic "lambda_function_association" {
        for_each = ordered_cache_behavior.value.lambda_function_associations
        content {
          event_type   = lambda_function_association.value.event_type
          lambda_arn   = lambda_function_association.value.lambda_arn
          include_body = lambda_function_association.value.include_body
        }
      }
    }
  }

  # ── Viewer Certificate ────────────────────────────────────────────────────────
  viewer_certificate {
    acm_certificate_arn      = var.acm_certificate_arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = var.minimum_protocol_version
  }

  # ── Geo Restriction ───────────────────────────────────────────────────────────
  restrictions {
    geo_restriction {
      restriction_type = var.geo_restriction_type
      locations        = var.geo_restriction_locations
    }
  }

  # ── Custom Error Responses ────────────────────────────────────────────────────
  dynamic "custom_error_response" {
    for_each = var.custom_error_responses
    content {
      error_code            = custom_error_response.value.error_code
      response_page_path    = custom_error_response.value.response_page_path
      response_code         = custom_error_response.value.response_code
      error_caching_min_ttl = custom_error_response.value.error_caching_min_ttl
    }
  }

  tags = merge(var.tags, {
    Hostname     = var.hostname
    ManagedBy    = "terraform"
    MigratedFrom = "cloudflare"
  })

  lifecycle {
    create_before_destroy = true
  }
}
