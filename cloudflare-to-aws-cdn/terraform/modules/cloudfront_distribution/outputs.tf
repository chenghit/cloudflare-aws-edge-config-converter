output "distribution_id" {
  description = "The CloudFront distribution ID"
  value       = aws_cloudfront_distribution.this.id
}

output "distribution_arn" {
  description = "The ARN of the CloudFront distribution"
  value       = aws_cloudfront_distribution.this.arn
}

output "domain_name" {
  description = "The CloudFront distribution domain name (e.g. d111111abcdef8.cloudfront.net)"
  value       = aws_cloudfront_distribution.this.domain_name
}

output "hosted_zone_id" {
  description = "The CloudFront Route 53 hosted zone ID (for ALIAS records)"
  value       = aws_cloudfront_distribution.this.hosted_zone_id
}

output "etag" {
  description = "The current version of the distribution's information"
  value       = aws_cloudfront_distribution.this.etag
}

output "status" {
  description = "The current status of the distribution (Deployed or InProgress)"
  value       = aws_cloudfront_distribution.this.status
}
