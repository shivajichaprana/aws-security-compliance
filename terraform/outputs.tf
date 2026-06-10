output "config_bucket_name" {
  description = "S3 bucket receiving Config snapshots and configuration history."
  value       = aws_s3_bucket.config.bucket
}

output "config_recorder_name" {
  description = "Name of the AWS Config configuration recorder."
  value       = aws_config_configuration_recorder.main.name
}

output "organization_aggregator_arn" {
  description = "ARN of the organization-wide Config aggregator (null when disabled)."
  value       = try(aws_config_configuration_aggregator.organization[0].arn, null)
}

output "cis_rule_names" {
  description = "Names of every CIS-aligned managed Config rule deployed by this stack."
  value       = sort([for rule in aws_config_config_rule.cis : rule.name])
}
