output "state_bucket_name" {
  description = "S3 bucket name for Terraform remote state."
  value       = aws_s3_bucket.terraform_state.id
}

output "state_bucket_arn" {
  description = "ARN of the Terraform remote state bucket."
  value       = aws_s3_bucket.terraform_state.arn
}

output "lock_table_name" {
  description = "DynamoDB table name for Terraform state locking."
  value       = aws_dynamodb_table.terraform_locks.name
}

output "lock_table_arn" {
  description = "ARN of the Terraform state lock table."
  value       = aws_dynamodb_table.terraform_locks.arn
}

output "aws_region" {
  description = "AWS region where bootstrap resources were created."
  value       = var.aws_region
}
