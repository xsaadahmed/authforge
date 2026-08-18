output "rds_endpoint" {
  description = "RDS connection endpoint."
  value       = module.rds.endpoint
}

output "rds_master_user_secret_arn" {
  description = "ARN of the RDS-managed master password secret."
  value       = module.rds.master_user_secret_arn
}

output "redis_endpoint" {
  description = "Primary Redis hostname."
  value       = module.redis.address
}

output "redis_port" {
  description = "Redis port."
  value       = module.redis.port
}

output "ecr_repository_url" {
  description = "ECR repository URL for container images."
  value       = module.ecr.repository_url
}

output "totp_encryption_key_secret_arn" {
  description = "ARN of the TOTP encryption key secret."
  value       = module.secrets.totp_encryption_key_secret_arn
}

output "admin_api_token_secret_arn" {
  description = "ARN of the admin API token secret."
  value       = module.secrets.admin_api_token_secret_arn
}

output "redis_auth_token_secret_arn" {
  description = "ARN of the Redis AUTH token secret."
  value       = module.secrets.redis_auth_token_secret_arn
}

output "app_secret_name_prefix" {
  description = "Secrets Manager prefix for Terraform-managed app secrets."
  value       = module.secrets.secret_name_prefix
}
