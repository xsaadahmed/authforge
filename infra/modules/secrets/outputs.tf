output "totp_encryption_key_secret_arn" {
  description = "ARN of the TOTP encryption key secret."
  value       = aws_secretsmanager_secret.totp_encryption_key.arn
}

output "totp_encryption_key_secret_name" {
  description = "Secrets Manager name of the TOTP encryption key."
  value       = aws_secretsmanager_secret.totp_encryption_key.name
}

output "admin_api_token_secret_arn" {
  description = "ARN of the admin API token secret."
  value       = aws_secretsmanager_secret.admin_api_token.arn
}

output "admin_api_token_secret_name" {
  description = "Secrets Manager name of the admin API token."
  value       = aws_secretsmanager_secret.admin_api_token.name
}

output "redis_auth_token_secret_arn" {
  description = "ARN of the Redis AUTH token secret."
  value       = aws_secretsmanager_secret.redis_auth_token.arn
}

output "redis_auth_token_secret_name" {
  description = "Secrets Manager name of the Redis AUTH token."
  value       = aws_secretsmanager_secret.redis_auth_token.name
}

output "redis_auth_token" {
  description = "Redis AUTH token value for ElastiCache provisioning. Pass only to the Redis module."
  value       = random_password.redis_auth_token.result
  sensitive   = true
}

output "secret_name_prefix" {
  description = "Prefix for Terraform-managed AuthForge secrets in this environment."
  value       = local.secret_prefix
}
