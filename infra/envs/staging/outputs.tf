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

output "alb_dns_name" {
  description = "DNS name of the staging Application Load Balancer."
  value       = module.alb.alb_dns_name
}

output "alb_url" {
  description = "HTTP(S) URL served by the ALB listener."
  value       = module.alb.url
}

output "issuer" {
  description = "AUTHFORGE_ISSUER value injected into ECS tasks."
  value       = "https://${module.alb.alb_dns_name}"
}

output "ecs_cluster_name" {
  description = "ECS cluster name."
  value       = module.ecs.cluster_name
}

output "ecs_service_name" {
  description = "ECS service name."
  value       = module.ecs.service_name
}

output "database_url_secret_arn" {
  description = "ARN of the assembled AUTHFORGE_DATABASE_URL secret."
  value       = module.ecs.database_url_secret_arn
}

output "redis_url_secret_arn" {
  description = "ARN of the assembled AUTHFORGE_REDIS_URL secret."
  value       = module.ecs.redis_url_secret_arn
}

output "signing_key_secret_name_prefix" {
  description = "AUTHFORGE_AWS_SECRET_NAME_PREFIX for runtime signing keys."
  value       = local.signing_key_secret_name_prefix
}
