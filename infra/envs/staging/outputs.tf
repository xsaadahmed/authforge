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

output "aws_region" {
  description = "AWS region for this environment."
  value       = var.aws_region
}

output "ecs_cluster_name" {
  description = "ECS cluster name."
  value       = module.ecs.cluster_name
}

output "ecs_service_name" {
  description = "ECS service name."
  value       = module.ecs.service_name
}

output "ecs_task_definition_arn" {
  description = "ECS task definition ARN (use for one-off run-task)."
  value       = module.ecs.task_definition_arn
}

output "ecs_container_name" {
  description = "Container name inside the ECS task definition."
  value       = module.ecs.container_name
}

output "ecs_log_group_name" {
  description = "CloudWatch log group for ECS tasks."
  value       = module.ecs.log_group_name
}

output "private_subnet_ids" {
  description = "Private subnet IDs for ECS tasks."
  value       = module.vpc.private_subnet_ids
}

output "ecs_security_group_id" {
  description = "Security group ID for ECS tasks."
  value       = module.security_groups.ecs_security_group_id
}

output "ecr_repository_url" {
  description = "ECR repository URL for container images."
  value       = module.ecr.repository_url
}

output "github_plan_role_arn" {
  description = "GitHub Actions OIDC role ARN for Terraform plan (PRs)."
  value       = module.github_oidc.plan_role_arn
}

output "github_apply_role_arn" {
  description = "GitHub Actions OIDC role ARN for apply/deploy (main branch)."
  value       = module.github_oidc.apply_role_arn
}

output "sns_alerts_topic_arn" {
  description = "SNS topic ARN for CloudWatch alarms (subscribe manually)."
  value       = module.observability.sns_topic_arn
}

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
