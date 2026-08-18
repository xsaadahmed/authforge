variable "environment" {
  description = "Deployment environment (staging, prod)."
  type        = string
}

variable "project" {
  description = "Project name used in resource naming."
  type        = string
  default     = "authforge"
}

variable "aws_region" {
  description = "AWS region for the ECS service."
  type        = string
}

variable "vpc_id" {
  description = "VPC ID for the ECS service."
  type        = string
}

variable "private_subnet_ids" {
  description = "Private subnet IDs for ECS tasks."
  type        = list(string)
}

variable "ecs_security_group_id" {
  description = "Security group ID for ECS tasks."
  type        = string
}

variable "target_group_arn" {
  description = "ALB target group ARN."
  type        = string
}

variable "issuer" {
  description = "External issuer URL (AUTHFORGE_ISSUER). Must use https for staging/prod Settings validation."
  type        = string
}

variable "execution_role_arn" {
  description = "ECS task execution role ARN."
  type        = string
}

variable "execution_role_name" {
  description = "ECS task execution role name for inline policy attachment."
  type        = string
}

variable "task_role_arn" {
  description = "ECS task role ARN."
  type        = string
}

variable "task_role_name" {
  description = "ECS task role name for inline policy attachment."
  type        = string
}

variable "ecr_repository_arn" {
  description = "ARN of the ECR repository."
  type        = string
}

variable "ecr_repository_url" {
  description = "URL of the ECR repository."
  type        = string
}

variable "image_tag" {
  description = "Container image tag to deploy."
  type        = string
  default     = "latest"
}

variable "container_port" {
  description = "Container port exposed by the application."
  type        = number
  default     = 8000
}

variable "cpu" {
  description = "Fargate task CPU units."
  type        = string
  default     = "512"
}

variable "memory" {
  description = "Fargate task memory in MB."
  type        = string
  default     = "1024"
}

variable "desired_count" {
  description = "Desired number of ECS tasks."
  type        = number
  default     = 2
}

variable "autoscaling_min_capacity" {
  description = "Minimum task count for autoscaling."
  type        = number
  default     = 2
}

variable "autoscaling_max_capacity" {
  description = "Maximum task count for autoscaling."
  type        = number
  default     = 4
}

variable "autoscaling_cpu_target" {
  description = "Target CPU utilization percentage for autoscaling."
  type        = number
  default     = 60
}

variable "log_retention_in_days" {
  description = "CloudWatch Logs retention for the task log group."
  type        = number
  default     = 30
}

variable "rds_master_user_secret_arn" {
  description = "ARN of the RDS-managed master user secret."
  type        = string
}

variable "rds_address" {
  description = "RDS hostname."
  type        = string
}

variable "rds_port" {
  description = "RDS port."
  type        = number
}

variable "db_name" {
  description = "PostgreSQL database name."
  type        = string
}

variable "redis_address" {
  description = "Redis primary endpoint hostname."
  type        = string
}

variable "redis_port" {
  description = "Redis port."
  type        = number
}

variable "totp_encryption_key_secret_arn" {
  description = "ARN of the TOTP encryption key secret."
  type        = string
}

variable "admin_api_token_secret_arn" {
  description = "ARN of the admin API token secret."
  type        = string
}

variable "redis_auth_token_secret_arn" {
  description = "ARN of the Redis AUTH token secret."
  type        = string
}

variable "app_secret_name_prefix" {
  description = "Secrets Manager prefix for Terraform-managed app secrets (authforge/{environment})."
  type        = string
}

variable "signing_key_secret_name_prefix" {
  description = "Secrets Manager prefix for runtime signing keys."
  type        = string
}

variable "log_level" {
  description = "Application log level (AUTHFORGE_LOG_LEVEL)."
  type        = string
  default     = "INFO"
}
