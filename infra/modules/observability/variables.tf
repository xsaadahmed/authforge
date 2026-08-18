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
  description = "AWS region for alarm dimensions."
  type        = string
}

variable "alb_arn_suffix" {
  description = "Application Load Balancer ARN suffix for CloudWatch dimensions."
  type        = string
}

variable "ecs_cluster_name" {
  description = "ECS cluster name for service metrics."
  type        = string
}

variable "ecs_service_name" {
  description = "ECS service name for service metrics."
  type        = string
}

variable "ecs_log_group_name" {
  description = "CloudWatch log group where ECS tasks emit EMF metrics."
  type        = string
}

variable "ecs_desired_task_count" {
  description = "Expected steady-state ECS task count for the running-task alarm."
  type        = number
  default     = 2
}

variable "alb_5xx_threshold" {
  description = "Sum of target 5xx responses in one period before alarming."
  type        = number
  default     = 10
}

variable "refresh_reuse_detected_threshold" {
  description = "Count of RefreshReuseDetected events in one period before alarming."
  type        = number
  default     = 1
}
