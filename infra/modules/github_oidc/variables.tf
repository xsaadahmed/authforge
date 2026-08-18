variable "project" {
  description = "Project name used in IAM role naming."
  type        = string
  default     = "authforge"
}

variable "environment" {
  description = "Deployment environment label for IAM role naming."
  type        = string
}

variable "aws_region" {
  description = "AWS region for ARN construction."
  type        = string
}

variable "github_repository" {
  description = "GitHub repository slug (org/name) allowed to assume CI roles."
  type        = string
}

variable "state_bucket_name" {
  description = "Terraform remote state S3 bucket name."
  type        = string
}

variable "state_key_prefix" {
  description = "Terraform state key prefix within the bucket (e.g. staging/)."
  type        = string
  default     = "staging/"
}

variable "lock_table_name" {
  description = "Terraform state lock DynamoDB table name."
  type        = string
}

variable "ecr_repository_arn" {
  description = "ARN of the ECR repository CI may push to."
  type        = string
}

variable "ecs_cluster_name" {
  description = "ECS cluster name CI may deploy to."
  type        = string
}

variable "ecs_service_name" {
  description = "ECS service name CI may deploy to."
  type        = string
}
