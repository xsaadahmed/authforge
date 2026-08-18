variable "environment" {
  description = "Deployment environment (staging, prod)."
  type        = string
}

variable "project" {
  description = "Project name used in resource naming."
  type        = string
  default     = "authforge"
}

variable "vpc_id" {
  description = "VPC ID where security groups are created."
  type        = string
}
