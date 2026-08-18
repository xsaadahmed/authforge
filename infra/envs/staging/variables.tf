variable "environment" {
  description = "Deployment environment name."
  type        = string
}

variable "aws_region" {
  description = "AWS region for this environment."
  type        = string
}

variable "vpc_cidr" {
  description = "VPC CIDR block."
  type        = string
}

variable "project" {
  description = "Project name used in resource naming and tagging."
  type        = string
  default     = "authforge"
}

variable "availability_zones" {
  description = "Optional override for AZ names."
  type        = list(string)
  default     = []
}

variable "enable_https" {
  description = "Enable HTTPS on the ALB with ACM certificate termination."
  type        = bool
  default     = false
}

variable "certificate_arn" {
  description = "ACM certificate ARN when enable_https is true."
  type        = string
  default     = null
}

variable "image_tag" {
  description = "ECR image tag deployed to ECS."
  type        = string
  default     = "latest"
}
