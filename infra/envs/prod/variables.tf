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
