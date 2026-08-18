variable "environment" {
  description = "Deployment environment (staging, prod)."
  type        = string
}

variable "project" {
  description = "Project name used in resource naming."
  type        = string
  default     = "authforge"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC."
  type        = string
}

variable "aws_region" {
  description = "AWS region used to discover availability zones."
  type        = string
}

variable "availability_zones" {
  description = "Optional override for AZ names. When empty, the first two available AZs in the region are used."
  type        = list(string)
  default     = []
}
