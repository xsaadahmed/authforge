variable "environment" {
  description = "Deployment environment (staging, prod)."
  type        = string
}

variable "project" {
  description = "Project name used in IAM resource naming."
  type        = string
  default     = "authforge"
}
