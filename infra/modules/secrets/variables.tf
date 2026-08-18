variable "environment" {
  description = "Deployment environment (staging, prod)."
  type        = string
}

variable "project" {
  description = "Project name used in secret naming."
  type        = string
  default     = "authforge"
}

variable "recovery_window_in_days" {
  description = "Secrets Manager recovery window for Terraform-managed secrets."
  type        = number
  default     = 7
}
