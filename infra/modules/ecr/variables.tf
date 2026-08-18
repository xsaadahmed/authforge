variable "environment" {
  description = "Deployment environment (staging, prod)."
  type        = string
}

variable "project" {
  description = "Project name used in the repository name."
  type        = string
  default     = "authforge"
}

variable "untagged_image_max_age_days" {
  description = "Maximum age in days before untagged images expire."
  type        = number
  default     = 7
}

variable "tagged_image_count_to_retain" {
  description = "Number of tagged images to retain."
  type        = number
  default     = 10
}
