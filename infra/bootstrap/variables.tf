variable "aws_region" {
  description = "AWS region for the Terraform state backend resources."
  type        = string
  default     = "us-east-1"
}

variable "state_bucket_name" {
  description = "Globally unique S3 bucket name for Terraform remote state."
  type        = string
  default     = "authforge-terraform-state"
}

variable "lock_table_name" {
  description = "DynamoDB table name for Terraform state locking."
  type        = string
  default     = "authforge-terraform-locks"
}

variable "project" {
  description = "Project tag applied to bootstrap resources."
  type        = string
  default     = "authforge"
}

variable "environment" {
  description = "Environment label for bootstrap resources (not a runtime env)."
  type        = string
  default     = "bootstrap"
}
