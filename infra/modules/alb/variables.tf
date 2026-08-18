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
  description = "VPC ID for the load balancer."
  type        = string
}

variable "subnet_ids" {
  description = "Public subnet IDs for the load balancer."
  type        = list(string)
}

variable "security_group_ids" {
  description = "Security group IDs for the load balancer."
  type        = list(string)
}

variable "target_port" {
  description = "Port on which ECS tasks receive traffic."
  type        = number
  default     = 8000
}

variable "health_check_path" {
  description = "Target group health check path."
  type        = string
  default     = "/health"
}

variable "enable_https" {
  description = "When true, terminate TLS on the ALB and redirect HTTP to HTTPS."
  type        = bool
  default     = false
}

variable "certificate_arn" {
  description = "ACM certificate ARN for the HTTPS listener. Required when enable_https is true."
  type        = string
  default     = null

  validation {
    condition     = !var.enable_https || var.certificate_arn != null
    error_message = "certificate_arn must be set when enable_https is true."
  }
}

variable "idle_timeout" {
  description = "ALB idle timeout in seconds."
  type        = number
  default     = 60
}
