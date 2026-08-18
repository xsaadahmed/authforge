variable "environment" {
  description = "Deployment environment (staging, prod)."
  type        = string
}

variable "project" {
  description = "Project name used in resource naming."
  type        = string
  default     = "authforge"
}

variable "subnet_ids" {
  description = "Private subnet IDs for the ElastiCache subnet group."
  type        = list(string)
}

variable "security_group_ids" {
  description = "Security group IDs attached to the Redis cluster."
  type        = list(string)
}

variable "auth_token" {
  description = "Redis AUTH token. Sourced from the secrets module; never exposed as a root output."
  type        = string
  sensitive   = true
}

variable "node_type" {
  description = "ElastiCache node type."
  type        = string
  default     = "cache.t4g.micro"
}

variable "engine_version" {
  description = "Redis engine version."
  type        = string
  default     = "7.1"
}

variable "port" {
  description = "Redis port."
  type        = number
  default     = 6379
}

variable "num_cache_nodes" {
  description = "Number of cache nodes. Staging uses a single node."
  type        = number
  default     = 1
}
