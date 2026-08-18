output "cluster_id" {
  description = "ECS cluster ID."
  value       = aws_ecs_cluster.this.id
}

output "cluster_name" {
  description = "ECS cluster name."
  value       = aws_ecs_cluster.this.name
}

output "service_name" {
  description = "ECS service name."
  value       = aws_ecs_service.this.name
}

output "service_arn" {
  description = "ECS service ARN."
  value       = aws_ecs_service.this.id
}

output "task_definition_arn" {
  description = "ECS task definition ARN."
  value       = aws_ecs_task_definition.this.arn
}

output "log_group_name" {
  description = "CloudWatch log group for ECS tasks."
  value       = aws_cloudwatch_log_group.this.name
}

output "log_group_arn" {
  description = "CloudWatch log group ARN."
  value       = aws_cloudwatch_log_group.this.arn
}

output "database_url_secret_arn" {
  description = "ARN of the assembled database URL secret."
  value       = aws_secretsmanager_secret.database_url.arn
}

output "redis_url_secret_arn" {
  description = "ARN of the assembled Redis URL secret."
  value       = aws_secretsmanager_secret.redis_url.arn
}

output "container_environment" {
  description = "Non-secret container environment variables."
  value       = local.container_environment
}

output "container_secret_names" {
  description = "Secret-backed environment variable names injected into the task."
  value       = [for secret in local.container_secrets : secret.name]
}
