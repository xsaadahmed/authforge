output "repository_name" {
  description = "ECR repository name."
  value       = aws_ecr_repository.this.name
}

output "repository_arn" {
  description = "ARN of the ECR repository."
  value       = aws_ecr_repository.this.arn
}

output "repository_url" {
  description = "URL of the ECR repository."
  value       = aws_ecr_repository.this.repository_url
}

output "registry_id" {
  description = "AWS account ID of the registry."
  value       = aws_ecr_repository.this.registry_id
}
