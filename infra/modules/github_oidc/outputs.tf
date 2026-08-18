output "github_oidc_provider_arn" {
  description = "ARN of the GitHub Actions OIDC provider."
  value       = local.github_oidc_provider_arn
}

output "plan_role_arn" {
  description = "ARN of the GitHub Actions Terraform plan role."
  value       = aws_iam_role.plan.arn
}

output "plan_role_name" {
  description = "Name of the GitHub Actions Terraform plan role."
  value       = aws_iam_role.plan.name
}

output "apply_role_arn" {
  description = "ARN of the GitHub Actions deploy/apply role (main branch only)."
  value       = aws_iam_role.apply.arn
}

output "apply_role_name" {
  description = "Name of the GitHub Actions deploy/apply role."
  value       = aws_iam_role.apply.name
}
