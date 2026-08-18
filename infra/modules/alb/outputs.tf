output "alb_arn" {
  description = "ARN of the Application Load Balancer."
  value       = aws_lb.this.arn
}

output "alb_arn_suffix" {
  description = "ARN suffix of the Application Load Balancer for CloudWatch dimensions."
  value       = aws_lb.this.arn_suffix
}

output "alb_dns_name" {
  description = "DNS name of the Application Load Balancer."
  value       = aws_lb.this.dns_name
}

output "alb_zone_id" {
  description = "Route53 zone ID of the ALB."
  value       = aws_lb.this.zone_id
}

output "target_group_arn" {
  description = "ARN of the target group for ECS tasks."
  value       = aws_lb_target_group.this.arn
}

output "target_group_name" {
  description = "Name of the target group."
  value       = aws_lb_target_group.this.name
}

output "url" {
  description = "External base URL for the load balancer using the active listener scheme."
  value       = var.enable_https ? "https://${aws_lb.this.dns_name}" : "http://${aws_lb.this.dns_name}"
}
