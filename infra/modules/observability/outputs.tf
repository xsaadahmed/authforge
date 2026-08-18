output "sns_topic_arn" {
  description = "SNS topic ARN for observability alarms (subscribe manually)."
  value       = aws_sns_topic.alerts.arn
}

output "sns_topic_name" {
  description = "SNS topic name for observability alarms."
  value       = aws_sns_topic.alerts.name
}

output "alb_5xx_alarm_arn" {
  description = "ARN of the ALB 5xx alarm."
  value       = aws_cloudwatch_metric_alarm.alb_target_5xx.arn
}

output "ecs_running_tasks_alarm_arn" {
  description = "ARN of the ECS running-task-count alarm."
  value       = aws_cloudwatch_metric_alarm.ecs_running_tasks.arn
}

output "refresh_reuse_detected_alarm_arn" {
  description = "ARN of the refresh reuse detected alarm."
  value       = aws_cloudwatch_metric_alarm.refresh_reuse_detected.arn
}
