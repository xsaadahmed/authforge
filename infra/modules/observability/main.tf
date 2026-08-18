locals {
  name_prefix = "${var.project}-${var.environment}"
}

resource "aws_sns_topic" "alerts" {
  name = "${local.name_prefix}-alerts"

  tags = {
    Name = "${local.name_prefix}-alerts"
  }
}

resource "aws_cloudwatch_metric_alarm" "alb_target_5xx" {
  alarm_name          = "${local.name_prefix}-alb-target-5xx"
  alarm_description   = "Elevated ALB target 5xx responses for AuthForge ${var.environment}."
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "HTTPCode_Target_5XX_Count"
  namespace           = "AWS/ApplicationELB"
  period              = 300
  statistic           = "Sum"
  threshold           = var.alb_5xx_threshold
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]

  dimensions = {
    LoadBalancer = var.alb_arn_suffix
  }
}

resource "aws_cloudwatch_metric_alarm" "ecs_running_tasks" {
  alarm_name          = "${local.name_prefix}-ecs-running-tasks-low"
  alarm_description   = "ECS running task count is below desired for AuthForge ${var.environment}."
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 2
  threshold           = var.ecs_desired_task_count
  treat_missing_data  = "breaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]

  metric_query {
    id          = "running"
    return_data = true

    metric {
      metric_name = "RunningTaskCount"
      namespace   = "AWS/ECS"
      period      = 60
      stat        = "Average"

      dimensions = {
        ClusterName = var.ecs_cluster_name
        ServiceName = var.ecs_service_name
      }
    }
  }
}

resource "aws_cloudwatch_log_metric_filter" "refresh_reuse_detected" {
  name           = "${local.name_prefix}-refresh-reuse-detected"
  log_group_name = var.ecs_log_group_name
  pattern        = "{ $.RefreshReuseDetected >= 1 }"

  metric_transformation {
    name          = "RefreshReuseDetected"
    namespace     = "AuthForge/Logs"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "refresh_reuse_detected" {
  alarm_name          = "${local.name_prefix}-refresh-reuse-detected"
  alarm_description   = "Possible refresh token theft in progress (spec §20) — reuse detection fired."
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "RefreshReuseDetected"
  namespace           = "AuthForge/Logs"
  period              = 60
  statistic           = "Sum"
  threshold           = var.refresh_reuse_detected_threshold
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
}
