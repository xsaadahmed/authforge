locals {
  name_prefix = "${var.project}-${var.environment}"
}

data "aws_iam_policy_document" "ecs_task_execution_assume" {
  statement {
    sid     = "EcsTaskExecutionAssumeRole"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

# Task execution and task role inline policies are attached by the ECS module once ECR,
# CloudWatch Logs, and Secrets Manager resources exist.
resource "aws_iam_role" "ecs_task_execution" {
  name               = "${local.name_prefix}-ecs-task-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_execution_assume.json
  description        = "ECS task execution role for AuthForge (${var.environment})"
}

data "aws_iam_policy_document" "ecs_task_assume" {
  statement {
    sid     = "EcsTaskAssumeRole"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

# Empty task role placeholder. Application permissions will be attached in a
# later phase once the runtime needs AWS API access beyond what the execution
# role provides.
resource "aws_iam_role" "ecs_task" {
  name               = "${local.name_prefix}-ecs-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_assume.json
  description        = "ECS task role placeholder for AuthForge (${var.environment})"
}
