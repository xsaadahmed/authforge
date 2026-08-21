data "aws_caller_identity" "current" {}

data "aws_secretsmanager_secret_version" "rds_master" {
  secret_id = var.rds_master_user_secret_arn
}

data "aws_secretsmanager_secret_version" "redis_auth_token" {
  secret_id = var.redis_auth_token_secret_arn
}

locals {
  name_prefix      = "${var.project}-${var.environment}"
  container_name   = "authforge"
  image_uri        = "${var.ecr_repository_url}:${var.image_tag}"
  rds_credentials  = jsondecode(data.aws_secretsmanager_secret_version.rds_master.secret_string)
  redis_auth_token = data.aws_secretsmanager_secret_version.redis_auth_token.secret_string

  database_url = format(
    "postgresql+asyncpg://%s:%s@%s:%s/%s",
    local.rds_credentials.username,
    urlencode(local.rds_credentials.password),
    var.rds_address,
    var.rds_port,
    var.db_name,
  )

  redis_url = format(
    "rediss://:%s@%s:%s/0",
    urlencode(local.redis_auth_token),
    var.redis_address,
    var.redis_port,
  )

  signing_keys_secret_arn_wildcard = "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:${var.signing_key_secret_name_prefix}/*"

  container_environment = [
    { name = "AUTHFORGE_ENVIRONMENT", value = var.environment },
    { name = "AUTHFORGE_ISSUER", value = var.issuer },
    { name = "AUTHFORGE_SIGNING_KEY_PROVIDER", value = "aws_secrets_manager" },
    { name = "AUTHFORGE_LOG_LEVEL", value = var.log_level },
    { name = "AUTHFORGE_AWS_REGION", value = var.aws_region },
    { name = "AUTHFORGE_AWS_SECRET_NAME_PREFIX", value = var.signing_key_secret_name_prefix },
  ]

  container_secrets = [
    { name = "AUTHFORGE_DATABASE_URL", valueFrom = aws_secretsmanager_secret.database_url.arn },
    { name = "AUTHFORGE_REDIS_URL", valueFrom = aws_secretsmanager_secret.redis_url.arn },
    { name = "AUTHFORGE_TOTP_ENCRYPTION_KEY", valueFrom = var.totp_encryption_key_secret_arn },
    { name = "AUTHFORGE_ADMIN_API_TOKEN", valueFrom = var.admin_api_token_secret_arn },
  ]

  execution_secret_arns = [
    aws_secretsmanager_secret.database_url.arn,
    aws_secretsmanager_secret.redis_url.arn,
    var.totp_encryption_key_secret_arn,
    var.admin_api_token_secret_arn,
    var.rds_master_user_secret_arn,
    var.redis_auth_token_secret_arn,
    local.signing_keys_secret_arn_wildcard,
  ]
}

resource "aws_secretsmanager_secret" "database_url" {
  name                    = "${var.app_secret_name_prefix}/database_url"
  description             = "Assembled Postgres URL for AuthForge (${var.environment})"
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "database_url" {
  secret_id     = aws_secretsmanager_secret.database_url.id
  secret_string = local.database_url
}

resource "aws_secretsmanager_secret" "redis_url" {
  name                    = "${var.app_secret_name_prefix}/redis_url"
  description             = "Assembled Redis URL for AuthForge (${var.environment})"
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "redis_url" {
  secret_id     = aws_secretsmanager_secret.redis_url.id
  secret_string = local.redis_url
}

resource "aws_cloudwatch_log_group" "this" {
  name              = "/ecs/${local.name_prefix}"
  retention_in_days = var.log_retention_in_days

  tags = {
    Name = "${local.name_prefix}-ecs-logs"
  }
}

data "aws_iam_policy_document" "execution" {
  statement {
    sid    = "EcrAuth"
    effect = "Allow"
    actions = [
      "ecr:GetAuthorizationToken",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "EcrPull"
    effect = "Allow"
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchGetImage",
    ]
    resources = [var.ecr_repository_arn]
  }

  statement {
    sid    = "Logs"
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["${aws_cloudwatch_log_group.this.arn}:*"]
  }

  statement {
    sid    = "Secrets"
    effect = "Allow"
    actions = [
      "secretsmanager:GetSecretValue",
    ]
    resources = local.execution_secret_arns
  }
}

resource "aws_iam_role_policy" "execution" {
  name   = "${local.name_prefix}-ecs-execution"
  role   = var.execution_role_name
  policy = data.aws_iam_policy_document.execution.json
}

data "aws_iam_policy_document" "task" {
  statement {
    sid    = "SigningKeySecretsRead"
    effect = "Allow"
    actions = [
      "secretsmanager:GetSecretValue",
    ]
    resources = [local.signing_keys_secret_arn_wildcard]
  }

  statement {
    sid    = "SigningKeySecretsManage"
    effect = "Allow"
    actions = [
      "secretsmanager:CreateSecret",
      "secretsmanager:DeleteSecret",
      "secretsmanager:TagResource",
      "secretsmanager:DescribeSecret",
    ]
    resources = [local.signing_keys_secret_arn_wildcard]
  }
}

resource "aws_iam_role_policy" "task" {
  name   = "${local.name_prefix}-ecs-task"
  role   = var.task_role_name
  policy = data.aws_iam_policy_document.task.json
}

resource "aws_ecs_cluster" "this" {
  name = local.name_prefix

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = {
    Name = local.name_prefix
  }
}

resource "aws_ecs_task_definition" "this" {
  family                   = local.name_prefix
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.cpu
  memory                   = var.memory
  execution_role_arn       = var.execution_role_arn
  task_role_arn            = var.task_role_arn

  container_definitions = jsonencode([
    {
      name      = local.container_name
      image     = local.image_uri
      essential = true

      portMappings = [
        {
          containerPort = var.container_port
          hostPort      = var.container_port
          protocol      = "tcp"
        }
      ]

      environment = local.container_environment
      secrets     = local.container_secrets

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.this.name
          awslogs-region        = var.aws_region
          awslogs-stream-prefix = "ecs"
        }
      }

      # No container healthCheck: ALB target-group checks cover the service, and the same
      # task definition is reused for one-off admin/migrate run-task overrides (those never
      # bind :8000, so a container healthCheck would kill them mid-command).
    }
  ])

  tags = {
    Name = local.name_prefix
  }
}

resource "aws_ecs_service" "this" {
  name            = local.name_prefix
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.this.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [var.ecs_security_group_id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = var.target_group_arn
    container_name   = local.container_name
    container_port   = var.container_port
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }
}

resource "aws_appautoscaling_target" "this" {
  max_capacity       = var.autoscaling_max_capacity
  min_capacity       = var.autoscaling_min_capacity
  resource_id        = "service/${aws_ecs_cluster.this.name}/${aws_ecs_service.this.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "cpu" {
  name               = "${local.name_prefix}-cpu-target"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.this.resource_id
  scalable_dimension = aws_appautoscaling_target.this.scalable_dimension
  service_namespace  = aws_appautoscaling_target.this.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }

    target_value       = var.autoscaling_cpu_target
    scale_in_cooldown  = 300
    scale_out_cooldown = 60
  }
}
