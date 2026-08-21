data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

locals {
  name_prefix = "${var.project}-${var.environment}"

  github_oidc_url = "https://token.actions.githubusercontent.com"

  # OIDC provider ARNs use a fixed suffix; no need to read the created resource ARN.
  github_oidc_provider_arn = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/token.actions.githubusercontent.com"

  state_bucket_arn        = "arn:${data.aws_partition.current.partition}:s3:::${var.state_bucket_name}"
  state_object_arn_prefix = "${local.state_bucket_arn}/${var.state_key_prefix}*"
  lock_table_arn          = "arn:${data.aws_partition.current.partition}:dynamodb:${var.aws_region}:${data.aws_caller_identity.current.account_id}:table/${var.lock_table_name}"

  ecs_cluster_arn = "arn:${data.aws_partition.current.partition}:ecs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:cluster/${var.ecs_cluster_name}"
  ecs_service_arn = "arn:${data.aws_partition.current.partition}:ecs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:service/${var.ecs_cluster_name}/${var.ecs_service_name}"

  plan_trust_subjects = [
    "repo:${var.github_repository}:pull_request",
    "repo:${var.github_repository}:ref:refs/heads/main",
  ]

  apply_trust_subjects = [
    "repo:${var.github_repository}:ref:refs/heads/main",
  ]
}

resource "aws_iam_openid_connect_provider" "github" {
  count = var.create_github_oidc_provider ? 1 : 0

  url = local.github_oidc_url

  client_id_list = [
    "sts.amazonaws.com",
  ]

  thumbprint_list = [
    "6938fd488e0b040084aebca22bec6c8c9e78340d",
    "1c58a3a8518e8759bf075b76b750d7fbf2b48a92",
  ]

  tags = {
    Name = "${local.name_prefix}-github-oidc"
  }
}

data "aws_iam_policy_document" "plan_assume" {
  statement {
    sid     = "GitHubActionsPlan"
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [local.github_oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = local.plan_trust_subjects
    }
  }
}

data "aws_iam_policy_document" "apply_assume" {
  statement {
    sid     = "GitHubActionsApply"
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [local.github_oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = local.apply_trust_subjects
    }
  }
}

resource "aws_iam_role" "plan" {
  name               = "${local.name_prefix}-github-plan"
  assume_role_policy = data.aws_iam_policy_document.plan_assume.json
  description        = "GitHub Actions Terraform plan role for ${var.github_repository}"
}

resource "aws_iam_role" "apply" {
  name               = "${local.name_prefix}-github-apply"
  assume_role_policy = data.aws_iam_policy_document.apply_assume.json
  description        = "GitHub Actions deploy role for ${var.github_repository} (main branch only)"
}

data "aws_iam_policy_document" "state_backend_read" {
  statement {
    sid    = "TerraformStateList"
    effect = "Allow"
    actions = [
      "s3:ListBucket",
    ]
    resources = [local.state_bucket_arn]

    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["${var.state_key_prefix}*"]
    }
  }

  statement {
    sid    = "TerraformStateRead"
    effect = "Allow"
    actions = [
      "s3:GetObject",
    ]
    resources = [local.state_object_arn_prefix]
  }

  statement {
    sid    = "TerraformStateLock"
    effect = "Allow"
    actions = [
      "dynamodb:DescribeTable",
      "dynamodb:GetItem",
      "dynamodb:PutItem",
      "dynamodb:DeleteItem",
    ]
    resources = [local.lock_table_arn]
  }
}

data "aws_iam_policy_document" "state_backend_write" {
  statement {
    sid    = "TerraformStateWrite"
    effect = "Allow"
    actions = [
      "s3:PutObject",
      "s3:DeleteObject",
    ]
    resources = [local.state_object_arn_prefix]
  }
}

data "aws_iam_policy_document" "terraform_plan_read" {
  statement {
    sid    = "DescribeAuthForgeResources"
    effect = "Allow"
    actions = [
      "ec2:Describe*",
      "elasticloadbalancing:Describe*",
      "ecs:Describe*",
      "ecs:List*",
      "ecr:Describe*",
      "ecr:List*",
      "rds:Describe*",
      "elasticache:Describe*",
      "elasticache:List*",
      "secretsmanager:Describe*",
      "secretsmanager:GetResourcePolicy",
      "secretsmanager:ListSecretVersionIds",
      "iam:GetRole",
      "iam:GetRolePolicy",
      "iam:ListRolePolicies",
      "iam:ListAttachedRolePolicies",
      "logs:DescribeLogGroups",
      "logs:DescribeMetricFilters",
      "sns:GetTopicAttributes",
      "sns:ListTagsForResource",
      "cloudwatch:DescribeAlarms",
      "cloudwatch:ListTagsForResource",
      "application-autoscaling:Describe*",
    ]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/Project"
      values   = [var.project]
    }
  }
}

# Plan role cannot mutate infrastructure or push images; it can refresh state for terraform plan.
data "aws_iam_policy_document" "plan" {
  source_policy_documents = [
    data.aws_iam_policy_document.state_backend_read.json,
    data.aws_iam_policy_document.terraform_plan_read.json,
  ]
}

resource "aws_iam_role_policy" "plan" {
  name   = "${local.name_prefix}-github-plan"
  role   = aws_iam_role.plan.id
  policy = data.aws_iam_policy_document.plan.json
}

data "aws_iam_policy_document" "ecr_push" {
  statement {
    sid    = "EcrAuth"
    effect = "Allow"
    actions = [
      "ecr:GetAuthorizationToken",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "EcrPush"
    effect = "Allow"
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:CompleteLayerUpload",
      "ecr:InitiateLayerUpload",
      "ecr:PutImage",
      "ecr:UploadLayerPart",
    ]
    resources = [var.ecr_repository_arn]
  }
}

data "aws_iam_policy_document" "ecs_deploy" {
  statement {
    sid    = "EcsDeploy"
    effect = "Allow"
    actions = [
      "ecs:DescribeServices",
      "ecs:UpdateService",
    ]
    resources = [
      local.ecs_cluster_arn,
      local.ecs_service_arn,
    ]
  }
}

data "aws_iam_policy_document" "terraform_apply_write" {
  statement {
    sid    = "MutateAuthForgeResources"
    effect = "Allow"
    actions = [
      "ec2:*",
      "elasticloadbalancing:*",
      "ecs:*",
      "ecr:*",
      "rds:*",
      "elasticache:*",
      "secretsmanager:*",
      "iam:*",
      "logs:*",
      "sns:*",
      "cloudwatch:*",
      "application-autoscaling:*",
    ]
    resources = ["*"]

    condition {
      test     = "StringEqualsIfExists"
      variable = "aws:ResourceTag/Project"
      values   = [var.project]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/Project"
      values   = [var.project]
    }
  }
}

data "aws_iam_policy_document" "apply" {
  source_policy_documents = [
    data.aws_iam_policy_document.state_backend_read.json,
    data.aws_iam_policy_document.state_backend_write.json,
    data.aws_iam_policy_document.terraform_plan_read.json,
    data.aws_iam_policy_document.terraform_apply_write.json,
    data.aws_iam_policy_document.ecr_push.json,
    data.aws_iam_policy_document.ecs_deploy.json,
  ]
}

resource "aws_iam_role_policy" "apply" {
  name   = "${local.name_prefix}-github-apply"
  role   = aws_iam_role.apply.id
  policy = data.aws_iam_policy_document.apply.json
}
