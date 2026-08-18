locals {
  repository_name = var.project
}

resource "aws_ecr_repository" "this" {
  name                 = local.repository_name
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    Name = local.repository_name
  }
}

resource "aws_ecr_lifecycle_policy" "this" {
  repository = aws_ecr_repository.this.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Expire untagged images older than ${var.untagged_image_max_age_days} days"
        selection = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = var.untagged_image_max_age_days
        }
        action = {
          type = "expire"
        }
      },
      {
        rulePriority = 2
        description  = "Keep the last ${var.tagged_image_count_to_retain} tagged images"
        selection = {
          tagStatus     = "tagged"
          tagPrefixList = ["v", "sha", "release", "staging", "prod", "main", "latest", "build"]
          countType     = "imageCountMoreThan"
          countNumber   = var.tagged_image_count_to_retain
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}
