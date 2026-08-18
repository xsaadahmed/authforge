terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # Values must match infra/bootstrap outputs after bootstrap has been applied manually.
  backend "s3" {
    bucket         = "authforge-terraform-state"
    key            = "staging/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "authforge-terraform-locks"
    encrypt        = true
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = var.project
      Environment = var.environment
    }
  }
}

locals {
  signing_key_secret_name_prefix = "${var.project}/${var.environment}/signing-keys"
}

module "vpc" {
  source = "../../modules/vpc"

  environment        = var.environment
  project            = var.project
  vpc_cidr           = var.vpc_cidr
  aws_region         = var.aws_region
  availability_zones = var.availability_zones
}

module "security_groups" {
  source = "../../modules/security_groups"

  environment = var.environment
  project     = var.project
  vpc_id      = module.vpc.vpc_id
}

module "iam" {
  source = "../../modules/iam"

  environment = var.environment
  project     = var.project
}

module "secrets" {
  source = "../../modules/secrets"

  environment = var.environment
  project     = var.project
}

module "ecr" {
  source = "../../modules/ecr"

  environment = var.environment
  project     = var.project
}

module "rds" {
  source = "../../modules/rds"

  environment         = var.environment
  project             = var.project
  subnet_ids          = module.vpc.private_subnet_ids
  security_group_ids  = [module.security_groups.rds_security_group_id]
  skip_final_snapshot = true
  deletion_protection = false
  multi_az            = false

  depends_on = [module.security_groups]
}

module "redis" {
  source = "../../modules/redis"

  environment        = var.environment
  project            = var.project
  subnet_ids         = module.vpc.private_subnet_ids
  security_group_ids = [module.security_groups.redis_security_group_id]
  auth_token         = module.secrets.redis_auth_token

  depends_on = [module.secrets, module.security_groups]
}

module "alb" {
  source = "../../modules/alb"

  environment        = var.environment
  project            = var.project
  vpc_id             = module.vpc.vpc_id
  subnet_ids         = module.vpc.public_subnet_ids
  security_group_ids = [module.security_groups.alb_security_group_id]
  enable_https       = var.enable_https
  certificate_arn    = var.certificate_arn

  depends_on = [module.security_groups]
}

module "ecs" {
  source = "../../modules/ecs"

  environment           = var.environment
  project               = var.project
  aws_region            = var.aws_region
  vpc_id                = module.vpc.vpc_id
  private_subnet_ids    = module.vpc.private_subnet_ids
  ecs_security_group_id = module.security_groups.ecs_security_group_id
  target_group_arn      = module.alb.target_group_arn
  issuer                = "https://${module.alb.alb_dns_name}"

  execution_role_arn  = module.iam.ecs_task_execution_role_arn
  execution_role_name = module.iam.ecs_task_execution_role_name
  task_role_arn       = module.iam.ecs_task_role_arn
  task_role_name      = module.iam.ecs_task_role_name

  ecr_repository_arn = module.ecr.repository_arn
  ecr_repository_url = module.ecr.repository_url
  image_tag          = var.image_tag

  rds_master_user_secret_arn = module.rds.master_user_secret_arn
  rds_address                = module.rds.address
  rds_port                   = module.rds.port
  db_name                    = module.rds.db_name

  redis_address = module.redis.address
  redis_port    = module.redis.port

  totp_encryption_key_secret_arn = module.secrets.totp_encryption_key_secret_arn
  admin_api_token_secret_arn     = module.secrets.admin_api_token_secret_arn
  redis_auth_token_secret_arn    = module.secrets.redis_auth_token_secret_arn
  app_secret_name_prefix         = module.secrets.secret_name_prefix
  signing_key_secret_name_prefix = local.signing_key_secret_name_prefix

  depends_on = [
    module.alb,
    module.iam,
    module.rds,
    module.redis,
    module.secrets,
    module.ecr,
    module.security_groups,
  ]
}
