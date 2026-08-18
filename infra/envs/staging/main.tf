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
