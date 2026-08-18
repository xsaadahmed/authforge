terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Values must match infra/bootstrap outputs after bootstrap has been applied manually.
  backend "s3" {
    bucket         = "authforge-terraform-state"
    key            = "prod/terraform.tfstate"
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
