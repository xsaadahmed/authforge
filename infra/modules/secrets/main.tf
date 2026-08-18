terraform {
  required_providers {
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

locals {
  # authforge/{environment}/{name} — matches the authforge/* prefix convention used by
  # signing keys (authforge/signing-keys/{kid}) in app/services/key_providers.py.
  secret_prefix = "${var.project}/${var.environment}"
}

resource "random_password" "totp_encryption_key" {
  length  = 64
  special = true
}

resource "random_password" "admin_api_token" {
  length  = 48
  special = false
}

resource "random_password" "redis_auth_token" {
  length           = 32
  special          = true
  override_special = "!&#$^*~.-_="
}

resource "aws_secretsmanager_secret" "totp_encryption_key" {
  name                    = "${local.secret_prefix}/totp_encryption_key"
  description             = "TOTP encryption key for AuthForge (${var.environment})"
  recovery_window_in_days = var.recovery_window_in_days
}

resource "aws_secretsmanager_secret_version" "totp_encryption_key" {
  secret_id     = aws_secretsmanager_secret.totp_encryption_key.id
  secret_string = random_password.totp_encryption_key.result
}

resource "aws_secretsmanager_secret" "admin_api_token" {
  name                    = "${local.secret_prefix}/admin_api_token"
  description             = "Admin API bearer token for AuthForge (${var.environment})"
  recovery_window_in_days = var.recovery_window_in_days
}

resource "aws_secretsmanager_secret_version" "admin_api_token" {
  secret_id     = aws_secretsmanager_secret.admin_api_token.id
  secret_string = random_password.admin_api_token.result
}

resource "aws_secretsmanager_secret" "redis_auth_token" {
  name                    = "${local.secret_prefix}/redis_auth_token"
  description             = "ElastiCache Redis AUTH token for AuthForge (${var.environment})"
  recovery_window_in_days = var.recovery_window_in_days
}

resource "aws_secretsmanager_secret_version" "redis_auth_token" {
  secret_id     = aws_secretsmanager_secret.redis_auth_token.id
  secret_string = random_password.redis_auth_token.result
}
