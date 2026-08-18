locals {
  name_prefix = "${var.project}-${var.environment}"
}

resource "aws_elasticache_subnet_group" "this" {
  name       = "${local.name_prefix}-redis"
  subnet_ids = var.subnet_ids

  tags = {
    Name = "${local.name_prefix}-redis-subnet-group"
  }
}

# Staging runs a single-node replication group for cost. Production would use multiple
# cache clusters with automatic failover enabled across AZs.
resource "aws_elasticache_replication_group" "this" {
  replication_group_id = "${local.name_prefix}-redis"
  description          = "AuthForge Redis (${var.environment})"

  engine         = "redis"
  engine_version = var.engine_version
  node_type      = var.node_type
  port           = var.port

  num_cache_clusters         = var.num_cache_nodes
  automatic_failover_enabled = false
  multi_az_enabled           = false

  subnet_group_name  = aws_elasticache_subnet_group.this.name
  security_group_ids = var.security_group_ids

  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  auth_token                 = var.auth_token

  tags = {
    Name = "${local.name_prefix}-redis"
  }
}
