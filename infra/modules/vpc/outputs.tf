output "vpc_id" {
  description = "ID of the VPC."
  value       = aws_vpc.this.id
}

output "vpc_cidr_block" {
  description = "CIDR block of the VPC."
  value       = aws_vpc.this.cidr_block
}

output "availability_zones" {
  description = "Availability zones used by the VPC subnets."
  value       = local.azs
}

output "public_subnet_ids" {
  description = "IDs of public subnets (one per AZ)."
  value       = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  description = "IDs of private subnets (one per AZ)."
  value       = aws_subnet.private[*].id
}

output "nat_gateway_id" {
  description = "ID of the shared NAT Gateway."
  value       = aws_nat_gateway.this.id
}

output "internet_gateway_id" {
  description = "ID of the Internet Gateway."
  value       = aws_internet_gateway.this.id
}
