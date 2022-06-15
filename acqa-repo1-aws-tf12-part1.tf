provider "aws" {
  region = "us-east-1"
#  skip_credentials_validation = true
#  skip_requesting_account_id  = true
#  access_key                  = "mock_access_key"
#  secret_key                  = "mock_secret_key"
}

# # Create a VPC to launch our instances into
# resource "aws_vpc" "tcs-qe-vpc1" {
#   cidr_block = "10.0.0.0/16"
#   tags = {
#     Name = format("%s-vpc1", var.acqaPrefix)
#     TcsQEResource = "true"
#     Owner = "ACQA"
#     Drift = "Test"
#   }
# }

# Create a security group with most of the vulnerabilities
resource "aws_security_group" "tcs-qe-sg1-withoutnametag" {
  name        = "tcs-qe-sg1-withoutnametag"
  description = "This security group is for API test automation"
  vpc_id      = "vpc-0b9a8f63a00fe47cc"

  tags = {
    TcsQEResource = "true"
  }

  # HTTP access from the VPC - changed
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/24"]
  }
}

resource "aws_security_group" "tcs-qe-sg2-withoutnametag" {
  name        = "tcs-qe-sg2-withoutnametag"
  description = "This security group is for API test automation"
  vpc_id      = "vpc-0b9a8f63a00fe47cc"

  tags = {
    TcsQEResource = "true"
  }

  # HTTP access from the VPC - changed
  ingress {
    from_port   = 9020
    to_port     = 9030
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/24"]
  }
}

# Create S3 bucket
resource "aws_s3_bucket" "tcs-qe-s3-bucket1-withoutnametag" {
  bucket = "tcs-qe-s3-bucket1-withoutnametag"
  tags = {
    TcsQEResource = "true"
  }
}

# Create acl resource to grant permissions on bucket
resource "aws_s3_bucket_acl" "tcs-qe-s3-bucket1-acl" {
  bucket = aws_s3_bucket.tcs-qe-s3-bucket1-withoutnametag.id
  acl    = "private"
}

# Create S3 bucket
resource "aws_s3_bucket" "tcs-qe-s3-bucket2-withoutnametag" {
  bucket = "tcs-qe-s3-bucket2-withoutnametag"
  tags = {
    TcsQEResource = "true"
  }
}

# Create acl resource to grant permissions on bucket
resource "aws_s3_bucket_acl" "tcs-qe-s3-bucket2-acl" {
  bucket = aws_s3_bucket.tcs-qe-s3-bucket2-withoutnametag.id
  acl    = "private"
}