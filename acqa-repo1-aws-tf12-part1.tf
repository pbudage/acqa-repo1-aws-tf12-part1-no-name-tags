provider "aws" {
  region = "ca-central-1"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  access_key                  = "mock_access_key"
  secret_key                  = "mock_secret_key"
}

# Create a security group with most of the vulnerabilities
resource "aws_security_group" "tcs-qe-sg1-withoutnametag-5362" {
  name        = "tcs-qe-sg1-withoutnametag-5362"
  description = "This security group is for API test automation"
  vpc_id      = "vpc-0dcfc6c7488b848c7"

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

resource "aws_security_group" "tcs-qe-sg2-withoutnametag-5362" {
  name        = "tcs-qe-sg2-withoutnametag"
  description = "This security group is for API test automation"
  vpc_id      = "vpc-0dcfc6c7488b848c7"

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
resource "aws_s3_bucket" "tcs-qe-s3-bucket1-withoutnametag-5362" {
  bucket = "tcs-qe-s3-bucket1-withoutnametag-5362"
  tags = {
    TcsQEResource = "true"
  }
}

# Create acl resource to grant permissions on bucket
resource "aws_s3_bucket_acl" "tcs-qe-s3-bucket1-acl-5362" {
  bucket = aws_s3_bucket.tcs-qe-s3-bucket1-withoutnametag-5362.id
  acl    = "private"
}

# Create S3 bucket
resource "aws_s3_bucket" "tcs-qe-s3-bucket2-withoutnametag-5362" {
  bucket = "tcs-qe-s3-bucket2-withoutnametag-5362"
  tags = {
    TcsQEResource = "true"
  }
}

# Create acl resource to grant permissions on bucket
resource "aws_s3_bucket_acl" "tcs-qe-s3-bucket2-acl-5362" {
  bucket = aws_s3_bucket.tcs-qe-s3-bucket2-withoutnametag-5362.id
  acl    = "private"
}
