provider "aws" {
  region = "us-east-1"
}

# EC2 Instance for the Django Application
resource "aws_instance" "blog_instance" {
  ami           = "ami-0e001c9271cf7f3b9" 
  instance_type = "t2.micro"
  #key_name      = "example-key"
  security_groups = [aws_security_group.web_sg.name]

  tags = {
    Name = "ExampleBlogInstance"
  }
}

# Security Group with Permissive Configurations
resource "aws_security_group" "web_sg" {
  name = "web-sg"

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "WebTrafficSG"
  }
}

# S3 Bucket with Public Access for Storing Blog Media
resource "aws_s3_bucket" "blog_media" {
  bucket = "example-blog-media"
  acl    = "public-read"

  tags = {
    Name = "PublicBlogMediaBucket"
  }
}

# CloudTrail for monitoring API activity with misconfigured logging
resource "aws_cloudtrail" "example_blog_trail" {
  name                          = "example-blog-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.bucket

  include_global_service_events = true
  is_multi_region_trail         = true
  enable_logging                = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true
    data_resource {
      type = "AWS::S3::Object"
      values = ["arn:aws:s3:::"]
    }
  }
}

# S3 Bucket for CloudTrail logs
resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket = "example-blog-cloudtrail-logs"
  acl    = "log-delivery-write"

  tags = {
    Name = "CloudTrailLogsBucket"
  }
}

/*
# RDS PostgreSQL Database
resource "aws_db_instance" "blog_db" {
  allocated_storage    = 20
  engine               = "postgres"
  engine_version       = "12.4"
  instance_class       = "db.t3.micro"
  db_name                 = "exampleblogdb"
  username             = "dbadmin"
  password             = "securepassword"
  parameter_group_name = "default.postgres12"
  skip_final_snapshot  = true
  publicly_accessible  = true

  tags = {
    Name = "ExampleBlogDB"
  }
}
*/

# VPC for the Django Blog
resource "aws_vpc" "blog_vpc" {
  cidr_block = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "BlogVPC"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "blog_gw" {
  vpc_id = aws_vpc.blog_vpc.id

  tags = {
    Name = "BlogInternetGateway"
  }
}

# Route Table with a default route to the Internet
resource "aws_route_table" "blog_route_table" {
  vpc_id = aws_vpc.blog_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.blog_gw.id
  }

  tags = {
    Name = "BlogRouteTable"
  }
}

# Associate Route Table to VPC
resource "aws_route_table_association" "a" {
  subnet_id      = aws_subnet.blog_subnet.id
  route_table_id = aws_route_table.blog_route_table.id
}

# Subnet for EC2 and RDS instances
resource "aws_subnet" "blog_subnet" {
  vpc_id            = aws_vpc.blog_vpc.id
  cidr_block        = "10.0.1.0/24"
  map_public_ip_on_launch = true

  tags = {
    Name = "BlogSubnet"
  }
}

# Output the public IP of the EC2 Instance
output "blog_instance_public_ip" {
  value = aws_instance.blog_instance.public_ip
}
