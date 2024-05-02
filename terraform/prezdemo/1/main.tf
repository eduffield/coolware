provider "aws" {
  region = "us-east-1"
}

# EC2 Instance for the Django Application
resource "aws_instance" "blog_instance" {
  ami           = "ami-0e001c9271cf7f3b9"
  instance_type = "t2.micro"
  security_groups = [aws_security_group.web_sg.name]

  tags = {
    Name = "ExampleBlogInstance"
  }
}

# Security Group for Web Traffic
resource "aws_security_group" "web_sg" {
  name = "web-sg"

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
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

# Security Group with Vulnerable Configurations
resource "aws_security_group" "vulnerable_sg" {
  name = "vulnerable-sg"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 21
    to_port     = 21
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "VulnerableSG"
  }
}

# EBS Volume Attached to EC2 Instance
resource "aws_ebs_volume" "blog_volume" {
  availability_zone = aws_instance.blog_instance.availability_zone
  size              = 10

  tags = {
    Name = "ExampleBlogVolume"
  }
}

# Attach EBS to EC2
resource "aws_volume_attachment" "ebs_attachment" {
  device_name = "/dev/sdh"
  volume_id   = aws_ebs_volume.blog_volume.id
  instance_id = aws_instance.blog_instance.id
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

  tags = {
    Name = "ExampleBlogDB"
  }
}
*/
# Elastic Load Balancer
resource "aws_elb" "blog_elb" {
  name               = "example-blog-elb"
  availability_zones = ["us-east-1a"]

  listener {
    instance_port     = 80
    instance_protocol = "HTTP"
    lb_port           = 80
    lb_protocol       = "HTTP"
  }

  health_check {
    target              = "HTTP:80/"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }

  instances = [aws_instance.blog_instance.id]
}

# Output the public IP of the EC2 Instance
output "blog_instance_public_ip" {
  value = aws_instance.blog_instance.public_ip
}
