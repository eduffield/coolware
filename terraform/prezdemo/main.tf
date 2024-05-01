provider "aws" {
  region = "us-east-1"
}

resource "aws_security_group" "blog_sg" {
  name        = "blog_sg"
  description = "Security group for the Example Blog app"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "blog_instance" {
  ami           = "ami-0b0ea68c435eb488d"
  instance_type = "t2.micro"
  # key_name      = "example-key"            # Ensure you have this key pair available
  security_groups = [aws_security_group.blog_sg.name]

  user_data = <<-EOF
                  #!/bin/bash
                  sudo apt update
                  sudo apt install python3-pip python3-dev libpq-dev postgresql postgresql-contrib nginx curl -y
                  sudo pip3 install virtualenv
                  mkdir ~/myproject
                  cd ~/myproject
                  virtualenv myprojectenv
                  source myprojectenv/bin/activate
                  pip install django gunicorn psycopg2
                  django-admin startproject exampleblog .
                  # Additional setup like configuring settings.py for production can be added here
                  EOF

  tags = {
    Name = "ExampleBlogInstance"
  }
}

/*
resource "aws_db_instance" "blog_db" {
  allocated_storage    = 20
  storage_type         = "gp2"
  engine               = "postgres"
  engine_version       = "12"  # Adjust to a compatible version if necessary
  instance_class       = "db.t3.micro"  # Updated instance class
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
resource "aws_elb" "blog_elb" {
  name               = "example-blog-elb"
  availability_zones = ["us-east-1a", "us-east-1b"]

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

  instances                   = [aws_instance.blog_instance.id]
  cross_zone_load_balancing   = true
  idle_timeout                = 400
}

