terraform {
  required_version = ">= 1.6.0"
}

resource "aws_security_group" "administration" {
  name = "public-administration"

  ingress {
    description = "Temporary SSH administration"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
