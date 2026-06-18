data "aws_availability_zones" "available" {
  state = "available"
}

# Latest Amazon Linux 2023 arm64 AMI (Graviton) via the public SSM parameter.
data "aws_ssm_parameter" "al2023_arm64" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64"
}

# --- networking (PRD §8: VPC + public subnet + IGW) --------------------------

resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = var.name }
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = var.name }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.this.id
  cidr_block              = var.subnet_cidr
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true

  tags = { Name = "${var.name}-public" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }

  tags = { Name = "${var.name}-public" }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# --- security group ----------------------------------------------------------

resource "aws_security_group" "this" {
  name        = "${var.name}-sg"
  description = "bridgefu SIP/RTP gateway"
  vpc_id      = aws_vpc.this.id

  # SSH (deploy.sh + admin) — restricted to admin_cidr.
  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_cidr]
  }

  # Health/metrics HTTP — restricted to admin_cidr.
  ingress {
    description = "bridgefu /healthz + /metrics"
    from_port   = 9090
    to_port     = 9090
    protocol    = "tcp"
    cidr_blocks = [var.admin_cidr]
  }

  # SIP signaling (UDP + TCP) — from sip_cidr (default open for POC).
  ingress {
    description = "SIP UDP"
    from_port   = 5060
    to_port     = 5060
    protocol    = "udp"
    cidr_blocks = [var.sip_cidr]
  }

  ingress {
    description = "SIP TCP"
    from_port   = 5060
    to_port     = 5060
    protocol    = "tcp"
    cidr_blocks = [var.sip_cidr]
  }

  # RTP media (UDP) — from sip_cidr (default open for POC).
  ingress {
    description = "RTP media"
    from_port   = 16384
    to_port     = 32767
    protocol    = "udp"
    cidr_blocks = [var.sip_cidr]
  }

  egress {
    description = "all egress"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.name}-sg" }
}

# --- IAM instance role (least-privilege Connect control plane) ---------------

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "this" {
  name               = "${var.name}-role"
  assume_role_policy = data.aws_iam_policy_document.assume.json
  tags               = { Name = var.name }
}

# PRD §6: only StartWebRTCContact + StopContact. Resource "*" for the POC —
# TODO: scope to the specific instance + contact-flow ARNs once stable.
data "aws_iam_policy_document" "connect" {
  statement {
    sid    = "ConnectControlPlane"
    effect = "Allow"
    actions = [
      "connect:StartWebRTCContact",
      "connect:StopContact",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "connect" {
  name   = "${var.name}-connect"
  role   = aws_iam_role.this.id
  policy = data.aws_iam_policy_document.connect.json
}

resource "aws_iam_instance_profile" "this" {
  name = "${var.name}-profile"
  role = aws_iam_role.this.name
}

# --- key pair + instance -----------------------------------------------------

resource "aws_key_pair" "this" {
  key_name   = "${var.name}-key"
  public_key = var.public_key
}

resource "aws_instance" "this" {
  ami                    = data.aws_ssm_parameter.al2023_arm64.value
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.this.id]
  iam_instance_profile   = aws_iam_instance_profile.this.name
  key_name               = aws_key_pair.this.key_name

  # IMDSv2 required (the daemon's imds.rs uses token-authenticated IMDSv2).
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_size = var.root_volume_gb
    volume_type = "gp3"
  }

  user_data = templatefile("${path.module}/templates/user_data.sh.tftpl", {})

  tags = { Name = var.name }
}

# --- Elastic IP (stable public address for SIP signaling + media) ------------

resource "aws_eip" "this" {
  instance   = aws_instance.this.id
  domain     = "vpc"
  depends_on = [aws_internet_gateway.this]

  tags = { Name = var.name }
}
