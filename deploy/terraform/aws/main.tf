data "aws_region" "current" {}

resource "aws_security_group" "media" {
  name   = "${var.name}-media"
  vpc_id = var.vpc_id

  dynamic "ingress" {
    for_each = [
      { protocol = "udp", from = var.sip_port, to = var.sip_port },
      { protocol = "tcp", from = var.sip_port, to = var.sip_port },
      { protocol = "udp", from = var.quic_port, to = var.quic_port },
      { protocol = "udp", from = var.rtp_port_start, to = var.rtp_port_end },
      { protocol = "tcp", from = var.api_port, to = var.api_port }
    ]
    content {
      protocol    = ingress.value.protocol
      from_port   = ingress.value.from
      to_port     = ingress.value.to
      cidr_blocks = ["0.0.0.0/0"]
    }
  }
  egress {
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_ecs_cluster" "this" { name = var.name }
resource "aws_ecs_capacity_provider" "ec2" {
  name = "${var.name}-ec2"
  auto_scaling_group_provider {
    auto_scaling_group_arn         = var.autoscaling_group_arn
    managed_termination_protection = "DISABLED"
    managed_scaling {
      status          = "ENABLED"
      target_capacity = 80
    }
  }
}
resource "aws_ecs_cluster_capacity_providers" "this" {
  cluster_name       = aws_ecs_cluster.this.name
  capacity_providers = [aws_ecs_capacity_provider.ec2.name]
  default_capacity_provider_strategy {
    capacity_provider = aws_ecs_capacity_provider.ec2.name
    weight            = 1
  }
}

resource "aws_iam_role" "execution" {
  name = "${var.name}-execution"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "ecs-tasks.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}
resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}
resource "aws_iam_role_policy" "secrets" {
  count = length(var.secret_arns) == 0 ? 0 : 1
  role  = aws_iam_role.execution.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["secretsmanager:GetSecretValue"], Resource = values(var.secret_arns) }]
  })
}
resource "aws_cloudwatch_log_group" "this" {
  name              = "/bridgefu/${var.name}"
  retention_in_days = 30
}

resource "aws_ecs_task_definition" "worker" {
  family                   = "${var.name}-worker"
  requires_compatibilities = ["EC2"]
  network_mode             = "host"
  cpu                      = 2048
  memory                   = 4096
  execution_role_arn       = aws_iam_role.execution.arn
  volume {
    name      = "config"
    host_path = var.config_host_path
  }
  container_definitions = jsonencode([{
    name                   = "bridgefu"
    image                  = var.image
    essential              = true
    readonlyRootFilesystem = true
    command                = ["--config", "/etc/bridgefu/bridgefu.yaml"]
    mountPoints            = [{ sourceVolume = "config", containerPath = "/etc/bridgefu", readOnly = true }]
    secrets                = [for name, arn in var.secret_arns : { name = name, valueFrom = arn }]
    portMappings = [
      { containerPort = var.sip_port, hostPort = var.sip_port, protocol = "udp" },
      { containerPort = var.sip_port, hostPort = var.sip_port, protocol = "tcp" },
      { containerPort = var.quic_port, hostPort = var.quic_port, protocol = "udp" },
      { containerPort = var.api_port, hostPort = var.api_port, protocol = "tcp" }
    ]
    healthCheck      = { command = ["CMD-SHELL", "curl -fsS http://127.0.0.1:${var.api_port}/readyz || exit 1"], interval = 15, timeout = 5, retries = 3, startPeriod = 30 }
    logConfiguration = { logDriver = "awslogs", options = { "awslogs-group" = aws_cloudwatch_log_group.this.name, "awslogs-region" = data.aws_region.current.name, "awslogs-stream-prefix" = "worker" } }
  }])
}

resource "aws_lb" "sip" {
  name               = substr("${var.name}-sip", 0, 32)
  load_balancer_type = "network"
  subnets            = var.subnet_ids
}
resource "aws_lb_target_group" "sip" {
  name        = substr("${var.name}-sip", 0, 32)
  port        = var.sip_port
  protocol    = "TCP_UDP"
  vpc_id      = var.vpc_id
  target_type = "instance"
  health_check {
    protocol = "HTTP"
    port     = tostring(var.api_port)
    path     = "/readyz"
  }
}
resource "aws_lb_listener" "sip" {
  load_balancer_arn = aws_lb.sip.arn
  port              = var.sip_port
  protocol          = "TCP_UDP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.sip.arn
  }
}

resource "aws_lb" "quic" {
  name               = substr("${var.name}-quic", 0, 32)
  load_balancer_type = "network"
  subnets            = var.subnet_ids
}
resource "aws_lb_target_group" "quic" {
  name        = substr("${var.name}-quic", 0, 32)
  port        = var.quic_port
  protocol    = "QUIC"
  vpc_id      = var.vpc_id
  target_type = "instance"
  health_check {
    protocol = "HTTP"
    port     = tostring(var.api_port)
    path     = "/readyz"
  }
}
resource "aws_lb_listener" "quic" {
  load_balancer_arn = aws_lb.quic.arn
  port              = var.quic_port
  protocol          = "QUIC"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.quic.arn
  }
}

resource "aws_ecs_service" "worker" {
  name            = "${var.name}-worker"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.worker.arn
  desired_count   = var.desired_workers
  capacity_provider_strategy {
    capacity_provider = aws_ecs_capacity_provider.ec2.name
    weight            = 1
  }
  load_balancer {
    target_group_arn = aws_lb_target_group.sip.arn
    container_name   = "bridgefu"
    container_port   = var.sip_port
  }
  load_balancer {
    target_group_arn = aws_lb_target_group.quic.arn
    container_name   = "bridgefu"
    container_port   = var.quic_port
  }
}

resource "aws_db_subnet_group" "this" {
  name       = var.name
  subnet_ids = var.subnet_ids
}
resource "aws_db_instance" "postgres" {
  identifier                = var.name
  engine                    = "postgres"
  engine_version            = "17"
  instance_class            = "db.t4g.medium"
  allocated_storage         = 50
  storage_encrypted         = true
  db_name                   = var.database_name
  username                  = var.database_username
  password                  = var.database_password
  db_subnet_group_name      = aws_db_subnet_group.this.name
  backup_retention_period   = 7
  multi_az                  = true
  skip_final_snapshot       = false
  final_snapshot_identifier = "${var.name}-final"
}
resource "aws_elasticache_subnet_group" "this" {
  name       = var.name
  subnet_ids = var.subnet_ids
}
resource "aws_elasticache_replication_group" "redis" {
  replication_group_id       = var.name
  description                = "Bridgefu coordination"
  node_type                  = "cache.t4g.small"
  port                       = 6379
  subnet_group_name          = aws_elasticache_subnet_group.this.name
  automatic_failover_enabled = true
  num_cache_clusters         = 2
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
}

output "sip_endpoint" { value = aws_lb.sip.dns_name }
output "quic_endpoint" { value = aws_lb.quic.dns_name }
output "postgres_endpoint" { value = aws_db_instance.postgres.address }
output "redis_endpoint" { value = aws_elasticache_replication_group.redis.primary_endpoint_address }
