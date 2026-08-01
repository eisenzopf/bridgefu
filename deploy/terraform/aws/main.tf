data "aws_region" "current" {}

locals {
  role_capacity_providers = {
    gateway  = aws_ecs_capacity_provider.gateway.name
    worker   = aws_ecs_capacity_provider.worker.name
    moqrelay = aws_ecs_capacity_provider.moq_relay.name
  }

  role_config_paths = {
    gateway  = var.gateway_config_host_path
    worker   = var.worker_config_host_path
    moqrelay = var.moq_relay_config_host_path
  }

  role_resources = {
    gateway = {
      cpu     = var.gateway_cpu
      memory  = var.gateway_memory
      desired = var.desired_gateways
      min     = var.min_gateways
      max     = var.max_gateways
      ports = [
        { containerPort = var.gateway_quic_port, hostPort = var.gateway_quic_port, protocol = "udp" },
        { containerPort = var.api_port, hostPort = var.api_port, protocol = "tcp" },
        { containerPort = var.sip_port, hostPort = var.sip_port, protocol = "udp" },
        { containerPort = var.webrtc_ws_port, hostPort = var.webrtc_ws_port, protocol = "tcp" },
        { containerPort = var.webrtc_whip_port, hostPort = var.webrtc_whip_port, protocol = "tcp" },
        { containerPort = var.webrtc_media_port, hostPort = var.webrtc_media_port, protocol = "udp" },
        { containerPort = var.operations_port, hostPort = var.operations_port, protocol = "tcp" },
      ]
    }
    worker = {
      cpu     = var.worker_cpu
      memory  = var.worker_memory
      desired = var.desired_workers
      min     = var.min_workers
      max     = var.max_workers
      ports = [
        { containerPort = var.private_forwarding_port, hostPort = var.private_forwarding_port, protocol = "udp" },
        { containerPort = var.operations_port, hostPort = var.operations_port, protocol = "tcp" },
      ]
    }
    moqrelay = {
      cpu     = var.moq_relay_cpu
      memory  = var.moq_relay_memory
      desired = var.desired_moq_relays
      min     = var.min_moq_relays
      max     = var.max_moq_relays
      ports = [
        { containerPort = var.moq_publisher_port, hostPort = var.moq_publisher_port, protocol = "udp" },
        { containerPort = var.moq_webtransport_port, hostPort = var.moq_webtransport_port, protocol = "udp" },
        { containerPort = var.moq_raw_quic_port, hostPort = var.moq_raw_quic_port, protocol = "udp" },
        { containerPort = var.operations_port, hostPort = var.operations_port, protocol = "tcp" },
      ]
    }
  }

  role_load_balancers = {
    gateway = [
      { target_group_arn = aws_lb_target_group.gateway_quic.arn, container_port = var.gateway_quic_port },
      { target_group_arn = aws_lb_target_group.gateway_api.arn, container_port = var.api_port },
      { target_group_arn = aws_lb_target_group.gateway_sip.arn, container_port = var.sip_port },
      { target_group_arn = aws_lb_target_group.gateway_webrtc_ws.arn, container_port = var.webrtc_ws_port },
      { target_group_arn = aws_lb_target_group.gateway_webrtc_whip.arn, container_port = var.webrtc_whip_port },
    ]
    worker = []
    moqrelay = [
      { target_group_arn = aws_lb_target_group.moq_publisher.arn, container_port = var.moq_publisher_port },
      { target_group_arn = aws_lb_target_group.moq_webtransport.arn, container_port = var.moq_webtransport_port },
      { target_group_arn = aws_lb_target_group.moq_raw_quic.arn, container_port = var.moq_raw_quic_port },
    ]
  }

  secret_arns = values(var.secret_arns)
  common_environment = [
    { name = "OTEL_EXPORTER_OTLP_ENDPOINT", value = var.otel_exporter_endpoint },
    { name = "RUST_LOG", value = var.rust_log },
  ]
}

check "role_service_capacity" {
  assert {
    condition = alltrue([
      var.min_gateways >= 1 && var.desired_gateways >= var.min_gateways && var.desired_gateways <= var.max_gateways,
      var.min_workers >= 1 && var.desired_workers >= var.min_workers && var.desired_workers <= var.max_workers,
      var.min_moq_relays >= 1 && var.desired_moq_relays >= var.min_moq_relays && var.desired_moq_relays <= var.max_moq_relays,
    ])
    error_message = "each desired role count must be between its positive min and max."
  }
}

check "moq_listener_ports_match" {
  assert {
    condition = toset(var.moq_relay_ports) == toset([
      var.moq_publisher_port,
      var.moq_webtransport_port,
      var.moq_raw_quic_port,
    ])
    error_message = "moq_relay_ports must exactly match the three named MOQT listener ports."
  }
}

check "gateway_media_eips_match_instances" {
  assert {
    condition     = toset(keys(var.gateway_media_eip_allocation_ids)) == toset(keys(var.gateway_instance_ids))
    error_message = "gateway_media_eip_allocation_ids and gateway_instance_ids must have identical keys."
  }
}

check "gateway_listener_ports_are_distinct" {
  assert {
    condition = length(distinct([
      var.api_port,
      var.operations_port,
      var.sip_port,
      var.gateway_quic_port,
      var.private_forwarding_port,
      var.webrtc_ws_port,
      var.webrtc_whip_port,
      var.webrtc_media_port,
    ])) == 8
    error_message = "gateway API, operations, SIP, QUIC, forwarding, WebRTC signaling, and WebRTC media ports must be distinct."
  }
}

resource "aws_ecs_cluster" "this" {
  name = var.name

  setting {
    name  = "containerInsights"
    value = "enhanced"
  }
}

resource "aws_ecs_capacity_provider" "gateway" {
  name = "${var.name}-gateway"
  auto_scaling_group_provider {
    auto_scaling_group_arn         = var.gateway_autoscaling_group_arn
    managed_termination_protection = "DISABLED"
    managed_scaling {
      status                    = "ENABLED"
      target_capacity           = 100
      minimum_scaling_step_size = 1
      maximum_scaling_step_size = 2
    }
  }
}

resource "aws_ecs_capacity_provider" "worker" {
  name = "${var.name}-worker"
  auto_scaling_group_provider {
    auto_scaling_group_arn         = var.worker_autoscaling_group_arn
    managed_termination_protection = "DISABLED"
    managed_scaling {
      status                    = "ENABLED"
      target_capacity           = 80
      minimum_scaling_step_size = 1
      maximum_scaling_step_size = 5
    }
  }
}

resource "aws_ecs_capacity_provider" "moq_relay" {
  name = "${var.name}-moq-relay"
  auto_scaling_group_provider {
    auto_scaling_group_arn         = var.moq_relay_autoscaling_group_arn
    managed_termination_protection = "DISABLED"
    managed_scaling {
      status                    = "ENABLED"
      target_capacity           = 80
      minimum_scaling_step_size = 1
      maximum_scaling_step_size = 5
    }
  }
}

resource "aws_ecs_cluster_capacity_providers" "this" {
  cluster_name = aws_ecs_cluster.this.name
  capacity_providers = [
    aws_ecs_capacity_provider.gateway.name,
    aws_ecs_capacity_provider.worker.name,
    aws_ecs_capacity_provider.moq_relay.name,
  ]
}

resource "aws_cloudwatch_log_group" "bridgefu" {
  for_each          = local.role_resources
  name              = "/bridgefu/${var.name}/${each.key}"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.cloudwatch_kms_key_arn
}

resource "aws_cloudwatch_log_group" "redis_slow" {
  name              = "/bridgefu/${var.name}/redis/slow"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.cloudwatch_kms_key_arn
}

resource "aws_cloudwatch_log_group" "redis_engine" {
  name              = "/bridgefu/${var.name}/redis/engine"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.cloudwatch_kms_key_arn
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

resource "aws_iam_role_policy" "execution_secrets" {
  count = length(local.secret_arns) == 0 ? 0 : 1
  role  = aws_iam_role.execution.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["secretsmanager:GetSecretValue"], Resource = local.secret_arns }]
  })
}

resource "aws_iam_role_policy" "execution_secret_kms" {
  count = length(var.secret_kms_key_arns) == 0 ? 0 : 1
  role  = aws_iam_role.execution.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["kms:Decrypt"], Resource = var.secret_kms_key_arns }]
  })
}

resource "aws_iam_role" "runtime" {
  name = "${var.name}-runtime"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "ecs-tasks.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy" "runtime_telemetry" {
  role = aws_iam_role.runtime.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "cloudwatch:PutMetricData",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "xray:PutTelemetryRecords",
        "xray:PutTraceSegments",
      ]
      Resource = "*"
    }]
  })
}

resource "aws_iam_role_policy" "runtime_connect" {
  count = length(var.amazon_connect_instance_arns) == 0 ? 0 : 1
  role  = aws_iam_role.runtime.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "connect:DescribeContact",
        "connect:StartWebRTCContact",
        "connect:StopContact",
      ]
      Resource = flatten([
        for arn in var.amazon_connect_instance_arns : [arn, "${arn}/contact/*"]
      ])
    }]
  })
}

resource "aws_iam_role_policy" "runtime_extra" {
  count  = var.runtime_policy_json == null ? 0 : 1
  name   = "${var.name}-runtime-extra"
  role   = aws_iam_role.runtime.id
  policy = var.runtime_policy_json
}

resource "aws_iam_role_policy_attachment" "runtime_managed" {
  for_each   = toset(var.runtime_managed_policy_arns)
  role       = aws_iam_role.runtime.name
  policy_arn = each.value
}

resource "aws_ecs_task_definition" "role" {
  for_each                 = local.role_resources
  family                   = "${var.name}-${each.key}"
  requires_compatibilities = ["EC2"]
  network_mode             = "host"
  cpu                      = each.value.cpu
  memory                   = each.value.memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.runtime.arn

  volume {
    name      = "config"
    host_path = local.role_config_paths[each.key]
  }

  volume {
    name      = "otel-config"
    host_path = var.otel_config_host_path
  }

  container_definitions = jsonencode([
    {
      name                   = "bridgefu"
      image                  = var.image
      essential              = true
      user                   = "65532:65532"
      readonlyRootFilesystem = true
      command                = ["--config", "/etc/bridgefu/bridgefu.yaml", "run"]
      stopTimeout            = var.drain_timeout_seconds
      linuxParameters = {
        initProcessEnabled = true
        capabilities       = { drop = ["ALL"] }
      }
      mountPoints = [{ sourceVolume = "config", containerPath = "/etc/bridgefu", readOnly = true }]
      environment = concat(local.common_environment, [
        { name = "BRIDGEFU_DEPLOYMENT_ROLE", value = each.key == "moqrelay" ? "moq-relay" : each.key },
        { name = "OTEL_SERVICE_NAME", value = "bridgefu-${each.key}" },
      ])
      secrets      = [for name, arn in var.secret_arns : { name = name, valueFrom = arn }]
      portMappings = each.value.ports
      healthCheck = {
        command     = ["CMD", "/usr/local/bin/bridgefu", "healthcheck", "--address", "127.0.0.1:${var.operations_port}", "--path", "/readyz", "--timeout-ms", "5000"]
        interval    = 15
        timeout     = 5
        retries     = 3
        startPeriod = 30
      }
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.bridgefu[each.key].name
          "awslogs-region"        = data.aws_region.current.region
          "awslogs-stream-prefix" = "bridgefu"
        }
      }
    },
    {
      name                   = "otel-collector"
      image                  = var.otel_collector_image
      essential              = true
      user                   = "65532:65532"
      readonlyRootFilesystem = true
      command                = ["--config=/etc/otel/config.yaml"]
      stopTimeout            = 30
      linuxParameters = {
        initProcessEnabled = true
        capabilities       = { drop = ["ALL"] }
      }
      mountPoints = [{ sourceVolume = "otel-config", containerPath = "/etc/otel", readOnly = true }]
      portMappings = [
        { containerPort = 4317, hostPort = 4317, protocol = "tcp" },
        { containerPort = 4318, hostPort = 4318, protocol = "tcp" },
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.bridgefu[each.key].name
          "awslogs-region"        = data.aws_region.current.region
          "awslogs-stream-prefix" = "otel"
        }
      }
    },
  ])
}

resource "aws_ecs_service" "role" {
  for_each                           = local.role_resources
  name                               = "${var.name}-${each.key}"
  cluster                            = aws_ecs_cluster.this.id
  task_definition                    = aws_ecs_task_definition.role[each.key].arn
  desired_count                      = each.value.desired
  deployment_minimum_healthy_percent = 50
  deployment_maximum_percent         = 200
  health_check_grace_period_seconds  = length(local.role_load_balancers[each.key]) == 0 ? null : 30

  capacity_provider_strategy {
    capacity_provider = local.role_capacity_providers[each.key]
    weight            = 1
  }

  ordered_placement_strategy {
    type  = "spread"
    field = "attribute:ecs.availability-zone"
  }

  placement_constraints {
    type = "distinctInstance"
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  dynamic "load_balancer" {
    for_each = local.role_load_balancers[each.key]
    content {
      target_group_arn = load_balancer.value.target_group_arn
      container_name   = "bridgefu"
      container_port   = load_balancer.value.container_port
    }
  }

  lifecycle {
    ignore_changes = [desired_count]
  }

  depends_on = [
    aws_ecs_cluster_capacity_providers.this,
    aws_db_instance.postgres,
    aws_elasticache_replication_group.redis,
  ]
}

resource "aws_appautoscaling_target" "role" {
  for_each           = local.role_resources
  max_capacity       = each.value.max
  min_capacity       = each.value.min
  resource_id        = "service/${aws_ecs_cluster.this.name}/${aws_ecs_service.role[each.key].name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "role_cpu" {
  for_each           = local.role_resources
  name               = "${var.name}-${each.key}-cpu"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.role[each.key].resource_id
  scalable_dimension = aws_appautoscaling_target.role[each.key].scalable_dimension
  service_namespace  = aws_appautoscaling_target.role[each.key].service_namespace

  target_tracking_scaling_policy_configuration {
    target_value = var.autoscaling_cpu_target
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    scale_in_cooldown  = var.scale_in_cooldown_seconds
    scale_out_cooldown = var.scale_out_cooldown_seconds
  }
}

resource "aws_db_subnet_group" "this" {
  name       = var.name
  subnet_ids = var.private_subnet_ids
}

resource "aws_db_parameter_group" "postgres" {
  name   = "${var.name}-postgres17"
  family = "postgres17"
  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }
}

resource "aws_db_instance" "postgres" {
  identifier                          = var.name
  engine                              = "postgres"
  engine_version                      = var.postgres_engine_version
  instance_class                      = var.postgres_instance_class
  allocated_storage                   = var.postgres_allocated_storage_gib
  max_allocated_storage               = var.postgres_max_allocated_storage_gib
  storage_encrypted                   = true
  kms_key_id                          = var.data_kms_key_arn
  db_name                             = var.database_name
  username                            = var.database_username
  manage_master_user_password         = true
  master_user_secret_kms_key_id       = var.data_kms_key_arn
  db_subnet_group_name                = aws_db_subnet_group.this.name
  parameter_group_name                = aws_db_parameter_group.postgres.name
  vpc_security_group_ids              = [aws_security_group.data.id]
  backup_retention_period             = var.database_backup_retention_days
  multi_az                            = true
  auto_minor_version_upgrade          = true
  performance_insights_enabled        = true
  performance_insights_kms_key_id     = var.data_kms_key_arn
  monitoring_interval                 = 0
  deletion_protection                 = var.database_deletion_protection
  skip_final_snapshot                 = var.skip_final_snapshot
  final_snapshot_identifier           = var.skip_final_snapshot ? null : "${var.name}-final"
  copy_tags_to_snapshot               = true
  iam_database_authentication_enabled = true
}

resource "aws_elasticache_subnet_group" "this" {
  name       = var.name
  subnet_ids = var.private_subnet_ids
}

resource "aws_elasticache_replication_group" "redis" {
  replication_group_id       = var.name
  description                = "Bridgefu clustered coordination"
  node_type                  = var.redis_node_type
  port                       = 6379
  subnet_group_name          = aws_elasticache_subnet_group.this.name
  automatic_failover_enabled = true
  multi_az_enabled           = true
  num_cache_clusters         = var.redis_cluster_nodes
  engine                     = "redis"
  engine_version             = var.redis_engine_version
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  security_group_ids         = [aws_security_group.data.id]
  user_group_ids             = var.redis_user_group_ids
  kms_key_id                 = var.data_kms_key_arn
  snapshot_retention_limit   = var.redis_snapshot_retention_days
  apply_immediately          = false

  log_delivery_configuration {
    destination      = aws_cloudwatch_log_group.redis_slow.name
    destination_type = "cloudwatch-logs"
    log_format       = "json"
    log_type         = "slow-log"
  }
  log_delivery_configuration {
    destination      = aws_cloudwatch_log_group.redis_engine.name
    destination_type = "cloudwatch-logs"
    log_format       = "json"
    log_type         = "engine-log"
  }
}

output "cluster_name" { value = aws_ecs_cluster.this.name }
output "gateway_api_endpoint" { value = aws_lb.gateway_api.dns_name }
output "gateway_sip_webrtc_endpoint" { value = aws_lb.gateway_api.dns_name }
output "gateway_media_eip_associations" {
  value = {
    for key, association in aws_eip_association.gateway_media : key => association.public_ip
  }
}
output "gateway_operational_endpoint" {
  description = "Deprecated compatibility alias for gateway_api_endpoint."
  value       = aws_lb.gateway_api.dns_name
}
output "quic_endpoint" { value = aws_lb.quic.dns_name }
output "postgres_endpoint" { value = aws_db_instance.postgres.address }
output "redis_endpoint" { value = aws_elasticache_replication_group.redis.primary_endpoint_address }
output "runtime_role_arn" { value = aws_iam_role.runtime.arn }
output "role_security_group_ids" {
  value = {
    gateway  = aws_security_group.gateway.id
    worker   = aws_security_group.worker.id
    moqrelay = aws_security_group.moq_relay.id
  }
}
output "database_master_secret_arn" {
  value     = try(aws_db_instance.postgres.master_user_secret[0].secret_arn, null)
  sensitive = true
}
