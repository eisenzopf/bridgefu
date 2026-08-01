resource "aws_security_group" "gateway_api_nlb" {
  name        = "${var.name}-api-nlb"
  description = "Restricted gateway SIP, WSS, WHIPS, call-control, and webhook listeners; QUIC is separate"
  vpc_id      = var.vpc_id

  ingress {
    protocol    = "tcp"
    from_port   = var.api_port
    to_port     = var.api_port
    cidr_blocks = var.api_cidrs
  }
  ingress {
    protocol    = "udp"
    from_port   = var.sip_port
    to_port     = var.sip_port
    cidr_blocks = var.signaling_cidrs
  }
  ingress {
    protocol    = "tcp"
    from_port   = var.webrtc_ws_port
    to_port     = var.webrtc_ws_port
    cidr_blocks = var.webrtc_cidrs
  }
  ingress {
    protocol    = "tcp"
    from_port   = var.webrtc_whip_port
    to_port     = var.webrtc_whip_port
    cidr_blocks = var.webrtc_cidrs
  }
  egress {
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "quic_nlb" {
  name        = "${var.name}-quic-nlb"
  description = "Dedicated QUIC NLB; AWS forbids mixing QUIC and UDP listeners"
  vpc_id      = var.vpc_id

  dynamic "ingress" {
    for_each = toset(concat([var.gateway_quic_port], var.moq_relay_ports))
    content {
      protocol    = "udp"
      from_port   = ingress.value
      to_port     = ingress.value
      cidr_blocks = var.quic_cidrs
    }
  }
  egress {
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "gateway" {
  name        = "${var.name}-gateway"
  description = "Bridgefu authenticated SIP, WebRTC, HTTPS, and public UCTP gateways"
  vpc_id      = var.vpc_id

  dynamic "ingress" {
    for_each = [
      { protocol = "tcp", from = var.api_port, to = var.api_port, source = aws_security_group.gateway_api_nlb.id },
      { protocol = "udp", from = var.sip_port, to = var.sip_port, source = aws_security_group.gateway_api_nlb.id },
      { protocol = "tcp", from = var.webrtc_ws_port, to = var.webrtc_ws_port, source = aws_security_group.gateway_api_nlb.id },
      { protocol = "tcp", from = var.webrtc_whip_port, to = var.webrtc_whip_port, source = aws_security_group.gateway_api_nlb.id },
      { protocol = "udp", from = var.gateway_quic_port, to = var.gateway_quic_port, source = aws_security_group.quic_nlb.id },
      { protocol = "tcp", from = var.operations_port, to = var.operations_port, source = aws_security_group.gateway_api_nlb.id },
      { protocol = "tcp", from = var.operations_port, to = var.operations_port, source = aws_security_group.quic_nlb.id },
    ]
    content {
      protocol        = ingress.value.protocol
      from_port       = ingress.value.from
      to_port         = ingress.value.to
      security_groups = [ingress.value.source]
    }
  }
  ingress {
    protocol    = "udp"
    from_port   = var.rtp_port_start
    to_port     = var.rtp_port_end
    cidr_blocks = var.media_cidrs
  }
  ingress {
    protocol    = "udp"
    from_port   = var.webrtc_media_port
    to_port     = var.webrtc_media_port
    cidr_blocks = var.webrtc_cidrs
  }
  ingress {
    protocol    = "tcp"
    from_port   = var.operations_port
    to_port     = var.operations_port
    cidr_blocks = var.operator_cidrs
  }
  egress {
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_eip_association" "gateway_media" {
  for_each = var.gateway_media_eip_allocation_ids

  allocation_id = each.value
  instance_id   = var.gateway_instance_ids[each.key]
}

resource "aws_security_group" "worker" {
  name        = "${var.name}-worker"
  description = "Private call workers"
  vpc_id      = var.vpc_id

  ingress {
    protocol        = "udp"
    from_port       = var.private_forwarding_port
    to_port         = var.private_forwarding_port
    security_groups = [aws_security_group.gateway.id]
  }
  ingress {
    protocol    = "tcp"
    from_port   = var.operations_port
    to_port     = var.operations_port
    cidr_blocks = var.operator_cidrs
  }
  egress {
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "moq_relay" {
  name        = "${var.name}-moq-relay"
  description = "MOQT relay tier"
  vpc_id      = var.vpc_id

  dynamic "ingress" {
    for_each = toset(var.moq_relay_ports)
    content {
      protocol        = "udp"
      from_port       = ingress.value
      to_port         = ingress.value
      security_groups = [aws_security_group.quic_nlb.id]
    }
  }
  ingress {
    protocol    = "tcp"
    from_port   = var.operations_port
    to_port     = var.operations_port
    cidr_blocks = var.operator_cidrs
  }
  ingress {
    protocol        = "tcp"
    from_port       = var.operations_port
    to_port         = var.operations_port
    security_groups = [aws_security_group.quic_nlb.id]
  }
  egress {
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "data" {
  name        = "${var.name}-data"
  description = "PostgreSQL and Redis from Bridgefu roles only"
  vpc_id      = var.vpc_id

  ingress {
    protocol  = "tcp"
    from_port = 5432
    to_port   = 5432
    security_groups = [
      aws_security_group.gateway.id,
      aws_security_group.worker.id,
    ]
  }
  ingress {
    protocol  = "tcp"
    from_port = 6379
    to_port   = 6379
    security_groups = [
      aws_security_group.gateway.id,
      aws_security_group.worker.id,
    ]
  }
  egress {
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_lb" "gateway_api" {
  name                             = substr("${var.name}-api-edge", 0, 32)
  internal                         = false
  load_balancer_type               = "network"
  security_groups                  = [aws_security_group.gateway_api_nlb.id]
  enable_cross_zone_load_balancing = true

  dynamic "subnet_mapping" {
    for_each = var.public_subnet_ids
    content {
      subnet_id = subnet_mapping.value
      # Keep the legacy variable name source-compatible. These stable NLB
      # addresses serve SIP, WSS/WHIPS, and the HTTPS API.
      allocation_id = lookup(var.sip_nlb_eip_allocation_ids, subnet_mapping.value, null)
    }
  }
}

resource "aws_lb" "quic" {
  name                             = substr("${var.name}-quic-edge", 0, 32)
  internal                         = false
  load_balancer_type               = "network"
  security_groups                  = [aws_security_group.quic_nlb.id]
  enable_cross_zone_load_balancing = true

  dynamic "subnet_mapping" {
    for_each = var.public_subnet_ids
    content {
      subnet_id     = subnet_mapping.value
      allocation_id = lookup(var.quic_nlb_eip_allocation_ids, subnet_mapping.value, null)
    }
  }
}

resource "aws_lb_target_group" "gateway_api" {
  name                 = substr("${var.name}-api", 0, 32)
  port                 = var.api_port
  protocol             = "TCP"
  vpc_id               = var.vpc_id
  target_type          = "instance"
  deregistration_delay = var.target_deregistration_delay_seconds
  health_check {
    protocol = "HTTP"
    port     = tostring(var.operations_port)
    path     = "/readyz"
  }
}

resource "aws_lb_target_group" "gateway_sip" {
  name                 = substr("${var.name}-gateway-sip", 0, 32)
  port                 = var.sip_port
  protocol             = "UDP"
  vpc_id               = var.vpc_id
  target_type          = "instance"
  deregistration_delay = var.target_deregistration_delay_seconds
  health_check {
    protocol = "HTTP"
    port     = tostring(var.operations_port)
    path     = "/readyz"
  }
}

resource "aws_lb_target_group" "gateway_webrtc_ws" {
  name                 = substr("${var.name}-gateway-wss", 0, 32)
  port                 = var.webrtc_ws_port
  protocol             = "TCP"
  vpc_id               = var.vpc_id
  target_type          = "instance"
  deregistration_delay = var.target_deregistration_delay_seconds
  stickiness {
    enabled = true
    type    = "source_ip"
  }
  health_check {
    protocol = "HTTP"
    port     = tostring(var.operations_port)
    path     = "/readyz"
  }
}

resource "aws_lb_target_group" "gateway_webrtc_whip" {
  name                 = substr("${var.name}-gateway-whips", 0, 32)
  port                 = var.webrtc_whip_port
  protocol             = "TCP"
  vpc_id               = var.vpc_id
  target_type          = "instance"
  deregistration_delay = var.target_deregistration_delay_seconds
  stickiness {
    enabled = true
    type    = "source_ip"
  }
  health_check {
    protocol = "HTTP"
    port     = tostring(var.operations_port)
    path     = "/readyz"
  }
}

resource "aws_lb_target_group" "gateway_quic" {
  name                 = substr("${var.name}-gateway-quic", 0, 32)
  port                 = var.gateway_quic_port
  protocol             = "QUIC"
  vpc_id               = var.vpc_id
  target_type          = "instance"
  deregistration_delay = var.target_deregistration_delay_seconds
  health_check {
    protocol = "HTTP"
    port     = tostring(var.operations_port)
    path     = "/readyz"
  }
}

resource "aws_lb_target_group" "moq_publisher" {
  name                 = substr("${var.name}-moq-publisher", 0, 32)
  port                 = var.moq_publisher_port
  protocol             = "QUIC"
  vpc_id               = var.vpc_id
  target_type          = "instance"
  deregistration_delay = var.target_deregistration_delay_seconds
  health_check {
    protocol = "HTTP"
    port     = tostring(var.operations_port)
    path     = "/readyz"
  }
}

resource "aws_lb_target_group" "moq_webtransport" {
  name                 = substr("${var.name}-moq-webtransport", 0, 32)
  port                 = var.moq_webtransport_port
  protocol             = "QUIC"
  vpc_id               = var.vpc_id
  target_type          = "instance"
  deregistration_delay = var.target_deregistration_delay_seconds
  health_check {
    protocol = "HTTP"
    port     = tostring(var.operations_port)
    path     = "/readyz"
  }
}

resource "aws_lb_target_group" "moq_raw_quic" {
  name                 = substr("${var.name}-moq-raw-quic", 0, 32)
  port                 = var.moq_raw_quic_port
  protocol             = "QUIC"
  vpc_id               = var.vpc_id
  target_type          = "instance"
  deregistration_delay = var.target_deregistration_delay_seconds
  health_check {
    protocol = "HTTP"
    port     = tostring(var.operations_port)
    path     = "/readyz"
  }
}

resource "aws_lb_listener" "gateway_api" {
  load_balancer_arn = aws_lb.gateway_api.arn
  port              = var.api_port
  protocol          = "TCP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.gateway_api.arn
  }
}

resource "aws_lb_listener" "gateway_sip" {
  load_balancer_arn = aws_lb.gateway_api.arn
  port              = var.sip_port
  protocol          = "UDP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.gateway_sip.arn
  }
}

resource "aws_lb_listener" "gateway_webrtc_ws" {
  load_balancer_arn = aws_lb.gateway_api.arn
  port              = var.webrtc_ws_port
  protocol          = "TCP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.gateway_webrtc_ws.arn
  }
}

resource "aws_lb_listener" "gateway_webrtc_whip" {
  load_balancer_arn = aws_lb.gateway_api.arn
  port              = var.webrtc_whip_port
  protocol          = "TCP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.gateway_webrtc_whip.arn
  }
}

resource "aws_lb_listener" "gateway_quic" {
  load_balancer_arn = aws_lb.quic.arn
  port              = var.gateway_quic_port
  protocol          = "QUIC"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.gateway_quic.arn
  }
}

resource "aws_lb_listener" "moq_publisher" {
  load_balancer_arn = aws_lb.quic.arn
  port              = var.moq_publisher_port
  protocol          = "QUIC"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.moq_publisher.arn
  }
}

resource "aws_lb_listener" "moq_webtransport" {
  load_balancer_arn = aws_lb.quic.arn
  port              = var.moq_webtransport_port
  protocol          = "QUIC"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.moq_webtransport.arn
  }
}

resource "aws_lb_listener" "moq_raw_quic" {
  load_balancer_arn = aws_lb.quic.arn
  port              = var.moq_raw_quic_port
  protocol          = "QUIC"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.moq_raw_quic.arn
  }
}
