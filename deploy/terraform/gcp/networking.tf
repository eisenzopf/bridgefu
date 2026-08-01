resource "google_compute_address" "gateway_quic" {
  name         = "${var.name}-gateway-quic"
  region       = var.region
  address_type = "EXTERNAL"
  network_tier = "PREMIUM"
}

resource "google_compute_address" "moq_relay" {
  name         = "${var.name}-moq-relay"
  region       = var.region
  address_type = "EXTERNAL"
  network_tier = "PREMIUM"
}

resource "google_compute_region_health_check" "gateway" {
  name               = "${var.name}-gateway"
  region             = var.region
  timeout_sec        = 2
  check_interval_sec = 5

  http_health_check {
    port         = var.operations_port
    request_path = "/readyz"
  }
}

resource "google_compute_region_health_check" "moq_relay" {
  name               = "${var.name}-moq-relay"
  region             = var.region
  timeout_sec        = 2
  check_interval_sec = 5

  http_health_check {
    port         = var.operations_port
    request_path = "/readyz"
  }
}

resource "google_compute_region_backend_service" "gateway_quic" {
  name                  = "${var.name}-gateway-quic"
  region                = var.region
  protocol              = "UDP"
  load_balancing_scheme = "EXTERNAL"
  health_checks         = [google_compute_region_health_check.gateway.id]
  session_affinity      = "CLIENT_IP"

  dynamic "backend" {
    for_each = toset(google_container_node_pool.gateway.managed_instance_group_urls)
    content {
      group = backend.value
    }
  }
}

resource "google_compute_region_backend_service" "gateway_api" {
  name                  = "${var.name}-gateway-api"
  region                = var.region
  protocol              = "TCP"
  load_balancing_scheme = "EXTERNAL"
  health_checks         = [google_compute_region_health_check.gateway.id]
  session_affinity      = "CLIENT_IP"

  dynamic "backend" {
    for_each = toset(google_container_node_pool.gateway.managed_instance_group_urls)
    content {
      group = backend.value
    }
  }
}

resource "google_compute_region_backend_service" "moq_relay" {
  name                  = "${var.name}-moq-relay"
  region                = var.region
  protocol              = "UDP"
  load_balancing_scheme = "EXTERNAL"
  health_checks         = [google_compute_region_health_check.moq_relay.id]
  session_affinity      = "CLIENT_IP"

  dynamic "backend" {
    for_each = toset(google_container_node_pool.moq_relay.managed_instance_group_urls)
    content {
      group = backend.value
    }
  }
}

# One UDP passthrough rule preserves source addresses and covers public UCTP,
# SIP signaling, the bounded RTP range, and the fixed WebRTC ICE/DTLS mux
# port. Firewall rules below keep unrelated UDP ports closed. A separate TCP
# rule carries HTTPS API plus WSS and WHIP/WHEP over HTTPS.
resource "google_compute_forwarding_rule" "gateway_quic" {
  name                  = "${var.name}-gateway-quic"
  region                = var.region
  load_balancing_scheme = "EXTERNAL"
  backend_service       = google_compute_region_backend_service.gateway_quic.id
  ip_address            = google_compute_address.gateway_quic.id
  ip_protocol           = "UDP"
  all_ports             = true
  network_tier          = "PREMIUM"
}

resource "google_compute_forwarding_rule" "gateway_api" {
  name                  = "${var.name}-gateway-api"
  region                = var.region
  load_balancing_scheme = "EXTERNAL"
  backend_service       = google_compute_region_backend_service.gateway_api.id
  ip_address            = google_compute_address.gateway_quic.id
  ip_protocol           = "TCP"
  ports = [
    tostring(var.api_port),
    tostring(var.webrtc_ws_port),
    tostring(var.webrtc_whip_port),
  ]
  network_tier = "PREMIUM"
}

resource "google_compute_forwarding_rule" "moq_relay" {
  name                  = "${var.name}-moq-relay"
  region                = var.region
  load_balancing_scheme = "EXTERNAL"
  backend_service       = google_compute_region_backend_service.moq_relay.id
  ip_address            = google_compute_address.moq_relay.id
  ip_protocol           = "UDP"
  ports = [
    tostring(var.moq_publisher_port),
    tostring(var.moq_webtransport_port),
    tostring(var.moq_raw_quic_port),
  ]
  network_tier = "PREMIUM"
}

resource "google_compute_firewall" "gateway_api" {
  name          = "${var.name}-gateway-api"
  network       = data.google_compute_network.this.name
  source_ranges = var.api_cidrs
  target_tags   = ["${var.name}-gateway"]
  allow {
    protocol = "tcp"
    ports    = [tostring(var.api_port)]
  }
}

resource "google_compute_firewall" "gateway_quic" {
  name          = "${var.name}-gateway-quic"
  network       = data.google_compute_network.this.name
  source_ranges = var.quic_cidrs
  target_tags   = ["${var.name}-gateway"]
  allow {
    protocol = "udp"
    ports    = [tostring(var.gateway_quic_port)]
  }
}

resource "google_compute_firewall" "gateway_sip" {
  name          = "${var.name}-gateway-sip"
  network       = data.google_compute_network.this.name
  source_ranges = var.signaling_cidrs
  target_tags   = ["${var.name}-gateway"]
  allow {
    protocol = "udp"
    ports    = [tostring(var.sip_port)]
  }
}

resource "google_compute_firewall" "gateway_rtp" {
  name          = "${var.name}-gateway-rtp"
  network       = data.google_compute_network.this.name
  source_ranges = var.media_cidrs
  target_tags   = ["${var.name}-gateway"]
  allow {
    protocol = "udp"
    ports    = ["${var.rtp_port_start}-${var.rtp_port_end}"]
  }
}

resource "google_compute_firewall" "gateway_webrtc_signaling" {
  name          = "${var.name}-gateway-webrtc-signaling"
  network       = data.google_compute_network.this.name
  source_ranges = var.webrtc_cidrs
  target_tags   = ["${var.name}-gateway"]
  allow {
    protocol = "tcp"
    ports = [
      tostring(var.webrtc_ws_port),
      tostring(var.webrtc_whip_port),
    ]
  }
}

resource "google_compute_firewall" "gateway_webrtc_media" {
  name          = "${var.name}-gateway-webrtc-media"
  network       = data.google_compute_network.this.name
  source_ranges = var.webrtc_cidrs
  target_tags   = ["${var.name}-gateway"]
  allow {
    protocol = "udp"
    ports    = [tostring(var.webrtc_media_port)]
  }
}

resource "google_compute_firewall" "moq_relay" {
  name          = "${var.name}-moq-relay"
  network       = data.google_compute_network.this.name
  source_ranges = var.quic_cidrs
  target_tags   = ["${var.name}-moq-relay"]
  allow {
    protocol = "udp"
    ports = [
      tostring(var.moq_publisher_port),
      tostring(var.moq_webtransport_port),
      tostring(var.moq_raw_quic_port),
    ]
  }
}

resource "google_compute_firewall" "health_checks" {
  name          = "${var.name}-health-checks"
  network       = data.google_compute_network.this.name
  source_ranges = ["35.191.0.0/16", "130.211.0.0/22"]
  target_tags   = ["${var.name}-gateway", "${var.name}-moq-relay"]
  allow {
    protocol = "tcp"
    ports    = [tostring(var.operations_port)]
  }
}

resource "google_compute_firewall" "private_forwarding" {
  name        = "${var.name}-private-forwarding"
  network     = data.google_compute_network.this.name
  source_tags = ["${var.name}-gateway"]
  target_tags = ["${var.name}-worker"]
  allow {
    protocol = "udp"
    ports    = [tostring(var.private_forwarding_port)]
  }
}

output "gateway_quic_address" { value = google_compute_address.gateway_quic.address }
output "moq_relay_address" { value = google_compute_address.moq_relay.address }
