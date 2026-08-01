provider "google" {
  project = var.project_id
  region  = var.region
}

data "google_client_config" "current" {}

locals {
  required_services = toset([
    "artifactregistry.googleapis.com",
    "cloudtrace.googleapis.com",
    "compute.googleapis.com",
    "container.googleapis.com",
    "iam.googleapis.com",
    "logging.googleapis.com",
    "monitoring.googleapis.com",
    "redis.googleapis.com",
    "secretmanager.googleapis.com",
    "servicenetworking.googleapis.com",
    "sqladmin.googleapis.com",
  ])

  workload_roles = toset([
    "roles/cloudsql.client",
    "roles/cloudsql.instanceUser",
    "roles/cloudtrace.agent",
    "roles/logging.logWriter",
    "roles/monitoring.metricWriter",
  ])

  node_roles = toset([
    "roles/artifactregistry.reader",
    "roles/logging.logWriter",
    "roles/monitoring.metricWriter",
    "roles/monitoring.viewer",
    "roles/stackdriver.resourceMetadata.writer",
  ])

  external_secret_versions = concat(
    values(var.gateway_secret_versions),
    values(var.worker_secret_versions),
    values(var.moq_relay_secret_versions),
    values(var.otel_secret_versions),
  )
  external_secret_ids = toset([
    for resource in local.external_secret_versions : join("/", slice(split("/", resource), 0, 4))
  ])

  database_iam_user = trimsuffix(google_service_account.bridgefu.email, ".gserviceaccount.com")
  database_url      = "postgresql://${urlencode(local.database_iam_user)}@127.0.0.1:5432/${var.database_name}?sslmode=disable"
}

check "external_secrets_are_project_local" {
  assert {
    condition = alltrue([
      for resource in local.external_secret_versions : startswith(resource, "projects/${var.project_id}/secrets/")
    ])
    error_message = "all workload Secret Manager versions must belong to project_id so IAM bindings are unambiguous."
  }
}

check "worker_capacity_is_preprovisioned" {
  assert {
    condition = (
      var.worker_min_replicas >= 1 &&
      var.worker_max_replicas >= var.worker_min_replicas &&
      var.worker_pool_max_nodes >= var.worker_pool_min_nodes
    )
    error_message = "worker replica and pool maxima must be greater than or equal to their positive minima."
  }
}

check "media_port_range" {
  assert {
    condition     = var.rtp_port_start >= 1024 && var.rtp_port_end >= var.rtp_port_start && var.rtp_port_end <= 65535
    error_message = "RTP ports must be an ordered range between 1024 and 65535."
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

resource "google_project_service" "required" {
  for_each           = local.required_services
  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

data "google_compute_network" "this" {
  name       = var.network_name
  depends_on = [google_project_service.required]
}

resource "google_compute_global_address" "private_services" {
  name          = "${var.name}-private-services"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = var.private_service_prefix_length
  network       = data.google_compute_network.this.id
}

resource "google_service_networking_connection" "private_services" {
  network                 = data.google_compute_network.this.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_services.name]
}

resource "google_service_account" "bridgefu" {
  account_id   = substr("${var.name}-runtime", 0, 30)
  display_name = "Bridgefu runtime and telemetry"
}

resource "google_service_account" "nodes" {
  account_id   = substr("${var.name}-nodes", 0, 30)
  display_name = "Bridgefu GKE nodes"
}

resource "google_project_iam_member" "nodes" {
  for_each = local.node_roles
  project  = var.project_id
  role     = each.value
  member   = "serviceAccount:${google_service_account.nodes.email}"
}

resource "google_project_iam_member" "workload" {
  for_each = local.workload_roles
  project  = var.project_id
  role     = each.value
  member   = "serviceAccount:${google_service_account.bridgefu.email}"
}

resource "google_container_cluster" "this" {
  name                     = var.name
  location                 = var.region
  network                  = data.google_compute_network.this.id
  remove_default_node_pool = true
  initial_node_count       = 1
  deletion_protection      = var.deletion_protection
  enable_shielded_nodes    = true
  datapath_provider        = "ADVANCED_DATAPATH"

  release_channel {
    channel = var.gke_release_channel
  }
  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }
  secret_manager_config {
    enabled = true
  }
  ip_allocation_policy {}
  logging_config {
    enable_components = ["SYSTEM_COMPONENTS", "WORKLOADS"]
  }
  monitoring_config {
    enable_components = [
      "SYSTEM_COMPONENTS",
      "APISERVER",
      "SCHEDULER",
      "CONTROLLER_MANAGER",
      "STORAGE",
      "HPA",
      "POD",
      "DAEMONSET",
      "DEPLOYMENT",
      "STATEFULSET",
    ]
    managed_prometheus {
      enabled = true
    }
  }

  maintenance_policy {
    recurring_window {
      start_time = var.maintenance_start_time
      end_time   = var.maintenance_end_time
      recurrence = var.maintenance_recurrence
    }
  }

  depends_on = [google_project_service.required]
}

resource "google_container_node_pool" "system" {
  name               = "system"
  location           = var.region
  cluster            = google_container_cluster.this.name
  initial_node_count = var.system_pool_min_nodes

  autoscaling {
    min_node_count  = var.system_pool_min_nodes
    max_node_count  = var.system_pool_max_nodes
    location_policy = "BALANCED"
  }
  management {
    auto_repair  = true
    auto_upgrade = true
  }
  node_config {
    machine_type    = var.system_machine_type
    service_account = google_service_account.nodes.email
    labels          = { "bridgefu-role" = "system" }
    tags            = ["${var.name}-system"]
    oauth_scopes    = ["https://www.googleapis.com/auth/cloud-platform"]
    workload_metadata_config { mode = "GKE_METADATA" }
    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }
  }
}

resource "google_container_node_pool" "gateway" {
  name               = "gateway-media"
  location           = var.region
  cluster            = google_container_cluster.this.name
  initial_node_count = var.gateway_pool_min_nodes

  autoscaling {
    min_node_count  = var.gateway_pool_min_nodes
    max_node_count  = var.gateway_pool_max_nodes
    location_policy = "BALANCED"
  }
  management {
    auto_repair  = true
    auto_upgrade = true
  }
  node_config {
    machine_type    = var.gateway_machine_type
    service_account = google_service_account.nodes.email
    labels          = { "bridgefu-role" = "gateway" }
    tags            = ["${var.name}-gateway"]
    oauth_scopes    = ["https://www.googleapis.com/auth/cloud-platform"]
    taint {
      key    = "bridgefu-role"
      value  = "gateway"
      effect = "NO_SCHEDULE"
    }
    workload_metadata_config { mode = "GKE_METADATA" }
    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }
  }
}

resource "google_container_node_pool" "worker" {
  name               = "worker-media"
  location           = var.region
  cluster            = google_container_cluster.this.name
  initial_node_count = var.worker_pool_min_nodes

  autoscaling {
    min_node_count  = var.worker_pool_min_nodes
    max_node_count  = var.worker_pool_max_nodes
    location_policy = "BALANCED"
  }
  management {
    auto_repair  = true
    auto_upgrade = true
  }
  node_config {
    machine_type    = var.worker_machine_type
    service_account = google_service_account.nodes.email
    labels          = { "bridgefu-role" = "worker" }
    tags            = ["${var.name}-worker"]
    oauth_scopes    = ["https://www.googleapis.com/auth/cloud-platform"]
    taint {
      key    = "bridgefu-role"
      value  = "worker"
      effect = "NO_SCHEDULE"
    }
    workload_metadata_config { mode = "GKE_METADATA" }
    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }
  }
}

resource "google_container_node_pool" "moq_relay" {
  name               = "moq-relay"
  location           = var.region
  cluster            = google_container_cluster.this.name
  initial_node_count = var.moq_relay_pool_min_nodes

  autoscaling {
    min_node_count  = var.moq_relay_pool_min_nodes
    max_node_count  = var.moq_relay_pool_max_nodes
    location_policy = "BALANCED"
  }
  management {
    auto_repair  = true
    auto_upgrade = true
  }
  node_config {
    machine_type    = var.moq_relay_machine_type
    service_account = google_service_account.nodes.email
    labels          = { "bridgefu-role" = "moq-relay" }
    tags            = ["${var.name}-moq-relay"]
    oauth_scopes    = ["https://www.googleapis.com/auth/cloud-platform"]
    taint {
      key    = "bridgefu-role"
      value  = "moq-relay"
      effect = "NO_SCHEDULE"
    }
    workload_metadata_config { mode = "GKE_METADATA" }
    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }
  }
}

resource "google_sql_database_instance" "postgres" {
  name                = var.name
  region              = var.region
  database_version    = var.postgres_version
  deletion_protection = var.deletion_protection

  settings {
    tier              = var.postgres_tier
    availability_type = "REGIONAL"
    disk_autoresize   = true
    disk_size         = var.postgres_disk_size_gib
    disk_type         = "PD_SSD"

    database_flags {
      name  = "cloudsql.iam_authentication"
      value = "on"
    }
    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
      transaction_log_retention_days = var.postgres_log_retention_days
    }
    ip_configuration {
      ipv4_enabled    = false
      private_network = data.google_compute_network.this.id
      ssl_mode        = "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"
    }
    insights_config {
      query_insights_enabled  = true
      record_application_tags = true
      record_client_address   = false
    }
  }
  depends_on = [google_service_networking_connection.private_services]
}

resource "google_sql_database" "bridgefu" {
  name     = var.database_name
  instance = google_sql_database_instance.postgres.name
}

resource "google_sql_user" "bridgefu_iam" {
  name     = local.database_iam_user
  instance = google_sql_database_instance.postgres.name
  type     = "CLOUD_IAM_SERVICE_ACCOUNT"
}

resource "google_redis_instance" "redis" {
  name                    = var.name
  region                  = var.region
  tier                    = "STANDARD_HA"
  memory_size_gb          = var.redis_memory_size_gib
  redis_version           = var.redis_version
  authorized_network      = data.google_compute_network.this.id
  transit_encryption_mode = "SERVER_AUTHENTICATION"
  auth_enabled            = true
  read_replicas_mode      = "READ_REPLICAS_ENABLED"
  replica_count           = var.redis_replica_count
  connect_mode            = "PRIVATE_SERVICE_ACCESS"
  depends_on = [
    google_project_service.required,
    google_service_networking_connection.private_services,
  ]
}

resource "google_secret_manager_secret" "redis_url" {
  secret_id = "${var.name}-redis-url"
  replication {
    auto {}
  }
  depends_on = [google_project_service.required]
}

resource "google_secret_manager_secret_version" "redis_url" {
  secret                 = google_secret_manager_secret.redis_url.id
  secret_data_wo         = "rediss://:${urlencode(google_redis_instance.redis.auth_string)}@${google_redis_instance.redis.host}:${google_redis_instance.redis.port}"
  secret_data_wo_version = var.redis_secret_generation
  deletion_policy        = "DISABLE"
}

resource "google_secret_manager_secret" "redis_ca" {
  secret_id = "${var.name}-redis-ca"
  replication {
    auto {}
  }
  depends_on = [google_project_service.required]
}

resource "google_secret_manager_secret_version" "redis_ca" {
  secret                 = google_secret_manager_secret.redis_ca.id
  secret_data_wo         = google_redis_instance.redis.server_ca_certs[0].cert
  secret_data_wo_version = var.redis_secret_generation
  deletion_policy        = "DISABLE"
}

resource "google_secret_manager_secret_iam_member" "external" {
  for_each  = local.external_secret_ids
  project   = var.project_id
  secret_id = each.value
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.bridgefu.email}"
}

resource "google_secret_manager_secret_iam_member" "redis_url" {
  project   = var.project_id
  secret_id = google_secret_manager_secret.redis_url.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.bridgefu.email}"
}

resource "google_secret_manager_secret_iam_member" "redis_ca" {
  project   = var.project_id
  secret_id = google_secret_manager_secret.redis_ca.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.bridgefu.email}"
}

output "cluster" { value = google_container_cluster.this.name }
output "cluster_location" { value = google_container_cluster.this.location }
output "postgres" { value = google_sql_database_instance.postgres.connection_name }
output "redis" { value = google_redis_instance.redis.host }
output "redis_url_secret" { value = google_secret_manager_secret.redis_url.id }
output "redis_ca_secret" { value = google_secret_manager_secret.redis_ca.id }
output "runtime_service_account" { value = google_service_account.bridgefu.email }
