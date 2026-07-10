variable "project_id" { type = string }
variable "region" {
  type    = string
  default = "us-central1"
}
variable "name" {
  type    = string
  default = "bridgefu"
}
variable "network" {
  type    = string
  default = "default"
}
variable "config_secret" {
  type      = string
  sensitive = true
}

provider "google" {
  project = var.project_id
  region  = var.region
}
resource "google_container_cluster" "this" {
  name                     = var.name
  location                 = var.region
  network                  = var.network
  remove_default_node_pool = true
  initial_node_count       = 1
  release_channel { channel = "REGULAR" }
  workload_identity_config { workload_pool = "${var.project_id}.svc.id.goog" }
  ip_allocation_policy {}
}
resource "google_container_node_pool" "media" {
  name       = "media"
  location   = var.region
  cluster    = google_container_cluster.this.name
  node_count = 2
  autoscaling {
    min_node_count = 2
    max_node_count = 20
  }
  node_config {
    machine_type = "c4-standard-8"
    labels       = { workload = "realtime-media" }
    taint {
      key    = "workload"
      value  = "realtime-media"
      effect = "NO_SCHEDULE"
    }
    oauth_scopes = ["https://www.googleapis.com/auth/cloud-platform"]
  }
}
resource "google_sql_database_instance" "postgres" {
  name             = var.name
  region           = var.region
  database_version = "POSTGRES_17"
  settings {
    tier              = "db-custom-2-7680"
    availability_type = "REGIONAL"
    disk_autoresize   = true
    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
    }
  }
  deletion_protection = true
}
resource "google_redis_instance" "redis" {
  name                    = var.name
  region                  = var.region
  tier                    = "STANDARD_HA"
  memory_size_gb          = 5
  redis_version           = "REDIS_7_2"
  authorized_network      = var.network
  transit_encryption_mode = "SERVER_AUTHENTICATION"
}
resource "google_secret_manager_secret" "config" {
  secret_id = "${var.name}-config"
  replication {
    auto {}
  }
}
resource "google_secret_manager_secret_version" "config" {
  secret      = google_secret_manager_secret.config.id
  secret_data = var.config_secret
}
output "cluster" { value = google_container_cluster.this.name }
output "postgres" { value = google_sql_database_instance.postgres.connection_name }
output "redis" { value = google_redis_instance.redis.host }
output "config_secret" { value = google_secret_manager_secret.config.id }
