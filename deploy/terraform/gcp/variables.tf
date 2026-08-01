variable "project_id" { type = string }
variable "region" {
  type    = string
  default = "us-central1"
}
variable "name" {
  type    = string
  default = "bridgefu"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,20}$", var.name))
    error_message = "name must be 2-21 lowercase alphanumeric or hyphen characters."
  }
}
variable "network_name" {
  type    = string
  default = "default"
}
variable "deletion_protection" {
  type    = bool
  default = true
}
variable "private_service_prefix_length" {
  type    = number
  default = 16
}

variable "image" {
  description = "Immutable Bridgefu image reference; tags are rejected."
  type        = string
  validation {
    condition     = can(regex("@sha256:[0-9a-f]{64}$", var.image))
    error_message = "image must be pinned by sha256 digest."
  }
}
variable "cloud_sql_proxy_image" {
  description = "Immutable Cloud SQL Auth Proxy image."
  type        = string
  validation {
    condition     = can(regex("@sha256:[0-9a-f]{64}$", var.cloud_sql_proxy_image))
    error_message = "cloud_sql_proxy_image must be pinned by sha256 digest."
  }
}
variable "gcloud_image" {
  description = "Immutable Google Cloud CLI image used only by init containers to fetch explicit Secret Manager versions."
  type        = string
  validation {
    condition     = can(regex("@sha256:[0-9a-f]{64}$", var.gcloud_image))
    error_message = "gcloud_image must be pinned by sha256 digest."
  }
}
variable "otel_collector_image" {
  description = "Immutable OpenTelemetry Collector image."
  type        = string
  validation {
    condition     = can(regex("@sha256:[0-9a-f]{64}$", var.otel_collector_image))
    error_message = "otel_collector_image must be pinned by sha256 digest."
  }
}

variable "gateway_secret_versions" {
  description = "Filename-to-explicit-Secret-Manager-version map. Must include bridgefu.yaml plus referenced TLS files."
  type        = map(string)
  validation {
    condition = contains(keys(var.gateway_secret_versions), "bridgefu.yaml") && alltrue([
      for path, resource in var.gateway_secret_versions :
      can(regex("^[A-Za-z0-9._-]+$", path)) && can(regex("^projects/[^/]+/secrets/[^/]+/versions/([1-9][0-9]*)$", resource))
    ])
    error_message = "gateway_secret_versions must include bridgefu.yaml and use safe filenames plus immutable Secret Manager version resources."
  }
}
variable "worker_secret_versions" {
  description = "All worker slot configs and TLS files. Include bridgefu-worker-0.yaml through max replica minus one."
  type        = map(string)
  validation {
    condition = contains(keys(var.worker_secret_versions), "bridgefu-worker-0.yaml") && alltrue([
      for path, resource in var.worker_secret_versions :
      can(regex("^[A-Za-z0-9._-]+$", path)) && can(regex("^projects/[^/]+/secrets/[^/]+/versions/([1-9][0-9]*)$", resource))
    ])
    error_message = "worker_secret_versions must include the first worker slot and immutable Secret Manager versions."
  }
}
variable "moq_relay_secret_versions" {
  type = map(string)
  validation {
    condition = contains(keys(var.moq_relay_secret_versions), "bridgefu.yaml") && alltrue([
      for path, resource in var.moq_relay_secret_versions :
      can(regex("^[A-Za-z0-9._-]+$", path)) && can(regex("^projects/[^/]+/secrets/[^/]+/versions/([1-9][0-9]*)$", resource))
    ])
    error_message = "moq_relay_secret_versions must include bridgefu.yaml and immutable Secret Manager versions."
  }
}
variable "otel_secret_versions" {
  type = map(string)
  validation {
    condition = contains(keys(var.otel_secret_versions), "config.yaml") && alltrue([
      for path, resource in var.otel_secret_versions :
      can(regex("^[A-Za-z0-9._-]+$", path)) && can(regex("^projects/[^/]+/secrets/[^/]+/versions/([1-9][0-9]*)$", resource))
    ])
    error_message = "otel_secret_versions must include config.yaml and immutable Secret Manager versions."
  }
}

variable "gke_release_channel" {
  type    = string
  default = "REGULAR"
}
variable "maintenance_start_time" {
  type    = string
  default = "2026-01-04T09:00:00Z"
}
variable "maintenance_end_time" {
  type    = string
  default = "2026-01-04T13:00:00Z"
}
variable "maintenance_recurrence" {
  type    = string
  default = "FREQ=WEEKLY;BYDAY=SU"
}

variable "system_machine_type" {
  type    = string
  default = "e2-standard-4"
}
variable "gateway_machine_type" {
  type    = string
  default = "c4-standard-8"
}
variable "worker_machine_type" {
  type    = string
  default = "c4-standard-16"
}
variable "moq_relay_machine_type" {
  type    = string
  default = "c4-standard-8"
}
variable "system_pool_min_nodes" {
  type    = number
  default = 1
}
variable "system_pool_max_nodes" {
  type    = number
  default = 3
}
variable "gateway_pool_min_nodes" {
  type    = number
  default = 1
}
variable "gateway_pool_max_nodes" {
  type    = number
  default = 4
}
variable "worker_pool_min_nodes" {
  type    = number
  default = 1
}
variable "worker_pool_max_nodes" {
  type    = number
  default = 20
}
variable "moq_relay_pool_min_nodes" {
  type    = number
  default = 1
}
variable "moq_relay_pool_max_nodes" {
  type    = number
  default = 20
}

variable "worker_min_replicas" {
  type    = number
  default = 2
}
variable "worker_max_replicas" {
  type    = number
  default = 20
}
variable "worker_cpu_target_percent" {
  type    = number
  default = 60
}
variable "otel_replicas" {
  type    = number
  default = 2
}
variable "termination_grace_period_seconds" {
  type    = number
  default = 120
}

variable "api_port" {
  description = "Dedicated gateway HTTPS /v1 call-control and provider-webhook TCP pass-through port."
  type        = number
  default     = 9080
}
variable "operations_port" {
  description = "Role-local health and metrics TCP port; never mounts /v1 or provider webhooks."
  type        = number
  default     = 9090
}
variable "sip_port" {
  description = "Authenticated native SIP/UDP listener port on the split gateway."
  type        = number
  default     = 5070
}
variable "webrtc_ws_port" {
  description = "Native WebRTC WSS signaling port; Bridgefu terminates TLS."
  type        = number
  default     = 8080
}
variable "webrtc_whip_port" {
  description = "WHIP/WHEP HTTPS port; Bridgefu terminates TLS."
  type        = number
  default     = 8081
}
variable "webrtc_media_port" {
  description = "Fixed rvoip ICE/DTLS media UDP mux port exposed by the gateway passthrough load balancer."
  type        = number
  default     = 40000
}
variable "gateway_quic_port" {
  type    = number
  default = 4446
}
variable "private_forwarding_port" {
  type    = number
  default = 9443
}
variable "rtp_port_start" {
  description = "First SIP/RTP UDP port exposed by the gateway passthrough load balancer."
  type        = number
  default     = 16384
}
variable "rtp_port_end" {
  description = "Last SIP/RTP UDP port exposed by the gateway passthrough load balancer."
  type        = number
  default     = 32767
  validation {
    condition     = var.rtp_port_end >= var.rtp_port_start && var.rtp_port_end <= 65535
    error_message = "rtp_port_end must be between rtp_port_start and 65535."
  }
}
variable "moq_publisher_port" {
  type    = number
  default = 4443
}
variable "moq_webtransport_port" {
  type    = number
  default = 4444
}
variable "moq_raw_quic_port" {
  type    = number
  default = 4445
}

variable "signaling_cidrs" {
  description = "CIDRs allowed to reach authenticated SIP signaling on the gateway passthrough load balancer."
  type        = list(string)
  validation {
    condition     = length(var.signaling_cidrs) > 0 && alltrue([for cidr in var.signaling_cidrs : can(cidrnetmask(cidr))])
    error_message = "signaling_cidrs must contain at least one valid CIDR."
  }
}
variable "media_cidrs" {
  description = "CIDRs allowed to reach the gateway SIP/RTP UDP range."
  type        = list(string)
  validation {
    condition     = length(var.media_cidrs) > 0 && alltrue([for cidr in var.media_cidrs : can(cidrnetmask(cidr))])
    error_message = "media_cidrs must contain at least one valid CIDR."
  }
}
variable "webrtc_cidrs" {
  description = "CIDRs allowed to reach WSS/WHIPS and ICE/DTLS media on the gateway load balancer."
  type        = list(string)
  validation {
    condition     = length(var.webrtc_cidrs) > 0 && alltrue([for cidr in var.webrtc_cidrs : can(cidrnetmask(cidr))])
    error_message = "webrtc_cidrs must contain at least one valid CIDR."
  }
}
variable "api_cidrs" {
  description = "CIDRs allowed to reach only the gateway HTTP API and provider webhooks. Restrict this to a reviewed TLS-terminating ingress or disposable smoke clients."
  type        = list(string)
  validation {
    condition     = length(var.api_cidrs) > 0 && alltrue([for cidr in var.api_cidrs : can(cidrnetmask(cidr))])
    error_message = "api_cidrs must contain valid CIDRs."
  }
}
variable "quic_cidrs" {
  type = list(string)
  validation {
    condition     = length(var.quic_cidrs) > 0 && alltrue([for cidr in var.quic_cidrs : can(cidrnetmask(cidr))])
    error_message = "quic_cidrs must contain valid CIDRs."
  }
}

variable "database_name" {
  type    = string
  default = "bridgefu"
}
variable "postgres_version" {
  type    = string
  default = "POSTGRES_17"
}
variable "postgres_tier" {
  type    = string
  default = "db-custom-4-15360"
}
variable "postgres_disk_size_gib" {
  type    = number
  default = 100
}
variable "postgres_log_retention_days" {
  type    = number
  default = 7
}
variable "redis_memory_size_gib" {
  type    = number
  default = 5
}
variable "redis_version" {
  type    = string
  default = "REDIS_7_2"
}
variable "redis_replica_count" {
  type    = number
  default = 2
}
variable "redis_secret_generation" {
  description = "Increment deliberately to write a new write-only Redis URL Secret Manager version."
  type        = number
  default     = 1
}

variable "gateway_cpu_request" {
  type    = string
  default = "1000m"
}
variable "gateway_memory_request" {
  type    = string
  default = "1Gi"
}
variable "gateway_cpu_limit" {
  type    = string
  default = "4"
}
variable "gateway_memory_limit" {
  type    = string
  default = "4Gi"
}
variable "worker_cpu_request" {
  type    = string
  default = "2000m"
}
variable "worker_memory_request" {
  type    = string
  default = "2Gi"
}
variable "worker_cpu_limit" {
  type    = string
  default = "8"
}
variable "worker_memory_limit" {
  type    = string
  default = "8Gi"
}
variable "moq_relay_cpu_request" {
  type    = string
  default = "2000m"
}
variable "moq_relay_memory_request" {
  type    = string
  default = "2Gi"
}
variable "moq_relay_cpu_limit" {
  type    = string
  default = "8"
}
variable "moq_relay_memory_limit" {
  type    = string
  default = "8Gi"
}
