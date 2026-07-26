variable "name" {
  type    = string
  default = "bridgefu"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,20}$", var.name))
    error_message = "name must be 2-21 lowercase alphanumeric or hyphen characters."
  }
}

variable "vpc_id" { type = string }
variable "public_subnet_ids" {
  type = list(string)
  validation {
    condition     = length(var.public_subnet_ids) >= 2
    error_message = "at least two public subnets in distinct availability zones are required."
  }
}
variable "private_subnet_ids" {
  type = list(string)
  validation {
    condition     = length(var.private_subnet_ids) >= 2
    error_message = "at least two private subnets in distinct availability zones are required."
  }
}

variable "gateway_autoscaling_group_arn" { type = string }
variable "worker_autoscaling_group_arn" { type = string }
variable "moq_relay_autoscaling_group_arn" { type = string }

variable "gateway_instance_ids" {
  description = "Stable gateway EC2 instance IDs keyed by operator-owned gateway identity; every native media gateway receives one direct media EIP."
  type        = map(string)
  validation {
    condition     = length(var.gateway_instance_ids) > 0 && alltrue([for id in values(var.gateway_instance_ids) : can(regex("^i-[0-9a-f]+$", id))])
    error_message = "gateway_instance_ids must contain at least one valid EC2 instance ID."
  }
}

variable "gateway_media_eip_allocation_ids" {
  description = "Existing EIP allocation IDs keyed exactly like gateway_instance_ids for direct RTP and WebRTC media routing."
  type        = map(string)
  validation {
    condition     = length(var.gateway_media_eip_allocation_ids) > 0 && alltrue([for id in values(var.gateway_media_eip_allocation_ids) : can(regex("^eipalloc-[0-9a-f]+$", id))])
    error_message = "gateway_media_eip_allocation_ids must contain at least one valid EIP allocation ID."
  }
}

variable "sip_nlb_eip_allocation_ids" {
  description = "Optional public-subnet-to-EIP mapping for the gateway SIP, WSS/WHIPS, and HTTPS API NLB."
  type        = map(string)
  default     = {}
  validation {
    condition     = alltrue([for subnet in keys(var.sip_nlb_eip_allocation_ids) : contains(var.public_subnet_ids, subnet)])
    error_message = "sip_nlb_eip_allocation_ids keys must be public_subnet_ids."
  }
}
variable "quic_nlb_eip_allocation_ids" {
  description = "Optional public-subnet-to-EIP-allocation mapping for the separate QUIC NLB."
  type        = map(string)
  default     = {}
  validation {
    condition     = alltrue([for subnet in keys(var.quic_nlb_eip_allocation_ids) : contains(var.public_subnet_ids, subnet)])
    error_message = "quic_nlb_eip_allocation_ids keys must be public_subnet_ids."
  }
}

variable "image" {
  description = "Immutable Bridgefu image reference; tags are rejected."
  type        = string
  validation {
    condition     = can(regex("@sha256:[0-9a-f]{64}$", var.image))
    error_message = "image must be pinned by sha256 digest."
  }
}
variable "otel_collector_image" {
  description = "Immutable OpenTelemetry Collector image used as an ECS sidecar."
  type        = string
  validation {
    condition     = can(regex("@sha256:[0-9a-f]{64}$", var.otel_collector_image))
    error_message = "otel_collector_image must be pinned by sha256 digest."
  }
}

variable "gateway_config_host_path" {
  type    = string
  default = "/etc/bridgefu/gateway"
}
variable "worker_config_host_path" {
  type    = string
  default = "/etc/bridgefu/worker"
}
variable "moq_relay_config_host_path" {
  type    = string
  default = "/etc/bridgefu/moq-relay"
}
variable "otel_config_host_path" {
  type    = string
  default = "/etc/bridgefu/otel"
}

variable "otel_exporter_endpoint" {
  type    = string
  default = "http://127.0.0.1:4317"
  validation {
    condition     = can(regex("^https?://", var.otel_exporter_endpoint))
    error_message = "otel_exporter_endpoint must be an http(s) URL."
  }
}
variable "rust_log" {
  type    = string
  default = "info"
}

variable "gateway_cpu" {
  type    = number
  default = 2048
}
variable "gateway_memory" {
  type    = number
  default = 4096
}
variable "worker_cpu" {
  type    = number
  default = 4096
}
variable "worker_memory" {
  type    = number
  default = 8192
}
variable "moq_relay_cpu" {
  type    = number
  default = 4096
}
variable "moq_relay_memory" {
  type    = number
  default = 8192
}

variable "desired_gateways" {
  type    = number
  default = 2
}
variable "min_gateways" {
  type    = number
  default = 2
}
variable "max_gateways" {
  type    = number
  default = 4
}
variable "desired_workers" {
  type    = number
  default = 2
}
variable "min_workers" {
  type    = number
  default = 2
}
variable "max_workers" {
  type    = number
  default = 20
}
variable "desired_moq_relays" {
  type    = number
  default = 2
}
variable "min_moq_relays" {
  type    = number
  default = 2
}
variable "max_moq_relays" {
  type    = number
  default = 20
}

variable "autoscaling_cpu_target" {
  type    = number
  default = 60
  validation {
    condition     = var.autoscaling_cpu_target >= 10 && var.autoscaling_cpu_target <= 90
    error_message = "autoscaling_cpu_target must be between 10 and 90."
  }
}
variable "scale_in_cooldown_seconds" {
  type    = number
  default = 300
}
variable "scale_out_cooldown_seconds" {
  type    = number
  default = 30
}

variable "sip_port" {
  description = "Authenticated native SIP/UDP listener port on the split gateway."
  type        = number
  default     = 5070
}
variable "gateway_quic_port" {
  type    = number
  default = 4446
}
variable "private_forwarding_port" {
  type    = number
  default = 9443
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
  description = "Fixed rvoip ICE/DTLS media UDP mux port advertised by each gateway media EIP."
  type        = number
  default     = 40000
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
variable "moq_relay_ports" {
  type    = list(number)
  default = [4443, 4444, 4445]
  validation {
    condition     = length(var.moq_relay_ports) == 3 && length(distinct(var.moq_relay_ports)) == 3
    error_message = "moq_relay_ports must contain the three unique configured MOQT listener ports."
  }
}
variable "rtp_port_start" {
  description = "First direct-EIP SIP/RTP UDP port on every gateway host."
  type        = number
  default     = 16384
}
variable "rtp_port_end" {
  description = "Last direct-EIP SIP/RTP UDP port on every gateway host."
  type        = number
  default     = 32767
  validation {
    condition     = var.rtp_port_end >= var.rtp_port_start && var.rtp_port_end <= 65535
    error_message = "rtp_port_end must be between rtp_port_start and 65535."
  }
}

variable "signaling_cidrs" {
  description = "CIDRs allowed to reach authenticated SIP signaling through the gateway NLB."
  type        = list(string)
  validation {
    condition     = length(var.signaling_cidrs) > 0 && alltrue([for cidr in var.signaling_cidrs : can(cidrnetmask(cidr))])
    error_message = "signaling_cidrs must contain at least one valid CIDR."
  }
}
variable "media_cidrs" {
  description = "CIDRs allowed to send SIP/RTP directly to gateway media EIPs."
  type        = list(string)
  validation {
    condition     = length(var.media_cidrs) > 0 && alltrue([for cidr in var.media_cidrs : can(cidrnetmask(cidr))])
    error_message = "media_cidrs must contain at least one valid CIDR."
  }
}
variable "quic_cidrs" {
  type = list(string)
  validation {
    condition     = length(var.quic_cidrs) > 0 && alltrue([for cidr in var.quic_cidrs : can(cidrnetmask(cidr))])
    error_message = "quic_cidrs must contain valid CIDRs."
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
variable "webrtc_cidrs" {
  description = "CIDRs allowed to reach WSS/WHIPS through the NLB and ICE/DTLS media on gateway EIPs."
  type        = list(string)
  validation {
    condition     = length(var.webrtc_cidrs) > 0 && alltrue([for cidr in var.webrtc_cidrs : can(cidrnetmask(cidr))])
    error_message = "webrtc_cidrs must contain at least one valid CIDR."
  }
}
variable "operator_cidrs" {
  type = list(string)
  validation {
    condition     = length(var.operator_cidrs) > 0 && alltrue([for cidr in var.operator_cidrs : can(cidrnetmask(cidr))])
    error_message = "operator_cidrs must contain valid CIDRs."
  }
}

variable "secret_arns" {
  type    = map(string)
  default = {}
  validation {
    condition = alltrue([
      for name, arn in var.secret_arns :
      can(regex("^[A-Z][A-Z0-9_]*$", name)) && can(regex("^arn:aws:secretsmanager:", arn))
    ])
    error_message = "secret_arns keys must be environment-variable names and values must be Secrets Manager ARNs."
  }
}
variable "secret_kms_key_arns" {
  type    = list(string)
  default = []
}
variable "data_kms_key_arn" {
  type     = string
  default  = null
  nullable = true
}
variable "cloudwatch_kms_key_arn" {
  type     = string
  default  = null
  nullable = true
}
variable "amazon_connect_instance_arns" {
  type    = list(string)
  default = []
}
variable "runtime_policy_json" {
  description = "Optional reviewed least-privilege policy JSON for provider-specific runtime access."
  type        = string
  default     = null
  nullable    = true
  validation {
    condition     = var.runtime_policy_json == null || can(jsondecode(var.runtime_policy_json))
    error_message = "runtime_policy_json must be valid IAM policy JSON."
  }
}
variable "runtime_managed_policy_arns" {
  type    = list(string)
  default = []
}

variable "database_name" {
  type    = string
  default = "bridgefu"
}
variable "database_username" {
  type    = string
  default = "bridgefu"
}
variable "postgres_engine_version" {
  type    = string
  default = "17"
}
variable "postgres_instance_class" {
  type    = string
  default = "db.r7g.large"
}
variable "postgres_allocated_storage_gib" {
  type    = number
  default = 100
}
variable "postgres_max_allocated_storage_gib" {
  type    = number
  default = 1000
}
variable "database_backup_retention_days" {
  type    = number
  default = 14
}
variable "database_deletion_protection" {
  type    = bool
  default = true
}
variable "skip_final_snapshot" {
  type    = bool
  default = false
}

variable "redis_node_type" {
  type    = string
  default = "cache.r7g.large"
}
variable "redis_cluster_nodes" {
  type    = number
  default = 2
}
variable "redis_engine_version" {
  type    = string
  default = "7.2"
}
variable "redis_snapshot_retention_days" {
  type    = number
  default = 7
}
variable "redis_user_group_ids" {
  description = "Existing ElastiCache RBAC user group IDs; auth material remains outside Terraform variables."
  type        = list(string)
  validation {
    condition     = length(var.redis_user_group_ids) > 0
    error_message = "at least one ElastiCache RBAC user group is required."
  }
}

variable "drain_timeout_seconds" {
  type    = number
  default = 120
  validation {
    condition     = var.drain_timeout_seconds >= 10 && var.drain_timeout_seconds <= 120
    error_message = "ECS stop timeout must be between 10 and 120 seconds."
  }
}
variable "target_deregistration_delay_seconds" {
  type    = number
  default = 120
}
variable "log_retention_days" {
  type    = number
  default = 30
}
