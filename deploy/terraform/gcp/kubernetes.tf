locals {
  secret_fetch_prefix = "umask 077; mkdir -p /run/bridgefu-secrets;"

  gateway_secret_fetch = join(" ", concat(
    [local.secret_fetch_prefix],
    [for path in sort(keys(var.gateway_secret_versions)) : format(
      "gcloud secrets versions access '%s' --secret='%s' --project='%s' --quiet > '/run/bridgefu-secrets/%s';",
      split("/", var.gateway_secret_versions[path])[5],
      split("/", var.gateway_secret_versions[path])[3],
      split("/", var.gateway_secret_versions[path])[1],
      path,
    )],
    [format(
      "gcloud secrets versions access '%s' --secret='%s' --project='%s' --quiet > '/run/bridgefu-secrets/redis-url'; gcloud secrets versions access '%s' --secret='%s' --project='%s' --quiet > '/run/bridgefu-secrets/redis-ca.pem'; chmod -R go-rwx /run/bridgefu-secrets",
      google_secret_manager_secret_version.redis_url.version,
      google_secret_manager_secret.redis_url.secret_id,
      var.project_id,
      google_secret_manager_secret_version.redis_ca.version,
      google_secret_manager_secret.redis_ca.secret_id,
      var.project_id,
    )],
  ))

  worker_secret_fetch = join(" ", concat(
    [local.secret_fetch_prefix],
    [for path in sort(keys(var.worker_secret_versions)) : format(
      "gcloud secrets versions access '%s' --secret='%s' --project='%s' --quiet > '/run/bridgefu-secrets/%s';",
      split("/", var.worker_secret_versions[path])[5],
      split("/", var.worker_secret_versions[path])[3],
      split("/", var.worker_secret_versions[path])[1],
      path,
    )],
    [format(
      "gcloud secrets versions access '%s' --secret='%s' --project='%s' --quiet > '/run/bridgefu-secrets/redis-url'; gcloud secrets versions access '%s' --secret='%s' --project='%s' --quiet > '/run/bridgefu-secrets/redis-ca.pem'; chmod -R go-rwx /run/bridgefu-secrets",
      google_secret_manager_secret_version.redis_url.version,
      google_secret_manager_secret.redis_url.secret_id,
      var.project_id,
      google_secret_manager_secret_version.redis_ca.version,
      google_secret_manager_secret.redis_ca.secret_id,
      var.project_id,
    )],
  ))

  moq_relay_secret_fetch = join(" ", concat(
    [local.secret_fetch_prefix],
    [for path in sort(keys(var.moq_relay_secret_versions)) : format(
      "gcloud secrets versions access '%s' --secret='%s' --project='%s' --quiet > '/run/bridgefu-secrets/%s';",
      split("/", var.moq_relay_secret_versions[path])[5],
      split("/", var.moq_relay_secret_versions[path])[3],
      split("/", var.moq_relay_secret_versions[path])[1],
      path,
    )],
    [format(
      "gcloud secrets versions access '%s' --secret='%s' --project='%s' --quiet > '/run/bridgefu-secrets/redis-url'; gcloud secrets versions access '%s' --secret='%s' --project='%s' --quiet > '/run/bridgefu-secrets/redis-ca.pem'; chmod -R go-rwx /run/bridgefu-secrets",
      google_secret_manager_secret_version.redis_url.version,
      google_secret_manager_secret.redis_url.secret_id,
      var.project_id,
      google_secret_manager_secret_version.redis_ca.version,
      google_secret_manager_secret.redis_ca.secret_id,
      var.project_id,
    )],
  ))

  otel_secret_fetch = join(" ", concat(
    [local.secret_fetch_prefix],
    [for path in sort(keys(var.otel_secret_versions)) : format(
      "gcloud secrets versions access '%s' --secret='%s' --project='%s' --quiet > '/run/bridgefu-secrets/%s';",
      split("/", var.otel_secret_versions[path])[5],
      split("/", var.otel_secret_versions[path])[3],
      split("/", var.otel_secret_versions[path])[1],
      path,
    )],
    ["chmod -R go-rwx /run/bridgefu-secrets"],
  ))

  common_labels = {
    "app.kubernetes.io/name"       = "bridgefu"
    "app.kubernetes.io/part-of"    = "bridgefu"
    "app.kubernetes.io/managed-by" = "terraform"
  }
}

resource "kubernetes_namespace_v1" "bridgefu" {
  metadata {
    name = var.name
    labels = {
      "app.kubernetes.io/name" = "bridgefu"
    }
  }
  depends_on = [google_container_node_pool.system]
}

resource "kubernetes_service_account_v1" "bridgefu" {
  metadata {
    name      = "bridgefu"
    namespace = kubernetes_namespace_v1.bridgefu.metadata[0].name
    annotations = {
      "iam.gke.io/gcp-service-account" = google_service_account.bridgefu.email
    }
  }
}

resource "google_service_account_iam_member" "workload_identity" {
  service_account_id = google_service_account.bridgefu.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project_id}.svc.id.goog[${kubernetes_namespace_v1.bridgefu.metadata[0].name}/${kubernetes_service_account_v1.bridgefu.metadata[0].name}]"
}

resource "kubernetes_cluster_role_v1" "otel_discovery" {
  metadata { name = "${var.name}-otel-discovery" }
  rule {
    api_groups = [""]
    resources  = ["endpoints", "namespaces", "nodes", "nodes/proxy", "pods", "services"]
    verbs      = ["get", "list", "watch"]
  }
  rule {
    api_groups = ["apps"]
    resources  = ["daemonsets", "deployments", "replicasets", "statefulsets"]
    verbs      = ["get", "list", "watch"]
  }
}

resource "kubernetes_cluster_role_binding_v1" "otel_discovery" {
  metadata { name = "${var.name}-otel-discovery" }
  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = kubernetes_cluster_role_v1.otel_discovery.metadata[0].name
  }
  subject {
    kind      = "ServiceAccount"
    name      = kubernetes_service_account_v1.bridgefu.metadata[0].name
    namespace = kubernetes_namespace_v1.bridgefu.metadata[0].name
  }
}

resource "kubernetes_daemon_set_v1" "gateway" {
  metadata {
    name      = "bridgefu-gateway"
    namespace = kubernetes_namespace_v1.bridgefu.metadata[0].name
    labels    = merge(local.common_labels, { "bridgefu.io/role" = "gateway" })
  }

  spec {
    selector { match_labels = { "app.kubernetes.io/name" = "bridgefu", "bridgefu.io/role" = "gateway" } }
    strategy {
      type = "RollingUpdate"
      rolling_update { max_unavailable = "1" }
    }
    template {
      metadata {
        labels = merge(local.common_labels, { "bridgefu.io/role" = "gateway" })
        annotations = {
          "prometheus.io/path"   = "/metrics"
          "prometheus.io/port"   = tostring(var.operations_port)
          "prometheus.io/scrape" = "true"
        }
      }
      spec {
        host_network                     = true
        dns_policy                       = "ClusterFirstWithHostNet"
        service_account_name             = kubernetes_service_account_v1.bridgefu.metadata[0].name
        termination_grace_period_seconds = var.termination_grace_period_seconds
        automount_service_account_token  = true

        node_selector = { "bridgefu-role" = "gateway" }
        toleration {
          key      = "bridgefu-role"
          operator = "Equal"
          value    = "gateway"
          effect   = "NoSchedule"
        }
        security_context {
          run_as_non_root = true
          run_as_user     = 65532
          run_as_group    = 65532
          fs_group        = 65532
          seccomp_profile { type = "RuntimeDefault" }
        }

        init_container {
          name    = "fetch-secrets"
          image   = var.gcloud_image
          command = ["/bin/sh", "-ec", local.gateway_secret_fetch]
          env {
            name  = "CLOUDSDK_CONFIG"
            value = "/tmp/gcloud"
          }
          volume_mount {
            name       = "secrets"
            mount_path = "/run/bridgefu-secrets"
          }
          volume_mount {
            name       = "tmp"
            mount_path = "/tmp"
          }
          security_context {
            allow_privilege_escalation = false
            read_only_root_filesystem  = true
            capabilities { drop = ["ALL"] }
          }
          resources {
            requests = { cpu = "50m", memory = "128Mi" }
            limits   = { cpu = "500m", memory = "512Mi" }
          }
        }

        container {
          name    = "bridgefu"
          image   = var.image
          command = ["/bin/sh", "-ec"]
          args = [
            "cat /etc/ssl/certs/ca-certificates.crt /run/bridgefu-secrets/redis-ca.pem > /tmp/bridgefu-ca.pem; export SSL_CERT_FILE=/tmp/bridgefu-ca.pem; export BRIDGEFU_REDIS_URL=\"$(cat /run/bridgefu-secrets/redis-url)\"; exec /usr/local/bin/bridgefu --config /run/bridgefu-secrets/bridgefu.yaml run",
          ]
          env {
            name  = "BRIDGEFU_DATABASE_URL"
            value = local.database_url
          }
          port {
            name           = "gateway-quic"
            container_port = var.gateway_quic_port
            host_port      = var.gateway_quic_port
            protocol       = "UDP"
          }
          port {
            name           = "public-api"
            container_port = var.api_port
            host_port      = var.api_port
            protocol       = "TCP"
          }
          port {
            name           = "sip"
            container_port = var.sip_port
            host_port      = var.sip_port
            protocol       = "UDP"
          }
          port {
            name           = "webrtc-wss"
            container_port = var.webrtc_ws_port
            host_port      = var.webrtc_ws_port
            protocol       = "TCP"
          }
          port {
            name           = "whip-whep"
            container_port = var.webrtc_whip_port
            host_port      = var.webrtc_whip_port
            protocol       = "TCP"
          }
          port {
            name           = "webrtc-media"
            container_port = var.webrtc_media_port
            host_port      = var.webrtc_media_port
            protocol       = "UDP"
          }
          port {
            name           = "operations"
            container_port = var.operations_port
            host_port      = var.operations_port
            protocol       = "TCP"
          }
          volume_mount {
            name       = "secrets"
            mount_path = "/run/bridgefu-secrets"
            read_only  = true
          }
          volume_mount {
            name       = "tmp"
            mount_path = "/tmp"
          }
          security_context {
            allow_privilege_escalation = false
            read_only_root_filesystem  = true
            capabilities { drop = ["ALL"] }
          }
          readiness_probe {
            http_get {
              path   = "/readyz"
              port   = var.operations_port
              scheme = "HTTP"
            }
            initial_delay_seconds = 5
            period_seconds        = 5
            timeout_seconds       = 2
            failure_threshold     = 3
          }
          liveness_probe {
            http_get {
              path   = "/livez"
              port   = var.operations_port
              scheme = "HTTP"
            }
            initial_delay_seconds = 20
            period_seconds        = 15
            timeout_seconds       = 3
            failure_threshold     = 3
          }
          resources {
            requests = { cpu = var.gateway_cpu_request, memory = var.gateway_memory_request }
            limits   = { cpu = var.gateway_cpu_limit, memory = var.gateway_memory_limit }
          }
        }

        container {
          name  = "cloud-sql-proxy"
          image = var.cloud_sql_proxy_image
          args = [
            "--address=127.0.0.1",
            "--auto-iam-authn",
            "--port=5432",
            "--structured-logs",
            google_sql_database_instance.postgres.connection_name,
          ]
          security_context {
            allow_privilege_escalation = false
            read_only_root_filesystem  = true
            capabilities { drop = ["ALL"] }
          }
          resources {
            requests = { cpu = "100m", memory = "128Mi" }
            limits   = { cpu = "1000m", memory = "512Mi" }
          }
        }

        volume {
          name = "secrets"
          empty_dir { medium = "Memory" }
        }
        volume {
          name = "tmp"
          empty_dir { medium = "Memory" }
        }
      }
    }
  }

  depends_on = [
    google_container_node_pool.gateway,
    google_secret_manager_secret_iam_member.external,
    google_secret_manager_secret_iam_member.redis_url,
    google_secret_manager_secret_iam_member.redis_ca,
    google_service_account_iam_member.workload_identity,
  ]
}

resource "kubernetes_service_v1" "gateway_http" {
  metadata {
    name      = "bridgefu-gateway"
    namespace = kubernetes_namespace_v1.bridgefu.metadata[0].name
  }
  spec {
    cluster_ip = "None"
    selector   = { "app.kubernetes.io/name" = "bridgefu", "bridgefu.io/role" = "gateway" }
    port {
      name        = "metrics"
      port        = var.operations_port
      target_port = tostring(var.operations_port)
      protocol    = "TCP"
    }
  }
}

resource "kubernetes_service_v1" "worker" {
  metadata {
    name      = "bridgefu-worker"
    namespace = kubernetes_namespace_v1.bridgefu.metadata[0].name
  }
  spec {
    cluster_ip                  = "None"
    publish_not_ready_addresses = false
    selector                    = { "app.kubernetes.io/name" = "bridgefu", "bridgefu.io/role" = "worker" }
    port {
      name        = "forwarding"
      port        = var.private_forwarding_port
      target_port = tostring(var.private_forwarding_port)
      protocol    = "UDP"
    }
    port {
      name        = "metrics"
      port        = var.operations_port
      target_port = tostring(var.operations_port)
      protocol    = "TCP"
    }
  }
}

resource "kubernetes_stateful_set_v1" "worker" {
  metadata {
    name      = "bridgefu-worker"
    namespace = kubernetes_namespace_v1.bridgefu.metadata[0].name
    labels    = merge(local.common_labels, { "bridgefu.io/role" = "worker" })
  }

  spec {
    service_name          = kubernetes_service_v1.worker.metadata[0].name
    replicas              = var.worker_min_replicas
    pod_management_policy = "Parallel"
    selector { match_labels = { "app.kubernetes.io/name" = "bridgefu", "bridgefu.io/role" = "worker" } }
    update_strategy { type = "RollingUpdate" }

    template {
      metadata {
        labels = merge(local.common_labels, { "bridgefu.io/role" = "worker" })
        annotations = {
          "prometheus.io/path"   = "/metrics"
          "prometheus.io/port"   = tostring(var.operations_port)
          "prometheus.io/scrape" = "true"
        }
      }
      spec {
        service_account_name             = kubernetes_service_account_v1.bridgefu.metadata[0].name
        termination_grace_period_seconds = var.termination_grace_period_seconds
        node_selector                    = { "bridgefu-role" = "worker" }
        toleration {
          key      = "bridgefu-role"
          operator = "Equal"
          value    = "worker"
          effect   = "NoSchedule"
        }
        security_context {
          run_as_non_root = true
          run_as_user     = 65532
          run_as_group    = 65532
          fs_group        = 65532
          seccomp_profile { type = "RuntimeDefault" }
        }
        affinity {
          pod_anti_affinity {
            preferred_during_scheduling_ignored_during_execution {
              weight = 100
              pod_affinity_term {
                topology_key = "kubernetes.io/hostname"
                label_selector { match_labels = { "app.kubernetes.io/name" = "bridgefu", "bridgefu.io/role" = "worker" } }
              }
            }
          }
        }

        init_container {
          name    = "fetch-secrets"
          image   = var.gcloud_image
          command = ["/bin/sh", "-ec", local.worker_secret_fetch]
          env {
            name  = "CLOUDSDK_CONFIG"
            value = "/tmp/gcloud"
          }
          volume_mount {
            name       = "secrets"
            mount_path = "/run/bridgefu-secrets"
          }
          volume_mount {
            name       = "tmp"
            mount_path = "/tmp"
          }
          security_context {
            allow_privilege_escalation = false
            read_only_root_filesystem  = true
            capabilities { drop = ["ALL"] }
          }
          resources {
            requests = { cpu = "50m", memory = "128Mi" }
            limits   = { cpu = "500m", memory = "512Mi" }
          }
        }

        container {
          name    = "bridgefu"
          image   = var.image
          command = ["/bin/sh", "-ec"]
          args = [
            "cat /etc/ssl/certs/ca-certificates.crt /run/bridgefu-secrets/redis-ca.pem > /tmp/bridgefu-ca.pem; export SSL_CERT_FILE=/tmp/bridgefu-ca.pem; export BRIDGEFU_REDIS_URL=\"$(cat /run/bridgefu-secrets/redis-url)\"; test -r \"/run/bridgefu-secrets/$${HOSTNAME}.yaml\"; exec /usr/local/bin/bridgefu --config \"/run/bridgefu-secrets/$${HOSTNAME}.yaml\" run",
          ]
          env {
            name  = "BRIDGEFU_DATABASE_URL"
            value = local.database_url
          }
          port {
            name           = "forwarding"
            container_port = var.private_forwarding_port
            protocol       = "UDP"
          }
          port {
            name           = "http"
            container_port = var.operations_port
            protocol       = "TCP"
          }
          volume_mount {
            name       = "secrets"
            mount_path = "/run/bridgefu-secrets"
            read_only  = true
          }
          volume_mount {
            name       = "tmp"
            mount_path = "/tmp"
          }
          security_context {
            allow_privilege_escalation = false
            read_only_root_filesystem  = true
            capabilities { drop = ["ALL"] }
          }
          readiness_probe {
            http_get {
              path   = "/readyz"
              port   = var.operations_port
              scheme = "HTTP"
            }
            initial_delay_seconds = 5
            period_seconds        = 5
            timeout_seconds       = 2
            failure_threshold     = 3
          }
          liveness_probe {
            http_get {
              path   = "/livez"
              port   = var.operations_port
              scheme = "HTTP"
            }
            initial_delay_seconds = 20
            period_seconds        = 15
            timeout_seconds       = 3
            failure_threshold     = 3
          }
          resources {
            requests = { cpu = var.worker_cpu_request, memory = var.worker_memory_request }
            limits   = { cpu = var.worker_cpu_limit, memory = var.worker_memory_limit }
          }
        }

        container {
          name  = "cloud-sql-proxy"
          image = var.cloud_sql_proxy_image
          args = [
            "--address=127.0.0.1",
            "--auto-iam-authn",
            "--port=5432",
            "--structured-logs",
            google_sql_database_instance.postgres.connection_name,
          ]
          security_context {
            allow_privilege_escalation = false
            read_only_root_filesystem  = true
            capabilities { drop = ["ALL"] }
          }
          resources {
            requests = { cpu = "100m", memory = "128Mi" }
            limits   = { cpu = "1000m", memory = "512Mi" }
          }
        }

        volume {
          name = "secrets"
          empty_dir { medium = "Memory" }
        }
        volume {
          name = "tmp"
          empty_dir { medium = "Memory" }
        }
      }
    }
  }

  lifecycle {
    precondition {
      condition = alltrue([
        for ordinal in range(var.worker_max_replicas) :
        contains(keys(var.worker_secret_versions), "bridgefu-worker-${ordinal}.yaml")
      ])
      error_message = "worker_secret_versions must provision one immutable config for every HPA ordinal through worker_max_replicas - 1."
    }
  }

  depends_on = [
    google_container_node_pool.worker,
    google_secret_manager_secret_iam_member.external,
    google_secret_manager_secret_iam_member.redis_url,
    google_secret_manager_secret_iam_member.redis_ca,
    google_service_account_iam_member.workload_identity,
  ]
}

resource "kubernetes_horizontal_pod_autoscaler_v2" "worker" {
  metadata {
    name      = "bridgefu-worker"
    namespace = kubernetes_namespace_v1.bridgefu.metadata[0].name
  }
  spec {
    min_replicas = var.worker_min_replicas
    max_replicas = var.worker_max_replicas
    scale_target_ref {
      api_version = "apps/v1"
      kind        = "StatefulSet"
      name        = kubernetes_stateful_set_v1.worker.metadata[0].name
    }
    metric {
      type = "Resource"
      resource {
        name = "cpu"
        target {
          type                = "Utilization"
          average_utilization = var.worker_cpu_target_percent
        }
      }
    }
    behavior {
      scale_down {
        stabilization_window_seconds = 600
        select_policy                = "Min"
        policy {
          type           = "Pods"
          value          = 1
          period_seconds = 300
        }
      }
      scale_up {
        stabilization_window_seconds = 30
        select_policy                = "Max"
        policy {
          type           = "Percent"
          value          = 100
          period_seconds = 60
        }
        policy {
          type           = "Pods"
          value          = 2
          period_seconds = 60
        }
      }
    }
  }
}

resource "kubernetes_daemon_set_v1" "moq_relay" {
  metadata {
    name      = "bridgefu-moq-relay"
    namespace = kubernetes_namespace_v1.bridgefu.metadata[0].name
    labels    = merge(local.common_labels, { "bridgefu.io/role" = "moq-relay" })
  }
  spec {
    selector { match_labels = { "app.kubernetes.io/name" = "bridgefu", "bridgefu.io/role" = "moq-relay" } }
    strategy {
      type = "RollingUpdate"
      rolling_update { max_unavailable = "1" }
    }
    template {
      metadata {
        labels = merge(local.common_labels, { "bridgefu.io/role" = "moq-relay" })
        annotations = {
          "prometheus.io/path"   = "/metrics"
          "prometheus.io/port"   = tostring(var.operations_port)
          "prometheus.io/scrape" = "true"
        }
      }
      spec {
        host_network                     = true
        dns_policy                       = "ClusterFirstWithHostNet"
        service_account_name             = kubernetes_service_account_v1.bridgefu.metadata[0].name
        termination_grace_period_seconds = var.termination_grace_period_seconds
        node_selector                    = { "bridgefu-role" = "moq-relay" }
        toleration {
          key      = "bridgefu-role"
          operator = "Equal"
          value    = "moq-relay"
          effect   = "NoSchedule"
        }
        security_context {
          run_as_non_root = true
          run_as_user     = 65532
          run_as_group    = 65532
          fs_group        = 65532
          seccomp_profile { type = "RuntimeDefault" }
        }
        init_container {
          name    = "fetch-secrets"
          image   = var.gcloud_image
          command = ["/bin/sh", "-ec", local.moq_relay_secret_fetch]
          env {
            name  = "CLOUDSDK_CONFIG"
            value = "/tmp/gcloud"
          }
          volume_mount {
            name       = "secrets"
            mount_path = "/run/bridgefu-secrets"
          }
          volume_mount {
            name       = "tmp"
            mount_path = "/tmp"
          }
          security_context {
            allow_privilege_escalation = false
            read_only_root_filesystem  = true
            capabilities { drop = ["ALL"] }
          }
          resources {
            requests = { cpu = "50m", memory = "128Mi" }
            limits   = { cpu = "500m", memory = "512Mi" }
          }
        }
        container {
          name    = "bridgefu"
          image   = var.image
          command = ["/bin/sh", "-ec"]
          args = [
            "cat /etc/ssl/certs/ca-certificates.crt /run/bridgefu-secrets/redis-ca.pem > /tmp/bridgefu-ca.pem; export SSL_CERT_FILE=/tmp/bridgefu-ca.pem; export BRIDGEFU_REDIS_URL=\"$(cat /run/bridgefu-secrets/redis-url)\"; exec /usr/local/bin/bridgefu --config /run/bridgefu-secrets/bridgefu.yaml run",
          ]
          port {
            name           = "publisher"
            container_port = var.moq_publisher_port
            host_port      = var.moq_publisher_port
            protocol       = "UDP"
          }
          port {
            name           = "webtransport"
            container_port = var.moq_webtransport_port
            host_port      = var.moq_webtransport_port
            protocol       = "UDP"
          }
          port {
            name           = "raw-quic"
            container_port = var.moq_raw_quic_port
            host_port      = var.moq_raw_quic_port
            protocol       = "UDP"
          }
          port {
            name           = "http"
            container_port = var.operations_port
            host_port      = var.operations_port
            protocol       = "TCP"
          }
          volume_mount {
            name       = "secrets"
            mount_path = "/run/bridgefu-secrets"
            read_only  = true
          }
          volume_mount {
            name       = "tmp"
            mount_path = "/tmp"
          }
          security_context {
            allow_privilege_escalation = false
            read_only_root_filesystem  = true
            capabilities { drop = ["ALL"] }
          }
          readiness_probe {
            http_get {
              path   = "/readyz"
              port   = var.operations_port
              scheme = "HTTP"
            }
            initial_delay_seconds = 5
            period_seconds        = 5
            timeout_seconds       = 2
            failure_threshold     = 3
          }
          liveness_probe {
            http_get {
              path   = "/livez"
              port   = var.operations_port
              scheme = "HTTP"
            }
            initial_delay_seconds = 20
            period_seconds        = 15
            timeout_seconds       = 3
            failure_threshold     = 3
          }
          resources {
            requests = { cpu = var.moq_relay_cpu_request, memory = var.moq_relay_memory_request }
            limits   = { cpu = var.moq_relay_cpu_limit, memory = var.moq_relay_memory_limit }
          }
        }
        volume {
          name = "secrets"
          empty_dir { medium = "Memory" }
        }
        volume {
          name = "tmp"
          empty_dir { medium = "Memory" }
        }
      }
    }
  }
  depends_on = [
    google_container_node_pool.moq_relay,
    google_secret_manager_secret_iam_member.external,
    google_secret_manager_secret_iam_member.redis_url,
    google_secret_manager_secret_iam_member.redis_ca,
    google_service_account_iam_member.workload_identity,
  ]
}

resource "kubernetes_service_v1" "moq_relay_metrics" {
  metadata {
    name      = "bridgefu-moq-relay"
    namespace = kubernetes_namespace_v1.bridgefu.metadata[0].name
  }
  spec {
    cluster_ip = "None"
    selector   = { "app.kubernetes.io/name" = "bridgefu", "bridgefu.io/role" = "moq-relay" }
    port {
      name        = "metrics"
      port        = var.operations_port
      target_port = tostring(var.operations_port)
      protocol    = "TCP"
    }
  }
}

resource "kubernetes_deployment_v1" "otel" {
  metadata {
    name      = "bridgefu-otel"
    namespace = kubernetes_namespace_v1.bridgefu.metadata[0].name
    labels    = merge(local.common_labels, { "bridgefu.io/role" = "otel" })
  }
  spec {
    replicas = var.otel_replicas
    selector { match_labels = { "app.kubernetes.io/name" = "bridgefu", "bridgefu.io/role" = "otel" } }
    strategy {
      type = "RollingUpdate"
      rolling_update {
        max_surge       = "1"
        max_unavailable = "0"
      }
    }
    template {
      metadata { labels = merge(local.common_labels, { "bridgefu.io/role" = "otel" }) }
      spec {
        service_account_name             = kubernetes_service_account_v1.bridgefu.metadata[0].name
        termination_grace_period_seconds = 30
        node_selector                    = { "bridgefu-role" = "system" }
        security_context {
          run_as_non_root = true
          run_as_user     = 65532
          run_as_group    = 65532
          fs_group        = 65532
          seccomp_profile { type = "RuntimeDefault" }
        }
        init_container {
          name    = "fetch-config"
          image   = var.gcloud_image
          command = ["/bin/sh", "-ec", local.otel_secret_fetch]
          env {
            name  = "CLOUDSDK_CONFIG"
            value = "/tmp/gcloud"
          }
          volume_mount {
            name       = "secrets"
            mount_path = "/run/bridgefu-secrets"
          }
          volume_mount {
            name       = "tmp"
            mount_path = "/tmp"
          }
          security_context {
            allow_privilege_escalation = false
            read_only_root_filesystem  = true
            capabilities { drop = ["ALL"] }
          }
        }
        container {
          name  = "otel-collector"
          image = var.otel_collector_image
          args  = ["--config=/run/bridgefu-secrets/config.yaml"]
          port {
            name           = "otlp-grpc"
            container_port = 4317
            protocol       = "TCP"
          }
          port {
            name           = "otlp-http"
            container_port = 4318
            protocol       = "TCP"
          }
          port {
            name           = "health"
            container_port = 13133
            protocol       = "TCP"
          }
          volume_mount {
            name       = "secrets"
            mount_path = "/run/bridgefu-secrets"
            read_only  = true
          }
          volume_mount {
            name       = "tmp"
            mount_path = "/tmp"
          }
          security_context {
            allow_privilege_escalation = false
            read_only_root_filesystem  = true
            capabilities { drop = ["ALL"] }
          }
          readiness_probe {
            http_get {
              path   = "/"
              port   = 13133
              scheme = "HTTP"
            }
            initial_delay_seconds = 5
            period_seconds        = 10
          }
          liveness_probe {
            http_get {
              path   = "/"
              port   = 13133
              scheme = "HTTP"
            }
            initial_delay_seconds = 15
            period_seconds        = 15
          }
          resources {
            requests = { cpu = "250m", memory = "512Mi" }
            limits   = { cpu = "2", memory = "2Gi" }
          }
        }
        volume {
          name = "secrets"
          empty_dir { medium = "Memory" }
        }
        volume {
          name = "tmp"
          empty_dir { medium = "Memory" }
        }
      }
    }
  }
  depends_on = [
    google_container_node_pool.system,
    google_secret_manager_secret_iam_member.external,
    google_service_account_iam_member.workload_identity,
    kubernetes_cluster_role_binding_v1.otel_discovery,
  ]
}

resource "kubernetes_service_v1" "otel" {
  metadata {
    name      = "bridgefu-otel"
    namespace = kubernetes_namespace_v1.bridgefu.metadata[0].name
  }
  spec {
    selector = { "app.kubernetes.io/name" = "bridgefu", "bridgefu.io/role" = "otel" }
    port {
      name        = "otlp-grpc"
      port        = 4317
      target_port = "otlp-grpc"
      protocol    = "TCP"
    }
    port {
      name        = "otlp-http"
      port        = 4318
      target_port = "otlp-http"
      protocol    = "TCP"
    }
  }
}

resource "kubernetes_pod_disruption_budget_v1" "worker" {
  metadata {
    name      = "bridgefu-worker"
    namespace = kubernetes_namespace_v1.bridgefu.metadata[0].name
  }
  spec {
    min_available = 1
    selector { match_labels = { "app.kubernetes.io/name" = "bridgefu", "bridgefu.io/role" = "worker" } }
  }
}

resource "kubernetes_pod_disruption_budget_v1" "otel" {
  metadata {
    name      = "bridgefu-otel"
    namespace = kubernetes_namespace_v1.bridgefu.metadata[0].name
  }
  spec {
    min_available = 1
    selector { match_labels = { "app.kubernetes.io/name" = "bridgefu", "bridgefu.io/role" = "otel" } }
  }
}

output "worker_discovery" {
  description = "Gateway configs map pre-provisioned worker IDs to these stable StatefulSet DNS names."
  value = [
    for ordinal in range(var.worker_max_replicas) :
    "bridgefu-worker-${ordinal}.bridgefu-worker.${kubernetes_namespace_v1.bridgefu.metadata[0].name}.svc.cluster.local:${var.private_forwarding_port}"
  ]
}
output "otel_endpoint" {
  value = "http://${kubernetes_service_v1.otel.metadata[0].name}.${kubernetes_namespace_v1.bridgefu.metadata[0].name}.svc.cluster.local:4317"
}
