# Cluster Terraform

`aws/` composes an existing ECS-optimized EC2 autoscaling group with an ECS
capacity provider, host-network media workers, separate SIP and QUIC NLBs,
RDS PostgreSQL, ElastiCache Redis, Secrets Manager injection, health checks,
draining, and CloudWatch logs. RTP ports remain explicit security-group inputs.

`gcp/` creates a regional GKE Standard cluster with a dedicated autoscaled
media node pool, regional Cloud SQL PostgreSQL, HA Memorystore, Workload
Identity, and Secret Manager. Expose SIP/RTP and QUIC with separate GKE
`LoadBalancer` Services using `loadBalancerClass:
networking.gke.io/l4-regional-external` and `externalTrafficPolicy: Local` so
the regional passthrough load balancer preserves packet addresses.

These modules deliberately require network, credential, certificate, image,
port, and capacity values from the caller. Production state backends, DNS,
certificate issuance, organization policy, and alert destinations remain
environment-owned rather than hidden in a generic module.
