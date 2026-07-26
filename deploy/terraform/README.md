# Cluster Terraform

These root modules describe the intended role-separated Bridgefu cloud
topology. They are intentionally not applied by CI, contain no production
credentials, and do not create DNS, public certificates, carrier allowlists,
or a remote Terraform state backend. A successful static validation is not a
claim that the credentialed Gate 10 smoke test has run.

Every container input rejects mutable tags and requires an OCI digest. Copy a
`terraform.tfvars.example` only into a disposable account or project, replace
every placeholder digest and resource ID, and review the complete plan before
an apply.

## AWS: ECS on EC2

`aws/` creates one ECS cluster with three independent EC2 capacity providers,
task definitions, services, and CPU autoscaling targets:

- `gateway` exposes authenticated SIP/RTP, WSS, WHIP/WHEP over HTTPS, the
  versioned HTTPS call-control/provider-webhook API, health/metrics, and public
  UCTP/QUIC. It runs with host networking on a gateway-only Auto Scaling group
  and forwards every accepted attachment to its call-pinned worker.
- `worker` runs the durable call engine, MediaGraph, transcoding, Amazon
  adapter, and private mTLS UCTP forwarding listener on a worker-only group.
- `moqrelay` runs only the authenticated MOQT relay listeners on a relay-only
  group.

The module also creates Multi-AZ RDS PostgreSQL with forced TLS and IAM
database authentication, TLS-only ElastiCache Redis with a required precreated
RBAC user group, role-scoped security groups, task/execution IAM roles,
CloudWatch logs, and an OpenTelemetry Collector sidecar for every role. The
runtime IAM role includes telemetry and optional resource-scoped Amazon
Connect access; additional provider access must be supplied as reviewed policy
JSON or managed policy ARNs.

The module creates:

- a CIDR-restricted gateway NLB for SIP/UDP, WSS, WHIP/WHEP HTTPS, `/v1`, and
  provider webhooks; and
- a separate QUIC NLB for public UCTP and all three MOQT listeners.

The legacy-named `sip_nlb_eip_allocation_ids` input may provide stable per-AZ
addresses for the gateway signaling/API NLB. RTP and the fixed WebRTC ICE/DTLS
mux use one existing direct EIP per gateway host, associated by the exact-keyed
`gateway_instance_ids` and `gateway_media_eip_allocation_ids` maps. Each host's
immutable `bridgefu.yaml` must advertise its own media EIP. An Auto Scaling
replacement changes the instance ID; operators must preprovision the
replacement identity/config/EIP mapping and re-apply before admitting it.
This static association is intentionally visible rather than pretending that
an arbitrary RTP range migrates through an NLB.

The routes are isolated at the listener boundary: `api_port` passes HTTPS only
to the gateway's TLS-terminated `api.http_bind` public router (`/v1` and
provider webhooks); `webrtc_ws_port` and `webrtc_whip_port` pass through to
rvoip WSS and WHIP/WHEP HTTPS; and `sip_port` reaches only authenticated
SIP/UDP. `operations_port` targets `observability.http_bind` and carries only
health and metrics. NLB health checks use operations; `/metrics` is never
mounted on a public listener.

The three supplied Auto Scaling groups remain environment-owned. Attach the
corresponding `role_security_group_ids` output to each launch template and
install these read-only host paths during immutable bootstrap:

```text
/etc/bridgefu/gateway/bridgefu.yaml
/etc/bridgefu/worker/bridgefu.yaml
/etc/bridgefu/moq-relay/bridgefu.yaml
/etc/bridgefu/otel/config.yaml
```

Every worker host needs a different stable `persistence.worker_id`, matching
certificate identity, and a matching entry in each gateway configuration.
Worker service autoscaling is bounded by those preprovisioned worker
identities. Secret values are injected from `secret_arns`; gateway bootstrap must
install a serverAuth certificate/key for `private_forwarding.gateway.public_uctp`
separately from the private-forwarding client certificate. Configs should use
`env:BRIDGEFU_DATABASE_URL`, `env:BRIDGEFU_REDIS_URL`, and the other explicit
environment references rather than embedding credentials on disk.

Application prerequisite: the role must not be promoted merely because these
network resources validate. Its `/readyz` remains false until the gateway has
bound public UCTP, SIP, WSS, and WHIP/WHEP and authenticated its worker
forwarders. The credentialed smoke below is the release evidence for that
contract; routed but unbound ports are a hard failure.

## GCP: GKE Standard

`gcp/` creates a regional GKE Standard cluster with four separately autoscaled
node pools:

- an untainted system pool for the OpenTelemetry Collector;
- a tainted gateway media pool running a host-network DaemonSet;
- a tainted worker media pool running a StatefulSet and conservative CPU HPA;
- a tainted relay pool running a host-network MOQT DaemonSet.

Regional external passthrough Network Load Balancers target the managed
instance groups directly. One all-ports UDP forwarding rule preserves source
addresses for SIP, the bounded RTP range, WebRTC ICE/DTLS, and public UCTP;
protocol-specific firewall rules keep unrelated UDP ports closed. A TCP rule
on the same stable address carries HTTPS API, WSS, and WHIP/WHEP HTTPS. MOQT
relays retain a separate address. Gateway DaemonSets ensure every backend node
owns the listeners and expands with its node pool.

GKE uses the same route isolation: the public TCP rule reaches only the API,
WSS, and WHIP/WHEP ports; probes and Prometheus use `operations_port`. The
health-check firewall permits Google health check ranges only on operations,
while API, SIP, RTP, WebRTC, and QUIC CIDR policies remain separate.

The data plane includes private regional Cloud SQL PostgreSQL, automatic IAM
database authentication through a digest-pinned Cloud SQL Auth Proxy sidecar,
HA Memorystore with TLS/authentication/read replicas, Workload Identity,
Managed Prometheus cluster telemetry, and a digest-pinned OpenTelemetry
Collector Deployment. The collector configuration must enable its health
extension on port 13133 and export to the desired Google telemetry backends.

All supplied Bridgefu, certificate, key, and collector secrets are exact
Secret Manager version resources. A short-lived `gcloud` init container reads
them through Workload Identity into a memory-backed volume; Terraform never
reads those payloads. The generated Redis URL is written with the provider's
write-only Secret Manager attribute and fetched the same way. The module also
writes Memorystore's instance CA with a write-only attribute; Bridgefu combines
it with the image's system roots and points rustls at that in-memory bundle, so
both Redis and public HTTPS roots remain trusted. Memorystore's generated auth
token is nevertheless a sensitive computed provider value, so the Terraform
backend must be encrypted and access-controlled.

`gateway_secret_versions` must include a serverAuth public UCTP certificate
and key separately from the clientAuth identity used for private worker
forwarding.

Workers use stable StatefulSet ordinals. `worker_secret_versions` must contain
`bridgefu-worker-0.yaml` through `bridgefu-worker-(max-1).yaml`; each config has
a unique UUID and certificate. Gateway configs map those UUIDs to the
`worker_discovery` DNS names output by Terraform. Scale-down has a ten-minute
stabilization window and removes one worker at a time so Bridgefu can drain,
but the maximum pod termination grace period must still cover the configured
call drain policy.

## Static validation

From the repository root:

```sh
deploy/terraform/check.sh
```

That script runs formatting checks plus credential-free provider
initialization and validation for both roots. The equivalent manual commands
are:

```sh
terraform fmt -check -recursive deploy/terraform
terraform -chdir=deploy/terraform/aws init -backend=false
terraform -chdir=deploy/terraform/aws validate
terraform -chdir=deploy/terraform/gcp init -backend=false
terraform -chdir=deploy/terraform/gcp validate
```

## Credentialed smoke boundary

An authorized disposable-account smoke must still perform all of the
following before Gate 10 can close:

1. Apply the AWS or GCP root and wait for every dependency-aware `/readyz`.
2. Install a reviewed public certificate/private key through `api.tls`, verify
   HTTPS through the TCP pass-through load balancer, then create/read/control a
   call and deliver one signature-verified provider webhook.
3. Exercise the authenticated public UCTP attachment through the split gateway.
4. Create exact SIP and WebRTC attachment tokens, complete authenticated
   SIP/RTP and WSS plus WHIP/WHEP media paths through their pinned workers,
   exchange DataMessages and DTMF, and prove replay/cross-tenant rejection.
5. Exercise clustered broadcast creation plus the relay/listener runtime.
6. Confirm Prometheus metrics, OTLP traces, call drain, and redaction.
7. Trigger a worker and relay replacement and verify active sessions drain.
8. Run `terraform destroy` on success or failure and prove no billable resource
   remains.

The load balancers pass through TCP and Bridgefu terminates HTTPS/WSS/WHIPS
with rustls. These roots deliberately do not issue a public certificate: the
reviewed key pair must be supplied through the role's secret config volume.
SIP Bearer authentication is still a cleartext SIP mechanism; production
carrier paths should use the configured Telnyx Digest identity or a private,
CIDR-restricted signaling network until Bridgefu exposes rvoip's additional
listener policies.

Production state backends, artifact publication, public DNS/certificates, and
any apply or destroy require separate owner authorization.
