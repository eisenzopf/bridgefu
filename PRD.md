# bridgefu — Product Requirements (v0.1, POC)

## 1. Problem & goal

We need a small, always-on **SIP → Amazon Connect gateway** we can point a
**Vapi** application at, to test the full transfer-with-context flow:

```
PSTN caller ─▶ Vapi app ─(SIP transfer/REFER with custom X- headers)─▶ bridgefu
            ─▶ Amazon Connect (StartWebRTCContact, attributes drive the screen pop)
            ─▶ live agent (CCP rings, screen pop populated, two-way audio)
```

The underlying capability is already built and validated in the `rvoip`
workspace (`rvoip-amazon-connect`): SIP UAS → custom-header→Connect-attribute
translation → `StartWebRTCContact` → native Amazon Chime SDK WebRTC media join →
bidirectional G.711⟷Opus bridge → teardown. We proved it end-to-end with a
`connect-probe` (control plane + Chime signaling + DTLS media + two-way audio
with a live agent) and a SIPp tone test.

`bridgefu` is the **deployable productization** of that capability: a
config-file-driven daemon that runs forever on an EC2 instance so we can run a
real Vapi↔Connect transfer test.

**Primary success metric:** a Vapi-initiated SIP transfer carrying `X-` headers
lands on an Amazon Connect agent with those values visible in the screen pop, and
audio flows both ways.

## 2. Users

- **Operator/admin** — edits one YAML config file (AWS instance/flow IDs, region,
  SIP addressing, the header→attribute map), deploys to EC2 via Terraform + a
  deploy script, and watches logs/metrics. No Rust knowledge required to operate.

## 3. Scope

**In scope (v0.1):**
- Single-tenant SIP UAS that accepts inbound INVITEs (incl. REFER-driven transfer
  targets — we are the transfer *target*, so we just receive an INVITE).
- Custom SIP header → Amazon Connect contact-attribute mapping (configurable
  rename table + pass-through policy).
- `StartWebRTCContact` + native Chime media join + bidirectional audio bridge
  (G.711 ⟷ Opus) + teardown on either-side hangup.
- YAML configuration; runs as a long-lived service (systemd + Docker,
  auto-restart).
- Observability: structured JSON logs, `/healthz`, Prometheus `/metrics`.
- One-command EC2 deployment via Terraform (VPC, Elastic IP, security group, IAM
  instance role) + a deploy script.

**Out of scope (v0.1):**
- Multi-tenant / multiple instances/flows per process.
- High availability / horizontal scale / clustering.
- TLS-SIP (SIPS) and SRTP from the carrier (plain UDP/RTP for the POC).
- Outbound (Connect → SIP) origination; video / screen-share.
- An admin UI or hot config reload (restart to apply config changes).
- Hardened public exposure (the POC opens SIP/RTP broadly; see §6 security).

## 4. Functional requirements

- **FR1 — SIP ingress.** Bind a SIP UAS (UDP+TCP) on a configurable address/port;
  auto-answer inbound INVITEs; advertise a routable public address.
- **FR2 — Header mapping.** Read all custom (`X-`/`Other`) headers off the INVITE;
  translate to Connect attributes via a configurable rename table and unmapped
  policy (`drop` or `pass_prefixed`); sanitize keys to Connect's `[A-Za-z0-9_-]`
  and honor the 32 KB attribute cap.
- **FR3 — Place the contact.** Call `StartWebRTCContact` with the mapped
  attributes against the configured instance + contact flow.
- **FR4 — Media bridge.** Join the returned Chime meeting over WebRTC and bridge
  audio both ways with the inbound SIP leg, transcoding G.711 ⟷ Opus.
- **FR5 — Teardown.** On SIP BYE, leave the Chime meeting + `StopContact`; on the
  Connect/agent leg ending, hang up the SIP carrier (BYE). No leaked contacts.
- **FR6 — Diagnostics.** Log the full set of inbound INVITE headers and the
  resulting attribute map at `debug`, so we can confirm whether the carrier
  preserved the `X-` headers across the transfer (the key risk).

## 5. Configuration (YAML)

Single file (default `/etc/bridgefu/bridgefu.yaml`), passed via `--config`.
Restart to apply changes. AWS credentials come from the environment / EC2
instance role — never from this file.

```yaml
aws:
  region: us-west-2
  instance_id: 83a72e61-xxxx-xxxx-xxxx-xxxxxxxxxxxx
  contact_flow_id: 2a3b3059-xxxx-xxxx-xxxx-xxxxxxxxxxxx   # agent/screen-pop flow

sip:
  bind_ip: 0.0.0.0
  port: 5060
  advertised_ip: auto        # "auto" → IMDSv2 public-ipv4 (the Elastic IP); or a literal IP
  media_public_ip: auto      # SDP c=/m= public IP (EC2 1:1 NAT); "auto" or a literal IP

contact:
  default_display_name: "Vapi caller"
  signaling_timeout_secs: 15
  media_connect_timeout_secs: 30
  keepalive_interval_secs: 10
  session_idle_ttl_secs: 120

mapping:
  unmapped: drop             # drop | pass_prefixed
  passthrough_prefix: "X-"
  rename:                    # inbound SIP header  ->  Connect attribute key
    X-Vapi-Customer-Id: HostedWidget-customerId
    X-Vapi-Call-Id:     HostedWidget-vapiCallId
    X-Account-Tier:     HostedWidget-accountTier

observability:
  log_level: info            # tracing EnvFilter (e.g. "info,rvoip_amazon_connect=debug")
  log_format: json           # json | pretty
  http_bind: 0.0.0.0:9090    # serves /healthz and /metrics
```

The attribute keys must match what the Connect contact flow's *Check contact
attributes* block reads (the hosted widget surfaces them as
`$.Attributes.HostedWidget-<name>`, hence the `HostedWidget-` prefix to reuse the
same screen pop).

## 6. Non-functional requirements

- **Reliability** — runs forever; auto-restart on crash (systemd `Restart=always`
  / Docker `--restart=always`). Graceful shutdown on SIGTERM/SIGINT.
- **Observability** — JSON logs to stdout/journald; `/healthz` (liveness);
  Prometheus `/metrics` (active bridges, contacts started, failures, plus rvoip's
  internal counters).
- **Networking** — EC2/GCP 1:1 NAT aware: advertise the public IP in SIP
  signaling (`Via`/`Contact`) and in SDP media (`c=`/`m=`), auto-detected via
  IMDSv2.
- **Security (POC posture)** — AWS creds via EC2 instance role (least-privilege:
  `connect:StartWebRTCContact`, `connect:StopContact`). SIP/RTP are opened broadly
  for the test with an explicit TODO + a Terraform variable to lock to
  Vapi/carrier CIDRs. Not hardened for untrusted public exposure.
- **Operability** — one YAML file; `terraform apply` + `deploy.sh` to stand up /
  update; arm64 Graviton, Amazon Linux 2023.

## 7. Architecture

`bridgefu` is a thin daemon over `rvoip-amazon-connect`'s `ConnectScreenPopServer`:
parse YAML → build `ScreenPopServerConfig` (`SipConfig` + `ConnectConfig` +
`AttributeMapping` + `AwsConnectStarter`) → `serve()` under a shutdown guard,
alongside an axum health/metrics server.

- Local dev: depends on `rvoip-amazon-connect` by **path** (`../rvoip`).
- Production/Docker: depends on the **published `rvoip-amazon-connect = 0.1.1`**
  from crates.io (the Docker build pins the registry version).

## 8. Deployment

- **Packaging:** multi-stage Docker image (deps from crates.io, so it builds off
  the instance), run via systemd with `--network host` + `--restart=always`.
- **Infra (Terraform):** VPC + public subnet + IGW, Elastic IP, security group
  (SSH/metrics from admin CIDR; SIP 5060 + RTP 16384–32767 from a configurable
  CIDR, default open for testing), IAM instance role, AL2023 arm64 `t4g.small`.
- **Build is off-instance** (laptop/CI); the small instance only runs the image.

## 9. Success criteria

1. `terraform apply` + `deploy.sh` produces a running gateway; `/healthz` returns
   200 and the SIP UAS logs "listening".
2. A Vapi app transfers a PSTN call (SIP, with `X-` headers) to the gateway's
   public `sip:<eip>:5060`.
3. Logs show: INVITE received → **inbound headers include the `X-` set** →
   `attributes=N>0` → `StartWebRTCContact` (real `contact_id`) → Chime connected →
   "bridged".
4. The agent CCP rings, the **screen pop shows the transferred values**, and audio
   flows both directions.
5. On hangup (either side), the other leg tears down cleanly (no leaked contacts).

## 10. Open questions / future

- Lock SIP/RTP to Vapi/carrier CIDRs once known (security group var).
- Whether the carrier preserves `X-` headers across REFER — the FR6 diagnostics
  exist specifically to answer this on the first live test.
- Later: TLS-SIP, multi-flow routing, HA, CloudWatch dashboards/alarms, hot reload.
