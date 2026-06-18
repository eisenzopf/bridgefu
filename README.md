# bridgefu

A small, always-on **SIP → Amazon Connect gateway**. Point a Vapi application at
it and it will accept the inbound SIP transfer, carry the call's custom `X-`
headers into Amazon Connect contact attributes (driving the agent screen pop),
join the Chime WebRTC media leg, and bridge audio both ways.

```
PSTN caller ─▶ Vapi app ─(SIP transfer/REFER with X- headers)─▶ bridgefu
            ─▶ Amazon Connect (StartWebRTCContact, attributes drive the screen pop)
            ─▶ live agent (CCP rings, screen pop populated, two-way audio)
```

`bridgefu` is a thin daemon over `rvoip-amazon-connect`'s `ConnectScreenPopServer`.
See [PRD.md](PRD.md) for the full product spec.

---

## How it's built and deployed

- The daemon depends on the `rvoip` workspace **by path** (`../rvoip/...`). Some
  rvoip crates are **not published to crates.io**, so we always build against a
  local checkout — never the registry.
- Deployment target: a single **arm64 / Graviton, Amazon Linux 2023** EC2 instance
  (default `t4g.2xlarge`).
- The instance **builds the Docker image itself**: Terraform's bootstrap clones
  `github.com/eisenzopf/rvoip`, and `deploy.sh` syncs the bridgefu source up,
  then runs `docker build` on the instance. The first build is slow; afterward the
  rvoip layers cache and redeploys only recompile bridgefu.
- The image runs under **systemd** (`Restart=always`) with `docker run --network host`.

```
On the instance:
  /opt/build/rvoip      <- git clone of github.com/eisenzopf/rvoip
  /opt/build/bridgefu   <- rsync of this repo (deploy.sh)
  docker build -f bridgefu/deploy/Dockerfile /opt/build   # ../rvoip path dep resolves
```

---

## Prerequisites

On your **laptop / build host**:

- [Terraform](https://developer.hashicorp.com/terraform/downloads) ≥ 1.5
- [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) v2, authenticated (see below)
- An SSH keypair (`ssh-keygen -t ed25519`)
- `rsync`, `ssh`, `scp` (standard on macOS/Linux)

You do **not** need Docker or Rust locally — the build happens on the instance.

An **Amazon Connect instance** with a contact flow configured for the screen pop
(see [Amazon Connect setup](#amazon-connect-setup)).

---

## AWS authentication

Two distinct credential paths:

1. **Terraform + deploy.sh (your laptop)** — uses your AWS credentials to create
   infra. Provide them however the AWS CLI/SDK expects:

   ```bash
   export AWS_PROFILE=your-profile          # or:
   export AWS_ACCESS_KEY_ID=...
   export AWS_SECRET_ACCESS_KEY=...
   export AWS_REGION=us-west-2              # match var.region
   ```

   Your principal needs permissions for EC2, VPC, EIP, IAM (role/profile/policy),
   and SSM parameter read.

2. **bridgefu at runtime (on the instance)** — uses the **EC2 instance role**
   created by Terraform. No AWS keys ever live in config or on the box. The role
   is least-privilege: only `connect:StartWebRTCContact` and `connect:StopContact`.
   The daemon resolves region + credentials via the standard AWS chain
   (`AwsConnectStarter::from_env`), and discovers its public IP via IMDSv2.

---

## Amazon Connect setup

You need two IDs for `bridgefu.yaml`:

- **`instance_id`** — Amazon Connect → your instance → the instance ID (a UUID).
- **`contact_flow_id`** — the contact flow that handles the inbound contact and
  performs the screen pop (a UUID, visible in the flow's URL / ARN).

The mapped attribute keys must match what the flow's *Check contact attributes*
block reads. The hosted widget surfaces them as `$.Attributes.HostedWidget-<name>`,
which is why the default `rename` map targets `HostedWidget-*` keys — so the same
screen pop is reused. Edit the `mapping.rename` table in your config to match your
flow.

See [docs/amazon-connect.md](docs/amazon-connect.md) for the full setup: finding the
IDs, the attribute-mapping contract, what the contact flow must read, verifying the
`X-` header path (PRD FR6), and common errors.

---

## Configuration

`bridgefu` reads one YAML file (`/etc/bridgefu/bridgefu.yaml` on the instance).
Copy the example and edit:

```bash
cp config/bridgefu.example.yaml bridgefu.yaml
$EDITOR bridgefu.yaml          # set aws.region + instance_id + contact_flow_id
```

Leave `sip.advertised_ip` and `sip.media_public_ip` as `auto` — on EC2 the daemon
resolves the public (Elastic) IP via IMDSv2. AWS credentials are **never** in this
file. See [config/bridgefu.example.yaml](config/bridgefu.example.yaml) for every
field. Restart the service to apply config changes (no hot reload).

---

## Deploy

```bash
# 1. Stand up the infra.
cd terraform
cp terraform.tfvars.example terraform.tfvars
$EDITOR terraform.tfvars       # public_key, admin_cidr, region (and optionally sip_cidr)
terraform init
terraform apply

# 2. Grab the Elastic IP and other outputs.
terraform output
#   public_ip      = "<EIP>"
#   sip_uri        = "sip:<EIP>:5060"
#   ...

# 3. Fill in your config (from the repo root).
cd ..
cp config/bridgefu.example.yaml bridgefu.yaml
$EDITOR bridgefu.yaml

# 4. Build on the instance + start the service.
INSTANCE_IP=$(terraform -chdir=terraform output -raw public_ip) \
SSH_KEY=~/.ssh/id_ed25519 \
CONFIG=./bridgefu.yaml \
./deploy.sh
```

`deploy.sh` syncs the source, builds the image on the instance, installs the
systemd unit, restarts the service, and polls `/healthz`. The first run includes
the cold rvoip build — expect several minutes.

### Verify

```bash
curl http://<EIP>:9090/healthz                       # -> ok   (from admin_cidr)
ssh ec2-user@<EIP> 'sudo journalctl -u bridgefu -f'  # SIP UAS "listening"
```

---

## Point Vapi at it

Configure your Vapi app's SIP transfer/REFER target to:

```
sip:<EIP>:5060
```

attaching the custom headers your flow expects, e.g.:

```
X-Vapi-Customer-Id: <id>
X-Vapi-Call-Id:     <id>
X-Account-Tier:     <tier>
```

These map (per `mapping.rename`) to `HostedWidget-customerId` /
`HostedWidget-vapiCallId` / `HostedWidget-accountTier` contact attributes.

A successful test (PRD §9): logs show `INVITE received` → inbound headers include
the `X-` set → `attributes=N>0` → `StartWebRTCContact` with a real `contact_id` →
Chime connected → `bridged`; the agent CCP rings with the screen pop populated and
audio flows both ways; hanging up either leg tears down the other (no leaked
contacts).

---

## Operations

```bash
ssh ec2-user@<EIP>
sudo systemctl status bridgefu
sudo systemctl restart bridgefu          # apply a new config
sudo journalctl -u bridgefu -f           # follow logs (structured JSON)
docker logs bridgefu                     # same, via docker

curl http://<EIP>:9090/metrics           # Prometheus (from admin_cidr)
#   bridgefu_active_sessions
#   bridgefu_contacts_started_total
#   bridgefu_failures_total
#   + rvoip's internal counters
```

To redeploy after a code or config change, just re-run `deploy.sh`.

---

## Security (POC posture)

This is a proof-of-concept and is **not hardened for untrusted public exposure**:

- **SIP/RTP are open by default** (`sip_cidr = 0.0.0.0/0`). **TODO:** set `sip_cidr`
  to the Vapi/carrier CIDRs once known and `terraform apply`.
- SSH (22) and metrics (9090) are restricted to `admin_cidr` — set this to your IP.
- The IAM policy uses `Resource = "*"` for the two Connect actions. **TODO:** scope
  to the specific instance + contact-flow ARNs.
- Plain UDP/RTP (no SIPS/SRTP) for the POC.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `docker build` killed / OOM (SIGKILL, signal 9) | Build host ran out of RAM. The full rvoip tree needs real memory — use `t4g.2xlarge` (32 GB) or larger; don't build on a 2 GB box. |
| `package X requires rustc 1.9x` | The AWS SDK crates float their MSRV above rvoip's declared 1.88. `deploy/Dockerfile` pins the builder to `rust:1.95`; bump it if a future `cargo update` raises the floor again. |
| First build very slow | Expected — the full rvoip tree compiles once. Redeploys reuse cached layers. |
| `IMDS request timed out (not on EC2?)` | You're running off-EC2, or IMDSv2 is blocked. Set literal IPs for `advertised_ip` / `media_public_ip` instead of `auto`. |
| `X-` headers missing in logs | The core risk this test exists to answer (PRD FR6). Set `log_level: "info,rvoip_amazon_connect=debug"` to log the full inbound header set and the resulting attribute map. |
| `AccessDenied` on StartWebRTCContact | Region mismatch (config vs Connect instance) or the contact flow isn't WebRTC-enabled; confirm `instance_id`/`contact_flow_id`. |
| No audio / one-way audio | RTP blocked — confirm `sip_cidr` allows UDP 16384–32767 from the carrier, and the EIP is what's advertised in SDP. |

---

## Local development

```bash
# Builds against ../rvoip (path dep). Requires the rvoip workspace checked out
# as a sibling of this repo.
cargo build
cargo run -- --config config/bridgefu.example.yaml   # fails fast on placeholder IDs
```

## Layout

```
src/                      daemon (main, config, observability, imds)
config/bridgefu.example.yaml
deploy/Dockerfile         multi-stage arm64 image (context = parent of rvoip + bridgefu)
deploy/bridgefu.service   systemd unit (docker run --network host, Restart=always)
deploy.sh                 sync -> build-on-instance -> restart -> healthcheck
terraform/                VPC, EIP, security group, IAM role, AL2023 arm64 instance
```
