#!/usr/bin/env bash
#
# deploy.sh — push the bridgefu source to the EC2 instance, build the Docker
# image there (rvoip is fetched from crates.io during the build), and (re)start
# the systemd service. Run from the bridgefu repo root.
#
# Required env vars:
#   INSTANCE_IP   Public/Elastic IP of the instance (terraform output public_ip)
#   SSH_KEY       Path to the private key matching terraform var.public_key
#   CONFIG        Path to your filled-in bridgefu.yaml (region + instance/flow IDs)
#
# Optional:
#   SSH_USER      Login user (default: ec2-user)
#   REMOTE_DIR    Build dir on the instance (default: /opt/build)
#
# Example:
#   INSTANCE_IP=$(terraform -chdir=terraform output -raw public_ip) \
#   SSH_KEY=~/.ssh/id_ed25519 CONFIG=./bridgefu.yaml ./deploy.sh
set -euo pipefail

: "${INSTANCE_IP:?set INSTANCE_IP (e.g. terraform output -raw public_ip)}"
: "${SSH_KEY:?set SSH_KEY (path to the private key)}"
: "${CONFIG:?set CONFIG (path to your bridgefu.yaml)}"
SSH_USER="${SSH_USER:-ec2-user}"
REMOTE_DIR="${REMOTE_DIR:-/opt/build}"

if [ ! -f "$CONFIG" ]; then
  echo "CONFIG file not found: $CONFIG" >&2
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SSH_OPTS=(-i "$SSH_KEY" -o StrictHostKeyChecking=accept-new -o ServerAliveInterval=30)
REMOTE="${SSH_USER}@${INSTANCE_IP}"

ssh_run() { ssh "${SSH_OPTS[@]}" "$REMOTE" "$@"; }

echo "==> [1/5] Syncing bridgefu source to ${REMOTE}:${REMOTE_DIR}/bridgefu"
rsync -az --delete \
  --exclude '.git' \
  --exclude 'target' \
  --exclude '*.log' \
  --exclude 'terraform/.terraform' \
  --exclude 'terraform/terraform.tfstate*' \
  -e "ssh ${SSH_OPTS[*]}" \
  "${REPO_ROOT}/" "${REMOTE}:${REMOTE_DIR}/bridgefu/"

echo "==> [2/5] Installing config to /etc/bridgefu/bridgefu.yaml"
scp "${SSH_OPTS[@]}" "$CONFIG" "${REMOTE}:/tmp/bridgefu.yaml"
ssh_run "sudo install -D -m 0644 /tmp/bridgefu.yaml /etc/bridgefu/bridgefu.yaml && rm -f /tmp/bridgefu.yaml"

echo "==> [3/5] Building image on instance (first cold build is slow; crates.io deps cache after)"
ssh_run "set -e
  cd '${REMOTE_DIR}/bridgefu'
  docker build -t bridgefu:latest -f deploy/Dockerfile ."

echo "==> [4/5] Installing + (re)starting systemd service"
ssh_run "sudo install -D -m 0644 '${REMOTE_DIR}/bridgefu/deploy/bridgefu.service' /etc/systemd/system/bridgefu.service \
  && sudo systemctl daemon-reload \
  && sudo systemctl enable bridgefu \
  && sudo systemctl restart bridgefu"

echo "==> [5/5] Waiting for /healthz"
ok=""
for i in $(seq 1 30); do
  if ssh_run "curl -fsS http://localhost:9090/healthz >/dev/null 2>&1"; then
    ok=1
    break
  fi
  sleep 2
done

echo
if [ -n "$ok" ]; then
  echo "✅ bridgefu is healthy on ${INSTANCE_IP}"
else
  echo "⚠️  /healthz did not come up in time — recent logs:" >&2
fi
echo "----- journalctl -u bridgefu (last 30 lines) -----"
ssh_run "sudo journalctl -u bridgefu -n 30 --no-pager" || true
echo "--------------------------------------------------"
echo "SIP target:   sip:${INSTANCE_IP}:5060"
echo "Metrics:      http://${INSTANCE_IP}:9090/metrics  (from admin_cidr)"
echo "Live logs:    ssh ${REMOTE} 'sudo journalctl -u bridgefu -f'"

[ -n "$ok" ]
