#!/usr/bin/env bash
set -euo pipefail

if [[ $(id -u) -ne 0 ]]; then
  echo "Bridgefu HA bootstrap must run as root" >&2
  exit 1
fi
source /etc/bridgefu/runtime.conf
if [[ "$BRIDGEFU_ROLE" != gateway && "$BRIDGEFU_ROLE" != worker ]]; then
  echo "Bridgefu HA role is invalid" >&2
  exit 1
fi

systemctl stop ecs.service 2>/dev/null || true
dnf install -y iproute-tc jq openssl python3 amazon-cloudwatch-agent
getent group bridgefu >/dev/null || groupadd --system --gid 65532 bridgefu
install -d -o root -g bridgefu -m 0750 \
  /etc/bridgefu /etc/bridgefu/tls /etc/bridgefu/private \
  /run/bridgefu /run/bridgefu/secrets
install -d -o root -g root -m 0755 \
  /opt/aws/amazon-cloudwatch-agent/var \
  /opt/aws/amazon-cloudwatch-agent/etc

install -o root -g root -m 0755 \
  "$BRIDGEFU_BUNDLE_DIR/bridgefu-ha-load-secrets.py" \
  /usr/local/sbin/bridgefu-ha-load-secrets
install -o root -g root -m 0755 \
  "$BRIDGEFU_BUNDLE_DIR/render-ha.py" \
  /usr/local/sbin/bridgefu-render-ha
install -o root -g root -m 0755 \
  "$BRIDGEFU_BUNDLE_DIR/bridgefu-ha-scale-protection" \
  /usr/local/sbin/bridgefu-ha-scale-protection
install -o root -g root -m 0644 \
  "$BRIDGEFU_BUNDLE_DIR/bridgefu-ha-scale-protection.service" \
  /etc/systemd/system/bridgefu-ha-scale-protection.service
install -o root -g root -m 0644 \
  "$BRIDGEFU_BUNDLE_DIR/bridgefu-ha-scale-protection.timer" \
  /etc/systemd/system/bridgefu-ha-scale-protection.timer
/usr/local/sbin/bridgefu-ha-load-secrets
/usr/local/sbin/bridgefu-render-ha
chown root:bridgefu /etc/bridgefu/bridgefu.yaml

if [[ "$BRIDGEFU_ROLE" == gateway ]]; then
  install -o root -g root -m 0755 \
    "$BRIDGEFU_BUNDLE_DIR/bridgefu-ha-cert-refresh" \
    /usr/local/sbin/bridgefu-ha-cert-refresh
  install -o root -g root -m 0755 \
    "$BRIDGEFU_BUNDLE_DIR/bridgefu-ha-cert-reload" \
    /usr/local/sbin/bridgefu-ha-cert-reload
  install -o root -g root -m 0644 \
    "$BRIDGEFU_BUNDLE_DIR/bridgefu-ha-cert-refresh.service" \
    /etc/systemd/system/bridgefu-ha-cert-refresh.service
  install -o root -g root -m 0644 \
    "$BRIDGEFU_BUNDLE_DIR/bridgefu-ha-cert-refresh.timer" \
    /etc/systemd/system/bridgefu-ha-cert-refresh.timer
  install -o root -g root -m 0644 \
    "$BRIDGEFU_BUNDLE_DIR/bridgefu-ha-cert-reload.service" \
    /etc/systemd/system/bridgefu-ha-cert-reload.service
  install -o root -g root -m 0644 \
    "$BRIDGEFU_BUNDLE_DIR/bridgefu-ha-cert-reload.timer" \
    /etc/systemd/system/bridgefu-ha-cert-reload.timer
  /usr/local/sbin/bridgefu-ha-cert-refresh
  systemctl daemon-reload
  systemctl enable --now \
    bridgefu-ha-cert-refresh.timer \
    bridgefu-ha-cert-reload.timer
fi

cat > /etc/ecs/ecs.config <<EOF
ECS_CLUSTER=$BRIDGEFU_ECS_CLUSTER
ECS_ENABLE_TASK_IAM_ROLE=true
ECS_ENABLE_TASK_IAM_ROLE_NETWORK_HOST=true
ECS_ENABLE_CONTAINER_METADATA=true
ECS_IMAGE_CLEANUP_INTERVAL=30m
ECS_IMAGE_MINIMUM_CLEANUP_AGE=1h
ECS_RESERVED_MEMORY=256
ECS_INSTANCE_ATTRIBUTES={"bridgefu.role":"$BRIDGEFU_ROLE","bridgefu.slot":"$BRIDGEFU_SLOT"}
EOF
chmod 0600 /etc/ecs/ecs.config

cat > /etc/sysctl.d/90-bridgefu-media.conf <<'EOF'
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.netdev_max_backlog = 8192
EOF
sysctl --system >/dev/null

/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
  -a fetch-config -m ec2 -s \
  -c file:/opt/aws/amazon-cloudwatch-agent/etc/bridgefu.json
systemctl enable --now ecs.service
systemctl daemon-reload
systemctl enable --now bridgefu-ha-scale-protection.timer
