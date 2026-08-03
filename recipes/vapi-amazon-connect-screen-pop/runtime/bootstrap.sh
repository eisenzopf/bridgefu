#!/usr/bin/env bash
set -euo pipefail

if [[ $(id -u) -ne 0 ]]; then
  echo "Bridgefu bootstrap must run as root" >&2
  exit 1
fi
set -a
source /etc/bridgefu/runtime.conf
set +a

record_step() {
  if [[ -n "${BRIDGEFU_BOOTSTRAP_STATUS_FILE:-}" ]]; then
    printf '%s\n' "$1" > "$BRIDGEFU_BOOTSTRAP_STATUS_FILE"
  fi
}

record_step data-volume-discovery
getent group bridgefu >/dev/null || groupadd --system --gid 65532 bridgefu
install -d -o root -g bridgefu -m 0750 /etc/bridgefu /etc/bridgefu/tls
install -d -o 65532 -g bridgefu -m 0750 /var/lib/bridgefu
install -d -o root -g root -m 0755 /run/bridgefu

root_source="$(findmnt -n -o SOURCE /)"
root_parent="$(lsblk -n -o PKNAME "$root_source" | head -n1)"
data_device=''
for _ in $(seq 1 90); do
  candidates=()
  for path in /dev/nvme*n1 /dev/xvd?; do
    [[ -b "$path" ]] || continue
    [[ "$(basename "$path")" == "$root_parent" ]] && continue
    if ! lsblk -n -o MOUNTPOINT "$path" | grep -q '/'; then
      candidates+=("$path")
    fi
  done
  if [[ ${#candidates[@]} -eq 1 ]]; then
    data_device="${candidates[0]}"
    break
  fi
  sleep 2
done
if [[ -z "$data_device" ]]; then
  echo "Unable to identify the dedicated Bridgefu data volume" >&2
  exit 1
fi

record_step data-volume-format
filesystem="$(blkid -s TYPE -o value "$data_device" || true)"
if [[ -z "$filesystem" ]]; then
  mkfs.xfs -f "$data_device" >/dev/null
  filesystem=xfs
elif [[ "$filesystem" != xfs ]]; then
  echo "Unexpected filesystem on the Bridgefu data volume" >&2
  exit 1
fi
uuid="$(blkid -s UUID -o value "$data_device")"
if ! grep -q "UUID=$uuid" /etc/fstab; then
  printf 'UUID=%s /var/lib/bridgefu xfs defaults,nofail,noatime,nodev,nosuid 0 2\n' "$uuid" >> /etc/fstab
fi
mount /var/lib/bridgefu || mount -a
chown 65532:bridgefu /var/lib/bridgefu
chmod 0750 /var/lib/bridgefu

record_step runtime-assets-install
install -o root -g root -m 0755 "$BRIDGEFU_BUNDLE_DIR/bridgefu-load-secrets" /usr/local/sbin/bridgefu-load-secrets
install -o root -g root -m 0755 "$BRIDGEFU_BUNDLE_DIR/bridgefu-pull-image" /usr/local/sbin/bridgefu-pull-image
install -o root -g root -m 0644 "$BRIDGEFU_BUNDLE_DIR/bridgefu.service" /etc/systemd/system/bridgefu.service
if [[ "$BRIDGEFU_SIP_SECURITY" == sips_srtp ]]; then
  install -o root -g root -m 0755 "$BRIDGEFU_BUNDLE_DIR/bridgefu-cert-refresh" /usr/local/sbin/bridgefu-cert-refresh
  install -o root -g root -m 0755 "$BRIDGEFU_BUNDLE_DIR/bridgefu-cert-reload" /usr/local/sbin/bridgefu-cert-reload
  install -o root -g root -m 0644 "$BRIDGEFU_BUNDLE_DIR/bridgefu-cert-refresh.service" /etc/systemd/system/bridgefu-cert-refresh.service
  install -o root -g root -m 0644 "$BRIDGEFU_BUNDLE_DIR/bridgefu-cert-refresh.timer" /etc/systemd/system/bridgefu-cert-refresh.timer
  install -o root -g root -m 0644 "$BRIDGEFU_BUNDLE_DIR/bridgefu-cert-reload.service" /etc/systemd/system/bridgefu-cert-reload.service
  install -o root -g root -m 0644 "$BRIDGEFU_BUNDLE_DIR/bridgefu-cert-reload.timer" /etc/systemd/system/bridgefu-cert-reload.timer
fi

record_step runtime-config-render
BRIDGEFU_PRIVATE_IP="$(TOKEN="$(curl -fsS -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' http://169.254.169.254/latest/api/token)"; curl -fsS -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/local-ipv4)"
export BRIDGEFU_PRIVATE_IP
python3 "$BRIDGEFU_BUNDLE_DIR/render.py"
chown root:bridgefu /etc/bridgefu/bridgefu.yaml
chown root:haproxy /etc/haproxy/haproxy.cfg

record_step docker-start
systemctl daemon-reload
systemctl enable --now docker.service
if [[ "$BRIDGEFU_SIP_SECURITY" == sips_srtp ]]; then
  /usr/local/sbin/bridgefu-cert-refresh
fi
record_step proxy-start
systemctl enable --now haproxy.service
if [[ "$BRIDGEFU_SIP_SECURITY" == sips_srtp ]]; then
  systemctl enable bridgefu-cert-refresh.timer bridgefu-cert-reload.timer
  systemctl start bridgefu-cert-refresh.timer bridgefu-cert-reload.timer
fi

record_step cloudwatch-agent-start
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
  -a fetch-config -m ec2 -s \
  -c file:/opt/aws/amazon-cloudwatch-agent/etc/bridgefu.json
record_step bridgefu-service-start
if ! systemctl enable --now bridgefu.service; then
  systemctl status --no-pager --lines=40 bridgefu.service >&2 || true
  journalctl --no-pager --lines=80 --unit=bridgefu.service >&2 || true
  exit 1
fi

record_step bridgefu-readiness
for _ in $(seq 1 90); do
  if curl --silent --fail --max-time 2 http://127.0.0.1:9090/readyz >/dev/null; then
    break
  fi
  sleep 2
done
curl --silent --fail --max-time 3 http://127.0.0.1:9090/readyz >/dev/null
record_step control-readiness
control_ready=false
for _ in $(seq 1 30); do
  if [[ "$BRIDGEFU_SIP_SECURITY" == sips_srtp ]]; then
    if curl --silent --fail --max-time 3 \
      --resolve "$BRIDGEFU_CONTROL_HOSTNAME:443:$BRIDGEFU_PRIVATE_IP" \
      --cacert /etc/bridgefu/tls/fullchain.pem \
      "https://$BRIDGEFU_CONTROL_HOSTNAME/readyz" >/dev/null \
      && echo | openssl s_client \
        -connect 127.0.0.1:5061 \
        -servername "$BRIDGEFU_SIP_HOSTNAME" \
        -verify_hostname "$BRIDGEFU_SIP_HOSTNAME" \
        -CAfile /etc/bridgefu/tls/fullchain.pem \
        -brief >/dev/null 2>&1; then
      control_ready=true
      break
    fi
  elif curl --silent --fail --max-time 3 \
    --resolve "$BRIDGEFU_CONTROL_HOSTNAME:443:$BRIDGEFU_PRIVATE_IP" \
    "http://$BRIDGEFU_CONTROL_HOSTNAME:443/readyz" >/dev/null; then
    control_ready=true
    break
  fi
  sleep 2
done
if [[ "$control_ready" != true ]]; then
  echo "Bridgefu control proxy did not become ready" >&2
  systemctl status --no-pager --lines=40 haproxy.service bridgefu.service >&2 || true
  exit 1
fi
