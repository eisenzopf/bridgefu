#!/usr/bin/env bash
set -euo pipefail

if [[ $(id -u) -ne 0 ]]; then
  echo "Bridgefu bootstrap must run as root" >&2
  exit 1
fi

set -a
# shellcheck source=/dev/null
source /etc/bridgefu/runtime.conf
set +a

bundle=/opt/bridgefu/bootstrap
install -d -o root -g root -m 0755 /run/bridgefu
install -d -o root -g 65532 -m 0750 /etc/bridgefu /etc/bridgefu/tls
install -d -o 65532 -g 65532 -m 0750 /var/lib/bridgefu
install -o root -g root -m 0755 "$bundle/bridgefu-load-secrets" /usr/local/sbin/bridgefu-load-secrets
install -o root -g root -m 0755 "$bundle/bridgefu-pull-image" /usr/local/sbin/bridgefu-pull-image
install -o root -g root -m 0644 "$bundle/bridgefu.service" /etc/systemd/system/bridgefu.service

origin_verify="$(aws secretsmanager get-secret-value --region "$AWS_REGION" \
  --secret-id "$BRIDGEFU_ORIGIN_VERIFY_SECRET_ARN" --query SecretString --output text)"
export BRIDGEFU_ORIGIN_VERIFY="$origin_verify"
python3 "$bundle/render.py"
unset BRIDGEFU_ORIGIN_VERIFY origin_verify
chown root:65532 /etc/bridgefu/bridgefu.yaml

openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 30 \
  -subj '/CN=bridgefu-loopback' \
  -addext 'subjectAltName=IP:127.0.0.1,DNS:localhost' \
  -keyout /etc/bridgefu/tls/signaling.key \
  -out /etc/bridgefu/tls/signaling.crt >/dev/null 2>&1
chown root:65532 /etc/bridgefu/tls/signaling.key /etc/bridgefu/tls/signaling.crt
chmod 0640 /etc/bridgefu/tls/signaling.key /etc/bridgefu/tls/signaling.crt

systemctl daemon-reload
systemctl enable --now docker.service
nginx -t
systemctl enable --now nginx.service
if ! systemctl enable --now bridgefu.service; then
  systemctl status --no-pager --lines=60 bridgefu.service nginx.service >&2 || true
  journalctl --no-pager --lines=120 --unit=bridgefu.service >&2 || true
  exit 1
fi

for _ in $(seq 1 120); do
  if curl -fsS --max-time 2 http://127.0.0.1:9090/readyz >/dev/null \
    && curl -fsS --max-time 2 http://127.0.0.1:8080/origin-healthz >/dev/null; then
    exit 0
  fi
  sleep 2
done
systemctl status --no-pager --lines=60 bridgefu.service nginx.service >&2 || true
exit 1
