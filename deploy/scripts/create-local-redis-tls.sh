#!/usr/bin/env bash
set -euo pipefail

destination="${1:?usage: create-local-redis-tls.sh DESTINATION}"
mkdir -p "$destination"
destination=$(cd "$destination" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 7 \
  -subj '/CN=Bridgefu local Redis CA' \
  -keyout "$work/ca.key" -out "$destination/ca.crt" >/dev/null 2>&1

openssl req -newkey rsa:3072 -sha256 -nodes \
  -subj '/CN=redis' \
  -keyout "$destination/redis.key" -out "$work/redis.csr" >/dev/null 2>&1

cat >"$work/extensions" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:redis,DNS:localhost,IP:127.0.0.1
EOF

openssl x509 -req -sha256 -days 7 \
  -in "$work/redis.csr" \
  -CA "$destination/ca.crt" -CAkey "$work/ca.key" -CAcreateserial \
  -extfile "$work/extensions" -out "$destination/redis.crt" >/dev/null 2>&1

openssl req -newkey rsa:3072 -sha256 -nodes \
  -subj '/CN=worker' \
  -keyout "$destination/worker.key" -out "$work/worker.csr" >/dev/null 2>&1

cat >"$work/worker-extensions" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:worker,DNS:localhost,IP:127.0.0.1
EOF

openssl x509 -req -sha256 -days 7 \
  -in "$work/worker.csr" \
  -CA "$destination/ca.crt" -CAkey "$work/ca.key" -CAcreateserial \
  -extfile "$work/worker-extensions" -out "$destination/worker.crt" >/dev/null 2>&1

openssl req -newkey rsa:3072 -sha256 -nodes \
  -subj '/CN=gateway' \
  -keyout "$destination/gateway.key" -out "$work/gateway.csr" >/dev/null 2>&1

cat >"$work/gateway-extensions" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
subjectAltName=DNS:gateway,DNS:localhost,IP:127.0.0.1
EOF

openssl x509 -req -sha256 -days 7 \
  -in "$work/gateway.csr" \
  -CA "$destination/ca.crt" -CAkey "$work/ca.key" -CAcreateserial \
  -extfile "$work/gateway-extensions" -out "$destination/gateway.crt" >/dev/null 2>&1

openssl req -newkey rsa:3072 -sha256 -nodes \
  -subj '/CN=public-uctp' \
  -keyout "$destination/public-uctp.key" -out "$work/public-uctp.csr" >/dev/null 2>&1

cat >"$work/public-uctp-extensions" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:gateway,DNS:public-uctp,DNS:localhost,IP:127.0.0.1
EOF

openssl x509 -req -sha256 -days 7 \
  -in "$work/public-uctp.csr" \
  -CA "$destination/ca.crt" -CAkey "$work/ca.key" -CAcreateserial \
  -extfile "$work/public-uctp-extensions" -out "$destination/public-uctp.crt" >/dev/null 2>&1

openssl req -newkey rsa:3072 -sha256 -nodes \
  -subj '/CN=bridgefu-public-api' \
  -keyout "$destination/public-api.key" -out "$work/public-api.csr" >/dev/null 2>&1

cat >"$work/public-api-extensions" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:gateway,DNS:localhost,IP:127.0.0.1
EOF

openssl x509 -req -sha256 -days 7 \
  -in "$work/public-api.csr" \
  -CA "$destination/ca.crt" -CAkey "$work/ca.key" -CAcreateserial \
  -extfile "$work/public-api-extensions" -out "$destination/public-api.crt" >/dev/null 2>&1

chmod 0600 \
  "$destination/redis.key" \
  "$destination/worker.key" \
  "$destination/gateway.key" \
  "$destination/public-uctp.key" \
  "$destination/public-api.key"
chmod 0644 \
  "$destination/ca.crt" \
  "$destination/redis.crt" \
  "$destination/worker.crt" \
  "$destination/gateway.crt" \
  "$destination/public-uctp.crt" \
  "$destination/public-api.crt"
printf 'created disposable Redis, gateway/worker mTLS, public UCTP, and HTTPS API TLS material in %s\n' "$destination"
