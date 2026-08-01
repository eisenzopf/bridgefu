#!/usr/bin/env bash
set -euo pipefail

postgres_image="postgres:17.5-alpine@sha256:6567bca8d7bc8c82c5922425a0baee57be8402df92bae5eacad5f01ae9544daa"
redis_image="redis:7.2-alpine@sha256:dfa18828cbc07b3ae6a95ec7343f6c214fdee2d836197b4be8e9904420762cd8"
postgres_container="bridgefu-coordination-postgres-${PPID}-$$"
redis_container="bridgefu-coordination-redis-${PPID}-$$"

cleanup() {
  docker rm -f "${postgres_container}" "${redis_container}" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

docker run --detach --rm \
  --name "${postgres_container}" \
  --env POSTGRES_USER=bridgefu \
  --env POSTGRES_PASSWORD=bridgefu-test-only \
  --env POSTGRES_DB=bridgefu_repository_test \
  --publish 127.0.0.1::5432 \
  "${postgres_image}" >/dev/null

docker run --detach --rm \
  --name "${redis_container}" \
  --publish 127.0.0.1::6379 \
  "${redis_image}" >/dev/null

for _ in $(seq 1 60); do
  if docker exec "${postgres_container}" pg_isready \
    --username bridgefu \
    --dbname bridgefu_repository_test >/dev/null 2>&1 && \
    docker exec "${redis_container}" redis-cli ping 2>/dev/null | grep -q '^PONG$'; then
    break
  fi
  sleep 1
done

if ! docker exec "${postgres_container}" pg_isready \
  --username bridgefu \
  --dbname bridgefu_repository_test >/dev/null 2>&1; then
  docker logs "${postgres_container}" >&2
  exit 1
fi

if ! docker exec "${redis_container}" redis-cli ping 2>/dev/null | grep -q '^PONG$'; then
  docker logs "${redis_container}" >&2
  exit 1
fi

postgres_port="$(docker port "${postgres_container}" 5432/tcp | sed -E 's/.*:([0-9]+)$/\1/')"
redis_port="$(docker port "${redis_container}" 6379/tcp | sed -E 's/.*:([0-9]+)$/\1/')"
export BRIDGEFU_TEST_POSTGRES_URL="postgres://bridgefu:bridgefu-test-only@127.0.0.1:${postgres_port}/bridgefu_repository_test"
export BRIDGEFU_TEST_REDIS_URL="redis://127.0.0.1:${redis_port}"

cargo test --locked --test coordination_sql -- --ignored --nocapture --test-threads=1
cargo test --locked --test redis_coordination -- --ignored --nocapture --test-threads=1
