#!/usr/bin/env bash
set -euo pipefail

image="postgres:17.5-alpine@sha256:6567bca8d7bc8c82c5922425a0baee57be8402df92bae5eacad5f01ae9544daa"
container="bridgefu-repository-test-${PPID}-$$"

cleanup() {
  docker rm -f "${container}" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

docker run --detach --rm \
  --name "${container}" \
  --env POSTGRES_USER=bridgefu \
  --env POSTGRES_PASSWORD=bridgefu-test-only \
  --env POSTGRES_DB=bridgefu_repository_test \
  --publish 127.0.0.1::5432 \
  "${image}" >/dev/null

for _ in $(seq 1 60); do
  if docker exec "${container}" pg_isready \
    --username bridgefu \
    --dbname bridgefu_repository_test >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

if ! docker exec "${container}" pg_isready \
  --username bridgefu \
  --dbname bridgefu_repository_test >/dev/null 2>&1; then
  docker logs "${container}" >&2
  exit 1
fi

port="$(docker port "${container}" 5432/tcp | sed -E 's/.*:([0-9]+)$/\1/')"
export BRIDGEFU_TEST_POSTGRES_URL="postgres://bridgefu:bridgefu-test-only@127.0.0.1:${port}/bridgefu_repository_test"

cargo test --locked --test repository_conformance -- --nocapture --test-threads=1
cargo test --locked --test call_service_repository_conformance -- --nocapture --test-threads=1
