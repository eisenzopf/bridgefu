#!/usr/bin/env bash
set -euo pipefail

# Reproduce the currently qualifying independent MOQT draft-19 WebTransport
# flow and the two known independent-client capability gaps. This script never
# edits either implementation and never contacts maintainers.

readonly MOQ_DEV_REPOSITORY="https://github.com/moq-dev/moq.git"
readonly MOQ_DEV_REVISION="ea97ce44470e35a49f5f18acf8ad96daa37aabea"
readonly MOQ_RS_REVISION="ef52ac8656513bb3b07b4b9b80152ac24bb2467e"

for command in cargo git jq openssl rg; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "required command is unavailable: ${command}" >&2
    exit 2
  fi
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
moq_rs_source="${MOQ_RS_DIR:-${repo_root}/../moq-rs}"
artifact_dir="${ARTIFACT_DIR:-${repo_root}/moq-interop-artifacts}"
port="${MOQ_INTEROP_PORT:-45543}"
deadline_seconds="${MOQ_INTEROP_TIMEOUT_SECONDS:-30}"
run_dir="$(mktemp -d)"
target_dir="${CARGO_TARGET_DIR:-${run_dir}/target}"
candidate_dir=""
fork_worktree="${run_dir}/moq-rs"
pids=()

cleanup() {
  set +e
  for pid in "${pids[@]:-}"; do
    if [[ -n "${pid}" ]]; then
      kill "${pid}" 2>/dev/null || true
    fi
  done
  for pid in "${pids[@]:-}"; do
    if [[ -n "${pid}" ]]; then
      wait "${pid}" 2>/dev/null || true
    fi
  done
  if [[ -d "${fork_worktree}" ]]; then
    git -C "${moq_rs_source}" worktree remove --force "${fork_worktree}" >/dev/null 2>&1 || true
  fi
  rm -rf "${run_dir}"
}
trap cleanup EXIT INT TERM

wait_for_pattern() {
  local file="$1"
  local pattern="$2"
  local description="$3"
  local deadline=$((SECONDS + deadline_seconds))
  while ((SECONDS < deadline)); do
    if [[ -f "${file}" ]] && rg -q -- "${pattern}" "${file}"; then
      return 0
    fi
    sleep 0.2
  done
  echo "timed out waiting for ${description}; inspect ${file}" >&2
  return 1
}

stop_pid() {
  local pid="$1"
  kill "${pid}" 2>/dev/null || true
  wait "${pid}" 2>/dev/null || true
  local index
  for index in "${!pids[@]}"; do
    if [[ "${pids[${index}]}" = "${pid}" ]]; then
      pids[${index}]=""
    fi
  done
}

mkdir -p "${artifact_dir}"

if ! git -C "${moq_rs_source}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "private moq-rs checkout not found: ${moq_rs_source}" >&2
  echo "set MOQ_RS_DIR to the local private-fork checkout" >&2
  exit 2
fi
git -C "${moq_rs_source}" cat-file -e "${MOQ_RS_REVISION}^{commit}"
git -C "${moq_rs_source}" worktree add --detach "${fork_worktree}" "${MOQ_RS_REVISION}" >/dev/null

if [[ -n "${MOQ_DEV_DIR:-}" ]]; then
  candidate_dir="${MOQ_DEV_DIR}"
else
  candidate_dir="${run_dir}/moq-dev"
  git init -q "${candidate_dir}"
  git -C "${candidate_dir}" remote add origin "${MOQ_DEV_REPOSITORY}"
  git -C "${candidate_dir}" fetch -q --depth=1 origin "${MOQ_DEV_REVISION}"
  git -C "${candidate_dir}" checkout -q --detach FETCH_HEAD
fi

test "$(git -C "${candidate_dir}" rev-parse HEAD)" = "${MOQ_DEV_REVISION}"
if [[ -n "$(git -C "${candidate_dir}" status --porcelain --untracked-files=no)" ]]; then
  echo "independent candidate has tracked modifications: ${candidate_dir}" >&2
  exit 2
fi

export CARGO_TARGET_DIR="${target_dir}"
cargo build --manifest-path "${fork_worktree}/Cargo.toml" \
  -p moq-relay-ietf --bin moq-relay-ietf
cargo build --manifest-path "${candidate_dir}/Cargo.toml" \
  -p moq-native --example clock

publisher_dir="${run_dir}/publisher"
mkdir -p "${publisher_dir}/src"
cat >"${publisher_dir}/Cargo.toml" <<EOF
[package]
name = "bridgefu-moq-interop-publisher"
version = "0.0.0"
edition = "2021"
publish = false

[dependencies]
anyhow = "1"
bytes = "1"
moq-native-ietf = { path = "${fork_worktree}/moq-native-ietf" }
moq-transport = { path = "${fork_worktree}/moq-transport" }
tokio = { version = "1", features = ["macros", "rt-multi-thread", "time"] }
url = "2"
EOF

cat >"${publisher_dir}/src/main.rs" <<'EOF'
use std::{net::SocketAddr, time::Duration};

use anyhow::Context;
use bytes::Bytes;
use moq_native_ietf::quic;
use moq_transport::{
    coding::TrackNamespace,
    serve::{self, Subgroup},
    session::Publisher,
};
use url::Url;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let port = std::env::var("MOQ_INTEROP_PORT").context("MOQ_INTEROP_PORT")?;
    let tls = moq_native_ietf::tls::Args {
        disable_verify: true,
        ..Default::default()
    }
    .load()?;
    let endpoint = quic::Endpoint::new(quic::Config::new(
        "[::]:0".parse::<SocketAddr>()?,
        None,
        tls,
    )?)?;
    let url = Url::parse(&format!(
        "moqt://127.0.0.1:{port}/tenant/broadcast"
    ))?;
    let (target, policy) = quic::compatibility_target(&url)?;
    let connection = endpoint.client.connect_target(&target, policy, None).await?;
    let (session, mut publisher) = Publisher::connect(connection.session, connection.negotiated)
        .await
        .context("publisher session")?;

    let (mut tracks_writer, _, tracks_reader) = serve::Tracks {
        namespace: TrackNamespace::from_utf8_path("clock"),
    }
    .produce();
    let track = tracks_writer.create("now").context("create track")?;
    let mut subgroups = track.subgroups()?;

    let generate = async move {
        for group_id in 0_u64.. {
            let mut subgroup = subgroups.create(Subgroup {
                group_id,
                subgroup_id: 0,
                priority: 0,
                first_object: true,
                end_of_group: true,
            })?;
            subgroup.write(Bytes::from(format!("group-{group_id}:")))?;
            subgroup.write(Bytes::from_static(b"object"))?;
            drop(subgroup);
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };

    tokio::select! {
        result = session.run() => result.context("session")?,
        result = publisher.publish_namespace(tracks_reader) => result.context("publish namespace")?,
        result = generate => result.context("generate")?,
    }
    Ok(())
}
EOF
cargo build --manifest-path "${publisher_dir}/Cargo.toml"

tls_config="${run_dir}/openssl.cnf"
cat >"${tls_config}" <<'EOF'
[req]
distinguished_name = dn
x509_extensions = extensions
prompt = no
[dn]
CN = localhost
[extensions]
subjectAltName = @alt_names
[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF
openssl req -x509 -nodes -newkey rsa:2048 -days 1 \
  -config "${tls_config}" \
  -keyout "${run_dir}/localhost.key" \
  -out "${run_dir}/localhost.crt" >/dev/null 2>&1

relay_log="${artifact_dir}/relay.log"
publisher_log="${artifact_dir}/publisher.log"
wt_log="${artifact_dir}/moq-dev-webtransport.log"
raw_log="${artifact_dir}/moq-dev-raw-quic.log"
coordinator_file="${run_dir}/coordinator.json"
: >"${relay_log}"
: >"${publisher_log}"
: >"${wt_log}"
: >"${raw_log}"

RUST_LOG=debug "${target_dir}/debug/moq-relay-ietf" \
  --bind "127.0.0.1:${port}" \
  --tls-cert "${run_dir}/localhost.crt" \
  --tls-key "${run_dir}/localhost.key" \
  --insecure-development \
  --listener-security development \
  --coordinator-file "${coordinator_file}" \
  >"${relay_log}" 2>&1 &
relay_pid=$!
pids+=("${relay_pid}")
wait_for_pattern "${relay_log}" "listening on 127\\.0\\.0\\.1:${port}" "relay readiness"

MOQ_INTEROP_PORT="${port}" RUST_LOG=debug \
  "${target_dir}/debug/bridgefu-moq-interop-publisher" \
  >"${publisher_log}" 2>&1 &
publisher_pid=$!
pids+=("${publisher_pid}")
wait_for_pattern "${coordinator_file}" "636c6f636b" "clock namespace registration"

RUST_LOG=debug "${target_dir}/debug/examples/clock" \
  --broadcast clock \
  --track now \
  --client-connect "https://127.0.0.1:${port}/tenant/broadcast" \
  --client-version moq-transport-19 \
  --client-tls-disable-verify \
  --backoff-timeout 5s \
  subscribe >"${wt_log}" 2>&1 &
wt_pid=$!
pids+=("${wt_pid}")
wait_for_pattern "${wt_log}" "subscribe_namespace ok" "SUBSCRIBE_NAMESPACE acceptance"
wait_for_pattern "${wt_log}" "received subscribe ok" "SUBSCRIBE_OK"
wait_for_pattern "${wt_log}" "group-[0-9]+:object" "live MOQT Object"
stop_pid "${wt_pid}"

# The raw-QUIC attempt is an expected negative result for this exact
# independent revision: it does not emit draft-19 PATH/AUTHORITY SETUP options.
RUST_LOG=debug "${target_dir}/debug/examples/clock" \
  --broadcast clock \
  --track now \
  --client-connect "moqt://127.0.0.1:${port}/tenant/broadcast" \
  --client-version moq-transport-19 \
  --client-tls-disable-verify \
  --backoff-timeout 5s \
  subscribe >"${raw_log}" 2>&1 &
raw_pid=$!
pids+=("${raw_pid}")
wait_for_pattern "${relay_log}" "malformed connection authority: native QUIC clients must send AUTHORITY" \
  "the known raw-QUIC PATH/AUTHORITY blocker"
stop_pid "${raw_pid}"

setup_block="$(sed -n '/async fn run_setup/,/Accept incoming uni streams/p' \
  "${candidate_dir}/rs/moq-net/src/ietf/session.rs")"
setup_token_supported=false
if rg -q "Authorization|AUTHORIZATION" <<<"${setup_block}"; then
  setup_token_supported=true
fi

subscriber_fetch_supported=true
if rg -q 'FetchHeader::TYPE => Err\(Error::Unsupported\)' \
  "${candidate_dir}/rs/moq-net/src/ietf/session.rs"; then
  subscriber_fetch_supported=false
fi

test "$(git -C "${candidate_dir}" rev-parse HEAD)" = "${MOQ_DEV_REVISION}"
test -z "$(git -C "${candidate_dir}" status --porcelain --untracked-files=no)"

jq -n \
  --arg generatedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg independentRepository "${MOQ_DEV_REPOSITORY}" \
  --arg independentRevision "${MOQ_DEV_REVISION}" \
  --arg privateForkRevision "${MOQ_RS_REVISION}" \
  --argjson setupTokenSupported "${setup_token_supported}" \
  --argjson subscriberFetchSupported "${subscriber_fetch_supported}" \
  '{
    generatedAt: $generatedAt,
    gate5Complete: false,
    independent: {
      repository: $independentRepository,
      revision: $independentRevision,
      trackedSourceModified: false
    },
    privateForkRevision: $privateForkRevision,
    privateForkNamespaceDiscovery: {
      mode: "bounded-dynamic-coordinator-updates",
      dynamicUpdatesImplemented: true
    },
    webTransport: {
      status: "pass",
      protocol: "moqt-19",
      checks: ["SETUP", "SUBSCRIBE_NAMESPACE", "NAMESPACE", "SUBSCRIBE", "SUBSCRIBE_OK", "live-object"]
    },
    rawQuic: {
      status: "blocked-independent-peer",
      reason: "independent revision omits mandatory native PATH/AUTHORITY SETUP options"
    },
    setupAuthorizationToken: {
      supportedByIndependentSetupSender: $setupTokenSupported
    },
    retainedJoiningFetch: {
      status: "not-qualified",
      independentSubscriberSupport: $subscriberFetchSupported
    }
  }' | tee "${artifact_dir}/report.json"

echo "interop artifacts: ${artifact_dir}"
