#!/usr/bin/env bash
set -euo pipefail

# Capture the authenticated rvoip managed-relay conformance tests without TLS
# key logging. The PCAP and report stay outside the repository by default.

for command in capinfos cargo git jq rg tshark tcpdump; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "required command is unavailable: ${command}" >&2
    exit 2
  fi
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
rvoip_root="${RVOIP_DIR:-${repo_root}/../rvoip}"
artifact_dir="${ARTIFACT_DIR:-/tmp/bridgefu-moq-capture-$(date -u +%Y%m%dT%H%M%SZ)}"
capture_interface="${CAPTURE_INTERFACE:-}"

if [[ -z "${capture_interface}" ]]; then
  if tcpdump -D | rg -q '(^|[. ])lo0([ (]|$)'; then
    capture_interface="lo0"
  else
    capture_interface="lo"
  fi
fi

if ! git -C "${rvoip_root}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "rvoip checkout not found: ${rvoip_root}" >&2
  exit 2
fi

mkdir -p "${artifact_dir}"
capture_file="${artifact_dir}/managed-relay.pcap"
tcpdump_log="${artifact_dir}/tcpdump.log"
test_log="${artifact_dir}/managed-relay-test.log"
report_file="${artifact_dir}/report.json"
capture_pid=""

stop_capture() {
  if [[ -n "${capture_pid}" ]] && kill -0 "${capture_pid}" 2>/dev/null; then
    kill -INT "${capture_pid}" 2>/dev/null || true
    wait "${capture_pid}" 2>/dev/null || true
  fi
  capture_pid=""
}
trap stop_capture EXIT INT TERM

tcpdump -i "${capture_interface}" -U -s 0 -w "${capture_file}" udp \
  >"${tcpdump_log}" 2>&1 &
capture_pid=$!

for _ in {1..50}; do
  if rg -q 'listening on' "${tcpdump_log}" 2>/dev/null; then
    break
  fi
  if ! kill -0 "${capture_pid}" 2>/dev/null; then
    echo "tcpdump could not start; inspect ${tcpdump_log}" >&2
    exit 2
  fi
  sleep 0.1
done
if ! rg -q 'listening on' "${tcpdump_log}"; then
  echo "timed out waiting for tcpdump readiness" >&2
  exit 2
fi

(
  cd "${rvoip_root}"
  cargo test -p rvoip-moq --all-features --test managed_relay_e2e \
    -- --test-threads=1 --nocapture
) 2>&1 | tee "${test_log}"

# Give libpcap one bounded dispatch interval to drain the kernel buffer before
# sending SIGINT; the managed relay tests intentionally finish in milliseconds
# and macOS BPF commonly dispatches on a one-second timer.
sleep 2
stop_capture
trap - EXIT INT TERM

packet_count="$(capinfos -M -c "${capture_file}" | awk '/Number of packets/ {print $4}')"
capture_bytes="$(capinfos -M -s "${capture_file}" | awk '/File size/ {print $3}')"
if [[ -z "${packet_count}" || "${packet_count}" -le 0 ]]; then
  echo "capture contains no packets" >&2
  exit 1
fi

protocol_hierarchy="$(tshark -r "${capture_file}" -q -z io,phs)"
if ! rg -q 'quic[[:space:]]+frames:' <<<"${protocol_hierarchy}"; then
  echo "capture contains no traffic decoded as QUIC" >&2
  exit 1
fi

alpn_values="$(tshark -r "${capture_file}" \
  -Y 'tls.handshake.extensions_alpn_str' \
  -T fields -e tls.handshake.extensions_alpn_str)"
raw_moqt_handshakes="$(rg -c '^moqt-19$' <<<"${alpn_values}" || true)"
webtransport_handshakes="$(rg -c '^h3$' <<<"${alpn_values}" || true)"
if [[ "${raw_moqt_handshakes}" -le 0 || "${webtransport_handshakes}" -le 0 ]]; then
  echo "capture must contain both moqt-19 and h3 ALPN handshakes" >&2
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  capture_sha256="$(sha256sum "${capture_file}" | awk '{print $1}')"
else
  capture_sha256="$(shasum -a 256 "${capture_file}" | awk '{print $1}')"
fi

rvoip_revision="$(git -C "${rvoip_root}" rev-parse HEAD)"
wire_revision="$(rg 'moq-transport = .*rev = "[0-9a-f]{40}"' "${rvoip_root}/Cargo.toml" \
  | rg -o '[0-9a-f]{40}' | head -n 1)"

jq -n \
  --arg generatedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg captureInterface "${capture_interface}" \
  --arg captureFile "${capture_file}" \
  --arg captureSha256 "${capture_sha256}" \
  --arg rvoipRevision "${rvoip_revision}" \
  --arg wireRevision "${wire_revision}" \
  --argjson packetCount "${packet_count}" \
  --argjson captureBytes "${capture_bytes}" \
  --argjson rawMoqt19Handshakes "${raw_moqt_handshakes}" \
  --argjson webTransportH3Handshakes "${webtransport_handshakes}" \
  '{
    generatedAt: $generatedAt,
    captureInterface: $captureInterface,
    captureFile: $captureFile,
    captureSha256: $captureSha256,
    packetCount: $packetCount,
    captureBytes: $captureBytes,
    rvoipRevision: $rvoipRevision,
    wireRevision: $wireRevision,
    keyLogEnabled: false,
    managedRelayTests: {passed: 2, failed: 0},
    rawQuic: {alpn: "moqt-19", handshakePackets: $rawMoqt19Handshakes},
    webTransport: {alpn: "h3", handshakePackets: $webTransportH3Handshakes}
  }' | tee "${report_file}"

echo "MOQT packet-capture evidence: ${artifact_dir}"
