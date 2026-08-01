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
capture_mode="${RVOIP_CAPTURE_MODE:-release}"
reviewed_revision="${RVOIP_REVIEWED_REVISION:-}"

case "${capture_mode}" in
  release | diagnostic) ;;
  *)
    echo "RVOIP_CAPTURE_MODE must be 'release' or 'diagnostic'" >&2
    exit 2
    ;;
esac

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

rvoip_revision_before="$(git -C "${rvoip_root}" rev-parse HEAD)"
rvoip_status_before="$(git -C "${rvoip_root}" status --porcelain=v1 --untracked-files=all)"
rvoip_status_fingerprint_before="$(
  printf '%s' "${rvoip_status_before}" | git -C "${rvoip_root}" hash-object --stdin
)"

if [[ -n "${reviewed_revision}" ]]; then
  if [[ ! "${reviewed_revision}" =~ ^[0-9a-f]{40}$ ]]; then
    echo "RVOIP_REVIEWED_REVISION must be an exact lowercase 40-character Git commit" >&2
    exit 2
  fi
  if ! git -C "${rvoip_root}" cat-file -e "${reviewed_revision}^{commit}" 2>/dev/null; then
    echo "reviewed rvoip revision is not present in the checkout: ${reviewed_revision}" >&2
    exit 2
  fi
  if [[ "${rvoip_revision_before}" != "${reviewed_revision}" ]]; then
    echo "rvoip HEAD ${rvoip_revision_before} does not match reviewed revision ${reviewed_revision}" >&2
    exit 2
  fi
fi

if [[ "${capture_mode}" == "release" ]]; then
  if [[ -z "${reviewed_revision}" ]]; then
    echo "release capture requires RVOIP_REVIEWED_REVISION with the exact reviewed commit" >&2
    exit 2
  fi
  if [[ -n "${rvoip_status_before}" ]]; then
    echo "release capture requires a clean rvoip worktree" >&2
    exit 2
  fi
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
  cargo test --locked -p rvoip-moq --all-features --test managed_relay_e2e \
    -- --test-threads=1 --nocapture
) 2>&1 | tee "${test_log}"

test_summary="$(
  rg '^test result: ok\. [0-9]+ passed; [0-9]+ failed;' "${test_log}" |
    tail -n 1 || true
)"
if [[ -z "${test_summary}" ]]; then
  echo "managed relay test log contains no successful test summary" >&2
  exit 1
fi
managed_tests_passed="$(
  sed -E 's/^test result: ok\. ([0-9]+) passed;.*$/\1/' <<<"${test_summary}"
)"
managed_tests_failed="$(
  sed -E 's/^test result: ok\. [0-9]+ passed; ([0-9]+) failed;.*$/\1/' <<<"${test_summary}"
)"

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

rvoip_revision_after="$(git -C "${rvoip_root}" rev-parse HEAD)"
rvoip_status_after="$(git -C "${rvoip_root}" status --porcelain=v1 --untracked-files=all)"
rvoip_status_fingerprint_after="$(
  printf '%s' "${rvoip_status_after}" | git -C "${rvoip_root}" hash-object --stdin
)"
source_stable=false
if [[
  "${rvoip_revision_after}" == "${rvoip_revision_before}" &&
    "${rvoip_status_fingerprint_after}" == "${rvoip_status_fingerprint_before}"
]]; then
  source_stable=true
fi

source_clean_before=false
source_clean_after=false
[[ -z "${rvoip_status_before}" ]] && source_clean_before=true
[[ -z "${rvoip_status_after}" ]] && source_clean_after=true

if [[ "${capture_mode}" == "release" ]]; then
  if [[
    "${rvoip_revision_after}" != "${reviewed_revision}" ||
      "${source_clean_after}" != true ||
      "${source_stable}" != true
  ]]; then
    echo "rvoip revision or worktree changed during release capture; evidence is rejected" >&2
    exit 1
  fi
fi

release_qualified=false
if [[
  "${capture_mode}" == "release" &&
    "${rvoip_revision_after}" == "${reviewed_revision}" &&
    "${source_clean_before}" == true &&
    "${source_clean_after}" == true &&
    "${source_stable}" == true
]]; then
  release_qualified=true
fi

wire_revision="$(
  rg 'moq-transport = .*rev = "[0-9a-f]{40}"' "${rvoip_root}/Cargo.toml" |
    rg -o '[0-9a-f]{40}' |
    head -n 1 || true
)"
if [[ -n "${wire_revision}" ]]; then
  wire_source_kind="pinned-git"
elif rg -q \
  'moq-transport = .*package = "rvoip-moq-transport".*path = ' \
  "${rvoip_root}/Cargo.toml"; then
  wire_source_kind="reviewed-rvoip-tree"
  wire_revision="${rvoip_revision_after}"
else
  echo "could not prove the MOQT wire engine source revision" >&2
  exit 1
fi

jq -n \
  --arg generatedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg captureInterface "${capture_interface}" \
  --arg captureFile "${capture_file}" \
  --arg captureSha256 "${capture_sha256}" \
  --arg captureMode "${capture_mode}" \
  --arg rvoipRevision "${rvoip_revision_after}" \
  --arg reviewedRvoipRevision "${reviewed_revision}" \
  --arg sourceStatusFingerprintBefore "${rvoip_status_fingerprint_before}" \
  --arg sourceStatusFingerprintAfter "${rvoip_status_fingerprint_after}" \
  --arg wireSourceKind "${wire_source_kind}" \
  --arg wireRevision "${wire_revision}" \
  --argjson releaseQualified "${release_qualified}" \
  --argjson sourceCleanBefore "${source_clean_before}" \
  --argjson sourceCleanAfter "${source_clean_after}" \
  --argjson sourceStable "${source_stable}" \
  --argjson packetCount "${packet_count}" \
  --argjson captureBytes "${capture_bytes}" \
  --argjson managedTestsPassed "${managed_tests_passed}" \
  --argjson managedTestsFailed "${managed_tests_failed}" \
  --argjson rawMoqt19Handshakes "${raw_moqt_handshakes}" \
  --argjson webTransportH3Handshakes "${webtransport_handshakes}" \
  '{
    generatedAt: $generatedAt,
    captureMode: $captureMode,
    releaseQualified: $releaseQualified,
    captureInterface: $captureInterface,
    captureFile: $captureFile,
    captureSha256: $captureSha256,
    packetCount: $packetCount,
    captureBytes: $captureBytes,
    rvoipRevision: $rvoipRevision,
    reviewedRvoipRevision: (
      if $reviewedRvoipRevision == "" then null else $reviewedRvoipRevision end
    ),
    source: {
      cleanBefore: $sourceCleanBefore,
      cleanAfter: $sourceCleanAfter,
      stableDuringCapture: $sourceStable,
      statusFingerprintBefore: $sourceStatusFingerprintBefore,
      statusFingerprintAfter: $sourceStatusFingerprintAfter
    },
    wireRevision: $wireRevision,
    wireSource: {
      kind: $wireSourceKind,
      revision: $wireRevision
    },
    keyLogEnabled: false,
    managedRelayTests: {
      passed: $managedTestsPassed,
      failed: $managedTestsFailed
    },
    rawQuic: {alpn: "moqt-19", handshakePackets: $rawMoqt19Handshakes},
    webTransport: {alpn: "h3", handshakePackets: $webTransportH3Handshakes}
  }' | tee "${report_file}"

echo "MOQT packet-capture evidence: ${artifact_dir}"
