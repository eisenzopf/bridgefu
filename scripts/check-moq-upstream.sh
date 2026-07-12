#!/usr/bin/env bash
set -euo pipefail

manifest="${1:-docs/moq-compatibility.json}"
report="${2:-moq-upstream-report.json}"

for command in curl jq awk; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "required command is unavailable: ${command}" >&2
    exit 2
  fi
done

if command -v sha256sum >/dev/null 2>&1; then
  hash_file() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
  hash_file() { shasum -a 256 "$1" | awk '{print $1}'; }
else
  echo "required SHA-256 command is unavailable (sha256sum or shasum)" >&2
  exit 2
fi

if [[ ! -f "${manifest}" ]]; then
  echo "compatibility manifest not found: ${manifest}" >&2
  exit 2
fi

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

drift=false
standards='[]'

while IFS=$'\t' read -r role name expected_revision expected_sha; do
  api_document="${tmp_dir}/${role}.json"
  archive_document="${tmp_dir}/${role}.txt"
  curl --fail --silent --show-error --location \
    "https://datatracker.ietf.org/api/v1/doc/document/?name=${name}" \
    --output "${api_document}"
  actual_revision="$(jq -er '.objects[0].rev' "${api_document}")"
  curl --fail --silent --show-error --location \
    "https://www.ietf.org/archive/id/${name}-${expected_revision}.txt" \
    --output "${archive_document}"
  actual_sha="$(hash_file "${archive_document}")"
  matches=true
  if [[ "${actual_revision}" != "${expected_revision}" || "${actual_sha}" != "${expected_sha}" ]]; then
    matches=false
    drift=true
  fi
  standards="$(jq \
    --arg role "${role}" \
    --arg name "${name}" \
    --arg expectedRevision "${expected_revision}" \
    --arg actualRevision "${actual_revision}" \
    --arg expectedArchiveSha256 "${expected_sha}" \
    --arg actualArchiveSha256 "${actual_sha}" \
    --argjson matches "${matches}" \
    '. + [{role: $role, name: $name, expectedRevision: $expectedRevision, actualRevision: $actualRevision, expectedArchiveSha256: $expectedArchiveSha256, actualArchiveSha256: $actualArchiveSha256, matches: $matches}]' \
    <<<"${standards}")"
done < <(jq -r '.standards | to_entries[] | [.key, .value.name, .value.revision, .value.archiveSha256] | @tsv' "${manifest}")

upstream_repo="$(jq -er '.wireLibrary.upstream' "${manifest}")"
fork_repo="$(jq -er '.wireLibrary.fork' "${manifest}")"
port_base="$(jq -er '.wireLibrary.portBaseRevision' "${manifest}")"
reviewed_fork="$(jq -r '.wireLibrary.reviewedForkRevision // ""' "${manifest}")"
upstream_head="$(curl --fail --silent --show-error --location \
  "https://api.github.com/repos/${upstream_repo}/commits/main" | jq -er '.sha')"
fork_head="$(curl --fail --silent --show-error --location \
  "https://api.github.com/repos/${fork_repo}/commits/main" | jq -er '.sha')"

jq -n \
  --arg generatedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --argjson drift "${drift}" \
  --argjson standards "${standards}" \
  --arg upstreamRepo "${upstream_repo}" \
  --arg upstreamHead "${upstream_head}" \
  --arg forkRepo "${fork_repo}" \
  --arg forkHead "${fork_head}" \
  --arg portBaseRevision "${port_base}" \
  --arg reviewedForkRevision "${reviewed_fork}" \
  '{generatedAt: $generatedAt, driftDetected: $drift, standards: $standards, wireLibrary: {upstream: $upstreamRepo, upstreamHead: $upstreamHead, fork: $forkRepo, forkMainHead: $forkHead, portBaseRevision: $portBaseRevision, reviewedForkRevision: (if $reviewedForkRevision == "" then null else $reviewedForkRevision end)}}' \
  >"${report}"

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    echo "## MOQT upstream watch"
    echo
    echo "This job is report-only. It never changes a dependency or contacts an upstream maintainer."
    echo
    jq -r '.standards[] | "- \(.name): pinned \(.expectedRevision), current \(.actualRevision), archive match=\(.matches)"' "${report}"
    echo "- ${upstream_repo} main: ${upstream_head}"
    echo "- Reviewed fork revision: ${reviewed_fork:-not yet pinned}"
    echo "- Drift detected: ${drift}"
  } >>"${GITHUB_STEP_SUMMARY}"
fi

jq . "${report}"
