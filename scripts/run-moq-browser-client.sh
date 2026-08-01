#!/usr/bin/env bash
set -euo pipefail

readonly MOQ_DEV_REPOSITORY="https://github.com/moq-dev/moq.git"
readonly MOQ_DEV_REVISION="ea97ce44470e35a49f5f18acf8ad96daa37aabea"

for command in git node npm; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "required command is unavailable: ${command}" >&2
    exit 2
  fi
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fixture="${repo_root}/tests/moq-browser-e2e"
run_dir="$(mktemp -d)"
source_dir="${run_dir}/moq-dev"
app_dir="${run_dir}/bridgefu-moq-browser-e2e"

cleanup() {
  rm -rf "${run_dir}"
}
trap cleanup EXIT INT TERM

git init -q "${source_dir}"
git -C "${source_dir}" remote add origin "${MOQ_DEV_REPOSITORY}"
git -C "${source_dir}" fetch -q --depth=1 origin "${MOQ_DEV_REVISION}"
git -C "${source_dir}" checkout -q --detach FETCH_HEAD
test "$(git -C "${source_dir}" rev-parse HEAD)" = "${MOQ_DEV_REVISION}"
node "${fixture}/patch-moq-dev.mjs" "${source_dir}"

mkdir -p "${app_dir}"
cp "${fixture}/package.json" "${fixture}/package-lock.json" "${fixture}/vite.config.ts" "${fixture}/index.html" "${app_dir}/"
cp -R "${fixture}/src" "${app_dir}/src"
(
  cd "${app_dir}"
  npm ci --ignore-scripts --no-audit --no-fund
)

export MOQ_DEV_SOURCE="${source_dir}"
cd "${app_dir}"
exec npm run dev -- --port "${MOQ_BROWSER_APP_PORT:-4173}"
