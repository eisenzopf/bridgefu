# Bridgefu 0.9.1 release checks

Local validation completed on November 23, 2026. The source is prepared for a
release PR. Push the candidate and pass CI plus the protected image-candidate
workflow before creating the release tag. No public image or tag is implied by
this report.

## What changed

- Stable SIPS routes can pass customer-selected SIP headers into Connect.
- Correlation IDs are optional per recipe. Field names, header names, and
  Connect attribute names remain customer configurable.
- Two [Vapi/Connect recipes](../examples/vapi-amazon-connect/README.md) provide
  assistants, Lambda code, Connect flows, setup instructions, and a live-test
  harness. CI now runs their configuration and handler tests.
- Customer-specific fixture names were replaced with generic names. Private
  example state, rendered local settings, and Terraform variables are excluded
  from Docker build contexts as well as source control.
- The Cargo package, lockfile, CLI, and all three OCI labels use `0.9.1`.

## Validation results

| Check | Result |
| --- | --- |
| Locked Rust all-target suite | 789 passed, 0 failed, 20 opt-in cases ignored |
| Strict all-target, all-feature Clippy | Passed |
| Rust formatting and Git whitespace | Passed |
| Example Python tests | 8 passed |
| Configuration schema and negative fixtures | Passed |
| Credential-free runtime smoke | All 9 checks passed, including Compose preflight |
| Database repository and coordination checks | 41 passed, including 6 opt-in cases from the all-target suite |
| Release-image policy and verifier unit tests | Passed; 10 verifier tests |
| ShellCheck | Passed |
| AWS/GCP Terraform formatting and validation | Passed; no infrastructure applied |
| Recipe documentation links | Passed |
| CLI version | `bridgefu 0.9.1` |

The database checks used isolated PostgreSQL 16.14 and Redis 7.2.7 processes.
The pinned Docker image could not unpack because the local Docker daemon
reported an `unpigz` I/O error. Both temporary database processes were stopped.
CI must still exercise its pinned PostgreSQL/Redis containers. macOS linking
emitted an unwind-table size warning; tests and strict Clippy completed.

## Privacy review

Gitleaks 8.30.1 scanned a snapshot of tracked files plus nonignored new files,
and the reachable Git history. Findings were reviewed: they were the repeated
synthetic key used by tests and `YOUR_TOKEN` in API documentation, not live
credentials. Known environment and private live-test credentials, IDs, and
addresses were also compared against the publishable tree. Only documented
placeholders and public provider signaling addresses overlapped.

No customer-branded fixture references, actual customer/test server IPs, or
known live secrets were found in the publishable tree. Loopback, private test
networks, documentation ranges, public DNS test values, and provider network
ranges remain intentionally. The unrelated Rust cryptography dependency and
ordinary telephone terminology remain unchanged. Private raw evidence stays
outside the repository.

## Repeat the checks

From the repository root, with the documented Rust toolchain, Python example
dependencies, Docker, Terraform, and ShellCheck installed:

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features --no-deps -- -D warnings
cargo test --locked --all-targets
python3 -m unittest discover -s examples/vapi-amazon-connect/tests -p 'test_*.py'
python3 scripts/check-config-schema.py
bash deploy/scripts/check-release-image.sh
python3 deploy/scripts/test_verify_multiarch_oci.py
python3 deploy/scripts/test_select_oci_platform.py
python3 deploy/scripts/test_verify_trivy_policy.py
shellcheck deploy.sh deploy/scripts/*.sh
bash scripts/test-repository-backends.sh
bash scripts/test-coordination-backends.sh
cargo build --locked --bin bridgefu
python3 deploy/scripts/runtime-smoke.py --binary target/debug/bridgefu \
  --output /tmp/bridgefu-runtime-smoke.json
terraform fmt -check -recursive deploy/terraform
terraform -chdir=deploy/terraform/aws init -backend=false -input=false
terraform -chdir=deploy/terraform/aws validate -no-color
terraform -chdir=deploy/terraform/gcp init -backend=false -input=false
terraform -chdir=deploy/terraform/gcp validate -no-color
git diff --check
```

The database scripts create and remove disposable containers. To reproduce the
local fallback instead, start isolated PostgreSQL and Redis 7.2 instances, set
`BRIDGEFU_TEST_POSTGRES_URL` and `BRIDGEFU_TEST_REDIS_URL` to those instances,
and run:

```sh
cargo test --locked --test repository_conformance \
  --test call_service_repository_conformance --test call_service_runtime \
  -- --test-threads=1
cargo test --locked --test coordination_sql --test redis_coordination \
  --test private_egress_redis -- --ignored --test-threads=1
```

Stop the isolated instances afterward. These checks use synthetic data.

## Live evidence and remaining release gate

Both actual Vapi → Bridgefu → Connect recipes passed on November 20. See
[the report](../examples/vapi-amazon-connect/tests/results.json) and
[reproduction instructions](../examples/vapi-amazon-connect/tests/E2E.md).
That report identifies the pre-version-bump source. The final local checks above
do not claim a new live cloud run. The calls used TLS with optional SRTP;
strict SRTP, mTLS, load qualification, and customer QA remain outside that evidence.

After pushing the final commit, run CI and dispatch
[release-image-candidate.yml](../.github/workflows/release-image-candidate.yml)
with that exact 40-character commit ID. Review the retained amd64/arm64 OCI
artifact, SBOM, provenance, and vulnerability-policy results. Only then tag
that same commit `v0.9.1` and publish the reviewed artifact. The candidate
workflow builds and scans; it does not publish an image.
