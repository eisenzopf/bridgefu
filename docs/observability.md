# Observability contract

Bridgefu emits structured logs, W3C-correlated OTLP traces, Prometheus metrics,
and authenticated tenant-scoped diagnostics. This page is the Bridgefu 1.0
release inventory; rvoip transport crates may add their own lower-level media,
ICE, DTLS, RTP, UCTP, and MOQT series to the same recorder.

## Surfaces

| Surface | Exposure | Contract |
|---|---|---|
| `/livez` | operational listener | Process can continue serving; it may still be draining or not ready. |
| `/readyz`, `/healthz` | operational listener | Dependencies and role lifecycle are ready for admission. |
| `/metrics` | operational listener | Prometheus text; keep the listener network-restricted. |
| `/diagnostics` | public API listener | Bearer-authenticated and tenant-scoped; uses the stricter diagnostics rate budget. |
| `/v1/diagnostics/screen-pop/{correlation_id}` | public API listener | Bearer-authenticated, tenant-scoped, and returns only a correlation fingerprint plus bounded lifecycle evidence. |
| JSON stdout | process output | Structured operational events; secrets and media/context payloads are excluded. |
| OTLP/gRPC | configured collector | Parent-based W3C traces with bounded queue, batch, sampling, export, and shutdown settings. |

The split `gateway` never mounts health or Prometheus routes on the public API
listener. The all-in-one compatibility process retains its combined listener;
operators must network-restrict it accordingly.

## Release metric inventory

Labels listed below are the complete Bridgefu-owned label set for each metric.
`tenant` is selected only from the finite configured routing table and
`provider` only from the finite provider registry. Enumerated labels such as
`result`, `reason`, `state`, `direction`, and `operation` are code-owned.

| Metric | Type | Labels | Purpose |
|---|---|---|---|
| `bridgefu_process_ready` | gauge | `role` | Role admission readiness. |
| `bridgefu_process_lifecycle_transitions_total` | counter | `role`, `state` | Startup, degradation, drain, and terminal transitions. |
| `bridgefu_active_sessions` | gauge | `tenant` | Active legacy Amazon sessions. |
| `bridgefu_contacts_started_total` | gauge | `tenant` | Legacy Amazon contact-start count snapshot. |
| `bridgefu_failures_total` | gauge | `tenant` | Legacy Amazon failure count snapshot. |
| `bridgefu_calls_routed_total` | counter | `tenant` | Legacy tenant routing decisions. |
| `bridgefu_unknown_tenant_total` | counter | none | Rejected legacy routes without a configured tenant. |
| `bridgefu_auth_failures_total` | counter | `surface` | Authentication failures by fixed ingress surface. |
| `bridgefu_call_operations_total` | counter | `operation`, `result` | Durable call create/hangup/transfer/DTMF outcomes. |
| `bridgefu_attachment_admission_total` | counter | `result` | Single-use attachment consumption. |
| `bridgefu_recipe_sip_admission_total` | counter | `result` | Exact stable-URI recipe admission (`created_or_replayed`, `rejected`, or `unavailable`). |
| `bridgefu_reference_tenant_canary_admission_total` | counter | `result` | Protected canary route decisions. |
| `bridgefu_transfer_status_total` | counter | `transport`, `result` | Transport transfer progress and terminal status. |
| `bridgefu_operational_ephemeral_total` | counter | `kind` | Non-durable adapter event classes. |
| `bridgefu_context_data_messages_total` | counter | `result`, `reason` | Bound DataChannel/context forwarding decisions. |
| `bridgefu_initial_context_total` | counter | `result`, `reason` | Durable pre-INVITE context lifecycle. |
| `bridgefu_handoff_status_total` | counter | `status`, `result` | Browser handoff-status delivery outcomes. |
| `bridgefu_destination_progress_total` | counter | `early_media` | Owned destination progress events by early-media indication. |
| `bridgefu_provisional_early_media_total` | counter | `result` | Provisional attach-then-dial media lifecycle outcomes. |
| `bridgefu_pending_private_operational_total` | counter | `result` | Private operational events staged before route ownership is complete. |
| `bridgefu_provider_client_state_total` | counter | `provider`, `role`, `result`, `reason` | Provider client-state validation outcomes. |
| `bridgefu_active_broadcasts` | gauge | `transport` | Active UCTP or MOQT broadcasts. |
| `bridgefu_broadcast_commands_total` | counter | `operation`, `result` | Durable remote-broadcast command outcomes. |
| `bridgefu_sanitized_broadcast_events_total` | counter | `result`, `reason` | Optional public-event track admission and drops. |
| `bridgefu_provider_webhooks_total` | counter | `provider`, `result` | Verified/deduplicated provider webhook outcomes. |
| `bridgefu_provider_circuit_open` | gauge | `provider` | Provider circuit state. |
| `bridgefu_provider_circuit_rejections_total` | counter | `provider` | Commands rejected while the circuit is open. |
| `bridgefu_provider_circuit_transitions_total` | counter | `provider`, `state` | Provider circuit open/close transitions. |
| `bridgefu_api_rate_limit_requests_total` | counter | `surface`, `outcome` | Control, diagnostics, and webhook admission decisions. |
| `bridgefu_api_rate_limit_tracked_identities` | gauge | none | Bounded one-way identity-key cache occupancy. |
| `bridgefu_gateway_native_ingress_ready` | gauge | none | Native SIP/WebRTC gateway ingress readiness. |
| `bridgefu_gateway_native_active_routes` | gauge | none | Active native SIP/WebRTC attachment routes. |
| `bridgefu_gateway_native_admissions_total` | counter | `outcome` | Native attachment admissions. |
| `bridgefu_gateway_native_media_dropped_total` | counter | `direction` | Bounded native-edge media queue drops. |
| `bridgefu_gateway_native_route_failures_total` | counter | `reason` | Native private-route failures. |
| `bridgefu_gateway_native_rtcp_terminated_total` | counter | `direction` | Hop-by-hop native RTCP termination. |
| `bridgefu_gateway_native_unsupported_total` | counter | `operation` | Explicitly rejected native operations. |
| `bridgefu_gateway_public_uctp_ready` | gauge | none | Public UCTP gateway ingress readiness. |
| `bridgefu_gateway_public_uctp_admissions_total` | counter | `outcome` | Public UCTP attachment admissions. |
| `bridgefu_gateway_public_uctp_media_dropped_total` | counter | `direction` | Public UCTP media queue drops. |
| `bridgefu_gateway_public_uctp_route_failures_total` | counter | `reason` | Public UCTP private-route failures. |
| `bridgefu_gateway_public_uctp_control_dropped_total` | counter | `direction` | Bounded public UCTP reliable-control drops. |
| `bridgefu_private_forwarding_worker_ready` | gauge | none | Worker mTLS/UCTP listener readiness. |
| `bridgefu_private_forwarding_active_routes` | gauge | none | Active pinned gateway-to-worker routes. |
| `bridgefu_private_forwarding_peer_connections` | gauge | none | Pooled private peer connections. |
| `bridgefu_private_forwarding_routes_total` | counter | `outcome` | Private route lifecycle. |
| `bridgefu_private_forwarding_packets_total` | counter | `direction` | Private RTP/RTCP/data forwarding. |
| `bridgefu_private_forwarding_drops_total` | counter | `reason` | Invalid, unknown, or backpressured private packets. |
| `bridgefu_private_egress_active_routes` | gauge | none | Active private worker-owned egress routes. |
| `bridgefu_private_egress_commands_total` | counter | `operation`, `outcome` | Idempotent private-egress command outcomes. |
| `bridgefu_amazon_durable_cleanups_pending` | gauge | none | Durable Amazon cleanup journal backlog. |
| `bridgefu_amazon_cleanup_reconcile_failures_total` | counter | none | Cleanup reconciliation failures. |
| `bridgefu_amazon_pending_contact_cleanups` | gauge | none | Legacy adapter contact cleanups pending at drain. |
| `bridgefu_legacy_drain_incomplete` | gauge | none | Compatibility runtime failed to converge before its drain deadline. |
| `bridgefu_screen_pop_evidence_entries` | gauge | none | Bounded in-memory evidence entries. |
| `bridgefu_screen_pop_evidence_records_total` | counter | `stage`, `result` | Screen-pop evidence state decisions. |
| `bridgefu_screen_pop_evidence_evictions_total` | counter | `reason` | Evidence capacity/TTL evictions. |
| `bridgefu_screen_pop_evidence_lookups_total` | counter | `result` | Authenticated evidence lookup hit/miss. |
| `bridgefu_screen_pop_lifecycle_events_total` | counter | `stage`, `result` | Sanitized lifecycle ingest outcomes. |
| `bridgefu_screen_pop_lifecycle_errors_total` | counter | `error` | Fixed-class lifecycle ingest failures. |
| `bridgefu_screen_pop_lifecycle_lag_seconds` | histogram | `stage` | Ingest lag from sanitized rvoip lifecycle events. |

Call, leg, connection, broadcast, message, subject, issuer, correlation, token,
and remote-address identifiers are forbidden metric labels. They belong in
structured logs and traces, where retention and access controls can be applied.

## Diagnostics inventory

`/diagnostics` returns the binary version; authenticated tenant; call-control
availability, repository kind, and execution placement; configured provider
names; per-broadcast protocol/lifecycle/health, graph counters, bounded queue
depth/capacity, drop/eviction/transcode aggregates, and sanitized-event
aggregates; aggregate API rate-policy/identity-cache occupancy; target MOQT draft;
configured context-header names; and generic listener addresses. It
excludes credentials, identity digests, tokens, context values, raw SIP
headers, provider payloads, call connection IDs, and media bytes.

Readiness exposes only dependency states (`process_role`, legacy Amazon
listener, call runtime/control runtime, and generic bridge configuration).

## Request admission

`api.rate_limit` configures independent token buckets for authenticated control
requests, authenticated diagnostics, and pre-verification provider webhooks.
Control/diagnostic identities are a process-salted one-way digest of issuer,
tenant, and subject. The webhook bucket is intentionally gateway-wide because its claimed
provider/tenant is untrusted until signature verification. The cache is capped
by `max_tracked_identities`, idle-reclaimed, and fails closed for an unseen
identity at capacity. Rejections return HTTP `429` and an integer
`Retry-After`; no identity is used as a metric label. The webhook body is
bounded at 256 KiB before signature verification or persistence work. Budgets
are per gateway process; use the load balancer/WAF for a cluster-wide ceiling.

## Hermetic release checks

- `cargo test --locked --bin bridgefu observability::tests::release_metric_inventory_is_documented_and_bounded -- --exact`
- `cargo test --locked --bin bridgefu api::tests::api_rate_policy_returns_429_with_retry_after_per_surface -- --exact`
- `cargo test --locked --bin bridgefu api::tests::authenticated_diagnostics_match_the_documented_release_inventory -- --exact`
- `deploy/scripts/runtime-smoke.py` retains hashed evidence for durable call
  execution, bidirectional codec media, context/DataMessage translation, a
  real shared media source feeding broadcasts, subscriber-token issuance,
  diagnostics, and cleanup without cloud or provider credentials. Its source
  record includes tracked and untracked Bridgefu/rvoip state plus exact locked
  WebRTC, RTC, and moq-transport revisions/checksums.
- `scripts/release-runtime-smoke.sh` is the short developer form covering the
  same three media-runtime checks without the broader role/configuration suite.
