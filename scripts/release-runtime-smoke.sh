#!/usr/bin/env bash
set -euo pipefail

export CARGO_INCREMENTAL=0

cargo test --locked --test call_execution_supervisor \
  sip_webrtc_media_graph_is_directional_codec_exact_and_cleanup_owned -- --exact
cargo test --locked --test call_execution_supervisor \
  inbound_sip_context_reaches_the_peer_data_channel_and_later_messages_bridge -- --exact
cargo test --locked --bin bridgefu \
  api::tests::durable_broadcasts_share_real_source_and_cleanup_managed_state -- --exact
