import assert from "node:assert/strict";
import test from "node:test";

import {
  BRIDGEFU_CONTEXT_CONTENT_TYPE,
  BRIDGEFU_CONTEXT_LABEL,
  BRIDGEFU_HANDOFF_CONTENT_TYPE,
  BRIDGEFU_HANDOFF_LABEL,
  RVOIP_DATA_MESSAGE_PROTOCOL,
  createBridgefuContextMessage,
  decodeRvoipDataMessage,
  encodeRvoipDataMessage,
  normalizeBridgefuRouteAttachment,
  parseBridgefuContextMessage,
  parseBridgefuHandoffMessage,
} from "../dist/index.js";

const encoder = new TextEncoder();

test("accepts only a bounded reliable server handoff envelope", () => {
  const message = {
    label: BRIDGEFU_HANDOFF_LABEL,
    contentType: BRIDGEFU_HANDOFF_CONTENT_TYPE,
    data: encoder.encode(JSON.stringify({
      version: 1,
      call_id: "call-a",
      replacement_leg_id: "leg-agent",
      binding_generation: 2,
      status: "connected",
    })),
    reliability: { mode: "reliable-ordered" },
    messageId: "handoff-1",
  };
  assert.equal(parseBridgefuHandoffMessage(message).status, "connected");
  assert.throws(
    () => parseBridgefuHandoffMessage({ ...message, reliability: { mode: "reliable-unordered" } }),
    /not an authenticated/,
  );
  assert.throws(
    () => parseBridgefuHandoffMessage({
      ...message,
      data: encoder.encode(JSON.stringify({
        version: 1,
        call_id: "call-a",
        replacement_leg_id: "leg-agent",
        binding_generation: 2,
        status: "connected",
        forged: true,
      })),
    }),
    /unknown field/,
  );
});

test("normalizes the exact named-route attachment contract", () => {
  const normalized = normalizeBridgefuRouteAttachment(
    {
      type: "webrtc",
      signaling_uri: "wss://edge.bridgefu.example/webrtc",
      token: "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
      signaling_credential: {
        usage: "bridgefu-webrtc-signaling",
        token: "bfs1.signed-attachment-bound-token",
        expires_at: "2030-01-01T00:02:00Z",
      },
      subprotocols: [
        "rvoip.webrtc.v1",
        "token.bfs1.signed-attachment-bound-token",
        "bridgefu.attach.abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
      ],
      ice_servers: [
        {
          urls: ["turns:turn.bridgefu.example:5349?transport=tcp"],
          username: "temporary-user",
          credential: "temporary-secret",
        },
      ],
      expires_at: "2030-01-01T00:02:00Z",
    },
    { tenantId: "tenant-a", callId: "call-a", legId: "leg-browser" },
  );

  assert.deepEqual(normalized, {
    version: 1,
    transport: "webrtc",
    signalingUrl: "wss://edge.bridgefu.example/webrtc",
    attachmentToken: "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
    expiresAt: "2030-01-01T00:02:00Z",
    tenantId: "tenant-a",
    callId: "call-a",
    legId: "leg-browser",
    signalingCredential: {
      usage: "bridgefu-webrtc-signaling",
      token: "bfs1.signed-attachment-bound-token",
      expiresAt: "2030-01-01T00:02:00Z",
    },
    iceServers: [
      {
        urls: ["turns:turn.bridgefu.example:5349?transport=tcp"],
        username: "temporary-user",
        credential: "temporary-secret",
      },
    ],
  });
});

test("rejects a route attachment whose private subprotocol does not match", () => {
  assert.throws(
    () =>
      normalizeBridgefuRouteAttachment(
        {
          type: "webrtc",
          signaling_uri: "wss://edge.bridgefu.example/webrtc",
          token: "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
          signaling_credential: {
            usage: "bridgefu-webrtc-signaling",
            token: "bfs1.signed-attachment-bound-token",
            expires_at: "2030-01-01T00:02:00Z",
          },
          subprotocols: [
            "rvoip.webrtc.v1",
            "token.bfs1.signed-attachment-bound-token",
            "bridgefu.attach.some-other-token",
          ],
          ice_servers: [],
          expires_at: "2030-01-01T00:02:00Z",
        },
        { tenantId: "tenant-a", callId: "call-a", legId: "leg-browser" },
      ),
    /subprotocols do not match/,
  );
});

test("round-trips the rvoip RVDM v1 binary frame", () => {
  const message = {
    label: "telemetry.bin",
    contentType: "application/octet-stream",
    data: new Uint8Array([0, 1, 2, 255]),
    reliability: { mode: "max-retransmits", ordered: false, count: 3 },
    messageId: "message-123",
  };

  const encoded = encodeRvoipDataMessage(message);
  assert.ok(encoded instanceof Uint8Array);
  assert.deepEqual([...encoded.subarray(0, 8)], [0x52, 0x56, 0x44, 0x4d, 1, 1, 0, 0]);

  const decoded = decodeRvoipDataMessage(encoded, {
    label: message.label,
    reliability: message.reliability,
  });
  assert.equal(decoded.label, message.label);
  assert.equal(decoded.contentType, message.contentType);
  assert.equal(decoded.messageId, message.messageId);
  assert.deepEqual(decoded.reliability, message.reliability);
  assert.deepEqual([...decoded.data], [...message.data]);
});

test("uses the rvoip text envelope and validates bridgefu.context.v1", () => {
  const attachment = {
    version: 1,
    transport: "webrtc",
    signalingUrl: "wss://edge.bridgefu.example/webrtc",
    attachmentToken: "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
    expiresAt: "2030-01-01T00:02:00Z",
    tenantId: "tenant-a",
    callId: "call-a",
    legId: "leg-browser",
  };
  const message = createBridgefuContextMessage(
    attachment,
    { correlationId: "corr-123", metadata: { account_tier: "gold" } },
    "message-context",
  );

  assert.equal(message.label, BRIDGEFU_CONTEXT_LABEL);
  assert.equal(message.contentType, BRIDGEFU_CONTEXT_CONTENT_TYPE);
  const encoded = encodeRvoipDataMessage(message);
  assert.equal(typeof encoded, "string");
  assert.match(encoded, /^rvoip-data-v1:/);

  const decoded = decodeRvoipDataMessage(encoded, {
    label: BRIDGEFU_CONTEXT_LABEL,
    reliability: { mode: "reliable-ordered" },
  });
  assert.deepEqual(parseBridgefuContextMessage(decoded), {
    version: 1,
    correlation_id: "corr-123",
    tenant_id: "tenant-a",
    call_id: "call-a",
    source_leg_id: "leg-browser",
    metadata: { account_tier: "gold" },
  });
});

test("rejects channel-contract mismatches and unsafe context", () => {
  const binary = encodeRvoipDataMessage({
    label: "one",
    contentType: "application/octet-stream",
    data: new Uint8Array(),
    reliability: { mode: "reliable-ordered" },
    messageId: "id-1",
  });
  assert.throws(
    () =>
      decodeRvoipDataMessage(binary, {
        label: "two",
        reliability: { mode: "reliable-ordered" },
      }),
    /does not match its DataChannel contract/,
  );

  const unsafeContext = {
    label: BRIDGEFU_CONTEXT_LABEL,
    contentType: BRIDGEFU_CONTEXT_CONTENT_TYPE,
    data: encoder.encode(
      JSON.stringify({
        version: 1,
        correlation_id: "corr",
        tenant_id: "tenant-a",
        call_id: "call-a",
        source_leg_id: "leg-a",
        metadata: {},
        tenant_override: "tenant-b",
      }),
    ),
    reliability: { mode: "reliable-ordered" },
    messageId: "context-id",
  };
  assert.throws(() => parseBridgefuContextMessage(unsafeContext), /unknown field/);

  assert.throws(
    () =>
      encodeRvoipDataMessage({
        label: "one",
        contentType: "application/@invalid",
        data: new Uint8Array(),
        reliability: { mode: "reliable-ordered" },
        messageId: "id-2",
      }),
    /not a MIME media type/,
  );
});

test("exports the negotiated DataChannel protocol constant", () => {
  assert.equal(RVOIP_DATA_MESSAGE_PROTOCOL, "rvoip.data.v1");
});
