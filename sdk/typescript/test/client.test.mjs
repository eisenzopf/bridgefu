import assert from "node:assert/strict";
import test from "node:test";

import {
  BRIDGEFU_CONTEXT_LABEL,
  BRIDGEFU_HANDOFF_CONTENT_TYPE,
  BRIDGEFU_HANDOFF_LABEL,
  BridgefuWebRtcClient,
  RVOIP_DATA_MESSAGE_PROTOCOL,
  decodeRvoipDataMessage,
  encodeRvoipDataMessage,
  normalizeBridgefuRouteAttachment,
} from "../dist/index.js";

class FakeTrack {
  kind = "audio";
  stopped = false;

  stop() {
    this.stopped = true;
  }
}

class FakeStream {
  constructor(track) {
    this.track = track;
  }

  getAudioTracks() {
    return [this.track];
  }

  getTracks() {
    return [this.track];
  }
}

class FakeDtmf {
  canInsertDTMF = true;
  calls = [];

  insertDTMF(tones, duration, gap) {
    this.calls.push({ tones, duration, gap });
  }
}

class FakeDataChannel {
  readyState = "open";
  sent = [];
  onmessage = null;
  onclose = null;

  constructor(label, options = {}) {
    this.label = label;
    this.protocol = options.protocol ?? "";
    this.ordered = options.ordered ?? true;
    this.maxPacketLifeTime = options.maxPacketLifeTime ?? null;
    this.maxRetransmits = options.maxRetransmits ?? null;
  }

  send(data) {
    if (this.readyState !== "open") throw new Error("channel closed");
    this.sent.push(data);
  }

  close() {
    this.readyState = "closed";
    this.onclose?.();
  }

  receive(data) {
    this.onmessage?.({ data });
  }
}

class FakePeerConnection {
  connectionState = "new";
  localDescription = null;
  remoteDescriptions = [];
  remoteDescriptionStarted = 0;
  remoteDescriptionGate = null;
  remoteCandidates = [];
  channels = [];
  senders = [];
  closed = false;
  onicecandidate = null;
  ontrack = null;
  ondatachannel = null;
  onconnectionstatechange = null;

  constructor(configuration) {
    this.configuration = configuration;
  }

  addTrack(track) {
    const sender = { track, dtmf: new FakeDtmf() };
    this.senders.push(sender);
    return sender;
  }

  getSenders() {
    return this.senders;
  }

  createDataChannel(label, options = {}) {
    const channel = new FakeDataChannel(label, options);
    this.channels.push(channel);
    return channel;
  }

  async createOffer() {
    return { type: "offer", sdp: "v=0\r\na=group:BUNDLE 0\r\n" };
  }

  async setLocalDescription(description) {
    this.localDescription = description;
  }

  async setRemoteDescription(description) {
    this.remoteDescriptionStarted += 1;
    await this.remoteDescriptionGate;
    this.remoteDescriptions.push(description);
  }

  deferRemoteDescription() {
    let release;
    this.remoteDescriptionGate = new Promise((resolve) => {
      release = resolve;
    });
    return release;
  }

  async addIceCandidate(candidate) {
    this.remoteCandidates.push(candidate);
  }

  emitIce(candidate) {
    this.onicecandidate?.({
      candidate:
        candidate === null
          ? null
          : {
              candidate: candidate.candidate,
              toJSON: () => ({ ...candidate }),
            },
    });
  }

  setConnectionState(state) {
    this.connectionState = state;
    this.onconnectionstatechange?.();
  }

  emitTrack(track, stream) {
    this.ontrack?.({ track, streams: [stream] });
  }

  close() {
    this.closed = true;
    this.connectionState = "closed";
  }
}

class FakeWebSocket {
  readyState = 0;
  protocol = "";
  sent = [];
  closeCall = null;
  onopen = null;
  onmessage = null;
  onerror = null;
  onclose = null;

  constructor(url, protocols) {
    this.url = url;
    this.protocols = protocols;
  }

  open(protocol = "rvoip.webrtc.v1") {
    this.protocol = protocol;
    this.readyState = 1;
    this.onopen?.({});
  }

  send(data) {
    if (this.readyState !== 1) throw new Error("socket not open");
    this.sent.push(data);
  }

  receive(message) {
    this.onmessage?.({ data: JSON.stringify(message) });
  }

  abnormalClose() {
    this.readyState = 3;
    this.onclose?.({ code: 1006 });
  }

  close(code, reason) {
    this.readyState = 3;
    this.closeCall = { code, reason };
    this.onclose?.({ code });
  }
}

function createHarness({ mediaFailure = null } = {}) {
  const peers = [];
  const sockets = [];
  const tracks = [];
  let ids = 0;
  const environment = {
    createPeerConnection(configuration) {
      const peer = new FakePeerConnection(configuration);
      peers.push(peer);
      return peer;
    },
    createWebSocket(url, protocols) {
      const socket = new FakeWebSocket(url, protocols);
      sockets.push(socket);
      return socket;
    },
    async getUserMedia() {
      if (mediaFailure) throw mediaFailure;
      const track = new FakeTrack();
      tracks.push(track);
      return new FakeStream(track);
    },
    now: () => Date.parse("2029-12-31T23:59:00Z"),
    randomId: () => `deterministic-${++ids}`,
  };
  return { environment, peers, sockets, tracks };
}

function attachment(token = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG") {
  return {
    version: 1,
    transport: "webrtc",
    signalingUrl: "wss://edge.bridgefu.example/webrtc",
    attachmentToken: token,
    expiresAt: "2030-01-01T00:02:00Z",
    tenantId: "tenant-a",
    callId: "call-a",
    legId: "leg-browser",
    signalingCredential: {
      usage: "bridgefu-webrtc-signaling",
      token: "fixture-attachment-bound-signaling-token",
      expiresAt: "2030-01-01T00:01:30Z",
    },
    iceServers: [
      {
        urls: ["turns:turn.bridgefu.example:5349?transport=tcp"],
        username: "temporary-user",
        credential: "temporary-secret",
      },
    ],
  };
}

test("normalizes the attachment-bound signaling credential returned by a route", () => {
  const raw = {
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
    ice_servers: [],
    expires_at: "2030-01-01T00:02:00Z",
  };

  const normalized = normalizeBridgefuRouteAttachment(raw, {
    tenantId: "tenant-a",
    callId: "call-a",
    legId: "leg-browser",
  });
  assert.deepEqual(normalized.signalingCredential, {
    usage: "bridgefu-webrtc-signaling",
    token: "bfs1.signed-attachment-bound-token",
    expiresAt: "2030-01-01T00:02:00Z",
  });
  assert.throws(
    () =>
      normalizeBridgefuRouteAttachment(
        {
          ...raw,
          subprotocols: [
            "rvoip.webrtc.v1",
            "token.bfs1.credential-for-another-call",
            raw.subprotocols[2],
          ],
        },
        { tenantId: "tenant-a", callId: "call-a", legId: "leg-browser" },
      ),
    /do not match/,
  );
});

async function waitFor(predicate, message = "condition") {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  throw new Error(`timed out waiting for ${message}`);
}

async function completeConnection(
  client,
  harness,
  descriptor,
  index = 0,
  { readyBeforePeer = false } = {},
) {
  const connecting = index === 0 ? client.connect(descriptor) : client.reconnect(descriptor);
  await waitFor(
    () => harness.peers.length > index && harness.sockets.length > index,
    "peer and socket",
  );
  const peer = harness.peers[index];
  const socket = harness.sockets[index];
  socket.open();
  await waitFor(() => socket.sent.length === 1, "offer");
  const offer = JSON.parse(socket.sent[0]);
  assert.equal(offer.type, "offer-ready");
  assert.equal(
    socket.protocols.includes(`token.${descriptor.signalingCredential.token}`),
    true,
  );
  socket.receive({
    type: "answer",
    sdp: "v=0\r\na=group:BUNDLE 0\r\n",
    connection_id: `server-connection-${index + 1}`,
    candidate: "",
    request_id: offer.request_id,
  });
  await waitFor(() => peer.remoteDescriptions.length === 1, "remote description");
  const ready = {
    type: "ready",
    connection_id: `server-connection-${index + 1}`,
    request_id: offer.request_id,
  };
  if (readyBeforePeer) {
    socket.receive(ready);
    await waitFor(() => client.serverConnectionId !== null, "answer ownership");
    assert.equal(client.state, "connecting");
    peer.setConnectionState("connected");
  } else {
    peer.setConnectionState("connected");
    assert.equal(client.state, "connecting");
    socket.receive(ready);
  }
  await connecting;
  return { peer, socket, offer };
}

test("runs rvoip WSS/peer lifecycle, media, DataMessages, context, DTMF, and cleanup", async () => {
  const harness = createHarness();
  const remoteAudio = {
    srcObject: null,
    plays: 0,
    async play() {
      this.plays += 1;
    },
  };
  const ringback = { starts: 0, stops: [], start() { this.starts += 1; }, stop(reason) { this.stops.push(reason); } };
  const handoffs = [];
  const contexts = [];
  const handoffMessages = [];
  const rawMessages = [];
  const client = new BridgefuWebRtcClient({
    environment: harness.environment,
    ringback,
    remoteAudioElement: remoteAudio,
    signalingCredential: async () => ({
      usage: "bridgefu-webrtc-signaling",
      token: "short-lived-signaling-token",
      expiresAt: "2030-01-01T00:01:00Z",
    }),
    dataChannels: [
      {
        label: "events",
        options: {
          protocol: RVOIP_DATA_MESSAGE_PROTOCOL,
          ordered: false,
          maxRetransmits: 3,
        },
      },
      { label: "raw.application", options: { ordered: false } },
    ],
  });
  client.on("handoff", (event) => handoffs.push(event.status));
  client.on("context", (event) => contexts.push(event.envelope));
  client.on("handoffMessage", (event) => handoffMessages.push(event.envelope));
  client.on("rawMessage", (event) => rawMessages.push(event));

  const descriptor = { ...attachment(), signalingCredential: undefined };
  const connecting = client.connect(descriptor);
  await waitFor(() => harness.peers.length === 1 && harness.sockets.length === 1);
  const peer = harness.peers[0];
  const socket = harness.sockets[0];
  assert.deepEqual(peer.configuration.iceServers, attachment().iceServers);
  assert.equal(peer.senders.length, 1);
  assert.deepEqual(
    peer.channels.map((channel) => channel.label),
    [BRIDGEFU_CONTEXT_LABEL, BRIDGEFU_HANDOFF_LABEL, "events", "raw.application"],
  );

  peer.emitIce({ candidate: "candidate:1 1 udp 1 192.0.2.1 5000 typ host", sdpMid: "0" });
  peer.emitIce(null);
  socket.open();
  await waitFor(() => socket.sent.length === 1, "offer");
  assert.deepEqual(socket.protocols, [
    "rvoip.webrtc.v1",
    "token.short-lived-signaling-token",
    `bridgefu.attach.${attachment().attachmentToken}`,
  ]);
  assert.equal(new URL(socket.url).searchParams.has("access_token"), false);
  const offer = JSON.parse(socket.sent[0]);
  assert.equal(offer.type, "offer-ready");
  assert.match(offer.request_id, /^browser-deterministic-/);

  socket.receive({
    type: "answer",
    sdp: "v=0\r\na=group:BUNDLE 0\r\n",
    connection_id: "server-connection-1",
    candidate: "",
    request_id: offer.request_id,
  });
  await waitFor(() => socket.sent.length === 3, "queued ICE flush");
  assert.deepEqual(
    socket.sent.slice(1).map((message) => JSON.parse(message).type),
    ["ice-candidate", "ice-complete"],
  );
  peer.setConnectionState("connected");
  assert.equal(client.state, "connecting", "peer connectivity must not bypass remote admission");
  socket.receive({
    type: "ready",
    connection_id: "server-connection-1",
    request_id: offer.request_id,
  });
  await connecting;
  assert.equal(client.state, "connected");
  assert.equal(client.serverConnectionId, "server-connection-1");
  assert.equal(ringback.starts, 1);
  assert.deepEqual(ringback.stops, ["connected"]);

  const remoteStream = new FakeStream(new FakeTrack());
  peer.emitTrack(remoteStream.track, remoteStream);
  assert.equal(remoteAudio.srcObject, remoteStream);
  assert.equal(remoteAudio.plays, 1);

  const remoteRaw = new FakeDataChannel("server.raw");
  peer.ondatachannel({ channel: remoteRaw });
  remoteRaw.receive("from-server");
  assert.equal(rawMessages.length, 1);
  assert.equal(rawMessages[0].channel.label, "server.raw");
  assert.equal(rawMessages[0].data, "from-server");

  const contextChannel = client.getDataChannel(BRIDGEFU_CONTEXT_LABEL);
  const sentContext = client.sendContext({
    correlationId: "corr-browser",
    metadata: { account_tier: "gold" },
  });
  assert.equal(typeof contextChannel.sent.at(-1), "string");
  const contextRoundTrip = decodeRvoipDataMessage(contextChannel.sent.at(-1), {
    label: BRIDGEFU_CONTEXT_LABEL,
    reliability: { mode: "reliable-ordered" },
  });
  assert.deepEqual([...contextRoundTrip.data], [...sentContext.data]);
  contextChannel.receive(encodeRvoipDataMessage(sentContext));
  await waitFor(() => contexts.length === 1, "context event");
  assert.equal(contexts[0].tenant_id, "tenant-a");

  const handoffChannel = client.getDataChannel(BRIDGEFU_HANDOFF_LABEL);
  const handoffMessage = {
    label: BRIDGEFU_HANDOFF_LABEL,
    contentType: BRIDGEFU_HANDOFF_CONTENT_TYPE,
    data: new TextEncoder().encode(JSON.stringify({
      version: 1,
      call_id: "call-a",
      replacement_leg_id: "leg-agent",
      binding_generation: 2,
      status: "ringing",
      detail_code: "destination_ringing",
    })),
    reliability: { mode: "reliable-ordered" },
    messageId: "handoff-status-1",
  };
  handoffChannel.receive(encodeRvoipDataMessage(handoffMessage));
  await waitFor(() => handoffMessages.length === 1, "handoff status event");
  assert.equal(handoffMessages[0].status, "ringing");
  assert.equal(ringback.starts, 2);

  handoffChannel.receive(encodeRvoipDataMessage({
    ...handoffMessage,
    data: new TextEncoder().encode(JSON.stringify({
      version: 1,
      call_id: "call-a",
      replacement_leg_id: "leg-agent",
      binding_generation: 2,
      status: "resumed",
      detail_code: "destination_failed",
    })),
    messageId: "handoff-status-2",
  }));
  await waitFor(() => handoffMessages.length === 2, "resumed handoff status event");
  assert.equal(handoffMessages[1].status, "resumed");
  assert.deepEqual(ringback.stops, ["connected", "resumed"]);

  const typed = client.sendDataMessage(
    "events",
    "application/octet-stream",
    new Uint8Array([4, 5, 6]),
  );
  assert.deepEqual(typed.reliability, {
    mode: "max-retransmits",
    ordered: false,
    count: 3,
  });
  client.sendRaw("raw.application", "hello");
  assert.equal(client.getDataChannel("raw.application").sent.at(-1), "hello");

  client.sendDtmf("12a#", 120, 80);
  assert.deepEqual(peer.senders[0].dtmf.calls, [
    { tones: "12A#", duration: 120, gap: 80 },
  ]);

  peer.senders[0].dtmf.canInsertDTMF = false;
  assert.throws(
    () => client.sendDtmf("7"),
    (error) => error.code === "dtmf-unavailable" && /cannot insert/.test(error.message),
  );

  socket.receive({
    type: "ice-candidate",
    connection_id: "server-connection-1",
    candidate: JSON.stringify({ candidate: "candidate:2", sdpMid: "0" }),
  });
  socket.receive({
    type: "ice-candidate",
    connection_id: "server-connection-1",
    candidate: JSON.stringify({
      candidate: "candidate:3",
      sdpMid: "",
      sdpMLineIndex: 0,
    }),
  });
  socket.receive({ type: "ice-complete", connection_id: "server-connection-1" });
  await waitFor(() => peer.remoteCandidates.length === 3, "remote ICE");
  assert.equal(peer.remoteCandidates[0].candidate, "candidate:2");
  assert.equal(peer.remoteCandidates[0].sdpMid, "0");
  assert.deepEqual(peer.remoteCandidates[1], {
    candidate: "candidate:3",
    sdpMLineIndex: 0,
  });
  assert.equal(peer.remoteCandidates[2], null);

  await client.disconnect();
  assert.equal(client.state, "closed");
  assert.equal(peer.closed, true);
  assert.equal(harness.tracks[0].stopped, true);
  assert.equal(remoteAudio.srcObject, null);
  assert.deepEqual(JSON.parse(socket.sent.at(-1)), {
    type: "bye",
    connection_id: "server-connection-1",
  });
  assert.equal(socket.closeCall.code, 1000);
  assert.deepEqual(handoffs, [
    "preparing",
    "ringing",
    "attaching",
    "connected",
    "ringing",
    "resumed",
    "ended",
  ]);
});

test("fails closed when the exact remote admission is rejected", async () => {
  const harness = createHarness();
  const client = new BridgefuWebRtcClient({ environment: harness.environment });
  const connecting = client.connect(attachment());
  const rejected = assert.rejects(
    connecting,
    (error) =>
      error.code === "signaling-failed" && /remote application rejected/.test(error.message),
  );
  await waitFor(() => harness.peers.length === 1 && harness.sockets.length === 1);
  const peer = harness.peers[0];
  const socket = harness.sockets[0];
  socket.open();
  await waitFor(() => socket.sent.length === 1, "offer-ready");
  const offer = JSON.parse(socket.sent[0]);
  socket.receive({
    type: "answer",
    sdp: "v=0\r\na=group:BUNDLE 0\r\n",
    connection_id: "server-rejected",
    request_id: offer.request_id,
  });
  await waitFor(() => peer.remoteDescriptions.length === 1, "remote description");
  peer.setConnectionState("connected");
  assert.equal(client.state, "connecting");
  socket.receive({
    type: "rejected",
    connection_id: "server-rejected",
    request_id: offer.request_id,
  });
  await rejected;
  assert.equal(client.state, "failed");
  assert.equal(peer.closed, true);
});

test("serializes rapid answer and readiness frames before committing route ownership", async () => {
  const harness = createHarness();
  const client = new BridgefuWebRtcClient({ environment: harness.environment });
  const connecting = client.connect(attachment());
  await waitFor(() => harness.peers.length === 1 && harness.sockets.length === 1);
  const peer = harness.peers[0];
  const socket = harness.sockets[0];
  const releaseRemoteDescription = peer.deferRemoteDescription();
  socket.open();
  await waitFor(() => socket.sent.length === 1, "offer-ready");
  const offer = JSON.parse(socket.sent[0]);

  socket.receive({
    type: "answer",
    sdp: "v=0\r\na=group:BUNDLE 0\r\n",
    connection_id: "server-serialized",
    request_id: offer.request_id,
  });
  socket.receive({
    type: "ready",
    connection_id: "server-serialized",
    request_id: offer.request_id,
  });
  peer.setConnectionState("connected");
  await waitFor(() => peer.remoteDescriptionStarted === 1, "remote description start");
  assert.equal(client.serverConnectionId, null);
  assert.equal(client.state, "connecting");

  releaseRemoteDescription();
  await connecting;
  assert.equal(client.serverConnectionId, "server-serialized");
  assert.equal(client.state, "connected");
  await client.disconnect();
});

test("retains exact readiness until peer connectivity completes", async () => {
  const harness = createHarness();
  const client = new BridgefuWebRtcClient({ environment: harness.environment });
  const connected = await completeConnection(
    client,
    harness,
    attachment(),
    0,
    { readyBeforePeer: true },
  );
  assert.equal(client.state, "connected");
  await client.disconnect();
  assert.equal(connected.peer.closed, true);
});

test("rejects an admission outcome that is not bound to the offer request", async () => {
  const harness = createHarness();
  const client = new BridgefuWebRtcClient({ environment: harness.environment });
  const connecting = client.connect(attachment());
  const rejected = assert.rejects(
    connecting,
    (error) => error.code === "protocol-error" && /ownership mismatch/.test(error.message),
  );
  await waitFor(() => harness.peers.length === 1 && harness.sockets.length === 1);
  const peer = harness.peers[0];
  const socket = harness.sockets[0];
  socket.open();
  await waitFor(() => socket.sent.length === 1, "offer-ready");
  const offer = JSON.parse(socket.sent[0]);
  socket.receive({
    type: "answer",
    sdp: "v=0\r\na=group:BUNDLE 0\r\n",
    connection_id: "server-owned",
    request_id: offer.request_id,
  });
  await waitFor(() => peer.remoteDescriptions.length === 1, "remote description");
  socket.receive({
    type: "ready",
    connection_id: "server-owned",
    request_id: `${offer.request_id}-forged`,
  });
  await rejected;
  assert.equal(client.state, "failed");
  assert.equal(peer.closed, true);
});

test("rejects readiness bound to another connection", async () => {
  const harness = createHarness();
  const client = new BridgefuWebRtcClient({ environment: harness.environment });
  const connecting = client.connect(attachment());
  const rejected = assert.rejects(
    connecting,
    (error) => error.code === "protocol-error" && /route ownership mismatch/.test(error.message),
  );
  await waitFor(() => harness.peers.length === 1 && harness.sockets.length === 1);
  const socket = harness.sockets[0];
  socket.open();
  await waitFor(() => socket.sent.length === 1, "offer-ready");
  const offer = JSON.parse(socket.sent[0]);
  socket.receive({
    type: "answer",
    sdp: "v=0\r\na=group:BUNDLE 0\r\n",
    connection_id: "server-owned",
    request_id: offer.request_id,
  });
  await waitFor(() => client.serverConnectionId === "server-owned", "answer ownership");
  socket.receive({
    type: "ready",
    connection_id: "server-forged",
    request_id: offer.request_id,
  });
  await rejected;
  assert.equal(client.state, "failed");
});

test("rejects admission outcomes before an answer establishes route ownership", async () => {
  for (const type of ["ready", "rejected"]) {
    const harness = createHarness();
    const client = new BridgefuWebRtcClient({ environment: harness.environment });
    const connecting = client.connect(attachment(`preanswer-${type}-abcdefghijklmnopqrstuv`));
    const rejected = assert.rejects(
      connecting,
      (error) => error.code === "protocol-error" && /route ownership mismatch/.test(error.message),
    );
    await waitFor(() => harness.sockets.length === 1);
    const socket = harness.sockets[0];
    socket.open();
    await waitFor(() => socket.sent.length === 1, "offer-ready");
    const offer = JSON.parse(socket.sent[0]);
    socket.receive({
      type,
      connection_id: "server-not-yet-owned",
      request_id: offer.request_id,
    });
    await rejected;
    assert.equal(client.state, "failed");
  }
});

test("rejects malformed and duplicate admission readiness", async () => {
  const malformedHarness = createHarness();
  const malformedClient = new BridgefuWebRtcClient({ environment: malformedHarness.environment });
  const malformedConnecting = malformedClient.connect(attachment());
  const malformedRejected = assert.rejects(
    malformedConnecting,
    (error) => error.code === "protocol-error" && /unexpected payload/.test(error.message),
  );
  await waitFor(() => malformedHarness.sockets.length === 1);
  const malformedSocket = malformedHarness.sockets[0];
  malformedSocket.open();
  await waitFor(() => malformedSocket.sent.length === 1, "offer-ready");
  const malformedOffer = JSON.parse(malformedSocket.sent[0]);
  malformedSocket.receive({
    type: "answer",
    sdp: "v=0\r\na=group:BUNDLE 0\r\n",
    connection_id: "server-malformed",
    request_id: malformedOffer.request_id,
  });
  await waitFor(() => malformedClient.serverConnectionId === "server-malformed");
  malformedSocket.receive({
    type: "ready",
    sdp: "unexpected",
    connection_id: "server-malformed",
    request_id: malformedOffer.request_id,
  });
  await malformedRejected;

  const duplicateHarness = createHarness();
  const errors = [];
  const duplicateClient = new BridgefuWebRtcClient({ environment: duplicateHarness.environment });
  duplicateClient.on("error", (event) => errors.push(event.error));
  const connected = await completeConnection(duplicateClient, duplicateHarness, attachment());
  connected.socket.receive({
    type: "ready",
    connection_id: "server-connection-1",
    request_id: connected.offer.request_id,
  });
  await waitFor(() => duplicateClient.state === "failed", "duplicate readiness failure");
  assert.equal(errors.at(-1).code, "protocol-error");
  assert.match(errors.at(-1).message, /duplicate admission readiness/);
});

test("remote BYE or signaling loss before readiness never attaches the browser", async () => {
  const byeHarness = createHarness();
  const byeClient = new BridgefuWebRtcClient({ environment: byeHarness.environment });
  const byeConnecting = byeClient.connect(attachment());
  const byeRejected = assert.rejects(
    byeConnecting,
    (error) => error.code === "signaling-failed" && /ended during attachment/.test(error.message),
  );
  await waitFor(() => byeHarness.sockets.length === 1);
  const byeSocket = byeHarness.sockets[0];
  byeSocket.open();
  await waitFor(() => byeSocket.sent.length === 1, "offer-ready");
  const byeOffer = JSON.parse(byeSocket.sent[0]);
  byeSocket.receive({
    type: "answer",
    sdp: "v=0\r\na=group:BUNDLE 0\r\n",
    connection_id: "server-bye",
    request_id: byeOffer.request_id,
  });
  await waitFor(() => byeClient.serverConnectionId === "server-bye");
  byeSocket.receive({ type: "bye", connection_id: "server-bye" });
  await byeRejected;
  assert.equal(byeClient.state, "closed");

  const closeHarness = createHarness();
  const closeClient = new BridgefuWebRtcClient({ environment: closeHarness.environment });
  const closeConnecting = closeClient.connect(
    attachment("socket-close-before-ready-abcdefghijklmnop"),
  );
  const closeRejected = assert.rejects(
    closeConnecting,
    (error) => error.code === "signaling-failed" && /closed before attachment/.test(error.message),
  );
  await waitFor(() => closeHarness.sockets.length === 1);
  closeHarness.sockets[0].open();
  closeHarness.sockets[0].abnormalClose();
  await closeRejected;
  assert.equal(closeClient.state, "failed");
});

test("peer connectivity and an answer cannot bypass the readiness deadline", async () => {
  const harness = createHarness();
  const client = new BridgefuWebRtcClient({
    environment: harness.environment,
    connectTimeoutMs: 20,
  });
  const connecting = client.connect(attachment());
  const rejected = assert.rejects(
    connecting,
    (error) => error.code === "timeout" && /attachment timed out/.test(error.message),
  );
  await waitFor(() => harness.peers.length === 1 && harness.sockets.length === 1);
  const peer = harness.peers[0];
  const socket = harness.sockets[0];
  socket.open();
  await waitFor(() => socket.sent.length === 1, "offer-ready");
  const offer = JSON.parse(socket.sent[0]);
  socket.receive({
    type: "answer",
    sdp: "v=0\r\na=group:BUNDLE 0\r\n",
    connection_id: "server-never-ready",
    request_id: offer.request_id,
  });
  await waitFor(() => client.serverConnectionId === "server-never-ready");
  peer.setConnectionState("connected");
  assert.equal(client.state, "connecting");
  await rejected;
  assert.equal(client.state, "failed");
  assert.equal(peer.closed, true);
});

test("requires a fresh single-use attachment after signaling loss", async () => {
  const harness = createHarness();
  const reconnectEvents = [];
  const client = new BridgefuWebRtcClient({ environment: harness.environment });
  client.on("reconnectRequired", (event) => reconnectEvents.push(event.reason));
  const first = attachment();
  const connected = await completeConnection(client, harness, first);

  connected.socket.abnormalClose();
  await waitFor(() => client.state === "reconnect-required", "reconnect-required state");
  assert.deepEqual(reconnectEvents, ["signaling-closed"]);
  assert.equal(connected.peer.closed, true);
  await assert.rejects(client.reconnect(first), /fresh single-use attachment token/);

  const second = attachment("BCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefgh");
  const reconnected = await completeConnection(client, harness, second, 1);
  assert.equal(client.state, "connected");
  assert.equal(client.serverConnectionId, "server-connection-2");
  await client.disconnect();
  assert.equal(reconnected.peer.closed, true);
});

test("fails cleanly when microphone acquisition is denied", async () => {
  const harness = createHarness({ mediaFailure: new Error("permission denied") });
  const errors = [];
  const client = new BridgefuWebRtcClient({ environment: harness.environment });
  client.on("error", (event) => errors.push(event.error));

  await assert.rejects(
    client.connect(attachment()),
    (error) => error.code === "media-unavailable" && error.message === "microphone access failed",
  );
  assert.equal(client.state, "failed");
  assert.equal(harness.peers.length, 0);
  assert.equal(harness.sockets.length, 0);
  assert.equal(errors.length, 1);
});
