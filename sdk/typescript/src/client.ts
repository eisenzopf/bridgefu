import {
  BRIDGEFU_CONTEXT_LABEL,
  BRIDGEFU_HANDOFF_LABEL,
  RELIABLE_ORDERED,
  RVOIP_DATA_MESSAGE_PROTOCOL,
  createBridgefuContextMessage,
  decodeRvoipDataChannelMessage,
  parseBridgefuContextMessage,
  parseBridgefuHandoffMessage,
  reliabilityFromDataChannel,
  sendRvoipDataMessage,
  type DataReliability,
  type RvoipDataMessage,
} from "./data-message.js";
import {
  BRIDGEFU_ATTACHMENT_PROTOCOL_PREFIX,
  BridgefuWebRtcError,
  RVOIP_SIGNALING_TOKEN_PROTOCOL_PREFIX,
  RVOIP_WEBRTC_SIGNALING_PROTOCOL,
  type BridgefuBrowserEnvironment,
  type BridgefuContextInput,
  type BridgefuDataChannelSpec,
  type BridgefuHandoffStatus,
  type BridgefuSignalingCredential,
  type BridgefuWebRtcAttachment,
  type BridgefuWebRtcClientOptions,
  type BridgefuWebRtcEventMap,
  type BridgefuWebRtcEventName,
  type BridgefuWebRtcState,
} from "./types.js";

interface SignalingMessage {
  type: string;
  sdp?: string;
  connection_id?: string;
  candidate?: string;
  request_id?: string;
}

interface Deferred<T> {
  promise: Promise<T>;
  resolve(value: T): void;
  reject(reason: unknown): void;
}

type PendingIce = RTCIceCandidateInit | null;
type ErasedListener = (event: unknown) => void;

const WEBSOCKET_OPEN = 1;
const DEFAULT_CONNECT_TIMEOUT_MS = 15_000;
const DEFAULT_DISCONNECT_GRACE_MS = 5_000;
const MAX_SIGNALING_FRAME_BYTES = 64 * 1024;
const MAX_SIGNALING_BACKLOG = 128;

/**
 * Browser-side owner for one Bridgefu WebRTC attachment.
 *
 * A client instance handles one active attachment at a time. Reconnection
 * requires a freshly issued descriptor because Bridgefu tokens are single-use.
 */
export class BridgefuWebRtcClient {
  private readonly environment: BridgefuBrowserEnvironment;
  private readonly rtcConfiguration: RTCConfiguration;
  private readonly microphone: boolean | MediaTrackConstraints;
  private readonly credentialProvider: BridgefuWebRtcClientOptions["signalingCredential"];
  private readonly ringback: BridgefuWebRtcClientOptions["ringback"];
  private readonly remoteAudioElement: BridgefuWebRtcClientOptions["remoteAudioElement"];
  private readonly connectTimeoutMs: number;
  private readonly disconnectGraceMs: number;
  private readonly allowInsecureLocalhost: boolean;
  private readonly channelSpecs: BridgefuDataChannelSpec[] = [];
  private readonly listeners = new Map<BridgefuWebRtcEventName, Set<ErasedListener>>();
  private readonly channels = new Map<string, RTCDataChannel>();

  private stateValue: BridgefuWebRtcState = "idle";
  private handoffStatus: BridgefuHandoffStatus | null = null;
  private lastHandoffGeneration = 0;
  private generation = 0;
  private intentionalClose = false;
  private ringbackActive = false;
  private peer: RTCPeerConnection | null = null;
  private socket: WebSocket | null = null;
  private localStream: MediaStream | null = null;
  private attachment: BridgefuWebRtcAttachment | null = null;
  private lastAttachmentToken: string | null = null;
  private connectionId: string | null = null;
  private requestId: string | null = null;
  private offerSdp: string | null = null;
  private peerConnected = false;
  private remoteAdmissionReady = false;
  private pendingIce: PendingIce[] = [];
  private signalingQueue: Promise<void> = Promise.resolve();
  private signalingBacklog = 0;
  private connectWaiter: Deferred<void> | null = null;
  private connectTimer: ReturnType<typeof setTimeout> | null = null;
  private disconnectTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(options: BridgefuWebRtcClientOptions = {}) {
    this.environment = options.environment ?? defaultBrowserEnvironment();
    this.rtcConfiguration = { ...(options.rtcConfiguration ?? {}) };
    this.microphone = options.microphone ?? true;
    this.credentialProvider = options.signalingCredential;
    this.ringback = options.ringback;
    this.remoteAudioElement = options.remoteAudioElement;
    this.connectTimeoutMs = options.connectTimeoutMs ?? DEFAULT_CONNECT_TIMEOUT_MS;
    this.disconnectGraceMs = options.disconnectGraceMs ?? DEFAULT_DISCONNECT_GRACE_MS;
    this.allowInsecureLocalhost = options.allowInsecureLocalhost ?? false;
    if (!Number.isFinite(this.connectTimeoutMs) || this.connectTimeoutMs <= 0) {
      throw new BridgefuWebRtcError("invalid-state", "connectTimeoutMs must be positive");
    }
    if (!Number.isFinite(this.disconnectGraceMs) || this.disconnectGraceMs < 0) {
      throw new BridgefuWebRtcError("invalid-state", "disconnectGraceMs must not be negative");
    }
    for (const spec of options.dataChannels ?? []) {
      this.addDataChannel(spec);
    }
  }

  get state(): BridgefuWebRtcState {
    return this.stateValue;
  }

  get peerConnection(): RTCPeerConnection | null {
    return this.peer;
  }

  get serverConnectionId(): string | null {
    return this.connectionId;
  }

  on<K extends BridgefuWebRtcEventName>(
    name: K,
    listener: (event: BridgefuWebRtcEventMap[K]) => void,
  ): () => void {
    let listeners = this.listeners.get(name);
    if (!listeners) {
      listeners = new Set();
      this.listeners.set(name, listeners);
    }
    const erased = listener as ErasedListener;
    listeners.add(erased);
    return () => listeners?.delete(erased);
  }

  /** Register an arbitrary DataChannel before the next initial offer. */
  addDataChannel(spec: BridgefuDataChannelSpec): void {
    if (!new Set<BridgefuWebRtcState>(["idle", "closed"]).has(this.stateValue)) {
      throw new BridgefuWebRtcError(
        "invalid-state",
        "DataChannels must be registered before connecting",
      );
    }
    validateDataChannelLabel(spec.label);
    if (spec.label === BRIDGEFU_CONTEXT_LABEL) {
      throw new BridgefuWebRtcError(
        "invalid-state",
        `${BRIDGEFU_CONTEXT_LABEL} is managed by the SDK`,
      );
    }
    if (spec.label === BRIDGEFU_HANDOFF_LABEL) {
      throw new BridgefuWebRtcError(
        "invalid-state",
        `${BRIDGEFU_HANDOFF_LABEL} is reserved for authenticated server status`,
      );
    }
    if (this.channelSpecs.some((existing) => existing.label === spec.label)) {
      throw new BridgefuWebRtcError("invalid-state", "DataChannel label is already registered");
    }
    if (spec.options?.maxPacketLifeTime !== undefined && spec.options.maxRetransmits !== undefined) {
      throw new BridgefuWebRtcError(
        "invalid-state",
        "maxPacketLifeTime and maxRetransmits are mutually exclusive",
      );
    }
    this.channelSpecs.push({ label: spec.label, options: { ...(spec.options ?? {}) } });
  }

  async connect(attachment: BridgefuWebRtcAttachment): Promise<void> {
    if (!new Set<BridgefuWebRtcState>(["idle", "closed"]).has(this.stateValue)) {
      throw new BridgefuWebRtcError("invalid-state", `cannot connect while ${this.stateValue}`);
    }
    return this.connectInternal(attachment);
  }

  /**
   * Tear down the old route and attach with a fresh single-use descriptor.
   * Replaying the previous attachment is rejected locally.
   */
  async reconnect(attachment: BridgefuWebRtcAttachment): Promise<void> {
    if (attachment.attachmentToken === this.lastAttachmentToken) {
      throw new BridgefuWebRtcError(
        "invalid-attachment",
        "reconnect requires a fresh single-use attachment token",
      );
    }
    this.setState("reconnecting");
    this.setHandoff("reconnecting");
    this.stopRingback("reconnecting");
    this.connectWaiter?.reject(
      new BridgefuWebRtcError("invalid-state", "connection replaced by reconnect"),
    );
    await this.cleanupResources(this.connectionId !== null);
    return this.connectInternal(attachment);
  }

  async disconnect(): Promise<void> {
    if (this.stateValue === "idle" || this.stateValue === "closed") {
      return;
    }
    this.setState("closing");
    this.connectWaiter?.reject(new BridgefuWebRtcError("invalid-state", "connection closed"));
    this.setHandoff("ended");
    this.stopRingback("ended");
    await this.cleanupResources(true);
    this.setState("closed");
  }

  getDataChannel(label: string): RTCDataChannel | null {
    return this.channels.get(label) ?? null;
  }

  sendRaw(label: string, data: string | ArrayBuffer | ArrayBufferView): void {
    const channel = this.requireOpenChannel(label);
    if (typeof data === "string") {
      channel.send(data);
      return;
    }
    if (data instanceof ArrayBuffer) {
      channel.send(data);
      return;
    }
    const copy = new Uint8Array(data.buffer, data.byteOffset, data.byteLength).slice();
    channel.send(copy.buffer);
  }

  sendDataMessage(
    label: string,
    contentType: string,
    data: string | Uint8Array,
    reliability?: DataReliability,
  ): RvoipDataMessage {
    const channel = this.requireOpenChannel(label);
    const message: RvoipDataMessage = {
      label,
      contentType,
      data: typeof data === "string" ? new TextEncoder().encode(data) : new Uint8Array(data),
      reliability: reliability ?? reliabilityFromDataChannel(channel),
      messageId: this.nextMessageId(),
    };
    sendRvoipDataMessage(channel, message);
    return message;
  }

  sendContext(input: BridgefuContextInput): RvoipDataMessage {
    const attachment = this.attachment;
    if (!attachment) {
      throw new BridgefuWebRtcError("invalid-state", "no active attachment");
    }
    const channel = this.requireOpenChannel(BRIDGEFU_CONTEXT_LABEL);
    const message = createBridgefuContextMessage(attachment, input, this.nextMessageId());
    sendRvoipDataMessage(channel, message);
    return message;
  }

  sendDtmf(tones: string, durationMs = 100, interToneGapMs = 70): void {
    if (!/^[0-9A-Da-d#*,]+$/.test(tones)) {
      throw new BridgefuWebRtcError("dtmf-unavailable", "invalid DTMF tone sequence");
    }
    if (durationMs < 40 || durationMs > 6_000 || interToneGapMs < 30) {
      throw new BridgefuWebRtcError("dtmf-unavailable", "invalid DTMF timing");
    }
    const sender = this.peer
      ?.getSenders()
      .find(
        (candidate) =>
          candidate.track?.kind === "audio" &&
          candidate.dtmf !== null &&
          candidate.dtmf.canInsertDTMF,
      );
    if (!sender?.dtmf?.canInsertDTMF) {
      throw new BridgefuWebRtcError(
        "dtmf-unavailable",
        "the negotiated browser audio sender cannot insert RFC 4733 DTMF",
      );
    }
    sender.dtmf.insertDTMF(tones.toUpperCase(), durationMs, interToneGapMs);
  }

  private async connectInternal(attachment: BridgefuWebRtcAttachment): Promise<void> {
    validateAttachment(attachment, this.environment.now(), this.allowInsecureLocalhost);
    if (attachment.attachmentToken === this.lastAttachmentToken) {
      throw new BridgefuWebRtcError(
        "invalid-attachment",
        "a single-use attachment token cannot be replayed",
      );
    }
    const generation = ++this.generation;
    this.intentionalClose = false;
    this.attachment = { ...attachment };
    this.lastAttachmentToken = attachment.attachmentToken;
    this.connectionId = null;
    this.requestId = this.nextRequestId();
    this.pendingIce = [];
    this.peerConnected = false;
    this.remoteAdmissionReady = false;
    this.signalingQueue = Promise.resolve();
    this.signalingBacklog = 0;
    this.lastHandoffGeneration = 0;
    this.setState("connecting");
    this.setHandoff("preparing");
    const waiter = deferred<void>();
    this.connectWaiter = waiter;
    this.connectTimer = setTimeout(() => {
      void this.fail(
        new BridgefuWebRtcError("timeout", "WebRTC attachment timed out"),
        generation,
      );
    }, this.connectTimeoutMs);

    try {
      const credential = attachment.signalingCredential
        ? { ...attachment.signalingCredential }
        : this.credentialProvider
          ? await this.credentialProvider({ ...attachment })
          : null;
      if (credential) {
        validateCredential(credential, this.environment.now());
      }
      this.assertGeneration(generation);

      if (this.microphone !== false) {
        try {
          this.localStream = await this.environment.getUserMedia({
            audio: this.microphone,
            video: false,
          });
        } catch (cause) {
          throw new BridgefuWebRtcError(
            "media-unavailable",
            "microphone access failed",
            { cause },
          );
        }
      }
      this.assertGeneration(generation);

      const peer = this.environment.createPeerConnection(
        configurationForAttachment(this.rtcConfiguration, attachment),
      );
      this.peer = peer;
      this.bindPeer(peer, generation);
      for (const track of this.localStream?.getAudioTracks() ?? []) {
        peer.addTrack(track, this.localStream as MediaStream);
      }
      this.installDataChannels(peer);

      const offer = await peer.createOffer({ offerToReceiveAudio: true, offerToReceiveVideo: false });
      await peer.setLocalDescription(offer);
      this.offerSdp = peer.localDescription?.sdp ?? offer.sdp ?? null;
      if (!this.offerSdp) {
        throw new BridgefuWebRtcError("protocol-error", "browser produced no local offer SDP");
      }

      // Permission prompts and offer generation can outlive short-lived route
      // credentials. Revalidate immediately before any network authority is
      // presented so an expired descriptor never reaches the signaling edge.
      validateAttachment(attachment, this.environment.now(), this.allowInsecureLocalhost);
      if (credential) {
        validateCredential(credential, this.environment.now());
      }
      this.assertGeneration(generation);

      const protocols = [
        RVOIP_WEBRTC_SIGNALING_PROTOCOL,
        ...(credential
          ? [`${RVOIP_SIGNALING_TOKEN_PROTOCOL_PREFIX}${credential.token}`]
          : []),
        `${BRIDGEFU_ATTACHMENT_PROTOCOL_PREFIX}${attachment.attachmentToken}`,
      ];
      const socket = this.environment.createWebSocket(attachment.signalingUrl, protocols);
      this.socket = socket;
      this.bindSocket(socket, generation);
    } catch (cause) {
      const error = asBridgefuError(cause);
      await this.fail(error, generation);
      // `fail` rejects the waiter used by asynchronous socket/peer handlers.
      // Observe that rejection here before returning the synchronous setup
      // error so a failed credential/media/socket factory cannot create an
      // unhandled rejection in the host page.
      await waiter.promise.catch(() => undefined);
      if (this.connectTimer) {
        clearTimeout(this.connectTimer);
        this.connectTimer = null;
      }
      if (this.connectWaiter === waiter) {
        this.connectWaiter = null;
      }
      throw error;
    }

    try {
      await waiter.promise;
    } finally {
      if (this.connectTimer) {
        clearTimeout(this.connectTimer);
        this.connectTimer = null;
      }
      if (this.connectWaiter === waiter) {
        this.connectWaiter = null;
      }
    }
  }

  private bindPeer(peer: RTCPeerConnection, generation: number): void {
    peer.onicecandidate = (event) => {
      if (generation !== this.generation) return;
      const candidate = event.candidate?.candidate
        ? event.candidate.toJSON()
        : null;
      try {
        this.sendOrQueueIce(candidate);
      } catch (cause) {
        void this.fail(asBridgefuError(cause), generation);
      }
    };
    peer.ontrack = (event) => {
      if (generation !== this.generation) return;
      if (event.track.kind === "audio" && this.remoteAudioElement && event.streams[0]) {
        this.remoteAudioElement.srcObject = event.streams[0];
        void this.remoteAudioElement.play().catch(() => {
          // Autoplay policy is application/UI state, not a transport failure.
        });
      }
      this.emit("remoteTrack", { event });
    };
    peer.ondatachannel = (event) => {
      if (generation !== this.generation) return;
      this.attachDataChannel(event.channel, "remote");
    };
    peer.onconnectionstatechange = () => {
      if (generation !== this.generation) return;
      switch (peer.connectionState) {
        case "connected":
          this.clearDisconnectTimer();
          this.peerConnected = true;
          this.tryCompleteAttachment(generation);
          break;
        case "disconnected":
          this.peerConnected = false;
          this.scheduleDisconnectFailure(generation);
          break;
        case "failed":
          this.peerConnected = false;
          void this.requireReconnect("peer-failed", generation);
          break;
        case "closed":
          this.peerConnected = false;
          if (!this.intentionalClose) {
            void this.requireReconnect("peer-failed", generation);
          }
          break;
        default:
          break;
      }
    };
  }

  private bindSocket(socket: WebSocket, generation: number): void {
    socket.onopen = () => {
      if (generation !== this.generation) return;
      if (socket.protocol !== RVOIP_WEBRTC_SIGNALING_PROTOCOL) {
        void this.fail(
          new BridgefuWebRtcError(
            "protocol-error",
            `server did not select ${RVOIP_WEBRTC_SIGNALING_PROTOCOL}`,
          ),
          generation,
        );
        return;
      }
      try {
        this.setHandoff("ringing");
        this.startRingback();
        this.sendSignaling({
          type: "offer-ready",
          sdp: this.offerSdp ?? "",
          request_id: this.requestId ?? "",
        });
      } catch (cause) {
        void this.fail(asBridgefuError(cause), generation);
      }
    };
    socket.onmessage = (event) => {
      if (generation !== this.generation || this.intentionalClose) return;
      if (this.signalingBacklog >= MAX_SIGNALING_BACKLOG) {
        void this.fail(
          new BridgefuWebRtcError("protocol-error", "signaling backlog limit exceeded"),
          generation,
        );
        return;
      }
      this.signalingBacklog += 1;
      const queued = this.signalingQueue.then(async () => {
        if (generation !== this.generation || this.intentionalClose) return;
        await this.handleSignalingMessage(event.data, generation);
      });
      // Keep the original rejected promise as the queue tail. Once any frame
      // fails validation, later frames on this attachment are never applied;
      // attaching a separate observer prevents an unhandled rejection while
      // preserving that fail-closed ordering fence.
      this.signalingQueue = queued;
      void queued.then(
        () => {
          if (generation === this.generation) {
            this.signalingBacklog = Math.max(0, this.signalingBacklog - 1);
          }
        },
        (cause: unknown) => {
          if (generation === this.generation) {
            this.signalingBacklog = Math.max(0, this.signalingBacklog - 1);
          }
          void this.fail(asBridgefuError(cause), generation);
        },
      );
    };
    socket.onerror = () => {
      if (generation !== this.generation || this.intentionalClose) return;
      void this.fail(
        new BridgefuWebRtcError("signaling-failed", "WebSocket signaling failed"),
        generation,
      );
    };
    socket.onclose = () => {
      if (generation !== this.generation || this.intentionalClose) return;
      if (this.stateValue === "connected") {
        void this.requireReconnect("signaling-closed", generation);
      } else {
        void this.fail(
          new BridgefuWebRtcError("signaling-failed", "WebSocket closed before attachment"),
          generation,
        );
      }
    };
  }

  private async handleSignalingMessage(data: unknown, generation: number): Promise<void> {
    if (typeof data !== "string") {
      throw new BridgefuWebRtcError("protocol-error", "signaling frames must be JSON text");
    }
    if (new TextEncoder().encode(data).length > MAX_SIGNALING_FRAME_BYTES) {
      throw new BridgefuWebRtcError("protocol-error", "signaling frame is too large");
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(data);
    } catch (cause) {
      throw new BridgefuWebRtcError("protocol-error", "invalid signaling JSON", { cause });
    }
    if (!isRecord(parsed) || typeof parsed.type !== "string") {
      throw new BridgefuWebRtcError("protocol-error", "invalid signaling envelope");
    }
    const message = parsed as unknown as SignalingMessage;
    switch (message.type) {
      case "answer": {
        if (
          typeof message.sdp !== "string" ||
          !message.sdp ||
          typeof message.connection_id !== "string" ||
          !message.connection_id ||
          message.request_id !== this.requestId ||
          this.connectionId !== null
        ) {
          throw new BridgefuWebRtcError("protocol-error", "invalid or mismatched answer");
        }
        const peer = this.peer;
        if (!peer) {
          throw new BridgefuWebRtcError("protocol-error", "answer has no live peer connection");
        }
        this.setHandoff("attaching");
        await peer.setRemoteDescription({ type: "answer", sdp: message.sdp });
        this.assertGeneration(generation);
        this.connectionId = message.connection_id;
        this.flushPendingIce();
        break;
      }
      case "ready":
        this.requireEmptyAdmissionPayload(message);
        this.requireAdmissionOutcomeMatch(message);
        if (this.remoteAdmissionReady) {
          throw new BridgefuWebRtcError("protocol-error", "duplicate admission readiness");
        }
        this.remoteAdmissionReady = true;
        this.tryCompleteAttachment(generation);
        break;
      case "rejected":
        this.requireEmptyAdmissionPayload(message);
        this.requireAdmissionOutcomeMatch(message);
        throw new BridgefuWebRtcError(
          "signaling-failed",
          "the remote application rejected this WebRTC attachment",
        );
      case "ice-candidate": {
        this.requireConnectionMatch(message.connection_id);
        if (typeof message.candidate !== "string" || !message.candidate) {
          throw new BridgefuWebRtcError("protocol-error", "invalid remote ICE candidate");
        }
        const candidate: unknown = JSON.parse(message.candidate);
        if (!isRecord(candidate) || typeof candidate.candidate !== "string") {
          throw new BridgefuWebRtcError("protocol-error", "invalid remote ICE candidate JSON");
        }
        let candidateInit = candidate as unknown as RTCIceCandidateInit;
        // rvoip-rtc 0.3.8 emits an empty sdpMid together with a valid m-line
        // index for trickled candidates. An empty MID names no media section;
        // Chromium accepts the promise but does not form a candidate pair.
        // Remove only that invalid empty selector and retain the explicit
        // m-line index. Non-empty MIDs and candidates without a valid index are
        // never rewritten.
        if (
          candidate.sdpMid === "" &&
          Number.isInteger(candidate.sdpMLineIndex) &&
          Number(candidate.sdpMLineIndex) >= 0 &&
          Number(candidate.sdpMLineIndex) <= 65_535
        ) {
          const { sdpMid: _invalidEmptyMid, ...indexedCandidate } = candidate;
          candidateInit = indexedCandidate as unknown as RTCIceCandidateInit;
        }
        await this.peer?.addIceCandidate(candidateInit);
        break;
      }
      case "ice-complete":
        this.requireConnectionMatch(message.connection_id);
        await this.peer?.addIceCandidate(null);
        break;
      case "bye":
        this.requireConnectionMatch(message.connection_id);
        this.connectWaiter?.reject(
          new BridgefuWebRtcError("signaling-failed", "remote peer ended during attachment"),
        );
        this.setHandoff("ended");
        this.stopRingback("ended");
        await this.cleanupResources(false);
        this.setState("closed");
        break;
      default:
        throw new BridgefuWebRtcError("protocol-error", "unsupported signaling message type");
    }
  }

  private installDataChannels(peer: RTCPeerConnection): void {
    const context = peer.createDataChannel(BRIDGEFU_CONTEXT_LABEL, {
      ordered: true,
      protocol: RVOIP_DATA_MESSAGE_PROTOCOL,
    });
    this.attachDataChannel(context, "local");
    const handoff = peer.createDataChannel(BRIDGEFU_HANDOFF_LABEL, {
      ordered: true,
      protocol: RVOIP_DATA_MESSAGE_PROTOCOL,
    });
    this.attachDataChannel(handoff, "local");
    for (const spec of this.channelSpecs) {
      this.attachDataChannel(peer.createDataChannel(spec.label, spec.options), "local");
    }
  }

  private attachDataChannel(channel: RTCDataChannel, origin: "local" | "remote"): void {
    validateDataChannelLabel(channel.label);
    const previous = this.channels.get(channel.label);
    if (previous && previous !== channel && previous.readyState !== "closed") {
      channel.close();
      this.emit("error", {
        error: new BridgefuWebRtcError(
          "protocol-error",
          "duplicate live DataChannel label was rejected",
        ),
      });
      return;
    }
    this.channels.set(channel.label, channel);
    channel.onmessage = (event) => {
      if (channel.protocol !== RVOIP_DATA_MESSAGE_PROTOCOL) {
        this.emit("rawMessage", { channel, data: event.data });
        return;
      }
      void decodeRvoipDataChannelMessage(channel, event.data)
        .then((message) => {
          this.emit("dataMessage", { channel, message });
          if (message.label === BRIDGEFU_CONTEXT_LABEL) {
            const envelope = parseBridgefuContextMessage(message);
            if (
              this.attachment &&
              (envelope.tenant_id !== this.attachment.tenantId ||
                envelope.call_id !== this.attachment.callId)
            ) {
              throw new Error("received Bridgefu context belongs to another call");
            }
            this.emit("context", { channel, envelope, message });
          } else if (message.label === BRIDGEFU_HANDOFF_LABEL) {
            const envelope = parseBridgefuHandoffMessage(message);
            if (!this.attachment || envelope.call_id !== this.attachment.callId) {
              throw new Error("received Bridgefu handoff status belongs to another call");
            }
            if (envelope.binding_generation < this.lastHandoffGeneration) {
              throw new Error("received stale Bridgefu handoff status generation");
            }
            this.lastHandoffGeneration = envelope.binding_generation;
            this.applyServerHandoffStatus(envelope.status, envelope.detail_code);
            this.emit("handoffMessage", { channel, envelope, message });
          }
        })
        .catch((cause: unknown) => {
          this.emit("error", {
            error: new BridgefuWebRtcError(
              "protocol-error",
              "invalid inbound DataChannel message",
              { cause },
            ),
          });
        });
    };
    channel.onclose = () => {
      if (this.channels.get(channel.label) === channel) {
        this.channels.delete(channel.label);
      }
    };
    this.emit("dataChannel", { channel, origin });
  }

  private sendOrQueueIce(candidate: PendingIce): void {
    if (!this.connectionId || this.socket?.readyState !== WEBSOCKET_OPEN) {
      this.pendingIce.push(candidate);
      return;
    }
    if (candidate === null) {
      this.sendSignaling({ type: "ice-complete", connection_id: this.connectionId });
    } else {
      this.sendSignaling({
        type: "ice-candidate",
        connection_id: this.connectionId,
        candidate: JSON.stringify(candidate),
      });
    }
  }

  private flushPendingIce(): void {
    const pending = this.pendingIce;
    this.pendingIce = [];
    for (const candidate of pending) {
      this.sendOrQueueIce(candidate);
    }
  }

  private sendSignaling(message: SignalingMessage): void {
    if (this.socket?.readyState !== WEBSOCKET_OPEN) {
      throw new BridgefuWebRtcError("signaling-failed", "WebSocket is not open");
    }
    this.socket.send(JSON.stringify(message));
  }

  private requireConnectionMatch(connectionId: unknown): void {
    if (
      typeof connectionId !== "string" ||
      !connectionId ||
      !this.connectionId ||
      connectionId !== this.connectionId
    ) {
      throw new BridgefuWebRtcError("protocol-error", "signaling route ownership mismatch");
    }
  }

  private requireAdmissionOutcomeMatch(message: SignalingMessage): void {
    this.requireConnectionMatch(message.connection_id);
    if (
      typeof message.request_id !== "string" ||
      !this.requestId ||
      message.request_id !== this.requestId
    ) {
      throw new BridgefuWebRtcError(
        "protocol-error",
        "signaling admission outcome ownership mismatch",
      );
    }
  }

  private requireEmptyAdmissionPayload(message: SignalingMessage): void {
    if ((message.sdp ?? "") !== "" || (message.candidate ?? "") !== "") {
      throw new BridgefuWebRtcError(
        "protocol-error",
        "signaling admission outcome contains an unexpected payload",
      );
    }
  }

  private tryCompleteAttachment(generation: number): void {
    if (
      generation !== this.generation ||
      !this.peerConnected ||
      !this.remoteAdmissionReady ||
      !this.connectionId ||
      this.stateValue === "connected"
    ) {
      return;
    }
    this.setState("connected");
    this.setHandoff("connected");
    this.stopRingback("connected");
    this.connectWaiter?.resolve(undefined);
  }

  private requireOpenChannel(label: string): RTCDataChannel {
    const channel = this.channels.get(label);
    if (!channel || channel.readyState !== "open") {
      throw new BridgefuWebRtcError(
        "data-channel-unavailable",
        `DataChannel ${label} is not open`,
      );
    }
    return channel;
  }

  private scheduleDisconnectFailure(generation: number): void {
    this.clearDisconnectTimer();
    this.disconnectTimer = setTimeout(() => {
      if (this.peer?.connectionState === "disconnected") {
        void this.requireReconnect("peer-disconnected", generation);
      }
    }, this.disconnectGraceMs);
  }

  private clearDisconnectTimer(): void {
    if (this.disconnectTimer) {
      clearTimeout(this.disconnectTimer);
      this.disconnectTimer = null;
    }
  }

  private async requireReconnect(
    reason: BridgefuWebRtcEventMap["reconnectRequired"]["reason"],
    generation: number,
  ): Promise<void> {
    if (generation !== this.generation || this.intentionalClose) return;
    const error = new BridgefuWebRtcError(
      "signaling-failed",
      "the attachment ended; reconnect with a fresh descriptor",
    );
    this.connectWaiter?.reject(error);
    this.setHandoff("failed", reason);
    this.stopRingback("failed");
    await this.cleanupResources(false);
    this.setState("reconnect-required");
    this.emit("reconnectRequired", { reason });
  }

  private async fail(error: BridgefuWebRtcError, generation: number): Promise<void> {
    if (generation !== this.generation || this.intentionalClose) return;
    this.emit("error", { error });
    this.connectWaiter?.reject(error);
    this.setHandoff("failed", error.code);
    this.stopRingback("failed");
    await this.cleanupResources(false);
    this.setState("failed");
  }

  private async cleanupResources(sendBye: boolean): Promise<void> {
    this.intentionalClose = true;
    this.clearDisconnectTimer();
    if (this.connectTimer) {
      clearTimeout(this.connectTimer);
      this.connectTimer = null;
    }

    const socket = this.socket;
    this.socket = null;
    if (socket) {
      if (sendBye && socket.readyState === WEBSOCKET_OPEN && this.connectionId) {
        try {
          socket.send(JSON.stringify({ type: "bye", connection_id: this.connectionId }));
        } catch {
          // The peer route is still closed locally below.
        }
      }
      socket.onopen = null;
      socket.onmessage = null;
      socket.onerror = null;
      socket.onclose = null;
      try {
        socket.close(1000, "bridgefu-client-close");
      } catch {
        // Already closed.
      }
    }

    const channels = [...this.channels.values()];
    this.channels.clear();
    for (const channel of channels) {
      channel.onmessage = null;
      channel.onclose = null;
      try {
        channel.close();
      } catch {
        // Already closed.
      }
    }

    const peer = this.peer;
    this.peer = null;
    if (peer) {
      peer.onicecandidate = null;
      peer.ontrack = null;
      peer.ondatachannel = null;
      peer.onconnectionstatechange = null;
      peer.close();
    }
    for (const track of this.localStream?.getTracks() ?? []) {
      track.stop();
    }
    this.localStream = null;
    if (this.remoteAudioElement) {
      this.remoteAudioElement.srcObject = null;
    }
    this.attachment = null;
    this.connectionId = null;
    this.requestId = null;
    this.offerSdp = null;
    this.peerConnected = false;
    this.remoteAdmissionReady = false;
    this.pendingIce = [];
    this.signalingBacklog = 0;
  }

  private setState(state: BridgefuWebRtcState): void {
    if (state === this.stateValue) return;
    const previous = this.stateValue;
    this.stateValue = state;
    this.emit("state", { previous, state });
  }

  private setHandoff(status: BridgefuHandoffStatus, detail?: string): void {
    if (status === this.handoffStatus && detail === undefined) return;
    const previous = this.handoffStatus;
    this.handoffStatus = status;
    this.emit("handoff", { previous, status, ...(detail ? { detail } : {}) });
  }

  private applyServerHandoffStatus(
    status: Exclude<BridgefuHandoffStatus, "reconnecting">,
    detail?: string,
  ): void {
    this.setHandoff(status, detail);
    if (status === "preparing" || status === "ringing" || status === "attaching") {
      this.startRingback();
    } else {
      this.stopRingback(status === "resumed" ? "resumed" : status);
    }
  }

  private startRingback(): void {
    if (this.ringbackActive || !this.ringback) return;
    this.ringbackActive = true;
    this.invokeRingback(() => this.ringback?.start());
  }

  private stopRingback(reason: Parameters<NonNullable<typeof this.ringback>["stop"]>[0]): void {
    if (!this.ringbackActive || !this.ringback) return;
    this.ringbackActive = false;
    this.invokeRingback(() => this.ringback?.stop(reason));
  }

  private invokeRingback(operation: () => void | Promise<void> | undefined): void {
    try {
      void Promise.resolve(operation()).catch((cause: unknown) => {
        this.emit("error", {
          error: new BridgefuWebRtcError("media-unavailable", "ringback hook failed", { cause }),
        });
      });
    } catch (cause) {
      this.emit("error", {
        error: new BridgefuWebRtcError("media-unavailable", "ringback hook failed", { cause }),
      });
    }
  }

  private emit<K extends BridgefuWebRtcEventName>(
    name: K,
    event: BridgefuWebRtcEventMap[K],
  ): void {
    for (const listener of this.listeners.get(name) ?? []) {
      try {
        listener(event);
      } catch {
        // An application observer cannot take down signaling or cleanup.
      }
    }
  }

  private nextRequestId(): string {
    const value = `browser-${this.environment.randomId()}`
      .replace(/[^A-Za-z0-9._:-]/g, "-")
      .slice(0, 128);
    if (!value || value.length > 128) {
      throw new BridgefuWebRtcError("protocol-error", "could not create a signaling request ID");
    }
    return value;
  }

  private nextMessageId(): string {
    return `msg_${this.environment.randomId()}`
      .replace(/[\u0000-\u001f\u007f]/g, "-")
      .slice(0, 128);
  }

  private assertGeneration(generation: number): void {
    if (generation !== this.generation || this.intentionalClose) {
      throw new BridgefuWebRtcError("invalid-state", "connection attempt was superseded");
    }
  }
}

function defaultBrowserEnvironment(): BridgefuBrowserEnvironment {
  return {
    createPeerConnection: (configuration) => new RTCPeerConnection(configuration),
    createWebSocket: (url, protocols) => new WebSocket(url, protocols),
    getUserMedia: (constraints) => navigator.mediaDevices.getUserMedia(constraints),
    now: () => Date.now(),
    randomId: () =>
      globalThis.crypto?.randomUUID?.() ??
      `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`,
  };
}

function configurationForAttachment(
  configured: Readonly<RTCConfiguration>,
  attachment: Readonly<BridgefuWebRtcAttachment>,
): RTCConfiguration {
  if (!attachment.iceServers) {
    return { ...configured };
  }
  return {
    ...configured,
    iceServers: attachment.iceServers.map((server) => ({
      ...server,
      urls: Array.isArray(server.urls) ? [...server.urls] : server.urls,
    })),
  };
}

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

function validateAttachment(
  attachment: BridgefuWebRtcAttachment,
  now: number,
  allowInsecureLocalhost: boolean,
): void {
  if (attachment.version !== 1 || attachment.transport !== "webrtc") {
    throw new BridgefuWebRtcError("invalid-attachment", "unsupported attachment descriptor");
  }
  if (!/^[A-Za-z0-9_-]{16,512}$/.test(attachment.attachmentToken)) {
    throw new BridgefuWebRtcError("invalid-attachment", "invalid attachment token");
  }
  for (const [name, value] of Object.entries({
    tenantId: attachment.tenantId,
    callId: attachment.callId,
    legId: attachment.legId,
  })) {
    if (!value || new TextEncoder().encode(value).length > 512 || /[\r\n\0]/.test(value)) {
      throw new BridgefuWebRtcError("invalid-attachment", `invalid attachment ${name}`);
    }
  }
  const expiry = Date.parse(attachment.expiresAt);
  if (!Number.isFinite(expiry) || expiry <= now) {
    throw new BridgefuWebRtcError("invalid-attachment", "attachment is expired");
  }
  let url: URL;
  try {
    url = new URL(attachment.signalingUrl);
  } catch (cause) {
    throw new BridgefuWebRtcError("invalid-attachment", "invalid signaling URL", { cause });
  }
  const local =
    url.hostname === "localhost" ||
    url.hostname === "127.0.0.1" ||
    url.hostname === "::1" ||
    url.hostname === "[::1]";
  if (url.protocol !== "wss:" && !(allowInsecureLocalhost && local && url.protocol === "ws:")) {
    throw new BridgefuWebRtcError("invalid-attachment", "signaling requires WSS");
  }
  if (url.username || url.password || url.hash || url.searchParams.has("access_token")) {
    throw new BridgefuWebRtcError(
      "invalid-attachment",
      "signaling URL must not contain credentials or access tokens",
    );
  }
}

function validateCredential(credential: BridgefuSignalingCredential, now: number): void {
  if (
    credential.usage !== "bridgefu-webrtc-signaling" ||
    credential.token.length > 4_096 ||
    !/^[A-Za-z0-9!#$%&'*+\-.^_`|~]+$/.test(credential.token)
  ) {
    throw new BridgefuWebRtcError(
      "invalid-credential",
      "invalid signaling-only credential",
    );
  }
  const expiry = Date.parse(credential.expiresAt);
  if (!Number.isFinite(expiry) || expiry <= now) {
    throw new BridgefuWebRtcError("invalid-credential", "signaling credential is expired");
  }
}

function validateDataChannelLabel(label: string): void {
  if (!label || new TextEncoder().encode(label).length > 128 || /[\u0000-\u001f\u007f]/.test(label)) {
    throw new BridgefuWebRtcError("invalid-state", "invalid DataChannel label");
  }
}

function asBridgefuError(cause: unknown): BridgefuWebRtcError {
  return cause instanceof BridgefuWebRtcError
    ? cause
    : new BridgefuWebRtcError(
        "signaling-failed",
        cause instanceof Error && cause.message
          ? `WebRTC attachment failed: ${cause.message}`
          : "WebRTC attachment failed",
        { cause },
      );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
