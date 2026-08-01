import type { RvoipDataMessage } from "./data-message.js";

/** rvoip WebSocket signaling subprotocol selected by the server. */
export const RVOIP_WEBRTC_SIGNALING_PROTOCOL = "rvoip.webrtc.v1";

/** Private subprotocol prefix carrying one single-use Bridgefu attachment. */
export const BRIDGEFU_ATTACHMENT_PROTOCOL_PREFIX = "bridgefu.attach.";

/** Private subprotocol prefix carrying a signaling-only bearer. */
export const RVOIP_SIGNALING_TOKEN_PROTOCOL_PREFIX = "token.";

/**
 * Everything a browser needs to attach one exact inbound WebRTC leg.
 *
 * This descriptor intentionally contains no Bridgefu control-plane bearer.
 * The attachment token is short-lived, single-use routing material.
 */
export interface BridgefuWebRtcAttachment {
  version: 1;
  transport: "webrtc";
  signalingUrl: string;
  attachmentToken: string;
  expiresAt: string;
  tenantId: string;
  callId: string;
  legId: string;
  /** Attachment-bound bearer accepted only by the WebRTC signaling edge. */
  signalingCredential?: BridgefuSignalingCredential;
  /** Server-provided STUN/TURN configuration for this route. */
  iceServers?: readonly RTCIceServer[];
}

/** WebRTC attachment shape returned by Bridgefu's named-route REST API. */
export interface BridgefuRouteWebRtcAttachment {
  type: "webrtc";
  signaling_uri: string;
  token: string;
  signaling_credential: {
    usage: "bridgefu-webrtc-signaling";
    token: string;
    expires_at: string;
  };
  subprotocols: readonly string[];
  ice_servers: readonly RTCIceServer[];
  expires_at: string;
}

/** Authenticated call identity surrounding a named-route attachment. */
export interface BridgefuAttachmentBinding {
  tenantId: string;
  callId: string;
  legId: string;
}

/**
 * A short-lived credential minted only for the WebRTC signaling surface.
 * Applications must never return their Bridgefu REST/API bearer here.
 */
export interface BridgefuSignalingCredential {
  usage: "bridgefu-webrtc-signaling";
  token: string;
  expiresAt: string;
}

export type BridgefuSignalingCredentialProvider = (
  attachment: Readonly<BridgefuWebRtcAttachment>,
) => Promise<BridgefuSignalingCredential>;

export type BridgefuWebRtcState =
  | "idle"
  | "connecting"
  | "connected"
  | "reconnecting"
  | "reconnect-required"
  | "closing"
  | "closed"
  | "failed";

export type BridgefuHandoffStatus =
  | "preparing"
  | "ringing"
  | "attaching"
  | "connected"
  | "resumed"
  | "reconnecting"
  | "ended"
  | "failed";

export interface BridgefuRingbackController {
  start(): void | Promise<void>;
  stop(reason: "connected" | "resumed" | "ended" | "failed" | "reconnecting"): void | Promise<void>;
}

/** An application DataChannel created before the initial offer. */
export interface BridgefuDataChannelSpec {
  label: string;
  options?: RTCDataChannelInit;
}

export interface BridgefuBrowserEnvironment {
  createPeerConnection(configuration: RTCConfiguration): RTCPeerConnection;
  createWebSocket(url: string, protocols: string[]): WebSocket;
  getUserMedia(constraints: MediaStreamConstraints): Promise<MediaStream>;
  now(): number;
  randomId(): string;
}

export interface BridgefuWebRtcClientOptions {
  rtcConfiguration?: RTCConfiguration;
  microphone?: boolean | MediaTrackConstraints;
  signalingCredential?: BridgefuSignalingCredentialProvider;
  ringback?: BridgefuRingbackController;
  remoteAudioElement?: HTMLMediaElement;
  dataChannels?: BridgefuDataChannelSpec[];
  connectTimeoutMs?: number;
  disconnectGraceMs?: number;
  allowInsecureLocalhost?: boolean;
  environment?: BridgefuBrowserEnvironment;
}

export interface BridgefuContextInput {
  correlationId: string;
  metadata?: Readonly<Record<string, string>>;
}

export interface BridgefuContextEnvelopeV1 {
  version: 1;
  correlation_id: string;
  tenant_id: string;
  call_id: string;
  source_leg_id: string;
  metadata: Record<string, string>;
}

/** Bridgefu-authenticated replacement status received only on its reserved channel. */
export interface BridgefuHandoffEnvelopeV1 {
  version: 1;
  call_id: string;
  replacement_leg_id: string;
  binding_generation: number;
  status: Exclude<BridgefuHandoffStatus, "reconnecting">;
  detail_code?: string;
}

export interface BridgefuWebRtcEventMap {
  state: {
    previous: BridgefuWebRtcState;
    state: BridgefuWebRtcState;
  };
  handoff: {
    previous: BridgefuHandoffStatus | null;
    status: BridgefuHandoffStatus;
    detail?: string;
  };
  remoteTrack: {
    event: RTCTrackEvent;
  };
  dataChannel: {
    channel: RTCDataChannel;
    origin: "local" | "remote";
  };
  dataMessage: {
    channel: RTCDataChannel;
    message: RvoipDataMessage;
  };
  rawMessage: {
    channel: RTCDataChannel;
    data: unknown;
  };
  context: {
    channel: RTCDataChannel;
    envelope: BridgefuContextEnvelopeV1;
    message: RvoipDataMessage;
  };
  handoffMessage: {
    channel: RTCDataChannel;
    envelope: BridgefuHandoffEnvelopeV1;
    message: RvoipDataMessage;
  };
  reconnectRequired: {
    reason: "signaling-closed" | "peer-disconnected" | "peer-failed";
  };
  error: {
    error: BridgefuWebRtcError;
  };
}

export type BridgefuWebRtcEventName = keyof BridgefuWebRtcEventMap;

export class BridgefuWebRtcError extends Error {
  readonly code:
    | "invalid-attachment"
    | "invalid-credential"
    | "invalid-state"
    | "media-unavailable"
    | "signaling-failed"
    | "protocol-error"
    | "timeout"
    | "data-channel-unavailable"
    | "dtmf-unavailable";

  constructor(code: BridgefuWebRtcError["code"], message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "BridgefuWebRtcError";
    this.code = code;
  }
}
