import {
  BRIDGEFU_ATTACHMENT_PROTOCOL_PREFIX,
  RVOIP_SIGNALING_TOKEN_PROTOCOL_PREFIX,
  RVOIP_WEBRTC_SIGNALING_PROTOCOL,
  type BridgefuAttachmentBinding,
  type BridgefuRouteWebRtcAttachment,
  type BridgefuWebRtcAttachment,
} from "./types.js";

/**
 * Normalize the snake_case named-route REST response into the self-contained
 * descriptor consumed by {@link BridgefuWebRtcClient}.
 *
 * The surrounding call response supplies the authenticated tenant/call/leg
 * binding. This helper checks that the server's private attachment
 * subprotocol and token agree before either value reaches WebSocket setup.
 */
export function normalizeBridgefuRouteAttachment(
  attachment: Readonly<BridgefuRouteWebRtcAttachment>,
  binding: Readonly<BridgefuAttachmentBinding>,
): BridgefuWebRtcAttachment {
  if (attachment.type !== "webrtc") {
    throw new Error("named-route attachment is not WebRTC");
  }
  const expectedPrivateProtocol = `${BRIDGEFU_ATTACHMENT_PROTOCOL_PREFIX}${attachment.token}`;
  const expectedCredentialProtocol = `${RVOIP_SIGNALING_TOKEN_PROTOCOL_PREFIX}${attachment.signaling_credential.token}`;
  if (
    attachment.subprotocols.length !== 3 ||
    attachment.subprotocols[0] !== RVOIP_WEBRTC_SIGNALING_PROTOCOL ||
    attachment.subprotocols[1] !== expectedCredentialProtocol ||
    attachment.subprotocols[2] !== expectedPrivateProtocol
  ) {
    throw new Error("named-route attachment subprotocols do not match its token");
  }
  return {
    version: 1,
    transport: "webrtc",
    signalingUrl: attachment.signaling_uri,
    attachmentToken: attachment.token,
    expiresAt: attachment.expires_at,
    tenantId: binding.tenantId,
    callId: binding.callId,
    legId: binding.legId,
    signalingCredential: {
      usage: attachment.signaling_credential.usage,
      token: attachment.signaling_credential.token,
      expiresAt: attachment.signaling_credential.expires_at,
    },
    iceServers: attachment.ice_servers.map(cloneIceServer),
  };
}

function cloneIceServer(server: RTCIceServer): RTCIceServer {
  return {
    urls: Array.isArray(server.urls) ? [...server.urls] : server.urls,
    ...(server.username !== undefined ? { username: server.username } : {}),
    ...(server.credential !== undefined ? { credential: server.credential } : {}),
  };
}
