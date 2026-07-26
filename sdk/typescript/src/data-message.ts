import type {
  BridgefuContextEnvelopeV1,
  BridgefuContextInput,
  BridgefuHandoffEnvelopeV1,
  BridgefuWebRtcAttachment,
} from "./types.js";

export const RVOIP_DATA_MESSAGE_PROTOCOL = "rvoip.data.v1";
export const BRIDGEFU_CONTEXT_LABEL = "bridgefu.context.v1";
export const BRIDGEFU_CONTEXT_CONTENT_TYPE =
  "application/vnd.bridgefu.context.v1+json";
export const BRIDGEFU_HANDOFF_LABEL = "bridgefu.handoff.v1";
export const BRIDGEFU_HANDOFF_CONTENT_TYPE =
  "application/vnd.bridgefu.handoff.v1+json";

const MAGIC = new Uint8Array([0x52, 0x56, 0x44, 0x4d]); // RVDM
const WIRE_VERSION = 1;
const HEADER_BYTES = 22;
const TEXT_PREFIX = "rvoip-data-v1:";
const MAX_WEBRTC_DATA_MESSAGE_BYTES = 16 * 1024;
const MAX_DATA_BODY_BYTES = 64 * 1024;
const MAX_LABEL_BYTES = 128;
const MAX_CONTENT_TYPE_BYTES = 255;
const MAX_MESSAGE_ID_BYTES = 128;
const MAX_CONTEXT_ENTRIES = 64;
const MAX_CONTEXT_VALUE_BYTES = 2_048;
const MAX_CONTEXT_IDENTIFIER_BYTES = 512;
const MAX_HANDOFF_BYTES = 2 * 1024;
const RESERVED_CONTEXT_KEYS = new Set([
  "tenant_id",
  "call_id",
  "source_leg_id",
  "version",
]);

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

export type DataReliability =
  | { mode: "reliable-ordered" }
  | { mode: "reliable-unordered" }
  | { mode: "max-retransmits"; ordered: boolean; count: number }
  | { mode: "max-lifetime"; ordered: boolean; milliseconds: number };

export const RELIABLE_ORDERED: DataReliability = {
  mode: "reliable-ordered",
};

export interface RvoipDataMessage {
  label: string;
  contentType: string;
  data: Uint8Array;
  reliability: DataReliability;
  messageId: string;
}

export type EncodedRvoipDataMessage = string | Uint8Array;

export function dataChannelInitForReliability(
  reliability: DataReliability,
): RTCDataChannelInit {
  validateReliability(reliability);
  switch (reliability.mode) {
    case "reliable-ordered":
      return { ordered: true, protocol: RVOIP_DATA_MESSAGE_PROTOCOL };
    case "reliable-unordered":
      return { ordered: false, protocol: RVOIP_DATA_MESSAGE_PROTOCOL };
    case "max-retransmits":
      return {
        ordered: reliability.ordered,
        maxRetransmits: reliability.count,
        protocol: RVOIP_DATA_MESSAGE_PROTOCOL,
      };
    case "max-lifetime":
      return {
        ordered: reliability.ordered,
        maxPacketLifeTime: reliability.milliseconds,
        protocol: RVOIP_DATA_MESSAGE_PROTOCOL,
      };
  }
}

export function reliabilityFromDataChannel(channel: RTCDataChannel): DataReliability {
  if (channel.maxPacketLifeTime !== null && channel.maxRetransmits !== null) {
    throw new Error("DataChannel cannot set both lifetime and retransmit limits");
  }
  if (channel.maxPacketLifeTime !== null) {
    return {
      mode: "max-lifetime",
      ordered: channel.ordered,
      milliseconds: channel.maxPacketLifeTime,
    };
  }
  if (channel.maxRetransmits !== null) {
    return {
      mode: "max-retransmits",
      ordered: channel.ordered,
      count: channel.maxRetransmits,
    };
  }
  return channel.ordered
    ? { mode: "reliable-ordered" }
    : { mode: "reliable-unordered" };
}

/** Encode the exact rvoip-webrtc `RVDM` v1 DataChannel wire envelope. */
export function encodeRvoipDataMessage(
  message: Readonly<RvoipDataMessage>,
): EncodedRvoipDataMessage {
  validateDataMessage(message);
  const label = encoder.encode(message.label);
  const messageId = encoder.encode(message.messageId);
  const contentType = encoder.encode(message.contentType);
  const body = new Uint8Array(message.data);
  const total = HEADER_BYTES + label.length + messageId.length + contentType.length + body.length;
  if (total > MAX_WEBRTC_DATA_MESSAGE_BYTES) {
    throw new Error(`encoded DataMessage exceeds ${MAX_WEBRTC_DATA_MESSAGE_BYTES} bytes`);
  }

  const frame = new Uint8Array(total);
  frame.set(MAGIC, 0);
  frame[4] = WIRE_VERSION;
  const reliability = encodeReliability(message.reliability);
  frame[5] = reliability.kind;
  frame[6] = reliability.ordered ? 1 : 0;
  frame[7] = 0;
  const view = new DataView(frame.buffer);
  view.setUint32(8, reliability.value);
  view.setUint16(12, label.length);
  view.setUint16(14, messageId.length);
  view.setUint16(16, contentType.length);
  view.setUint32(18, body.length);
  let offset = HEADER_BYTES;
  frame.set(label, offset);
  offset += label.length;
  frame.set(messageId, offset);
  offset += messageId.length;
  frame.set(contentType, offset);
  offset += contentType.length;
  frame.set(body, offset);

  if (isTextualContentType(message.contentType)) {
    const encoded = `${TEXT_PREFIX}${base64UrlEncode(frame)}`;
    if (encoder.encode(encoded).length > MAX_WEBRTC_DATA_MESSAGE_BYTES) {
      throw new Error(`encoded DataMessage exceeds ${MAX_WEBRTC_DATA_MESSAGE_BYTES} bytes`);
    }
    return encoded;
  }
  return frame;
}

/** Decode and authenticate label/reliability against the receiving channel. */
export function decodeRvoipDataMessage(
  encoded: EncodedRvoipDataMessage,
  expected?: {
    label: string;
    reliability: DataReliability;
  },
): RvoipDataMessage {
  const isText = typeof encoded === "string";
  const frame = isText
    ? base64UrlDecode(requireTextPrefix(encoded))
    : new Uint8Array(encoded);
  if (frame.length > MAX_WEBRTC_DATA_MESSAGE_BYTES || frame.length < HEADER_BYTES) {
    throw new Error("invalid rvoip DataMessage frame length");
  }
  if (!MAGIC.every((value, index) => frame[index] === value)) {
    throw new Error("invalid rvoip DataMessage magic");
  }
  if (frame[4] !== WIRE_VERSION || frame[7] !== 0 || (frame[6] ?? 2) > 1) {
    throw new Error("unsupported or malformed rvoip DataMessage version");
  }

  const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
  const reliability = decodeReliability(
    requiredByte(frame, 5),
    requiredByte(frame, 6) === 1,
    view.getUint32(8),
  );
  const labelLength = view.getUint16(12);
  const idLength = view.getUint16(14);
  const contentTypeLength = view.getUint16(16);
  const bodyLength = view.getUint32(18);
  const expectedLength =
    HEADER_BYTES + labelLength + idLength + contentTypeLength + bodyLength;
  if (expectedLength !== frame.length) {
    throw new Error("rvoip DataMessage length fields do not match the frame");
  }

  let offset = HEADER_BYTES;
  const label = decodeUtf8(frame.subarray(offset, offset + labelLength));
  offset += labelLength;
  const messageId = decodeUtf8(frame.subarray(offset, offset + idLength));
  offset += idLength;
  const contentType = decodeUtf8(frame.subarray(offset, offset + contentTypeLength));
  offset += contentTypeLength;
  const message: RvoipDataMessage = {
    label,
    messageId,
    contentType,
    data: frame.slice(offset),
    reliability,
  };
  validateDataMessage(message);
  if (isText !== isTextualContentType(contentType)) {
    throw new Error("rvoip DataMessage text/binary kind does not match its content type");
  }
  if (
    expected &&
    (message.label !== expected.label ||
      !sameReliability(message.reliability, expected.reliability))
  ) {
    throw new Error("rvoip DataMessage does not match its DataChannel contract");
  }
  return message;
}

export async function decodeRvoipDataChannelMessage(
  channel: RTCDataChannel,
  data: unknown,
): Promise<RvoipDataMessage> {
  if (channel.protocol !== RVOIP_DATA_MESSAGE_PROTOCOL) {
    throw new Error("DataChannel does not use the rvoip DataMessage protocol");
  }
  const encoded = await normalizeChannelPayload(data);
  return decodeRvoipDataMessage(encoded, {
    label: channel.label,
    reliability: reliabilityFromDataChannel(channel),
  });
}

export function sendRvoipDataMessage(
  channel: RTCDataChannel,
  message: Readonly<RvoipDataMessage>,
): void {
  if (channel.readyState !== "open") {
    throw new Error("DataChannel is not open");
  }
  if (channel.protocol !== RVOIP_DATA_MESSAGE_PROTOCOL) {
    throw new Error("DataChannel does not use the rvoip DataMessage protocol");
  }
  if (
    message.label !== channel.label ||
    !sameReliability(message.reliability, reliabilityFromDataChannel(channel))
  ) {
    throw new Error("DataMessage does not match its DataChannel contract");
  }
  const encoded = encodeRvoipDataMessage(message);
  if (typeof encoded === "string") {
    channel.send(encoded);
  } else {
    const copy = encoded.slice();
    channel.send(copy.buffer);
  }
}

export function createBridgefuContextMessage(
  attachment: Readonly<BridgefuWebRtcAttachment>,
  input: Readonly<BridgefuContextInput>,
  messageId: string,
): RvoipDataMessage {
  const envelope: BridgefuContextEnvelopeV1 = {
    version: 1,
    correlation_id: input.correlationId,
    tenant_id: attachment.tenantId,
    call_id: attachment.callId,
    source_leg_id: attachment.legId,
    metadata: { ...(input.metadata ?? {}) },
  };
  validateContextEnvelope(envelope);
  const data = encoder.encode(JSON.stringify(envelope));
  if (data.length > MAX_WEBRTC_DATA_MESSAGE_BYTES) {
    throw new Error("Bridgefu context envelope exceeds 16 KiB");
  }
  return {
    label: BRIDGEFU_CONTEXT_LABEL,
    contentType: BRIDGEFU_CONTEXT_CONTENT_TYPE,
    data,
    reliability: RELIABLE_ORDERED,
    messageId,
  };
}

export function parseBridgefuContextMessage(
  message: Readonly<RvoipDataMessage>,
): BridgefuContextEnvelopeV1 {
  if (
    message.label !== BRIDGEFU_CONTEXT_LABEL ||
    message.contentType !== BRIDGEFU_CONTEXT_CONTENT_TYPE
  ) {
    throw new Error("DataMessage is not bridgefu.context.v1");
  }
  if (message.data.byteLength > MAX_WEBRTC_DATA_MESSAGE_BYTES) {
    throw new Error("Bridgefu context envelope exceeds 16 KiB");
  }
  const parsed: unknown = JSON.parse(decodeUtf8(message.data));
  if (!isRecord(parsed)) {
    throw new Error("Bridgefu context envelope must be an object");
  }
  const allowed = new Set([
    "version",
    "correlation_id",
    "tenant_id",
    "call_id",
    "source_leg_id",
    "metadata",
  ]);
  if (Object.keys(parsed).some((key) => !allowed.has(key))) {
    throw new Error("Bridgefu context envelope contains an unknown field");
  }
  const envelope: BridgefuContextEnvelopeV1 = {
    version: parsed.version as 1,
    correlation_id: parsed.correlation_id as string,
    tenant_id: parsed.tenant_id as string,
    call_id: parsed.call_id as string,
    source_leg_id: parsed.source_leg_id as string,
    metadata: (parsed.metadata ?? {}) as Record<string, string>,
  };
  validateContextEnvelope(envelope);
  return envelope;
}

export function parseBridgefuHandoffMessage(
  message: Readonly<RvoipDataMessage>,
): BridgefuHandoffEnvelopeV1 {
  if (
    message.label !== BRIDGEFU_HANDOFF_LABEL ||
    message.contentType !== BRIDGEFU_HANDOFF_CONTENT_TYPE ||
    message.reliability.mode !== "reliable-ordered" ||
    message.data.byteLength > MAX_HANDOFF_BYTES
  ) {
    throw new Error("DataMessage is not an authenticated Bridgefu handoff status");
  }
  const parsed: unknown = JSON.parse(decodeUtf8(message.data));
  if (!isRecord(parsed)) {
    throw new Error("Bridgefu handoff status must be an object");
  }
  const allowed = new Set([
    "version",
    "call_id",
    "replacement_leg_id",
    "binding_generation",
    "status",
    "detail_code",
  ]);
  if (Object.keys(parsed).some((key) => !allowed.has(key))) {
    throw new Error("Bridgefu handoff status contains an unknown field");
  }
  if (parsed.version !== 1) {
    throw new Error("unsupported Bridgefu handoff status version");
  }
  validateContextValue(parsed.call_id, "call_id", MAX_CONTEXT_IDENTIFIER_BYTES, false);
  validateContextValue(
    parsed.replacement_leg_id,
    "replacement_leg_id",
    MAX_CONTEXT_IDENTIFIER_BYTES,
    false,
  );
  if (
    !Number.isSafeInteger(parsed.binding_generation) ||
    (parsed.binding_generation as number) < 1
  ) {
    throw new Error("invalid Bridgefu handoff binding generation");
  }
  const statuses = new Set([
    "preparing",
    "ringing",
    "attaching",
    "connected",
    "resumed",
    "failed",
    "ended",
  ]);
  if (typeof parsed.status !== "string" || !statuses.has(parsed.status)) {
    throw new Error("invalid Bridgefu handoff status");
  }
  if (
    parsed.detail_code !== undefined &&
    (typeof parsed.detail_code !== "string" ||
      !/^[A-Za-z0-9_.-]{1,128}$/.test(parsed.detail_code))
  ) {
    throw new Error("invalid Bridgefu handoff detail code");
  }
  return parsed as unknown as BridgefuHandoffEnvelopeV1;
}

function validateDataMessage(message: Readonly<RvoipDataMessage>): void {
  validateBoundedText(message.label, "DataMessage label", MAX_LABEL_BYTES);
  validateBoundedText(message.messageId, "DataMessage ID", MAX_MESSAGE_ID_BYTES);
  validateBoundedText(message.contentType, "DataMessage content type", MAX_CONTENT_TYPE_BYTES);
  if (!validContentType(message.contentType)) {
    throw new Error("DataMessage content type is not a MIME media type");
  }
  if (message.data.byteLength > MAX_DATA_BODY_BYTES) {
    throw new Error(`DataMessage body exceeds ${MAX_DATA_BODY_BYTES} bytes`);
  }
  validateReliability(message.reliability);
}

function validateReliability(reliability: DataReliability): void {
  switch (reliability.mode) {
    case "reliable-ordered":
    case "reliable-unordered":
      return;
    case "max-retransmits":
      if (!Number.isInteger(reliability.count) || reliability.count < 0 || reliability.count > 65_535) {
        throw new Error("max retransmits must fit u16");
      }
      return;
    case "max-lifetime":
      if (
        !Number.isInteger(reliability.milliseconds) ||
        reliability.milliseconds < 1 ||
        reliability.milliseconds > 65_535
      ) {
        throw new Error("max lifetime must be between 1 and 65535 milliseconds");
      }
  }
}

function encodeReliability(reliability: DataReliability): {
  kind: number;
  ordered: boolean;
  value: number;
} {
  switch (reliability.mode) {
    case "reliable-ordered":
      return { kind: 0, ordered: true, value: 0 };
    case "reliable-unordered":
      return { kind: 0, ordered: false, value: 0 };
    case "max-retransmits":
      return { kind: 1, ordered: reliability.ordered, value: reliability.count };
    case "max-lifetime":
      return { kind: 2, ordered: reliability.ordered, value: reliability.milliseconds };
  }
}

function decodeReliability(kind: number, ordered: boolean, value: number): DataReliability {
  if (kind === 0 && value === 0) {
    return ordered ? { mode: "reliable-ordered" } : { mode: "reliable-unordered" };
  }
  if (kind === 1 && value <= 65_535) {
    return { mode: "max-retransmits", ordered, count: value };
  }
  if (kind === 2 && value >= 1 && value <= 65_535) {
    return { mode: "max-lifetime", ordered, milliseconds: value };
  }
  throw new Error("unsupported rvoip DataMessage reliability");
}

function sameReliability(left: DataReliability, right: DataReliability): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function isTextualContentType(contentType: string): boolean {
  const mediaType = contentType.split(";", 1)[0]?.trim().toLowerCase() ?? "";
  return (
    mediaType.startsWith("text/") ||
    mediaType === "application/json" ||
    mediaType.endsWith("+json") ||
    mediaType === "application/xml" ||
    mediaType.endsWith("+xml")
  );
}

function validContentType(value: string): boolean {
  const sections = value.split(";");
  const mediaType = sections.shift()?.trim() ?? "";
  const slash = mediaType.indexOf("/");
  if (
    slash <= 0 ||
    slash !== mediaType.lastIndexOf("/") ||
    !mimeToken(mediaType.slice(0, slash)) ||
    !mimeToken(mediaType.slice(slash + 1))
  ) {
    return false;
  }
  return sections.every((section) => {
    const parameter = section.trim();
    return (
      parameter.length > 0 &&
      [...parameter].every(
        (character) => character.charCodeAt(0) <= 0x7f && !/[\u0000-\u001f\u007f]/.test(character),
      )
    );
  });
}

function mimeToken(value: string): boolean {
  return value.length > 0 && /^[A-Za-z0-9!#$%&'*+.^_`|~-]+$/.test(value);
}

function requireTextPrefix(value: string): string {
  if (!value.startsWith(TEXT_PREFIX)) {
    throw new Error("invalid rvoip text DataMessage prefix");
  }
  return value.slice(TEXT_PREFIX.length);
}

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function base64UrlDecode(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(value)) {
    throw new Error("invalid base64url DataMessage envelope");
  }
  const padded = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(
    Math.ceil(value.length / 4) * 4,
    "=",
  );
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

async function normalizeChannelPayload(data: unknown): Promise<EncodedRvoipDataMessage> {
  if (typeof data === "string") {
    return data;
  }
  if (data instanceof ArrayBuffer) {
    return new Uint8Array(data);
  }
  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength));
  }
  if (typeof Blob !== "undefined" && data instanceof Blob) {
    return new Uint8Array(await data.arrayBuffer());
  }
  throw new Error("unsupported DataChannel payload type");
}

function decodeUtf8(bytes: Uint8Array): string {
  try {
    return decoder.decode(bytes);
  } catch (cause) {
    throw new Error("rvoip DataMessage contains invalid UTF-8", { cause });
  }
}

function requiredByte(frame: Uint8Array, index: number): number {
  const value = frame[index];
  if (value === undefined) {
    throw new Error("truncated rvoip DataMessage");
  }
  return value;
}

function validateContextEnvelope(envelope: BridgefuContextEnvelopeV1): void {
  if (envelope.version !== 1) {
    throw new Error("unsupported Bridgefu context version");
  }
  for (const [name, value] of Object.entries({
    correlation_id: envelope.correlation_id,
    tenant_id: envelope.tenant_id,
    call_id: envelope.call_id,
    source_leg_id: envelope.source_leg_id,
  })) {
    validateContextValue(value, name, MAX_CONTEXT_IDENTIFIER_BYTES, false);
  }
  if (!isRecord(envelope.metadata)) {
    throw new Error("Bridgefu context metadata must be an object");
  }
  const entries = Object.entries(envelope.metadata);
  if (entries.length > MAX_CONTEXT_ENTRIES) {
    throw new Error(`Bridgefu context metadata exceeds ${MAX_CONTEXT_ENTRIES} entries`);
  }
  for (const [key, value] of entries) {
    if (
      !key ||
      encoder.encode(key).length > 128 ||
      RESERVED_CONTEXT_KEYS.has(key) ||
      !/^[A-Za-z0-9_.-]+$/.test(key)
    ) {
      throw new Error(`invalid or reserved Bridgefu context metadata key: ${key}`);
    }
    validateContextValue(value, key, MAX_CONTEXT_VALUE_BYTES, true);
  }
}

function validateContextValue(
  value: unknown,
  name: string,
  maximumBytes: number,
  allowEmpty: boolean,
): asserts value is string {
  if (
    typeof value !== "string" ||
    (!allowEmpty && value.length === 0) ||
    encoder.encode(value).length > maximumBytes ||
    /[\r\n\0]/.test(value)
  ) {
    throw new Error(`invalid Bridgefu context value: ${name}`);
  }
}

function validateBoundedText(value: string, name: string, maximumBytes: number): void {
  if (!value || encoder.encode(value).length > maximumBytes || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new Error(`${name} is empty, oversized, or control-bearing`);
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
