#!/usr/bin/env node
/**
 * Controlled Amazon Connect Agent Workspace observer.
 *
 * This harness obtains facts from the real browser session: exact synthetic
 * screen-pop values, an instrumented inbound WebRTC track, the deterministic
 * fake microphone stream plus outbound RTP counters, Agent Workspace number-pad
 * DTMF with a Connect Streams fallback, and the contact's terminal UI. It accepts
 * selectors and paths,
 * never pass/fail booleans. Only field names, counts, timestamps, hashes, and a
 * 12-hex correlation fingerprint are retained.
 */

import { createHash } from "node:crypto";
import {
  chmodSync,
  closeSync,
  existsSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const PRODUCER = "bridgefu-agent-workspace-playwright@1";
const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "../../..");
const require = createRequire(join(ROOT, "sdk/typescript/package.json"));
process.env.PLAYWRIGHT_BROWSERS_PATH ??= "0";
const { chromium } = require("playwright");

const REQUIRED_FIELDS = [
  "customer_name",
  "issue_summary",
  "intent",
  "verification_status",
];
const SCREEN_POP_LABELS = Object.freeze({
  customer_name: "Customer:",
  issue_summary: "Issue:",
  intent: "Intent:",
  verification_status: "Verification:",
});
const SESSION_KEYS = new Set([
  "schema_version",
  "execution_id",
  "recipe",
  "release_id",
  "source_tree_sha256",
  "image",
  "session_id",
  "scenario_id",
  "hangup_origin",
  "security",
  "codec",
  "network_profile",
  "network_contract",
  "started_at",
  "started_epoch_ms",
  "correlation_id",
  "correlation_fingerprint",
  "source_call_id",
  "source_org_id",
  "source_call_fingerprint",
  "sip_uri",
  "sip_header",
  "expected_context",
  "session_hmac",
]);
const QUALIFIED_SCENARIOS = new Set([
  "sip-rtp-pcmu",
  "sip-rtp-pcma",
  "sips-srtp-pcmu",
  "sips-srtp-pcma",
  "vapi-web-transfer",
]);
const MAX_JSON_BYTES = 1024 * 1024;
const PROBE_SECONDS = 120;
const SAMPLE_RATE = 48_000;
const AGENT_MARKER_HZ = 880;
const AGENT_DTMF_SIX_LOW_HZ = 770;
const AGENT_DTMF_SIX_HIGH_HZ = 1_477;
const PROBE_INITIAL_SILENCE_MS = 5_000;
const PROBE_CYCLE_MS = 10_000;
const PROBE_PULSES_PER_CYCLE = 5;
const PROBE_PULSE_MS = 100;
const PROBE_DTMF_SIX_START_MS = 4_500;
const PROBE_DTMF_SIX_DURATION_MS = 300;

class HarnessError extends Error {}

function fail(message) {
  throw new HarnessError(message);
}

function sha256Bytes(value) {
  return createHash("sha256").update(value).digest("hex");
}

function sha256File(path) {
  return sha256Bytes(readFileSync(path));
}

function privateRegularFile(path, maximum = MAX_JSON_BYTES) {
  const details = lstatSync(path);
  if (!details.isFile() || details.isSymbolicLink()) {
    fail("private input must be a regular non-symlink file");
  }
  if (details.size <= 0 || details.size > maximum) {
    fail("private input exceeds its size boundary");
  }
  if ((details.mode & 0o077) !== 0) {
    fail("private input permissions must be mode 0600");
  }
}

function boundedJson(path) {
  privateRegularFile(path);
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch {
    fail("private input is not valid UTF-8 JSON");
  }
}

function exactKeys(value, expected) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).length === expected.size &&
    Object.keys(value).every((key) => expected.has(key))
  );
}

function validNetworkContract(profile, contract) {
  if (!contract || typeof contract !== "object" || Array.isArray(contract)) return false;
  if (
    Object.keys(contract).sort().join(",") !==
    "delay_ms,jitter_ms,loss_percent,reorder_percent"
  ) return false;
  const expected =
    profile === "baseline"
      ? [0, 0, 0, 0]
      : profile === "moderate-wan"
        ? [80, 20, 1, 0.1]
        : null;
  return (
    expected !== null &&
    [
      contract.delay_ms,
      contract.jitter_ms,
      contract.loss_percent,
      contract.reorder_percent,
    ].every((value, index) => value === expected[index])
  );
}

function validateSession(path) {
  const value = boundedJson(path);
  if (!exactKeys(value, SESSION_KEYS)) fail("private session shape changed");
  if (
    value.schema_version !== 1 ||
    value.recipe !== "vapi-amazon-connect-screen-pop@1" ||
    !/^bft-[a-z0-9-]{4,20}$/.test(value.execution_id) ||
    !QUALIFIED_SCENARIOS.has(value.scenario_id) ||
    !validNetworkContract(value.network_profile, value.network_contract) ||
    !["source", "agent"].includes(value.hangup_origin) ||
    !/^[0-9a-f]{12}$/.test(value.correlation_fingerprint) ||
    !/^[0-9a-f]{12}$/.test(value.source_call_fingerprint) ||
    !/^bf1_[A-Za-z0-9_-]{43}$/.test(value.correlation_id) ||
    sha256Bytes(value.correlation_id).slice(0, 12) !==
      value.correlation_fingerprint ||
    !value.expected_context ||
    typeof value.expected_context !== "object" ||
    !REQUIRED_FIELDS.every(
      (field) =>
        typeof value.expected_context[field] === "string" &&
        value.expected_context[field].length > 0,
    )
  ) {
    fail("private session violates the Agent Workspace contract");
  }
  if (
    value.expected_context.customer_name !== "Bridgefu Synthetic Caller" ||
    value.expected_context.verification_status !== "synthetic" ||
    value.expected_context.intent !== "qualification"
  ) {
    fail("Agent Workspace qualification accepts synthetic context only");
  }
  return value;
}

function validateConnectUrl(value) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    fail("Connect Agent Workspace URL is invalid");
  }
  if (
    parsed.protocol !== "https:" ||
    parsed.username ||
    parsed.password ||
    !parsed.hostname.endsWith(".my.connect.aws") ||
    !parsed.pathname.startsWith("/agent-app-v2/") ||
    parsed.hash
  ) {
    fail("use the default HTTPS Amazon Connect Agent Workspace URL");
  }
  return parsed;
}

function parseOptions(values, allowedFlags = new Set()) {
  const result = new Map();
  for (let index = 0; index < values.length; index += 1) {
    const name = values[index];
    if (!name.startsWith("--")) fail("unexpected positional argument");
    if (allowedFlags.has(name)) {
      result.set(name, true);
      continue;
    }
    const value = values[index + 1];
    if (!value || value.startsWith("--")) fail(`missing value for ${name}`);
    if (result.has(name)) fail(`duplicate option ${name}`);
    result.set(name, value);
    index += 1;
  }
  return result;
}

function required(options, name) {
  const value = options.get(name);
  if (typeof value !== "string" || value.length === 0) fail(`${name} is required`);
  return value;
}

function timeoutMilliseconds(options, fallback) {
  const value = options.get("--timeout-seconds") ?? String(fallback);
  if (!/^[0-9]+$/.test(value)) fail("timeout seconds must be an integer");
  const seconds = Number(value);
  if (seconds < 30 || seconds > 600) {
    fail("timeout seconds must be between 30 and 600");
  }
  return seconds * 1000;
}

function exclusiveJson(path, value) {
  if (existsSync(path)) fail("observation output already exists");
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  chmodSync(dirname(path), 0o700);
  const temporary = `${path}.tmp`;
  const descriptor = openSync(temporary, "wx", 0o600);
  try {
    writeFileSync(descriptor, `${JSON.stringify(value, null, 2)}\n`, "utf8");
  } finally {
    closeSync(descriptor);
  }
  renameSync(temporary, path);
  chmodSync(path, 0o600);
}

function writeProbeWav(path) {
  if (existsSync(path)) fail("fake microphone probe path already exists");
  const sampleCount = PROBE_SECONDS * SAMPLE_RATE;
  const bytesPerSample = 2;
  const bodyBytes = sampleCount * bytesPerSample;
  const buffer = Buffer.alloc(44 + bodyBytes);
  buffer.write("RIFF", 0);
  buffer.writeUInt32LE(36 + bodyBytes, 4);
  buffer.write("WAVEfmt ", 8);
  buffer.writeUInt32LE(16, 16);
  buffer.writeUInt16LE(1, 20);
  buffer.writeUInt16LE(1, 22);
  buffer.writeUInt32LE(SAMPLE_RATE, 24);
  buffer.writeUInt32LE(SAMPLE_RATE * bytesPerSample, 28);
  buffer.writeUInt16LE(bytesPerSample, 32);
  buffer.writeUInt16LE(16, 34);
  buffer.write("data", 36);
  buffer.writeUInt32LE(bodyBytes, 40);
  for (let sample = 0; sample < sampleCount; sample += 1) {
    const elapsedMs = (sample * 1000) / SAMPLE_RATE;
    const afterSilence = elapsedMs - PROBE_INITIAL_SILENCE_MS;
    const cycle = ((afterSilence % PROBE_CYCLE_MS) + PROBE_CYCLE_MS) % PROBE_CYCLE_MS;
    const pulseIndex = Math.floor(cycle / 1000);
    const inPulse =
      afterSilence >= 0 &&
      pulseIndex < PROBE_PULSES_PER_CYCLE &&
      cycle - pulseIndex * 1000 < PROBE_PULSE_MS;
    const inDtmfSix =
      afterSilence >= 0 &&
      cycle >= PROBE_DTMF_SIX_START_MS &&
      cycle < PROBE_DTMF_SIX_START_MS + PROBE_DTMF_SIX_DURATION_MS;
    let value = 0;
    if (inPulse) {
      value = Math.round(
        (Math.sin((2 * Math.PI * AGENT_MARKER_HZ * sample) / SAMPLE_RATE) +
          Math.sin((2 * Math.PI * AGENT_DTMF_SIX_LOW_HZ * sample) / SAMPLE_RATE) +
          Math.sin((2 * Math.PI * AGENT_DTMF_SIX_HIGH_HZ * sample) / SAMPLE_RATE)) *
          2730,
      );
    } else if (inDtmfSix) {
      value = Math.round(
        (Math.sin((2 * Math.PI * AGENT_DTMF_SIX_LOW_HZ * sample) / SAMPLE_RATE) +
          Math.sin((2 * Math.PI * AGENT_DTMF_SIX_HIGH_HZ * sample) / SAMPLE_RATE)) *
          4095,
      );
    }
    buffer.writeInt16LE(value, 44 + sample * bytesPerSample);
  }
  const descriptor = openSync(path, "wx", 0o600);
  try {
    writeFileSync(descriptor, buffer);
  } finally {
    closeSync(descriptor);
  }
}

async function waitUntil(operation, timeoutMs, message, intervalMs = 250) {
  const deadline = Date.now() + timeoutMs;
  let lastError;
  while (Date.now() < deadline) {
    try {
      const result = await operation();
      if (result) return result;
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolvePromise) => setTimeout(resolvePromise, intervalMs));
  }
  if (lastError) fail(`${message}: ${lastError.message}`);
  fail(message);
}

async function visibleExact(page, text) {
  for (const frame of page.frames()) {
    try {
      if (await frame.getByText(text, { exact: true }).first().isVisible()) return true;
    } catch {
      // A frame can detach while Agent Workspace changes contacts.
    }
  }
  return false;
}

async function visibleTextIncludes(page, values) {
  for (const frame of page.frames()) {
    try {
      const text = await frame.locator("body").innerText({ timeout: 1000 });
      if (values.every((value) => text.includes(value))) return true;
    } catch {
      // A frame can detach while Agent Workspace changes contacts.
    }
  }
  return false;
}

async function visibleLabeledValue(page, label, value) {
  const expected = `${label} ${value}`.replace(/\s+/g, " ").trim();
  for (const frame of page.frames()) {
    try {
      const text = await frame.locator("body").innerText({ timeout: 1000 });
      if (text.replace(/\s+/g, " ").includes(expected)) return true;
    } catch {
      // A frame can detach while Agent Workspace changes contacts.
    }
  }
  return false;
}

async function syntheticContextAbsent(page, session) {
  for (const field of REQUIRED_FIELDS) {
    if (
      await visibleLabeledValue(
        page,
        SCREEN_POP_LABELS[field],
        session.expected_context[field],
      )
    ) return false;
  }
  return true;
}

async function clickButton(page, patterns) {
  for (const frame of page.frames()) {
    for (const pattern of patterns) {
      try {
        const button = frame.getByRole("button", { name: pattern }).first();
        if (await button.isVisible()) {
          await button.click({ timeout: 3000 });
          return true;
        }
      } catch {
        // Continue across transient frames and the next exact control pattern.
      }
    }
  }
  return false;
}

async function clickButtonWithin(page, patterns, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  do {
    if (await clickButton(page, patterns)) return true;
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 100));
  } while (Date.now() < deadline);
  return false;
}

async function clickNestedNumberPadDigit(page, digit, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  for (const frame of page.frames()) {
    for (const selector of [
      'iframe[title="Contact Control Panel Number Pad"]',
      'iframe[title*="Number Pad"]',
    ]) {
      let childFrame = null;
      let frameHandle = null;
      try {
        frameHandle = await frame.locator(selector).first().elementHandle();
        childFrame = await frameHandle?.contentFrame();
      } catch {
        // The number-pad iframe may still be attaching.
      }
      if (childFrame) {
        for (const control of [
          childFrame.getByRole("button", { name: new RegExp(`^${digit}$`) }).first(),
          childFrame.getByText(digit, { exact: true }).first(),
        ]) {
          const remaining = deadline - Date.now();
          if (remaining <= 0) return false;
          try {
            await control.click({ timeout: Math.min(remaining, 750) });
            return true;
          } catch {
            // Try the next keypad accessibility variant.
          }
        }
      }
      await frameHandle?.dispose();
      const numberPad = frame.frameLocator(selector);
      for (const control of [
        numberPad.getByRole("button", { name: new RegExp(`^${digit}$`) }).first(),
        numberPad.getByText(digit, { exact: true }).first(),
      ]) {
        const remaining = deadline - Date.now();
        if (remaining <= 0) return false;
        try {
          await control.click({ timeout: Math.min(remaining, 750) });
          return true;
        } catch {
          // Continue across outer frames and keypad accessibility variants.
        }
      }
    }
  }
  return false;
}

async function sendDigitsViaConnectStreams(page, digits) {
  for (const frame of page.frames()) {
    try {
      const sent = await frame.evaluate(async (value) => {
        const streams = globalThis.connect;
        if (typeof streams?.Agent !== "function") return false;
        const agent = new streams.Agent();
        const contacts =
          typeof agent.getContacts === "function" ? agent.getContacts() : [];
        for (const contact of contacts) {
          const connection =
            contact.getActiveInitialConnection?.()
            ?? contact.getInitialConnection?.();
          if (
            !connection
            || typeof connection.sendDigits !== "function"
            || (typeof connection.isActive === "function" && !connection.isActive())
          ) continue;
          return await new Promise((resolvePromise) => {
            let finished = false;
            const settle = (result) => {
              if (finished) return;
              finished = true;
              resolvePromise(result);
            };
            const timer = setTimeout(() => settle(false), 3000);
            const callbacks = {
              success: () => {
                clearTimeout(timer);
                settle(true);
              },
              failure: () => {
                clearTimeout(timer);
                settle(false);
              },
            };
            try {
              connection.sendDigits(value, callbacks);
            } catch {
              clearTimeout(timer);
              settle(false);
            }
          });
        }
        return false;
      }, digits);
      if (sent) return true;
    } catch {
      // The Streams API is hosted in one of the Agent Workspace frames.
    }
  }
  return false;
}

async function buttonVisible(page, patterns) {
  for (const frame of page.frames()) {
    for (const pattern of patterns) {
      try {
        if (await frame.getByRole("button", { name: pattern }).first().isVisible()) {
          return true;
        }
      } catch {
        // Continue across transient frames and the next exact control pattern.
      }
    }
  }
  return false;
}

async function workspaceReady(page) {
  return (
    (await buttonVisible(page, [/^Available$/i])) ||
    (await visibleExact(page, "Available")) ||
    (await visibleExact(page, "Offline")) ||
    (await visibleExact(page, "Not Ready"))
  );
}

async function ensureAvailable(page, timeoutMs) {
  await waitUntil(
    async () =>
      (await visibleExact(page, "Available")) ||
      (await buttonVisible(page, [/^Available$/i])),
    Math.min(timeoutMs, 30_000),
    "Agent Workspace did not present the API-selected Available status",
  );
}

async function waitForAutoAcceptedContact(page, timeoutMs) {
  return waitUntil(
    async () => {
      const probe = await probeSnapshot(page);
      return (
        Number.isInteger(probe.captureRequestedAtMs) &&
        Number.isInteger(probe.captureResolvedAtMs) &&
        probe.remoteAudioTracks > 0 &&
        probe.audioPacketsSent > 0 &&
        probe.audioBytesSent > 0
      );
    },
    timeoutMs,
    "Agent Workspace did not auto-accept the synthetic contact",
  );
}

async function endControlVisible(page) {
  for (const frame of page.frames()) {
    for (const pattern of [/End call/i, /Hang up/i, /Disconnect/i]) {
      try {
        if (await frame.getByRole("button", { name: pattern }).first().isVisible()) return true;
      } catch {
        // Detached frame; continue.
      }
    }
  }
  return false;
}

async function probeSnapshot(page) {
  const snapshots = [];
  for (const frame of page.frames()) {
    try {
      const value = await frame.evaluate(async () => {
        const state = globalThis.__bridgefuAgentProbe;
        if (!state) return null;
        let audioPacketsSent = 0;
        let audioBytesSent = 0;
        for (const peer of globalThis.__bridgefuAgentPeerConnections ?? []) {
          try {
            const report = await peer.getStats();
            for (const row of report.values()) {
              if (row.type === "outbound-rtp" && row.kind === "audio" && !row.isRemote) {
                audioPacketsSent += Number(row.packetsSent ?? 0);
                audioBytesSent += Number(row.bytesSent ?? 0);
              }
            }
          } catch {
            // Closed peer; its last counters are not evidence for this snapshot.
          }
        }
        return {
          captureRequestedAtMs: state.captureRequestedAtMs,
          captureResolvedAtMs: state.captureResolvedAtMs,
          sourceMarkerObservedAtMs: [...state.sourceMarkerObservedAtMs],
          sourceMarkerFrames: state.sourceMarkerFrames,
          dtmfSourceToAgentObserved: state.dtmfSourceToAgentObserved,
          remoteAudioTracks: state.remoteAudioTracks,
          audioPacketsSent,
          audioBytesSent,
        };
      });
      if (value) snapshots.push(value);
    } catch {
      // Cross-origin or detached frames without the installed probe are ignored.
    }
  }
  const capture = snapshots
    .filter((item) => Number.isInteger(item.captureRequestedAtMs))
    .sort((left, right) => left.captureRequestedAtMs - right.captureRequestedAtMs)[0];
  const source = snapshots
    .filter((item) => item.sourceMarkerObservedAtMs.length > 0)
    .sort(
      (left, right) =>
        right.sourceMarkerObservedAtMs.length - left.sourceMarkerObservedAtMs.length,
    )[0];
  return {
    captureRequestedAtMs: capture?.captureRequestedAtMs ?? null,
    captureResolvedAtMs: capture?.captureResolvedAtMs ?? null,
    sourceMarkerObservedAtMs: source?.sourceMarkerObservedAtMs ?? [],
    sourceMarkerFrames: source?.sourceMarkerFrames ?? 0,
    dtmfSourceToAgentObserved: snapshots.some(
      (item) => item.dtmfSourceToAgentObserved,
    ),
    remoteAudioTracks: snapshots.reduce(
      (total, item) => total + item.remoteAudioTracks,
      0,
    ),
    audioPacketsSent: snapshots.reduce(
      (total, item) => total + item.audioPacketsSent,
      0,
    ),
    audioBytesSent: snapshots.reduce(
      (total, item) => total + item.audioBytesSent,
      0,
    ),
  };
}

function agentMarkerSchedule(captureStartedAtMs, acceptedAtMs, observedAtMs) {
  const firstMarker = captureStartedAtMs + PROBE_INITIAL_SILENCE_MS;
  const firstCycle = Math.max(
    0,
    Math.ceil((acceptedAtMs + 500 - firstMarker) / PROBE_CYCLE_MS),
  );
  const result = [];
  for (let cycle = firstCycle; result.length < 32; cycle += 1) {
    const cycleStart = firstMarker + cycle * PROBE_CYCLE_MS;
    for (let pulse = 0; pulse < PROBE_PULSES_PER_CYCLE; pulse += 1) {
      const timestamp = cycleStart + pulse * 1000;
      if (timestamp > observedAtMs) return result;
      result.push(timestamp);
    }
  }
  return result;
}

function installProbe() {
  if (globalThis.__bridgefuAgentProbe) return;
  // Playwright serializes this function into the browser page, so every value
  // used by the probe must be defined inside the function rather than captured.
  const requiredDtmfAnalyserFrames = 5;
  const state = {
    captureRequestedAtMs: null,
    captureResolvedAtMs: null,
    sourceMarkerObservedAtMs: [],
    sourceMarkerFrames: 0,
    sourceMarkerActive: false,
    sourceMarkerLastEdgeMs: 0,
    dtmfSourceToAgentObserved: false,
    dtmfConsecutiveFrames: 0,
    remoteAudioTracks: 0,
  };
  globalThis.__bridgefuAgentProbe = state;
  globalThis.__bridgefuAgentPeerConnections = [];

  const mediaDevices = navigator.mediaDevices;
  if (mediaDevices?.getUserMedia) {
    const original = mediaDevices.getUserMedia.bind(mediaDevices);
    mediaDevices.getUserMedia = async (...argumentsList) => {
      state.captureRequestedAtMs ??= Date.now();
      const stream = await original(...argumentsList);
      state.captureResolvedAtMs ??= Date.now();
      return stream;
    };
  }

  const power = (samples, sampleRate, frequency) => {
    const coefficient = 2 * Math.cos((2 * Math.PI * frequency) / sampleRate);
    let previous = 0;
    let beforePrevious = 0;
    for (const sample of samples) {
      const current = sample + coefficient * previous - beforePrevious;
      beforePrevious = previous;
      previous = current;
    }
    return (
      (previous * previous + beforePrevious * beforePrevious -
        coefficient * previous * beforePrevious) /
      (samples.length * samples.length)
    );
  };

  const observeTrack = (track) => {
    state.remoteAudioTracks += 1;
    const AudioContextClass = globalThis.AudioContext ?? globalThis.webkitAudioContext;
    if (!AudioContextClass) return;
    const context = new AudioContextClass();
    const source = context.createMediaStreamSource(new MediaStream([track]));
    const analyser = context.createAnalyser();
    analyser.fftSize = 2048;
    source.connect(analyser);
    const samples = new Float32Array(analyser.fftSize);
    const timer = setInterval(async () => {
      if (track.readyState === "ended") {
        clearInterval(timer);
        await context.close().catch(() => {});
        return;
      }
      await context.resume().catch(() => {});
      analyser.getFloatTimeDomainData(samples);
      let energy = 0;
      for (const sample of samples) energy += sample * sample;
      const rms = Math.sqrt(energy / samples.length);
      const marker = rms > 0.01 && power(samples, context.sampleRate, 997) > 0.0003;
      if (marker) {
        state.sourceMarkerFrames += 1;
        const now = Date.now();
        if (
          !state.sourceMarkerActive &&
          now - state.sourceMarkerLastEdgeMs >= 500 &&
          state.sourceMarkerObservedAtMs.length < 16
        ) {
          state.sourceMarkerObservedAtMs.push(now);
          state.sourceMarkerLastEdgeMs = now;
        }
      }
      state.sourceMarkerActive = marker;
      const low = power(samples, context.sampleRate, 770);
      const high = power(samples, context.sampleRate, 1336);
      const dtmf = rms > 0.01 && low > 0.00015 && high > 0.00015;
      state.dtmfConsecutiveFrames = dtmf ? state.dtmfConsecutiveFrames + 1 : 0;
      if (state.dtmfConsecutiveFrames >= requiredDtmfAnalyserFrames) {
        state.dtmfSourceToAgentObserved = true;
      }
    }, 20);
  };

  const NativePeerConnection = globalThis.RTCPeerConnection;
  if (NativePeerConnection) {
    globalThis.RTCPeerConnection = new Proxy(NativePeerConnection, {
      construct(Target, argumentsList, NewTarget) {
        const peer = Reflect.construct(Target, argumentsList, NewTarget);
        globalThis.__bridgefuAgentPeerConnections.push(peer);
        peer.addEventListener("track", (event) => {
          if (event.track?.kind === "audio") observeTrack(event.track);
        });
        return peer;
      },
    });
  }
}

async function authenticate(options) {
  const connectUrl = validateConnectUrl(required(options, "--connect-url"));
  const storageState = resolve(required(options, "--storage-state"));
  const timeoutMs = timeoutMilliseconds(options, 300);
  const credentialPath = options.get("--credential-file");
  let credential = null;
  if (credentialPath) {
    const value = boundedJson(resolve(credentialPath));
    if (
      !exactKeys(value, new Set(["username", "password"])) ||
      typeof value.username !== "string" ||
      !/^[A-Za-z0-9._@-]{1,128}$/.test(value.username) ||
      typeof value.password !== "string" ||
      value.password.length < 12 ||
      value.password.length > 128
    ) {
      fail("generated Connect credential has an invalid shape");
    }
    credential = value;
  }
  if (existsSync(storageState)) fail("storage-state output already exists");
  mkdirSync(dirname(storageState), { recursive: true, mode: 0o700 });
  chmodSync(dirname(storageState), 0o700);
  const browser = await chromium.launch({
    headless: credential !== null && !options.has("--headed"),
    args: credential === null ? [] : ["--no-sandbox"],
  });
  try {
    const context = await browser.newContext();
    const page = await context.newPage();
    await page.goto(connectUrl.href, { waitUntil: "domcontentloaded", timeout: 30_000 });
    if (credential !== null) {
      const username = page
        .locator(
          'input[autocomplete="username"], input[name*="username" i], input[type="email"], input[type="text"]',
        )
        .first();
      const password = page
        .locator('input[autocomplete="current-password"], input[name*="password" i], input[type="password"]')
        .first();
      await username.waitFor({ state: "visible", timeout: Math.min(timeoutMs, 60_000) });
      await username.fill(credential.username);
      if (!(await password.isVisible().catch(() => false))) {
        const continued = await clickButton(page, [/^Next$/i, /^Continue$/i]);
        if (!continued) fail("Connect login username continuation was unavailable");
      }
      await password.waitFor({ state: "visible", timeout: Math.min(timeoutMs, 60_000) });
      await password.fill(credential.password);
      const submitted = await clickButton(page, [/Sign in/i, /Log in/i, /Login/i]);
      if (!submitted) fail("Connect login submit control was unavailable");
    }
    await waitUntil(
      () => workspaceReady(page),
      timeoutMs,
      "Agent Workspace login did not complete before the deadline",
      1000,
    );
    const temporary = `${storageState}.tmp`;
    await context.storageState({ path: temporary });
    chmodSync(temporary, 0o600);
    renameSync(temporary, storageState);
    chmodSync(storageState, 0o600);
    process.stdout.write(`${storageState}\n`);
  } finally {
    await browser.close();
  }
}

async function observe(options) {
  const sessionPath = resolve(required(options, "--session"));
  const storageState = resolve(required(options, "--storage-state"));
  const screenshotPath = resolve(required(options, "--screenshot"));
  const observationPath = resolve(required(options, "--observation"));
  const connectUrl = validateConnectUrl(required(options, "--connect-url"));
  const timeoutMs = timeoutMilliseconds(options, 180);
  const expectMissingContext = options.has("--expect-missing-context");
  const session = validateSession(sessionPath);
  privateRegularFile(storageState);
  if (existsSync(screenshotPath) || existsSync(observationPath)) {
    fail("Agent Workspace evidence output already exists");
  }
  mkdirSync(dirname(observationPath), { recursive: true, mode: 0o700 });
  chmodSync(dirname(observationPath), 0o700);
  mkdirSync(dirname(screenshotPath), { recursive: true, mode: 0o700 });
  chmodSync(dirname(screenshotPath), 0o700);
  const probePath = join(dirname(observationPath), `.agent-probe-${session.session_id}.wav`);
  writeProbeWav(probePath);
  const executablePath = chromium.executablePath();
  if (!existsSync(executablePath)) {
    fail("Playwright Chromium is absent; install the pinned SDK browser first");
  }
  const browser = await chromium.launch({
    headless: !options.has("--headed"),
    args: [
      "--use-fake-ui-for-media-stream",
      "--use-fake-device-for-media-stream",
      `--use-file-for-fake-audio-capture=${probePath}`,
      "--autoplay-policy=no-user-gesture-required",
      "--no-sandbox",
    ],
  });
  try {
    const context = await browser.newContext({
      storageState,
      permissions: ["microphone"],
      viewport: { width: 1440, height: 1100 },
    });
    await context.addInitScript(installProbe);
    const page = await context.newPage();
    await page.goto(connectUrl.href, { waitUntil: "domcontentloaded", timeout: 30_000 });
    await waitUntil(
      () => workspaceReady(page),
      Math.min(timeoutMs, 60_000),
      "authenticated Agent Workspace was not ready",
    );
    await ensureAvailable(page, timeoutMs);
    await waitForAutoAcceptedContact(page, timeoutMs);
    if (expectMissingContext) {
      await waitUntil(
        async () =>
          (await visibleTextIncludes(page, ["Bridgefu caller context"]))
          && (await visibleLabeledValue(page, "Context available:", "false"))
          && (await syntheticContextAbsent(page, session)),
        Math.min(timeoutMs, 60_000),
        "Agent Workspace did not render the missing-context guide",
      );
      const stableUntil = Date.now() + 5_000;
      while (Date.now() < stableUntil) {
        if (!(await syntheticContextAbsent(page, session))) {
          fail("synthetic context appeared during missing-context observation");
        }
        await new Promise((resolvePromise) => setTimeout(resolvePromise, 250));
      }
    } else {
      await waitUntil(
        async () => {
          if (
            !(await visibleTextIncludes(page, ["Bridgefu caller context"]))
            || !(await visibleLabeledValue(page, "Context available:", "true"))
          ) return false;
          for (const field of REQUIRED_FIELDS) {
            if (
              !(await visibleLabeledValue(
                page,
                SCREEN_POP_LABELS[field],
                session.expected_context[field],
              ))
            ) return false;
          }
          return true;
        },
        Math.min(timeoutMs, 60_000),
        "Agent Workspace did not render the exact synthetic screen pop",
      );
    }
    await waitUntil(
      async () => {
        const probe = await probeSnapshot(page);
        const sourceMediaReadyAtMs = probe.sourceMarkerObservedAtMs[0];
        return (
          probe.sourceMarkerObservedAtMs.length >= 5 &&
          probe.dtmfSourceToAgentObserved &&
          probe.captureRequestedAtMs &&
          Number.isInteger(sourceMediaReadyAtMs) &&
          agentMarkerSchedule(
            probe.captureRequestedAtMs,
            sourceMediaReadyAtMs,
            Date.now(),
          ).length >= 5 &&
          probe.remoteAudioTracks > 0 &&
          probe.audioPacketsSent > 0 &&
          probe.audioBytesSent > 0
        );
      },
      Math.min(timeoutMs, 90_000),
      "Agent Workspace media/DTMF browser observations did not converge",
    );
    const keypadOpened = await clickButton(page, [
      /Number pad/i,
      /Keypad/i,
      /Dial pad/i,
      /Dialpad/i,
    ]);
    const keypadDigitSent = keypadOpened
      ? (await clickNestedNumberPadDigit(page, "6", 1_500))
        || (await clickButtonWithin(page, [/^6$/], 500))
      : false;
    const streamsDigitSent = keypadDigitSent
      ? false
      : await sendDigitsViaConnectStreams(page, "6");
    if (!keypadDigitSent && !streamsDigitSent) {
      if (!keypadOpened) fail("Agent Workspace keypad control was not available");
      fail("Agent Workspace did not expose DTMF digit 6");
    }

    const mediaProbe = await probeSnapshot(page);
    await page.screenshot({ path: screenshotPath, fullPage: false });
    chmodSync(screenshotPath, 0o600);
    const screenshotSha256 = sha256File(screenshotPath);
    let localEndCompleted = false;
    let remoteEndObserved = false;
    if (session.hangup_origin === "agent") {
      const ended = await clickButton(page, [/End call/i, /Hang up/i, /Disconnect/i]);
      if (!ended) fail("Agent Workspace end-call control was unavailable");
      localEndCompleted = true;
    } else {
      await waitUntil(
        async () => !(await endControlVisible(page)),
        Math.min(timeoutMs, 60_000),
        "Agent Workspace did not observe the source hangup",
      );
      remoteEndObserved = true;
    }
    await waitUntil(
      async () => !(await endControlVisible(page)),
      Math.min(timeoutMs, 30_000),
      "Agent Workspace contact controls did not clean up",
    );
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 1000));
    if (await endControlVisible(page)) fail("Agent Workspace contact cleanup was not stable");

    const observedAtMs = Date.now();
    const agentMarkerSentAtMs = agentMarkerSchedule(
      mediaProbe.captureRequestedAtMs,
      mediaProbe.sourceMarkerObservedAtMs[0],
      observedAtMs,
    );
    if (
      mediaProbe.sourceMarkerObservedAtMs.length < 5 ||
      mediaProbe.sourceMarkerFrames < 5 ||
      agentMarkerSentAtMs.length < 5 ||
      mediaProbe.audioPacketsSent < 5 ||
      !mediaProbe.dtmfSourceToAgentObserved
    ) {
      fail("Agent Workspace final media evidence is incomplete");
    }
    const screenObservation = expectMissingContext
      ? {
          generic_screen: {
            visible: true,
            context_available_false: true,
            synthetic_context_absent: true,
            screenshot_sha256: screenshotSha256,
          },
        }
      : {
          screen_pop: {
            visible: true,
            visible_fields: REQUIRED_FIELDS,
            screenshot_sha256: screenshotSha256,
          },
        };
    const observation = {
      schema_version: 1,
      producer: PRODUCER,
      producer_revision_sha256: sha256File(fileURLToPath(import.meta.url)),
      execution_id: session.execution_id,
      scenario_id: session.scenario_id,
      hangup_origin: session.hangup_origin,
      correlation_fingerprint: session.correlation_fingerprint,
      source_call_fingerprint: session.source_call_fingerprint,
      observed_at: new Date(observedAtMs).toISOString(),
      ...screenObservation,
      media: {
        source_to_agent_marker_frames: mediaProbe.sourceMarkerFrames,
        source_marker_observed_at_ms: mediaProbe.sourceMarkerObservedAtMs.slice(0, 16),
        agent_marker_sent_at_ms: agentMarkerSentAtMs.slice(0, 32),
        agent_to_source_marker_frames_sent: agentMarkerSentAtMs.length * 5,
        dtmf_source_to_agent_observed: true,
        dtmf_agent_to_source_sent: true,
      },
      hangup: {
        origin: session.hangup_origin,
        local_end_completed: localEndCompleted,
        remote_end_observed: remoteEndObserved,
        cleanup_observed: true,
      },
      redacted: true,
    };
    exclusiveJson(observationPath, observation);
    process.stdout.write(`${observationPath}\n`);
    await context.close();
  } finally {
    await browser.close();
    rmSync(probePath, { force: true });
  }
}

async function main() {
  const [command, ...values] = process.argv.slice(2);
  if (command === "auth") {
    const options = parseOptions(values, new Set(["--headed"]));
    for (const name of options.keys()) {
      if (
        ![
          "--connect-url",
          "--storage-state",
          "--timeout-seconds",
          "--credential-file",
          "--headed",
        ].includes(name)
      ) {
        fail(`unknown auth option ${name}`);
      }
    }
    await authenticate(options);
    return;
  }
  if (command === "observe") {
    const options = parseOptions(
      values,
      new Set(["--headed", "--expect-missing-context"]),
    );
    for (const name of options.keys()) {
      if (
        ![
          "--session",
          "--storage-state",
          "--connect-url",
          "--screenshot",
          "--observation",
          "--timeout-seconds",
          "--headed",
          "--expect-missing-context",
        ].includes(name)
      ) {
        fail(`unknown observe option ${name}`);
      }
    }
    await observe(options);
    return;
  }
  fail("command must be auth or observe");
}

main().catch((error) => {
  const message = error instanceof HarnessError ? error.message : "Agent Workspace harness failed";
  process.stderr.write(`error: ${message}\n`);
  process.exitCode = 1;
});
