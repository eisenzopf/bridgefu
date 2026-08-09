#!/usr/bin/env node
/**
 * Controlled stock Vapi webCall source for the flagship recipe.
 *
 * The exact immutable demo-site bundle is served either by the deployed
 * CloudFront distribution or, for a non-deployed qualification, on 127.0.0.1.
 * The browser-safe public key stays in process memory, the raw Vapi call ID is
 * exchanged through a mode-0600 handshake, and retained output contains only
 * hashes, counts, timestamps, and fixed labels.
 */

import { createHash, randomBytes } from "node:crypto";
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
import { createServer } from "node:http";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const PRODUCER = "bridgefu-vapi-web-playwright@1";
const SDK_VERSION = "2.5.2";
const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "../../..");
const require = createRequire(join(ROOT, "sdk/typescript/package.json"));
process.env.PLAYWRIGHT_BROWSERS_PATH ??= "0";
const { chromium } = require("playwright");

const MAX_JSON_BYTES = 1024 * 1024;
const MAX_SITE_FILE_BYTES = 2 * 1024 * 1024;
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
const SAMPLE_RATE = 48_000;
const PROBE_SECONDS = 120;
const SOURCE_MARKER_HZ = 997;
const AGENT_MARKER_HZ = 880;
const PROBE_INITIAL_SILENCE_MS = 5_000;
const PROBE_CYCLE_MS = 10_000;
const PROBE_PULSES_PER_CYCLE = 5;
const PROBE_PULSE_MS = 100;
const DTMF_START_MS = 6_000;
const DTMF_DURATION_MS = 350;

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

function privateRegularFile(path, maximum = MAX_JSON_BYTES) {
  const details = lstatSync(path);
  if (!details.isFile() || details.isSymbolicLink()) fail("private input is not a regular file");
  if (details.size <= 0 || details.size > maximum) fail("private input exceeds its boundary");
  if ((details.mode & 0o077) !== 0) fail("private input permissions must be mode 0600");
}

function boundedPublicFile(path) {
  const details = lstatSync(path);
  if (!details.isFile() || details.isSymbolicLink()) fail("site input is not a regular file");
  if (details.size <= 0 || details.size > MAX_SITE_FILE_BYTES) fail("site input exceeds its boundary");
  return readFileSync(path);
}

function privateJson(path) {
  privateRegularFile(path);
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch {
    fail("private input is not valid UTF-8 JSON");
  }
}

function exclusiveJson(path, value) {
  if (existsSync(path)) fail("private output already exists");
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

function parseOptions(values) {
  const options = new Map();
  for (let index = 0; index < values.length; index += 1) {
    const name = values[index];
    if (!name.startsWith("--")) fail("unexpected positional argument");
    if (name === "--headed") {
      options.set(name, true);
      continue;
    }
    const value = values[index + 1];
    if (!value || value.startsWith("--")) fail(`missing value for ${name}`);
    if (options.has(name)) fail(`duplicate option ${name}`);
    options.set(name, value);
    index += 1;
  }
  return options;
}

function required(options, name) {
  const value = options.get(name);
  if (typeof value !== "string" || value.length === 0) fail(`${name} is required`);
  return value;
}

function timeoutMilliseconds(options) {
  const raw = options.get("--timeout-seconds") ?? "180";
  if (!/^[0-9]+$/.test(raw)) fail("timeout seconds must be an integer");
  const seconds = Number(raw);
  if (seconds < 30 || seconds > 600) fail("timeout seconds must be between 30 and 600");
  return seconds * 1000;
}

function validatePublicKey(value) {
  if (typeof value !== "string" || value.length < 8 || value.length > 256 || /[\s<>"']/.test(value)) {
    fail("VAPI_PUBLIC_KEY is missing or invalid");
  }
  return value;
}

function validateAssistantId(value) {
  if (!/^[0-9a-f]{8}-[0-9a-f-]{27,40}$/i.test(value)) fail("assistant ID is invalid");
  return value;
}

function validateSha256(value, label) {
  if (!/^[0-9a-f]{64}$/.test(value)) fail(`${label} digest is invalid`);
  return value;
}

function validateSiteUrl(value) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    fail("deployed demo-site URL is invalid");
  }
  if (
    parsed.protocol !== "https:" ||
    parsed.username ||
    parsed.password ||
    parsed.port ||
    !/^d[a-z0-9]+\.cloudfront\.net$/.test(parsed.hostname) ||
    !["", "/"].includes(parsed.pathname) ||
    parsed.search ||
    parsed.hash
  ) {
    fail("deployed demo-site URL must be an exact CloudFront HTTPS origin");
  }
  return `${parsed.origin}/`;
}

function writeProbeWav(path) {
  if (existsSync(path)) fail("fake microphone path already exists");
  const sampleCount = PROBE_SECONDS * SAMPLE_RATE;
  const bodyBytes = sampleCount * 2;
  const buffer = Buffer.alloc(44 + bodyBytes);
  buffer.write("RIFF", 0);
  buffer.writeUInt32LE(36 + bodyBytes, 4);
  buffer.write("WAVEfmt ", 8);
  buffer.writeUInt32LE(16, 16);
  buffer.writeUInt16LE(1, 20);
  buffer.writeUInt16LE(1, 22);
  buffer.writeUInt32LE(SAMPLE_RATE, 24);
  buffer.writeUInt32LE(SAMPLE_RATE * 2, 28);
  buffer.writeUInt16LE(2, 32);
  buffer.writeUInt16LE(16, 34);
  buffer.write("data", 36);
  buffer.writeUInt32LE(bodyBytes, 40);
  for (let sample = 0; sample < sampleCount; sample += 1) {
    const elapsedMs = (sample * 1000) / SAMPLE_RATE;
    const afterSilence = elapsedMs - PROBE_INITIAL_SILENCE_MS;
    const cycle = ((afterSilence % PROBE_CYCLE_MS) + PROBE_CYCLE_MS) % PROBE_CYCLE_MS;
    const pulse = Math.floor(cycle / 1000);
    const marker =
      afterSilence >= 0 &&
      pulse < PROBE_PULSES_PER_CYCLE &&
      cycle - pulse * 1000 < PROBE_PULSE_MS;
    const dtmf =
      afterSilence >= 0 &&
      cycle >= DTMF_START_MS &&
      cycle < DTMF_START_MS + DTMF_DURATION_MS;
    let value = 0;
    if (marker) value += Math.sin((2 * Math.PI * SOURCE_MARKER_HZ * sample) / SAMPLE_RATE);
    if (dtmf) {
      value += 0.55 * Math.sin((2 * Math.PI * 770 * sample) / SAMPLE_RATE);
      value += 0.55 * Math.sin((2 * Math.PI * 1336 * sample) / SAMPLE_RATE);
    }
    buffer.writeInt16LE(Math.round(Math.max(-1, Math.min(1, value)) * 8191), 44 + sample * 2);
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

async function waitForPrivateFile(path, timeoutMs) {
  return waitUntil(
    () => {
      if (!existsSync(path)) return false;
      privateRegularFile(path);
      return true;
    },
    timeoutMs,
    "private orchestration file did not arrive",
  );
}

function validateSession(path, callId, hangupOrigin) {
  const session = privateJson(path);
  if (!exactKeys(session, SESSION_KEYS)) fail("private session shape changed");
  const callFingerprint = sha256Bytes(callId).slice(0, 12);
  if (
    session.schema_version !== 1 ||
    session.recipe !== "vapi-amazon-connect-screen-pop@1" ||
    session.scenario_id !== "vapi-web-transfer" ||
    session.hangup_origin !== hangupOrigin ||
    !["sips_srtp", "sip_rtp"].includes(session.security) ||
    session.codec !== "negotiated" ||
    !validNetworkContract(session.network_profile, session.network_contract) ||
    session.sip_uri !== null ||
    session.source_call_id !== callId ||
    !/^[A-Za-z0-9_-]{1,128}$/.test(session.source_org_id) ||
    session.source_call_fingerprint !== callFingerprint ||
    !/^bf1_[A-Za-z0-9_-]{43}$/.test(session.correlation_id) ||
    sha256Bytes(session.correlation_id).slice(0, 12) !== session.correlation_fingerprint ||
    session.sip_header?.name !== "X-Correlation-Id" ||
    session.sip_header?.value !== session.correlation_id ||
    session.expected_context?.customer_name !== "Bridgefu Synthetic Caller" ||
    session.expected_context?.issue_summary !==
      `Qualification vapi-web-transfer ${hangupOrigin} hangup.` ||
    session.expected_context?.intent !== "qualification" ||
    session.expected_context?.verification_status !== "synthetic"
  ) {
    fail("private session violates the Vapi source contract");
  }
  return session;
}

function installProbe() {
  if (globalThis.__bridgefuVapiProbe) return;
  const state = {
    captureRequestedAtMs: null,
    captureResolvedAtMs: null,
    agentMarkerObservedAtMs: [],
    agentMarkerFrames: 0,
    agentMarkerActive: false,
    agentMarkerLastEdgeMs: 0,
    dtmfAgentToSourceObserved: false,
    dtmfActive: false,
    remoteAudioTracks: 0,
  };
  globalThis.__bridgefuVapiProbe = state;
  globalThis.__bridgefuVapiPeers = [];
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
      (previous * previous + beforePrevious * beforePrevious - coefficient * previous * beforePrevious) /
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
      const marker = rms > 0.01 && power(samples, context.sampleRate, AGENT_MARKER_HZ) > 0.0003;
      if (marker) {
        state.agentMarkerFrames += 1;
        const now = Date.now();
        if (
          !state.agentMarkerActive &&
          now - state.agentMarkerLastEdgeMs >= 500 &&
          state.agentMarkerObservedAtMs.length < 16
        ) {
          state.agentMarkerObservedAtMs.push(now);
          state.agentMarkerLastEdgeMs = now;
        }
      }
      state.agentMarkerActive = marker;
      const low = power(samples, context.sampleRate, 770);
      const high = power(samples, context.sampleRate, 1477);
      const dtmf = rms > 0.01 && low > 0.00015 && high > 0.00015;
      if (dtmf && !state.dtmfActive) state.dtmfAgentToSourceObserved = true;
      state.dtmfActive = dtmf;
    }, 20);
  };
  const NativePeerConnection = globalThis.RTCPeerConnection;
  if (NativePeerConnection) {
    globalThis.RTCPeerConnection = new Proxy(NativePeerConnection, {
      construct(Target, argumentsList, NewTarget) {
        const peer = Reflect.construct(Target, argumentsList, NewTarget);
        globalThis.__bridgefuVapiPeers.push(peer);
        peer.addEventListener("track", (event) => {
          if (event.track?.kind === "audio") observeTrack(event.track);
        });
        return peer;
      },
    });
  }
}

async function probeSnapshot(page) {
  return page.evaluate(async () => {
    const state = globalThis.__bridgefuVapiProbe;
    if (!state) return null;
    let audioPacketsSent = 0;
    let audioBytesSent = 0;
    let telephoneEventPacketsReceived = 0;
    for (const peer of globalThis.__bridgefuVapiPeers ?? []) {
      try {
        const report = await peer.getStats();
        const telephoneEventCodecs = new Set();
        for (const row of report.values()) {
          if (
            row.type === "codec" &&
            typeof row.mimeType === "string" &&
            row.mimeType.toLowerCase() === "audio/telephone-event"
          ) {
            telephoneEventCodecs.add(row.id);
          }
        }
        for (const row of report.values()) {
          if (row.type === "outbound-rtp" && row.kind === "audio" && !row.isRemote) {
            audioPacketsSent += Number(row.packetsSent ?? 0);
            audioBytesSent += Number(row.bytesSent ?? 0);
          }
          if (
            row.type === "inbound-rtp" &&
            telephoneEventCodecs.has(row.codecId)
          ) {
            telephoneEventPacketsReceived += Number(row.packetsReceived ?? 0);
          }
        }
      } catch {
        // Closed peer counters are intentionally excluded.
      }
    }
    return {
      captureRequestedAtMs: state.captureRequestedAtMs,
      captureResolvedAtMs: state.captureResolvedAtMs,
      agentMarkerObservedAtMs: [...state.agentMarkerObservedAtMs],
      agentMarkerFrames: state.agentMarkerFrames,
      dtmfAgentToSourceObserved: state.dtmfAgentToSourceObserved,
      remoteAudioTracks: state.remoteAudioTracks,
      audioPacketsSent,
      audioBytesSent,
      telephoneEventPacketsReceived,
    };
  });
}

function sourceMarkerSchedule(captureStartedAtMs, triggerAtMs, observedAtMs) {
  const firstMarker = captureStartedAtMs + PROBE_INITIAL_SILENCE_MS;
  const firstCycle = Math.max(0, Math.ceil((triggerAtMs + 500 - firstMarker) / PROBE_CYCLE_MS));
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

async function applicationSnapshot(page, nonce) {
  return page.evaluate(
    (qualificationNonce) =>
      globalThis.__BRIDGEFU_RECIPE_QUALIFICATION__?.snapshot(qualificationNonce) ?? null,
    nonce,
  );
}

async function waitForSiteReady(page, timeoutMs) {
  try {
    await waitUntil(
      () => page.locator("#start").isEnabled(),
      timeoutMs,
      "immutable Vapi demo site did not become ready",
    );
  } catch (error) {
    const state = await page.evaluate(() => {
      const value = globalThis.__BRIDGEFU_RECIPE_TEST__;
      return value && typeof value === "object"
        ? { status: value.status, errorType: value.errorType }
        : null;
    }).catch(() => null);
    if (state?.status === "failed") {
      if (state.errorType === "configuration-invalid") {
        fail("immutable Vapi demo site rejected its configuration");
      }
      if (state.errorType === "configuration-unavailable") {
        fail("immutable Vapi demo site configuration was unavailable");
      }
      fail("immutable Vapi demo site failed during initialization");
    }
    if (state?.status === "loading") {
      fail("immutable Vapi demo site configuration load did not settle");
    }
    throw error;
  }
}

function contentType(path) {
  if (path.endsWith(".html")) return "text/html; charset=utf-8";
  if (path.endsWith(".css")) return "text/css; charset=utf-8";
  if (path.endsWith(".js")) return "text/javascript; charset=utf-8";
  if (path.endsWith(".json")) return "application/json; charset=utf-8";
  return "text/plain; charset=utf-8";
}

async function localSite(siteDir, config) {
  const assets = new Map();
  for (const name of ["index.html", "style.css", "app.js", "app.js.LEGAL.txt", "third-party-licenses.json"]) {
    assets.set(`/${name}`, boundedPublicFile(join(siteDir, name)));
  }
  const server = createServer((request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    const path = url.pathname === "/" ? "/index.html" : url.pathname;
    const body = path === "/config.json" ? Buffer.from(JSON.stringify(config)) : assets.get(path);
    if (request.method !== "GET" || !body) {
      response.writeHead(404, { "Cache-Control": "no-store" });
      response.end();
      return;
    }
    response.writeHead(200, {
      "Cache-Control": "no-store",
      "Content-Type": contentType(path),
      "Cross-Origin-Opener-Policy": "same-origin",
      "Permissions-Policy": "microphone=(self)",
      "Referrer-Policy": "no-referrer",
      "X-Content-Type-Options": "nosniff",
    });
    response.end(body);
  });
  await new Promise((resolvePromise, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolvePromise);
  });
  const address = server.address();
  if (!address || typeof address === "string") fail("local qualification site did not bind");
  return {
    url: `http://127.0.0.1:${address.port}/`,
    close: () => new Promise((resolvePromise) => server.close(resolvePromise)),
  };
}

async function observe(options) {
  const siteDirectoryOption = options.get("--site-dir");
  const siteUrlOption = options.get("--site-url");
  if ((typeof siteDirectoryOption === "string") === (typeof siteUrlOption === "string")) {
    fail("provide exactly one of --site-dir or --site-url");
  }
  const siteDir =
    typeof siteDirectoryOption === "string" ? resolve(siteDirectoryOption) : null;
  const assistantId = validateAssistantId(required(options, "--assistant-id"));
  const sessionPath = resolve(required(options, "--session"));
  const readyPath = resolve(required(options, "--ready"));
  const triggerPath = resolve(required(options, "--trigger"));
  const observationPath = resolve(required(options, "--observation"));
  const siteBundleSha256 = validateSha256(
    required(options, "--site-bundle-sha256"),
    "site bundle",
  );
  const hangupOrigin = required(options, "--hangup-origin");
  if (!["source", "agent"].includes(hangupOrigin)) fail("hangup origin is invalid");
  const timeoutMs = timeoutMilliseconds(options);
  const publicKey = validatePublicKey(process.env.VAPI_PUBLIC_KEY);
  for (const output of [readyPath, triggerPath, observationPath]) {
    if (existsSync(output)) fail("qualification output path already exists");
  }
  const nonce = randomBytes(32).toString("base64url");
  const qualificationConfig = {
    schema_version: 1,
    recipe: "vapi-amazon-connect-screen-pop@1",
    vapi_public_key: publicKey,
    vapi_assistant_id: assistantId,
    release_revision: siteBundleSha256,
    qualification_nonce: nonce,
    qualification_hangup_origin: hangupOrigin,
  };
  const site = siteDir
    ? await localSite(siteDir, qualificationConfig)
    : { url: validateSiteUrl(siteUrlOption), close: async () => {} };
  const probePath = join(dirname(observationPath), `.vapi-probe-${randomBytes(12).toString("hex")}.wav`);
  writeProbeWav(probePath);
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
    const context = await browser.newContext({ permissions: ["microphone"] });
    await context.addInitScript(installProbe);
    const page = await context.newPage();
    if (!siteDir) {
      await page.route(new URL("config.json", site.url).href, (route) =>
        route.fulfill({
          status: 200,
          contentType: "application/json; charset=utf-8",
          headers: { "Cache-Control": "no-store" },
          body: JSON.stringify(qualificationConfig),
        }),
      );
    }
    const navigation = await page.goto(site.url, {
      waitUntil: "domcontentloaded",
      timeout: 30_000,
    });
    if (!navigation || navigation.status() !== 200) {
      fail("immutable Vapi demo site navigation failed");
    }
    if (!siteDir) {
      const headers = navigation.headers();
      if (
        !headers["cache-control"]?.toLowerCase().includes("no-store") ||
        headers["x-frame-options"]?.toUpperCase() !== "DENY" ||
        headers["x-content-type-options"]?.toLowerCase() !== "nosniff" ||
        headers["cross-origin-opener-policy"]?.toLowerCase() !== "same-origin" ||
        headers["permissions-policy"]?.replaceAll(" ", "") !== "microphone=(self)" ||
        !headers["content-security-policy"]?.includes("frame-ancestors 'none'")
      ) {
        fail("deployed CloudFront demo site security headers changed");
      }
    }
    await waitForSiteReady(page, Math.min(timeoutMs, 30_000));
    const startedAtMs = Date.now();
    await page.locator("#start").click();
    const initial = await waitUntil(
      async () => {
        const value = await applicationSnapshot(page, nonce);
        return value?.callStartObserved && typeof value.callId === "string" ? value : false;
      },
      Math.min(timeoutMs, 90_000),
      "stock Vapi webCall did not start",
    );
    const callId = initial.callId;
    const sourceCallFingerprint = sha256Bytes(callId).slice(0, 12);
    exclusiveJson(readyPath, {
      schema_version: 1,
      call_id: callId,
      source_call_fingerprint: sourceCallFingerprint,
      started_at: new Date(startedAtMs).toISOString(),
      started_epoch_ms: startedAtMs,
    });
    await waitForPrivateFile(sessionPath, timeoutMs);
    const session = validateSession(sessionPath, callId, hangupOrigin);
    await waitForPrivateFile(triggerPath, timeoutMs);
    const triggerAtMs = Date.now();
    const triggered = await page.evaluate(
      (qualificationNonce) =>
        globalThis.__BRIDGEFU_RECIPE_QUALIFICATION__?.triggerTransfer(qualificationNonce) ?? false,
      nonce,
    );
    if (!triggered) fail("Vapi transfer trigger was not accepted exactly once");
    await waitUntil(
      async () => {
        const probe = await probeSnapshot(page);
        return (
          probe?.agentMarkerObservedAtMs.length >= 5 &&
          probe.agentMarkerFrames >= 5 &&
          (probe.dtmfAgentToSourceObserved || probe.telephoneEventPacketsReceived > 0) &&
          probe.remoteAudioTracks > 0 &&
          probe.audioPacketsSent > 5 &&
          probe.audioBytesSent > 0
        );
      },
      Math.min(timeoutMs, 120_000),
      "Vapi browser media/DTMF observations did not converge",
    );
    let localEndCompleted = false;
    let remoteEndObserved = false;
    if (hangupOrigin === "source") {
      const ended = await page.evaluate(
        (qualificationNonce) =>
          globalThis.__BRIDGEFU_RECIPE_QUALIFICATION__?.endFromSource(qualificationNonce) ?? false,
        nonce,
      );
      if (!ended) fail("Vapi browser could not originate hangup");
      localEndCompleted = true;
    }
    await waitUntil(
      async () => (await applicationSnapshot(page, nonce))?.callEndObserved === true,
      Math.min(timeoutMs, 60_000),
      "Vapi browser did not observe terminal cleanup",
    );
    if (hangupOrigin === "agent") remoteEndObserved = true;
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 1000));
    const application = await applicationSnapshot(page, nonce);
    if (!application?.callEndObserved) fail("Vapi browser cleanup was not stable");
    const probe = await probeSnapshot(page);
    const observedAtMs = Date.now();
    const sourceMarkers = sourceMarkerSchedule(
      probe.captureRequestedAtMs,
      triggerAtMs,
      observedAtMs,
    );
    if (
      sourceMarkers.length < 5 ||
      probe.agentMarkerObservedAtMs.length < 5 ||
      probe.agentMarkerFrames < 5 ||
      (!probe.dtmfAgentToSourceObserved && probe.telephoneEventPacketsReceived <= 0)
    ) {
      fail("Vapi browser final media evidence is incomplete");
    }
    exclusiveJson(observationPath, {
      schema_version: 1,
      producer: PRODUCER,
      producer_revision_sha256: sha256File(fileURLToPath(import.meta.url)),
      site_bundle_sha256: siteBundleSha256,
      browser_sdk_version: SDK_VERSION,
      execution_id: session.execution_id,
      scenario_id: session.scenario_id,
      hangup_origin: session.hangup_origin,
      correlation_fingerprint: session.correlation_fingerprint,
      source_call_fingerprint: sourceCallFingerprint,
      observed_at: new Date(observedAtMs).toISOString(),
      vapi: {
        web_call_started: true,
        transfer_trigger_sent: true,
        call_end_observed: true,
      },
      media: {
        codec: "negotiated",
        security: "srtp",
        source_marker_sent_at_ms: sourceMarkers.slice(0, 32),
        agent_marker_observed_at_ms: probe.agentMarkerObservedAtMs.slice(0, 16),
        source_to_agent_marker_frames_sent: sourceMarkers.length * 5,
        agent_to_source_marker_frames: probe.agentMarkerFrames,
        dtmf_source_to_agent_sent: true,
        dtmf_agent_to_source_observed: true,
      },
      hangup: {
        origin: session.hangup_origin,
        local_end_completed: localEndCompleted,
        remote_end_observed: remoteEndObserved,
        cleanup_observed: true,
      },
      redacted: true,
    });
  } finally {
    await browser.close();
    await site.close();
    rmSync(probePath, { force: true });
  }
}

async function main() {
  const [command, ...values] = process.argv.slice(2);
  if (command !== "observe") fail("expected observe command");
  await observe(parseOptions(values));
}

main().catch((error) => {
  process.stderr.write(`error: ${error instanceof HarnessError ? error.message : "Vapi browser observer failed"}\n`);
  process.exitCode = 1;
});
