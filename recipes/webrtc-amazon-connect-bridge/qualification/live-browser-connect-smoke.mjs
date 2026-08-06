#!/usr/bin/env node
/**
 * Diagnostic live proof for browser WebRTC -> Bridgefu -> Amazon Connect.
 *
 * The reusable Bridgefu API credential remains on the EC2 host. This controller
 * asks the host to mint one short-lived attachment through SSM, keeps that
 * descriptor in memory, drives real Chromium through the public CloudFront WSS
 * endpoint, and runs the synthetic Agent Workspace observer concurrently.
 */

import { spawn, spawnSync } from "node:child_process";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import {
  chmodSync,
  closeSync,
  existsSync,
  mkdirSync,
  openSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { createServer } from "node:http";
import { dirname, join, normalize, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "../../..");
const SDK_ROOT = join(ROOT, "sdk/typescript/dist");
const AGENT = join(
  ROOT,
  "recipes/vapi-amazon-connect-screen-pop/qualification/agent-workspace-playwright.mjs",
);
const MAX_AWS_OUTPUT = 2 * 1024 * 1024;
const SOURCE_SAMPLE_RATE = 48_000;
const SOURCE_SECONDS = 120;

class SmokeError extends Error {}

function fail(message) {
  throw new SmokeError(message);
}

function parseOptions(values) {
  const options = new Map();
  for (let index = 0; index < values.length; index += 2) {
    const name = values[index];
    const value = values[index + 1];
    if (!name?.startsWith("--") || !value || value.startsWith("--")) {
      fail(`invalid option near ${name ?? "end of arguments"}`);
    }
    if (options.has(name)) fail(`duplicate option ${name}`);
    options.set(name, value);
  }
  return options;
}

function required(options, name) {
  const value = options.get(name);
  if (!value) fail(`${name} is required`);
  return value;
}

function aws(profile, region, argumentsList) {
  const result = spawnSync(
    "aws",
    [
      ...argumentsList,
      "--profile",
      profile,
      "--region",
      region,
      "--no-cli-pager",
      "--output",
      "json",
    ],
    { cwd: ROOT, encoding: "utf8", maxBuffer: MAX_AWS_OUTPUT },
  );
  if (result.status !== 0) {
    fail(`AWS command failed: ${(result.stderr || "unknown error").trim().slice(0, 500)}`);
  }
  try {
    return JSON.parse(result.stdout);
  } catch {
    fail("AWS command returned invalid JSON");
  }
}

function stackResource(resources, logicalId) {
  const matches = resources.StackResources.filter(
    (resource) => resource.LogicalResourceId === logicalId,
  );
  if (matches.length !== 1 || !matches[0].PhysicalResourceId) {
    fail(`stack resource ${logicalId} was not unique and complete`);
  }
  return matches[0].PhysicalResourceId;
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function privateJson(path, value) {
  const descriptor = openSync(path, "wx", 0o600);
  try {
    writeFileSync(descriptor, `${JSON.stringify(value, null, 2)}\n`, "utf8");
  } finally {
    closeSync(descriptor);
  }
  chmodSync(path, 0o600);
}

function writeSourceWav(path) {
  const sampleCount = SOURCE_SECONDS * SOURCE_SAMPLE_RATE;
  const data = Buffer.alloc(sampleCount * 2);
  for (let index = 0; index < sampleCount; index += 1) {
    const elapsedMs = (index * 1000) / SOURCE_SAMPLE_RATE;
    const afterSilence = elapsedMs - 5_000;
    const cycle = ((afterSilence % 10_000) + 10_000) % 10_000;
    const pulseIndex = Math.floor(cycle / 1000);
    const marker = afterSilence >= 0 && pulseIndex < 5 && cycle - pulseIndex * 1000 < 100;
    const sample = marker
      ? Math.round(Math.sin((2 * Math.PI * 997 * index) / SOURCE_SAMPLE_RATE) * 12_000)
      : 0;
    data.writeInt16LE(sample, index * 2);
  }
  const header = Buffer.alloc(44);
  header.write("RIFF", 0);
  header.writeUInt32LE(36 + data.length, 4);
  header.write("WAVEfmt ", 8);
  header.writeUInt32LE(16, 16);
  header.writeUInt16LE(1, 20);
  header.writeUInt16LE(1, 22);
  header.writeUInt32LE(SOURCE_SAMPLE_RATE, 24);
  header.writeUInt32LE(SOURCE_SAMPLE_RATE * 2, 28);
  header.writeUInt16LE(2, 32);
  header.writeUInt16LE(16, 34);
  header.write("data", 36);
  header.writeUInt32LE(data.length, 40);
  const descriptor = openSync(path, "wx", 0o600);
  try {
    writeFileSync(descriptor, Buffer.concat([header, data]));
  } finally {
    closeSync(descriptor);
  }
}

async function sleep(milliseconds) {
  await new Promise((resolvePromise) => setTimeout(resolvePromise, milliseconds));
}

async function issueRouteCall(profile, region, stackName, correlationId, metadata) {
  const rootResources = aws(profile, region, [
    "cloudformation",
    "describe-stack-resources",
    "--stack-name",
    stackName,
  ]);
  const runtimeStack = stackResource(rootResources, "Runtime");
  const runtimeResources = aws(profile, region, [
    "cloudformation",
    "describe-stack-resources",
    "--stack-name",
    runtimeStack,
  ]);
  const instanceId = stackResource(runtimeResources, "RuntimeInstance");
  const request = JSON.stringify({
    ingress: "webrtc",
    context: { correlation_id: correlationId, metadata },
  });
  const commands = [
    "set -a; source /run/bridgefu/runtime.env; set +a",
    `curl --fail-with-body --silent --show-error -X POST -H 'Authorization: Bearer '$BRIDGEFU_API_BEARER_TOKEN -H 'Idempotency-Key: ${randomUUID()}' -H 'Content-Type: application/json' http://127.0.0.1:9090/v1/routes/support/calls --data '${request}'`,
  ];
  const sent = aws(profile, region, [
    "ssm",
    "send-command",
    "--instance-ids",
    instanceId,
    "--document-name",
    "AWS-RunShellScript",
    "--comment",
    "bridgefu-browser-connect-live-smoke",
    "--parameters",
    JSON.stringify({ commands }),
  ]);
  const commandId = sent.Command?.CommandId;
  if (!commandId) fail("SSM did not return a command ID");
  await sleep(2000);
  const deadline = Date.now() + 60_000;
  while (Date.now() < deadline) {
    const invocation = aws(profile, region, [
      "ssm",
      "get-command-invocation",
      "--command-id",
      commandId,
      "--instance-id",
      instanceId,
    ]);
    if (invocation.Status === "Success") {
      try {
        return JSON.parse(invocation.StandardOutputContent);
      } catch {
        fail("Bridgefu route creation returned invalid JSON");
      }
    }
    if (["Failed", "Cancelled", "TimedOut"].includes(invocation.Status)) {
      fail(`Bridgefu route creation failed with ${invocation.Status}`);
    }
    await sleep(1000);
  }
  fail("Bridgefu route creation exceeded 60 seconds");
}

const BROWSER_PAGE = String.raw`<!doctype html>
<meta charset="utf-8">
<script type="module">
import { BridgefuWebRtcClient, normalizeBridgefuRouteAttachment } from "/sdk/index.js";
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const waitFor = async (label, probe, timeoutMs) => {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const value = await probe();
    if (value) return value;
    await sleep(100);
  }
  throw new Error(label + " deadline");
};
const audioBytes = async (peer, direction) => {
  let bytes = 0;
  for (const report of (await peer.getStats()).values()) {
    const kind = report.kind ?? report.mediaType;
    if (report.type === direction + "-rtp" && kind === "audio") {
      bytes += direction === "inbound" ? (report.bytesReceived ?? 0) : (report.bytesSent ?? 0);
    }
  }
  return bytes;
};
window.__bridgefuSmoke = (async () => {
  const fixture = await fetch("/attachment", { cache: "no-store" }).then((response) => {
    if (!response.ok) throw new Error("attachment unavailable: " + response.status);
    return response.json();
  });
  const call = fixture.route_call;
  const source = call.legs.find((leg) => leg.direction === "inbound" && leg.kind === "webrtc");
  if (!source) throw new Error("route call has no inbound WebRTC leg");
  const attachment = normalizeBridgefuRouteAttachment(call.attachment, {
    tenantId: call.tenant_id,
    callId: call.call_id,
    legId: source.leg_id,
  });
  const handoff = [];
  let remoteTracks = 0;
  let markerFrames = 0;
  let markerEdges = 0;
  let markerActive = false;
  let markerLastEdge = 0;
  const audioContexts = [];
  const client = new BridgefuWebRtcClient({ microphone: true, connectTimeoutMs: 30_000, disconnectGraceMs: 0 });
  client.on("handoff", ({ status }) => handoff.push({ status, at: Date.now() }));
  client.on("remoteTrack", ({ event }) => {
    if (event.track.kind !== "audio") return;
    remoteTracks += 1;
    const context = new AudioContext();
    const analyser = context.createAnalyser();
    analyser.fftSize = 4096;
    const stream = new MediaStream([event.track]);
    context.createMediaStreamSource(stream).connect(analyser);
    const bins = new Float32Array(analyser.frequencyBinCount);
    const timer = setInterval(() => {
      analyser.getFloatFrequencyData(bins);
      const index = Math.round(880 * analyser.fftSize / context.sampleRate);
      const active = bins[index] > -55;
      if (active) markerFrames += 1;
      if (active && !markerActive && Date.now() - markerLastEdge > 500) {
        markerEdges += 1;
        markerLastEdge = Date.now();
      }
      markerActive = active;
      if (event.track.readyState === "ended") clearInterval(timer);
    }, 50);
    audioContexts.push(context);
  });
  await client.connect(attachment);
  const peer = client.peerConnection;
  if (!peer) throw new Error("peer connection missing after connect");
  await waitFor("connected handoff", () => handoff.some((event) => event.status === "connected"), 120_000);
  const connectedAt = handoff.find((event) => event.status === "connected").at;
  const outboundBytes = await waitFor("outbound audio", () => audioBytes(peer, "outbound"), 20_000);
  const inboundBytes = await waitFor("inbound audio", () => audioBytes(peer, "inbound"), 30_000);
  await waitFor("remote track", () => remoteTracks > 0, 10_000);
  await waitFor("agent marker", () => markerEdges >= 5, 40_000);
  client.sendDtmf("5", 120, 70);
  await waitFor("30-second connected duration", () => Date.now() - connectedAt >= 30_000, 45_000);
  if (fixture.hangup_origin === "source") {
    await client.disconnect();
  } else {
    await waitFor("agent hangup", () => client.state === "closed", 90_000);
  }
  const replay = new BridgefuWebRtcClient({ microphone: false, connectTimeoutMs: 5_000, disconnectGraceMs: 0 });
  let replayRejected = false;
  try {
    await replay.connect(attachment);
    await replay.disconnect();
  } catch {
    replayRejected = true;
  }
  for (const context of audioContexts) await context.close().catch(() => {});
  if (!replayRejected) throw new Error("consumed attachment replay was accepted");
  return {
    connected: true,
    selectedSubprotocolRequired: true,
    handoff: handoff.map((event) => event.status),
    remoteTracks,
    markerFrames,
    markerEdges,
    outboundBytes,
    inboundBytes,
    connectedDurationMs: Date.now() - connectedAt,
    dtmfSent: true,
    replayRejected,
    terminalSide: fixture.hangup_origin,
    finalState: client.state,
  };
})();
</script>`;

async function runBrowser(routeCall, hangupOrigin, sourceWav) {
  let attachmentReads = 0;
  const server = createServer((request, response) => {
    if (request.url === "/") {
      response.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
      response.end(BROWSER_PAGE);
      return;
    }
    if (request.url === "/attachment") {
      attachmentReads += 1;
      if (attachmentReads !== 1) {
        response.writeHead(410, { "cache-control": "no-store" });
        response.end();
        return;
      }
      response.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
      response.end(JSON.stringify({ route_call: routeCall, hangup_origin: hangupOrigin }));
      return;
    }
    if (request.url?.startsWith("/sdk/")) {
      const relative = normalize(request.url.slice("/sdk/".length));
      const candidate = resolve(SDK_ROOT, relative);
      if (!candidate.startsWith(`${SDK_ROOT}/`) || !existsSync(candidate)) {
        response.writeHead(404);
        response.end();
        return;
      }
      response.writeHead(200, { "content-type": "text/javascript; charset=utf-8", "cache-control": "no-store" });
      response.end(readFileSync(candidate));
      return;
    }
    response.writeHead(404);
    response.end();
  });
  await new Promise((resolvePromise, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolvePromise);
  });
  const address = server.address();
  if (!address || typeof address === "string") fail("local browser server did not bind TCP");
  const { chromium } = await import(
    pathToFileURL(join(ROOT, "sdk/typescript/node_modules/playwright/index.mjs")).href
  );
  const browser = await chromium.launch({
    headless: true,
    args: [
      "--use-fake-ui-for-media-stream",
      "--use-fake-device-for-media-stream",
      `--use-file-for-fake-audio-capture=${sourceWav}`,
      "--autoplay-policy=no-user-gesture-required",
      "--no-sandbox",
    ],
  });
  try {
    const context = await browser.newContext({ permissions: ["microphone"] });
    const page = await context.newPage();
    const diagnostics = [];
    page.on("console", (message) => diagnostics.push(`console:${message.type()}:${message.text()}`));
    page.on("pageerror", (error) => diagnostics.push(`pageerror:${error.message}`));
    await page.goto(`http://127.0.0.1:${address.port}/`, { waitUntil: "load", timeout: 20_000 });
    let result;
    try {
      result = await page.evaluate(() => window.__bridgefuSmoke);
    } catch (error) {
      throw new SmokeError(
        `browser qualification failed: ${error.message}; diagnostics=${JSON.stringify(diagnostics.slice(0, 20))}`,
      );
    }
    await context.close();
    return { ...result, diagnostics: diagnostics.slice(0, 20) };
  } finally {
    await browser.close();
    await new Promise((resolvePromise) => server.close(resolvePromise));
  }
}

function runAgent(connectUrl, storageState, sessionPath, screenshotPath, observationPath) {
  const child = spawn(
    process.execPath,
    [
      AGENT,
      "observe",
      "--session",
      sessionPath,
      "--storage-state",
      storageState,
      "--connect-url",
      connectUrl,
      "--screenshot",
      screenshotPath,
      "--observation",
      observationPath,
      "--timeout-seconds",
      "180",
    ],
    { cwd: ROOT, stdio: ["ignore", "pipe", "pipe"] },
  );
  const completion = new Promise((resolvePromise, reject) => {
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.once("error", reject);
    child.once("exit", (code) => {
      if (code === 0) resolvePromise(stdout.trim());
      else reject(new SmokeError(`Agent Workspace observer failed: ${stderr.trim().slice(0, 1000)}`));
    });
  });
  return { child, completion };
}

async function main() {
  const options = parseOptions(process.argv.slice(2));
  const allowed = new Set([
    "--aws-profile",
    "--region",
    "--stack-name",
    "--connect-url",
    "--storage-state",
    "--output-dir",
    "--hangup-origin",
  ]);
  for (const name of options.keys()) if (!allowed.has(name)) fail(`unknown option ${name}`);
  const profile = required(options, "--aws-profile");
  const region = required(options, "--region");
  const stackName = required(options, "--stack-name");
  const connectUrl = required(options, "--connect-url");
  const storageState = resolve(required(options, "--storage-state"));
  const outputDir = resolve(required(options, "--output-dir"));
  const hangupOrigin = options.get("--hangup-origin") ?? "source";
  if (!['source', 'agent'].includes(hangupOrigin)) fail("hangup origin must be source or agent");
  if (!existsSync(storageState)) fail("Agent Workspace storage state does not exist");
  mkdirSync(outputDir, { recursive: true, mode: 0o700 });
  chmodSync(outputDir, 0o700);
  const runId = `${Date.now()}-${hangupOrigin}`;
  const correlationId = `bf1_${randomBytes(32).toString("base64url")}`;
  const expectedContext = {
    customer_name: "Bridgefu Synthetic Caller",
    issue_summary: "Direct browser WebRTC qualification",
    intent: "qualification",
    verification_status: "synthetic",
  };
  const routeCall = await issueRouteCall(profile, region, stackName, correlationId, expectedContext);
  if (!routeCall.call_id || !Array.isArray(routeCall.legs) || !routeCall.attachment) {
    fail("Bridgefu route response is missing its attachment binding");
  }
  const revision = spawnSync("git", ["rev-parse", "HEAD"], { cwd: ROOT, encoding: "utf8" }).stdout.trim();
  const startedAt = new Date();
  const session = {
    schema_version: 1,
    execution_id: "bft-browser-np",
    recipe: "webrtc-amazon-connect-bridge@1",
    release_id: revision.slice(0, 12),
    source_tree_sha256: revision,
    image: "immutable-live-stack-image",
    session_id: randomUUID(),
    scenario_id: "browser-webrtc-opus",
    hangup_origin: hangupOrigin,
    security: "wss-ice-dtls-srtp",
    codec: "opus",
    network_profile: "baseline",
    network_contract: { delay_ms: 0, jitter_ms: 0, loss_percent: 0, reorder_percent: 0 },
    started_at: startedAt.toISOString(),
    started_epoch_ms: startedAt.getTime(),
    correlation_id: correlationId,
    correlation_fingerprint: sha256(correlationId).slice(0, 12),
    source_call_id: routeCall.call_id,
    source_org_id: "bridgefu",
    source_call_fingerprint: sha256(routeCall.call_id).slice(0, 12),
    sip_uri: "not-applicable",
    sip_header: "not-applicable",
    expected_context: expectedContext,
    session_hmac: randomBytes(32).toString("base64url"),
  };
  const sessionPath = join(outputDir, `${runId}-session.private.json`);
  const screenshotPath = join(outputDir, `${runId}-agent-workspace.png`);
  const agentObservationPath = join(outputDir, `${runId}-agent-observation.json`);
  const browserObservationPath = join(outputDir, `${runId}-browser-observation.json`);
  const sourceWav = join(outputDir, `${runId}-source.private.wav`);
  privateJson(sessionPath, session);
  writeSourceWav(sourceWav);
  const agent = runAgent(connectUrl, storageState, sessionPath, screenshotPath, agentObservationPath);
  let agentError = null;
  const agentCompletion = agent.completion.catch((error) => {
    agentError = error;
  });
  let browserObservation;
  try {
    browserObservation = await runBrowser(routeCall, hangupOrigin, sourceWav);
    await agentCompletion;
    if (agentError) throw agentError;
  } catch (error) {
    agent.child.kill("SIGTERM");
    await agentCompletion;
    throw error;
  } finally {
    rmSync(sourceWav, { force: true });
  }
  privateJson(browserObservationPath, {
    schema_version: 1,
    producer: "bridgefu-live-browser-connect-smoke@1",
    observed_at: new Date().toISOString(),
    scenario_id: "browser-webrtc-opus",
    hangup_origin: hangupOrigin,
    correlation_fingerprint: session.correlation_fingerprint,
    ...browserObservation,
    redacted: true,
  });
  process.stdout.write(`${JSON.stringify({
    passed: true,
    hangup_origin: hangupOrigin,
    connected_duration_ms: browserObservation.connectedDurationMs,
    inbound_audio_bytes: browserObservation.inboundBytes,
    outbound_audio_bytes: browserObservation.outboundBytes,
    agent_marker_edges: browserObservation.markerEdges,
    attachment_replay_rejected: browserObservation.replayRejected,
    browser_observation: browserObservationPath,
    agent_observation: agentObservationPath,
    screenshot: screenshotPath,
  })}\n`);
}

main().catch((error) => {
  const message = error instanceof SmokeError ? error.message : String(error?.stack ?? error);
  process.stderr.write(`error: ${message}\n`);
  process.exitCode = 1;
});
