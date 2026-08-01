import {
  BridgefuWebRtcClient,
  normalizeBridgefuRouteAttachment,
} from "../dist/index.js";

const status = document.querySelector("#status");
const route = document.querySelector("#route");
const correlation = document.querySelector("#correlation");
const connectButton = document.querySelector("#connect");
const hangupButton = document.querySelector("#hangup");
const dtmfButton = document.querySelector("#dtmf");
const remoteAudio = document.querySelector("#remote");

const ringback = oscillatorRingback();
const client = new BridgefuWebRtcClient({
  remoteAudioElement: remoteAudio,
  ringback,
});

client.on("handoff", ({ status: next }) => {
  status.textContent = `Handoff: ${next}`;
  const connected = next === "connected";
  hangupButton.disabled = !connected;
  dtmfButton.disabled = !connected;
});
client.on("reconnectRequired", () => {
  status.textContent = "Connection ended. Press Connect for a fresh attachment.";
  connectButton.disabled = false;
});
client.on("error", ({ error }) => {
  status.textContent = `Call error: ${error.code}`;
  connectButton.disabled = false;
});

connectButton.addEventListener("click", async () => {
  connectButton.disabled = true;
  try {
    const routeCall = await createRouteCall(route.value, correlation.value);
    const browserLeg = routeCall.legs.find(
      (leg) => leg.direction === "inbound" && leg.kind === "webrtc",
    );
    if (!browserLeg) throw new Error("route returned no inbound WebRTC leg");
    const attachment = normalizeBridgefuRouteAttachment(routeCall.attachment, {
      tenantId: routeCall.tenant_id,
      callId: routeCall.call_id,
      legId: browserLeg.leg_id,
    });
    if (client.state === "reconnect-required" || client.state === "failed") {
      await client.reconnect(attachment);
    } else {
      await client.connect(attachment);
    }
    client.sendContext({ correlationId: correlation.value });
  } catch (error) {
    status.textContent = `Unable to connect: ${safeError(error)}`;
    connectButton.disabled = false;
  }
});

hangupButton.addEventListener("click", async () => {
  await client.disconnect();
  connectButton.disabled = false;
  hangupButton.disabled = true;
  dtmfButton.disabled = true;
});

dtmfButton.addEventListener("click", () => client.sendDtmf("1#"));

async function createRouteCall(routeId, correlationId) {
  const response = await fetch("/demo/bridgefu-route", {
    method: "POST",
    credentials: "same-origin",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ route_id: routeId, correlation_id: correlationId }),
  });
  if (!response.ok) throw new Error(`route request failed (${response.status})`);
  return response.json();
}

function safeError(error) {
  return error && typeof error === "object" && "code" in error
    ? String(error.code)
    : "unexpected-error";
}

function oscillatorRingback() {
  let context;
  let oscillator;
  let timer;
  return {
    start() {
      context ??= new AudioContext();
      oscillator = context.createOscillator();
      const gain = context.createGain();
      oscillator.frequency.value = 440;
      gain.gain.value = 0.04;
      oscillator.connect(gain).connect(context.destination);
      oscillator.start();
      timer = setTimeout(() => this.stop(), 800);
    },
    stop() {
      if (timer) clearTimeout(timer);
      oscillator?.stop();
      oscillator = undefined;
    },
  };
}
