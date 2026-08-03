import Vapi from "@vapi-ai/web";

const elements = {
  status: document.querySelector("#status"),
  transcript: document.querySelector("#transcript"),
  start: document.querySelector("#start"),
  mute: document.querySelector("#mute"),
  end: document.querySelector("#end"),
};

const safeState = {
  recipe: "vapi-amazon-connect-screen-pop@1",
  status: "loading",
  callStartObserved: false,
  callEndObserved: false,
  remoteAudioSamples: 0,
  errorType: null,
};
window.__BRIDGEFU_RECIPE_TEST__ = safeState;

let client;
let muted = false;
let qualification;

function setStatus(status, text) {
  safeState.status = status;
  elements.status.textContent = text;
}

function safeErrorType(value) {
  const normalized = String(value ?? "unknown").toLowerCase();
  return /^[a-z0-9._-]{1,64}$/.test(normalized) ? normalized : "unknown";
}

function validPublicValue(value) {
  return typeof value === "string"
    && value.length >= 8
    && value.length <= 256
    && !/[\s<>"']/.test(value);
}

function validQualificationNonce(value) {
  return typeof value === "string" && /^[A-Za-z0-9_-]{32,128}$/.test(value);
}

function installQualificationControl(config) {
  if (
    !validQualificationNonce(config.qualification_nonce)
    || !["source", "agent"].includes(config.qualification_hangup_origin)
  ) return;
  const state = {
    callId: null,
    triggerSent: false,
    sourceEndRequested: false,
  };
  qualification = state;
  const authorize = (nonce) => nonce === config.qualification_nonce;
  window.__BRIDGEFU_RECIPE_QUALIFICATION__ = Object.freeze({
    snapshot(nonce) {
      if (!authorize(nonce)) return null;
      return {
        callId: state.callId,
        triggerSent: state.triggerSent,
        sourceEndRequested: state.sourceEndRequested,
        callStartObserved: safeState.callStartObserved,
        callEndObserved: safeState.callEndObserved,
        status: safeState.status,
      };
    },
    triggerTransfer(nonce) {
      if (!authorize(nonce) || !client || !state.callId || state.triggerSent) return false;
      state.triggerSent = true;
      const context = {
        customer_name: "Bridgefu Synthetic Caller",
        issue_summary: `Qualification vapi-web-transfer ${config.qualification_hangup_origin} hangup.`,
        intent: "qualification",
        verification_status: "synthetic",
      };
      client.send({
        type: "add-message",
        message: {
          role: "user",
          content: `This is an authorized synthetic nonproduction qualification. Call prepare_handoff exactly once with this exact JSON object: ${JSON.stringify(context)}. After that tool succeeds, invoke the transfer tool now.`,
        },
        triggerResponseEnabled: true,
      });
      return true;
    },
    endFromSource(nonce) {
      if (!authorize(nonce) || !client || state.sourceEndRequested) return false;
      state.sourceEndRequested = true;
      client.stop();
      return true;
    },
  });
}

function connectEvents(vapi) {
  vapi.on("call-start", () => {
    safeState.callStartObserved = true;
    setStatus("active", "Call connected");
    elements.start.disabled = true;
    elements.mute.disabled = false;
    elements.end.disabled = false;
  });
  vapi.on("call-end", () => {
    safeState.callEndObserved = true;
    setStatus("ended", "Call ended");
    elements.start.disabled = false;
    elements.mute.disabled = true;
    elements.end.disabled = true;
    elements.transcript.textContent = "";
    muted = false;
    elements.mute.textContent = "Mute";
  });
  vapi.on("volume-level", (volume) => {
    if (Number.isFinite(volume) && volume > 0.02) {
      safeState.remoteAudioSamples += 1;
    }
  });
  vapi.on("message", (message) => {
    if (
      message?.type === "transcript"
      && message.transcriptType === "final"
      && typeof message.transcript === "string"
    ) {
      const speaker = message.role === "assistant" ? "Assistant" : "You";
      elements.transcript.textContent = `${speaker}: ${message.transcript.slice(0, 500)}`;
    }
  });
  vapi.on("error", (error) => {
    safeState.errorType = safeErrorType(error?.type ?? error?.stage);
    setStatus("failed", "The test call could not continue. Check the recipe dashboard.");
    elements.start.disabled = false;
    elements.mute.disabled = true;
    elements.end.disabled = true;
  });
}

async function load() {
  try {
    const response = await fetch("./config.json", {
      cache: "no-store",
      credentials: "omit",
      redirect: "error",
    });
    if (!response.ok) throw new Error("configuration-unavailable");
    const config = await response.json();
    if (
      config?.schema_version !== 1
      || config?.recipe !== safeState.recipe
      || !validPublicValue(config?.vapi_public_key)
      || !validPublicValue(config?.vapi_assistant_id)
    ) {
      throw new Error("configuration-invalid");
    }
    client = new Vapi(config.vapi_public_key);
    connectEvents(client);
    installQualificationControl(config);
    setStatus("ready", "Ready for a synthetic test call");
    elements.start.disabled = false;

    elements.start.addEventListener("click", async () => {
      elements.start.disabled = true;
      safeState.errorType = null;
      safeState.callStartObserved = false;
      safeState.callEndObserved = false;
      safeState.remoteAudioSamples = 0;
      setStatus("starting", "Requesting microphone and starting call…");
      try {
        const call = await client.start(config.vapi_assistant_id, {
          variableValues: {
            bridgefu_recipe_test: "synthetic-nonproduction",
            bridgefu_recipe_revision: String(config.release_revision ?? "unknown").slice(0, 80),
          },
        });
        if (qualification && typeof call?.id === "string") qualification.callId = call.id;
      } catch (error) {
        safeState.errorType = safeErrorType(error?.name ?? "start-failed");
        setStatus("failed", "Call start failed. Allow microphone access and try again.");
        elements.start.disabled = false;
      }
    });

    elements.mute.addEventListener("click", () => {
      muted = !muted;
      client.setMuted(muted);
      elements.mute.textContent = muted ? "Unmute" : "Mute";
    });
    elements.end.addEventListener("click", () => client.stop());
  } catch (error) {
    safeState.errorType = safeErrorType(error?.message ?? "load-failed");
    setStatus("failed", "Test configuration is unavailable. Check the deployment status.");
  }
}

window.addEventListener("pagehide", () => {
  delete window.__BRIDGEFU_RECIPE_QUALIFICATION__;
  try { client?.stop(); } catch { /* best-effort cleanup */ }
});

void load();
