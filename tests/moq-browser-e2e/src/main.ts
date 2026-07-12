import * as Moq from "@moq/net";

const form = document.querySelector<HTMLFormElement>("#connection-form");
const status = document.querySelector<HTMLParagraphElement>("[data-testid=status]");
const result = document.querySelector<HTMLPreElement>("[data-testid=result]");
if (!form || !status || !result) throw new Error("conformance page is incomplete");

function decodeSha256(value: string): Uint8Array {
  const normalized = value.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(normalized)) throw new Error("certificate hash must be 32-byte hexadecimal");
  return Uint8Array.from(normalized.match(/../g) ?? [], (byte) => Number.parseInt(byte, 16));
}

async function run(fields: FormData): Promise<void> {
  const endpoint = String(fields.get("endpoint") ?? "");
  const namespace = String(fields.get("namespace") ?? "");
  const trackName = String(fields.get("track") ?? "catalog");
  const token = String(fields.get("token") ?? "");
  const certificateHash = String(fields.get("certificateHash") ?? "");

  const connection = await Moq.Connection.connect(new URL(endpoint), {
    authorization: token,
    websocket: { enabled: false },
    webtransport: {
      serverCertificateHashes: [{ algorithm: "sha-256", value: decodeSha256(certificateHash) }]
    }
  });
  if (connection.version !== "moqt-19") throw new Error(`unexpected negotiated protocol ${connection.version}`);

  const broadcast = connection.consume(Moq.Path.from(namespace));
  const track = broadcast.subscribe(trackName, 0);
  const group = await track.recvGroup();
  if (!group) throw new Error("track ended before its first group");
  const object = await group.readFrame();
  if (!object) throw new Error("group ended before Object 0");
  const catalog = JSON.parse(new TextDecoder().decode(object));
  if (catalog.version !== "draft-01") throw new Error("unexpected MSF catalog version");

  result.textContent = JSON.stringify({
    catalogVersion: catalog.version,
    protocol: connection.version,
    track: trackName,
    trackCount: Array.isArray(catalog.tracks) ? catalog.tracks.length : 0
  });
  status.dataset.state = "passed";
  status.textContent = "Passed";
  connection.close();
}

form.addEventListener("submit", (event) => {
  event.preventDefault();
  status.dataset.state = "running";
  status.textContent = "Running";
  result.textContent = "";
  void run(new FormData(form)).catch((error: unknown) => {
    status.dataset.state = "failed";
    status.textContent = "Failed";
    result.textContent = error instanceof Error ? error.message : "unknown conformance failure";
  });
});
