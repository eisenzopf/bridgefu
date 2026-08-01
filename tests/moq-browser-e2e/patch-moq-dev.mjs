import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

const source = process.argv[2];
if (!source) throw new Error("usage: node patch-moq-dev.mjs <moq-dev-source>");

function replaceExactly(file, before, after) {
  const absolute = path.join(source, file);
  const input = readFileSync(absolute, "utf8");
  const first = input.indexOf(before);
  if (first < 0 || input.indexOf(before, first + before.length) >= 0) {
    throw new Error(`expected one exact patch site in ${file}`);
  }
  writeFileSync(absolute, input.replace(before, after));
}

const connect = "js/net/src/connection/connect.ts";
replaceExactly(
  connect,
  "export interface ConnectProps {\n\t// WebTransport options.",
  "export interface ConnectProps {\n\t// Draft-19 structured SETUP bearer credential. Never added to the URL.\n\tauthorization?: string;\n\n\t// WebTransport options.",
);
replaceExactly(
  connect,
  "return connectTransport(url, props.transport);",
  "return connectTransport(url, props.transport, props.authorization);",
);
replaceExactly(
  connect,
  "return await handshakeAlpn(url, session as WebTransport, modernVersion);",
  "return await handshakeAlpn(url, session as WebTransport, modernVersion, props?.authorization);",
);
replaceExactly(
  connect,
  "async function connectTransport(url: URL, session: WebTransport): Promise<Established>",
  "async function connectTransport(url: URL, session: WebTransport, authorization?: string): Promise<Established>",
);
replaceExactly(
  connect,
  "return await handshakeAlpn(url, session, modernVersion);",
  "return await handshakeAlpn(url, session, modernVersion, authorization);",
);
replaceExactly(
  connect,
  "async function handshakeAlpn(url: URL, session: WebTransport, version: Ietf.IetfVersion): Promise<Established> {\n\tconst controlStream = await exchangeSetup(session, version, \"moq-lite-js\");",
  "async function handshakeAlpn(\n\turl: URL,\n\tsession: WebTransport,\n\tversion: Ietf.IetfVersion,\n\tauthorization?: string,\n): Promise<Established> {\n\tconst controlStream = await exchangeSetup(session, version, \"moq-lite-js\", authorization);",
);

replaceExactly(
  "js/net/src/connection/handshake.ts",
  "\timplementation: string,\n): Promise<Stream> {\n\tconst encoder = new TextEncoder();\n\tconst params = new Ietf.SetupOptions();",
  "\timplementation: string,\n\tauthorization?: string,\n): Promise<Stream> {\n\tconst encoder = new TextEncoder();\n\tconst params = new Ietf.SetupOptions();\n\tif (authorization !== undefined) {\n\t\tconst value = encoder.encode(authorization);\n\t\tif (value.length === 0 || value.length > 4096) {\n\t\t\tthrow new Error(\"authorization token must contain 1 to 4096 bytes\");\n\t\t}\n\t\tconst structured = new Uint8Array(value.length + 2);\n\t\tstructured[0] = 3; // USE_VALUE\n\t\tstructured[1] = 0; // out-of-band bearer token type\n\t\tstructured.set(value, 2);\n\t\tparams.setBytes(Ietf.SetupOption.AuthorizationToken, structured);\n\t}",
);
