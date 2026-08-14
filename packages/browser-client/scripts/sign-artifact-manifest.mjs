#!/usr/bin/env node
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

import { validateArtifactPayload } from "./artifact-payload-schema.mjs";
import { signArtifactPayload } from "./artifact-signing.mjs";

const args = Object.fromEntries(
  process.argv.slice(2).map((argument) => {
    const [key, ...value] = argument.replace(/^--/, "").split("=");
    return [key.replaceAll("-", "_"), value.join("=")];
  }),
);
const keyId = args.key_id;
const output = args.output;
if (!keyId || !/^[a-zA-Z0-9._-]{1,64}$/.test(keyId) || !output) {
  throw new Error(
    "usage: --key-id=<pinned-id> --output=<manifest.json> with " +
      "DARKNYX_CLIENT_ARTIFACT_SIGNING_KEY_PKCS8_B64 set",
  );
}
const encodedKey = process.env.DARKNYX_CLIENT_ARTIFACT_SIGNING_KEY_PKCS8_B64;
if (!encodedKey) {
  throw new Error("artifact signing key environment variable is not set");
}
const packageRoot = resolve(import.meta.dirname, "..");
const payload = await readFile(
  resolve(packageRoot, "artifacts/client-artifacts.v1.payload.json"),
);
let payloadValue;
try {
  payloadValue = JSON.parse(payload.toString("utf8"));
} catch {
  throw new Error("artifact manifest payload is not valid JSON");
}
validateArtifactPayload(payloadValue);
const keyBytes = Buffer.from(encodedKey, "base64");
try {
  const signature = signArtifactPayload(payload, keyBytes);
  const envelope = {
    envelope_version: 1,
    key_id: keyId,
    payload: payload.toString("base64url"),
    signature: signature.toString("base64url"),
  };
  await writeFile(resolve(output), `${JSON.stringify(envelope, null, 2)}\n`, {
    encoding: "utf8",
    mode: 0o644,
    flag: "wx",
  });
} finally {
  keyBytes.fill(0);
}
