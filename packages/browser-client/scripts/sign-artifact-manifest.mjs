#!/usr/bin/env node
import { createPrivateKey, sign } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

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
const keyBytes = Buffer.from(encodedKey, "base64");
try {
  const privateKey = createPrivateKey({
    key: keyBytes,
    format: "der",
    type: "pkcs8",
  });
  if (privateKey.asymmetricKeyType !== "ed25519") {
    throw new Error("artifact signing key must be Ed25519");
  }
  const domain = Buffer.from("darknyx/client-artifact-manifest/v1\0");
  const signature = sign(null, Buffer.concat([domain, payload]), privateKey);
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
