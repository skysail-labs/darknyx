#!/usr/bin/env node
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  verify,
} from "node:crypto";
import { copyFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";

import { validateArtifactPayload } from "./artifact-payload-schema.mjs";
import { signArtifactPayload } from "./artifact-signing.mjs";

const packageRoot = resolve(import.meta.dirname, "..");
const repoRoot = resolve(packageRoot, "../..");
const allowed = new Set([
  "origin",
  "release-id",
  "venue-id",
  "vault-program-id",
  "expected-compose-hash",
  "expected-oracle-mode",
  "expected-mrtd",
  "artifact-key-id",
  "circuit-version",
  "proving-key-version",
  "output",
]);
const args = new Map();
for (const argument of process.argv.slice(2)) {
  const match = /^--([a-z-]+)=(.+)$/.exec(argument);
  if (!match || !allowed.has(match[1]) || args.has(match[1])) {
    throw new Error(`unknown, malformed, or duplicate argument: ${argument}`);
  }
  args.set(match[1], match[2]);
}
const required = (name) => {
  const value = args.get(name);
  if (!value) throw new Error(`--${name}=... is required`);
  return value;
};
const id = (name) => {
  const value = required(name);
  if (!/^[a-z0-9][a-z0-9._-]{0,127}$/.test(value)) {
    throw new Error(`--${name} is not a canonical release identifier`);
  }
  return value;
};
const hex64 = (name) => {
  const value = required(name);
  if (!/^[0-9a-f]{64}$/.test(value)) {
    throw new Error(`--${name} must be 32-byte lowercase hex`);
  }
  return value;
};
const oracleMode = () => {
  const value = required("expected-oracle-mode");
  if (value !== "pyth-router-quorum-v1" && value !== "pyth-solana-push-v1") {
    throw new Error("--expected-oracle-mode is not a supported versioned source");
  }
  return value;
};
const origin = new URL(required("origin"));
const local = origin.protocol === "http:" && origin.hostname === "localhost";
if (
  (origin.protocol !== "https:" && !local) ||
  origin.username ||
  origin.password ||
  origin.pathname !== "/" ||
  origin.search ||
  origin.hash
) {
  throw new Error(
    "--origin must be a credential-free HTTPS origin or localhost",
  );
}

const outputRoot = resolve(
  args.get("output") ??
    process.env.DARKNYX_TRADER_STATIC_ROOT ??
    resolve(repoRoot, ".devnet/trader-static"),
);
await readFile(resolve(outputRoot, "build-manifest.json"));
const artifactsRoot = resolve(outputRoot, "artifacts");
await mkdir(artifactsRoot);

const payloadPath = resolve(
  packageRoot,
  "artifacts/client-artifacts.v1.payload.json",
);
const payloadBytes = await readFile(payloadPath);
const payload = validateArtifactPayload(
  JSON.parse(payloadBytes.toString("utf8")),
);

const sourceFor = (artifactPath, kind) => {
  const [circuit, file, ...extra] = artifactPath.split("/");
  if (!circuit || !file || extra.length) {
    throw new Error(`artifact path has an unsupported layout: ${artifactPath}`);
  }
  const root = resolve(repoRoot, "circuits/build", circuit);
  if (kind === "wasm") return resolve(root, "circuit_js/circuit.wasm");
  if (kind === "zkey") return resolve(root, "circuit_final.zkey");
  return resolve(root, "verification_key.json");
};

let files = 0;
let totalBytes = 0;
for (const circuit of Object.values(payload.circuits)) {
  for (const kind of ["wasm", "zkey", "verification_key"]) {
    const artifact = circuit[kind];
    const source = sourceFor(artifact.path, kind);
    const bytes = await readFile(source);
    const digest = createHash("sha256").update(bytes).digest("hex");
    if (bytes.length !== artifact.bytes || digest !== artifact.sha256) {
      throw new Error(
        `local artifact disagrees with signed payload: ${artifact.path}`,
      );
    }
    const destination = resolve(artifactsRoot, artifact.path);
    if (!destination.startsWith(`${artifactsRoot}/`)) {
      throw new Error(`artifact escaped the release root: ${artifact.path}`);
    }
    await mkdir(dirname(destination), { recursive: true, mode: 0o755 });
    await copyFile(source, destination);
    files += 1;
    totalBytes += bytes.length;
  }
}

const encodedKey = process.env.DARKNYX_CLIENT_ARTIFACT_SIGNING_KEY_PKCS8_B64;
if (!encodedKey)
  throw new Error("artifact signing key environment variable is not set");
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
  const publicJwk = createPublicKey(privateKey).export({ format: "jwk" });
  if (publicJwk.kty !== "OKP" || publicJwk.crv !== "Ed25519" || !publicJwk.x) {
    throw new Error("artifact signing key has an invalid public component");
  }
  const signature = signArtifactPayload(payloadBytes, keyBytes);
  const signedMessage = Buffer.concat([
    Buffer.from("darknyx/client-artifact-manifest/v1\0"),
    payloadBytes,
  ]);
  if (!verify(null, signedMessage, createPublicKey(privateKey), signature)) {
    throw new Error("artifact manifest self-verification failed");
  }
  const envelope = {
    envelope_version: 1,
    key_id: id("artifact-key-id"),
    payload: payloadBytes.toString("base64url"),
    signature: signature.toString("base64url"),
  };
  await writeFile(
    resolve(artifactsRoot, "manifest.json"),
    `${JSON.stringify(envelope, null, 2)}\n`,
    { encoding: "utf8", mode: 0o644, flag: "wx" },
  );
  const release = {
    schema_version: 1,
    release_id: id("release-id"),
    venue_id: id("venue-id"),
    gateway_url: new URL("/api/darknyx/venue/", origin).toString(),
    rpc_url: new URL("/api/darknyx/rpc", origin).toString(),
    vault_program_id: required("vault-program-id"),
    expected_compose_hash: hex64("expected-compose-hash"),
    expected_oracle_mode: oracleMode(),
    ...(args.has("expected-mrtd")
      ? { expected_mrtd: hex64("expected-mrtd") }
      : {}),
    artifact_manifest_url: new URL(
      "/artifacts/manifest.json",
      origin,
    ).toString(),
    artifact_set_id: payload.artifact_set_id,
    artifact_protocol_version: payload.protocol_version,
    artifact_key_id: id("artifact-key-id"),
    artifact_public_key: publicJwk.x,
    circuit_version: id("circuit-version"),
    proving_key_version: id("proving-key-version"),
  };
  if (!/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(release.vault_program_id)) {
    throw new Error("--vault-program-id is not base58");
  }
  await writeFile(
    resolve(outputRoot, "release.json"),
    `${JSON.stringify(release)}\n`,
    { encoding: "utf8", mode: 0o644, flag: "wx" },
  );
  process.stdout.write(
    `assembled ${release.release_id}: ${files} verified artifacts, ${totalBytes} bytes\n`,
  );
} finally {
  keyBytes.fill(0);
}
