import { readFile } from "node:fs/promises";

import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  fetchVerifiedArtifact,
  loadSignedArtifactManifest,
  parseClientArtifactManifest,
} from "../src/prover/artifact-manifest.js";

const encoder = new TextEncoder();
const domain = encoder.encode("darknyx/client-artifact-manifest/v1\0");
const payload = JSON.parse(
  await readFile(
    new URL("../artifacts/client-artifacts.v1.payload.json", import.meta.url),
    "utf8",
  ),
);

function base64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

async function signedEnvelope(value = payload) {
  const keys = await crypto.subtle.generateKey("Ed25519", true, [
    "sign",
    "verify",
  ]);
  const publicKey = new Uint8Array(
    await crypto.subtle.exportKey("raw", keys.publicKey),
  );
  const body = encoder.encode(JSON.stringify(value));
  const message = new Uint8Array(domain.length + body.length);
  message.set(domain);
  message.set(body, domain.length);
  const signature = new Uint8Array(
    await crypto.subtle.sign("Ed25519", keys.privateKey, message),
  );
  const envelope = JSON.stringify({
    envelope_version: 1,
    key_id: "release-2026-08",
    payload: base64url(body),
    signature: base64url(signature),
  });
  return { envelope, publicKey };
}

beforeEach(() => {
  vi.unstubAllGlobals();
});

describe("signed client artifact manifest", () => {
  it("accepts the exact pinned signer, set id, protocol, and five circuits", async () => {
    const { envelope, publicKey } = await signedEnvelope();
    const fetchImpl = vi.fn(
      async () =>
        new Response(envelope, {
          headers: { "content-length": String(Buffer.byteLength(envelope)) },
        }),
    );
    const manifest = await loadSignedArtifactManifest({
      manifestUrl: "https://client.darknyx.example/artifacts/manifest.json",
      expectedArtifactSetId: payload.artifact_set_id,
      expectedProtocolVersion: 1,
      trustedKeyId: "release-2026-08",
      trustedPublicKey: publicKey,
      fetchImpl,
    });
    expect(Object.keys(manifest.circuits)).toHaveLength(5);
    expect(manifest.circuits.input.public_inputs).toBe(4);
    expect(manifest.circuits.spend.public_inputs).toBe(7);
  });

  it("fails closed on a bad signature, rollback id, arity, or unsafe path", async () => {
    const { envelope, publicKey } = await signedEnvelope();
    const corrupted = JSON.parse(envelope);
    corrupted.signature = `${corrupted.signature[0] === "A" ? "B" : "A"}${corrupted.signature.slice(1)}`;
    await expect(
      loadSignedArtifactManifest({
        manifestUrl: "https://client.darknyx.example/artifacts/manifest.json",
        expectedArtifactSetId: payload.artifact_set_id,
        expectedProtocolVersion: 1,
        trustedKeyId: "release-2026-08",
        trustedPublicKey: publicKey,
        fetchImpl: async () => new Response(JSON.stringify(corrupted)),
      }),
    ).rejects.toThrow(/signature is invalid/);

    expect(() =>
      parseClientArtifactManifest(payload, "older-artifact-set", 1),
    ).toThrow(/pinned release/);
    expect(() =>
      parseClientArtifactManifest(
        {
          ...payload,
          circuits: {
            ...payload.circuits,
            input: { ...payload.circuits.input, public_inputs: 3 },
          },
        },
        payload.artifact_set_id,
        1,
      ),
    ).toThrow(/arity/);
    expect(() =>
      parseClientArtifactManifest(
        {
          ...payload,
          circuits: {
            ...payload.circuits,
            input: {
              ...payload.circuits.input,
              wasm: { ...payload.circuits.input.wasm, path: "../circuit.wasm" },
            },
          },
        },
        payload.artifact_set_id,
        1,
      ),
    ).toThrow(/safe relative path/);
  });

  it("checks exact size and SHA-256 before returning artifact bytes", async () => {
    const bytes = encoder.encode("verified artifact bytes");
    const sha256 = Buffer.from(
      await crypto.subtle.digest("SHA-256", bytes),
    ).toString("hex");
    const descriptor = {
      path: "valid_input/circuit.wasm",
      bytes: bytes.length,
      sha256,
    };
    await expect(
      fetchVerifiedArtifact(
        "https://client.darknyx.example/artifacts/manifest.json",
        "set-id",
        descriptor,
        async () =>
          new Response(bytes, {
            headers: { "content-length": String(bytes.length) },
          }),
      ),
    ).resolves.toEqual(bytes);
    await expect(
      fetchVerifiedArtifact(
        "https://client.darknyx.example/artifacts/manifest.json",
        "set-id",
        { ...descriptor, sha256: "00".repeat(32) },
        async () => new Response(bytes),
      ),
    ).rejects.toThrow(/SHA-256/);
    await expect(
      fetchVerifiedArtifact(
        "https://client.darknyx.example/artifacts/manifest.json",
        "set-id",
        { ...descriptor, bytes: bytes.length - 1 },
        async () => new Response(bytes),
      ),
    ).rejects.toThrow(/exceeded|byte length/);
  });

  it("evicts a corrupt cached artifact and verifies one fresh refetch", async () => {
    const bytes = encoder.encode("verified artifact bytes");
    const corrupt = encoder.encode("corrupted artifact byte");
    const sha256 = Buffer.from(
      await crypto.subtle.digest("SHA-256", bytes),
    ).toString("hex");
    const cache = {
      match: vi.fn(async () => new Response(corrupt)),
      delete: vi.fn(async () => true),
      put: vi.fn(async () => undefined),
    };
    vi.stubGlobal("caches", {
      open: vi.fn(async () => cache),
      keys: vi.fn(async () => []),
      delete: vi.fn(async () => true),
    });
    const fetchImpl = vi.fn(async () => new Response(bytes));
    await expect(
      fetchVerifiedArtifact(
        "https://client.darknyx.example/artifacts/manifest.json",
        "set-id",
        {
          path: "valid_input/circuit.wasm",
          bytes: bytes.length,
          sha256,
        },
        fetchImpl,
      ),
    ).resolves.toEqual(bytes);
    expect(cache.delete).toHaveBeenCalledOnce();
    expect(fetchImpl).toHaveBeenCalledOnce();
    expect(cache.put).toHaveBeenCalledOnce();
  });
});
