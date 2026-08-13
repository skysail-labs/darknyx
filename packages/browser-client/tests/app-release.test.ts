import { describe, expect, it } from "vitest";

import {
  decodeReleasePublicKey,
  parseBrowserApplicationRelease,
  releaseVenueConfig,
} from "../src/app/release.js";

const release = {
  schema_version: 1,
  release_id: "devnet-2026-08-11",
  venue_id: "devnet",
  gateway_url: "https://app.example/api/darknyx/venue/",
  rpc_url: "https://app.example/api/darknyx/rpc",
  vault_program_id: "C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx",
  expected_compose_hash: "ab".repeat(32),
  expected_oracle_mode: "pyth-solana-push-v1" as const,
  artifact_manifest_url: "https://app.example/artifacts/manifest.json",
  artifact_set_id: "client-artifacts-v1",
  artifact_protocol_version: 1,
  artifact_key_id: "release-key-v1",
  artifact_public_key: Buffer.alloc(32, 7).toString("base64url"),
  circuit_version: "note-use-v1",
  proving_key_version: "phase2-v1",
};

describe("production browser release", () => {
  it("maps an exact public release to the trusted venue and prover pins", () => {
    const parsed = parseBrowserApplicationRelease(release);
    expect(releaseVenueConfig(parsed)).toEqual({
      venueId: "devnet",
      gatewayUrl: "https://app.example/api/darknyx/venue/",
      rpcUrl: "https://app.example/api/darknyx/rpc",
      vaultProgramId: release.vault_program_id,
      expectedComposeHash: release.expected_compose_hash,
      expectedOracleMode: "pyth-solana-push-v1",
    });
    expect(decodeReleasePublicKey(parsed.artifact_public_key)).toEqual(
      new Uint8Array(32).fill(7),
    );
  });

  it("rejects secret-bearing, unknown, queried, and incomplete releases", () => {
    expect(() =>
      parseBrowserApplicationRelease({ ...release, api_secret: "leak" }),
    ).toThrow(/invalid pin/);
    expect(() =>
      parseBrowserApplicationRelease({
        ...release,
        rpc_url: "https://rpc.example/?api-key=leak",
      }),
    ).toThrow(/credential-free HTTPS/);
    const { venue_id: _venue, ...missing } = release;
    expect(() => parseBrowserApplicationRelease(missing)).toThrow(
      /invalid pin/,
    );
  });

  it("permits only the explicit localhost HTTP development exception", () => {
    expect(() =>
      parseBrowserApplicationRelease({
        ...release,
        gateway_url: "http://localhost:8080/api/darknyx/venue/",
        rpc_url: "http://localhost:8080/api/darknyx/rpc",
        artifact_manifest_url: "http://localhost:8080/artifacts/manifest.json",
      }),
    ).not.toThrow();
    expect(() =>
      parseBrowserApplicationRelease({
        ...release,
        gateway_url: "http://192.0.2.1/",
      }),
    ).toThrow(/credential-free HTTPS/);
  });
});
