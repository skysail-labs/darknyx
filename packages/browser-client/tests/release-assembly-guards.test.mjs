import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import {
  artifactSource,
  claimArtifactDestination,
  validateVaultProgramId,
} from "../scripts/release-assembly-guards.mjs";

describe("release assembly guards", () => {
  it("binds artifact sources to the enclosing circuit and canonical path", () => {
    expect(
      artifactSource(
        "/repo",
        "input",
        "valid_input/circuit.wasm",
        "wasm",
      ),
    ).toBe(resolve("/repo/circuits/build/valid_input/circuit_js/circuit.wasm"));
    expect(() =>
      artifactSource(
        "/repo",
        "input",
        "valid_deposit/circuit.wasm",
        "wasm",
      ),
    ).toThrow(/canonical path/);
  });

  it("rejects duplicate release destinations", () => {
    const destinations = new Set();
    claimArtifactDestination(destinations, "/release/input/circuit.wasm", "a");
    expect(() =>
      claimArtifactDestination(
        destinations,
        "/release/input/circuit.wasm",
        "b",
      ),
    ).toThrow(/duplicate artifact destination/);
  });

  it("requires a program ID to decode to exactly 32 bytes", () => {
    expect(() =>
      validateVaultProgramId("C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx"),
    ).not.toThrow();
    expect(() => validateVaultProgramId("z".repeat(44))).toThrow(
      /decode to 32 bytes/,
    );
    expect(() => validateVaultProgramId("0".repeat(32))).toThrow(/not base58/);
  });
});
