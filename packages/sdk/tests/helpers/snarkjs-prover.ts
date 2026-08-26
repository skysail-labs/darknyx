/**
 * Devnet E2E test helper — thin shell-out wrapper around
 * `node_modules/.bin/snarkjs groth16 fullprove`.
 *
 * It lives under `tests/helpers/`, not in `src/`, so the SDK itself never
 * takes a dependency on a CLI binary. The shipped in-process prover is
 * `BrowserProverSuite` (`packages/browser-client/src/prover/`), which the
 * browser uses; this helper serves the Node test path only.
 *
 * What this does, mirroring `programs/vault/tests/common/mod.rs::snarkjs_fullprove`:
 *
 *   1. Writes `input.json` (all fields as decimal strings) into a tmp dir.
 *   2. Invokes `snarkjs groth16 fullprove <input> <wasm> <zkey> <proof> <public>`.
 *   3. Parses `proof.json` into the on-chain verifier byte layout:
 *        - pi_a: [x||y] BE 64 bytes, with y NEGATED (groth16-solana convention).
 *        - pi_b: [x1||x0||y1||y0] BE 128 bytes (coord-pair swap).
 *        - pi_c: [x||y] BE 64 bytes.
 *   4. Parses `public.json` into a list of 32-byte BE field-element arrays.
 *
 * Output shape matches `Groth16OnChainProof` in `packages/sdk/src/idl/vault-client.ts`,
 * so the result can be passed straight into the corresponding vault
 * instruction builder.
 */

import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import type { Groth16OnChainProof } from "../../src/idl/vault-client.js";
import { formatGroth16ForOnChain } from "../../src/zk/groth16-format.js";

export interface SnarkjsProofResult {
  proof: Groth16OnChainProof;
  publicInputsBE: Uint8Array[]; // each 32 bytes, big-endian
}

export interface SnarkjsFullProveOpts {
  /** Absolute path to the compiled `.wasm` (e.g. `circuits/build/<name>/circuit_js/circuit.wasm`). */
  circuitWasmPath: string;
  /** Absolute path to the compiled `.zkey` (e.g. `circuits/build/<name>/circuit_final.zkey`). */
  circuitZkeyPath: string;
  /** Repo root — used to find `node_modules/.bin/snarkjs`. */
  repoRoot: string;
  /** Optional tmp dir; defaults to `<os.tmpdir>/darknyx-snarkjs-<random>`. */
  tmpDir?: string;
}

/**
 * Shell out to snarkjs and return (proof, publicInputs) in the exact byte
 * layout the on-chain groth16-solana verifier expects.
 *
 * `inputs` is the circuit-witness object: every field MUST be a decimal
 * string (or an array of decimal strings). This mirrors the `format!`
 * blocks in the Rust tests — keep the keys in lock-step with the circuit's
 * `signal input` declarations.
 */
export function snarkjsFullProve(
  inputs: Record<string, string | string[]>,
  opts: SnarkjsFullProveOpts,
): SnarkjsProofResult {
  const tmp =
    opts.tmpDir ??
    join(
      tmpdir(),
      `darknyx-snarkjs-${Date.now()}-${Math.random().toString(16).slice(2)}`,
    );
  mkdirSync(tmp, { recursive: true, mode: 0o700 });
  const inputPath = join(tmp, "input.json");
  const proofPath = join(tmp, "proof.json");
  const publicPath = join(tmp, "public.json");

  try {
    writeFileSync(inputPath, JSON.stringify(inputs), { mode: 0o600 });

    const snarkjsBin = resolve(opts.repoRoot, "node_modules/.bin/snarkjs");
    execFileSync(
      snarkjsBin,
      [
        "groth16",
        "fullprove",
        inputPath,
        opts.circuitWasmPath,
        opts.circuitZkeyPath,
        proofPath,
        publicPath,
      ],
      { stdio: "pipe" },
    );

    const proofJson = JSON.parse(readFileSync(proofPath, "utf8"));
    const publicJson = JSON.parse(readFileSync(publicPath, "utf8"));
    return formatGroth16ForOnChain(proofJson, publicJson);
  } finally {
    try {
      rmSync(tmp, { recursive: true, force: true });
    } catch {
      // Best-effort cleanup cannot hide the original proving failure.
    }
  }
}
