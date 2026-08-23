/**
 * Smoke test for the shell-out snarkjs prover helper.
 *
 * Requires:
 *   - `npm install` has been run (so `node_modules/.bin/snarkjs` exists).
 *   - Circuits built (`bash scripts/build-circuits.sh`).
 *
 * If either is missing, the test is skipped — we don't want CI that doesn't
 * ship circuit artifacts to fail.
 *
 * What this verifies (end-to-end):
 *   1. `snarkjsFullProve` writes input.json, shells out, parses proof.json.
 *   2. The first public input == the BE-32 userCommitment produced by the
 *      pure-TS `userCommitmentFromKeys` helper (i.e. the circuit sees the
 *      same commitment we compute off-chain).
 *   3. pi_a / pi_b / pi_c have the correct widths for the on-chain verifier.
 *
 * This is the SDK-side counterpart to
 * `programs/vault/tests/user_commitment_registration.rs`.
 */

import { existsSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

import {
  deriveMasterViewingKey,
  deriveSpendingKey,
} from "../../src/keys/key-generators.js";
import { userCommitmentFromKeys } from "../../src/keys/user-commitment.js";

import { snarkjsFullProve } from "./snarkjs-prover.js";

const REPO_ROOT = resolve(__dirname, "../../../..");
const CREATE_WASM = resolve(
  REPO_ROOT,
  "circuits/build/valid_wallet_create/circuit_js/circuit.wasm",
);
const CREATE_ZKEY = resolve(
  REPO_ROOT,
  "circuits/build/valid_wallet_create/circuit_final.zkey",
);
const SNARKJS_BIN = resolve(REPO_ROOT, "node_modules/.bin/snarkjs");

const CIRCUITS_READY =
  existsSync(CREATE_WASM) && existsSync(CREATE_ZKEY) && existsSync(SNARKJS_BIN);

const maybeDescribe = CIRCUITS_READY ? describe : describe.skip;

function decFr(x: bigint): string {
  return x.toString();
}

// Fixed seed mirrors programs/vault/tests/user_commitment_registration.rs
function fixedSeed(): Uint8Array {
  const seed = new Uint8Array(64);
  for (let i = 0; i < 64; i++) seed[i] = (i * 7) & 0xff;
  return seed;
}

maybeDescribe("snarkjs-prover helper: VALID_WALLET_CREATE", () => {
  it(
    "[fullprove_emits_pi_a_pi_b_pi_c_and_public_inputs] end-to-end",
    { timeout: 60_000 },
    async () => {
      const seed = fixedSeed();
      const sk = deriveSpendingKey(seed);
      const vk = deriveMasterViewingKey(seed);

      // Use a deterministic root-key pubkey to keep this offline.
      const rootKeyPubkey = new Uint8Array(32);
      rootKeyPubkey[0] = 0x11;

      const r0 = 1n;
      const r1 = 2n;
      const r2 = 3n;

      const uc = await userCommitmentFromKeys({
        rootKeyPubkey,
        spendingKey: sk,
        viewingKey: vk,
        r0,
        r1,
        r2,
      });

      // Split rootKey into (lo, hi) the same way the circuit does.
      const hi = BigInt(
        "0x" +
          Array.from(rootKeyPubkey.subarray(0, 16))
            .map((b) => b.toString(16).padStart(2, "0"))
            .join(""),
      );
      const lo = BigInt(
        "0x" +
          Array.from(rootKeyPubkey.subarray(16, 32))
            .map((b) => b.toString(16).padStart(2, "0"))
            .join(""),
      );

      // userCommitment from poseidon → decimal string for snarkjs.
      const ucBigint = BigInt(
        "0x" +
          Array.from(uc)
            .map((b) => b.toString(16).padStart(2, "0"))
            .join(""),
      );

      const { proof, publicInputsBE } = snarkjsFullProve(
        {
          userCommitment: decFr(ucBigint),
          rootKey: [decFr(lo), decFr(hi)],
          spendingKey: decFr(sk),
          viewingKey: decFr(vk),
          r0: decFr(r0),
          r1: decFr(r1),
          r2: decFr(r2),
        },
        {
          circuitWasmPath: CREATE_WASM,
          circuitZkeyPath: CREATE_ZKEY,
          repoRoot: REPO_ROOT,
        },
      );

      expect(proof.piA.length).toBe(64);
      expect(proof.piB.length).toBe(128);
      expect(proof.piC.length).toBe(64);
      expect(publicInputsBE.length).toBe(1);
      expect(publicInputsBE[0]).toEqual(uc);
    },
  );
});
