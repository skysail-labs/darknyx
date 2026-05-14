/**
 * VALID_INPUT prover smoke test.
 *
 * Builds a single-leaf shadow Merkle tree, constructs a note from a fixed
 * opening, generates a real Groth16 proof via the snarkjs helper, and asserts
 * the proof byte layout + public inputs match what the on-chain `lock_note`
 * verifier expects.
 *
 * Skipped if the circuit artefacts haven't been built yet (run
 * `scripts/build-circuits.sh`).
 */

import { describe, expect, it } from "vitest";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Keypair } from "@solana/web3.js";

import { noteCommitment, ownerCommitment, pubkeyToFrPair } from "../src/utxo/note.js";
import { MerkleShadow } from "./helpers/merkle-shadow.ts";
import { be32ToBigInt } from "./helpers/e2e-helpers.js";
import { proveValidInput } from "./helpers/valid-input-prover.ts";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "..", "..", "..");
const wasm = resolve(repoRoot, "circuits/build/valid_input/circuit_js/circuit.wasm");
const zkey = resolve(repoRoot, "circuits/build/valid_input/circuit_final.zkey");

const available = existsSync(wasm) && existsSync(zkey);
const ait = (name: string, fn: () => Promise<void>) =>
  available ? it(name, fn, 60_000) : it.skip(name, fn);

describe("VALID_INPUT prover (snarkjs end-to-end)", () => {
  ait("produces a proof whose public inputs match the circuit declaration", async () => {
    // Note opening (small in-field values for safety on both Rust + circomlibjs).
    const spendingKey = 12345678901234567890n;
    const ownerBlinding = 42n;
    const nonce = 7n;
    const blindingR = 11n;
    const amount = 1_000_000n;
    const tokenMint = Keypair.generate().publicKey.toBytes();

    // Build the note commitment + drop it into a fresh shadow tree.
    const ownerCommitFr = await ownerCommitment(spendingKey, ownerBlinding);
    const noteCommitBE = await noteCommitment({
      tokenMint,
      amount,
      ownerCommitment: ownerCommitFr,
      nonce,
      blindingR,
    });
    const tree = await MerkleShadow.create();
    await tree.append(noteCommitBE);
    const witness = await tree.witness(0);

    const result = await proveValidInput({
      repoRoot,
      spendingKey,
      ownerCommitmentBlinding: ownerBlinding,
      nonce,
      blindingR,
      tokenMint,
      amount,
      merkleRootBE: witness.root,
      merkleWitness: {
        pathElements: witness.siblings.map(be32ToBigInt),
        pathIndices: witness.indices,
      },
    });

    // Proof byte layout (matches groth16-solana).
    expect(result.proof.piA.length).toBe(64);
    expect(result.proof.piB.length).toBe(128);
    expect(result.proof.piC.length).toBe(64);

    // Five public inputs in circuit-declaration order:
    //   [merkleRoot, noteCommitment, tokenMint_lo, tokenMint_hi, amount]
    expect(result.publicInputsBE.length).toBe(5);
    for (const pi of result.publicInputsBE) expect(pi.length).toBe(32);

    // Sanity: returned commitment matches what the tree saw.
    expect(Buffer.from(result.noteCommitmentBE).toString("hex")).toBe(
      Buffer.from(noteCommitBE).toString("hex"),
    );

    // Sanity: public input 0 is the merkle_root we asked for.
    expect(Buffer.from(result.publicInputsBE[0]).toString("hex")).toBe(
      Buffer.from(witness.root).toString("hex"),
    );

    // Sanity: public input 1 is the note commitment.
    expect(Buffer.from(result.publicInputsBE[1]).toString("hex")).toBe(
      Buffer.from(noteCommitBE).toString("hex"),
    );

    // Sanity: public inputs 2,3 reconstruct the original mint.
    const [expLo, expHi] = pubkeyToFrPair(tokenMint);
    expect(be32ToBigInt(result.publicInputsBE[2])).toBe(expLo);
    expect(be32ToBigInt(result.publicInputsBE[3])).toBe(expHi);

    // Sanity: public input 4 is the amount.
    expect(be32ToBigInt(result.publicInputsBE[4])).toBe(amount);
  });

  ait("rejects a witness for a leaf that's not in the tree", async () => {
    // Same opening, but the merkle witness is for a DIFFERENT leaf.
    const spendingKey = 1n;
    const ownerBlinding = 2n;
    const nonce = 3n;
    const blindingR = 4n;
    const amount = 5n;
    const tokenMint = Keypair.generate().publicKey.toBytes();

    const ownerCommitFr = await ownerCommitment(spendingKey, ownerBlinding);

    const tree = await MerkleShadow.create();
    // Append a DIFFERENT note as leaf 0.
    const fakeLeaf = new Uint8Array(32);
    fakeLeaf[31] = 0xab;
    await tree.append(fakeLeaf);
    // Now the witness for index 0 is for the fake leaf — feeding our real
    // note's opening should make snarkjs unable to satisfy the constraints.
    const witness = await tree.witness(0);

    await expect(
      proveValidInput({
        repoRoot,
        spendingKey,
        ownerCommitmentBlinding: ownerBlinding,
        nonce,
        blindingR,
        tokenMint,
        amount,
        merkleRootBE: witness.root,
        merkleWitness: {
          pathElements: witness.siblings.map(be32ToBigInt),
          pathIndices: witness.indices,
        },
      }),
    ).rejects.toThrow();
    // Silence unused warning if helper is moved.
    void ownerCommitFr;
  });
});
