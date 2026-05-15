/**
 * VALID_CREATE prover smoke test.
 *
 * Constructs a synthetic match (alice buys 50 BASE for 5000 QUOTE, no
 * change, no fee), computes all four note commitments via the same helpers
 * the production path uses, then asks the prover for a Groth16 proof and
 * asserts the public-input vector matches the circuit declaration order.
 *
 * Also exercises the change-note branch (alice's deposit exceeds notional
 * so buyer_change_amt > 0 → note_e is non-zero).
 *
 * Skipped if circuit artefacts haven't been built.
 */

import { describe, expect, it } from "vitest";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Keypair } from "@solana/web3.js";

import { noteCommitment, pubkeyToFrPair } from "../src/utxo/note.js";
import { be32ToBigInt } from "./helpers/e2e-helpers.ts";
import { proveValidCreate } from "./helpers/valid-create-prover.ts";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "..", "..", "..");
const wasm = resolve(repoRoot, "circuits/build/valid_create/circuit_js/circuit.wasm");
const zkey = resolve(repoRoot, "circuits/build/valid_create/circuit_final.zkey");

const available = existsSync(wasm) && existsSync(zkey);
const ait = (name: string, fn: () => Promise<void>) =>
  available ? it(name, fn, 60_000) : it.skip(name, fn);

const ZERO_32 = new Uint8Array(32);

describe("VALID_CREATE prover (snarkjs end-to-end)", () => {
  ait("exact-fill, no change, no fee — all 16 public inputs land in declaration order", async () => {
    const quoteMint = Keypair.generate().publicKey.toBytes();
    const baseMint = Keypair.generate().publicKey.toBytes();

    const aliceOwner = 0xa11ceeen;
    const bobOwner = 0xb0bbeefn;

    // Alice deposited exactly 5000 QUOTE; Bob deposited exactly 50 BASE; exact fill.
    const aliceAmount = 5_000n;
    const bobAmount = 50n;
    const baseAmount = 50n;
    const quoteAmount = 5_000n;

    const inputA = { ownerCommit: aliceOwner, amount: aliceAmount, nonce: 1n, blindingR: 2n };
    const inputB = { ownerCommit: bobOwner,   amount: bobAmount,   nonce: 3n, blindingR: 4n };
    const outputC = { ownerCommit: aliceOwner, amount: baseAmount,  nonce: 5n, blindingR: 6n };
    const outputD = { ownerCommit: bobOwner,   amount: quoteAmount, nonce: 7n, blindingR: 8n };

    const noteA = await noteCommitment({
      tokenMint: quoteMint, amount: aliceAmount,
      ownerCommitment: aliceOwner, nonce: 1n, blindingR: 2n,
    });
    const noteB = await noteCommitment({
      tokenMint: baseMint, amount: bobAmount,
      ownerCommitment: bobOwner, nonce: 3n, blindingR: 4n,
    });
    const noteC = await noteCommitment({
      tokenMint: baseMint, amount: baseAmount,
      ownerCommitment: aliceOwner, nonce: 5n, blindingR: 6n,
    });
    const noteD = await noteCommitment({
      tokenMint: quoteMint, amount: quoteAmount,
      ownerCommitment: bobOwner, nonce: 7n, blindingR: 8n,
    });

    const result = await proveValidCreate({
      repoRoot,
      quoteMint, baseMint,
      inputA, inputAcommitmentBE: noteA,
      inputB, inputBcommitmentBE: noteB,
      outputC, outputCcommitmentBE: noteC,
      outputD, outputDcommitmentBE: noteD,
      outputE: undefined, outputEcommitmentBE: ZERO_32,
      outputF: undefined, outputFcommitmentBE: ZERO_32,
      baseAmount, quoteAmount,
      buyerChangeAmt: 0n, sellerChangeAmt: 0n,
      buyerFeeAmt: 0n, sellerFeeAmt: 0n,
    });

    expect(result.proof.piA.length).toBe(64);
    expect(result.proof.piB.length).toBe(128);
    expect(result.proof.piC.length).toBe(64);

    expect(result.publicInputsBE.length).toBe(16);
    for (const pi of result.publicInputsBE) expect(pi.length).toBe(32);

    // Order: note_a, note_b, note_c, note_d, note_e, note_f,
    //        qmint_lo, qmint_hi, bmint_lo, bmint_hi,
    //        base_amt, quote_amt, buyer_chg, seller_chg, buyer_fee, seller_fee
    expect(Buffer.from(result.publicInputsBE[0]).toString("hex"))
      .toBe(Buffer.from(noteA).toString("hex"));
    expect(Buffer.from(result.publicInputsBE[1]).toString("hex"))
      .toBe(Buffer.from(noteB).toString("hex"));
    expect(Buffer.from(result.publicInputsBE[2]).toString("hex"))
      .toBe(Buffer.from(noteC).toString("hex"));
    expect(Buffer.from(result.publicInputsBE[3]).toString("hex"))
      .toBe(Buffer.from(noteD).toString("hex"));
    expect(be32ToBigInt(result.publicInputsBE[4])).toBe(0n);
    expect(be32ToBigInt(result.publicInputsBE[5])).toBe(0n);

    const [qLo, qHi] = pubkeyToFrPair(quoteMint);
    const [bLo, bHi] = pubkeyToFrPair(baseMint);
    expect(be32ToBigInt(result.publicInputsBE[6])).toBe(qLo);
    expect(be32ToBigInt(result.publicInputsBE[7])).toBe(qHi);
    expect(be32ToBigInt(result.publicInputsBE[8])).toBe(bLo);
    expect(be32ToBigInt(result.publicInputsBE[9])).toBe(bHi);

    expect(be32ToBigInt(result.publicInputsBE[10])).toBe(baseAmount);
    expect(be32ToBigInt(result.publicInputsBE[11])).toBe(quoteAmount);
    expect(be32ToBigInt(result.publicInputsBE[12])).toBe(0n);
    expect(be32ToBigInt(result.publicInputsBE[13])).toBe(0n);
    expect(be32ToBigInt(result.publicInputsBE[14])).toBe(0n);
    expect(be32ToBigInt(result.publicInputsBE[15])).toBe(0n);
  });

  ait("over-collateralised buyer with non-zero change — note_e is real, note_f stays zero", async () => {
    const quoteMint = Keypair.generate().publicKey.toBytes();
    const baseMint = Keypair.generate().publicKey.toBytes();

    const aliceOwner = 0xa11ceeen;
    const bobOwner = 0xb0bbeefn;

    // Alice deposited 7500 QUOTE but only wants to buy 50 BASE @ 100 = 5000.
    // Change = 7500 - 5000 - 0 (no fee in this test) = 2500.
    const aliceAmount = 7_500n;
    const bobAmount = 50n;
    const baseAmount = 50n;
    const quoteAmount = 5_000n;
    const buyerChange = 2_500n;

    const inputA = { ownerCommit: aliceOwner, amount: aliceAmount, nonce: 11n, blindingR: 12n };
    const inputB = { ownerCommit: bobOwner,   amount: bobAmount,   nonce: 13n, blindingR: 14n };
    const outputC = { ownerCommit: aliceOwner, amount: baseAmount,  nonce: 15n, blindingR: 16n };
    const outputD = { ownerCommit: bobOwner,   amount: quoteAmount, nonce: 17n, blindingR: 18n };
    const outputE = { ownerCommit: aliceOwner, amount: buyerChange, nonce: 19n, blindingR: 20n };

    const noteA = await noteCommitment({
      tokenMint: quoteMint, amount: aliceAmount,
      ownerCommitment: aliceOwner, nonce: 11n, blindingR: 12n,
    });
    const noteB = await noteCommitment({
      tokenMint: baseMint, amount: bobAmount,
      ownerCommitment: bobOwner, nonce: 13n, blindingR: 14n,
    });
    const noteC = await noteCommitment({
      tokenMint: baseMint, amount: baseAmount,
      ownerCommitment: aliceOwner, nonce: 15n, blindingR: 16n,
    });
    const noteD = await noteCommitment({
      tokenMint: quoteMint, amount: quoteAmount,
      ownerCommitment: bobOwner, nonce: 17n, blindingR: 18n,
    });
    const noteE = await noteCommitment({
      tokenMint: quoteMint, amount: buyerChange,
      ownerCommitment: aliceOwner, nonce: 19n, blindingR: 20n,
    });

    const result = await proveValidCreate({
      repoRoot,
      quoteMint, baseMint,
      inputA, inputAcommitmentBE: noteA,
      inputB, inputBcommitmentBE: noteB,
      outputC, outputCcommitmentBE: noteC,
      outputD, outputDcommitmentBE: noteD,
      outputE, outputEcommitmentBE: noteE,
      outputF: undefined, outputFcommitmentBE: ZERO_32,
      baseAmount, quoteAmount,
      buyerChangeAmt: buyerChange, sellerChangeAmt: 0n,
      buyerFeeAmt: 0n, sellerFeeAmt: 0n,
    });

    expect(result.publicInputsBE.length).toBe(16);
    // note_e (idx 4) should now be the real commitment.
    expect(Buffer.from(result.publicInputsBE[4]).toString("hex"))
      .toBe(Buffer.from(noteE).toString("hex"));
    // note_f (idx 5) is still zero.
    expect(be32ToBigInt(result.publicInputsBE[5])).toBe(0n);
  });

  ait("rejects a misrouted output — note_c addressed to the wrong owner fails", async () => {
    // The classic VALID_CREATE attack: TEE tries to assign Alice's BASE
    // trade leg to its OWN owner_commit. The circuit must catch this.
    const quoteMint = Keypair.generate().publicKey.toBytes();
    const baseMint = Keypair.generate().publicKey.toBytes();

    const aliceOwner = 0xa11ceeen;
    const bobOwner = 0xb0bbeefn;
    const teeOwner = 0xdeadbeefn;

    const aliceAmount = 5_000n;
    const bobAmount = 50n;
    const baseAmount = 50n;
    const quoteAmount = 5_000n;

    const inputA = { ownerCommit: aliceOwner, amount: aliceAmount, nonce: 1n, blindingR: 2n };
    const inputB = { ownerCommit: bobOwner,   amount: bobAmount,   nonce: 3n, blindingR: 4n };
    // Malicious: note_c declared as TEE-owned in the public commitment...
    const malicious_outputC = { ownerCommit: teeOwner, amount: baseAmount, nonce: 5n, blindingR: 6n };
    const outputD = { ownerCommit: bobOwner, amount: quoteAmount, nonce: 7n, blindingR: 8n };

    const noteA = await noteCommitment({
      tokenMint: quoteMint, amount: aliceAmount,
      ownerCommitment: aliceOwner, nonce: 1n, blindingR: 2n,
    });
    const noteB = await noteCommitment({
      tokenMint: baseMint, amount: bobAmount,
      ownerCommitment: bobOwner, nonce: 3n, blindingR: 4n,
    });
    // ...but compute note_c hash WITH the TEE owner so the public commit matches the bad opening
    const noteC_malicious = await noteCommitment({
      tokenMint: baseMint, amount: baseAmount,
      ownerCommitment: teeOwner, nonce: 5n, blindingR: 6n,
    });
    const noteD = await noteCommitment({
      tokenMint: quoteMint, amount: quoteAmount,
      ownerCommitment: bobOwner, nonce: 7n, blindingR: 8n,
    });

    // The circuit constraint `note_c == Poseidon(..., a_owner_commit, ...)` with
    // a_owner_commit pinned by `note_a == Poseidon(..., a_owner_commit, ...)`
    // means the only way for noteC_malicious to satisfy is if aliceOwner == teeOwner,
    // which it isn't. snarkjs will fail to find a witness.
    await expect(
      proveValidCreate({
        repoRoot,
        quoteMint, baseMint,
        inputA, inputAcommitmentBE: noteA,
        inputB, inputBcommitmentBE: noteB,
        outputC: malicious_outputC, outputCcommitmentBE: noteC_malicious,
        outputD, outputDcommitmentBE: noteD,
        outputE: undefined, outputEcommitmentBE: ZERO_32,
        outputF: undefined, outputFcommitmentBE: ZERO_32,
        baseAmount, quoteAmount,
        buyerChangeAmt: 0n, sellerChangeAmt: 0n,
        buyerFeeAmt: 0n, sellerFeeAmt: 0n,
      }),
    ).rejects.toThrow();
  });
});
