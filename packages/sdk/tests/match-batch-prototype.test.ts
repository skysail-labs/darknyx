/**
 * v3.5 — batched match-validity prover validation across N ∈ {2, 4, 16}.
 *
 * Three things this suite is gating:
 *   1. **Architecture works**: every supported N (2 / 4 / 16) generates a
 *      proof that snarkjs accepts. If snarkjs's internal verifier accepts
 *      it, every constraint in the circuit body is satisfied.
 *   2. **Leaf hash + Merkle root parity**: TS-computed leaves + root agree
 *      with the circuit's internally-derived values. This is the property
 *      the on-chain Merkle-inclusion check will rely on.
 *   3. **Negative paths reject**: malformed witnesses (bad VALID_PRICE math,
 *      corrupted note commitment) are rejected — either at the prover's
 *      precondition check (readable error) or at witness generation
 *      (opaque snarkjs error).
 *
 * Cross-validation against the per-match `valid_create` + `valid_price`
 * circuits comes via integration tests once the on-chain
 * `verify_match_batch` ix lands; this suite is the upstream sanity gate.
 */

import { describe, expect, it } from "vitest";
import { resolve } from "node:path";
import { existsSync } from "node:fs";

import { noteCommitmentV2 } from "../src/utxo/note.js";
import { bn254ToBE32 } from "../src/keys/key-generators.js";
import {
  deriveMatchFeeInner,
  deriveMatchOutputInner,
} from "../src/utxo/match-output.js";
import {
  proveMatchBatch,
  computeBatchLeaf,
  computeBatchRoot,
  type MatchSlotWitness,
  type BatchSize,
} from "./helpers/match-batch-prover.js";

const REPO_ROOT = resolve(__dirname, "../../..");

function circuitPaths(N: BatchSize) {
  const dir = `circuits/build/match_batch_n${N}`;
  return {
    wasm: resolve(REPO_ROOT, `${dir}/circuit_js/circuit.wasm`),
    zkey: resolve(REPO_ROOT, `${dir}/circuit_final.zkey`),
    vk: resolve(REPO_ROOT, `${dir}/verification_key.json`),
  };
}

function artefactsReady(N: BatchSize): boolean {
  const { wasm, zkey, vk } = circuitPaths(N);
  return existsSync(wasm) && existsSync(zkey) && existsSync(vk);
}

const bytesToBigIntBE = (bytes: Uint8Array): bigint =>
  bytes.reduce((acc, byte) => (acc << 8n) | BigInt(byte), 0n);

/**
 * Build a fully-valid match-slot witness. Note commitments are computed
 * from the witness so the per-slot VALID_CREATE openings hold by
 * construction.
 */
async function buildSlot(args: {
  quoteMint: Uint8Array;
  baseMint: Uint8Array;
  buyerOwnerCommit: bigint;
  sellerOwnerCommit: bigint;
  baseAmount: bigint;
  clearingPrice: bigint;
  buyerChange: bigint;
  sellerChange: bigint;
  buyerFee: bigint;
  sellerFee: bigint;
  batchSlot: bigint;
  /** Salt the inner_hashes so multiple slots in the same batch
   *  don't accidentally collide commitments. */
  slotIdx: number;
  /** Circuit fee-floor PUBLIC input (bps). Defaults to 0 (floor is a
   *  no-op). Batch-level: every slot must carry the same value. */
  feeRateBps?: bigint;
  priceScale?: bigint;
}): Promise<MatchSlotWitness> {
  const priceScale = args.priceScale ?? 1n;
  const numerator = args.baseAmount * args.clearingPrice;
  const quoteAmount = numerator / priceScale;
  const priceRemainder = numerator % priceScale;
  const aAmount = quoteAmount + args.buyerChange + args.buyerFee;
  const bAmount = args.baseAmount + args.sellerChange + args.sellerFee;

  // One inner_hash per note (v2). Salt by slot so leaves stay distinct.
  const I = (idx: number) => BigInt(0xa0a0 + args.slotIdx * 100 + idx);
  const aInner = I(1);
  const bInner = I(2);
  const cInner = bytesToBigIntBE(await deriveMatchOutputInner(bn254ToBE32(aInner), 0xc1));
  const dInner = bytesToBigIntBE(await deriveMatchOutputInner(bn254ToBE32(bInner), 0xd1));
  const eInner = bytesToBigIntBE(await deriveMatchOutputInner(bn254ToBE32(aInner), 0xb1));
  const fInner = bytesToBigIntBE(await deriveMatchOutputInner(bn254ToBE32(bInner), 0x5e));

  const noteA = await noteCommitmentV2({
    tokenMint: args.quoteMint,
    amount: aAmount,
    ownerCommitment: args.buyerOwnerCommit,
    innerHash: aInner,
  });
  const noteB = await noteCommitmentV2({
    tokenMint: args.baseMint,
    amount: bAmount,
    ownerCommitment: args.sellerOwnerCommit,
    innerHash: bInner,
  });
  const noteC = await noteCommitmentV2({
    tokenMint: args.baseMint,
    amount: args.baseAmount,
    ownerCommitment: args.buyerOwnerCommit,
    innerHash: cInner,
  });
  const noteD = await noteCommitmentV2({
    tokenMint: args.quoteMint,
    amount: quoteAmount,
    ownerCommitment: args.sellerOwnerCommit,
    innerHash: dInner,
  });
  const zero = new Uint8Array(32);
  const noteE =
    args.buyerChange === 0n
      ? zero
      : await noteCommitmentV2({
          tokenMint: args.quoteMint,
          amount: args.buyerChange,
          ownerCommitment: args.buyerOwnerCommit,
          innerHash: eInner,
        });
  const noteF =
    args.sellerChange === 0n
      ? zero
      : await noteCommitmentV2({
          tokenMint: args.baseMint,
          amount: args.sellerChange,
          ownerCommitment: args.sellerOwnerCommit,
          innerHash: fInner,
        });

  return {
    noteAcommitment: noteA,
    noteBcommitment: noteB,
    noteCcommitment: noteC,
    noteDcommitment: noteD,
    noteEcommitment: noteE,
    noteFcommitment: noteF,
    quoteMint: args.quoteMint,
    baseMint: args.baseMint,
    baseAmount: args.baseAmount,
    quoteAmount,
    buyerChangeAmt: args.buyerChange,
    sellerChangeAmt: args.sellerChange,
    buyerFeeAmt: args.buyerFee,
    sellerFeeAmt: args.sellerFee,
    batchSlot: args.batchSlot,
    isActive: true,
    aOwnerCommit: args.buyerOwnerCommit,
    bOwnerCommit: args.sellerOwnerCommit,
    aAmount,
    bAmount,
    aInner,
    bInner,
    cInner,
    dInner,
    eInner,
    fInner,
    clearingPrice: args.clearingPrice,
    priceRemainder,
    // Fee notes default to none; `bindFeeNotes` fills each fee-bearing match.
    noteFeeBaseCommitment: new Uint8Array(32),
    noteFeeQuoteCommitment: new Uint8Array(32),
    feeRateBps: args.feeRateBps ?? 0n,
    protocolOwnerCommitment: 0n,
    priceScale,
    feeBaseInner: 0n,
    feeQuoteInner: 0n,
  };
}

/**
 * Bind each match's protocol fee notes to its consumed input commitments.
 */
async function bindFeeNotes(
  slots: MatchSlotWitness[],
  args: {
    quoteMint: Uint8Array;
    baseMint: Uint8Array;
    protocolOwner: bigint;
  },
): Promise<void> {
  const zero = new Uint8Array(32);
  for (const s of slots) {
    s.protocolOwnerCommitment = args.protocolOwner;
    s.feeBaseInner = bytesToBigIntBE(await deriveMatchFeeInner(s.noteBcommitment, 0xfb));
    s.feeQuoteInner = bytesToBigIntBE(await deriveMatchFeeInner(s.noteAcommitment, 0xfc));
    s.noteFeeBaseCommitment =
      s.sellerFeeAmt === 0n
        ? zero
        : await noteCommitmentV2({
            tokenMint: args.baseMint,
            amount: s.sellerFeeAmt,
            ownerCommitment: args.protocolOwner,
            innerHash: s.feeBaseInner,
          });
    s.noteFeeQuoteCommitment =
      s.buyerFeeAmt === 0n
        ? zero
        : await noteCommitmentV2({
            tokenMint: args.quoteMint,
            amount: s.buyerFeeAmt,
            ownerCommitment: args.protocolOwner,
            innerHash: s.feeQuoteInner,
          });
  }
}

function rand32(seed: number): Uint8Array {
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = (seed + i * 37) & 0xff;
  out[0] &= 0x0f; // Keep within the BN254 scalar field.
  return out;
}

/** Default exact-fill scenario reused across N. */
async function defaultBatch(N: BatchSize): Promise<MatchSlotWitness[]> {
  const quoteMint = rand32(0xaa);
  const baseMint = rand32(0xbb);
  const buyerCommit = 0x1234567890abcdefn;
  const sellerCommit = 0xfedcba0987654321n;
  const slots: MatchSlotWitness[] = [];
  for (let i = 0; i < N; i++) {
    slots.push(
      await buildSlot({
        quoteMint,
        baseMint,
        buyerOwnerCommit: buyerCommit,
        sellerOwnerCommit: sellerCommit,
        // Different base amounts per slot so the leaves are distinct.
        baseAmount: 10n + BigInt(i) * 5n,
        clearingPrice: 100n,
        buyerChange: 0n,
        sellerChange: 0n,
        buyerFee: 0n,
        sellerFee: 0n,
        // C-08: batch_slot === slot index.
        batchSlot: BigInt(i),
        slotIdx: i,
      }),
    );
  }
  return slots;
}

// ---------------------------------------------------------------------------
// Positive scenarios per N
// ---------------------------------------------------------------------------

for (const N of [2, 4, 16] as const) {
  const ready = artefactsReady(N);
  const d = ready ? describe : describe.skip;

  d(`v3.5 batched validity — N=${N}`, () => {
    it(`[exact_fill_no_change] all-slot proof verifies + leaves match TS`, async () => {
      const slots = await defaultBatch(N);
      const result = await proveMatchBatch({ repoRoot: REPO_ROOT, slots });

      // [merkle_root, fee_rate_bps].
      expect(result.publicInputsBE.length).toBe(8);
      expect(result.publicInputsBE[0]).toEqual(result.merkleRoot);

      // TS-side leaf + root reproduce the circuit's internal computation.
      for (let i = 0; i < N; i++) {
        const tsLeaf = await computeBatchLeaf(slots[i]);
        expect(result.leaves[i]).toEqual(tsLeaf);
      }
      const tsRoot = await computeBatchRoot(result.leaves);
      expect(result.merkleRoot).toEqual(tsRoot);

      // Proof byte layout sanity.
      expect(result.proof.piA.length).toBe(64);
      expect(result.proof.piB.length).toBe(128);
      expect(result.proof.piC.length).toBe(64);
    }, 240_000); // N=16 proof gen can be ~30-60s on M1.
  });
}

// ---------------------------------------------------------------------------
// Mixed-shape scenarios — change-note slots interleaved with exact-fill
// ---------------------------------------------------------------------------

const ready2 = artefactsReady(2);
(ready2 ? describe : describe.skip)("v3.5 — N=2 mixed-shape coverage", () => {
  it("[with_change_notes] one exact-fill + one over-collateralised with buyer change + fee", async () => {
    const quoteMint = rand32(0xcc);
    const baseMint = rand32(0xdd);
    const buyerCommit = 0xaaaaaaaa00000001n;
    const sellerCommit = 0xbbbbbbbb00000002n;

    const slots: MatchSlotWitness[] = [
      await buildSlot({
        quoteMint,
        baseMint,
        buyerOwnerCommit: buyerCommit,
        sellerOwnerCommit: sellerCommit,
        // C-04 (exact fee): fee == ⌊quote·rate/10000⌋. Slot 0 stays fee-free by
        // keeping its notional tiny (quote = 1·200 = 200 ⇒ ⌊200·30/10000⌋ = 0),
        // so buyerFee 0 is exact at the batch rate 30.
        baseAmount: 1n,
        clearingPrice: 200n,
        buyerChange: 0n,
        sellerChange: 0n,
        buyerFee: 0n,
        sellerFee: 0n,
        feeRateBps: 30n,
        batchSlot: 0n, // C-08: batch_slot === slot index
        slotIdx: 0,
      }),
      await buildSlot({
        quoteMint,
        baseMint,
        buyerOwnerCommit: buyerCommit,
        sellerOwnerCommit: sellerCommit,
        // quote = 25·200 = 5000 ⇒ exact fee ⌊5000·30/10000⌋ = 15.
        baseAmount: 25n,
        clearingPrice: 200n,
        buyerChange: 1_000n,
        sellerChange: 0n,
        buyerFee: 15n,
        sellerFee: 0n,
        feeRateBps: 30n,
        batchSlot: 1n, // C-08: batch_slot === slot index
        slotIdx: 1,
      }),
    ];
    // Slot 1 charges a buyer fee; bind its per-match fee note.
    await bindFeeNotes(slots, {
      quoteMint,
      baseMint,
      protocolOwner: 0x07070707n,
    });

    const result = await proveMatchBatch({ repoRoot: REPO_ROOT, slots });

    expect(result.publicInputsBE.length).toBe(8);
    expect(result.leaves[0]).not.toEqual(result.leaves[1]); // distinct shapes → distinct leaves.

    const tsRoot = await computeBatchRoot(result.leaves);
    expect(result.merkleRoot).toEqual(tsRoot);
  }, 120_000);
});

// ---------------------------------------------------------------------------
// Exact fee (amount-privacy P1b + C-04) — in-circuit floor `(fee+1)*10000 >
// notional*rate` AND ceiling `fee*10000 <= notional*rate` ⇒ fee is pinned to
// exactly ⌊notional*rate/10000⌋.
// ---------------------------------------------------------------------------

(ready2 ? describe : describe.skip)("v3.5 — N=2 fee floor", () => {
  // base=10, price=100 → quote=1000. At rate=30 the buyer floor is
  // ⌊1000*30/10000⌋ = 3; the seller floor is ⌊10*30/10000⌋ = 0.
  const quoteMint = rand32(0xee);
  const baseMint = rand32(0xff);
  const buyerCommit = 0xc0ffee00n;
  const sellerCommit = 0xdecaf000n;

  async function feeBatch(buyerFee: bigint): Promise<MatchSlotWitness[]> {
    const mk = (idx: number) =>
      buildSlot({
        quoteMint,
        baseMint,
        buyerOwnerCommit: buyerCommit,
        sellerOwnerCommit: sellerCommit,
        baseAmount: 10n,
        clearingPrice: 100n,
        buyerChange: 0n,
        sellerChange: 0n,
        buyerFee,
        sellerFee: 0n,
        batchSlot: BigInt(idx), // C-08: batch_slot === slot index
        slotIdx: idx,
        feeRateBps: 30n,
      });
    const slots = [await mk(0), await mk(1)];
    await bindFeeNotes(slots, {
      quoteMint,
      baseMint,
      protocolOwner: 0x07070707n,
    });
    return slots;
  }

  it("[fee_at_floor] charging exactly the floor proves at rate=30", async () => {
    const result = await proveMatchBatch({
      repoRoot: REPO_ROOT,
      slots: await feeBatch(3n),
    });
    // fee_rate_bps is the 2nd public input (value 30).
    expect(result.publicInputsBE.length).toBe(8);
    const fee = result.publicInputsBE[1];
    expect(fee[31]).toBe(30);
  }, 60_000);

  it("[fee_below_floor] under-charging is UNPROVABLE at rate=30", async () => {
    // buyerFee=2 < floor 3 ⇒ (2+1)*10000 = 30000 is NOT > 1000*30 = 30000,
    // so the in-circuit GreaterThan (floor) fails witness generation.
    await expect(
      proveMatchBatch({ repoRoot: REPO_ROOT, slots: await feeBatch(2n) }),
    ).rejects.toThrow();
  }, 60_000);

  it("[fee_above_floor] over-charging is UNPROVABLE at rate=30 (C-04 ceiling)", async () => {
    // buyerFee=4 > exact fee 3 ⇒ 4*10000 = 40000 is NOT <= 1000*30 = 30000, so
    // the in-circuit LessEqThan (ceiling) fails witness generation. Without the
    // C-04 ceiling this would prove — a malicious TEE could confiscate the trade
    // into the protocol fee notes.
    await expect(
      proveMatchBatch({ repoRoot: REPO_ROOT, slots: await feeBatch(4n) }),
    ).rejects.toThrow();
  }, 60_000);
});

// ---------------------------------------------------------------------------
// Negative paths — what's supposed to be rejected, IS rejected.
// ---------------------------------------------------------------------------

(ready2 ? describe : describe.skip)("v3.5 — N=2 negative paths", () => {
  it("[zero_quote_active] active slot with quote_amount == 0 is UNPROVABLE (U-03)", async () => {
    // priceScale=1000: slot 0 fills positively (base=1000, price=1 → quote=1);
    // slot 1's notional floors to zero quote (base=1, price=1 → quote=0). Such a
    // clear would mint an unspendable zero-amount note_d. The scaled-floor and
    // conservation prechecks PASS (1 == 0*1000 + 1; aAmount == quote+change+fee),
    // so this reaches witness generation and fails ONLY on the circuit's
    // `is_active * quoteIsZero === 0` gate.
    const quoteMint = rand32(0x3a);
    const baseMint = rand32(0x3b);
    const common = {
      quoteMint,
      baseMint,
      buyerOwnerCommit: 0x1111n,
      sellerOwnerCommit: 0x2222n,
      sellerChange: 0n,
      buyerFee: 0n,
      sellerFee: 0n,
      priceScale: 1000n,
    };
    const slots = [
      await buildSlot({
        ...common,
        baseAmount: 1000n,
        clearingPrice: 1n,
        buyerChange: 0n,
        batchSlot: 0n,
        slotIdx: 0,
      }),
      await buildSlot({
        ...common,
        baseAmount: 1n,
        clearingPrice: 1n,
        // Keep aAmount positive so the failure is unambiguously the zero-quote
        // gate, not an all-zero input note.
        buyerChange: 5n,
        batchSlot: 1n,
        slotIdx: 1,
      }),
    ];
    expect(slots[1].quoteAmount).toBe(0n);
    await expect(
      proveMatchBatch({ repoRoot: REPO_ROOT, slots }),
    ).rejects.toThrow();
  }, 30_000);

  it("[bad_price_math] prover precondition rejects quote != base × price", async () => {
    const slots = await defaultBatch(2);
    // Deliberately corrupt slot[0] so the headline VALID_PRICE constraint
    // would fail. Bumping quoteAmount up by 1 breaks `quote = base × price`
    // without affecting any other constraint precheck.
    slots[0] = { ...slots[0], quoteAmount: slots[0].quoteAmount + 1n };

    await expect(
      proveMatchBatch({ repoRoot: REPO_ROOT, slots }),
    ).rejects.toThrow(/scaled floor equation/);
  }, 30_000);

  it("[bad_conservation] prover precondition rejects a_amount != quote + change + fee", async () => {
    const slots = await defaultBatch(2);
    // Bump aAmount by 1 — breaks `a_amount = quote_amount + buyer_change + buyer_fee`.
    slots[1] = { ...slots[1], aAmount: slots[1].aAmount + 1n };

    await expect(
      proveMatchBatch({ repoRoot: REPO_ROOT, slots }),
    ).rejects.toThrow(/a_amount conservation/);
  }, 30_000);

  it("[bad_note_commitment] snarkjs rejects when noteA doesn't open to its commitment", async () => {
    const slots = await defaultBatch(2);
    // Corrupt noteA's commitment AFTER the witness is built. This bypasses
    // the prover's quick-checks (which only verify the high-level
    // VALID_PRICE / conservation arithmetic, not the per-note Poseidon
    // openings). snarkjs's witness generator should fail because the
    // constraint `note_a_commitment === Poseidon6(2, qm_lo, qm_hi,
    // a_amount, a_owner_commit, a_inner)` no longer holds.
    const corrupted = new Uint8Array(slots[0].noteAcommitment);
    corrupted[31] ^= 0x01;
    slots[0] = { ...slots[0], noteAcommitment: corrupted };

    await expect(
      proveMatchBatch({ repoRoot: REPO_ROOT, slots }),
    ).rejects.toThrow();
  }, 60_000);

  it("[CS-03] rejects a user output built with arbitrary inner randomness", async () => {
    const slots = await defaultBatch(2);
    slots[0].noteCcommitment = await noteCommitmentV2({
      tokenMint: slots[0].baseMint,
      amount: slots[0].baseAmount,
      ownerCommitment: slots[0].aOwnerCommit,
      innerHash: 0xdeadbeefn,
    });
    slots[0].cInner = 0xdeadbeefn; // ignored: no such circuit witness in v3.
    await expect(
      proveMatchBatch({ repoRoot: REPO_ROOT, slots }),
    ).rejects.toThrow();
  }, 60_000);

  it("[CS-02] rejects a slot whose notes use a different market mint", async () => {
    const slots = await defaultBatch(2);
    const otherBase = rand32(0x41);
    slots[1] = await buildSlot({
      quoteMint: slots[0].quoteMint,
      baseMint: otherBase,
      buyerOwnerCommit: slots[1].aOwnerCommit,
      sellerOwnerCommit: slots[1].bOwnerCommit,
      baseAmount: 15n,
      clearingPrice: 100n,
      buyerChange: 0n,
      sellerChange: 0n,
      buyerFee: 0n,
      sellerFee: 0n,
      batchSlot: 1n,
      slotIdx: 1,
    });
    await expect(
      proveMatchBatch({ repoRoot: REPO_ROOT, slots }),
    ).rejects.toThrow();
  }, 60_000);

  it("[CS-01] rejects a phantom inactive slot carrying commitments or fees", async () => {
    const slots = await defaultBatch(2);
    slots[1].isActive = false;
    await expect(
      proveMatchBatch({ repoRoot: REPO_ROOT, slots }),
    ).rejects.toThrow();
  }, 60_000);

  it("[scaled_floor] accepts a non-zero constrained remainder", async () => {
    const quoteMint = rand32(0x51);
    const baseMint = rand32(0x61);
    const slots = await Promise.all(
      [0, 1].map((slotIdx) =>
        buildSlot({
          quoteMint,
          baseMint,
          buyerOwnerCommit: 11n,
          sellerOwnerCommit: 12n,
          baseAmount: 7n,
          clearingPrice: 10n,
          priceScale: 3n,
          buyerChange: 0n,
          sellerChange: 0n,
          buyerFee: 0n,
          sellerFee: 0n,
          batchSlot: BigInt(slotIdx),
          slotIdx,
        }),
      ),
    );
    expect(slots[0].quoteAmount).toBe(23n);
    expect(slots[0].priceRemainder).toBe(1n);
    await expect(
      proveMatchBatch({ repoRoot: REPO_ROOT, slots }),
    ).resolves.toBeDefined();
  }, 60_000);
});
