/**
 * v3.5 — batched match-validity prover (parameterised over N).
 *
 * Single Groth16 proof attesting that VALID_CREATE + VALID_PRICE hold
 * for all N matches in a batch. The proof's one public input is the
 * Merkle root over the per-slot leaves; the on-chain
 * `tee_forced_settle` handler recomputes the leaf for the match it
 * sees, walks a log2(N)-depth inclusion path, and asserts the root
 * matches the `BatchValidityMarker` PDA seed.
 *
 * Supports N ∈ {2, 4, 16} via the precompiled zkeys at
 * `circuits/build/match_batch_n{N}/`. N=16 is the production batch
 * size (matches `BATCH_RESULTS_CAPACITY` on-chain); N=2 and N=4 exist
 * as scaling-validation steps and fast unit-test instances.
 *
 * Leaf-hash layout — MUST match `template MatchSlot()` in
 * `circuits/templates/match_batch.circom`. Single Poseidon10 (10 inputs ≤ 12
 * = light-poseidon's MAX_X5_LEN-1, so the on-chain handler can re-derive this
 * hash via solana_poseidon::hashv). Commitment-only (amount-privacy, P1b): the
 * note commitments bind the amounts/mints/price transitively, so the leaf no
 * longer hashes them (the old two-stage Poseidon12+Poseidon9 leaf, tags
 * 20/21, is retired).
 *
 *   leaf = Poseidon10(DOMAIN_LEAF_V2=23,
 *                     note_a, note_b, note_c, note_d, note_e, note_f,
 *                     note_fee_base, note_fee_quote,
 *                     batch_slot)
 *
 * Internal Merkle-tree node (also matches the circuit):
 *   parent = Poseidon3(DOMAIN_BATCH_ROOT=22, left, right)
 */

import { writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { buildPoseidon } from "circomlibjs";

import type { Groth16OnChainProof } from "../../src/idl/vault-client.js";
import { bn254ToBE32 } from "../../src/keys/key-generators.js";
import { snarkjsFullProve } from "./snarkjs-prover.js";

// Domain tags — MUST match the circuit constants.
const DOMAIN_BATCH_ROOT = 22n;
// Commitment-only leaf (amount-privacy, P1b). Replaces the old two-stage
// leaf's DOMAIN_LEAF_INNER=20 / DOMAIN_LEAF_TOP=21.
const DOMAIN_LEAF_V2 = 23n;

type PoseidonFn = ((inputs: bigint[]) => Uint8Array) & {
  F: { toObject: (x: Uint8Array) => bigint };
};

let cached: PoseidonFn | null = null;
async function getPoseidon(): Promise<PoseidonFn> {
  if (cached) return cached;
  const p = await buildPoseidon();
  const fn = ((inputs: bigint[]) =>
    p(inputs.map((i) => p.F.e(i)))) as PoseidonFn;
  fn.F = p.F;
  cached = fn;
  return fn;
}

/** Per-slot witness — every input the per-match circuits required, in one row. */
export interface MatchSlotWitness {
  // ── VALID_CREATE-equivalent public fields ──
  noteAcommitment: Uint8Array;
  noteBcommitment: Uint8Array;
  noteCcommitment: Uint8Array;
  noteDcommitment: Uint8Array;
  /** All-zero when there's no buyer change. */
  noteEcommitment: Uint8Array;
  /** All-zero when there's no seller change. */
  noteFcommitment: Uint8Array;
  quoteMint: Uint8Array;
  baseMint: Uint8Array;
  baseAmount: bigint;
  quoteAmount: bigint;
  buyerChangeAmt: bigint;
  sellerChangeAmt: bigint;
  buyerFeeAmt: bigint;
  sellerFeeAmt: bigint;
  // ── VALID_PRICE-equivalent fields ──
  batchSlot: bigint;
  // ── VALID_CREATE private witnesses (v2: one inner_hash per note) ──
  aOwnerCommit: bigint;
  bOwnerCommit: bigint;
  aAmount: bigint;
  bAmount: bigint;
  aInner: bigint;
  bInner: bigint;
  cInner: bigint;
  dInner: bigint;
  /** Only meaningful when buyerChangeAmt != 0. */
  eInner: bigint;
  /** Only meaningful when sellerChangeAmt != 0. */
  fInner: bigint;
  // ── VALID_PRICE private witness ──
  clearingPrice: bigint;
  // ── Protocol fee notes (per-slot; non-zero only on the flush slot 0) ──
  /** Base-mint (seller) fee note commitment; all-zero off slot 0 / no fee. */
  noteFeeBaseCommitment: Uint8Array;
  /** Quote-mint (buyer) fee note commitment; all-zero off slot 0 / no fee. */
  noteFeeQuoteCommitment: Uint8Array;
  // ── Batch-level (same on every slot; the prover reads slots[0]) ──
  /** Protocol fee rate (bps) — the circuit fee-floor PUBLIC input. */
  feeRateBps: bigint;
  /** Protocol fee-note owner — the fee-note-binding PUBLIC input. */
  protocolOwnerCommitment: bigint;
  /** Fee-note inner_hashes (derive_inner(batch_slot, FEE_ROLE_*)). */
  feeBaseInner: bigint;
  feeQuoteInner: bigint;
}

export interface BatchProveResult {
  proof: Groth16OnChainProof;
  /** 32-byte Merkle root — the single public input. */
  merkleRoot: Uint8Array;
  /** Per-slot leaves in input order. */
  leaves: Uint8Array[];
  /** snarkjs public-inputs vector. Single 32-byte element (== merkleRoot). */
  publicInputsBE: Uint8Array[];
}

export type BatchSize = 2 | 4 | 16;

function bigintFromBE32(bytes: Uint8Array): bigint {
  let acc = 0n;
  for (const b of bytes) acc = (acc << 8n) | BigInt(b);
  return acc;
}

/** Split a 32-byte BE pubkey into [lo_u128_be, hi_u128_be] as Fr scalars. */
function pubkeyToFrPair(pk: Uint8Array): [bigint, bigint] {
  if (pk.length !== 32) throw new Error("pubkeyToFrPair: expected 32 bytes");
  let lo = 0n;
  let hi = 0n;
  for (let i = 0; i < 16; i++) hi = (hi << 8n) | BigInt(pk[i]);
  for (let i = 16; i < 32; i++) lo = (lo << 8n) | BigInt(pk[i]);
  return [lo, hi];
}

/**
 * Build a fully-valid all-zero slot. Used to pad a batch up to the
 * next-supported N when the matcher produced fewer than N real
 * matches. Every per-slot constraint trivially holds:
 *
 *   - All Poseidon6 note openings collapse to
 *     `Poseidon6(2, 0, 0, 0, 0, 0)`, so note_a/b/c/d all equal
 *     this same dummy hash (note_e/f stay zero because the IsZero
 *     gates short-circuit them when buyer/seller_change_amt == 0).
 *   - Conservation: a_amount = 0 = 0 + 0 + 0. Same for b.
 *   - VALID_PRICE: 0 = 0 * 0. Range checks pass (0 is u64-valid).
 *
 * Two dummy slots in the same batch produce IDENTICAL leaves — the
 * Merkle root still uniquely commits to the batch as a whole (the
 * one real-match slot makes the root distinct from any other batch),
 * so this is safe.
 */
export async function dummySlot(): Promise<MatchSlotWitness> {
  const p = await getPoseidon();
  // Poseidon6(DOMAIN_NOTE=2, mint_lo=0, mint_hi=0, amount=0,
  //           owner_commit=0, inner_hash=0)
  const dummyNote = bn254ToBE32(p.F.toObject(p([2n, 0n, 0n, 0n, 0n, 0n])));
  const zero32 = new Uint8Array(32);
  return {
    noteAcommitment: dummyNote,
    noteBcommitment: dummyNote,
    noteCcommitment: dummyNote,
    noteDcommitment: dummyNote,
    noteEcommitment: zero32,
    noteFcommitment: zero32,
    quoteMint: zero32,
    baseMint: zero32,
    baseAmount: 0n,
    quoteAmount: 0n,
    buyerChangeAmt: 0n,
    sellerChangeAmt: 0n,
    buyerFeeAmt: 0n,
    sellerFeeAmt: 0n,
    batchSlot: 0n,
    aOwnerCommit: 0n,
    bOwnerCommit: 0n,
    aAmount: 0n,
    bAmount: 0n,
    aInner: 0n,
    bInner: 0n,
    cInner: 0n,
    dInner: 0n,
    eInner: 0n,
    fInner: 0n,
    clearingPrice: 0n,
    noteFeeBaseCommitment: zero32,
    noteFeeQuoteCommitment: zero32,
    feeRateBps: 0n,
    protocolOwnerCommitment: 0n,
    feeBaseInner: 0n,
    feeQuoteInner: 0n,
  };
}

/**
 * Pad an array of slots to exactly N entries using dummy slots. Used by
 * the devnet test driver when the matcher has fewer than N=16 real
 * matches in a batch but still needs the on-chain N=16 verifier to
 * accept the proof.
 */
export async function padBatch(
  realSlots: MatchSlotWitness[],
  N: BatchSize,
): Promise<MatchSlotWitness[]> {
  if (realSlots.length > N) {
    throw new Error(`padBatch: have ${realSlots.length} slots, N=${N}`);
  }
  if (realSlots.length === N) return realSlots;
  const dummy = await dummySlot();
  const padded = [...realSlots];
  // C-08: VALID_MATCH_BATCH now binds `batch_slot === slot index`, so each pad
  // slot must carry its position (real slots already carry theirs). Spread the
  // shared dummy into a fresh object per position with the right batchSlot.
  while (padded.length < N)
    padded.push({ ...dummy, batchSlot: BigInt(padded.length) });
  return padded;
}

/**
 * Compute the per-slot leaf hash. MUST match `template MatchSlot()` in the
 * circuit exactly — divergence here breaks Merkle inclusion on-chain.
 */
export async function computeBatchLeaf(
  slot: MatchSlotWitness,
): Promise<Uint8Array> {
  const p = await getPoseidon();
  // Commitment-only leaf (amount-privacy, P1b): Poseidon10(DOMAIN_LEAF_V2,
  // note_a..note_f, note_fee_base, note_fee_quote, batch_slot). The
  // amounts/mints/price are bound transitively via the note commitments, so
  // they leave the leaf.
  const leaf = p.F.toObject(
    p([
      DOMAIN_LEAF_V2,
      bigintFromBE32(slot.noteAcommitment),
      bigintFromBE32(slot.noteBcommitment),
      bigintFromBE32(slot.noteCcommitment),
      bigintFromBE32(slot.noteDcommitment),
      bigintFromBE32(slot.noteEcommitment),
      bigintFromBE32(slot.noteFcommitment),
      bigintFromBE32(slot.noteFeeBaseCommitment),
      bigintFromBE32(slot.noteFeeQuoteCommitment),
      slot.batchSlot,
    ]),
  );
  return bn254ToBE32(leaf);
}

/**
 * Build the binary-tree Merkle root over N leaves (N must be a power of 2).
 * Internal node = Poseidon3(DOMAIN_BATCH_ROOT, left, right). Identical to
 * `template MerkleRoot(N)` in the circuit.
 */
export async function computeBatchRoot(
  leaves: Uint8Array[],
): Promise<Uint8Array> {
  if (leaves.length === 0 || (leaves.length & (leaves.length - 1)) !== 0) {
    throw new Error(
      `computeBatchRoot: N (${leaves.length}) must be a power of 2`,
    );
  }
  const p = await getPoseidon();
  let level: bigint[] = leaves.map(bigintFromBE32);
  while (level.length > 1) {
    const next: bigint[] = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(p.F.toObject(p([DOMAIN_BATCH_ROOT, level[i], level[i + 1]])));
    }
    level = next;
  }
  return bn254ToBE32(level[0]);
}

/**
 * Build the Merkle inclusion path for `index` against the N-leaf tree.
 * Returns:
 *   - `siblings`: the sibling hash at each level (depth = log2(N) entries).
 *     siblings[0] is the leaf-level sibling; siblings[depth-1] is the root's
 *     sibling (its peer at the level just below root).
 *   - `indices[i]`: 0 if the current node is the LEFT child at level i, 1
 *     if it's the RIGHT child. The on-chain handler uses this to know
 *     which way to combine each sibling.
 *
 * Internal-node hashes are computed level-by-level so siblings ABOVE the
 * leaf level are real hashes (previous versions of this helper used dummy
 * values, which would have made the returned siblings beyond depth-1 wrong).
 *
 * The on-chain settle handler walks this same path to verify a single match
 * against the batch root committed in the BatchValidityMarker PDA.
 */
export async function merkleInclusionPath(
  leaves: Uint8Array[],
  index: number,
): Promise<{ siblings: Uint8Array[]; indices: number[] }> {
  if (leaves.length === 0 || (leaves.length & (leaves.length - 1)) !== 0) {
    throw new Error("merkleInclusionPath: N must be a power of 2");
  }
  if (index < 0 || index >= leaves.length) {
    throw new Error(`merkleInclusionPath: index ${index} out of range`);
  }
  const p = await getPoseidon();
  const siblings: Uint8Array[] = [];
  const indices: number[] = [];

  let currentLevel: Uint8Array[] = leaves;
  let currentIndex = index;
  while (currentLevel.length > 1) {
    const siblingIndex = currentIndex ^ 1;
    siblings.push(currentLevel[siblingIndex]);
    indices.push(currentIndex & 1);

    // Hash adjacent pairs to compute the next level. Must use the same
    // domain-tagged Poseidon3 the circuit's MerkleRoot template uses.
    const next: Uint8Array[] = [];
    for (let i = 0; i < currentLevel.length; i += 2) {
      const parent = p.F.toObject(
        p([
          DOMAIN_BATCH_ROOT,
          bigintFromBE32(currentLevel[i]),
          bigintFromBE32(currentLevel[i + 1]),
        ]),
      );
      next.push(bn254ToBE32(parent));
    }
    currentLevel = next;
    currentIndex = currentIndex >> 1;
  }
  return { siblings, indices };
}

export interface MatchBatchProveParams {
  repoRoot: string;
  slots: MatchSlotWitness[];
}

/**
 * Generate a batched validity proof. `slots.length` must be one of {2, 4, 16},
 * matching the precompiled zkey at `circuits/build/match_batch_n{N}/`.
 */
export async function proveMatchBatch(
  args: MatchBatchProveParams,
): Promise<BatchProveResult> {
  const N = args.slots.length as BatchSize;
  if (N !== 2 && N !== 4 && N !== 16) {
    throw new Error(
      `proveMatchBatch: unsupported batch size N=${N} (must be 2, 4, or 16)`,
    );
  }

  // Sanity-check the headline constraints before invoking snarkjs.
  args.slots.forEach((slot, i) => {
    if (slot.quoteAmount !== slot.baseAmount * slot.clearingPrice) {
      throw new Error(
        `match-batch-prover[slot${i}]: quote (${slot.quoteAmount}) !== ` +
          `base (${slot.baseAmount}) * price (${slot.clearingPrice})`,
      );
    }
    if (
      slot.aAmount !==
      slot.quoteAmount + slot.buyerChangeAmt + slot.buyerFeeAmt
    ) {
      throw new Error(
        `match-batch-prover[slot${i}]: a_amount conservation failed ` +
          `(${slot.aAmount} != ${slot.quoteAmount} + ${slot.buyerChangeAmt} + ${slot.buyerFeeAmt})`,
      );
    }
    if (
      slot.bAmount !==
      slot.baseAmount + slot.sellerChangeAmt + slot.sellerFeeAmt
    ) {
      throw new Error(
        `match-batch-prover[slot${i}]: b_amount conservation failed`,
      );
    }
  });

  // Compute leaves + root off-circuit; the circuit re-derives the same.
  const leaves = await Promise.all(args.slots.map(computeBatchLeaf));
  const merkleRoot = await computeBatchRoot(leaves);

  const inputs: Record<string, string | string[]> = {
    merkle_root: bigintFromBE32(merkleRoot).toString(),
    // Batch-level PUBLIC/private inputs (single values, read from slot 0).
    // Circuit `main` public order: [merkle_root, fee_rate_bps, protocol_owner].
    fee_rate_bps: args.slots[0].feeRateBps.toString(),
    protocol_owner_commitment: args.slots[0].protocolOwnerCommitment.toString(),
    fee_base_inner: args.slots[0].feeBaseInner.toString(),
    fee_quote_inner: args.slots[0].feeQuoteInner.toString(),
    // VALID_CREATE-equivalent public fields
    note_a_commitment: args.slots.map((s) =>
      bigintFromBE32(s.noteAcommitment).toString(),
    ),
    note_b_commitment: args.slots.map((s) =>
      bigintFromBE32(s.noteBcommitment).toString(),
    ),
    note_c_commitment: args.slots.map((s) =>
      bigintFromBE32(s.noteCcommitment).toString(),
    ),
    note_d_commitment: args.slots.map((s) =>
      bigintFromBE32(s.noteDcommitment).toString(),
    ),
    note_e_commitment: args.slots.map((s) =>
      bigintFromBE32(s.noteEcommitment).toString(),
    ),
    note_f_commitment: args.slots.map((s) =>
      bigintFromBE32(s.noteFcommitment).toString(),
    ),
    note_fee_base_commitment: args.slots.map((s) =>
      bigintFromBE32(s.noteFeeBaseCommitment).toString(),
    ),
    note_fee_quote_commitment: args.slots.map((s) =>
      bigintFromBE32(s.noteFeeQuoteCommitment).toString(),
    ),
    quote_mint_lo: args.slots.map((s) =>
      pubkeyToFrPair(s.quoteMint)[0].toString(),
    ),
    quote_mint_hi: args.slots.map((s) =>
      pubkeyToFrPair(s.quoteMint)[1].toString(),
    ),
    base_mint_lo: args.slots.map((s) =>
      pubkeyToFrPair(s.baseMint)[0].toString(),
    ),
    base_mint_hi: args.slots.map((s) =>
      pubkeyToFrPair(s.baseMint)[1].toString(),
    ),
    base_amount: args.slots.map((s) => s.baseAmount.toString()),
    quote_amount: args.slots.map((s) => s.quoteAmount.toString()),
    buyer_change_amt: args.slots.map((s) => s.buyerChangeAmt.toString()),
    seller_change_amt: args.slots.map((s) => s.sellerChangeAmt.toString()),
    buyer_fee_amt: args.slots.map((s) => s.buyerFeeAmt.toString()),
    seller_fee_amt: args.slots.map((s) => s.sellerFeeAmt.toString()),
    batch_slot: args.slots.map((s) => s.batchSlot.toString()),
    // VALID_CREATE private witnesses
    a_owner_commit: args.slots.map((s) => s.aOwnerCommit.toString()),
    b_owner_commit: args.slots.map((s) => s.bOwnerCommit.toString()),
    a_amount: args.slots.map((s) => s.aAmount.toString()),
    b_amount: args.slots.map((s) => s.bAmount.toString()),
    a_inner: args.slots.map((s) => s.aInner.toString()),
    b_inner: args.slots.map((s) => s.bInner.toString()),
    c_inner: args.slots.map((s) => s.cInner.toString()),
    d_inner: args.slots.map((s) => s.dInner.toString()),
    e_inner: args.slots.map((s) => s.eInner.toString()),
    f_inner: args.slots.map((s) => s.fInner.toString()),
    // VALID_PRICE private witness
    clearing_price: args.slots.map((s) => s.clearingPrice.toString()),
  };

  // (witness-gen bench, Step 1) Dump the circom input.json so the native C++
  // witness generator + node-wasm reference can be timed on the EXACT same
  // inputs as our prover. Gated by DUMP_CIRCOM_INPUT=<path>; no-op otherwise.
  if (process.env.DUMP_CIRCOM_INPUT) {
    writeFileSync(process.env.DUMP_CIRCOM_INPUT, JSON.stringify(inputs));
  }

  const wasmRel = `circuits/build/match_batch_n${N}/circuit_js/circuit.wasm`;
  const zkeyRel = `circuits/build/match_batch_n${N}/circuit_final.zkey`;

  const result = await snarkjsFullProve(inputs, {
    repoRoot: args.repoRoot,
    circuitWasmPath: resolve(args.repoRoot, wasmRel),
    circuitZkeyPath: resolve(args.repoRoot, zkeyRel),
  });

  return {
    proof: result.proof,
    merkleRoot,
    leaves,
    publicInputsBE: result.publicInputsBE,
  };
}
