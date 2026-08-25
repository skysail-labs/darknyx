/**
 * Batched match-validity prover (parameterised over N).
 *
 * Single Groth16 proof attesting that output construction, market binding,
 * scaled pricing, conservation, and per-match fees hold for all active
 * matches in a batch. Its two public inputs are the Merkle root plus a digest
 * of governed fee/market values; the on-chain
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
 * `circuits/templates/match_batch.circom`. Single Poseidon11 (11 inputs ≤ 12
 * = light-poseidon's MAX_X5_LEN-1, so the on-chain handler can re-derive this
 * hash via solana_poseidon::hashv). Commitment-only (amount-privacy): the
 * note commitments bind the amounts/mints/price transitively, so the leaf no
 * longer hashes them (the old two-stage Poseidon12+Poseidon9 leaf, tags
 * 20/21, is retired).
 *
 *   leaf = Poseidon12(DOMAIN_LEAF_V3=31, active,
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
import { matchConfigDigest } from "../../src/utxo/match-config.js";
import { snarkjsFullProve } from "./snarkjs-prover.js";

// Domain tags — MUST match the circuit constants.
const DOMAIN_BATCH_ROOT = 22n;
// Commitment-only leaf (amount-privacy). Replaces the old two-stage
// leaf's DOMAIN_LEAF_INNER=20 / DOMAIN_LEAF_TOP=21.
/** `Poseidon3(29, note_commitment, inner_hash)` — the public consume handle. */
const DOMAIN_NOTE_USE = 29n;
/** `Poseidon3(30, tag_e, tag_f)` — folds the two relock tags into one leaf slot. */
const DOMAIN_RELOCK_DIGEST = 30n;
/** The Poseidon(12) leaf that replaced the Poseidon(11) commitment-only one. */
const DOMAIN_LEAF_V3 = 31n;
/** `Poseidon3(24, consumed_input_inner, role)` — output inner derivation. */
const DOMAIN_MATCH_OUTPUT_INNER = 24n;
const ROLE_CHANGE_BUYER = 0xb1n;
const ROLE_CHANGE_SELLER = 0x5en;

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
  isActive: boolean;
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
  priceRemainder: bigint;
  // ── Per-match protocol fee notes ──
  /** Base-mint (seller) fee note commitment; all-zero when the fee is zero. */
  noteFeeBaseCommitment: Uint8Array;
  /** Quote-mint (buyer) fee note commitment; all-zero when the fee is zero. */
  noteFeeQuoteCommitment: Uint8Array;
  // ── Batch-level (same on every slot; the prover reads slots[0]) ──
  /** Protocol fee rate (bps) — bound through the public config digest. */
  feeRateBps: bigint;
  /** Protocol fee-note owner — bound through the public config digest. */
  protocolOwnerCommitment: bigint;
  /** Governed fixed-point denominator — bound through the public config digest. */
  priceScale: bigint;
  /** Private governed scalar used to derive all fee-note inners in this batch. */
  feeEpochKey: bigint;
  /** `Poseidon2(35, feeEpochKey)`, bound through the config digest. */
  feeKeyBinding: bigint;
  /** Monotonic governance epoch selecting `feeEpochKey`. */
  feeKeyEpoch: bigint;
  /** Canonical derived fee-note inners retained for parity assertions. */
  feeBaseInner: bigint;
  feeQuoteInner: bigint;
}

export interface BatchProveResult {
  proof: Groth16OnChainProof;
  /** 32-byte Merkle root — the first of two public inputs. */
  merkleRoot: Uint8Array;
  /** Per-slot leaves in input order. */
  leaves: Uint8Array[];
  /** `[merkle_root, config_digest]` in canonical circuit order. */
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
  const zero32 = new Uint8Array(32);
  return {
    noteAcommitment: zero32,
    noteBcommitment: zero32,
    noteCcommitment: zero32,
    noteDcommitment: zero32,
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
    isActive: false,
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
    priceRemainder: 0n,
    noteFeeBaseCommitment: zero32,
    noteFeeQuoteCommitment: zero32,
    feeRateBps: 0n,
    protocolOwnerCommitment: 0n,
    priceScale: 1n,
    feeEpochKey: 0n,
    feeKeyBinding: 0n,
    feeKeyEpoch: 0n,
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
  const hash = (inputs: bigint[]): bigint => p.F.toObject(p(inputs));
  const tag = (commitment: bigint, inner: bigint): bigint =>
    hash([DOMAIN_NOTE_USE, commitment, inner]);

  // The two CONSUMED inputs enter the leaf as tags, not commitments — a leaf
  // carrying the commitments would put them right back on chain via the batch
  // root, defeating the point.
  const tagA = tag(bigintFromBE32(slot.noteAcommitment), slot.aInner);
  const tagB = tag(bigintFromBE32(slot.noteBcommitment), slot.bInner);

  // The relock tags are masked exactly like their commitments: a slot with no
  // change publishes tag 0, so the on-chain settle never derives a relock PDA
  // for a note that does not exist. The circuit masks
  // `(1 - changeIsZero) * Poseidon3(29, hashE.out, eInner)`; because
  // note_e_commitment is itself masked to 0 in that case, testing the
  // commitment for zero here reproduces it.
  const eCommit = bigintFromBE32(slot.noteEcommitment);
  const fCommit = bigintFromBE32(slot.noteFcommitment);
  const tagE =
    eCommit === 0n
      ? 0n
      : tag(
          eCommit,
          hash([DOMAIN_MATCH_OUTPUT_INNER, slot.aInner, ROLE_CHANGE_BUYER]),
        );
  const tagF =
    fCommit === 0n
      ? 0n
      : tag(
          fCommit,
          hash([DOMAIN_MATCH_OUTPUT_INNER, slot.bInner, ROLE_CHANGE_SELLER]),
        );

  // Poseidon12(DOMAIN_LEAF_V3, active, tag_a, tag_b, note_c..note_f,
  // note_fee_base, note_fee_quote, batch_slot, relock_digest). Binding the two
  // relock tags as separate fields would need 13 inputs, one over
  // light-poseidon's cap; the digest lands it at exactly 12.
  const relockDigest = hash([DOMAIN_RELOCK_DIGEST, tagE, tagF]);
  const leaf = hash([
    DOMAIN_LEAF_V3,
    slot.isActive ? 1n : 0n,
    tagA,
    tagB,
    bigintFromBE32(slot.noteCcommitment),
    bigintFromBE32(slot.noteDcommitment),
    eCommit,
    fCommit,
    bigintFromBE32(slot.noteFeeBaseCommitment),
    bigintFromBE32(slot.noteFeeQuoteCommitment),
    slot.batchSlot,
    relockDigest,
  ]);
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
  /** Negative-test hook: replace the governed digest while retaining its preimage. */
  configDigestOverride?: Uint8Array;
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
    if (
      slot.baseAmount * slot.clearingPrice !==
      slot.quoteAmount * slot.priceScale + slot.priceRemainder
    ) {
      throw new Error(
        `match-batch-prover[slot${i}]: scaled floor equation failed`,
      );
    }
    if (
      slot.priceScale <= 0n ||
      slot.priceRemainder < 0n ||
      slot.priceRemainder >= slot.priceScale
    ) {
      throw new Error(
        `match-batch-prover[slot${i}]: invalid price scale/remainder`,
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
  const configDigest =
    args.configDigestOverride ??
    (await matchConfigDigest({
      feeRateBps: args.slots[0].feeRateBps,
      protocolOwnerCommitment: bn254ToBE32(
        args.slots[0].protocolOwnerCommitment,
      ),
      baseMint: args.slots[0].baseMint,
      quoteMint: args.slots[0].quoteMint,
      priceScale: args.slots[0].priceScale,
      feeKeyBinding: bn254ToBE32(args.slots[0].feeKeyBinding),
      feeKeyEpoch: args.slots[0].feeKeyEpoch,
    }));

  const inputs: Record<string, string | string[]> = {
    merkle_root: bigintFromBE32(merkleRoot).toString(),
    config_digest: bigintFromBE32(configDigest).toString(),
    // Batch-level PUBLIC/private inputs (single values, read from slot 0).
    // The governed preimage is private but constrained to config_digest.
    fee_rate_bps: args.slots[0].feeRateBps.toString(),
    protocol_owner_commitment: args.slots[0].protocolOwnerCommitment.toString(),
    base_mint_lo: pubkeyToFrPair(args.slots[0].baseMint)[0].toString(),
    base_mint_hi: pubkeyToFrPair(args.slots[0].baseMint)[1].toString(),
    quote_mint_lo: pubkeyToFrPair(args.slots[0].quoteMint)[0].toString(),
    quote_mint_hi: pubkeyToFrPair(args.slots[0].quoteMint)[1].toString(),
    price_scale: args.slots[0].priceScale.toString(),
    fee_key_binding: args.slots[0].feeKeyBinding.toString(),
    fee_key_epoch: args.slots[0].feeKeyEpoch.toString(),
    fee_epoch_key: args.slots[0].feeEpochKey.toString(),
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
    base_amount: args.slots.map((s) => s.baseAmount.toString()),
    quote_amount: args.slots.map((s) => s.quoteAmount.toString()),
    buyer_change_amt: args.slots.map((s) => s.buyerChangeAmt.toString()),
    seller_change_amt: args.slots.map((s) => s.sellerChangeAmt.toString()),
    buyer_fee_amt: args.slots.map((s) => s.buyerFeeAmt.toString()),
    seller_fee_amt: args.slots.map((s) => s.sellerFeeAmt.toString()),
    batch_slot: args.slots.map((s) => s.batchSlot.toString()),
    is_active: args.slots.map((s) => (s.isActive ? "1" : "0")),
    // VALID_CREATE private witnesses
    a_owner_commit: args.slots.map((s) => s.aOwnerCommit.toString()),
    b_owner_commit: args.slots.map((s) => s.bOwnerCommit.toString()),
    a_amount: args.slots.map((s) => s.aAmount.toString()),
    b_amount: args.slots.map((s) => s.bAmount.toString()),
    a_inner: args.slots.map((s) => s.aInner.toString()),
    b_inner: args.slots.map((s) => s.bInner.toString()),
    // VALID_PRICE private witness
    clearing_price: args.slots.map((s) => s.clearingPrice.toString()),
    price_remainder: args.slots.map((s) => s.priceRemainder.toString()),
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
