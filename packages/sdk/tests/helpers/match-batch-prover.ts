/**
 * v3.5 prototype — batched match-validity prover (N=2).
 *
 * Generates a single Groth16 proof attesting that BOTH VALID_CREATE AND
 * VALID_PRICE hold for N=2 matches simultaneously. The proof's single
 * public input is a Merkle root committing to the per-slot bound values;
 * the on-chain `tee_forced_settle` handler recomputes the leaf for the
 * match it sees, walks a Merkle inclusion path, and asserts the root
 * matches the `BatchValidityMarker` PDA seed.
 *
 * Once cross-validated against the per-match `valid_create` +
 * `valid_price` circuits, the same shape generalises to N=4 → N=16 with
 * a binary-tree Merkle root (depth 1 → depth 4).
 *
 * Leaf-hash layout (must match `circuits/match_batch_n2/circuit.circom`):
 *   h1 = Poseidon7(DOMAIN_LEAF_INNER=20, note_a, note_b, note_c, note_d, note_e, note_f)
 *   h2 = Poseidon7(h1, qm_lo, qm_hi, bm_lo, bm_hi, base_amt, quote_amt)
 *   h3 = Poseidon7(h2, buyer_change, seller_change, buyer_fee, seller_fee, 0, 0)
 *   leaf = Poseidon4(DOMAIN_LEAF_TOP=21, h3, price_commitment, batch_slot)
 *
 * Internal Merkle node (must match the circuit too):
 *   parent = Poseidon3(DOMAIN_BATCH_ROOT=22, left, right)
 */

import { resolve } from "node:path";
import { buildPoseidon } from "circomlibjs";

import type { Groth16OnChainProof } from "../../src/idl/vault-client.js";
import { bn254ToBE32 } from "../../src/keys/key-generators.js";
import { priceCommitment } from "../../src/zk/price-commitment.js";
import { snarkjsFullProve } from "./snarkjs-prover.js";

const WASM_REL = "circuits/build/match_batch_n2/circuit_js/circuit.wasm";
const ZKEY_REL = "circuits/build/match_batch_n2/circuit_final.zkey";

// Domain tags — MUST match the circuit constants.
const DOMAIN_LEAF_INNER = 20n;
const DOMAIN_LEAF_TOP = 21n;
const DOMAIN_BATCH_ROOT = 22n;

type PoseidonFn = ((inputs: bigint[]) => Uint8Array) & {
  F: { toObject: (x: Uint8Array) => bigint };
};

let cached: PoseidonFn | null = null;
async function getPoseidon(): Promise<PoseidonFn> {
  if (cached) return cached;
  const p = await buildPoseidon();
  const fn = ((inputs: bigint[]) => p(inputs.map((i) => p.F.e(i)))) as PoseidonFn;
  fn.F = p.F;
  cached = fn;
  return fn;
}

/**
 * Per-slot witness — every input the per-match circuits expected,
 * routed into one batch row.
 *
 * Note: `clearingPrice` is private to VALID_PRICE; the circuit derives
 * `priceCommitment` from `(clearingPrice, batchSlot)` and constrains it
 * to equal the slot's `priceCommitmentExpected` (computed off-chain via
 * `priceCommitment(...)` below and supplied as the slot's public-ish
 * value through the leaf hash). All amounts are `u64` and must satisfy
 * `quoteAmount === baseAmount * clearingPrice`.
 */
export interface MatchSlotWitness {
  // ── VALID_CREATE public fields ──
  noteAcommitment: Uint8Array;   // 32 bytes BE
  noteBcommitment: Uint8Array;
  noteCcommitment: Uint8Array;
  noteDcommitment: Uint8Array;
  /** All-zero when there's no buyer change. */
  noteEcommitment: Uint8Array;
  /** All-zero when there's no seller change. */
  noteFcommitment: Uint8Array;
  /** 32-byte mint pubkey, split into [lo, hi] u128 halves below. */
  quoteMint: Uint8Array;
  baseMint: Uint8Array;
  baseAmount: bigint;
  quoteAmount: bigint;
  buyerChangeAmt: bigint;
  sellerChangeAmt: bigint;
  buyerFeeAmt: bigint;
  sellerFeeAmt: bigint;
  // ── VALID_PRICE public field ──
  batchSlot: bigint;
  // ── VALID_CREATE private witnesses ──
  aOwnerCommit: bigint;
  bOwnerCommit: bigint;
  aAmount: bigint;
  bAmount: bigint;
  aNonce: bigint;
  aBlinding: bigint;
  bNonce: bigint;
  bBlinding: bigint;
  cNonce: bigint;
  cBlinding: bigint;
  dNonce: bigint;
  dBlinding: bigint;
  /** Only used when buyerChangeAmt != 0 (else: any value works, can be 0n). */
  eNonce: bigint;
  eBlinding: bigint;
  /** Only used when sellerChangeAmt != 0. */
  fNonce: bigint;
  fBlinding: bigint;
  // ── VALID_PRICE private witness ──
  clearingPrice: bigint;
}

export interface BatchProveResult {
  proof: Groth16OnChainProof;
  /** 32-byte Merkle root (the one and only public input). */
  merkleRoot: Uint8Array;
  /** Per-slot leaf hashes — same order as input slots. Useful for tests + the on-chain Merkle inclusion proof. */
  leaves: Uint8Array[];
  /** snarkjs public-inputs vector, single 32-byte element (merkleRoot). */
  publicInputsBE: Uint8Array[];
}

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
 * Compute the per-slot leaf hash. MUST match the chain
 * h1 → h2 → h3 → leafTop in MatchSlot's circuit body.
 */
export async function computeBatchLeaf(slot: MatchSlotWitness): Promise<Uint8Array> {
  const p = await getPoseidon();
  const [qLo, qHi] = pubkeyToFrPair(slot.quoteMint);
  const [bLo, bHi] = pubkeyToFrPair(slot.baseMint);
  const pc = await priceCommitment(slot.clearingPrice, slot.batchSlot);

  const h1 = p.F.toObject(
    p([
      DOMAIN_LEAF_INNER,
      bigintFromBE32(slot.noteAcommitment),
      bigintFromBE32(slot.noteBcommitment),
      bigintFromBE32(slot.noteCcommitment),
      bigintFromBE32(slot.noteDcommitment),
      bigintFromBE32(slot.noteEcommitment),
      bigintFromBE32(slot.noteFcommitment),
    ]),
  );

  const h2 = p.F.toObject(
    p([
      h1,
      qLo,
      qHi,
      bLo,
      bHi,
      slot.baseAmount,
      slot.quoteAmount,
    ]),
  );

  const h3 = p.F.toObject(
    p([
      h2,
      slot.buyerChangeAmt,
      slot.sellerChangeAmt,
      slot.buyerFeeAmt,
      slot.sellerFeeAmt,
      0n,
      0n,
    ]),
  );

  const leaf = p.F.toObject(
    p([DOMAIN_LEAF_TOP, h3, bigintFromBE32(pc), slot.batchSlot]),
  );
  return bn254ToBE32(leaf);
}

/** Combine two leaves into the batch Merkle root (depth 1, N=2). */
export async function computeBatchRoot2(
  leafA: Uint8Array,
  leafB: Uint8Array,
): Promise<Uint8Array> {
  const p = await getPoseidon();
  const root = p.F.toObject(
    p([DOMAIN_BATCH_ROOT, bigintFromBE32(leafA), bigintFromBE32(leafB)]),
  );
  return bn254ToBE32(root);
}

export interface MatchBatch2ProveParams {
  repoRoot: string;
  slot0: MatchSlotWitness;
  slot1: MatchSlotWitness;
}

export async function proveMatchBatch2(
  args: MatchBatch2ProveParams,
): Promise<BatchProveResult> {
  // Sanity check the headline VALID_PRICE constraint up-front so a
  // mismatch surfaces as a readable error rather than as snarkjs's
  // generic "constraint failed at line X".
  for (const [name, slot] of [
    ["slot0", args.slot0],
    ["slot1", args.slot1],
  ] as const) {
    if (slot.quoteAmount !== slot.baseAmount * slot.clearingPrice) {
      throw new Error(
        `match-batch-prover[${name}]: quote (${slot.quoteAmount}) !== ` +
          `base (${slot.baseAmount}) * price (${slot.clearingPrice})`,
      );
    }
    if (slot.aAmount !== slot.quoteAmount + slot.buyerChangeAmt + slot.buyerFeeAmt) {
      throw new Error(
        `match-batch-prover[${name}]: a_amount conservation failed ` +
          `(${slot.aAmount} != ${slot.quoteAmount} + ${slot.buyerChangeAmt} + ${slot.buyerFeeAmt})`,
      );
    }
    if (slot.bAmount !== slot.baseAmount + slot.sellerChangeAmt + slot.sellerFeeAmt) {
      throw new Error(
        `match-batch-prover[${name}]: b_amount conservation failed`,
      );
    }
  }

  // Compute leaves + root off-chain (the circuit re-derives the same).
  const leaf0 = await computeBatchLeaf(args.slot0);
  const leaf1 = await computeBatchLeaf(args.slot1);
  const merkleRoot = await computeBatchRoot2(leaf0, leaf1);

  // Build snarkjs input.json. Public input first (merkle_root), then all
  // per-slot arrays. Circom expects decimal strings.
  const slots = [args.slot0, args.slot1];
  const inputs: Record<string, string | string[]> = {
    merkle_root: bigintFromBE32(merkleRoot).toString(),
    // VALID_CREATE public fields
    note_a_commitment: slots.map((s) => bigintFromBE32(s.noteAcommitment).toString()),
    note_b_commitment: slots.map((s) => bigintFromBE32(s.noteBcommitment).toString()),
    note_c_commitment: slots.map((s) => bigintFromBE32(s.noteCcommitment).toString()),
    note_d_commitment: slots.map((s) => bigintFromBE32(s.noteDcommitment).toString()),
    note_e_commitment: slots.map((s) => bigintFromBE32(s.noteEcommitment).toString()),
    note_f_commitment: slots.map((s) => bigintFromBE32(s.noteFcommitment).toString()),
    quote_mint_lo: slots.map((s) => pubkeyToFrPair(s.quoteMint)[0].toString()),
    quote_mint_hi: slots.map((s) => pubkeyToFrPair(s.quoteMint)[1].toString()),
    base_mint_lo: slots.map((s) => pubkeyToFrPair(s.baseMint)[0].toString()),
    base_mint_hi: slots.map((s) => pubkeyToFrPair(s.baseMint)[1].toString()),
    base_amount: slots.map((s) => s.baseAmount.toString()),
    quote_amount: slots.map((s) => s.quoteAmount.toString()),
    buyer_change_amt: slots.map((s) => s.buyerChangeAmt.toString()),
    seller_change_amt: slots.map((s) => s.sellerChangeAmt.toString()),
    buyer_fee_amt: slots.map((s) => s.buyerFeeAmt.toString()),
    seller_fee_amt: slots.map((s) => s.sellerFeeAmt.toString()),
    // VALID_PRICE public field
    price_commitment: await Promise.all(
      slots.map(async (s) =>
        bigintFromBE32(await priceCommitment(s.clearingPrice, s.batchSlot)).toString(),
      ),
    ),
    batch_slot: slots.map((s) => s.batchSlot.toString()),
    // VALID_CREATE private witnesses
    a_owner_commit: slots.map((s) => s.aOwnerCommit.toString()),
    b_owner_commit: slots.map((s) => s.bOwnerCommit.toString()),
    a_amount: slots.map((s) => s.aAmount.toString()),
    b_amount: slots.map((s) => s.bAmount.toString()),
    a_nonce: slots.map((s) => s.aNonce.toString()),
    a_blinding: slots.map((s) => s.aBlinding.toString()),
    b_nonce: slots.map((s) => s.bNonce.toString()),
    b_blinding: slots.map((s) => s.bBlinding.toString()),
    c_nonce: slots.map((s) => s.cNonce.toString()),
    c_blinding: slots.map((s) => s.cBlinding.toString()),
    d_nonce: slots.map((s) => s.dNonce.toString()),
    d_blinding: slots.map((s) => s.dBlinding.toString()),
    e_nonce: slots.map((s) => s.eNonce.toString()),
    e_blinding: slots.map((s) => s.eBlinding.toString()),
    f_nonce: slots.map((s) => s.fNonce.toString()),
    f_blinding: slots.map((s) => s.fBlinding.toString()),
    // VALID_PRICE private witness
    clearing_price: slots.map((s) => s.clearingPrice.toString()),
  };

  const result = await snarkjsFullProve(inputs, {
    repoRoot: args.repoRoot,
    circuitWasmPath: resolve(args.repoRoot, WASM_REL),
    circuitZkeyPath: resolve(args.repoRoot, ZKEY_REL),
  });

  return {
    proof: result.proof,
    merkleRoot,
    leaves: [leaf0, leaf1],
    publicInputsBE: result.publicInputsBE,
  };
}
