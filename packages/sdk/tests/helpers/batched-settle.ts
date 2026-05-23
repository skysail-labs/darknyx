/**
 * v3.5 — one-shot helper that drives a settle through the batched
 * `verify_match_batch` + `tee_forced_settle_batched` path.
 *
 * Encapsulates the four steps each test site otherwise has to repeat:
 *
 *   1. Generate the batched Groth16 + land `verify_match_batch`
 *      (via `landVerifyMatchBatch`, which pads the single real match
 *      to N=16 with dummy slots).
 *   2. Compute the Merkle inclusion path for slot 0.
 *   3. Create a per-batch Address Lookup Table holding the 5
 *      derivable PDAs that aren't init'd by Anchor (so they can
 *      be ALT'd; init'd accounts can't be). Wait one slot for the
 *      ALT to be usable.
 *   4. Send the settle as a v0 tx that stacks the static settle ALT
 *      + the per-batch ALT, packing the tx well under 1232 bytes.
 *
 * The caller constructs the `realSlot: MatchSlotWitness` from the
 * already-built payload + persona data. The helper handles
 * everything from there.
 *
 * For production matchers, the per-batch ALT-create+wait would be
 * amortised across all N=16 settles in the same batch (or via a
 * rolling-ALT pool — see `docs/v3.5-migration.md`). The one-ALT-per-
 * settle pattern here is convenient for tests with a single match,
 * not optimal for throughput.
 */

import {
  AddressLookupTableProgram,
  ComputeBudgetProgram,
  Connection,
  Keypair,
  PublicKey,
  Transaction,
  sendAndConfirmTransaction,
} from "@solana/web3.js";

import {
  batchValidityMarkerPda,
  noteLockPda,
} from "../../src/idl/vault-client.js";
import {
  buildEd25519VerifyIx,
  buildSettleBatchedIx,
  type MatchResultPayload,
} from "../../src/settlement/settle-builder.js";
import {
  merkleInclusionPath,
  type MatchSlotWitness,
} from "./match-batch-prover.js";
import { sendSettleV0 } from "./settle-v0.js";
import { landVerifyMatchBatch } from "./verify-match-batch.js";

const ZERO_32 = new Uint8Array(32);

export interface SettleViaBatchedParams {
  connection: Connection;
  vaultProgramId: PublicKey;
  /** The TEE authority — signer + payer. */
  teeKeypair: Keypair;
  /** Per-slot witness for the ONE real match in this settle.
   *  The helper handles padding to N=16 internally. */
  realSlot: MatchSlotWitness;
  payload: MatchResultPayload;
  /** TEE Ed25519 signature over canonical_payload_hash(payload). */
  teeSig: Uint8Array;
  /** SHA-256 canonical payload hash — what the TEE signed. */
  canonicalHash: Uint8Array;
  /** The static settle ALT created by devnet-setup. */
  settleLookupTable: PublicKey;
  repoRoot: string;
  /** Optional callback for per-step tx-signature logging. */
  onTx?: (label: string, signature: string) => void;
}

export interface SettleViaBatchedResult {
  /** Tx signature of the verify_match_batch tx. */
  verifyTxSig: string;
  /** Tx signature of the per-batch ALT create+extend. */
  altTxSig: string;
  /** Tx signature of the tee_forced_settle_batched tx. */
  settleTxSig: string;
  /** Pubkey of the per-batch ALT — useful if the test wants to
   *  inspect it. */
  batchAlt: PublicKey;
}

export async function settleViaBatched(
  p: SettleViaBatchedParams,
): Promise<SettleViaBatchedResult> {
  const log = (label: string, sig: string) => {
    if (p.onTx) p.onTx(label, sig);
  };

  // ─── Step 1: prove + verify_match_batch ──────────────────────────
  const batchResult = await landVerifyMatchBatch({
    connection: p.connection,
    vaultProgramId: p.vaultProgramId,
    teeKeypair: p.teeKeypair,
    realSlots: [p.realSlot],
    repoRoot: p.repoRoot,
  });
  log("verify_match_batch", batchResult.txSig);

  // ─── Step 2: Merkle inclusion path (depth-4 for N=16) ────────────
  const inclusion = await merkleInclusionPath(batchResult.leaves, 0);
  if (inclusion.siblings.length !== 4) {
    throw new Error(
      `settleViaBatched: expected depth-4 inclusion path, got ${inclusion.siblings.length}`,
    );
  }

  // ─── Step 3: per-batch ALT (5 derived PDAs to save ~155 B) ──────
  // note_lock_e / note_lock_f use the payload's actual note_e/f
  // commitments — they're zero for exact-fill, non-zero for
  // change-note paths. PDA derivation works for both.
  const [lockA] = noteLockPda(p.vaultProgramId, p.payload.noteAcommitment);
  const [lockB] = noteLockPda(p.vaultProgramId, p.payload.noteBcommitment);
  const [lockE] = noteLockPda(p.vaultProgramId, p.payload.noteEcommitment ?? ZERO_32);
  const [lockF] = noteLockPda(p.vaultProgramId, p.payload.noteFcommitment ?? ZERO_32);
  const [batchMarker] = batchValidityMarkerPda(
    p.vaultProgramId,
    batchResult.merkleRoot,
  );

  // `createLookupTable` requires a `recentSlot` that exists in the
  // SlotHashes sysvar. `getSlot("confirmed")` can return a slot the
  // leader skipped — when that happens the runtime rejects it
  // ("…is not a recent slot"). The slot reported alongside a fresh
  // blockhash is guaranteed to be in SlotHashes since SlotHashes is
  // updated every landed slot.
  const blockhashCtx = await p.connection.getLatestBlockhashAndContext("confirmed");
  const slotForAlt = blockhashCtx.context.slot;
  const [createAltIx, batchAlt] = AddressLookupTableProgram.createLookupTable({
    authority: p.teeKeypair.publicKey,
    payer: p.teeKeypair.publicKey,
    recentSlot: slotForAlt,
  });
  const extendAltIx = AddressLookupTableProgram.extendLookupTable({
    payer: p.teeKeypair.publicKey,
    authority: p.teeKeypair.publicKey,
    lookupTable: batchAlt,
    addresses: [lockA, lockB, lockE, lockF, batchMarker],
  });
  const altTx = new Transaction().add(createAltIx, extendAltIx);
  const altTxSig = await sendAndConfirmTransaction(
    p.connection,
    altTx,
    [p.teeKeypair],
    { commitment: "confirmed" },
  );
  log(`per-batch ALT ${batchAlt.toBase58().slice(0, 8)}…`, altTxSig);

  // Wait one slot so the ALT is usable.
  for (let attempt = 0; attempt < 30; attempt++) {
    const now = await p.connection.getSlot("confirmed");
    if (now > slotForAlt) break;
    await new Promise((r) => setTimeout(r, 400));
  }

  // ─── Step 4: tee_forced_settle_batched via v0 + stacked ALTs ─────
  const settleTxSig = await sendSettleV0({
    connection: p.connection,
    signer: p.teeKeypair,
    altPubkey: p.settleLookupTable,
    extraAltPubkeys: [batchAlt],
    instructions: [
      ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
      buildEd25519VerifyIx({
        teePubkey: p.teeKeypair.publicKey.toBytes(),
        signature: p.teeSig,
        message: p.canonicalHash,
      }),
      buildSettleBatchedIx({
        programId: p.vaultProgramId,
        teeAuthority: p.teeKeypair.publicKey,
        payload: p.payload,
        matchIndex: 0,
        merkleProof: [
          inclusion.siblings[0],
          inclusion.siblings[1],
          inclusion.siblings[2],
          inclusion.siblings[3],
        ],
        merkleRoot: batchResult.merkleRoot,
      }),
    ],
  });
  log("Ed25519 + tee_forced_settle_batched", settleTxSig);

  return {
    verifyTxSig: batchResult.txSig,
    altTxSig,
    settleTxSig,
    batchAlt,
  };
}
