/**
 * v3.5 — one-shot helper that drives a settle through the batched
 * `verify_match_batch` + `tee_forced_settle_batched` path.
 *
 * Encapsulates the five steps each test site otherwise has to repeat:
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
 *   5. Close the `BatchValidityMarker` to reclaim its ~49-byte rent.
 *      The on-chain `tee_forced_settle_batched` handler deliberately
 *      does NOT close the marker (one marker covers all N matches in
 *      the batch). Every test site here lands exactly one real
 *      settle per batch, so we always close at step 5.
 *
 * The caller constructs the `realSlot: MatchSlotWitness` from the
 * already-built payload + persona data. The helper handles
 * everything from there.
 *
 * For production matchers, the per-batch ALT-create+wait would be
 * amortised across all N=16 settles in the same batch (or via a
 * rolling-ALT pool — see `docs/v3.5-migration.md`), and the close
 * would land once after the LAST settle. The one-ALT-and-one-close
 * per settle pattern here is convenient for tests with a single
 * real match, not optimal for throughput.
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
  buildCloseBatchValidityMarkerIx,
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
  /** Tx signature of the close_batch_validity_marker tx. */
  closeTxSig: string;
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

  // ─── Step 5: close the BatchValidityMarker to reclaim its rent ──
  // The on-chain handler doesn't close (one marker, many matches);
  // we land an explicit close because every test site here is a
  // 1-real-match-per-batch flow.
  const closeTx = new Transaction().add(
    buildCloseBatchValidityMarkerIx({
      programId: p.vaultProgramId,
      authority: p.teeKeypair.publicKey,
      payer: p.teeKeypair.publicKey,
      merkleRoot: batchResult.merkleRoot,
    }),
  );
  const closeTxSig = await sendAndConfirmTransaction(
    p.connection,
    closeTx,
    [p.teeKeypair],
    { commitment: "confirmed" },
  );
  log("close_batch_validity_marker", closeTxSig);

  return {
    verifyTxSig: batchResult.txSig,
    altTxSig,
    settleTxSig,
    closeTxSig,
    batchAlt,
  };
}

// ===========================================================================
// v3.5 — multi-match production helper
// ===========================================================================
//
// `settleViaBatched` (above) does one real match per call and is what every
// existing devnet test uses. This sibling helper, `settleBatchViaBatched`,
// is the production-matcher shape: ONE verify, ONE ALT (containing every
// real match's derivable PDAs), N settles fired CONCURRENTLY via Promise.all,
// ONE close. For N=16 real matches per batch, this turns ~16 × per-tx
// confirm-latency into ~1 × per-tx confirm-latency.
//
// Why the parallel-settle step works: all N settles take `mut` on
// `VaultConfig`, so Solana's runtime serialises them at block-inclusion
// time (one settle per slot). But each tx is an INDEPENDENT RPC
// `sendTransaction` call — the polls for `confirmed` overlap. Wall-clock
// is the time for the leader to land all N in consecutive slots, not
// N × the per-tx confirm latency.
//
// Why this isn't exercised by the current tests: they all have N=1 real
// match per batch, so `Promise.all([oneItem])` collapses to `await
// oneItem`. The helper is here so a production matcher can import it as
// is once it actually has multi-match batches; in the meantime, see
// `programs/matching_engine/tests/tee_forced_settle_batched.rs::
// test_two_matches_share_one_marker` for the on-chain side of the
// invariant this helper relies on (one marker covers all N matches).

export interface BatchMatchInput {
  /** Per-slot witness for one real match. */
  realSlot: MatchSlotWitness;
  /** Payload for this match — must canonically hash to `canonicalHash`. */
  payload: MatchResultPayload;
  /** TEE Ed25519 signature over `canonicalHash`. */
  teeSig: Uint8Array;
  /** SHA-256 canonical payload hash — what the TEE signed. */
  canonicalHash: Uint8Array;
}

export interface SettleBatchViaBatchedParams {
  connection: Connection;
  vaultProgramId: PublicKey;
  /** TEE authority — signs every settle + the marker close. */
  teeKeypair: Keypair;
  /** 1..16 real matches. Order matters: index i in this array is
   *  `match_index = i` on-chain (slot i in the Merkle tree). The
   *  helper pads to N=16 internally via `landVerifyMatchBatch`. */
  matches: BatchMatchInput[];
  /** The static settle ALT created by devnet-setup. */
  settleLookupTable: PublicKey;
  repoRoot: string;
  /** Optional per-step tx-signature logger. */
  onTx?: (label: string, signature: string) => void;
}

export interface SettleBatchViaBatchedResult {
  /** Tx signature of the verify_match_batch tx (1 per batch). */
  verifyTxSig: string;
  /** Tx signatures of the ALT-create + ALT-extend(s). For matches.length
   *  ≤ ~7 this is one tx; for N=16 it's 2-3 because Solana's
   *  per-extend tx-size cap forces chunking. */
  altSetupTxSigs: string[];
  /** Tx signatures of the N settles, in match-index order. */
  settleTxSigs: string[];
  /** Tx signature of the close_batch_validity_marker tx (1 per batch). */
  closeTxSig: string;
  /** Pubkey of the per-batch ALT. */
  batchAlt: PublicKey;
}

/**
 * Production-matcher settle: lands a whole batch of up to 16 matches
 * through the v3.5 batched path, amortising verify + ALT + close
 * across all of them and firing the N per-match settles concurrently.
 *
 * Wall-clock model (assuming RPC confirm latency T):
 *   sequential — verify (T) + ALT setup (T × ceil(addr/28)) +
 *     N × settle (N × T) + close (T)  ≈ (N + 3) × T
 *   parallel   — verify (T) + ALT setup (T × ceil(addr/28)) +
 *     max(settle_i for i in 0..N) (~T) + close (T)  ≈ 4 × T
 *
 * At N=16, that's ~19T vs ~4T — a ~5× reduction in critical-path
 * latency. The settles still serialise on-chain (VaultConfig mut
 * contention), so on-chain throughput is unchanged; only off-chain
 * orchestration latency improves.
 */
export async function settleBatchViaBatched(
  p: SettleBatchViaBatchedParams,
): Promise<SettleBatchViaBatchedResult> {
  if (p.matches.length === 0) {
    throw new Error("settleBatchViaBatched: matches must be non-empty");
  }
  if (p.matches.length > 16) {
    throw new Error(
      `settleBatchViaBatched: at most 16 matches per batch (got ${p.matches.length}); the on-chain handler walks a depth-4 Merkle path that's hardcoded for N=16`,
    );
  }
  const log = (label: string, sig: string) => {
    if (p.onTx) p.onTx(label, sig);
  };

  // ─── Step 1: prove + verify_match_batch (covers all N at once) ───
  const batchResult = await landVerifyMatchBatch({
    connection: p.connection,
    vaultProgramId: p.vaultProgramId,
    teeKeypair: p.teeKeypair,
    realSlots: p.matches.map((m) => m.realSlot),
    repoRoot: p.repoRoot,
  });
  log("verify_match_batch", batchResult.txSig);

  // ─── Step 2: per-match Merkle inclusion paths ────────────────────
  const inclusions = await Promise.all(
    p.matches.map((_, i) => merkleInclusionPath(batchResult.leaves, i)),
  );
  for (let i = 0; i < inclusions.length; i++) {
    if (inclusions[i].siblings.length !== 4) {
      throw new Error(
        `settleBatchViaBatched: expected depth-4 inclusion path at match ${i}, got ${inclusions[i].siblings.length}`,
      );
    }
  }

  // ─── Step 3: collect derivable PDAs into the per-batch ALT ───────
  // 4 lock PDAs per match (a, b, e, f) + 1 shared marker.
  // Dedup because exact-fill matches collapse note_lock_e/f to the
  // same zero-commitment PDA — Anchor's ALT extend rejects duplicate
  // pubkeys.
  const [batchMarker] = batchValidityMarkerPda(
    p.vaultProgramId,
    batchResult.merkleRoot,
  );
  const altAddrsRaw: PublicKey[] = [];
  for (const m of p.matches) {
    altAddrsRaw.push(noteLockPda(p.vaultProgramId, m.payload.noteAcommitment)[0]);
    altAddrsRaw.push(noteLockPda(p.vaultProgramId, m.payload.noteBcommitment)[0]);
    altAddrsRaw.push(
      noteLockPda(p.vaultProgramId, m.payload.noteEcommitment ?? ZERO_32)[0],
    );
    altAddrsRaw.push(
      noteLockPda(p.vaultProgramId, m.payload.noteFcommitment ?? ZERO_32)[0],
    );
  }
  altAddrsRaw.push(batchMarker);
  const seen = new Set<string>();
  const altAddrs: PublicKey[] = [];
  for (const a of altAddrsRaw) {
    const k = a.toBase58();
    if (seen.has(k)) continue;
    seen.add(k);
    altAddrs.push(a);
  }

  // Solana caps `extendLookupTable` ix data by tx-size. ~28 addresses
  // when combined with `createLookupTable` in the same tx; ~30 in a
  // standalone extend. Conservative chunks of 28 keep us under
  // 1232 bytes either way.
  const EXTEND_CHUNK = 28;
  const blockhashCtx = await p.connection.getLatestBlockhashAndContext("confirmed");
  const slotForAlt = blockhashCtx.context.slot;
  const [createAltIx, batchAlt] = AddressLookupTableProgram.createLookupTable({
    authority: p.teeKeypair.publicKey,
    payer: p.teeKeypair.publicKey,
    recentSlot: slotForAlt,
  });

  const altSetupTxSigs: string[] = [];

  // First tx: create + first extend chunk.
  const firstChunk = altAddrs.slice(0, EXTEND_CHUNK);
  const firstExtendIx = AddressLookupTableProgram.extendLookupTable({
    payer: p.teeKeypair.publicKey,
    authority: p.teeKeypair.publicKey,
    lookupTable: batchAlt,
    addresses: firstChunk,
  });
  const firstTx = new Transaction().add(createAltIx, firstExtendIx);
  altSetupTxSigs.push(
    await sendAndConfirmTransaction(
      p.connection,
      firstTx,
      [p.teeKeypair],
      { commitment: "confirmed" },
    ),
  );
  log(`per-batch ALT ${batchAlt.toBase58().slice(0, 8)}… create+extend[0]`, altSetupTxSigs[0]);

  // Subsequent extends, if the address list overflowed.
  for (let off = EXTEND_CHUNK; off < altAddrs.length; off += EXTEND_CHUNK) {
    const chunk = altAddrs.slice(off, off + EXTEND_CHUNK);
    const extendTx = new Transaction().add(
      AddressLookupTableProgram.extendLookupTable({
        payer: p.teeKeypair.publicKey,
        authority: p.teeKeypair.publicKey,
        lookupTable: batchAlt,
        addresses: chunk,
      }),
    );
    const sig = await sendAndConfirmTransaction(
      p.connection,
      extendTx,
      [p.teeKeypair],
      { commitment: "confirmed" },
    );
    altSetupTxSigs.push(sig);
    log(`per-batch ALT extend[${altSetupTxSigs.length - 1}]`, sig);
  }

  // Wait one slot so the ALT is usable in v0 txs.
  for (let attempt = 0; attempt < 30; attempt++) {
    const now = await p.connection.getSlot("confirmed");
    if (now > slotForAlt) break;
    await new Promise((r) => setTimeout(r, 400));
  }

  // ─── Step 4: fire N settles concurrently ─────────────────────────
  // Each tx is independent at the RPC layer. The Solana runtime
  // serialises them at block-inclusion time (VaultConfig mut), but
  // the *RPC round-trips* overlap rather than stack — turning
  // N × confirm_latency into max(times) ≈ 1 × confirm_latency for
  // the whole set.
  const settleTxSigs = await Promise.all(
    p.matches.map(async (m, i) => {
      const sig = await sendSettleV0({
        connection: p.connection,
        signer: p.teeKeypair,
        altPubkey: p.settleLookupTable,
        extraAltPubkeys: [batchAlt],
        instructions: [
          ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
          buildEd25519VerifyIx({
            teePubkey: p.teeKeypair.publicKey.toBytes(),
            signature: m.teeSig,
            message: m.canonicalHash,
          }),
          buildSettleBatchedIx({
            programId: p.vaultProgramId,
            teeAuthority: p.teeKeypair.publicKey,
            payload: m.payload,
            matchIndex: i,
            merkleProof: [
              inclusions[i].siblings[0],
              inclusions[i].siblings[1],
              inclusions[i].siblings[2],
              inclusions[i].siblings[3],
            ],
            merkleRoot: batchResult.merkleRoot,
          }),
        ],
      });
      log(`tee_forced_settle_batched[match=${i}]`, sig);
      return sig;
    }),
  );

  // ─── Step 5: close the marker once for the whole batch ───────────
  const closeTx = new Transaction().add(
    buildCloseBatchValidityMarkerIx({
      programId: p.vaultProgramId,
      authority: p.teeKeypair.publicKey,
      payer: p.teeKeypair.publicKey,
      merkleRoot: batchResult.merkleRoot,
    }),
  );
  const closeTxSig = await sendAndConfirmTransaction(
    p.connection,
    closeTx,
    [p.teeKeypair],
    { commitment: "confirmed" },
  );
  log("close_batch_validity_marker", closeTxSig);

  return {
    verifyTxSig: batchResult.txSig,
    altSetupTxSigs,
    settleTxSigs,
    closeTxSig,
    batchAlt,
  };
}
