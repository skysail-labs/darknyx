/**
 * v3.5 — `tee_forced_settle_batched` SDK builder.
 *
 * Mirrors `settle-builder.test.ts`, but covers the batched-validity ix
 * that replaces the v3.1 per-match `verify_valid_create` +
 * `verify_valid_price` + `tee_forced_settle` triplet.
 *
 * Verifies that:
 *   1. Account ordering matches `TeeForcedSettleBatched<'info>`
 *      (14 accounts, merkle_tree at slot 2, batch_validity_marker at slot 12).
 *   2. Data starts with `sha256("global:tee_forced_settle_batched")[..8]`.
 *   3. `ix.data` length = 8 (disc) + 1 (tree_id) + 488 (Borsh payload)
 *                       + 1 (matchIndex u8) + 128 (4 × 32-byte siblings)
 *                       = 626 bytes.
 *   4. The 4 Merkle siblings are encoded contiguously with NO length
 *      prefix (Anchor's `[[u8; 32]; 4]` wire shape).
 *   5. The match-index byte lives at offset `8 + 1 + 488` and reflects the
 *      caller-supplied value.
 *   6. Account slot 12 (`batch_validity_marker`) is the PDA derived
 *      from `[b"batch_validity", merkleRoot]` under the program id.
 *   7. note_lock_e / note_lock_f are derived from the payload's
 *      noteEcommitment / noteFcommitment (so they collapse to a
 *      ZERO-commitment lock for exact-fill, and to real distinct
 *      locks for change-note variants).
 *   8. Input-validation throws fire for the documented bad shapes.
 *
 * All tests are pure TypeScript — no RPC / LiteSVM / devnet required.
 */

import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  Keypair,
  PublicKey,
  SystemProgram,
  SYSVAR_INSTRUCTIONS_PUBKEY,
} from "@solana/web3.js";

import {
  RELOCK_ORDER_ID_NONE,
  ZERO_COMMITMENT,
  buildCloseBatchValidityMarkerIx,
  buildSettleBatchedIx,
  canonicalPayloadHash,
  exactFillPayload,
  serializePayload,
  type MatchResultPayload,
} from "../src/settlement/settle-builder.js";
import {
  batchValidityMarkerPda,
  noteLockPda,
} from "../src/idl/vault-client.js";

const PROGRAM_ID = new PublicKey(
  "C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx",
);

function filled(len: number, v: number): Uint8Array {
  const b = new Uint8Array(len);
  b.fill(v);
  return b;
}

function exactFillFixture(): MatchResultPayload {
  return exactFillPayload({
    matchId: filled(16, 0x11),
    noteAcommitment: filled(32, 0xa1),
    noteBcommitment: filled(32, 0xb1),
    noteCcommitment: filled(32, 0xc1),
    noteDcommitment: filled(32, 0xd1),
    orderIdA: filled(16, 0x01),
    orderIdB: filled(16, 0x02),
  });
}

function fourSiblings(): [Uint8Array, Uint8Array, Uint8Array, Uint8Array] {
  return [
    filled(32, 0x21),
    filled(32, 0x22),
    filled(32, 0x23),
    filled(32, 0x24),
  ];
}

describe("v3.5 — settle-builder-batched: buildSettleBatchedIx", () => {
  it("[hash_cross_env_parity] payload v9 canonical hash matches Rust and on-chain", () => {
    expect(
      Buffer.from(canonicalPayloadHash(exactFillFixture())).toString("hex"),
    ).toBe("63a10a281ed28632d4fee9c71b38f926f2cda8be6f78850d4f7926655ec8cfa2");
  });

  it("[settle_batched_accounts_layout] account ordering matches TeeForcedSettleBatched", () => {
    const tee = Keypair.generate();
    const payload = exactFillFixture();
    const merkleRoot = filled(32, 0xf0);
    const ix = buildSettleBatchedIx({
      programId: PROGRAM_ID,
      treeId: 0,
      teeAuthority: tee.publicKey,
      payload,
      matchIndex: 0,
      merkleProof: fourSiblings(),
      merkleRoot,
    });

    expect(ix.programId.toBase58()).toBe(PROGRAM_ID.toBase58());
    // 12 accounts: tee + vault_config + merkle_tree + locks(a,b) + consumed(a,b)
    //            + locks(e,f) + sysvar + batch_marker + system. (The two
    //            nullifier_entry accounts were removed with the freeze fix.)
    expect(ix.keys.length).toBe(12);

    // Slot 0: tee_authority (mut, signer).
    expect(ix.keys[0].pubkey.toBase58()).toBe(tee.publicKey.toBase58());
    expect(ix.keys[0].isSigner).toBe(true);
    expect(ix.keys[0].isWritable).toBe(true);

    // Slot 9: instructions sysvar.
    expect(ix.keys[9].pubkey.toBase58()).toBe(
      SYSVAR_INSTRUCTIONS_PUBKEY.toBase58(),
    );
    expect(ix.keys[9].isWritable).toBe(false);

    // Slots 7/8 are dummy relock destinations on an exact fill, and slot 10 is
    // the shared marker. All three are read-only on Tx D.
    expect(ix.keys[7].isWritable).toBe(false);
    expect(ix.keys[8].isWritable).toBe(false);
    expect(ix.keys[10].isWritable).toBe(false);

    // Slot 11: system_program.
    expect(ix.keys[11].pubkey.toBase58()).toBe(
      SystemProgram.programId.toBase58(),
    );
    expect(ix.keys[11].isSigner).toBe(false);
    expect(ix.keys[11].isWritable).toBe(false);
  });

  it("[settle_batched_distinct_shards_no_shared_writes] distinct-shard Tx Ds share no writable account", () => {
    const payload0 = exactFillFixture();
    const payload1: MatchResultPayload = {
      ...exactFillFixture(),
      noteAcommitment: filled(32, 0xa2),
      noteBcommitment: filled(32, 0xb2),
      noteCcommitment: filled(32, 0xc2),
      noteDcommitment: filled(32, 0xd2),
    };
    const args = {
      programId: PROGRAM_ID,
      merkleProof: fourSiblings(),
      merkleRoot: filled(32, 0xf0),
    };
    const ix0 = buildSettleBatchedIx({
      ...args,
      treeId: 0,
      teeAuthority: Keypair.generate().publicKey,
      payload: payload0,
      matchIndex: 0,
    });
    const ix1 = buildSettleBatchedIx({
      ...args,
      treeId: 1,
      teeAuthority: Keypair.generate().publicKey,
      payload: payload1,
      matchIndex: 1,
    });
    const writable0 = new Set(
      [ix0.keys[0], ...ix0.keys.filter((k) => k.isWritable)].map((k) =>
        k.pubkey.toBase58(),
      ),
    );
    const shared = [ix1.keys[0], ...ix1.keys.filter((k) => k.isWritable)]
      .map((k) => k.pubkey.toBase58())
      .filter((key) => writable0.has(key));
    expect(shared).toEqual([]);
  });

  it("[settle_batched_anchor_discriminator_present] data starts with sha256('global:tee_forced_settle_batched')[..8]", () => {
    const tee = Keypair.generate();
    const ix = buildSettleBatchedIx({
      programId: PROGRAM_ID,
      treeId: 0,
      teeAuthority: tee.publicKey,
      payload: exactFillFixture(),
      matchIndex: 0,
      merkleProof: fourSiblings(),
      merkleRoot: filled(32, 0xf0),
    });
    const expectedDisc = new Uint8Array(
      createHash("sha256").update("global:tee_forced_settle_batched").digest(),
    ).slice(0, 8);
    expect(new Uint8Array(ix.data).slice(0, 8)).toEqual(expectedDisc);
  });

  it("[settle_batched_data_size] data length matches disc + payload + match_index + 4×32 siblings", () => {
    const tee = Keypair.generate();
    const payload = exactFillFixture();
    const ix = buildSettleBatchedIx({
      programId: PROGRAM_ID,
      treeId: 0,
      teeAuthority: tee.publicKey,
      payload,
      matchIndex: 0,
      merkleProof: fourSiblings(),
      merkleRoot: filled(32, 0xf0),
    });
    // 488-byte v9 Borsh payload — v8's 552 minus two unused nullifiers.
    const payloadBytes = serializePayload(payload);
    expect(payloadBytes.length).toBe(488);
    // 8 disc + tree_id + 488 payload + match_index + 4 × 32 siblings.
    expect(ix.data.length).toBe(8 + 1 + 488 + 1 + 128);
    expect(ix.data.length).toBe(626);
  });

  it("[settle_batched_siblings_encoding] 4 siblings encoded contiguously without a length prefix", () => {
    const tee = Keypair.generate();
    const siblings = fourSiblings();
    const ix = buildSettleBatchedIx({
      programId: PROGRAM_ID,
      treeId: 0,
      teeAuthority: tee.publicKey,
      payload: exactFillFixture(),
      matchIndex: 0,
      merkleProof: siblings,
      merkleRoot: filled(32, 0xf0),
    });
    const buf = new Uint8Array(ix.data);
    // Siblings start right after disc + payload + 1-byte match_index.
    const siblingsOffset = 8 + 1 + 488 + 1;
    for (let i = 0; i < 4; i++) {
      const slice = buf.slice(
        siblingsOffset + i * 32,
        siblingsOffset + (i + 1) * 32,
      );
      expect(slice).toEqual(siblings[i]);
    }
    // Anchor's `[[u8; 32]; 4]` is fixed-length, so there's no Borsh
    // length prefix. Total trailing region must be exactly 128 bytes.
    expect(buf.length - siblingsOffset).toBe(128);
  });

  it("[settle_batched_match_index_encoding] match_index byte sits between payload and siblings", () => {
    const tee = Keypair.generate();
    const args = {
      programId: PROGRAM_ID,
      treeId: 0,
      teeAuthority: tee.publicKey,
      payload: exactFillFixture(),
      merkleProof: fourSiblings(),
      merkleRoot: filled(32, 0xf0),
    };
    const ix0 = buildSettleBatchedIx({ ...args, matchIndex: 0 });
    const ix7 = buildSettleBatchedIx({ ...args, matchIndex: 7 });
    const ix15 = buildSettleBatchedIx({ ...args, matchIndex: 15 });
    const off = 8 + 1 + 488;
    expect(ix0.data[off]).toBe(0);
    expect(ix7.data[off]).toBe(7);
    expect(ix15.data[off]).toBe(15);
    // The match_index byte is the ONLY difference between the three ixs.
    const dropMatchByte = (d: Buffer): Buffer =>
      Buffer.concat([d.subarray(0, off), d.subarray(off + 1)]);
    expect(dropMatchByte(ix0.data)).toEqual(dropMatchByte(ix7.data));
    expect(dropMatchByte(ix0.data)).toEqual(dropMatchByte(ix15.data));
  });

  it('[settle_batched_marker_pda_derivation] account 10 = PDA([b"batch_validity", merkleRoot])', () => {
    const tee = Keypair.generate();
    const merkleRoot = filled(32, 0x77);
    const ix = buildSettleBatchedIx({
      programId: PROGRAM_ID,
      treeId: 0,
      teeAuthority: tee.publicKey,
      payload: exactFillFixture(),
      matchIndex: 3,
      merkleProof: fourSiblings(),
      merkleRoot,
    });
    const [expected] = batchValidityMarkerPda(PROGRAM_ID, merkleRoot);
    expect(ix.keys[10].pubkey.toBase58()).toBe(expected.toBase58());

    // Marker is keyed by the root, so a different root → different PDA.
    const ix2 = buildSettleBatchedIx({
      programId: PROGRAM_ID,
      treeId: 0,
      teeAuthority: tee.publicKey,
      payload: exactFillFixture(),
      matchIndex: 3,
      merkleProof: fourSiblings(),
      merkleRoot: filled(32, 0x88),
    });
    expect(ix2.keys[10].pubkey.toBase58()).not.toBe(
      ix.keys[10].pubkey.toBase58(),
    );
  });

  it("[settle_batched_lock_e_f_pdas] note_lock_e / note_lock_f derive from payload commitments", () => {
    const tee = Keypair.generate();

    // Exact-fill: noteE / noteF both zero → both locks derive from
    // ZERO_COMMITMENT and therefore collide on the same PDA.
    const exact = exactFillFixture();
    expect(exact.noteEcommitment).toEqual(ZERO_COMMITMENT);
    expect(exact.noteFcommitment).toEqual(ZERO_COMMITMENT);
    const ixExact = buildSettleBatchedIx({
      programId: PROGRAM_ID,
      treeId: 0,
      teeAuthority: tee.publicKey,
      payload: exact,
      matchIndex: 0,
      merkleProof: fourSiblings(),
      merkleRoot: filled(32, 0xf0),
    });
    const [zeroLock] = noteLockPda(PROGRAM_ID, ZERO_COMMITMENT);
    expect(ixExact.keys[7].pubkey.toBase58()).toBe(zeroLock.toBase58());
    expect(ixExact.keys[8].pubkey.toBase58()).toBe(zeroLock.toBase58());
    expect(ixExact.keys[7].isWritable).toBe(false);
    expect(ixExact.keys[8].isWritable).toBe(false);

    // Change-note variant: noteE non-zero → lock_e diverges from lock_f.
    const withChange: MatchResultPayload = {
      ...exact,
      noteEcommitment: filled(32, 0xe2),
    };
    const ixChange = buildSettleBatchedIx({
      programId: PROGRAM_ID,
      treeId: 0,
      teeAuthority: tee.publicKey,
      payload: withChange,
      matchIndex: 0,
      merkleProof: fourSiblings(),
      merkleRoot: filled(32, 0xf0),
    });
    const [lockE] = noteLockPda(PROGRAM_ID, withChange.noteEcommitment);
    expect(ixChange.keys[7].pubkey.toBase58()).toBe(lockE.toBase58());
    expect(ixChange.keys[7].pubkey.toBase58()).not.toBe(
      ixChange.keys[8].pubkey.toBase58(),
    );
    // A change note is not necessarily continued as an order. Without a
    // relock id its destination PDA remains read-only.
    expect(ixChange.keys[7].isWritable).toBe(false);
  });

  it("[settle_batched_match_index_validation] rejects matchIndex < 0 or > 15", () => {
    const tee = Keypair.generate();
    const base = {
      programId: PROGRAM_ID,
      treeId: 0,
      teeAuthority: tee.publicKey,
      payload: exactFillFixture(),
      merkleProof: fourSiblings(),
      merkleRoot: filled(32, 0xf0),
    };
    expect(() => buildSettleBatchedIx({ ...base, matchIndex: -1 })).toThrow(
      /matchIndex/,
    );
    expect(() => buildSettleBatchedIx({ ...base, matchIndex: 16 })).toThrow(
      /matchIndex/,
    );
    // Boundary OKs.
    expect(() =>
      buildSettleBatchedIx({ ...base, matchIndex: 0 }),
    ).not.toThrow();
    expect(() =>
      buildSettleBatchedIx({ ...base, matchIndex: 15 }),
    ).not.toThrow();
  });

  it("[settle_batched_tree_id_validation] rejects negative, non-integer, or out-of-byte treeId", () => {
    const tee = Keypair.generate();
    const base = {
      programId: PROGRAM_ID,
      teeAuthority: tee.publicKey,
      payload: exactFillFixture(),
      matchIndex: 0,
      merkleProof: fourSiblings(),
      merkleRoot: filled(32, 0xf0),
    };
    expect(() => buildSettleBatchedIx({ ...base, treeId: -1 })).toThrow(
      /treeId/,
    );
    expect(() => buildSettleBatchedIx({ ...base, treeId: 1.5 })).toThrow(
      /treeId/,
    );
    expect(() => buildSettleBatchedIx({ ...base, treeId: 256 })).toThrow(
      /treeId/,
    );
    // Boundary OKs.
    expect(() => buildSettleBatchedIx({ ...base, treeId: 0 })).not.toThrow();
    expect(() => buildSettleBatchedIx({ ...base, treeId: 255 })).not.toThrow();
  });

  it("[settle_batched_merkle_proof_validation] rejects wrong sibling count or wrong sibling length", () => {
    const tee = Keypair.generate();
    const base = {
      programId: PROGRAM_ID,
      treeId: 0,
      teeAuthority: tee.publicKey,
      payload: exactFillFixture(),
      matchIndex: 0,
      merkleRoot: filled(32, 0xf0),
    };
    // 3 siblings instead of 4. Cast away the tuple type to feed a bad
    // value through the runtime check the helper enforces for matchers
    // that build the ix dynamically.
    expect(() =>
      buildSettleBatchedIx({
        ...base,
        merkleProof: [
          filled(32, 1),
          filled(32, 2),
          filled(32, 3),
        ] as unknown as [Uint8Array, Uint8Array, Uint8Array, Uint8Array],
      }),
    ).toThrow(/merkleProof/);

    // 4 siblings, one of them not 32 bytes.
    expect(() =>
      buildSettleBatchedIx({
        ...base,
        merkleProof: [
          filled(32, 1),
          filled(31, 2),
          filled(32, 3),
          filled(32, 4),
        ],
      }),
    ).toThrow(/merkleProof\[1\].*32 bytes/);
  });

  it("[settle_batched_merkle_root_validation] rejects merkleRoot of wrong length", () => {
    const tee = Keypair.generate();
    const base = {
      programId: PROGRAM_ID,
      treeId: 0,
      teeAuthority: tee.publicKey,
      payload: exactFillFixture(),
      matchIndex: 0,
      merkleProof: fourSiblings(),
    };
    expect(() =>
      buildSettleBatchedIx({ ...base, merkleRoot: filled(31, 0xf0) }),
    ).toThrow(/merkleRoot.*32 bytes/);
    expect(() =>
      buildSettleBatchedIx({ ...base, merkleRoot: filled(33, 0xf0) }),
    ).toThrow(/merkleRoot.*32 bytes/);
  });

  it("[close_marker_accounts_layout] account ordering: authority, payer, marker", () => {
    const tee = Keypair.generate();
    const merkleRoot = filled(32, 0x55);
    const ix = buildCloseBatchValidityMarkerIx({
      programId: PROGRAM_ID,
      authority: tee.publicKey,
      payer: tee.publicKey,
      merkleRoot,
    });
    expect(ix.programId.toBase58()).toBe(PROGRAM_ID.toBase58());
    expect(ix.keys.length).toBe(3);

    // 0: authority — signer, non-writable (no rent flows here).
    expect(ix.keys[0].pubkey.toBase58()).toBe(tee.publicKey.toBase58());
    expect(ix.keys[0].isSigner).toBe(true);
    expect(ix.keys[0].isWritable).toBe(false);

    // 1: payer — refund recipient (mut). Marker's `has_one = payer`
    // enforces `payer == marker.payer`.
    expect(ix.keys[1].pubkey.toBase58()).toBe(tee.publicKey.toBase58());
    expect(ix.keys[1].isSigner).toBe(false);
    expect(ix.keys[1].isWritable).toBe(true);

    // 2: marker PDA, derived from [b"batch_validity", merkleRoot].
    const [expectedMarker] = batchValidityMarkerPda(PROGRAM_ID, merkleRoot);
    expect(ix.keys[2].pubkey.toBase58()).toBe(expectedMarker.toBase58());
    expect(ix.keys[2].isWritable).toBe(true);
  });

  it("[close_marker_discriminator_and_data_size] disc + 32-byte merkle_root arg", () => {
    const tee = Keypair.generate();
    const merkleRoot = filled(32, 0xab);
    const ix = buildCloseBatchValidityMarkerIx({
      programId: PROGRAM_ID,
      authority: tee.publicKey,
      payer: tee.publicKey,
      merkleRoot,
    });
    const expectedDisc = new Uint8Array(
      createHash("sha256")
        .update("global:close_batch_validity_marker")
        .digest(),
    ).slice(0, 8);
    expect(new Uint8Array(ix.data).slice(0, 8)).toEqual(expectedDisc);
    // disc (8) + merkle_root (32) = 40 bytes total.
    expect(ix.data.length).toBe(40);
    expect(new Uint8Array(ix.data).slice(8, 40)).toEqual(merkleRoot);
  });

  it("[close_marker_root_validation] rejects merkleRoot of wrong length", () => {
    const tee = Keypair.generate();
    const base = {
      programId: PROGRAM_ID,
      authority: tee.publicKey,
      payer: tee.publicKey,
    };
    expect(() =>
      buildCloseBatchValidityMarkerIx({
        ...base,
        merkleRoot: filled(31, 0xab),
      }),
    ).toThrow(/merkleRoot.*32 bytes/);
    expect(() =>
      buildCloseBatchValidityMarkerIx({
        ...base,
        merkleRoot: filled(33, 0xab),
      }),
    ).toThrow(/merkleRoot.*32 bytes/);
  });

  it("[close_marker_authority_distinct_from_payer] expiry-GC path: third-party authority sweeps to payer", () => {
    // When the matcher's marker has expired without being closed, any
    // signer may sweep the rent — but the refund still flows to
    // `marker.payer` (enforced via Anchor `has_one`). The builder
    // simply lays out the accounts; the on-chain handler checks
    // `clock.slot >= marker.expiry_slot` for every authority.
    const payer = Keypair.generate();
    const sweeper = Keypair.generate();
    const merkleRoot = filled(32, 0x99);
    const ix = buildCloseBatchValidityMarkerIx({
      programId: PROGRAM_ID,
      authority: sweeper.publicKey,
      payer: payer.publicKey,
      merkleRoot,
    });
    expect(ix.keys[0].pubkey.toBase58()).toBe(sweeper.publicKey.toBase58());
    expect(ix.keys[0].isSigner).toBe(true);
    expect(ix.keys[1].pubkey.toBase58()).toBe(payer.publicKey.toBase58());
    expect(ix.keys[1].isWritable).toBe(true);
  });

  it("[settle_batched_payload_relock_passthrough] relock fields survive the Borsh serialisation", () => {
    // The batched ix carries the exact same payload struct as the
    // per-match path, so re-lock fields (used by tee_forced_settle to
    // re-lock buyer/seller change notes against the continuing order)
    // round-trip byte-for-byte. Build with non-default relock metadata
    // and inspect the payload region of ix.data.
    const tee = Keypair.generate();
    const base = exactFillFixture();
    const relock: MatchResultPayload = {
      ...base,
      noteEcommitment: filled(32, 0xe2),
      buyerRelockOrderId: filled(16, 0xab),
      buyerRelockExpiry: 1_234_567n,
    };
    expect(relock.buyerRelockOrderId).not.toEqual(RELOCK_ORDER_ID_NONE);

    const ix = buildSettleBatchedIx({
      programId: PROGRAM_ID,
      treeId: 0,
      teeAuthority: tee.publicKey,
      payload: relock,
      matchIndex: 0,
      merkleProof: fourSiblings(),
      merkleRoot: filled(32, 0xf0),
    });
    expect(ix.keys[7].isWritable).toBe(true);
    expect(ix.keys[8].isWritable).toBe(false);
    const payloadBytes = new Uint8Array(ix.data).slice(9, 9 + 488);
    expect(payloadBytes).toEqual(serializePayload(relock));
  });
});
