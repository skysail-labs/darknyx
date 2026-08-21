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
 *   3. `ix.data` length = 8 (disc) + 1 (tree_id) + 552 (Borsh payload)
 *                       + 1 (matchIndex u8) + 128 (4 × 32-byte siblings)
 *                       = 626 bytes.
 *   4. The 4 Merkle siblings are encoded contiguously with NO length
 *      prefix (Anchor's `[[u8; 32]; 4]` wire shape).
 *   5. The match-index byte lives at offset `8 + 1 + 552` and reflects the
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
import { dummyAddress } from "./helpers/e2e-helpers.js";

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
    noteAuseTag: filled(32, 0xa1),
    noteBuseTag: filled(32, 0xb1),
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
  it("[hash_cross_env_parity] payload v11 canonical hash matches Rust and on-chain", () => {
    expect(
      Buffer.from(canonicalPayloadHash(exactFillFixture())).toString("hex"),
    ).toBe("039828e122696147495ba9df91daae71cc5289657ad7ec66c74659d0d00d8f65");
  });

  it("[settle_batched_accounts_layout] account ordering matches TeeForcedSettleBatched", async () => {
    const tee = await Keypair.generate();
    const payload = exactFillFixture();
    const merkleRoot = filled(32, 0xf0);
    const ix = await buildSettleBatchedIx({
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

  it("[settle_batched_distinct_shards_no_shared_writes] distinct-shard Tx Ds share no writable account", async () => {
    const payload0 = exactFillFixture();
    const payload1: MatchResultPayload = {
      ...exactFillFixture(),
      noteAuseTag: filled(32, 0xa2),
      noteBuseTag: filled(32, 0xb2),
      noteCcommitment: filled(32, 0xc2),
      noteDcommitment: filled(32, 0xd2),
    };
    const args = {
      programId: PROGRAM_ID,
      merkleProof: fourSiblings(),
      merkleRoot: filled(32, 0xf0),
    };
    const ix0 = await buildSettleBatchedIx({
      ...args,
      treeId: 0,
      teeAuthority: dummyAddress(),
      payload: payload0,
      matchIndex: 0,
    });
    const ix1 = await buildSettleBatchedIx({
      ...args,
      treeId: 1,
      teeAuthority: dummyAddress(),
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

  it("[settle_batched_anchor_discriminator_present] data starts with sha256('global:tee_forced_settle_batched')[..8]", async () => {
    const tee = await Keypair.generate();
    const ix = await buildSettleBatchedIx({
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

  it("[settle_batched_data_size] data length matches disc + payload + match_index + 4×32 siblings", async () => {
    const tee = await Keypair.generate();
    const payload = exactFillFixture();
    const ix = await buildSettleBatchedIx({
      programId: PROGRAM_ID,
      treeId: 0,
      teeAuthority: tee.publicKey,
      payload,
      matchIndex: 0,
      merkleProof: fourSiblings(),
      merkleRoot: filled(32, 0xf0),
    });
    // 552-byte v11 Borsh payload — v9's 552 plus the two relock tags.
    const payloadBytes = serializePayload(payload);
    expect(payloadBytes.length).toBe(552);
    // 8 disc + tree_id + 552 payload + match_index + 4 × 32 siblings.
    expect(ix.data.length).toBe(8 + 1 + 552 + 1 + 128);
    expect(ix.data.length).toBe(690);
  });

  it("[settle_batched_siblings_encoding] 4 siblings encoded contiguously without a length prefix", async () => {
    const tee = await Keypair.generate();
    const siblings = fourSiblings();
    const ix = await buildSettleBatchedIx({
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
    const siblingsOffset = 8 + 1 + 552 + 1;
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

  it("[settle_batched_match_index_encoding] match_index byte sits between payload and siblings", async () => {
    const tee = await Keypair.generate();
    const args = {
      programId: PROGRAM_ID,
      treeId: 0,
      teeAuthority: tee.publicKey,
      payload: exactFillFixture(),
      merkleProof: fourSiblings(),
      merkleRoot: filled(32, 0xf0),
    };
    const ix0 = await buildSettleBatchedIx({ ...args, matchIndex: 0 });
    const ix7 = await buildSettleBatchedIx({ ...args, matchIndex: 7 });
    const ix15 = await buildSettleBatchedIx({ ...args, matchIndex: 15 });
    const off = 8 + 1 + 552;
    expect(ix0.data[off]).toBe(0);
    expect(ix7.data[off]).toBe(7);
    expect(ix15.data[off]).toBe(15);
    // The match_index byte is the ONLY difference between the three ixs.
    // v3 ix.data is a Uint8Array, so splice through Uint8Array rather than
    // Buffer.concat -- `toEqual` distinguishes the two constructors.
    const dropMatchByte = (d: Uint8Array): Uint8Array => {
      const out = new Uint8Array(d.length - 1);
      out.set(d.subarray(0, off), 0);
      out.set(d.subarray(off + 1), off);
      return out;
    };
    expect(dropMatchByte(ix0.data)).toEqual(dropMatchByte(ix7.data));
    expect(dropMatchByte(ix0.data)).toEqual(dropMatchByte(ix15.data));
  });

  it('[settle_batched_marker_pda_derivation] account 10 = PDA([b"batch_validity", merkleRoot])', async () => {
    const tee = await Keypair.generate();
    const merkleRoot = filled(32, 0x77);
    const ix = await buildSettleBatchedIx({
      programId: PROGRAM_ID,
      treeId: 0,
      teeAuthority: tee.publicKey,
      payload: exactFillFixture(),
      matchIndex: 3,
      merkleProof: fourSiblings(),
      merkleRoot,
    });
    const [expected] = await batchValidityMarkerPda(PROGRAM_ID, merkleRoot);
    expect(ix.keys[10].pubkey.toBase58()).toBe(expected.toBase58());

    // Marker is keyed by the root, so a different root → different PDA.
    const ix2 = await buildSettleBatchedIx({
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

  it("[settle_batched_lock_e_f_pdas] note_lock_e / note_lock_f derive from the relock TAGS, not the change commitments", async () => {
    const tee = await Keypair.generate();

    // Exact-fill: noteE / noteF tags both zero → both locks derive from
    // ZERO_COMMITMENT and therefore collide on the same PDA. That dedup is
    // worth 32 bytes of a now-59-byte Tx D headroom, so it is asserted, not
    // assumed (CLAUDE.md §6).
    const exact = exactFillFixture();
    expect(exact.noteEuseTag).toEqual(ZERO_COMMITMENT);
    expect(exact.noteFuseTag).toEqual(ZERO_COMMITMENT);
    const ixExact = await buildSettleBatchedIx({
      programId: PROGRAM_ID,
      treeId: 0,
      teeAuthority: tee.publicKey,
      payload: exact,
      matchIndex: 0,
      merkleProof: fourSiblings(),
      merkleRoot: filled(32, 0xf0),
    });
    const [zeroLock] = await noteLockPda(PROGRAM_ID, ZERO_COMMITMENT);
    expect(ixExact.keys[7].pubkey.toBase58()).toBe(zeroLock.toBase58());
    expect(ixExact.keys[8].pubkey.toBase58()).toBe(zeroLock.toBase58());
    expect(ixExact.keys[7].isWritable).toBe(false);
    expect(ixExact.keys[8].isWritable).toBe(false);

    // Change-note variant: the buyer's relock TAG is non-zero → lock_e
    // diverges from lock_f. Note the commitment moves too, as it does in a
    // real settle; the assertions below pin that only the TAG is load-bearing.
    const withChange: MatchResultPayload = {
      ...exact,
      noteEcommitment: filled(32, 0xe2),
      noteEuseTag: filled(32, 0xe3),
    };
    const ixChange = await buildSettleBatchedIx({
      programId: PROGRAM_ID,
      treeId: 0,
      teeAuthority: tee.publicKey,
      payload: withChange,
      matchIndex: 0,
      merkleProof: fourSiblings(),
      merkleRoot: filled(32, 0xf0),
    });
    const [lockE] = await noteLockPda(PROGRAM_ID, withChange.noteEuseTag);
    expect(ixChange.keys[7].pubkey.toBase58()).toBe(lockE.toBase58());
    expect(ixChange.keys[7].pubkey.toBase58()).not.toBe(
      ixChange.keys[8].pubkey.toBase58(),
    );

    // THE confusion this whole layer is exposed to: both fields are 32 bytes,
    // so seeding the lock from the change COMMITMENT compiles, derives a
    // plausible address, and fails only on-chain as a missing account. Two
    // assertions pin the direction:
    //   (a) the commitment's address is NOT the one the builder emitted, and
    //   (b) changing only the commitment leaves the lock address fixed.
    const [wrongLock] = await noteLockPda(
      PROGRAM_ID,
      withChange.noteEcommitment,
    );
    expect(ixChange.keys[7].pubkey.toBase58()).not.toBe(wrongLock.toBase58());

    const movedCommitment = await buildSettleBatchedIx({
      programId: PROGRAM_ID,
      treeId: 0,
      teeAuthority: tee.publicKey,
      payload: { ...withChange, noteEcommitment: filled(32, 0xe9) },
      matchIndex: 0,
      merkleProof: fourSiblings(),
      merkleRoot: filled(32, 0xf0),
    });
    expect(movedCommitment.keys[7].pubkey.toBase58()).toBe(lockE.toBase58());
    // A change note is not necessarily continued as an order. Without a
    // relock id its destination PDA remains read-only.
    expect(ixChange.keys[7].isWritable).toBe(false);
  });

  it("[settle_batched_match_index_validation] rejects matchIndex < 0 or > 15", async () => {
    const tee = await Keypair.generate();
    const base = {
      programId: PROGRAM_ID,
      treeId: 0,
      teeAuthority: tee.publicKey,
      payload: exactFillFixture(),
      merkleProof: fourSiblings(),
      merkleRoot: filled(32, 0xf0),
    };
    await expect(
      buildSettleBatchedIx({ ...base, matchIndex: -1 }),
    ).rejects.toThrow(/matchIndex/);
    await expect(
      buildSettleBatchedIx({ ...base, matchIndex: 16 }),
    ).rejects.toThrow(/matchIndex/);
    // Boundary OKs.
    await expect(
      buildSettleBatchedIx({ ...base, matchIndex: 0 }),
    ).resolves.toBeDefined();
    await expect(
      buildSettleBatchedIx({ ...base, matchIndex: 15 }),
    ).resolves.toBeDefined();
  });

  it("[settle_batched_tree_id_validation] rejects negative, non-integer, or out-of-byte treeId", async () => {
    const tee = await Keypair.generate();
    const base = {
      programId: PROGRAM_ID,
      teeAuthority: tee.publicKey,
      payload: exactFillFixture(),
      matchIndex: 0,
      merkleProof: fourSiblings(),
      merkleRoot: filled(32, 0xf0),
    };
    await expect(buildSettleBatchedIx({ ...base, treeId: -1 })).rejects.toThrow(
      /treeId/,
    );
    await expect(
      buildSettleBatchedIx({ ...base, treeId: 1.5 }),
    ).rejects.toThrow(/treeId/);
    await expect(
      buildSettleBatchedIx({ ...base, treeId: 256 }),
    ).rejects.toThrow(/treeId/);
    // Boundary OKs.
    await expect(
      buildSettleBatchedIx({ ...base, treeId: 0 }),
    ).resolves.toBeDefined();
    await expect(
      buildSettleBatchedIx({ ...base, treeId: 255 }),
    ).resolves.toBeDefined();
  });

  it("[settle_batched_merkle_proof_validation] rejects wrong sibling count or wrong sibling length", async () => {
    const tee = await Keypair.generate();
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
    await expect(
      buildSettleBatchedIx({
        ...base,
        merkleProof: [
          filled(32, 1),
          filled(32, 2),
          filled(32, 3),
        ] as unknown as [Uint8Array, Uint8Array, Uint8Array, Uint8Array],
      }),
    ).rejects.toThrow(/merkleProof/);

    // 4 siblings, one of them not 32 bytes.
    await expect(
      buildSettleBatchedIx({
        ...base,
        merkleProof: [
          filled(32, 1),
          filled(31, 2),
          filled(32, 3),
          filled(32, 4),
        ],
      }),
    ).rejects.toThrow(/merkleProof\[1\].*32 bytes/);
  });

  it("[settle_batched_merkle_root_validation] rejects merkleRoot of wrong length", async () => {
    const tee = await Keypair.generate();
    const base = {
      programId: PROGRAM_ID,
      treeId: 0,
      teeAuthority: tee.publicKey,
      payload: exactFillFixture(),
      matchIndex: 0,
      merkleProof: fourSiblings(),
    };
    await expect(
      buildSettleBatchedIx({ ...base, merkleRoot: filled(31, 0xf0) }),
    ).rejects.toThrow(/merkleRoot.*32 bytes/);
    await expect(
      buildSettleBatchedIx({ ...base, merkleRoot: filled(33, 0xf0) }),
    ).rejects.toThrow(/merkleRoot.*32 bytes/);
  });

  it("[close_marker_accounts_layout] account ordering: authority, marker", async () => {
    const tee = await Keypair.generate();
    const merkleRoot = filled(32, 0x55);
    const ix = await buildCloseBatchValidityMarkerIx({
      programId: PROGRAM_ID,
      authority: tee.publicKey,
      merkleRoot,
    });
    expect(ix.programId.toBase58()).toBe(PROGRAM_ID.toBase58());
    // v2 collapsed the separate `payer` slot into `authority`: passing one
    // address in both (which every caller did) trips the duplicate-mutable
    // check on chain. Two accounts now, not three.
    expect(ix.keys.length).toBe(2);

    // 0: authority — signer AND refund recipient, so writable. Must equal
    //    marker.payer; an on-chain constraint enforces it.
    expect(ix.keys[0].pubkey.toBase58()).toBe(tee.publicKey.toBase58());
    expect(ix.keys[0].isSigner).toBe(true);
    expect(ix.keys[0].isWritable).toBe(true);

    // 2: marker PDA, derived from [b"batch_validity", merkleRoot].
    const [expectedMarker] = await batchValidityMarkerPda(
      PROGRAM_ID,
      merkleRoot,
    );
    expect(ix.keys[1].pubkey.toBase58()).toBe(expectedMarker.toBase58());
    expect(ix.keys[1].isWritable).toBe(true);
  });

  it("[close_marker_discriminator_and_data_size] disc + 32-byte merkle_root arg", async () => {
    const tee = await Keypair.generate();
    const merkleRoot = filled(32, 0xab);
    const ix = await buildCloseBatchValidityMarkerIx({
      programId: PROGRAM_ID,
      authority: tee.publicKey,
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

  it("[close_marker_root_validation] rejects merkleRoot of wrong length", async () => {
    const tee = await Keypair.generate();
    const base = {
      programId: PROGRAM_ID,
      authority: tee.publicKey,
      payer: tee.publicKey,
    };
    await expect(
      buildCloseBatchValidityMarkerIx({
        ...base,
        merkleRoot: filled(31, 0xab),
      }),
    ).rejects.toThrow(/merkleRoot.*32 bytes/);
    await expect(
      buildCloseBatchValidityMarkerIx({
        ...base,
        merkleRoot: filled(33, 0xab),
      }),
    ).rejects.toThrow(/merkleRoot.*32 bytes/);
  });

  it("[close_marker_authority_is_the_only_slot] a third-party sweeper can no longer be expressed", async () => {
    // BEHAVIOUR CHANGE, pinned deliberately. v1 took a separate `payer` refund
    // slot bound by `has_one = payer`, so any signer could sweep an expired
    // marker while the rent still reached the recorded payer. v2 rejects that
    // shape: the sweeper always passes authority == payer, and one address in
    // two slots (one `mut`) trips the duplicate-mutable check before the
    // handler runs.
    //
    // The builder now has ONE slot, so "sweeper distinct from payer" is not
    // representable at all — the on-chain constraint pins authority to
    // marker.payer. This test exists so the property is not quietly restored.
    const sweeper = await Keypair.generate();
    const merkleRoot = filled(32, 0x99);
    const ix = await buildCloseBatchValidityMarkerIx({
      programId: PROGRAM_ID,
      authority: sweeper.publicKey,
      merkleRoot,
    });
    expect(ix.keys.length).toBe(2);
    expect(ix.keys[0].pubkey.toBase58()).toBe(sweeper.publicKey.toBase58());
    expect(ix.keys[0].isSigner).toBe(true);
    // Writable, because the marker now closes into this account.
    expect(ix.keys[0].isWritable).toBe(true);
    // Slot 1 is the marker PDA, not a payer.
    const [expected] = await batchValidityMarkerPda(PROGRAM_ID, merkleRoot);
    expect(ix.keys[1].pubkey.toBase58()).toBe(expected.toBase58());
  });

  it("[settle_batched_payload_relock_passthrough] relock fields survive the Borsh serialisation", async () => {
    // The batched ix carries the exact same payload struct as the
    // per-match path, so re-lock fields (used by tee_forced_settle to
    // re-lock buyer/seller change notes against the continuing order)
    // round-trip byte-for-byte. Build with non-default relock metadata
    // and inspect the payload region of ix.data.
    const tee = await Keypair.generate();
    const base = exactFillFixture();
    const relock: MatchResultPayload = {
      ...base,
      noteEcommitment: filled(32, 0xe2),
      noteEuseTag: filled(32, 0xe3),
      buyerRelockOrderId: filled(16, 0xab),
      buyerRelockExpiry: 1_234_567n,
    };
    expect(relock.buyerRelockOrderId).not.toEqual(RELOCK_ORDER_ID_NONE);

    const ix = await buildSettleBatchedIx({
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
    const payloadBytes = new Uint8Array(ix.data).slice(9, 9 + 552);
    expect(payloadBytes).toEqual(serializePayload(relock));
  });
});
