/**
 * Audit 2026-07-25 S-03 — `release_lock` reachability.
 *
 * The instruction has existed on-chain since the lock lifecycle landed, but
 * had no builder in any shipped component: no SDK helper, no TEE caller, no
 * script, no test. The 2026-07-20 D-01 analysis of the settle-failure freeze
 * concluded the recovery path was "`release_lock` + re-place" — a path that
 * was not implemented anywhere. Because `withdraw` and `merge` both reject on
 * the mere existence of a lock account, an unreleased lock made a note
 * unspendable, unmergeable, and unlockable through every shipped interface.
 *
 * These tests pin the wire format and the account order, and pin that a
 * client can now tell an expired lock from a live one.
 */

import { describe, it, expect } from "vitest";
import { PublicKey } from "@solana/web3.js";

import {
  anchorDiscriminator,
  buildReleaseLockInstruction,
  noteLockPda,
  parseNoteLock,
} from "../src/idl/vault-client.js";
import { noteUseTagFromBytes } from "../src/utxo/note-identity.js";

const PROGRAM_ID = new PublicKey(
  "C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx",
);

const RENT_RECEIVER = new PublicKey(
  "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
);

function useTag(fill: number) {
  const v = new Uint8Array(32).fill(fill);
  v[0] = 0; // Fr-safe, matching how real commitments look
  return noteUseTagFromBytes(v);
}

describe("buildReleaseLockInstruction", () => {
  it("emits disc(8) || note_commitment(32) with no other args", async () => {
    const noteUseTag = useTag(0x42);
    const ix = await buildReleaseLockInstruction({
      programId: PROGRAM_ID,
      rentReceiver: RENT_RECEIVER,
      noteUseTag,
    });

    expect(ix.programId.equals(PROGRAM_ID)).toBe(true);
    expect(ix.data.length).toBe(8 + 32);
    expect(new Uint8Array(ix.data.subarray(0, 8))).toEqual(
      anchorDiscriminator("release_lock"),
    );
    expect(new Uint8Array(ix.data.subarray(8, 40))).toEqual(noteUseTag);
  });

  it("passes exactly [rent_receiver(signer,mut), note_lock(mut)]", async () => {
    const noteUseTag = useTag(0x07);
    const ix = await buildReleaseLockInstruction({
      programId: PROGRAM_ID,
      rentReceiver: RENT_RECEIVER,
      noteUseTag,
    });
    const [expectedLock] = await noteLockPda(PROGRAM_ID, noteUseTag);

    expect(ix.keys.length).toBe(2);
    // The rent receiver signs and is credited the reclaimed rent — the
    // on-chain `close = rent_receiver` has no has_one binding to the TEE key
    // that created the lock, so release is permissionless after expiry.
    expect(ix.keys[0].pubkey.equals(RENT_RECEIVER)).toBe(true);
    expect(ix.keys[0].isSigner).toBe(true);
    expect(ix.keys[0].isWritable).toBe(true);
    // The lock account is closed, so it must be writable.
    expect(ix.keys[1].pubkey.equals(expectedLock)).toBe(true);
    expect(ix.keys[1].isSigner).toBe(false);
    expect(ix.keys[1].isWritable).toBe(true);
  });

  it("derives a distinct lock PDA per note commitment", async () => {
    const a = await buildReleaseLockInstruction({
      programId: PROGRAM_ID,
      rentReceiver: RENT_RECEIVER,
      noteUseTag: useTag(1),
    });
    const b = await buildReleaseLockInstruction({
      programId: PROGRAM_ID,
      rentReceiver: RENT_RECEIVER,
      noteUseTag: useTag(2),
    });
    expect(a.keys[1].pubkey.equals(b.keys[1].pubkey)).toBe(false);
  });
});

describe("parseNoteLock", () => {
  /** Build a NoteLock account buffer in the on-chain layout. */
  function encodeNoteLock(expirySlot: bigint): Uint8Array {
    const LEN = 8 + 32 + 16 + 8 + 1 + 7;
    const buf = new Uint8Array(LEN);
    buf.set(new Uint8Array(32).fill(0xbb), 8); // token_mint
    buf.set(new Uint8Array(16).fill(0xcc), 40); // order_id
    new DataView(buf.buffer).setBigUint64(56, expirySlot, true);
    return buf;
  }

  it("reads expiry_slot from the correct offset", () => {
    const parsed = parseNoteLock(encodeNoteLock(123_456_789n));
    expect(parsed).not.toBeNull();
    expect(parsed!.expirySlot).toBe(123_456_789n);
    expect(parsed!.orderId).toEqual(new Uint8Array(16).fill(0xcc));
  });

  it("fails closed on a short buffer instead of misreading an offset", () => {
    // Reading a truncated / unexpected account must not yield a bogus expiry
    // that a caller could act on.
    expect(parseNoteLock(new Uint8Array(71))).toBeNull();
    expect(parseNoteLock(new Uint8Array(0))).toBeNull();
    expect(parseNoteLock(new Uint8Array(136))).toBeNull();
  });

  it("round-trips a zero expiry without treating it as absent", () => {
    const parsed = parseNoteLock(encodeNoteLock(0n));
    expect(parsed).not.toBeNull();
    expect(parsed!.expirySlot).toBe(0n);
  });
});
