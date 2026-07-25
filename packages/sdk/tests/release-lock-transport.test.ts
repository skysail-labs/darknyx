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

const PROGRAM_ID = new PublicKey(
  "C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx",
);

const RENT_RECEIVER = new PublicKey(
  "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
);

function commitment(fill: number): Uint8Array {
  const v = new Uint8Array(32).fill(fill);
  v[0] = 0; // Fr-safe, matching how real commitments look
  return v;
}

describe("buildReleaseLockInstruction", () => {
  it("emits disc(8) || note_commitment(32) with no other args", () => {
    const noteCommitment = commitment(0x42);
    const ix = buildReleaseLockInstruction({
      programId: PROGRAM_ID,
      rentReceiver: RENT_RECEIVER,
      noteCommitment,
    });

    expect(ix.programId.equals(PROGRAM_ID)).toBe(true);
    expect(ix.data.length).toBe(8 + 32);
    expect(new Uint8Array(ix.data.subarray(0, 8))).toEqual(
      anchorDiscriminator("release_lock"),
    );
    expect(new Uint8Array(ix.data.subarray(8, 40))).toEqual(noteCommitment);
  });

  it("passes exactly [rent_receiver(signer,mut), note_lock(mut)]", () => {
    const noteCommitment = commitment(0x07);
    const ix = buildReleaseLockInstruction({
      programId: PROGRAM_ID,
      rentReceiver: RENT_RECEIVER,
      noteCommitment,
    });
    const [expectedLock] = noteLockPda(PROGRAM_ID, noteCommitment);

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

  it("derives a distinct lock PDA per note commitment", () => {
    const a = buildReleaseLockInstruction({
      programId: PROGRAM_ID,
      rentReceiver: RENT_RECEIVER,
      noteCommitment: commitment(1),
    });
    const b = buildReleaseLockInstruction({
      programId: PROGRAM_ID,
      rentReceiver: RENT_RECEIVER,
      noteCommitment: commitment(2),
    });
    expect(a.keys[1].pubkey.equals(b.keys[1].pubkey)).toBe(false);
  });
});

describe("parseNoteLock", () => {
  /** Build a NoteLock account buffer in the on-chain layout. */
  function encodeNoteLock(expirySlot: bigint): Uint8Array {
    const LEN = 8 + 32 + 32 + 16 + 8 + 32 + 1 + 7;
    const buf = new Uint8Array(LEN);
    buf.set(commitment(0xaa), 8); // note_commitment
    buf.set(new Uint8Array(32).fill(0xbb), 40); // token_mint
    buf.set(new Uint8Array(16).fill(0xcc), 72); // order_id
    new DataView(buf.buffer).setBigUint64(88, expirySlot, true);
    buf.set(new Uint8Array(32).fill(0xdd), 96); // locked_by
    return buf;
  }

  it("reads expiry_slot from the correct offset", () => {
    const parsed = parseNoteLock(encodeNoteLock(123_456_789n));
    expect(parsed).not.toBeNull();
    expect(parsed!.expirySlot).toBe(123_456_789n);
    expect(parsed!.noteCommitment).toEqual(commitment(0xaa));
    expect(parsed!.orderId).toEqual(new Uint8Array(16).fill(0xcc));
  });

  it("fails closed on a short buffer instead of misreading an offset", () => {
    // Reading a truncated / unexpected account must not yield a bogus expiry
    // that a caller could act on.
    expect(parseNoteLock(new Uint8Array(87))).toBeNull();
    expect(parseNoteLock(new Uint8Array(0))).toBeNull();
  });

  it("round-trips a zero expiry without treating it as absent", () => {
    const parsed = parseNoteLock(encodeNoteLock(0n));
    expect(parsed).not.toBeNull();
    expect(parsed!.expirySlot).toBe(0n);
  });
});
