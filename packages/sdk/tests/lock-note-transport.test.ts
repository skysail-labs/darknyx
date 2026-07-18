import { Keypair, PublicKey, SystemProgram } from "@solana/web3.js";
import { describe, expect, it } from "vitest";

import {
  buildLockNoteInstruction,
  consumedNotePda,
  merkleTreePda,
  noteLockPda,
  vaultConfigPda,
} from "../src/idl/vault-client.js";

const PROGRAM_ID = new PublicKey(
  "C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx",
);
const filled = (length: number, byte: number): Uint8Array =>
  new Uint8Array(length).fill(byte);

describe("lock_note v3 amount-private transport", () => {
  it("omits amount and places token mint directly after expiry", () => {
    const mint = new PublicKey(filled(32, 0x44));
    const ix = buildLockNoteInstruction({
      programId: PROGRAM_ID,
      treeId: 3,
      teeAuthority: Keypair.generate().publicKey,
      noteCommitment: filled(32, 0x11),
      orderId: filled(16, 0x22),
      expirySlot: 0x0102_0304_0506_0708n,
      tokenMint: mint,
      merkleRoot: filled(32, 0x55),
      proof: {
        piA: filled(64, 0x66),
        piB: filled(128, 0x77),
        piC: filled(64, 0x88),
      },
    });

    // 8 discriminator + 377-byte Borsh body (8 bytes smaller than v2).
    expect(ix.data).toHaveLength(385);
    const mintOffset = 8 + 1 + 32 + 16 + 8;
    expect(ix.data.subarray(mintOffset, mintOffset + 32)).toEqual(
      Buffer.from(mint.toBytes()),
    );
    expect(ix.data.subarray(mintOffset + 32, mintOffset + 64)).toEqual(
      Buffer.from(filled(32, 0x55)),
    );
  });

  it("pins the account order incl. the U-02 consumed_note guard", () => {
    const teeAuthority = Keypair.generate().publicKey;
    const noteCommitment = filled(32, 0x11);
    const ix = buildLockNoteInstruction({
      programId: PROGRAM_ID,
      treeId: 3,
      teeAuthority,
      noteCommitment,
      orderId: filled(16, 0x22),
      expirySlot: 1n,
      tokenMint: new PublicKey(filled(32, 0x44)),
      merkleRoot: filled(32, 0x55),
      proof: { piA: filled(64, 0x66), piB: filled(128, 0x77), piC: filled(64, 0x88) },
    });

    // Mirror of programs/vault/src/instructions/lock_note.rs LockNote<'info>.
    expect(ix.keys).toHaveLength(6);
    expect(ix.keys[0].pubkey.equals(teeAuthority)).toBe(true);
    expect(ix.keys[1].pubkey.equals(vaultConfigPda(PROGRAM_ID)[0])).toBe(true);
    expect(ix.keys[2].pubkey.equals(merkleTreePda(PROGRAM_ID, 3)[0])).toBe(true);
    expect(ix.keys[3].pubkey.equals(noteLockPda(PROGRAM_ID, noteCommitment)[0])).toBe(
      true,
    );
    expect(ix.keys[3].isWritable).toBe(true);
    // [4] consumed_note — read-only must-be-absent guard.
    expect(
      ix.keys[4].pubkey.equals(consumedNotePda(PROGRAM_ID, noteCommitment)[0]),
    ).toBe(true);
    expect(ix.keys[4].isWritable).toBe(false);
    expect(ix.keys[5].pubkey.equals(SystemProgram.programId)).toBe(true);
  });
});
