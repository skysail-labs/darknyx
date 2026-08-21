import { describe, expect, it } from "vitest";
import { Keypair, PublicKey, SystemProgram } from "@solana/web3.js";

import {
  buildMergeInstruction,
  consumedNotePda,
  merkleTreePda,
  noteLockPda,
  vaultConfigPda,
} from "../src/idl/vault-client.js";
import { dummyAddress } from "./helpers/e2e-helpers.js";

const filled = (length: number, byte: number): Uint8Array =>
  new Uint8Array(length).fill(byte);

const PROGRAM_ID = new PublicKey(
  "C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx",
);

describe("merge transport lifecycle accounts", () => {
  it("passes consumed PDAs then absent NoteLock PDAs for active inputs only", async () => {
    const payer = dummyAddress();
    const mint = dummyAddress();
    // Handles, not leaves: the merge ix carries note-use tags.
    const t0 = filled(32, 0x11);
    const t1 = filled(32, 0x12);
    const zero = new Uint8Array(32);
    const ix = await buildMergeInstruction({
      programId: PROGRAM_ID,
      treeId: 3,
      payer,
      inputUseTags: [t0, t1, zero, zero],
      outputCommitment: filled(32, 0x21),
      tokenMint: mint,
      merkleRoot: filled(32, 0x31),
      k: 4,
      proof: {
        piA: filled(64, 0x41),
        piB: filled(128, 0x42),
        piC: filled(64, 0x43),
      },
    });

    expect(ix.keys).toHaveLength(8);
    expect(ix.keys[0]).toMatchObject({
      pubkey: payer,
      isSigner: true,
      isWritable: true,
    });
    expect(
      ix.keys[1].pubkey.equals((await vaultConfigPda(PROGRAM_ID))[0]),
    ).toBe(true);
    expect(ix.keys[1].isWritable).toBe(false);
    expect(
      ix.keys[2].pubkey.equals((await merkleTreePda(PROGRAM_ID, 3))[0]),
    ).toBe(true);
    expect(ix.keys[2].isWritable).toBe(true);
    expect(ix.keys[3].pubkey.equals(SystemProgram.programId)).toBe(true);

    expect(
      ix.keys[4].pubkey.equals((await consumedNotePda(PROGRAM_ID, t0))[0]),
    ).toBe(true);
    expect(
      ix.keys[5].pubkey.equals((await consumedNotePda(PROGRAM_ID, t1))[0]),
    ).toBe(true);
    expect(ix.keys[4].isWritable).toBe(true);
    expect(ix.keys[5].isWritable).toBe(true);

    expect(
      ix.keys[6].pubkey.equals((await noteLockPda(PROGRAM_ID, t0))[0]),
    ).toBe(true);
    expect(
      ix.keys[7].pubkey.equals((await noteLockPda(PROGRAM_ID, t1))[0]),
    ).toBe(true);
    expect(ix.keys[6].isWritable).toBe(false);
    expect(ix.keys[7].isWritable).toBe(false);
  });

  it("rejects an all-dummy transport before submission", async () => {
    await expect(
      buildMergeInstruction({
        programId: PROGRAM_ID,
        treeId: 0,
        payer: dummyAddress(),
        inputUseTags: [new Uint8Array(32), new Uint8Array(32)],
        outputCommitment: filled(32, 0x21),
        tokenMint: dummyAddress(),
        merkleRoot: filled(32, 0x31),
        k: 2,
        proof: {
          piA: filled(64, 0x41),
          piB: filled(128, 0x42),
          piC: filled(64, 0x43),
        },
      }),
    ).rejects.toThrow(/at least one active/);
  });
});
