import { Keypair, PublicKey, SystemProgram } from "@solana/web3.js";
import { describe, expect, it } from "vitest";

import {
  batchValidityMarkerPda,
  buildVerifyMatchBatchInstruction,
  marketConfigPda,
  vaultConfigPda,
} from "../src/idl/vault-client.js";
import { dummyAddress } from "./helpers/e2e-helpers.js";

const PROGRAM_ID = new PublicKey(
  "C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx",
);
const filled = (length: number, byte: number): Uint8Array =>
  new Uint8Array(length).fill(byte);

describe("verify_match_batch transport", () => {
  it("authenticates the fixed fee-recovery record in Tx B", async () => {
    const payer = dummyAddress();
    const baseMint = new PublicKey(filled(32, 0x44));
    const quoteMint = new PublicKey(filled(32, 0x55));
    const root = filled(32, 0x66);
    const ix = await buildVerifyMatchBatchInstruction({
      programId: PROGRAM_ID,
      payer,
      baseMint,
      quoteMint,
      merkleRoot: root,
      feeKeyEpoch: 7n,
      feeRecoveryCiphertext: filled(272, 0x77),
      proof: {
        piA: filled(64, 0x11),
        piB: filled(128, 0x22),
        piC: filled(64, 0x33),
      },
    });

    // disc + root + proof + epoch + fixed XChaCha ciphertext.
    expect(ix.data).toHaveLength(576);
    expect(new DataView(ix.data.buffer, ix.data.byteOffset).getBigUint64(296, true)).toBe(7n);
    expect(ix.data.subarray(304)).toEqual(filled(272, 0x77));
    expect(ix.keys).toEqual([
      { pubkey: payer, isSigner: true, isWritable: true },
      {
        pubkey: (await vaultConfigPda(PROGRAM_ID))[0],
        isSigner: false,
        isWritable: false,
      },
      {
        pubkey: (await marketConfigPda(PROGRAM_ID, baseMint, quoteMint))[0],
        isSigner: false,
        isWritable: false,
      },
      {
        pubkey: (await batchValidityMarkerPda(PROGRAM_ID, root))[0],
        isSigner: false,
        isWritable: true,
      },
      {
        pubkey: SystemProgram.programId,
        isSigner: false,
        isWritable: false,
      },
    ]);
  });
});
