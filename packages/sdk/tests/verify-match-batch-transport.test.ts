import { Keypair, PublicKey, SystemProgram } from "@solana/web3.js";
import { describe, expect, it } from "vitest";

import {
  batchValidityMarkerPda,
  buildVerifyMatchBatchInstruction,
  marketConfigPda,
  vaultConfigPda,
} from "../src/idl/vault-client.js";

const PROGRAM_ID = new PublicKey(
  "C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx",
);
const filled = (length: number, byte: number): Uint8Array =>
  new Uint8Array(length).fill(byte);

describe("verify_match_batch v3 transport", () => {
  it("adds the governed market as a read-only account without changing Tx B data", () => {
    const payer = Keypair.generate().publicKey;
    const baseMint = new PublicKey(filled(32, 0x44));
    const quoteMint = new PublicKey(filled(32, 0x55));
    const root = filled(32, 0x66);
    const ix = buildVerifyMatchBatchInstruction({
      programId: PROGRAM_ID,
      payer,
      baseMint,
      quoteMint,
      merkleRoot: root,
      expirySlot: 123n,
      proof: {
        piA: filled(64, 0x11),
        piB: filled(128, 0x22),
        piC: filled(64, 0x33),
      },
    });

    expect(ix.data).toHaveLength(304);
    expect(ix.keys).toEqual([
      { pubkey: payer, isSigner: true, isWritable: true },
      {
        pubkey: vaultConfigPda(PROGRAM_ID)[0],
        isSigner: false,
        isWritable: false,
      },
      {
        pubkey: marketConfigPda(PROGRAM_ID, baseMint, quoteMint)[0],
        isSigner: false,
        isWritable: false,
      },
      {
        pubkey: batchValidityMarkerPda(PROGRAM_ID, root)[0],
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
