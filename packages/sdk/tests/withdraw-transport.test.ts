/**
 * Tests the withdraw factory's transport behaviour using a stub ProofProvider.
 * Since the real snarkjs prover doesn't ship until Phase 3, we inject a simple
 * fake prover that returns a fixed-length proof. The test asserts:
 *   - merkle-proof-fetch / note-build / proof-generation / instruction-build /
 *     transaction-send stages fire in order
 *   - the correct VALID_SPEND public inputs are forwarded to the prover
 *   - the built instruction has the expected discriminator, PDA set, and u64 amount
 *   - prover-provided proof bytes show up in the instruction data
 */

import { describe, it, expect } from "vitest";
import {
  PublicKey,
  Transaction,
  TransactionInstruction,
} from "@solana/web3.js";
import type { Buffer as NodeBuffer } from "node:buffer";

import { getWithdrawFunction } from "../src/utxo/withdraw.js";
import { deriveNoteUseTag } from "../src/utxo/note-use.js";
import { noteCommitmentV2 } from "../src/utxo/note.js";
import { bn254ToBE32 } from "../src/keys/key-generators.js";
import type {
  AccountInfoProvider,
  MerkleProofProvider,
  MasterSeedStorage,
  SolanaConnectionProvider,
  TransactionForwarder,
} from "../src/providers.js";
import { DarkPoolClient } from "../src/client.js";
import { anchorDiscriminator } from "../src/idl/vault-client.js";
import type {
  IDarkPoolZkProverSuite,
  SpendInputs,
} from "../src/zk/prover-suite.js";

const PROGRAM_ID = new PublicKey(
  "C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx",
);

class FakeProverSuite implements IDarkPoolZkProverSuite {
  public capturedSpendInputs: SpendInputs[] = [];
  walletCreate = {
    prove: async () => {
      throw new Error("not used in withdraw test");
    },
  };
  deposit = {
    prove: async () => {
      throw new Error("not used in withdraw test");
    },
  };
  /** Set by a test to the note-use TAG the SDK will compute locally (SW-26). */
  expectedNoteUseTag: Uint8Array | null = null;
  /**
   * Set by a test to corrupt the otherwise-correct public signals, so the SW-26
   * check is exercised with everything else about the withdraw unchanged.
   */
  corruptPublicInputs: ((v: Uint8Array[]) => Uint8Array[]) | null = null;
  spend = {
    prove: async (inputs: SpendInputs) => {
      this.capturedSpendInputs.push(inputs);
      const proof = {
        piA: new Uint8Array(64).fill(0xaa),
        piB: new Uint8Array(128).fill(0xbb),
        piC: new Uint8Array(64).fill(0xcc),
        // Public signals are now validated on every prove path (SW-26), so the
        // stub has to produce the real vector rather than `[]`. Order mirrors
        // `programs/vault/src/instructions/withdraw.rs`.
        publicInputs: [
          // VALID_SPEND's wire-0 output is the note-use tag; the commitment is
          // a private intermediate the circuit never publishes. Both are
          // computed inside the circuit, so the stub echoes what the caller set.
          this.expectedNoteUseTag ?? new Uint8Array(32),
          bn254ToBE32(inputs.merkleRoot),
          bn254ToBE32(inputs.nullifier),
          bn254ToBE32(inputs.tokenMint[0]),
          bn254ToBE32(inputs.tokenMint[1]),
          bn254ToBE32(inputs.amount),
          bn254ToBE32(inputs.recipient[0]),
          bn254ToBE32(inputs.recipient[1]),
        ],
      };
      return this.corruptPublicInputs
        ? { ...proof, publicInputs: this.corruptPublicInputs(proof.publicInputs) }
        : proof;
    },
  };
  merge = {
    prove: async () => {
      throw new Error("not used in withdraw test");
    },
  };
}

function makeProviders(captureIxs: TransactionInstruction[]): {
  accountInfoProvider: AccountInfoProvider;
  transactionForwarder: TransactionForwarder;
  merkleProofProvider: MerkleProofProvider;
} {
  return {
    accountInfoProvider: {
      getAccountInfo: async () => null,
    },
    transactionForwarder: {
      sendAndConfirm: async (txOrIxs) => {
        if (Array.isArray(txOrIxs)) {
          captureIxs.push(...txOrIxs);
        } else {
          captureIxs.push(...(txOrIxs as Transaction).instructions);
        }
        return "withdraw_sig_xyz";
      },
    },
    merkleProofProvider: {
      getInclusionProof: async (_: bigint) => ({
        root: new Uint8Array(32).fill(0x11),
        siblings: Array.from({ length: 20 }, (_, i) =>
          new Uint8Array(32).fill(0x20 + i),
        ),
        pathIndices: Array.from({ length: 20 }, (_, i) => i & 1),
      }),
    },
  };
}

function makeClient(
  providers: ReturnType<typeof makeProviders>,
  prover: IDarkPoolZkProverSuite,
): DarkPoolClient {
  const storage: MasterSeedStorage = {
    load: async () => {
      const b = new Uint8Array(64);
      for (let i = 0; i < 64; i++) b[i] = i;
      return b;
    },
    store: async () => {},
  };
  const conn: SolanaConnectionProvider = {
    connection: {} as never,
    perRpcUrl: "http://stub",
  };
  return new DarkPoolClient({
    programId: PROGRAM_ID,
    seedMode: { type: "csprng", storage },
    connectionProvider: conn,
    providers,
    zkProver: prover,
    ownerCommitmentBlinding: 55n,
  });
}

describe("getWithdrawFunction", () => {
  it("assembles the correct VALID_SPEND input + withdraw instruction", async () => {
    const ixs: TransactionInstruction[] = [];
    const providers = makeProviders(ixs);
    const prover = new FakeProverSuite();
    const client = makeClient(providers, prover);
    const stages: string[] = [];

    const mintBytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) mintBytes[i] = i + 1;
    const notePlaintext = {
      tokenMint: mintBytes,
      amount: 250_000n,
      ownerCommitment: 3n,
      innerHash: 9n,
    };
    // Public signals are validated on every prove path now (SW-26), so the
    // stub must return the vector the SDK computes locally.
    prover.expectedNoteUseTag = await deriveNoteUseTag(
      await noteCommitmentV2(notePlaintext),
      bn254ToBE32(notePlaintext.innerHash),
    );

    const receipt = await getWithdrawFunction({ client })({
      payer: new PublicKey(mintBytes),
      tokenMint: mintBytes,
      amount: 250_000n,
      destinationTokenAccount: new PublicKey(mintBytes),
      notePlaintext,
      leafIndex: 3n,
      callbacks: {
        pre: (s) => {
          stages.push(s);
        },
      },
    });

    expect(receipt.signature).toBe("withdraw_sig_xyz");
    expect(receipt.nullifier).toHaveLength(32);
    expect(stages).toEqual([
      "merkle-proof-fetch",
      "note-build",
      "proof-generation",
      "instruction-build",
      "transaction-send",
    ]);

    // Prover must have received the correct amount + merkle data.
    expect(prover.capturedSpendInputs).toHaveLength(1);
    const si = prover.capturedSpendInputs[0];
    expect(si.amount).toBe(250_000n);
    // The note's inner_hash must reach the prover unchanged.
    expect(si.innerHash).toBe(notePlaintext.innerHash);
    expect(si.merklePath).toHaveLength(20);
    expect(si.merkleIndices).toHaveLength(20);

    // One instruction built.
    expect(ixs).toHaveLength(1);
    const ix = ixs[0];
    const disc = Buffer.from(anchorDiscriminator("withdraw"));
    expect((ix.data as NodeBuffer).subarray(0, 8).equals(disc)).toBe(true);

    // Data layout: disc(8) || tree_id(1) || note_commitment(32) || nullifier(32)
    //   || merkle_root(32) || amount(u64 LE) || pi_a(64) || pi_b(128) || pi_c(64)
    const d = ix.data as NodeBuffer;
    expect(d.length).toBe(8 + 1 + 32 + 32 + 32 + 8 + 64 + 128 + 64);
    expect(d[8]).toBe(0); // tree_id
    const amt = d.readBigUInt64LE(8 + 1 + 32 + 32 + 32);
    expect(amt).toBe(250_000n);
    // Proof bytes (0xaa / 0xbb / 0xcc) should be present at the tail.
    const tailStart = 8 + 1 + 32 + 32 + 32 + 8;
    expect(d[tailStart]).toBe(0xaa);
    expect(d[tailStart + 64]).toBe(0xbb);
    expect(d[tailStart + 64 + 128]).toBe(0xcc);
  });

  // SW-26: the on-chain verifier rebuilds its public inputs from the
  // INSTRUCTION data, never from the proof, so a prover that returns signals
  // for a different statement yields a transaction that fails on-chain as
  // `InvalidProof (6000)` — after the fee is spent, far from the cause. The
  // prover is injectable (`client.zkProver`) and the daemon's runs in a
  // separate process, so this is a real shape rather than a theoretical one.
  //
  // Both cases assert the transaction is NEVER SENT. Asserting only that the
  // call rejects would pass even if the send happened first and the throw came
  // afterwards, which is the failure that costs money.
  describe("public-signal validation before send", () => {
    async function withdrawWith(
      corrupt: (v: Uint8Array[]) => Uint8Array[],
    ): Promise<{ error: Error | null; sent: TransactionInstruction[] }> {
      const ixs: TransactionInstruction[] = [];
      const providers = makeProviders(ixs);
      const prover = new FakeProverSuite();
      const client = makeClient(providers, prover);

      const mintBytes = new Uint8Array(32);
      for (let i = 0; i < 32; i++) mintBytes[i] = i + 1;
      const notePlaintext = {
        tokenMint: mintBytes,
        amount: 250_000n,
        ownerCommitment: 3n,
        innerHash: 9n,
      };
      prover.expectedNoteUseTag = await deriveNoteUseTag(
      await noteCommitmentV2(notePlaintext),
      bn254ToBE32(notePlaintext.innerHash),
    );
      prover.corruptPublicInputs = corrupt;

      let error: Error | null = null;
      try {
        await getWithdrawFunction({ client })({
          payer: new PublicKey(mintBytes),
          tokenMint: mintBytes,
          amount: 250_000n,
          destinationTokenAccount: new PublicKey(mintBytes),
          notePlaintext,
          leafIndex: 3n,
        });
      } catch (e) {
        error = e as Error;
      }
      return { error, sent: ixs };
    }

    it("refuses a public-input vector of the wrong length", async () => {
      const { error, sent } = await withdrawWith((v) => v.slice(0, v.length - 1));
      expect(error?.message).toMatch(/public inputs/i);
      expect(sent).toHaveLength(0);
    });

    it("refuses a vector whose element disagrees with the local value", async () => {
      // Same length, one element changed — the case a length check alone
      // cannot see, and the one that corresponds to proving a different note.
      const { error, sent } = await withdrawWith((v) => {
        const out = v.map((x) => Uint8Array.from(x));
        out[1] = new Uint8Array(32).fill(0x7f); // merkle_root
        return out;
      });
      expect(error?.message).toMatch(/public inputs/i);
      expect(sent).toHaveLength(0);
    });
  });

  it("rejects partial withdrawals", async () => {
    const ixs: TransactionInstruction[] = [];
    const providers = makeProviders(ixs);
    const client = makeClient(providers, new FakeProverSuite());
    const mint = new Uint8Array(32);
    const withdraw = getWithdrawFunction({ client });

    await expect(
      withdraw({
        payer: new PublicKey(mint),
        tokenMint: mint,
        amount: 100n,
        destinationTokenAccount: new PublicKey(mint),
        notePlaintext: {
          tokenMint: mint,
          amount: 200n, // mismatch!
          ownerCommitment: 1n,
          innerHash: 1n,
        },
        leafIndex: 0n,
      }),
    ).rejects.toMatchObject({ stage: "parameter" });
  });
});
