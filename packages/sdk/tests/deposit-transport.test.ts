/**
 * Tests the deposit factory's transport behaviour using mock providers.
 * The goal is to exercise:
 *   - stage callback ordering
 *   - correct instruction construction (discriminator, PDA, byte layout)
 *   - bigint nonce / amount encoding
 *   - error path when vault_config is missing
 */

import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import {
  PublicKey,
  Transaction,
  TransactionInstruction,
} from "@solana/web3.js";

import {
  getDepositFunction,
  getDepositRetryFunction,
} from "../src/utxo/deposit.js";
import { DarkPoolError } from "../src/errors.js";
import type {
  AccountInfoProvider,
  MerkleProofProvider,
  MasterSeedStorage,
  SolanaConnectionProvider,
  TransactionForwarder,
} from "../src/providers.js";
import { DarkPoolClient } from "../src/client.js";
import {
  UnimplementedProverSuite,
  type DepositInputs,
} from "../src/zk/prover-suite.js";
import { BN254_R, bn254ToBE32 } from "../src/keys/key-generators.js";
import {
  anchorDiscriminator,
  vaultConfigPda,
  merkleTreePda,
} from "../src/idl/vault-client.js";

// v3 exposes TransactionInstruction.data as a Uint8Array. These assertions
// used to cast it to a node Buffer -- a cast the compiler trusts and the
// runtime does not, which is why they typechecked and then failed on
// `.equals` / `.readBigUInt64LE`. Read through a DataView instead, and
// compare Uint8Array to Uint8Array.
const u64le = (d: Uint8Array, at: number): bigint =>
  new DataView(d.buffer, d.byteOffset, d.byteLength).getBigUint64(at, true);

const PROGRAM_ID = new PublicKey(
  "C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx",
);

/** Build a MerkleTree-shard-shaped buffer with `leafCount` at offset 8.
 *  Post-sharding the tree state lives in the per-shard MerkleTree account
 *  (8 disc + 8 leaf_count + ...), not VaultConfig. */
function fakeMerkleTreeData(leafCount: bigint): Buffer {
  const b = Buffer.alloc(320, 0);
  b.writeBigUInt64LE(leafCount, 8);
  return b;
}

/** The deposit's actual leaf index is read back from the NoteCreated event in
 *  the confirmed tx. Build a synthetic `Program data:` log carrying it. Body:
 *  tree_id(1) ‖ leaf_index(8) ‖ commitment(32) ‖ token_mint(32) ‖ amount(8) ‖ new_root(32). */
const EVENT_LEAF_INDEX = 99n;
function noteCreatedLog(leafIndex: bigint): string {
  const disc = createHash("sha256")
    .update("event:NoteCreated")
    .digest()
    .subarray(0, 8);
  const body = Buffer.alloc(1 + 8 + 32 + 32 + 8 + 32, 0);
  body.writeBigUInt64LE(leafIndex, 1); // after tree_id(1)
  return `Program data: ${Buffer.concat([disc, body]).toString("base64")}`;
}

function makeProviders(opts: {
  vaultConfigData?: Buffer | null;
  captureIxs?: TransactionInstruction[];
  forwarderReply?: string;
  forwarderError?: Error;
}): {
  accountInfoProvider: AccountInfoProvider;
  transactionForwarder: TransactionForwarder;
  merkleProofProvider: MerkleProofProvider;
} {
  return {
    accountInfoProvider: {
      getAccountInfo: async (pk: PublicKey) => {
        if (opts.vaultConfigData === null) return null;
        return {
          data: opts.vaultConfigData ?? fakeMerkleTreeData(7n),
          owner: PROGRAM_ID,
        };
      },
    },
    transactionForwarder: {
      sendAndConfirm: async (txOrIxs) => {
        if (Array.isArray(txOrIxs)) {
          opts.captureIxs?.push(...txOrIxs);
        } else {
          opts.captureIxs?.push(...(txOrIxs as Transaction).instructions);
        }
        if (opts.forwarderError) throw opts.forwarderError;
        return opts.forwarderReply ?? "deposit_sig_stub";
      },
    },
    merkleProofProvider: {
      getInclusionProof: async () => ({
        root: new Uint8Array(32),
        siblings: [],
        pathIndices: [],
      }),
    },
  };
}

function makeClient(
  providers: ReturnType<typeof makeProviders>,
): DarkPoolClient {
  const conn: SolanaConnectionProvider = {
    connection: {
      getTransaction: async () => ({
        meta: {
          // Bracketed in the vault's own frame: the decoder attributes
          // `Program data:` to the innermost open program, so a bare event
          // line belongs to no program and is ignored.
          logMessages: [
            `Program ${PROGRAM_ID.toBase58()} invoke [1]`,
            noteCreatedLog(EVENT_LEAF_INDEX),
            `Program ${PROGRAM_ID.toBase58()} success`,
          ],
        },
      }),
    } as never,
    perRpcUrl: "http://stub",
  };
  const storage: MasterSeedStorage = {
    load: async () => {
      const b = new Uint8Array(64);
      for (let i = 0; i < 64; i++) b[i] = i;
      return b;
    },
    store: async () => {},
  };
  const prover = new UnimplementedProverSuite();
  prover.deposit = {
    prove: async (inputs: DepositInputs) => ({
      piA: new Uint8Array(64).fill(0xaa),
      piB: new Uint8Array(128).fill(0xbb),
      piC: new Uint8Array(64).fill(0xcc),
      publicInputs: [
        inputs.noteCommitment,
        inputs.tokenMint[0],
        inputs.tokenMint[1],
        inputs.amount,
        inputs.recoveryNonce,
      ].map(bn254ToBE32),
    }),
  };
  return new DarkPoolClient({
    programId: PROGRAM_ID,
    seedMode: { type: "csprng", storage },
    connectionProvider: conn,
    providers,
    zkProver: prover,
  });
}

describe("getDepositFunction", () => {
  it("builds a valid deposit instruction and records stages", async () => {
    const ixs: TransactionInstruction[] = [];
    const providers = makeProviders({
      vaultConfigData: fakeMerkleTreeData(42n),
      captureIxs: ixs,
      forwarderReply: "deposit_sig_abc",
    });
    const client = makeClient(providers);
    const stages: string[] = [];
    let generatedNonce: Uint8Array | undefined;

    const deposit = getDepositFunction({ client });
    const mintBytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) mintBytes[i] = i + 1;

    const receipt = await deposit({
      depositor: new PublicKey(mintBytes), // reuse as stub pubkey
      tokenMint: mintBytes,
      amount: 1_000_000n,
      depositorTokenAccount: new PublicKey(mintBytes),
      onRecoveryNonceGenerated: (nonce) => {
        generatedNonce = nonce;
      },
      callbacks: {
        pre: (s) => {
          stages.push(s);
        },
      },
    });

    expect(receipt.signature).toBe("deposit_sig_abc");
    // leafIndex comes from the NoteCreated event, NOT the pre-send leaf_count read.
    expect(receipt.leafIndex).toBe(EVENT_LEAF_INDEX);
    expect(receipt.noteCommitment).toHaveLength(32);
    expect(generatedNonce).toHaveLength(32);
    expect(receipt.notePlaintext.recoveryNonce).toBe(
      [...generatedNonce!].reduce(
        (value, byte) => (value << 8n) | BigInt(byte),
        0n,
      ),
    );
    expect(receipt.notePlaintext.recoveryNonce).toBeGreaterThan(0n);
    expect(receipt.notePlaintext.recoveryNonce).toBeLessThan(BN254_R);
    expect(stages).toEqual([
      "merkle-position-fetch",
      "note-build",
      "proof-generation",
      "instruction-build",
      "transaction-send",
    ]);
    expect(ixs).toHaveLength(1);
    const ix = ixs[0];
    expect(ix.programId.toBase58()).toBe(PROGRAM_ID.toBase58());
    // Discriminator check.
    const disc = anchorDiscriminator("deposit");
    expect(ix.data.subarray(0, 8)).toEqual(disc);
    // [1] vault_config (read-only), [2] merkle_tree[0] (the leaf-append shard).
    const [vaultPda] = await vaultConfigPda(PROGRAM_ID);
    expect(ix.keys[1].pubkey.toBase58()).toBe(vaultPda.toBase58());
    const [treePda] = await merkleTreePda(PROGRAM_ID, 0);
    expect(ix.keys[2].pubkey.toBase58()).toBe(treePda.toBase58());
    // tree_id(1) at offset 8, then amount (u64 LE) at offset 9.
    expect(ix.data[8]).toBe(0);
    expect(u64le(ix.data, 9)).toBe(1_000_000n);
    expect(ix.data).toHaveLength(337);
    expect(Buffer.from(ix.data.subarray(17, 49))).toEqual(
      Buffer.from(receipt.noteCommitment),
    );
    expect(Buffer.from(ix.data.subarray(81, 145))).toEqual(
      Buffer.alloc(64, 0xaa),
    );
  });

  it("throws parameter error on zero amount", async () => {
    const providers = makeProviders({});
    const client = makeClient(providers);
    const deposit = getDepositFunction({ client });
    const mint = new Uint8Array(32);
    await expect(
      deposit({
        depositor: new PublicKey(mint),
        tokenMint: mint,
        amount: 0n,
        depositorTokenAccount: new PublicKey(mint),
      }),
    ).rejects.toMatchObject({ stage: "parameter" });
  });

  it("throws merkle-position-fetch when vault_config is missing", async () => {
    const providers = makeProviders({ vaultConfigData: null });
    const client = makeClient(providers);
    const deposit = getDepositFunction({ client });
    const mint = new Uint8Array(32);
    await expect(
      deposit({
        depositor: new PublicKey(mint),
        tokenMint: mint,
        amount: 1n,
        depositorTokenAccount: new PublicKey(mint),
      }),
    ).rejects.toBeInstanceOf(DarkPoolError);
  });

  it("uses a fresh nonce for a fresh deposit and preserves an explicit retry", async () => {
    const providers = makeProviders({
      vaultConfigData: fakeMerkleTreeData(0n),
      forwarderReply: "deposit_sig_abc",
    });
    const client = makeClient(providers);
    const deposit = getDepositFunction({ client });
    const retry = getDepositRetryFunction({ client });
    const mint = new Uint8Array(32).fill(7);
    const base = {
      depositor: new PublicKey(mint),
      tokenMint: mint,
      amount: 12n,
      depositorTokenAccount: new PublicKey(mint),
    };
    let firstNonce: Uint8Array | undefined;
    const first = await deposit({
      ...base,
      onRecoveryNonceGenerated: (nonce) => {
        firstNonce = nonce;
      },
    });
    const second = await deposit(base);
    const redriven = await retry({ ...base, recoveryNonce: firstNonce! });

    expect(second.noteCommitment).not.toEqual(first.noteCommitment);
    expect(redriven.noteCommitment).toEqual(first.noteCommitment);
    expect(redriven.notePlaintext.innerHash).toBe(
      first.notePlaintext.innerHash,
    );
  });

  it("exposes the nonce before an ambiguous send so the exact note can be redriven", async () => {
    const firstIxs: TransactionInstruction[] = [];
    const firstClient = makeClient(
      makeProviders({
        vaultConfigData: fakeMerkleTreeData(0n),
        captureIxs: firstIxs,
        forwarderError: new Error("confirmation timed out"),
      }),
    );
    const mint = new Uint8Array(32).fill(8);
    const base = {
      depositor: new PublicKey(mint),
      tokenMint: mint,
      amount: 44n,
      depositorTokenAccount: new PublicKey(mint),
    };
    let nonce: Uint8Array | undefined;
    await expect(
      getDepositFunction({ client: firstClient })({
        ...base,
        onRecoveryNonceGenerated: (value) => {
          nonce = value;
        },
      }),
    ).rejects.toThrow(/confirmation timed out/);
    expect(nonce).toHaveLength(32);

    const retryIxs: TransactionInstruction[] = [];
    const retryClient = makeClient(
      makeProviders({
        vaultConfigData: fakeMerkleTreeData(0n),
        captureIxs: retryIxs,
      }),
    );
    const retryReceipt = await getDepositRetryFunction({ client: retryClient })(
      {
        ...base,
        recoveryNonce: nonce!,
      },
    );

    // The public statement is byte-identical through the recovery nonce.
    // Proof bytes begin at offset 81 and may differ with a randomized prover.
    expect(retryIxs[0].data.subarray(0, 81)).toEqual(
      firstIxs[0].data.subarray(0, 81),
    );
    expect(retryReceipt.noteCommitment).toEqual(
      firstIxs[0].data.subarray(17, 49),
    );
    expect(retryIxs[0].keys.map((key) => key.pubkey.toBase58())).toEqual(
      firstIxs[0].keys.map((key) => key.pubkey.toBase58()),
    );
  });
});
