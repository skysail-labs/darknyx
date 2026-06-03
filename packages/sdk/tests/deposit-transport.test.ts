/**
 * Tests the deposit factory's transport behaviour using mock providers.
 * The goal is to exercise:
 *   - stage callback ordering
 *   - correct instruction construction (discriminator, PDA, byte layout)
 *   - bigint nonce / amount encoding
 *   - error path when vault_config is missing
 */

import { describe, it, expect } from "vitest";
import { PublicKey, Transaction, TransactionInstruction } from "@solana/web3.js";
import type { Buffer as NodeBuffer } from "node:buffer";

import { getDepositFunction } from "../src/utxo/deposit.js";
import { DarkPoolError } from "../src/errors.js";
import type {
  AccountInfoProvider,
  MerkleProofProvider,
  MasterSeedStorage,
  SolanaConnectionProvider,
  TransactionForwarder,
} from "../src/providers.js";
import { DarkPoolClient } from "../src/client.js";
import { UnimplementedProverSuite } from "../src/zk/prover-suite.js";
import { anchorDiscriminator, vaultConfigPda } from "../src/idl/vault-client.js";

const PROGRAM_ID = new PublicKey("C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx");

/** Build a VaultConfig-shaped buffer with `leafCount` at offset 104. */
function fakeVaultConfigData(leafCount: bigint): Buffer {
  // 8 (disc) + 32 (admin) + 32 (tee) + 32 (root_key) + 8 (leaf_count) + ...
  const b = Buffer.alloc(320, 0);
  b.writeBigUInt64LE(leafCount, 104);
  return b;
}

function makeProviders(opts: {
  vaultConfigData?: Buffer | null;
  captureIxs?: TransactionInstruction[];
  forwarderReply?: string;
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
          data: opts.vaultConfigData ?? fakeVaultConfigData(7n),
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
    connection: {} as never,
    perRpcUrl: "http://stub",
  };
  const storage: MasterSeedStorage = {
    load: async () => {
      const b = new Uint8Array(64);
      for (let i = 0; i < 64; i++) b[i] = i;
      return b;
    },
    store: async () => {},
    generate: async () => new Uint8Array(64),
  };
  return new DarkPoolClient({
    programId: PROGRAM_ID,
    seedMode: { type: "csprng", storage },
    connectionProvider: conn,
    providers,
    zkProver: new UnimplementedProverSuite(),
    ownerCommitmentBlinding: 1234n,
  });
}

describe("getDepositFunction", () => {
  it("builds a valid deposit instruction and records stages", async () => {
    const ixs: TransactionInstruction[] = [];
    const providers = makeProviders({
      vaultConfigData: fakeVaultConfigData(42n),
      captureIxs: ixs,
      forwarderReply: "deposit_sig_abc",
    });
    const client = makeClient(providers);
    const stages: string[] = [];

    const deposit = getDepositFunction({ client });
    const mintBytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) mintBytes[i] = i + 1;

    const receipt = await deposit({
      depositor: new PublicKey(mintBytes), // reuse as stub pubkey
      tokenMint: mintBytes,
      amount: 1_000_000n,
      depositorTokenAccount: new PublicKey(mintBytes),
      callbacks: {
        pre: (s) => {
          stages.push(s);
        },
      },
    });

    expect(receipt.signature).toBe("deposit_sig_abc");
    expect(receipt.leafIndex).toBe(42n);
    expect(receipt.noteCommitment).toHaveLength(32);
    expect(stages).toEqual([
      "merkle-position-fetch",
      "note-build",
      "instruction-build",
      "transaction-send",
    ]);
    expect(ixs).toHaveLength(1);
    const ix = ixs[0];
    expect(ix.programId.toBase58()).toBe(PROGRAM_ID.toBase58());
    // Discriminator check.
    const disc = Buffer.from(anchorDiscriminator("deposit"));
    expect((ix.data as NodeBuffer).subarray(0, 8).equals(disc)).toBe(true);
    // Second vault account must be the vault_config PDA.
    const [vaultPda] = vaultConfigPda(PROGRAM_ID);
    expect(ix.keys[1].pubkey.toBase58()).toBe(vaultPda.toBase58());
    // Amount (u64 LE at offset 8).
    expect((ix.data as NodeBuffer).readBigUInt64LE(8)).toBe(1_000_000n);
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
});
