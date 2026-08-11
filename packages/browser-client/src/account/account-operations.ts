import {
  getAssociatedTokenAddressSync,
  TOKEN_PROGRAM_ID,
} from "@solana/spl-token";
import {
  Connection,
  PublicKey,
  TransactionMessage,
  VersionedTransaction,
  type TransactionInstruction,
} from "@solana/web3.js";
import {
  assertPublicInputs,
  buildDepositInstruction,
  buildMergeInstruction,
  buildWithdrawInstruction,
  type DepositInputs,
  type MergeInputs,
  type SpendInputs,
} from "@darknyx/sdk/browser-account";
import {
  bn254ToBE32,
  pubkeyToFrPair,
} from "@darknyx/sdk/browser-inventory-crypto";

import {
  requestVaultInternal,
  type BrowserVault,
} from "../custody/browser-vault.js";
import type { BrowserInventory } from "../inventory/browser-inventory.js";
import type { InventoryNote } from "../inventory/types.js";
import type { BrowserProverSuite } from "../prover/browser-prover.js";
import type {
  TrustedVenueSession,
  VenueReleaseConfig,
} from "../venue/types.js";
import type { ExternalWalletController } from "../wallet/wallet-standard.js";

const HEX32 = /^[0-9a-f]{64}$/;
const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

const hex = (bytes: Uint8Array): string =>
  Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");

function base58(bytes: Uint8Array): string {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  let encoded = "";
  while (value > 0n) {
    encoded = BASE58[Number(value % 58n)] + encoded;
    value /= 58n;
  }
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros += 1;
  return "1".repeat(zeros) + (encoded || (zeros === 0 ? "1" : ""));
}

interface Inclusion {
  root: string;
  siblings: string[];
  pathIndices: number[];
}

interface PreparedDeposit {
  witness: DepositInputs;
  commitment: Uint8Array;
  recoveryNonce: Uint8Array;
}

interface PreparedSpend {
  witness: SpendInputs;
  noteUseTag: Uint8Array;
  nullifier: Uint8Array;
  merkleRoot: Uint8Array;
}

interface PreparedMerge {
  witness: MergeInputs;
  inputUseTags: Uint8Array[];
  outputCommitment: Uint8Array;
  tokenMint: Uint8Array;
  merkleRoot: Uint8Array;
  k: 2 | 4;
}

export type AccountOperationKind = "deposit" | "withdraw" | "merge";
export type AccountOperationResult =
  | { status: "finalized"; signature: string }
  | { status: "ambiguous"; signature: string; message: string };

export class AccountOperationError extends Error {
  constructor(
    readonly operation: AccountOperationKind,
    readonly stage: "prepare" | "prove" | "wallet" | "finalize",
    message: string,
  ) {
    super(message);
    this.name = "AccountOperationError";
  }
}

export interface BrowserAccountOperationsOptions {
  release: VenueReleaseConfig;
  venue: TrustedVenueSession;
  vault: BrowserVault;
  inventory: BrowserInventory;
  prover: BrowserProverSuite;
  wallet: ExternalWalletController;
  fetchImpl?: typeof fetch;
  /** Test/integration seam; production defaults to the release-pinned RPC. */
  connection?: Pick<Connection, "getLatestBlockhash" | "confirmTransaction">;
  onProgress?(operation: AccountOperationKind, stage: string): void;
}

/** Typed deposit/withdraw/merge composition; no generic prove/sign surface. */
export class BrowserAccountOperations {
  readonly #options: BrowserAccountOperationsOptions;
  readonly #connection: Pick<
    Connection,
    "getLatestBlockhash" | "confirmTransaction"
  >;
  readonly #programId: PublicKey;

  constructor(options: BrowserAccountOperationsOptions) {
    this.#options = options;
    this.#connection =
      options.connection ?? new Connection(options.release.rpcUrl, "finalized");
    this.#programId = new PublicKey(options.release.vaultProgramId);
  }

  #walletAddress(): PublicKey {
    const wallet = this.#options.wallet.current();
    if (!wallet) throw new Error("connect an external wallet first");
    return new PublicKey(wallet.address);
  }

  async #inclusion(note: InventoryNote): Promise<Inclusion> {
    const token = await this.#options.venue.token();
    if (!token) throw new Error("session broker returned an empty token");
    const url = new URL("/tree/inclusion", this.#options.release.gatewayUrl);
    url.searchParams.set("commitment", note.commitment);
    url.searchParams.set("tree_id", String(note.treeId ?? 0));
    const response = await (this.#options.fetchImpl ?? fetch)(url, {
      headers: { authorization: `Bearer ${token}` },
    });
    if (!response.ok)
      throw new Error(`tree inclusion failed (${response.status})`);
    const body = (await response.json()) as Record<string, unknown>;
    if (
      typeof body.merkle_root !== "string" ||
      !HEX32.test(body.merkle_root) ||
      !Array.isArray(body.siblings) ||
      body.siblings.length !== 20 ||
      body.siblings.some(
        (value) => typeof value !== "string" || !HEX32.test(value),
      ) ||
      !Number.isSafeInteger(body.leaf_index) ||
      (body.leaf_index as number) < 0 ||
      (body.leaf_index as number) >= 1 << 20
    ) {
      throw new Error("tree inclusion response is malformed");
    }
    await this.#options.inventory.assertAcceptedRoot(
      note.treeId ?? 0,
      body.merkle_root,
    );
    const leafIndex = body.leaf_index as number;
    return {
      root: body.merkle_root,
      siblings: body.siblings as string[],
      pathIndices: Array.from(
        { length: 20 },
        (_, index) => (leafIndex >> index) & 1,
      ),
    };
  }

  async #sendFinalized(
    operation: AccountOperationKind,
    instruction: TransactionInstruction,
  ): Promise<AccountOperationResult> {
    const payer = this.#walletAddress();
    const latest = await this.#connection.getLatestBlockhash("finalized");
    const message = new TransactionMessage({
      payerKey: payer,
      recentBlockhash: latest.blockhash,
      instructions: [instruction],
    }).compileToV0Message();
    const transaction = new VersionedTransaction(message).serialize();
    this.#options.onProgress?.(operation, "wallet_approval");
    let signatureBytes: Uint8Array;
    try {
      signatureBytes =
        await this.#options.wallet.signAndSendTransaction(transaction);
    } catch (error) {
      throw new AccountOperationError(
        operation,
        "wallet",
        error instanceof Error ? error.message : String(error),
      );
    }
    const signature = base58(signatureBytes);
    this.#options.onProgress?.(operation, "finalizing");
    try {
      const confirmation = await this.#connection.confirmTransaction(
        { signature, ...latest },
        "finalized",
      );
      if (confirmation.value.err) {
        throw new Error(JSON.stringify(confirmation.value.err));
      }
      return { status: "finalized", signature };
    } catch (error) {
      return {
        status: "ambiguous",
        signature,
        message: error instanceof Error ? error.message : String(error),
      };
    }
  }

  async deposit(params: {
    tokenMint: string;
    amount: bigint;
  }): Promise<AccountOperationResult> {
    const operation = "deposit";
    if (params.amount <= 0n)
      throw new AccountOperationError(
        operation,
        "prepare",
        "deposit amount must be positive",
      );
    const mint = new PublicKey(params.tokenMint);
    const depositor = this.#walletAddress();
    const tokenAccount = getAssociatedTokenAddressSync(mint, depositor);
    const depositIndex = await this.#options.inventory.allocateDepositIndex();
    const treeId = depositIndex % this.#options.venue.numTrees;
    this.#options.onProgress?.(operation, "preparing");
    const prepared = await requestVaultInternal<PreparedDeposit>(
      this.#options.vault,
      "prepareDeposit",
      {
        tokenMint: hex(mint.toBytes()),
        amount: params.amount.toString(),
        depositIndex,
      },
    );
    this.#options.onProgress?.(operation, "proving");
    const proof = await this.#options.prover.deposit.prove(prepared.witness);
    const [mintLo, mintHi] = pubkeyToFrPair(mint.toBytes());
    assertPublicInputs("VALID_DEPOSIT", proof.publicInputs, [
      prepared.commitment,
      bn254ToBE32(mintLo),
      bn254ToBE32(mintHi),
      bn254ToBE32(params.amount),
      prepared.recoveryNonce,
    ]);
    const instruction = buildDepositInstruction({
      programId: this.#programId,
      treeId,
      depositor,
      tokenMint: mint,
      depositorTokenAccount: tokenAccount,
      tokenProgramId: TOKEN_PROGRAM_ID,
      amount: params.amount,
      noteCommitment: prepared.commitment,
      recoveryNonce: prepared.recoveryNonce,
      proof,
    });
    return this.#sendFinalized(operation, instruction);
  }

  async withdraw(params: {
    tokenMint: string;
    amount: bigint;
  }): Promise<AccountOperationResult> {
    const operation = "withdraw";
    const mint = new PublicKey(params.tokenMint);
    const held = await this.#options.inventory.reserveAccountExact(
      hex(mint.toBytes()),
      params.amount,
    );
    if (!held) {
      throw new AccountOperationError(
        operation,
        "prepare",
        "withdrawal must match one spendable note; consolidate to withdraw the full balance",
      );
    }
    let result: AccountOperationResult;
    try {
      this.#options.onProgress?.(operation, "preparing");
      const inclusion = await this.#inclusion(held.note);
      const destination = getAssociatedTokenAddressSync(
        mint,
        this.#walletAddress(),
      );
      const prepared = await requestVaultInternal<PreparedSpend>(
        this.#options.vault,
        "prepareSpend",
        {
          note: held.note,
          merkleRoot: inclusion.root,
          siblings: inclusion.siblings,
          pathIndices: inclusion.pathIndices,
          destination: hex(destination.toBytes()),
        },
      );
      this.#options.onProgress?.(operation, "proving");
      const proof = await this.#options.prover.spend.prove(prepared.witness);
      const [mintLo, mintHi] = pubkeyToFrPair(mint.toBytes());
      const [destinationLo, destinationHi] = pubkeyToFrPair(
        destination.toBytes(),
      );
      assertPublicInputs("VALID_SPEND", proof.publicInputs, [
        prepared.noteUseTag,
        prepared.merkleRoot,
        prepared.nullifier,
        bn254ToBE32(mintLo),
        bn254ToBE32(mintHi),
        bn254ToBE32(params.amount),
        bn254ToBE32(destinationLo),
        bn254ToBE32(destinationHi),
      ]);
      const instruction = buildWithdrawInstruction({
        programId: this.#programId,
        treeId: held.note.treeId ?? 0,
        payer: this.#walletAddress(),
        tokenMint: mint,
        destinationTokenAccount: destination,
        tokenProgramId: TOKEN_PROGRAM_ID,
        noteUseTag: prepared.noteUseTag,
        nullifier: prepared.nullifier,
        merkleRoot: prepared.merkleRoot,
        amount: params.amount,
        proof,
      });
      result = await this.#sendFinalized(operation, instruction);
    } catch (error) {
      // #sendFinalized turns every post-signature failure into an ambiguous
      // result. A thrown error therefore proves that no transaction signature
      // was returned and the note is safe to make spendable again.
      await this.#options.inventory.releaseReservation(held.reservationId);
      throw error;
    }
    if (result.status === "finalized") {
      await this.#options.inventory.markConsumed(held.note.commitment);
    }
    return result;
  }

  async merge(tokenMint: string): Promise<AccountOperationResult> {
    const operation = "merge";
    const mint = new PublicKey(tokenMint);
    const held = await this.#options.inventory.reserveAccountMerge(
      hex(mint.toBytes()),
    );
    if (held.length < 2) {
      throw new AccountOperationError(
        operation,
        "prepare",
        "at least two spendable notes on one shard are required",
      );
    }
    let result: AccountOperationResult;
    try {
      this.#options.onProgress?.(operation, "preparing");
      const inclusions = await Promise.all(
        held.map(({ note }) => this.#inclusion(note)),
      );
      const prepared = await requestVaultInternal<PreparedMerge>(
        this.#options.vault,
        "prepareMerge",
        { inputs: held.map(({ note }) => note), inclusions },
      );
      this.#options.onProgress?.(operation, "proving");
      const proof = await this.#options.prover.merge.prove(prepared.witness);
      const [mintLo, mintHi] = pubkeyToFrPair(mint.toBytes());
      assertPublicInputs("VALID_MERGE", proof.publicInputs, [
        prepared.outputCommitment,
        ...prepared.inputUseTags,
        prepared.merkleRoot,
        bn254ToBE32(mintLo),
        bn254ToBE32(mintHi),
      ]);
      const instruction = buildMergeInstruction({
        programId: this.#programId,
        treeId: held[0].note.treeId ?? 0,
        payer: this.#walletAddress(),
        inputUseTags: prepared.inputUseTags,
        outputCommitment: prepared.outputCommitment,
        tokenMint: mint,
        merkleRoot: prepared.merkleRoot,
        k: prepared.k,
        proof,
      });
      result = await this.#sendFinalized(operation, instruction);
    } catch (error) {
      await Promise.all(
        held.map(({ reservationId }) =>
          this.#options.inventory.releaseReservation(reservationId),
        ),
      );
      throw error;
    }
    if (result.status === "finalized") {
      await Promise.all(
        held.map(({ note }) =>
          this.#options.inventory.markConsumed(note.commitment),
        ),
      );
    }
    return result;
  }
}
