import {
  findAssociatedTokenPda,
  TOKEN_PROGRAM_ADDRESS,
} from "@solana-program/token";

// `@solana/spl-token` peer-depends on web3.js v1 and cannot coexist with v3,
// so ATA derivation moved to `@solana-program/token`. It is async there
// (WebCrypto) and returns a kit-branded Address string, while the vault SDK
// wants the v3 `Address` class -- convert once, here.
const TOKEN_PROGRAM_ID = new PublicKey(TOKEN_PROGRAM_ADDRESS);

async function associatedTokenAddress(
  mint: PublicKey,
  owner: PublicKey,
): Promise<PublicKey> {
  const [ata] = await findAssociatedTokenPda({
    mint: mint.toBase58(),
    owner: owner.toBase58(),
    tokenProgram: TOKEN_PROGRAM_ADDRESS,
  });
  return new PublicKey(ata);
}
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
  noteCommitmentFromBytes,
  noteUseTagFromBytes,
  type DepositInputs,
  type MergeInputs,
  type SpendInputs,
} from "@darknyx/sdk/browser-account";
import { apiUrl } from "@darknyx/sdk/api-url";
import {
  bn254ToBE32,
  pubkeyToFrPair,
} from "@darknyx/sdk/browser-inventory-crypto";
import bs58 from "bs58";

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

const hex = (bytes: Uint8Array): string =>
  Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");

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
export type AccountOperationProgressStage =
  | "preparing"
  | "proving"
  | "wallet_approval"
  | "finalizing";
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
  onProgress?(
    operation: AccountOperationKind,
    stage: AccountOperationProgressStage,
  ): void;
  requestTimeoutMs?: number;
}

/** Typed deposit/withdraw/merge composition; no generic prove/sign surface. */
export class BrowserAccountOperations {
  readonly #options: BrowserAccountOperationsOptions;
  readonly #connection: Pick<
    Connection,
    "getLatestBlockhash" | "confirmTransaction"
  >;
  readonly #programId: PublicKey;
  readonly #requestTimeoutMs: number;

  constructor(options: BrowserAccountOperationsOptions) {
    this.#options = options;
    this.#connection =
      options.connection ?? new Connection(options.release.rpcUrl, "finalized");
    this.#programId = new PublicKey(options.release.vaultProgramId);
    this.#requestTimeoutMs = options.requestTimeoutMs ?? 20_000;
    if (
      !Number.isFinite(this.#requestTimeoutMs) ||
      this.#requestTimeoutMs <= 0
    ) {
      throw new Error("account-operation request timeout must be positive");
    }
  }

  async #bounded<T>(label: string, operation: Promise<T>): Promise<T> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(
        () => reject(new Error(`${label} timed out`)),
        this.#requestTimeoutMs,
      );
    });
    try {
      return await Promise.race([operation, timeout]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  #walletAddress(): PublicKey {
    const wallet = this.#options.wallet.current();
    if (!wallet) throw new Error("connect an external wallet first");
    return new PublicKey(wallet.address);
  }

  async #inclusion(note: InventoryNote): Promise<Inclusion> {
    const token = await this.#bounded(
      "session token",
      this.#options.venue.token(),
    );
    if (!token) throw new Error("session broker returned an empty token");
    const url = apiUrl(this.#options.release.gatewayUrl, "tree/inclusion");
    url.searchParams.set("commitment", note.commitment);
    url.searchParams.set("tree_id", String(note.treeId));
    const abort = new AbortController();
    const timer = setTimeout(() => abort.abort(), this.#requestTimeoutMs);
    let response: Response;
    try {
      response = await (
        this.#options.fetchImpl ?? globalThis.fetch.bind(globalThis)
      )(url, {
        headers: { authorization: `Bearer ${token}` },
        signal: abort.signal,
      });
    } finally {
      clearTimeout(timer);
    }
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
      note.treeId,
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
    const latest = await this.#bounded(
      "latest blockhash",
      this.#connection.getLatestBlockhash("finalized"),
    );
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
    const signature = bs58.encode(signatureBytes);
    this.#options.onProgress?.(operation, "finalizing");
    try {
      const confirmation = await this.#bounded(
        "finalized transaction confirmation",
        this.#connection.confirmTransaction(
          { signature, ...latest },
          "finalized",
        ),
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
    const tokenAccount = await associatedTokenAddress(mint, depositor);
    this.#options.onProgress?.(operation, "preparing");
    const prepared = await requestVaultInternal<PreparedDeposit>(
      this.#options.vault,
      "prepareDeposit",
      {
        tokenMint: hex(mint.toBytes()),
        amount: params.amount.toString(),
      },
    );
    const treeId = prepared.recoveryNonce[31] % this.#options.venue.numTrees;
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
    const instruction = await buildDepositInstruction({
      programId: this.#programId,
      treeId,
      depositor,
      tokenMint: mint,
      depositorTokenAccount: tokenAccount,
      tokenProgramId: TOKEN_PROGRAM_ID,
      amount: params.amount,
      noteCommitment: noteCommitmentFromBytes(prepared.commitment),
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
      const destination = await associatedTokenAddress(
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
        bn254ToBE32(mintLo),
        bn254ToBE32(mintHi),
        bn254ToBE32(params.amount),
        bn254ToBE32(destinationLo),
        bn254ToBE32(destinationHi),
      ]);
      const instruction = await buildWithdrawInstruction({
        programId: this.#programId,
        treeId: held.note.treeId,
        payer: this.#walletAddress(),
        tokenMint: mint,
        destinationTokenAccount: destination,
        tokenProgramId: TOKEN_PROGRAM_ID,
        noteUseTag: noteUseTagFromBytes(prepared.noteUseTag),
        merkleRoot: prepared.merkleRoot,
        amount: params.amount,
        proof,
      });
      result = await this.#sendFinalized(operation, instruction);
    } catch (error) {
      // Wallet Standard may reject after broadcasting but before returning a
      // signature. Keep the reservation unless failure happened before wallet
      // submission; finalized reconciliation decides the uncertain case.
      if (
        !(error instanceof AccountOperationError) ||
        error.stage !== "wallet"
      ) {
        await this.#options.inventory.releaseReservation(held.reservationId);
      }
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
      const instruction = await buildMergeInstruction({
        programId: this.#programId,
        treeId: held[0].note.treeId,
        payer: this.#walletAddress(),
        inputUseTags: prepared.inputUseTags.map(noteUseTagFromBytes),
        outputCommitment: noteCommitmentFromBytes(prepared.outputCommitment),
        tokenMint: mint,
        merkleRoot: prepared.merkleRoot,
        k: prepared.k,
        proof,
      });
      result = await this.#sendFinalized(operation, instruction);
    } catch (error) {
      if (
        !(error instanceof AccountOperationError) ||
        error.stage !== "wallet"
      ) {
        await Promise.all(
          held.map(({ reservationId }) =>
            this.#options.inventory.releaseReservation(reservationId),
          ),
        );
      }
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
