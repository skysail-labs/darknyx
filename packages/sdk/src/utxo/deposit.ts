/**
 * getDepositFunction — factory-function pattern (Section 23.3.2).
 *
 * Usage:
 *   const deposit = getDepositFunction({ client });
 *   const receipt = await deposit({
 *     tokenMint: mintBytes,
 *     amount: 100_000_000n,
 *     depositorTokenAccount: new PublicKey(...),
 *   });
 *
 * Staged errors (Section 23.3.2): each `throw` uses a distinct stage tag so
 * callers can distinguish "failed before any tx" from "tx sent but not
 * confirmed" without parsing free-text messages.
 */

import { PublicKey } from "@solana/web3.js";

import type { DarkPoolClient } from "../client.js";
import type { TransactionCallbacks } from "../providers.js";
import type { StoredNote } from "./note-store.js";
import { DarkPoolError } from "../errors.js";
import { noteCommitmentV2, ownerCommitment } from "./note.js";
import { bn254ToBE32, deriveBlindingFactor } from "../keys/key-generators.js";
import { buildDepositInstruction, vaultConfigPda } from "../idl/vault-client.js";

/** SPL Token program id (classic, not Token-2022). */
const TOKEN_PROGRAM_ID = new PublicKey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");

export interface DepositParams {
  /** Fee-payer / signer for the deposit transaction. */
  depositor: PublicKey;
  /** 32-byte SPL mint. */
  tokenMint: Uint8Array;
  /** Amount in base units. */
  amount: bigint;
  /** Depositor's SPL associated token account that holds `tokenMint`. */
  depositorTokenAccount: PublicKey;
  /** Override the SPL token program id (for Token-2022). */
  tokenProgramId?: PublicKey;
  callbacks?: TransactionCallbacks;
}

export interface DepositReceipt {
  signature: string;
  leafIndex: bigint;
  noteCommitment: Uint8Array;
  notePlaintext: {
    tokenMint: Uint8Array;
    amount: bigint;
    ownerCommitment: bigint;
    /** v2: single inner_hash (deterministic from masterSeed + leafIndex). */
    innerHash: bigint;
  };
}

/**
 * Convert a deposit receipt into a storable wallet note. Call
 * `store.put(depositNoteFromReceipt(receipt))` after a deposit so the wallet's
 * balance + coin-selection see it. (Deposits aren't recoverable from the seed
 * alone on a fresh device — record them here; trade-change notes recover via the
 * fills indexer.)
 */
export function depositNoteFromReceipt(receipt: DepositReceipt): StoredNote {
  return {
    commitment: Buffer.from(receipt.noteCommitment).toString("hex"),
    tokenMint: receipt.notePlaintext.tokenMint,
    amount: receipt.notePlaintext.amount,
    ownerCommitment: receipt.notePlaintext.ownerCommitment,
    innerHash: receipt.notePlaintext.innerHash,
    leafIndex: receipt.leafIndex,
  };
}

export function getDepositFunction(
  { client }: { client: DarkPoolClient },
): (params: DepositParams) => Promise<DepositReceipt> {
  return async (params) => {
    if (params.amount <= 0n) {
      throw new DarkPoolError("parameter", "deposit amount must be > 0");
    }
    if (params.tokenMint.length !== 32) {
      throw new DarkPoolError("parameter", "tokenMint must be 32 bytes");
    }

    const { masterSeed, spendingKey, ownerBlinding } = await client.getResolvedKeys();

    // --- Stage: merkle-position-fetch ---
    await params.callbacks?.pre?.("merkle-position-fetch");
    const [vaultPda] = vaultConfigPda(client.programId);
    const info = await client.providers.accountInfoProvider.getAccountInfo(vaultPda);
    if (!info) {
      throw new DarkPoolError(
        "merkle-position-fetch",
        "vault_config not initialised — deploy/init the program first",
      );
    }
    // VaultConfig layout (offsets after the 8-byte Anchor discriminator):
    //   admin:      Pubkey        @   8
    //   tee_pubkey: Pubkey        @  40
    //   root_key:   Pubkey        @  72
    //   leaf_count: u64 LE        @ 104
    const data = info.data;
    if (data.byteLength < 112) {
      throw new DarkPoolError(
        "merkle-position-fetch",
        `vault_config data too small: ${data.byteLength}`,
      );
    }
    const leafIndex = new DataView(
      data.buffer,
      data.byteOffset + 104,
      8,
    ).getBigUint64(0, true);

    // --- Stage: note-build ---
    await params.callbacks?.pre?.("note-build");
    // v2: the note's single randomness field is a deterministic, recoverable
    // inner_hash derived from (masterSeed, leafIndex) — reuses the existing
    // blinding-factor KDF (the client can regenerate it from its leaf index).
    const innerHash = deriveBlindingFactor(masterSeed, leafIndex);
    const owner = await ownerCommitment(spendingKey, ownerBlinding);
    const innerBytes = bn254ToBE32(innerHash);
    const ownerBytes = bn254ToBE32(owner);

    const commitment = await noteCommitmentV2({
      tokenMint: params.tokenMint,
      amount: params.amount,
      ownerCommitment: owner,
      innerHash,
    });

    // --- Stage: instruction-build ---
    await params.callbacks?.pre?.("instruction-build");
    const tokenMintPk = new PublicKey(params.tokenMint);
    const ix = buildDepositInstruction({
      programId: client.programId,
      depositor: params.depositor,
      tokenMint: tokenMintPk,
      depositorTokenAccount: params.depositorTokenAccount,
      tokenProgramId: params.tokenProgramId ?? TOKEN_PROGRAM_ID,
      amount: params.amount,
      ownerCommitment: ownerBytes,
      innerHash: innerBytes,
    });

    // --- Stage: transaction-send ---
    await params.callbacks?.pre?.("transaction-send");
    const signature = await client.providers.transactionForwarder.sendAndConfirm(
      [ix],
    );
    await params.callbacks?.post?.("transaction-send", signature);

    return {
      signature,
      leafIndex,
      noteCommitment: commitment,
      notePlaintext: {
        tokenMint: params.tokenMint,
        amount: params.amount,
        ownerCommitment: owner,
        innerHash,
      },
    };
  };
}
