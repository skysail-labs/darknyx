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
import { buildDepositInstruction, merkleTreePda } from "../idl/vault-client.js";
import { readNoteCreatedLeafIndex } from "./leaf-index.js";

/** SPL Token program id (classic, not Token-2022). */
const TOKEN_PROGRAM_ID = new PublicKey(
  "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
);

export interface DepositParams {
  /** Fee-payer / signer for the deposit transaction. */
  depositor: PublicKey;
  /** Which Merkle-tree shard to deposit into (default 0). The note's actual
   *  leaf index is read back from the deposit's `NoteCreated` event. */
  treeId?: number;
  /** Client-side monotonic counter that seeds this note's `inner_hash`
   *  (`deriveBlindingFactor(seed, depositIndex)`) — INDEPENDENT of the leaf
   *  position, so a concurrent on-chain append can't desync the opening from
   *  where the leaf lands. Recover the note by commitment, not by index. The
   *  caller owns the counter; merge outputs no longer use counters. */
  depositIndex: bigint;
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
    /** v2: single inner_hash (deterministic from masterSeed + depositIndex). */
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

export function getDepositFunction({
  client,
}: {
  client: DarkPoolClient;
}): (params: DepositParams) => Promise<DepositReceipt> {
  return async (params) => {
    if (params.amount <= 0n) {
      throw new DarkPoolError("parameter", "deposit amount must be > 0");
    }
    if (params.tokenMint.length !== 32) {
      throw new DarkPoolError("parameter", "tokenMint must be 32 bytes");
    }

    const { masterSeed, spendingKey, ownerBlinding } =
      await client.getResolvedKeys();
    const treeId = params.treeId ?? 0;

    // --- Stage: merkle-position-fetch ---
    await params.callbacks?.pre?.("merkle-position-fetch");
    // Guard: the target shard must be initialised (the deposit ix appends to
    // its MerkleTree account). We no longer read leaf_count to PREDICT the
    // index — the actual index is read back from the NoteCreated event after
    // confirm, which is immune to concurrent appends.
    const [treePda] = merkleTreePda(client.programId, treeId);
    const info =
      await client.providers.accountInfoProvider.getAccountInfo(treePda);
    if (!info) {
      throw new DarkPoolError(
        "merkle-position-fetch",
        `merkle_tree shard ${treeId} not initialised — run initialize_tree(${treeId}) first`,
      );
    }

    // --- Stage: note-build ---
    await params.callbacks?.pre?.("note-build");
    // The note's inner_hash is derived from a client-side `depositIndex`,
    // NOT the leaf position — so the opening stays recoverable (by commitment)
    // regardless of where the leaf actually lands. See DepositParams.depositIndex.
    const innerHash = deriveBlindingFactor(masterSeed, params.depositIndex);
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
      treeId,
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
    const signature =
      await client.providers.transactionForwarder.sendAndConfirm([ix]);
    await params.callbacks?.post?.("transaction-send", signature);

    // Read the ACTUAL leaf index from the confirmed tx's NoteCreated event —
    // race-proof against appends that landed between build and execution.
    const leafIndex = await readNoteCreatedLeafIndex(
      client.connectionProvider.connection,
      signature,
    );

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
