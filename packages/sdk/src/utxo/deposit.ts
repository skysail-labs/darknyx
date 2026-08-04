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
import { bn254ToBE32, deriveBlindingFactor,
  deriveNoteSecret,
} from "../keys/key-generators.js";
import { assertPublicInputs } from "../zk/assert-public-inputs.js";
import { buildDepositInstruction, merkleTreePda } from "../idl/vault-client.js";
import { readNoteCreatedLeafIndex } from "./leaf-index.js";
import { deriveDepositInnerHash } from "./deposit-inner.js";
import { pubkeyToFrPair } from "./note.js";

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
  /** Client-side nonce index. It derives a pseudorandom public recovery nonce;
   *  the proof derives the hidden inner hash from that nonce + hidden owner. */
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
  treeId: number;
  leafIndex: bigint;
  noteCommitment: Uint8Array;
  notePlaintext: {
    tokenMint: Uint8Array;
    amount: bigint;
    ownerCommitment: bigint;
    /** Poseidon3(27, ownerCommitment, recoveryNonce). */
    innerHash: bigint;
    recoveryNonce: bigint;
  };
}

/**
 * Convert a deposit receipt into a storable wallet note. Call
 * `store.put(depositNoteFromReceipt(receipt))` after a deposit so the wallet's
 * balance + coin-selection see it immediately. A replacement device can also
 * reconstruct it from seed + finalized deposit instruction/event through
 * `recoverNotesFromChain`.
 */
export function depositNoteFromReceipt(receipt: DepositReceipt): StoredNote {
  return {
    commitment: Buffer.from(receipt.noteCommitment).toString("hex"),
    tokenMint: receipt.notePlaintext.tokenMint,
    amount: receipt.notePlaintext.amount,
    ownerCommitment: receipt.notePlaintext.ownerCommitment,
    innerHash: receipt.notePlaintext.innerHash,
    leafIndex: receipt.leafIndex,
    treeId: receipt.treeId,
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
    const recoveryNonce = deriveBlindingFactor(
      masterSeed,
      params.depositIndex,
    );
    const owner = await ownerCommitment(spendingKey, ownerBlinding);
    const ownerBytes = bn254ToBE32(owner);
    const recoveryNonceBytes = bn254ToBE32(recoveryNonce);
    // The per-note secret is keyed on the PUBLIC recovery nonce, so cold
    // recovery re-derives it from seed + chain with nothing extra persisted.
    // It is what stops the inner — and the note-use tag derived from it — being
    // a function of on-chain data plus one wallet-wide owner commitment.
    const noteSecretBytes = bn254ToBE32(
      deriveNoteSecret(masterSeed, recoveryNonceBytes),
    );
    const innerBytes = await deriveDepositInnerHash(
      ownerBytes,
      recoveryNonceBytes,
      noteSecretBytes,
    );
    const innerHash = bytesToBigIntBE(innerBytes);

    const commitment = await noteCommitmentV2({
      tokenMint: params.tokenMint,
      amount: params.amount,
      ownerCommitment: owner,
      innerHash,
    });

    // --- Stage: proof-generation ---
    await params.callbacks?.pre?.("proof-generation");
    let proof;
    try {
      const [mintLo, mintHi] = pubkeyToFrPair(params.tokenMint);
      proof = await client.zkProver.deposit.prove({
        noteCommitment: bytesToBigIntBE(commitment),
        tokenMint: [mintLo, mintHi],
        amount: params.amount,
        recoveryNonce,
        spendingKey,
        ownerCommitmentBlinding: ownerBlinding,
        noteSecret: bytesToBigIntBE(noteSecretBytes),
      });
      const expectedPublic = [
        commitment,
        bn254ToBE32(mintLo),
        bn254ToBE32(mintHi),
        bn254ToBE32(params.amount),
        recoveryNonceBytes,
      ];
      assertPublicInputs("VALID_DEPOSIT", proof.publicInputs, expectedPublic);
    } catch (e) {
      throw new DarkPoolError("proof-generation", (e as Error).message, e);
    }

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
      noteCommitment: commitment,
      recoveryNonce: recoveryNonceBytes,
      proof: { piA: proof.piA, piB: proof.piB, piC: proof.piC },
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
      client.programId,
    );

    return {
      signature,
      treeId,
      leafIndex,
      noteCommitment: commitment,
      notePlaintext: {
        tokenMint: params.tokenMint,
        amount: params.amount,
        ownerCommitment: owner,
        innerHash,
        recoveryNonce,
      },
    };
  };
}

function bytesToBigIntBE(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((value, index) => value === b[index]);
}
