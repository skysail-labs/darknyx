/**
 * getWithdrawFunction — factory-function pattern (Section 23.3.2).
 *
 * Pulls a Merkle inclusion proof for the caller's note, invokes the injected
 * ZK prover to produce a VALID_SPEND proof, builds the on-chain `withdraw`
 * instruction, and submits it via the injected transaction forwarder.
 */

import { PublicKey } from "@solana/web3.js";

import type { DarkPoolClient } from "../client.js";
import type { TransactionCallbacks } from "../providers.js";
import { DarkPoolError } from "../errors.js";
import { noteCommitmentV2, nullifierV2 as computeNullifierV2 } from "./note.js";
import { buildWithdrawInstruction } from "../idl/vault-client.js";

/** SPL Token program id (classic). */
const TOKEN_PROGRAM_ID = new PublicKey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");

export interface WithdrawParams {
  /** Fee-payer / signer for the withdraw transaction. */
  payer: PublicKey;
  /** Which Merkle-tree shard the spent note lives in (default 0). */
  treeId?: number;
  tokenMint: Uint8Array;
  amount: bigint;
  /** Destination SPL token account (must match `tokenMint`). */
  destinationTokenAccount: PublicKey;
  /** The note's plaintext (stored locally by the user). */
  notePlaintext: {
    tokenMint: Uint8Array;
    amount: bigint;
    ownerCommitment: bigint;
    /** v2: single inner_hash replacing the old (nonce, blindingR) pair. */
    innerHash: bigint;
  };
  /** Merkle leaf index of the note. */
  leafIndex: bigint;
  tokenProgramId?: PublicKey;
  callbacks?: TransactionCallbacks;
}

export interface WithdrawReceipt {
  signature: string;
  nullifier: Uint8Array;
  merkleRoot: Uint8Array;
}

function uint8ArrayToBigIntBE(x: Uint8Array): bigint {
  let acc = 0n;
  for (const b of x) acc = (acc << 8n) | BigInt(b);
  return acc;
}

function pubkeyPairBE(pk: Uint8Array): [bigint, bigint] {
  // Match Rust `pubkey_to_fr_pair`: hi = first 16 bytes BE, lo = last 16 bytes BE.
  if (pk.length !== 32) throw new Error("pubkey must be 32 bytes");
  let hi = 0n;
  for (let i = 0; i < 16; i++) hi = (hi << 8n) | BigInt(pk[i]);
  let lo = 0n;
  for (let i = 16; i < 32; i++) lo = (lo << 8n) | BigInt(pk[i]);
  return [lo, hi];
}

export function getWithdrawFunction(
  { client }: { client: DarkPoolClient },
): (params: WithdrawParams) => Promise<WithdrawReceipt> {
  return async (params) => {
    if (params.amount <= 0n) {
      throw new DarkPoolError("parameter", "withdraw amount must be > 0");
    }
    if (params.amount !== params.notePlaintext.amount) {
      throw new DarkPoolError(
        "parameter",
        "withdraw amount must equal the note's plaintext amount (no partial withdrawals)",
      );
    }
    // The commitment hashes `notePlaintext.tokenMint` but the prover inputs +
    // the on-chain instruction use `params.tokenMint`; a mismatch would make
    // the proof reconstruct a different note than the one being spent. Pin
    // them to a single canonical mint here.
    if (Buffer.compare(Buffer.from(params.tokenMint), Buffer.from(params.notePlaintext.tokenMint)) !== 0) {
      throw new DarkPoolError(
        "parameter",
        "params.tokenMint must equal notePlaintext.tokenMint",
      );
    }

    const { spendingKey } = await client.getResolvedKeys();

    // --- Stage: merkle-proof-fetch ---
    await params.callbacks?.pre?.("merkle-proof-fetch");
    let mProof;
    try {
      mProof = await client.providers.merkleProofProvider.getInclusionProof(
        params.leafIndex,
      );
    } catch (e) {
      throw new DarkPoolError("merkle-proof-fetch", (e as Error).message, e);
    }
    if (mProof.siblings.length !== 20 || mProof.pathIndices.length !== 20) {
      throw new DarkPoolError(
        "merkle-proof-fetch",
        `expected 20-level Merkle path, got ${mProof.siblings.length} siblings`,
      );
    }

    // --- Stage: note-build ---
    await params.callbacks?.pre?.("note-build");
    const commitment = await noteCommitmentV2(params.notePlaintext);
    const nullifierBytes = await computeNullifierV2(spendingKey, params.notePlaintext.innerHash);

    // --- Stage: proof-generation (delegated to injected prover) ---
    await params.callbacks?.pre?.("proof-generation");
    const { ownerBlinding } = await client.getResolvedKeys();
    let proof;
    try {
      const [mintLo, mintHi] = pubkeyPairBE(params.tokenMint);
      proof = await client.zkProver.spend.prove({
        merkleRoot: uint8ArrayToBigIntBE(mProof.root),
        nullifier: uint8ArrayToBigIntBE(nullifierBytes),
        tokenMint: [mintLo, mintHi],
        amount: params.amount,
        spendingKey,
        ownerCommitmentBlinding: ownerBlinding,
        innerHash: params.notePlaintext.innerHash,
        merklePath: mProof.siblings.map(uint8ArrayToBigIntBE),
        merkleIndices: mProof.pathIndices,
      });
    } catch (e) {
      throw new DarkPoolError("proof-generation", (e as Error).message, e);
    }

    // --- Stage: instruction-build ---
    await params.callbacks?.pre?.("instruction-build");
    const tokenMintPk = new PublicKey(params.tokenMint);
    const ix = buildWithdrawInstruction({
      programId: client.programId,
      treeId: params.treeId ?? 0,
      payer: params.payer,
      tokenMint: tokenMintPk,
      destinationTokenAccount: params.destinationTokenAccount,
      tokenProgramId: params.tokenProgramId ?? TOKEN_PROGRAM_ID,
      noteCommitment: commitment,
      nullifier: nullifierBytes,
      merkleRoot: mProof.root,
      amount: params.amount,
      proof: {
        piA: proof.piA,
        piB: proof.piB,
        piC: proof.piC,
      },
    });

    // --- Stage: transaction-send ---
    await params.callbacks?.pre?.("transaction-send");
    let signature;
    try {
      signature = await client.providers.transactionForwarder.sendAndConfirm([ix]);
    } catch (e) {
      throw new DarkPoolError("transaction-send", (e as Error).message, e);
    }
    await params.callbacks?.post?.("transaction-send", signature);

    return {
      signature,
      nullifier: nullifierBytes,
      merkleRoot: mProof.root,
    };
  };
}
