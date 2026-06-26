import { createHash } from "node:crypto";

import {
  getDarkPoolClient,
  UnimplementedProverSuite,
  type DarkPoolClient,
} from "@nyx/sdk";
import {
  Connection,
  Keypair,
  sendAndConfirmTransaction,
  Transaction,
} from "@solana/web3.js";

/** Deterministic darkpool seed per demo persona — mirrors `live-er-flow/route.ts`. */
export function actorSeed(role: "taker" | "maker", kp: Keypair): Uint8Array {
  const h1 = createHash("sha256")
    .update(`demo-${role}-seed-v1`)
    .update(kp.publicKey.toBytes())
    .digest();
  const h2 = createHash("sha256")
    .update(`demo-${role}-seed-v2`)
    .update(kp.publicKey.toBytes())
    .digest();
  return new Uint8Array(Buffer.concat([h1, h2]));
}

export function makePersonaDarkPoolClient(
  connection: Connection,
  erRpcUrl: string,
  vaultProgramId: import("@solana/web3.js").PublicKey,
  meProgramId: import("@solana/web3.js").PublicKey,
  signer: Keypair,
  role: "taker" | "maker",
): DarkPoolClient {
  const seed = actorSeed(role, signer);
  const storage = {
    load: async () => seed,
    store: async () => undefined,
    generate: async () => seed,
  };
  return getDarkPoolClient({
    programId: vaultProgramId,
    matchingEngineProgramId: meProgramId,
    seedMode: { type: "csprng", storage },
    connectionProvider: { connection, perRpcUrl: erRpcUrl },
    providers: {
      accountInfoProvider: {
        getAccountInfo: async (pubkey) => {
          const account = await connection.getAccountInfo(pubkey, "confirmed");
          if (!account) return null;
          return { data: account.data, owner: account.owner };
        },
      },
      transactionForwarder: {
        sendAndConfirm: async (txOrIxs) => {
          const tx = Array.isArray(txOrIxs)
            ? new Transaction().add(...txOrIxs)
            : txOrIxs;
          return sendAndConfirmTransaction(connection, tx, [signer], {
            commitment: "confirmed",
          });
        },
      },
      merkleProofProvider: {
        getInclusionProof: async () => {
          throw new Error("merkleProofProvider not used for persona deposit");
        },
      },
    },
    zkProver: new UnimplementedProverSuite("not needed for deposit"),
    ownerCommitmentBlinding: role === "taker" ? BigInt(1111) : BigInt(2222),
  });
}
