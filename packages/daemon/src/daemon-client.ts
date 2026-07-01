/**
 * createDaemonClient — a deposit-capable SDK `DarkPoolClient` for the daemon.
 *
 * Wires the daemon's keystore (seed + owner blinding) + the operator's payer
 * keypair + a Helius connection into the SDK client that backs the daemon's
 * direct on-chain actions.
 *
 * SCOPE: this client is wired for **deposit** only. `getDepositFunction` uses
 * just the connection / account-info / forwarder providers, so the `zkProver`
 * and `merkleProofProvider` are deliberate throwing stubs — MERGE / WITHDRAW
 * need a real merge zk-prover + a leaf-indexed Merkle-proof provider, built +
 * devnet-validated at integration time. Construct a fuller client for those.
 */

import { Keypair, PublicKey } from "@solana/web3.js";
import {
  getDarkPoolClient,
  UnimplementedProverSuite,
  type DarkPoolClient,
  type MerkleProofProvider,
} from "@nyx/sdk";

import type { Keystore } from "./keystore.js";
import {
  accountInfoProvider,
  connectionProvider,
  createConnection,
  fixedSeedMode,
  keypairForwarder,
} from "./solana-providers.js";

/** A throwing Merkle-proof stub — deposit doesn't need inclusion proofs;
 *  merge/withdraw do (build a real leaf-indexed provider for those). */
const STUB_MERKLE: MerkleProofProvider = {
  getInclusionProof() {
    throw new Error(
      "merkleProofProvider not configured on this deposit-only client",
    );
  },
};

export interface DaemonClientOptions {
  programId: PublicKey;
  rpcUrl: string;
  payer: Keypair;
  keystore: Keystore;
}

export function createDaemonClient(opts: DaemonClientOptions): DarkPoolClient {
  const connection = createConnection(opts.rpcUrl);
  return getDarkPoolClient({
    programId: opts.programId,
    seedMode: fixedSeedMode(opts.keystore.masterSeed),
    connectionProvider: connectionProvider(connection),
    providers: {
      accountInfoProvider: accountInfoProvider(connection),
      transactionForwarder: keypairForwarder(connection, opts.payer),
      merkleProofProvider: STUB_MERKLE,
    },
    zkProver: new UnimplementedProverSuite(),
    ownerCommitmentBlinding: opts.keystore.ownerBlinding,
  });
}
