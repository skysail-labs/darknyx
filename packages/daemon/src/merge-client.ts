/**
 * createMergeClient — the FULLER SDK `DarkPoolClient` that activates auto-merge.
 *
 * Unlike the deposit-only client, this wires a real Merkle-proof provider
 * ({@link TreeLeavesMerkleProvider}, a `/tree/leaves` snapshot) + a real merge
 * zk-prover ({@link nodeMergeProver}). It returns the client + the provider so
 * the caller can `refresh()` the snapshot immediately before each merge (so the
 * proof's root is recent enough to still be in the program's recent-roots window
 * when the tx lands).
 */

import { Keypair, PublicKey } from "@solana/web3.js";
import { getDarkPoolClient, type DarkPoolClient } from "@nyx/sdk";

import type { Keystore } from "./keystore.js";
import {
  accountInfoProvider,
  connectionProvider,
  createConnection,
  fixedSeedMode,
  keypairForwarder,
} from "./solana-providers.js";
import {
  TreeLeavesMerkleProvider,
  type LeavesFetcher,
} from "./tree-merkle-provider.js";
import { nodeMergeProver, type MergeCircuitArtifacts } from "./merge-prover.js";

export interface MergeClientOptions {
  programId: PublicKey;
  rpcUrl: string;
  payer: Keypair;
  keystore: Keystore;
  artifacts: MergeCircuitArtifacts;
  leavesFetcher: LeavesFetcher;
  treeId?: number;
}

export function createMergeClient(opts: MergeClientOptions): {
  client: DarkPoolClient;
  merkleProvider: TreeLeavesMerkleProvider;
} {
  const connection = createConnection(opts.rpcUrl);
  const merkleProvider = new TreeLeavesMerkleProvider({
    fetcher: opts.leavesFetcher,
    treeId: opts.treeId,
  });
  const client = getDarkPoolClient({
    programId: opts.programId,
    seedMode: fixedSeedMode(opts.keystore.masterSeed),
    connectionProvider: connectionProvider(connection),
    providers: {
      accountInfoProvider: accountInfoProvider(connection),
      transactionForwarder: keypairForwarder(connection, opts.payer),
      merkleProofProvider: merkleProvider,
    },
    zkProver: nodeMergeProver(opts.artifacts),
    ownerCommitmentBlinding: opts.keystore.ownerBlinding,
  });
  return { client, merkleProvider };
}
