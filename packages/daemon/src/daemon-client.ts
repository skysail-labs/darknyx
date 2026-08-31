/**
 * createDaemonClient — a deposit-capable SDK `DarkPoolClient` for the daemon.
 *
 * Wires the daemon's keystore (seed-derived spending/recovery keys) + the operator's payer
 * keypair + a configured Solana connection into the SDK client that backs the daemon's
 * direct on-chain actions.
 *
 * SCOPE: this client is wired for **deposit** only. Deposits generate a real
 * VALID_DEPOSIT proof locally; MERGE / WITHDRAW retain throwing prover and
 * Merkle-path stubs. Construct a fuller client for those actions.
 */

import { Keypair, PublicKey } from "@solana/web3.js";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  getDarkPoolClient,
  nodeValidDepositProver,
  UnimplementedProverSuite,
  type DarkPoolClient,
  type MerkleProofProvider,
  type ValidDepositArtifacts,
} from "@darknyx/sdk";

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
  depositArtifacts?: ValidDepositArtifacts;
}

export function createDaemonClient(opts: DaemonClientOptions): DarkPoolClient {
  const connection = createConnection(opts.rpcUrl);
  const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
  const circuitsDir =
    process.env.DARKNYX_DAEMON_CIRCUITS_DIR ??
    resolve(repoRoot, "circuits/build");
  const stubs = new UnimplementedProverSuite("deposit-only daemon client");
  const deposit = nodeValidDepositProver(
    opts.depositArtifacts ?? {
      wasmPath: resolve(circuitsDir, "valid_deposit/circuit_js/circuit.wasm"),
      zkeyPath: resolve(circuitsDir, "valid_deposit/circuit_final.zkey"),
    },
  );
  return getDarkPoolClient({
    programId: opts.programId,
    seedMode: fixedSeedMode(opts.keystore.masterSeed),
    connectionProvider: connectionProvider(connection),
    providers: {
      accountInfoProvider: accountInfoProvider(connection),
      transactionForwarder: keypairForwarder(connection, opts.payer),
      merkleProofProvider: STUB_MERKLE,
    },
    zkProver: {
      deposit,
      spend: stubs.spend,
      merge: stubs.merge,
    },
  });
}
