/**
 * Phase 4 TS glue — cancel_order SDK flow.
 *
 * The on-chain status-flip is covered in
 * programs/matching_engine/tests/run_batch.rs. These tests cover the SDK
 * pipeline around it: parameter validation, attestation gating, and the
 * transaction-send → JWT-refresh → retry path matching submit-order.
 */

import { describe, expect, it } from "vitest";
import { Keypair, PublicKey } from "@solana/web3.js";

import { DarkPoolClient, type NoteStatusInfo } from "../src/client.js";
import { DarkPoolError } from "../src/errors.js";
import { UnimplementedProverSuite } from "../src/zk/prover-suite.js";
import { MockPerSessionManager } from "../src/per/session-manager.js";
import {
  getOrderCancelFunction,
  type CancelOrderParams,
} from "../src/orders/cancel-order.js";
import { buildCancelOrderInstruction } from "../src/idl/matching-engine-client.js";
import type {
  AccountInfoProvider,
  MasterSeedStorage,
  MerkleProofProvider,
  SolanaConnectionProvider,
  TransactionForwarder,
} from "../src/providers.js";

const VAULT_PROGRAM_ID = new PublicKey(
  "C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx",
);
const ME_PROGRAM_ID = new PublicKey(
  "6EasFxo6RCWrK4KAwcdUJqL4KjReLC3rtah8EtHgHSqe",
);

function makeClient(opts: { noteStatus?: NoteStatusInfo } = {}): DarkPoolClient {
  const conn: SolanaConnectionProvider = {
    connection: {} as never,
    perRpcUrl: "http://127.0.0.1:65535",
  };
  const storage: MasterSeedStorage = {
    load: async () => new Uint8Array(64),
    store: async () => {},
    generate: async () => new Uint8Array(64),
  };
  const providers = {
    accountInfoProvider: {
      getAccountInfo: async () => null,
    } as AccountInfoProvider,
    transactionForwarder: {
      sendAndConfirm: async () => "unused",
    } as TransactionForwarder,
    merkleProofProvider: {
      getInclusionProof: async () => ({
        root: new Uint8Array(32),
        siblings: [],
        pathIndices: [],
      }),
    } as MerkleProofProvider,
  };
  const client = new DarkPoolClient({
    programId: VAULT_PROGRAM_ID,
    matchingEngineProgramId: ME_PROGRAM_ID,
    seedMode: { type: "csprng", storage },
    connectionProvider: conn,
    providers,
    zkProver: new UnimplementedProverSuite(),
    ownerCommitmentBlinding: 0n,
  });
  if (opts.noteStatus) {
    client.getNoteStatus = async (): Promise<NoteStatusInfo> =>
      opts.noteStatus as NoteStatusInfo;
  }
  return client;
}

function makeCancelParams(
  overrides: Partial<CancelOrderParams> = {},
): CancelOrderParams {
  return {
    tradingKey: Keypair.generate().publicKey,
    market: Keypair.generate().publicKey,
    slotIdx: 0,
    ...overrides,
  };
}

describe("Privacy-fix — getOrderCancelFunction", () => {
  it("[cancel_param_slotidx_range] rejects out-of-range slotIdx", async () => {
    const client = makeClient();
    const session = new MockPerSessionManager();
    const fn = getOrderCancelFunction({ client }, { perSessionManager: session });
    await expect(
      fn(makeCancelParams({ slotIdx: -1 })),
    ).rejects.toMatchObject({ stage: "parameter" });
    expect(session.sendCallCount).toBe(0);
  });

  it("[cancel_attestation_failure_aborts] attestation failure blocks send", async () => {
    const client = makeClient();
    const session = new MockPerSessionManager();
    session.attestationOk = false;
    const fn = getOrderCancelFunction({ client }, { perSessionManager: session });
    await expect(fn(makeCancelParams())).rejects.toMatchObject({
      stage: "attestation-verify",
    });
    expect(session.sendCallCount).toBe(0);
    expect(session.tokenFetchCount).toBe(0);
  });

  it("[cancel_happy_path] returns a signature and sends exactly one ix", async () => {
    const client = makeClient();
    const session = new MockPerSessionManager("cancel_sig_ok");
    const fn = getOrderCancelFunction({ client }, { perSessionManager: session });
    const receipt = await fn(makeCancelParams());
    expect(receipt.signature).toBe("cancel_sig_ok");
    expect(session.sendCallCount).toBe(1);
    // The built ix targets the matching_engine program id.
    expect(session.lastIx?.programId.toBase58()).toBe(ME_PROGRAM_ID.toBase58());
  });

  it("[cancel_jwt_refresh_on_401] 401 triggers token refresh and retry", async () => {
    const client = makeClient();
    const session = new MockPerSessionManager("cancel_retry_sig");
    session.injectNext401 = true;
    const fn = getOrderCancelFunction({ client }, { perSessionManager: session });
    const receipt = await fn(makeCancelParams());
    expect(receipt.signature).toBe("cancel_retry_sig");
    expect(session.tokenFetchCount).toBeGreaterThanOrEqual(2);
    expect(session.sendCallCount).toBe(2);
  });

  it("[cancel_ix_layout] cancel_order ix carries discriminator + market + slot_idx", () => {
    const market = Keypair.generate().publicKey;
    const ix = buildCancelOrderInstruction({
      programId: ME_PROGRAM_ID,
      tradingKey: Keypair.generate().publicKey,
      market,
      slotIdx: 2,
    });
    // 8 (disc) + 32 (market) + 1 (slot_idx) = 41 bytes.
    expect(ix.data.length).toBe(41);
    expect(ix.data.subarray(8, 40).equals(market.toBuffer())).toBe(true);
    expect(ix.data[40]).toBe(2);
    // Accounts: signer + pending_order PDA. 2 keys.
    expect(ix.keys.length).toBe(2);
    expect(ix.keys[0].isSigner).toBe(true);
    expect(ix.keys[1].isWritable).toBe(true);
  });

  it("[cancel_ignores_note_status] cancel never queries note_lock status (lock stays until expiry)", async () => {
    // Even if the note shows "locked" we must let cancel through — the lock
    // is INTENTIONAL and cancellation does not release it.
    const client = makeClient({ noteStatus: { status: "locked" } });
    const session = new MockPerSessionManager("cancel_sig");
    const fn = getOrderCancelFunction({ client }, { perSessionManager: session });
    const r = await fn(makeCancelParams());
    expect(r.signature).toBe("cancel_sig");
  });
});
