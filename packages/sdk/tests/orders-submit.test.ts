/**
 * Privacy-fix submit_order — TS unit suite.
 *
 * Verifies that:
 *   1. attestation failure aborts before any network IO
 *   2. JWT refresh on 401 retries the send exactly once
 *   3. parameter validation rejects malformed inputs
 *   4. happy path returns the PendingOrder PDA we wrote to
 *   5. each pipeline stage throws DarkPoolError with its own `stage` tag
 *   6. the built ix targets the PendingOrder PDA (not the legacy DarkCLOB)
 *
 * The on-chain half (slot reuse, ConstraintSeeds enforcement, run_batch
 * matching) lives in `programs/matching_engine/tests/`.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Keypair, PublicKey } from "@solana/web3.js";

import { DarkPoolClient } from "../src/client.js";
import { DarkPoolError } from "../src/errors.js";
import { UnimplementedProverSuite } from "../src/zk/prover-suite.js";
import {
  MockPerSessionManager,
  LivePerSessionManager,
} from "../src/per/session-manager.js";
import {
  getOrderSubmitFunction,
  type OrderParams,
} from "../src/orders/submit-order.js";
import { pendingOrderPda } from "../src/idl/matching-engine-client.js";
import type {
  AccountInfoProvider,
  MasterSeedStorage,
  MerkleProofProvider,
  SolanaConnectionProvider,
  TransactionForwarder,
} from "../src/providers.js";
import { startMockTeeServer, type MockTeeServerHandle } from "./mocks/mock-tee-server.js";

const VAULT_PROGRAM_ID = new PublicKey(
  "C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx",
);
const ME_PROGRAM_ID = new PublicKey(
  "6EasFxo6RCWrK4KAwcdUJqL4KjReLC3rtah8EtHgHSqe",
);

function makeAccountInfoProvider(
  statuses: Map<string, { data: Buffer; owner: PublicKey } | null>,
): AccountInfoProvider {
  return {
    getAccountInfo: async (pk: PublicKey) => statuses.get(pk.toBase58()) ?? null,
  };
}

function makeClient(opts: {
  accountInfoStatuses?: Map<string, { data: Buffer; owner: PublicKey } | null>;
  perRpcUrl?: string;
}): DarkPoolClient {
  const conn: SolanaConnectionProvider = {
    connection: {} as never,
    perRpcUrl: opts.perRpcUrl ?? "http://127.0.0.1:65535",
  };
  const storage: MasterSeedStorage = {
    load: async () => new Uint8Array(64),
    store: async () => {},
    generate: async () => new Uint8Array(64),
  };
  const statuses = opts.accountInfoStatuses ?? new Map();
  const providers = {
    accountInfoProvider: makeAccountInfoProvider(statuses),
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
  return client;
}

function makeParams(overrides: Partial<OrderParams> = {}): OrderParams {
  const trading = Keypair.generate().publicKey;
  const market = Keypair.generate().publicKey;
  const noteCommitment = new Uint8Array(32);
  for (let i = 0; i < 32; i++) noteCommitment[i] = i + 1;
  const userCommitment = new Uint8Array(32);
  for (let i = 0; i < 32; i++) userCommitment[i] = 33 + (i % 200);
  const orderId = new Uint8Array(16);
  for (let i = 0; i < 16; i++) orderId[i] = 100 + i;
  return {
    tradingKey: trading,
    market,
    slotIdx: 0,
    userCommitment,
    noteCommitment,
    amount: 10n,
    priceLimit: 110n,
    side: "bid",
    noteAmount: 1_100_000n,
    expirySlot: 100n,
    orderId,
    ...overrides,
  };
}

describe("Privacy-fix submit_order pipeline", () => {
  it("[attestation-failure] throws 'attestation-verify' and sends no tx", async () => {
    const client = makeClient({});
    const session = new MockPerSessionManager();
    session.attestationOk = false;
    const submit = getOrderSubmitFunction({ client }, { perSessionManager: session });
    await expect(submit(makeParams())).rejects.toMatchObject({
      stage: "attestation-verify",
    });
    expect(session.sendCallCount).toBe(0);
    expect(session.tokenFetchCount).toBe(0);
  });

  it("[parameter-validation] rejects zero amount", async () => {
    const client = makeClient({});
    const session = new MockPerSessionManager();
    const submit = getOrderSubmitFunction({ client }, { perSessionManager: session });
    await expect(submit(makeParams({ amount: 0n }))).rejects.toMatchObject({
      stage: "parameter",
    });
  });

  it("[parameter-validation] rejects out-of-range slotIdx", async () => {
    const client = makeClient({});
    const session = new MockPerSessionManager();
    const submit = getOrderSubmitFunction({ client }, { perSessionManager: session });
    await expect(submit(makeParams({ slotIdx: 99 }))).rejects.toMatchObject({
      stage: "parameter",
    });
  });

  it("[parameter-validation] rejects 16-byte orderId of wrong length", async () => {
    const client = makeClient({});
    const session = new MockPerSessionManager();
    const submit = getOrderSubmitFunction({ client }, { perSessionManager: session });
    await expect(
      submit(makeParams({ orderId: new Uint8Array(8) })),
    ).rejects.toMatchObject({ stage: "parameter" });
  });

  it("[happy-path] receipt contains the PendingOrder PDA we wrote to", async () => {
    const client = makeClient({});
    const session = new MockPerSessionManager("happy_sig_ok");
    const submit = getOrderSubmitFunction({ client }, { perSessionManager: session });
    const params = makeParams();
    const receipt = await submit(params);
    expect(receipt.signature).toBe("happy_sig_ok");
    expect(receipt.pendingOrderPda).toBeInstanceOf(PublicKey);
    const [expected] = pendingOrderPda(
      ME_PROGRAM_ID,
      params.market,
      params.tradingKey,
      params.slotIdx,
    );
    expect(receipt.pendingOrderPda.toBase58()).toBe(expected.toBase58());
    expect(session.sendCallCount).toBe(1);
    expect(session.lastJwt).toBe("mock_jwt_ok");
  });

  it("[jwt-refresh-on-401] session manager refreshes once and the order succeeds on retry", async () => {
    const client = makeClient({});
    const session = new MockPerSessionManager("retry_sig_ok");
    session.injectNext401 = true;
    const submit = getOrderSubmitFunction({ client }, { perSessionManager: session });
    const receipt = await submit(makeParams());
    expect(receipt.signature).toBe("retry_sig_ok");
    expect(session.tokenFetchCount).toBeGreaterThanOrEqual(2);
    expect(session.lastJwt).not.toBe("mock_jwt_ok");
    expect(session.sendCallCount).toBe(2);
  });

  it("[staged-errors] each stage throws DarkPoolError with its own `stage` tag", async () => {
    const client = makeClient({});

    // Stage 1: attestation
    const s1 = new MockPerSessionManager();
    s1.attestationOk = false;
    const f1 = getOrderSubmitFunction({ client }, { perSessionManager: s1 });
    await expect(f1(makeParams())).rejects.toMatchObject({ stage: "attestation-verify" });

    // Stage 2: auth-token-fetch
    const s2 = new MockPerSessionManager();
    s2.getToken = async () => {
      throw new DarkPoolError("auth-token-fetch", "mock");
    };
    const f2 = getOrderSubmitFunction({ client }, { perSessionManager: s2 });
    await expect(f2(makeParams())).rejects.toMatchObject({ stage: "auth-token-fetch" });

    // Stage 5: transaction-send (non-401, non-retryable)
    const s5 = new MockPerSessionManager();
    s5.injectNextFailure = new DarkPoolError("transaction-send", "rpc-5xx");
    const f5 = getOrderSubmitFunction({ client }, { perSessionManager: s5 });
    await expect(f5(makeParams())).rejects.toMatchObject({ stage: "transaction-send" });
  });

  it("[ix-targets-pending-order] the built ix lists exactly [trading_key, pendingOrderPda]", async () => {
    const client = makeClient({});
    const session = new MockPerSessionManager("ok_sig");
    const submit = getOrderSubmitFunction({ client }, { perSessionManager: session });
    const params = makeParams();
    const receipt = await submit(params);
    expect(session.lastIx).not.toBeNull();
    const ix = session.lastIx!;
    expect(ix.keys).toHaveLength(2);
    expect(ix.keys[0].pubkey.toBase58()).toBe(params.tradingKey.toBase58());
    expect(ix.keys[0].isSigner).toBe(true);
    expect(ix.keys[1].pubkey.toBase58()).toBe(receipt.pendingOrderPda.toBase58());
    expect(ix.keys[1].isWritable).toBe(true);
  });
});

describe("LivePerSessionManager + mock TEE HTTP", () => {
  let tee: MockTeeServerHandle;
  beforeAll(async () => {
    tee = await startMockTeeServer();
  });
  afterAll(async () => {
    await tee.close();
  });

  it("[invalid-jwt] tampered JWT yields 401 from the TEE", async () => {
    const kp = Keypair.generate();
    const traderPubkey = kp.publicKey.toBytes();
    const nacl = await import("tweetnacl").catch(() => null as unknown as {
      sign: { detached: (m: Uint8Array, sk: Uint8Array) => Uint8Array };
    });
    const mgr = new LivePerSessionManager({
      perRpcUrl: tee.url,
      traderPubkey,
      signNonce: async (nonce) => {
        if (nacl) {
          return nacl.sign.detached(nonce, kp.secretKey);
        }
        return new Uint8Array(64);
      },
    });

    const attestOk = await mgr.verifyAttestation();
    expect(attestOk).toBe(true);
    const jwt = await mgr.getToken();
    expect(jwt).toMatch(/\./);

    const tamperedJwt = jwt.split(".")[0] + ".AAAA";
    const dummyIx = {
      keys: [],
      programId: VAULT_PROGRAM_ID,
      data: Buffer.from([0]),
    };
    await expect(
      mgr.sendInstruction(
        dummyIx as never,
        tamperedJwt,
        { traderPubkey },
      ),
    ).rejects.toMatchObject({ stage: "auth-token-fetch" });
  });

  it("[attestation-via-http] verifier returns false when server disables attestation", async () => {
    const kp = Keypair.generate();
    tee.setAttestationOk(false);
    const mgr = new LivePerSessionManager({
      perRpcUrl: tee.url,
      traderPubkey: kp.publicKey.toBytes(),
      signNonce: async () => new Uint8Array(64),
    });
    const ok = await mgr.verifyAttestation();
    expect(ok).toBe(false);
    tee.setAttestationOk(true);
  });
});
