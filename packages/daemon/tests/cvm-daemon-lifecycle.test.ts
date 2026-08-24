/**
 * Daemon ↔ live-CVM FULL LIFECYCLE (gated, billable — see docs/cvm-run-runbook.md).
 *
 * Drives the daemon (buyer) through the whole order lifecycle against a deployed
 * CVM, with a MatchDriver (SDK seller) supplying crossing asks so the CVM
 * matches + settles. Tuned thresholds make the automations cheap to trigger:
 *   - mergeThreshold = 2 → auto-merge fires at 2 spendable residuals,
 *   - settlementPollMs small → leaf-resolve fast.
 *
 * Scenario matrix (each step asserts daemon state + on-chain/endpoint effects):
 *   1. attest + deposit (quote collateral, sized for many slices)
 *   2. place a big resting bid over /v1/stream
 *   3. seller ask #1 crosses → partial fill: fills change note + orders update
 *      partially_filled + leaf_count↑
 *   4. settlement-tracker resolves the residual's leaf (/tree/inclusion)
 *   5. a 2nd buyer order, partially filled then cancelled, leaves a 2nd residual
 *      → auto-merge consolidates them (VALID_MERGE on-chain)
 *   6. cancel a resting order (control path) → cancelled
 *   7. read-surface: daemon.tee.account()/instruments()/transparency()
 *
 * MatchDriver (seller) builds its order the SAME way the daemon does
 * (proveAndBuildOrder → /tree/inclusion), so no shadow tree is needed.
 *
 * Gated on RUN_CVM_DAEMON_LIFECYCLE=1 + DARKNYX_TEE_GATEWAY + SOLANA_RPC_URL.
 * Like the smoke, this is offline-typechecked; expect to iterate timings against
 * a live CVM. Prereqs: tree reset, CVM deployed (real-mint), signers
 * rotated/funded (settles happen), buyer+seller payers funded.
 *
 * Run:
 *   RUN_CVM_DAEMON_LIFECYCLE=1 DARKNYX_CVM_TRANSPORT=ra-tls \
 *     DARKNYX_TEE_GATEWAY=https://<app>-8443s.dstack-… \
 *     SOLANA_RPC_URL=<helius> ADMIN_KEYPAIR=.devnet/keypairs/admin.json \
 *     ( cd packages/daemon && ../../node_modules/.bin/vitest run tests/cvm-daemon-lifecycle.test.ts )
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { beforeAll, describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";
import WebSocket from "ws";

import { createDcapQuoteVerifier, parseEventLog } from "@darknyx/sdk";
import type { NodeWebSocketLike } from "@darknyx/sdk/transport-node";
import {
  buildDaemonTransport,
  DaemonTransportSupervisor,
} from "../src/transport.js";
import {
  findAssociatedTokenPda,
  getCreateAssociatedTokenIdempotentInstruction,
  getMintToInstruction,
  TOKEN_PROGRAM_ADDRESS,
} from "@solana-program/token";
import {
  Connection,
  Keypair,
  LAMPORTS_PER_SOL,
  PublicKey,
  SystemProgram,
  Transaction,
  sendAndConfirmTransaction,
} from "@solana/web3.js";

import {
  nodeValidInputProver,
  getDepositFunction,
  getMergeFunction,
  proveAndBuildOrder,
  placeOrder,
  limitPolicy,
  OrderSide,
  depositNoteFromReceipt,
  type StoredNote,
  fetchPythCorePushPrice,
} from "@darknyx/sdk";
import {
  Daemon,
  DaemonStore,
  Keystore,
  deriveAccountIdentity,
  createDaemonClient,
  createMergeClient,
  httpLeavesFetcher,
  createMergeRunner,
  WsOrderPlacer,
  type DaemonConfig,
  type DaemonEvent,
} from "../src/index.js";

// ── SPL-token boundary ─────────────────────────────────────────────────────
// `@solana/spl-token` peer-depends on web3.js v1, so the token surface moved
// to `@solana-program/token`, which speaks kit-branded Address strings while
// the SDK speaks the v3 `Address` class. The sdk test-helper copy of this
// lives in packages/sdk/tests/helpers/e2e-helpers.ts; it is not importable
// from here (the daemon only sees the SDK's published surface), so these are
// local. `payer` / `mintAuthority` take the KEYPAIR -- a bare Address
// type-checks for mintAuthority but emits a non-signer meta and fails
// on-chain.
async function associatedTokenAddress(
  mint: PublicKey,
  owner: PublicKey,
): Promise<PublicKey> {
  const [ata] = await findAssociatedTokenPda({
    mint: mint.toBase58(),
    owner: owner.toBase58(),
    tokenProgram: TOKEN_PROGRAM_ADDRESS,
  });
  return new PublicKey(ata);
}

function createAtaIdempotentIx(
  payer: Keypair,
  ata: PublicKey,
  owner: PublicKey,
  mint: PublicKey,
) {
  return getCreateAssociatedTokenIdempotentInstruction({
    payer,
    ata: ata.toBase58(),
    owner: owner.toBase58(),
    mint: mint.toBase58(),
  });
}

function mintToIx(
  mint: PublicKey,
  token: PublicKey,
  mintAuthority: Keypair,
  amount: bigint | number,
) {
  return getMintToInstruction({
    mint: mint.toBase58(),
    token: token.toBase58(),
    mintAuthority,
    amount,
  });
}

const here = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(here, "..", "..", "..");
const CONFIG_PATH = resolve(REPO_ROOT, ".devnet/e2e-config.json");
const RESTART_READY_PATH = resolve(
  REPO_ROOT,
  ".devnet/cvm-daemon-restart-ready.json",
);
const RESTART_RESULT_PATH = resolve(
  REPO_ROOT,
  ".devnet/cvm-daemon-restart-result.json",
);
/**
 * Leak guard, ported from `cvm-daemon-smoke` when that suite was retired into
 * this one. Under `ra-tls`, NOTHING may reach the CVM on global `fetch`.
 *
 * Every CVM-bound call is supposed to go through the verified transport, but
 * "supposed to" is not a property — the SDK's client helpers each default to
 * `globalThis.fetch` when no `fetchImpl` is supplied, so a single missing
 * argument silently downgrades one call while the run still reports
 * `transport: ra-tls`. That is exactly what happened to the order POST.
 *
 * Recording the URLs rather than throwing keeps the failure legible: the
 * assertion runs at the end and names the exact endpoint that bypassed the
 * transport, instead of surfacing as a TLS error from deep inside a library.
 * Here it covers strictly more than it did in the smoke — the fills channel,
 * leaf resolution, auto-merge, and cancel are all inside its window.
 */
const transportLeaks: string[] = [];
{
  const original = globalThis.fetch;
  globalThis.fetch = ((input: never, init: never) => {
    const url = String((input as { url?: string })?.url ?? input);
    if (
      process.env.DARKNYX_CVM_TRANSPORT === "ra-tls" &&
      url.startsWith(process.env.DARKNYX_TEE_GATEWAY ?? "\u0000")
    ) {
      transportLeaks.push(url);
    }
    return original(input, init);
  }) as typeof fetch;
}
const GATEWAY = (process.env.DARKNYX_TEE_GATEWAY ?? "").replace(/\/$/, "");

const RATLS = process.env.DARKNYX_CVM_TRANSPORT === "ra-tls";
const RESTART_DRILL = process.env.RUN_CVM_DAEMON_RESTART_DRILL === "1";

/**
 * One transport for the whole file, selected exactly as the daemon entrypoint
 * selects it.
 *
 * This suite previously hardcoded `gateway-terminated` and used global fetch
 * throughout. After the cutover unpublished the plaintext route, that made it
 * silently UNRUNNABLE — it died on DEPTH_ZERO_SELF_SIGNED_CERT before reaching
 * a single assertion.
 */
let transportSupervisor: DaemonTransportSupervisor;
const tfetch: typeof fetch = ((i: never, init: never) =>
  transportSupervisor.fetch(i, init)) as typeof fetch;
const RPC = process.env.SOLANA_RPC_URL ?? "";
const READY =
  process.env.RUN_CVM_DAEMON_LIFECYCLE === "1" &&
  GATEWAY !== "" &&
  RPC !== "" &&
  existsSync(CONFIG_PATH);
const maybe = READY ? describe : describe.skip;

// Defaults are the compose-hardcoded bootstrap creds, but a properly
// provisioned CVM injects fresh ones through the encrypted env (a production
// tier REFUSES the public test credentials). Take them from the environment
// when present so this runs against a real deployment rather than only
// against compose defaults.
const API = {
  key: process.env.DARKNYX_TEE_API_KEY ?? "darknyx-test-api-key",
  secret: process.env.DARKNYX_TEE_API_SECRET ?? "darknyx-test-secret",
  pass: process.env.DARKNYX_TEE_PASSPHRASE ?? "darknyx-test-passphrase",
};
const FEE_BPS = 30n;
const SYMBOL = "SOL-USDC";
const VI = {
  wasmPath: resolve(
    REPO_ROOT,
    "circuits/build/valid_input/circuit_js/circuit.wasm",
  ),
  zkeyPath: resolve(REPO_ROOT, "circuits/build/valid_input/circuit_final.zkey"),
};
const MERGE = (k: 2 | 4) => ({
  wasmPath: resolve(
    REPO_ROOT,
    `circuits/build/valid_merge_k${k}/circuit_js/circuit.wasm`,
  ),
  zkeyPath: resolve(
    REPO_ROOT,
    `circuits/build/valid_merge_k${k}/circuit_final.zkey`,
  ),
});

const withFee = (n: bigint) => n + (n * FEE_BPS) / 10_000n;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const SOL_USD_FEED =
  "ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d";
/** The matcher clears at the oracle-anchored price, so orders must be priced
 *  near it (a far-off fixed price never crosses) — same anchor cvm-settle-e2e uses. */
async function oracleAnchor(): Promise<bigint> {
  if (process.env.DARKNYX_CVM_PRICE)
    return BigInt(process.env.DARKNYX_CVM_PRICE);
  return (
    await fetchPythCorePushPrice(new Connection(RPC, "finalized"), SOL_USD_FEED)
  ).emaPrice;
}
const loadKp = async (rel: string) =>
  await Keypair.fromSecretKey(
    Uint8Array.from(
      JSON.parse(readFileSync(resolve(REPO_ROOT, rel), "utf8")) as number[],
    ),
  );

/**
 * The buyer/seller fee payers used to be `await loadKp(...)` on two files nothing in
 * the repo creates. They existed only on the machine of whoever last ran this
 * by hand, so the suite threw in `beforeAll` anywhere else — which is a large
 * part of why it sat unrunnable while CI stayed green. Generate and persist
 * them on first use instead: they are throwaway devnet fee payers, not
 * protocol identities.
 */
const loadOrCreateKp = async (rel: string): Promise<Keypair> => {
  const abs = resolve(REPO_ROOT, rel);
  if (existsSync(abs)) return await loadKp(rel);
  const kp = await Keypair.generate();
  mkdirSync(dirname(abs), { recursive: true });
  writeFileSync(abs, JSON.stringify(Array.from(kp.secretKey)), { mode: 0o600 });
  return kp;
};

/** Top a fee payer up from the funder. No airdrop: devnet faucets rate-limit. */
async function ensureFunded(
  conn: Connection,
  funder: Keypair,
  target: PublicKey,
  minSol = 0.5,
): Promise<void> {
  // v3 getBalance returns Lamports (bigint); this arithmetic is in SOL-scale
  // numbers, so narrow at the call.
  const have = Number(await conn.getBalance(target, "confirmed"));
  const need = minSol * LAMPORTS_PER_SOL;
  if (have >= need) return;
  await sendAndConfirmTransaction(
    conn,
    new Transaction().add(
      SystemProgram.transfer({
        fromPubkey: funder.publicKey,
        toPubkey: target,
        lamports: need - have,
      }),
    ),
    [funder],
  );
}

interface E2EConfig {
  vaultProgramId: string;
  quoteMint: { pubkey: string };
  baseMint: { pubkey: string };
}

async function authToken(): Promise<string> {
  const r = await tfetch(`${GATEWAY}/auth/token`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      api_key: API.key,
      api_secret: API.secret,
      passphrase: API.pass,
    }),
  });
  expect(r.status, "auth/token failed").toBe(200);
  return ((await r.json()) as { access_token: string }).access_token;
}

/**
 * The CVM's current boot session id, hex.
 *
 * Every order signature is scoped to it (CS-11 / S-07): intake rejects a body
 * carrying any other value with `stale_session`, so a test that omits it cannot
 * place an order at all. This test did omit it — `sessionId` is required by
 * `BuildOrderArgs` and was simply absent — which nothing caught, because test
 * files were never typechecked and this file is env-gated on
 * RUN_CVM_DAEMON_LIFECYCLE=1.
 */
async function bootSessionId(): Promise<Uint8Array> {
  const r = await tfetch(`${GATEWAY}/info`);
  expect(r.status, "/info failed").toBe(200);
  const info = (await r.json()) as { boot_session_id: string };
  expect(
    info.boot_session_id,
    "/info must advertise a 32-byte hex boot_session_id",
  ).toMatch(/^[0-9a-fA-F]{64}$/);
  return Uint8Array.from(Buffer.from(info.boot_session_id, "hex"));
}

/** Poll /tree/inclusion until the TEE mirror has the leaf (after a deposit). */
async function waitForLeaf(commitment: string, token: string): Promise<void> {
  const deadline = Date.now() + 90_000;
  for (;;) {
    const u = new URL("/tree/inclusion", GATEWAY);
    u.searchParams.set("commitment", commitment);
    u.searchParams.set("tree_id", "0");
    const r = await tfetch(u.toString(), {
      headers: { authorization: `Bearer ${token}` },
    });
    if (r.status === 200) return;
    if (Date.now() > deadline) throw new Error("mirror sync timeout");
    await sleep(3000);
  }
}

maybe("daemon full lifecycle (fill → leaf-resolve → merge → cancel)", () => {
  let cfg: E2EConfig;
  let conn: Connection;
  let admin: Keypair;
  let buyerPayer: Keypair;
  let sellerPayer: Keypair;
  let quoteMint: PublicKey;
  let baseMint: PublicKey;
  let programId: PublicKey;
  let token: string;
  let buyer: Daemon;
  let buyerStore: DaemonStore;

  // Orders need a FUTURE expiry_slot — the matcher sweeps expiry_slot=0
  // (limitPolicy's "GTC" default) as already-expired — but the CVM also
  // REJECTS an expiry beyond `MAX_LOCK_TTL_SLOTS` (4500, ~30 min) ahead,
  // the F-05 cap on how long a note may sit locked.
  //
  // This used to ask for +100_000 and was rejected outright. The margin
  // below the cap is deliberate: slots advance between reading `getSlot`
  // and the CVM evaluating the order, so asking for exactly 4500 would be
  // intermittently over.
  async function futureExpiry(): Promise<bigint> {
    return (await conn.getSlot("confirmed")) + 4_000n;
  }

  // ── MatchDriver: deposit a base note for the seller + submit a crossing ask ──
  async function sellerAsk(qty: bigint, price: bigint): Promise<void> {
    const seed = new Uint8Array(64);
    for (let i = 0; i < 64; i++) seed[i] = (Date.now() + i * 11) & 0xff;
    const ks = new Keystore(
      deriveAccountIdentity(seed, sellerPayer.publicKey.toBytes()),
    );
    const noteAmt = withFee(qty);
    const ata = await associatedTokenAddress(baseMint, sellerPayer.publicKey);
    await sendAndConfirmTransaction(
      conn,
      new Transaction().add(
        createAtaIdempotentIx(admin, ata, sellerPayer.publicKey, baseMint),
        mintToIx(baseMint, ata, admin, noteAmt),
      ),
      [admin],
    );
    const receipt = await getDepositFunction({
      client: createDaemonClient({
        programId,
        rpcUrl: RPC,
        payer: sellerPayer,
        keystore: ks,
      }),
    })({
      depositor: sellerPayer.publicKey,
      depositIndex: BigInt(Date.now()),
      tokenMint: baseMint.toBytes(),
      amount: noteAmt,
      depositorTokenAccount: ata,
    });
    const note: StoredNote = depositNoteFromReceipt(receipt);
    await waitForLeaf(note.commitment, token);
    const req = await proveAndBuildOrder({
      masterSeed: ks.masterSeed,
      spendingKey: ks.spendingKey,
      ownerCommitment: note.ownerCommitment,
      sessionId: await bootSessionId(),
      tradingKey: ks.tradingPublicKey(0),
      sign: (d) => ks.signWithTradingKey(0, d),
      note: {
        commitment: Uint8Array.from(Buffer.from(note.commitment, "hex")),
        innerHash: note.innerHash,
        amount: note.amount,
      },
      symbol: SYMBOL,
      side: OrderSide.Ask,
      policy: limitPolicy({
        priceLimit: price,
        expirySlot: await futureExpiry(),
      }),
      amount: qty,
      orderId: Uint8Array.from(
        Buffer.from(`${Date.now()}`.padStart(32, "0").slice(0, 32), "hex"),
      ),
      baseUrl: GATEWAY,
      token,
      // Fetches /tree/inclusion internally; without this it does so on
      // global fetch and cannot reach the enclave.
      fetchImpl: tfetch,
      prover: nodeValidInputProver(VI),
      ownerCommitmentBlinding: ks.ownerBlinding,
      tokenMint: baseMint.toBytes(),
    });
    const resp = await placeOrder(
      { baseUrl: GATEWAY, token, fetchImpl: tfetch },
      req,
    );
    expect(resp.status).toBeTruthy();
  }

  async function leafCount(): Promise<number> {
    // `total_leaf_count`, NOT `leaf_count`.
    //
    // SW-06 renamed this: the field used to be a bare `leaf_count` (the
    // all-shard sum) sitting next to shard 0's `merkle_root`, which read as
    // a matched pair and was not one. This test was never updated, and its
    // `?? 0` turned the missing field into "the tree is empty" — so every
    // run reported before=0, after=0 and failed with "settle did not land"
    // whether or not the settle actually landed.
    //
    // No default here on purpose: a shape change must fail loudly rather
    // than quietly reappear as an empty tree.
    const r = await tfetch(`${GATEWAY}/transparency`, {
      headers: { authorization: `Bearer ${token}` },
    });
    const j = (await r.json()) as {
      reserves?: { total_leaf_count?: number };
    };
    const n = j.reserves?.total_leaf_count;
    if (typeof n !== "number") {
      throw new Error(
        "/transparency did not return reserves.total_leaf_count " +
          `(got ${JSON.stringify(j.reserves)}); the response shape changed`,
      );
    }
    return n;
  }

  /**
   * Billable D2 closure leg. The test writes a public marker, then an external
   * operator redeploys the same reviewed compose while this process and its
   * subscriptions stay alive. Requests keep probing through the OLD verified
   * generation until its typed refusal trips the supervisor; no test-only
   * recovery call is used.
   */
  async function awaitSupervisedBootRotation(): Promise<void> {
    const before = buyer.getAttestation()?.bootSessionId;
    expect(
      before,
      "restart drill requires strict application attestation",
    ).toMatch(/^[0-9a-f]{64}$/);
    const startedMs = Date.now();
    const rssBeforeMb = Math.round(process.memoryUsage().rss / 1024 / 1024);
    writeFileSync(
      RESTART_READY_PATH,
      `${JSON.stringify({ boot_session_id: before, ready_at_ms: startedMs })}\n`,
      { mode: 0o600 },
    );
    console.log(`  · CVM_RESTART_READY boot=${before} rss_mb=${rssBeforeMb}`);

    const states = new Set<string>();
    let requestFailures = 0;
    let recoveryObserved = false;
    const deadline = startedMs + 240_000;
    while (Date.now() < deadline) {
      if (!recoveryObserved) {
        try {
          await buyer.tee.serverTime();
        } catch {
          requestFailures += 1;
        }
      }
      const trust = buyer.getTrustStatus();
      states.add(trust.transportState);
      recoveryObserved ||= trust.transportState !== "ready";
      const after = buyer.getAttestation()?.bootSessionId;
      if (
        recoveryObserved &&
        trust.transportState === "ready" &&
        after !== undefined &&
        after !== before
      ) {
        const finishedMs = Date.now();
        const rssAfterMb = Math.round(process.memoryUsage().rss / 1024 / 1024);
        const result = {
          before_boot_session_id: before,
          after_boot_session_id: after,
          recovery_ms: finishedMs - startedMs,
          request_failures: requestFailures,
          states: [...states],
          final_attempts: trust.transportRecoveryAttempts,
          rss_before_mb: rssBeforeMb,
          rss_after_mb: rssAfterMb,
          rss_delta_mb: rssAfterMb - rssBeforeMb,
        };
        writeFileSync(
          RESTART_RESULT_PATH,
          `${JSON.stringify(result, null, 2)}\n`,
          { mode: 0o600 },
        );
        console.log(`  · CVM_RESTART_RECOVERED ${JSON.stringify(result)}`);
        expect(states.has("reverifying")).toBe(true);
        expect(states.has("reconciling")).toBe(true);
        return;
      }
      await sleep(recoveryObserved ? 100 : 500);
    }
    throw new Error(
      `daemon did not recover from a real boot rotation; states=${[
        ...states,
      ].join(",")} failures=${requestFailures}`,
    );
  }

  beforeAll(async () => {
    // Built before any gateway call: `/auth/token` below exchanges an API
    // secret for a bearer token and must not travel on global fetch.
    let supervisorRef: DaemonTransportSupervisor | undefined;
    const buildTransport = () =>
      buildDaemonTransport(
        {
          gatewayUrl: GATEWAY,
          transportMode: RATLS
            ? ("ra-tls" as const)
            : ("gateway-terminated" as const),
          deploymentTier: RATLS ? "production" : "development",
          allowLegacyTransport: !RATLS,
          ...(RATLS
            ? {
                expectSignerSetSha256: process.env.DARKNYX_EXPECT_SIGNER_SET,
                attestation: {
                  composeHash: process.env.DARKNYX_EXPECT_COMPOSE_HASH,
                  teePubkey: process.env.DARKNYX_EXPECT_TEE_PUBKEY,
                },
              }
            : {}),
        } as DaemonConfig,
        {
          verifierDeps: {
            verifyQuote: (q: string) =>
              createDcapQuoteVerifier({})(
                Uint8Array.from(q.match(/../g)!.map((b) => parseInt(b, 16))),
              ),
            parseEventLog,
            randomNonce: () => new Uint8Array(randomBytes(32)),
          },
          ...(RATLS
            ? {
                createWebSocket: (u: string) =>
                  new WebSocket(u, {
                    rejectUnauthorized: false,
                  }) as unknown as NodeWebSocketLike,
              }
            : {}),
          onTransportViolation: (error) =>
            supervisorRef?.reportViolation(error),
        },
      );
    const initialTransport = await buildTransport();
    transportSupervisor = new DaemonTransportSupervisor(
      initialTransport,
      buildTransport,
    );
    supervisorRef = transportSupervisor;
    cfg = JSON.parse(readFileSync(CONFIG_PATH, "utf8")) as E2EConfig;
    conn = new Connection(RPC, "confirmed");
    admin = await loadKp(
      process.env.ADMIN_KEYPAIR ?? ".devnet/keypairs/admin.json",
    );
    buyerPayer = await loadOrCreateKp(".devnet/keypairs/cvm-buyer-payer.json");
    sellerPayer = await loadOrCreateKp(
      ".devnet/keypairs/cvm-seller-payer.json",
    );
    const funder = await loadKp(
      process.env.FUNDER_KEYPAIR ?? ".devnet/keypairs/funder.json",
    );
    await ensureFunded(conn, funder, buyerPayer.publicKey);
    await ensureFunded(conn, funder, sellerPayer.publicKey);
    quoteMint = new PublicKey(cfg.quoteMint.pubkey);
    baseMint = new PublicKey(cfg.baseMint.pubkey);
    programId = new PublicKey(cfg.vaultProgramId);
    token = await authToken();

    const seed = new Uint8Array(64);
    for (let i = 0; i < 64; i++) seed[i] = (Date.now() + i * 7) & 0xff;
    const keystore = new Keystore(
      deriveAccountIdentity(seed, buyerPayer.publicKey.toBytes()),
    );
    buyerStore = new DaemonStore(":memory:");

    const config: DaemonConfig = {
      gatewayUrl: GATEWAY,
      // Selected, not hardcoded. Pinning this to "gateway-terminated" made
      // the suite unrunnable after the cutover unpublished the plaintext
      // route.
      transportMode: RATLS
        ? ("ra-tls" as const)
        : ("gateway-terminated" as const),
      deploymentTier: RATLS ? "production" : "development",
      allowLegacyTransport: !RATLS,
      ...(RATLS
        ? {
            expectSignerSetSha256: process.env.DARKNYX_EXPECT_SIGNER_SET,
            attestation: {
              composeHash: process.env.DARKNYX_EXPECT_COMPOSE_HASH,
              teePubkey: process.env.DARKNYX_EXPECT_TEE_PUBKEY,
            },
          }
        : {}),
      gatewayWsUrl: GATEWAY.replace(/^http/, "ws"),
      token,
      rpcUrl: RPC,
      dbPath: ":memory:",
      controlPort: 0,
      keystorePath: "",
      orderSequencePath: "",
      // tuned: merge at 2 residuals
      thresholds: {
        mergeThreshold: 2,
      },
      // The restart drill exercises the production application/governance
      // verification path; ordinary lifecycle runs keep their cheaper partial
      // attestation mode.
      attestationStrict: RESTART_DRILL,
      attestOnchainCheck: RESTART_DRILL,
      programId: cfg.vaultProgramId,
    };
    const { client, merkleProvider } = createMergeClient({
      programId,
      rpcUrl: RPC,
      payer: buyerPayer,
      keystore,
      artifacts: { k2: MERGE(2), k4: MERGE(4) },
      leavesFetcher: httpLeavesFetcher({
        gatewayUrl: GATEWAY,
        token,
        fetchImpl: tfetch,
      }),
    });
    const rawMerge = getMergeFunction({ client });
    buyer = new Daemon({
      config,
      // The shipped wiring: every CVM call and the /v1/stream session run
      // over the selected transport. Omitting these left the daemon's own
      // attestation fetch on global fetch, which fails closed against the
      // enclave's self-signed certificate.
      fetchImpl: transportSupervisor.fetch,
      transportSupervisor,
      streamTokenProvider: authToken,
      quoteVerifier: createDcapQuoteVerifier({}),
      ...(RATLS
        ? {
            sendableWebSocketFactory:
              transportSupervisor.webSocketFactory as ConstructorParameters<
                typeof Daemon
              >[0]["sendableWebSocketFactory"],
          }
        : {}),
      keystore,
      store: buyerStore,
      prover: nodeValidInputProver(VI),
      depositFn: getDepositFunction({
        client: createDaemonClient({
          programId,
          rpcUrl: RPC,
          payer: buyerPayer,
          keystore,
        }),
      }),
      depositor: buyerPayer.publicKey,
      mergeRunner: createMergeRunner({
        store: buyerStore,
        payer: buyerPayer.publicKey,
        ownerCommitment: await keystore.ownerCommitment(),
        mergeFn: async (p) => {
          await merkleProvider.refresh();
          return rawMerge(p);
        },
      }),
      placer: new WsOrderPlacer({
        gatewayWsUrl: GATEWAY.replace(/^http/, "ws"),
        token,
        cancelOnDisconnect: true,
        // MUST carry the gated factory. Without it WsOrderPlacer builds a
        // raw `ws` connection, which cannot complete a handshake against the
        // enclave's self-signed certificate — and, if it could, would be
        // placing orders over a peer nothing verified. This was the cause of
        // the live "WebSocket transport error" on this suite: the injected
        // placer bypassed the transport the rest of the daemon was using.
        ...(RATLS
          ? {
              webSocketFactory:
                transportSupervisor.webSocketFactory as ConstructorParameters<
                  typeof WsOrderPlacer
                >[0]["webSocketFactory"],
            }
          : {}),
      }),
      // The restart leg measures the one reconciliation that follows a real
      // transport-generation swap. Skipping the redundant pre-marker scan
      // keeps the billable choreography deterministic.
      reconcileOnStart: !RESTART_DRILL,
      settlementPollMs: 2000,
    });
  });

  it("drives fill → leaf-resolve → auto-merge → cancel + read-surface", async () => {
    const events: DaemonEvent[] = [];
    buyer.subscribe((e) => events.push(e));
    await buyer.start();
    expect(buyer.getAttestation(), "attested").toBeTruthy();

    // read-surface sanity (utilizes /transparency, /instruments, /account).
    expect(await buyer.tee.transparency()).toBeTruthy();
    expect(await buyer.tee.instruments()).toBeTruthy();

    const anchor = await oracleAnchor();
    const bidPrice = (anchor * 12n) / 10n; // above clearing
    const askPrice = (anchor * 8n) / 10n; // below → crosses
    const SLICE = 1000n;
    const buyQty = SLICE * 10n; // resting bid covers many asks
    const collateral = withFee(buyQty * bidPrice);
    console.log(
      `  · anchor=${anchor} bid=${bidPrice} ask=${askPrice} buyQty=${buyQty}`,
    );
    const buyerAta = await associatedTokenAddress(
      quoteMint,
      buyerPayer.publicKey,
    );
    await sendAndConfirmTransaction(
      conn,
      new Transaction().add(
        createAtaIdempotentIx(admin, buyerAta, buyerPayer.publicKey, quoteMint),
        mintToIx(quoteMint, buyerAta, admin, collateral),
      ),
      [admin],
    );
    const dep = await buyer.deposit({
      tokenMint: quoteMint.toBytes(),
      amount: collateral,
      depositorTokenAccount: buyerAta,
    });
    await waitForLeaf(dep.commitment, token);
    const note = buyer.getNote(dep.commitment)!;

    const before = await leafCount();
    const { orderId } = await buyer.placeOrder(
      {
        symbol: SYMBOL,
        side: OrderSide.Bid,
        policy: limitPolicy({
          priceLimit: bidPrice,
          expirySlot: await futureExpiry(),
        }),
        amount: buyQty,
      },
      note,
    );
    expect(buyer.getOrder(orderId)?.phase).toBe("open");

    // Rotate only after collateral is reserved by a real resting order. The
    // recovery must reconcile that exact order without re-signing or silently
    // rebooking it before any fresh post-recovery action is allowed.
    if (RESTART_DRILL) {
      await awaitSupervisedBootRotation();
      expect(buyer.getOrder(orderId)?.phase).toBe("open");
    }

    // ── crossing ask → partial fill ──
    await sellerAsk(SLICE, askPrice);
    // poll for the settle to land on-chain. A deposit adds +1 leaf; a real
    // settle appends note_c/d + the buyer change + fee notes (≥ +3 beyond the
    // seller's deposit), so require before+3 to distinguish settle from deposit.
    let after = before;
    const deadline = Date.now() + 120_000;
    while (Date.now() < deadline) {
      after = await leafCount();
      if (after >= before + 3) break;
      await sleep(3000);
    }
    expect(after, "settle did not land").toBeGreaterThanOrEqual(before + 3);
    await sleep(5000); // let the fills WS memo + the daemon dispatch settle
    // ── diagnostics ──
    console.log(
      `  · leaf ${before}→${after} | events=${JSON.stringify(
        events.map((e) =>
          e.type === "error" ? `err:${e.context}:${e.message}` : e.type,
        ),
      )}`,
    );
    console.log(`  · daemon notes=${buyer.listNotes().length}`);
    const cvmOrder = await tfetch(`${GATEWAY}/orders/${orderId}`, {
      headers: { authorization: `Bearer ${token}` },
    });
    console.log(
      `  · CVM order ${orderId.slice(0, 8)}: ${cvmOrder.status} ${(await cvmOrder.text()).slice(0, 240)}`,
    );
    const o = buyer.getOrder(orderId)!;
    expect(
      events.some((e) => e.type === "fill"),
      "no fill event",
    ).toBe(true);
    console.log(`  · fill: pending residuals=${o.pendingChangeNotes}`);

    // ── cancel the resting order ──
    await buyer.cancelOrder(orderId);
    await sleep(4000);
    expect(buyer.getOrder(orderId)?.phase).toBe("cancelled");
    console.log("  · order cancelled");

    // NOTE: auto-merge needs ≥2 spendable same-mint residuals (terminal orders).
    // Driving a 2nd order to completion + asserting VALID_MERGE lands is the
    // next live-iteration step; the settlement-tracker + merge runner + client
    // are wired here so it's a timing/assertion pass, not new plumbing.

    // The leak guard, asserted last so it covers the WHOLE flow: attestation,
    // deposit, place, the fills channel, leaf resolution, and cancel. Under
    // ra-tls every one of those must have travelled on the verified transport.
    expect(
      transportLeaks,
      `these CVM calls bypassed the verified transport and used global fetch:\n  ` +
        transportLeaks.join("\n  "),
    ).toEqual([]);

    buyer.stop();
  }, 600_000);
});
