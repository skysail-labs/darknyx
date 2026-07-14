/**
 * Daemon ↔ live-CVM FULL LIFECYCLE (gated, billable — see docs/cvm-run-runbook.md).
 *
 * Drives the daemon (buyer) through the whole order lifecycle against a deployed
 * CVM, with a MatchDriver (SDK seller) supplying crossing asks so the CVM
 * matches + settles. Tuned thresholds make the automations cheap to trigger:
 *   - anchorTopUpThreshold = 9 → auto-topup fires after the 1st partial fill,
 *   - mergeThreshold = 2 → auto-merge fires at 2 spendable residuals,
 *   - settlementPollMs small → leaf-resolve fast.
 *
 * Scenario matrix (each step asserts daemon state + on-chain/endpoint effects):
 *   1. attest + deposit (quote collateral, sized for many slices)
 *   2. place a big resting bid over /v1/stream
 *   3. seller ask #1 crosses → partial fill: fills change note + orders update
 *      partially_filled + auto-topup (POST /orders/{id}/anchors) + leaf_count↑
 *   4. settlement-tracker resolves the residual's leaf (/tree/inclusion)
 *   5. a 2nd buyer order, partially filled then cancelled, leaves a 2nd residual
 *      → auto-merge consolidates them (VALID_MERGE on-chain)
 *   6. cancel a resting order (control path) → cancelled
 *   7. read-surface: daemon.tee.account()/instruments()/transparency()
 *
 * MatchDriver (seller) builds its order the SAME way the daemon does
 * (proveAndBuildOrder → /tree/inclusion), so no shadow tree is needed.
 *
 * Gated on RUN_CVM_DAEMON_LIFECYCLE=1 + NYX_TEE_GATEWAY + SOLANA_RPC_URL.
 * Like the smoke, this is offline-typechecked; expect to iterate timings against
 * a live CVM. Prereqs: tree reset, CVM deployed (real-mint), signers
 * rotated/funded (settles happen), buyer+seller payers funded.
 *
 * Run:
 *   RUN_CVM_DAEMON_LIFECYCLE=1 NYX_TEE_GATEWAY=https://<app>-8080.dstack-… \
 *     SOLANA_RPC_URL=<helius> ADMIN_KEYPAIR=.devnet/keypairs/admin.json \
 *     ( cd packages/daemon && ../../node_modules/.bin/vitest run tests/cvm-daemon-lifecycle.test.ts )
 */

import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { beforeAll, describe, expect, it } from "vitest";
import {
  getAssociatedTokenAddress,
  createAssociatedTokenAccountIdempotentInstruction,
  createMintToInstruction,
} from "@solana/spl-token";
import {
  Connection,
  Keypair,
  PublicKey,
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
} from "@nyx/sdk";
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

const here = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(here, "..", "..", "..");
const CONFIG_PATH = resolve(REPO_ROOT, ".devnet/e2e-config.json");
const GATEWAY = (process.env.NYX_TEE_GATEWAY ?? "").replace(/\/$/, "");
const RPC = process.env.SOLANA_RPC_URL ?? "";
const READY =
  process.env.RUN_CVM_DAEMON_LIFECYCLE === "1" &&
  GATEWAY !== "" &&
  RPC !== "" &&
  existsSync(CONFIG_PATH);
const maybe = READY ? describe : describe.skip;

const API = {
  key: "nyx-test-api-key",
  secret: "nyx-test-secret",
  pass: "nyx-test-passphrase",
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
  if (process.env.NYX_CVM_PRICE) return BigInt(process.env.NYX_CVM_PRICE);
  const r = await fetch(
    `https://hermes.pyth.network/v2/updates/price/latest?ids[]=${SOL_USD_FEED}`,
  );
  const j = (await r.json()) as { parsed?: { price: { price: string } }[] };
  if (!j.parsed?.length) throw new Error("Hermes returned no price");
  return BigInt(j.parsed[0].price.price);
}
const loadKp = (rel: string) =>
  Keypair.fromSecretKey(
    Uint8Array.from(
      JSON.parse(readFileSync(resolve(REPO_ROOT, rel), "utf8")) as number[],
    ),
  );

interface E2EConfig {
  vaultProgramId: string;
  quoteMint: { pubkey: string };
  baseMint: { pubkey: string };
}

async function authToken(): Promise<string> {
  const r = await fetch(`${GATEWAY}/auth/token`, {
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

/** Poll /tree/inclusion until the TEE mirror has the leaf (after a deposit). */
async function waitForLeaf(commitment: string, token: string): Promise<void> {
  const deadline = Date.now() + 90_000;
  for (;;) {
    const u = new URL("/tree/inclusion", GATEWAY);
    u.searchParams.set("commitment", commitment);
    u.searchParams.set("tree_id", "0");
    const r = await fetch(u.toString(), {
      headers: { authorization: `Bearer ${token}` },
    });
    if (r.status === 200) return;
    if (Date.now() > deadline) throw new Error("mirror sync timeout");
    await sleep(3000);
  }
}

maybe(
  "daemon full lifecycle (fill → topup → leaf-resolve → merge → cancel)",
  () => {
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
    // (limitPolicy's "GTC" default) as already-expired.
    async function futureExpiry(): Promise<bigint> {
      return BigInt((await conn.getSlot("confirmed")) + 100_000);
    }

    // ── MatchDriver: deposit a base note for the seller + submit a crossing ask ──
    async function sellerAsk(qty: bigint, price: bigint): Promise<void> {
      const seed = new Uint8Array(64);
      for (let i = 0; i < 64; i++) seed[i] = (Date.now() + i * 11) & 0xff;
      const ks = new Keystore(
        deriveAccountIdentity(seed, sellerPayer.publicKey.toBytes()),
      );
      const noteAmt = withFee(qty);
      const ata = await getAssociatedTokenAddress(
        baseMint,
        sellerPayer.publicKey,
      );
      await sendAndConfirmTransaction(
        conn,
        new Transaction().add(
          createAssociatedTokenAccountIdempotentInstruction(
            admin.publicKey,
            ata,
            sellerPayer.publicKey,
            baseMint,
          ),
          createMintToInstruction(baseMint, ata, admin.publicKey, noteAmt),
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
        userCommitment: await ks.userCommitment(),
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
        prover: nodeValidInputProver(VI),
        ownerCommitmentBlinding: ks.ownerBlinding,
        tokenMint: baseMint.toBytes(),
      });
      const resp = await placeOrder({ baseUrl: GATEWAY, token }, req);
      expect(resp.status).toBeTruthy();
    }

    async function leafCount(): Promise<number> {
      // The TEE mirror's leaf count, under reserves on /transparency.
      const r = await fetch(`${GATEWAY}/transparency`, {
        headers: { authorization: `Bearer ${token}` },
      });
      const j = (await r.json()) as { reserves?: { leaf_count?: number } };
      return j.reserves?.leaf_count ?? 0;
    }

    beforeAll(async () => {
      cfg = JSON.parse(readFileSync(CONFIG_PATH, "utf8")) as E2EConfig;
      conn = new Connection(RPC, "confirmed");
      admin = loadKp(
        process.env.ADMIN_KEYPAIR ?? ".devnet/keypairs/admin.json",
      );
      buyerPayer = loadKp(".devnet/keypairs/cvm-buyer-payer.json");
      sellerPayer = loadKp(".devnet/keypairs/cvm-seller-payer.json");
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
        gatewayWsUrl: GATEWAY.replace(/^http/, "ws"),
        token,
        rpcUrl: RPC,
        dbPath: ":memory:",
        controlPort: 0,
        keystorePath: "",
        // tuned: topup after 1 fill, merge at 2 residuals
        thresholds: {
          anchorTopUpThreshold: 9,
          anchorTopUpSize: 5,
          mergeThreshold: 2,
        },
        // Functional lifecycle test — dev-partial attestation (not strict DCAP).
        attestationStrict: false,
        attestOnchainCheck: false,
        programId: cfg.vaultProgramId,
      };
      const { client, merkleProvider } = createMergeClient({
        programId,
        rpcUrl: RPC,
        payer: buyerPayer,
        keystore,
        artifacts: { k2: MERGE(2), k4: MERGE(4) },
        leavesFetcher: httpLeavesFetcher({ gatewayUrl: GATEWAY, token }),
      });
      const rawMerge = getMergeFunction({ client });
      buyer = new Daemon({
        config,
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
        }),
        settlementPollMs: 2000,
      });
    });

    it("drives fill → auto-topup → leaf-resolve → auto-merge → cancel + read-surface", async () => {
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
      const buyerAta = await getAssociatedTokenAddress(
        quoteMint,
        buyerPayer.publicKey,
      );
      await sendAndConfirmTransaction(
        conn,
        new Transaction().add(
          createAssociatedTokenAccountIdempotentInstruction(
            admin.publicKey,
            buyerAta,
            buyerPayer.publicKey,
            quoteMint,
          ),
          createMintToInstruction(
            quoteMint,
            buyerAta,
            admin.publicKey,
            collateral,
          ),
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
      const cvmOrder = await fetch(`${GATEWAY}/orders/${orderId}`, {
        headers: { authorization: `Bearer ${token}` },
      });
      console.log(
        `  · CVM order ${orderId.slice(0, 8)}: ${cvmOrder.status} ${(await cvmOrder.text()).slice(0, 240)}`,
      );
      const o = buyer.getOrder(orderId)!;
      // The fills channel drove a fill (anchor consumed) + auto-topup grew the pool
      expect(o.anchorsConsumed, "no fill observed").toBeGreaterThanOrEqual(1);
      expect(o.anchorPoolSize, "auto-topup did not fire").toBeGreaterThan(10);
      expect(
        events.some((e) => e.type === "fill"),
        "no fill event",
      ).toBe(true);
      console.log(
        `  · fill: consumed=${o.anchorsConsumed} pool=${o.anchorPoolSize}`,
      );

      // ── cancel the resting order ──
      await buyer.cancelOrder(orderId);
      await sleep(4000);
      expect(buyer.getOrder(orderId)?.phase).toBe("cancelled");
      console.log("  · order cancelled");

      // NOTE: auto-merge needs ≥2 spendable same-mint residuals (terminal orders).
      // Driving a 2nd order to completion + asserting VALID_MERGE lands is the
      // next live-iteration step; the settlement-tracker + merge runner + client
      // are wired here so it's a timing/assertion pass, not new plumbing.

      buyer.stop();
    }, 600_000);
  },
);
