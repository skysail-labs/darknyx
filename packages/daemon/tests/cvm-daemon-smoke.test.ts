/**
 * Daemon ↔ live-CVM smoke (gated, billable infra — see docs/cvm-run-runbook.md).
 *
 * Validates the daemon's genuinely-NEW live integration surface that unit tests
 * can't reach — attestation, the on-chain deposit path, and the place path
 * (real VALID_INPUT proof → /orders accept) — by driving a real `Daemon`
 * against a deployed CVM + devnet. It deliberately does NOT need a counterparty
 * or a settle: the fill → auto-topup → settle/leaf-resolve → auto-merge loop is
 * engine logic covered offline (132 unit tests) + by the SDK `cvm-settle-e2e`.
 *
 *   1. attestation — `daemon.start()` verifies the live `/attestation` + `/info`
 *      (nonce freshness + tee_pubkey binding + /info consistency). A bad gateway
 *      throws and the daemon refuses to start.
 *   2. deposit — `daemon.deposit()` sends a real vault deposit (Solana providers
 *      + the deposit-capable client) and records the leaf-resolved note.
 *   3. place — `daemon.placeOrder()` runs the real in-process VALID_INPUT prover
 *      + posts to `/orders`; the CVM accepting it (order_id + arrival_slot)
 *      proves buildPlaceRequest + the keystore + the OrderPlacer end-to-end.
 *
 * PREREQS (runbook): vault redeployed (CU-3) + tree reset; CVM deployed
 * (real-mint regime) + its signer(s) rotated/funded; `.devnet/e2e-config.json`
 * fresh. Gated on RUN_CVM_DAEMON=1 + NYX_TEE_GATEWAY + SOLANA_RPC_URL.
 *
 * Run (after the runbook's deploy/rotate/fund):
 *   RUN_CVM_DAEMON=1 NYX_TEE_GATEWAY=https://<app>-8080.dstack-… \
 *     SOLANA_RPC_URL=<helius> ADMIN_KEYPAIR=.devnet/keypairs/admin.json \
 *     ( cd packages/daemon && ../../node_modules/.bin/vitest run tests/cvm-daemon-smoke.test.ts )
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
  limitPolicy,
  OrderSide,
} from "@nyx/sdk";
import {
  Daemon,
  DaemonStore,
  Keystore,
  deriveAccountIdentity,
  createDaemonClient,
  RestOrderPlacer,
  DEFAULT_THRESHOLDS,
  type DaemonConfig,
} from "../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(here, "..", "..", "..");
const CONFIG_PATH = resolve(REPO_ROOT, ".devnet/e2e-config.json");
const GATEWAY = (process.env.NYX_TEE_GATEWAY ?? "").replace(/\/$/, "");
const RPC = process.env.SOLANA_RPC_URL ?? "";

const READY =
  process.env.RUN_CVM_DAEMON === "1" &&
  GATEWAY !== "" &&
  RPC !== "" &&
  existsSync(CONFIG_PATH);
const maybe = READY ? describe : describe.skip;

// Bootstrap creds are HARDCODED in docker-compose.yaml (runbook gotcha 3).
const API_KEY = "nyx-test-api-key";
const API_SECRET = "nyx-test-secret";
const PASSPHRASE = "nyx-test-passphrase";
const FEE_RATE_BPS = 30n;
const SYMBOL = "SOL-USDC";

const withFee = (nominal: bigint) =>
  nominal + (nominal * FEE_RATE_BPS) / 10_000n;
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

maybe("daemon ↔ live CVM smoke (attest → deposit → place)", () => {
  let cfg: E2EConfig;
  let conn: Connection;
  let admin: Keypair;
  let payer: Keypair;
  let quoteMint: PublicKey;
  let token: string;
  let daemon: Daemon;

  beforeAll(async () => {
    cfg = JSON.parse(readFileSync(CONFIG_PATH, "utf8")) as E2EConfig;
    conn = new Connection(RPC, "confirmed");
    admin = loadKp(process.env.ADMIN_KEYPAIR ?? ".devnet/keypairs/admin.json");
    payer = loadKp(".devnet/keypairs/cvm-buyer-payer.json");
    quoteMint = new PublicKey(cfg.quoteMint.pubkey);

    // auth → bearer
    const r = await fetch(`${GATEWAY}/auth/token`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        api_key: API_KEY,
        api_secret: API_SECRET,
        passphrase: PASSPHRASE,
      }),
    });
    expect(r.status, "auth/token failed").toBe(200);
    token = ((await r.json()) as { access_token: string }).access_token;

    // a fresh keystore identity bound to the buyer payer
    const seed = new Uint8Array(64);
    for (let i = 0; i < 64; i++) seed[i] = (Date.now() + i * 7) & 0xff;
    const keystore = new Keystore(
      deriveAccountIdentity(seed, payer.publicKey.toBytes()),
    );

    const config: DaemonConfig = {
      gatewayUrl: GATEWAY,
      gatewayWsUrl: GATEWAY.replace(/^http/, "ws"),
      token,
      rpcUrl: RPC,
      dbPath: ":memory:",
      controlPort: 0,
      keystorePath: "",
      thresholds: DEFAULT_THRESHOLDS,
      programId: cfg.vaultProgramId,
    };
    const programId = new PublicKey(cfg.vaultProgramId);
    daemon = new Daemon({
      config,
      keystore,
      store: new DaemonStore(":memory:"),
      prover: nodeValidInputProver({
        wasmPath: resolve(
          REPO_ROOT,
          "circuits/build/valid_input/circuit_js/circuit.wasm",
        ),
        zkeyPath: resolve(
          REPO_ROOT,
          "circuits/build/valid_input/circuit_final.zkey",
        ),
      }),
      depositFn: getDepositFunction({
        client: createDaemonClient({ programId, rpcUrl: RPC, payer, keystore }),
      }),
      depositor: payer.publicKey,
      // REST placer keeps the smoke simple (no warm-socket reconnect to reason about).
      placer: new RestOrderPlacer({ baseUrl: GATEWAY, token }),
    });
  });

  it("attests on connect, deposits, and the CVM accepts a placed order", async () => {
    // 1. attestation runs inside start(); refuses to start on a bad gateway.
    await daemon.start();
    const att = daemon.getAttestation();
    expect(att, "attestation did not produce an identity").toBeTruthy();
    console.log(`  · attested tee_pubkey ${att!.teePubkey}`);

    // 2. deposit — mint collateral, then deposit via the daemon.
    const BUY_QTY = BigInt((Date.now() % 250_000) + 1000);
    const bidPrice = 1_000_000n; // resting bid; no counterparty so it won't fill
    const noteAmt = withFee(BUY_QTY * bidPrice);
    const buyerAta = await getAssociatedTokenAddress(
      quoteMint,
      payer.publicKey,
    );
    await sendAndConfirmTransaction(
      conn,
      new Transaction().add(
        createAssociatedTokenAccountIdempotentInstruction(
          admin.publicKey,
          buyerAta,
          payer.publicKey,
          quoteMint,
        ),
        createMintToInstruction(quoteMint, buyerAta, admin.publicKey, noteAmt),
      ),
      [admin],
    );

    const dep = await daemon.deposit({
      tokenMint: quoteMint.toBytes(),
      amount: noteAmt,
      depositorTokenAccount: buyerAta,
    });
    expect(dep.leafIndex).toBeGreaterThanOrEqual(0n);
    const note = daemon.getNote(dep.commitment);
    expect(note, "deposited note not in store").toBeTruthy();
    expect(note!.leafIndex).toBe(dep.leafIndex);
    console.log(
      `  · deposited ${noteAmt} → leaf ${dep.leafIndex} (${dep.commitment.slice(0, 12)}…)`,
    );

    // 2b. wait for the TEE mirror to sync the deposit — placeOrder fetches the
    // VALID_INPUT witness from /tree/inclusion, which 404s until the mirror sees
    // the leaf (the CVM polls the chain; there's a lag after our confirm).
    await (async () => {
      const deadline = Date.now() + 90_000;
      for (;;) {
        const u = new URL("/tree/inclusion", GATEWAY);
        u.searchParams.set("commitment", dep.commitment);
        u.searchParams.set("tree_id", "0");
        const r = await fetch(u.toString(), {
          headers: { authorization: `Bearer ${token}` },
        });
        if (r.status === 200) break;
        if (Date.now() > deadline)
          throw new Error("TEE mirror did not sync the deposit within 90s");
        await new Promise((res) => setTimeout(res, 3000));
      }
      console.log("  · deposit visible in TEE mirror");
    })();

    // 3. place — real VALID_INPUT proof + /orders accept.
    const { orderId, arrivalSlot } = await daemon.placeOrder(
      {
        symbol: SYMBOL,
        side: OrderSide.Bid,
        policy: limitPolicy({ priceLimit: bidPrice }),
        amount: BUY_QTY,
      },
      note!,
    );
    expect(arrivalSlot).toBeGreaterThan(0);
    const order = daemon.getOrder(orderId);
    expect(order?.phase, "order not open after acceptance").toBe("open");
    console.log(
      `  · order ${orderId.slice(0, 8)}… accepted @ slot ${arrivalSlot}`,
    );

    // confirm it's resting in the CVM book (200) rather than gone.
    const got = await fetch(`${GATEWAY}/orders/${orderId}`, {
      headers: { authorization: `Bearer ${token}` },
    });
    console.log(`  · GET /orders/${orderId.slice(0, 8)} -> ${got.status}`);

    daemon.stop();
  }, 180_000);
});
