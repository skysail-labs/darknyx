/**
 * Focused two-market CVM correctness rehearsal.
 *
 * One boot serves SOL-USDC and BTC-USDC. The test deposits every input before
 * matching begins, then submits one crossing pair per market concurrently.
 * Both market schedulers therefore share the real prover, signer set, ALT
 * pool, Merkle shards, and venue-wide settlement semaphore in the same CVM.
 *
 * It additionally verifies:
 *   - /instruments advertises both governed mint pairs from one endpoint;
 *   - cross-market modify is rejected without mutating the original order;
 *   - cancel routes back to the original isolated book;
 *   - disabling either MarketConfig pauses the venue-wide trading gate; and
 *   - restoring governance resumes it.
 *
 * Prerequisites:
 *   1. node scripts/setup-second-devnet-market.mjs
 *   2. reset every tree, then cold-boot the CVM with DARKNYX_TEE_MARKETS_JSON
 *   3. RUN_CVM_E2E=1 and the usual private RPC/CVM credential env
 */

import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

import {
  Connection,
  Keypair,
  LAMPORTS_PER_SOL,
  PublicKey,
  sendAndConfirmTransaction,
  SystemProgram,
  Transaction,
} from "@solana/web3.js";
import nacl from "tweetnacl";
import { describe, expect, it } from "vitest";

import {
  buildUpdateMarketConfigInstruction,
  vaultConfigPda,
} from "../src/idl/vault-client.js";
import {
  bn254ToBE32,
  deriveOrderId,
  deriveViewingEncKeypair,
} from "../src/keys/key-generators.js";
import {
  cancelCanonicalDigest,
  orderCanonicalDigest,
  OrderSide,
  OrderType,
} from "../src/orders/canonical.js";
import { nullifierV2 } from "../src/utxo/note.js";
import {
  authToken,
  CvmHarness,
  fetchBootSessionId,
  fetchOracleAnchorForFeed,
  floorPriceToTick,
  FEE_RATE_BPS,
  gwFetch,
  hex,
  makePersona,
  scaledQuote,
  type DepositedNote,
  type Persona,
  withFee,
} from "./helpers/cvm-harness.js";
import {
  StepTimer,
  associatedTokenAddress,
  createAtaIdempotentIx,
  loadKeypairRel,
  mintToIx,
} from "./helpers/e2e-helpers.js";

interface MarketFixture {
  symbol: string;
  oracleFeedId: string;
  baseMint: { pubkey: string; decimals: number };
  quoteMint: { pubkey: string; decimals: number };
  marketConfigPda: string;
  market: {
    enabled: boolean;
    priceScale: string;
    tickSize: string;
    minOrderSize: string;
    circuitBreakerBps: string;
  };
}

interface MultiMarketConfig {
  vaultProgramId: string;
  vaultConfigPda: string;
  numTrees: number;
  settleLookupTable: string;
  markets: [MarketFixture, MarketFixture];
}

interface BuiltOrder {
  orderId: Uint8Array;
  body: Record<string, unknown>;
  symbol: string;
}

interface MarketRun {
  fixture: MarketFixture;
  buyer: Persona;
  seller: Persona;
  buyerNote: DepositedNote;
  sellerNote: DepositedNote;
  bidPrice: bigint;
  askPrice: bigint;
  qty: bigint;
}

const REPO_ROOT = resolve(__dirname, "../../..");
const CONFIG_PATH = resolve(REPO_ROOT, ".devnet/multi-market-e2e-config.json");
const GATEWAY = (process.env.DARKNYX_TEE_GATEWAY ?? "").replace(/\/$/, "");
const READY =
  process.env.RUN_CVM_E2E === "1" && GATEWAY !== "" && existsSync(CONFIG_PATH);
const maybeDescribe = READY ? describe : describe.skip;
const SETTLE_TIMEOUT_MS = Number(
  process.env.DARKNYX_CVM_SETTLE_TIMEOUT_MS ?? "240000",
);

async function fetchAnchor(feedId: string): Promise<bigint> {
  return fetchOracleAnchorForFeed(feedId);
}

async function fundPersona(
  connection: Connection,
  funder: Keypair,
  persona: Persona,
): Promise<void> {
  if (
    (await connection.getBalance(persona.payer.publicKey)) >=
    0.05 * LAMPORTS_PER_SOL
  ) {
    return;
  }
  await sendAndConfirmTransaction(
    connection,
    new Transaction().add(
      SystemProgram.transfer({
        fromPubkey: funder.publicKey,
        toPubkey: persona.payer.publicKey,
        lamports: 0.1 * LAMPORTS_PER_SOL,
      }),
    ),
    [funder],
    { commitment: "confirmed" },
  );
}

async function mintCollateral(
  connection: Connection,
  admin: Keypair,
  persona: Persona,
  mint: PublicKey,
  amount: bigint,
): Promise<PublicKey> {
  const ata = await associatedTokenAddress(mint, persona.payer.publicKey);
  await sendAndConfirmTransaction(
    connection,
    new Transaction().add(
      createAtaIdempotentIx(admin, ata, persona.payer.publicKey, mint),
      mintToIx(mint, ata, admin, amount),
    ),
    [admin],
    { commitment: "confirmed" },
  );
  return ata;
}

maybeDescribe(
  "CVM multi-market — isolated books sharing one settle plane",
  () => {
    it("routes, settles, and governance-pauses two markets in one boot", async () => {
      const timer = new StepTimer();
      const cfg = JSON.parse(
        readFileSync(CONFIG_PATH, "utf8"),
      ) as MultiMarketConfig;
      expect(cfg.markets).toHaveLength(2);
      expect(new Set(cfg.markets.map((market) => market.symbol)).size).toBe(2);

      const connection = new Connection(
        process.env.SOLANA_RPC_URL ?? "https://api.devnet.solana.com",
        "confirmed",
      );
      const admin = await loadKeypairRel(
        REPO_ROOT,
        process.env.ADMIN_KEYPAIR ?? ".devnet/keypairs/admin.json",
      );
      const funder = process.env.FUNDER_KEYPAIR
        ? await loadKeypairRel(REPO_ROOT, process.env.FUNDER_KEYPAIR)
        : admin;
      const programId = new PublicKey(cfg.vaultProgramId);
      vaultConfigPda(programId);
      const harness = await CvmHarness.create(
        connection,
        programId,
        cfg.numTrees,
      );
      expect(
        await harness.leafCount(),
        "trees not empty — reset every shard and cold-boot the CVM first",
      ).toBe(0);

      const bootSessionId = await fetchBootSessionId(GATEWAY);
      const token = await authToken(GATEWAY);

      const instrumentsResponse = await gwFetch(`${GATEWAY}/instruments`);
      expect(instrumentsResponse.status).toBe(200);
      const instruments = (await instrumentsResponse.json()) as {
        symbol: string;
        base_mint: string;
        quote_mint: string;
        trading_enabled: boolean;
      }[];
      expect(instruments.map((instrument) => instrument.symbol).sort()).toEqual(
        cfg.markets.map((market) => market.symbol).sort(),
      );
      for (const market of cfg.markets) {
        expect(instruments).toContainEqual(
          expect.objectContaining({
            symbol: market.symbol,
            base_mint: market.baseMint.pubkey,
            quote_mint: market.quoteMint.pubkey,
            trading_enabled: true,
          }),
        );
      }
      console.log(
        `  · one endpoint advertises ${instruments
          .map((instrument) => instrument.symbol)
          .join(", ")}`,
      );

      const personas = {
        solBuyer: await makePersona(REPO_ROOT, "cvm-mm-sol-buyer", 0x31),
        solSeller: await makePersona(REPO_ROOT, "cvm-mm-sol-seller", 0x51),
        btcBuyer: await makePersona(REPO_ROOT, "cvm-mm-btc-buyer", 0x71),
        btcSeller: await makePersona(REPO_ROOT, "cvm-mm-btc-seller", 0x91),
        routeProbe: await makePersona(REPO_ROOT, "cvm-mm-route-probe", 0xb1),
      };
      await timer.step("fund five devnet payers", () =>
        Promise.all(
          Object.values(personas).map((persona) =>
            fundPersona(connection, funder, persona),
          ),
        ).then(() => undefined),
      );

      const anchors = await timer.step(
        "fetch both finalized Pyth push anchors",
        () =>
          Promise.all(
            cfg.markets.map((market) => fetchAnchor(market.oracleFeedId)),
          ),
      );
      const quantities = [
        BigInt((Date.now() % 150_000) + 10_000),
        BigInt((Date.now() % 120_000) + 20_000),
      ];

      const marketPersonas = [
        [personas.solBuyer, personas.solSeller],
        [personas.btcBuyer, personas.btcSeller],
      ] as const;
      const runs: Omit<MarketRun, "buyerNote" | "sellerNote">[] =
        cfg.markets.map((fixture, index) => {
          const tick = BigInt(fixture.market.tickSize);
          return {
            fixture,
            buyer: marketPersonas[index][0],
            seller: marketPersonas[index][1],
            bidPrice: floorPriceToTick((anchors[index] * 12n) / 10n, tick),
            askPrice: floorPriceToTick((anchors[index] * 8n) / 10n, tick),
            qty: quantities[index],
          };
        });

      const depositedRuns: MarketRun[] = [];
      let nextTree = 0;
      for (const run of runs) {
        const baseMint = new PublicKey(run.fixture.baseMint.pubkey);
        const quoteMint = new PublicKey(run.fixture.quoteMint.pubkey);
        const priceScale = BigInt(run.fixture.market.priceScale);
        const buyerAmount = withFee(
          scaledQuote(run.qty, run.bidPrice, priceScale),
        );
        const sellerAmount = withFee(run.qty);
        const [buyerAta, sellerAta] = await timer.step(
          `mint ${run.fixture.symbol} collateral`,
          () =>
            Promise.all([
              mintCollateral(
                connection,
                admin,
                run.buyer,
                quoteMint,
                buyerAmount,
              ),
              mintCollateral(
                connection,
                admin,
                run.seller,
                baseMint,
                sellerAmount,
              ),
            ]),
        );
        const buyerNote = await timer.step(
          `deposit ${run.fixture.symbol} buyer`,
          () =>
            harness.deposit(
              run.buyer,
              quoteMint,
              buyerAta,
              buyerAmount,
              nextTree++ % cfg.numTrees,
            ),
        );
        const sellerNote = await timer.step(
          `deposit ${run.fixture.symbol} seller`,
          () =>
            harness.deposit(
              run.seller,
              baseMint,
              sellerAta,
              sellerAmount,
              nextTree++ % cfg.numTrees,
            ),
        );
        depositedRuns.push({ ...run, buyerNote, sellerNote });
      }

      // One extra SOL note drives the live cross-market modify + cancel checks.
      const primary = cfg.markets[0];
      const probeMint = new PublicKey(primary.baseMint.pubkey);
      const probeQty = BigInt(primary.market.minOrderSize) + 1000n;
      const probeAmount = withFee(probeQty);
      const probeAta = await mintCollateral(
        connection,
        admin,
        personas.routeProbe,
        probeMint,
        probeAmount,
      );
      const probeNote = await timer.step("deposit route-probe note", () =>
        harness.deposit(
          personas.routeProbe,
          probeMint,
          probeAta,
          probeAmount,
          nextTree++ % cfg.numTrees,
        ),
      );
      const depositCount = await harness.leafCount();
      expect(depositCount).toBe(5);

      const slot = await connection.getSlot("confirmed");
      const expirySlot = BigInt(slot + 3_000);
      const baseOrderIndex = Date.now() % 800_000;

      async function buildOrder(
        persona: Persona,
        fixture: MarketFixture,
        side: OrderSide,
        priceLimit: bigint,
        note: DepositedNote,
        qty: bigint,
        orderIndex: number,
        arrivalNonce = 1n,
      ): Promise<BuiltOrder> {
        const orderId = deriveOrderId(persona.masterSeed, orderIndex);
        const viewingPubkey = deriveViewingEncKeypair(
          persona.masterSeed,
        ).publicKey;
        const proof = await harness.viProof(REPO_ROOT, persona, note);
        const digest = orderCanonicalDigest({
          symbol: new TextEncoder().encode(fixture.symbol),
          side,
          orderType: OrderType.Limit,
          amount: qty,
          priceLimit,
          minFillSize: 0n,
          expirySlot,
          orderId,
          noteCommitment: note.commitment,
          arrivalNonce,
          viewingPubkey,
          sessionId: bootSessionId,
        });
        const signature = nacl.sign.detached(digest, persona.trading.secretKey);
        return {
          orderId,
          symbol: fixture.symbol,
          body: {
            symbol: fixture.symbol,
            side: side === OrderSide.Bid ? "bid" : "ask",
            order_type: "limit",
            amount: Number(qty),
            price_limit: Number(priceLimit),
            min_fill_size: 0,
            expiry_slot: Number(expirySlot),
            order_id: hex(orderId),
            note_commitment: hex(note.commitment),
            arrival_nonce: Number(arrivalNonce),
            trading_key: hex(persona.trading.publicKey.toBytes()),
            trading_key_signature: hex(signature),
            owner_commitment: hex(bn254ToBE32(persona.ownerCommit)),
            note_inner_hash: hex(bn254ToBE32(note.innerHash)),
            nullifier: hex(
              await nullifierV2(persona.spendingKey, note.innerHash),
            ),
            merkle_root: hex(proof.root),
            valid_input_proof: hex(proof.proofBytes),
            collateral_amount: Number(note.amount),
            tree_id: note.treeId,
            viewing_pubkey: hex(viewingPubkey),
            session_id: hex(bootSessionId),
          },
        };
      }

      async function submitOrder(order: BuiltOrder): Promise<Response> {
        return gwFetch(`${GATEWAY}/orders`, {
          method: "POST",
          headers: {
            authorization: `Bearer ${token}`,
            "content-type": "application/json",
          },
          body: JSON.stringify(order.body),
        });
      }

      function cancelBody(
        persona: Persona,
        orderId: Uint8Array,
        cancelNonce: bigint,
      ) {
        const tradingKey = persona.trading.publicKey.toBytes();
        const signature = nacl.sign.detached(
          cancelCanonicalDigest({
            orderId,
            tradingKey,
            cancelNonce,
            sessionId: bootSessionId,
          }),
          persona.trading.secretKey,
        );
        return {
          trading_key: hex(tradingKey),
          cancel_nonce: cancelNonce.toString(),
          session_id: hex(bootSessionId),
          trading_key_signature: hex(signature),
        };
      }

      const probePrice = floorPriceToTick(
        anchors[0] * 2n,
        BigInt(primary.market.tickSize),
      );
      const probeOrder = await buildOrder(
        personas.routeProbe,
        primary,
        OrderSide.Ask,
        probePrice,
        probeNote,
        probeQty,
        baseOrderIndex,
      );
      expect((await submitOrder(probeOrder)).status).toBe(202);

      const crossMarketReplacement = await buildOrder(
        personas.routeProbe,
        cfg.markets[1],
        OrderSide.Ask,
        floorPriceToTick(
          anchors[1] * 2n,
          BigInt(cfg.markets[1].market.tickSize),
        ),
        probeNote,
        probeQty,
        baseOrderIndex + 1,
        2n,
      );
      const modifySignature = nacl.sign.detached(
        cancelCanonicalDigest({
          orderId: probeOrder.orderId,
          tradingKey: personas.routeProbe.trading.publicKey.toBytes(),
          cancelNonce: 1n,
          sessionId: bootSessionId,
        }),
        personas.routeProbe.trading.secretKey,
      );
      const modifyResponse = await gwFetch(
        `${GATEWAY}/orders/${hex(probeOrder.orderId)}`,
        {
          method: "PUT",
          headers: {
            authorization: `Bearer ${token}`,
            "content-type": "application/json",
          },
          body: JSON.stringify({
            cancel_signature: hex(modifySignature),
            cancel_nonce: "1",
            replacement: crossMarketReplacement.body,
          }),
        },
      );
      expect(modifyResponse.status).toBe(400);
      expect(await modifyResponse.text()).toContain(
        "modify cannot move an order between markets",
      );
      const originalAfterModify = await gwFetch(
        `${GATEWAY}/orders/${hex(probeOrder.orderId)}`,
        { headers: { authorization: `Bearer ${token}` } },
      );
      expect(originalAfterModify.status).toBe(200);
      expect(
        ((await originalAfterModify.json()) as { symbol?: string }).symbol,
      ).toBe(primary.symbol);

      const cancelResponse = await gwFetch(
        `${GATEWAY}/orders/${hex(probeOrder.orderId)}`,
        {
          method: "DELETE",
          headers: {
            authorization: `Bearer ${token}`,
            "content-type": "application/json",
          },
          body: JSON.stringify(
            cancelBody(personas.routeProbe, probeOrder.orderId, 2n),
          ),
        },
      );
      expect(cancelResponse.status).toBe(200);
      console.log(
        "  · cross-market modify rejected; original market cancel routed successfully",
      );

      const crossingOrders: BuiltOrder[] = [];
      for (let index = 0; index < depositedRuns.length; index++) {
        const run = depositedRuns[index];
        crossingOrders.push(
          await timer.step(`prove ${run.fixture.symbol} bid input`, () =>
            buildOrder(
              run.buyer,
              run.fixture,
              OrderSide.Bid,
              run.bidPrice,
              run.buyerNote,
              run.qty,
              baseOrderIndex + 100 + index,
            ),
          ),
          await timer.step(`prove ${run.fixture.symbol} ask input`, () =>
            buildOrder(
              run.seller,
              run.fixture,
              OrderSide.Ask,
              run.askPrice,
              run.sellerNote,
              run.qty,
              baseOrderIndex + 200 + index,
            ),
          ),
        );
      }

      const submitStarted = Date.now();
      const statuses = await Promise.all(
        crossingOrders.map(async (order) => {
          const response = await submitOrder(order);
          if (!response.ok) {
            console.log(
              `  !! ${order.symbol} order ${response.status}: ${await response.text()}`,
            );
          }
          return response.status;
        }),
      );
      expect(statuses.every((status) => status === 202)).toBe(true);
      console.log(
        `  · submitted both crossing pairs in ${Date.now() - submitStarted}ms`,
      );

      const pendingByMarket = new Set<string>();
      let finalCount = depositCount;
      let allTerminal = false;
      const minimumOutputLeaves = 4 * depositedRuns.length;
      const deadline = Date.now() + SETTLE_TIMEOUT_MS;
      while (Date.now() < deadline) {
        const orderResponses = await Promise.all(
          crossingOrders.map((order) =>
            gwFetch(`${GATEWAY}/orders/${hex(order.orderId)}`, {
              headers: { authorization: `Bearer ${token}` },
            }),
          ),
        );
        allTerminal = orderResponses.every(
          (response) => response.status === 404,
        );
        for (let index = 0; index < orderResponses.length; index++) {
          const response = orderResponses[index];
          if (response.status !== 200) continue;
          const body = (await response.json()) as {
            status?: string;
            symbol?: string;
          };
          expect(body.symbol).toBe(crossingOrders[index].symbol);
          if (body.status === "pending_settlement") {
            pendingByMarket.add(crossingOrders[index].symbol);
          }
        }
        finalCount = await harness.leafCount();
        if (allTerminal && finalCount >= depositCount + minimumOutputLeaves) {
          break;
        }
        await new Promise((resolvePromise) => setTimeout(resolvePromise, 750));
      }
      console.log(
        `  · both markets settled: leaves ${depositCount} → ${finalCount}; pending observed=${[
          ...pendingByMarket,
        ].join(",")}`,
      );
      expect(allTerminal, "one market still has a live exact-fill order").toBe(
        true,
      );
      expect(finalCount).toBeGreaterThanOrEqual(
        depositCount + minimumOutputLeaves,
      );
      expect([...pendingByMarket].sort()).toEqual(
        cfg.markets.map((market) => market.symbol).sort(),
      );
      timer.mark("settle both markets");

      const second = cfg.markets[1];
      const secondBase = new PublicKey(second.baseMint.pubkey);
      const secondQuote = new PublicKey(second.quoteMint.pubkey);
      async function setSecondMarketEnabled(enabled: boolean): Promise<void> {
        const signature = await sendAndConfirmTransaction(
          connection,
          new Transaction().add(
            await buildUpdateMarketConfigInstruction({
              programId,
              admin: admin.publicKey,
              baseMint: secondBase,
              quoteMint: secondQuote,
              enabled,
              priceScale: BigInt(second.market.priceScale),
              tickSize: BigInt(second.market.tickSize),
              minOrderSize: BigInt(second.market.minOrderSize),
              circuitBreakerBps: BigInt(second.market.circuitBreakerBps),
            }),
          ),
          [admin],
          { commitment: "confirmed" },
        );
        console.log(
          `  · BTC-USDC governance enabled=${enabled} tx=${signature}`,
        );
      }

      async function waitForMatcherRunning(expected: boolean): Promise<void> {
        const governanceDeadline = Date.now() + 150_000;
        while (Date.now() < governanceDeadline) {
          const response = await gwFetch(`${GATEWAY}/system/status`);
          if (response.status === 200) {
            const status = (await response.json()) as {
              matcher_running?: boolean;
              degraded?: boolean;
            };
            if (
              status.matcher_running === expected &&
              status.degraded === !expected
            ) {
              return;
            }
          }
          await new Promise((resolvePromise) =>
            setTimeout(resolvePromise, 2_000),
          );
        }
        throw new Error(
          `governance monitor did not set matcher_running=${expected}`,
        );
      }

      await setSecondMarketEnabled(false);
      try {
        await waitForMatcherRunning(false);
        console.log(
          "  · disabling one MarketConfig paused the venue-wide trading gate",
        );
      } finally {
        await setSecondMarketEnabled(true);
        await waitForMatcherRunning(true);
        console.log("  · restoring MarketConfig resumed the trading gate");
      }
      timer.mark("governance pause + resume");
      timer.report("CVM multi-market rehearsal timings");
    }, 900_000);
  },
);
