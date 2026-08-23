/**
 * CVM e2e — SELF-TRADE PREVENTION.
 *
 * The matcher must never match two orders from the SAME owner (a wash trade):
 * `darkpool-matcher/src/algorithm.rs::generate_matches` skips any crossing pair
 * whose `owner_commitment` is equal. That identity is note-BOUND (intake pins it
 * to the collateral note via `verify_commitment`), so a caller can't spoof it.
 *
 * This flow proves it end-to-end against a live CVM:
 *   1. ONE persona (`self`) deposits a QUOTE note (bid collateral) AND a BASE
 *      note (ask collateral), then submits a crossing bid + ask — both carrying
 *      the SAME owner_commitment.
 *   2. Assert NO self-match: over a window the on-chain leaf_count stays flat and
 *      both orders remain OPEN (GET /orders/{id} → 200, not 404/matched-and-gone).
 *   3. POSITIVE CONTROL: a SECOND persona (`taker`) submits an ask that crosses
 *      the still-open bid. Assert this DOES settle (leaf_count grows, the bid is
 *      now matched-and-gone). This proves the matcher was alive and the pair was
 *      price-matchable — so step 2's non-match was the same-owner rule, not a
 *      dead book.
 *
 * PREREQUISITES: identical to `cvm-settle-e2e` — a fresh `devnet-setup` (reset)
 * so the tree starts empty, a CVM deployed against the real e2e-config mints +
 * private RPC + sync floor, and `vault_config.tee_pubkeys` rotated to the CVM's
 * K shard signers (each funded). See docs/cvm-run-runbook.md.
 *
 * Gated on RUN_CVM_E2E=1 + DARKNYX_TEE_GATEWAY=<https://…>.
 *
 * Run:
 *   RUN_CVM_E2E=1 DARKNYX_TEE_GATEWAY=https://<app_id>-8080.dstack-pha-prod5.phala.network \
 *     FUNDER_KEYPAIR=~/.config/solana/id.json ADMIN_KEYPAIR=.devnet/keypairs/admin.json \
 *     ( cd packages/sdk && ../../node_modules/.bin/vitest run tests/cvm-self-trade.test.ts )
 */

import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

import { beforeAll, describe, expect, it } from "vitest";
import nacl from "tweetnacl";
import {
  Connection,
  Keypair,
  PublicKey,
  Transaction,
  SystemProgram,
  LAMPORTS_PER_SOL,
  sendAndConfirmTransaction,
} from "@solana/web3.js";

import {
  deriveOrderId,
  bn254ToBE32,
  deriveViewingEncKeypair,
} from "../src/keys/key-generators.js";
import { nullifierV2 } from "../src/utxo/note.js";
import { vaultConfigPda } from "../src/idl/vault-client.js";
import {
  orderCanonicalDigest,
  OrderSide,
  OrderType,
} from "../src/orders/canonical.js";
import {
  associatedTokenAddress,
  createAtaIdempotentIx,
  loadKeypairRel,
  mintToIx,
} from "./helpers/e2e-helpers.js";
import {
  CvmHarness,
  makePersona,
  gwFetch,
  authToken,
  fetchOracleAnchor,
  fetchBootSessionId,
  hex,
  withFee,
  scaledQuote,
  floorPriceToTick,
  FEE_RATE_BPS,
  SYMBOL,
  type Persona,
  type DepositedNote,
} from "./helpers/cvm-harness.js";
import type { E2EConfig } from "./devnet-setup.test.js";

const REPO_ROOT = resolve(__dirname, "../../..");
const CONFIG_PATH = resolve(REPO_ROOT, ".devnet/e2e-config.json");
const GATEWAY = (process.env.DARKNYX_TEE_GATEWAY ?? "").replace(/\/$/, "");

const READY =
  process.env.RUN_CVM_E2E === "1" && GATEWAY !== "" && existsSync(CONFIG_PATH);
const maybeDescribe = READY ? describe : describe.skip;

// How long to watch for a (forbidden) self-match before concluding it was
// correctly prevented. The matcher ticks within seconds; a generous window
// keeps the negative assertion robust without waiting a full settle timeout.
const NO_MATCH_WINDOW_MS = Number(
  process.env.DARKNYX_CVM_NO_MATCH_MS ?? "25000",
);
// How long to wait for the positive-control cross-owner settle to land.
const SETTLE_TIMEOUT_MS = Number(
  process.env.DARKNYX_CVM_SETTLE_TIMEOUT_MS ?? "90000",
);

maybeDescribe("CVM self-trade prevention", () => {
  let cfg: E2EConfig;
  let conn: Connection;
  let admin: Keypair;
  let funder: Keypair;
  let vaultProgramId: PublicKey;
  let baseMint: PublicKey;
  let quoteMint: PublicKey;
  let self_: Persona;
  let taker: Persona;

  beforeAll(async () => {
    cfg = JSON.parse(readFileSync(CONFIG_PATH, "utf8")) as E2EConfig;
    conn = new Connection(
      process.env.SOLANA_RPC_URL ?? "https://api.devnet.solana.com",
      "confirmed",
    );
    admin = await loadKeypairRel(
      REPO_ROOT,
      process.env.ADMIN_KEYPAIR ?? ".devnet/keypairs/admin.json",
    );
    funder = process.env.FUNDER_KEYPAIR
      ? await loadKeypairRel(REPO_ROOT, process.env.FUNDER_KEYPAIR)
      : admin;
    vaultProgramId = new PublicKey(cfg.vaultProgramId);
    baseMint = new PublicKey(cfg.baseMint.pubkey);
    quoteMint = new PublicKey(cfg.quoteMint.pubkey);
    // Distinct seeds → distinct owner_commitment (the self-trade key).
    self_ = await makePersona(REPO_ROOT, "cvm-selftrade", 0x50);
    taker = await makePersona(REPO_ROOT, "cvm-selftrade-taker", 0x90);
  });

  it(
    "refuses to match a same-owner crossing pair, then matches a cross-owner ask",
    async () => {
      const QTY = BigInt(
        process.env.DARKNYX_CVM_BASE_QTY ??
          String((Date.now() % 250_000) + 1000),
      );
      const N = Number(
        process.env.DARKNYX_CVM_ORDER_N ?? String(Date.now() % 1_000_000),
      );

      const anchor = await fetchOracleAnchor();
      const tickSize = BigInt(cfg.market.tickSize);
      const bidPrice = floorPriceToTick((anchor * 12n) / 10n, tickSize); // high → crosses
      const askPrice = floorPriceToTick((anchor * 8n) / 10n, tickSize); // low → crossed
      const PRICE_SCALE = BigInt(cfg.market.priceScale);
      console.log(
        `  · QTY=${QTY} bid=${bidPrice} ask=${askPrice} feeBps=${FEE_RATE_BPS}`,
      );

      const numTrees = (cfg as unknown as { numTrees?: number }).numTrees ?? 1;
      const harness = await CvmHarness.create(conn, vaultProgramId, numTrees);

      const startCount = await harness.leafCount();
      expect(
        startCount,
        "tree not empty — run devnet-setup (reset) first",
      ).toBe(0);

      // ── fund the two payers ───────────────────────────────────────────
      for (const p of [self_, taker]) {
        const bal = await conn.getBalance(p.payer.publicKey);
        if (bal < 0.05 * LAMPORTS_PER_SOL) {
          await sendAndConfirmTransaction(
            conn,
            new Transaction().add(
              SystemProgram.transfer({
                fromPubkey: funder.publicKey,
                toPubkey: p.payer.publicKey,
                lamports: 0.1 * LAMPORTS_PER_SOL,
              }),
            ),
            [funder],
          );
        }
      }

      // ── collateral: self needs a QUOTE note (bid) + a BASE note (ask);
      //    taker needs a BASE note (its crossing ask) ─────────────────────
      const bidNoteAmt = withFee(scaledQuote(QTY, bidPrice, PRICE_SCALE)); // quote
      const askNoteAmt = withFee(QTY); // base
      const selfQuoteAta = await associatedTokenAddress(
        quoteMint,
        self_.payer.publicKey,
      );
      const selfBaseAta = await associatedTokenAddress(
        baseMint,
        self_.payer.publicKey,
      );
      const takerBaseAta = await associatedTokenAddress(
        baseMint,
        taker.payer.publicKey,
      );
      await sendAndConfirmTransaction(
        conn,
        new Transaction().add(
          createAtaIdempotentIx(
            admin,
            selfQuoteAta,
            self_.payer.publicKey,
            quoteMint,
          ),
          createAtaIdempotentIx(
            admin,
            selfBaseAta,
            self_.payer.publicKey,
            baseMint,
          ),
          createAtaIdempotentIx(
            admin,
            takerBaseAta,
            taker.payer.publicKey,
            baseMint,
          ),
          mintToIx(quoteMint, selfQuoteAta, admin, bidNoteAmt),
          mintToIx(baseMint, selfBaseAta, admin, askNoteAmt),
          mintToIx(baseMint, takerBaseAta, admin, askNoteAmt),
        ),
        [admin],
      );

      const selfBidNote = await harness.deposit(
        self_,
        quoteMint,
        selfQuoteAta,
        bidNoteAmt,
      );
      const selfAskNote = await harness.deposit(
        self_,
        baseMint,
        selfBaseAta,
        askNoteAmt,
      );
      const takerAskNote = await harness.deposit(
        taker,
        baseMint,
        takerBaseAta,
        askNoteAmt,
      );
      const depositCount = await harness.leafCount();
      expect(depositCount).toBe(3);

      // ── VALID_INPUT proofs (relayed to lock_note via the order) ───────
      const selfBidVI = await harness.viProof(REPO_ROOT, self_, selfBidNote);
      const selfAskVI = await harness.viProof(REPO_ROOT, self_, selfAskNote);
      const takerAskVI = await harness.viProof(REPO_ROOT, taker, takerAskNote);

      const slot = await conn.getSlot("confirmed");
      // Production intake caps lock TTLs at 4,500 slots.
      const expirySlot = slot + 3_000n;
      const bootSessionId = await fetchBootSessionId(GATEWAY);

      // Build a signed limit-order body (a plain-limit subset of the settle
      // test's inline builder — no fills/re-match knobs needed here).
      async function buildOrder(
        p: Persona,
        side: OrderSide,
        priceLimit: bigint,
        note: DepositedNote,
        vi: { proofBytes: Uint8Array; root: Uint8Array },
        orderIndex: number,
        arrivalNonce: bigint = 1n,
      ) {
        const orderId = deriveOrderId(p.masterSeed, orderIndex);
        const viewingPubkey = deriveViewingEncKeypair(p.masterSeed).publicKey;
        const digest = orderCanonicalDigest({
          symbol: new TextEncoder().encode(SYMBOL),
          side,
          orderType: OrderType.Limit,
          amount: QTY,
          priceLimit,
          minFillSize: 0n,
          expirySlot,
          orderId,
          noteCommitment: note.commitment,
          arrivalNonce,
          viewingPubkey,
          sessionId: bootSessionId,
        });
        const sig = nacl.sign.detached(digest, p.trading.secretKey);
        return {
          order_id: hex(orderId),
          body: {
            symbol: SYMBOL,
            side: side === OrderSide.Bid ? "bid" : "ask",
            order_type: "limit",
            amount: Number(QTY),
            price_limit: Number(priceLimit),
            min_fill_size: 0,
            expiry_slot: Number(expirySlot),
            order_id: hex(orderId),
            note_commitment: hex(note.commitment),
            arrival_nonce: Number(arrivalNonce),
            trading_key: hex(p.trading.publicKey.toBytes()),
            trading_key_signature: hex(sig),
            owner_commitment: hex(bn254ToBE32(p.ownerCommit)),
            note_inner_hash: hex(bn254ToBE32(note.innerHash)),
            nullifier: hex(await nullifierV2(p.spendingKey, note.innerHash)),
            merkle_root: hex(vi.root),
            valid_input_proof: hex(vi.proofBytes),
            collateral_amount: Number(note.amount),
            tree_id: note.treeId,
            viewing_pubkey: hex(viewingPubkey),
            session_id: hex(bootSessionId),
          },
        };
      }

      const selfBid = await buildOrder(
        self_,
        OrderSide.Bid,
        bidPrice,
        selfBidNote,
        selfBidVI,
        N,
      );
      const selfAsk = await buildOrder(
        self_,
        OrderSide.Ask,
        askPrice,
        selfAskNote,
        selfAskVI,
        N + 1,
        2n,
      );
      const takerAsk = await buildOrder(
        taker,
        OrderSide.Ask,
        askPrice,
        takerAskNote,
        takerAskVI,
        N + 2,
      );

      const token = await authToken(GATEWAY);
      const submit = async (body: object): Promise<number> => {
        const r = await gwFetch(`${GATEWAY}/orders`, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            authorization: `Bearer ${token}`,
          },
          body: JSON.stringify(body),
        });
        if (!String(r.status).startsWith("2")) {
          console.log(`  !! /orders ${r.status}: ${await r.text()}`);
        }
        return r.status;
      };
      const isOpen = async (orderId: string): Promise<boolean> => {
        const r = await gwFetch(`${GATEWAY}/orders/${orderId}`, {
          headers: { authorization: `Bearer ${token}` },
        });
        return r.status === 200;
      };

      // ── 1. submit the same-owner crossing pair ────────────────────────
      const b1 = await submit(selfBid.body);
      const a1 = await submit(selfAsk.body);
      expect(String(b1).startsWith("2"), `self bid rejected (${b1})`).toBe(
        true,
      );
      expect(String(a1).startsWith("2"), `self ask rejected (${a1})`).toBe(
        true,
      );
      console.log(
        `  · self orders accepted (bid=${selfBid.order_id.slice(0, 8)}, ask=${selfAsk.order_id.slice(0, 8)})`,
      );

      // ── 2. assert NO self-match over the window ───────────────────────
      const deadline = Date.now() + NO_MATCH_WINDOW_MS;
      while (Date.now() < deadline) {
        const c = await harness.leafCount();
        expect(
          c,
          `SELF-MATCH LEAKED — leaf_count grew ${depositCount}→${c}; the matcher settled a same-owner pair`,
        ).toBe(depositCount);
        await new Promise((r) => setTimeout(r, 3000));
      }
      expect(
        await isOpen(selfBid.order_id),
        "self bid should still be open",
      ).toBe(true);
      expect(
        await isOpen(selfAsk.order_id),
        "self ask should still be open",
      ).toBe(true);
      console.log(
        `  · self-trade prevented — no settle after ${NO_MATCH_WINDOW_MS}ms, both orders still open`,
      );

      // ── 3. POSITIVE CONTROL: cross-owner ask crosses the open bid ──────
      const a2 = await submit(takerAsk.body);
      expect(String(a2).startsWith("2"), `taker ask rejected (${a2})`).toBe(
        true,
      );
      console.log(
        `  · taker ask accepted (${takerAsk.order_id.slice(0, 8)}) — expecting a settle`,
      );

      let finalCount = depositCount;
      const settleDeadline = Date.now() + SETTLE_TIMEOUT_MS;
      while (Date.now() < settleDeadline) {
        finalCount = await harness.leafCount();
        if (finalCount > depositCount) break;
        await new Promise((r) => setTimeout(r, 3000));
      }
      console.log(`  · on-chain leaf_count: ${depositCount} → ${finalCount}`);
      expect(
        finalCount,
        "cross-owner ask did NOT settle — matcher may be down (positive control failed)",
      ).toBeGreaterThan(depositCount);
      // The self bid matched the taker's ask → matched-and-gone; the self ask
      // had no remaining crossing bid and stays open.
      expect(
        await isOpen(selfBid.order_id),
        "self bid should be matched-and-gone",
      ).toBe(false);
      console.log(
        "  · cross-owner match settled — self-trade prevention confirmed (matcher live, pair was matchable)",
      );
    },
    Number(process.env.DARKNYX_CVM_TEST_TIMEOUT_MS ?? "300000"),
  );
});
