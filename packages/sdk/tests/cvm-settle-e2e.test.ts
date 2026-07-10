/**
 * Phase 3b/3c — first REAL CVM-driven settle e2e.
 *
 * Unlike `devnet-trade-flow` (where the SDK plays the TEE and drives
 * lock/verify/settle itself), here the **CVM** does the matching AND
 * the settle: we deposit two real notes, submit a crossing buy + sell
 * to the live enclave's `POST /orders`, and the CVM's settle scheduler
 * runs lock_note → verify_match_batch → tee_forced_settle_batched →
 * close, signed by its own dstack key. We assert the settle landed by
 * watching the on-chain `VaultConfig.leaf_count` grow.
 *
 * PREREQUISITES (3c orchestration — see memory tee_api_plan / spot-check):
 *   1. Vault redeployed with the v6 payload + the set_tee_pubkey ix.
 *   2. `devnet-setup` run FRESH (reset_merkle_tree) right before this,
 *      so the on-chain tree starts EMPTY — our two deposits land at
 *      leaf 0,1 and our in-memory MerkleShadow matches the on-chain
 *      root (the VALID_INPUT proof root must be in the vault's recent
 *      ring at lock time).
 *   3. A CVM deployed with the REAL e2e-config mints + a private RPC +
 *      the sync floor:
 *        phala deploy -e NYX_TEE_BASE_MINT=<base58> \
 *          -e NYX_TEE_QUOTE_MINT=<base58> \
 *          -e NYX_TEE_SOLANA_RPC_URL=<helius> \
 *          -e NYX_TEE_SYNC_FROM_SLOT=<reset slot> …
 *   4. `vault_config.tee_pubkey` rotated to the CVM's /info signer
 *      (set_tee_pubkey, admin keypair), and that signer funded with SOL
 *      (`solana transfer`).
 *
 * Gated on RUN_CVM_E2E=1 + NYX_TEE_GATEWAY=<https://…>. Pricing is
 * anchored to the live Hermes feed (override with NYX_CVM_PRICE);
 * NYX_CVM_BASE_QTY tunes the trade size.
 *
 * Run:
 *   RUN_CVM_E2E=1 NYX_TEE_GATEWAY=https://<app_id>-8080.dstack-pha-prod5.phala.network \
 *     FUNDER_KEYPAIR=~/.config/solana/id.json ADMIN_KEYPAIR=.devnet/keypairs/admin.json \
 *     ( cd packages/sdk && ../../node_modules/.bin/vitest run tests/cvm-settle-e2e.test.ts )
 */

import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

import { beforeAll, describe, expect, it } from "vitest";
import nacl from "tweetnacl";
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
import { buildAnchorPool, anchorsToJson } from "../src/orders/anchor-pool.js";
import { vaultConfigPda } from "../src/idl/vault-client.js";
import {
  orderCanonicalDigest,
  OrderSide,
  OrderType,
} from "../src/orders/canonical.js";
import { fetchOrderFills } from "../src/fills/history.js";
import { recoverChangeFromChain } from "../src/fills/recover.js";
import {
  subscribeFills,
  type FillsSubscription,
} from "../src/fills/ws-client.js";
import {
  InMemoryNoteStore,
  type ChangeNoteRecord,
} from "../src/utxo/note-store.js";
import {
  loadKeypairRel,
  StepTimer,
  fetchSettleTimeline,
  reportSettleTimeline,
} from "./helpers/e2e-helpers.js";
import {
  CvmHarness,
  makePersona,
  gwFetch,
  fetchOracleAnchor,
  hex,
  withFee,
  FEE_RATE_BPS,
  SYMBOL,
  API_KEY,
  API_SECRET,
  PASSPHRASE,
  type Persona,
  type DepositedNote,
} from "./helpers/cvm-harness.js";
import type { E2EConfig } from "./devnet-setup.test.js";

const REPO_ROOT = resolve(__dirname, "../../..");
const CONFIG_PATH = resolve(REPO_ROOT, ".devnet/e2e-config.json");
const GATEWAY = (process.env.NYX_TEE_GATEWAY ?? "").replace(/\/$/, "");

const READY =
  process.env.RUN_CVM_E2E === "1" && GATEWAY !== "" && existsSync(CONFIG_PATH);
const maybeDescribe = READY ? describe : describe.skip;

// CVM creds, SYMBOL, FEE_RATE_BPS, gwFetch, fetchOracleAnchor, hex, withFee,
// Persona/makePersona, and the shard-aware deposit/witness harness all live in
// `./helpers/cvm-harness.ts` (shared across the cvm-* tests).
const SETTLE_TIMEOUT_MS = Number(
  process.env.NYX_CVM_SETTLE_TIMEOUT_MS ?? "60000",
);

// Fills mode (opt-in): when NYX_INDEXER_URL points at a locally-running indexer
// (`scripts/run-indexer-local.sh`), additionally assert the buyer's continuation
// change note surfaces over BOTH paths — the durable off-TEE indexer
// (GET /fills, decoded from the on-chain settle) and the live per-account WS
// (FillMemo). The WS half needs a CVM built from the fills commit; the indexer
// half works against any deployed CVM (it only reads the chain).
const INDEXER_URL = (process.env.NYX_INDEXER_URL ?? "").replace(/\/$/, "");
const FILLS = INDEXER_URL !== "";

// Cross-batch re-match (opt-in, requires FILLS). After the buyer's residual
// relocks onto an anchor in batch 1, submit a SECOND ask so the matcher
// re-matches that relocked note in a NEW batch and settles it again — proving
// a partial fill's continuation actually re-matches across batches, not just
// that one continuation note is minted. Needs a 3rd (seller2) deposit up-front.
const REMATCH = FILLS && process.env.NYX_CVM_REMATCH === "1";

maybeDescribe(
  "Phase 3 — CVM-driven settle e2e (deposit → CVM match → CVM settle)",
  () => {
    let cfg: E2EConfig;
    let conn: Connection;
    let admin: Keypair;
    let funder: Keypair;
    let vaultProgramId: PublicKey;
    let vaultPda: PublicKey;
    let baseMint: PublicKey;
    let quoteMint: PublicKey;
    let buyer: Persona;
    let seller: Persona;

    beforeAll(async () => {
      cfg = JSON.parse(readFileSync(CONFIG_PATH, "utf8")) as E2EConfig;
      conn = new Connection(
        process.env.SOLANA_RPC_URL ?? "https://api.devnet.solana.com",
        "confirmed",
      );
      admin = loadKeypairRel(
        REPO_ROOT,
        process.env.ADMIN_KEYPAIR ?? ".devnet/keypairs/admin.json",
      );
      funder = process.env.FUNDER_KEYPAIR
        ? loadKeypairRel(REPO_ROOT, process.env.FUNDER_KEYPAIR)
        : admin;
      vaultProgramId = new PublicKey(cfg.vaultProgramId);
      [vaultPda] = vaultConfigPda(vaultProgramId);
      baseMint = new PublicKey(cfg.baseMint.pubkey);
      quoteMint = new PublicKey(cfg.quoteMint.pubkey);
      buyer = await makePersona(REPO_ROOT, "cvm-buyer", 0x40);
      seller = await makePersona(REPO_ROOT, "cvm-seller", 0x80);
    });

    it(
      "CVM matches a crossing pair and settles on-chain",
      async () => {
        // Per-run-unique base qty so the deposited note commitments (and
        // thus the NoteLock / ConsumedNote PDAs) are FRESH each run —
        // reset_merkle_tree clears the tree but NOT those PDAs, so a fixed
        // note would collide ("Allocate: account already in use") on the
        // second run. Override with NYX_CVM_BASE_QTY for a fixed value.
        //
        // Capped at 250k: the buyer's collateral is BUY_QTY×bidPrice×(1+fee),
        // and in FILLS mode BUY_QTY = 2×BASE_QTY. The order body sends
        // `collateral_amount` as a JSON number, so it must stay ≤ 2^53
        // (Number.MAX_SAFE_INTEGER ≈ 9.007e15) or `Number(noteAmt)` rounds it and
        // intake rejects it as 1 below the required floor. 2×250k×bidPrice(~7.4e9)
        // ≈ 3.7e15 — comfortably exact even if SOL's price doubles.
        const BASE_QTY = BigInt(
          process.env.NYX_CVM_BASE_QTY ?? String((Date.now() % 250_000) + 1000),
        );
        // Run-unique order-id index. Order ids are now DETERMINISTIC
        // (`deriveOrderId(seed, n)`) so fills mode can query the indexer by the
        // exact id we used; the run-unique `n` keeps re-runs from colliding on the
        // same id (and lets the indexer's by-order_id rows stay per-run).
        const ORDER_N = Number(
          process.env.NYX_CVM_ORDER_N ?? String(Date.now() % 1_000_000),
        );
        const t = new StepTimer();
        const anchor = await t.step("oracle anchor (Hermes)", () =>
          fetchOracleAnchor(),
        );
        const bidPrice = (anchor * 12n) / 10n;
        const askPrice = (anchor * 8n) / 10n;
        // In FILLS mode we validate the anchor-pool partial-fill CONTINUATION: the
        // buyer over-buys (bids 2× the seller's qty) so only BASE_QTY crosses and
        // the residual relocks onto anchor[0]. That relock is the ONLY path that
        // rewrites note_e to an anchor-based change note (reconstructChangeNote)
        // AND emits a live FillMemo (assign_continuation_anchors) — both fills
        // assertions are continuation-only, so a full fill can't exercise them.
        // Without FILLS we keep the simpler full-fill settle check (BUY_QTY=BASE_QTY).
        // Override the multiplier with NYX_CVM_BUY_MULT.
        const BUY_MULT = BigInt(
          process.env.NYX_CVM_BUY_MULT ?? (FILLS ? "2" : "1"),
        );
        const BUY_QTY = BASE_QTY * BUY_MULT;
        console.log(
          `  · BASE_QTY=${BASE_QTY} buyQty=${BUY_QTY} (mult ${BUY_MULT}${FILLS ? ", partial-fill continuation" : ""}) bid=${bidPrice} ask=${askPrice} feeBps=${FEE_RATE_BPS}`,
        );

        // Number of Merkle shards (K). Deposits + settle outputs route across
        // them; the harness keeps one shadow per shard and recovers each note's
        // (tree_id, leaf_index) from its NoteCreated event.
        const numTrees =
          (cfg as unknown as { numTrees?: number }).numTrees ?? 1;
        const harness = await CvmHarness.create(conn, vaultProgramId, numTrees);

        // The tree must be empty (fresh reset) so each shard's shadow starts from
        // 0 and matches on-chain.
        const startCount = await harness.leafCount();
        expect(
          startCount,
          "tree not empty — run devnet-setup (reset) first",
        ).toBe(0);

        // For the cross-batch re-match we need a 2nd ask, so a 3rd deposit
        // (seller2). It's pre-deposited up-front: its VALID_INPUT root stays in
        // the vault's 64-deep recent-root ring through batch 1's settle, so the
        // proof is still valid when batch 2 locks it.
        const seller2 = REMATCH
          ? await makePersona(REPO_ROOT, "cvm-seller2", 0xc0)
          : null;
        const personas = seller2 ? [buyer, seller, seller2] : [buyer, seller];

        // ── 1. fund payers + mint collateral ───────────────────────────
        await t.step("fund payers (SOL)", async () => {
          for (const p of personas) {
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
        });

        const buyerQuoteAta = await getAssociatedTokenAddress(
          quoteMint,
          buyer.payer.publicKey,
        );
        const sellerBaseAta = await getAssociatedTokenAddress(
          baseMint,
          seller.payer.publicKey,
        );
        // Each side locks NOMINAL collateral + its OWN protocol fee, matching
        // the intake derivation (orders.rs: note_amount = nominal + nominal *
        // bps / 10_000, floored). Bid nominal = qty × price (quote); ask
        // nominal = qty (base). With fees off (bps=0) both collapse to the
        // nominal, unchanged. Floor division must match intake exactly so the
        // re-derived commitment lines up. (`withFee` is shared from cvm-harness.)
        // Over-collateralization knob: deposit a buyer note LARGER than the order
        // needs (NYX_CVM_BUYER_SURPLUS quote units). The order declares its actual
        // collateral_amount; intake accepts note ≥ required and the matcher returns
        // the surplus as an (even bigger) change note. Default 0 ⇒ exact-at-limit.
        const BUYER_SURPLUS = BigInt(process.env.NYX_CVM_BUYER_SURPLUS ?? "0");
        const buyerNoteAmt = withFee(BUY_QTY * bidPrice) + BUYER_SURPLUS;
        const sellerNoteAmt = withFee(BASE_QTY);

        await t.step("mint collateral (ATAs + mintTo)", () =>
          sendAndConfirmTransaction(
            conn,
            new Transaction().add(
              createAssociatedTokenAccountIdempotentInstruction(
                admin.publicKey,
                buyerQuoteAta,
                buyer.payer.publicKey,
                quoteMint,
              ),
              createAssociatedTokenAccountIdempotentInstruction(
                admin.publicKey,
                sellerBaseAta,
                seller.payer.publicKey,
                baseMint,
              ),
              createMintToInstruction(
                quoteMint,
                buyerQuoteAta,
                admin.publicKey,
                buyerNoteAmt,
              ),
              createMintToInstruction(
                baseMint,
                sellerBaseAta,
                admin.publicKey,
                sellerNoteAmt,
              ),
            ),
            [admin],
          ),
        );

        // ── 2. deposit both notes; mirror into the per-shard shadow trees ──
        // The harness reads each deposit's actual (tree_id, leaf_index) back from
        // its NoteCreated event and appends to that shard's shadow, so the
        // VALID_INPUT witness is built against the right tree.
        const buyerNote = await t.step("deposit buyer note", () =>
          harness.deposit(buyer, quoteMint, buyerQuoteAta, buyerNoteAmt),
        );
        const sellerNote = await t.step("deposit seller note", () =>
          harness.deposit(seller, baseMint, sellerBaseAta, sellerNoteAmt),
        );

        // seller2: a 2nd ask's collateral, deposited now (leaf 2) for the
        // batch-2 re-match. Same base amount as seller1.
        let seller2Note: DepositedNote | null = null;
        if (seller2) {
          const seller2BaseAta = await getAssociatedTokenAddress(
            baseMint,
            seller2.payer.publicKey,
          );
          await t.step("mint seller2 collateral", () =>
            sendAndConfirmTransaction(
              conn,
              new Transaction().add(
                createAssociatedTokenAccountIdempotentInstruction(
                  admin.publicKey,
                  seller2BaseAta,
                  seller2.payer.publicKey,
                  baseMint,
                ),
                createMintToInstruction(
                  baseMint,
                  seller2BaseAta,
                  admin.publicKey,
                  sellerNoteAmt,
                ),
              ),
              [admin],
            ),
          );
          seller2Note = await t.step("deposit seller2 note", () =>
            harness.deposit(seller2, baseMint, seller2BaseAta, sellerNoteAmt),
          );
        }

        // shadow root must equal on-chain current_root (so the VALID_INPUT
        // proof root is in the vault's recent ring at lock time).
        const depositCount = await harness.leafCount();
        expect(depositCount).toBe(REMATCH ? 3 : 2);

        // ── 3. VALID_INPUT proofs (relayed to lock_note via the order) ──
        // harness.viProof witnesses against the shard the note landed in.
        const buyerVI = await t.step("VALID_INPUT prove buyer (snarkjs)", () =>
          harness.viProof(REPO_ROOT, buyer, buyerNote),
        );
        const sellerVI = await t.step(
          "VALID_INPUT prove seller (snarkjs)",
          () => harness.viProof(REPO_ROOT, seller, sellerNote),
        );
        const seller2VI =
          seller2 && seller2Note
            ? await t.step("VALID_INPUT prove seller2 (snarkjs)", () =>
                harness.viProof(REPO_ROOT, seller2, seller2Note!),
              )
            : null;

        // ── 4. build + sign the two orders ─────────────────────────────
        const slot = await conn.getSlot("confirmed");
        // Within MAX_LOCK_TTL_SLOTS (4_500 ≈ 30 min; F-05) so intake accepts it
        // and the settle-time lock_note doesn't hit the cap. Far more than the
        // ~90 s the test needs, with margin for TEE/client slot-view skew.
        const expirySlot = BigInt(slot + 3_000);

        async function buildOrder(
          p: Persona,
          side: OrderSide,
          priceLimit: bigint,
          note: DepositedNote,
          vi: { proofBytes: Uint8Array; root: Uint8Array },
          orderIndex: number,
          qty: bigint,
          expiryOverride?: bigint,
        ) {
          // F-05: an over-cap expiry lets us assert intake rejects it; normal
          // orders use the within-cap module `expirySlot`.
          const exp = expiryOverride ?? expirySlot;
          // Deterministic per (seed, n) — buyer + seller have distinct seeds, so
          // the same n yields distinct ids. Recoverable by the fills gap-scan.
          const orderId = deriveOrderId(p.masterSeed, orderIndex);
          // v2: the order carries a fixed continuation anchor pool whose hash
          // is bound into the signed (v2) canonical digest.
          const pool = await buildAnchorPool(
            p.masterSeed,
            p.spendingKey,
            orderId,
          );
          const digest = orderCanonicalDigest({
            symbol: new TextEncoder().encode(SYMBOL),
            side,
            orderType: OrderType.Limit,
            amount: qty,
            priceLimit,
            minFillSize: 0n,
            expirySlot: exp,
            orderId,
            noteCommitment: note.commitment,
            userCommitment: p.userCommitment,
            arrivalNonce: 1n,
            anchorPoolHash: pool.poolHash,
          });
          const sig = nacl.sign.detached(digest, p.trading.secretKey);
          return {
            symbol: SYMBOL,
            side: side === OrderSide.Bid ? "bid" : "ask",
            order_type: "limit",
            amount: Number(qty),
            price_limit: Number(priceLimit),
            min_fill_size: 0,
            expiry_slot: Number(exp),
            order_id: hex(orderId),
            note_commitment: hex(note.commitment),
            user_commitment: hex(p.userCommitment),
            arrival_nonce: 1,
            trading_key: hex(p.trading.publicKey.toBytes()),
            trading_key_signature: hex(sig),
            owner_commitment: hex(bn254ToBE32(p.ownerCommit)),
            note_inner_hash: hex(bn254ToBE32(note.innerHash)),
            nullifier: hex(await nullifierV2(p.spendingKey, note.innerHash)),
            merkle_root: hex(vi.root),
            valid_input_proof: hex(vi.proofBytes),
            // Declare the note's ACTUAL amount. For an exact-collateral order this
            // equals the derived floor (a no-op); for an over-collateralized one
            // it's larger and intake accepts note ≥ required.
            collateral_amount: Number(note.amount),
            tree_id: note.treeId,
            // Change-amount recovery (Proposal B): the seed-derived viewing key
            // the TEE encrypts this order's change_amount to on-chain. NOT in the
            // signed canonical (so the digest above is unchanged). Without it the
            // TEE writes the all-zero fill_recovery sentinel and recovery can't run.
            viewing_pubkey: hex(
              deriveViewingEncKeypair(p.masterSeed).publicKey,
            ),
            anchors: anchorsToJson(pool.anchors),
          };
        }
        const buyerOrder = await buildOrder(
          buyer,
          OrderSide.Bid,
          bidPrice,
          buyerNote,
          buyerVI,
          ORDER_N,
          BUY_QTY,
        );
        const sellerOrder = await buildOrder(
          seller,
          OrderSide.Ask,
          askPrice,
          sellerNote,
          sellerVI,
          ORDER_N,
          BASE_QTY,
        );

        // ── 5. auth + submit both orders to the CVM ────────────────────
        const tokRes = await t.step("auth/token (CVM)", () =>
          gwFetch(`${GATEWAY}/auth/token`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
              api_key: API_KEY,
              api_secret: API_SECRET,
              passphrase: PASSPHRASE,
            }),
          }),
        );
        expect(tokRes.status, "auth/token failed").toBe(200);
        const token = ((await tokRes.json()) as { access_token: string })
          .access_token;

        // ── F-05: intake rejects an over-cap expiry (never enters the book) ──
        const overCapOrder = await buildOrder(
          buyer,
          OrderSide.Bid,
          bidPrice,
          buyerNote,
          buyerVI,
          ORDER_N + 777, // distinct order id
          BASE_QTY,
          BigInt(slot + 100_000), // ≫ MAX_LOCK_TTL_SLOTS (~4_500)
        );
        const overCapResp = await t.step(
          "F-05: over-cap expiry rejected at intake",
          () =>
            gwFetch(`${GATEWAY}/orders`, {
              method: "POST",
              headers: {
                "content-type": "application/json",
                authorization: `Bearer ${token}`,
              },
              body: JSON.stringify(overCapOrder),
            }),
        );
        expect(
          overCapResp.status,
          "over-cap expiry must be rejected at intake (F-05)",
        ).toBe(400);
        const overCapJson = (await overCapResp.json()) as { code?: number };
        expect(overCapJson.code, "expected expiry_too_far (1007)").toBe(1007);
        console.log(
          "  · F-05: over-cap order rejected at intake (400 expiry_too_far)",
        );

        // Fills (live): open the per-account WS BEFORE submitting. The matcher
        // emits the FillMemo at MATCH time (broadcast, not buffered for late
        // subscribers), so we must be connected first. Verifies + stores via the
        // real client path (buyer keys — the buyer is the side that changes).
        const wsStore = new InMemoryNoteStore();
        const wsFills: ChangeNoteRecord[] = [];
        let wsSub: FillsSubscription | undefined;
        if (FILLS) {
          wsSub = subscribeFills({
            gatewayWsUrl: GATEWAY.replace(/^http/, "ws"),
            token,
            masterSeed: buyer.masterSeed,
            ownerCommitment: buyer.ownerCommit,
            store: wsStore,
            onFill: (r) => wsFills.push(r),
            onError: (e) => console.log(`  !! ws/fills: ${e.message}`),
          });
          await new Promise((r) => setTimeout(r, 2000)); // let the upgrade connect
        }

        async function submit(body: object): Promise<number> {
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
        }
        const s1 = await t.step("submit buyer order (intake + VI verify)", () =>
          submit(buyerOrder),
        );
        const s2 = await t.step(
          "submit seller order (intake + VI verify)",
          () => submit(sellerOrder),
        );
        expect(String(s1).startsWith("2"), `buyer order rejected (${s1})`).toBe(
          true,
        );
        expect(
          String(s2).startsWith("2"),
          `seller order rejected (${s2})`,
        ).toBe(true);
        console.log(
          `  · orders accepted (buyer=${buyerOrder.order_id.slice(0, 8)} bid=${bidPrice}, seller=${sellerOrder.order_id.slice(0, 8)} ask=${askPrice})`,
        );

        // Diagnostic: confirm both are in the book (200) vs matched-and-gone
        // (404), to localise a no-settle to matching vs the settle pipeline.
        for (const [n, o] of [
          ["buyer", buyerOrder],
          ["seller", sellerOrder],
        ] as const) {
          const r = await gwFetch(`${GATEWAY}/orders/${o.order_id}`, {
            headers: { authorization: `Bearer ${token}` },
          });
          console.log(
            `  · GET /orders/${n} -> ${r.status} ${(await r.text()).slice(0, 200)}`,
          );
        }
        console.log("  · waiting for match + settle…");

        // ── 6. watch on-chain leaf_count grow (settle appended note_c/d) ─
        // The black box: wall-time from "orders accepted" to the settle landing
        // on-chain — covers the CVM matcher tick + lock_note → verify_match_batch
        // → per-batch ALT → tee_forced_settle_batched → close (5 txs). For the
        // per-stage split, cross-reference `phala cvms logs` (each stage is logged
        // with a timestamp); this client-side number is the end-to-end latency.
        let finalCount = depositCount;
        await t.step(
          "CVM match + settle (on-chain leaf_count +2)",
          async () => {
            const deadline = Date.now() + SETTLE_TIMEOUT_MS;
            while (Date.now() < deadline) {
              finalCount = await harness.leafCount();
              if (finalCount >= depositCount + 2) break;
              await new Promise((r) => setTimeout(r, 3000));
            }
          },
        );
        console.log(`  · on-chain leaf_count: ${depositCount} → ${finalCount}`);
        expect(
          finalCount,
          "settle did not land — CVM logs (phala cvms logs) show the failing settle stage",
        ).toBeGreaterThanOrEqual(depositCount + 2);

        // Per-stage settle breakdown: read the 5 settle txs off the CVM signer's
        // on-chain history (lock×2 → verify → settle → close) and report their
        // slot/blockTime deltas. Best-effort — never fails the test.
        try {
          const infoRes = await gwFetch(`${GATEWAY}/info`);
          const info = (await infoRes.json()) as { tee_pubkey?: string };
          if (info.tee_pubkey) {
            const timeline = await fetchSettleTimeline(
              conn,
              new PublicKey(info.tee_pubkey),
              {
                limit: 12,
                vaultProgramId: cfg.vaultProgramId,
              },
            );
            reportSettleTimeline(
              "cvm settle pipeline (on-chain, CVM signer)",
              timeline,
            );
          }
        } catch (e) {
          console.log(
            `  !! settle-timeline probe failed: ${(e as Error).message}`,
          );
        }

        // ── 7. fills delivery (durable indexer + live WS) ──────────────
        if (FILLS) {
          const buyerId = buyerOrder.order_id;

          // Durable: poll the local indexer until it has decoded the buyer's
          // change note from the on-chain settle. The indexer tracks FINALIZED,
          // which lags the CONFIRMED leaf_count above — and the watcher only
          // ingests a settle once it finalizes (~13-30s) AND its poll cycle
          // reaches it. The leaf_count wait above already burned part of the
          // budget at CONFIRMED, so give finalization a generous window
          // (override with NYX_CVM_INDEXER_TIMEOUT_MS).
          const IDX_TIMEOUT_MS = Number(
            process.env.NYX_CVM_INDEXER_TIMEOUT_MS ?? "120000",
          );
          let idxFills = await fetchOrderFills(INDEXER_URL, buyerId);
          await t.step("indexer fill delivery (finalized lag)", async () => {
            const fDeadline = Date.now() + IDX_TIMEOUT_MS;
            while (
              Date.now() < fDeadline &&
              !idxFills.some((f) => f.changeNoteCommitment)
            ) {
              await new Promise((r) => setTimeout(r, 3000));
              idxFills = await fetchOrderFills(INDEXER_URL, buyerId);
            }
          });
          console.log(
            `  · indexer fills[${buyerId.slice(0, 8)}]: ${JSON.stringify(idxFills)}`,
          );
          // Amount-privacy (P3b): the indexer is a COMMITMENT LOCATOR — it
          // surfaces THAT the buyer got a change note + its commitment, but NOT
          // the amount. The spendable amount + opening come from the FillMemo.
          const change = idxFills.find(
            (f) => f.side === "buyer" && f.changeNoteCommitment,
          );
          expect(
            change,
            "indexer did not surface the buyer change-note fill",
          ).toBeTruthy();

          // Live: wait for the per-account WS to deliver + verify the FillMemo
          // for THIS located commitment. The verified ChangeNoteRecord is the
          // spendable opening — `verifyFillMemo` recomputed the commitment from
          // the memo's amount + inner_hash (the Vuln-4 integrity check), so a
          // record that matches the indexer-located commitment is the
          // locator↔memo cross-check.
          await t.step("live WS fill delivery", async () => {
            const wsDeadline = Date.now() + 15_000;
            while (
              Date.now() < wsDeadline &&
              !wsFills.some(
                (r) =>
                  r.orderId === buyerId &&
                  r.commitment === change!.changeNoteCommitment,
              )
            ) {
              await new Promise((r) => setTimeout(r, 1000));
            }
          });
          const memoRec = wsFills.find(
            (r) =>
              r.orderId === buyerId &&
              r.commitment === change!.changeNoteCommitment,
          );
          expect(
            memoRec,
            "live /ws/fills did not deliver+verify the buyer FillMemo for the located commitment (is the CVM built from the fills commit?)",
          ).toBeTruthy();

          // The memo's amount is the authoritative (off-chain) change amount.
          expect(
            memoRec!.amount,
            "change amount must be positive",
          ).toBeGreaterThan(0n);

          // Over-collateralization: the surplus we deposited must come back in
          // the change note (on top of any price-improvement surplus).
          if (BUYER_SURPLUS > 0n) {
            expect(
              memoRec!.amount,
              "over-collateral surplus did not return as change",
            ).toBeGreaterThanOrEqual(BUYER_SURPLUS);
          }

          // The continuation consumed an anchor from the pool (index ≥ 0) —
          // the whole point of the anchor pool (the buyer's residual relocked
          // onto an anchor and keeps trading).
          expect(
            memoRec!.anchorIndex,
            "continuation did not consume an anchor",
          ).toBeGreaterThanOrEqual(0);
          console.log(
            `  · fills OK — indexer located + WS memo verified buyer change note ${change!.changeNoteCommitment!.slice(0, 12)}… (amount ${memoRec!.amount}, anchor ${memoRec!.anchorIndex})`,
          );

          // ── 7b. ON-CHAIN CHANGE-AMOUNT RECOVERY (Proposal B) ─────────
          // The live memo above proves the WS tail. This proves the PERMANENT
          // backstop: a FRESH client with only the seed recovers the SAME change
          // note (amount + opening) by DECRYPTING the on-chain ciphertext the
          // indexer surfaced (`change.ephemeralPubkey` + `change.changeEnc`) and
          // self-verifying it against the on-chain commitment — no memo, no live
          // WS, surviving a CVM redeploy. This replaced the retired durable
          // memo-replay log (`GET /fills/replay`).
          await t.step(
            "on-chain change-amount recovery (Proposal B)",
            async () => {
              const coldStore = new InMemoryNoteStore();
              const recovered = await recoverChangeFromChain(change!, {
                masterSeed: buyer.masterSeed,
                ownerCommitment: buyer.ownerCommit,
                baseMint: baseMint.toBytes(),
                quoteMint: quoteMint.toBytes(),
              });
              expect(
                recovered,
                "recoverChangeFromChain did not recover the buyer change note from the on-chain ciphertext (is the CVM built from the recovery commits?)",
              ).toBeTruthy();
              // The chain-recovered amount must match the live memo byte-for-byte.
              expect(recovered!.amount).toBe(memoRec!.amount);
              // And it lands spendable in a cold store (recovered from chain alone).
              await coldStore.put(recovered!);
              const stored = await coldStore.get(change!.changeNoteCommitment!);
              expect(stored?.amount).toBe(memoRec!.amount);
              console.log(
                `  · on-chain recovery OK — decrypted + self-verified amount ${recovered!.amount} into a cold store (no memo)`,
              );
            },
          );

          // ── 8. cross-batch RE-MATCH (opt-in) ─────────────────────────
          // The buyer's residual relocked onto anchor[0] in batch 1 and stays in
          // the book. Submit a SECOND ask: the matcher must re-match that
          // relocked note (note_e from batch 1) in a NEW batch and settle it
          // again — the real proof that a partial fill continues across batches,
          // not just that one continuation note is minted.
          if (REMATCH && seller2 && seller2Note && seller2VI) {
            const leafBeforeRematch = await harness.leafCount();
            const seller2Order = await buildOrder(
              seller2,
              OrderSide.Ask,
              askPrice,
              seller2Note,
              seller2VI,
              ORDER_N + 1, // distinct order_id from the batch-1 ask
              BASE_QTY,
            );
            const s3 = await t.step(
              "submit 2nd ask (re-match the relocked residual)",
              () => submit(seller2Order),
            );
            expect(String(s3).startsWith("2"), `2nd ask rejected (${s3})`).toBe(
              true,
            );

            let leafAfterRematch = leafBeforeRematch;
            await t.step(
              "CVM re-match + settle batch 2 (from the relocked note)",
              async () => {
                const deadline = Date.now() + SETTLE_TIMEOUT_MS;
                while (Date.now() < deadline) {
                  leafAfterRematch = await harness.leafCount();
                  if (leafAfterRematch >= leafBeforeRematch + 2) break;
                  await new Promise((r) => setTimeout(r, 3000));
                }
              },
            );
            // The ONLY order the 2nd ask can match is the buyer's relocked
            // residual, so a second settle landing proves the residual re-matched
            // from the relocked note.
            expect(
              leafAfterRematch,
              "residual did not re-match + settle in a 2nd batch (cross-batch continuation broken?)",
            ).toBeGreaterThanOrEqual(leafBeforeRematch + 2);
            console.log(
              `  · re-match settled: leaf_count ${leafBeforeRematch} → ${leafAfterRematch}`,
            );

            // The buyer order_id now carries a SECOND fill (batch 2), under the
            // SAME order_id — i.e. the same order continued across batches.
            let fills2 = await fetchOrderFills(INDEXER_URL, buyerId);
            await t.step(
              "indexer 2nd fill (re-match, finalized lag)",
              async () => {
                const d2 = Date.now() + IDX_TIMEOUT_MS;
                while (Date.now() < d2 && fills2.length < 2) {
                  await new Promise((r) => setTimeout(r, 3000));
                  fills2 = await fetchOrderFills(INDEXER_URL, buyerId);
                }
              },
            );
            expect(
              fills2.length,
              "buyer order_id did not get a 2nd fill from the re-match",
            ).toBeGreaterThanOrEqual(2);
            // The 2nd fill is a distinct on-chain settle (different signature).
            const sigs = new Set(fills2.map((f) => f.signature));
            expect(
              sigs.size,
              "the 2 fills came from the same settle tx",
            ).toBeGreaterThanOrEqual(2);
            console.log(
              `  · re-match: buyer order_id has ${fills2.length} fills across ${sigs.size} settles (batch1 continuation + batch2)`,
            );
          }
        }
        wsSub?.close();
        t.report("cvm-settle-e2e: deposit → CVM match → CVM settle → fills");
      },
      // settle wait + the (widened) indexer finalization window + WS + slack.
      // The re-match phase adds a 2nd settle + a 2nd finalized-indexer wait.
      SETTLE_TIMEOUT_MS + 420_000,
    );
  },
);
