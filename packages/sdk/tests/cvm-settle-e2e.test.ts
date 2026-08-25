/**
 * The CVM-driven settle e2e: a real enclave matches AND settles on devnet.
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
 *        phala deploy -e DARKNYX_TEE_BASE_MINT=<base58> \
 *          -e DARKNYX_TEE_QUOTE_MINT=<base58> \
 *          -e DARKNYX_TEE_SOLANA_RPC_URL=<helius> \
 *          -e DARKNYX_TEE_SYNC_FROM_SLOT=<reset slot> …
 *   4. `vault_config.tee_pubkey` rotated to the CVM's /info signer
 *      (set_tee_pubkey, admin keypair), and that signer funded with SOL
 *      (`solana transfer`).
 *
 * Gated on RUN_CVM_E2E=1 + DARKNYX_TEE_GATEWAY=<https://…>. Pricing is
 * anchored to the live finalized Pyth push feed (override with DARKNYX_CVM_PRICE);
 * DARKNYX_CVM_BASE_QTY tunes the trade size.
 *
 * Run:
 *   RUN_CVM_E2E=1 DARKNYX_CVM_TRANSPORT=ra-tls \
 *     DARKNYX_TEE_GATEWAY=https://<app_id>-8443s.dstack-pha-<node>.phala.network \
 *     FUNDER_KEYPAIR=~/.config/solana/id.json ADMIN_KEYPAIR=.devnet/keypairs/admin.json \
 *     ( cd packages/sdk && ../../node_modules/.bin/vitest run tests/cvm-settle-e2e.test.ts )
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
import { vaultConfigPda } from "../src/idl/vault-client.js";
import {
  orderCanonicalDigest,
  OrderSide,
  OrderType,
} from "../src/orders/canonical.js";
import { fetchOrderFills } from "../src/fills/history.js";
import { recoverNotesFromChain } from "../src/fills/cold-recovery.js";
import { recoverFillFromChain } from "../src/fills/recover.js";
import { decodeSettleFills } from "../src/fills/chain-history.js";
import {
  subscribeFills,
  type FillsSubscription,
} from "../src/fills/ws-client.js";
import {
  InMemoryNoteStore,
  type ChangeNoteRecord,
} from "../src/utxo/note-store.js";
import {
  StepTimer,
  associatedTokenAddress,
  createAtaIdempotentIx,
  fetchSettleTimeline,
  loadKeypairRel,
  mintToIx,
  reportSettleTimeline,
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
  API_KEY,
  API_SECRET,
  PASSPHRASE,
  type Persona,
  type DepositedNote,
} from "./helpers/cvm-harness.js";
import type { E2EConfig } from "./devnet-setup.test.js";
import { slotToNumber } from "../src/types/slot.js";

const REPO_ROOT = resolve(__dirname, "../../..");
const CONFIG_PATH = resolve(REPO_ROOT, ".devnet/e2e-config.json");
const GATEWAY = (process.env.DARKNYX_TEE_GATEWAY ?? "").replace(/\/$/, "");

const READY =
  process.env.RUN_CVM_E2E === "1" && GATEWAY !== "" && existsSync(CONFIG_PATH);
const maybeDescribe = READY ? describe : describe.skip;

// CVM creds, SYMBOL, FEE_RATE_BPS, gwFetch, fetchOracleAnchor, hex, withFee,
// Persona/makePersona, and the shard-aware deposit/witness harness all live in
// `./helpers/cvm-harness.ts` (shared across the cvm-* tests).
const SETTLE_TIMEOUT_MS = Number(
  process.env.DARKNYX_CVM_SETTLE_TIMEOUT_MS ?? "60000",
);

// Fills mode (opt-in): when DARKNYX_INDEXER_URL points at a locally-running indexer
// (`scripts/run-indexer-local.sh`), additionally assert the buyer's continuation
// change note surfaces over BOTH paths — the durable off-TEE indexer
// (GET /fills, decoded from the on-chain settle) and the live per-account WS
// (FillMemo). The WS half needs a CVM built from the fills commit; the indexer
// half works against any deployed CVM (it only reads the chain).
const INDEXER_URL = (process.env.DARKNYX_INDEXER_URL ?? "").replace(/\/$/, "");
const FILLS = INDEXER_URL !== "";

// Indexer-free disaster-recovery drill (opt-in because finalized-chain polling
// lengthens the billable test). This deliberately makes the buyer order partial
// and proves that seed + finalized Solana history alone reconstructs its
// deposit, trade, and continuation openings. No live memo or indexer row is
// supplied to the recovery routine.
const CHAIN_RECOVERY = process.env.DARKNYX_CVM_CHAIN_RECOVERY === "1";

// The fee-key epoch drill deliberately settles epoch B without resetting the
// epoch-A leaves. This mode cold-boots the CVM, authenticates to its mirror,
// and replays every shard into the local witness trees before depositing the
// second crossing pair. Ordinary leaf-count suites keep the stricter empty-tree
// precondition.
const REUSE_EXISTING_TREE = process.env.DARKNYX_CVM_REUSE_EXISTING_TREE === "1";

// Cross-batch re-match (opt-in, requires FILLS). After the buyer's residual
// relocks onto an anchor in batch 1, submit a SECOND ask so the matcher
// re-matches that relocked note in a NEW batch and settles it again — proving
// a partial fill's continuation actually re-matches across batches, not just
// that one continuation note is minted. Needs a 3rd (seller2) deposit up-front.
const REMATCH = FILLS && process.env.DARKNYX_CVM_REMATCH === "1";

maybeDescribe(
  "CVM-driven settle e2e (deposit → CVM match → CVM settle)",
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
      admin = await loadKeypairRel(
        REPO_ROOT,
        process.env.ADMIN_KEYPAIR ?? ".devnet/keypairs/admin.json",
      );
      funder = process.env.FUNDER_KEYPAIR
        ? await loadKeypairRel(REPO_ROOT, process.env.FUNDER_KEYPAIR)
        : admin;
      vaultProgramId = new PublicKey(cfg.vaultProgramId);
      [vaultPda] = await vaultConfigPda(vaultProgramId);
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
        // second run. Override with DARKNYX_CVM_BASE_QTY for a fixed value.
        //
        // Capped at 250k: the buyer's collateral is
        // floor(BUY_QTY×bidPrice/priceScale)×(1+fee),
        // and in FILLS mode BUY_QTY = 2×BASE_QTY. The order body sends
        // `collateral_amount` as a JSON number, so it must stay ≤ 2^53
        // (Number.MAX_SAFE_INTEGER ≈ 9.007e15) or `Number(noteAmt)` rounds it and
        // intake rejects it as 1 below the required floor. 2×250k×bidPrice(~7.4e9)
        // ≈ 3.7e15 — comfortably exact even if SOL's price doubles.
        const BASE_QTY = BigInt(
          process.env.DARKNYX_CVM_BASE_QTY ??
            String((Date.now() % 250_000) + 1000),
        );
        // Run-unique order-id index. Order ids are now DETERMINISTIC
        // (`deriveOrderId(seed, n)`) so fills mode can query the indexer by the
        // exact id we used; the run-unique `n` keeps re-runs from colliding on the
        // same id (and lets the indexer's by-order_id rows stay per-run).
        const ORDER_N = Number(
          process.env.DARKNYX_CVM_ORDER_N ?? String(Date.now() % 1_000_000),
        );
        const t = new StepTimer();
        const anchor = await t.step("oracle anchor (finalized Pyth push)", () =>
          fetchOracleAnchor(),
        );
        const tickSize = BigInt(cfg.market.tickSize);
        const bidPrice = floorPriceToTick((anchor * 12n) / 10n, tickSize);
        const askPrice = floorPriceToTick((anchor * 8n) / 10n, tickSize);
        const PRICE_SCALE = BigInt(cfg.market.priceScale);
        // In fills or chain-recovery mode we validate a derived partial-fill
        // CONTINUATION: the
        // buyer over-buys (bids 2× the seller's qty) so only BASE_QTY crosses and
        // the residual relocks onto a change note derived from the consumed
        // input inner. This exercises the live memo's consumed-input binding.
        // Without either mode we keep the simpler full-fill settle check
        // (BUY_QTY=BASE_QTY).
        // Override the multiplier with DARKNYX_CVM_BUY_MULT.
        const BUY_MULT = BigInt(
          process.env.DARKNYX_CVM_BUY_MULT ??
            (FILLS || CHAIN_RECOVERY ? "2" : "1"),
        );
        const BUY_QTY = BASE_QTY * BUY_MULT;
        console.log(
          `  · BASE_QTY=${BASE_QTY} buyQty=${BUY_QTY} (mult ${BUY_MULT}${FILLS || CHAIN_RECOVERY ? ", partial-fill continuation" : ""}) bid=${bidPrice} ask=${askPrice} feeBps=${FEE_RATE_BPS}`,
        );

        // Number of Merkle shards (K). Deposits + settle outputs route across
        // them; the harness keeps one shadow per shard and recovers each note's
        // (tree_id, leaf_index) from its NoteCreated event.
        const numTrees =
          (cfg as unknown as { numTrees?: number }).numTrees ?? 1;
        const harness = REUSE_EXISTING_TREE
          ? await CvmHarness.createHydrated(
              conn,
              vaultProgramId,
              numTrees,
              async (treeId, from, to) => {
                const token = await authToken(GATEWAY);
                const url = new URL(`${GATEWAY}/tree/leaves`);
                url.searchParams.set("tree_id", String(treeId));
                url.searchParams.set("from", String(from));
                url.searchParams.set("to", String(to));
                const response = await gwFetch(url.toString(), {
                  headers: { authorization: `Bearer ${token}` },
                });
                if (!response.ok) {
                  throw new Error(
                    `/tree/leaves failed (${response.status}): ${await response.text()}`,
                  );
                }
                const body = (await response.json()) as {
                  leaves: Array<{ leaf_index: number; value: string }>;
                  merkle_root: string;
                };
                if (!/^[0-9a-f]{64}$/i.test(body.merkle_root)) {
                  throw new Error("/tree/leaves returned a malformed root");
                }
                return {
                  leaves: body.leaves.map((leaf) => ({
                    leafIndex: leaf.leaf_index,
                    value: Uint8Array.from(Buffer.from(leaf.value, "hex")),
                  })),
                  merkleRoot: Uint8Array.from(
                    Buffer.from(body.merkle_root, "hex"),
                  ),
                };
              },
            )
          : await CvmHarness.create(conn, vaultProgramId, numTrees);

        // Normal suites start from a fresh reset. The two-epoch fee drill is
        // the sole exception: it has just hydrated all epoch-A leaves and must
        // preserve them so their recovered notes remain spendable.
        const startCount = await harness.leafCount();
        if (REUSE_EXISTING_TREE) {
          expect(
            startCount,
            "epoch-B rehearsal expected preserved epoch-A leaves",
          ).toBeGreaterThan(0);
          console.log(`  · hydrated ${startCount} preserved leaves`);
        } else {
          expect(
            startCount,
            "tree not empty — run devnet-setup (reset) first",
          ).toBe(0);
        }
        const recoveryFloorSlot = CHAIN_RECOVERY
          ? slotToNumber(await conn.getSlot("finalized"))
          : undefined;

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

        const buyerQuoteAta = await associatedTokenAddress(
          quoteMint,
          buyer.payer.publicKey,
        );
        const sellerBaseAta = await associatedTokenAddress(
          baseMint,
          seller.payer.publicKey,
        );
        // Each side locks NOMINAL collateral + its OWN protocol fee, matching
        // the intake derivation (orders.rs: note_amount = nominal + nominal *
        // bps / 10_000, floored). Bid nominal is
        // floor(qty × price / priceScale) quote; ask
        // nominal = qty (base). With fees off (bps=0) both collapse to the
        // nominal, unchanged. Floor division must match intake exactly so the
        // re-derived commitment lines up. (`withFee` is shared from cvm-harness.)
        // Over-collateralization knob: deposit a buyer note LARGER than the order
        // needs (DARKNYX_CVM_BUYER_SURPLUS quote units). The order declares its actual
        // collateral_amount; intake accepts note ≥ required and the matcher returns
        // the surplus as an (even bigger) change note. Default 0 ⇒ exact-at-limit.
        const BUYER_SURPLUS = BigInt(
          process.env.DARKNYX_CVM_BUYER_SURPLUS ?? "0",
        );
        const buyerNoteAmt =
          withFee(scaledQuote(BUY_QTY, bidPrice, PRICE_SCALE)) + BUYER_SURPLUS;
        const sellerNoteAmt = withFee(BASE_QTY);

        await t.step("mint collateral (ATAs + mintTo)", () =>
          sendAndConfirmTransaction(
            conn,
            new Transaction().add(
              createAtaIdempotentIx(
                admin,
                buyerQuoteAta,
                buyer.payer.publicKey,
                quoteMint,
              ),
              createAtaIdempotentIx(
                admin,
                sellerBaseAta,
                seller.payer.publicKey,
                baseMint,
              ),
              mintToIx(quoteMint, buyerQuoteAta, admin, buyerNoteAmt),
              mintToIx(baseMint, sellerBaseAta, admin, sellerNoteAmt),
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
          const seller2BaseAta = await associatedTokenAddress(
            baseMint,
            seller2.payer.publicKey,
          );
          await t.step("mint seller2 collateral", () =>
            sendAndConfirmTransaction(
              conn,
              new Transaction().add(
                createAtaIdempotentIx(
                  admin,
                  seller2BaseAta,
                  seller2.payer.publicKey,
                  baseMint,
                ),
                mintToIx(baseMint, seller2BaseAta, admin, sellerNoteAmt),
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
        expect(depositCount).toBe(startCount + (REMATCH ? 3 : 2));

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
        const expirySlot = slot + 3_000n;
        const bootSessionId = await fetchBootSessionId(GATEWAY);

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
          const viewingPubkey = deriveViewingEncKeypair(p.masterSeed).publicKey;
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
            arrivalNonce: 1n,
            viewingPubkey,
            sessionId: bootSessionId,
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
            arrival_nonce: 1,
            trading_key: hex(p.trading.publicKey.toBytes()),
            trading_key_signature: hex(sig),
            owner_commitment: hex(bn254ToBE32(p.ownerCommit)),
            note_inner_hash: hex(bn254ToBE32(note.innerHash)),
            merkle_root: hex(vi.root),
            valid_input_proof: hex(vi.proofBytes),
            // Declare the note's ACTUAL amount. For an exact-collateral order this
            // equals the derived floor (a no-op); for an over-collateralized one
            // it's larger and intake accepts note ≥ required.
            collateral_amount: Number(note.amount),
            tree_id: note.treeId,
            viewing_pubkey: hex(viewingPubkey),
            session_id: hex(bootSessionId),
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
          slot + 100_000n, // ≫ MAX_LOCK_TTL_SLOTS (~4_500)
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
        await wsStore.put({
          commitment: hex(buyerNote.commitment),
          tokenMint: buyerNote.mint.toBytes(),
          amount: buyerNote.amount,
          ownerCommitment: buyer.ownerCommit,
          innerHash: buyerNote.innerHash,
          leafIndex: BigInt(buyerNote.leafIndex),
        });
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

        // The protocol-level privacy assertion for note-use tags. Find THIS
        // match's settle instruction by its signed order ids, then inspect the
        // serialized transaction rather than trusting the decoder's field
        // names: consumed Merkle commitments must be absent, while the output
        // commitments carried by Tx D must remain present.
        await t.step("note-use unlinkability (settle wire)", async () => {
          const infoRes = await gwFetch(`${GATEWAY}/info`);
          expect(infoRes.status).toBe(200);
          const info = (await infoRes.json()) as { tee_pubkey?: string };
          expect(info.tee_pubkey).toBeTruthy();

          const timeline = await fetchSettleTimeline(
            conn,
            new PublicKey(info.tee_pubkey!),
            { limit: 20, vaultProgramId: cfg.vaultProgramId },
          );
          let matched:
            | { wire: Buffer; outputs: Uint8Array[]; signature: string }
            | undefined;
          for (const row of timeline
            .filter((r) => r.stage === "tee_forced_settle_batched")
            .reverse()) {
            const tx = await conn.getTransaction(row.signature, {
              maxSupportedTransactionVersion: 0,
              commitment: "confirmed",
            });
            if (!tx) continue;
            const message = tx.transaction.message;
            const keys = message.getAccountKeys({
              accountKeysFromLookups: tx.meta?.loadedAddresses ?? undefined,
            });
            for (const ix of message.compiledInstructions) {
              if (
                keys.get(ix.programIdIndex)?.toBase58() !== cfg.vaultProgramId
              ) {
                continue;
              }
              const fills = decodeSettleFills(ix.data, row.signature, row.slot);
              if (
                !fills ||
                !fills.some((f) => f.orderId === buyerOrder.order_id) ||
                !fills.some((f) => f.orderId === sellerOrder.order_id)
              ) {
                continue;
              }
              matched = {
                // The message is the observer-visible signed payload. It
                // contains every instruction byte (where the old commitments
                // leaked) without adding nondeterministic signature bytes.
                wire: Buffer.from(message.serialize()),
                outputs: fills.map((f) =>
                  Uint8Array.from(Buffer.from(f.tradeNoteCommitment, "hex")),
                ),
                signature: row.signature,
              };
              break;
            }
            if (matched) break;
          }

          expect(matched, "could not locate this match's Tx D").toBeTruthy();
          for (const inputCommitment of [
            buyerNote.commitment,
            sellerNote.commitment,
          ]) {
            expect(
              matched!.wire.includes(Buffer.from(inputCommitment)),
              "a consumed Merkle commitment leaked into Tx D",
            ).toBe(false);
          }
          for (const outputCommitment of matched!.outputs) {
            expect(
              matched!.wire.includes(Buffer.from(outputCommitment)),
              "an output commitment expected in Tx D was absent",
            ).toBe(true);
          }
          console.log(
            `  · unlinkability OK — inputs absent, outputs present in Tx D ${matched!.signature}`,
          );
        });

        // Permanent recovery backstop: scan finalized vault history from before
        // the deposits, identify only notes owned by the buyer seed, decrypt the
        // recovery-v3 settlement tuple, and rebuild the partial-fill DAG. This
        // has no dependency on the live stream, mutable CVM state, or indexer.
        if (CHAIN_RECOVERY) {
          let recovered:
            | Awaited<ReturnType<typeof recoverNotesFromChain>>
            | undefined;
          await t.step("seed + finalized-chain cold recovery", async () => {
            const deadline = Date.now() + 120_000;
            while (Date.now() < deadline) {
              recovered = await recoverNotesFromChain({
                connection: conn,
                programId: vaultProgramId,
                masterSeed: buyer.masterSeed,
                baseMint: baseMint.toBytes(),
                quoteMint: quoteMint.toBytes(),
                sinceSlot: recoveryFloorSlot,
              });
              if (
                recovered.recovered.deposits >= 1 &&
                recovered.recovered.trade >= 1 &&
                recovered.recovered.change >= 1
              ) {
                break;
              }
              await new Promise((r) => setTimeout(r, 3000));
            }
          });
          expect(
            recovered,
            "cold recovery did not return a result",
          ).toBeTruthy();
          expect(recovered!.recovered.deposits).toBeGreaterThanOrEqual(1);
          expect(recovered!.recovered.trade).toBeGreaterThanOrEqual(1);
          expect(recovered!.recovered.change).toBeGreaterThanOrEqual(1);
          expect(recovered!.unresolvedSettlements).toBe(0);

          const trade = recovered!.notes.find(
            (note) =>
              note.orderId === buyerOrder.order_id &&
              Buffer.from(note.tokenMint).equals(
                Buffer.from(baseMint.toBytes()),
              ),
          );
          const change = recovered!.notes.find(
            (note) =>
              note.orderId === buyerOrder.order_id &&
              Buffer.from(note.tokenMint).equals(
                Buffer.from(quoteMint.toBytes()),
              ),
          );
          expect(trade?.amount).toBe(BASE_QTY);
          expect(trade?.leafIndex).toBeDefined();
          expect(
            change?.amount,
            "partial-fill change was not recovered",
          ).toBeGreaterThan(0n);
          expect(change?.leafIndex).toBeDefined();
          console.log(
            `  · cold recovery OK — deposit + trade ${trade!.amount} + change ${change!.amount} rebuilt from finalized chain only`,
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
          // (override with DARKNYX_CVM_INDEXER_TIMEOUT_MS).
          const IDX_TIMEOUT_MS = Number(
            process.env.DARKNYX_CVM_INDEXER_TIMEOUT_MS ?? "120000",
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
          // Amount-privacy: the indexer is a COMMITMENT LOCATOR — it
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
            "live fills channel did not deliver+verify the buyer FillMemo for the located commitment (is the CVM built from the stream commit?)",
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

          // The memo must name the exact deposited input that v3 consumed.
          expect(memoRec!.consumedCommitment).toBe(hex(buyerNote.commitment));
          console.log(
            `  · fills OK — indexer located + WS memo verified buyer change note ${change!.changeNoteCommitment!.slice(0, 12)}… (amount ${memoRec!.amount}, consumed ${memoRec!.consumedCommitment!.slice(0, 12)}…)`,
          );

          // ── 7b. ON-CHAIN TRADE + CHANGE RECOVERY V2 ─────────────────
          // The live memo above proves the WS tail. This proves the PERMANENT
          // backstop: a client with the seed + consumed input opening recovers
          // the trade note AND the same change note by decrypting the on-chain
          // ciphertext (`change.ephemeralPubkey` + `change.outputEnc`) and
          // self-verifying it against the on-chain commitment — no memo, no live
          // WS, surviving a CVM redeploy. This replaced the retired durable
          // memo-replay log (`GET /fills/replay`).
          await t.step("on-chain trade + change recovery v3", async () => {
            const coldStore = new InMemoryNoteStore();
            const inputRecord = {
              commitment: hex(buyerNote.commitment),
              tokenMint: buyerNote.mint.toBytes(),
              amount: buyerNote.amount,
              ownerCommitment: buyer.ownerCommit,
              innerHash: buyerNote.innerHash,
              leafIndex: BigInt(buyerNote.leafIndex),
            };
            await coldStore.put(inputRecord);
            const recovered = await recoverFillFromChain(change!, {
              masterSeed: buyer.masterSeed,
              candidateInputs: [inputRecord],
              baseMint: baseMint.toBytes(),
              quoteMint: quoteMint.toBytes(),
            });
            expect(
              recovered,
              "recoverFillFromChain did not recover the buyer outputs from the on-chain ciphertext (is the CVM built from the recovery-v3 image?)",
            ).toBeTruthy();
            expect(recovered!.trade.amount).toBe(BASE_QTY);
            // The chain-recovered amount must match the live memo byte-for-byte.
            expect(recovered!.change!.amount).toBe(memoRec!.amount);
            // And it lands spendable in a cold store.
            await coldStore.put(recovered!.trade);
            await coldStore.put(recovered!.change!);
            const stored = await coldStore.get(change!.changeNoteCommitment!);
            expect(stored?.amount).toBe(memoRec!.amount);
            console.log(
              `  · on-chain recovery OK — trade ${recovered!.trade.amount} + change ${recovered!.change!.amount} recovered into a cold store (no memo)`,
            );
          });

          // ── 8. cross-batch RE-MATCH (opt-in) ─────────────────────────
          // The buyer's output-derived residual was relocked in batch 1 and
          // stays in the book. Submit a SECOND ask: the matcher must re-match that
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
