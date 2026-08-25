/**
 * CVM merge-before-order e2e — the consolidate-then-trade flow.
 *
 * A trader's collateral is split across two small notes that no single order can
 * back. They MERGE the two into one (VALID_MERGE K=2) on devnet, then place an
 * order collateralized by the MERGED note. We assert the CVM accepts the order
 * and settles the crossing pair on-chain.
 *
 * This is cvm-settle-e2e with the seller's ASK note produced by a merge instead
 * of a single deposit — proving a merged note is a real, order-collateralizable
 * leaf (the VALID_INPUT witness against the merge OUTPUT leaf is the new path).
 *
 * Layout (single shard 0, fresh reset):
 *   leaf 0,1 = seller's two base notes (A0, A1)   → merged
 *   leaf 2   = buyer's quote note
 *   leaf 3   = merge output (base, SUM = A0+A1)    → the ask's collateral
 *
 * SUM is chosen to equal `withFee(Q)` so the merged note exactly covers the
 * ask's fee-inclusive collateral for qty Q (intake's `orders.rs` derivation).
 *
 * Gate: RUN_CVM_E2E=1 + DARKNYX_TEE_GATEWAY + the VALID_MERGE artifacts. Run:
 *   RUN_CVM_E2E=1 DARKNYX_TEE_GATEWAY=$GW SOLANA_RPC_URL=$HELIUS \
 *     FUNDER_KEYPAIR=~/.config/solana/id.json ADMIN_KEYPAIR=.devnet/keypairs/admin.json \
 *     ( cd packages/sdk && ../../node_modules/.bin/vitest run --project cvm tests/cvm-merge-then-order.test.ts )
 */
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

import { beforeAll, describe, expect, it } from "vitest";
import nacl from "tweetnacl";
import {
  ComputeBudgetProgram,
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
import {
  vaultConfigPda,
  buildMergeInstruction,
} from "../src/idl/vault-client.js";
import { readNoteMergedLeafIndex } from "../src/utxo/leaf-index.js";
import { deriveNoteUseTag } from "../src/utxo/note-use.js";
import { noteCommitmentFromBytes } from "../src/utxo/note-identity.js";
import { decodeSettleFills } from "../src/fills/chain-history.js";
import {
  orderCanonicalDigest,
  OrderSide,
  OrderType,
} from "../src/orders/canonical.js";
import { proveValidMerge } from "./helpers/merge-prover.js";
import {
  StepTimer,
  associatedTokenAddress,
  be32ToBigInt,
  createAtaIdempotentIx,
  fetchSettleTimeline,
  loadKeypairRel,
  mintToIx,
} from "./helpers/e2e-helpers.js";
import {
  CvmHarness,
  makePersona,
  gwFetch,
  fetchOracleAnchor,
  fetchBootSessionId,
  authToken,
  hex,
  withFee,
  scaledQuote,
  floorPriceToTick,
  FEE_RATE_BPS,
  SYMBOL,
  type Persona,
  type DepositedNote,
} from "./helpers/cvm-harness.js";
import { deriveLegacyMergeInner } from "./helpers/privacy-observer.js";
import type { E2EConfig } from "./devnet-setup.test.js";

const REPO_ROOT = resolve(__dirname, "../../..");
const CONFIG_PATH = resolve(REPO_ROOT, ".devnet/e2e-config.json");
const MERGE_ZKEY = resolve(
  REPO_ROOT,
  "circuits/build/valid_merge_k2/circuit_final.zkey",
);
const GATEWAY = (process.env.DARKNYX_TEE_GATEWAY ?? "").replace(/\/$/, "");
const READY =
  process.env.RUN_CVM_E2E === "1" &&
  GATEWAY !== "" &&
  existsSync(CONFIG_PATH) &&
  existsSync(MERGE_ZKEY);
const maybeDescribe = READY ? describe : describe.skip;

const SETTLE_TIMEOUT_MS = Number(
  process.env.DARKNYX_CVM_SETTLE_TIMEOUT_MS ?? "120000",
);

maybeDescribe(
  "CVM merge-then-order (deposit×2 → merge → order off merged note)",
  () => {
    let cfg: E2EConfig;
    let conn: Connection;
    let admin: Keypair;
    let funder: Keypair;
    let vaultProgramId: PublicKey;
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
      baseMint = new PublicKey(cfg.baseMint.pubkey);
      quoteMint = new PublicKey(cfg.quoteMint.pubkey);
      buyer = await makePersona(REPO_ROOT, "cvm-merge-buyer", 0x50);
      seller = await makePersona(REPO_ROOT, "cvm-merge-seller", 0x90);
    });

    it(
      "merges two notes and places a settling order off the merged note",
      async () => {
        const t = new StepTimer();
        const numTrees =
          (cfg as unknown as { numTrees?: number }).numTrees ?? 1;
        const harness = await CvmHarness.create(conn, vaultProgramId, numTrees);

        const startCount = await harness.leafCount();
        expect(startCount, "tree not empty — reset first").toBe(0);

        const anchor = await t.step("oracle anchor", () => fetchOracleAnchor());
        const tickSize = BigInt(cfg.market.tickSize);
        const bidPrice = floorPriceToTick((anchor * 12n) / 10n, tickSize);
        const askPrice = floorPriceToTick((anchor * 8n) / 10n, tickSize);
        const PRICE_SCALE = BigInt(cfg.market.priceScale);

        // Q (= ask qty). The merged note must equal withFee(Q) so it exactly
        // covers the ask's fee-inclusive collateral. Per-run-unique commitments.
        const Q = BigInt(
          process.env.DARKNYX_CVM_BASE_QTY ??
            String((Date.now() % 200_000) + 2000),
        );
        const mergedAmt = withFee(Q); // = A0 + A1
        const A1 = mergedAmt / 2n;
        const A0 = mergedAmt - A1; // A0 + A1 === mergedAmt exactly
        const buyerNoteAmt = withFee(scaledQuote(Q, bidPrice, PRICE_SCALE));
        const ORDER_N = Number(
          process.env.DARKNYX_CVM_ORDER_N ?? String(Date.now() % 1_000_000),
        );
        console.log(
          `  · Q=${Q} mergedAmt=${mergedAmt} (A0=${A0}+A1=${A1}) buyerNote=${buyerNoteAmt} bid=${bidPrice} ask=${askPrice} feeBps=${FEE_RATE_BPS}`,
        );

        // ── 1. fund payers ──
        await t.step("fund payers (SOL)", async () => {
          for (const p of [buyer, seller]) {
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

        const sellerBaseAta = await associatedTokenAddress(
          baseMint,
          seller.payer.publicKey,
        );
        const buyerQuoteAta = await associatedTokenAddress(
          quoteMint,
          buyer.payer.publicKey,
        );

        // ── 2. mint collateral: seller's two base notes + buyer's quote note ──
        await t.step("mint collateral", async () =>
          sendAndConfirmTransaction(
            conn,
            new Transaction().add(
              createAtaIdempotentIx(
                admin,
                sellerBaseAta,
                seller.payer.publicKey,
                baseMint,
              ),
              createAtaIdempotentIx(
                admin,
                buyerQuoteAta,
                buyer.payer.publicKey,
                quoteMint,
              ),
              mintToIx(baseMint, sellerBaseAta, admin, A0 + A1),
              mintToIx(quoteMint, buyerQuoteAta, admin, buyerNoteAmt),
            ),
            [admin],
          ),
        );

        // ── 3. deposit (all to shard 0 for deterministic merge witness) ──
        const sellerNote0 = await t.step("deposit seller note 0", async () =>
          harness.deposit(seller, baseMint, sellerBaseAta, A0, 0),
        );
        const sellerNote1 = await t.step("deposit seller note 1", async () =>
          harness.deposit(seller, baseMint, sellerBaseAta, A1, 0),
        );
        const buyerNote = await t.step("deposit buyer note", async () =>
          harness.deposit(buyer, quoteMint, buyerQuoteAta, buyerNoteAmt, 0),
        );
        expect(await harness.leafCount()).toBe(3);

        // ── 4. MERGE the two seller notes (K=2) against the 3-leaf shard-0 root ──
        const shadow = harness.shadows[0];
        const w0 = await shadow.witness(sellerNote0.leafIndex);
        const w1 = await shadow.witness(sellerNote1.leafIndex);
        const root = await shadow.computeRoot();
        const mergeRes = await t.step("VALID_MERGE prove (K=2)", async () =>
          proveValidMerge({
            repoRoot: REPO_ROOT,
            k: 2,
            spendingKey: seller.spendingKey,
            tokenMint: baseMint.toBytes(),
            merkleRootBE: root,
            slots: [
              {
                amount: sellerNote0.amount,
                innerHash: sellerNote0.innerHash,
                pathElements: w0.siblings.map(be32ToBigInt),
                pathIndices: w0.indices,
              },
              {
                amount: sellerNote1.amount,
                innerHash: sellerNote1.innerHash,
                pathElements: w1.siblings.map(be32ToBigInt),
                pathIndices: w1.indices,
              },
            ],
          }),
        );
        const mergeSig = await t.step("merge ix submit", async () =>
          sendAndConfirmTransaction(
            conn,
            new Transaction().add(
              ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 }),
              await buildMergeInstruction({
                programId: vaultProgramId,
                treeId: 0,
                payer: seller.payer.publicKey,
                inputUseTags: mergeRes.inputUseTagsBE,
                outputCommitment: mergeRes.outputCommitmentBE,
                tokenMint: baseMint,
                merkleRoot: root,
                k: 2,
                proof: mergeRes.proof,
              }),
            ),
            [seller.payer],
          ),
        );
        const mergedLeaf = Number(
          await readNoteMergedLeafIndex(conn, mergeSig, vaultProgramId),
        );
        expect(mergedLeaf, "merge output appended at leaf 3").toBe(3);
        await shadow.append(mergeRes.outputCommitmentBE);
        expect(await harness.leafCount()).toBe(4);
        console.log(
          `  · merged → note ${hex(mergeRes.outputCommitmentBE).slice(0, 12)}… (${mergeRes.outputAmount}) at leaf ${mergedLeaf}`,
        );

        // PA-02 setup: an observer can still derive the retired commitment-
        // based inner and tag from the two public input leaves. Preserve that
        // candidate so the later Tx D can prove it is not the handle consumed
        // by the v2 private-inner-derived merge descendant.
        const legacyMergeInner = await deriveLegacyMergeInner([
          sellerNote0.commitment,
          sellerNote1.commitment,
        ]);
        const legacyMergeTag = await deriveNoteUseTag(
          noteCommitmentFromBytes(mergeRes.outputCommitmentBE),
          legacyMergeInner,
        );
        const actualMergeTag = await deriveNoteUseTag(
          noteCommitmentFromBytes(mergeRes.outputCommitmentBE),
          bn254ToBE32(mergeRes.outputInnerHash),
        );
        expect(actualMergeTag).not.toEqual(legacyMergeTag);

        // The merged note, shaped as an order-collateral note (same owner as the
        // seller's deposits; witnessed against the merge OUTPUT leaf).
        const mergedNote: DepositedNote = {
          mint: baseMint,
          amount: mergeRes.outputAmount,
          innerHash: mergeRes.outputInnerHash,
          commitment: mergeRes.outputCommitmentBE,
          treeId: 0,
          leafIndex: mergedLeaf,
        };

        // ── 5. VALID_INPUT proofs ──
        const sellerVI = await t.step(
          "VALID_INPUT prove seller (merged note)",
          () => harness.viProof(REPO_ROOT, seller, mergedNote),
        );
        const buyerVI = await t.step("VALID_INPUT prove buyer", async () =>
          harness.viProof(REPO_ROOT, buyer, buyerNote),
        );

        // ── 6. build + sign the two orders (mirrors cvm-settle-e2e) ──
        const slot = await conn.getSlot("confirmed");
        // Production intake caps lock TTLs at 4,500 slots. Keep the live
        // fixture comfortably inside that boundary so it exercises settlement
        // instead of the intended long-expiry rejection path.
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
        ) {
          const orderId = deriveOrderId(p.masterSeed, orderIndex);
          const viewingPubkey = deriveViewingEncKeypair(p.masterSeed).publicKey;
          const digest = orderCanonicalDigest({
            symbol: new TextEncoder().encode(SYMBOL),
            side,
            orderType: OrderType.Limit,
            amount: qty,
            priceLimit,
            minFillSize: 0n,
            expirySlot,
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
            expiry_slot: Number(expirySlot),
            order_id: hex(orderId),
            note_commitment: hex(note.commitment),
            arrival_nonce: 1,
            trading_key: hex(p.trading.publicKey.toBytes()),
            trading_key_signature: hex(sig),
            owner_commitment: hex(bn254ToBE32(p.ownerCommit)),
            note_inner_hash: hex(bn254ToBE32(note.innerHash)),
            merkle_root: hex(vi.root),
            valid_input_proof: hex(vi.proofBytes),
            collateral_amount: Number(note.amount),
            tree_id: note.treeId,
            viewing_pubkey: hex(viewingPubkey),
            session_id: hex(bootSessionId),
          };
        }
        const sellerOrder = await buildOrder(
          seller,
          OrderSide.Ask,
          askPrice,
          mergedNote,
          sellerVI,
          ORDER_N,
          Q,
        );
        const buyerOrder = await buildOrder(
          buyer,
          OrderSide.Bid,
          bidPrice,
          buyerNote,
          buyerVI,
          ORDER_N,
          Q,
        );

        // ── 7. submit both orders ──
        const token = await authToken(GATEWAY);
        async function submit(body: object): Promise<number> {
          const r = await gwFetch(`${GATEWAY}/orders`, {
            method: "POST",
            headers: {
              "content-type": "application/json",
              authorization: `Bearer ${token}`,
            },
            body: JSON.stringify(body),
          });
          if (!String(r.status).startsWith("2"))
            console.log(
              `  !! /orders ${r.status}: ${(await r.text()).slice(0, 200)}`,
            );
          return r.status;
        }
        const sAsk = await t.step(
          "submit ask (merged-note collateral)",
          async () => submit(sellerOrder),
        );
        const sBid = await t.step("submit bid", () => submit(buyerOrder));
        expect(String(sAsk).startsWith("2"), `ask rejected (${sAsk})`).toBe(
          true,
        );
        expect(String(sBid).startsWith("2"), `bid rejected (${sBid})`).toBe(
          true,
        );

        // ── 8. watch the settle land (leaf_count grows by ≥2) ──
        const before = await harness.leafCount();
        let finalCount = before;
        await t.step("CVM match + settle", async () => {
          const deadline = Date.now() + SETTLE_TIMEOUT_MS;
          while (Date.now() < deadline) {
            finalCount = await harness.leafCount();
            if (finalCount >= before + 2) break;
            await new Promise((r) => setTimeout(r, 3000));
          }
        });
        console.log(`  · on-chain leaf_count: ${before} → ${finalCount}`);
        expect(
          finalCount,
          "merged-note order did not settle — check CVM logs",
        ).toBeGreaterThanOrEqual(before + 2);

        await t.step(
          "PA-02 observer-negative (later merge use tag)",
          async () => {
            const infoRes = await gwFetch(`${GATEWAY}/info`);
            expect(infoRes.status).toBe(200);
            const info = (await infoRes.json()) as { tee_pubkey?: string };
            expect(info.tee_pubkey).toBeTruthy();
            const timeline = await fetchSettleTimeline(
              conn,
              new PublicKey(info.tee_pubkey!),
              { limit: 20, vaultProgramId: cfg.vaultProgramId },
            );
            let observedTag: string | undefined;
            let settleSignature: string | undefined;
            for (const row of timeline
              .filter((entry) => entry.stage === "tee_forced_settle_batched")
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
                const fills = decodeSettleFills(
                  ix.data,
                  row.signature,
                  row.slot,
                );
                const sellerFill = fills?.find(
                  (fill) => fill.orderId === sellerOrder.order_id,
                );
                if (!sellerFill) continue;
                observedTag = sellerFill.inputNoteUseTag;
                settleSignature = row.signature;
                break;
              }
              if (observedTag) break;
            }
            expect(
              observedTag,
              "could not locate merged note's later use tag",
            ).toBe(hex(actualMergeTag));
            expect(
              observedTag,
              "public merge leaves reconstructed the later use tag",
            ).not.toBe(hex(legacyMergeTag));
            console.log(
              `  · PA-02 observer-negative OK — retired tag missed Tx D ${settleSignature}`,
            );
          },
        );
        t.report("cvm-merge-then-order: deposit×2 → MERGE → order → settle");
      },
      SETTLE_TIMEOUT_MS + 300_000,
    );
  },
);
