/**
 * Multi-match concurrent-settle profiler (perf — settle throughput bottleneck).
 *
 * The 1-match cvm-settle-e2e hides the per-match on-chain settle cost behind the
 * one-time per-batch ALT-activation wait (~14s). This test deposits M real
 * crossing pairs and submits them together so the matcher settles several
 * matches — across one or a few batches — letting us read the PER-MATCH Tx D
 * confirm latency from the CVM logs:
 *
 *   phala cvms logs <cvm> | grep "settle Tx D confirmed (per-match)"
 *
 * The FIRST Tx D in a batch eats the ALT-activation wait; the marginal ones
 * reveal the steady-state on-chain settle ceiling — post tree-sharding the
 * concurrent Tx D's round-robin across K shard fee-payers + K trees, so they
 * co-include in a block rather than serializing on a single tree's Merkle
 * append. That ceiling is the number that decides whether the on-chain settle,
 * vs the prover (~5 matches/s, hardware-bound per the local bench), is the
 * current throughput bottleneck.
 *
 * SHARDING: deposits round-robin across the K shards (via the shard-aware
 * `CvmHarness`), so this also exercises the per-shard VALID_INPUT witness on
 * non-zero shards (cvm-settle-e2e only ever lands on shard 0). The harness reads
 * each deposit's real (tree_id, leaf_index) back from its NoteCreated event, so
 * the witness is built against whichever shard the program appended to.
 *
 * NOTE: orders are submitted concurrently (Promise.all) and can span multiple
 * matcher ticks, so the batch boundaries + per-match timings are APPROXIMATE —
 * treat them as a steady-state estimate, not a guaranteed single-batch measurement.
 *
 * Real-mint regime + a fresh tree reset (like cvm-settle-e2e). Run:
 *   RUN_CVM_E2E=1 NYX_CVM_MATCHES=4 NYX_TEE_GATEWAY=$GW SOLANA_RPC_URL=$HELIUS \
 *     FUNDER_KEYPAIR=~/.config/solana/id.json ADMIN_KEYPAIR=.devnet/keypairs/admin.json \
 *     ( cd packages/sdk && ../../node_modules/.bin/vitest run --project cvm tests/cvm-multimatch-settle.test.ts )
 */
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";
import nacl from "tweetnacl";
import {
  getAssociatedTokenAddress,
  createAssociatedTokenAccountIdempotentInstruction,
  createMintToInstruction,
} from "@solana/spl-token";
import {
  Connection,
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
import { loadKeypairRel } from "./helpers/e2e-helpers.js";
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
  FEE_RATE_BPS,
  SYMBOL,
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

const MATCHES = Number(process.env.NYX_CVM_MATCHES ?? "4");
const SETTLE_TIMEOUT_MS = Number(
  process.env.NYX_CVM_SETTLE_TIMEOUT_MS ?? "180000",
);

maybeDescribe("Perf — multi-match concurrent settle profile", () => {
  it(`deposits ${MATCHES} crossing pairs and settles them (read per-Tx-D timing from CVM logs)`, async () => {
    const cfg = JSON.parse(readFileSync(CONFIG_PATH, "utf8")) as E2EConfig;
    const bootSessionId = await fetchBootSessionId(GATEWAY);
    const conn = new Connection(
      process.env.SOLANA_RPC_URL ?? "https://api.devnet.solana.com",
      "confirmed",
    );
    const admin = loadKeypairRel(
      REPO_ROOT,
      process.env.ADMIN_KEYPAIR ?? ".devnet/keypairs/admin.json",
    );
    const funder = process.env.FUNDER_KEYPAIR
      ? loadKeypairRel(REPO_ROOT, process.env.FUNDER_KEYPAIR)
      : admin;
    const vaultProgramId = new PublicKey(cfg.vaultProgramId);
    vaultConfigPda(vaultProgramId); // (assert program id is well-formed)
    const baseMint = new PublicKey(cfg.baseMint.pubkey);
    const quoteMint = new PublicKey(cfg.quoteMint.pubkey);
    // K shards. Deposits round-robin across them; settle OUTPUTS also
    // round-robin, so the pool's leaf count is the SUM across shards.
    const numTrees = (cfg as { numTrees?: number }).numTrees ?? 1;
    const harness = await CvmHarness.create(conn, vaultProgramId, numTrees);

    const buyer = await makePersona(REPO_ROOT, "cvm-buyer", 0x40);
    const seller = await makePersona(REPO_ROOT, "cvm-seller", 0x80);

    const startCount = await harness.leafCount();
    expect(startCount, "trees not empty — reset the merkle trees first").toBe(
      0,
    );

    const anchor = await fetchOracleAnchor();
    const bidPrice = (anchor * 12n) / 10n;
    const askPrice = (anchor * 8n) / 10n;
    const PRICE_SCALE = BigInt(cfg.market.priceScale);
    // SAME qty for every pair → the uniform-price match is cleanly pairwise
    // (M bids × M asks, all full fills, NO partial-fill residual/relock) so all
    // M matches land in ONE batch — exactly what we want for a clean per-batch
    // co-inclusion measurement (and one settle pipeline, not M, which keeps the
    // RPC under the rate limit). Commitments stay unique via the per-leaf
    // inner_hash, so identical amounts don't collide.
    const baseSalt = BigInt(Date.now() % 200_000) + 1000n;
    const qtys = Array.from({ length: MATCHES }, () => baseSalt);
    console.log(
      `  · matches=${MATCHES} shards=${numTrees} bid=${bidPrice} ask=${askPrice} feeBps=${FEE_RATE_BPS} qtys=${qtys.join(",")}`,
    );

    // Fund both payers.
    for (const p of [buyer, seller]) {
      const bal = await conn.getBalance(p.payer.publicKey);
      if (bal < 0.05 * LAMPORTS_PER_SOL) {
        await sendAndConfirmTransaction(
          conn,
          new Transaction().add(
            SystemProgram.transfer({
              fromPubkey: funder.publicKey,
              toPubkey: p.payer.publicKey,
              lamports: 0.2 * LAMPORTS_PER_SOL,
            }),
          ),
          [funder],
        );
      }
    }

    const buyerQuoteAta = await getAssociatedTokenAddress(
      quoteMint,
      buyer.payer.publicKey,
    );
    const sellerBaseAta = await getAssociatedTokenAddress(
      baseMint,
      seller.payer.publicKey,
    );
    const buyerNoteAmts = qtys.map((q) =>
      withFee(scaledQuote(q, bidPrice, PRICE_SCALE)),
    );
    const sellerNoteAmts = qtys.map((q) => withFee(q));

    // Mint enough collateral for all M notes per side (one ATA per side).
    await sendAndConfirmTransaction(
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
          buyerNoteAmts.reduce((a, b) => a + b, 0n),
        ),
        createMintToInstruction(
          baseMint,
          sellerBaseAta,
          admin.publicKey,
          sellerNoteAmts.reduce((a, b) => a + b, 0n),
        ),
      ),
      [admin],
    );

    // Deposit the 2M notes ROUND-ROBINED across the K shards — the order body
    // now carries `tree_id`, so the settle's lock_note routes each input to
    // its own shard and a batch's inputs can span shards (the cross-shard fix:
    // tee tree_id threading in api/orders.rs + settle/assemble.rs). The harness
    // recovers each note's (tree_id, leaf_index) from its NoteCreated event +
    // mirrors into shadows[tree_id], so the witness is shard-correct; the order
    // body sends note.treeId. This exercises the per-shard VALID_INPUT witness
    // on non-zero shards (cvm-settle-e2e only ever lands on shard 0). Settle
    // OUTPUTS also round-robin across shards (leaf_count sums across shards).
    const buyerNotes: DepositedNote[] = [];
    const sellerNotes: DepositedNote[] = [];
    for (let i = 0; i < MATCHES; i++) {
      buyerNotes.push(
        await harness.deposit(
          buyer,
          quoteMint,
          buyerQuoteAta,
          buyerNoteAmts[i],
          (2 * i) % numTrees,
        ),
      );
      sellerNotes.push(
        await harness.deposit(
          seller,
          baseMint,
          sellerBaseAta,
          sellerNoteAmts[i],
          (2 * i + 1) % numTrees,
        ),
      );
    }
    const depositCount = await harness.leafCount();
    expect(depositCount).toBe(2 * MATCHES);
    console.log(
      `  · deposited ${2 * MATCHES} notes (leaf_count ${startCount} → ${depositCount})`,
    );

    const slot = await conn.getSlot("confirmed");
    // Production intake caps lock TTLs at 4,500 slots.
    const expirySlot = BigInt(slot + 3_000);
    async function buildOrder(
      p: Persona,
      side: OrderSide,
      priceLimit: bigint,
      note: DepositedNote,
      orderIndex: number,
      qty: bigint,
    ) {
      const orderId = deriveOrderId(p.masterSeed, orderIndex);
      const viewingPubkey = deriveViewingEncKeypair(p.masterSeed).publicKey;
      // Each concurrently-submitted fixture gets a distinct trading key, so
      // per-key nonce monotonicity is deterministic even when HTTP arrivals
      // reorder. Owner commitment—not trading key—drives self-trade policy.
      const tradingSeed = new Uint8Array(32);
      tradingSeed.set(orderId, 0);
      tradingSeed.set(orderId, 16);
      const trading = nacl.sign.keyPair.fromSeed(tradingSeed);
      const vi = await harness.viProof(REPO_ROOT, p, note);
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
        userCommitment: p.userCommitment,
        arrivalNonce: 1n,
        viewingPubkey,
        sessionId: bootSessionId,
      });
      const sig = nacl.sign.detached(digest, trading.secretKey);
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
        user_commitment: hex(p.userCommitment),
        arrival_nonce: 1,
        trading_key: hex(trading.publicKey),
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
      };
    }

    // Build every order (snarkjs proofs — the slow part, done up front).
    const orderN = Date.now() % 1_000_000;
    const orders: object[] = [];
    for (let i = 0; i < MATCHES; i++) {
      orders.push(
        await buildOrder(
          buyer,
          OrderSide.Bid,
          bidPrice,
          buyerNotes[i],
          orderN + i,
          qtys[i],
        ),
      );
      orders.push(
        await buildOrder(
          seller,
          OrderSide.Ask,
          askPrice,
          sellerNotes[i],
          orderN + 1000 + i,
          qtys[i],
        ),
      );
    }

    const token = await authToken(GATEWAY);

    // Submit ALL orders as fast as possible (concurrently) so they land in the
    // same matcher tick → ideally one batch of M (or a few — both are useful:
    // a multi-match batch shows the per-Tx-D loop; multiple batches show #4's
    // pipelining).
    const submitStart = Date.now();
    const statuses = await Promise.all(
      orders.map((o) =>
        gwFetch(`${GATEWAY}/orders`, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            authorization: `Bearer ${token}`,
          },
          body: JSON.stringify(o),
        }).then(async (r) => {
          if (!String(r.status).startsWith("2"))
            console.log(
              `  !! /orders ${r.status}: ${(await r.text()).slice(0, 200)}`,
            );
          return r.status;
        }),
      ),
    );
    const accepted = statuses.filter((s) => String(s).startsWith("2")).length;
    console.log(
      `  · submitted ${orders.length} orders in ${Date.now() - submitStart}ms — ${accepted} accepted (2xx)`,
    );
    expect(accepted, "some orders rejected").toBe(orders.length);
    const firstOrderId = (orders[0] as { order_id: string }).order_id;

    // Each match appends ≥ note_c + note_d (2 leaves); wait for all M.
    const wantLeaves = depositCount + 2 * MATCHES;
    const settleStart = Date.now();
    let finalCount = depositCount;
    let sawPendingSettlement = false;
    const deadline = Date.now() + SETTLE_TIMEOUT_MS;
    while (Date.now() < deadline) {
      const orderStatus = await gwFetch(`${GATEWAY}/orders/${firstOrderId}`, {
        headers: { authorization: `Bearer ${token}` },
      });
      if (orderStatus.status === 200) {
        const body = (await orderStatus.json()) as { status?: string };
        sawPendingSettlement ||= body.status === "pending_settlement";
      }
      finalCount = await harness.leafCount();
      if (finalCount >= wantLeaves) break;
      await new Promise((r) => setTimeout(r, 2000));
    }
    const settleWallMs = Date.now() - settleStart;
    console.log(
      `  · leaf_count ${depositCount} → ${finalCount} (wanted ≥${wantLeaves}) in ${settleWallMs}ms wall ` +
        `→ ~${((finalCount - depositCount) / 2 / (settleWallMs / 1000)).toFixed(2)} matches/s end-to-end`,
    );
    console.log(
      `  · READ PER-Tx-D + per-stage timing: phala cvms logs <cvm> | grep -E "settle Tx D confirmed|settle pipeline timing"`,
    );
    expect(
      finalCount,
      "not all matches settled — check CVM logs for the failing stage",
    ).toBeGreaterThanOrEqual(wantLeaves);
    expect(
      sawPendingSettlement,
      "matched order never exposed the finality-gated pending state",
    ).toBe(true);
    const finalizedOrder = await gwFetch(`${GATEWAY}/orders/${firstOrderId}`, {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(
      finalizedOrder.status,
      "confirmed exact-fill order should leave the live book",
    ).toBe(404);
  }, 600_000);
});
