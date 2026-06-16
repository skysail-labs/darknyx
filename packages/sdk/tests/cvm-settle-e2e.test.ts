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
  TOKEN_PROGRAM_ID,
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
  deriveSpendingKey,
  deriveMasterViewingKey,
  deriveBlindingFactor,
  deriveOrderId,
  bn254ToBE32,
} from "../src/keys/key-generators.js";
import { userCommitmentFromKeys } from "../src/keys/user-commitment.js";
import {
  ownerCommitment,
  noteCommitmentV2,
  nullifierV2,
} from "../src/utxo/note.js";
import { buildAnchorPool, anchorsToJson } from "../src/orders/anchor-pool.js";
import {
  vaultConfigPda,
  merkleTreePda,
  buildDepositInstruction,
} from "../src/idl/vault-client.js";
import { readNoteCreated } from "../src/utxo/leaf-index.js";
import {
  orderCanonicalDigest,
  OrderSide,
  OrderType,
} from "../src/orders/canonical.js";
import {
  fetchOrderFills,
  reconstructChangeNote,
} from "../src/fills/history.js";
import {
  subscribeFills,
  type FillsSubscription,
} from "../src/fills/ws-client.js";
import {
  InMemoryNoteStore,
  type ChangeNoteRecord,
} from "../src/utxo/note-store.js";
import { MerkleShadow } from "./helpers/merkle-shadow.js";
import { proveValidInput } from "./helpers/valid-input-prover.js";
import {
  be32ToBigInt,
  loadKeypairRel,
  loadOrCreateKeypair,
  StepTimer,
  fetchSettleTimeline,
  reportSettleTimeline,
} from "./helpers/e2e-helpers.js";
import type { E2EConfig } from "./devnet-setup.test.js";

const REPO_ROOT = resolve(__dirname, "../../..");
const CONFIG_PATH = resolve(REPO_ROOT, ".devnet/e2e-config.json");
const GATEWAY = (process.env.NYX_TEE_GATEWAY ?? "").replace(/\/$/, "");

const READY =
  process.env.RUN_CVM_E2E === "1" && GATEWAY !== "" && existsSync(CONFIG_PATH);
const maybeDescribe = READY ? describe : describe.skip;

// CVM bootstrap admin creds (match deploy/docker-compose.yaml).
const API_KEY = process.env.NYX_TEE_API_KEY ?? "nyx-test-api-key";
const API_SECRET = process.env.NYX_TEE_API_SECRET ?? "nyx-test-secret";
const PASSPHRASE = process.env.NYX_TEE_PASSPHRASE ?? "nyx-test-passphrase";

const SYMBOL = "SOL-USDC";
const SOL_USD_FEED =
  "ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d";
const SETTLE_TIMEOUT_MS = Number(
  process.env.NYX_CVM_SETTLE_TIMEOUT_MS ?? "60000",
);
// Protocol fee the CVM matcher charges — MUST match the CVM's
// NYX_TEE_FEE_RATE_BPS (default 30). The matcher's fee model is
// additive: seller_charge = crossable + seller_fee (base), so the ASK
// collateral note must cover qty + fee or run_batch rejects the match
// as conservation-breaking. (The buyer's quote fee is absorbed by the
// bid's price headroom — bid 1.2×anchor > clearing.) Set to 0 when the
// CVM runs fee-free.
const FEE_RATE_BPS = BigInt(process.env.NYX_CVM_FEE_RATE_BPS ?? "30");

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

function hex(b: Uint8Array): string {
  return Buffer.from(b).toString("hex");
}

/** fetch with retries — the dstack gateway can transiently close the
 *  socket (UND_ERR_SOCKET) for the first minute after a CVM restart. */
async function gwFetch(
  url: string,
  init?: RequestInit,
  tries = 6,
): Promise<Response> {
  let last: unknown;
  for (let i = 0; i < tries; i++) {
    try {
      return await fetch(url, init);
    } catch (e) {
      last = e;
      await new Promise((r) => setTimeout(r, 3000));
    }
  }
  throw last;
}

/** Fetch the live raw SOL/USD price integer the CVM's oracle uses. */
async function fetchOracleAnchor(): Promise<bigint> {
  if (process.env.NYX_CVM_PRICE) return BigInt(process.env.NYX_CVM_PRICE);
  const url = `https://hermes.pyth.network/v2/updates/price/latest?ids[]=${SOL_USD_FEED}`;
  const res = await fetch(url);
  const j = (await res.json()) as {
    parsed: { price: { price: string; expo: number } }[];
  };
  const raw = BigInt(j.parsed[0].price.price);
  console.log(
    `  · oracle anchor (raw SOL/USD): ${raw} (expo ${j.parsed[0].price.expo})`,
  );
  return raw;
}

/** Total on-chain leaf count, summed across the K `MerkleTree` shard accounts.
 *  Post-sharding the tree state moved out of `VaultConfig` into one `MerkleTree`
 *  per shard (`leaf_count: u64` @ offset 8, after the 8-byte Anchor disc — see
 *  `crates/nyx-tee/src/merkle/sync.rs`). Deposits/settles spread leaves across
 *  shards, so a settle that adds N output notes grows this SUM by N regardless
 *  of routing. */
async function onChainLeafCount(
  conn: Connection,
  programId: PublicKey,
  numTrees: number,
): Promise<number> {
  let total = 0;
  for (let treeId = 0; treeId < Math.max(1, numTrees); treeId++) {
    const [pda] = merkleTreePda(programId, treeId);
    const info = await conn.getAccountInfo(pda);
    if (!info)
      throw new Error(`MerkleTree shard ${treeId} missing — run devnet-setup`);
    total += Number(
      new DataView(info.data.buffer, info.data.byteOffset + 8, 8).getBigUint64(
        0,
        true,
      ),
    );
  }
  return total;
}

interface Persona {
  name: string;
  payer: Keypair;
  trading: Keypair; // Ed25519 key that signs the order body
  masterSeed: Uint8Array;
  spendingKey: bigint;
  ownerBlinding: bigint;
  ownerCommit: bigint;
  userCommitment: Uint8Array; // 32B BE
}

// Per-run salt so the persona's seed-derived keys — and therefore the
// amount-INDEPENDENT v2 nullifiers (Poseidon3(DOMAIN_NULL, spending_key,
// inner_hash)) — are fresh each run. Without this the deposit inner_hash
// (deriveBlindingFactor(masterSeed, leafIndex) at a fixed masterSeed + fresh
// tree leaf 0/1) repeats, so the settle's NullifierEntry PDA collides on the
// 2nd run with "Allocate: account already in use". Randomising BASE_QTY only
// freshens the commitment (ConsumedNoteEntry), NOT the nullifier.
const RUN_SALT = BigInt(process.env.NYX_CVM_RUN_SALT ?? String(Date.now()));

async function makePersona(name: string, seed0: number): Promise<Persona> {
  const payer = loadOrCreateKeypair(
    resolve(REPO_ROOT, `.devnet/keypairs/${name}-payer.json`),
  );
  const trading = loadOrCreateKeypair(
    resolve(REPO_ROOT, `.devnet/keypairs/${name}-trading.json`),
  );
  const masterSeed = new Uint8Array(64);
  for (let i = 0; i < 64; i++) {
    masterSeed[i] =
      (seed0 + i * 7 + Number((RUN_SALT >> BigInt(i % 53)) & 0xffn)) & 0xff;
  }
  const spendingKey = deriveSpendingKey(masterSeed);
  const viewingKey = deriveMasterViewingKey(masterSeed);
  const ownerBlinding = BigInt(seed0) + 0xfeedn;
  const ownerCommit = await ownerCommitment(spendingKey, ownerBlinding);
  const userCommitment = await userCommitmentFromKeys({
    rootKeyPubkey: payer.publicKey.toBytes(),
    spendingKey,
    viewingKey,
    r0: BigInt(seed0) + 1n,
    r1: BigInt(seed0) + 2n,
    r2: BigInt(seed0) + 3n,
  });
  // Intake requires the top byte to be exactly 0 (it Poseidon-hashes
  // this when constructing change notes). A real Poseidon output is
  // Fr-safe (top byte ≤ 0x30) but not necessarily 0; for an exact-fill
  // trade (no change notes) it's opaque, so zero the top byte to pass
  // the stricter intake check — same shape the loadgen/orders fixtures use.
  userCommitment[0] = 0;
  return {
    name,
    payer,
    trading,
    masterSeed,
    spendingKey,
    ownerBlinding,
    ownerCommit,
    userCommitment,
  };
}

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
      buyer = await makePersona("cvm-buyer", 0x40);
      seller = await makePersona("cvm-seller", 0x80);
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
        // them; we keep one shadow per shard and recover each note's
        // (tree_id, leaf_index) from its NoteCreated event.
        const numTrees =
          (cfg as unknown as { numTrees?: number }).numTrees ?? 1;

        // The tree must be empty (fresh reset) so each shard's shadow starts from
        // 0 and matches on-chain.
        const startCount = await onChainLeafCount(
          conn,
          vaultProgramId,
          numTrees,
        );
        expect(
          startCount,
          "tree not empty — run devnet-setup (reset) first",
        ).toBe(0);

        // For the cross-batch re-match we need a 2nd ask, so a 3rd deposit
        // (seller2). It's pre-deposited up-front: its VALID_INPUT root stays in
        // the vault's 64-deep recent-root ring through batch 1's settle, so the
        // proof is still valid when batch 2 locks it.
        const seller2 = REMATCH ? await makePersona("cvm-seller2", 0xc0) : null;
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
        // re-derived commitment lines up.
        const withFee = (nominal: bigint) =>
          nominal + (nominal * FEE_RATE_BPS) / 10_000n;
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
        // One shadow per shard — a deposit lands in a shard the PROGRAM chooses,
        // so we read the actual (tree_id, leaf_index) back from the NoteCreated
        // event and append to that shard's shadow (matching on-chain shard state).
        const shadows = await Promise.all(
          Array.from({ length: numTrees }, () => MerkleShadow.create()),
        );
        async function deposit(
          p: Persona,
          mint: PublicKey,
          ata: PublicKey,
          amount: bigint,
        ) {
          // The inner_hash is just a deterministic per-deposit nonce baked into the
          // committed leaf; use the pre-deposit total count (0,1,2 in this isolated
          // run). v2: a single inner_hash replaces the old (nonce, blinding) pair.
          const nonce = await onChainLeafCount(conn, vaultProgramId, numTrees);
          const innerHash = deriveBlindingFactor(p.masterSeed, BigInt(nonce));
          const commitment = await noteCommitmentV2({
            tokenMint: mint.toBytes(),
            amount,
            ownerCommitment: p.ownerCommit,
            innerHash,
          });
          const ix = buildDepositInstruction({
            programId: vaultProgramId,
            depositor: p.payer.publicKey,
            tokenMint: mint,
            depositorTokenAccount: ata,
            tokenProgramId: TOKEN_PROGRAM_ID,
            amount,
            ownerCommitment: bn254ToBE32(p.ownerCommit),
            innerHash: bn254ToBE32(innerHash),
          });
          const sig = await sendAndConfirmTransaction(
            conn,
            new Transaction().add(ix),
            [p.payer],
          );
          // Recover the shard + position the program actually appended to.
          const { treeId, leafIndex } = await readNoteCreated(conn, sig);
          await shadows[treeId].append(commitment);
          console.log(
            `  · ${p.name} deposited shard ${treeId} leaf ${leafIndex} (${sig.slice(0, 8)}…)`,
          );
          return {
            mint,
            amount,
            innerHash,
            commitment,
            treeId,
            leafIndex: Number(leafIndex),
          };
        }
        const buyerNote = await t.step("deposit buyer note", () =>
          deposit(buyer, quoteMint, buyerQuoteAta, buyerNoteAmt),
        );
        const sellerNote = await t.step("deposit seller note", () =>
          deposit(seller, baseMint, sellerBaseAta, sellerNoteAmt),
        );

        // seller2: a 2nd ask's collateral, deposited now (leaf 2) for the
        // batch-2 re-match. Same base amount as seller1.
        let seller2Note: Awaited<ReturnType<typeof deposit>> | null = null;
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
            deposit(seller2, baseMint, seller2BaseAta, sellerNoteAmt),
          );
        }

        // shadow root must equal on-chain current_root (so the VALID_INPUT
        // proof root is in the vault's recent ring at lock time).
        const depositCount = await onChainLeafCount(
          conn,
          vaultProgramId,
          numTrees,
        );
        expect(depositCount).toBe(REMATCH ? 3 : 2);

        // ── 3. VALID_INPUT proofs (relayed to lock_note via the order) ──
        async function viProof(p: Persona, note: typeof buyerNote) {
          // Witness against the shard the note landed in (its shadow root must
          // equal that shard's on-chain MerkleTree.current_root at lock time).
          const w = await shadows[note.treeId].witness(note.leafIndex);
          const vi = await proveValidInput({
            repoRoot: REPO_ROOT,
            spendingKey: p.spendingKey,
            ownerCommitmentBlinding: p.ownerBlinding,
            innerHash: note.innerHash,
            tokenMint: note.mint.toBytes(),
            amount: note.amount,
            merkleRootBE: w.root,
            merkleWitness: {
              pathElements: w.siblings.map(be32ToBigInt),
              pathIndices: w.indices,
            },
          });
          const proofBytes = new Uint8Array([
            ...vi.proof.piA,
            ...vi.proof.piB,
            ...vi.proof.piC,
          ]);
          return { proofBytes, root: w.root };
        }
        const buyerVI = await t.step("VALID_INPUT prove buyer (snarkjs)", () =>
          viProof(buyer, buyerNote),
        );
        const sellerVI = await t.step(
          "VALID_INPUT prove seller (snarkjs)",
          () => viProof(seller, sellerNote),
        );
        const seller2VI =
          seller2 && seller2Note
            ? await t.step("VALID_INPUT prove seller2 (snarkjs)", () =>
                viProof(seller2, seller2Note!),
              )
            : null;

        // ── 4. build + sign the two orders ─────────────────────────────
        const slot = await conn.getSlot("confirmed");
        const expirySlot = BigInt(slot + 50_000);

        async function buildOrder(
          p: Persona,
          side: OrderSide,
          priceLimit: bigint,
          note: typeof buyerNote,
          vi: { proofBytes: Uint8Array; root: Uint8Array },
          orderIndex: number,
          qty: bigint,
        ) {
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
            expirySlot,
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
            expiry_slot: Number(expirySlot),
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
              finalCount = await onChainLeafCount(
                conn,
                vaultProgramId,
                numTrees,
              );
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
          const change = idxFills.find(
            (f) => f.side === "buyer" && f.changeNoteCommitment,
          );
          expect(
            change,
            "indexer did not surface the buyer change-note fill",
          ).toBeTruthy();
          expect(BigInt(change!.changeAmount)).toBeGreaterThan(0n);

          // Over-collateralization: the surplus we deposited must come back in the
          // change note (on top of any price-improvement surplus).
          if (BUYER_SURPLUS > 0n) {
            expect(
              BigInt(change!.changeAmount),
              "over-collateral surplus did not return as change",
            ).toBeGreaterThanOrEqual(BUYER_SURPLUS);
          }

          // The durable path recovers the spendable opening from the seed alone
          // (the anchor-index search = the Vuln-4 integrity check): the commitment
          // must reproduce exactly. This ONLY succeeds for an anchor-based
          // CONTINUATION note (partial fill) — proving the buyer's residual
          // relocked onto an anchor, which is the whole point of the anchor pool.
          const rec = await reconstructChangeNote(change!, {
            masterSeed: buyer.masterSeed,
            ownerCommitment: buyer.ownerCommit,
            baseMint: baseMint.toBytes(),
            quoteMint: quoteMint.toBytes(),
          });
          expect(
            rec,
            "could not reconstruct the change note — note_e is not anchor-based (was this a full fill, not a continuation?)",
          ).not.toBeNull();
          expect(rec!.commitment).toBe(change!.changeNoteCommitment);
          // The continuation consumed an anchor from the pool (index ≥ 0).
          expect(
            rec!.anchorIndex,
            "continuation did not consume an anchor",
          ).toBeGreaterThanOrEqual(0);
          console.log(
            `  · continuation note recovered at anchor index ${rec!.anchorIndex}`,
          );

          // Live: the per-account WS delivered + verified the same memo.
          await t.step("live WS fill delivery", async () => {
            const wsDeadline = Date.now() + 15_000;
            while (
              Date.now() < wsDeadline &&
              !wsFills.some((r) => r.orderId === buyerId)
            ) {
              await new Promise((r) => setTimeout(r, 1000));
            }
          });
          expect(
            wsFills.some((r) => r.orderId === buyerId),
            "live /ws/fills did not deliver the buyer FillMemo (is the CVM built from the fills commit?)",
          ).toBe(true);
          console.log(
            `  · fills OK — indexer + WS both surfaced buyer change note ${change!.changeNoteCommitment.slice(0, 12)}…`,
          );

          // ── 8. cross-batch RE-MATCH (opt-in) ─────────────────────────
          // The buyer's residual relocked onto anchor[0] in batch 1 and stays in
          // the book. Submit a SECOND ask: the matcher must re-match that
          // relocked note (note_e from batch 1) in a NEW batch and settle it
          // again — the real proof that a partial fill continues across batches,
          // not just that one continuation note is minted.
          if (REMATCH && seller2 && seller2Note && seller2VI) {
            const leafBeforeRematch = await onChainLeafCount(
              conn,
              vaultProgramId,
              numTrees,
            );
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
                  leafAfterRematch = await onChainLeafCount(
                    conn,
                    vaultProgramId,
                    numTrees,
                  );
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
