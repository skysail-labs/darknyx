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
  bn254ToBE32,
} from "../src/keys/key-generators.js";
import { userCommitmentFromKeys } from "../src/keys/user-commitment.js";
import { ownerCommitment, noteCommitment, nullifier } from "../src/utxo/note.js";
import { vaultConfigPda, buildDepositInstruction } from "../src/idl/vault-client.js";
import { orderCanonicalDigest, OrderSide, OrderType } from "../src/orders/canonical.js";
import { MerkleShadow } from "./helpers/merkle-shadow.js";
import { proveValidInput } from "./helpers/valid-input-prover.js";
import { be32ToBigInt, loadKeypairRel, loadOrCreateKeypair } from "./helpers/e2e-helpers.js";
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
const SOL_USD_FEED = "ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d";
const SETTLE_TIMEOUT_MS = Number(process.env.NYX_CVM_SETTLE_TIMEOUT_MS ?? "60000");
// Protocol fee the CVM matcher charges — MUST match the CVM's
// NYX_TEE_FEE_RATE_BPS (default 30). The matcher's fee model is
// additive: seller_charge = crossable + seller_fee (base), so the ASK
// collateral note must cover qty + fee or run_batch rejects the match
// as conservation-breaking. (The buyer's quote fee is absorbed by the
// bid's price headroom — bid 1.2×anchor > clearing.) Set to 0 when the
// CVM runs fee-free.
const FEE_RATE_BPS = BigInt(process.env.NYX_CVM_FEE_RATE_BPS ?? "30");

function hex(b: Uint8Array): string {
  return Buffer.from(b).toString("hex");
}

/** fetch with retries — the dstack gateway can transiently close the
 *  socket (UND_ERR_SOCKET) for the first minute after a CVM restart. */
async function gwFetch(url: string, init?: RequestInit, tries = 6): Promise<Response> {
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
  const j = (await res.json()) as { parsed: { price: { price: string; expo: number } }[] };
  const raw = BigInt(j.parsed[0].price.price);
  console.log(`  · oracle anchor (raw SOL/USD): ${raw} (expo ${j.parsed[0].price.expo})`);
  return raw;
}

/** Read on-chain VaultConfig.leaf_count (u64 @ offset 104). */
async function onChainLeafCount(conn: Connection, vaultPda: PublicKey): Promise<number> {
  const info = await conn.getAccountInfo(vaultPda);
  if (!info) throw new Error("vault_config missing — run devnet-setup");
  return Number(
    new DataView(info.data.buffer, info.data.byteOffset + 104, 8).getBigUint64(0, true),
  );
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

async function makePersona(name: string, seed0: number): Promise<Persona> {
  const payer = loadOrCreateKeypair(resolve(REPO_ROOT, `.devnet/keypairs/${name}-payer.json`));
  const trading = loadOrCreateKeypair(resolve(REPO_ROOT, `.devnet/keypairs/${name}-trading.json`));
  const masterSeed = new Uint8Array(64);
  for (let i = 0; i < 64; i++) masterSeed[i] = (seed0 + i * 7) & 0xff;
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
  return { name, payer, trading, masterSeed, spendingKey, ownerBlinding, ownerCommit, userCommitment };
}

maybeDescribe("Phase 3 — CVM-driven settle e2e (deposit → CVM match → CVM settle)", () => {
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
    conn = new Connection(process.env.SOLANA_RPC_URL ?? "https://api.devnet.solana.com", "confirmed");
    admin = loadKeypairRel(REPO_ROOT, process.env.ADMIN_KEYPAIR ?? ".devnet/keypairs/admin.json");
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
      const BASE_QTY = BigInt(process.env.NYX_CVM_BASE_QTY ?? String((Date.now() % 900_000) + 1000));
      const anchor = await fetchOracleAnchor();
      const bidPrice = (anchor * 12n) / 10n;
      const askPrice = (anchor * 8n) / 10n;
      console.log(
        `  · BASE_QTY=${BASE_QTY} bid=${bidPrice} ask=${askPrice} feeBps=${FEE_RATE_BPS} sellerBaseFee=${(BASE_QTY * FEE_RATE_BPS) / 10_000n}`,
      );

      // The tree must be empty (fresh reset) so our deposits land at 0,1
      // and the shadow matches on-chain.
      const startCount = await onChainLeafCount(conn, vaultPda);
      expect(startCount, "tree not empty — run devnet-setup (reset) first").toBe(0);

      // ── 1. fund payers + mint collateral ───────────────────────────
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

      const buyerQuoteAta = await getAssociatedTokenAddress(quoteMint, buyer.payer.publicKey);
      const sellerBaseAta = await getAssociatedTokenAddress(baseMint, seller.payer.publicKey);
      // Each side locks NOMINAL collateral + its OWN protocol fee, matching
      // the intake derivation (orders.rs: note_amount = nominal + nominal *
      // bps / 10_000, floored). Bid nominal = qty × price (quote); ask
      // nominal = qty (base). With fees off (bps=0) both collapse to the
      // nominal, unchanged. Floor division must match intake exactly so the
      // re-derived commitment lines up.
      const withFee = (nominal: bigint) => nominal + (nominal * FEE_RATE_BPS) / 10_000n;
      const buyerNoteAmt = withFee(BASE_QTY * bidPrice);
      const sellerNoteAmt = withFee(BASE_QTY);

      await sendAndConfirmTransaction(
        conn,
        new Transaction().add(
          createAssociatedTokenAccountIdempotentInstruction(
            admin.publicKey, buyerQuoteAta, buyer.payer.publicKey, quoteMint,
          ),
          createAssociatedTokenAccountIdempotentInstruction(
            admin.publicKey, sellerBaseAta, seller.payer.publicKey, baseMint,
          ),
          createMintToInstruction(quoteMint, buyerQuoteAta, admin.publicKey, buyerNoteAmt),
          createMintToInstruction(baseMint, sellerBaseAta, admin.publicKey, sellerNoteAmt),
        ),
        [admin],
      );

      // ── 2. deposit both notes; mirror into a shadow tree ───────────
      const tree = await MerkleShadow.create();
      async function deposit(p: Persona, mint: PublicKey, ata: PublicKey, amount: bigint) {
        const leafIndex = await onChainLeafCount(conn, vaultPda);
        const nonce = deriveBlindingFactor(p.masterSeed, BigInt(leafIndex));
        const blindingR = deriveBlindingFactor(p.masterSeed, BigInt(leafIndex) + 1n);
        const commitment = await noteCommitment({
          tokenMint: mint.toBytes(),
          amount,
          ownerCommitment: p.ownerCommit,
          nonce,
          blindingR,
        });
        const ix = buildDepositInstruction({
          programId: vaultProgramId,
          depositor: p.payer.publicKey,
          tokenMint: mint,
          depositorTokenAccount: ata,
          tokenProgramId: TOKEN_PROGRAM_ID,
          amount,
          ownerCommitment: bn254ToBE32(p.ownerCommit),
          nonce: bn254ToBE32(nonce),
          blindingR: bn254ToBE32(blindingR),
        });
        const sig = await sendAndConfirmTransaction(conn, new Transaction().add(ix), [p.payer]);
        await tree.append(commitment);
        console.log(`  · ${p.name} deposited leaf ${leafIndex} (${sig.slice(0, 8)}…)`);
        return { mint, amount, nonce, blindingR, commitment, leafIndex };
      }
      const buyerNote = await deposit(buyer, quoteMint, buyerQuoteAta, buyerNoteAmt);
      const sellerNote = await deposit(seller, baseMint, sellerBaseAta, sellerNoteAmt);

      // shadow root must equal on-chain current_root (so the VALID_INPUT
      // proof root is in the vault's recent ring at lock time).
      const depositCount = await onChainLeafCount(conn, vaultPda);
      expect(depositCount).toBe(2);

      // ── 3. VALID_INPUT proofs (relayed to lock_note via the order) ──
      async function viProof(p: Persona, note: typeof buyerNote) {
        const w = await tree.witness(note.leafIndex);
        const vi = await proveValidInput({
          repoRoot: REPO_ROOT,
          spendingKey: p.spendingKey,
          ownerCommitmentBlinding: p.ownerBlinding,
          nonce: note.nonce,
          blindingR: note.blindingR,
          tokenMint: note.mint.toBytes(),
          amount: note.amount,
          merkleRootBE: w.root,
          merkleWitness: {
            pathElements: w.siblings.map(be32ToBigInt),
            pathIndices: w.indices,
          },
        });
        const proofBytes = new Uint8Array([...vi.proof.piA, ...vi.proof.piB, ...vi.proof.piC]);
        return { proofBytes, root: w.root };
      }
      const buyerVI = await viProof(buyer, buyerNote);
      const sellerVI = await viProof(seller, sellerNote);

      // ── 4. build + sign the two orders ─────────────────────────────
      const slot = await conn.getSlot("confirmed");
      const expirySlot = BigInt(slot + 50_000);

      async function buildOrder(
        p: Persona,
        side: OrderSide,
        priceLimit: bigint,
        note: typeof buyerNote,
        vi: { proofBytes: Uint8Array; root: Uint8Array },
      ) {
        const orderId = nacl.randomBytes(16);
        const digest = orderCanonicalDigest({
          symbol: new TextEncoder().encode(SYMBOL),
          side,
          orderType: OrderType.Limit,
          amount: BASE_QTY,
          priceLimit,
          minFillSize: 0n,
          expirySlot,
          orderId,
          noteCommitment: note.commitment,
          userCommitment: p.userCommitment,
          arrivalNonce: 1n,
        });
        const sig = nacl.sign.detached(digest, p.trading.secretKey);
        return {
          symbol: SYMBOL,
          side: side === OrderSide.Bid ? "bid" : "ask",
          order_type: "limit",
          amount: Number(BASE_QTY),
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
          note_nonce: hex(bn254ToBE32(note.nonce)),
          note_blinding: hex(bn254ToBE32(note.blindingR)),
          nullifier: hex(await nullifier(p.spendingKey, note.commitment)),
          merkle_root: hex(vi.root),
          valid_input_proof: hex(vi.proofBytes),
        };
      }
      const buyerOrder = await buildOrder(buyer, OrderSide.Bid, bidPrice, buyerNote, buyerVI);
      const sellerOrder = await buildOrder(seller, OrderSide.Ask, askPrice, sellerNote, sellerVI);

      // ── 5. auth + submit both orders to the CVM ────────────────────
      const tokRes = await gwFetch(`${GATEWAY}/auth/token`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ api_key: API_KEY, api_secret: API_SECRET, passphrase: PASSPHRASE }),
      });
      expect(tokRes.status, "auth/token failed").toBe(200);
      const token = ((await tokRes.json()) as { access_token: string }).access_token;

      async function submit(body: object): Promise<number> {
        const r = await gwFetch(`${GATEWAY}/orders`, {
          method: "POST",
          headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
          body: JSON.stringify(body),
        });
        if (!String(r.status).startsWith("2")) {
          console.log(`  !! /orders ${r.status}: ${await r.text()}`);
        }
        return r.status;
      }
      const s1 = await submit(buyerOrder);
      const s2 = await submit(sellerOrder);
      expect(String(s1).startsWith("2"), `buyer order rejected (${s1})`).toBe(true);
      expect(String(s2).startsWith("2"), `seller order rejected (${s2})`).toBe(true);
      console.log(`  · orders accepted (buyer=${buyerOrder.order_id.slice(0, 8)} bid=${bidPrice}, seller=${sellerOrder.order_id.slice(0, 8)} ask=${askPrice})`);

      // Diagnostic: confirm both are in the book (200) vs matched-and-gone
      // (404), to localise a no-settle to matching vs the settle pipeline.
      for (const [n, o] of [["buyer", buyerOrder], ["seller", sellerOrder]] as const) {
        const r = await gwFetch(`${GATEWAY}/orders/${o.order_id}`, {
          headers: { authorization: `Bearer ${token}` },
        });
        console.log(`  · GET /orders/${n} -> ${r.status} ${(await r.text()).slice(0, 200)}`);
      }
      console.log("  · waiting for match + settle…");

      // ── 6. watch on-chain leaf_count grow (settle appended note_c/d) ─
      const deadline = Date.now() + SETTLE_TIMEOUT_MS;
      let finalCount = depositCount;
      while (Date.now() < deadline) {
        finalCount = await onChainLeafCount(conn, vaultPda);
        if (finalCount >= depositCount + 2) break;
        await new Promise((r) => setTimeout(r, 3000));
      }
      console.log(`  · on-chain leaf_count: ${depositCount} → ${finalCount}`);
      expect(
        finalCount,
        "settle did not land — CVM logs (phala cvms logs) show the failing settle stage",
      ).toBeGreaterThanOrEqual(depositCount + 2);
    },
    SETTLE_TIMEOUT_MS + 120_000,
  );
});
