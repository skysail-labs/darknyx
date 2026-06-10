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
 * NOTE: orders are submitted concurrently (Promise.all) and can span multiple
 * matcher ticks, so the batch boundaries + per-match timings are APPROXIMATE —
 * treat them as a steady-state estimate, not a guaranteed single-batch measurement.
 *
 * Real-mint regime + a fresh tree reset (like cvm-settle-e2e). Run:
 *   RUN_CVM_E2E=1 NYX_CVM_MATCHES=4 NYX_TEE_GATEWAY=$GW SOLANA_RPC_URL=$HELIUS \
 *     FUNDER_KEYPAIR=~/.config/solana/id.json ADMIN_KEYPAIR=.devnet/keypairs/admin.json \
 *     ( cd packages/sdk && ../../node_modules/.bin/vitest run tests/cvm-multimatch-settle.test.ts )
 */
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";
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
import { ownerCommitment, noteCommitmentV2, nullifierV2 } from "../src/utxo/note.js";
import { buildAnchorPool, anchorsToJson } from "../src/orders/anchor-pool.js";
import { vaultConfigPda, merkleTreePda, buildDepositInstruction } from "../src/idl/vault-client.js";
import { orderCanonicalDigest, OrderSide, OrderType } from "../src/orders/canonical.js";
import { MerkleShadow } from "./helpers/merkle-shadow.js";
import { proveValidInput } from "./helpers/valid-input-prover.js";
import { be32ToBigInt, loadKeypairRel, loadOrCreateKeypair } from "./helpers/e2e-helpers.js";
import type { E2EConfig } from "./devnet-setup.test.js";

const REPO_ROOT = resolve(__dirname, "../../..");
const CONFIG_PATH = resolve(REPO_ROOT, ".devnet/e2e-config.json");
const GATEWAY = (process.env.NYX_TEE_GATEWAY ?? "").replace(/\/$/, "");
const READY = process.env.RUN_CVM_E2E === "1" && GATEWAY !== "" && existsSync(CONFIG_PATH);
const maybeDescribe = READY ? describe : describe.skip;

const API_KEY = process.env.NYX_TEE_API_KEY ?? "nyx-test-api-key";
const API_SECRET = process.env.NYX_TEE_API_SECRET ?? "nyx-test-secret";
const PASSPHRASE = process.env.NYX_TEE_PASSPHRASE ?? "nyx-test-passphrase";
const SYMBOL = "SOL-USDC";
const SOL_USD_FEED = "ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d";
const FEE_RATE_BPS = BigInt(process.env.NYX_CVM_FEE_RATE_BPS ?? "30");
const MATCHES = Number(process.env.NYX_CVM_MATCHES ?? "4");
const SETTLE_TIMEOUT_MS = Number(process.env.NYX_CVM_SETTLE_TIMEOUT_MS ?? "180000");
const RUN_SALT = BigInt(process.env.NYX_CVM_RUN_SALT ?? String(Date.now()));

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

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

async function fetchOracleAnchor(): Promise<bigint> {
  if (process.env.NYX_CVM_PRICE) return BigInt(process.env.NYX_CVM_PRICE);
  const url = `https://hermes.pyth.network/v2/updates/price/latest?ids[]=${SOL_USD_FEED}`;
  const j = (await (await fetch(url)).json()) as { parsed: { price: { price: string } }[] };
  return BigInt(j.parsed[0].price.price);
}

// Post-sharding the tree state lives in K per-shard MerkleTree accounts
// (8 disc + 8 leaf_count + …). leaf_count is at offset 8.
async function shardLeafCount(
  conn: Connection,
  programId: PublicKey,
  treeId: number,
): Promise<number> {
  const [treePda] = merkleTreePda(programId, treeId);
  const info = await conn.getAccountInfo(treePda);
  if (!info) throw new Error(`merkle_tree shard ${treeId} missing — run devnet-setup`);
  return Number(new DataView(info.data.buffer, info.data.byteOffset + 8, 8).getBigUint64(0, true));
}

// Total leaves across all K shards. Settle outputs round-robin across shards,
// so the pool's leaf count is the SUM (a single shard sees only its slice).
async function totalLeafCount(
  conn: Connection,
  programId: PublicKey,
  numTrees: number,
): Promise<number> {
  let total = 0;
  for (let treeId = 0; treeId < numTrees; treeId++) {
    total += await shardLeafCount(conn, programId, treeId);
  }
  return total;
}

interface Persona {
  name: string;
  payer: Keypair;
  trading: Keypair;
  masterSeed: Uint8Array;
  spendingKey: bigint;
  ownerBlinding: bigint;
  ownerCommit: bigint;
  userCommitment: Uint8Array;
}

async function makePersona(name: string, seed0: number): Promise<Persona> {
  const payer = loadOrCreateKeypair(resolve(REPO_ROOT, `.devnet/keypairs/${name}-payer.json`));
  const trading = loadOrCreateKeypair(resolve(REPO_ROOT, `.devnet/keypairs/${name}-trading.json`));
  const masterSeed = new Uint8Array(64);
  for (let i = 0; i < 64; i++) {
    masterSeed[i] = (seed0 + i * 7 + Number((RUN_SALT >> BigInt(i % 53)) & 0xffn)) & 0xff;
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
  userCommitment[0] = 0;
  return { name, payer, trading, masterSeed, spendingKey, ownerBlinding, ownerCommit, userCommitment };
}

maybeDescribe("Perf — multi-match concurrent settle profile", () => {
  it(
    `deposits ${MATCHES} crossing pairs and settles them (read per-Tx-D timing from CVM logs)`,
    async () => {
      const cfg = JSON.parse(readFileSync(CONFIG_PATH, "utf8")) as E2EConfig;
      const conn = new Connection(process.env.SOLANA_RPC_URL ?? "https://api.devnet.solana.com", "confirmed");
      const admin = loadKeypairRel(REPO_ROOT, process.env.ADMIN_KEYPAIR ?? ".devnet/keypairs/admin.json");
      const funder = process.env.FUNDER_KEYPAIR ? loadKeypairRel(REPO_ROOT, process.env.FUNDER_KEYPAIR) : admin;
      const vaultProgramId = new PublicKey(cfg.vaultProgramId);
      const [vaultPda] = vaultConfigPda(vaultProgramId);
      const baseMint = new PublicKey(cfg.baseMint.pubkey);
      const quoteMint = new PublicKey(cfg.quoteMint.pubkey);
      // K shards (default 1). Deposits all go to shard 0; settle OUTPUTS
      // round-robin across all K, so totals are summed across shards.
      const NUM_TREES = (cfg as { numTrees?: number }).numTrees ?? 1;

      const buyer = await makePersona("cvm-buyer", 0x40);
      const seller = await makePersona("cvm-seller", 0x80);

      const startCount = await totalLeafCount(conn, vaultProgramId, NUM_TREES);
      expect(startCount, "trees not empty — reset the merkle trees first").toBe(0);

      const anchor = await fetchOracleAnchor();
      const bidPrice = (anchor * 12n) / 10n;
      const askPrice = (anchor * 8n) / 10n;
      const withFee = (nominal: bigint) => nominal + (nominal * FEE_RATE_BPS) / 10_000n;
      // SAME qty for every pair → the uniform-price match is cleanly pairwise
      // (M bids × M asks, all full fills, NO partial-fill residual/relock) so all
      // M matches land in ONE batch — exactly what we want for a clean per-batch
      // co-inclusion measurement (and one settle pipeline, not M, which keeps the
      // RPC under the rate limit). Commitments stay unique via the per-leaf
      // inner_hash, so identical amounts don't collide.
      const baseSalt = BigInt(Date.now() % 200_000) + 1000n;
      const qtys = Array.from({ length: MATCHES }, () => baseSalt);
      console.log(`  · matches=${MATCHES} bid=${bidPrice} ask=${askPrice} feeBps=${FEE_RATE_BPS} qtys=${qtys.join(",")}`);

      // Fund both payers.
      for (const p of [buyer, seller]) {
        const bal = await conn.getBalance(p.payer.publicKey);
        if (bal < 0.05 * LAMPORTS_PER_SOL) {
          await sendAndConfirmTransaction(
            conn,
            new Transaction().add(
              SystemProgram.transfer({ fromPubkey: funder.publicKey, toPubkey: p.payer.publicKey, lamports: 0.2 * LAMPORTS_PER_SOL }),
            ),
            [funder],
          );
        }
      }

      const buyerQuoteAta = await getAssociatedTokenAddress(quoteMint, buyer.payer.publicKey);
      const sellerBaseAta = await getAssociatedTokenAddress(baseMint, seller.payer.publicKey);
      const buyerNoteAmts = qtys.map((q) => withFee(q * bidPrice));
      const sellerNoteAmts = qtys.map((q) => withFee(q));

      // Mint enough collateral for all M notes per side (one ATA per side).
      await sendAndConfirmTransaction(
        conn,
        new Transaction().add(
          createAssociatedTokenAccountIdempotentInstruction(admin.publicKey, buyerQuoteAta, buyer.payer.publicKey, quoteMint),
          createAssociatedTokenAccountIdempotentInstruction(admin.publicKey, sellerBaseAta, seller.payer.publicKey, baseMint),
          createMintToInstruction(quoteMint, buyerQuoteAta, admin.publicKey, buyerNoteAmts.reduce((a, b) => a + b, 0n)),
          createMintToInstruction(baseMint, sellerBaseAta, admin.publicKey, sellerNoteAmts.reduce((a, b) => a + b, 0n)),
        ),
        [admin],
      );

      // Deposit all 2M notes, mirroring into one shadow tree.
      const tree = await MerkleShadow.create();
      async function deposit(p: Persona, mint: PublicKey, ata: PublicKey, amount: bigint) {
        // All deposits go to shard 0 → leaf index is shard 0's leaf_count.
        const leafIndex = await shardLeafCount(conn, vaultProgramId, 0);
        const innerHash = deriveBlindingFactor(p.masterSeed, BigInt(leafIndex));
        const commitment = await noteCommitmentV2({ tokenMint: mint.toBytes(), amount, ownerCommitment: p.ownerCommit, innerHash });
        const ix = buildDepositInstruction({
          programId: vaultProgramId,
          treeId: 0,
          depositor: p.payer.publicKey,
          tokenMint: mint,
          depositorTokenAccount: ata,
          tokenProgramId: TOKEN_PROGRAM_ID,
          amount,
          ownerCommitment: bn254ToBE32(p.ownerCommit),
          innerHash: bn254ToBE32(innerHash),
        });
        await sendAndConfirmTransaction(conn, new Transaction().add(ix), [p.payer]);
        await tree.append(commitment);
        return { mint, amount, innerHash, commitment, leafIndex };
      }
      type Note = Awaited<ReturnType<typeof deposit>>;
      const buyerNotes: Note[] = [];
      const sellerNotes: Note[] = [];
      // Interleave deposits so buyer/seller leaves alternate (doesn't matter for
      // correctness — the shadow tracks the actual leaf index per note).
      for (let i = 0; i < MATCHES; i++) {
        buyerNotes.push(await deposit(buyer, quoteMint, buyerQuoteAta, buyerNoteAmts[i]));
        sellerNotes.push(await deposit(seller, baseMint, sellerBaseAta, sellerNoteAmts[i]));
      }
      const depositCount = await totalLeafCount(conn, vaultProgramId, NUM_TREES);
      expect(depositCount).toBe(2 * MATCHES);
      console.log(`  · deposited ${2 * MATCHES} notes (leaf_count ${startCount} → ${depositCount})`);

      async function viProof(p: Persona, note: Note) {
        const w = await tree.witness(note.leafIndex);
        const vi = await proveValidInput({
          repoRoot: REPO_ROOT,
          spendingKey: p.spendingKey,
          ownerCommitmentBlinding: p.ownerBlinding,
          innerHash: note.innerHash,
          tokenMint: note.mint.toBytes(),
          amount: note.amount,
          merkleRootBE: w.root,
          merkleWitness: { pathElements: w.siblings.map(be32ToBigInt), pathIndices: w.indices },
        });
        return { proofBytes: new Uint8Array([...vi.proof.piA, ...vi.proof.piB, ...vi.proof.piC]), root: w.root };
      }

      const slot = await conn.getSlot("confirmed");
      const expirySlot = BigInt(slot + 50_000);
      async function buildOrder(p: Persona, side: OrderSide, priceLimit: bigint, note: Note, orderIndex: number, qty: bigint) {
        const orderId = deriveOrderId(p.masterSeed, orderIndex);
        const pool = await buildAnchorPool(p.masterSeed, p.spendingKey, orderId);
        const vi = await viProof(p, note);
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
          collateral_amount: Number(note.amount),
          anchors: anchorsToJson(pool.anchors),
        };
      }

      // Build every order (snarkjs proofs — the slow part, done up front).
      const orderN = Date.now() % 1_000_000;
      const orders: object[] = [];
      for (let i = 0; i < MATCHES; i++) {
        orders.push(await buildOrder(buyer, OrderSide.Bid, bidPrice, buyerNotes[i], orderN + i, qtys[i]));
        orders.push(await buildOrder(seller, OrderSide.Ask, askPrice, sellerNotes[i], orderN + 1000 + i, qtys[i]));
      }

      const tokRes = await gwFetch(`${GATEWAY}/auth/token`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ api_key: API_KEY, api_secret: API_SECRET, passphrase: PASSPHRASE }),
      });
      expect(tokRes.status).toBe(200);
      const token = ((await tokRes.json()) as { access_token: string }).access_token;

      // Submit ALL orders as fast as possible (concurrently) so they land in the
      // same matcher tick → ideally one batch of M (or a few — both are useful:
      // a multi-match batch shows the per-Tx-D loop; multiple batches show #4's
      // pipelining).
      const submitStart = Date.now();
      const statuses = await Promise.all(
        orders.map((o) =>
          gwFetch(`${GATEWAY}/orders`, {
            method: "POST",
            headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
            body: JSON.stringify(o),
          }).then(async (r) => {
            if (!String(r.status).startsWith("2")) console.log(`  !! /orders ${r.status}: ${(await r.text()).slice(0, 200)}`);
            return r.status;
          }),
        ),
      );
      const accepted = statuses.filter((s) => String(s).startsWith("2")).length;
      console.log(`  · submitted ${orders.length} orders in ${Date.now() - submitStart}ms — ${accepted} accepted (2xx)`);
      expect(accepted, "some orders rejected").toBe(orders.length);

      // Each match appends ≥ note_c + note_d (2 leaves); wait for all M.
      const wantLeaves = depositCount + 2 * MATCHES;
      const settleStart = Date.now();
      let finalCount = depositCount;
      const deadline = Date.now() + SETTLE_TIMEOUT_MS;
      while (Date.now() < deadline) {
        finalCount = await totalLeafCount(conn, vaultProgramId, NUM_TREES);
        if (finalCount >= wantLeaves) break;
        await new Promise((r) => setTimeout(r, 2000));
      }
      const settleWallMs = Date.now() - settleStart;
      console.log(
        `  · leaf_count ${depositCount} → ${finalCount} (wanted ≥${wantLeaves}) in ${settleWallMs}ms wall ` +
          `→ ~${((finalCount - depositCount) / 2 / (settleWallMs / 1000)).toFixed(2)} matches/s end-to-end`,
      );
      console.log(`  · READ PER-Tx-D + per-stage timing: phala cvms logs <cvm> | grep -E "settle Tx D confirmed|settle pipeline timing"`);
      expect(finalCount, "not all matches settled — check CVM logs for the failing stage").toBeGreaterThanOrEqual(wantLeaves);
    },
    600_000,
  );
});
