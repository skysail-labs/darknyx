/**
 * Shared scaffolding for the CVM (`cvm-*`) e2e tests — extracted from
 * `cvm-settle-e2e.test.ts` so `cvm-settle-e2e`, `cvm-multimatch-settle`,
 * `cvm-merge-then-order`, and `cvm-api-surface` all drive the live enclave the
 * same way (and so the shard-aware deposit/witness logic lives in ONE place).
 *
 * Tree-sharding model (the load-bearing invariant these helpers encode):
 *   - A deposit is CALLER-ROUTED: the depositor picks the shard by passing the
 *     `merkle_tree[treeId]` PDA + `tree_id` byte (vault `deposit.rs`). The
 *     program appends the leaf to THAT shard. We read the actual
 *     `(tree_id, leaf_index)` back from the `NoteCreated` event and mirror into
 *     a per-shard `MerkleShadow`, so a VALID_INPUT witness is always built
 *     against the shard the note actually landed in.
 *   - Settle OUTPUTS round-robin across all K shards, so the pool's leaf count
 *     is the SUM across shards (`leafCount()`).
 *
 * Secrets/gateway come from env (loaded by `tests/setup-env.ts` from `.env`).
 */

import { resolve } from "node:path";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { TOKEN_PROGRAM_ID } from "@solana/spl-token";
import {
  Connection,
  ComputeBudgetProgram,
  Keypair,
  PublicKey,
  Transaction,
  sendAndConfirmTransaction,
} from "@solana/web3.js";

import {
  deriveSpendingKey,
  deriveMasterViewingKey,
  deriveBlindingFactor,
  bn254ToBE32,
} from "../../src/keys/key-generators.js";
import { userCommitmentFromKeys } from "../../src/keys/user-commitment.js";
import {
  ownerCommitment,
  noteCommitmentV2,
  pubkeyToFrPair,
} from "../../src/utxo/note.js";
import {
  merkleTreePda,
  buildDepositInstruction,
} from "../../src/idl/vault-client.js";
import { readNoteCreated } from "../../src/utxo/leaf-index.js";
import { MerkleShadow } from "./merkle-shadow.js";
import { proveValidInput } from "./valid-input-prover.js";
import { be32ToBigInt, loadOrCreateKeypair } from "./e2e-helpers.js";
import { deriveDepositInnerHash } from "../../src/utxo/deposit-inner.js";
import { nodeValidDepositProver } from "../../src/zk/valid-deposit-prover.js";

const REPO_ROOT = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../../../..",
);
const DEPOSIT_PROVER = nodeValidDepositProver({
  wasmPath: resolve(
    REPO_ROOT,
    "circuits/build/valid_deposit/circuit_js/circuit.wasm",
  ),
  zkeyPath: resolve(
    REPO_ROOT,
    "circuits/build/valid_deposit/circuit_final.zkey",
  ),
});

// ── Market + auth constants (match encrypted deploy env + e2e-config) ──
export const SYMBOL = "SOL-USDC";
export const SOL_USD_FEED =
  "ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d";
function cvmCredential(name: string, localFixture: string): string {
  const value = process.env[name];
  if (process.env.RUN_CVM_E2E === "1" && !value) {
    throw new Error(
      `${name} is required for live CVM tests; load the encrypted-deploy credentials`,
    );
  }
  return value ?? localFixture;
}

/** Live CVM credentials are generated per test window and injected through the
 * encrypted deploy env. Public fixture defaults remain only for non-live local
 * simulator tests. See docs/cvm-run-runbook.md. */
export const API_KEY = cvmCredential("DARKNYX_TEE_API_KEY", "darknyx-test-api-key");
export const API_SECRET = cvmCredential(
  "DARKNYX_TEE_API_SECRET",
  "darknyx-test-secret",
);
export const PASSPHRASE = cvmCredential(
  "DARKNYX_TEE_PASSPHRASE",
  "darknyx-test-passphrase",
);

/** Protocol fee bps — MUST match the CVM's DARKNYX_TEE_FEE_RATE_BPS (default 30). */
export const FEE_RATE_BPS = BigInt(process.env.DARKNYX_CVM_FEE_RATE_BPS ?? "30");

/** Per-run salt so persona seed-derived keys (and the amount-independent v2
 *  nullifiers) are fresh each run — a fixed seed would collide the settle's
 *  NullifierEntry PDA ("Allocate: account already in use") on a 2nd run since
 *  reset_merkle_tree clears the tree but NOT those PDAs. */
export const RUN_SALT = BigInt(
  process.env.DARKNYX_CVM_RUN_SALT ?? String(Date.now()),
);

export const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");

/** Each side locks NOMINAL + its OWN protocol fee (floored), matching intake's
 *  `orders.rs` derivation so the re-derived commitment lines up. */
export const withFee = (nominal: bigint): bigint =>
  nominal + (nominal * FEE_RATE_BPS) / 10_000n;

/** Governed fixed-point quote conversion used by matcher, intake, and circuit. */
export const scaledQuote = (
  baseAmount: bigint,
  price: bigint,
  priceScale: bigint,
): bigint => {
  if (priceScale <= 0n) throw new Error("priceScale must be positive");
  return (baseAmount * price) / priceScale;
};

/** fetch with retries — the dstack gateway can transiently close the socket
 *  (UND_ERR_SOCKET) for the first minute after a CVM restart. */
export async function gwFetch(
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

/** Fetch and validate the fresh 32-byte process-boot session that every order
 * signature must bind. A CVM restart intentionally invalidates old bodies. */
export async function fetchBootSessionId(gateway: string): Promise<Uint8Array> {
  const response = await gwFetch(`${gateway.replace(/\/$/, "")}/info`);
  if (!response.ok) {
    throw new Error(`/info returned ${response.status}: ${await response.text()}`);
  }
  const body = (await response.json()) as { boot_session_id?: string };
  if (!body.boot_session_id?.match(/^[0-9a-f]{64}$/i)) {
    throw new Error("/info boot_session_id must be 32-byte hex");
  }
  return Uint8Array.from(Buffer.from(body.boot_session_id, "hex"));
}

/** Fetch the live raw SOL/USD price integer the CVM's oracle uses. */
export async function fetchOracleAnchor(): Promise<bigint> {
  if (process.env.DARKNYX_CVM_PRICE) return BigInt(process.env.DARKNYX_CVM_PRICE);
  const url = `https://hermes.pyth.network/v2/updates/price/latest?ids[]=${SOL_USD_FEED}`;
  const j = (await (await fetch(url)).json()) as {
    parsed?: { price: { price: string; expo: number } }[];
  };
  if (!j.parsed || j.parsed.length === 0) {
    throw new Error(`Hermes returned no price data for ${SOL_USD_FEED}`);
  }
  const raw = BigInt(j.parsed[0].price.price);
  console.log(
    `  · oracle anchor (raw SOL/USD): ${raw} (expo ${j.parsed[0].price.expo})`,
  );
  return raw;
}

/** Acquire a bearer token from the CVM's bootstrap admin creds. */
export async function authToken(gateway: string): Promise<string> {
  const res = await gwFetch(`${gateway}/auth/token`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      api_key: API_KEY,
      api_secret: API_SECRET,
      passphrase: PASSPHRASE,
    }),
  });
  if (res.status !== 200) {
    throw new Error(`auth/token failed (${res.status}): ${await res.text()}`);
  }
  const body = (await res.json()) as { access_token?: unknown };
  if (typeof body.access_token !== "string") {
    throw new Error(
      `auth/token: response missing access_token: ${JSON.stringify(body)}`,
    );
  }
  return body.access_token;
}

export interface Persona {
  name: string;
  payer: Keypair;
  trading: Keypair; // Ed25519 key that signs the order body
  masterSeed: Uint8Array;
  spendingKey: bigint;
  ownerBlinding: bigint;
  ownerCommit: bigint;
  userCommitment: Uint8Array; // 32B BE
}

export async function makePersona(
  repoRoot: string,
  name: string,
  seed0: number,
): Promise<Persona> {
  const payer = loadOrCreateKeypair(
    resolve(repoRoot, `.devnet/keypairs/${name}-payer.json`),
  );
  const trading = loadOrCreateKeypair(
    resolve(repoRoot, `.devnet/keypairs/${name}-trading.json`),
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
  // Intake requires the top byte to be exactly 0 (it Poseidon-hashes this when
  // constructing change notes). Zero it to pass the stricter intake check.
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

/** A deposited note: its opening + the shard/position the program appended it
 *  at (both needed for the per-shard VALID_INPUT witness). */
export interface DepositedNote {
  mint: PublicKey;
  amount: bigint;
  innerHash: bigint;
  commitment: Uint8Array;
  treeId: number;
  leafIndex: number;
}

/**
 * Shard-aware deposit + witness harness. One `MerkleShadow` per shard; each
 * deposit recovers its real `(tree_id, leaf_index)` from the NoteCreated event
 * and appends to that shard's shadow, so `viProof` witnesses against the right
 * tree regardless of how deposits are routed.
 */
export class CvmHarness {
  private constructor(
    private readonly conn: Connection,
    private readonly vaultProgramId: PublicKey,
    readonly numTrees: number,
    readonly shadows: MerkleShadow[],
  ) {}

  static async create(
    conn: Connection,
    vaultProgramId: PublicKey,
    numTrees: number,
  ): Promise<CvmHarness> {
    const k = Math.max(1, numTrees);
    const shadows = await Promise.all(
      Array.from({ length: k }, () => MerkleShadow.create()),
    );
    return new CvmHarness(conn, vaultProgramId, k, shadows);
  }

  /** Total on-chain leaf count summed across the K `MerkleTree` shards
   *  (`leaf_count: u64` @ offset 8, after the 8-byte Anchor disc). */
  async leafCount(): Promise<number> {
    let total = 0;
    for (let treeId = 0; treeId < this.numTrees; treeId++) {
      const [pda] = merkleTreePda(this.vaultProgramId, treeId);
      const info = await this.conn.getAccountInfo(pda);
      if (!info)
        throw new Error(
          `MerkleTree shard ${treeId} missing — run devnet-setup`,
        );
      total += Number(
        new DataView(
          info.data.buffer,
          info.data.byteOffset + 8,
          8,
        ).getBigUint64(0, true),
      );
    }
    return total;
  }

  /** Deposit one note into shard `treeId` (default 0), mirror into that shard's
   *  shadow, and return the opening + recovered `(treeId, leafIndex)`. */
  async deposit(
    p: Persona,
    mint: PublicKey,
    ata: PublicKey,
    amount: bigint,
    treeId = 0,
  ): Promise<DepositedNote> {
    // The public nonce is deterministic and pseudorandom; the hidden inner is
    // derived from it plus the hidden owner commitment inside VALID_DEPOSIT.
    const nonceIndex = await this.leafCount();
    const recoveryNonce = deriveBlindingFactor(
      p.masterSeed,
      BigInt(nonceIndex),
    );
    const innerHash = be32ToBigInt(
      await deriveDepositInnerHash(
        bn254ToBE32(p.ownerCommit),
        bn254ToBE32(recoveryNonce),
      ),
    );
    const commitment = await noteCommitmentV2({
      tokenMint: mint.toBytes(),
      amount,
      ownerCommitment: p.ownerCommit,
      innerHash,
    });
    const [mintLo, mintHi] = pubkeyToFrPair(mint.toBytes());
    const proof = await DEPOSIT_PROVER.prove({
      noteCommitment: be32ToBigInt(commitment),
      tokenMint: [mintLo, mintHi],
      amount,
      recoveryNonce,
      spendingKey: p.spendingKey,
      ownerCommitmentBlinding: p.ownerBlinding,
    });
    const ix = buildDepositInstruction({
      programId: this.vaultProgramId,
      treeId,
      depositor: p.payer.publicKey,
      tokenMint: mint,
      depositorTokenAccount: ata,
      tokenProgramId: TOKEN_PROGRAM_ID,
      amount,
      noteCommitment: commitment,
      recoveryNonce: bn254ToBE32(recoveryNonce),
      proof,
    });
    const sig = await sendAndConfirmTransaction(
      this.conn,
      new Transaction().add(
        ComputeBudgetProgram.setComputeUnitLimit({ units: 300_000 }),
        ix,
      ),
      [p.payer],
    );
    const recovered = await readNoteCreated(this.conn, sig);
    await this.shadows[recovered.treeId].append(commitment);
    console.log(
      `  · ${p.name} deposited shard ${recovered.treeId} leaf ${recovered.leafIndex} (${sig.slice(0, 8)}…)`,
    );
    return {
      mint,
      amount,
      innerHash,
      commitment,
      treeId: recovered.treeId,
      leafIndex: Number(recovered.leafIndex),
    };
  }

  /** Build a VALID_INPUT proof for `note`, witnessing against the shard it
   *  landed in (its shadow root must equal that shard's on-chain current_root
   *  at lock time). */
  async viProof(
    repoRoot: string,
    p: Persona,
    note: DepositedNote,
  ): Promise<{ proofBytes: Uint8Array; root: Uint8Array }> {
    const w = await this.shadows[note.treeId].witness(note.leafIndex);
    const vi = await proveValidInput({
      repoRoot,
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
    return {
      proofBytes: new Uint8Array([
        ...vi.proof.piA,
        ...vi.proof.piB,
        ...vi.proof.piC,
      ]),
      root: w.root,
    };
  }
}
