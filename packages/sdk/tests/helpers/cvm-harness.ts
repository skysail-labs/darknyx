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

import type { NodeWebSocketLike } from "../../src/tee/transport-ws.node.js";
import type { SendableWebSocketLike } from "../../src/orders/trading-ws-client.js";
import { TransportVerificationError } from "../../src/tee/verify-transport.js";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { TOKEN_PROGRAM_ID } from "./e2e-helpers.js";
import {
  Connection,
  ComputeBudgetProgram,
  Keypair,
  PublicKey,
  Transaction,
  TransactionExpiredBlockheightExceededError,
  sendAndConfirmTransaction,
} from "@solana/web3.js";

import {
  deriveSpendingKey,
  deriveBlindingFactor,
  deriveNoteSecret,
  bn254ToBE32,
} from "../../src/keys/key-generators.js";
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
import { fetchPythCorePushPrice } from "../../src/oracle/pyth-push.js";

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
export const API_KEY = cvmCredential(
  "DARKNYX_TEE_API_KEY",
  "darknyx-test-api-key",
);
export const API_SECRET = cvmCredential(
  "DARKNYX_TEE_API_SECRET",
  "darknyx-test-secret",
);
export const PASSPHRASE = cvmCredential(
  "DARKNYX_TEE_PASSPHRASE",
  "darknyx-test-passphrase",
);

/** Protocol fee bps — MUST match the CVM's DARKNYX_TEE_FEE_RATE_BPS (default 30). */
export const FEE_RATE_BPS = BigInt(
  process.env.DARKNYX_CVM_FEE_RATE_BPS ?? "30",
);

export async function landedSignatureAfterBlockheightExpiry(
  connection: Pick<Connection, "getSignatureStatuses">,
  error: unknown,
): Promise<string | undefined> {
  if (!(error instanceof TransactionExpiredBlockheightExceededError)) {
    return undefined;
  }
  const response = await connection.getSignatureStatuses([error.signature], {
    searchTransactionHistory: true,
  });
  const status = response.value[0];
  if (!status) return undefined;
  if (status.err) {
    throw new Error(
      `expired transaction ${error.signature} landed with an error`,
    );
  }
  return error.signature;
}

/** Per-run salt so persona seed-derived commitments are fresh each run — a
 * fixed seed can reproduce a deposited/consumed-note PDA on a second run,
 * because reset_merkle_tree clears roots but not those replay guards. */
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

/** Round a positive test price down to the finalized market tick. Live oracle
 *  prices are not guaranteed to be tick-aligned, while production intake now
 *  rejects every off-tick nonzero limit (U-08). */
export const floorPriceToTick = (price: bigint, tickSize: bigint): bigint => {
  if (price <= 0n) throw new Error("price must be positive");
  if (tickSize <= 0n) throw new Error("tickSize must be positive");
  const aligned = price - (price % tickSize);
  if (aligned === 0n) throw new Error("tickSize exceeds the positive price");
  return aligned;
};

/**
 * The transport every `cvm-*` suite uses (T-03P).
 *
 * `DARKNYX_CVM_TRANSPORT=ra-tls` routes through the verified transport: the
 * enclave's certificate is checked against a quote-bound manifest on the socket
 * carrying each request. Anything else is the legacy gateway-terminated path.
 *
 * This is the single conversion point for all six suites — they all reach the
 * CVM through `gwFetch` — which is why the cutover is one edit here rather than
 * six.
 *
 * Built lazily and once: establishing the transport costs a TDX quote
 * (~1.5 s), and a per-request rebuild would both slow the suite and defeat the
 * point of pinning one verified connection.
 *
 * Cached only on SUCCESS. Caching a rejected promise would poison the transport
 * for the rest of the process — a transient failure during CVM restart would
 * become permanent, and in tests each case would inherit the first case's
 * error rather than producing its own.
 */
let verifiedFetch: Promise<typeof fetch> | undefined;
/**
 * SPKI established by the transport verification, needed to gate the
 * WebSocket upgrade. Kept beside the fetch because both must describe the SAME
 * boot session: a socket verified under a previous boot is exactly what
 * `boot_session_mismatch` exists to reject.
 */
let verifiedSpki: Uint8Array | undefined;

function ratlsRequested(): boolean {
  return process.env.DARKNYX_CVM_TRANSPORT === "ra-tls";
}

async function getTransport(): Promise<typeof fetch> {
  verifiedFetch ??= (async () => {
    const compose = process.env.DARKNYX_EXPECT_COMPOSE_HASH?.trim();
    const signers = process.env.DARKNYX_EXPECT_SIGNER_SET?.trim();
    const gateway = process.env.DARKNYX_TEE_GATEWAY?.trim();
    // Fail loudly rather than falling back. A cvm suite that silently ran over
    // the legacy path while the operator believed it was testing ra-tls would
    // report a green cutover that never happened.
    if (!gateway) throw new Error("DARKNYX_TEE_GATEWAY is required");
    if (!compose || !signers) {
      throw new Error(
        "DARKNYX_CVM_TRANSPORT=ra-tls requires DARKNYX_EXPECT_COMPOSE_HASH and " +
          "DARKNYX_EXPECT_SIGNER_SET; without them a verified transport proves " +
          "a channel to some enclave, not the governed one",
      );
    }
    const { TransportAgent, createVerifiedFetch } =
      await import("../../src/tee/transport-agent.node.js");
    const { parseEventLog } = await import("../../src/tee/verify-core.js");
    const { createDcapQuoteVerifier } = await import("../../src/tee/dcap.js");
    const { randomBytes } = await import("node:crypto");
    const dcap = createDcapQuoteVerifier({});
    const agent = new TransportAgent();
    const { verifyTransportOnSocket } =
      await import("../../src/tee/transport-agent.node.js");
    const verifyDeps = {
      verifyQuote: (quoteHex: string) =>
        dcap(
          Uint8Array.from(
            quoteHex.match(/../g)?.map((b) => parseInt(b, 16)) ?? [],
          ),
        ),
      parseEventLog,
      randomNonce: () => new Uint8Array(randomBytes(32)),
    };
    const expectedSignerSet = Uint8Array.from(
      signers.match(/../g)!.map((b) => parseInt(b, 16)),
    );
    // Verify once up front so the SPKI is available to the WebSocket gate.
    // Without this the stream would open unchecked while HTTP was verified —
    // the partial mode that is worse than no protection, because the operator
    // and the logs would both say "verified".
    const established = await verifyTransportOnSocket({
      baseUrl: gateway,
      agent,
      deps: verifyDeps,
      expectedComposeHash: compose,
      expectedSignerSetSha256: expectedSignerSet,
    });
    verifiedSpki = established.spkiSha256;
    return createVerifiedFetch({
      baseUrl: gateway,
      agent,
      deps: verifyDeps,
      expectedComposeHash: compose,
      expectedSignerSetSha256: expectedSignerSet,
    });
  })().catch((e: unknown) => {
    verifiedFetch = undefined; // do not cache a failure
    verifiedSpki = undefined;
    throw e;
  });
  return verifiedFetch;
}

/**
 * Open a WebSocket to the CVM, gated the same way `gwFetch` is.
 *
 * Under `ra-tls` this checks the upgrade socket's certificate against the SPKI
 * established during transport verification, and discards queued frames if it
 * does not match — so no credential is ever written to an unverified stream.
 * Under the legacy path it is a plain `ws` connection, unchanged.
 *
 * The returned object exposes the `ws` event API (`on`) that the cvm suites
 * already use, so converting a test is a one-line substitution rather than a
 * rewrite of its event handling.
 */
export async function gwWebSocket(url: string): Promise<SendableWebSocketLike> {
  const { default: WS } = await import("ws");
  if (!ratlsRequested()) return new WS(url) as unknown as SendableWebSocketLike;

  // Ensure verification has run; this is what populates `verifiedSpki`.
  await getTransport();
  if (!verifiedSpki) {
    throw new Error(
      "ra-tls requested but no verified SPKI is available — refusing to open " +
        "an ungated stream",
    );
  }
  const { createVerifiedWebSocketFactory } =
    await import("../../src/tee/transport-ws.node.js");
  return createVerifiedWebSocketFactory({
    verifiedSpkiSha256: verifiedSpki,
    // `rejectUnauthorized: false` is safe ONLY because the SPKI gate below is
    // what actually authenticates the peer: Node's CA check cannot validate an
    // enclave-generated boot-scoped certificate, and the quote-bound SPKI is a
    // strictly stronger check than any CA chain would be. It is not a
    // "make TLS pass" shortcut — with the gate removed, this line alone would
    // accept any certificate from anyone.
    createSocket: (u: string) =>
      new WS(u, { rejectUnauthorized: false }) as unknown as NodeWebSocketLike,
    onViolation: (e) => {
      // Loud: a rejected upgrade under ra-tls is the exact event this whole
      // remediation exists to make visible.
      console.error(`[cvm-harness] WebSocket transport violation: ${e.kind}`);
    },
  })(url);
}

/** fetch with retries — the dstack gateway can transiently close the socket
 *  (UND_ERR_SOCKET) for the first minute after a CVM restart. */
/**
 * The transport a consumer should be given when it takes its own `fetchImpl`.
 *
 * Same selection as {@link gwFetch}: the verified transport under `ra-tls`,
 * plain fetch otherwise. Exposed because SDK entry points such as
 * `verifyTeeAttestation` do their own fetching, and handing them the global
 * one would leave those calls on an unverified connection while the rest of
 * the suite is verified.
 */
export async function gwTransportFetch(): Promise<typeof fetch> {
  return ratlsRequested() ? await getTransport() : fetch;
}

export async function gwFetch(
  url: string,
  init?: RequestInit,
  tries = 6,
): Promise<Response> {
  const f = ratlsRequested() ? await getTransport() : fetch;
  let last: unknown;
  for (let i = 0; i < tries; i++) {
    try {
      return await f(url, init);
    } catch (e) {
      // NEVER retry a security rejection. The loop exists for UND_ERR_SOCKET
      // while a CVM restarts; a `spki_mismatch` or `signer_set_mismatch` is a
      // verdict, not a transient. Retrying one burns six verification
      // exchanges and — worse — reports the failure as a timeout after ~18s
      // instead of naming the peer that failed its check.
      if (e instanceof TransportVerificationError) throw e;
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
    throw new Error(
      `/info returned ${response.status}: ${await response.text()}`,
    );
  }
  const body = (await response.json()) as { boot_session_id?: string };
  if (!body.boot_session_id?.match(/^[0-9a-f]{64}$/i)) {
    throw new Error("/info boot_session_id must be 32-byte hex");
  }
  return Uint8Array.from(Buffer.from(body.boot_session_id, "hex"));
}

/** Fetch the finalized upgraded Pyth Core push EMA the CVM uses in dev mode. */
export async function fetchOracleAnchorForFeed(
  feedId: string,
): Promise<bigint> {
  if (process.env.DARKNYX_CVM_PRICE)
    return BigInt(process.env.DARKNYX_CVM_PRICE);
  const rpc = process.env.SOLANA_RPC_URL?.trim();
  if (!rpc) throw new Error("SOLANA_RPC_URL is required for Pyth push prices");
  const price = await fetchPythCorePushPrice(
    new Connection(rpc, "finalized"),
    feedId,
  );
  const raw = price.emaPrice;
  console.log(
    `  · oracle anchor (finalized Pyth push EMA): ${raw} (expo ${price.exponent}, age ${Date.now() - Number(price.publishTime * 1000n)} ms)`,
  );
  return raw;
}

/** Fetch the live raw SOL/USD EMA integer the CVM's oracle uses. */
export async function fetchOracleAnchor(): Promise<bigint> {
  return fetchOracleAnchorForFeed(SOL_USD_FEED);
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
  ownerCommit: bigint;
}

export async function makePersona(
  repoRoot: string,
  name: string,
  seed0: number,
): Promise<Persona> {
  const payer = await loadOrCreateKeypair(
    resolve(repoRoot, `.devnet/keypairs/${name}-payer.json`),
  );
  const trading = await loadOrCreateKeypair(
    resolve(repoRoot, `.devnet/keypairs/${name}-trading.json`),
  );
  const masterSeed = new Uint8Array(64);
  for (let i = 0; i < 64; i++) {
    masterSeed[i] =
      (seed0 + i * 7 + Number((RUN_SALT >> BigInt(i % 53)) & 0xffn)) & 0xff;
  }
  const spendingKey = deriveSpendingKey(masterSeed);
  const ownerCommit = await ownerCommitment(spendingKey);
  // A `userCommitment` used to live here, zeroed in its top byte to satisfy an
  // intake check that audit 2026-07-25 (T-07) found both wrong and guarding
  // nothing. `ownerCommit` is the identity intake actually verifies.
  return {
    name,
    payer,
    trading,
    masterSeed,
    spendingKey,
    ownerCommit,
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

export interface MerkleLeafPage {
  leaves: Array<{ leafIndex: number; value: Uint8Array }>;
  merkleRoot: Uint8Array;
}

export type MerkleLeafPageLoader = (
  treeId: number,
  from: number,
  to: number,
) => Promise<MerkleLeafPage>;

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

  /**
   * Rebuild every test shadow from an already-running CVM mirror.
   *
   * Normal leaf-count suites intentionally start from an empty reset. The fee
   * epoch drill is different: epoch-B settlement must preserve epoch-A leaves
   * so the old fee notes remain spendable. After the required cold boot this
   * loader pages the authenticated `/tree/leaves` surface, checks that every
   * shard is contiguous, and verifies the locally replayed root before any new
   * deposit or VALID_INPUT proof is attempted.
   */
  static async createHydrated(
    conn: Connection,
    vaultProgramId: PublicKey,
    numTrees: number,
    loadPage: MerkleLeafPageLoader,
  ): Promise<CvmHarness> {
    const harness = await CvmHarness.create(conn, vaultProgramId, numTrees);
    const pageSize = 10_000;
    let onchainCount = 0;

    for (let treeId = 0; treeId < harness.numTrees; treeId++) {
      let from = 0;
      let advertisedRoot: Uint8Array | undefined;
      for (;;) {
        const page = await loadPage(treeId, from, from + pageSize);
        if (page.merkleRoot.length !== 32) {
          throw new Error(`tree ${treeId} returned a malformed Merkle root`);
        }
        if (
          advertisedRoot &&
          !Buffer.from(advertisedRoot).equals(Buffer.from(page.merkleRoot))
        ) {
          throw new Error(`tree ${treeId} changed while its leaves were paged`);
        }
        advertisedRoot = page.merkleRoot;

        for (const leaf of page.leaves) {
          if (leaf.leafIndex !== from || leaf.value.length !== 32) {
            throw new Error(
              `tree ${treeId} returned a non-contiguous or malformed leaf at ${from}`,
            );
          }
          await harness.shadows[treeId].append(leaf.value);
          from += 1;
        }
        if (page.leaves.length < pageSize) break;
      }

      if (!advertisedRoot) {
        throw new Error(`tree ${treeId} returned no Merkle-root snapshot`);
      }
      const replayedRoot = await harness.shadows[treeId].computeRoot();
      if (!Buffer.from(replayedRoot).equals(Buffer.from(advertisedRoot))) {
        throw new Error(`tree ${treeId} replay root disagrees with the CVM`);
      }

      const [treePda] = await merkleTreePda(vaultProgramId, treeId);
      const info = await conn.getAccountInfo(treePda);
      if (!info) {
        throw new Error(
          `MerkleTree shard ${treeId} missing — run devnet-setup`,
        );
      }
      if (info.data.length < 48) {
        throw new Error(`MerkleTree shard ${treeId} account is truncated`);
      }
      const currentRoot = info.data.subarray(16, 48);
      if (!Buffer.from(replayedRoot).equals(Buffer.from(currentRoot))) {
        throw new Error(
          `tree ${treeId} replay root disagrees with on-chain current_root`,
        );
      }
      onchainCount += Number(
        new DataView(
          info.data.buffer,
          info.data.byteOffset + 8,
          8,
        ).getBigUint64(0, true),
      );
    }

    const mirroredCount = harness.shadows.reduce(
      (sum, shadow) => sum + shadow.leafCount,
      0,
    );
    if (mirroredCount !== onchainCount) {
      throw new Error(
        `hydrated ${mirroredCount} leaves but on-chain shards report ${onchainCount}`,
      );
    }
    return harness;
  }

  /** Total on-chain leaf count summed across the K `MerkleTree` shards
   *  (`leaf_count: u64` @ offset 8, after the 8-byte Anchor disc). */
  async leafCount(): Promise<number> {
    let total = 0;
    for (let treeId = 0; treeId < this.numTrees; treeId++) {
      const [pda] = await merkleTreePda(this.vaultProgramId, treeId);
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
    const recoveryNonceBytes = bn254ToBE32(recoveryNonce);
    const innerHash = be32ToBigInt(
      await deriveDepositInnerHash(
        recoveryNonceBytes,
        bn254ToBE32(deriveNoteSecret(p.masterSeed, recoveryNonceBytes)),
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
      noteSecret: deriveNoteSecret(p.masterSeed, recoveryNonceBytes),
    });
    const ix = await buildDepositInstruction({
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
    let sig: string | undefined;
    for (let attempt = 1; attempt <= 3; attempt += 1) {
      try {
        // Rebuild the Transaction on every attempt. web3.js mutates it with a
        // recent blockhash and signatures, so reusing the same instance would
        // merely resend the stale blockhash that triggered the retry.
        sig = await sendAndConfirmTransaction(
          this.conn,
          new Transaction().add(
            ComputeBudgetProgram.setComputeUnitLimit({ units: 300_000 }),
            ix,
          ),
          [p.payer],
        );
        break;
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        const landed = await landedSignatureAfterBlockheightExpiry(
          this.conn,
          error,
        );
        if (landed) {
          sig = landed;
          break;
        }
        const retryable =
          error instanceof TransactionExpiredBlockheightExceededError ||
          message.includes("Blockhash not found");
        if (!retryable || attempt === 3) {
          throw error;
        }
        console.warn(
          `  · deposit blockhash expired before landing; retrying with a fresh transaction (${attempt}/3)`,
        );
      }
    }
    if (!sig) throw new Error("deposit exhausted blockhash retries");
    const recovered = await readNoteCreated(
      this.conn,
      sig,
      this.vaultProgramId,
    );
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
