#!/usr/bin/env node
/**
 * darknyx-daemon entrypoint.
 *
 * Loads config + the encrypted keystore, builds the in-process VALID_INPUT
 * prover, wires the Daemon, and serves the local control API. Keys + proving
 * stay on this host.
 *
 *   DARKNYX_DAEMON_GATEWAY_URL=https://<app>-8080.dstack-…  \
 *   DARKNYX_DAEMON_TOKEN=<jwt>  DARKNYX_DAEMON_RPC_URL=$HELIUS   \
 *   DARKNYX_DAEMON_API_KEY=<key> DARKNYX_DAEMON_API_SECRET=<secret> \
 *   DARKNYX_DAEMON_API_PASSPHRASE=<passphrase>               \
 *   DARKNYX_DAEMON_KEYSTORE=./darknyx-keystore.json             \
 *   # one-time recovery only: DARKNYX_DAEMON_SEQUENCE_INIT=<next-index> \
 *   DARKNYX_DAEMON_KEYSTORE_PASSPHRASE=<passphrase>         \
 *   DARKNYX_DAEMON_VI_WASM=circuits/build/valid_input/circuit_js/circuit.wasm \
 *   DARKNYX_DAEMON_VI_ZKEY=circuits/build/valid_input/circuit_final.zkey      \
 *   node dist/bin/daemon.js
 */

import { chmodSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { resolve } from "node:path";
import { Keypair, PublicKey } from "@solana/web3.js";
import {
  nodeValidInputProver,
  getDepositFunction,
  getMergeFunction,
  limitPolicy,
  OrderSide,
  createDcapQuoteVerifier,
} from "@darknyx/sdk";

import { loadConfig } from "../src/config.js";
import { DaemonStore } from "../src/store.js";
import { loadKeystore } from "../src/keystore.js";
import { DurableOrderSequence } from "../src/order-sequence.js";
import { createDaemonClient } from "../src/daemon-client.js";
import { createMergeClient } from "../src/merge-client.js";
import { httpLeavesFetcher } from "../src/tree-merkle-provider.js";
import { createMergeRunner } from "../src/merge-runner.js";
import { Daemon } from "../src/daemon.js";
import {
  startControlServer,
  type PlaceMapper,
  type DepositMapper,
} from "../src/control-api.js";

function required(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is required`);
  return v;
}

/** Build the stream's short-lived-token refresh callback when long-lived API
 * credentials are supplied. Credentials are all-or-none and never logged. */
function streamTokenProvider(
  gatewayUrl: string,
): (() => Promise<string>) | undefined {
  const apiKey = process.env.DARKNYX_DAEMON_API_KEY;
  const apiSecret = process.env.DARKNYX_DAEMON_API_SECRET;
  const passphrase = process.env.DARKNYX_DAEMON_API_PASSPHRASE;
  const supplied = [apiKey, apiSecret, passphrase].filter(Boolean).length;
  if (supplied === 0) return undefined;
  if (supplied !== 3) {
    throw new Error(
      "DARKNYX_DAEMON_API_KEY, DARKNYX_DAEMON_API_SECRET, and DARKNYX_DAEMON_API_PASSPHRASE must be supplied together",
    );
  }
  return async () => {
    const response = await fetch(
      `${gatewayUrl.replace(/\/$/, "")}/auth/token`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          api_key: apiKey,
          api_secret: apiSecret,
          passphrase,
        }),
      },
    );
    if (!response.ok) {
      throw new Error(
        `stream token refresh failed with HTTP ${response.status}`,
      );
    }
    const body = (await response.json()) as { access_token?: unknown };
    if (
      typeof body.access_token !== "string" ||
      body.access_token.length === 0
    ) {
      throw new Error("stream token refresh returned no access_token");
    }
    return body.access_token;
  };
}

/** Load a Solana keypair from a `solana-keygen` JSON file (array of bytes). */
function loadKeypair(path: string): Keypair {
  const bytes = JSON.parse(readFileSync(path, "utf8")) as number[];
  return Keypair.fromSecretKey(Uint8Array.from(bytes));
}

/**
 * The control-plane bearer token (SW-19).
 *
 * Required, never optional: this surface places orders and moves funds, and a
 * default-insecure local server is reachable from any page the operator's
 * browser visits. When `DARKNYX_DAEMON_CONTROL_TOKEN` is unset we generate one
 * and persist it `0600` beside the database, then print the path — the pattern
 * Jupyter and similar local servers use. A cross-origin page cannot read that
 * file, which is what defeats DNS rebinding as well as CSRF.
 *
 * Persisted rather than regenerated per boot so a strategy process does not
 * have to be restarted alongside the daemon.
 */
function resolveControlToken(dbPath: string): string {
  const fromEnv = process.env.DARKNYX_DAEMON_CONTROL_TOKEN;
  if (fromEnv && fromEnv.length > 0) return fromEnv;

  const tokenPath = `${dbPath}.control-token`;
  try {
    const existing = readFileSync(tokenPath, "utf8").trim();
    if (existing.length > 0) {
      console.log(`[daemon] control token: ${tokenPath}`);
      return existing;
    }
  } catch {
    // Not yet created — fall through and mint one.
  }
  const token = randomBytes(32).toString("hex");
  writeFileSync(tokenPath, `${token}\n`, { mode: 0o600 });
  chmodSync(tokenPath, 0o600); // umask can loosen the create mode
  console.log(
    `[daemon] generated a control token at ${tokenPath} (mode 0600). ` +
      "Set DARKNYX_DAEMON_CONTROL_TOKEN to supply your own.",
  );
  return token;
}

async function main(): Promise<void> {
  const config = loadConfig();
  const keystore = loadKeystore(
    config.keystorePath,
    required("DARKNYX_DAEMON_KEYSTORE_PASSPHRASE"),
  );
  const store = new DaemonStore(config.dbPath);
  let orderSequence: DurableOrderSequence;
  try {
    orderSequence = DurableOrderSequence.open(
      config.orderSequencePath,
      keystore.masterSeed,
    );
  } catch (error) {
    const observedNext = store.maxSeedIndex() + 1;
    const explicitRaw = process.env.DARKNYX_DAEMON_SEQUENCE_INIT;
    const explicitNext =
      explicitRaw === undefined || explicitRaw === ""
        ? undefined
        : Number(explicitRaw);
    if (
      explicitNext !== undefined &&
      (!Number.isSafeInteger(explicitNext) ||
        explicitNext < 0 ||
        explicitNext > 0x1_0000_0000)
    ) {
      throw new Error(
        "DARKNYX_DAEMON_SEQUENCE_INIT must be an integer in 0..4294967296",
      );
    }
    if (
      !existsSync(config.orderSequencePath) &&
      (observedNext > 0 || explicitNext !== undefined)
    ) {
      // Safe one-time migration: the existing DB proves every lower index was
      // already allocated. A truly empty/lost DB needs an explicit recovered
      // high-water mark; silently assuming zero is the bug this closes.
      const initialNext = Math.max(observedNext, explicitNext ?? 0);
      orderSequence = DurableOrderSequence.create(
        config.orderSequencePath,
        keystore.masterSeed,
        initialNext,
      );
      console.warn(
        `[daemon] created order-sequence root at ${initialNext}; ` +
          "remove DARKNYX_DAEMON_SEQUENCE_INIT before the next boot",
      );
    } else {
      throw new Error(
        `cannot open durable order sequence ${config.orderSequencePath}: ${
          error instanceof Error ? error.message : error
        }. Restore it with the keystore, or set DARKNYX_DAEMON_SEQUENCE_INIT once ` +
          "to a conservative recovered high-water mark; never use zero for an identity that has traded.",
      );
    }
  }
  const prover = nodeValidInputProver({
    wasmPath: required("DARKNYX_DAEMON_VI_WASM"),
    zkeyPath: required("DARKNYX_DAEMON_VI_ZKEY"),
  });

  // Direct on-chain actions (deposit, auto-merge) are enabled only when a payer
  // keypair is configured.
  const programId = new PublicKey(config.programId);
  const circuitsDir =
    process.env.DARKNYX_DAEMON_CIRCUITS_DIR ?? "circuits/build";
  let depositFn;
  let depositor;
  let mergeRunner;
  if (config.payerKeypairPath) {
    const payer = loadKeypair(config.payerKeypairPath);
    depositor = payer.publicKey;
    depositFn = getDepositFunction({
      client: createDaemonClient({
        programId,
        rpcUrl: config.rpcUrl,
        payer,
        keystore,
        depositArtifacts: {
          wasmPath: resolve(
            circuitsDir,
            "valid_deposit/circuit_js/circuit.wasm",
          ),
          zkeyPath: resolve(circuitsDir, "valid_deposit/circuit_final.zkey"),
        },
      }),
    });

    // Auto-merge needs the merge circuit artifacts (snarkjs k=2/4) present.
    const art = (k: 2 | 4) => ({
      wasmPath: resolve(
        circuitsDir,
        `valid_merge_k${k}/circuit_js/circuit.wasm`,
      ),
      zkeyPath: resolve(circuitsDir, `valid_merge_k${k}/circuit_final.zkey`),
    });
    if (existsSync(art(2).wasmPath) && existsSync(art(2).zkeyPath)) {
      const { client, merkleProvider } = createMergeClient({
        programId,
        rpcUrl: config.rpcUrl,
        payer,
        keystore,
        artifacts: { k2: art(2), k4: art(4) },
        leavesFetcher: httpLeavesFetcher({
          gatewayUrl: config.gatewayUrl,
          token: config.token,
        }),
      });
      const rawMerge = getMergeFunction({ client });
      // Refresh the tree snapshot before each merge so the proof's root is recent.
      const mergeFn: typeof rawMerge = async (params) => {
        await merkleProvider.refresh();
        return rawMerge(params);
      };
      mergeRunner = createMergeRunner({
        store,
        payer: payer.publicKey,
        ownerCommitment: await keystore.ownerCommitment(),
        mergeFn,
      });
    } else {
      console.warn(
        "[daemon] merge circuit artifacts not found — auto-merge disabled",
      );
    }
  }

  // Attestation is on by default; DARKNYX_DAEMON_SKIP_ATTEST=1 disables it entirely
  // (local dstack-simulator, whose stub quotes can't be DCAP-verified by design).
  // Otherwise we wire the real Intel-TCB DCAP verifier so strict mode can enforce.
  const skipAttest = process.env.DARKNYX_DAEMON_SKIP_ATTEST === "1";
  const daemon = new Daemon({
    config,
    keystore,
    store,
    orderSequence,
    prover,
    depositFn,
    depositor,
    mergeRunner,
    streamTokenProvider: streamTokenProvider(config.gatewayUrl),
    verifyAttestation: skipAttest ? false : undefined,
    quoteVerifier: skipAttest
      ? undefined
      : createDcapQuoteVerifier({ pccsUrl: config.pccsUrl }),
  });
  await daemon.start();
  const att = daemon.getAttestation();
  if (att) {
    console.log(
      `[daemon] attested gateway: tee_pubkey ${att.teePubkey} compose ${att.composeHash} ` +
        `(dcap ${att.dcapVerified ? "verified" : "SKIPPED — not a security guarantee"})`,
    );
  } else {
    console.warn(
      "[daemon] WARNING: attestation skipped (DARKNYX_DAEMON_SKIP_ATTEST) — do NOT use against a production gateway",
    );
  }

  // Map a control-API `POST /orders` body → SDK intent + the note to spend.
  // The note is either pinned (`note_commitment`) or auto-selected from the
  // balance (`collateral_mint` + `collateral_min`).
  const mapPlace: PlaceMapper = (raw) => {
    const b = raw as {
      symbol: string;
      side: "bid" | "ask";
      price_limit: string | number;
      amount: string | number;
      min_fill_size?: string | number;
      expiry_slot?: string | number;
      note_commitment?: string;
      collateral_mint?: string;
      collateral_min?: string | number;
    };
    let note;
    if (b.note_commitment) {
      note = daemon.getNote(b.note_commitment);
      if (!note) throw new Error(`unknown note ${b.note_commitment}`);
    } else if (b.collateral_mint && b.collateral_min !== undefined) {
      note = daemon.selectNote({
        mint: Uint8Array.from(Buffer.from(b.collateral_mint, "hex")),
        minAmount: BigInt(b.collateral_min),
      });
      if (!note) {
        throw new Error(
          `no spendable note covering ${b.collateral_min} of ${b.collateral_mint}`,
        );
      }
    } else {
      throw new Error(
        "provide note_commitment, or collateral_mint + collateral_min",
      );
    }
    if (b.expiry_slot === undefined) {
      throw new Error(
        "expiry_slot is required; read /tee/time and provide a future absolute Solana slot",
      );
    }
    return {
      note,
      intent: {
        symbol: b.symbol,
        side: b.side === "ask" ? OrderSide.Ask : OrderSide.Bid,
        policy: limitPolicy({
          priceLimit: BigInt(b.price_limit),
          minFillSize:
            b.min_fill_size !== undefined ? BigInt(b.min_fill_size) : undefined,
          expirySlot: BigInt(b.expiry_slot),
        }),
        amount: BigInt(b.amount),
      },
    };
  };

  // Map a `POST /deposit` body → DepositRequest (only wired when deposit is on).
  const mapDeposit: DepositMapper | undefined = depositFn
    ? (raw) => {
        const b = raw as {
          mint: string;
          amount: string | number;
          depositor_token_account: string;
          tree_id?: number;
        };
        return {
          tokenMint: Uint8Array.from(Buffer.from(b.mint, "hex")),
          amount: BigInt(b.amount),
          depositorTokenAccount: new PublicKey(b.depositor_token_account),
          treeId: b.tree_id,
        };
      }
    : undefined;

  const { server, port } = await startControlServer(
    {
      daemon,
      mapPlace,
      mapDeposit,
      controlToken: resolveControlToken(config.dbPath),
    },
    config.controlPort,
  );
  console.log(
    `[daemon] control API on 127.0.0.1:${port} | gateway ${config.gatewayUrl}`,
  );

  const shutdown = () => {
    console.log("[daemon] shutting down");
    server.close();
    daemon.stop();
    store.close();
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch((e) => {
  console.error("[daemon] fatal:", e);
  process.exit(1);
});
