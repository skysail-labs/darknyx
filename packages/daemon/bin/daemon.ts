#!/usr/bin/env node
/**
 * nyx-daemon entrypoint.
 *
 * Loads config + the encrypted keystore, builds the in-process VALID_INPUT
 * prover, wires the Daemon, and serves the local control API. Keys + proving
 * stay on this host.
 *
 *   NYX_DAEMON_GATEWAY_URL=https://<app>-8080.dstack-…  \
 *   NYX_DAEMON_TOKEN=<jwt>  NYX_DAEMON_RPC_URL=$HELIUS   \
 *   NYX_DAEMON_KEYSTORE=./nyx-keystore.json             \
 *   NYX_DAEMON_KEYSTORE_PASSPHRASE=<passphrase>         \
 *   NYX_DAEMON_VI_WASM=circuits/build/valid_input/circuit_js/circuit.wasm \
 *   NYX_DAEMON_VI_ZKEY=circuits/build/valid_input/circuit_final.zkey      \
 *   node dist/bin/daemon.js
 */

import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { Keypair, PublicKey } from "@solana/web3.js";
import {
  nodeValidInputProver,
  getDepositFunction,
  getMergeFunction,
  limitPolicy,
  OrderSide,
} from "@nyx/sdk";

import { loadConfig } from "../src/config.js";
import { DaemonStore } from "../src/store.js";
import { loadKeystore } from "../src/keystore.js";
import { createDaemonClient } from "../src/daemon-client.js";
import { createMergeClient } from "../src/merge-client.js";
import { httpLeavesFetcher } from "../src/tree-merkle-provider.js";
import { createMergeRunner } from "../src/merge-runner.js";
import { Daemon } from "../src/daemon.js";
import { createDcapQuoteVerifier } from "../src/dcap.js";
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

/** Load a Solana keypair from a `solana-keygen` JSON file (array of bytes). */
function loadKeypair(path: string): Keypair {
  const bytes = JSON.parse(readFileSync(path, "utf8")) as number[];
  return Keypair.fromSecretKey(Uint8Array.from(bytes));
}

async function main(): Promise<void> {
  const config = loadConfig();
  const keystore = loadKeystore(
    config.keystorePath,
    required("NYX_DAEMON_KEYSTORE_PASSPHRASE"),
  );
  const store = new DaemonStore(config.dbPath);
  const prover = nodeValidInputProver({
    wasmPath: required("NYX_DAEMON_VI_WASM"),
    zkeyPath: required("NYX_DAEMON_VI_ZKEY"),
  });

  // Direct on-chain actions (deposit, auto-merge) are enabled only when a payer
  // keypair is configured.
  const programId = new PublicKey(config.programId);
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
      }),
    });

    // Auto-merge needs the merge circuit artifacts (snarkjs k=2/4) present.
    const circuitsDir = process.env.NYX_DAEMON_CIRCUITS_DIR ?? "circuits/build";
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

  // Attestation is on by default; NYX_DAEMON_SKIP_ATTEST=1 disables it entirely
  // (local dstack-simulator, whose stub quotes can't be DCAP-verified by design).
  // Otherwise we wire the real Intel-TCB DCAP verifier so strict mode can enforce.
  const skipAttest = process.env.NYX_DAEMON_SKIP_ATTEST === "1";
  const daemon = new Daemon({
    config,
    keystore,
    store,
    prover,
    depositFn,
    depositor,
    mergeRunner,
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
      "[daemon] WARNING: attestation skipped (NYX_DAEMON_SKIP_ATTEST) — do NOT use against a production gateway",
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
    return {
      note,
      intent: {
        symbol: b.symbol,
        side: b.side === "ask" ? OrderSide.Ask : OrderSide.Bid,
        policy: limitPolicy({
          priceLimit: BigInt(b.price_limit),
          minFillSize:
            b.min_fill_size !== undefined ? BigInt(b.min_fill_size) : undefined,
          expirySlot:
            b.expiry_slot !== undefined ? BigInt(b.expiry_slot) : undefined,
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
      controlToken: process.env.NYX_DAEMON_CONTROL_TOKEN,
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
