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

import { nodeValidInputProver, limitPolicy, OrderSide } from "@nyx/sdk";

import { loadConfig } from "../src/config.js";
import { DaemonStore } from "../src/store.js";
import { loadKeystore } from "../src/keystore.js";
import { Daemon } from "../src/daemon.js";
import { startControlServer, type PlaceMapper } from "../src/control-api.js";

function required(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is required`);
  return v;
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

  const daemon = new Daemon({
    config,
    keystore,
    store,
    prover,
    // Attestation is on by default; NYX_DAEMON_SKIP_ATTEST=1 disables it (local
    // dstack-simulator, whose stub quotes can't be verified by design).
    verifyAttestation:
      process.env.NYX_DAEMON_SKIP_ATTEST === "1" ? false : undefined,
  });
  await daemon.start();
  const att = daemon.getAttestation();
  if (att) {
    console.log(
      `[daemon] attested gateway: tee_pubkey ${att.teePubkey} compose ${att.composeHash}`,
    );
  } else {
    console.warn("[daemon] WARNING: attestation skipped");
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

  const { server, port } = await startControlServer(
    {
      daemon,
      mapPlace,
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
