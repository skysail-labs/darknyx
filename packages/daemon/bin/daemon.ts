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

  const daemon = new Daemon({ config, keystore, store, prover });
  await daemon.start();

  // Map a control-API `POST /orders` body → SDK intent + the note to spend.
  const mapPlace: PlaceMapper = (raw) => {
    const b = raw as {
      symbol: string;
      side: "bid" | "ask";
      price_limit: string | number;
      amount: string | number;
      min_fill_size?: string | number;
      expiry_slot?: string | number;
      note_commitment: string;
    };
    const note = daemon.getNote(b.note_commitment);
    if (!note) throw new Error(`unknown note ${b.note_commitment}`);
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
