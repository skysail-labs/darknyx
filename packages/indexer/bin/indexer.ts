#!/usr/bin/env node
/**
 * Darknyx indexer entrypoint. Watches the vault's settle txs (finalized) and serves
 * fills by order_id. Account-agnostic; the chain is the durable record.
 *
 *   INDEXER_RPC_URL=$SOLANA_RPC_URL INDEXER_DB=/tmp/darknyx-idx.sqlite node dist/bin/indexer.js
 *
 * The watcher scans via `getTransactionsForAddress` (gTFA), so
 * INDEXER_RPC_URL must name a provider that implements it; gTFA is not a
 * standard Solana RPC method.
 *
 * See scripts/run-indexer-local.sh for the local-testing one-liner.
 */

import { Connection, PublicKey } from "@solana/web3.js";
import { FillsDb } from "../src/db.js";
import { Watcher } from "../src/watcher.js";
import { startServer } from "../src/server.js";
import { loadConfig } from "../src/config.js";

async function main(): Promise<void> {
  const cfg = loadConfig();
  // Finalized commitment everywhere → settle txs are irreversible, so no reorg
  // handling is needed.
  const connection = new Connection(cfg.rpcUrl, "finalized");
  const db = new FillsDb(cfg.dbPath);
  const programId = new PublicKey(cfg.programId);

  const { port } = await startServer(db, cfg.port);
  console.log(
    `[indexer] serving on :${port} | program ${cfg.programId} | db ${cfg.dbPath}`,
  );

  const watcher = new Watcher({ connection, programId, db });

  // Live-tail cold-start (opt-in): skip the (possibly days-long) backfill page
  // so a settle that lands after boot surfaces in seconds. See IndexerConfig.
  if (cfg.startFromTip) {
    await watcher.seedCursorToTip();
  }

  const shutdown = () => {
    console.log("[indexer] shutting down");
    watcher.stop();
    db.close();
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);

  await watcher.run(cfg.pollMs);
}

main().catch((e) => {
  console.error("[indexer] fatal:", e);
  process.exit(1);
});
