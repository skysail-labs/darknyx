#!/usr/bin/env node
import { createReleaseHost } from "./host.js";
import { loadTraderHostRuntimeConfig } from "./runtime-config.js";

async function main(): Promise<void> {
  const checkOnly = process.argv.slice(2).includes("--check-config");
  if (process.argv.length > (checkOnly ? 3 : 2)) {
    throw new Error("usage: darknyx-trader-host [--check-config]");
  }
  const config = await loadTraderHostRuntimeConfig();
  // Constructing the host validates the static root, public endpoint pins,
  // limits, and all serving headers even during a check-only deployment gate.
  const server = createReleaseHost(config.host);
  if (checkOnly) {
    server.close();
    process.stdout.write("trader-host configuration OK\n");
    return;
  }
  server.on("error", (error) => {
    process.stderr.write(`trader-host server error: ${error.message}\n`);
    process.exitCode = 1;
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(config.port, config.listenHost, () => {
      server.off("error", reject);
      resolve();
    });
  });
  process.stdout.write(
    `trader-host listening on ${config.listenHost}:${config.port}\n`,
  );
  let stopping = false;
  const stop = (signal: NodeJS.Signals) => {
    if (stopping) return;
    stopping = true;
    process.stdout.write(`trader-host received ${signal}; draining\n`);
    server.closeAllConnections();
    server.close((error) => {
      if (error)
        process.stderr.write(`trader-host shutdown failed: ${error.message}\n`);
      process.exit(error ? 1 : 0);
    });
    setTimeout(() => process.exit(1), 10_000).unref();
  };
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
}

main().catch((error: unknown) => {
  const message =
    error instanceof Error ? error.message : "unknown startup failure";
  process.stderr.write(`trader-host startup refused: ${message}\n`);
  process.exitCode = 1;
});
