import { rm } from "node:fs/promises";

import { build } from "esbuild";

await rm(new URL("../dist", import.meta.url), { recursive: true, force: true });

const shared = {
  bundle: true,
  platform: "browser",
  target: ["chrome113", "edge113"],
  sourcemap: true,
  legalComments: "linked",
};

await Promise.all([
  build({
    ...shared,
    entryPoints: [new URL("../src/index.ts", import.meta.url).pathname],
    format: "esm",
    outfile: new URL("../dist/index.js", import.meta.url).pathname,
  }),
  build({
    ...shared,
    entryPoints: [
      new URL("../src/custody/vault.worker.ts", import.meta.url).pathname,
    ],
    format: "iife",
    outfile: new URL("../dist/vault.worker.js", import.meta.url).pathname,
  }),
  build({
    ...shared,
    entryPoints: [new URL("../src/internal.ts", import.meta.url).pathname],
    format: "esm",
    outfile: new URL("../dist/internal.js", import.meta.url).pathname,
  }),
  build({
    ...shared,
    entryPoints: [
      new URL("../src/prover/prover.worker.ts", import.meta.url).pathname,
    ],
    format: "iife",
    outfile: new URL("../dist/prover.worker.js", import.meta.url).pathname,
  }),
]);
