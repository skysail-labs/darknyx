import { rm } from "node:fs/promises";

import { build } from "esbuild";

await rm(new URL("../dist", import.meta.url), { recursive: true, force: true });

const shared = {
  bundle: true,
  platform: "browser",
  target: ["chrome113", "edge113"],
  inject: [new URL("./node-shims.ts", import.meta.url).pathname],
  sourcemap: true,
  legalComments: "linked",
};

await build({
  ...shared,
  entryPoints: {
    index: new URL("../src/index.ts", import.meta.url).pathname,
    internal: new URL("../src/internal.ts", import.meta.url).pathname,
  },
  format: "esm",
  splitting: true,
  outdir: new URL("../dist", import.meta.url).pathname,
  // Keep shared chunks beside the entrypoints: BrowserVault deliberately
  // resolves its default Worker relative to the module that defines it.
  chunkNames: "[name]-[hash]",
});

await build({
  bundle: true,
  platform: "browser",
  target: ["chrome113", "edge113"],
  sourcemap: true,
  legalComments: "linked",
  entryPoints: {
    ui: new URL("../src/ui/index.ts", import.meta.url).pathname,
  },
  format: "esm",
  outdir: new URL("../dist", import.meta.url).pathname,
  external: ["react", "react/jsx-runtime", "lucide-react"],
});

await Promise.all([
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
    entryPoints: [
      new URL("../src/prover/prover.worker.ts", import.meta.url).pathname,
    ],
    format: "iife",
    outfile: new URL("../dist/prover.worker.js", import.meta.url).pathname,
  }),
]);

if (process.env.DARKNYX_UI_PREVIEW === "1") {
  await build({
    bundle: true,
    platform: "browser",
    target: ["chrome113", "edge113"],
    sourcemap: true,
    legalComments: "linked",
    entryPoints: {
      "ui-preview": new URL("../tests/ui-preview.tsx", import.meta.url)
        .pathname,
    },
    format: "esm",
    outdir: new URL("../dist", import.meta.url).pathname,
  });
}
