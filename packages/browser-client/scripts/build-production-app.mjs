import { createHash } from "node:crypto";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { basename, relative, resolve } from "node:path";

import { build } from "esbuild";

const packageRoot = resolve(import.meta.dirname, "..");
const outputRoot = resolve(
  process.env.DARKNYX_TRADER_STATIC_ROOT ??
    resolve(packageRoot, "../../.devnet/trader-static"),
);
const assetsRoot = resolve(outputRoot, "assets");
await rm(outputRoot, { recursive: true, force: true });
await mkdir(assetsRoot, { recursive: true, mode: 0o755 });

const shared = {
  bundle: true,
  platform: "browser",
  target: ["chrome113", "edge113"],
  minify: true,
  sourcemap: false,
  legalComments: "external",
  inject: [resolve(packageRoot, "scripts/node-shims.ts")],
  metafile: true,
};

const workers = await build({
  ...shared,
  entryPoints: {
    "vault.worker": resolve(packageRoot, "src/custody/vault.worker.ts"),
    "prover.worker": resolve(packageRoot, "src/prover/prover.worker.ts"),
  },
  format: "iife",
  outdir: assetsRoot,
  entryNames: "[name].[hash]",
});

function entryOutput(metafile, suffix) {
  const match = Object.entries(metafile.outputs).find(([, output]) =>
    output.entryPoint?.endsWith(suffix),
  );
  if (!match) throw new Error(`production build did not emit ${suffix}`);
  return { key: match[0], path: resolve(match[0]) };
}

const vaultWorker = entryOutput(workers.metafile, "vault.worker.ts").path;
const proverWorker = entryOutput(workers.metafile, "prover.worker.ts").path;
const webPath = (path) =>
  `/${relative(outputRoot, path).replaceAll("\\", "/")}`;

const application = await build({
  ...shared,
  entryPoints: {
    app: resolve(packageRoot, "src/app/main.tsx"),
    "tradingview-frame": resolve(packageRoot, "src/app/tradingview-frame.ts"),
  },
  format: "esm",
  splitting: true,
  outdir: assetsRoot,
  entryNames: "[name].[hash]",
  chunkNames: "chunk.[hash]",
  assetNames: "[name].[hash]",
  define: {
    __DARKNYX_VAULT_WORKER_PATH__: JSON.stringify(webPath(vaultWorker)),
    __DARKNYX_PROVER_WORKER_PATH__: JSON.stringify(webPath(proverWorker)),
  },
});
const appOutput = entryOutput(application.metafile, "src/app/main.tsx");
const app = appOutput.path;
const tradingViewFrameOutput = entryOutput(
  application.metafile,
  "src/app/tradingview-frame.ts",
);
const tradingViewFrame = tradingViewFrameOutput.path;
const appMeta = application.metafile.outputs[appOutput.key];
const css = appMeta?.cssBundle ? resolve(appMeta.cssBundle) : undefined;
if (!css) throw new Error("production build did not emit application CSS");

async function integrity(path) {
  return `sha256-${createHash("sha256")
    .update(await readFile(path))
    .digest("base64")}`;
}

const html = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="color-scheme" content="dark">
    <meta name="description" content="Private spot trading on Darknyx">
    <title>Darknyx Trader</title>
    <link rel="stylesheet" href="${webPath(css)}" integrity="${await integrity(css)}" crossorigin="anonymous">
    <script type="module" src="${webPath(app)}" integrity="${await integrity(app)}" crossorigin="anonymous"></script>
  </head>
  <body>
    <div id="darknyx-trader-root" aria-live="polite">
      <noscript>Darknyx requires JavaScript for local zero-knowledge proving.</noscript>
    </div>
  </body>
</html>
`;
await writeFile(resolve(outputRoot, "index.html"), html, {
  encoding: "utf8",
  mode: 0o644,
});

const tradingViewHtml = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="color-scheme" content="dark">
    <title>Darknyx public price chart</title>
    <script type="module" src="${webPath(tradingViewFrame)}" integrity="${await integrity(tradingViewFrame)}" crossorigin="anonymous"></script>
  </head>
  <body>
    <div id="tradingview-frame" class="tradingview-widget-container" aria-label="Public TradingView price chart"></div>
  </body>
</html>
`;
await writeFile(resolve(outputRoot, "tradingview.html"), tradingViewHtml, {
  encoding: "utf8",
  mode: 0o644,
});

const outputs = [
  ...Object.keys(workers.metafile.outputs),
  ...Object.keys(application.metafile.outputs),
].map((path) => resolve(path));
const manifest = {
  schema_version: 1,
  entry: webPath(app),
  stylesheet: webPath(css),
  vault_worker: webPath(vaultWorker),
  prover_worker: webPath(proverWorker),
  tradingview_frame: webPath(tradingViewFrame),
  files: await Promise.all(
    outputs
      .filter((path) => !path.endsWith(".map"))
      .sort()
      .map(async (path) => ({
        path: webPath(path),
        bytes: (await readFile(path)).length,
        sha256: createHash("sha256")
          .update(await readFile(path))
          .digest("hex"),
      })),
  ),
};
await writeFile(
  resolve(outputRoot, "build-manifest.json"),
  `${JSON.stringify(manifest, null, 2)}\n`,
  { encoding: "utf8", mode: 0o644 },
);
console.log(`production trader build: ${outputRoot}`);
console.log(`entry: ${basename(app)}`);
