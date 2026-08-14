#!/usr/bin/env node
import { generateKeyPairSync, sign } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";

import { buildFixtures } from "../../client-prover-bench/src/fixtures.mjs";

const packageRoot = resolve(fileURLToPath(new URL(".", import.meta.url)), "..");
const repositoryRoot = resolve(packageRoot, "../..");
const chromeCandidates =
  process.platform === "darwin"
    ? ["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"]
    : [
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
      ];
const chrome = process.env.CHROME_PATH ?? chromeCandidates.find(existsSync);
if (!chrome) throw new Error("Chrome/Chromium not found; set CHROME_PATH");

const payloadBytes = await readFile(
  resolve(packageRoot, "artifacts/client-artifacts.v1.payload.json"),
);
const payload = JSON.parse(payloadBytes.toString("utf8"));
const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const domain = Buffer.from("darknyx/client-artifact-manifest/v1\0");
const signature = sign(null, Buffer.concat([domain, payloadBytes]), privateKey);
const rawPublicKey = publicKey
  .export({ type: "spki", format: "der" })
  .subarray(-32);
const envelope = Buffer.from(
  JSON.stringify({
    envelope_version: 1,
    key_id: "browser-product-test",
    payload: payloadBytes.toString("base64url"),
    signature: signature.toString("base64url"),
  }),
);
const fixtures = await buildFixtures();
const assets = new Map([
  [
    "/",
    [
      await readFile(resolve(packageRoot, "tests/prover-page.html")),
      "text/html; charset=utf-8",
    ],
  ],
  [
    "/prover-page.js",
    [
      await readFile(resolve(packageRoot, "tests/prover-page.js")),
      "text/javascript; charset=utf-8",
    ],
  ],
  [
    "/dist/internal.js",
    [
      await readFile(resolve(packageRoot, "dist/internal.js")),
      "text/javascript; charset=utf-8",
    ],
  ],
  [
    "/dist/prover.worker.js",
    [
      await readFile(resolve(packageRoot, "dist/prover.worker.js")),
      "text/javascript; charset=utf-8",
    ],
  ],
  ["/artifacts/manifest.json", [envelope, "application/json"]],
]);
const builds = {
  wallet_create: "valid_wallet_create",
  deposit: "valid_deposit",
  input: "valid_input",
  spend: "valid_spend",
  merge_k2: "valid_merge_k2",
  merge_k4: "valid_merge_k4",
};
for (const [circuit, build] of Object.entries(builds)) {
  for (const [kind, file] of Object.entries({
    wasm: "circuit_js/circuit.wasm",
    zkey: "circuit_final.zkey",
    verification_key: "verification_key.json",
  })) {
    const descriptor = payload.circuits[circuit][kind];
    assets.set(`/artifacts/${descriptor.path}`, [
      await readFile(resolve(repositoryRoot, "circuits/build", build, file)),
      kind === "wasm"
        ? "application/wasm"
        : kind === "verification_key"
          ? "application/json"
          : "application/octet-stream",
    ]);
  }
}

const config = Buffer.from(
  JSON.stringify({
    artifact_set_id: payload.artifact_set_id,
    key_id: "browser-product-test",
    public_key: [...rawPublicKey],
    fixtures,
  }),
);
const csp = [
  "default-src 'none'",
  "script-src 'self' 'wasm-unsafe-eval'",
  "connect-src 'self'",
  "worker-src 'self' blob:",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
  "object-src 'none'",
  "require-trusted-types-for 'script'",
  "trusted-types darknyx-prover-worker darknyx-snarkjs-worker",
].join("; ");
let finish;
const resultPromise = new Promise((resolveResult) => {
  finish = resolveResult;
});
const server = createServer(async (request, response) => {
  try {
    response.setHeader("Cross-Origin-Opener-Policy", "same-origin");
    response.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
    response.setHeader("Cross-Origin-Resource-Policy", "same-origin");
    response.setHeader("Content-Security-Policy", csp);
    response.setHeader("Cache-Control", "no-store");
    const url = new URL(request.url, "http://localhost");
    if (request.method === "POST" && url.pathname === "/result") {
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      finish(JSON.parse(Buffer.concat(chunks).toString("utf8")));
      response.writeHead(204).end();
      return;
    }
    if (url.pathname === "/config.json") {
      response.setHeader("Content-Type", "application/json");
      response.setHeader("Content-Length", config.length);
      response.end(config);
      return;
    }
    if (url.pathname.startsWith("/dist/")) {
      const distRoot = resolve(packageRoot, "dist");
      const assetPath = resolve(packageRoot, url.pathname.slice(1));
      if (!assetPath.startsWith(`${distRoot}/`)) {
        response.writeHead(404).end();
        return;
      }
      const body = await readFile(assetPath);
      response.setHeader("Content-Type", "text/javascript; charset=utf-8");
      response.setHeader("Content-Length", body.length);
      response.end(body);
      return;
    }
    const asset = assets.get(url.pathname);
    if (!asset) {
      response.writeHead(404).end();
      return;
    }
    response.setHeader("Content-Type", asset[1]);
    response.setHeader("Content-Length", asset[0].length);
    response.end(asset[0]);
  } catch (error) {
    response.writeHead(500).end(String(error));
  }
});
await new Promise((resolveListen) =>
  server.listen(0, "localhost", resolveListen),
);
const port = server.address().port;
const profile = await mkdtemp(resolve(tmpdir(), "darknyx-prover-chrome-"));
const child = spawn(
  chrome,
  [
    "--headless=new",
    "--no-first-run",
    "--disable-background-networking",
    `--user-data-dir=${profile}`,
    `http://localhost:${port}/`,
  ],
  { stdio: ["ignore", "ignore", "pipe"] },
);
let stderr = "";
child.stderr.on("data", (chunk) => {
  stderr += chunk.toString();
});
let timeout;
try {
  const processFailure = new Promise((resolveFailure) => {
    child.once("error", (error) => {
      resolveFailure({ ok: false, error: `Chrome failed to start: ${error}` });
    });
    child.once("exit", (code, signal) => {
      resolveFailure({
        ok: false,
        error: `Chrome exited before reporting (${code ?? signal ?? "unknown"})`,
      });
    });
  });
  const timedOut = new Promise((resolveTimeout) => {
    timeout = setTimeout(
      () => resolveTimeout({ ok: false, error: "browser prover timed out" }),
      180_000,
    );
  });
  const result = await Promise.race([resultPromise, processFailure, timedOut]);
  if (!result.ok) throw new Error(`${result.error}\n${stderr.slice(-4000)}`);
  if (
    result.result.all_six_proved_and_verified !== true ||
    result.result.cross_origin_isolated !== true ||
    result.result.heartbeat_ticks < 10 ||
    result.result.max_main_thread_stall_ms >= 100
  ) {
    throw new Error(
      `browser prover acceptance failed: ${JSON.stringify(result)}`,
    );
  }
  process.stdout.write(`${JSON.stringify(result.result, null, 2)}\n`);
} finally {
  clearTimeout(timeout);
  if (child.exitCode === null) {
    child.kill("SIGTERM");
    await new Promise((resolveExit) => {
      const kill = setTimeout(() => {
        child.kill("SIGKILL");
        resolveExit();
      }, 2_000);
      child.once("exit", () => {
        clearTimeout(kill);
        resolveExit();
      });
    });
  }
  await new Promise((resolveClose) => server.close(resolveClose));
  await rm(profile, {
    recursive: true,
    force: true,
    maxRetries: 8,
    retryDelay: 100,
  });
}
