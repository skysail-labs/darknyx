#!/usr/bin/env node
import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { basename, resolve } from "node:path";

import {
  artifactMetadata,
  CIRCUITS,
  circuitArtifacts,
  requireArtifacts,
  selectedCircuits,
} from "./circuits.mjs";
import { buildFixtures } from "./fixtures.mjs";
import {
  hostMetadata,
  parseArgs,
  positiveInteger,
  SCHEMA_VERSION,
  writeReport,
} from "./report.mjs";
import { summarizeSamples } from "./stats.mjs";

const args = parseArgs(process.argv.slice(2));
const selected = selectedCircuits(args.circuits);
const fixtures = await buildFixtures();
const chrome =
  args.chrome ??
  (process.platform === "darwin"
    ? "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
    : "/usr/bin/google-chrome");
const networkMbps = Number(args.network_mbps ?? 0);
if (!Number.isFinite(networkMbps) || networkMbps < 0) {
  throw new Error("network-mbps must be a non-negative number");
}

const browserPage = await readFile(
  resolve(import.meta.dirname, "browser-page.html"),
);
const browserWorker = await readFile(
  resolve(import.meta.dirname, "browser-worker.js"),
);
const snarkjsBundle = await readFile(
  resolve(
    import.meta.dirname,
    "../../../node_modules/snarkjs/build/snarkjs.min.js",
  ),
);

function sendBuffer(request, response, body, contentType, throttle = false) {
  const range = request.headers.range;
  response.setHeader("Content-Type", contentType);
  response.setHeader("Cache-Control", "public, max-age=31536000, immutable");
  response.setHeader("Accept-Ranges", "bytes");
  let start = 0;
  let end = body.length - 1;
  if (range) {
    const match = /^bytes=(\d+)-(\d*)$/.exec(range);
    if (!match) {
      response.writeHead(416).end();
      return;
    }
    start = Number(match[1]);
    end = match[2] ? Number(match[2]) : end;
    response.statusCode = 206;
    response.setHeader("Content-Range", `bytes ${start}-${end}/${body.length}`);
  }
  const slice = body.subarray(start, end + 1);
  response.setHeader("Content-Length", slice.length);
  const delayMs =
    throttle && networkMbps > 0
      ? (slice.length * 8) / (networkMbps * 1_000)
      : 0;
  if (delayMs > 0) setTimeout(() => response.end(slice), delayMs);
  else response.end(slice);
}

async function runCircuit(name) {
  const artifacts = circuitArtifacts(name);
  await requireArtifacts(artifacts);
  const artifactBodies = {
    wasm: await readFile(artifacts.wasm),
    zkey: await readFile(artifacts.zkey),
    vkey: await readFile(artifacts.verificationKey),
  };
  const warmRuns = positiveInteger(
    args.warm_runs,
    CIRCUITS[name].warmRuns,
    "warm-runs",
  );
  const coldRuns = positiveInteger(args.cold_runs, 10, "cold-runs");
  const warmups = positiveInteger(args.warmups, 1, "warmups");

  const launch = async (session) => {
    const config = {
      fixture: fixtures[name],
      warmRuns: session.warmRuns,
      coldRuns: session.coldRuns,
      warmups: session.warmups,
      collectMemory: session.collectMemory,
      urls: {
        wasm: "/artifacts/circuit.wasm",
        zkey: "/artifacts/circuit_final.zkey",
        verificationKey: "/artifacts/verification_key.json",
      },
    };
    let finish;
    const resultPromise = new Promise((resolvePromise) => {
      finish = resolvePromise;
    });
    const server = createServer(async (request, response) => {
      response.setHeader("Cross-Origin-Opener-Policy", "same-origin");
      response.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
      const url = new URL(request.url, "http://127.0.0.1");
      if (request.method === "POST" && url.pathname === "/result") {
        const chunks = [];
        for await (const chunk of request) chunks.push(chunk);
        finish(JSON.parse(Buffer.concat(chunks).toString("utf8")));
        response.writeHead(204).end();
        return;
      }
      if (url.pathname === "/")
        return sendBuffer(request, response, browserPage, "text/html");
      if (url.pathname === "/browser-worker.js")
        return sendBuffer(request, response, browserWorker, "text/javascript");
      if (url.pathname === "/vendor/snarkjs.js")
        return sendBuffer(request, response, snarkjsBundle, "text/javascript");
      if (url.pathname === "/config.json")
        return sendBuffer(
          request,
          response,
          Buffer.from(JSON.stringify(config)),
          "application/json",
        );
      if (url.pathname === "/artifacts/circuit.wasm")
        return sendBuffer(
          request,
          response,
          artifactBodies.wasm,
          "application/wasm",
          true,
        );
      if (url.pathname === "/artifacts/circuit_final.zkey")
        return sendBuffer(
          request,
          response,
          artifactBodies.zkey,
          "application/octet-stream",
          true,
        );
      if (url.pathname === "/artifacts/verification_key.json")
        return sendBuffer(
          request,
          response,
          artifactBodies.vkey,
          "application/json",
        );
      response.writeHead(404).end();
    });
    await new Promise((resolvePromise) =>
      server.listen(0, "127.0.0.1", resolvePromise),
    );
    const address = server.address();
    const profile = await mkdtemp(resolve(tmpdir(), "darknyx-chrome-"));
    const child = spawn(
      chrome,
      [
        "--headless=new",
        "--no-first-run",
        "--disable-background-networking",
        `--user-data-dir=${profile}`,
        `http://127.0.0.1:${address.port}/`,
      ],
      { stdio: ["ignore", "ignore", "pipe"] },
    );
    let stderr = "";
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });
    const timeoutMs = positiveInteger(
      args.timeout_ms,
      30 * 60_000,
      "timeout-ms",
    );
    let timeoutId;
    const timeout = new Promise((resolvePromise) => {
      timeoutId = setTimeout(
        () =>
          resolvePromise({ error: `browser timed out after ${timeoutMs}ms` }),
        timeoutMs,
      );
    });
    const result = await Promise.race([resultPromise, timeout]);
    clearTimeout(timeoutId);
    if (child.exitCode === null) {
      const exited = new Promise((resolvePromise) =>
        child.once("exit", resolvePromise),
      );
      child.kill("SIGTERM");
      await exited;
    }
    await new Promise((resolvePromise) => server.close(resolvePromise));
    await rm(profile, { recursive: true, force: true });
    if (result.error)
      throw new Error(
        `${result.error}\nChrome stderr:\n${stderr.slice(-4000)}`,
      );
    return result;
  };

  const warmResult = await launch({
    warmups,
    warmRuns,
    coldRuns: 0,
    collectMemory: true,
  });
  const cold = [];
  const coldBrowserSessions = [];
  for (let index = 0; index < coldRuns; index += 1) {
    const result = await launch({
      warmups: 0,
      warmRuns: 0,
      coldRuns: 1,
      collectMemory: false,
    });
    cold.push(...result.cold);
    coldBrowserSessions.push(result.browser);
    process.stderr.write(`\r${name} cold starts: ${index + 1}/${coldRuns}`);
  }
  if (coldRuns > 0) process.stderr.write("\n");
  return {
    artifacts: await artifactMetadata(artifacts),
    warmups,
    browser: warmResult.browser,
    cold_browser_sessions: coldBrowserSessions,
    warm: {
      samples: warmResult.warm,
      summary: summarizeSamples(warmResult.warm),
    },
    cold: { samples: cold, summary: summarizeSamples(cold) },
  };
}

const results = {};
for (const name of selected) {
  process.stderr.write(`benchmarking ${name} in ${basename(chrome)}\n`);
  results[name] = await runCircuit(name);
}
const report = {
  schema_version: SCHEMA_VERSION,
  backend: "chrome-worker-snarkjs",
  host: hostMetadata({
    device_label: args.device_label ?? null,
    simulated_network_mbps: networkMbps || null,
  }),
  results,
};
if (args.output) {
  const path = await writeReport(report, args.output);
  process.stderr.write(`wrote ${path}\n`);
}
process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
