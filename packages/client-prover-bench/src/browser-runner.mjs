#!/usr/bin/env node
import { execFile, spawn } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { basename, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import { promisify } from "node:util";

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
import { summarizeSamples, summarizeSoak } from "./stats.mjs";

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

const run = promisify(execFile);

function median(values) {
  if (values.length === 0) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0
    ? (sorted[middle - 1] + sorted[middle]) / 2
    : sorted[middle];
}

async function processTreeRss(rootPid) {
  if (process.platform === "win32") {
    const script = [
      `$root=${rootPid}`,
      "$rows=Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId",
      "$ids=[System.Collections.Generic.HashSet[int]]::new()",
      "$null=$ids.Add($root)",
      "do {$changed=$false; foreach($row in $rows) {if($ids.Contains([int]$row.ParentProcessId) -and $ids.Add([int]$row.ProcessId)) {$changed=$true}}} while($changed)",
      "$sum=(Get-Process -Id @($ids) -ErrorAction SilentlyContinue | Measure-Object WorkingSet64 -Sum).Sum",
      "Write-Output ([int64]$sum)",
    ].join("; ");
    const { stdout } = await run("powershell.exe", [
      "-NoProfile",
      "-NonInteractive",
      "-Command",
      script,
    ]);
    const rssBytes = Number(stdout.trim());
    return Number.isFinite(rssBytes) ? rssBytes : null;
  }
  const { stdout } = await run("ps", ["-axo", "pid=,ppid=,rss="]);
  const rows = stdout
    .trim()
    .split("\n")
    .map((line) => line.trim().split(/\s+/).map(Number))
    .filter(([pid, ppid, rss]) =>
      [pid, ppid, rss].every((value) => Number.isFinite(value)),
    );
  const tree = new Set([rootPid]);
  let changed = true;
  while (changed) {
    changed = false;
    for (const [pid, ppid] of rows) {
      if (tree.has(ppid) && !tree.has(pid)) {
        tree.add(pid);
        changed = true;
      }
    }
  }
  return (
    rows
      .filter(([pid]) => tree.has(pid))
      .reduce((sum, [, , rssKib]) => sum + rssKib, 0) * 1024
  );
}

function summarizeRss(samples) {
  if (samples.length === 0) return null;
  const quartileSize = Math.max(1, Math.floor(samples.length / 4));
  const first = median(
    samples.slice(0, quartileSize).map(({ rss_bytes }) => rss_bytes),
  );
  const last = median(
    samples.slice(-quartileSize).map(({ rss_bytes }) => rss_bytes),
  );
  return {
    sample_count: samples.length,
    peak_rss_bytes: Math.max(...samples.map(({ rss_bytes }) => rss_bytes)),
    first_quartile_median_rss_bytes: first,
    last_quartile_median_rss_bytes: last,
    growth_bytes: last - first,
  };
}

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
  const soakSeconds = positiveInteger(args.soak_seconds, 0, "soak-seconds");
  if (soakSeconds > 0 && warmRuns > 0) {
    throw new Error(
      "run a soak separately with --warm-runs 0 so latency sampling remains independent",
    );
  }

  const launch = async (session) => {
    let benchmarkPhase = "setup";
    const config = {
      fixture: fixtures[name],
      warmRuns: session.warmRuns,
      coldRuns: session.coldRuns,
      warmups: session.warmups,
      collectMemory: session.collectMemory,
      soakSeconds: session.soakSeconds,
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
      if (request.method === "POST" && url.pathname === "/phase") {
        const chunks = [];
        for await (const chunk of request) chunks.push(chunk);
        const phase = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        if (phase.phase === "soak") benchmarkPhase = "soak";
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
        "--enable-precise-memory-info",
        `--user-data-dir=${profile}`,
        `http://127.0.0.1:${address.port}/`,
      ],
      { stdio: ["ignore", "ignore", "pipe"] },
    );
    const rssStarted = performance.now();
    const rssSamples = [];
    let sampleRss = true;
    const rssSampler = (async () => {
      while (sampleRss) {
        try {
          const rssBytes = await processTreeRss(child.pid);
          if (rssBytes !== null) {
            rssSamples.push({
              elapsed_ms: Number((performance.now() - rssStarted).toFixed(2)),
              rss_bytes: rssBytes,
              phase: benchmarkPhase,
            });
          }
        } catch {
          // The child may exit between the result POST and the final sample.
        }
        await new Promise((resolvePromise) =>
          setTimeout(resolvePromise, 1_000),
        );
      }
    })();
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
    sampleRss = false;
    await rssSampler;
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
    result.browser.process_tree_rss = summarizeRss(rssSamples);
    result.browser.soak_process_tree_rss = summarizeRss(
      rssSamples.filter(({ phase }) => phase === "soak"),
    );
    result.browser.process_tree_rss_samples = rssSamples;
    return result;
  };

  const warmResult = await launch({
    warmups,
    warmRuns,
    coldRuns: 0,
    soakSeconds,
    collectMemory: true,
  });
  const cold = [];
  const coldBrowserSessions = [];
  for (let index = 0; index < coldRuns; index += 1) {
    const result = await launch({
      warmups: 0,
      warmRuns: 0,
      coldRuns: 1,
      soakSeconds: 0,
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
    ...(soakSeconds > 0
      ? {
          soak: {
            samples: warmResult.soak,
            ...summarizeSoak(warmResult.soak, warmResult.soak_elapsed_ms),
            measured_memory_bytes_before:
              warmResult.browser.soak_process_tree_rss
                ?.first_quartile_median_rss_bytes ?? null,
            measured_memory_bytes_after:
              warmResult.browser.soak_process_tree_rss
                ?.last_quartile_median_rss_bytes ?? null,
            measured_memory_source: "chrome-process-tree-rss",
            memory_growth_bytes:
              warmResult.browser.soak_process_tree_rss?.growth_bytes ?? null,
            peak_memory_bytes:
              warmResult.browser.process_tree_rss?.peak_rss_bytes ?? null,
            max_main_thread_stall_ms:
              warmResult.browser.max_main_thread_stall_ms,
          },
        }
      : {}),
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
