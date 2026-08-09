#!/usr/bin/env node
import { mkdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { performance } from "node:perf_hooks";

import * as snarkjs from "snarkjs";

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

async function timedSample(name, fixture, scratch, index) {
  const artifacts = circuitArtifacts(name);
  const artifactStart = performance.now();
  const verificationKey = JSON.parse(
    await readFile(artifacts.verificationKey, "utf8"),
  );
  await Promise.all([readFile(artifacts.wasm), readFile(artifacts.zkey)]);
  const artifactLoadMs = performance.now() - artifactStart;
  const witnessPath = resolve(scratch, `${name}-${index}.wtns`);

  const witnessStart = performance.now();
  await snarkjs.wtns.calculate(fixture.input, artifacts.wasm, witnessPath);
  const witnessMs = performance.now() - witnessStart;

  const proveStart = performance.now();
  const { proof, publicSignals } = await snarkjs.groth16.prove(
    artifacts.zkey,
    witnessPath,
  );
  const proveMs = performance.now() - proveStart;

  if (
    JSON.stringify(publicSignals) !== JSON.stringify(fixture.expectedPublic)
  ) {
    throw new Error(
      `${name} public signals differ from deterministic fixture:\n` +
        `expected ${JSON.stringify(fixture.expectedPublic)}\n` +
        `received ${JSON.stringify(publicSignals)}`,
    );
  }
  const verifyStart = performance.now();
  const verified = await snarkjs.groth16.verify(
    verificationKey,
    publicSignals,
    proof,
  );
  const verifyMs = performance.now() - verifyStart;
  if (!verified) throw new Error(`${name} proof failed local verification`);
  await rm(witnessPath, { force: true });

  return {
    artifact_load_ms: artifactLoadMs,
    witness_ms: witnessMs,
    prove_ms: proveMs,
    verify_ms: verifyMs,
    end_to_end_ms: artifactLoadMs + witnessMs + proveMs + verifyMs,
    // Node reports maxRSS in KiB on every supported platform.
    process_high_water_rss_bytes: process.resourceUsage().maxRSS * 1024,
  };
}

const args = parseArgs(process.argv.slice(2));
const selected = selectedCircuits(args.circuits);
const fixtures = await buildFixtures();
const scratch = resolve(tmpdir(), `darknyx-client-prover-${process.pid}`);
await mkdir(scratch, { recursive: true });

const results = {};
try {
  for (const name of selected) {
    const artifacts = circuitArtifacts(name);
    await requireArtifacts(artifacts);
    const warmRuns = positiveInteger(
      args.warm_runs,
      CIRCUITS[name].warmRuns,
      "warm-runs",
    );
    const warmups = positiveInteger(args.warmups, 1, "warmups");
    const soakSeconds = positiveInteger(args.soak_seconds, 0, "soak-seconds");
    for (let i = 0; i < warmups; i += 1) {
      await timedSample(name, fixtures[name], scratch, `warmup-${i}`);
    }
    const samples = [];
    for (let i = 0; i < warmRuns; i += 1) {
      samples.push(await timedSample(name, fixtures[name], scratch, i));
      process.stderr.write(`\r${name}: ${i + 1}/${warmRuns}`);
    }
    process.stderr.write("\n");
    const soak = [];
    const soakStarted = performance.now();
    while (performance.now() - soakStarted < soakSeconds * 1000) {
      soak.push(
        await timedSample(name, fixtures[name], scratch, `soak-${soak.length}`),
      );
      process.stderr.write(
        `\r${name} soak: ${Math.min(soakSeconds, Math.floor((performance.now() - soakStarted) / 1000))}/${soakSeconds}s`,
      );
    }
    const soakElapsedMs = performance.now() - soakStarted;
    if (soakSeconds > 0) process.stderr.write("\n");
    results[name] = {
      artifacts: await artifactMetadata(artifacts),
      warmups,
      samples,
      summary: summarizeSamples(samples),
      process_high_water_rss_bytes:
        samples.length === 0
          ? null
          : Math.max(
              ...samples.map((sample) => sample.process_high_water_rss_bytes),
            ),
      ...(soakSeconds > 0
        ? {
            soak: {
              samples: soak,
              ...summarizeSoak(soak, soakElapsedMs),
              process_high_water_rss_bytes: Math.max(
                ...soak.map((sample) => sample.process_high_water_rss_bytes),
              ),
            },
          }
        : {}),
    };
  }
} finally {
  await rm(scratch, { recursive: true, force: true });
}

const report = {
  schema_version: SCHEMA_VERSION,
  backend: "node-snarkjs",
  mode: "warm",
  host: hostMetadata({ device_label: args.device_label ?? null }),
  results,
};
if (args.output) {
  const path = await writeReport(report, args.output);
  process.stderr.write(`wrote ${path}\n`);
}
process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
