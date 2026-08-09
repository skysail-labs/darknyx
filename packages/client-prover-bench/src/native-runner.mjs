#!/usr/bin/env node
import { execFile } from "node:child_process";
import { access, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { constants } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { performance } from "node:perf_hooks";
import { promisify } from "node:util";

import * as snarkjs from "snarkjs";

import {
  artifactMetadata,
  CIRCUITS,
  circuitArtifacts,
  repoRoot,
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

const run = promisify(execFile);
const args = parseArgs(process.argv.slice(2));
const selected = selectedCircuits(args.circuits);
const fixtures = await buildFixtures();
const defaultRapid = resolve(
  repoRoot(),
  "third_party/rapidsnark/build_prover/src/prover",
);
const rapid = resolve(
  args.rapidsnark ?? process.env.RAPIDSNARK_BIN ?? defaultRapid,
);
await access(rapid, constants.X_OK);
const scratch = resolve(tmpdir(), `darknyx-native-prover-${process.pid}`);
await mkdir(scratch, { recursive: true });

async function sample(name, fixture, index) {
  const artifacts = circuitArtifacts(name);
  const input = resolve(scratch, `${name}-${index}.json`);
  const witness = resolve(scratch, `${name}-${index}.wtns`);
  const proof = resolve(scratch, `${name}-${index}-proof.json`);
  const publicSignalsPath = resolve(scratch, `${name}-${index}-public.json`);
  await writeFile(input, JSON.stringify(fixture.input));

  const artifactStarted = performance.now();
  const verificationKey = JSON.parse(
    await readFile(artifacts.verificationKey, "utf8"),
  );
  await readFile(artifacts.zkey);
  const artifactLoadMs = performance.now() - artifactStarted;
  const witnessStarted = performance.now();
  await run(artifacts.nativeWitness, [input, witness]);
  const witnessMs = performance.now() - witnessStarted;
  const proveStarted = performance.now();
  await run(rapid, [artifacts.zkey, witness, proof, publicSignalsPath]);
  const proveMs = performance.now() - proveStarted;
  const [proofJson, publicSignals] = await Promise.all([
    readFile(proof, "utf8").then(JSON.parse),
    readFile(publicSignalsPath, "utf8").then(JSON.parse),
  ]);
  if (
    JSON.stringify(publicSignals) !== JSON.stringify(fixture.expectedPublic)
  ) {
    throw new Error(`${name} native public-signal mismatch`);
  }
  const verifyStarted = performance.now();
  const verified = await snarkjs.groth16.verify(
    verificationKey,
    publicSignals,
    proofJson,
  );
  const verifyMs = performance.now() - verifyStarted;
  if (!verified)
    throw new Error(`${name} native proof failed local verification`);
  await Promise.all(
    [input, witness, proof, publicSignalsPath].map((path) =>
      rm(path, { force: true }),
    ),
  );
  return {
    artifact_load_ms: artifactLoadMs,
    witness_ms: witnessMs,
    prove_ms: proveMs,
    verify_ms: verifyMs,
    end_to_end_ms: artifactLoadMs + witnessMs + proveMs + verifyMs,
  };
}

const results = {};
try {
  for (const name of selected) {
    const artifacts = circuitArtifacts(name);
    await requireArtifacts(artifacts, { native: true });
    const runs = positiveInteger(args.runs, CIRCUITS[name].warmRuns, "runs");
    const warmups = positiveInteger(args.warmups, 1, "warmups");
    const soakSeconds = positiveInteger(args.soak_seconds, 0, "soak-seconds");
    for (let index = 0; index < warmups; index += 1) {
      await sample(name, fixtures[name], `warmup-${index}`);
    }
    const samples = [];
    for (let index = 0; index < runs; index += 1) {
      samples.push(await sample(name, fixtures[name], index));
      process.stderr.write(`\r${name}: ${index + 1}/${runs}`);
    }
    process.stderr.write("\n");
    const soak = [];
    const soakStarted = performance.now();
    while (performance.now() - soakStarted < soakSeconds * 1000) {
      soak.push(await sample(name, fixtures[name], `soak-${soak.length}`));
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
      ...(soakSeconds > 0
        ? {
            soak: {
              samples: soak,
              ...summarizeSoak(soak, soakElapsedMs),
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
  backend: "native-circom-rapidsnark",
  host: hostMetadata({
    device_label: args.device_label ?? null,
    rapidsnark: rapid,
  }),
  results,
};
if (args.output) {
  const path = await writeReport(report, args.output);
  process.stderr.write(`wrote ${path}\n`);
}
process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
