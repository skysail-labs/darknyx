#!/usr/bin/env node

import { mkdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { performance } from "node:perf_hooks";
import process from "node:process";

import * as circomlibjs from "circomlibjs";
import * as snarkjs from "snarkjs";

const RUNS = Number.parseInt(process.env.NYX_DEPOSIT_BENCH_RUNS ?? "10", 10);
if (!Number.isInteger(RUNS) || RUNS < 2) {
  throw new Error("NYX_DEPOSIT_BENCH_RUNS must be an integer >= 2");
}

const root = resolve(import.meta.dirname, "..");
const build = resolve(root, "circuits/build/valid_deposit");
const wasm = resolve(build, "circuit_js/circuit.wasm");
const zkey = resolve(build, "circuit_final.zkey");
const verificationKey = JSON.parse(
  await readFile(resolve(build, "verification_key.json"), "utf8"),
);
const scratch = resolve(tmpdir(), `nyx-valid-deposit-bench-${process.pid}`);
await mkdir(scratch, { recursive: true });

const poseidon = await circomlibjs.buildPoseidon();
const fr = (value) => BigInt(poseidon.F.toObject(value));
const hash = (...values) => fr(poseidon(values));

const spendingKey = 123456789n;
const ownerCommitmentBlinding = 987654321n;
const recoveryNonce = 112233445566778899n;
const mintLo = 0x00112233445566778899aabbccddeeffn;
const mintHi = 0xffeeddccbbaa99887766554433221100n;
const amount = 5_015_000n;
const ownerCommitment = hash(1n, spendingKey, ownerCommitmentBlinding);
const innerHash = hash(27n, ownerCommitment, recoveryNonce);
const noteCommitment = hash(
  2n,
  mintLo,
  mintHi,
  amount,
  ownerCommitment,
  innerHash,
);

const inputs = {
  noteCommitment: noteCommitment.toString(),
  tokenMint: [mintLo.toString(), mintHi.toString()],
  amount: amount.toString(),
  recoveryNonce: recoveryNonce.toString(),
  spendingKey: spendingKey.toString(),
  ownerCommitmentBlinding: ownerCommitmentBlinding.toString(),
};
const expectedPublic = [
  noteCommitment,
  mintLo,
  mintHi,
  amount,
  recoveryNonce,
].map(String);

async function run(index) {
  const witnessPath = resolve(scratch, `witness-${index}.wtns`);
  const witnessStarted = performance.now();
  await snarkjs.wtns.calculate(inputs, wasm, witnessPath);
  const witnessMs = performance.now() - witnessStarted;

  const proveStarted = performance.now();
  const { proof, publicSignals } = await snarkjs.groth16.prove(zkey, witnessPath);
  const proveMs = performance.now() - proveStarted;
  await rm(witnessPath, { force: true });

  if (JSON.stringify(publicSignals) !== JSON.stringify(expectedPublic)) {
    throw new Error(
      `public-signal order mismatch: ${JSON.stringify(publicSignals)}`,
    );
  }
  if (!(await snarkjs.groth16.verify(verificationKey, publicSignals, proof))) {
    throw new Error("generated VALID_DEPOSIT proof did not verify");
  }
  return { witnessMs, proveMs, fullProveMs: witnessMs + proveMs };
}

// One untimed warm-up eliminates module/JIT/cache startup from the UX proxy.
await run("warmup");
const samples = [];
for (let i = 0; i < RUNS; i += 1) samples.push(await run(i));
await rm(scratch, { recursive: true, force: true });

function percentile(values, probability) {
  const sorted = [...values].sort((a, b) => a - b);
  const rank = Math.ceil(probability * sorted.length) - 1;
  return sorted[Math.max(0, rank)];
}

const metric = (key) => {
  const values = samples.map((sample) => sample[key]);
  return {
    p50_ms: Number(percentile(values, 0.5).toFixed(2)),
    p95_ms: Number(percentile(values, 0.95).toFixed(2)),
    max_ms: Number(Math.max(...values).toFixed(2)),
  };
};

console.log(
  JSON.stringify(
    {
      runs: RUNS,
      witness: metric("witnessMs"),
      prove: metric("proveMs"),
      full_prove: metric("fullProveMs"),
      public_inputs: expectedPublic.length,
    },
    null,
    2,
  ),
);
