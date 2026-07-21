#!/usr/bin/env node
// Times witness generation and snarkjs Groth16 proving for the production
// N=16 circuit versus isolated 8->2 and 8->1 statement-digest wrappers.

import { mkdir, readFile, unlink, writeFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { performance } from "node:perf_hooks";
import { buildPoseidon } from "circomlibjs";
import * as snarkjs from "snarkjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const out = resolve(root, "target/public-input-benchmarks");
const runs = Number.parseInt(process.env.BENCH_RUNS ?? "5", 10);
if (!Number.isInteger(runs) || runs < 1) throw new Error("BENCH_RUNS must be >= 1");

const poseidon = await buildPoseidon();
const poseidonFr = (inputs) =>
  BigInt(poseidon.F.toObject(poseidon(inputs.map((v) => poseidon.F.e(v)))));
const toDecimal = (value) => value.toString();

const N = 16;
const zeroes = () => Array.from({ length: N }, () => "0");
const batchSlots = Array.from({ length: N }, (_, i) => i.toString());
const leaves = batchSlots.map((slot) =>
  poseidonFr([23n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, BigInt(slot)]),
);
let level = leaves;
while (level.length > 1) {
  const next = [];
  for (let i = 0; i < level.length; i += 2) {
    next.push(poseidonFr([22n, level[i], level[i + 1]]));
  }
  level = next;
}

const governed = {
  fee_rate_bps: 0n,
  protocol_owner_commitment: 7n,
  base_mint_lo: 177n,
  base_mint_hi: 1n,
  quote_mint_lo: 158n,
  quote_mint_hi: 1n,
  price_scale: 1n,
};
const configValues = Object.values(governed);
const merkleRoot = level[0];
const baseInput = {
  merkle_root: toDecimal(merkleRoot),
  ...Object.fromEntries(
    Object.entries(governed).map(([key, value]) => [key, toDecimal(value)]),
  ),
  note_a_commitment: zeroes(),
  note_b_commitment: zeroes(),
  note_c_commitment: zeroes(),
  note_d_commitment: zeroes(),
  note_e_commitment: zeroes(),
  note_f_commitment: zeroes(),
  note_fee_base_commitment: zeroes(),
  note_fee_quote_commitment: zeroes(),
  base_amount: zeroes(),
  quote_amount: zeroes(),
  buyer_change_amt: zeroes(),
  seller_change_amt: zeroes(),
  buyer_fee_amt: zeroes(),
  seller_fee_amt: zeroes(),
  batch_slot: batchSlots,
  is_active: zeroes(),
  a_owner_commit: zeroes(),
  b_owner_commit: zeroes(),
  a_amount: zeroes(),
  b_amount: zeroes(),
  a_inner: zeroes(),
  b_inner: zeroes(),
  clearing_price: zeroes(),
  price_remainder: zeroes(),
};

const variants = [
  { name: "pi8", dir: "match_batch_n16_pi8", input: baseInput },
  {
    name: "pi2",
    dir: "match_batch_n16_pi2",
    input: {
      ...baseInput,
      statement_digest: toDecimal(poseidonFr([1001n, ...configValues])),
    },
  },
  {
    name: "pi1",
    dir: "match_batch_n16_pi1",
    input: {
      ...baseInput,
      statement_digest: toDecimal(
        poseidonFr([1002n, merkleRoot, ...configValues]),
      ),
    },
  },
];

const median = (values) => {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.floor(sorted.length / 2)];
};
const round = (value) => Math.round(value * 100) / 100;

await mkdir(resolve(out, "results"), { recursive: true });
const states = [];
for (const variant of variants) {
  const dir = resolve(out, variant.dir);
  const wasm = resolve(dir, "circuit_js/circuit.wasm");
  const zkey = resolve(dir, "circuit_final.zkey");
  const vk = JSON.parse(
    await readFile(resolve(dir, "verification_key.json"), "utf8"),
  );
  const wtns = resolve(out, "results", `${variant.name}.wtns`);

  // One untimed warm-up runs the same code paths and populates filesystem and
  // JS/WASM caches before the recorded samples.
  await snarkjs.wtns.calculate(variant.input, wasm, wtns);
  const warm = await snarkjs.groth16.prove(zkey, wtns);
  if (!(await snarkjs.groth16.verify(vk, warm.publicSignals, warm.proof))) {
    throw new Error(`${variant.name} warm-up proof failed verification`);
  }

  const r1csInfo = execFileSync(
    resolve(root, "node_modules/.bin/snarkjs"),
    ["r1cs", "info", resolve(dir, "circuit.r1cs")],
    { encoding: "utf8" },
  ).replace(/\x1b\[[0-9;]*m/g, "");
  const constraintsMatch = r1csInfo.match(/# of Constraints:\s*(\d+)/);
  if (!constraintsMatch) throw new Error(`cannot parse constraints for ${variant.name}`);
  states.push({
    ...variant,
    wasm,
    zkey,
    vk,
    wtns,
    constraints: Number.parseInt(constraintsMatch[1], 10),
    witnessMs: [],
    proveMs: [],
    lastProof: warm,
  });
}

// Interleave the variants and rotate their order each round. Sequentially
// completing all pi8 samples before pi2/pi1 would make thermal throttling and
// filesystem-cache order look like a circuit regression.
for (let roundIndex = 0; roundIndex < runs; roundIndex += 1) {
  for (let offset = 0; offset < states.length; offset += 1) {
    const state = states[(roundIndex + offset) % states.length];
    const started = performance.now();
    await snarkjs.wtns.calculate(state.input, state.wasm, state.wtns);
    state.witnessMs.push(performance.now() - started);
  }
  for (let offset = 0; offset < states.length; offset += 1) {
    const state = states[(roundIndex + offset) % states.length];
    const started = performance.now();
    state.lastProof = await snarkjs.groth16.prove(state.zkey, state.wtns);
    state.proveMs.push(performance.now() - started);
  }
}

const results = [];
for (const state of states) {
  if (
    !(await snarkjs.groth16.verify(
      state.vk,
      state.lastProof.publicSignals,
      state.lastProof.proof,
    ))
  ) {
    throw new Error(`${state.name} recorded proof failed verification`);
  }
  await unlink(state.wtns).catch(() => {});
  const result = {
    variant: state.name,
    publicInputs: state.vk.nPublic,
    constraints: state.constraints,
    witnessMs: state.witnessMs.map(round),
    witnessMedianMs: round(median(state.witnessMs)),
    proveMs: state.proveMs.map(round),
    proveMedianMs: round(median(state.proveMs)),
  };
  results.push(result);
  console.log(JSON.stringify(result));
}

const baseline = results[0];
for (const result of results) {
  const witnessPct = result.witnessMs.map(
    (value, i) => ((value - baseline.witnessMs[i]) / baseline.witnessMs[i]) * 100,
  );
  const provePct = result.proveMs.map(
    (value, i) => ((value - baseline.proveMs[i]) / baseline.proveMs[i]) * 100,
  );
  const combinedPct = result.proveMs.map((value, i) => {
    const current = value + result.witnessMs[i];
    const base = baseline.proveMs[i] + baseline.witnessMs[i];
    return ((current - base) / base) * 100;
  });
  result.witnessDeltaMs = round(
    median(result.witnessMs.map((value, i) => value - baseline.witnessMs[i])),
  );
  result.witnessDeltaPct = round(median(witnessPct));
  result.proveDeltaMs = round(
    median(result.proveMs.map((value, i) => value - baseline.proveMs[i])),
  );
  result.proveDeltaPct = round(median(provePct));
  result.combinedDeltaPct = round(median(combinedPct));
}

const timestamp = new Date().toISOString();
const json = {
  timestamp,
  node: process.version,
  platform: `${process.platform}/${process.arch}`,
  runs,
  results,
};
await writeFile(
  resolve(out, "results", "match-prover-results.json"),
  `${JSON.stringify(json, null, 2)}\n`,
);
const rows = results
  .map(
    (r) =>
      `| ${r.variant} | ${r.publicInputs} | ${r.constraints} | ${r.witnessMedianMs} | ${r.witnessDeltaMs} ms / ${r.witnessDeltaPct}% | ${r.proveMedianMs} | ${r.proveDeltaMs} ms / ${r.proveDeltaPct}% | ${r.combinedDeltaPct}% |`,
  )
  .join("\n");
await writeFile(
  resolve(out, "results", "match-prover-results.md"),
  `# Public-input compression prover benchmark\n\n` +
    `Generated ${timestamp} on ${process.platform}/${process.arch}, Node ${process.version}; ${runs} recorded samples after one warm-up.\n\n` +
    `Deltas are medians of paired per-round changes, not differences between unpaired medians.\n\n` +
    `| Variant | Public inputs | Constraints | Witness median ms | Paired witness delta | Prove median ms | Paired prove delta | Paired combined delta |\n` +
    `|---|---:|---:|---:|---:|---:|---:|---:|\n${rows}\n`,
);

// snarkjs may retain worker handles after its last prove. Results are durable
// at this point, so exit explicitly to keep the benchmark command bounded.
process.exit(0);
