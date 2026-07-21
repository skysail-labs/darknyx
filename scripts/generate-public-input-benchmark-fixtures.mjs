#!/usr/bin/env node
// Regenerates the three tiny proof fixtures used by the feature-gated litesvm
// verifier benchmark. The proving keys remain disposable under target/.

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { buildPoseidon } from "circomlibjs";
import * as snarkjs from "snarkjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const out = resolve(root, "target/public-input-benchmarks");
const tracked = resolve(root, "programs/vault/tests/fixtures");
const BN254_P = BigInt(
  "0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47",
);

const values = {
  merkle_root: 11n,
  fee_rate_bps: 30n,
  protocol_owner_commitment: 13n,
  base_mint_lo: 17n,
  base_mint_hi: 19n,
  quote_mint_lo: 23n,
  quote_mint_hi: 29n,
  price_scale: 100_000_000n,
};

function be32(value) {
  let v = BigInt(value);
  const bytes = new Uint8Array(32);
  for (let i = 31; i >= 0; i -= 1) {
    bytes[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  if (v !== 0n) throw new Error("field element does not fit 32 bytes");
  return bytes;
}

function g1(point, negate = false) {
  const x = BigInt(point[0]);
  const y = BigInt(point[1]);
  const encodedY = negate ? (BN254_P - y) % BN254_P : y;
  return Buffer.concat([Buffer.from(be32(x)), Buffer.from(be32(encodedY))]);
}

function g2(point) {
  return Buffer.concat([
    Buffer.from(be32(BigInt(point[0][1]))),
    Buffer.from(be32(BigInt(point[0][0]))),
    Buffer.from(be32(BigInt(point[1][1]))),
    Buffer.from(be32(BigInt(point[1][0]))),
  ]);
}

function onchainProof(proof) {
  const bytes = Buffer.concat([
    g1(proof.pi_a, true),
    g2(proof.pi_b),
    g1(proof.pi_c),
  ]);
  if (bytes.length !== 256) throw new Error(`unexpected proof size ${bytes.length}`);
  return bytes;
}

const poseidon = await buildPoseidon();
const poseidonFr = (inputs) =>
  BigInt(poseidon.F.toObject(poseidon(inputs.map((v) => poseidon.F.e(v)))));

const config = [
  values.fee_rate_bps,
  values.protocol_owner_commitment,
  values.base_mint_lo,
  values.base_mint_hi,
  values.quote_mint_lo,
  values.quote_mint_hi,
  values.price_scale,
];
const configDigest = poseidonFr([1001n, ...config]);
const fullDigest = poseidonFr([1002n, values.merkle_root, ...config]);
const stringify = (object) =>
  Object.fromEntries(Object.entries(object).map(([key, value]) => [key, value.toString()]));

const cases = [
  {
    n: 8,
    input: stringify({
      ...values,
      private_sum: Object.values(values).reduce((sum, value) => sum + value, 0n),
    }),
    expectedPublic: Object.values(values),
  },
  {
    n: 2,
    input: stringify({
      ...values,
      statement_digest: configDigest,
      private_root_copy: values.merkle_root,
    }),
    expectedPublic: [values.merkle_root, configDigest],
  },
  {
    n: 1,
    input: stringify({ ...values, statement_digest: fullDigest }),
    expectedPublic: [fullDigest],
  },
];

await mkdir(resolve(out, "fixture-inputs"), { recursive: true });
if (process.env.WRITE_TRACKED_FIXTURES === "1") {
  await mkdir(tracked, { recursive: true });
}

for (const bench of cases) {
  const dir = resolve(out, `verifier_pi${bench.n}`);
  const inputPath = resolve(out, "fixture-inputs", `verifier_pi${bench.n}.json`);
  await writeFile(inputPath, `${JSON.stringify(bench.input, null, 2)}\n`);
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    bench.input,
    resolve(dir, "circuit_js/circuit.wasm"),
    resolve(dir, "circuit_final.zkey"),
  );
  const vk = JSON.parse(await readFile(resolve(dir, "verification_key.json"), "utf8"));
  if (!(await snarkjs.groth16.verify(vk, publicSignals, proof))) {
    throw new Error(`verifier_pi${bench.n} proof did not verify`);
  }
  const expected = bench.expectedPublic.map(String);
  if (JSON.stringify(publicSignals) !== JSON.stringify(expected)) {
    throw new Error(
      `verifier_pi${bench.n} public order mismatch: ${JSON.stringify(publicSignals)} != ${JSON.stringify(expected)}`,
    );
  }
  const fixture = onchainProof(proof);
  const targetPath = resolve(out, `verifier_pi${bench.n}.proof.bin`);
  await writeFile(targetPath, fixture);
  if (process.env.WRITE_TRACKED_FIXTURES === "1") {
    await writeFile(resolve(tracked, `public_input_bench_pi${bench.n}.bin`), fixture);
  }
  console.log(
    `verifier_pi${bench.n}: nPublic=${publicSignals.length} proof=${fixture.length}B`,
  );
}

// circomlibjs/snarkjs may leave worker handles alive after the final proof.
// All awaited writes are complete here, so keep this command bounded in CI
// and local shells instead of waiting on implementation-owned handles.
process.exit(0);
