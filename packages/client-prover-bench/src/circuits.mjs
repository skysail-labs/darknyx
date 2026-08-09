import { createHash } from "node:crypto";
import { access, readFile, stat } from "node:fs/promises";
import { constants } from "node:fs";
import { resolve } from "node:path";

export const CIRCUITS = Object.freeze({
  wallet_create: { build: "valid_wallet_create", warmRuns: 100 },
  deposit: { build: "valid_deposit", warmRuns: 100 },
  input: { build: "valid_input", warmRuns: 300 },
  spend: { build: "valid_spend", warmRuns: 100 },
  merge_k2: { build: "valid_merge_k2", warmRuns: 100 },
  merge_k4: { build: "valid_merge_k4", warmRuns: 100 },
});

export function repoRoot() {
  return resolve(import.meta.dirname, "../../..");
}

export function circuitArtifacts(name, root = repoRoot()) {
  const descriptor = CIRCUITS[name];
  if (!descriptor) {
    throw new Error(
      `unknown circuit '${name}'; expected one of ${Object.keys(CIRCUITS).join(", ")}`,
    );
  }
  const buildDir = resolve(root, "circuits/build", descriptor.build);
  return {
    ...descriptor,
    name,
    buildDir,
    wasm: resolve(buildDir, "circuit_js/circuit.wasm"),
    zkey: resolve(buildDir, "circuit_final.zkey"),
    verificationKey: resolve(buildDir, "verification_key.json"),
    nativeWitness: resolve(buildDir, "circuit_cpp/native-witness"),
  };
}

export async function requireArtifacts(artifacts, { native = false } = {}) {
  const required = [
    artifacts.wasm,
    artifacts.zkey,
    artifacts.verificationKey,
    ...(native ? [artifacts.nativeWitness] : []),
  ];
  for (const path of required) await access(path, constants.R_OK);
}

export async function artifactMetadata(artifacts) {
  const entries = {};
  for (const [kind, path] of [
    ["wasm", artifacts.wasm],
    ["zkey", artifacts.zkey],
    ["verification_key", artifacts.verificationKey],
  ]) {
    const [bytes, info] = await Promise.all([readFile(path), stat(path)]);
    entries[kind] = {
      bytes: info.size,
      sha256: createHash("sha256").update(bytes).digest("hex"),
    };
  }
  return entries;
}

export function selectedCircuits(value) {
  if (!value || value === "all") return Object.keys(CIRCUITS);
  const selected = value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
  for (const name of selected) circuitArtifacts(name);
  return selected;
}
