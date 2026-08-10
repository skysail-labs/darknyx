import { createHash } from "node:crypto";
import { readFile, stat } from "node:fs/promises";
import { resolve } from "node:path";

const packageRoot = resolve(import.meta.dirname, "..");
const repositoryRoot = resolve(packageRoot, "../..");
const payload = JSON.parse(
  await readFile(
    resolve(packageRoot, "artifacts/client-artifacts.v1.payload.json"),
    "utf8",
  ),
);
const builds = {
  wallet_create: "valid_wallet_create",
  deposit: "valid_deposit",
  input: "valid_input",
  spend: "valid_spend",
  merge_k2: "valid_merge_k2",
  merge_k4: "valid_merge_k4",
};
const names = {
  wasm: "circuit_js/circuit.wasm",
  zkey: "circuit_final.zkey",
  verification_key: "verification_key.json",
};

for (const [circuit, build] of Object.entries(builds)) {
  for (const [kind, file] of Object.entries(names)) {
    const path = resolve(repositoryRoot, "circuits/build", build, file);
    const [bytes, metadata] = await Promise.all([readFile(path), stat(path)]);
    const expected = payload.circuits[circuit][kind];
    const sha256 = createHash("sha256").update(bytes).digest("hex");
    if (metadata.size !== expected.bytes || sha256 !== expected.sha256) {
      throw new Error(
        `${circuit}.${kind} does not match the release payload: ` +
          `${metadata.size}/${sha256} != ${expected.bytes}/${expected.sha256}`,
      );
    }
  }
}
process.stdout.write(
  `client artifact payload ${payload.artifact_set_id}: all six circuits verified\n`,
);
