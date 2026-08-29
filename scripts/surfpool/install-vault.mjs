#!/usr/bin/env node
/** Install the fingerprinted Darknyx vault SBF into a loopback Surfnet. */

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import { PublicKey } from "@solana/web3.js";

import { requireLoopbackRpc } from "./loopback.mjs";

const rpcUrl = process.env.SURFPOOL_RPC_URL ?? "http://127.0.0.1:18899";
requireLoopbackRpc(rpcUrl);

const programId =
  process.env.VAULT_PROGRAM_ID ??
  "C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx";
assert.equal(
  programId,
  "C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx",
  "qualification must use the canonical Darknyx vault program ID",
);
const programPath = resolve(
  process.env.VAULT_SBF_PATH ?? "target/deploy/vault.so",
);
const loaderId = new PublicKey("BPFLoaderUpgradeab1e11111111111111111111111");
const fingerprintPath = `${programPath}.fingerprint`;
const [program, fingerprint] = await Promise.all([
  readFile(programPath),
  readFile(fingerprintPath, "utf8"),
]);
assert.match(fingerprint, /^features=devnet-admin$/m);
assert.match(fingerprint, /^fingerprint=[0-9a-f]{64}$/m);

let id = 0;
async function rpc(method, params) {
  const response = await fetch(rpcUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: ++id, method, params }),
  });
  assert.equal(response.ok, true, `${method}: HTTP ${response.status}`);
  const body = await response.json();
  if (body.error) throw new Error(`${method}: ${JSON.stringify(body.error)}`);
  return body.result;
}

const chunkBytes = 2 * 1024 * 1024;
for (let offset = 0; offset < program.length; offset += chunkBytes) {
  const chunk = program.subarray(offset, offset + chunkBytes);
  await rpc("surfnet_writeProgram", [programId, chunk.toString("hex"), offset]);
}
const account = await rpc("getAccountInfo", [
  programId,
  { encoding: "base64", commitment: "confirmed" },
]);
assert.equal(account.value?.executable, true);
assert.equal(account.value?.owner, loaderId.toBase58());

// Upgradeable programs keep executable bytes in the loader-derived ProgramData
// account, after its 45-byte state header. The small Program account above only
// proves the pointer to this account.
const [programDataAddress] = await PublicKey.findProgramAddress(
  [new PublicKey(programId).toBytes()],
  loaderId,
);
const programDataAccount = await rpc("getAccountInfo", [
  programDataAddress.toBase58(),
  { encoding: "base64", commitment: "confirmed" },
]);
assert.equal(programDataAccount.value?.owner, loaderId.toBase58());
assert.equal(programDataAccount.value?.executable, false);
assert.ok(
  Array.isArray(programDataAccount.value?.data),
  "deployed ProgramData bytes are missing",
);
assert.equal(programDataAccount.value.data[1], "base64");
const rawProgramData = Buffer.from(programDataAccount.value.data[0], "base64");
assert.equal(rawProgramData.readUInt32LE(0), 3, "invalid ProgramData state");
const deployedProgram = rawProgramData.subarray(45);
const artifactSha256 = createHash("sha256").update(program).digest("hex");
const deployedSha256 = createHash("sha256")
  .update(deployedProgram)
  .digest("hex");
assert.equal(
  deployedSha256,
  artifactSha256,
  "deployed Surfnet program bytes differ from the built SBF artifact",
);

console.log(
  JSON.stringify(
    {
      result: "pass",
      rpcUrl,
      programId,
      programDataAddress: programDataAddress.toBase58(),
      programPath,
      bytes: program.length,
      artifactSha256,
      deployedSha256,
      deployedArtifactMatch: deployedSha256 === artifactSha256,
      fingerprint: fingerprint.trim().split("\n"),
    },
    null,
    2,
  ),
);
