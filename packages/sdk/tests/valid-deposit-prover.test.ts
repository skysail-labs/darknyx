/** VALID_DEPOSIT Node prover roundtrip and negative witness coverage. */

import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { bn254ToBE32 } from "../src/keys/key-generators.js";
import { deriveDepositInnerHash } from "../src/utxo/deposit-inner.js";
import {
  noteCommitmentV2,
  ownerCommitment,
  pubkeyToFrPair,
} from "../src/utxo/note.js";
import { nodeValidDepositProver } from "../src/zk/valid-deposit-prover.js";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "..", "..", "..");
const wasm = resolve(
  repoRoot,
  "circuits/build/valid_deposit/circuit_js/circuit.wasm",
);
const zkey = resolve(
  repoRoot,
  "circuits/build/valid_deposit/circuit_final.zkey",
);
const ready = existsSync(wasm) && existsSync(zkey);
const suite = ready ? describe : describe.skip;

const be32ToBig = (bytes: Uint8Array): bigint => {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
};

suite("VALID_DEPOSIT prover", () => {
  const spendingKey = 123456789n;
  const ownerBlinding = 987654321n;
  const recoveryNonce = 112233445566778899n;
  const mint = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
  const amount = 5_015_000n;

  async function inputs() {
    const owner = await ownerCommitment(spendingKey, ownerBlinding);
    const inner = await deriveDepositInnerHash(
      bn254ToBE32(owner),
      bn254ToBE32(recoveryNonce),
    );
    const commitment = await noteCommitmentV2({
      tokenMint: mint,
      amount,
      ownerCommitment: owner,
      innerHash: be32ToBig(inner),
    });
    const [mintLo, mintHi] = pubkeyToFrPair(mint);
    return {
      noteCommitment: be32ToBig(commitment),
      tokenMint: [mintLo, mintHi] as [bigint, bigint],
      amount,
      recoveryNonce,
      spendingKey,
      ownerCommitmentBlinding: ownerBlinding,
    };
  }

  it("emits the canonical five public inputs and a 256-byte proof", async () => {
    const prover = nodeValidDepositProver({ wasmPath: wasm, zkeyPath: zkey });
    const witness = await inputs();
    const proof = await prover.prove(witness);
    expect(proof.piA).toHaveLength(64);
    expect(proof.piB).toHaveLength(128);
    expect(proof.piC).toHaveLength(64);
    expect(proof.publicInputs.map((value) => Buffer.from(value))).toEqual(
      [
        witness.noteCommitment,
        witness.tokenMint[0],
        witness.tokenMint[1],
        witness.amount,
        witness.recoveryNonce,
      ].map((value) => Buffer.from(bn254ToBE32(value))),
    );
  });

  it("rejects a commitment that does not match the private opening", async () => {
    const prover = nodeValidDepositProver({ wasmPath: wasm, zkeyPath: zkey });
    const witness = await inputs();
    await expect(
      prover.prove({ ...witness, noteCommitment: witness.noteCommitment + 1n }),
    ).rejects.toThrow();
  });

  it("rejects every altered public or private opening field", async () => {
    const prover = nodeValidDepositProver({ wasmPath: wasm, zkeyPath: zkey });
    const witness = await inputs();
    const altered = [
      { ...witness, tokenMint: [witness.tokenMint[0] + 1n, witness.tokenMint[1]] as [bigint, bigint] },
      { ...witness, amount: witness.amount + 1n },
      { ...witness, recoveryNonce: witness.recoveryNonce + 1n },
      { ...witness, spendingKey: witness.spendingKey + 1n },
      {
        ...witness,
        ownerCommitmentBlinding: witness.ownerCommitmentBlinding + 1n,
      },
    ];
    for (const invalid of altered) {
      await expect(prover.prove(invalid)).rejects.toThrow();
    }
  });

  it("rejects zero and out-of-range amounts before proving", async () => {
    const prover = nodeValidDepositProver({ wasmPath: wasm, zkeyPath: zkey });
    const witness = await inputs();
    await expect(prover.prove({ ...witness, amount: 0n })).rejects.toThrow(
      /positive u64/,
    );
    await expect(
      prover.prove({ ...witness, amount: 0x1_0000_0000_0000_0000n }),
    ).rejects.toThrow(/positive u64/);
  });
});
