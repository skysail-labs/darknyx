/**
 * Note-use tag parity across TS and Rust, plus the two properties the
 * construction exists for.
 *
 * The tag is the public consumption handle that replaced the note commitment at
 * lock / settle / withdraw / merge. It is derived in three places that must
 * agree byte-for-byte — `darkpool-crypto` (host + enclave), this SDK, and the
 * circuits — so a divergence here surfaces on devnet as a missing `NoteLock`
 * PDA, which names nothing useful.
 */

import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { deriveNoteUseTag } from "../src/utxo/note-use.js";
import { noteCommitmentV2 } from "../src/utxo/note.js";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "..", "..", "..");
const rustHelper = resolve(repoRoot, "target/debug/examples/note-use-tag");

const scalar = (value: number): Uint8Array => {
  const out = new Uint8Array(32);
  out[31] = value;
  return out;
};
const hex = (value: Uint8Array): string => Buffer.from(value).toString("hex");

describe("note-use tag", () => {
  it("is deterministic and input separated", async () => {
    const first = await deriveNoteUseTag(scalar(7), scalar(9));
    expect(await deriveNoteUseTag(scalar(7), scalar(9))).toEqual(first);
    expect(await deriveNoteUseTag(scalar(7), scalar(10))).not.toEqual(first);
    expect(await deriveNoteUseTag(scalar(8), scalar(9))).not.toEqual(first);
  });

  it("does not treat its two inputs as interchangeable", async () => {
    // A tag that ignored argument order would collide across unrelated notes.
    expect(await deriveNoteUseTag(scalar(7), scalar(9))).not.toEqual(
      await deriveNoteUseTag(scalar(9), scalar(7)),
    );
  });

  it.skipIf(!existsSync(rustHelper))("matches Rust byte-for-byte", async () => {
    const commitment = scalar(7);
    const inner = scalar(9);
    const rust = spawnSync(rustHelper, [hex(commitment), hex(inner)], {
      encoding: "utf8",
    });
    expect(rust.status, rust.stderr).toBe(0);
    expect(rust.stdout.trim()).toBe(
      hex(await deriveNoteUseTag(commitment, inner)),
    );
  });

  /**
   * THE property the construction exists for.
   *
   * A tag over `inner_hash` alone would leave amount, owner and mint unbound —
   * and at settle the input commitment is only a private witness, so a prover
   * could pair a real lock with an inflated amount and mint value. Feeding the
   * commitment in is what prevents that; each perturbation below must move the
   * tag.
   */
  it("binds every field of the note, not just the inner hash", async () => {
    const mint = scalar(0x11);
    const owner = 0x22n;
    const inner = 0x33n;
    const amount = 1_000n;

    const commit = (
      m: Uint8Array,
      a: bigint,
      o: bigint,
      i: bigint,
    ): Promise<Uint8Array> =>
      noteCommitmentV2({
        tokenMint: m,
        amount: a,
        ownerCommitment: o,
        innerHash: i,
      });

    const innerBytes = scalar(0x33);
    const base = await deriveNoteUseTag(
      await commit(mint, amount, owner, inner),
      innerBytes,
    );

    // Amount — the substitution attack: same inner, larger claimed value.
    expect(
      await deriveNoteUseTag(
        await commit(mint, 10_000n, owner, inner),
        innerBytes,
      ),
    ).not.toEqual(base);

    // Owner — otherwise one user could spend against another's lock.
    expect(
      await deriveNoteUseTag(
        await commit(mint, amount, 0x23n, inner),
        innerBytes,
      ),
    ).not.toEqual(base);

    // Mint — otherwise a quote note could be consumed as a base note.
    expect(
      await deriveNoteUseTag(
        await commit(scalar(0x12), amount, owner, inner),
        innerBytes,
      ),
    ).not.toEqual(base);
  });

  /**
   * Unlinkability, stated as a test: an observer holds the commitment (it is a
   * public Merkle leaf) and must not be able to derive the tag from it. Asserted
   * by showing one commitment yields different tags under different inners, so
   * the private input is load-bearing.
   */
  it("is not determined by the public commitment alone", async () => {
    const c = scalar(0x55);
    expect(await deriveNoteUseTag(c, scalar(1))).not.toEqual(
      await deriveNoteUseTag(c, scalar(2)),
    );
  });

  it("rejects malformed byte inputs", () => {
    expect(() => deriveNoteUseTag(new Uint8Array(31), scalar(1))).toThrow(
      /noteCommitment/,
    );
    expect(() => deriveNoteUseTag(scalar(1), new Uint8Array(33))).toThrow(
      /innerHash/,
    );
  });
});
