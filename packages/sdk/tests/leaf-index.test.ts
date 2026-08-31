/**
 * Unit tests for the race-proof leaf-index reader (`utxo/leaf-index.ts`).
 * `leafIndexFromLogs` is pure over a tx's `logMessages`, so we synthesize the
 * exact `Program data:` lines the vault's NoteCreated / NoteMerged events log.
 */

import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import {
  leafIndexFromLogs,
  noteCreatedFromLogs,
  noteMergedFromLogs,
} from "../src/utxo/leaf-index.js";

/** The vault, and a program that is not the vault. */
const VAULT = "C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx";
const ATTACKER = "AttackerPRoGram11111111111111111111111111111";

/** Bracket `lines` in `program`'s invocation frame, the way the runtime does. */
function scoped(program: string, depth: number, lines: string[]): string[] {
  return [
    `Program ${program} invoke [${depth}]`,
    ...lines,
    `Program ${program} consumed 4242 of 200000 compute units`,
    `Program ${program} success`,
  ];
}

/** The common case: one top-level vault instruction emitting `lines`. */
const vaultTx = (lines: string[]) => scoped(VAULT, 1, lines);

function disc(name: string): Uint8Array {
  return new Uint8Array(
    createHash("sha256").update(`event:${name}`).digest().subarray(0, 8),
  );
}
const NOTE_CREATED = disc("NoteCreated");
const NOTE_MERGED = disc("NoteMerged");
const NOTE_CREATED_OFF = 1; // tree_id(1) | leaf_index(8) | …
const NOTE_MERGED_OFF = 1 + 32 + 32 + 1; // tree_id(1) | commitment(32) | mint(32) | k(1) | leaf_index(8) | …

function logLine(
  d: Uint8Array,
  bodyLen: number,
  leafOffset: number,
  leafIndex: bigint,
): string {
  const body = Buffer.alloc(bodyLen, 0);
  body.writeBigUInt64LE(leafIndex, leafOffset);
  return `Program data: ${Buffer.concat([Buffer.from(d), body]).toString("base64")}`;
}

describe("leafIndexFromLogs", () => {
  it("reads NoteCreated leaf_index", () => {
    const line = logLine(
      NOTE_CREATED,
      1 + 8 + 32 + 32 + 8 + 32,
      NOTE_CREATED_OFF,
      42n,
    );
    expect(
      leafIndexFromLogs(vaultTx([line]), NOTE_CREATED, NOTE_CREATED_OFF, VAULT),
    ).toBe(42n);
  });

  it("reads NoteMerged leaf_index (different body offset)", () => {
    const line = logLine(
      NOTE_MERGED,
      1 + 32 + 32 + 1 + 8 + 32,
      NOTE_MERGED_OFF,
      1000n,
    );
    expect(
      leafIndexFromLogs(vaultTx([line]), NOTE_MERGED, NOTE_MERGED_OFF, VAULT),
    ).toBe(1000n);
  });

  it("returns null when no matching event is present", () => {
    const other = logLine(
      NOTE_MERGED,
      1 + 32 + 32 + 1 + 8 + 32,
      NOTE_MERGED_OFF,
      7n,
    );
    // Looking for NoteCreated, only a NoteMerged line present.
    expect(
      leafIndexFromLogs(
        vaultTx([other]),
        NOTE_CREATED,
        NOTE_CREATED_OFF,
        VAULT,
      ),
    ).toBeNull();
  });

  it("ignores non-event log lines and picks the matching one", () => {
    const logs = vaultTx([
      "Program log: Instruction: Deposit",
      logLine(NOTE_CREATED, 1 + 8 + 32 + 32 + 8 + 32, NOTE_CREATED_OFF, 5n),
    ]);
    expect(leafIndexFromLogs(logs, NOTE_CREATED, NOTE_CREATED_OFF, VAULT)).toBe(
      5n,
    );
  });

  it("returns null on a truncated event body", () => {
    // disc present but body too short to hold the leaf_index.
    const short = `Program data: ${Buffer.concat([Buffer.from(NOTE_CREATED), Buffer.alloc(4)]).toString("base64")}`;
    expect(
      leafIndexFromLogs(
        vaultTx([short]),
        NOTE_CREATED,
        NOTE_CREATED_OFF,
        VAULT,
      ),
    ).toBeNull();
  });
});

describe("noteCreatedFromLogs", () => {
  /** Build a NoteCreated `Program data:` line with a given tree_id + leaf_index. */
  function noteCreatedLine(treeId: number, leafIndex: bigint): string {
    const body = Buffer.alloc(1 + 8 + 32 + 32 + 8 + 32, 0);
    body.writeUInt8(treeId, 0); // tree_id at body offset 0
    body.writeBigUInt64LE(leafIndex, NOTE_CREATED_OFF); // leaf_index at offset 1
    return `Program data: ${Buffer.concat([Buffer.from(NOTE_CREATED), body]).toString("base64")}`;
  }

  it("reads (tree_id, leaf_index) from a NoteCreated event", () => {
    expect(
      noteCreatedFromLogs(vaultTx([noteCreatedLine(3, 17n)]), VAULT),
    ).toEqual({ treeId: 3, leafIndex: 17n });
  });

  it("returns null when no NoteCreated event is present", () => {
    expect(
      noteCreatedFromLogs(
        vaultTx(["Program log: Instruction: Deposit"]),
        VAULT,
      ),
    ).toBeNull();
  });
});

describe("noteMergedFromLogs", () => {
  it("reads and preserves the confirmed merged output identity", () => {
    const body = Buffer.alloc(1 + 32 + 32 + 1 + 8 + 32, 0);
    body.writeUInt8(2, 0);
    body.fill(0x44, 1, 33);
    body.fill(0x55, 33, 65);
    body.writeUInt8(4, 65);
    body.writeBigUInt64LE(73n, NOTE_MERGED_OFF);
    const line = `Program data: ${Buffer.concat([
      Buffer.from(NOTE_MERGED),
      body,
    ]).toString("base64")}`;

    expect(noteMergedFromLogs(vaultTx([line]), VAULT)).toEqual({
      treeId: 2,
      outputCommitment: new Uint8Array(32).fill(0x44),
      tokenMint: new Uint8Array(32).fill(0x55),
      k: 4,
      leafIndex: 73n,
    });
  });

  it("ignores a byte-identical merge event emitted by another program", () => {
    const line = logLine(
      NOTE_MERGED,
      1 + 32 + 32 + 1 + 8 + 32,
      NOTE_MERGED_OFF,
      73n,
    );
    expect(noteMergedFromLogs(scoped(ATTACKER, 1, [line]), VAULT)).toBeNull();
  });
});

// ── Provenance (SW-24) ──────────────────────────────────────────────────
//
// `Program data:` is `sol_log_data`, callable by any program, and these
// decoders read the logs of a transaction fetched by signature. The realistic
// attacker is a hostile RPC returning fabricated `logMessages`; a forged
// leaf_index makes the client's own note look unspendable. Same construction
// the enclave's Merkle sync had, where it was a Critical.
describe("event provenance", () => {
  function noteCreatedLine(treeId: number, leafIndex: bigint): string {
    const body = Buffer.alloc(1 + 8 + 32 + 32 + 8 + 32, 0);
    body.writeUInt8(treeId, 0);
    body.writeBigUInt64LE(leafIndex, NOTE_CREATED_OFF);
    return `Program data: ${Buffer.concat([Buffer.from(NOTE_CREATED), body]).toString("base64")}`;
  }

  it("ignores a byte-identical event emitted by another program", () => {
    const logs = [
      ...scoped(ATTACKER, 1, [noteCreatedLine(0, 999n)]),
      ...vaultTx([noteCreatedLine(3, 17n)]),
    ];
    expect(noteCreatedFromLogs(logs, VAULT)).toEqual({
      treeId: 3,
      leafIndex: 17n,
    });
  });

  it("returns null when only a foreign program emitted the event", () => {
    const logs = scoped(ATTACKER, 1, [noteCreatedLine(0, 999n)]);
    expect(noteCreatedFromLogs(logs, VAULT)).toBeNull();
    expect(
      leafIndexFromLogs(logs, NOTE_CREATED, NOTE_CREATED_OFF, VAULT),
    ).toBeNull();
  });

  it("ignores an event from a program the vault CPI'd into", () => {
    const logs = vaultTx([
      ...scoped(ATTACKER, 2, [noteCreatedLine(0, 999n)]),
      noteCreatedLine(3, 17n),
    ]);
    expect(noteCreatedFromLogs(logs, VAULT)).toEqual({
      treeId: 3,
      leafIndex: 17n,
    });
  });

  it("still reads the vault when it is itself the CPI callee", () => {
    // Scope tracking must not degenerate into a "depth === 1" check.
    const logs = scoped(
      ATTACKER,
      1,
      scoped(VAULT, 2, [noteCreatedLine(3, 17n)]),
    );
    expect(noteCreatedFromLogs(logs, VAULT)).toEqual({
      treeId: 3,
      leafIndex: 17n,
    });
  });

  it("does not let program log TEXT forge a scope marker", () => {
    // `msg!` content is program-controlled. If the invoke pattern were matched
    // before `Program log:` was discarded, this would open a vault frame.
    const logs = scoped(ATTACKER, 1, [
      `Program log: Program ${VAULT} invoke [1]`,
      noteCreatedLine(0, 999n),
    ]);
    expect(noteCreatedFromLogs(logs, VAULT)).toBeNull();
  });

  it("does not trust an unbracketed event", () => {
    // Truncated logs leave no open frame. A missing index throws a clear error
    // the caller handles; a forged one silently strands the note.
    expect(noteCreatedFromLogs([noteCreatedLine(3, 17n)], VAULT)).toBeNull();
  });
});
