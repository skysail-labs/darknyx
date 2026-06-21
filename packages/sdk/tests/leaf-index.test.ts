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
} from "../src/utxo/leaf-index.js";

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
    expect(leafIndexFromLogs([line], NOTE_CREATED, NOTE_CREATED_OFF)).toBe(42n);
  });

  it("reads NoteMerged leaf_index (different body offset)", () => {
    const line = logLine(
      NOTE_MERGED,
      1 + 32 + 32 + 1 + 8 + 32,
      NOTE_MERGED_OFF,
      1000n,
    );
    expect(leafIndexFromLogs([line], NOTE_MERGED, NOTE_MERGED_OFF)).toBe(1000n);
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
      leafIndexFromLogs([other], NOTE_CREATED, NOTE_CREATED_OFF),
    ).toBeNull();
  });

  it("ignores non-event log lines and picks the matching one", () => {
    const logs = [
      "Program C63v… invoke [1]",
      "Program log: Instruction: Deposit",
      logLine(NOTE_CREATED, 1 + 8 + 32 + 32 + 8 + 32, NOTE_CREATED_OFF, 5n),
      "Program C63v… success",
    ];
    expect(leafIndexFromLogs(logs, NOTE_CREATED, NOTE_CREATED_OFF)).toBe(5n);
  });

  it("returns null on a truncated event body", () => {
    // disc present but body too short to hold the leaf_index.
    const short = `Program data: ${Buffer.concat([Buffer.from(NOTE_CREATED), Buffer.alloc(4)]).toString("base64")}`;
    expect(
      leafIndexFromLogs([short], NOTE_CREATED, NOTE_CREATED_OFF),
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
    expect(noteCreatedFromLogs([noteCreatedLine(3, 17n)])).toEqual({
      treeId: 3,
      leafIndex: 17n,
    });
  });

  it("returns null when no NoteCreated event is present", () => {
    expect(
      noteCreatedFromLogs(["Program log: Instruction: Deposit"]),
    ).toBeNull();
  });
});
