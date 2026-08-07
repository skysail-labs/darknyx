import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { DurableOrderSequence } from "../src/order-sequence.js";

const dirs: string[] = [];
const seed = new Uint8Array(64).fill(0x5a);

function tempPath(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "darknyx-sequence-"));
  dirs.push(dir);
  return path.join(dir, "orders.seq");
}

afterEach(() => {
  for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true });
});

describe("DurableOrderSequence", () => {
  it("persists a reservation before the caller records an order", () => {
    const file = tempPath();
    const sequence = DurableOrderSequence.create(file, seed);
    expect(sequence.reserve()).toBe(0);

    // Simulate a crash before SQLite receives the order. The reopened root has
    // still burned index zero, so a failed placement can create only a gap.
    const reopened = DurableOrderSequence.open(file, seed);
    expect(reopened.nextIndex).toBe(1);
    expect(reopened.reserve()).toBe(1);
    expect(fs.statSync(file).mode & 0o077).toBe(0);
  });

  it("advances for a legacy DB high-water but never rolls back", () => {
    const file = tempPath();
    const sequence = DurableOrderSequence.create(file, seed, 4);
    sequence.advanceTo(9);
    sequence.advanceTo(2);
    expect(DurableOrderSequence.open(file, seed).nextIndex).toBe(9);
  });

  it("rejects tampering and the wrong master seed", () => {
    const file = tempPath();
    DurableOrderSequence.create(file, seed, 7);
    const parsed = JSON.parse(fs.readFileSync(file, "utf8")) as {
      next_index: number;
    };
    parsed.next_index = 0;
    fs.writeFileSync(file, JSON.stringify(parsed), { mode: 0o600 });
    expect(() => DurableOrderSequence.open(file, seed)).toThrow(
      /authentication failed/,
    );

    DurableOrderSequence.create(file, seed, 7, true);
    expect(() =>
      DurableOrderSequence.open(file, new Uint8Array(64).fill(1)),
    ).toThrow(/authentication failed/);
  });
});
