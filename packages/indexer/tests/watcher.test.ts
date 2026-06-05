/**
 * Watcher tx-extraction + DB + HTTP query, end-to-end with no live RPC: a mocked
 * `getTransaction` response carrying one settle ix flows through extractFills →
 * FillsDb → GET /fills.
 */

import { createRequire } from "node:module";
import { describe, it, expect, afterEach } from "vitest";
import { PublicKey } from "@solana/web3.js";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { rmSync } from "node:fs";
import { serializePayload, type MatchResultPayload } from "../../sdk/src/settlement/settle-builder.js";
import { extractFills } from "../src/watcher.js";
import { FillsDb } from "../src/db.js";
import { startServer } from "../src/server.js";
import { SETTLE_DISCRIMINATOR, DEFAULT_PROGRAM_ID } from "../src/index.js";

// `node:sqlite` is Node 22+ (unflagged on 24). On older runtimes (CI pins Node
// 20) the DB-backed tests skip; the decode parity gate (decode.test.ts) and the
// pure extractFills test below still run everywhere.
const HAS_SQLITE = (() => {
  try {
    createRequire(import.meta.url)("node:sqlite");
    return true;
  } catch {
    return false;
  }
})();

const fill = (len: number, b: number) => new Uint8Array(len).fill(b);
const hexN = (b: number, len: number) => b.toString(16).padStart(2, "0").repeat(len);

function payload(): MatchResultPayload {
  return {
    matchId: fill(16, 0x11),
    noteAcommitment: fill(32, 0xa),
    noteBcommitment: fill(32, 0xb),
    noteCcommitment: fill(32, 0xc),
    noteDcommitment: fill(32, 0xd),
    noteEcommitment: fill(32, 0xee),
    noteFcommitment: fill(32, 0xff),
    nullifierA: fill(32, 0x1a),
    nullifierB: fill(32, 0x1b),
    orderIdA: fill(16, 0xaa),
    orderIdB: fill(16, 0xbb),
    baseAmount: 1000n,
    quoteAmount: 2000n,
    buyerChangeAmt: 111n,
    sellerChangeAmt: 222n,
    buyerFeeAmt: 3n,
    sellerFeeAmt: 4n,
    noteFeeBaseCommitment: fill(32, 0),
    noteFeeQuoteCommitment: fill(32, 0),
    buyerRelockOrderId: fill(16, 0),
    buyerRelockExpiry: 0n,
    sellerRelockOrderId: fill(16, 0),
    sellerRelockExpiry: 0n,
    clearingPrice: 1500n,
    batchSlot: 99n,
  };
}

function ixData(p: MatchResultPayload): Uint8Array {
  const body = serializePayload(p);
  const out = new Uint8Array(8 + body.length + 1 + 128);
  out.set(SETTLE_DISCRIMINATOR, 0);
  out.set(body, 8);
  return out;
}

const VAULT = new PublicKey(DEFAULT_PROGRAM_ID);
const OTHER = new PublicKey("So11111111111111111111111111111111111111112");

/** Build a minimal getTransaction-shaped object the watcher reads from. */
function mockTx(): any {
  const keys = [OTHER, VAULT];
  return {
    transaction: {
      message: {
        getAccountKeys: () => ({ get: (i: number) => keys[i] }),
        compiledInstructions: [
          { programIdIndex: 0, data: new Uint8Array([9, 9, 9]) }, // non-vault → skipped
          { programIdIndex: 1, data: ixData(payload()) }, // vault settle → 2 fills
        ],
      },
    },
    meta: { loadedAddresses: undefined },
  };
}

const dbs: FillsDb[] = [];
const dbPath = () => join(tmpdir(), `nyx-idx-test-${Math.random().toString(36).slice(2)}.sqlite`);
afterEach(() => {
  for (const d of dbs.splice(0)) d.close();
});

describe("watcher extractFills", () => {
  it("pulls fills only from the vault settle ix", () => {
    const fills = extractFills(VAULT, mockTx());
    expect(fills).toHaveLength(2);
    expect(fills.map((f) => f.side).sort()).toEqual(["buyer", "seller"]);
  });
});

describe.skipIf(!HAS_SQLITE)("db + server", () => {
  it("stores fills idempotently and serves them by order_id", async () => {
    const path = dbPath();
    const db = new FillsDb(path);
    dbs.push(db);

    const fills = extractFills(VAULT, mockTx());
    db.upsertFills("sigABC", 500, fills);
    db.upsertFills("sigABC", 500, fills); // idempotent re-scan

    const buyer = hexN(0xaa, 16);
    const rows = db.getFillsByOrder(buyer);
    expect(rows).toHaveLength(1); // not duplicated
    expect(rows[0].changeAmount).toBe("111");
    expect(rows[0].signature).toBe("sigABC");

    const { server, port } = await startServer(db, 0);
    try {
      const health = await (await fetch(`http://127.0.0.1:${port}/health`)).json();
      expect(health.ok).toBe(true);

      const res = await (await fetch(`http://127.0.0.1:${port}/fills?order_id=${buyer}`)).json();
      expect(res.fills).toHaveLength(1);
      expect(res.fills[0].changeNoteCommitment).toBe(hexN(0xee, 32));

      const miss = await (await fetch(`http://127.0.0.1:${port}/fills?order_id=${hexN(0x00, 16)}`)).json();
      expect(miss.fills).toHaveLength(0);
    } finally {
      server.close();
    }
    rmSync(path, { force: true });
  });

  it("advances the cursor", () => {
    const path = dbPath();
    const db = new FillsDb(path);
    dbs.push(db);
    expect(db.getCursor().lastSignature).toBeNull();
    db.setCursor("sigXYZ", 1234);
    expect(db.getCursor()).toEqual({ lastSignature: "sigXYZ", lastSlot: 1234 });
    rmSync(path, { force: true });
  });
});
