/**
 * Watcher tx-extraction + DB + HTTP query, with no live RPC: a synthetic gTFA
 * (jsonParsed) tx carrying one settle ix flows through extractFills → FillsDb →
 * GET /fills, and the gTFA scanner is injected to drive seedCursorToTip/pollOnce.
 */

import { createRequire } from "node:module";
import { describe, it, expect, afterEach } from "vitest";
import { PublicKey, type Connection } from "@solana/web3.js";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { rmSync } from "node:fs";
import {
  serializePayload,
  type MatchResultPayload,
} from "../../sdk/src/settlement/settle-builder.js";
import {
  extractFills,
  Watcher,
  type GtfaTx,
  type GtfaScan,
} from "../src/watcher.js";
import { base58Encode } from "../src/base58.js";
import { FillsDb } from "../src/db.js";
import { startServer } from "../src/server.js";
import { SETTLE_DISCRIMINATOR, DEFAULT_PROGRAM_ID } from "../src/index.js";

// `node:sqlite` is Node 22+ (unflagged on 24). On older runtimes (CI pins Node
// 20) the DB-backed tests skip; the pure extractFills test below still runs.
const HAS_SQLITE = (() => {
  try {
    createRequire(import.meta.url)("node:sqlite");
    return true;
  } catch {
    return false;
  }
})();

const fill = (len: number, b: number) => new Uint8Array(len).fill(b);
const hexN = (b: number, len: number) =>
  b.toString(16).padStart(2, "0").repeat(len);

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
    noteFeeBaseCommitment: fill(32, 0),
    noteFeeQuoteCommitment: fill(32, 0),
    buyerRelockOrderId: fill(16, 0),
    buyerRelockExpiry: 0n,
    sellerRelockOrderId: fill(16, 0),
    sellerRelockExpiry: 0n,
    batchSlot: 99n,
    fillRecovery: fill(128, 0),
  };
}

/** Real settle ix data shape: disc(8) ‖ tree_id(u8) ‖ payload ‖ match_index(1) ‖ 128 siblings.
 *  The leading tree_id (cross-shard output-shard id) must be present so the
 *  decoder's payload offset is tested against the true framing. */
function ixData(p: MatchResultPayload): Uint8Array {
  const body = serializePayload(p);
  const out = new Uint8Array(8 + 1 + body.length + 1 + 128);
  out.set(SETTLE_DISCRIMINATOR, 0);
  out[8] = 0x03; // tree_id — the byte the decoder must skip before the payload
  out.set(body, 9);
  return out;
}

const VAULT = new PublicKey(DEFAULT_PROGRAM_ID).toBase58();
const OTHER = new PublicKey(
  "So11111111111111111111111111111111111111112",
).toBase58();

/** A gTFA (jsonParsed) full tx with a non-vault ix + a vault settle ix. */
function gtfaTx(signature = "sig1", slot = 500): GtfaTx {
  return {
    slot,
    transaction: {
      signatures: [signature],
      message: {
        instructions: [
          { programId: OTHER, data: base58Encode(new Uint8Array([9, 9, 9])) }, // skipped
          { programId: VAULT, data: base58Encode(ixData(payload())) }, // 2 fills
        ],
      },
    },
    meta: { err: null },
  };
}

/** Stub connection — the gTFA scanner is injected, so rpcEndpoint is unused. */
const stubConn = { rpcEndpoint: "http://stub" } as unknown as Connection;

const dbs: FillsDb[] = [];
const dbPath = () =>
  join(tmpdir(), `nyx-idx-test-${Math.random().toString(36).slice(2)}.sqlite`);
afterEach(() => {
  for (const d of dbs.splice(0)) d.close();
});

describe("watcher extractFills", () => {
  it("pulls fills only from the vault settle ix", () => {
    const fills = extractFills(VAULT, gtfaTx());
    expect(fills).toHaveLength(2);
    expect(fills.map((f) => f.side).sort()).toEqual(["buyer", "seller"]);
  });
});

describe.skipIf(!HAS_SQLITE)("db + server", () => {
  it("stores fills idempotently and serves them by order_id", async () => {
    const path = dbPath();
    const db = new FillsDb(path);
    dbs.push(db);

    const fills = extractFills(VAULT, gtfaTx());
    db.upsertFills("sigABC", 500, fills);
    db.upsertFills("sigABC", 500, fills); // idempotent re-scan

    const buyer = hexN(0xaa, 16);
    const rows = db.getFillsByOrder(buyer);
    expect(rows).toHaveLength(1); // not duplicated
    expect(rows[0].isPartialFill).toBe(true);
    expect(rows[0].changeNoteCommitment).toBe(hexN(0xee, 32));
    expect(rows[0].signature).toBe("sigABC");

    const { server, port } = await startServer(db, 0);
    try {
      const health = await (
        await fetch(`http://127.0.0.1:${port}/health`)
      ).json();
      expect(health.ok).toBe(true);

      const res = await (
        await fetch(`http://127.0.0.1:${port}/fills?order_id=${buyer}`)
      ).json();
      expect(res.fills).toHaveLength(1);
      expect(res.fills[0].changeNoteCommitment).toBe(hexN(0xee, 32));

      const miss = await (
        await fetch(`http://127.0.0.1:${port}/fills?order_id=${hexN(0x00, 16)}`)
      ).json();
      expect(miss.fills).toHaveLength(0);
    } finally {
      server.close();
    }
    rmSync(path, { force: true });
  });

  it("pollOnce ingests fills from a gTFA page and advances the cursor", async () => {
    const path = dbPath();
    const db = new FillsDb(path);
    dbs.push(db);

    let calls = 0;
    const scan: GtfaScan = async (opts) => {
      calls += 1;
      if (calls === 1) {
        expect(opts.sortOrder).toBe("asc"); // oldest-first
        return { txs: [gtfaTx("sigPoll", 700)], nextToken: null };
      }
      return { txs: [], nextToken: null };
    };
    const w = new Watcher({
      connection: stubConn,
      programId: new PublicKey(VAULT),
      db,
      scan,
      log: () => {},
    });

    const n = await w.pollOnce();
    expect(n).toBe(2); // buyer + seller
    expect(db.getCursor()).toEqual({ lastSignature: "sigPoll", lastSlot: 700 });
    expect(db.getFillsByOrder(hexN(0xaa, 16))).toHaveLength(1);

    // Re-poll with no new txs → idempotent, cursor unchanged.
    expect(await w.pollOnce()).toBe(0);
    rmSync(path, { force: true });
  });

  it("seedCursorToTip seeds an empty cursor to the newest sig (no backfill)", async () => {
    const path = dbPath();
    const db = new FillsDb(path);
    dbs.push(db);
    const scan: GtfaScan = async (opts) => {
      expect(opts.sortOrder).toBe("desc"); // newest-first
      expect(opts.limit).toBe(1); // just the tip
      return { txs: [gtfaTx("tipSig", 999_999)], nextToken: null };
    };
    const w = new Watcher({
      connection: stubConn,
      programId: new PublicKey(VAULT),
      db,
      scan,
      log: () => {},
    });
    expect(await w.seedCursorToTip()).toBe(999_999);
    expect(db.getCursor()).toEqual({
      lastSignature: "tipSig",
      lastSlot: 999_999,
    });
    // seeding must NOT ingest any history
    expect(db.getFillsByOrder(hexN(0xaa, 16))).toHaveLength(0);
    rmSync(path, { force: true });
  });

  it("seedCursorToTip is a no-op once a cursor exists (never rewinds)", async () => {
    const path = dbPath();
    const db = new FillsDb(path);
    dbs.push(db);
    db.setCursor("existing", 42);
    let called = false;
    const scan: GtfaScan = async () => {
      called = true;
      return { txs: [], nextToken: null };
    };
    const w = new Watcher({
      connection: stubConn,
      programId: new PublicKey(VAULT),
      db,
      scan,
      log: () => {},
    });
    expect(await w.seedCursorToTip()).toBeNull();
    expect(called).toBe(false);
    expect(db.getCursor()).toEqual({ lastSignature: "existing", lastSlot: 42 });
    rmSync(path, { force: true });
  });
});
