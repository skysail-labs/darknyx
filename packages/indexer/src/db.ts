/**
 * SQLite-backed fills store (built-in `node:sqlite` — zero native deps).
 *
 * The chain is the durable record; this DB is a by-order_id query accelerator
 * the watcher can rebuild from a cursor at any time. Upserts are idempotent
 * (keyed by signature+match+side) so re-scanning a confirmed window on reorg is
 * safe.
 */

import { DatabaseSync } from "node:sqlite";
import type { SettleFill } from "./decode.js";

export interface FillRow extends SettleFill {
  signature: string;
  slot: number;
}

// Amount-privacy: the on-chain settle ix no longer carries amounts, so
// the indexer stores commitments + a partial-fill flag only (no change_amount /
// clearing_price columns). Recovery v3 stores the consumed input's note-use TAG
// (v11 — the settle ix no longer carries the consumed commitment), the exact
// trade/change commitments, and an opaque `(trade, change)` ciphertext; only the
// order owner's viewing key can decrypt it.
const SCHEMA = `
CREATE TABLE IF NOT EXISTS fills (
  order_id              TEXT    NOT NULL,
  side                  TEXT    NOT NULL,
  match_id              TEXT    NOT NULL,
  signature             TEXT    NOT NULL,
  slot                  INTEGER NOT NULL,
  is_partial_fill       INTEGER NOT NULL,
  input_note_use_tag    TEXT    NOT NULL,
  trade_note_commitment TEXT    NOT NULL,
  change_note_commitment TEXT,
  batch_slot            TEXT    NOT NULL,
  ephemeral_pubkey      TEXT,
  output_enc            TEXT,
  created_at            INTEGER NOT NULL,
  PRIMARY KEY (signature, match_id, side)
);
CREATE INDEX IF NOT EXISTS idx_fills_order ON fills (order_id, slot);
CREATE TABLE IF NOT EXISTS cursor (
  id             INTEGER PRIMARY KEY CHECK (id = 0),
  last_signature TEXT,
  last_slot      INTEGER
);
`;

export class FillsDb {
  private db: DatabaseSync;

  constructor(path: string) {
    this.db = new DatabaseSync(path);
    this.db.exec("PRAGMA journal_mode = WAL;");

    // v11 changes the consumed-input column's MEANING from a Merkle-leaf
    // commitment to an unlinkable use tag. SQLite cannot drop the retired
    // `input_note_commitment TEXT NOT NULL` column in place; simply adding the
    // tag column leaves that old NOT NULL constraint active, so every new
    // insert (which correctly has no input commitment) fails.
    //
    // This database is a rebuildable locator cache, and no honest migration can
    // derive a tag from a legacy commitment without the private inner hash.
    // Drop only the incompatible fills table and recreate it below. Preserve
    // the cursor: legacy rows are intentionally invalidated by the clean v11
    // cutover, while ingestion continues from the last scanned signature.
    const existing = this.db
      .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'fills'")
      .get();
    if (existing) {
      const columns = this.db.prepare("PRAGMA table_info(fills)").all() as Array<{
        name: string;
      }>;
      const names = new Set(columns.map((column) => column.name));
      // Drop on the retired column itself, not merely on absence of the new
      // one. An intermediate v11 build added `input_note_use_tag` while leaving
      // the old NOT NULL column behind; a later boot must repair that halfway
      // schema too.
      if (names.has("input_note_commitment")) {
        this.db.exec("DROP TABLE fills; DROP INDEX IF EXISTS idx_fills_order;");
      }
    }

    this.db.exec(SCHEMA);
    // Rebuildable locator DBs created before recovery v3 may still exist. Add
    // the new columns without pretending legacy rows are recoverable.
    for (const statement of [
      "ALTER TABLE fills ADD COLUMN input_note_use_tag TEXT",
      "ALTER TABLE fills ADD COLUMN trade_note_commitment TEXT",
      "ALTER TABLE fills ADD COLUMN output_enc TEXT",
    ]) {
      try {
        this.db.exec(statement);
      } catch (error) {
        if (!String(error).includes("duplicate column name")) throw error;
      }
    }
  }

  /** Idempotent insert of one settle ix's fill rows. */
  upsertFills(signature: string, slot: number, fills: SettleFill[]): void {
    const stmt = this.db.prepare(
      `INSERT OR IGNORE INTO fills
        (order_id, side, match_id, signature, slot, is_partial_fill,
         input_note_use_tag, trade_note_commitment, change_note_commitment,
         batch_slot, ephemeral_pubkey, output_enc, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    );
    const now = Date.now();
    for (const f of fills) {
      stmt.run(
        f.orderId,
        f.side,
        f.matchId,
        signature,
        slot,
        f.isPartialFill ? 1 : 0,
        f.inputNoteUseTag,
        f.tradeNoteCommitment,
        f.changeNoteCommitment,
        f.batchSlot,
        f.ephemeralPubkey,
        f.outputEnc,
        now,
      );
    }
  }

  /** All fills for an order id, oldest first, optionally from a slot cursor. */
  getFillsByOrder(orderId: string, sinceSlot = 0): FillRow[] {
    const rows = this.db
      .prepare(
        `SELECT order_id, side, match_id, signature, slot, is_partial_fill,
                input_note_use_tag, trade_note_commitment,
                change_note_commitment, batch_slot, ephemeral_pubkey, output_enc
           FROM fills
          WHERE order_id = ? AND slot >= ?
            AND input_note_use_tag IS NOT NULL
            AND trade_note_commitment IS NOT NULL
          ORDER BY slot ASC, side ASC`,
      )
      .all(orderId, sinceSlot) as Array<Record<string, unknown>>;
    return rows.map((r) => ({
      orderId: r.order_id as string,
      side: r.side as "buyer" | "seller",
      matchId: r.match_id as string,
      signature: r.signature as string,
      slot: r.slot as number,
      isPartialFill: (r.is_partial_fill as number) === 1,
      inputNoteUseTag: r.input_note_use_tag as string,
      tradeNoteCommitment: r.trade_note_commitment as string,
      changeNoteCommitment: (r.change_note_commitment as string | null) ?? null,
      batchSlot: r.batch_slot as string,
      ephemeralPubkey: (r.ephemeral_pubkey as string | null) ?? null,
      outputEnc: (r.output_enc as string | null) ?? null,
    }));
  }

  getCursor(): { lastSignature: string | null; lastSlot: number | null } {
    const row = this.db
      .prepare("SELECT last_signature, last_slot FROM cursor WHERE id = 0")
      .get() as
      | { last_signature: string | null; last_slot: number | null }
      | undefined;
    return {
      lastSignature: row?.last_signature ?? null,
      lastSlot: row?.last_slot ?? null,
    };
  }

  setCursor(lastSignature: string, lastSlot: number): void {
    this.db
      .prepare(
        `INSERT INTO cursor (id, last_signature, last_slot) VALUES (0, ?, ?)
         ON CONFLICT(id) DO UPDATE SET last_signature = excluded.last_signature,
                                       last_slot = excluded.last_slot`,
      )
      .run(lastSignature, lastSlot);
  }

  close(): void {
    this.db.close();
  }
}
