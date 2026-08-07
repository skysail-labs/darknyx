/**
 * Daemon persistence — `node:sqlite` (Node 22+, zero native deps).
 *
 * Two tables:
 *   - **notes** — the client's UTXO set. Implements the SDK `NoteStore`
 *     interface so the SDK's fills/settlement plumbing can write change notes
 *     straight through (`subscribeFills`, `recoverFillFromChain`, deposits).
 *   - **orders** — the daemon's `ManagedOrder` records, so a crash + restart
 *     can rebuild the lifecycle state machines instead of losing in-flight
 *     orders.
 *
 * The chain + encrypted seed remain the durable roots for NOTE recovery; this
 * DB is a local cache that can be rebuilt from them. The deterministic order
 * id/trading-key high-water mark is different: unmatched orders never reach
 * L1, so it lives in the separate authenticated `order-sequence` sidecar and
 * must be backed up with the keystore. bigints are stored as decimal TEXT
 * (sqlite has no native 256-bit integer); byte arrays as lowercase hex TEXT.
 */

import { DatabaseSync, type StatementSync } from "node:sqlite";
import type { NoteStore, StoredNote } from "@darknyx/sdk";

import { TERMINAL_PHASES } from "./types.js";
import type { ManagedOrder, OrderPhase, Side } from "./types.js";

const toHex = (b: Uint8Array): string => Buffer.from(b).toString("hex");
const fromHex = (h: string): Uint8Array =>
  Uint8Array.from(Buffer.from(h, "hex"));

const SCHEMA = `
CREATE TABLE IF NOT EXISTS notes (
  commitment        TEXT PRIMARY KEY,
  token_mint        TEXT NOT NULL,
  amount            TEXT NOT NULL,
  amount_sort       TEXT NOT NULL,
  owner_commitment  TEXT NOT NULL,
  inner_hash        TEXT NOT NULL,
  leaf_index        TEXT,
  order_id          TEXT,
  consumed_commitment TEXT
);
CREATE INDEX IF NOT EXISTS idx_notes_order ON notes (order_id);

CREATE TABLE IF NOT EXISTS orders (
  order_id            TEXT PRIMARY KEY,
  seed_index          INTEGER NOT NULL,
  symbol              TEXT NOT NULL,
  side                TEXT NOT NULL,
  price_raw           TEXT NOT NULL,
  size_raw            TEXT NOT NULL,
  phase               TEXT NOT NULL,
  merge_in_flight     INTEGER NOT NULL,
  pending_change_notes INTEGER NOT NULL,
  collateral_commitment TEXT,
  settlement_failure_reason TEXT,
  settlement_unlock_slot INTEGER,
  created_at          INTEGER NOT NULL,
  updated_at          INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_orders_phase ON orders (phase);
`;

interface NoteRow {
  commitment: string;
  token_mint: string;
  amount: string;
  owner_commitment: string;
  inner_hash: string;
  leaf_index: string | null;
  order_id: string | null;
  consumed_commitment: string | null;
}

const U64_MAX = 18_446_744_073_709_551_615n;

/** Lexicographically sortable decimal encoding for an unsigned u64. */
function amountSortKey(amount: bigint): string {
  if (amount < 0n || amount > U64_MAX) {
    throw new Error(`note amount must fit u64, got ${amount}`);
  }
  return amount.toString().padStart(20, "0");
}

interface OrderRow {
  order_id: string;
  seed_index: number;
  symbol: string;
  side: string;
  price_raw: string;
  size_raw: string;
  phase: string;
  merge_in_flight: number;
  pending_change_notes: number;
  collateral_commitment: string | null;
  settlement_failure_reason: string | null;
  settlement_unlock_slot: number | null;
  created_at: number;
  updated_at: number;
}

function rowToNote(r: NoteRow): StoredNote {
  const note: StoredNote = {
    commitment: r.commitment,
    tokenMint: fromHex(r.token_mint),
    amount: BigInt(r.amount),
    ownerCommitment: BigInt(r.owner_commitment),
    innerHash: BigInt(r.inner_hash),
  };
  if (r.leaf_index !== null) note.leafIndex = BigInt(r.leaf_index);
  if (r.order_id !== null) note.orderId = r.order_id;
  if (r.consumed_commitment !== null) {
    note.consumedCommitment = r.consumed_commitment;
  }
  return note;
}

function rowToOrder(r: OrderRow): ManagedOrder {
  return {
    orderId: r.order_id,
    seedIndex: r.seed_index,
    symbol: r.symbol,
    side: r.side as Side,
    priceRaw: BigInt(r.price_raw),
    sizeRaw: BigInt(r.size_raw),
    phase: r.phase as OrderPhase,
    mergeInFlight: r.merge_in_flight === 1,
    pendingChangeNotes: r.pending_change_notes,
    collateralCommitment: r.collateral_commitment ?? undefined,
    settlementFailureReason: r.settlement_failure_reason ?? undefined,
    settlementUnlockSlot: r.settlement_unlock_slot ?? undefined,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  };
}

/**
 * Local sqlite store. Implements {@link NoteStore} (the SDK UTXO interface) and
 * adds managed-order CRUD for crash recovery. Sync methods — sqlite is
 * synchronous, and `NoteStore` accepts `void | Promise<void>` returns.
 */
export class DaemonStore implements NoteStore {
  private readonly db: DatabaseSync;
  readonly isEphemeral: boolean;
  private readonly putNoteStmt: StatementSync;
  private readonly getNoteStmt: StatementSync;
  private readonly listNotesStmt: StatementSync;
  private readonly deleteNoteStmt: StatementSync;
  private readonly notesByOrderStmt: StatementSync;
  private readonly pendingLeafNotesStmt: StatementSync;
  private readonly selectCollateralStmt: StatementSync;
  private readonly putOrderStmt: StatementSync;
  private readonly getOrderStmt: StatementSync;
  private readonly listOrdersStmt: StatementSync;
  private readonly listActiveOrdersStmt: StatementSync;
  private readonly maxSeedIndexStmt: StatementSync;

  constructor(path: string) {
    this.isEphemeral = path === ":memory:";
    this.db = new DatabaseSync(path);
    this.db.exec("PRAGMA journal_mode = WAL;");
    this.db.exec(SCHEMA);
    // Existing development databases may predate the anchor-free memo schema.
    // Add the new provenance column without trusting or reusing anchor indices.
    const columns = this.db
      .prepare("PRAGMA table_info(notes)")
      .all() as unknown as Array<{ name: string }>;
    if (!columns.some((column) => column.name === "consumed_commitment")) {
      this.db.exec("ALTER TABLE notes ADD COLUMN consumed_commitment TEXT");
    }
    if (!columns.some((column) => column.name === "amount_sort")) {
      this.db.exec("ALTER TABLE notes ADD COLUMN amount_sort TEXT");
    }
    // Run on every open until no NULL remains. If power is lost after ALTER
    // but during backfill, the next boot resumes rather than treating a
    // half-migrated database as complete.
    const amountRows = this.db
      .prepare("SELECT commitment, amount FROM notes WHERE amount_sort IS NULL")
      .all() as unknown as Array<{ commitment: string; amount: string }>;
    if (amountRows.length > 0) {
      const backfill = this.db.prepare(
        "UPDATE notes SET amount_sort = ? WHERE commitment = ?",
      );
      for (const row of amountRows) {
        backfill.run(amountSortKey(BigInt(row.amount)), row.commitment);
      }
    }
    const orderColumns = this.db
      .prepare("PRAGMA table_info(orders)")
      .all() as unknown as Array<{ name: string }>;
    if (
      !orderColumns.some(
        (column) => column.name === "settlement_failure_reason",
      )
    ) {
      this.db.exec(
        "ALTER TABLE orders ADD COLUMN settlement_failure_reason TEXT",
      );
    }
    if (
      !orderColumns.some((column) => column.name === "settlement_unlock_slot")
    ) {
      this.db.exec(
        "ALTER TABLE orders ADD COLUMN settlement_unlock_slot INTEGER",
      );
    }
    if (!orderColumns.some((column) => column.name === "symbol")) {
      this.db.exec(
        "ALTER TABLE orders ADD COLUMN symbol TEXT NOT NULL DEFAULT 'UNKNOWN'",
      );
    }
    this.db.exec(`
      CREATE INDEX IF NOT EXISTS idx_notes_spendable_amount
        ON notes (token_mint, amount_sort) WHERE leaf_index IS NOT NULL;
      CREATE INDEX IF NOT EXISTS idx_notes_pending_leaf
        ON notes (commitment) WHERE order_id IS NOT NULL AND leaf_index IS NULL;
      PRAGMA synchronous = NORMAL;
    `);

    this.putNoteStmt = this.db.prepare(
      `INSERT INTO notes
         (commitment, token_mint, amount, amount_sort, owner_commitment,
          inner_hash, leaf_index, order_id, consumed_commitment)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(commitment) DO UPDATE SET
         token_mint = excluded.token_mint,
         amount = excluded.amount,
         amount_sort = excluded.amount_sort,
         owner_commitment = excluded.owner_commitment,
         inner_hash = excluded.inner_hash,
         leaf_index = excluded.leaf_index,
         order_id = excluded.order_id,
         consumed_commitment = excluded.consumed_commitment`,
    );
    this.getNoteStmt = this.db.prepare(
      "SELECT * FROM notes WHERE commitment = ?",
    );
    this.listNotesStmt = this.db.prepare("SELECT * FROM notes");
    this.deleteNoteStmt = this.db.prepare(
      "DELETE FROM notes WHERE commitment = ?",
    );
    this.notesByOrderStmt = this.db.prepare(
      "SELECT * FROM notes WHERE order_id = ?",
    );
    this.pendingLeafNotesStmt = this.db.prepare(
      `SELECT * FROM notes
        WHERE order_id IS NOT NULL AND leaf_index IS NULL`,
    );
    this.selectCollateralStmt = this.db.prepare(
      `SELECT n.* FROM notes n
        WHERE n.token_mint = ?
          AND n.leaf_index IS NOT NULL
          AND n.amount_sort >= ?
          AND NOT EXISTS (
            SELECT 1 FROM orders o
             WHERE o.phase IN ('pending', 'open')
               AND (o.collateral_commitment = n.commitment
                    OR o.order_id = n.order_id)
          )
        ORDER BY n.amount_sort ASC, n.rowid ASC
        LIMIT 1`,
    );
    this.putOrderStmt = this.db.prepare(
      `INSERT INTO orders
         (order_id, seed_index, symbol, side, price_raw, size_raw, phase,
          merge_in_flight, pending_change_notes, collateral_commitment,
          settlement_failure_reason, settlement_unlock_slot, created_at,
          updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(order_id) DO UPDATE SET
         seed_index = excluded.seed_index,
         symbol = excluded.symbol,
         side = excluded.side,
         price_raw = excluded.price_raw,
         size_raw = excluded.size_raw,
         phase = excluded.phase,
         merge_in_flight = excluded.merge_in_flight,
         pending_change_notes = excluded.pending_change_notes,
         collateral_commitment = excluded.collateral_commitment,
         settlement_failure_reason = excluded.settlement_failure_reason,
         settlement_unlock_slot = excluded.settlement_unlock_slot,
         updated_at = excluded.updated_at`,
    );
    this.getOrderStmt = this.db.prepare(
      "SELECT * FROM orders WHERE order_id = ?",
    );
    this.listOrdersStmt = this.db.prepare(
      "SELECT * FROM orders ORDER BY created_at ASC",
    );
    const terminal = [...TERMINAL_PHASES];
    const placeholders = terminal.map(() => "?").join(", ");
    this.listActiveOrdersStmt = this.db.prepare(
      `SELECT * FROM orders
        WHERE phase NOT IN (${placeholders})
        ORDER BY created_at ASC`,
    );
    this.maxSeedIndexStmt = this.db.prepare(
      "SELECT MAX(seed_index) AS m FROM orders",
    );
  }

  // ── NoteStore ──

  put(rec: StoredNote): void {
    this.putNoteStmt.run(
      rec.commitment,
      toHex(rec.tokenMint),
      rec.amount.toString(),
      amountSortKey(rec.amount),
      rec.ownerCommitment.toString(),
      rec.innerHash.toString(),
      rec.leafIndex !== undefined ? rec.leafIndex.toString() : null,
      rec.orderId ?? null,
      rec.consumedCommitment ?? null,
    );
  }

  get(commitment: string): StoredNote | undefined {
    const row = this.getNoteStmt.get(commitment) as NoteRow | undefined;
    return row ? rowToNote(row) : undefined;
  }

  list(): StoredNote[] {
    const rows = this.listNotesStmt.all() as unknown as NoteRow[];
    return rows.map(rowToNote);
  }

  delete(commitment: string): void {
    this.deleteNoteStmt.run(commitment);
  }

  /** Notes that came from a given order's continuation fills. */
  notesByOrder(orderId: string): StoredNote[] {
    const rows = this.notesByOrderStmt.all(orderId) as unknown as NoteRow[];
    return rows.map(rowToNote);
  }

  /** Change notes waiting for their settlement leaf, filtered in SQLite. */
  listPendingLeafNotes(): StoredNote[] {
    return (this.pendingLeafNotesStmt.all() as unknown as NoteRow[]).map(
      rowToNote,
    );
  }

  /** One indexed best-fit lookup, including live-order lock exclusion. */
  selectCollateral(
    tokenMint: Uint8Array,
    minAmount: bigint,
  ): StoredNote | undefined {
    if (minAmount > U64_MAX) return undefined;
    const row = this.selectCollateralStmt.get(
      toHex(tokenMint),
      amountSortKey(minAmount),
    ) as NoteRow | undefined;
    return row ? rowToNote(row) : undefined;
  }

  // ── Managed orders ──

  putOrder(o: ManagedOrder): void {
    this.putOrderStmt.run(
      o.orderId,
      o.seedIndex,
      o.symbol ?? "UNKNOWN",
      o.side,
      o.priceRaw.toString(),
      o.sizeRaw.toString(),
      o.phase,
      o.mergeInFlight ? 1 : 0,
      o.pendingChangeNotes,
      o.collateralCommitment ?? null,
      o.settlementFailureReason ?? null,
      o.settlementUnlockSlot ?? null,
      o.createdAt,
      o.updatedAt,
    );
  }

  getOrder(orderId: string): ManagedOrder | undefined {
    const row = this.getOrderStmt.get(orderId) as OrderRow | undefined;
    return row ? rowToOrder(row) : undefined;
  }

  listOrders(): ManagedOrder[] {
    const rows = this.listOrdersStmt.all() as unknown as OrderRow[];
    return rows.map(rowToOrder);
  }

  /** Non-terminal orders — the set to resume after a restart. */
  /**
   * Non-terminal orders — the set to resume and reconcile after a restart.
   *
   * The terminal set is DERIVED from `TERMINAL_PHASES` rather than written out
   * in the SQL. It used to be a hand-written list that omitted `'expired'`, so
   * this query resumed expired orders as live; the test that appeared to cover
   * it exercised only two of the five phases, so neither the omission nor the
   * divergence was caught (SW-11). Building the placeholders from the shared
   * constant makes the two physically unable to drift.
   */
  listActiveOrders(): ManagedOrder[] {
    const rows = this.listActiveOrdersStmt.all(
      ...TERMINAL_PHASES,
    ) as unknown as OrderRow[];
    return rows.map(rowToOrder);
  }

  /** Highest `seed_index` seen — the daemon derives the next order from +1. */
  maxSeedIndex(): number {
    const row = this.maxSeedIndexStmt.get() as { m: number | null } | undefined;
    return row?.m ?? -1;
  }

  close(): void {
    this.db.close();
  }
}
