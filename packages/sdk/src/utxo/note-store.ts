/**
 * Local note store — the client's UTXO set.
 *
 * Every record is everything the client needs to later spend a note (the v2
 * opening + commitment) plus its provenance. The TEE never holds these. Two
 * sources flow in:
 *   - **fill** (continuation change notes): built from a verified `FillMemo`
 *     (`orders/fill-memo.ts`) or recovered from the indexer (`fills/history.ts`).
 *   - **deposit**: recorded by the client at deposit time (`utxo/deposit.ts`).
 *
 * The wallet (`wallet/wallet.ts`) reads this set to compute balances + select
 * collateral. Provenance fields are optional + mutually exclusive: a deposit
 * note carries `leafIndex`; a fill note carries `orderId` + `anchorIndex`.
 */

export interface StoredNote {
  /** 32-byte note commitment (hex) — the store key. */
  commitment: string;
  /** v2 note opening. */
  tokenMint: Uint8Array;
  amount: bigint;
  ownerCommitment: bigint;
  /** v2 single inner_hash. */
  innerHash: bigint;
  // ── provenance (exactly one group is set) ──
  /** Deposit note: its leaf index in the on-chain tree. */
  leafIndex?: bigint;
  /** Fill (continuation change) note: the order it continued (16-byte hex). */
  orderId?: string;
  /** Fill note: the anchor-pool index that produced it. */
  anchorIndex?: number;
}

/**
 * Back-compat alias — the fills path constructs records with `orderId` +
 * `anchorIndex` set. Prefer `StoredNote` for new code.
 */
export type ChangeNoteRecord = StoredNote;

/** True for deposit-sourced notes (carry `leafIndex`). */
export function isDepositNote(n: StoredNote): boolean {
  return n.leafIndex !== undefined;
}

/** Minimal pluggable store interface — back it with IndexedDB / a file / etc. */
export interface NoteStore {
  put(rec: StoredNote): Promise<void> | void;
  get(commitment: string): Promise<StoredNote | undefined> | StoredNote | undefined;
  list(): Promise<StoredNote[]> | StoredNote[];
}

/** Default in-memory store (sufficient for tests + ephemeral sessions). */
export class InMemoryNoteStore implements NoteStore {
  private readonly map = new Map<string, StoredNote>();
  put(rec: StoredNote): void {
    this.map.set(rec.commitment, rec);
  }
  get(commitment: string): StoredNote | undefined {
    return this.map.get(commitment);
  }
  list(): StoredNote[] {
    return [...this.map.values()];
  }
}
