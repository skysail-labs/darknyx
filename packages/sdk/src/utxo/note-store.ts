/**
 * Local change-note store (Phase 8).
 *
 * A `ChangeNoteRecord` is everything the client needs to later WITHDRAW a
 * continuation change note (the `withdraw` notePlaintext shape + the
 * commitment + provenance). The TEE never holds these — the client builds
 * them from a verified `FillMemo` (see `orders/fill-memo.ts`).
 */

export interface ChangeNoteRecord {
  /** 32-byte note commitment (hex) — the store key. */
  commitment: string;
  /** Withdraw plaintext: the v2 note opening. */
  tokenMint: Uint8Array;
  amount: bigint;
  ownerCommitment: bigint;
  /** v2 single inner_hash. */
  innerHash: bigint;
  // ── provenance ──
  /** 16-byte order this change note continued (hex). */
  orderId: string;
  /** Anchor-pool index that produced it. */
  anchorIndex: number;
}

/** Minimal pluggable store interface — back it with IndexedDB / a file / etc. */
export interface NoteStore {
  put(rec: ChangeNoteRecord): Promise<void> | void;
  get(commitment: string): Promise<ChangeNoteRecord | undefined> | ChangeNoteRecord | undefined;
  list(): Promise<ChangeNoteRecord[]> | ChangeNoteRecord[];
}

/** Default in-memory store (sufficient for tests + ephemeral sessions). */
export class InMemoryNoteStore implements NoteStore {
  private readonly map = new Map<string, ChangeNoteRecord>();
  put(rec: ChangeNoteRecord): void {
    this.map.set(rec.commitment, rec);
  }
  get(commitment: string): ChangeNoteRecord | undefined {
    return this.map.get(commitment);
  }
  list(): ChangeNoteRecord[] {
    return [...this.map.values()];
  }
}
