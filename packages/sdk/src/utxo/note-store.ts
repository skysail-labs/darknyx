/**
 * Local note store — the client's UTXO set.
 *
 * Every record is everything the client needs to later spend a note (the v2
 * opening + commitment) plus its provenance. The TEE never holds these. Two
 * sources flow in:
 *   - **fill** (trade + continuation notes): built from a verified `FillMemo`
 *     or the recovery-v3 chain envelope;
 *   - **deposit/merge**: recorded live or rebuilt by `recoverNotesFromChain`.
 *
 * The wallet (`wallet/wallet.ts`) reads this set to compute balances + select
 * collateral. A deposit or merge note carries its chain leaf position; a fill
 * note additionally carries `orderId` plus the exact consumed input commitment
 * that derived it. Every chain-recovered note carries its exact shard + leaf
 * position when the event was available.
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
  // ── provenance ──
  /** Its leaf index in the on-chain tree, when known. */
  leafIndex?: bigint;
  /** Merkle-tree shard containing `leafIndex`. */
  treeId?: number;
  /** Fill (continuation change) note: the order it continued (16-byte hex). */
  orderId?: string;
  /** Fill note: exact input commitment consumed to produce it. */
  consumedCommitment?: string;
}

/**
 * Back-compat alias — the fills path constructs records with `orderId` +
 * `consumedCommitment` set. Prefer `StoredNote` for new code.
 */
export type ChangeNoteRecord = StoredNote;

/** True for deposit/merge-sourced notes (fill notes carry an `orderId`). */
export function isDepositNote(n: StoredNote): boolean {
  return n.orderId === undefined;
}

/** Minimal pluggable store interface — back it with IndexedDB / a file / etc. */
export interface NoteStore {
  put(rec: StoredNote): Promise<void> | void;
  get(
    commitment: string,
  ): Promise<StoredNote | undefined> | StoredNote | undefined;
  list(): Promise<StoredNote[]> | StoredNote[];
  /** Remove a note (e.g. after it's merged/spent). Optional — implement it for
   *  correct balances after consolidation. */
  delete?(commitment: string): Promise<void> | void;
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
  delete(commitment: string): void {
    this.map.delete(commitment);
  }
}
