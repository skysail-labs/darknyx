/**
 * Client-side UTXO wallet — balance + collateral coin-selection over the note
 * set.
 *
 * Nyx has no account→balance server mapping (a deliberate privacy choice): a
 * user's balance is the sum of their own unspent notes, exactly like a Bitcoin
 * wallet sums its UTXOs. Notes come from deposits (recorded at deposit time) and
 * trade-change (recovered via the fills WS/indexer) — both land in the same
 * `NoteStore`. "Unspent" is the on-chain note status (a note is spent once its
 * `ConsumedNote` PDA exists). Everything is recoverable from the seed + the
 * indexer, so nothing is owed to the user in a ledger we keep.
 */

import type { NoteStore, StoredNote } from "../utxo/note-store.js";
import { isDepositNote } from "../utxo/note-store.js";
import type { NoteStatus } from "../client.js";

export interface WalletNoteView {
  commitment: string;
  tokenMint: Uint8Array;
  amount: bigint;
  source: "deposit" | "fill";
  status: NoteStatus;
}

/** Result of `selectCollateral`. */
export type CollateralSelection =
  | { ok: true; note: StoredNote }
  /** No single note covers it, but the spendable set does → merge then order. */
  | { ok: false; reason: "merge-needed"; candidates: StoredNote[]; total: bigint }
  /** Even the full spendable set is below `required`. */
  | { ok: false; reason: "insufficient-funds"; total: bigint };

export interface WalletDeps {
  store: NoteStore;
  /** On-chain status of a note by its commitment hex. */
  noteStatus: (commitmentHex: string) => Promise<NoteStatus> | NoteStatus;
}

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const ascending = (a: StoredNote, b: StoredNote) => (a.amount < b.amount ? -1 : a.amount > b.amount ? 1 : 0);

/** Max input notes a single merge can consume (the largest VALID_MERGE circuit). */
export const MAX_MERGE_NOTES = 4;

/**
 * Performs ONE on-chain merge of the given (≤4) notes and returns the resulting
 * merged note. The implementation MUST prune the input notes from the store and
 * `put` the merged note (so subsequent balances + selection are correct).
 */
export type MergeFn = (notes: StoredNote[]) => Promise<StoredNote>;

/** Result of `selectForMerge`. */
export type MergeSelection =
  /** These ≤4 notes sum ≥ required — one merge suffices. */
  | { ok: true; notes: StoredNote[] }
  /** The 4 largest don't reach `required` but the full set does → merge these 4, then re-select. */
  | { ok: false; reason: "chain-needed"; notes: StoredNote[]; total: bigint }
  | { ok: false; reason: "insufficient-funds"; total: bigint };

export class Wallet {
  constructor(private readonly deps: WalletDeps) {}

  /** Every stored note with its current on-chain status (optionally filtered). */
  async listNotes(
    opts: { mint?: Uint8Array; spendableOnly?: boolean } = {},
  ): Promise<WalletNoteView[]> {
    const mintHex = opts.mint ? hex(opts.mint) : undefined;
    const out: WalletNoteView[] = [];
    for (const n of await this.deps.store.list()) {
      if (mintHex && hex(n.tokenMint) !== mintHex) continue;
      const status = await this.deps.noteStatus(n.commitment);
      if (opts.spendableOnly && status !== "active") continue;
      out.push({
        commitment: n.commitment,
        tokenMint: n.tokenMint,
        amount: n.amount,
        source: isDepositNote(n) ? "deposit" : "fill",
        status,
      });
    }
    return out;
  }

  /** Σ of spendable (status `active`) note amounts, optionally for one mint. */
  async getBalance(mint?: Uint8Array): Promise<bigint> {
    const spendable = await this.listNotes({ mint, spendableOnly: true });
    return spendable.reduce((s, n) => s + n.amount, 0n);
  }

  /**
   * Pick the smallest single spendable note that covers `required` for `mint`
   * (the over-collateral coin-selection — lock it and the surplus comes back as
   * a change note). When no single note covers `required` but the spendable set
   * does, return `merge-needed` (the deferred note-merge primitive is the
   * integration seam); when even the set is short, `insufficient-funds`.
   */
  async selectCollateral(required: bigint, mint: Uint8Array): Promise<CollateralSelection> {
    const spendable = await this.spendableNotes(mint);

    const fitting = spendable.filter((n) => n.amount >= required).sort(ascending);
    if (fitting.length > 0) return { ok: true, note: fitting[0] };

    const total = spendable.reduce((s, n) => s + n.amount, 0n);
    if (total >= required) {
      // Largest-first: the natural set to feed a merge.
      const candidates = [...spendable].sort((a, b) => -ascending(a, b));
      return { ok: false, reason: "merge-needed", candidates, total };
    }
    return { ok: false, reason: "insufficient-funds", total };
  }

  /**
   * Pick a set of spendable notes to merge so the result covers `required` for
   * `mint`. Greedy LARGEST-first (fewest inputs → cheapest proof), capped at the
   * merge circuit's max (4): `ok` = these ≤4 sum ≥ required (one merge);
   * `chain-needed` = the 4 largest fall short but the whole set covers it (merge
   * these 4, then re-select — `consolidate` chains); else `insufficient-funds`.
   */
  async selectForMerge(required: bigint, mint: Uint8Array): Promise<MergeSelection> {
    const spendable = (await this.spendableNotes(mint)).sort((a, b) => -ascending(a, b)); // largest-first
    const total = spendable.reduce((s, n) => s + n.amount, 0n);
    if (total < required) return { ok: false, reason: "insufficient-funds", total };

    const pick: StoredNote[] = [];
    let sum = 0n;
    for (const n of spendable) {
      pick.push(n);
      sum += n.amount;
      if (sum >= required || pick.length === MAX_MERGE_NOTES) break;
    }
    if (sum >= required) return { ok: true, notes: pick };
    return { ok: false, reason: "chain-needed", notes: spendable.slice(0, MAX_MERGE_NOTES), total };
  }

  /**
   * Consolidate spendable notes into a SINGLE note ≥ `required` for `mint`,
   * merging + chaining as needed, and return it. `mergeFn` performs each on-chain
   * merge (and prunes inputs + stores the merged note). If a single note already
   * covers `required`, returns it without merging.
   */
  async consolidate(required: bigint, mint: Uint8Array, mergeFn: MergeFn): Promise<StoredNote> {
    // Bounded: each merge reduces the note count by ≥1, so this terminates.
    for (let guard = 0; guard < 64; guard++) {
      const spendable = await this.spendableNotes(mint);
      const single = spendable.filter((n) => n.amount >= required).sort(ascending)[0];
      if (single) return single;

      const sel = await this.selectForMerge(required, mint);
      if (!sel.ok && sel.reason === "insufficient-funds") {
        throw new Error(`consolidate: insufficient funds (have ${sel.total}, need ${required})`);
      }
      const toMerge = sel.notes;
      if (toMerge.length < 2) throw new Error("consolidate: nothing to merge");
      await mergeFn(toMerge);
    }
    throw new Error("consolidate: exceeded merge iteration budget");
  }

  /** Spendable (status `active`) StoredNotes for a mint — the full opening. */
  private async spendableNotes(mint: Uint8Array): Promise<StoredNote[]> {
    const mintHex = hex(mint);
    const out: StoredNote[] = [];
    for (const n of await this.deps.store.list()) {
      if (hex(n.tokenMint) !== mintHex) continue;
      if ((await this.deps.noteStatus(n.commitment)) === "active") out.push(n);
    }
    return out;
  }
}

/** Structural view of `DarkPoolClient.getNoteStatus` — avoids an import cycle. */
export interface NoteStatusProvider {
  getNoteStatus(noteCommitment: Uint8Array): Promise<{ status: NoteStatus }>;
}

/** Build a `Wallet` backed by a client's on-chain note-status lookup. */
export function walletFromClient(provider: NoteStatusProvider, store: NoteStore): Wallet {
  return new Wallet({
    store,
    noteStatus: async (commitmentHex) =>
      (await provider.getNoteStatus(Uint8Array.from(Buffer.from(commitmentHex, "hex")))).status,
  });
}
