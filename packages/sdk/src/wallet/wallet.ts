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
    const mintHex = hex(mint);
    const spendable: StoredNote[] = [];
    for (const n of await this.deps.store.list()) {
      if (hex(n.tokenMint) !== mintHex) continue;
      if ((await this.deps.noteStatus(n.commitment)) === "active") spendable.push(n);
    }

    const fitting = spendable.filter((n) => n.amount >= required).sort(ascending);
    if (fitting.length > 0) return { ok: true, note: fitting[0] };

    const total = spendable.reduce((s, n) => s + n.amount, 0n);
    if (total >= required) {
      // Largest-first: the natural set to feed a future merge.
      const candidates = [...spendable].sort((a, b) => -ascending(a, b));
      return { ok: false, reason: "merge-needed", candidates, total };
    }
    return { ok: false, reason: "insufficient-funds", total };
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
