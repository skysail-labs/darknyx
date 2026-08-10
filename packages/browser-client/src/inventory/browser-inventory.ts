import {
  bn254ToBE32,
  deriveNoteUseTag,
  noteCommitmentV2,
  type StoredNote,
} from "@darknyx/sdk/browser-inventory-crypto";
import {
  readyProofHandle,
  reservationId,
  type InventoryIntentPort,
  type ReservationOutcome,
} from "@darknyx/client-core/internal";
import type {
  BalanceView,
  ProofReadinessView,
  TraderIntentDraft,
} from "@darknyx/client-core";

import type { InventorySnapshotStore } from "./inventory-store.js";
import type {
  BrowserMarketInventoryConfig,
  CachedInputProof,
  FinalizedRootRing,
  InputProofProducer,
  InventoryNote,
  InventorySnapshot,
  RecoveryReport,
} from "./types.js";

const U64_MAX = (1n << 64n) - 1n;
const BPS_SCALE = 10_000n;
const HEX32 = /^[0-9a-f]{64}$/;

const emptySnapshot = (): InventorySnapshot => ({
  format: "darknyx-browser-inventory",
  version: 1,
  notes: [],
  proofs: [],
  reservations: [],
  roots: [],
});

const hex = (value: Uint8Array): string =>
  Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");

const fromHex32 = (value: string, label: string): Uint8Array => {
  if (!HEX32.test(value))
    throw new Error(`${label} must be lowercase 32-byte hex`);
  return Uint8Array.from(value.match(/../g) ?? [], (byte) =>
    Number.parseInt(byte, 16),
  );
};

const same = (left: Uint8Array, right: Uint8Array): boolean =>
  left.length === right.length &&
  left.every((value, index) => value === right[index]);

function canonicalU64(value: string, label: string): bigint {
  if (!/^(0|[1-9]\d*)$/.test(value))
    throw new Error(`${label} is not canonical`);
  const parsed = BigInt(value);
  if (parsed < 0n || parsed > U64_MAX) throw new Error(`${label} is not a u64`);
  return parsed;
}

function validateMarket(market: BrowserMarketInventoryConfig): void {
  if (!/^[A-Z0-9]+-[A-Z0-9]+$/.test(market.symbol)) {
    throw new Error(`invalid market symbol ${market.symbol}`);
  }
  fromHex32(market.baseMintHex, "base mint");
  fromHex32(market.quoteMintHex, "quote mint");
  if (market.baseMintHex === market.quoteMintHex) {
    throw new Error(`market ${market.symbol} has identical mints`);
  }
  if (market.priceScale <= 0n || market.priceScale > U64_MAX) {
    throw new Error(
      `market ${market.symbol} price scale must be a positive u64`,
    );
  }
  if (market.feeRateBps < 0n || market.feeRateBps > BPS_SCALE) {
    throw new Error(`market ${market.symbol} fee rate is out of range`);
  }
}

function cacheKey(fields: {
  noteCommitment: string;
  noteUseTag: string;
  treeId: number;
  merkleRoot: string;
  circuitVersion: string;
  provingKeyVersion: string;
}): string {
  return [
    fields.noteCommitment,
    fields.noteUseTag,
    String(fields.treeId),
    fields.merkleRoot,
    fields.circuitVersion,
    fields.provingKeyVersion,
  ].join(":");
}

function requiredCollateral(
  draft: TraderIntentDraft,
  market: BrowserMarketInventoryConfig,
): { mint: string; amount: bigint } {
  const base = canonicalU64(draft.baseAmountAtoms, "base amount");
  const price = canonicalU64(draft.limitPriceTicks, "limit price");
  if (base === 0n) throw new Error("base amount must be positive");
  if (draft.side === "bid" && price === 0n) {
    throw new Error("bid limit price must be positive");
  }
  const nominal =
    draft.side === "bid" ? (base * price) / market.priceScale : base;
  const fee = (nominal * market.feeRateBps) / BPS_SCALE;
  const amount = nominal + fee;
  if (amount > U64_MAX) throw new Error("fee-inclusive collateral exceeds u64");
  return {
    mint: draft.side === "bid" ? market.quoteMintHex : market.baseMintHex,
    amount: amount > 0n ? amount : 1n,
  };
}

function rootPosition(
  snapshot: InventorySnapshot,
  treeId: number,
  root: string,
): number {
  const ring = snapshot.roots.find((candidate) => candidate.treeId === treeId);
  return ring?.acceptedRoots.indexOf(root) ?? -1;
}

function validateRootRing(ring: FinalizedRootRing): FinalizedRootRing {
  if (!Number.isInteger(ring.treeId) || ring.treeId < 0 || ring.treeId > 255) {
    throw new Error(`tree id must be a u8, got ${ring.treeId}`);
  }
  if (!Number.isSafeInteger(ring.finalizedSlot) || ring.finalizedSlot < 0) {
    throw new Error("finalized root slot must be a non-negative safe integer");
  }
  if (ring.acceptedRoots.length === 0 || ring.acceptedRoots.length > 65) {
    throw new Error("root ring must contain 1..65 roots");
  }
  const roots = ring.acceptedRoots.map((root) => {
    fromHex32(root, "Merkle root");
    if (/^0+$/.test(root)) throw new Error("Merkle root cannot be all zero");
    return root;
  });
  if (new Set(roots).size !== roots.length) {
    throw new Error("root ring contains duplicate roots");
  }
  return { ...ring, acceptedRoots: roots };
}

export interface BrowserInventoryOptions {
  store: InventorySnapshotStore;
  markets: readonly BrowserMarketInventoryConfig[];
  circuitVersion: string;
  provingKeyVersion: string;
  /** Refresh while at least this many newer roots are ahead of a proof. */
  refreshAtRootPosition?: number;
  now?: () => number;
  randomId?: () => string;
}

export type RecoveryConsumptionVerifier = (
  noteUseTag: string,
  treeId: number,
) => Promise<boolean>;

/**
 * Trusted inventory-plane coordinator. It is deliberately exported only from
 * the package's internal composition entrypoint, never the page-facing API.
 */
export class BrowserInventory implements InventoryIntentPort {
  readonly #store: InventorySnapshotStore;
  readonly #markets: Map<string, BrowserMarketInventoryConfig>;
  readonly #circuitVersion: string;
  readonly #provingKeyVersion: string;
  readonly #refreshAtRootPosition: number;
  readonly #now: () => number;
  readonly #randomId: () => string;
  readonly #proving = new Set<string>();
  #snapshot: InventorySnapshot;
  #queue: Promise<void> = Promise.resolve();

  private constructor(
    options: BrowserInventoryOptions,
    snapshot: InventorySnapshot,
  ) {
    this.#store = options.store;
    this.#markets = new Map();
    for (const market of options.markets) {
      validateMarket(market);
      if (this.#markets.has(market.symbol)) {
        throw new Error(`duplicate market symbol ${market.symbol}`);
      }
      this.#markets.set(market.symbol, market);
    }
    if (this.#markets.size === 0)
      throw new Error("at least one market is required");
    this.#circuitVersion = options.circuitVersion;
    this.#provingKeyVersion = options.provingKeyVersion;
    this.#refreshAtRootPosition = options.refreshAtRootPosition ?? 48;
    if (
      !Number.isInteger(this.#refreshAtRootPosition) ||
      this.#refreshAtRootPosition < 1 ||
      this.#refreshAtRootPosition > 64
    ) {
      throw new Error("root refresh position must be in 1..64");
    }
    this.#now = options.now ?? Date.now;
    this.#randomId = options.randomId ?? (() => crypto.randomUUID());
    this.#snapshot = snapshot;
    this.#validateSnapshot();
  }

  static async create(
    options: BrowserInventoryOptions,
  ): Promise<BrowserInventory> {
    const snapshot = (await options.store.load()) ?? emptySnapshot();
    const inventory = new BrowserInventory(options, snapshot);
    let changed = false;
    for (const proof of inventory.#snapshot.proofs) {
      if (
        proof.circuitVersion !== inventory.#circuitVersion ||
        proof.provingKeyVersion !== inventory.#provingKeyVersion
      ) {
        proof.state = "stale";
        proof.invalidationReason = "artifact_changed";
        changed = true;
      }
    }
    if (changed) await inventory.#save();
    return inventory;
  }

  #serialized<T>(operation: () => Promise<T>): Promise<T> {
    const run = this.#queue.then(operation);
    this.#queue = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  #validateSnapshot(): void {
    if (
      this.#snapshot.format !== "darknyx-browser-inventory" ||
      this.#snapshot.version !== 1
    ) {
      throw new Error("unsupported browser inventory snapshot");
    }
    const commitments = new Set<string>();
    for (const note of this.#snapshot.notes) {
      fromHex32(note.commitment, "note commitment");
      fromHex32(note.noteUseTag, "note-use tag");
      if (commitments.has(note.commitment))
        throw new Error("duplicate inventory note");
      commitments.add(note.commitment);
      if (note.amount <= 0n || note.amount > U64_MAX) {
        throw new Error("inventory note amount must be a positive u64");
      }
      if (note.tokenMint.length !== 32)
        throw new Error("inventory mint must be 32 bytes");
      const shouldHaveReservation =
        note.state === "reserved" || note.state === "pending_settlement";
      if (shouldHaveReservation !== Boolean(note.reservationId)) {
        throw new Error("inventory reservation state is inconsistent");
      }
    }
    const reservationIds = new Set<string>();
    const reservedNotes = new Set<string>();
    for (const reservation of this.#snapshot.reservations) {
      reservationId(reservation.reservationId);
      if (reservationIds.has(reservation.reservationId)) {
        throw new Error("duplicate inventory reservation");
      }
      if (reservedNotes.has(reservation.noteCommitment)) {
        throw new Error("one note cannot back multiple reservations");
      }
      reservationIds.add(reservation.reservationId);
      reservedNotes.add(reservation.noteCommitment);
      const note = this.#snapshot.notes.find(
        (candidate) => candidate.commitment === reservation.noteCommitment,
      );
      if (!note || note.reservationId !== reservation.reservationId) {
        throw new Error("inventory reservation does not match its note");
      }
    }
    for (const note of this.#snapshot.notes) {
      if (
        note.reservationId !== undefined &&
        !reservedNotes.has(note.commitment)
      ) {
        throw new Error("inventory note has no durable reservation");
      }
    }
  }

  async #save(): Promise<void> {
    this.#validateSnapshot();
    await this.#store.save(this.#snapshot);
  }

  async listBalances(): Promise<readonly BalanceView[]> {
    return this.#serialized(async () => {
      const totals = new Map<
        string,
        { spendable: bigint; reserved: bigint; pending: bigint }
      >();
      for (const note of this.#snapshot.notes) {
        if (note.state === "consumed") continue;
        const mint = hex(note.tokenMint);
        const total = totals.get(mint) ?? {
          spendable: 0n,
          reserved: 0n,
          pending: 0n,
        };
        if (note.state === "spendable") total.spendable += note.amount;
        else if (note.state === "pending_settlement")
          total.pending += note.amount;
        else total.reserved += note.amount;
        totals.set(mint, total);
      }
      return [...totals.entries()]
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([mint, total]) => ({
          mint,
          spendableAtoms: total.spendable.toString(),
          reservedAtoms: total.reserved.toString(),
          pendingSettlementAtoms: total.pending.toString(),
        }));
    });
  }

  async proofReadiness(): Promise<ProofReadinessView> {
    return this.#serialized(async () => {
      let ready = 0;
      let stale = 0;
      for (const proof of this.#snapshot.proofs) {
        if (proof.state === "ready") {
          ready += 1;
        } else stale += 1;
      }
      return {
        ready,
        proving: this.#proving.size,
        stale,
      };
    });
  }

  async synchronizeFinalizedRoots(
    rings: readonly FinalizedRootRing[],
  ): Promise<void> {
    await this.#serialized(async () => {
      const next = rings.map(validateRootRing);
      const ids = new Set<number>();
      for (const ring of next) {
        if (ids.has(ring.treeId)) throw new Error("duplicate root-ring shard");
        ids.add(ring.treeId);
        const prior = this.#snapshot.roots.find(
          (root) => root.treeId === ring.treeId,
        );
        if (prior && ring.finalizedSlot < prior.finalizedSlot) {
          throw new Error("finalized root slot moved backwards");
        }
      }
      const updatedIds = new Set(next.map((ring) => ring.treeId));
      this.#snapshot.roots = [
        ...this.#snapshot.roots.filter((ring) => !updatedIds.has(ring.treeId)),
        ...next,
      ].sort((left, right) => left.treeId - right.treeId);
      for (const proof of this.#snapshot.proofs) {
        const position = rootPosition(
          this.#snapshot,
          proof.treeId,
          proof.merkleRoot,
        );
        if (position < 0) {
          proof.state = "stale";
          proof.invalidationReason = "root_evicted";
        } else {
          proof.rootHistoryPosition = position;
        }
      }
      await this.#save();
    });
  }

  async cacheReadyProof(
    noteCommitment: string,
    merkleRoot: string,
    proofBytes: Uint8Array,
  ): Promise<string> {
    return this.#serialized(async () => {
      const note = this.#snapshot.notes.find(
        (candidate) => candidate.commitment === noteCommitment,
      );
      if (!note || note.state === "consumed")
        throw new Error("proof note is unavailable");
      if (proofBytes.length !== 256)
        throw new Error("VALID_INPUT proof must be 256 bytes");
      const position = rootPosition(
        this.#snapshot,
        note.treeId ?? 0,
        merkleRoot,
      );
      if (position < 0)
        throw new Error("proof root is not finalized and accepted");
      const fields = {
        noteCommitment,
        noteUseTag: note.noteUseTag,
        treeId: note.treeId ?? 0,
        merkleRoot,
        circuitVersion: this.#circuitVersion,
        provingKeyVersion: this.#provingKeyVersion,
      };
      const key = cacheKey(fields);
      const existing = this.#snapshot.proofs.find(
        (proof) => proof.cacheKey === key,
      );
      if (existing) {
        existing.proofBytes = Uint8Array.from(proofBytes);
        existing.createdAtMs = this.#now();
        existing.rootHistoryPosition = position;
        existing.state = "ready";
        delete existing.invalidationReason;
        await this.#save();
        return existing.handle;
      }
      const handle = readyProofHandle(`proof-${this.#randomId()}`);
      this.#snapshot.proofs.push({
        ...fields,
        handle,
        cacheKey: key,
        proofBytes: Uint8Array.from(proofBytes),
        createdAtMs: this.#now(),
        rootHistoryPosition: position,
        state: "ready",
      });
      await this.#save();
      return handle;
    });
  }

  async reserveReadyIntent(
    draft: TraderIntentDraft,
  ): Promise<ReservationOutcome> {
    return this.#serialized(async () => {
      const market = this.#markets.get(draft.marketSymbol);
      if (!market) throw new Error(`unsupported market ${draft.marketSymbol}`);
      const required = requiredCollateral(draft, market);
      const candidates = this.#snapshot.notes
        .filter(
          (note) =>
            note.state === "spendable" &&
            hex(note.tokenMint) === required.mint &&
            note.amount >= required.amount &&
            note.leafIndex !== undefined,
        )
        .sort((left, right) =>
          left.amount < right.amount ? -1 : left.amount > right.amount ? 1 : 0,
        );
      for (const note of candidates) {
        const proof = this.#snapshot.proofs
          .filter(
            (candidate) =>
              candidate.noteCommitment === note.commitment &&
              candidate.state === "ready" &&
              candidate.circuitVersion === this.#circuitVersion &&
              candidate.provingKeyVersion === this.#provingKeyVersion &&
              rootPosition(
                this.#snapshot,
                candidate.treeId,
                candidate.merkleRoot,
              ) >= 0,
          )
          .sort(
            (left, right) =>
              left.rootHistoryPosition - right.rootHistoryPosition,
          )[0];
        if (!proof) continue;
        const id = reservationId(`reservation-${this.#randomId()}`);
        note.state = "reserved";
        note.reservationId = id;
        this.#snapshot.reservations.push({
          reservationId: id,
          noteCommitment: note.commitment,
          proofHandle: proof.handle,
          createdAtMs: this.#now(),
        });
        await this.#save();
        return {
          status: "ready",
          reservation: {
            reservationId: id,
            proof: readyProofHandle(proof.handle),
          },
        };
      }
      return { status: "not_ready", retryAfterMs: 250 };
    });
  }

  async releaseReservation(id: string): Promise<void> {
    await this.#serialized(async () => {
      const index = this.#snapshot.reservations.findIndex(
        (candidate) => candidate.reservationId === id,
      );
      if (index < 0) return;
      const [reservation] = this.#snapshot.reservations.splice(index, 1);
      const note = this.#snapshot.notes.find(
        (candidate) => candidate.commitment === reservation.noteCommitment,
      );
      if (
        note &&
        (note.state === "reserved" || note.state === "pending_settlement") &&
        note.reservationId === id
      ) {
        note.state = "spendable";
        delete note.reservationId;
      }
      await this.#save();
    });
  }

  async markPendingSettlement(id: string): Promise<void> {
    await this.#serialized(async () => {
      const reservation = this.#snapshot.reservations.find(
        (candidate) => candidate.reservationId === id,
      );
      if (!reservation) throw new Error("unknown inventory reservation");
      const note = this.#snapshot.notes.find(
        (candidate) => candidate.commitment === reservation.noteCommitment,
      );
      if (!note || note.state !== "reserved" || note.reservationId !== id) {
        throw new Error("inventory reservation is inconsistent");
      }
      note.state = "pending_settlement";
      await this.#save();
    });
  }

  async markConsumed(noteCommitment: string): Promise<void> {
    await this.#serialized(async () => {
      const note = this.#snapshot.notes.find(
        (candidate) => candidate.commitment === noteCommitment,
      );
      if (!note) return;
      note.state = "consumed";
      delete note.reservationId;
      this.#snapshot.reservations = this.#snapshot.reservations.filter(
        (reservation) => reservation.noteCommitment !== noteCommitment,
      );
      for (const proof of this.#snapshot.proofs) {
        if (proof.noteCommitment === noteCommitment) {
          proof.state = "stale";
          proof.invalidationReason = "note_consumed";
        }
      }
      await this.#save();
    });
  }

  async resolveReservedProof(
    reservation: string,
    proofHandle: string,
  ): Promise<{ note: InventoryNote; proof: CachedInputProof }> {
    return this.#serialized(async () => {
      const held = this.#snapshot.reservations.find(
        (candidate) =>
          candidate.reservationId === reservation &&
          candidate.proofHandle === proofHandle,
      );
      if (!held) throw new Error("reservation does not own this proof handle");
      const note = this.#snapshot.notes.find(
        (candidate) => candidate.commitment === held.noteCommitment,
      );
      const proof = this.#snapshot.proofs.find(
        (candidate) => candidate.handle === proofHandle,
      );
      if (
        !note ||
        note.state !== "reserved" ||
        note.reservationId !== reservation ||
        !proof ||
        proof.state !== "ready" ||
        rootPosition(this.#snapshot, proof.treeId, proof.merkleRoot) < 0
      ) {
        throw new Error("reserved proof is no longer usable");
      }
      return { note: structuredClone(note), proof: structuredClone(proof) };
    });
  }

  async recover(
    report: RecoveryReport,
    isConsumed: RecoveryConsumptionVerifier,
  ): Promise<void> {
    if (report.unresolvedSettlements > 0 || report.unresolvedMerges > 0) {
      throw new Error("seed-plus-chain recovery has unresolved owned outputs");
    }
    const verified: InventoryNote[] = [];
    for (const candidate of report.notes) {
      const commitment = await noteCommitmentV2(candidate);
      if (
        !same(
          commitment,
          fromHex32(candidate.commitment, "recovered commitment"),
        )
      ) {
        throw new Error("recovered note opening does not match its commitment");
      }
      const tag = hex(
        await deriveNoteUseTag(commitment, bn254ToBE32(candidate.innerHash)),
      );
      const treeId = candidate.treeId ?? 0;
      const consumed = await isConsumed(tag, treeId);
      verified.push({
        ...structuredClone(candidate),
        noteUseTag: tag,
        state: consumed
          ? "consumed"
          : candidate.leafIndex === undefined
            ? "locked"
            : "spendable",
      });
    }
    await this.#serialized(async () => {
      const priorByCommitment = new Map(
        this.#snapshot.notes.map((note) => [note.commitment, note]),
      );
      this.#snapshot.notes = verified.map((note) => {
        const prior = priorByCommitment.get(note.commitment);
        if (
          prior &&
          note.state !== "consumed" &&
          (prior.state === "reserved" || prior.state === "pending_settlement")
        ) {
          return {
            ...note,
            state: prior.state,
            reservationId: prior.reservationId,
          };
        }
        return note;
      });
      const present = new Set(
        this.#snapshot.notes
          .filter((note) => note.reservationId !== undefined)
          .map((note) => `${note.commitment}:${note.reservationId}`),
      );
      this.#snapshot.reservations = this.#snapshot.reservations.filter(
        (reservation) =>
          present.has(
            `${reservation.noteCommitment}:${reservation.reservationId}`,
          ),
      );
      const consumed = new Set(
        this.#snapshot.notes
          .filter((note) => note.state === "consumed")
          .map((note) => note.commitment),
      );
      for (const proof of this.#snapshot.proofs) {
        if (consumed.has(proof.noteCommitment)) {
          proof.state = "stale";
          proof.invalidationReason = "note_consumed";
        }
      }
      await this.#save();
    });
  }

  async refreshExpiringProofs(produce: InputProofProducer): Promise<number> {
    const requests = await this.#serialized(async () => {
      const out: Array<{ note: InventoryNote; root: string; treeId: number }> =
        [];
      for (const note of this.#snapshot.notes) {
        if (note.state !== "spendable" || note.leafIndex === undefined)
          continue;
        const treeId = note.treeId ?? 0;
        const ring = this.#snapshot.roots.find(
          (candidate) => candidate.treeId === treeId,
        );
        if (!ring) continue;
        const currentRoot = ring.acceptedRoots[0];
        const hasCurrent = this.#snapshot.proofs.some(
          (proof) =>
            proof.noteCommitment === note.commitment &&
            proof.merkleRoot === currentRoot &&
            proof.circuitVersion === this.#circuitVersion &&
            proof.provingKeyVersion === this.#provingKeyVersion &&
            proof.state === "ready",
        );
        const needsRefresh = this.#snapshot.proofs
          .filter((proof) => proof.noteCommitment === note.commitment)
          .every(
            (proof) =>
              proof.state === "stale" ||
              proof.rootHistoryPosition >= this.#refreshAtRootPosition,
          );
        if (
          !hasCurrent &&
          needsRefresh &&
          !this.#proving.has(note.commitment)
        ) {
          this.#proving.add(note.commitment);
          out.push({ note: structuredClone(note), root: currentRoot, treeId });
        }
      }
      return out;
    });
    let completed = 0;
    let firstError: unknown;
    for (const request of requests) {
      try {
        const result = await produce({
          ...request,
          circuitVersion: this.#circuitVersion,
          provingKeyVersion: this.#provingKeyVersion,
        });
        await this.cacheReadyProof(
          request.note.commitment,
          request.root,
          result.proofBytes,
        );
        completed += 1;
      } catch (error) {
        firstError ??= error;
      } finally {
        await this.#serialized(async () => {
          this.#proving.delete(request.note.commitment);
        });
      }
    }
    if (firstError !== undefined) throw firstError;
    return completed;
  }
}
