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
  BrowserOrderKind,
  BrowserOrderRecord,
  CachedInputProof,
  FinalizedRootRing,
  InputProofProducer,
  InventoryNote,
  InventorySnapshot,
  RecoveryReport,
} from "./types.js";
import { canonicalU64, U64_MAX } from "../canonical-u64.js";

const BPS_SCALE = 10_000n;
const HEX32 = /^[0-9a-f]{64}$/;

const emptySnapshot = (): InventorySnapshot => ({
  format: "darknyx-browser-inventory",
  version: 3,
  notes: [],
  proofs: [],
  reservations: [],
  roots: [],
  orders: [],
  nextOrderIndex: 0,
  nextDepositIndex: 0,
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

function ceilDiv(numerator: bigint, denominator: bigint): bigint {
  return (numerator + denominator - 1n) / denominator;
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
    draft.side === "bid" ? ceilDiv(base * price, market.priceScale) : base;
  const fee = ceilDiv(nominal * market.feeRateBps, BPS_SCALE);
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
export type RecoveryLockVerifier = (
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
      this.#snapshot.version !== 3
    ) {
      throw new Error("unsupported browser inventory snapshot");
    }
    const commitments = new Set<string>();
    const supportedMints = new Set(
      [...this.#markets.values()].flatMap((market) => [
        market.baseMintHex,
        market.quoteMintHex,
      ]),
    );
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
      if (!supportedMints.has(hex(note.tokenMint))) {
        throw new Error("inventory note mint is not served by this venue");
      }
      if (
        !Number.isInteger(note.treeId) ||
        note.treeId === undefined ||
        note.treeId < 0 ||
        note.treeId > 255
      ) {
        throw new Error("inventory note tree id must be a u8");
      }
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
    if (
      !Number.isSafeInteger(this.#snapshot.nextOrderIndex) ||
      this.#snapshot.nextOrderIndex < 0 ||
      this.#snapshot.nextOrderIndex > 0xffff_ffff
    ) {
      throw new Error("inventory order index is invalid");
    }
    if (
      !Number.isSafeInteger(this.#snapshot.nextDepositIndex) ||
      this.#snapshot.nextDepositIndex < 0 ||
      this.#snapshot.nextDepositIndex > 0xffff_ffff
    ) {
      throw new Error("inventory deposit index is invalid");
    }
    const orderIds = new Set<string>();
    const tradingIndices = new Set<number>();
    for (const order of this.#snapshot.orders) {
      if (!/^[0-9a-f]{32}$/.test(order.orderId)) {
        throw new Error("inventory order id must be lowercase 16-byte hex");
      }
      if (orderIds.has(order.orderId))
        throw new Error("duplicate inventory order");
      if (
        !Number.isSafeInteger(order.tradingIndex) ||
        order.tradingIndex < 0 ||
        order.tradingIndex >= this.#snapshot.nextOrderIndex
      ) {
        throw new Error("inventory trading index is invalid");
      }
      if (tradingIndices.has(order.tradingIndex)) {
        throw new Error("trading index cannot be reused");
      }
      fromHex32(order.noteCommitment, "order note commitment");
      canonicalU64(order.nextCancelNonce, "next cancel nonce");
      if (canonicalU64(order.nextCancelNonce, "next cancel nonce") === 0n) {
        throw new Error("next cancel nonce must be positive");
      }
      if (
        ![
          "submitting",
          "open",
          "pending_settlement",
          "partially_filled",
          "fully_filled",
          "settlement_failed",
          "cancelled",
          "expired",
          "closed",
          "ambiguous",
          "rejected",
        ].includes(order.kind)
      ) {
        throw new Error("inventory order lifecycle kind is invalid");
      }
      orderIds.add(order.orderId);
      tradingIndices.add(order.tradingIndex);
    }
  }

  async #save(): Promise<void> {
    this.#validateSnapshot();
    await this.#store.save(this.#snapshot);
  }

  async #mutate<T>(operation: () => T | Promise<T>): Promise<T> {
    const previous = structuredClone(this.#snapshot);
    try {
      const result = await operation();
      await this.#save();
      return result;
    } catch (error) {
      this.#snapshot = previous;
      throw error;
    }
  }

  #pruneProofs(noteCommitment: string): void {
    const held = new Set(
      this.#snapshot.reservations
        .filter((reservation) => reservation.noteCommitment === noteCommitment)
        .map((reservation) => reservation.proofHandle),
    );
    const readyToKeep = new Set(
      this.#snapshot.proofs
        .filter(
          (proof) =>
            proof.noteCommitment === noteCommitment && proof.state === "ready",
        )
        .sort((left, right) =>
          left.rootHistoryPosition !== right.rootHistoryPosition
            ? left.rootHistoryPosition - right.rootHistoryPosition
            : right.createdAtMs - left.createdAtMs,
        )
        .slice(0, 2)
        .map((proof) => proof.handle),
    );
    this.#snapshot.proofs = this.#snapshot.proofs.filter((proof) => {
      if (proof.noteCommitment !== noteCommitment) return true;
      if (held.has(proof.handle) || readyToKeep.has(proof.handle)) return true;
      if (proof.state === "ready") return false;
      return !["root_evicted", "artifact_changed", "note_consumed"].includes(
        proof.invalidationReason ?? "",
      );
    });
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

  /** Allocate a never-reused HD order/trading-key index and persist it first. */
  async allocateOrderIndex(): Promise<number> {
    return this.#serialized(() =>
      this.#mutate(async () => {
        if (this.#snapshot.nextOrderIndex > 0xffff_fffe) {
          throw new Error("browser order sequence is exhausted");
        }
        const index = this.#snapshot.nextOrderIndex;
        this.#snapshot.nextOrderIndex += 1;
        return index;
      }),
    );
  }

  /** Allocate and persist a never-reused deposit recovery-nonce index. */
  async allocateDepositIndex(): Promise<number> {
    return this.#serialized(() =>
      this.#mutate(async () => {
        if (this.#snapshot.nextDepositIndex > 0xffff_fffe) {
          throw new Error("browser deposit sequence is exhausted");
        }
        const index = this.#snapshot.nextDepositIndex;
        this.#snapshot.nextDepositIndex += 1;
        return index;
      }),
    );
  }

  async reserveAccountExact(
    mint: string,
    amount: bigint,
  ): Promise<{ note: InventoryNote; reservationId: string } | null> {
    fromHex32(mint, "selection mint");
    if (amount <= 0n || amount > U64_MAX)
      throw new Error("selection amount is invalid");
    return this.#serialized(() =>
      this.#mutate(async () => {
        const note = this.#snapshot.notes.find(
          (candidate) =>
            candidate.state === "spendable" &&
            candidate.leafIndex !== undefined &&
            hex(candidate.tokenMint) === mint &&
            candidate.amount === amount,
        );
        if (!note) return null;
        const id = reservationId(`account-${this.#randomId()}`);
        note.state = "reserved";
        note.reservationId = id;
        this.#snapshot.reservations.push({
          reservationId: id,
          noteCommitment: note.commitment,
          proofHandle: `account-operation-${id}`,
          createdAtMs: this.#now(),
        });
        return { note: structuredClone(note), reservationId: id };
      }),
    );
  }

  async reserveAccountMerge(
    mint: string,
  ): Promise<readonly { note: InventoryNote; reservationId: string }[]> {
    fromHex32(mint, "merge mint");
    return this.#serialized(() =>
      this.#mutate(async () => {
        const candidates = this.#snapshot.notes
          .filter(
            (note) =>
              note.state === "spendable" &&
              note.leafIndex !== undefined &&
              hex(note.tokenMint) === mint,
          )
          .sort(
            (left, right) =>
              left.treeId - right.treeId ||
              (left.amount < right.amount
                ? -1
                : left.amount > right.amount
                  ? 1
                  : 0),
          );
        const treeId = candidates.find(
          (candidate) =>
            candidates.filter((other) => other.treeId === candidate.treeId)
              .length >= 2,
        )?.treeId;
        if (treeId === undefined) return [];
        const selected = candidates
          .filter((candidate) => candidate.treeId === treeId)
          .slice(0, 4);
        if (selected.length < 2) return [];
        const held = selected.map((note) => {
          const id = reservationId(`account-${this.#randomId()}`);
          note.state = "reserved";
          note.reservationId = id;
          this.#snapshot.reservations.push({
            reservationId: id,
            noteCommitment: note.commitment,
            proofHandle: `account-operation-${id}`,
            createdAtMs: this.#now(),
          });
          return { note: structuredClone(note), reservationId: id };
        });
        return held;
      }),
    );
  }

  async assertAcceptedRoot(treeId: number, root: string): Promise<void> {
    fromHex32(root, "Merkle root");
    await this.#serialized(async () => {
      if (rootPosition(this.#snapshot, treeId, root) < 0) {
        throw new Error("operation Merkle root is not finalized and accepted");
      }
    });
  }

  async bindReservationToOrder(record: BrowserOrderRecord): Promise<void> {
    await this.#serialized(() =>
      this.#mutate(async () => {
        const reservation = this.#snapshot.reservations.find(
          (candidate) => candidate.reservationId === record.reservationId,
        );
        if (
          !reservation ||
          reservation.noteCommitment !== record.noteCommitment ||
          this.#snapshot.orders.some(
            (candidate) => candidate.orderId === record.orderId,
          )
        ) {
          throw new Error("order does not match a live inventory reservation");
        }
        this.#snapshot.orders.push(structuredClone(record));
      }),
    );
  }

  /** Burn and persist a strictly increasing nonce before asking the Worker to sign. */
  async allocateCancelNonce(orderId: string): Promise<string> {
    return this.#serialized(() =>
      this.#mutate(async () => {
        const order = this.#snapshot.orders.find(
          (candidate) => candidate.orderId === orderId,
        );
        if (!order) throw new Error("unknown browser order");
        const nonce = canonicalU64(order.nextCancelNonce, "next cancel nonce");
        if (nonce === 0n || nonce === U64_MAX) {
          throw new Error("cancel nonce sequence is exhausted");
        }
        order.nextCancelNonce = (nonce + 1n).toString();
        return nonce.toString();
      }),
    );
  }

  async listOrders(): Promise<readonly BrowserOrderRecord[]> {
    return this.#serialized(async () =>
      structuredClone(
        [...this.#snapshot.orders].sort(
          (left, right) => right.updatedAtMs - left.updatedAtMs,
        ),
      ),
    );
  }

  /**
   * Reconcile durable client reservations against the authenticated venue's
   * complete open-order snapshot. Call this only after finalized-chain
   * recovery has classified every owned note: an absent order may release its
   * reservation only when that recovery left the note reusable.
   */
  async reconcileVenueOpenOrders(
    openOrderIds: readonly string[],
  ): Promise<void> {
    const active = new Set<string>();
    for (const orderId of openOrderIds) {
      if (!/^[0-9a-f]{32}$/.test(orderId)) {
        throw new Error("venue open-order id must be lowercase 16-byte hex");
      }
      if (active.has(orderId)) {
        throw new Error("venue open-order snapshot contains a duplicate id");
      }
      active.add(orderId);
    }
    await this.#serialized(() =>
      this.#mutate(async () => {
        for (const order of this.#snapshot.orders) {
          if (
            ![
              "submitting",
              "open",
              "pending_settlement",
              "partially_filled",
              "ambiguous",
            ].includes(order.kind) ||
            active.has(order.orderId)
          ) {
            continue;
          }
          const note = this.#snapshot.notes.find(
            (candidate) => candidate.commitment === order.noteCommitment,
          );
          const reusable = Boolean(
            note &&
              (note.state === "reserved" ||
                note.state === "pending_settlement") &&
              note.reservationId === order.reservationId,
          );
          if (reusable && note) {
            // `recover()` preserves a reservation only when finalized chain
            // state says the note is neither consumed nor locked.
            note.state = "spendable";
            delete note.reservationId;
          }
          this.#snapshot.reservations = this.#snapshot.reservations.filter(
            (candidate) => candidate.reservationId !== order.reservationId,
          );
          order.kind = "closed";
          order.reason = reusable
            ? "Closed while this client was offline; finalized chain state confirms collateral is unlocked"
            : "Closed while this client was offline; finalized chain state keeps collateral unavailable";
          order.updatedAtMs = this.#now();
        }
      }),
    );
  }

  async order(orderId: string): Promise<BrowserOrderRecord | null> {
    return this.#serialized(async () => {
      const found = this.#snapshot.orders.find(
        (candidate) => candidate.orderId === orderId,
      );
      return found ? structuredClone(found) : null;
    });
  }

  async updateOrder(
    orderId: string,
    update: {
      kind: BrowserOrderKind;
      filledAtoms?: string;
      reason?: string;
      lockExpirySlot?: string;
    },
  ): Promise<void> {
    await this.#serialized(async () => {
      const order = this.#snapshot.orders.find(
        (candidate) => candidate.orderId === orderId,
      );
      if (!order) throw new Error("unknown browser order");
      order.kind = update.kind;
      order.updatedAtMs = this.#now();
      if (update.filledAtoms !== undefined)
        order.filledAtoms = update.filledAtoms;
      if (update.reason !== undefined) order.reason = update.reason;
      if (update.lockExpirySlot !== undefined) {
        order.lockExpirySlot = update.lockExpirySlot;
      }
      await this.#save();
    });
  }

  /** Settlement failure leaves an on-chain lock but no reusable reservation. */
  async markOrderLocked(orderId: string): Promise<void> {
    await this.#serialized(async () => {
      const order = this.#snapshot.orders.find(
        (candidate) => candidate.orderId === orderId,
      );
      if (!order) throw new Error("unknown browser order");
      const note = this.#snapshot.notes.find(
        (candidate) => candidate.commitment === order.noteCommitment,
      );
      if (note && note.state !== "consumed") {
        note.state = "locked";
        delete note.reservationId;
      }
      this.#snapshot.reservations = this.#snapshot.reservations.filter(
        (candidate) => candidate.reservationId !== order.reservationId,
      );
      await this.#save();
    });
  }

  async synchronizeFinalizedRoots(
    rings: readonly FinalizedRootRing[],
  ): Promise<void> {
    await this.#serialized(() =>
      this.#mutate(async () => {
        const next = rings.map(validateRootRing);
        const ids = new Set<number>();
        for (const ring of next) {
          if (ids.has(ring.treeId))
            throw new Error("duplicate root-ring shard");
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
          ...this.#snapshot.roots.filter(
            (ring) => !updatedIds.has(ring.treeId),
          ),
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
      }),
    );
  }

  async cacheReadyProof(
    noteCommitment: string,
    merkleRoot: string,
    proofBytes: Uint8Array,
  ): Promise<string> {
    return this.#serialized(() =>
      this.#mutate(async () => {
        const note = this.#snapshot.notes.find(
          (candidate) => candidate.commitment === noteCommitment,
        );
        if (!note || note.state === "consumed")
          throw new Error("proof note is unavailable");
        if (proofBytes.length !== 256)
          throw new Error("VALID_INPUT proof must be 256 bytes");
        const position = rootPosition(this.#snapshot, note.treeId, merkleRoot);
        if (position < 0)
          throw new Error("proof root is not finalized and accepted");
        const fields = {
          noteCommitment,
          noteUseTag: note.noteUseTag,
          treeId: note.treeId,
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
          this.#pruneProofs(noteCommitment);
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
        this.#pruneProofs(noteCommitment);
        return handle;
      }),
    );
  }

  async reserveReadyIntent(
    draft: TraderIntentDraft,
  ): Promise<ReservationOutcome> {
    return this.#serialized(() =>
      this.#mutate(async () => {
        const market = this.#markets.get(draft.marketSymbol);
        if (!market)
          throw new Error(`unsupported market ${draft.marketSymbol}`);
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
            left.amount < right.amount
              ? -1
              : left.amount > right.amount
                ? 1
                : 0,
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
          return {
            status: "ready",
            reservation: {
              reservationId: id,
              proof: readyProofHandle(proof.handle),
            },
          };
        }
        return { status: "not_ready", retryAfterMs: 250 };
      }),
    );
  }

  async releaseReservation(id: string): Promise<void> {
    await this.#serialized(() =>
      this.#mutate(async () => {
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
      }),
    );
  }

  async markPendingSettlement(id: string): Promise<void> {
    await this.#serialized(() =>
      this.#mutate(async () => {
        const reservation = this.#snapshot.reservations.find(
          (candidate) => candidate.reservationId === id,
        );
        if (!reservation) throw new Error("unknown inventory reservation");
        const note = this.#snapshot.notes.find(
          (candidate) => candidate.commitment === reservation.noteCommitment,
        );
        if (
          !note ||
          (note.state !== "reserved" && note.state !== "pending_settlement") ||
          note.reservationId !== id
        ) {
          throw new Error("inventory reservation is inconsistent");
        }
        note.state = "pending_settlement";
      }),
    );
  }

  async markConsumed(noteCommitment: string): Promise<void> {
    await this.#serialized(() =>
      this.#mutate(async () => {
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
        this.#pruneProofs(noteCommitment);
      }),
    );
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
    isLocked?: RecoveryLockVerifier,
  ): Promise<void> {
    if (report.unresolvedSettlements > 0 || report.unresolvedMerges > 0) {
      throw new Error("seed-plus-chain recovery has unresolved owned outputs");
    }
    await this.#serialized(() =>
      this.#mutate(async () => {
        const verified: InventoryNote[] = [];
        for (const candidate of report.notes) {
          const commitment = await noteCommitmentV2(candidate);
          if (
            !same(
              commitment,
              fromHex32(candidate.commitment, "recovered commitment"),
            )
          ) {
            throw new Error(
              "recovered note opening does not match its commitment",
            );
          }
          const tag = hex(
            await deriveNoteUseTag(
              commitment,
              bn254ToBE32(candidate.innerHash),
            ),
          );
          if (
            !Number.isInteger(candidate.treeId) ||
            candidate.treeId === undefined ||
            candidate.treeId < 0 ||
            candidate.treeId > 255
          ) {
            throw new Error("recovered note tree id must be a u8");
          }
          const treeId = candidate.treeId;
          const consumed = await isConsumed(tag, treeId);
          const locked = !consumed && (await isLocked?.(tag, treeId)) === true;
          verified.push({
            ...structuredClone(candidate),
            treeId,
            noteUseTag: tag,
            state: consumed
              ? "consumed"
              : locked || candidate.leafIndex === undefined
                ? "locked"
                : "spendable",
          });
        }
        const priorByCommitment = new Map(
          this.#snapshot.notes.map((note) => [note.commitment, note]),
        );
        const recovered = verified.map((note) => {
          const prior = priorByCommitment.get(note.commitment);
          if (
            prior &&
            note.state === "spendable" &&
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
        this.#snapshot.notes = report.fullScan
          ? recovered
          : [
              ...this.#snapshot.notes.filter(
                (note) =>
                  !recovered.some(
                    (candidate) => candidate.commitment === note.commitment,
                  ),
              ),
              ...recovered,
            ];
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
        // A stream gap may hide one or several confirmed fills. Settlement
        // outputs are seed-recovered with both `orderId` and the exact
        // `consumedCommitment`, so walk that private continuation chain and move
        // the journal's current collateral pointer forward. The collateral mint
        // distinguishes a partial-fill continuation from the trade output.
        for (const order of this.#snapshot.orders) {
          if (
            order.kind === "fully_filled" ||
            order.kind === "settlement_failed" ||
            order.kind === "cancelled" ||
            order.kind === "expired" ||
            order.kind === "closed" ||
            order.kind === "rejected"
          ) {
            continue;
          }
          const market = this.#markets.get(order.marketSymbol);
          if (!market) continue;
          const collateralMint =
            order.side === "bid" ? market.quoteMintHex : market.baseMintHex;
          let current = order.noteCommitment;
          let changed = false;
          for (let depth = 0; depth <= verified.length; depth += 1) {
            const outputs = verified.filter(
              (note) =>
                note.orderId?.toLowerCase() === order.orderId &&
                note.consumedCommitment?.toLowerCase() === current,
            );
            if (outputs.length === 0) break;
            const continuation = outputs.find(
              (note) => hex(note.tokenMint) === collateralMint,
            );
            changed = true;
            if (!continuation) {
              order.kind = "fully_filled";
              break;
            }
            order.kind = "partially_filled";
            current = continuation.commitment;
            order.noteCommitment = current;
            const continuationNote = this.#snapshot.notes.find(
              (note) => note.commitment === current,
            );
            if (continuationNote) {
              continuationNote.state = "locked";
              delete continuationNote.reservationId;
              this.#snapshot.reservations = this.#snapshot.reservations.filter(
                (reservation) => reservation.noteCommitment !== current,
              );
            }
          }
          if (changed) order.updatedAtMs = this.#now();
        }
      }),
    );
  }

  async refreshExpiringProofs(produce: InputProofProducer): Promise<number> {
    const requests = await this.#serialized(async () => {
      const out: Array<{ note: InventoryNote; root: string; treeId: number }> =
        [];
      for (const note of this.#snapshot.notes) {
        if (note.state !== "spendable" || note.leafIndex === undefined)
          continue;
        const treeId = note.treeId;
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
