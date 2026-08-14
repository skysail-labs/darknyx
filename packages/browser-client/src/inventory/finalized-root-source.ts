import { Connection, PublicKey } from "@solana/web3.js";
import {
  consumedNotePda,
  merkleTreePda,
  noteLockPda,
} from "@darknyx/sdk/browser-inventory-crypto";
import { parseMerkleRootRing } from "@darknyx/sdk/merkle-root-ring";

import type { FinalizedRootRing } from "./types.js";

const hex = (value: Uint8Array): string =>
  Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");

export class SolanaFinalizedRootSource {
  readonly #connection: Connection;
  readonly #programId: PublicKey;

  constructor(connection: Connection, programId: PublicKey) {
    this.#connection = connection;
    this.#programId = programId;
  }

  async read(treeIds: readonly number[]): Promise<FinalizedRootRing[]> {
    return Promise.all(
      treeIds.map(async (treeId) => {
        if (!Number.isInteger(treeId) || treeId < 0 || treeId > 255) {
          throw new Error(`tree id must be a u8, got ${treeId}`);
        }
        const [address] = merkleTreePda(this.#programId, treeId);
        const response = await this.#connection.getAccountInfoAndContext(
          address,
          "finalized",
        );
        if (!response.value) {
          throw new Error(`Merkle tree shard ${treeId} is missing on chain`);
        }
        if (!response.value.owner.equals(this.#programId)) {
          throw new Error(`Merkle tree shard ${treeId} has the wrong owner`);
        }
        const parsed = parseMerkleRootRing(response.value.data, treeId);
        return {
          treeId,
          finalizedSlot: response.context.slot,
          acceptedRoots: parsed.acceptedRoots.map(hex),
        };
      }),
    );
  }

  /** Finalized consume-once guard used to filter recovered historical notes. */
  async isConsumed(noteUseTag: string, _treeId: number): Promise<boolean> {
    if (!/^[0-9a-f]{64}$/.test(noteUseTag)) {
      throw new Error("note-use tag must be lowercase 32-byte hex");
    }
    const tag = Uint8Array.from(noteUseTag.match(/../g) ?? [], (byte) =>
      Number.parseInt(byte, 16),
    );
    const [address] = consumedNotePda(this.#programId, tag);
    const account = await this.#connection.getAccountInfo(address, "finalized");
    if (!account) return false;
    if (!account.owner.equals(this.#programId)) {
      throw new Error("consumed-note PDA has the wrong owner");
    }
    return true;
  }

  /** Finalized lock guard: recovered continuations and failed inputs stay unavailable. */
  async isLocked(noteUseTag: string, _treeId: number): Promise<boolean> {
    if (!/^[0-9a-f]{64}$/.test(noteUseTag)) {
      throw new Error("note-use tag must be lowercase 32-byte hex");
    }
    const tag = Uint8Array.from(noteUseTag.match(/../g) ?? [], (byte) =>
      Number.parseInt(byte, 16),
    );
    const [address] = noteLockPda(this.#programId, tag);
    const account = await this.#connection.getAccountInfo(address, "finalized");
    if (!account) return false;
    if (!account.owner.equals(this.#programId)) {
      throw new Error("note-lock PDA has the wrong owner");
    }
    return true;
  }
}
