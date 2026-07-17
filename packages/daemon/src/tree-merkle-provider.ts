/**
 * TreeLeavesMerkleProvider — a {@link MerkleProofProvider} backed by a snapshot
 * of the TEE's tree.
 *
 * The SDK merge path asks for an inclusion proof per input by LEAF INDEX, and
 * needs all inputs to prove against ONE root. The TEE's `/tree/inclusion` is
 * keyed by commitment + returns the moving current root, so we instead page the
 * whole shard via `GET /tree/leaves` into a {@link LocalMerkleTree} and serve
 * every proof from that single snapshot. `refresh()` pulls a fresh snapshot
 * (call it before a merge so the root is recent enough to still be in the
 * program's recent-roots window when the tx lands).
 *
 * The fetch is injectable so the provider is unit-testable without a gateway.
 */

import type { MerkleProofProvider, RootVerifier } from "@darknyx/sdk";

import { LocalMerkleTree, TREE_DEPTH } from "./merkle-tree.js";

const MAX_LEAVES = 1 << TREE_DEPTH;

const fromHex32 = (value: string, label: string): Uint8Array => {
  const hex = value.replace(/^0x/, "");
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error(`${label} must be exactly 32 bytes of hex`);
  }
  return Uint8Array.from(Buffer.from(hex, "hex"));
};

const equalBytes = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.every((value, index) => value === b[index]);

/** One `/tree/leaves` page response. */
export interface LeavesPage {
  leaves: { leaf_index: number; value: string }[];
  merkle_root: string;
}

/** Fetches a half-open `[from, to)` page of leaves for a shard. */
export type LeavesFetcher = (
  from: number,
  to: number,
  treeId: number,
) => Promise<LeavesPage>;

/** Build a {@link LeavesFetcher} over `GET /tree/leaves`. */
export function httpLeavesFetcher(opts: {
  gatewayUrl: string;
  token: string;
  fetchImpl?: typeof fetch;
}): LeavesFetcher {
  return async (from, to, treeId) => {
    const f = opts.fetchImpl ?? fetch;
    const url = new URL("/tree/leaves", opts.gatewayUrl);
    url.searchParams.set("from", String(from));
    url.searchParams.set("to", String(to));
    url.searchParams.set("tree_id", String(treeId));
    const res = await f(url.toString(), {
      headers: { authorization: `Bearer ${opts.token}` },
    });
    if (!res.ok) throw new Error(`/tree/leaves ${res.status}`);
    return (await res.json()) as LeavesPage;
  };
}

export interface TreeLeavesMerkleProviderOptions {
  fetcher: LeavesFetcher;
  treeId?: number;
  /** Page size for `/tree/leaves` pagination (the TEE caps this). */
  pageSize?: number;
  /** Final trust gate: require the reconstructed snapshot root to appear in
   *  the on-chain shard's finalized recent-root ring. */
  verifyRoot?: RootVerifier;
}

export class TreeLeavesMerkleProvider implements MerkleProofProvider {
  private tree: LocalMerkleTree | null = null;
  private readonly treeId: number;
  private readonly pageSize: number;

  constructor(private readonly opts: TreeLeavesMerkleProviderOptions) {
    this.treeId = opts.treeId ?? 0;
    this.pageSize = opts.pageSize ?? 500;
    if (
      !Number.isInteger(this.treeId) ||
      this.treeId < 0 ||
      this.treeId > 255
    ) {
      throw new Error(`tree id must be a u8, got ${this.treeId}`);
    }
    if (!Number.isInteger(this.pageSize) || this.pageSize <= 0) {
      throw new Error(
        `page size must be a positive integer, got ${this.pageSize}`,
      );
    }
  }

  /** Pull a fresh full-shard snapshot into a local tree. Call before a merge. */
  async refresh(): Promise<void> {
    const all: Uint8Array[] = [];
    let advertisedRoot: Uint8Array | null = null;
    let from = 0;
    for (;;) {
      const page = await this.opts.fetcher(
        from,
        from + this.pageSize,
        this.treeId,
      );
      if (page.leaves.length > this.pageSize) {
        throw new Error(
          `/tree/leaves returned ${page.leaves.length} entries for a ${this.pageSize}-entry page`,
        );
      }
      const pageRoot = fromHex32(page.merkle_root, "merkle_root");
      if (advertisedRoot && !equalBytes(advertisedRoot, pageRoot)) {
        throw new Error("/tree/leaves root changed while paging the snapshot");
      }
      advertisedRoot ??= pageRoot;
      for (let i = 0; i < page.leaves.length; i++) {
        const entry = page.leaves[i];
        const expectedIndex = from + i;
        if (expectedIndex >= MAX_LEAVES) {
          throw new Error(
            `/tree/leaves exceeds the ${MAX_LEAVES}-leaf capacity`,
          );
        }
        if (entry.leaf_index !== expectedIndex) {
          throw new Error(
            `/tree/leaves expected leaf_index ${expectedIndex}, got ${entry.leaf_index}`,
          );
        }
        all[entry.leaf_index] = fromHex32(
          entry.value,
          `leaf ${entry.leaf_index}`,
        );
      }
      if (page.leaves.length < this.pageSize) break;
      from += this.pageSize;
      if (from === MAX_LEAVES) break;
    }
    const nextTree = await LocalMerkleTree.fromLeaves(all);
    const computedRoot = await nextTree.root();
    if (!advertisedRoot || !equalBytes(computedRoot, advertisedRoot)) {
      throw new Error(
        "reconstructed /tree/leaves root does not match the TEE snapshot root",
      );
    }
    await this.opts.verifyRoot?.(computedRoot, this.treeId);
    this.tree = nextTree;
  }

  async getInclusionProof(leafIndex: bigint): Promise<{
    root: Uint8Array;
    siblings: Uint8Array[];
    pathIndices: number[];
  }> {
    if (!this.tree) await this.refresh();
    const w = await this.tree!.witness(Number(leafIndex));
    return { root: w.root, siblings: w.siblings, pathIndices: w.indices };
  }
}
