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

import type { MerkleProofProvider } from "@nyx/sdk";

import { LocalMerkleTree } from "./merkle-tree.js";

const fromHex = (h: string): Uint8Array =>
  Uint8Array.from(Buffer.from(h.replace(/^0x/, ""), "hex"));

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
}

export class TreeLeavesMerkleProvider implements MerkleProofProvider {
  private tree: LocalMerkleTree | null = null;
  private readonly treeId: number;
  private readonly pageSize: number;

  constructor(private readonly opts: TreeLeavesMerkleProviderOptions) {
    this.treeId = opts.treeId ?? 0;
    this.pageSize = opts.pageSize ?? 500;
  }

  /** Pull a fresh full-shard snapshot into a local tree. Call before a merge. */
  async refresh(): Promise<void> {
    const all: Uint8Array[] = [];
    let from = 0;
    for (;;) {
      const page = await this.opts.fetcher(
        from,
        from + this.pageSize,
        this.treeId,
      );
      for (const e of page.leaves) all[e.leaf_index] = fromHex(e.value);
      if (page.leaves.length < this.pageSize) break;
      from += this.pageSize;
    }
    this.tree = await LocalMerkleTree.fromLeaves(all);
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
