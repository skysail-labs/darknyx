import { describe, expect, it } from "vitest";
import { Connection, PublicKey } from "@solana/web3.js";

import { CvmHarness, floorPriceToTick } from "./cvm-harness.js";
import { MerkleShadow } from "./merkle-shadow.js";

function leaf(value: number): Uint8Array {
  return new Uint8Array(32).fill(value);
}

function fakeConnection(counts: number[]): Connection {
  let call = 0;
  return {
    getAccountInfo: async () => {
      const data = new Uint8Array(16);
      new DataView(data.buffer).setBigUint64(
        8,
        BigInt(counts[call++ % counts.length]),
        true,
      );
      return { data };
    },
  } as unknown as Connection;
}

describe("floorPriceToTick", () => {
  it("preserves an aligned positive price", () => {
    expect(floorPriceToTick(125n, 5n)).toBe(125n);
  });

  it("floors an off-tick price", () => {
    expect(floorPriceToTick(129n, 5n)).toBe(125n);
  });

  it("rejects non-positive inputs and a tick larger than the price", () => {
    expect(() => floorPriceToTick(0n, 5n)).toThrow("price must be positive");
    expect(() => floorPriceToTick(10n, 0n)).toThrow(
      "tickSize must be positive",
    );
    expect(() => floorPriceToTick(4n, 5n)).toThrow(
      "tickSize exceeds the positive price",
    );
  });
});

describe("CvmHarness.createHydrated", () => {
  it("replays contiguous pages and checks the aggregate on-chain count", async () => {
    const shardLeaves = [[leaf(1), leaf(2)], [leaf(3)]];
    const roots = await Promise.all(
      shardLeaves.map(async (leaves) => {
        const shadow = await MerkleShadow.create();
        for (const value of leaves) await shadow.append(value);
        return shadow.computeRoot();
      }),
    );
    const harness = await CvmHarness.createHydrated(
      fakeConnection([2, 1]),
      new PublicKey(new Uint8Array(32).fill(7)),
      2,
      async (treeId, from) => ({
        leaves: shardLeaves[treeId].slice(from).map((value, offset) => ({
          leafIndex: from + offset,
          value,
        })),
        merkleRoot: roots[treeId],
      }),
    );

    expect(harness.shadows.map((shadow) => shadow.leafCount)).toEqual([2, 1]);
    expect(await harness.leafCount()).toBe(3);
  });

  it("rejects a gap before accepting a hydrated witness tree", async () => {
    const shadow = await MerkleShadow.create();
    await shadow.append(leaf(9));
    await expect(
      CvmHarness.createHydrated(
        fakeConnection([1]),
        new PublicKey(new Uint8Array(32).fill(8)),
        1,
        async () => ({
          leaves: [{ leafIndex: 1, value: leaf(9) }],
          merkleRoot: await shadow.computeRoot(),
        }),
      ),
    ).rejects.toThrow("non-contiguous");
  });
});
