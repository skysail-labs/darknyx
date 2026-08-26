import { describe, expect, it } from "vitest";

import {
  computeSettlementBatchLeaf,
  computeSettlementBatchRoot,
} from "../src/settlement/batch-binding.js";
import {
  exactFillPayload,
  type MatchResultPayload,
} from "../src/settlement/settle-builder.js";

const bytes = (length: number, value: number): Uint8Array => {
  const out = new Uint8Array(length).fill(value);
  if (length === 32) out[0] = 0;
  return out;
};

function payload(): MatchResultPayload {
  return {
    ...exactFillPayload({
      matchId: bytes(16, 1),
      noteAuseTag: bytes(32, 2),
      noteBuseTag: bytes(32, 3),
      noteCcommitment: bytes(32, 4),
      noteDcommitment: bytes(32, 5),
      orderIdA: bytes(16, 6),
      orderIdB: bytes(16, 7),
    }),
    noteFeeBaseCommitment: bytes(32, 8),
    noteFeeQuoteCommitment: bytes(32, 9),
    batchSlot: 3n,
  };
}

describe("finalized settlement batch binding", () => {
  it("recomputes a stable N=16 root from the Tx D payload and siblings", async () => {
    const value = payload();
    const siblings = [10, 11, 12, 13].map((item) => bytes(32, item));
    const leaf = await computeSettlementBatchLeaf(value);
    expect(Buffer.from(leaf).toString("hex")).toBe(
      "227bfaf15070d46854c20e13ab209066649c349b6c9ea08b9342b6699623f51a",
    );
    const first = await computeSettlementBatchRoot({
      leaf,
      matchIndex: 3,
      siblings,
    });
    expect(Buffer.from(first).toString("hex")).toBe(
      "19ce7fa75f6c9217e42bc2a7659e03583eb481248f2b6fd628bd0495cbcb19c2",
    );
    expect(
      await computeSettlementBatchRoot({ leaf, matchIndex: 3, siblings }),
    ).toEqual(first);
    expect(
      await computeSettlementBatchRoot({
        leaf: await computeSettlementBatchLeaf({
          ...value,
          noteFeeBaseCommitment: bytes(32, 14),
        }),
        matchIndex: 3,
        siblings,
      }),
    ).not.toEqual(first);
  });

  it("rejects an index/payload mismatch at the collector boundary", async () => {
    const leaf = await computeSettlementBatchLeaf(payload());
    await expect(
      computeSettlementBatchRoot({
        leaf,
        matchIndex: 16,
        siblings: [1, 2, 3, 4].map((item) => bytes(32, item)),
      }),
    ).rejects.toThrow(/\[0, 15\]/);
  });
});
