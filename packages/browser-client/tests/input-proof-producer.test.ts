import { describe, expect, it, vi } from "vitest";

import { BrowserVault } from "../src/index.js";
import { BrowserInputProofProducer } from "../src/internal.js";
import type { InventoryNote } from "../src/inventory/types.js";

class FakeWorker {
  onmessage: ((event: MessageEvent) => void) | null = null;
  onerror: ((event: ErrorEvent) => void) | null = null;
  readonly postMessage = vi.fn((message: { id: number; type: string }) => {
    if (message.type !== "validInputWitness") return;
    queueMicrotask(() =>
      this.onmessage?.({
        data: {
          id: message.id,
          ok: true,
          value: {
            merkleRoot: "1",
            noteUseTag: "2",
            tokenMint: ["3", "4"],
          },
        },
      } as MessageEvent),
    );
  });
  terminate(): void {}
}

const note: InventoryNote = {
  commitment: "11".repeat(32),
  noteUseTag: "22".repeat(32),
  tokenMint: new Uint8Array(32).fill(0x33),
  amount: 10n,
  ownerCommitment: 4n,
  innerHash: 5n,
  leafIndex: 3n,
  treeId: 0,
  state: "spendable",
};

describe("browser VALID_INPUT producer", () => {
  it("binds the inclusion response to the finalized refresh target", async () => {
    const worker = new FakeWorker();
    const vault = new BrowserVault({
      store: {
        load: async () => null,
        save: async () => undefined,
        clear: async () => undefined,
      },
      workerFactory: () => worker as unknown as Worker,
    });
    const proveValidInput = vi.fn(async () => ({
      piA: new Uint8Array(64).fill(1),
      piB: new Uint8Array(128).fill(2),
      piC: new Uint8Array(64).fill(3),
      publicInputs: [],
    }));
    const target = "44".repeat(32);
    const fetchImpl = vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            leaf_index: 3,
            merkle_root: target,
            siblings: Array.from({ length: 20 }, () => "55".repeat(32)),
          }),
          { status: 200 },
        ),
    );
    const producer = new BrowserInputProofProducer({
      vault,
      prover: { proveValidInput } as never,
      gatewayUrl: "https://cvm.example",
      token: "secret-token",
      fetchImpl,
    });

    await expect(
      producer.produce({
        note,
        root: target,
        treeId: 0,
        circuitVersion: "v3",
        provingKeyVersion: "pk1",
      }),
    ).resolves.toEqual({ proofBytes: expect.any(Uint8Array) });
    expect(worker.postMessage).toHaveBeenCalledWith(
      expect.objectContaining({ type: "validInputWitness" }),
    );
    expect(proveValidInput).toHaveBeenCalledOnce();
    vault.destroy();
  });

  it("rejects a different TEE root before custody or proving", async () => {
    const worker = new FakeWorker();
    const vault = new BrowserVault({
      store: {
        load: async () => null,
        save: async () => undefined,
        clear: async () => undefined,
      },
      workerFactory: () => worker as unknown as Worker,
    });
    const proveValidInput = vi.fn();
    const producer = new BrowserInputProofProducer({
      vault,
      prover: { proveValidInput } as never,
      gatewayUrl: "https://cvm.example",
      token: "secret-token",
      fetchImpl: async () =>
        new Response(
          JSON.stringify({
            leaf_index: 0,
            merkle_root: "66".repeat(32),
            siblings: Array.from({ length: 20 }, () => "55".repeat(32)),
          }),
        ),
    });
    await expect(
      producer.produce({
        note,
        root: "44".repeat(32),
        treeId: 0,
        circuitVersion: "v3",
        provingKeyVersion: "pk1",
      }),
    ).rejects.toThrow(/differs from finalized/);
    expect(worker.postMessage).not.toHaveBeenCalled();
    expect(proveValidInput).not.toHaveBeenCalled();
    vault.destroy();
  });
});
