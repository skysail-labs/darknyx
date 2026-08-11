import { getAssociatedTokenAddressSync } from "@solana/spl-token";
import { Keypair, PublicKey } from "@solana/web3.js";
import { pubkeyToFrPair } from "@darknyx/sdk/browser-inventory-crypto";
import { afterEach, describe, expect, it, vi } from "vitest";

import { BrowserVault } from "../src/index.js";
import {
  AccountOperationError,
  BrowserAccountOperations,
} from "../src/internal.js";

const be32 = (value: bigint): Uint8Array => {
  const out = new Uint8Array(32);
  let remaining = value;
  for (let index = 31; index >= 0; index -= 1) {
    out[index] = Number(remaining & 255n);
    remaining >>= 8n;
  }
  return out;
};

class ReplyWorker {
  onmessage: ((event: MessageEvent) => void) | null = null;
  onerror: ((event: ErrorEvent) => void) | null = null;

  constructor(readonly value: unknown) {}

  postMessage(message: { id: number }): void {
    queueMicrotask(() =>
      this.onmessage?.({
        data: { id: message.id, ok: true, value: this.value },
      } as MessageEvent),
    );
  }

  terminate(): void {}
}

describe("browser account operations", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("releases an exact-note reservation when the wallet rejects", async () => {
    const mint = Keypair.generate().publicKey;
    const wallet = Keypair.generate().publicKey;
    const root = new Uint8Array(32).fill(3);
    const tag = new Uint8Array(32).fill(4);
    const nullifier = new Uint8Array(32).fill(5);
    const destination = getAssociatedTokenAddressSync(mint, wallet);
    const commitment = "06".repeat(32);
    const note = {
      commitment,
      tokenMint: mint.toBytes(),
      amount: 17n,
      ownerCommitment: 8n,
      innerHash: 9n,
      leafIndex: 1n,
      treeId: 0,
      noteUseTag: "04".repeat(32),
      state: "reserved" as const,
      reservationId: "account-test",
    };
    const witness = {
      merkleRoot: 3n,
      nullifier: 5n,
      tokenMint: pubkeyToFrPair(mint.toBytes()),
      amount: 17n,
      spendingKey: 12n,
      ownerCommitmentBlinding: 13n,
      innerHash: 9n,
      merklePath: Array<bigint>(20).fill(0n),
      merkleIndices: Array<number>(20).fill(0),
      recipient: pubkeyToFrPair(destination.toBytes()),
    };
    const worker = new ReplyWorker({
      witness,
      noteUseTag: tag,
      nullifier,
      merkleRoot: root,
    });
    const vault = new BrowserVault({
      workerFactory: () => worker as unknown as Worker,
    });
    const released: string[] = [];
    const fetchMock = vi.fn(async (input: string | URL | Request) => {
      const url = String(input);
      if (url.includes("/tree/inclusion")) {
        return new Response(
          JSON.stringify({
            merkle_root: "03".repeat(32),
            siblings: Array<string>(20).fill("00".repeat(32)),
            leaf_index: 1,
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      return new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          result: {
            context: { slot: 1 },
            value: {
              blockhash: PublicKey.default.toBase58(),
              lastValidBlockHeight: 99,
            },
          },
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    });
    vi.stubGlobal("fetch", fetchMock);

    const operations = new BrowserAccountOperations({
      release: {
        venueId: "test",
        gatewayUrl: "https://venue.test",
        rpcUrl: "https://rpc.test",
        vaultProgramId: "C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx",
        expectedComposeHash: "test",
      },
      venue: { numTrees: 1, token: async () => "short-lived" } as never,
      vault,
      inventory: {
        reserveAccountExact: async () => ({
          note,
          reservationId: "account-test",
        }),
        assertAcceptedRoot: async () => undefined,
        releaseReservation: async (id: string) => void released.push(id),
      } as never,
      prover: {
        spend: {
          prove: async () => ({
            piA: new Uint8Array(64),
            piB: new Uint8Array(128),
            piC: new Uint8Array(64),
            publicInputs: [
              tag,
              root,
              nullifier,
              be32(witness.tokenMint[0]),
              be32(witness.tokenMint[1]),
              be32(witness.amount),
              be32(witness.recipient[0]),
              be32(witness.recipient[1]),
            ],
          }),
        },
      } as never,
      wallet: {
        current: () => ({ walletName: "Test", address: wallet.toBase58() }),
        signAndSendTransaction: async () => {
          throw new Error("user rejected");
        },
      } as never,
      fetchImpl: fetchMock as typeof fetch,
      connection: {
        getLatestBlockhash: async () => ({
          blockhash: PublicKey.default.toBase58(),
          lastValidBlockHeight: 99,
        }),
        confirmTransaction: async () => ({
          context: { slot: 1 },
          value: { err: null },
        }),
      } as never,
    });

    await expect(
      operations.withdraw({ tokenMint: mint.toBase58(), amount: 17n }),
    ).rejects.toMatchObject({
      name: AccountOperationError.name,
      stage: "wallet",
    });
    expect(released).toEqual(["account-test"]);
    vault.destroy();
  });
});
