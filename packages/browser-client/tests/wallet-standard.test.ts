import type { Wallet, WalletAccount } from "@wallet-standard/base";
import { StandardConnect, StandardDisconnect } from "@wallet-standard/features";
import { SolanaSignAndSendTransaction } from "@solana/wallet-standard-features";
import { describe, expect, it, vi } from "vitest";

import { ExternalWalletController } from "../src/internal.js";

const account = {
  address: "Wallet111111111111111111111111111111111111",
  publicKey: new Uint8Array(32),
  chains: ["solana:devnet"],
  features: [SolanaSignAndSendTransaction],
} satisfies WalletAccount;

function wallet(): Wallet {
  return {
    version: "1.0.0",
    name: "Test Wallet",
    icon: "data:image/svg+xml;base64,PHN2Zy8+",
    chains: ["solana:devnet"],
    accounts: [],
    features: {
      [StandardConnect]: {
        version: "1.0.0",
        connect: vi.fn(async () => ({ accounts: [account] })),
      },
      [StandardDisconnect]: {
        version: "1.0.0",
        disconnect: vi.fn(async () => undefined),
      },
      [SolanaSignAndSendTransaction]: {
        version: "1.0.0",
        supportedTransactionVersions: [0],
        signAndSendTransaction: vi.fn(async () => [
          { signature: new Uint8Array(64).fill(3) },
        ]),
      },
    },
  };
}

describe("external Wallet Standard boundary", () => {
  it("discovers, connects, and sends only bounded serialized transactions", async () => {
    const candidate = wallet();
    const controller = new ExternalWalletController({
      wallets: {
        get: () => [candidate],
        on: () => () => undefined,
        register: () => () => undefined,
      },
    });

    expect(controller.available()).toEqual([
      { name: "Test Wallet", icon: candidate.icon },
    ]);
    expect(await controller.connect("Test Wallet")).toEqual({
      walletName: "Test Wallet",
      address: account.address,
    });
    expect(
      await controller.signAndSendTransaction(new Uint8Array([1])),
    ).toEqual(new Uint8Array(64).fill(3));
    await expect(
      controller.signAndSendTransaction(new Uint8Array(1_233)),
    ).rejects.toThrow("invalid size");
    await controller.disconnect();
    expect(controller.current()).toBeNull();
  });

  it("clears an unregistered active wallet without requiring a subscription", async () => {
    const candidate = wallet();
    let unregister: ((...wallets: Wallet[]) => void) | undefined;
    const controller = new ExternalWalletController({
      wallets: {
        get: () => [candidate],
        on: (event, listener) => {
          if (event === "unregister") unregister = listener;
          return () => undefined;
        },
        register: () => () => undefined,
      },
    });
    await controller.connect("Test Wallet");
    unregister?.(candidate);
    expect(controller.current()).toBeNull();
    controller.destroy();
  });

  it("retains the active wallet when its disconnect cleanup rejects", async () => {
    const candidate = wallet();
    vi.mocked(
      candidate.features[StandardDisconnect]!.disconnect,
    ).mockRejectedValueOnce(new Error("wallet refused disconnect"));
    const controller = new ExternalWalletController({
      wallets: {
        get: () => [candidate],
        on: () => () => undefined,
        register: () => () => undefined,
      },
    });
    await controller.connect("Test Wallet");
    await expect(controller.disconnect()).rejects.toThrow(
      "wallet refused disconnect",
    );
    expect(controller.current()?.walletName).toBe("Test Wallet");
    controller.destroy();
  });
});
