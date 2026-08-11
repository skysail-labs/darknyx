import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import { TraderShell } from "../src/ui/trader-shell.js";
import type {
  TraderShellActions,
  TraderShellSnapshot,
} from "../src/ui/types.js";

const actions: TraderShellActions = {
  retryVenue: vi.fn(async () => undefined),
  selectInstrument: vi.fn(),
  connectWallet: vi.fn(async () => undefined),
  disconnectWallet: vi.fn(async () => undefined),
  provisionVault: vi.fn(async () => undefined),
  unlockVault: vi.fn(async () => undefined),
  lockVault: vi.fn(async () => undefined),
  refresh: vi.fn(async () => undefined),
  submitOrder: vi.fn(async () => ({
    status: "accepted" as const,
    orderId: "01",
  })),
  cancelOrder: vi.fn(async () => undefined),
  exportBackup: vi.fn(async () => ({
    format: "darknyx-master-seed-backup" as const,
    version: 2 as const,
    kdf: { name: "scrypt" as const, n: 131072, r: 8, p: 1, salt: "00" },
    cipher: {
      name: "aes-256-gcm" as const,
      iv: "00",
      ciphertext: "00",
      tag: "00",
    },
  })),
  restoreBackup: vi.fn(async () => undefined),
  deposit: vi.fn(async () => undefined),
  withdraw: vi.fn(async () => undefined),
  merge: vi.fn(async () => undefined),
};

function snapshot(
  override: Partial<TraderShellSnapshot> = {},
): TraderShellSnapshot {
  return {
    venue: { state: "checking", label: "Devnet" },
    vault: { state: "locked" },
    wallet: { state: "disconnected", availableWallets: [] },
    instruments: [],
    balances: [],
    proofReadiness: { ready: 0, proving: 0, stale: 0 },
    orders: [],
    ...override,
  };
}

describe("trader workspace", () => {
  it("renders a fail-closed boot without secret-bearing UI fields", () => {
    const html = renderToStaticMarkup(
      <TraderShell snapshot={snapshot()} actions={actions} />,
    );
    expect(html).toContain("Verifying venue");
    expect(html).toContain("Venue trust is not established");
    expect(html).not.toContain("master seed");
    expect(html).not.toContain("witness");
    expect(html).not.toContain("proof bytes");
  });

  it("distinguishes market-local pause from a trusted venue", () => {
    const html = renderToStaticMarkup(
      <TraderShell
        actions={actions}
        snapshot={snapshot({
          venue: {
            state: "trusted",
            label: "Devnet · TDX",
            governanceSlot: "4242",
          },
          vault: { state: "unlocked" },
          selectedSymbol: "SOL-USDC",
          instruments: [
            {
              symbol: "SOL-USDC",
              baseSymbol: "SOL",
              quoteSymbol: "USDC",
              tradingEnabled: false,
              minOrderSize: "10000",
              tickSize: "100",
            },
          ],
          proofReadiness: { ready: 1, proving: 0, stale: 0 },
        })}
      />,
    );
    expect(html).toContain("Attested");
    expect(html).toContain("This market is paused");
    expect(html).not.toContain("Verifying venue");
  });

  it("distinguishes a missing market selection from a paused market", () => {
    const html = renderToStaticMarkup(
      <TraderShell
        actions={actions}
        snapshot={snapshot({
          venue: { state: "trusted", label: "Devnet · TDX" },
          vault: { state: "unlocked" },
          proofReadiness: { ready: 1, proving: 0, stale: 0 },
        })}
      />,
    );
    expect(html).toContain("Select an attested market");
    expect(html).not.toContain("This market is paused");
  });

  it("keeps ambiguous settlement visible as a durable lifecycle state", () => {
    const html = renderToStaticMarkup(
      <TraderShell
        actions={actions}
        snapshot={snapshot({
          orders: [
            {
              orderId: "ab".repeat(16),
              symbol: "SOL-USDC",
              side: "bid",
              amount: "1000000000",
              limitPrice: "150000000",
              kind: "ambiguous",
              updatedAt: "now",
            },
          ],
        })}
      />,
    );
    expect(html).toContain("Reconciling");
    expect(html).toContain("status-dot is-pending");
    expect(html).not.toContain("status-dot is-bad");
    expect(html).not.toContain(">Cancel<");
  });

  it("explains exact-note withdrawal and keeps recovery actions state-gated", () => {
    const html = renderToStaticMarkup(
      <TraderShell
        actions={actions}
        snapshot={snapshot({
          venue: { state: "trusted", label: "Devnet · TDX" },
          vault: { state: "locked" },
          wallet: { state: "disconnected", availableWallets: [] },
          selectedSymbol: "SOL-USDC",
          instruments: [
            {
              symbol: "SOL-USDC",
              baseSymbol: "SOL",
              quoteSymbol: "USDC",
              tradingEnabled: true,
              minOrderSize: "0.01",
              tickSize: "0.01",
            },
          ],
        })}
      />,
    );
    expect(html).toContain("Fund, withdraw &amp; recover");
    expect(html).toContain("Withdrawals consume one exact note");
    expect(html).toContain("Portable recovery");
    expect(html).toContain('href="#account"');
  });
});
