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
    expect(html).not.toContain(">Cancel<");
  });
});
