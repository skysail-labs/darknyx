import { createRoot } from "react-dom/client";

import "../src/ui/styles.css";
import { TraderShell } from "../src/ui/trader-shell.js";
import type {
  TraderShellActions,
  TraderShellSnapshot,
} from "../src/ui/types.js";

const noop = async () => undefined;
const snapshot: TraderShellSnapshot = {
  venue: {
    state: "trusted",
    label: "Devnet · Intel TDX",
    composeHash: "f4a298a7f9427549f6a42f18cb175ee6",
    governanceSlot: "401,829,220",
  },
  vault: { state: "unlocked" },
  wallet: {
    state: "connected",
    walletName: "Phantom",
    address: "Gh9ZwEmdLJ8DscKNTkTqPbNwLNNBjuSzaG9Vp2KGtKJr",
    availableWallets: [],
  },
  selectedSymbol: "SOL-USDC",
  instruments: [
    {
      symbol: "SOL-USDC",
      baseSymbol: "SOL",
      quoteSymbol: "USDC",
      tradingEnabled: true,
      minOrderSize: "10000000",
      tickSize: "100",
    },
    {
      symbol: "BTC-USDC",
      baseSymbol: "BTC",
      quoteSymbol: "USDC",
      tradingEnabled: false,
      minOrderSize: "100",
      tickSize: "100",
    },
  ],
  balances: [
    {
      mint: "So11111111111111111111111111111111111111112",
      symbol: "SOL",
      spendable: "12.840000000",
      reserved: "1.000000000",
      pendingSettlement: "0",
    },
    {
      mint: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
      symbol: "USDC",
      spendable: "24,905.42",
      reserved: "2,120.00",
      pendingSettlement: "500.00",
    },
  ],
  proofReadiness: { ready: 3, proving: 1, stale: 0 },
  orders: [
    {
      orderId: "f59c4d0f723e4304b0ac7e7f0a9ca524",
      symbol: "SOL-USDC",
      side: "bid",
      amount: "1.000000000",
      limitPrice: "151.20",
      kind: "pending_settlement",
      updatedAt: "2s ago",
    },
    {
      orderId: "9cae249d8dbf4c8fb08ebf44b853ed4a",
      symbol: "SOL-USDC",
      side: "ask",
      amount: "2.500000000",
      limitPrice: "154.80",
      kind: "open",
      updatedAt: "1m ago",
    },
    {
      orderId: "618b831cf8ba4406ac79b70e1f23f4d2",
      symbol: "SOL-USDC",
      side: "bid",
      amount: "0.750000000",
      limitPrice: "149.60",
      kind: "fully_filled",
      updatedAt: "8m ago",
    },
  ],
  lastUpdated: "just now",
};

const actions: TraderShellActions = {
  retryVenue: noop,
  selectInstrument: () => undefined,
  connectWallet: noop,
  disconnectWallet: noop,
  provisionVault: noop,
  unlockVault: noop,
  lockVault: noop,
  refresh: noop,
  submitOrder: async () => ({ status: "accepted", orderId: "preview" }),
  cancelOrder: noop,
  exportBackup: async () => ({
    format: "darknyx-master-seed-backup",
    version: 2,
    kdf: { name: "scrypt", n: 131072, r: 8, p: 1, salt: "00" },
    cipher: { name: "aes-256-gcm", iv: "00", ciphertext: "00", tag: "00" },
  }),
  restoreBackup: noop,
  deposit: noop,
  withdraw: noop,
  merge: noop,
};

createRoot(document.querySelector("#root")!).render(
  <TraderShell snapshot={snapshot} actions={actions} />,
);
