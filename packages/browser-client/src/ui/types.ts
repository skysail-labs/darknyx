import type {
  ProofReadinessView,
  SubmitIntentResult,
  VaultStatus,
} from "@darknyx/client-core";

export interface InstrumentView {
  symbol: string;
  baseSymbol: string;
  quoteSymbol: string;
  tradingEnabled: boolean;
  /** Minimum human-readable amount denominated in the market's base asset. */
  minOrderSize: string;
  /** Human-readable quote-per-base price increment. */
  tickSize: string;
}

export interface WalletView {
  state: "disconnected" | "connecting" | "connected" | "failed";
  address?: string;
  walletName?: string;
  availableWallets: readonly { name: string; icon: string }[];
  error?: string;
}

export interface PrivateBalanceView {
  mint: string;
  symbol: string;
  spendable: string;
  reserved: string;
  pendingSettlement: string;
}

export interface TraderOrderDraft {
  marketSymbol: string;
  side: "bid" | "ask";
  /** User-entered decimal token amount; the trusted adapter converts to atoms. */
  amount: string;
  /** User-entered decimal price; the trusted adapter validates ticks. */
  limitPrice: string;
  orderType: "limit" | "ioc" | "fok";
}

export interface VenueView {
  state: "checking" | "trusted" | "degraded" | "failed";
  label: string;
  composeHash?: string;
  governanceSlot?: string;
  message?: string;
}

export type OrderLifecycleKind =
  | "submitting"
  | "open"
  | "pending_settlement"
  | "partially_filled"
  | "fully_filled"
  | "settlement_failed"
  | "cancelled"
  | "expired"
  | "ambiguous"
  | "rejected";

export interface OrderLifecycleView {
  orderId: string;
  symbol: string;
  side: "bid" | "ask";
  amount: string;
  limitPrice: string;
  filled?: string;
  kind: OrderLifecycleKind;
  reason?: string;
  updatedAt: string;
}

export interface TraderShellSnapshot {
  venue: VenueView;
  vault: VaultStatus;
  wallet: WalletView;
  instruments: readonly InstrumentView[];
  selectedSymbol?: string;
  balances: readonly PrivateBalanceView[];
  proofReadiness: ProofReadinessView;
  orders: readonly OrderLifecycleView[];
  lastUpdated?: string;
}

export interface TraderShellActions {
  retryVenue(): Promise<void>;
  selectInstrument(symbol: string): void;
  connectWallet(name: string): Promise<void>;
  disconnectWallet(): Promise<void>;
  provisionVault(): Promise<void>;
  unlockVault(): Promise<void>;
  lockVault(): Promise<void>;
  refresh(): Promise<void>;
  submitOrder(draft: TraderOrderDraft): Promise<SubmitIntentResult>;
  cancelOrder(orderId: string): Promise<void>;
}

export interface TraderShellProps {
  snapshot: TraderShellSnapshot;
  actions: TraderShellActions;
}

/** Narrow observable surface; privileged runtime objects never enter React. */
export interface TraderShellController {
  readonly actions: TraderShellActions;
  snapshot(): TraderShellSnapshot;
  subscribe(listener: (snapshot: TraderShellSnapshot) => void): () => void;
  start(): Promise<void>;
}
