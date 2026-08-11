import { PublicKey } from "@solana/web3.js";
import type { SubmitIntentResult, VaultStatus } from "@darknyx/client-core";

import { BrowserVault } from "../custody/browser-vault.js";
import type { RecoveryReport } from "../inventory/types.js";
import type { BrowserProverSuite } from "../prover/browser-prover.js";
import {
  bootstrapTrustedVenue,
  type BootstrapTrustedVenueOptions,
} from "../venue/trusted-venue.js";
import type {
  TrustedInstrument,
  TrustedVenueSession,
  VenueReleaseConfig,
} from "../venue/types.js";
import { ExternalWalletController } from "../wallet/wallet-standard.js";
import type {
  OrderLifecycleKind,
  TraderOrderDraft,
  TraderShellActions,
  TraderShellSnapshot,
} from "../ui/types.js";
import {
  createBrowserPrivateRuntime,
  type BrowserPrivateRuntime,
} from "./runtime.js";

const U64_MAX = (1n << 64n) - 1n;

function decimalParts(
  value: string,
  label: string,
): {
  numerator: bigint;
  denominator: bigint;
} {
  if (!/^(0|[1-9]\d*)(\.\d+)?$/.test(value)) {
    throw new Error(`${label} must be a canonical decimal`);
  }
  const [whole, fraction = ""] = value.split(".");
  return {
    numerator: BigInt(`${whole}${fraction}`),
    denominator: 10n ** BigInt(fraction.length),
  };
}

export function decimalToAtoms(value: string, decimals: number): bigint {
  if (!Number.isInteger(decimals) || decimals < 0 || decimals > 19) {
    throw new Error("token decimals are out of range");
  }
  const parsed = decimalParts(value, "amount");
  const scaled = parsed.numerator * 10n ** BigInt(decimals);
  if (scaled % parsed.denominator !== 0n) {
    throw new Error("amount has more precision than the token supports");
  }
  const atoms = scaled / parsed.denominator;
  if (atoms <= 0n || atoms > U64_MAX)
    throw new Error("amount is not a positive u64");
  return atoms;
}

export function decimalToPriceTicks(
  value: string,
  priceScale: bigint,
  tickSize: bigint,
): bigint {
  if (priceScale <= 0n || tickSize <= 0n) {
    throw new Error("market price scale and tick size must be positive");
  }
  const parsed = decimalParts(value, "limit price");
  const scaled = parsed.numerator * priceScale;
  if (scaled % parsed.denominator !== 0n) {
    throw new Error("limit price cannot be represented by the market scale");
  }
  const ticks = scaled / parsed.denominator;
  if (ticks > U64_MAX || ticks % tickSize !== 0n) {
    throw new Error("limit price is not on the governed tick size");
  }
  return ticks;
}

function formatUnits(value: bigint | string, decimals: number): string {
  const amount = typeof value === "string" ? BigInt(value) : value;
  if (decimals === 0) return amount.toString();
  const scale = 10n ** BigInt(decimals);
  const fraction = (amount % scale)
    .toString()
    .padStart(decimals, "0")
    .replace(/0+$/, "");
  return fraction
    ? `${amount / scale}.${fraction}`
    : (amount / scale).toString();
}

function formatScaled(value: string | bigint, scale: bigint): string {
  const amount = BigInt(value);
  const whole = amount / scale;
  const remainder = amount % scale;
  if (remainder === 0n) return whole.toString();
  // Governed scales are normally powers of ten. The fallback is bounded and
  // display-only; signing always uses the exact integer parsed above.
  const power = scale.toString().match(/^10*$/)?.[0].length;
  if (power) {
    return `${whole}.${remainder
      .toString()
      .padStart(power - 1, "0")
      .replace(/0+$/, "")}`;
  }
  return `${whole}.${((remainder * 100_000_000n) / scale)
    .toString()
    .padStart(8, "0")
    .replace(/0+$/, "")}`;
}

function mintHex(base58: string): string {
  return Array.from(new PublicKey(base58).toBytes(), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
}

export interface BrowserTraderControllerOptions {
  release: VenueReleaseConfig;
  prover: BrowserProverSuite;
  circuitVersion: string;
  provingKeyVersion: string;
  /** Runs seed-bound, multi-market chain recovery through the custody Worker. */
  recover(
    vault: BrowserVault,
    venue: TrustedVenueSession,
  ): Promise<RecoveryReport>;
  vault?: BrowserVault;
  wallet?: ExternalWalletController;
  bootstrapOptions?: BootstrapTrustedVenueOptions;
  venueLabel?: string;
  databaseName?: string;
  onError?(error: Error): void;
}

type Listener = (snapshot: TraderShellSnapshot) => void;

/** Observable adapter consumed by React without exposing privileged objects. */
export class BrowserTraderController {
  readonly #options: BrowserTraderControllerOptions;
  readonly #vault: BrowserVault;
  readonly #wallet: ExternalWalletController;
  readonly #listeners = new Set<Listener>();
  #venue: TrustedVenueSession | null = null;
  #runtime: BrowserPrivateRuntime | null = null;
  #selectedSymbol: string | undefined;
  #venueError: string | undefined;
  #walletError: string | undefined;
  #checking = true;
  #snapshot: TraderShellSnapshot;
  #updatePromise: Promise<void> | null = null;

  constructor(options: BrowserTraderControllerOptions) {
    this.#options = options;
    this.#vault = options.vault ?? new BrowserVault();
    this.#wallet = options.wallet ?? new ExternalWalletController();
    this.#snapshot = this.#emptySnapshot({ state: "locked" });
  }

  #emptySnapshot(vault: VaultStatus): TraderShellSnapshot {
    return {
      venue: {
        state: this.#checking ? "checking" : "failed",
        label: this.#options.venueLabel ?? "Darknyx private venue",
        message: this.#venueError,
      },
      vault,
      wallet: {
        state: this.#wallet.current() ? "connected" : "disconnected",
        ...this.#wallet.current(),
        availableWallets: this.#wallet.available(),
        error: this.#walletError,
      },
      instruments: [],
      selectedSymbol: this.#selectedSymbol,
      balances: [],
      proofReadiness: { ready: 0, proving: 0, stale: 0 },
      orders: [],
    };
  }

  snapshot(): TraderShellSnapshot {
    return structuredClone(this.#snapshot);
  }

  subscribe(listener: Listener): () => void {
    this.#listeners.add(listener);
    listener(this.snapshot());
    return () => this.#listeners.delete(listener);
  }

  #emit(): void {
    const snapshot = this.snapshot();
    for (const listener of this.#listeners) listener(snapshot);
  }

  async start(): Promise<void> {
    await this.#bootVenue();
  }

  async #bootVenue(): Promise<void> {
    this.#runtime?.close();
    this.#runtime = null;
    this.#checking = true;
    this.#venueError = undefined;
    await this.#update();
    try {
      this.#venue = await bootstrapTrustedVenue(
        this.#options.release,
        this.#options.bootstrapOptions,
      );
      this.#selectedSymbol =
        this.#venue.instruments.find((instrument) => instrument.tradingEnabled)
          ?.symbol ?? this.#venue.instruments[0]?.symbol;
      this.#checking = false;
      if ((await this.#vault.status()).state === "unlocked") {
        await this.#openRuntime();
      }
    } catch (error) {
      this.#venue = null;
      this.#checking = false;
      this.#venueError = error instanceof Error ? error.message : String(error);
      this.#options.onError?.(
        error instanceof Error ? error : new Error(String(error)),
      );
    }
    await this.#update();
  }

  async #openRuntime(): Promise<void> {
    if (!this.#venue || this.#runtime) return;
    this.#runtime = await createBrowserPrivateRuntime({
      release: this.#options.release,
      venue: this.#venue,
      vault: this.#vault,
      prover: this.#options.prover,
      circuitVersion: this.#options.circuitVersion,
      provingKeyVersion: this.#options.provingKeyVersion,
      databaseName: this.#options.databaseName,
      recover: () => this.#options.recover(this.#vault, this.#venue!),
      onChange: () => void this.#update(),
      onError: (error) => this.#options.onError?.(error),
    });
  }

  async #update(): Promise<void> {
    if (this.#updatePromise) return this.#updatePromise;
    this.#updatePromise = (async () => {
      const vault = await this.#vault.status();
      if (!this.#venue) {
        this.#snapshot = this.#emptySnapshot(vault);
        this.#emit();
        return;
      }
      const [balances, proofs, orders] = this.#runtime
        ? await Promise.all([
            this.#runtime.trader.balances(),
            this.#runtime.trader.proofReadiness(),
            this.#runtime.inventory.listOrders(),
          ])
        : [[], { ready: 0, proving: 0, stale: 0 }, []];
      const byMint = new Map<string, { symbol: string; decimals: number }>();
      for (const market of this.#venue.instruments) {
        byMint.set(mintHex(market.baseMint), {
          symbol: market.symbol.split("-")[0],
          decimals: market.baseDecimals,
        });
        byMint.set(mintHex(market.quoteMint), {
          symbol: market.symbol.split("-")[1],
          decimals: market.quoteDecimals,
        });
      }
      const marketBySymbol = new Map(
        this.#venue.instruments.map((market) => [market.symbol, market]),
      );
      this.#snapshot = {
        venue: {
          state: "trusted",
          label: this.#options.venueLabel ?? "Darknyx private venue",
          composeHash: this.#venue.attestation.composeHash,
          governanceSlot: this.#venue.finalizedGovernanceSlot.toString(),
          message: this.#venue.status.degraded
            ? "Some markets are locally paused; healthy instruments remain available."
            : undefined,
        },
        vault,
        wallet: {
          state: this.#wallet.current()
            ? "connected"
            : this.#walletError
              ? "failed"
              : "disconnected",
          ...this.#wallet.current(),
          availableWallets: this.#wallet.available(),
          error: this.#walletError,
        },
        instruments: this.#venue.instruments.map((market) => ({
          symbol: market.symbol,
          baseSymbol: market.symbol.split("-")[0],
          quoteSymbol: market.symbol.split("-")[1],
          tradingEnabled: market.tradingEnabled,
          minOrderSize: formatUnits(market.minOrderSize, market.baseDecimals),
          tickSize: formatScaled(market.tickSize, market.priceScale),
        })),
        selectedSymbol: this.#selectedSymbol,
        balances: balances.map((balance) => {
          const metadata = byMint.get(balance.mint) ?? {
            symbol: "Unknown",
            decimals: 0,
          };
          return {
            mint: balance.mint,
            symbol: metadata.symbol,
            spendable: formatUnits(balance.spendableAtoms, metadata.decimals),
            reserved: formatUnits(balance.reservedAtoms, metadata.decimals),
            pendingSettlement: formatUnits(
              balance.pendingSettlementAtoms,
              metadata.decimals,
            ),
          };
        }),
        proofReadiness: proofs,
        orders: orders.map((order) => {
          const market = marketBySymbol.get(order.marketSymbol);
          return {
            orderId: order.orderId,
            symbol: order.marketSymbol,
            side: order.side,
            amount: market
              ? formatUnits(order.baseAmountAtoms, market.baseDecimals)
              : order.baseAmountAtoms,
            limitPrice: market
              ? formatScaled(order.limitPriceTicks, market.priceScale)
              : order.limitPriceTicks,
            filled:
              market && order.filledAtoms
                ? formatUnits(order.filledAtoms, market.baseDecimals)
                : order.filledAtoms,
            kind: order.kind as OrderLifecycleKind,
            reason: order.reason,
            updatedAt: new Date(order.updatedAtMs).toISOString(),
          };
        }),
        lastUpdated: new Date().toISOString(),
      };
      this.#emit();
    })().finally(() => {
      this.#updatePromise = null;
    });
    return this.#updatePromise;
  }

  readonly actions: TraderShellActions = {
    retryVenue: () => this.#bootVenue(),
    selectInstrument: (symbol) => {
      if (!this.#venue?.instruments.some((market) => market.symbol === symbol))
        return;
      this.#selectedSymbol = symbol;
      void this.#update();
    },
    connectWallet: async (name) => {
      this.#walletError = undefined;
      try {
        await this.#wallet.connect(name);
      } catch (error) {
        this.#walletError =
          error instanceof Error ? error.message : String(error);
      }
      await this.#update();
    },
    disconnectWallet: async () => {
      await this.#wallet.disconnect();
      await this.#update();
    },
    provisionVault: async () => {
      await this.#vault.provision("Darknyx private vault");
      await this.#openRuntime();
      await this.#update();
    },
    unlockVault: async () => {
      await this.#vault.unlock();
      await this.#openRuntime();
      await this.#update();
    },
    lockVault: async () => {
      this.#runtime?.close();
      this.#runtime = null;
      await this.#vault.lock();
      await this.#update();
    },
    refresh: async () => {
      await this.#runtime?.refresh("manual");
      await this.#update();
    },
    submitOrder: (draft) => this.submitOrder(draft),
    cancelOrder: async (orderId) => {
      if (!this.#runtime) throw new Error("private runtime is locked");
      const cancel = await this.#runtime.authorizer.authorizeCancel(orderId);
      await this.#runtime.transport.cancel(orderId, cancel);
      await this.#update();
    },
  };

  async submitOrder(draft: TraderOrderDraft): Promise<SubmitIntentResult> {
    if (!this.#runtime || !this.#venue) {
      return { status: "pending", reason: "INVENTORY_UNAVAILABLE" };
    }
    const market = this.#venue.instruments.find(
      (candidate) => candidate.symbol === draft.marketSymbol,
    );
    if (!market || !market.tradingEnabled) {
      return { status: "rejected", code: "INVALID_INTENT", retryable: false };
    }
    const amount = decimalToAtoms(draft.amount, market.baseDecimals);
    if (amount < market.minOrderSize) {
      return { status: "rejected", code: "INVALID_INTENT", retryable: false };
    }
    const price = decimalToPriceTicks(
      draft.limitPrice,
      market.priceScale,
      market.tickSize,
    );
    const result = await this.#runtime.trader.submitIntent({
      protocolVersion: 1,
      marketSymbol: market.symbol,
      side: draft.side,
      baseAmountAtoms: amount.toString(),
      limitPriceTicks: price.toString(),
      attributes: {
        orderType: draft.orderType,
        minFillSize: "0",
        expirySlot: "0",
      },
    });
    await this.#update();
    return result;
  }

  destroy(): void {
    this.#runtime?.close();
    this.#runtime = null;
    this.#vault.destroy();
    this.#listeners.clear();
  }
}

export const controllerInternals = { formatUnits, formatScaled };
