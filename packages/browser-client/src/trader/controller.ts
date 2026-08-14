import { PublicKey } from "@solana/web3.js";
import type { SubmitIntentResult, VaultStatus } from "@darknyx/client-core";
import { gtcExpirySlot } from "@darknyx/sdk/browser-orders";
import { fetchServerTime } from "@darknyx/sdk/browser-attestation";

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
  TraderOrderDraft,
  TraderShellActions,
  TraderShellSnapshot,
} from "../ui/types.js";
import { BrowserAccountOperations } from "../account/account-operations.js";
import { inventoryStoreForVault } from "../inventory/browser-recovery.js";
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

export async function defaultGtcExpirySlot(
  gatewayUrl: string,
  fetchImpl: typeof fetch = globalThis.fetch.bind(globalThis),
): Promise<bigint> {
  const time = await fetchServerTime(gatewayUrl, { fetchImpl });
  if (!Number.isSafeInteger(time.slot) || time.slot < 0) {
    throw new Error("venue /time returned an invalid Solana slot");
  }
  return gtcExpirySlot(time.slot);
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
  #account: BrowserAccountOperations | null = null;
  #accountOperation: TraderShellSnapshot["accountOperation"];
  #accountOperationInFlight = false;
  #selectedSymbol: string | undefined;
  #venueError: string | undefined;
  #walletError: string | undefined;
  #checking = true;
  #snapshot: TraderShellSnapshot;
  #updatePromise: Promise<void> | null = null;
  #updateQueued = false;
  #runtimePromise: Promise<BrowserPrivateRuntime | null> | null = null;
  #runtimeGeneration = 0;

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
    this.#runtimeGeneration += 1;
    this.#runtime?.close();
    this.#runtime = null;
    this.#account = null;
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
    if (this.#runtimePromise) {
      await this.#runtimePromise;
      if (!this.#runtime && this.#venue) await this.#openRuntime();
      return;
    }
    const venue = this.#venue;
    const generation = this.#runtimeGeneration;
    this.#runtimePromise = (async () => {
      const runtime = await createBrowserPrivateRuntime({
        release: this.#options.release,
        venue,
        vault: this.#vault,
        prover: this.#options.prover,
        circuitVersion: this.#options.circuitVersion,
        provingKeyVersion: this.#options.provingKeyVersion,
        databaseName: this.#options.databaseName,
        recover: () => this.#options.recover(this.#vault, venue),
        onChange: () => void this.#update(),
        onError: (error) => this.#options.onError?.(error),
      });
      if (generation !== this.#runtimeGeneration || venue !== this.#venue) {
        runtime.close();
        return null;
      }
      this.#runtime = runtime;
      return runtime;
    })().finally(() => {
      this.#runtimePromise = null;
    });
    const openedRuntime = await this.#runtimePromise;
    if (!openedRuntime || venue !== this.#venue) return;
    this.#account = new BrowserAccountOperations({
      release: this.#options.release,
      venue,
      vault: this.#vault,
      inventory: openedRuntime.inventory,
      prover: this.#options.prover,
      wallet: this.#wallet,
      onProgress: (kind, stage) => {
        this.#accountOperation = {
          kind,
          state: stage,
          message: stage.replaceAll("_", " "),
        };
        void this.#update();
      },
    });
  }

  async #update(): Promise<void> {
    this.#updateQueued = true;
    if (this.#updatePromise) return this.#updatePromise;
    this.#updatePromise = (async () => {
      while (this.#updateQueued) {
        this.#updateQueued = false;
        try {
          await this.#performUpdate();
        } catch (error) {
          this.#options.onError?.(
            error instanceof Error ? error : new Error(String(error)),
          );
        }
      }
    })().finally(() => {
      this.#updatePromise = null;
      if (this.#updateQueued) void this.#update();
    });
    return this.#updatePromise;
  }

  async #performUpdate(): Promise<void> {
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
        const metadata = byMint.get(balance.mint);
        if (!metadata) {
          throw new Error(
            `inventory contains unsupported mint ${balance.mint}`,
          );
        }
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
          kind: order.kind,
          reason: order.reason,
          updatedAt: new Date(order.updatedAtMs).toISOString(),
        };
      }),
      accountOperation: this.#accountOperation,
      lastUpdated: new Date().toISOString(),
    };
    this.#emit();
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
      this.#runtimeGeneration += 1;
      this.#runtime?.close();
      this.#runtime = null;
      this.#account = null;
      await this.#vault.lock();
      await this.#update();
    },
    refresh: async () => {
      await this.#runtime?.refresh("manual");
      await this.#update();
    },
    submitOrder: (draft) => this.submitOrder(draft),
    cancelOrder: async (orderId) => {
      try {
        if (!this.#runtime) throw new Error("private runtime is locked");
        const cancel = await this.#runtime.authorizer.authorizeCancel(orderId);
        await this.#runtime.transport.cancel(orderId, cancel);
      } catch (error) {
        const normalized =
          error instanceof Error ? error : new Error(String(error));
        this.#options.onError?.(normalized);
        const order = await this.#runtime?.inventory.order(orderId);
        if (order) {
          await this.#runtime?.inventory.updateOrder(orderId, {
            kind: order.kind,
            reason: `Cancellation failed: ${normalized.message}`,
          });
        }
      }
      await this.#update();
    },
    exportBackup: (passphrase) => this.#vault.exportBackup(passphrase),
    restoreBackup: async (backup, passphrase) => {
      this.#runtimeGeneration += 1;
      this.#runtime?.close();
      this.#runtime = null;
      this.#account = null;
      await this.#vault.restoreBackup(
        backup,
        passphrase,
        "Restored Darknyx private vault",
      );
      const store = await inventoryStoreForVault(
        this.#vault,
        this.#options.databaseName,
      );
      await store.clear();
      await this.#openRuntime();
      await this.#update();
    },
    deposit: (draft) => this.#runAccountAmount("deposit", draft),
    withdraw: (draft) => this.#runAccountAmount("withdraw", draft),
    merge: (marketSymbol, asset) => this.#runMerge(marketSymbol, asset),
  };

  #asset(
    marketSymbol: string,
    asset: "base" | "quote",
  ): { mint: string; decimals: number } {
    const market = this.#venue?.instruments.find(
      (candidate) => candidate.symbol === marketSymbol,
    );
    if (!market) throw new Error("select an attested market");
    return asset === "base"
      ? { mint: market.baseMint, decimals: market.baseDecimals }
      : { mint: market.quoteMint, decimals: market.quoteDecimals };
  }

  async #requirePrivateRuntime(): Promise<{
    runtime: BrowserPrivateRuntime;
    account: BrowserAccountOperations;
  }> {
    if ((await this.#vault.status()).state !== "unlocked") {
      throw new Error("unlock the private vault first");
    }
    // Unlock/provision makes the custody Worker usable before finalized-chain
    // recovery and the authenticated stream have finished opening. Account
    // actions can therefore race the in-flight runtime even though the header
    // already (correctly) reports "Vault unlocked". Join that work instead of
    // misreporting the unlocked vault as locked.
    await this.#openRuntime();
    if (!this.#runtime || !this.#account) {
      throw new Error("private vault runtime did not finish initializing");
    }
    return { runtime: this.#runtime, account: this.#account };
  }

  async #runAccountAmount(
    kind: "deposit" | "withdraw",
    draft: { marketSymbol: string; asset: "base" | "quote"; amount: string },
  ): Promise<void> {
    if (this.#accountOperationInFlight) return;
    this.#accountOperationInFlight = true;
    try {
      const { account, runtime } = await this.#requirePrivateRuntime();
      const asset = this.#asset(draft.marketSymbol, draft.asset);
      const result = await account[kind]({
        tokenMint: asset.mint,
        amount: decimalToAtoms(draft.amount, asset.decimals),
      });
      this.#accountOperation = {
        kind,
        state: result.status,
        signature: result.signature,
        message:
          result.status === "finalized"
            ? `${kind} finalized on Solana`
            : "transaction submitted; finalized reconciliation is still pending",
      };
      await runtime.refresh(`${kind} ${result.status}`);
    } catch (error) {
      this.#accountOperation = {
        kind,
        state: "failed",
        message: error instanceof Error ? error.message : String(error),
      };
    } finally {
      this.#accountOperationInFlight = false;
      await this.#update();
    }
  }

  async #runMerge(
    marketSymbol: string,
    assetKind: "base" | "quote",
  ): Promise<void> {
    if (this.#accountOperationInFlight) return;
    this.#accountOperationInFlight = true;
    try {
      const { account, runtime } = await this.#requirePrivateRuntime();
      const asset = this.#asset(marketSymbol, assetKind);
      const result = await account.merge(asset.mint);
      this.#accountOperation = {
        kind: "merge",
        state: result.status,
        signature: result.signature,
        message:
          result.status === "finalized"
            ? "note consolidation finalized on Solana"
            : "merge submitted; finalized reconciliation is still pending",
      };
      await runtime.refresh(`merge ${result.status}`);
    } catch (error) {
      this.#accountOperation = {
        kind: "merge",
        state: "failed",
        message: error instanceof Error ? error.message : String(error),
      };
    } finally {
      this.#accountOperationInFlight = false;
      await this.#update();
    }
  }

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
    let amount: bigint;
    let price: bigint;
    try {
      amount = decimalToAtoms(draft.amount, market.baseDecimals);
      price = decimalToPriceTicks(
        draft.limitPrice,
        market.priceScale,
        market.tickSize,
      );
    } catch {
      return { status: "rejected", code: "INVALID_INTENT", retryable: false };
    }
    if (amount < market.minOrderSize) {
      return { status: "rejected", code: "INVALID_INTENT", retryable: false };
    }
    // Zero is the intentional market-ask sentinel. Only bids require a
    // positive cap; the inventory plane repeats this invariant before reserve.
    if (draft.side === "bid" && price === 0n) {
      return { status: "rejected", code: "INVALID_INTENT", retryable: false };
    }
    const expirySlot = await defaultGtcExpirySlot(
      this.#options.release.gatewayUrl,
      this.#options.bootstrapOptions?.fetchImpl,
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
        expirySlot: expirySlot.toString(),
      },
    });
    await this.#update();
    return result;
  }

  destroy(): void {
    this.#runtimeGeneration += 1;
    this.#runtime?.close();
    this.#runtime = null;
    this.#account = null;
    this.#vault.destroy();
    this.#listeners.clear();
  }
}

export const controllerInternals = { formatUnits, formatScaled };
