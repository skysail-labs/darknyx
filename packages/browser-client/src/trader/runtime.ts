import { Connection, PublicKey } from "@solana/web3.js";
import type { TraderClientPort } from "@darknyx/client-core";
import { createIntentCoordinator } from "@darknyx/client-core/internal";
import {
  TradingClient,
  type SendableWebSocketFactory,
} from "@darknyx/sdk/browser-orders";

import type { BrowserVault } from "../custody/browser-vault.js";
import { BrowserInventory } from "../inventory/browser-inventory.js";
import { SolanaFinalizedRootSource } from "../inventory/finalized-root-source.js";
import { BrowserInputProofProducer } from "../inventory/input-proof-producer.js";
import { inventoryStoreForVault } from "../inventory/browser-recovery.js";
import type { RecoveryReport } from "../inventory/types.js";
import type { BrowserProverSuite } from "../prover/browser-prover.js";
import type {
  TrustedVenueSession,
  VenueReleaseConfig,
} from "../venue/types.js";
import { BrowserIntentAuthorizer } from "./intent-authorizer.js";
import { BrowserLifecycleStream } from "./lifecycle-stream.js";
import { BrowserOrderTransport } from "./order-transport.js";

const hex = (bytes: Uint8Array): string =>
  Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
const BROWSER_CANCEL_ON_DISCONNECT = false;

function decodeOpenOrderIds(value: unknown): string[] {
  if (!value || typeof value !== "object") {
    throw new Error("venue account snapshot must be an object");
  }
  const openOrders = (value as { open_orders?: unknown }).open_orders;
  if (!Array.isArray(openOrders)) {
    throw new Error("venue account snapshot is missing open_orders");
  }
  return openOrders.map((entry) => {
    if (!entry || typeof entry !== "object") {
      throw new Error("venue open order must be an object");
    }
    const orderId = (entry as { order_id?: unknown }).order_id;
    if (typeof orderId !== "string" || !/^[0-9a-f]{32}$/.test(orderId)) {
      throw new Error("venue open order has an invalid order id");
    }
    return orderId;
  });
}

async function readVenueOpenOrderIds(
  gatewayUrl: string,
  tokenProvider: () => Promise<string>,
  fetchImpl: typeof fetch,
): Promise<string[]> {
  const response = await fetchImpl(new URL("account", gatewayUrl), {
    headers: { authorization: `Bearer ${await tokenProvider()}` },
  });
  if (!response.ok) {
    throw new Error(`venue account reconciliation failed (${response.status})`);
  }
  return decodeOpenOrderIds(await response.json());
}

function websocketOrigin(gatewayUrl: string): string {
  const url = new URL(gatewayUrl);
  if (url.protocol === "https:") url.protocol = "wss:";
  else if (url.protocol === "http:") url.protocol = "ws:";
  else throw new Error("venue gateway must use HTTP or HTTPS");
  return url.href.replace(/\/$/, "");
}

export interface BrowserPrivateRuntimeOptions {
  release: VenueReleaseConfig;
  venue: TrustedVenueSession;
  vault: BrowserVault;
  prover: BrowserProverSuite;
  circuitVersion: string;
  provingKeyVersion: string;
  /** Seed-bound recovery implementation; decrypted results never reach page UI. */
  recover(): Promise<RecoveryReport>;
  databaseName?: string;
  fetchImpl?: typeof fetch;
  webSocketFactory?: SendableWebSocketFactory;
  onChange?(): void;
  onError?(error: Error): void;
  onReconcile?(reason: string): void;
  refreshTimeoutMs?: number;
}

export interface BrowserPrivateRuntime {
  inventory: BrowserInventory;
  trader: TraderClientPort;
  authorizer: BrowserIntentAuthorizer;
  transport: BrowserOrderTransport;
  refresh(reason?: string): Promise<void>;
  close(): void;
}

/**
 * Compose custody, finalized chain state, cached proving, order transport and
 * lifecycle notifications. This module is internal: the page receives only a
 * TraderClientPort and view/action snapshots from the controller above it.
 */
export async function createBrowserPrivateRuntime(
  options: BrowserPrivateRuntimeOptions,
): Promise<BrowserPrivateRuntime> {
  const programId = new PublicKey(options.release.vaultProgramId);
  const connection = new Connection(options.release.rpcUrl, "finalized");
  const rootSource = new SolanaFinalizedRootSource(connection, programId);
  const store = await inventoryStoreForVault(
    options.vault,
    options.databaseName,
  );
  const inventory = await BrowserInventory.create({
    store,
    markets: options.venue.instruments.map((market) => ({
      symbol: market.symbol,
      baseMintHex: hex(new PublicKey(market.baseMint).toBytes()),
      quoteMintHex: hex(new PublicKey(market.quoteMint).toBytes()),
      priceScale: market.priceScale,
      feeRateBps: BigInt(options.venue.feeRateBps),
    })),
    circuitVersion: options.circuitVersion,
    provingKeyVersion: options.provingKeyVersion,
  });
  const tokenProvider = () => options.venue.token();
  const proofProducer = new BrowserInputProofProducer({
    vault: options.vault,
    prover: options.prover,
    gatewayUrl: options.release.gatewayUrl,
    tokenProvider,
    fetchImpl: options.fetchImpl,
  });

  const refreshTimeoutMs = options.refreshTimeoutMs ?? 30_000;
  if (!Number.isFinite(refreshTimeoutMs) || refreshTimeoutMs <= 0) {
    throw new Error("refresh timeout must be positive");
  }
  let refreshPromise: Promise<void> | null = null;
  let refreshQueued = false;
  const reasons: string[] = [];
  const runRefresh = async (reason: string): Promise<void> => {
    options.onReconcile?.(reason);
    const snapshotStartedAtMs = Date.now();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const work = (async () => {
      const treeIds = Array.from(
        { length: options.venue.numTrees },
        (_unused, treeId) => treeId,
      );
      const [rings, recovery, openOrderIds] = await Promise.all([
        rootSource.read(treeIds),
        options.recover(),
        readVenueOpenOrderIds(
          options.release.gatewayUrl,
          tokenProvider,
          options.fetchImpl ?? globalThis.fetch.bind(globalThis),
        ),
      ]);
      await inventory.synchronizeFinalizedRoots(rings);
      await inventory.recover(
        recovery,
        (tag, treeId) => rootSource.isConsumed(tag, treeId),
        (tag, treeId) => rootSource.isLocked(tag, treeId),
      );
      await inventory.reconcileVenueOpenOrders(openOrderIds, {
        snapshotStartedAtMs,
        // During boot no placement can be in flight because this runtime has
        // not been returned to the controller yet. Every later refresh can
        // overlap authorization or POST /orders and must preserve that state.
        preserveSubmitting: reason !== "startup",
      });
      options.onChange?.();
      // Proving is deliberately background work. A submit action only consumes
      // a ready cache entry and never blocks the UI on witness generation.
      void inventory
        .refreshExpiringProofs(proofProducer.produce)
        .then(() => options.onChange?.())
        .catch((error) =>
          options.onError?.(
            error instanceof Error ? error : new Error(String(error)),
          ),
        );
    })();
    const timeout = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(
        () =>
          reject(new Error(`finalized reconciliation timed out: ${reason}`)),
        refreshTimeoutMs,
      );
    });
    try {
      await Promise.race([work, timeout]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  };
  const refresh = (reason = "manual"): Promise<void> => {
    reasons.push(reason);
    refreshQueued = true;
    if (refreshPromise) return refreshPromise;
    refreshPromise = (async () => {
      while (refreshQueued) {
        refreshQueued = false;
        const runReasons = reasons.splice(0);
        await runRefresh(runReasons.join("; "));
      }
    })().finally(() => {
      refreshPromise = null;
      if (refreshQueued) {
        void refresh("queued after reconciliation completion").catch((error) =>
          options.onError?.(
            error instanceof Error ? error : new Error(String(error)),
          ),
        );
      }
    });
    return refreshPromise;
  };

  const initialToken = await tokenProvider();
  const stream = new TradingClient({
    gatewayWsUrl: websocketOrigin(options.release.gatewayUrl),
    token: initialToken,
    tokenProvider,
    // A browser reload or brief network transition must not silently behave
    // like "cancel all". Browser GTC orders are already bounded by their
    // signed expiry and are restored from /account after reconnect. Market-
    // maker daemons retain their separate fail-safe disconnect cancellation.
    cancelOnDisconnect: BROWSER_CANCEL_ON_DISCONNECT,
    webSocketFactory: options.webSocketFactory,
    onError: options.onError,
    onSequenceGap: (expected, received) =>
      void refresh(`sequence gap ${expected}:${received}`),
  });
  const authorizer = new BrowserIntentAuthorizer({
    vault: options.vault,
    inventory,
    bootSessionId: options.venue.attestation.bootSessionId.toLowerCase(),
  });
  const transport = new BrowserOrderTransport(stream, inventory);
  const trader = createIntentCoordinator({
    inventory,
    authorization: authorizer,
    transport,
  });
  const lifecycle = new BrowserLifecycleStream({
    stream,
    inventory,
    reconcile: refresh,
    onChange: options.onChange,
    onError: options.onError,
  });

  await refresh("startup");
  lifecycle.start();

  let closed = false;
  return {
    inventory,
    trader,
    authorizer,
    transport,
    refresh,
    close() {
      if (closed) return;
      closed = true;
      lifecycle.close();
      stream.close();
    },
  };
}

export const runtimeInternals = {
  decodeOpenOrderIds,
  cancelOnDisconnect: BROWSER_CANCEL_ON_DISCONNECT,
};
