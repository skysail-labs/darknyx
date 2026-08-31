import {
  Activity,
  AlertTriangle,
  ChevronDown,
  KeyRound,
  LineChart,
  LoaderCircle,
  Lock,
  LogOut,
  RefreshCw,
  ShieldCheck,
  Wallet,
  WalletCards,
} from "lucide-react";
import { useEffect, useRef, useState } from "react";

import { AccountDialog, type AccountTab } from "./account-dialog.js";
import { HorizonMark } from "./mark.js";
import { OrderTicket } from "./order-ticket.js";
import { lifecycleCopy, short, stateTone } from "./primitives.js";
import type { OrderLifecycleKind, TraderShellProps } from "./types.js";

type OrderFilter = "all" | "working" | "closed";

const WORKING: OrderLifecycleKind[] = [
  "submitting",
  "open",
  "pending_settlement",
  "partially_filled",
  "ambiguous",
];

function VenueBadge({ venue }: Pick<TraderShellProps["snapshot"], "venue">) {
  const icon =
    venue.state === "checking" ? (
      <LoaderCircle className="spin" />
    ) : venue.state === "trusted" ? (
      <ShieldCheck />
    ) : (
      <AlertTriangle />
    );
  return (
    <details
      className="trust-control"
      onKeyDown={(event) => {
        if (event.key !== "Escape") return;
        event.currentTarget.removeAttribute("open");
        event.currentTarget.querySelector("summary")?.focus();
      }}
    >
      <summary className={`trust-badge is-${venue.state}`}>
        <span className="trust-icon" aria-hidden="true">
          {icon}
        </span>
        <span className="trust-copy">
          <b>
            {venue.state === "trusted"
              ? "Attested"
              : venue.state === "degraded"
                ? "Partially available"
                : venue.state === "checking"
                  ? "Verifying"
                  : "Unavailable"}
          </b>
        </span>
        <ChevronDown aria-hidden="true" />
      </summary>
      <div className="trust-menu panel-popover">
        <p className="eyebrow">Venue identity</p>
        <div>
          <span>Venue</span>
          <b>{venue.label}</b>
        </div>
        <div>
          <span>Compose</span>
          <b className="mono">
            {venue.composeHash ? short(venue.composeHash, 8, 6) : "Pending"}
          </b>
        </div>
        <div>
          <span>Governance slot</span>
          <b className="mono">{venue.governanceSlot ?? "Pending"}</b>
        </div>
        {venue.message && <p className="muted">{venue.message}</p>}
      </div>
    </details>
  );
}

function WalletControl({ snapshot, actions }: TraderShellProps) {
  const [open, setOpen] = useState(false);
  const trigger = useRef<HTMLButtonElement>(null);
  const wallet = snapshot.wallet;

  useEffect(() => {
    if (!open) return;
    function closeOnEscape(event: globalThis.KeyboardEvent) {
      if (event.key !== "Escape") return;
      setOpen(false);
      trigger.current?.focus();
    }
    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [open]);

  if (wallet.state === "connected" && wallet.address) {
    return (
      <div className="wallet-control">
        <button
          ref={trigger}
          className="quiet-button mono"
          type="button"
          onClick={() => setOpen(!open)}
          aria-expanded={open}
          aria-controls="darknyx-wallet-menu"
          aria-label={`Wallet ${short(wallet.address)}`}
        >
          <span className="wallet-dot" aria-hidden="true" />
          <span className="wallet-address">{short(wallet.address)}</span>
          <ChevronDown aria-hidden="true" />
        </button>
        {open && (
          <div
            className="wallet-menu panel-popover"
            id="darknyx-wallet-menu"
            aria-label="Connected wallet"
          >
            <p className="eyebrow">Connected wallet</p>
            <strong>{wallet.walletName}</strong>
            <span className="mono muted">{wallet.address}</span>
            <button
              type="button"
              onClick={() => void actions.disconnectWallet()}
            >
              <LogOut aria-hidden="true" /> Disconnect
            </button>
          </div>
        )}
      </div>
    );
  }
  const available = wallet.availableWallets[0];
  const chooseWallet = wallet.availableWallets.length > 1;
  return (
    <div className="wallet-control">
      <button
        ref={trigger}
        className="quiet-button"
        type="button"
        disabled={wallet.state === "connecting" || !available}
        onClick={() => {
          if (!available) return;
          if (chooseWallet) setOpen(!open);
          else void actions.connectWallet(available.name);
        }}
        aria-expanded={chooseWallet ? open : undefined}
        aria-controls={chooseWallet ? "darknyx-wallet-menu" : undefined}
        aria-label={
          wallet.state === "connecting"
            ? "Connecting wallet"
            : wallet.state === "failed"
              ? "Retry wallet connection"
              : available
                ? `Connect ${available.name}`
                : "No compatible wallet found"
        }
      >
        <WalletCards aria-hidden="true" />
        <span className="wallet-label">
          {wallet.state === "connecting"
            ? "Connecting"
            : wallet.state === "failed"
              ? "Retry wallet"
              : available
                ? "Connect wallet"
                : "Install wallet"}
        </span>
      </button>
      {open && chooseWallet && (
        <div
          className="wallet-menu panel-popover"
          id="darknyx-wallet-menu"
          aria-label="Choose wallet"
        >
          <p className="eyebrow">Choose wallet</p>
          {wallet.availableWallets.map((candidate) => (
            <button
              key={candidate.name}
              type="button"
              onClick={() => {
                setOpen(false);
                void actions.connectWallet(candidate.name);
              }}
            >
              <img src={candidate.icon} alt="" aria-hidden="true" />
              <strong>{candidate.name}</strong>
            </button>
          ))}
        </div>
      )}
      {wallet.state === "failed" && wallet.error && (
        <p className="wallet-error" role="alert">
          {wallet.error}
        </p>
      )}
    </div>
  );
}

function KeyringControl({ snapshot, actions }: TraderShellProps) {
  const { vault } = snapshot;
  const locked = vault.state !== "unlocked";
  const label =
    vault.state === "unprovisioned"
      ? "Create access"
      : vault.state === "unlocked"
        ? "Unlocked"
        : vault.state === "busy"
          ? "Working"
          : "Unlock";
  const action =
    vault.state === "unprovisioned"
      ? actions.provisionVault
      : vault.state === "unlocked"
        ? actions.lockVault
        : actions.unlockVault;
  return (
    <div className="keyring-control">
      <button
        className={`vault-button ${locked ? "is-locked" : "is-live"}`}
        type="button"
        disabled={vault.state === "busy"}
        onClick={() => void action()}
        aria-label={
          vault.state === "unprovisioned"
            ? "Create Private Access"
            : vault.state === "unlocked"
              ? "Lock Private Access"
              : vault.state === "busy"
                ? "Private Access is working"
                : "Unlock Private Access"
        }
      >
        {vault.state === "busy" ? (
          <LoaderCircle className="spin" />
        ) : locked ? (
          <Lock />
        ) : (
          <KeyRound />
        )}
        <span>{label}</span>
      </button>
    </div>
  );
}

function MarketHeader({
  snapshot,
  actions,
  onManageAccount,
}: TraderShellProps & { onManageAccount(tab: AccountTab): void }) {
  const selected = snapshot.instruments.find(
    (instrument) => instrument.symbol === snapshot.selectedSymbol,
  );
  const working = snapshot.orders.filter((order) =>
    WORKING.includes(order.kind),
  ).length;
  return (
    <section className="market-header" aria-label="Market summary">
      <div className="market-identity">
        <span
          className={`market-signal ${selected?.tradingEnabled ? "is-live" : ""}`}
        />
        <div>
          <h1>
            {selected?.baseSymbol ?? "—"}
            <small>/{selected?.quoteSymbol ?? "—"}</small>
          </h1>
          <span className="market-sub">
            {selected?.tradingEnabled
              ? "Attested private market · uniform clearing price"
              : "Market paused"}
          </span>
        </div>
      </div>
      <dl className="market-stats">
        <div>
          <dt>Minimum order</dt>
          <dd className="mono">
            {selected ? `${selected.minOrderSize} ${selected.baseSymbol}` : "—"}
          </dd>
        </div>
        <div>
          <dt>Working orders</dt>
          <dd className="mono">{working}</dd>
        </div>
        <div>
          <dt>Price increment</dt>
          <dd className="mono">
            {selected ? `${selected.tickSize} ${selected.quoteSymbol}` : "—"}
          </dd>
        </div>
      </dl>
      <div className="market-actions">
        <button
          className="primary-button compact"
          type="button"
          onClick={() => onManageAccount("deposit")}
        >
          <Wallet aria-hidden="true" /> Manage balance
        </button>
        <button
          className="icon-button"
          type="button"
          aria-label="Refresh client state"
          onClick={() => void actions.refresh()}
        >
          <RefreshCw />
        </button>
      </div>
    </section>
  );
}

function ChartPanel({ chartSlot }: Pick<TraderShellProps, "chartSlot">) {
  return (
    <section className="chart-panel" aria-label="Price chart">
      {chartSlot ?? (
        <div className="chart-placeholder">
          <LineChart aria-hidden="true" />
          <b>No price feed configured</b>
          <p>
            The host application supplies the chart. The portable trader UI does
            not fetch market data itself.
          </p>
        </div>
      )}
    </section>
  );
}

function ActivityPanel({ snapshot, actions }: TraderShellProps) {
  const [filter, setFilter] = useState<OrderFilter>("all");
  const orders = snapshot.orders.filter((order) =>
    filter === "all"
      ? true
      : filter === "working"
        ? WORKING.includes(order.kind)
        : !WORKING.includes(order.kind),
  );

  return (
    <section className="activity-panel" id="activity">
      <div className="section-heading">
        <div className="tab-row" role="tablist" aria-label="Order filter">
          {(
            [
              { value: "all", label: "All" },
              { value: "working", label: "Working" },
              { value: "closed", label: "Closed" },
            ] as const
          ).map((entry) => (
            <button
              key={entry.value}
              type="button"
              role="tab"
              aria-selected={filter === entry.value}
              className={filter === entry.value ? "active" : ""}
              onClick={() => setFilter(entry.value)}
            >
              {entry.label}
              <em>
                {entry.value === "all"
                  ? snapshot.orders.length
                  : entry.value === "working"
                    ? snapshot.orders.filter((order) =>
                        WORKING.includes(order.kind),
                      ).length
                    : snapshot.orders.filter(
                        (order) => !WORKING.includes(order.kind),
                      ).length}
              </em>
            </button>
          ))}
        </div>
        <button
          className="quiet-button"
          type="button"
          onClick={() => void actions.refresh()}
        >
          <RefreshCw /> Refresh
        </button>
      </div>
      {orders.length === 0 ? (
        <div className="empty-state">
          <div className="empty-mark">
            <Activity aria-hidden="true" />
          </div>
          <h3>
            {snapshot.orders.length === 0
              ? "No orders yet"
              : "Nothing in this view"}
          </h3>
          <p>
            {snapshot.orders.length === 0
              ? "Private intents and finalized settlement outcomes appear here."
              : "Switch filters to see the rest of the lifecycle."}
          </p>
        </div>
      ) : (
        <div className="order-table" role="table" aria-label="Order lifecycle">
          <div className="order-row order-head" role="row">
            <span role="columnheader">Order</span>
            <span role="columnheader">Side</span>
            <span role="columnheader">Amount</span>
            <span role="columnheader">Limit</span>
            <span role="columnheader">Status</span>
            <span role="columnheader" aria-label="Actions" />
          </div>
          {orders.map((order) => (
            <div className="order-row" role="row" key={order.orderId}>
              <span role="cell">
                <b>{order.symbol}</b>
                <small className="mono">{short(order.orderId, 6, 4)}</small>
              </span>
              <span role="cell" className={`side-${order.side}`}>
                {order.side === "bid" ? "Buy" : "Sell"}
              </span>
              <span role="cell" className="mono">
                {order.amount}
              </span>
              <span role="cell" className="mono">
                {order.limitPrice}
              </span>
              <span role="cell">
                <i
                  className={`status-dot is-${stateTone(order.kind)}`}
                  aria-hidden="true"
                />
                {lifecycleCopy[order.kind]}
                {order.reason && <small>{order.reason}</small>}
              </span>
              <span role="cell">
                {(order.kind === "open" ||
                  order.kind === "partially_filled") && (
                  <button
                    className="text-button danger"
                    type="button"
                    onClick={() => void actions.cancelOrder(order.orderId)}
                  >
                    Cancel
                  </button>
                )}
              </span>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

function TrustBanner({ snapshot, actions }: TraderShellProps) {
  if (snapshot.venue.state === "trusted") return null;
  const failed = snapshot.venue.state === "failed";
  return (
    <div
      className={`trust-banner ${failed ? "is-failed" : ""}`}
      role={failed ? "alert" : "status"}
    >
      {snapshot.venue.state === "checking" ? (
        <LoaderCircle className="spin" />
      ) : (
        <AlertTriangle aria-hidden="true" />
      )}
      <div>
        <b>
          {failed
            ? "Venue trust is not established"
            : snapshot.venue.state === "degraded"
              ? "Some markets are paused"
              : "Verifying venue"}
        </b>
        <span>
          {snapshot.venue.message ??
            "Checking the attested enclave and finalized governance pins."}
        </span>
      </div>
      {failed && (
        <button type="button" onClick={() => void actions.retryVenue()}>
          Retry
        </button>
      )}
    </div>
  );
}

export function TraderShell({
  snapshot,
  actions,
  chartSlot,
}: TraderShellProps) {
  const [accountTab, setAccountTab] = useState<AccountTab | null>(null);
  const props = { snapshot, actions };

  return (
    <div className="darknyx-product" data-theme="dark">
      <header className="topbar">
        <a className="brand-lockup" href="/" aria-label="Darknyx home">
          <HorizonMark />
          <span className="brand-wordmark">darknyx</span>
        </a>
        <p className="brand-tagline">Settle in the dark. Prove in the light.</p>
        <div className="top-actions">
          <VenueBadge venue={snapshot.venue} />
          <KeyringControl {...props} />
          <WalletControl {...props} />
        </div>
      </header>
      <TrustBanner {...props} />
      <main className="workspace" id="trade">
        <div className="content-column">
          <MarketHeader {...props} onManageAccount={setAccountTab} />
          <ChartPanel chartSlot={chartSlot} />
          <ActivityPanel {...props} />
        </div>
        <OrderTicket {...props} onManageAccount={setAccountTab} />
      </main>
      <footer className="product-footer">
        <span>
          <i
            className={`status-dot is-${snapshot.venue.state === "trusted" ? "good" : "pending"}`}
            aria-hidden="true"
          />
          {snapshot.venue.label}
        </span>
        <span className="mono">Attested execution · Solana settlement</span>
        <span>
          {snapshot.lastUpdated
            ? `Updated ${snapshot.lastUpdated}`
            : "Awaiting first sync"}
        </span>
      </footer>
      <AccountDialog
        {...props}
        open={accountTab !== null}
        tab={accountTab ?? "deposit"}
        onTabChange={setAccountTab}
        onClose={() => setAccountTab(null)}
      />
    </div>
  );
}
