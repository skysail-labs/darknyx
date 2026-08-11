import {
  Activity,
  AlertTriangle,
  ArrowDownToLine,
  ArrowUpFromLine,
  Check,
  ChevronDown,
  KeyRound,
  Layers3,
  LoaderCircle,
  Lock,
  LogOut,
  RefreshCw,
  ShieldCheck,
  WalletCards,
  X,
} from "lucide-react";
import {
  useEffect,
  useMemo,
  useRef,
  useState,
  type FormEvent,
  type KeyboardEvent,
} from "react";

import { HorizonMark } from "./mark.js";
import type { OrderLifecycleKind, TraderShellProps } from "./types.js";

const lifecycleCopy: Record<OrderLifecycleKind, string> = {
  submitting: "Submitting",
  open: "Open",
  pending_settlement: "Pending settlement",
  partially_filled: "Partially filled",
  fully_filled: "Settled",
  settlement_failed: "Settlement failed",
  cancelled: "Cancelled",
  expired: "Expired",
  ambiguous: "Reconciling",
  rejected: "Rejected",
};

function short(value: string, head = 5, tail = 4): string {
  return value.length > head + tail + 1
    ? `${value.slice(0, head)}…${value.slice(-tail)}`
    : value;
}

function stateTone(kind: OrderLifecycleKind): string {
  if (kind === "fully_filled") return "good";
  if (
    kind === "settlement_failed" ||
    kind === "rejected" ||
    kind === "cancelled" ||
    kind === "expired"
  )
    return "bad";
  if (kind === "open") return "neutral";
  return "pending";
}

function VenueBadge({ venue }: Pick<TraderShellProps["snapshot"], "venue">) {
  function closeOnEscape(event: KeyboardEvent<HTMLDetailsElement>) {
    if (event.key !== "Escape") return;
    event.currentTarget.removeAttribute("open");
    event.currentTarget.querySelector("summary")?.focus();
  }

  const icon =
    venue.state === "checking" ? (
      <LoaderCircle className="spin" />
    ) : venue.state === "trusted" ? (
      <ShieldCheck />
    ) : (
      <AlertTriangle />
    );
  return (
    <details className="trust-control" onKeyDown={closeOnEscape}>
      <summary className={`trust-badge is-${venue.state}`}>
        <span className="trust-icon" aria-hidden="true">
          {icon}
        </span>
        <span>
          <b>{venue.state === "trusted" ? "Attested" : venue.state}</b>
          <small>{venue.label}</small>
        </span>
        <ChevronDown aria-hidden="true" />
      </summary>
      <div className="trust-menu panel-popover">
        <p className="eyebrow">Venue identity</p>
        <div>
          <span>Trust state</span>
          <b>{venue.state}</b>
        </div>
        <div>
          <span>Finalized governance</span>
          <b className="mono">{venue.governanceSlot ?? "—"}</b>
        </div>
        <div>
          <span>Compose hash</span>
          <b className="mono">
            {venue.composeHash ? short(venue.composeHash, 8, 8) : "—"}
          </b>
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
            <p className="eyebrow">External wallet</p>
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
  return (
    <div className="wallet-control">
      <button
        ref={trigger}
        className="primary-button compact"
        type="button"
        disabled={wallet.state === "connecting"}
        onClick={() => setOpen(!open)}
        aria-expanded={open}
        aria-controls="darknyx-wallet-menu"
        aria-label={
          wallet.state === "connecting"
            ? "Connecting wallet"
            : wallet.state === "failed"
              ? "Retry wallet connection"
              : "Connect wallet"
        }
      >
        <WalletCards aria-hidden="true" />
        <span className="wallet-label">
          {wallet.state === "connecting"
            ? "Connecting"
            : wallet.state === "failed"
              ? "Retry wallet"
              : "Connect wallet"}
        </span>
      </button>
      {open && (
        <div
          className="wallet-menu panel-popover"
          id="darknyx-wallet-menu"
          aria-label="Choose a wallet"
        >
          <p className="eyebrow">Choose a wallet</p>
          {wallet.state === "failed" && wallet.error && (
            <p className="wallet-error" role="alert">
              {wallet.error}
            </p>
          )}
          {wallet.availableWallets.length === 0 ? (
            <p className="muted">No compatible Solana wallet detected.</p>
          ) : (
            wallet.availableWallets.map((candidate) => (
              <button
                type="button"
                key={candidate.name}
                onClick={() => void actions.connectWallet(candidate.name)}
              >
                <img src={candidate.icon} alt="" />
                {candidate.name}
              </button>
            ))
          )}
        </div>
      )}
    </div>
  );
}

function VaultControl({ snapshot, actions }: TraderShellProps) {
  const { vault } = snapshot;
  const locked = vault.state !== "unlocked";
  const label =
    vault.state === "unprovisioned"
      ? "Create private vault"
      : vault.state === "unlocked"
        ? "Vault unlocked"
        : vault.state === "busy"
          ? "Vault busy"
          : "Unlock vault";
  const action =
    vault.state === "unprovisioned"
      ? actions.provisionVault
      : vault.state === "unlocked"
        ? actions.lockVault
        : actions.unlockVault;
  return (
    <button
      className={`vault-button ${locked ? "is-locked" : "is-live"}`}
      type="button"
      disabled={vault.state === "busy"}
      onClick={() => void action()}
    >
      {vault.state === "busy" ? (
        <LoaderCircle className="spin" />
      ) : locked ? (
        <Lock />
      ) : (
        <KeyRound />
      )}
      <span>{label}</span>
      <small>{vault.state === "unlocked" ? "Lock" : "Device protected"}</small>
    </button>
  );
}

function MarketRail({ snapshot, actions }: TraderShellProps) {
  return (
    <aside className="market-rail" aria-label="Markets">
      <div className="rail-heading">
        <span className="eyebrow">Markets</span>
      </div>
      <div className="market-list">
        {snapshot.venue.state === "checking" ? (
          Array.from({ length: 3 }, (_, index) => (
            <div
              className="market-skeleton skeleton"
              key={index}
              aria-hidden="true"
            />
          ))
        ) : snapshot.instruments.length === 0 ? (
          <div className="empty-compact">
            <Activity aria-hidden="true" />
            <span>
              {snapshot.venue.state === "trusted"
                ? "No markets are configured"
                : "Markets unavailable until venue verification"}
            </span>
          </div>
        ) : (
          snapshot.instruments.map((instrument) => (
            <button
              key={instrument.symbol}
              type="button"
              className={
                snapshot.selectedSymbol === instrument.symbol
                  ? "is-selected"
                  : ""
              }
              onClick={() => actions.selectInstrument(instrument.symbol)}
            >
              <span
                className={`market-signal ${instrument.tradingEnabled ? "is-live" : ""}`}
              />
              <span>
                <b>{instrument.baseSymbol}</b>
                <small>/{instrument.quoteSymbol}</small>
              </span>
              <em>{instrument.tradingEnabled ? "Live" : "Paused"}</em>
            </button>
          ))
        )}
      </div>
      <div className="rail-footer">
        <span className="eyebrow">Proof inventory</span>
        <div>
          <strong className="mono">{snapshot.proofReadiness.ready}</strong>
          <span>ready</span>
        </div>
        <div>
          <strong className="mono">{snapshot.proofReadiness.proving}</strong>
          <span>building</span>
        </div>
        <div>
          <strong className="mono">{snapshot.proofReadiness.stale}</strong>
          <span>stale</span>
        </div>
      </div>
    </aside>
  );
}

function BalanceStrip({ snapshot }: Pick<TraderShellProps, "snapshot">) {
  return (
    <section className="balance-strip" aria-label="Private balances">
      <div>
        <span className="eyebrow">Private balance</span>
        <p>Aggregate note inventory on this device</p>
      </div>
      {snapshot.vault.state === "busy" ? (
        <div className="balance-loading" aria-label="Recovering balances">
          <span className="balance-skeleton skeleton" aria-hidden="true" />
          <span className="balance-skeleton skeleton" aria-hidden="true" />
        </div>
      ) : snapshot.balances.length === 0 ? (
        <div className="balance-empty">
          {snapshot.vault.state === "unlocked"
            ? "No private balances yet"
            : "Unlock and recover to view balances"}
        </div>
      ) : (
        snapshot.balances.map((balance) => (
          <div className="balance-cell" key={balance.mint}>
            <span className="mono label-address">
              {balance.symbol} · {short(balance.mint, 4, 4)}
            </span>
            <strong className="mono">{balance.spendable}</strong>
            <small>
              {balance.reserved} reserved · {balance.pendingSettlement} settling
            </small>
          </div>
        ))
      )}
    </section>
  );
}

function ActivityTable({ snapshot, actions }: TraderShellProps) {
  return (
    <section className="activity-panel" id="activity">
      <div className="section-heading">
        <div>
          <span className="eyebrow">Lifecycle</span>
          <h2>Orders & settlement</h2>
        </div>
        <button
          className="quiet-button"
          type="button"
          onClick={() => void actions.refresh()}
        >
          <RefreshCw /> Refresh
        </button>
      </div>
      {snapshot.orders.length === 0 ? (
        <div className="empty-state">
          <div className="empty-mark">
            <Activity aria-hidden="true" />
          </div>
          <h3>No orders yet</h3>
          <p>
            Submitted intents and their on-chain settlement outcomes appear
            here.
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
          {snapshot.orders.map((order) => (
            <div className="order-row" role="row" key={order.orderId}>
              <span role="cell">
                <b>{order.symbol}</b>
                <small className="mono">{short(order.orderId, 6, 4)}</small>
              </span>
              <span role="cell" className={`side-${order.side}`}>
                {order.side}
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

function AccountPanel({ snapshot, actions }: TraderShellProps) {
  const selected = snapshot.instruments.find(
    (instrument) => instrument.symbol === snapshot.selectedSymbol,
  );
  const [asset, setAsset] = useState<"base" | "quote">("base");
  const [amount, setAmount] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [restoreFile, setRestoreFile] = useState<File | null>(null);
  const [backupStatus, setBackupStatus] = useState<string | null>(null);
  const operation = snapshot.accountOperation;
  const busy =
    operation !== undefined &&
    operation.state !== "finalized" &&
    operation.state !== "ambiguous" &&
    operation.state !== "failed";
  const blocked =
    snapshot.vault.state !== "unlocked" ||
    snapshot.wallet.state !== "connected" ||
    !selected;

  async function run(kind: "deposit" | "withdraw") {
    if (!selected || blocked || busy) return;
    await actions[kind]({
      marketSymbol: selected.symbol,
      asset,
      amount,
    });
  }

  async function downloadBackup() {
    setBackupStatus("Encrypting backup…");
    try {
      const backup = await actions.exportBackup(passphrase);
      const url = URL.createObjectURL(
        new Blob([JSON.stringify(backup, null, 2)], {
          type: "application/json",
        }),
      );
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = "darknyx-seed-backup-v2.json";
      anchor.click();
      URL.revokeObjectURL(url);
      setBackupStatus("Encrypted backup downloaded. Keep it offline.");
    } catch (error) {
      setBackupStatus(error instanceof Error ? error.message : String(error));
    }
  }

  async function restoreBackup() {
    if (!restoreFile) return;
    setBackupStatus("Restoring encrypted backup…");
    try {
      const backup = JSON.parse(await restoreFile.text());
      await actions.restoreBackup(backup, passphrase);
      setBackupStatus("Backup restored. Finalized chain recovery is running.");
    } catch (error) {
      setBackupStatus(error instanceof Error ? error.message : String(error));
    }
  }

  return (
    <section className="account-panel" id="account">
      <div className="section-heading">
        <div>
          <span className="eyebrow">Private account</span>
          <h2>Fund, withdraw & recover</h2>
        </div>
      </div>
      <div className="account-grid">
        <div className="account-card">
          <h3>Move assets</h3>
          <p>
            Deposits are public SPL transfers into a private note. Withdrawals
            consume one exact note; consolidate first to withdraw a combined
            balance.
          </p>
          <div className="account-segment" role="group" aria-label="Asset">
            <button
              type="button"
              className={asset === "base" ? "active" : ""}
              onClick={() => setAsset("base")}
            >
              {selected?.baseSymbol ?? "Base"}
            </button>
            <button
              type="button"
              className={asset === "quote" ? "active" : ""}
              onClick={() => setAsset("quote")}
            >
              {selected?.quoteSymbol ?? "Quote"}
            </button>
          </div>
          <label htmlFor="darknyx-account-amount">
            <span>Amount</span>
            <input
              id="darknyx-account-amount"
              className="mono"
              inputMode="decimal"
              pattern="[0-9]+([.][0-9]+)?"
              value={amount}
              onChange={(event) => setAmount(event.target.value)}
              placeholder="0"
              autoComplete="off"
            />
          </label>
          <div className="account-actions">
            <button
              type="button"
              disabled={blocked || busy || !amount}
              onClick={() => void run("deposit")}
            >
              <ArrowDownToLine /> Deposit
            </button>
            <button
              type="button"
              disabled={blocked || busy || !amount}
              onClick={() => void run("withdraw")}
            >
              <ArrowUpFromLine /> Withdraw
            </button>
            <button
              type="button"
              disabled={blocked || busy}
              onClick={() =>
                selected && void actions.merge(selected.symbol, asset)
              }
            >
              <Layers3 /> Consolidate
            </button>
          </div>
          {operation && (
            <div
              className={`account-result is-${operation.state}`}
              role="status"
            >
              {busy && <LoaderCircle className="spin" />}
              <span>
                <b>{operation.kind.replace("merge", "consolidation")}</b>
                {operation.message}
              </span>
            </div>
          )}
        </div>
        <div className="account-card backup-card">
          <h3>Portable recovery</h3>
          <p>
            Export the encrypted version-2 seed backup and keep it offline. The
            passphrase is never persisted; chain recovery rebuilds notes on a
            new device.
          </p>
          <label htmlFor="darknyx-backup-passphrase">
            <span>Backup passphrase</span>
            <input
              id="darknyx-backup-passphrase"
              type="password"
              value={passphrase}
              onChange={(event) => setPassphrase(event.target.value)}
              autoComplete="new-password"
              minLength={12}
            />
          </label>
          <button
            type="button"
            disabled={
              snapshot.vault.state !== "unlocked" || passphrase.length < 12
            }
            onClick={() => void downloadBackup()}
          >
            Export encrypted backup
          </button>
          <div className="restore-row">
            <input
              type="file"
              accept="application/json,.json"
              aria-label="Choose encrypted Darknyx backup"
              disabled={snapshot.vault.state !== "unprovisioned"}
              onChange={(event) =>
                setRestoreFile(event.target.files?.[0] ?? null)
              }
            />
            <button
              type="button"
              disabled={
                snapshot.vault.state !== "unprovisioned" ||
                !restoreFile ||
                passphrase.length < 12
              }
              onClick={() => void restoreBackup()}
            >
              Restore on this device
            </button>
          </div>
          {backupStatus && <p role="status">{backupStatus}</p>}
        </div>
      </div>
    </section>
  );
}

function OrderTicket({ snapshot, actions }: TraderShellProps) {
  const selected = snapshot.instruments.find(
    (instrument) => instrument.symbol === snapshot.selectedSymbol,
  );
  const [side, setSide] = useState<"bid" | "ask">("bid");
  const [amount, setAmount] = useState("");
  const [price, setPrice] = useState("");
  const [policy, setPolicy] = useState<"limit" | "ioc" | "fok">("limit");
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState<string | null>(null);

  const block = useMemo(() => {
    if (snapshot.venue.state !== "trusted")
      return "Venue trust is not established";
    if (!snapshot.selectedSymbol || !selected)
      return "Select an attested market";
    if (!selected.tradingEnabled) return "This market is paused";
    if (snapshot.vault.state !== "unlocked") return "Unlock the private vault";
    if (snapshot.proofReadiness.ready < 1)
      return "Waiting for an accepted-root proof";
    return null;
  }, [
    selected,
    snapshot.proofReadiness.ready,
    snapshot.selectedSymbol,
    snapshot.vault.state,
    snapshot.venue.state,
  ]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!selected || block || submitting) return;
    setSubmitting(true);
    setResult(null);
    try {
      const response = await actions.submitOrder({
        marketSymbol: selected.symbol,
        side,
        amount,
        limitPrice: price,
        orderType: policy,
      });
      setResult(
        response.status === "accepted"
          ? `Order ${short(response.orderId)} accepted`
          : response.status === "pending"
            ? `Pending: ${response.reason.toLowerCase().replaceAll("_", " ")}`
            : `Rejected: ${response.code.toLowerCase().replaceAll("_", " ")}`,
      );
    } catch {
      setResult("Order state is ambiguous. Reconciliation is in progress.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <aside className="ticket-panel" aria-label="Order ticket">
      <div className="ticket-heading">
        <div>
          <span className="eyebrow">Private intent</span>
          <h2>Place order</h2>
        </div>
      </div>
      <div className="side-switch" role="group" aria-label="Order side">
        <button
          type="button"
          className={side === "bid" ? "active" : ""}
          aria-pressed={side === "bid"}
          onClick={() => setSide("bid")}
        >
          Buy
        </button>
        <button
          type="button"
          className={side === "ask" ? "active" : ""}
          aria-pressed={side === "ask"}
          onClick={() => setSide("ask")}
        >
          Sell
        </button>
      </div>
      <form onSubmit={(event) => void submit(event)}>
        <label>
          <span>Market</span>
          <div className="readonly-field">
            <b>{selected?.symbol ?? "No market"}</b>
            <small>
              {selected?.tradingEnabled ? "Trading enabled" : "Unavailable"}
            </small>
          </div>
        </label>
        <label htmlFor="darknyx-order-amount">
          <span>
            Amount <small>{selected?.baseSymbol}</small>
          </span>
          <input
            id="darknyx-order-amount"
            type="text"
            className="mono"
            inputMode="decimal"
            pattern="[0-9]+([.][0-9]+)?"
            autoComplete="off"
            spellCheck={false}
            required
            value={amount}
            onChange={(event) => setAmount(event.target.value)}
            placeholder="0"
          />
        </label>
        <label htmlFor="darknyx-order-price">
          <span>
            Limit price <small>{selected?.quoteSymbol}</small>
          </span>
          <input
            id="darknyx-order-price"
            type="text"
            className="mono"
            inputMode="decimal"
            pattern="[0-9]+([.][0-9]+)?"
            autoComplete="off"
            spellCheck={false}
            required
            value={price}
            onChange={(event) => setPrice(event.target.value)}
            placeholder="0"
          />
        </label>
        <fieldset role="group" aria-label="Execution">
          <legend>Execution</legend>
          {(["limit", "ioc", "fok"] as const).map((kind) => (
            <button
              type="button"
              key={kind}
              className={policy === kind ? "active" : ""}
              aria-pressed={policy === kind}
              onClick={() => setPolicy(kind)}
            >
              {kind.toUpperCase()}
            </button>
          ))}
        </fieldset>
        <div className="ticket-proof">
          {snapshot.proofReadiness.ready > 0 ? (
            <Check aria-hidden="true" />
          ) : (
            <LoaderCircle className="spin" aria-hidden="true" />
          )}
          <span>
            <b>
              {snapshot.proofReadiness.ready > 0
                ? "Proof ready"
                : "Proof unavailable"}
            </b>
            <small>Order submission never proves on demand</small>
          </span>
        </div>
        {block && (
          <div className="blocking-message">
            <AlertTriangle aria-hidden="true" /> {block}
          </div>
        )}
        {result && (
          <div className="result-message" role="status">
            {result}
          </div>
        )}
        <button
          className="primary-button submit-order"
          type="submit"
          disabled={Boolean(block) || submitting || !amount || !price}
          aria-busy={submitting}
        >
          {submitting ? (
            <LoaderCircle className="spin" aria-hidden="true" />
          ) : (
            <Lock aria-hidden="true" />
          )}
          {submitting
            ? "Authorizing"
            : `${side === "bid" ? "Buy" : "Sell"} privately`}
        </button>
        <p className="ticket-footnote">
          Your limit and size enter the attested venue over the authenticated
          session. Settlement remains verifiable on Solana.
        </p>
      </form>
    </aside>
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
            ? "Venue verification failed"
            : snapshot.venue.state === "degraded"
              ? "Venue is degraded"
              : "Verifying venue"}
        </b>
        <span>
          {snapshot.venue.message ??
            "Checking finalized governance, TDX quote, and market configuration."}
        </span>
      </div>
      {failed && (
        <button type="button" onClick={() => void actions.retryVenue()}>
          Retry verification
        </button>
      )}
    </div>
  );
}

export function TraderShell({ snapshot, actions }: TraderShellProps) {
  return (
    <div className="darknyx-product" data-theme="dark">
      <header className="topbar">
        <a className="brand-lockup" href="/" aria-label="Darknyx home">
          <HorizonMark />
          <span className="brand-wordmark">darknyx</span>
        </a>
        <nav aria-label="Product">
          <a className="active" href="#trade">
            Trade
          </a>
          <a href="#activity">Activity</a>
          <a href="#account">Account</a>
        </nav>
        <div className="top-actions">
          <VenueBadge venue={snapshot.venue} />
          <WalletControl snapshot={snapshot} actions={actions} />
        </div>
      </header>
      <TrustBanner snapshot={snapshot} actions={actions} />
      <main className="workspace" id="trade">
        <MarketRail snapshot={snapshot} actions={actions} />
        <div className="content-column">
          <div className="context-bar">
            <div>
              <span className="eyebrow">Selected market</span>
              <h1>{snapshot.selectedSymbol ?? "Private markets"}</h1>
            </div>
            <div className="context-actions">
              <VaultControl snapshot={snapshot} actions={actions} />
              <button
                className="icon-button"
                type="button"
                aria-label="Refresh client state"
                onClick={() => void actions.refresh()}
              >
                <RefreshCw />
              </button>
            </div>
          </div>
          <BalanceStrip snapshot={snapshot} />
          <ActivityTable snapshot={snapshot} actions={actions} />
          <AccountPanel snapshot={snapshot} actions={actions} />
        </div>
        <OrderTicket snapshot={snapshot} actions={actions} />
      </main>
      <footer className="product-footer">
        <span>
          <i
            className={`status-dot is-${snapshot.venue.state === "trusted" ? "good" : "pending"}`}
            aria-hidden="true"
          />
          {snapshot.venue.label}
        </span>
        <span className="mono">
          Finalized governance {snapshot.venue.governanceSlot ?? "—"}
        </span>
        <span>
          {snapshot.lastUpdated
            ? `Updated ${snapshot.lastUpdated}`
            : "Awaiting first sync"}
        </span>
      </footer>
    </div>
  );
}
