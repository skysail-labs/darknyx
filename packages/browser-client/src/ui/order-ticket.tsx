import {
  AlertTriangle,
  Check,
  LoaderCircle,
  Lock,
  Plus,
  ShieldCheck,
} from "lucide-react";
import { useMemo, useState, type FormEvent } from "react";

import { short } from "./primitives.js";
import type { TraderShellProps } from "./types.js";

export interface OrderTicketProps extends TraderShellProps {
  onManageAccount(tab: "deposit" | "withdraw" | "consolidate"): void;
}

/**
 * Order entry plus the private balance it spends from. The balance sits above
 * the form deliberately: a trader must be able to see spendable value and the
 * ticket at the same time, without scrolling and without opening a dialog.
 */
export function OrderTicket({
  snapshot,
  actions,
  onManageAccount,
}: OrderTicketProps) {
  const selected = snapshot.instruments.find(
    (instrument) => instrument.symbol === snapshot.selectedSymbol,
  );
  const [side, setSide] = useState<"bid" | "ask">("bid");
  const [amount, setAmount] = useState("");
  const [price, setPrice] = useState("");
  const [policy, setPolicy] = useState<"limit" | "ioc" | "fok">("limit");
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState<string | null>(null);

  const unlocked = snapshot.vault.state === "unlocked";
  const spendSymbol =
    side === "bid" ? selected?.quoteSymbol : selected?.baseSymbol;
  const spendBalance = snapshot.balances.find(
    (balance) => balance.symbol === spendSymbol,
  );

  const block = useMemo(() => {
    if (
      snapshot.venue.state !== "trusted" &&
      snapshot.venue.state !== "degraded"
    )
      return "Venue trust is not established";
    if (!snapshot.selectedSymbol || !selected)
      return "Select an attested market";
    if (!selected.tradingEnabled) return "This market is paused";
    if (snapshot.vault.state !== "unlocked") return "Unlock Private Access";
    if (snapshot.wallet.state !== "connected") return "Connect a wallet";
    if (snapshot.proofReadiness.ready < 1) {
      const hasSpendableNote =
        (spendBalance?.spendableNoteCount ?? 0) > 0 ||
        Number(spendBalance?.spendable ?? "0") > 0;
      if (!hasSpendableNote) return "Deposit a private balance first";
      if (snapshot.proofReadiness.proving > 0)
        return "Preparing your private input proof";
      return "Private balance found, but its Merkle proof is unavailable";
    }
    return null;
  }, [
    selected,
    spendBalance,
    snapshot.proofReadiness.proving,
    snapshot.proofReadiness.ready,
    snapshot.selectedSymbol,
    snapshot.vault.state,
    snapshot.wallet.state,
    snapshot.venue.state,
  ]);

  const notional = useMemo(() => {
    const size = Number(amount);
    const limit = Number(price);
    if (!Number.isFinite(size) || !Number.isFinite(limit) || !size || !limit)
      return null;
    return (size * limit).toLocaleString(undefined, {
      minimumFractionDigits: 2,
      maximumFractionDigits: 2,
    });
  }, [amount, price]);

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
      if (response.status === "accepted") {
        setAmount("");
        setPrice("");
      }
    } catch {
      setResult("Order state is ambiguous. Reconciliation is in progress.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <aside className="ticket-panel" aria-label="Order ticket">
      <section className="balance-card" aria-label="Private balance">
        <div className="balance-card-head">
          <span className="eyebrow">Private balance</span>
          <button
            type="button"
            className="text-button accent"
            onClick={() => onManageAccount("deposit")}
          >
            <Plus aria-hidden="true" /> Manage
          </button>
        </div>
        {!unlocked ? (
          <p className="balance-card-locked">
            Unlock Private Access to reveal note inventory held on this device.
          </p>
        ) : snapshot.balances.length === 0 ? (
          <p className="balance-card-locked">
            No private balance yet. Deposit to create your first note.
          </p>
        ) : (
          <ul className="balance-card-list">
            {snapshot.balances.map((balance) => (
              <li key={balance.mint}>
                <span className="balance-symbol">{balance.symbol}</span>
                <b className="mono">{balance.spendable}</b>
                <small>
                  {balance.reserved} reserved · {balance.pendingSettlement}{" "}
                  settling
                </small>
              </li>
            ))}
          </ul>
        )}
      </section>

      <div className="ticket-heading">
        <div>
          <span className="eyebrow">Private intent</span>
          <h2>Place order</h2>
        </div>
      </div>

      <div className="side-switch" role="group" aria-label="Order side">
        <button
          type="button"
          className={side === "bid" ? "active is-buy" : ""}
          aria-pressed={side === "bid"}
          onClick={() => setSide("bid")}
        >
          Buy
        </button>
        <button
          type="button"
          className={side === "ask" ? "active is-sell" : ""}
          aria-pressed={side === "ask"}
          onClick={() => setSide("ask")}
        >
          Sell
        </button>
      </div>

      <form onSubmit={(event) => void submit(event)}>
        <label className="field" htmlFor="darknyx-order-amount">
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
          {selected && (
            <small className="field-hint">
              Minimum {selected.minOrderSize} {selected.baseSymbol}
            </small>
          )}
        </label>
        <label className="field" htmlFor="darknyx-order-price">
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
            placeholder={selected?.tickSize ?? "0"}
          />
          {selected && (
            <small className="field-hint">
              Price increment {selected.tickSize} {selected.quoteSymbol}
            </small>
          )}
        </label>

        <fieldset className="policy-row">
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

        <dl className="ticket-summary">
          <div>
            <dt>Order value</dt>
            <dd className="mono">
              {notional ? `${notional} ${selected?.quoteSymbol}` : "—"}
            </dd>
          </div>
          <div>
            <dt>Spendable {spendSymbol}</dt>
            <dd className="mono">{spendBalance?.spendable ?? "—"}</dd>
          </div>
        </dl>

        <div className="ticket-proof">
          {snapshot.proofReadiness.ready > 0 ? (
            <ShieldCheck aria-hidden="true" />
          ) : (
            <LoaderCircle className="spin" aria-hidden="true" />
          )}
          <span>
            <b>
              {snapshot.proofReadiness.ready > 0
                ? "Input proof ready"
                : snapshot.proofReadiness.proving > 0
                  ? "Generating input proof"
                  : "Input proof unavailable"}
            </b>
            <small>Prepared and verified locally before order submission</small>
          </span>
          {snapshot.proofReadiness.ready > 0 && (
            <Check className="proof-tick" aria-hidden="true" />
          )}
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
          className={`primary-button submit-order ${side === "ask" ? "is-sell" : ""}`}
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
            : `${side === "bid" ? "Buy" : "Sell"} ${selected?.baseSymbol ?? ""} privately`}
        </button>
        <p className="ticket-footnote">
          Your signed intent enters the attested venue privately. Settlement
          remains verifiable on Solana.
        </p>
      </form>
    </aside>
  );
}
