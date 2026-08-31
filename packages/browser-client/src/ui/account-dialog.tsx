import {
  ArrowDownToLine,
  ArrowUpFromLine,
  DownloadCloud,
  Layers3,
  LoaderCircle,
  ShieldCheck,
  UploadCloud,
} from "lucide-react";
import { useMemo, useState } from "react";

import { Dialog, Segmented, short } from "./primitives.js";
import type { TraderShellProps } from "./types.js";

export type AccountTab = "deposit" | "withdraw" | "consolidate" | "recovery";

const TABS: Array<{ value: AccountTab; label: string }> = [
  { value: "deposit", label: "Deposit" },
  { value: "withdraw", label: "Withdraw" },
  { value: "consolidate", label: "Consolidate" },
  { value: "recovery", label: "Recovery" },
];

export interface AccountDialogProps extends TraderShellProps {
  open: boolean;
  tab: AccountTab;
  onTabChange(tab: AccountTab): void;
  onClose(): void;
}

/**
 * Every private-account operation in one focused surface. It replaces the
 * page-bottom panel so funding never competes with the trade view for space
 * and never requires a scroll to reach.
 */
export function AccountDialog({
  snapshot,
  actions,
  open,
  tab,
  onTabChange,
  onClose,
}: AccountDialogProps) {
  const selected = snapshot.instruments.find(
    (instrument) => instrument.symbol === snapshot.selectedSymbol,
  );
  const [asset, setAsset] = useState<"base" | "quote">("base");
  const [amount, setAmount] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [restoreFile, setRestoreFile] = useState<File | null>(null);
  const [backupStatus, setBackupStatus] = useState<string | null>(null);
  const [accountError, setAccountError] = useState<string | null>(null);
  const [invoking, setInvoking] = useState(false);

  const operation = snapshot.accountOperation;
  const busy =
    (operation !== undefined &&
      operation.state !== "finalized" &&
      operation.state !== "confirmed" &&
      operation.state !== "ambiguous" &&
      operation.state !== "failed") ||
    invoking;

  const assetSymbol =
    asset === "base"
      ? (selected?.baseSymbol ?? "Base")
      : (selected?.quoteSymbol ?? "Quote");

  const privateBalance = snapshot.balances.find(
    (balance) => balance.symbol === assetSymbol,
  );

  const blocker = useMemo(() => {
    if (snapshot.vault.state !== "unlocked")
      return "Unlock Private Access to move value.";
    if (snapshot.wallet.state !== "connected")
      return "Connect a wallet to move value.";
    if (!selected) return "Select a market first.";
    return null;
  }, [selected, snapshot.vault.state, snapshot.wallet.state]);

  const available = tab === "withdraw" ? privateBalance?.spendable : undefined;

  async function run(kind: "deposit" | "withdraw") {
    if (!selected || blocker || busy) return;
    setInvoking(true);
    setAccountError(null);
    try {
      await actions[kind]({
        marketSymbol: selected.symbol,
        asset,
        amount,
      });
      setAmount("");
    } catch (error) {
      setAccountError(error instanceof Error ? error.message : String(error));
    } finally {
      setInvoking(false);
    }
  }

  async function runMerge() {
    if (!selected || blocker || busy) return;
    setInvoking(true);
    setAccountError(null);
    try {
      await actions.merge(selected.symbol, asset);
    } catch (error) {
      setAccountError(error instanceof Error ? error.message : String(error));
    } finally {
      setInvoking(false);
    }
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
      anchor.hidden = true;
      document.body.append(anchor);
      anchor.click();
      setTimeout(() => {
        anchor.remove();
        URL.revokeObjectURL(url);
      }, 0);
      setBackupStatus(
        "Encrypted backup generated. Verify that the download completed, then keep it offline.",
      );
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
      setBackupStatus("Backup restored and the Private Keyring is unlocked.");
    } catch (error) {
      setBackupStatus(error instanceof Error ? error.message : String(error));
    }
  }

  const moving = tab === "deposit" || tab === "withdraw";

  return (
    <Dialog
      open={open}
      title="Private account"
      description="Fund, withdraw, consolidate, and back up the note inventory held on this device."
      onClose={onClose}
    >
      <div
        className="dialog-tabs"
        role="tablist"
        aria-label="Account operation"
      >
        {TABS.map((entry) => (
          <button
            key={entry.value}
            type="button"
            role="tab"
            id={`darknyx-account-tab-${entry.value}`}
            aria-selected={tab === entry.value}
            aria-controls={`darknyx-account-pane-${entry.value}`}
            className={tab === entry.value ? "active" : ""}
            onClick={() => onTabChange(entry.value)}
          >
            {entry.label}
          </button>
        ))}
      </div>

      <div
        className="dialog-pane"
        role="tabpanel"
        id={`darknyx-account-pane-${tab}`}
        aria-labelledby={`darknyx-account-tab-${tab}`}
      >
        {tab !== "recovery" && (
          <>
            <Segmented<"base" | "quote">
              label="Asset"
              value={asset}
              onChange={setAsset}
              options={[
                { value: "base", label: selected?.baseSymbol ?? "Base" },
                { value: "quote", label: selected?.quoteSymbol ?? "Quote" },
              ]}
            />
            <div className="ledger-row">
              <div>
                <span className="eyebrow">Connected wallet</span>
                <b className="mono">
                  {snapshot.wallet.address
                    ? short(snapshot.wallet.address)
                    : "Not connected"}
                </b>
                <small>
                  {snapshot.wallet.walletName ?? "Wallet approval required"}
                </small>
              </div>
              <div className="ledger-arrow" aria-hidden="true">
                {tab === "withdraw" ? "←" : "→"}
              </div>
              <div>
                <span className="eyebrow">Private balance</span>
                <b className="mono">
                  {privateBalance?.spendable ?? "—"} {assetSymbol}
                </b>
                <small>
                  {privateBalance
                    ? `${privateBalance.noteCount ?? 0} notes · ${privateBalance.reserved} reserved · ${privateBalance.pendingSettlement} settling`
                    : "No recovered balance"}
                </small>
              </div>
            </div>
          </>
        )}

        {moving && (
          <>
            <label className="field" htmlFor="darknyx-account-amount">
              <span>
                Amount <small>{assetSymbol}</small>
              </span>
              <div className="input-affix">
                <input
                  id="darknyx-account-amount"
                  className="mono"
                  inputMode="decimal"
                  pattern="[0-9]+([.][0-9]+)?"
                  value={amount}
                  onChange={(event) => setAmount(event.target.value)}
                  placeholder="0"
                  autoComplete="off"
                  disabled={Boolean(blocker)}
                />
                {tab === "withdraw" && (
                  <button
                    type="button"
                    className="affix-button"
                    disabled={Boolean(blocker) || !available}
                    onClick={() =>
                      setAmount((available ?? "").replaceAll(",", ""))
                    }
                  >
                    Max
                  </button>
                )}
              </div>
              <small className="field-hint">
                {tab === "deposit"
                  ? "Your wallet approves the token transfer after the deposit proof is ready."
                  : "Withdrawals consume an exact eligible note. The gross withdrawal amount and recipient are public on Solana."}
              </small>
            </label>
            <button
              className="primary-button block"
              type="button"
              disabled={Boolean(blocker) || busy || !amount}
              onClick={() => void run(tab)}
            >
              {busy ? (
                <LoaderCircle className="spin" aria-hidden="true" />
              ) : tab === "deposit" ? (
                <ArrowDownToLine aria-hidden="true" />
              ) : (
                <ArrowUpFromLine aria-hidden="true" />
              )}
              {tab === "deposit" ? "Deposit privately" : "Withdraw to wallet"}
            </button>
          </>
        )}

        {tab === "consolidate" && (
          <>
            <p className="pane-copy">
              Consolidation merges several small notes into one. It does not
              change the value you hold; it reduces the number of openings a
              later order has to prove.
            </p>
            <div className="stat-tiles">
              <div>
                <span className="eyebrow">Spendable</span>
                <b className="mono">{privateBalance?.spendable ?? "—"}</b>
              </div>
              <div>
                <span className="eyebrow">Spendable notes</span>
                <b className="mono">
                  {privateBalance?.spendableNoteCount ?? "—"}
                </b>
              </div>
              <div>
                <span className="eyebrow">Mergeable together</span>
                <b className="mono">
                  {privateBalance?.mergeableNoteCount ?? "—"}
                </b>
              </div>
            </div>
            <button
              className="primary-button block"
              type="button"
              disabled={
                Boolean(blocker) ||
                busy ||
                !privateBalance ||
                (privateBalance.mergeableNoteCount ?? 0) < 2
              }
              onClick={() => void runMerge()}
            >
              {busy ? (
                <LoaderCircle className="spin" aria-hidden="true" />
              ) : (
                <Layers3 aria-hidden="true" />
              )}
              Consolidate {assetSymbol} notes
            </button>
            {!privateBalance && !blocker && (
              <p className="field-hint">
                Recover or deposit private notes before consolidating.
              </p>
            )}
            {privateBalance &&
              (privateBalance.mergeableNoteCount ?? 0) < 2 &&
              !blocker && (
                <p className="field-hint">
                  {privateBalance.spendableNoteCount === 1
                    ? "Only one spendable note is available. Deposit again before consolidating."
                    : `${privateBalance.spendableNoteCount ?? 0} spendable notes are split across ${privateBalance.shardCount ?? 0} Merkle shards. Consolidation requires at least two notes on one shard.`}
                </p>
              )}
          </>
        )}

        {tab === "recovery" && (
          <>
            <div className="callout is-good">
              <ShieldCheck aria-hidden="true" />
              <span>
                <b>Portable recovery</b>
                Export an encrypted seed backup before relying on this device
                for private account access.
              </span>
            </div>
            <label className="field" htmlFor="darknyx-backup-passphrase">
              <span>Backup passphrase</span>
              <input
                id="darknyx-backup-passphrase"
                type="password"
                value={passphrase}
                onChange={(event) => setPassphrase(event.target.value)}
                autoComplete="new-password"
                minLength={12}
              />
              <small className="field-hint">
                Minimum 12 characters. It is never persisted and cannot be
                recovered.
              </small>
            </label>
            <div className="pane-actions">
              <button
                type="button"
                disabled={
                  snapshot.vault.state !== "unlocked" || passphrase.length < 12
                }
                onClick={() => void downloadBackup()}
              >
                <DownloadCloud aria-hidden="true" /> Export encrypted backup
              </button>
            </div>
            <div className="restore-row">
              <span className="eyebrow">Restore on this device</span>
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
                <UploadCloud aria-hidden="true" /> Restore
              </button>
              {snapshot.vault.state !== "unprovisioned" && (
                <small className="field-hint">
                  Restore is available only before Private Access is created on
                  this browser profile.
                </small>
              )}
            </div>
            {backupStatus && (
              <p className="pane-status" role="status">
                {backupStatus}
              </p>
            )}
          </>
        )}

        {blocker && tab !== "recovery" && (
          <p className="pane-status is-blocked" role="status">
            {blocker}
          </p>
        )}
        {operation && tab !== "recovery" && (
          <div className={`pane-status is-${operation.state}`} role="status">
            {busy && <LoaderCircle className="spin" aria-hidden="true" />}
            <span>
              <b>
                {operation.kind === "merge" ? "consolidation" : operation.kind}
              </b>
              {operation.message}
            </span>
          </div>
        )}
        {accountError && (
          <p className="pane-status is-failed" role="alert">
            {accountError}
          </p>
        )}
      </div>
    </Dialog>
  );
}
