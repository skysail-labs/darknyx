"use client";

import { useMemo, useState } from "react";

import type { DemoOnChainScenario } from "@/lib/demo-scenario";

interface WithdrawProofPanelProps {
  scenario: DemoOnChainScenario;
}

type ReplayState = "idle" | "withdraw-success" | "replay-rejected";

function txExplorerUrl(signature: string) {
  return `https://explorer.solana.com/tx/${signature}?cluster=devnet`;
}

export function WithdrawProofPanel({ scenario }: WithdrawProofPanelProps) {
  const [state, setState] = useState<ReplayState>("idle");
  const hasWithdrawSignature = Boolean(
    scenario.withdrawReplay.firstWithdrawSignature,
  );

  const statusText = useMemo(() => {
    if (state === "idle") return "Ready";
    if (state === "withdraw-success") return "First withdrawal confirmed";
    return "Replay blocked";
  }, [state]);

  return (
    <section className="w-full rounded-2xl border border-zinc-200 bg-white p-6 shadow-sm">
      <div className="mb-5">
        <h2 className="text-xl font-semibold text-zinc-900">
          Panel C — Withdraw Proof + Replay Guard
        </h2>
        <p className="mt-1 text-sm text-zinc-600">
          Interactive demo mode using pre-recorded devnet evidence from the
          over-collateralised scenario.
        </p>
      </div>

      <div className="rounded-xl border border-zinc-200 bg-zinc-50 p-4">
        <p className="text-sm font-semibold text-zinc-900">
          Status: {statusText}
        </p>
        <p className="mt-1 text-xs text-zinc-600">
          Expected replay error code: {scenario.withdrawReplay.replayErrorCode}
        </p>
      </div>

      <div className="mt-4 flex flex-wrap gap-3">
        <button
          type="button"
          onClick={() => setState("withdraw-success")}
          className="rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white hover:bg-zinc-700"
        >
          Run Withdraw
        </button>
        <button
          type="button"
          onClick={() => setState("replay-rejected")}
          disabled={state === "idle"}
          className="rounded-lg border border-zinc-300 px-4 py-2 text-sm font-medium text-zinc-900 enabled:hover:bg-zinc-100 disabled:cursor-not-allowed disabled:opacity-50"
        >
          Attempt Second Withdrawal
        </button>
      </div>

      {state !== "idle" && (
        <div className="mt-5 rounded-xl border border-zinc-200 p-4">
          {state === "withdraw-success" ? (
            <div>
              <p className="text-sm font-semibold text-emerald-700">
                Withdraw accepted on L1
              </p>
              {hasWithdrawSignature &&
              scenario.withdrawReplay.firstWithdrawSignature ? (
                <a
                  href={txExplorerUrl(
                    scenario.withdrawReplay.firstWithdrawSignature,
                  )}
                  target="_blank"
                  rel="noreferrer"
                  className="mt-2 inline-block text-sm font-medium text-indigo-700 hover:text-indigo-900"
                >
                  View withdraw tx on explorer
                </a>
              ) : (
                <p className="mt-2 text-xs text-zinc-500">
                  Set `NEXT_PUBLIC_DEMO_WITHDRAW_TX_SIG` to attach explorer
                  evidence.
                </p>
              )}
            </div>
          ) : (
            <div>
              <p className="text-sm font-semibold text-rose-700">
                {scenario.withdrawReplay.replayErrorCode} —{" "}
                {scenario.withdrawReplay.replayErrorMessage}
              </p>
              <p className="mt-2 text-xs text-zinc-600">
                Nullifier: {scenario.withdrawReplay.nullifierHex}
              </p>
            </div>
          )}
        </div>
      )}
    </section>
  );
}
