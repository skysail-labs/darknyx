"use client";

import { useState } from "react";

type Action =
  | "per_auth"
  | "bootstrap"
  | "submit_taker"
  | "submit_maker"
  | "run_batch";

interface SignatureItem {
  label: string;
  signature: string;
  cluster: "l1" | "er";
}

interface ActionResult {
  ok: boolean;
  action: Action;
  message?: string;
  error?: string;
  tokenPreview?: string;
  signatures?: SignatureItem[];
}

function explorerLink(sig: string) {
  return `https://explorer.solana.com/tx/${sig}?cluster=devnet`;
}

const ACTION_LABELS: Record<Action, string> = {
  per_auth: "1) Verify PER login",
  bootstrap: "2) Bootstrap deposits + slots",
  submit_taker: "3) Submit taker order (BID preset)",
  submit_maker: "4) Submit maker order (ASK preset)",
  run_batch: "5) Run batch + commit",
};

export function LiveErSubmitPanel() {
  const [pendingAction, setPendingAction] = useState<Action | null>(null);
  const [results, setResults] = useState<ActionResult[]>([]);

  const runAction = async (action: Action) => {
    setPendingAction(action);
    try {
      const res = await fetch("/api/live-er-flow", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ action }),
      });
      const json = (await res.json()) as Omit<ActionResult, "action">;
      setResults((prev) => [
        {
          action,
          ok: Boolean(json.ok),
          message: json.message,
          error: json.error,
          tokenPreview: json.tokenPreview,
          signatures: json.signatures,
        },
        ...prev,
      ]);
    } catch (error) {
      setResults((prev) => [
        {
          action,
          ok: false,
          error: error instanceof Error ? error.message : String(error),
        },
        ...prev,
      ]);
    } finally {
      setPendingAction(null);
    }
  };

  return (
    <section className="w-full rounded-2xl border border-zinc-200 bg-white p-6 shadow-sm">
      <div className="mb-5">
        <h2 className="text-xl font-semibold text-zinc-900">
          Optional — Live ER submit_order panel
        </h2>
        <p className="mt-1 text-sm text-zinc-600">
          Runs deterministic maker/taker presets using your local secrets and
          devnet market config.
        </p>
      </div>

      <div className="grid gap-3 sm:grid-cols-2">
        {(Object.keys(ACTION_LABELS) as Action[]).map((action) => (
          <button
            key={action}
            type="button"
            onClick={() => runAction(action)}
            disabled={pendingAction !== null}
            className="rounded-lg border border-zinc-300 px-4 py-2 text-left text-sm font-medium text-zinc-900 enabled:hover:bg-zinc-100 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {pendingAction === action ? "Running…" : ACTION_LABELS[action]}
          </button>
        ))}
      </div>

      <div className="mt-5 space-y-3">
        {results.length === 0 && (
          <p className="text-sm text-zinc-500">No actions run yet.</p>
        )}
        {results.map((result, index) => (
          <div
            key={`${result.action}-${index}`}
            className="rounded-xl border border-zinc-200 p-4"
          >
            <div className="flex flex-wrap items-center gap-2">
              <p className="text-sm font-semibold text-zinc-900">
                {ACTION_LABELS[result.action]}
              </p>
              <span
                className={`rounded-full px-2 py-1 text-xs font-medium ${
                  result.ok
                    ? "bg-emerald-100 text-emerald-800"
                    : "bg-rose-100 text-rose-700"
                }`}
              >
                {result.ok ? "ok" : "failed"}
              </span>
            </div>
            {result.message && (
              <p className="mt-2 text-sm text-zinc-700">{result.message}</p>
            )}
            {result.tokenPreview && (
              <p className="mt-2 text-xs text-zinc-600">
                JWT preview: {result.tokenPreview}…
              </p>
            )}
            {result.error && (
              <p className="mt-2 text-sm text-rose-700">{result.error}</p>
            )}
            {result.signatures && result.signatures.length > 0 && (
              <ul className="mt-3 space-y-1">
                {result.signatures.map((sig) => (
                  <li
                    key={`${sig.label}-${sig.signature}`}
                    className="text-xs text-zinc-700"
                  >
                    <span className="font-semibold">{sig.label}:</span>{" "}
                    {sig.cluster === "l1" ? (
                      <a
                        href={explorerLink(sig.signature)}
                        target="_blank"
                        rel="noreferrer"
                        className="text-indigo-700 hover:text-indigo-900"
                      >
                        {sig.signature}
                      </a>
                    ) : (
                      <span>{sig.signature} (ER)</span>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </div>
        ))}
      </div>
    </section>
  );
}
