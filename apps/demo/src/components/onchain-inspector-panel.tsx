import type { DemoOnChainScenario } from "@/lib/demo-scenario";

interface OnChainInspectorPanelProps {
  scenario: DemoOnChainScenario;
}

function txExplorerUrl(signature: string) {
  return `https://explorer.solana.com/tx/${signature}?cluster=devnet`;
}

export function OnChainInspectorPanel({
  scenario,
}: OnChainInspectorPanelProps) {
  return (
    <section className="w-full rounded-2xl border border-zinc-200 bg-white p-6 shadow-sm">
      <div className="mb-5">
        <h2 className="text-xl font-semibold text-zinc-900">
          Panel B — On-chain Inspector
        </h2>
        <p className="mt-1 text-sm text-zinc-600">
          Cluster: {scenario.cluster}. Scenario: {scenario.name}. Snapshot date:{" "}
          {scenario.asOf}.
        </p>
      </div>

      <div className="rounded-xl border border-zinc-200">
        <div className="border-b border-zinc-200 bg-zinc-50 px-4 py-3 text-sm font-semibold text-zinc-800">
          Transaction evidence
        </div>
        <ul className="divide-y divide-zinc-200">
          {scenario.transactions.map((tx) => (
            <li key={tx.id} className="px-4 py-3">
              <div className="flex flex-wrap items-center gap-2">
                <p className="text-sm font-semibold text-zinc-900">
                  {tx.label}
                </p>
                <span
                  className={`rounded-full px-2 py-1 text-xs font-medium ${
                    tx.layer === "ER"
                      ? "bg-purple-100 text-purple-800"
                      : "bg-zinc-200 text-zinc-900"
                  }`}
                >
                  {tx.layer}
                </span>
              </div>
              <p className="mt-1 text-sm text-zinc-600">{tx.description}</p>
              {tx.signature ? (
                <a
                  href={txExplorerUrl(tx.signature)}
                  target="_blank"
                  rel="noreferrer"
                  className="mt-2 inline-block text-sm font-medium text-indigo-700 hover:text-indigo-900"
                >
                  Open tx on explorer
                </a>
              ) : (
                <p className="mt-2 text-xs text-zinc-500">
                  Attach signature via `NEXT_PUBLIC_DEMO_*_TX_SIG` env vars for
                  live explorer evidence.
                </p>
              )}
            </li>
          ))}
        </ul>
      </div>

      <div className="mt-5 rounded-xl border border-zinc-200">
        <div className="border-b border-zinc-200 bg-zinc-50 px-4 py-3 text-sm font-semibold text-zinc-800">
          Decoded settlement evidence
        </div>
        <dl className="grid grid-cols-1 gap-x-4 gap-y-3 p-4 text-sm text-zinc-700 sm:grid-cols-2">
          <div>
            <dt className="text-xs uppercase tracking-wide text-zinc-500">
              Match ID
            </dt>
            <dd className="font-mono text-xs text-zinc-900">
              {scenario.settlement.matchIdHex}
            </dd>
          </div>
          <div>
            <dt className="text-xs uppercase tracking-wide text-zinc-500">
              Merkle Root
            </dt>
            <dd className="font-mono text-xs text-zinc-900">
              {scenario.settlement.newMerkleRootHex}
            </dd>
          </div>
          <div>
            <dt className="text-xs uppercase tracking-wide text-zinc-500">
              Clearing Price
            </dt>
            <dd>{scenario.settlement.clearingPrice}</dd>
          </div>
          <div>
            <dt className="text-xs uppercase tracking-wide text-zinc-500">
              Base / Quote
            </dt>
            <dd>
              {scenario.settlement.baseAmount} /{" "}
              {scenario.settlement.quoteAmount}
            </dd>
          </div>
          <div>
            <dt className="text-xs uppercase tracking-wide text-zinc-500">
              Buyer Change / Fee
            </dt>
            <dd>
              {scenario.settlement.buyerChangeAmount} /{" "}
              {scenario.settlement.buyerFeeAmount}
            </dd>
          </div>
          <div>
            <dt className="text-xs uppercase tracking-wide text-zinc-500">
              Seller Change / Fee
            </dt>
            <dd>
              {scenario.settlement.sellerChangeAmount} /{" "}
              {scenario.settlement.sellerFeeAmount}
            </dd>
          </div>
          <div>
            <dt className="text-xs uppercase tracking-wide text-zinc-500">
              Trade leaves (C/D)
            </dt>
            <dd>
              {scenario.settlement.noteCLeaf} / {scenario.settlement.noteDLeaf}
            </dd>
          </div>
          <div>
            <dt className="text-xs uppercase tracking-wide text-zinc-500">
              Change leaves (E/F)
            </dt>
            <dd>
              {scenario.settlement.noteELeaf} / {scenario.settlement.noteFLeaf}
            </dd>
          </div>
          <div>
            <dt className="text-xs uppercase tracking-wide text-zinc-500">
              Fee leaf
            </dt>
            <dd>{scenario.settlement.feeLeaf}</dd>
          </div>
          <div>
            <dt className="text-xs uppercase tracking-wide text-zinc-500">
              Relock active (buyer/seller)
            </dt>
            <dd>
              {String(scenario.settlement.buyerRelockActive)} /{" "}
              {String(scenario.settlement.sellerRelockActive)}
            </dd>
          </div>
        </dl>
      </div>
    </section>
  );
}
