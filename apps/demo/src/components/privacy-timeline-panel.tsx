import type { PrivacyTimelineStep } from "@/lib/privacy-timeline";

interface PrivacyTimelinePanelProps {
  steps: PrivacyTimelineStep[];
}

const PRIVACY_BADGE: Record<PrivacyTimelineStep["privacy"], string> = {
  visible: "bg-amber-100 text-amber-800",
  private: "bg-emerald-100 text-emerald-800",
  mixed: "bg-blue-100 text-blue-800",
};

const LAYER_BADGE: Record<PrivacyTimelineStep["layer"], string> = {
  ER: "bg-purple-100 text-purple-800",
  L1: "bg-zinc-200 text-zinc-900",
};

function explorerUrl(signature?: string) {
  if (!signature) return null;
  return `https://explorer.solana.com/tx/${signature}?cluster=devnet`;
}

export function PrivacyTimelinePanel({ steps }: PrivacyTimelinePanelProps) {
  return (
    <section className="w-full rounded-2xl border border-zinc-200 bg-white p-6 shadow-sm">
      <div className="mb-5">
        <h2 className="text-xl font-semibold text-zinc-900">
          Panel A — Privacy Timeline
        </h2>
        <p className="mt-1 text-sm text-zinc-600">
          ER stages keep order intent private; L1 stages expose only
          settlement-level artifacts.
        </p>
      </div>

      <ol className="space-y-4">
        {steps.map((step, index) => {
          const txUrl = explorerUrl(step.signature);
          return (
            <li
              key={step.id}
              className="rounded-xl border border-zinc-200 bg-zinc-50 p-4"
            >
              <div className="flex flex-wrap items-center gap-2">
                <span className="inline-flex h-6 min-w-6 items-center justify-center rounded-full bg-zinc-900 px-2 text-xs font-semibold text-white">
                  {index + 1}
                </span>
                <h3 className="text-base font-semibold text-zinc-900">
                  {step.title}
                </h3>
                <span
                  className={`rounded-full px-2 py-1 text-xs font-medium ${LAYER_BADGE[step.layer]}`}
                >
                  {step.layer}
                </span>
                <span
                  className={`rounded-full px-2 py-1 text-xs font-medium capitalize ${PRIVACY_BADGE[step.privacy]}`}
                >
                  {step.privacy}
                </span>
              </div>

              <p className="mt-2 text-sm text-zinc-700">{step.summary}</p>

              {txUrl ? (
                <a
                  className="mt-3 inline-block text-sm font-medium text-indigo-700 hover:text-indigo-900"
                  href={txUrl}
                  target="_blank"
                  rel="noreferrer"
                >
                  View transaction evidence
                </a>
              ) : (
                <p className="mt-3 text-xs text-zinc-500">
                  Transaction evidence link will be attached per scenario run.
                </p>
              )}
            </li>
          );
        })}
      </ol>
    </section>
  );
}
