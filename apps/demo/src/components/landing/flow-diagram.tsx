interface Stage {
  id: string;
  cluster: "L1" | "ER" | "L1 + ER";
  title: string;
  body: string;
  primitives: string[];
}

const STAGES: Stage[] = [
  {
    id: "1",
    cluster: "L1",
    title: "Identity & deposit",
    body: "Sign a deterministic seed in your wallet, prove VALID_WALLET_CREATE in the browser, and shield SPL tokens into the vault as a UTXO note.",
    primitives: [
      "Phantom signMessage",
      "VALID_WALLET_CREATE",
      "vault::deposit",
    ],
  },
  {
    id: "2",
    cluster: "ER",
    title: "Submit & match privately",
    body: "Your trading key signs submit_order on the Ephemeral Rollup. run_batch clears the book at a uniform price. L1 sees only an aggregate snapshot.",
    primitives: ["delegate_pending_order", "submit_order", "run_batch"],
  },
  {
    id: "3",
    cluster: "L1 + ER",
    title: "Settle & withdraw",
    body: "An attested TEE settles atomically on L1 — locking input notes, appending output notes. Withdraw whenever, with a fresh VALID_SPEND proof.",
    primitives: ["undelegate_market", "tee_forced_settle", "VALID_SPEND"],
  },
];

export function FlowDiagram() {
  return (
    <section className="relative isolate border-t border-white/[0.06] bg-nyx-graphite-2/40 py-24">
      <div className="mx-auto max-w-6xl px-5 sm:px-7">
        <div className="flex flex-col items-start gap-2">
          <span className="nyx-eyebrow">How a private trade flows</span>
          <h2 className="nyx-display max-w-3xl text-[34px] leading-tight sm:text-[44px]">
            Three stages. Two clusters.
            <br />
            <span className="text-nyx-fog">One verifiable settlement.</span>
          </h2>
        </div>

        <ol className="mt-14 grid grid-cols-1 gap-4 md:grid-cols-3">
          {STAGES.map((s, idx) => (
            <li key={s.id} className="relative">
              {/* connector line on md+ */}
              {idx < STAGES.length - 1 ? (
                <div
                  className="hidden md:block absolute right-[-8px] top-12 h-px w-4 bg-gradient-to-r from-white/30 to-transparent"
                  aria-hidden="true"
                />
              ) : null}
              <div
                className={`group h-full rounded-md border border-white/[0.08] bg-nyx-graphite p-6 transition-colors hover:border-white/20 nyx-rise nyx-rise-delay-${idx + 1}`}
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono text-[24px] leading-none text-nyx-chalk">
                    0{s.id}
                  </span>
                  <span
                    className={`rounded-sm border px-2 py-0.5 font-mono text-[10px] uppercase tracking-[0.16em] ${
                      s.cluster === "L1"
                        ? "border-nyx-signal-green/40 text-nyx-signal-green"
                        : s.cluster === "ER"
                          ? "border-nyx-accent/50 text-nyx-accent"
                          : "border-nyx-signal-amber/45 text-nyx-signal-amber"
                    }`}
                  >
                    {s.cluster}
                  </span>
                </div>
                <h3 className="mt-5 text-[18px] font-semibold leading-snug text-nyx-chalk">
                  {s.title}
                </h3>
                <p className="mt-2 text-[13px] leading-relaxed text-nyx-fog">
                  {s.body}
                </p>
                <div className="mt-5 flex flex-wrap gap-1.5">
                  {s.primitives.map((p) => (
                    <code
                      key={p}
                      className="rounded-sm border border-white/[0.08] bg-white/[0.03] px-2 py-1 font-mono text-[10.5px] text-nyx-fog"
                    >
                      {p}
                    </code>
                  ))}
                </div>
              </div>
            </li>
          ))}
        </ol>

        <div className="mt-16 nyx-horizon" />

        <div className="mt-10 flex flex-wrap items-end justify-between gap-6">
          <p className="max-w-xl text-[13px] text-nyx-fog">
            Want to see every PDA, every cryptographic primitive, and every
            instruction the on-chain programs accept?
          </p>
          <a
            href="/architecture"
            className="inline-flex items-center gap-2 text-[12px] font-semibold uppercase tracking-[0.14em] text-nyx-chalk transition hover:text-nyx-accent"
          >
            Architecture deep-dive
            <svg
              width="11"
              height="11"
              viewBox="0 0 11 11"
              fill="none"
              aria-hidden="true"
            >
              <path
                d="M2 5.5h7m0 0L5.5 2m3.5 3.5L5.5 9"
                stroke="currentColor"
                strokeWidth="1.6"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
          </a>
        </div>
      </div>
    </section>
  );
}
