"use client";

interface Stage {
  id: string;
  cluster: "L1" | "TEE" | "L1 + TEE";
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
    primitives: ["Phantom signMessage", "VALID_WALLET_CREATE", "vault::deposit"],
  },
  {
    id: "2",
    cluster: "TEE",
    title: "Submit & match privately",
    body: "Your trading key signs an order into the Intel TDX enclave over RA-TLS. The TEE runs a frequent batch auction every 2 s — L1 never sees individual order intent.",
    primitives: ["POST /orders", "run_batch", "VALID_MATCH_BATCH"],
  },
  {
    id: "3",
    cluster: "L1 + TEE",
    title: "Settle & withdraw",
    body: "The TEE submits a Groth16 batch proof and settles atomically on L1 — locking input notes, appending output notes. Withdraw anytime with a fresh VALID_SPEND proof.",
    primitives: ["verify_match_batch", "tee_forced_settle_batched", "VALID_SPEND"],
  },
];

export function FlowDiagram() {
  return (
    <section
      className="relative isolate overflow-hidden border-t py-24"
      style={{
        borderColor: "rgba(255,255,255,0.06)",
        backgroundColor: "#050505",
        backgroundImage: "radial-gradient(rgba(255,255,255,0.08) 1px, transparent 1px)",
        backgroundSize: "18px 18px",
      }}
    >
      <div className="mx-auto max-w-6xl px-5 sm:px-7">
        <div className="flex flex-col items-start gap-2">
          <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "10px", letterSpacing: "0.18em", textTransform: "uppercase", color: "#d96820" }}>
            How a private trade flows
          </span>
          <h2 className="max-w-3xl leading-tight" style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "clamp(22px, 3vw, 34px)", fontWeight: 600, letterSpacing: "-0.02em" }}>
            <span style={{ color: "rgba(245,243,238,0.9)" }}>Three stages. Two clusters.</span>
            <br />
            <span style={{ color: "rgba(174,172,176,0.55)" }}>One verifiable settlement.</span>
          </h2>
        </div>

        <ol className="mt-16 grid grid-cols-1 gap-6 md:grid-cols-3">
          {STAGES.map((s, idx) => (
            <li key={s.id} className="relative">
              <div
                className={`group h-full p-7 transition-all duration-500 nyx-rise nyx-rise-delay-${idx + 1}`}
                style={{
                  border: "1px solid rgba(255,255,255,0.08)",
                  borderRadius: "30px",
                  background: "rgba(255,255,255,0.035)",
                  backdropFilter: "blur(14px)",
                  boxShadow: "0 0 0 1px rgba(255,255,255,0.02) inset",
                }}
              >
                <div className="flex items-center justify-between">
                  <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "22px", lineHeight: 1, color: "#d96820" }}>
                    0{s.id}
                  </span>
                  <span
                    className={`rounded-full border px-3 py-1 font-mono text-[10px] uppercase tracking-[0.16em] ${
                      s.cluster === "L1"
                        ? "border-nyx-signal-green/40 text-nyx-signal-green"
                        : s.cluster === "TEE"
                        ? "border-[#d96820]/50 text-[#d96820]"
                        : "border-nyx-signal-amber/45 text-nyx-signal-amber"
                    }`}
                  >
                    {s.cluster}
                  </span>
                </div>
                <h3 className="mt-6 leading-snug" style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "15px", fontWeight: 600, color: "rgba(245,243,238,0.9)" }}>
                  {s.title}
                </h3>
                <p className="mt-3" style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "11px", lineHeight: "1.8", color: "rgba(174,172,176,0.58)" }}>
                  {s.body}
                </p>
                <div className="mt-6 flex flex-wrap gap-2">
                  {s.primitives.map((p) => (
                    <code key={p} className="rounded-full border border-white/10 bg-white/[0.03] px-3 py-1 font-mono text-[10.5px] text-nyx-fog">
                      {p}
                    </code>
                  ))}
                </div>
              </div>
            </li>
          ))}
        </ol>

        <div className="mt-16 h-px w-full bg-white/[0.06]" />

        <div className="mt-10 flex flex-wrap items-end justify-between gap-6">
          <p className="max-w-xl text-[13px] text-nyx-fog">
            Want to see every PDA, every cryptographic primitive, and every instruction the on-chain programs accept?
          </p>
          <a href="/architecture" className="inline-flex items-center gap-2 text-[12px] font-semibold uppercase tracking-[0.14em] text-nyx-fog transition hover:text-[#d96820]">
            Architecture deep-dive
            <svg width="11" height="11" viewBox="0 0 11 11" fill="none" aria-hidden="true">
              <path d="M2 5.5h7m0 0L5.5 2m3.5 3.5L5.5 9" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          </a>
        </div>
      </div>
    </section>
  );
}
