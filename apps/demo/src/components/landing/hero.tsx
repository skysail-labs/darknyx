import Link from "next/link";

import { NyxMark } from "@/components/brand/nyx-mark";

export function LandingHero() {
  return (
    <section className="relative isolate overflow-hidden">
      <div className="nyx-aurora" />
      <div className="nyx-grid absolute inset-0 -z-10 opacity-70" />

      <div className="mx-auto max-w-6xl px-5 pt-24 pb-28 sm:px-7 sm:pt-32 sm:pb-36">
        <div className="nyx-rise inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/[0.03] px-3 py-1.5">
          <span className="relative flex h-1.5 w-1.5">
            <span className="absolute inset-0 rounded-full bg-nyx-signal-green opacity-75 animate-ping" />
            <span className="relative inline-flex rounded-full bg-nyx-signal-green h-1.5 w-1.5" />
          </span>
          <span className="font-mono text-[11px] uppercase tracking-[0.18em] text-nyx-fog">
            Live on Solana devnet
          </span>
        </div>

        <h1 className="nyx-rise nyx-rise-delay-1 nyx-display mt-7 max-w-4xl text-[44px] leading-[1.05] sm:text-[68px] sm:leading-[1.02]">
          <span className="text-nyx-chalk">Settle in the dark.</span>
          <br />
          <span className="text-nyx-fog">Prove in the light.</span>
        </h1>

        <p className="nyx-rise nyx-rise-delay-2 mt-6 max-w-2xl text-[17px] leading-relaxed text-nyx-fog sm:text-lg">
          Nyx is a privacy-preserving on-chain darkpool for Solana. Order intent
          stays inside an attested ephemeral rollup. Settlement lands as
          shielded UTXO notes verified by Groth16 zero-knowledge proofs — every
          balance reconciles, no individual order is exposed.
        </p>

        <div className="nyx-rise nyx-rise-delay-3 mt-9 flex flex-wrap items-center gap-3">
          <Link
            href="/dapp"
            className="group inline-flex items-center gap-2 rounded-sm bg-nyx-chalk px-5 py-3 text-[12px] font-semibold uppercase tracking-[0.14em] text-nyx-ink transition hover:bg-white"
          >
            <span>Launch dapp</span>
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
          </Link>
          <Link
            href="/architecture"
            className="inline-flex items-center gap-2 rounded-sm border border-white/15 px-5 py-3 text-[12px] font-semibold uppercase tracking-[0.14em] text-nyx-chalk transition hover:bg-white/5"
          >
            Read the architecture
          </Link>
        </div>

        {/* Hero device — animated half-moon over privacy ledger */}
        <div className="nyx-rise nyx-rise-delay-4 mt-16 flex flex-wrap items-end gap-12">
          <div className="relative">
            <div
              className="absolute -inset-8 rounded-full bg-[radial-gradient(closest-side,rgba(245,243,238,0.10),transparent)]"
              aria-hidden="true"
            />
            <NyxMark size={140} className="relative text-nyx-chalk nyx-drift" />
          </div>

          <PrivacyLedgerStrip />
        </div>
      </div>
    </section>
  );
}

/**
 * The "ledger" mini-component beside the hero — visually communicates the
 * privacy boundary: the order side is censored, the settlement leaf is public.
 */
function PrivacyLedgerStrip() {
  const rows: Array<{ label: string; value: string; hidden?: boolean }> = [
    { label: "submit_order", value: "side · price · amount", hidden: true },
    { label: "match_id", value: "0x7a3f…9c2d" },
    { label: "note_c (BASE buyer)", value: "Poseidon(mint, amt, owner, …)" },
    { label: "note_d (QUOTE seller)", value: "Poseidon(mint, amt, owner, …)" },
    { label: "settle_root", value: "0xd1b2…84a0" },
  ];
  return (
    <div className="relative w-full max-w-md flex-1 rounded-md border border-white/10 bg-nyx-graphite-2/80 p-4 backdrop-blur">
      <div className="mb-3 flex items-center justify-between">
        <span className="nyx-eyebrow">privacy ledger</span>
        <span className="font-mono text-[10px] text-nyx-fog">slot 0x…f3</span>
      </div>
      <ul className="space-y-2 font-mono text-[11px]">
        {rows.map((r) => (
          <li
            key={r.label}
            className="flex items-center justify-between gap-3 border-b border-white/[0.05] pb-1.5 last:border-0"
          >
            <span className="text-nyx-fog">{r.label}</span>
            {r.hidden ? (
              <span className="nyx-scanline relative inline-block min-w-[160px] rounded-sm bg-white/[0.06] px-2 py-1 text-[10px] uppercase tracking-[0.14em] text-nyx-fog">
                hidden in ER
              </span>
            ) : (
              <span className="truncate text-nyx-chalk">{r.value}</span>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}
