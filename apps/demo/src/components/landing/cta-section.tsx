import Link from "next/link";

import { NyxMark } from "@/components/brand/nyx-mark";

export function CtaSection() {
  return (
    <section className="relative isolate overflow-hidden border-t border-white/[0.06] bg-nyx-ink py-24">
      <div className="nyx-aurora" />
      <div className="mx-auto max-w-5xl px-5 text-center sm:px-7">
        <NyxMark size={64} className="mx-auto text-nyx-chalk nyx-drift" />
        <h2 className="nyx-display mt-7 text-[34px] leading-tight sm:text-[48px]">
          Try it on devnet.
          <br />
          <span className="text-nyx-fog">Every step is verifiable.</span>
        </h2>
        <p className="mx-auto mt-5 max-w-xl text-[15px] text-nyx-fog">
          Connect a Phantom wallet on Solana devnet and run the full flow —
          identity derivation, shielded deposit, ER-private order, TEE
          settlement, and proof-backed withdraw. Every receipt is an explorer
          link.
        </p>
        <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
          <Link
            href="/dapp"
            className="group inline-flex items-center gap-2 rounded-sm bg-nyx-chalk px-6 py-3.5 text-[12px] font-semibold uppercase tracking-[0.14em] text-nyx-ink transition hover:bg-white"
          >
            Launch dapp
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
            className="inline-flex items-center gap-2 rounded-sm border border-white/15 px-6 py-3.5 text-[12px] font-semibold uppercase tracking-[0.14em] text-nyx-chalk transition hover:bg-white/5"
          >
            Architecture
          </Link>
        </div>
      </div>
    </section>
  );
}
