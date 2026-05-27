import Link from "next/link";

import { NyxMark } from "@/components/brand/nyx-mark";

export function CtaSection() {
  return (
    <section className="relative isolate border-t py-24" style={{ borderColor: "rgba(255,255,255,0.06)" }}>
      <div className="mx-auto max-w-5xl px-5 text-center sm:px-7">
        <NyxMark size={56} className="mx-auto nyx-drift" style={{ color: "#d96820" }} />
        <h2 className="mt-7 leading-tight" style={{ fontFamily: "'JetBrains Mono', monospace", fontWeight: 600, letterSpacing: "-0.02em" }}>
          <span style={{  fontSize: "clamp(24px, 3.5vw, 40px)", color: "#d96820" }}>Soon live on Mainnet</span>
          <br />
          <span style={{  fontSize: "clamp(24px, 3vw, 35px)", color: "rgba(174,172,176,0.5)" }}>Privacy without sacrificing auditability</span>
        </h2>
        <p className="mx-auto mt-5 max-w-xl" style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "12px", lineHeight: "1.8", color: "rgba(174,172,176,0.55)" }}>
        </p>
        <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
          {/* <Link
            href="/dapp"
            className="group inline-flex items-center gap-2 rounded-sm px-6 py-3.5 text-[12px] font-semibold uppercase tracking-[0.14em] transition"
            style={{ fontFamily: "'JetBrains Mono', monospace", background: "rgba(217,104,32,0.18)", border: "1px solid rgba(217,104,32,0.4)", color: "#d96820" }}
          >
            Launch dapp
            <svg width="11" height="11" viewBox="0 0 11 11" fill="none" aria-hidden="true">
              <path
                d="M2 5.5h7m0 0L5.5 2m3.5 3.5L5.5 9"
                stroke="currentColor"
                strokeWidth="1.6"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
          </Link> */}
          <Link
            href="/architecture"
            className="inline-flex items-center gap-2 rounded-sm px-6 py-3.5 text-[12px] font-semibold uppercase tracking-[0.14em] transition"
            style={{ fontFamily: "'JetBrains Mono', monospace", border: "1px solid rgba(255,255,255,0.1)", color: "#aeacb0" }}
          >
            Architecture
          </Link>
        </div>
      </div>
    </section>
  );
}
