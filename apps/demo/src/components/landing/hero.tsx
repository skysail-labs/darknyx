"use client";

import Link from "next/link";

import { AsciiHeroBanner } from "@/components/landing/ascii-hero-banner";

function ScrollDownButton() {
  return (
    <button
      onClick={() => {
        document.getElementById("landing-content")?.scrollIntoView({ behavior: "smooth" });
      }}
      aria-label="Scroll down"
      className="flex items-center justify-center transition-opacity hover:opacity-70"
      style={{
        width: 40,
        height: 40,
        borderRadius: "50%",
        border: "1px solid rgba(217,104,32,0.45)",
        background: "rgba(217,104,32,0.08)",
        color: "#d96820",
        cursor: "pointer",
      }}
    >
      <svg width="16" height="22" viewBox="0 0 16 22" fill="none" aria-hidden="true">
        <defs>
          <linearGradient id="scroll-btn-trail" x1="8" y1="0" x2="8" y2="14" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor="#d96820" stopOpacity="0" />
            <stop offset="100%" stopColor="#d96820" stopOpacity="1" />
          </linearGradient>
        </defs>
        <line x1="8" y1="0" x2="8" y2="14" stroke="url(#scroll-btn-trail)" strokeWidth="1.5" strokeLinecap="round" />
        <path d="M3 12l5 6 5-6" stroke="#d96820" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" fill="none" />
      </svg>
    </button>
  );
}

export function LandingHero() {
  return (
    <section
      className="relative isolate border-b"
      style={{ borderColor: "rgba(255,255,255,0.06)", minHeight: "100dvh", display: "flex", flexDirection: "column" }}
    >
      <div className="mx-auto max-w-6xl px-5 py-20 sm:px-7 sm:py-28">
        <div className="flex flex-col gap-12 lg:flex-row lg:items-center lg:gap-16">

          {/* LEFT — text content */}
          <div className="flex-1 min-w-0">
            <div className="nyx-rise inline-flex items-center gap-2 px-3 py-1.5"
              style={{ border: "1px solid rgba(217,104,32,0.2)", borderRadius: "2px", background: "rgba(217,104,32,0.05)" }}>
              <span className="relative flex h-1.5 w-1.5">
                <span className="absolute inset-0 rounded-full bg-nyx-signal-green opacity-75 animate-ping" />
                <span className="relative inline-flex rounded-full bg-nyx-signal-green h-1.5 w-1.5" />
              </span>
              <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "10px", letterSpacing: "0.18em", textTransform: "uppercase", color: "rgba(174,172,176,0.7)" }}>
                Live on Solana devnet
              </span>
            </div>

            <h1 className="nyx-rise nyx-rise-delay-1 mt-7 leading-[1.05]"
              style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "clamp(28px, 4vw, 48px)", fontWeight: 600, letterSpacing: "-0.02em" }}>
              <span style={{ color: "#d96820" }}>Settle in the dark.</span>
              <br />
              <span style={{ color: "rgba(174,172,176,0.5)" }}>Prove in the light.</span>
            </h1>

            <p className="nyx-rise nyx-rise-delay-2 mt-6 max-w-lg leading-relaxed"
              style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "12px", color: "rgba(174,172,176,0.6)" }}>
              Private orderbook on Solana.<br />
              Orders match inside an attested ephemeral rollup, invisible to L1.<br />
              Every settlement is a Groth16 proof.
            </p>

            <div className="nyx-rise nyx-rise-delay-3 mt-8 flex flex-wrap items-center gap-3">
              <Link
                href="/landing"
                className="group inline-flex items-center gap-2 px-5 py-2.5 text-[11px] font-semibold uppercase tracking-[0.14em] transition"
                style={{ fontFamily: "'JetBrains Mono', monospace", background: "rgba(217,104,32,0.18)", border: "1px solid rgba(217,104,32,0.4)", color: "#d96820", borderRadius: "2px" }}
              >
                <span>Coming Soon</span>
                {/* <svg width="10" height="10" viewBox="0 0 11 11" fill="none" aria-hidden="true">
                  <path d="M2 5.5h7m0 0L5.5 2m3.5 3.5L5.5 9" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
                </svg> */}
              </Link>
              <Link
                href="/architecture"
                className="inline-flex items-center gap-2 px-5 py-2.5 text-[11px] font-semibold uppercase tracking-[0.14em] transition"
                style={{ fontFamily: "'JetBrains Mono', monospace", border: "1px solid rgba(255,255,255,0.1)", color: "#aeacb0", borderRadius: "2px" }}
              >
                Architecture
              </Link>
            </div>
          </div>

          {/* RIGHT — ASCII banner card */}
          <div className="nyx-rise nyx-rise-delay-2 w-full lg:w-120 shrink-0">
            <AsciiHeroBanner contained />
          </div>

        </div>

      </div>

      {/* Scroll-down button pinned near the bottom of the hero / viewport */}
      <div className="absolute bottom-18 left-0 right-0 flex justify-center">
        <ScrollDownButton />
      </div>
    </section>
  );
}
