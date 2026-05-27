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

      {/* ASCII banner — true full-bleed, no horizontal padding */}
      <div className="nyx-rise nyx-rise-delay-1 w-full mt-16">
        <AsciiHeroBanner contained />
      </div>

      {/* Bottom row — constrained to max-w-6xl, aligned with the rest of the page */}
      <div className="nyx-rise nyx-rise-delay-2 mx-auto w-full max-w-6xl px-5 sm:px-7 pt-10 pb-16">
        <div className="flex flex-col gap-8 sm:flex-row sm:items-end sm:justify-between">

          {/* Left — headline + description */}
          <div className="min-w-0">
            <h1 className="leading-[1.05]"
              style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "clamp(22px, 3vw, 36px)", fontWeight: 600, letterSpacing: "-0.02em" }}>
              <span style={{ color: "#d96820" }}>Settle in the dark<br/></span>
              <span style={{ color: "rgba(174,172,176,0.45)" }}> Prove in the light</span>
            </h1>
            <p className="mt-3 max-w-lg"
              style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "11.5px", lineHeight: 1.8, color: "rgba(174,172,176,0.5)" }}>
              Private orderbook on Solana. Orders match inside an attested Intel TDX enclave, invisible to L1. Every settlement is a Groth16 proof.
            </p>
          </div>

          {/* Right — buttons stacked */}
          <div className="flex flex-col gap-2 shrink-0 sm:items-end">
            <Link
              href="/landing"
              className="inline-flex items-center justify-center px-6 py-2.5 text-[11px] font-semibold uppercase tracking-[0.14em] transition"
              style={{ fontFamily: "'JetBrains Mono', monospace", background: "rgba(217,104,32,0.18)", border: "1px solid rgba(217,104,32,0.4)", color: "#d96820", borderRadius: "2px", minWidth: "160px" }}
            >
              Coming Soon
            </Link>
            <Link
              href="/architecture"
              className="inline-flex items-center justify-center px-6 py-2.5 text-[11px] font-semibold uppercase tracking-[0.14em] transition"
              style={{ fontFamily: "'JetBrains Mono', monospace", border: "1px solid rgba(255,255,255,0.1)", color: "#aeacb0", borderRadius: "2px", minWidth: "160px" }}
            >
              Architecture
            </Link>
          </div>

        </div>
      </div>

      {/* Scroll-down button */}
      <div className="absolute bottom-17 left-0 right-0 flex justify-center">
        <ScrollDownButton />
      </div>
    </section>
  );
}
