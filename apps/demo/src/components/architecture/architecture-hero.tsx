"use client";

import RichGridBackground from "@/components/architecture/rich-grid-bg";

function ScrollDownButton({ onClick }: { onClick?: () => void }) {
  return (
    <button
      onClick={onClick}
      aria-label="Scroll down"
      className="flex items-center justify-center transition-opacity hover:opacity-70"
      style={{
        width: 36,
        height: 36,
        borderRadius: "50%",
        border: "1px solid rgba(217,104,32,0.4)",
        background: "rgba(217,104,32,0.07)",
        cursor: "pointer",
      }}
    >
      <svg width="14" height="20" viewBox="0 0 14 20" fill="none" aria-hidden="true">
        <defs>
          <linearGradient id="arch-scroll-trail" x1="7" y1="0" x2="7" y2="13" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor="#d96820" stopOpacity="0" />
            <stop offset="100%" stopColor="#d96820" stopOpacity="1" />
          </linearGradient>
        </defs>
        <line x1="7" y1="0" x2="7" y2="13" stroke="url(#arch-scroll-trail)" strokeWidth="1.4" strokeLinecap="round" />
        <path d="M2.5 11l4.5 6 4.5-6" stroke="#d96820" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" fill="none" />
      </svg>
    </button>
  );
}

export function ArchitectureHero({ onScrollDown }: { onScrollDown?: () => void }) {
  return (
    <section
      className="relative isolate"
      style={{
        height: "calc(100dvh - 40px)",
        display: "flex",
        flexDirection: "column",
        overflow: "hidden",
        borderBottom: "1px solid rgba(255,255,255,0.05)",
      }}
    >
      <div className="absolute inset-0 pointer-events-none">
        <RichGridBackground stroke="rgba(255,255,255,1)" opacity={0.18} />
      </div>

      {/* MAIN — content contained within inner rect (17% inset on all sides) */}
      <div className="flex flex-1 flex-col justify-between" style={{ padding: "18dvh 18vw" }}>

        {/* Poster text — top */}
        <h1
          className="nyx-rise"
          style={{
            fontFamily: "'JetBrains Mono', monospace",
            fontWeight: 450,
            lineHeight: 1.12,
            letterSpacing: "-0.045em",
          }}
        >
          <span style={{ display: "block", fontSize: "clamp(48px, 7vw, 70px)", color: "#d96820" }}>
            Dark by default
          </span>
          <span style={{ display: "block", fontSize: "clamp(48px, 7vw, 70px)", color: "rgba(245,243,238,0.88)" }}>
            Auditable by design
          </span>
        </h1>

        {/* Metadata blocks — directly below heading, no dividers */}
        <div className="mt-14 flex flex-col gap-10 sm:flex-row sm:gap-22">

          {/* Architecture block */}
          <div>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "8.5px", letterSpacing: "0.24em", textTransform: "uppercase", color: "rgba(174,172,176,0.32)" }}>
              Architecture
            </div>
            <ul className="mt-4 flex flex-col gap-2.5">
              {[
                "TEE-attested execution",
                "Hidden order intent",
                "Groth16 settlement proofs",
                "Solana-native custody",
              ].map((item) => (
                <li key={item} className="flex items-start gap-2">
                  <span style={{ color: "rgba(217,104,32,0.5)", fontFamily: "'JetBrains Mono', monospace", fontSize: "13px", lineHeight: 1.4, marginTop: "1px" }}>·</span>
                  <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "13px", lineHeight: 1.5, color: "rgba(245,243,238,0.5)" }}>
                    {item}
                  </span>
                </li>
              ))}
            </ul>
          </div>

          {/* Status block */}
          <div>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "8.5px", letterSpacing: "0.24em", textTransform: "uppercase", color: "rgba(174,172,176,0.32)" }}>
              Status
            </div>
            <ul className="mt-4 flex flex-col gap-2.5">
              {[
                { value: "3", label: "Layers" },
                { value: "2", label: "Clusters" },
                { value: "6", label: "ZK Circuits" },
                { value: "1", label: "Settlement Path" },
              ].map((stat) => (
                <li key={stat.label} className="flex items-baseline gap-3">
                  <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "18px", fontWeight: 700, letterSpacing: "-0.04em", color: "rgba(245,243,238,0.7)", lineHeight: 1 }}>
                    {stat.value}
                  </span>
                  <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "12px", color: "rgba(174,172,176,0.38)" }}>
                    {stat.label}
                  </span>
                </li>
              ))}
            </ul>
          </div>

        </div>

        {/* Docs link + scroll button — bottom */}
        <div className="mt-auto flex items-center justify-between pt-16">
          <a
            href="https://github.com/skysail-labs/darknyx/blob/main/docs/ARCHITECTURE.md"
            style={{
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: "10px",
              letterSpacing: "0.16em",
              textTransform: "uppercase",
              color: "rgba(217,104,32,0.65)",
              textDecoration: "none",
              display: "inline-flex",
              alignItems: "center",
              gap: "8px",
            }}
          >
            docs/architecture.md
            <svg width="10" height="10" viewBox="0 0 10 10" fill="none">
              <path d="M2 5h6m0 0L5 2m3 3L5 8" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          </a>
          <ScrollDownButton onClick={onScrollDown} />
        </div>
      </div>
    </section>
  );
}
