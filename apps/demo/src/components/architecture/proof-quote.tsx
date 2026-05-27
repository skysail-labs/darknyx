"use client";

/* Between TransactionFlow and CryptoPrimitives */
export function ProofQuote() {
  return (
    <section
      className="relative overflow-hidden border-b"
      style={{
        borderColor: "rgba(255,255,255,0.05)",
        background: "rgba(0,0,0,0.4)",
      }}
    >
      <div className="flex flex-col lg:flex-row" style={{ minHeight: "320px" }}>

        {/* LEFT — stat only */}
        <div
          className="flex flex-col justify-center px-8 py-14 sm:px-12 lg:w-1/2"
          style={{ borderRight: "1px solid rgba(255,255,255,0.05)" }}
        >
          <div style={{
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: "clamp(52px, 9vw, 108px)",
            fontWeight: 700,
            lineHeight: 0.9,
            letterSpacing: "-0.05em",
            color: "#d96820",
          }}>
            N=16
          </div>
          <div className="mt-4" style={{
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: "13px",
            fontWeight: 500,
            lineHeight: 1.4,
            color: "rgba(245,243,238,0.55)",
          }}>
            Matches per batch proof.
          </div>
          <div className="mt-1" style={{
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: "11px",
            color: "rgba(174,172,176,0.32)",
          }}>
            VALID_MATCH_BATCH · Groth16 · BN254
          </div>
        </div>

        {/* RIGHT — ambient wireframe globe */}
        <div className="relative flex-1 overflow-hidden" style={{ minHeight: "320px" }}>
          <div
            className="absolute pointer-events-none"
            style={{ right: "-240px", top: "52%", transform: "translateY(-50%) rotate(-18deg)", width: "820px", height: "820px", opacity: 0.16 }}
          >
            <svg viewBox="0 0 1200 1200" className="h-full w-full" fill="none">
              <g stroke="rgba(255,255,255,0.16)" strokeWidth="1">
                <path d="M 170 600 A 430 120 0 0 1 1030 600" />
                <path d="M 170 600 A 430 220 0 0 1 1030 600" />
                <path d="M 170 600 A 430 320 0 0 1 1030 600" />
                <g transform="rotate(18 600 600)">
                  <ellipse cx="600" cy="600" rx="170" ry="430" />
                  <ellipse cx="600" cy="600" rx="280" ry="430" />
                  <ellipse cx="600" cy="600" rx="360" ry="430" />
                </g>
                <g transform="rotate(-26 600 600)">
                  <ellipse cx="600" cy="600" rx="220" ry="430" />
                  <ellipse cx="600" cy="600" rx="340" ry="430" />
                </g>
              </g>
              <ellipse cx="420" cy="600" rx="560" ry="180" transform="rotate(-24 420 600)"
                stroke="rgba(255,255,255,0.24)" strokeWidth="1.6" strokeDasharray="12 12" />
              <path d="M 120 720 L 280 540 L 280 420 L 360 420 L 360 620 L 260 720"
                fill="none" stroke="rgba(217,104,32,0.18)" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" />
              <path d="M 280 420 L 360 420" fill="none" stroke="#d96820" strokeWidth="2" strokeLinecap="round" filter="url(#orangeGlow-proof)" />
              <circle r="4" fill="#d96820" cx="320" cy="470" />
              <defs>
                <filter id="orangeGlow-proof">
                  <feGaussianBlur stdDeviation="4" result="blur" />
                  <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
                </filter>
                <mask id="fadeMask-proof">
                  <rect width="1200" height="1200" fill="white" />
                  <rect x="0" y="940" width="1200" height="260" fill="black" />
                  <rect x="0" y="0" width="180" height="1200" fill="black" />
                </mask>
              </defs>
              <rect width="1200" height="1200" fill="rgba(255,255,255,0.04)" opacity="0.18" mask="url(#fadeMask-proof)" />
            </svg>
          </div>
        </div>

      </div>
    </section>
  );
}
