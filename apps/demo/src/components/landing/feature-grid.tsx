"use client";

const orange = "#d96820";
const green = "rgba(95,184,95,1)";

const FEATURES = [
  {
    eyebrow: "01 · Hidden intent",
    title: "Orders never touch\nthe L1 mempool.",
    sub: "Side, price, amount stay inside the TDX enclave.",
    cluster: "TEE",
    clusterColor: orange,
    clusterBg: "rgba(217,104,32,0.10)",
    tech: "Intel TDX · Phala",
    image: "/card-1.jpg",
  },
  {
    eyebrow: "02 · Verifiable settlement",
    title: "Every fill is a\nGroth16 proof.",
    sub: "VALID_SPEND · VALID_MATCH_BATCH · BN254",
    cluster: "L1",
    clusterColor: green,
    clusterBg: "rgba(95,184,95,0.08)",
    tech: "groth16-solana",
    image: "/card-3.jpg",
  },
  {
    eyebrow: "03 · Attested executor",
    title: "TEE-signed atomic\nsettlement.",
    sub: "Intel TDX · Ed25519 attestation on-chain.",
    cluster: "TEE",
    clusterColor: orange,
    clusterBg: "rgba(217,104,32,0.10)",
    tech: "Phala Cloud",
    image: "/card-2.jpg",
  },
  {
    eyebrow: "04 · UTXO accounting",
    title: "Shielded notes,\npublic roots.",
    sub: "Depth-20 Poseidon Merkle · 32-root ring buffer.",
    cluster: "L1",
    clusterColor: green,
    clusterBg: "rgba(95,184,95,0.08)",
    tech: "darkpool-crypto",
    image: "/card-4.jpg",
  },
];

export function FeatureGrid() {
  return (
    <section id="landing-content" className="relative isolate border-t py-24"
      style={{ borderColor: "rgba(255,255,255,0.06)" }}>
      <div className="mx-auto max-w-6xl px-5 sm:px-7">

        <div className="max-w-2xl">
          <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "10px", letterSpacing: "0.18em", textTransform: "uppercase", color: orange }}>
            What Nyx gives you
          </span>
          <h2 className="mt-3 leading-tight" style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "clamp(22px, 3vw, 34px)", fontWeight: 600, letterSpacing: "-0.02em" }}>
            <span style={{ color: "rgba(245,243,238,0.85)" }}>A darkpool you can audit</span>
            <span style={{ color: "rgba(174,172,176,0.5)" }}> without compromising privacy.</span>
          </h2>
        </div>

        <div className="mt-12 grid grid-cols-1 sm:grid-cols-2 gap-px"
          style={{ background: "rgba(255,255,255,0.05)" }}>
          {FEATURES.map((f) => (
            <article key={f.eyebrow}
              className="group relative overflow-hidden"
              style={{ background: "#050506", minHeight: "300px", padding: "32px 32px 28px" }}>

              {/* background image */}
              <div className="absolute inset-0 pointer-events-none transition-opacity duration-500 group-hover:opacity-100"
                style={{
                  backgroundImage: `url(${f.image})`,
                  backgroundSize: "cover",
                  backgroundPosition: "center",
                  opacity: 0.8,
                }} />

              {/* dark gradient overlay so text stays readable */}
              <div className="absolute inset-0 pointer-events-none"
                style={{ background: "linear-gradient(135deg, rgba(5,5,6,0.88) 30%, rgba(5,5,6,0.15) 100%)" }} />

              {/* top row */}
              <div className="relative z-10 flex items-center justify-between">
                <div style={{
                  display: "inline-flex", alignItems: "center", gap: "6px",
                  padding: "4px 10px",
                  background: f.clusterBg,
                  border: `1px solid ${f.clusterColor}40`,
                  borderRadius: "2px",
                }}>
                  <div style={{ width: "5px", height: "5px", borderRadius: "50%", background: f.clusterColor, flexShrink: 0 }} />
                  <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "8.5px", letterSpacing: "0.18em", textTransform: "uppercase", color: f.clusterColor }}>
                    {f.cluster}
                  </span>
                </div>
                <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "9px", letterSpacing: "0.12em", color: "rgba(174,172,176,0.35)" }}>
                  {f.tech}
                </span>
              </div>

              {/* title block */}
              <div className="relative z-10 mt-10">
                <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "9px", letterSpacing: "0.2em", textTransform: "uppercase", color: "rgba(174,172,176,0.35)" }}>
                  {f.eyebrow}
                </div>
                <h3 className="mt-3" style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "clamp(18px, 2vw, 22px)", fontWeight: 600, lineHeight: 1.18, letterSpacing: "-0.025em", color: "rgba(245,243,238,0.92)", whiteSpace: "pre-line" }}>
                  {f.title}
                </h3>
              </div>

              {/* sub — bottom */}
              <div className="relative z-10 mt-8">
                <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "10.5px", color: "rgba(174,172,176,0.45)", lineHeight: 1.5 }}>
                  {f.sub}
                </span>
              </div>

              {/* hover line */}
              <div className="absolute inset-x-0 bottom-0 h-px opacity-0 transition-opacity duration-300 group-hover:opacity-100"
                style={{ background: `linear-gradient(to right, transparent, ${f.clusterColor}55, transparent)` }} />
            </article>
          ))}
        </div>

      </div>
    </section>
  );
}
