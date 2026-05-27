interface Layer {
  tag: string;
  cluster: "L1" | "TEE" | "Client";
  title: string;
  body: string;
  techs: string[];
}

const LAYERS: Layer[] = [
  {
    tag: "01",
    cluster: "L1",
    title: "Custody, Merkle tree, ZK verifier",
    body: "Anchor 0.32 vault program holds the depth-20 incremental Poseidon Merkle tree, 32-root ring buffer, TEE pubkey, and protocol-fee config. Withdrawals go through an on-chain Groth16 verifier (alt_bn128 syscall).",
    techs: ["vault", "matching_engine", "groth16-solana"],
  },
  {
    tag: "02",
    cluster: "TEE",
    title: "Hidden order intent + matching",
    body: "An Intel TDX enclave on Phala Cloud hosts the order book and matching engine. Orders arrive over RA-TLS. A batch auction fires every 2s; VALID_MATCH_BATCH Groth16 proof is generated inside the enclave before any L1 settlement.",
    techs: ["nyx-tee", "VALID_MATCH_BATCH", "ark-groth16"],
  },
  {
    tag: "03",
    cluster: "Client",
    title: "Key derivation, proofs, ix builders",
    body: "@nyx/sdk hand-codes every Anchor instruction. snarkjs runs in a Web Worker for VALID_WALLET_CREATE and VALID_SPEND. Key chain: Phantom signature → master seed → spending / viewing / trading keys.",
    techs: ["@nyx/sdk", "snarkjs", "darkpool-crypto"],
  },
];

const clusterColor = (c: string) =>
  c === "L1" ? "rgba(95,184,95,0.8)" : c === "TEE" ? "#d96820" : "rgba(174,172,176,0.6)";
const clusterBorder = (c: string) =>
  c === "L1" ? "rgba(95,184,95,0.35)" : c === "TEE" ? "rgba(217,104,32,0.45)" : "rgba(174,172,176,0.25)";

export function SystemOverview() {
  return (
    <div style={{ height: "100%", display: "flex", flexDirection: "column", overflow: "hidden" }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", gap: 0, borderBottom: "1px solid rgba(255,255,255,0.05)", flexShrink: 0 }}>
        <div style={{ padding: "8px 32px", borderRight: "1px solid rgba(255,255,255,0.05)" }}>
          <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "9px", letterSpacing: "0.22em", textTransform: "uppercase", color: "rgba(217,104,32,0.8)" }}>
            01 · System overview
          </span>
        </div>
        <div style={{ padding: "8px 24px" }}>
          <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "9px", letterSpacing: "0.16em", textTransform: "uppercase", color: "rgba(174,172,176,0.25)" }}>
            3 trust boundaries · 2 clusters · 6 ZK circuits
          </span>
        </div>
      </div>

      {/* Body */}
      <div style={{ flex: 1, display: "flex", overflow: "hidden" }}>
        {/* Left rail */}
        <div style={{ width: "220px", flexShrink: 0, borderRight: "1px solid rgba(255,255,255,0.05)", display: "flex", flexDirection: "column", justifyContent: "space-between", padding: "32px" }}>
          <div>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "clamp(56px, 7vw, 88px)", fontWeight: 700, lineHeight: 0.88, letterSpacing: "-0.04em", color: "rgba(255,255,255,0.04)", userSelect: "none" }}>03</div>
            <h2 style={{ marginTop: "16px", fontFamily: "'JetBrains Mono', monospace", fontSize: "clamp(14px, 1.4vw, 18px)", fontWeight: 600, lineHeight: 1.1, letterSpacing: "-0.025em", color: "rgba(245,243,238,0.9)" }}>
              Three trust<br />boundaries.
            </h2>
            <p style={{ marginTop: "10px", fontFamily: "'JetBrains Mono', monospace", fontSize: "11px", lineHeight: 1.7, color: "rgba(174,172,176,0.45)" }}>
              L1 settles.<br />TEE matches.<br />Client proves.
            </p>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
            {(["L1", "TEE", "Client"] as const).map((c) => (
              <div key={c} style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                <div style={{ height: "1px", flex: 1, background: clusterBorder(c) }} />
                <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "9px", letterSpacing: "0.16em", textTransform: "uppercase", color: clusterColor(c) }}>{c}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Cards */}
        <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
          {LAYERS.map((l, idx) => (
            <div key={l.tag} style={{ flex: 1, display: "flex", borderTop: idx > 0 ? "1px solid rgba(255,255,255,0.04)" : "none", overflow: "hidden" }}>
              {/* Tag */}
              <div style={{ width: "120px", flexShrink: 0, borderRight: "1px solid rgba(255,255,255,0.04)", padding: "20px 24px", display: "flex", flexDirection: "column", gap: "8px" }}>
                <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "24px", fontWeight: 700, color: "rgba(255,255,255,0.1)", letterSpacing: "-0.02em" }}>{l.tag}</span>
                <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "8.5px", letterSpacing: "0.14em", textTransform: "uppercase", padding: "2px 6px", border: `1px solid ${clusterBorder(l.cluster)}`, color: clusterColor(l.cluster), borderRadius: "2px", alignSelf: "flex-start" }}>{l.cluster}</span>
              </div>
              {/* Content */}
              <div style={{ flex: 1, padding: "20px 28px", overflow: "hidden" }}>
                <h3 style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "12.5px", fontWeight: 600, letterSpacing: "-0.01em", color: "rgba(245,243,238,0.88)", lineHeight: 1.3 }}>{l.title}</h3>
                <p style={{ marginTop: "8px", fontFamily: "'JetBrains Mono', monospace", fontSize: "11px", lineHeight: 1.8, color: "rgba(174,172,176,0.5)" }}>{l.body}</p>
                <div style={{ marginTop: "10px", display: "flex", flexWrap: "wrap", gap: "6px" }}>
                  {l.techs.map((t) => (
                    <code key={t} style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "10px", padding: "2px 7px", border: "1px solid rgba(255,255,255,0.07)", background: "rgba(255,255,255,0.02)", color: "rgba(174,172,176,0.45)", borderRadius: "2px" }}>{t}</code>
                  ))}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
