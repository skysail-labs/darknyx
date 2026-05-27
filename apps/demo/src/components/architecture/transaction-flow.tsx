interface FlowRow {
  step: string;
  cluster: "L1" | "TEE";
  ix: string;
  signer: string;
  privacy: string;
}

const FLOW: FlowRow[] = [
  { step: "01", cluster: "L1", ix: "vault::create_wallet", signer: "user payer", privacy: "links user_commitment to a Solana payer; identity-only" },
  { step: "02", cluster: "L1", ix: "vault::deposit", signer: "user payer", privacy: "reveals deposit amount + mint (SPL transfer)" },
  { step: "03", cluster: "L1", ix: "vault::lock_note (VALID_INPUT)", signer: "user trading_key", privacy: "commits to note being tradeable; no amount revealed" },
  { step: "04", cluster: "TEE", ix: "POST /order (RA-TLS)", signer: "user trading_key", privacy: "HIDDEN — side, price, amount encrypted inside TDX enclave" },
  { step: "05", cluster: "TEE", ix: "batch auction (in-enclave)", signer: "TEE / operator", privacy: "uniform-clearing-price matching, every 2 s, never leaves enclave" },
  { step: "06", cluster: "TEE", ix: "VALID_MATCH_BATCH proof (in-enclave)", signer: "TEE prover", privacy: "Groth16 proof over N=16 match slots; batch Merkle root sealed" },
  { step: "07", cluster: "L1", ix: "vault::verify_match_batch", signer: "TEE", privacy: "on-chain Groth16 verifier; creates BatchValidityMarker PDA" },
  { step: "08a", cluster: "L1", ix: "vault::lock_note (×2, per-match)", signer: "TEE", privacy: "pins note_a + note_b against double-spend before settle" },
  { step: "08b", cluster: "L1", ix: "Ed25519 + vault::tee_forced_settle_batched", signer: "TEE", privacy: "atomic note_a/b consume → note_c/d/fee append to Merkle tree" },
  { step: "09", cluster: "L1", ix: "vault::withdraw (VALID_SPEND)", signer: "recipient", privacy: "spends a note, reveals amount + mint + recipient ATA" },
];

export function TransactionFlow() {
  return (
    <div style={{ height: "100%", display: "flex", flexDirection: "column", overflow: "hidden" }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", borderBottom: "1px solid rgba(255,255,255,0.05)", flexShrink: 0 }}>
        <div style={{ padding: "8px 32px", borderRight: "1px solid rgba(255,255,255,0.05)" }}>
          <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "9px", letterSpacing: "0.22em", textTransform: "uppercase", color: "rgba(217,104,32,0.8)" }}>
            03 · End-to-end flow
          </span>
        </div>
        {[["9 transactions"], ["2 clusters"], ["1 settlement path"]].map(([t]) => (
          <div key={t} style={{ padding: "8px 16px", borderRight: "1px solid rgba(255,255,255,0.04)" }}>
            <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "9px", letterSpacing: "0.14em", textTransform: "uppercase", color: "rgba(174,172,176,0.22)" }}>{t}</span>
          </div>
        ))}
      </div>

      {/* Body */}
      <div style={{ flex: 1, display: "flex", overflow: "hidden" }}>
        {/* Left rail */}
        <div style={{ width: "200px", flexShrink: 0, borderRight: "1px solid rgba(255,255,255,0.05)", padding: "28px 28px", display: "flex", flexDirection: "column", justifyContent: "space-between" }}>
          <div>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "clamp(48px, 6vw, 80px)", fontWeight: 700, lineHeight: 0.88, letterSpacing: "-0.05em", color: "rgba(255,255,255,0.04)", userSelect: "none" }}>09</div>
            <h2 style={{ marginTop: "14px", fontFamily: "'JetBrains Mono', monospace", fontSize: "clamp(13px, 1.3vw, 17px)", fontWeight: 600, lineHeight: 1.15, letterSpacing: "-0.025em", color: "rgba(245,243,238,0.88)" }}>
              One trade.<br />Nine steps.
            </h2>
            <p style={{ marginTop: "8px", fontFamily: "'JetBrains Mono', monospace", fontSize: "10.5px", lineHeight: 1.75, color: "rgba(174,172,176,0.4)" }}>
              Steps 04–06 never touch L1. The enclave is the only place order intent lives.
            </p>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
            {[
              { color: "rgba(95,184,95,0.45)", label: "L1 — Solana", text: "rgba(95,184,95,0.6)" },
              { color: "rgba(217,104,32,0.45)", label: "TEE — Intel TDX", text: "rgba(217,104,32,0.6)" },
            ].map((l) => (
              <div key={l.label} style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <div style={{ height: "1px", width: "20px", background: l.color }} />
                <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "9px", letterSpacing: "0.14em", textTransform: "uppercase", color: l.text }}>{l.label}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Table */}
        <div style={{ flex: 1, overflow: "hidden", display: "flex", flexDirection: "column" }}>
          {/* Table header */}
          <div style={{ display: "grid", gridTemplateColumns: "44px 60px 1fr 120px 1fr", background: "rgba(255,255,255,0.015)", borderBottom: "1px solid rgba(255,255,255,0.05)", flexShrink: 0 }}>
            {["#", "Cluster", "Instruction", "Signer", "Privacy property"].map((h) => (
              <div key={h} style={{ padding: "7px 14px", fontFamily: "'JetBrains Mono', monospace", fontSize: "8px", letterSpacing: "0.18em", textTransform: "uppercase", color: "rgba(174,172,176,0.3)" }}>{h}</div>
            ))}
          </div>
          {/* Rows */}
          <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
            {FLOW.map((row, idx) => (
              <div key={row.step} style={{ flex: 1, display: "grid", gridTemplateColumns: "44px 60px 1fr 120px 1fr", borderTop: idx > 0 ? "1px solid rgba(255,255,255,0.04)" : "none", borderBottom: idx === FLOW.length - 1 ? "1px solid rgba(255,255,255,0.04)" : "none", background: row.cluster === "TEE" ? "rgba(217,104,32,0.02)" : "transparent", alignItems: "center" }}>
                <div style={{ padding: "0 14px", fontFamily: "'JetBrains Mono', monospace", fontSize: "10px", color: "rgba(255,255,255,0.18)", fontWeight: 600 }}>{row.step}</div>
                <div style={{ padding: "0 14px" }}>
                  <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "8px", letterSpacing: "0.12em", textTransform: "uppercase", padding: "2px 5px", border: `1px solid ${row.cluster === "L1" ? "rgba(95,184,95,0.35)" : "rgba(217,104,32,0.4)"}`, color: row.cluster === "L1" ? "rgba(95,184,95,0.8)" : "#d96820", borderRadius: "2px" }}>{row.cluster}</span>
                </div>
                <div style={{ padding: "0 14px" }}>
                  <code style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "10.5px", color: "rgba(245,243,238,0.72)" }}>{row.ix}</code>
                </div>
                <div style={{ padding: "0 14px", fontFamily: "'JetBrains Mono', monospace", fontSize: "10px", color: "rgba(174,172,176,0.4)" }}>{row.signer}</div>
                <div style={{ padding: "0 14px", fontFamily: "'JetBrains Mono', monospace", fontSize: "10px", color: row.privacy.startsWith("HIDDEN") ? "rgba(217,104,32,0.75)" : "rgba(174,172,176,0.4)", lineHeight: 1.4 }}>{row.privacy}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
