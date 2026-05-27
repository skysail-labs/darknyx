const GROUPS = [
  {
    label: "Cryptography",
    color: "#d96820",
    items: [
      { name: "Groth16 / BN254",          detail: "ZK proof system · VALID_WALLET_CREATE · VALID_SPEND · VALID_MATCH_BATCH" },
      { name: "Poseidon2",                 detail: "In-circuit hash · note commitments · nullifiers · depth-20 Merkle tree" },
      { name: "SHA-256 · SHA3",            detail: "Key derivation · canonical payload hash · inclusion commitment" },
      { name: "Ed25519 precompile",        detail: "TEE attestation signature · Solana native · tee_forced_settle_batched" },
    ],
  },
  {
    label: "Infrastructure",
    color: "rgba(95,184,95,0.85)",
    items: [
      { name: "Solana · Anchor 0.32",      detail: "L1 custody · on-chain Groth16 verifier · vault + matching_engine programs" },
      { name: "Intel TDX · Phala Cloud",   detail: "Attested enclave · RA-TLS order intake · in-enclave matching · batch proof generation" },
      { name: "dstack · admin multisig",   detail: "TEE pubkey rotation · custom domain via dstack-ingress · Phala Cloud hosting" },
    ],
  },
  {
    label: "SDK + Tooling",
    color: "rgba(174,172,176,0.6)",
    items: [
      { name: "@nyx/sdk",                  detail: "No-Anchor-runtime client · hand-coded discriminators · Borsh ix builders" },
      { name: "snarkjs",                   detail: "Browser-side prover · runs in Web Worker · VALID_WALLET_CREATE · VALID_SPEND" },
      { name: "darkpool-crypto (Rust)",    detail: "Host-side Poseidon · key derivation · byte-identical parity with TS SDK" },
    ],
  },
];

export function CryptoPrimitives() {
  return (
    <div style={{ height: "100%", display: "flex", flexDirection: "column", overflow: "hidden" }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", borderBottom: "1px solid rgba(255,255,255,0.05)", flexShrink: 0 }}>
        <div style={{ padding: "8px 32px", borderRight: "1px solid rgba(255,255,255,0.05)" }}>
          <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "9px", letterSpacing: "0.22em", textTransform: "uppercase", color: "rgba(217,104,32,0.8)" }}>
            04 · Crypto primitives + tech stack
          </span>
        </div>
        <div style={{ padding: "8px 24px" }}>
          <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "9px", letterSpacing: "0.14em", textTransform: "uppercase", color: "rgba(174,172,176,0.22)" }}>
            Standard + audited · no novel cryptography
          </span>
        </div>
      </div>

      {/* Body */}
      <div style={{ flex: 1, display: "flex", overflow: "hidden" }}>
        {/* Left rail */}
        <div style={{ width: "200px", flexShrink: 0, borderRight: "1px solid rgba(255,255,255,0.05)", padding: "32px 28px", display: "flex", flexDirection: "column", justifyContent: "center", gap: "12px" }}>
          <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "clamp(40px, 5vw, 68px)", fontWeight: 700, lineHeight: 0.88, letterSpacing: "-0.045em", color: "rgba(255,255,255,0.04)", userSelect: "none" }}>04</div>
          <h2 style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "clamp(13px, 1.3vw, 17px)", fontWeight: 600, lineHeight: 1.1, letterSpacing: "-0.025em", color: "rgba(245,243,238,0.9)" }}>
            Every choice<br />is boring<br />on purpose.
          </h2>
          <p style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "10px", lineHeight: 1.75, color: "rgba(174,172,176,0.38)" }}>
            No novel cryptography.<br />All primitives audited<br />and battle-tested.
          </p>
        </div>

        {/* Three group columns */}
        <div style={{ flex: 1, display: "flex", overflow: "hidden" }}>
          {GROUPS.map((g, gi) => (
            <div key={g.label} style={{
              flex: 1,
              borderLeft: gi > 0 ? "1px solid rgba(255,255,255,0.04)" : "none",
              display: "flex",
              flexDirection: "column",
              overflow: "hidden",
            }}>
              {/* group label */}
              <div style={{ padding: "14px 24px", borderBottom: "1px solid rgba(255,255,255,0.04)", flexShrink: 0 }}>
                <div style={{ display: "inline-flex", alignItems: "center", gap: "7px" }}>
                  <div style={{ width: "5px", height: "5px", borderRadius: "50%", background: g.color }} />
                  <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "8.5px", letterSpacing: "0.2em", textTransform: "uppercase", color: g.color }}>
                    {g.label}
                  </span>
                </div>
              </div>

              {/* items */}
              <div style={{ flex: 1, display: "flex", flexDirection: "column" }}>
                {g.items.map((item, ii) => (
                  <div key={item.name} style={{
                    flex: 1,
                    padding: "0 24px",
                    borderTop: ii > 0 ? "1px solid rgba(255,255,255,0.04)" : "none",
                    borderBottom: ii === g.items.length - 1 ? "1px solid rgba(255,255,255,0.04)" : "none",
                    display: "flex",
                    flexDirection: "column",
                    justifyContent: "center",
                    gap: "5px",
                  }}>
                    <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "12px", fontWeight: 600, color: "rgba(245,243,238,0.82)", letterSpacing: "-0.01em" }}>
                      {item.name}
                    </div>
                    <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "9.5px", lineHeight: 1.6, color: "rgba(174,172,176,0.38)" }}>
                      {item.detail}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
