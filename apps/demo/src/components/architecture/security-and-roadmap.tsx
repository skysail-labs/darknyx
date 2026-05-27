const PROTECTS_AGAINST = [
  { title: "Front-running of unmatched orders", body: "Order intent arrives over RA-TLS into the TDX enclave; side, price, and amount never appear on L1." },
  { title: "Replay of TEE-signed settlements", body: "consumed_note PDAs lock both legs; a second identical settle collides at PDA allocation." },
  { title: "Withdrawals without ownership", body: "VALID_SPEND requires the spending key; nullifier PDAs prevent double-spend." },
  { title: "Conservation violations", body: "tee_forced_settle_batched enforces note.amount = trade + change + fee exactly before any state mutation." },
  { title: "TEE phantom-locking or mis-routing outputs", body: "VALID_INPUT gates every lock_note; VALID_MATCH_BATCH (N=16 Groth16) binds all output notes and clearing price for the entire batch." },
];

const NOT_YET = [
  { title: "On-chain TDX quote verification (v3)", body: "v2 uses admin multisig + dstack-verifier off-chain. On-chain dcap-qvl BPF port deferred to v3." },
  { title: "Real Phase-2 Groth16 trusted setup", body: "All circuits use a deterministic dev contribution; a real MPC ceremony with ≥3 contributors is required before mainnet." },
  { title: "Browser prover (WebProverSuite)", body: "Replace snarkjs shell-out with an in-process WASM prover for VALID_WALLET_CREATE + VALID_SPEND in the browser." },
  { title: "Light Protocol compressed nullifiers", body: "Replace NullifierEntry + ConsumedNoteEntry PDAs with compressed accounts — ~60× cheaper per settle at scale." },
  { title: "Real protocol-owner keypair for fee withdrawal", body: "Fee notes accumulate but can't be spent until a real protocol-owner key is wired in." },
];

export function SecurityAndRoadmap() {
  return (
    <div style={{ height: "100%", display: "flex", flexDirection: "column", overflow: "hidden" }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", borderBottom: "1px solid rgba(255,255,255,0.05)", flexShrink: 0 }}>
        <div style={{ padding: "8px 32px" }}>
          <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "9px", letterSpacing: "0.22em", textTransform: "uppercase", color: "rgba(217,104,32,0.8)" }}>
            05–06 · Security + Roadmap
          </span>
        </div>
      </div>

      {/* Body — two equal columns */}
      <div style={{ flex: 1, display: "flex", overflow: "hidden" }}>
        {/* Security */}
        <div style={{ flex: 1, borderRight: "1px solid rgba(255,255,255,0.04)", display: "flex", flexDirection: "column", overflow: "hidden" }}>
          <div style={{ padding: "20px 32px 12px", flexShrink: 0 }}>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "8.5px", letterSpacing: "0.18em", textTransform: "uppercase", color: "rgba(174,172,176,0.3)" }}>05 · Security model</div>
            <h2 style={{ marginTop: "8px", fontFamily: "'JetBrains Mono', monospace", fontSize: "clamp(14px, 1.4vw, 20px)", fontWeight: 600, lineHeight: 1.05, letterSpacing: "-0.025em", color: "rgba(245,243,238,0.9)" }}>
              What the system protects against.
            </h2>
          </div>
          <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
            {PROTECTS_AGAINST.map((item, idx) => (
              <div key={item.title} style={{ flex: 1, display: "flex", alignItems: "center", gap: "16px", padding: "0 32px", borderTop: "1px solid rgba(255,255,255,0.04)" }}>
                <svg width="14" height="14" viewBox="0 0 14 14" fill="none" style={{ flexShrink: 0 }}>
                  <circle cx="7" cy="7" r="6" stroke="rgba(95,184,95,0.35)" strokeWidth="0.8" />
                  <path d="M4 7l2 2 4-4" stroke="rgba(95,184,95,0.7)" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
                <div>
                  <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "11.5px", fontWeight: 600, color: "rgba(245,243,238,0.78)", lineHeight: 1.3 }}>{item.title}</div>
                  <div style={{ marginTop: "4px", fontFamily: "'JetBrains Mono', monospace", fontSize: "10.5px", lineHeight: 1.65, color: "rgba(174,172,176,0.4)" }}>{item.body}</div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Roadmap */}
        <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
          <div style={{ padding: "20px 32px 12px", flexShrink: 0 }}>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "8.5px", letterSpacing: "0.18em", textTransform: "uppercase", color: "rgba(174,172,176,0.3)" }}>06 · Roadmap</div>
            <h2 style={{ marginTop: "8px", fontFamily: "'JetBrains Mono', monospace", fontSize: "clamp(14px, 1.4vw, 20px)", fontWeight: 600, lineHeight: 1.05, letterSpacing: "-0.025em", color: "rgba(245,243,238,0.9)" }}>
              What is <span style={{ color: "rgba(174,172,176,0.3)" }}>not</span> yet shipped.
            </h2>
          </div>
          <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
            {NOT_YET.map((item, idx) => (
              <div key={item.title} style={{ flex: 1, display: "flex", alignItems: "center", gap: "16px", padding: "0 32px", borderTop: "1px solid rgba(255,255,255,0.04)" }}>
                <div style={{ flexShrink: 0, fontFamily: "'JetBrains Mono', monospace", fontSize: "9px", letterSpacing: "0.12em", color: "rgba(174,172,176,0.18)", minWidth: "20px" }}>{String(idx + 1).padStart(2, "0")}</div>
                <div>
                  <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "11.5px", fontWeight: 600, color: "rgba(245,243,238,0.6)", lineHeight: 1.3 }}>{item.title}</div>
                  <div style={{ marginTop: "4px", fontFamily: "'JetBrains Mono', monospace", fontSize: "10.5px", lineHeight: 1.65, color: "rgba(174,172,176,0.35)" }}>{item.body}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
