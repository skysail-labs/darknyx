interface Row {
  object: string;
  l1Visible: boolean;
  notes: string;
}

const ROWS: Row[] = [
  { object: "Order side / price / amount", l1Visible: false, notes: "Stays in the TEE until run_batch matches" },
  { object: "Order's collateral note commitment", l1Visible: false, notes: "Same — only inside the TEE enclave" },
  { object: "User's trading-key signature on submit_order", l1Visible: false, notes: "The whole submit tx lives in the TEE" },
  { object: "note_commitment of the deposit note", l1Visible: true, notes: "Public on vault::deposit (always was)" },
  { object: "Deposit amount / mint", l1Visible: true, notes: "SPL transfer is on L1" },
  { object: "Match clearing price + matched volume", l1Visible: true, notes: "Surfaces in BatchResults after commit" },
  { object: "Settlement note commitments (note_c, note_d, note_fee)", l1Visible: true, notes: "TEE appends them in tee_forced_settle_batched" },
  { object: "Withdrawal amount + recipient ATA", l1Visible: true, notes: "SPL transfer-out is on L1" },
];

export function PrivacyTable() {
  return (
    <div style={{ height: "100%", display: "flex", flexDirection: "column", overflow: "hidden" }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", borderBottom: "1px solid rgba(255,255,255,0.05)", flexShrink: 0 }}>
        <div style={{ padding: "8px 32px", borderRight: "1px solid rgba(255,255,255,0.05)" }}>
          <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "9px", letterSpacing: "0.22em", textTransform: "uppercase", color: "rgba(217,104,32,0.8)" }}>
            02 · Privacy boundary
          </span>
        </div>
      </div>

      {/* Body */}
      <div style={{ flex: 1, display: "flex", overflow: "hidden" }}>
        {/* Left rail */}
        <div style={{ width: "220px", flexShrink: 0, borderRight: "1px solid rgba(255,255,255,0.05)", padding: "32px", display: "flex", flexDirection: "column", justifyContent: "space-between" }}>
          <div>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "clamp(48px, 6vw, 80px)", fontWeight: 700, lineHeight: 0.88, letterSpacing: "-0.045em", color: "rgba(255,255,255,0.04)", userSelect: "none" }}>02</div>
            <h2 style={{ marginTop: "14px", fontFamily: "'JetBrains Mono', monospace", fontSize: "clamp(14px, 1.4vw, 18px)", fontWeight: 600, lineHeight: 1.1, letterSpacing: "-0.025em", color: "rgba(245,243,238,0.9)" }}>
              What stays<br />hidden.
            </h2>
            <p style={{ marginTop: "10px", fontFamily: "'JetBrains Mono', monospace", fontSize: "11px", lineHeight: 1.75, color: "rgba(174,172,176,0.42)" }}>
              Nyx hides individual order intent. Aggregate match data is public — by design.
            </p>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
            {[
              { dot: "rgba(95,184,95,0.6)", color: "rgba(95,184,95,0.55)", label: "Hidden" },
              { dot: "rgba(217,163,65,0.6)", color: "rgba(217,163,65,0.55)", label: "Public on L1" },
            ].map((l) => (
              <div key={l.label} style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <div style={{ width: "6px", height: "6px", borderRadius: "50%", background: l.dot, flexShrink: 0 }} />
                <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "9px", letterSpacing: "0.16em", textTransform: "uppercase", color: l.color }}>{l.label}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Table */}
        <div style={{ flex: 1, overflow: "hidden", display: "flex", flexDirection: "column" }}>
          {/* Table header */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 100px 1fr", borderBottom: "1px solid rgba(255,255,255,0.05)", background: "rgba(255,255,255,0.015)", flexShrink: 0 }}>
            {["Object", "L1 visible?", "Notes"].map((h) => (
              <div key={h} style={{ padding: "8px 20px", fontFamily: "'JetBrains Mono', monospace", fontSize: "8.5px", letterSpacing: "0.18em", textTransform: "uppercase", color: "rgba(174,172,176,0.3)" }}>{h}</div>
            ))}
          </div>
          {/* Rows — flex so they fill height evenly */}
          <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
            {ROWS.map((r, idx) => (
              <div key={r.object} style={{ flex: 1, display: "grid", gridTemplateColumns: "1fr 100px 1fr", borderTop: idx > 0 ? "1px solid rgba(255,255,255,0.04)" : "none", borderBottom: idx === ROWS.length - 1 ? "1px solid rgba(255,255,255,0.04)" : "none", alignItems: "stretch" }}>
                <div style={{ padding: "0 20px", fontFamily: "'JetBrains Mono', monospace", fontSize: "11px", color: "rgba(245,243,238,0.7)", lineHeight: 1.4, display: "flex", alignItems: "center" }}>{r.object}</div>
                <div style={{ padding: "0 20px", display: "flex", alignItems: "center" }}>
                  {r.l1Visible ? (
                    <span style={{ display: "inline-flex", alignItems: "center", gap: "5px", fontFamily: "'JetBrains Mono', monospace", fontSize: "8px", letterSpacing: "0.12em", textTransform: "uppercase", padding: "2px 6px", border: "1px solid rgba(217,163,65,0.35)", background: "rgba(217,163,65,0.05)", color: "rgba(217,163,65,0.8)", borderRadius: "2px", whiteSpace: "nowrap" }}>
                      <span style={{ width: "4px", height: "4px", borderRadius: "50%", background: "rgba(217,163,65,0.7)", flexShrink: 0 }} />Public
                    </span>
                  ) : (
                    <span style={{ display: "inline-flex", alignItems: "center", gap: "5px", fontFamily: "'JetBrains Mono', monospace", fontSize: "8px", letterSpacing: "0.12em", textTransform: "uppercase", padding: "2px 6px", border: "1px solid rgba(95,184,95,0.3)", background: "rgba(95,184,95,0.04)", color: "rgba(95,184,95,0.75)", borderRadius: "2px", whiteSpace: "nowrap" }}>
                      <span style={{ width: "4px", height: "4px", borderRadius: "50%", background: "rgba(95,184,95,0.65)", flexShrink: 0 }} />Hidden
                    </span>
                  )}
                </div>
                <div style={{ padding: "0 20px", fontFamily: "'JetBrains Mono', monospace", fontSize: "10.5px", lineHeight: 1.6, color: "rgba(174,172,176,0.4)", display: "flex", alignItems: "center" }}>{r.notes}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
