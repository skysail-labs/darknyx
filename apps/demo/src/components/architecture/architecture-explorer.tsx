"use client";

import { useState } from "react";
import { SystemOverview } from "@/components/architecture/system-overview";
import { PrivacyTable } from "@/components/architecture/privacy-table";
import { TransactionFlow } from "@/components/architecture/transaction-flow";
import { CryptoPrimitives } from "@/components/architecture/crypto-primitives";
import { SecurityAndRoadmap } from "@/components/architecture/security-and-roadmap";

const SECTIONS = [
  {
    id: "system-overview",
    index: "01",
    title: "System Overview",
    sub: "3 layers · 2 clusters · 6 circuits",
    component: SystemOverview,
  },
  {
    id: "privacy-table",
    index: "02",
    title: "Privacy Boundary",
    sub: "What stays hidden on L1",
    component: PrivacyTable,
  },
  {
    id: "transaction-flow",
    index: "03",
    title: "Transaction Flow",
    sub: "10 transactions · 1 settlement path",
    component: TransactionFlow,
  },
  {
    id: "crypto-primitives",
    index: "04",
    title: "Crypto Primitives",
    sub: "Groth16 · Poseidon · BN254",
    component: CryptoPrimitives,
  },
  {
    id: "security-roadmap",
    index: "05",
    title: "Security & Roadmap",
    sub: "Protections + what's not yet shipped",
    component: SecurityAndRoadmap,
  },
] as const;

type SectionId = (typeof SECTIONS)[number]["id"];

export function ArchitectureExplorer({ onScrollUp }: { onScrollUp?: () => void }) {
  const [active, setActive] = useState<SectionId | null>(null);

  const activeIdx = active ? SECTIONS.findIndex((s) => s.id === active) : -1;
  const ActiveComponent = active ? SECTIONS[activeIdx].component : null;

  return (
    <section
      id="architecture-content"
      style={{
        height: "calc(100dvh - 40px)",
        display: "flex",
        flexDirection: "column",
        background: "#050506",
        borderBottom: "1px solid rgba(255,255,255,0.05)",
        overflow: "hidden",
      }}
    >
      {/* ── Section header bar ── */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "0 32px",
          height: "40px",
          borderBottom: "1px solid rgba(255,255,255,0.05)",
          flexShrink: 0,
        }}
      >
        {/* Left: back to menu or back to hero */}
        <div style={{ display: "flex", alignItems: "center", gap: "20px" }}>
          <button
            onClick={onScrollUp}
            style={{
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: "12px",
              letterSpacing: "0.2em",
              textTransform: "uppercase",
              color: "rgba(217,104,32,0.75)",
              background: "none",
              border: "none",
              cursor: "pointer",
              display: "flex",
              alignItems: "center",
              gap: "8px",
              padding: 0,
            }}
          >
            <svg width="8" height="12" viewBox="0 0 8 12" fill="none">
              <path d="M4 11V1m0 0L1 4M4 1l3 3" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
            hero
          </button>
          {active && (
            <button
              onClick={() => setActive(null)}
              style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: "9px",
                letterSpacing: "0.2em",
                textTransform: "uppercase",
                color: "rgba(217,104,32,0.7)",
                background: "none",
                border: "none",
                cursor: "pointer",
                display: "flex",
                alignItems: "center",
                gap: "8px",
                padding: 0,
              }}
            >
              <svg width="12" height="8" viewBox="0 0 12 8" fill="none">
                <path d="M11 4H1m0 0L4 1M1 4l3 3" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
              menu
            </button>
          )}
        </div>

        {/* Right: next section */}
        {active && activeIdx < SECTIONS.length - 1 ? (
          <button
            onClick={() => setActive(SECTIONS[activeIdx + 1].id)}
            style={{
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: "9px",
              letterSpacing: "0.2em",
              textTransform: "uppercase",
              color: "rgba(174,172,176,0.4)",
              background: "none",
              border: "none",
              cursor: "pointer",
              display: "flex",
              alignItems: "center",
              gap: "8px",
              padding: 0,
            }}
          >
            {SECTIONS[activeIdx + 1].title}
            <svg width="12" height="8" viewBox="0 0 12 8" fill="none">
              <path d="M1 4h10m0 0L8 1m3 3L8 7" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          </button>
        ) : active ? (
          <span style={{
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: "9px",
            letterSpacing: "0.2em",
            textTransform: "uppercase",
            color: "rgba(174,172,176,0.15)",
          }}>
            end
          </span>
        ) : null}
      </div>

      {/* ── Content area ── */}
      <div style={{ flex: 1, minHeight: 0, overflow: "hidden", display: "flex", flexDirection: "column" }}>
        {!active ? (
          /* MENU */
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(5, 1fr)",
              height: "100%",
            }}
          >
            {SECTIONS.map((s, idx) => (
              <button
                key={s.id}
                onClick={() => setActive(s.id)}
                style={{
                  display: "flex",
                  flexDirection: "column",
                  justifyContent: "space-between",
                  padding: "40px 32px",
                  background: "transparent",
                  border: "none",
                  borderRight: idx < SECTIONS.length - 1 ? "1px solid rgba(255,255,255,0.05)" : "none",
                  cursor: "pointer",
                  textAlign: "left",
                  transition: "background 0.15s",
                }}
                onMouseEnter={(e) => {
                  (e.currentTarget as HTMLButtonElement).style.background = "rgba(255,255,255,0.025)";
                }}
                onMouseLeave={(e) => {
                  (e.currentTarget as HTMLButtonElement).style.background = "transparent";
                }}
              >
                {/* Top: index */}
                <div style={{
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize: "11px",
                  letterSpacing: "0.1em",
                  color: "rgba(217,104,32,0.45)",
                }}>
                  {s.index}
                </div>

                {/* Middle: title */}
                <div>
                  <div style={{
                    fontFamily: "'JetBrains Mono', monospace",
                    fontSize: "clamp(14px, 1.4vw, 18px)",
                    fontWeight: 600,
                    letterSpacing: "-0.02em",
                    lineHeight: 1.2,
                    color: "rgba(245,243,238,0.85)",
                    marginBottom: "10px",
                  }}>
                    {s.title}
                  </div>
                  <div style={{
                    fontFamily: "'JetBrains Mono', monospace",
                    fontSize: "10px",
                    lineHeight: 1.6,
                    color: "rgba(174,172,176,0.3)",
                  }}>
                    {s.sub}
                  </div>
                </div>

                {/* Bottom: arrow */}
                <div style={{ display: "flex", justifyContent: "flex-end" }}>
                  <svg width="16" height="10" viewBox="0 0 16 10" fill="none">
                    <path d="M1 5h14m0 0L11 1m4 4-4 4" stroke="rgba(217,104,32,0.4)" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round" />
                  </svg>
                </div>
              </button>
            ))}
          </div>
        ) : (
          /* ACTIVE SECTION */
          ActiveComponent && <ActiveComponent />
        )}
      </div>
    </section>
  );
}
