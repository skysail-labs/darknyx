"use client";

import { useConnection, useWallet } from "@solana/wallet-adapter-react";
import { WalletDisconnectButton, WalletMultiButton } from "@solana/wallet-adapter-react-ui";
import { LAMPORTS_PER_SOL } from "@solana/web3.js";
import { useEffect, useState } from "react";

import { NyxFooter } from "@/components/brand/nyx-footer";
import { NyxNav } from "@/components/brand/nyx-nav";
import { FlowModal } from "@/components/dapp/flow-modal";
import { AsciiHeroBanner } from "@/components/landing/ascii-hero-banner";
// import { ProverSmokeTestPanel } from "@/components/dapp/prover-smoke-test-panel";

export default function DappPage() {
  const { connection } = useConnection();
  const { publicKey, connected, connecting } = useWallet();

  const [solBalance, setSolBalance] = useState<number | null>(null);
  const [mounted, setMounted] = useState(false);
  const [modalOpen, setModalOpen] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  useEffect(() => {
    if (!publicKey) { setSolBalance(null); return; }
    let cancelled = false;
    void (async () => {
      try {
        const lamports = await connection.getBalance(publicKey, { commitment: "confirmed" });
        if (!cancelled) setSolBalance(lamports / LAMPORTS_PER_SOL);
      } catch {
        if (!cancelled) setSolBalance(null);
      }
    })();
    return () => { cancelled = true; };
  }, [publicKey, connection]);

  return (
    <div className="flex min-h-screen flex-1 flex-col bg-nyx-ink text-nyx-chalk">
      <NyxNav tone="ink" active="dapp" launchHref={null} />

      <main className="flex-1">
        {/* Header */}
        <section className="relative isolate border-b border-white/6">
          <div className="nyx-aurora" />
          <div className="nyx-grid absolute inset-0 -z-10 opacity-60" />
          <div className="mx-auto max-w-6xl px-5 py-10 sm:px-7 sm:py-12">
            <div className="flex flex-wrap items-start justify-between gap-5">
              <div className="max-w-2xl">
                <span className="font-mono text-[11px] uppercase tracking-[0.18em] text-nyx-fog">
                  Live dapp · devnet
                </span>
                <h1 className="nyx-display mt-2 text-[34px] leading-[1.05] sm:text-[42px] whitespace-nowrap">
                  Welcome to Darknyx
                </h1>
              </div>
              <div className="flex flex-col items-end gap-2">
                <div className="flex items-center gap-2">
                  {mounted ? (
                    <>
                      <WalletMultiButton />
                      {connected ? <WalletDisconnectButton /> : null}
                    </>
                  ) : (
                    <button
                      type="button"
                      disabled
                      className="rounded px-4 py-2 text-[11px] font-semibold uppercase tracking-[0.12em]"
                      style={{ fontFamily: "'JetBrains Mono', monospace", background: "rgba(217,104,32,0.08)", border: "1px solid rgba(217,104,32,0.2)", color: "rgba(217,104,32,0.4)" }}
                    >
                      Loading wallet…
                    </button>
                  )}
                </div>
                <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-nyx-slate">
                  {!mounted ? "initializing…"
                    : connecting ? "connecting…"
                      : connected ? "wallet connected"
                        : "not connected"}
                </span>
                {solBalance != null && (
                  <span className="font-mono text-[11px] uppercase tracking-[0.14em]" style={{ color: "rgba(217,104,32,0.7)" }}>
                    {solBalance.toFixed(4)} SOL
                  </span>
                )}
              </div>
            </div>
          </div>
        </section>

        {/* Cards */}
        <section className="mx-auto w-full max-w-6xl space-y-4 px-5 py-10 sm:px-7">

          {/* MAIN CARD — Enter the Darkpool */}
          <div
            className="relative overflow-hidden rounded-2xl border p-8"
            style={{
              borderColor: "rgba(217,104,32,0.22)",
              background: "#050505",
              boxShadow: "0 0 0 1px rgba(0,0,0,0.5), inset 0 1px 0 rgba(217,104,32,0.06)",
              marginTop: "-50px"
            }}
          >
            {/* Subtle grid bg */}
            <div className="nyx-grid pointer-events-none absolute inset-0 opacity-30" />

            {/* Top tag */}
            <div className="relative mb-6 flex items-center justify-between">
              <span
                className="inline-flex items-center gap-2 rounded-full px-3 py-1 text-[10px] uppercase tracking-[0.18em]"
                style={{
                  fontFamily: "'JetBrains Mono', monospace",
                  background: "rgba(217,104,32,0.1)",
                  border: "1px solid rgba(217,104,32,0.2)",
                  color: "#d96820",
                }}
              >
                Full flow · 3 steps
              </span>
              <span
                className="text-[10px] uppercase tracking-[0.14em]"
                style={{ fontFamily: "'JetBrains Mono', monospace", color: "rgba(107,107,116,0.5)" }}
              >
                devnet
              </span>
            </div>

            <div className="relative flex flex-col gap-12 lg:flex-row lg:items-center lg:gap-8">
              {/* Left — text + CTA */}
              <div className="flex-1 min-w-0">
                <div className="mb-8">
                  <h2 className="text-[28px] font-semibold leading-tight text-nyx-chalk sm:text-[34px]">
                    Enter the Darkpool
                  </h2>
                  <p className="mt-3 text-[13px] text-nyx-fog">
                    Register your order in the orderbook
                  </p>

                  {/* Step pills */}
                  <div className="mt-5 flex flex-wrap gap-2">
                    {[
                      { n: "01", label: "Derive identity" },
                      { n: "02", label: "Trade on devnet" },
                      { n: "03", label: "Private deposit / withdraw" },
                    ].map(({ n, label }) => (
                      <div
                        key={n}
                        className="flex items-center gap-2 rounded px-3 py-1.5 text-[11px]"
                        style={{
                          fontFamily: "'JetBrains Mono', monospace",
                          background: "rgba(255,255,255,0.03)",
                          border: "1px solid rgba(255,255,255,0.07)",
                          color: "#aeacb0",
                        }}
                      >
                        <span style={{ color: "rgba(217,104,32,0.7)" }}>{n}</span>
                        {label}
                      </div>
                    ))}
                  </div>
                </div>

                {/* CTA */}
                <div className="flex items-center gap-4">
                  <button
                    type="button"
                    onClick={() => setModalOpen(true)}
                    className="group relative overflow-hidden rounded px-6 py-3 text-[12px] font-semibold uppercase tracking-[0.14em] transition-all"
                    style={{
                      fontFamily: "'JetBrains Mono', monospace",
                      background: connected
                        ? "rgba(217,104,32,0.18)"
                        : "rgba(255,255,255,0.04)",
                      border: connected
                        ? "1px solid rgba(217,104,32,0.4)"
                        : "1px solid rgba(255,255,255,0.1)",
                      color: connected ? "#d96820" : "#6b6b74",
                    }}
                  >
                    {connected ? "Open notebook →" : "Connect wallet to start"}
                  </button>

                  {connected && (
                    <span
                      className="text-[11px]"
                      style={{
                        fontFamily: "'JetBrains Mono', monospace",
                        color: "rgba(107,107,116,0.5)",
                      }}
                    >
                      {publicKey?.toBase58().slice(0, 8)}…
                    </span>
                  )}
                </div>
              </div>

              {/* Right — ASCII banner */}
              <div className="w-full lg:w-96 shrink-0" style={{ marginTop: "-50px" }}>
                <AsciiHeroBanner contained />
              </div>
            </div>
          </div>

          {/* SMALL CARD — Smoke test (commented out, re-enable for ZK pipeline testing)
          <div
            className="relative overflow-hidden rounded-2xl border p-8"
            style={{
              borderColor: "rgba(217,104,32,0.22)",
              background: "linear-gradient(135deg, #0d0f12 0%, #0a0c0e 100%)",
              boxShadow: "0 0 0 1px rgba(0,0,0,0.5), inset 0 1px 0 rgba(217,104,32,0.06)",
            }}
          >
            <div className="nyx-grid pointer-events-none absolute inset-0 opacity-30" />
            <div className="relative mb-4 flex items-center justify-between">
              <span style={{ fontFamily: "'JetBrains Mono', monospace", background: "rgba(217,104,32,0.1)", border: "1px solid rgba(217,104,32,0.2)", color: "#d96820" }}
                className="inline-flex items-center gap-2 rounded-full px-3 py-1 text-[10px] uppercase tracking-[0.18em]">
                ZK prover · smoke test
              </span>
              <span className="text-[10px] uppercase tracking-[0.14em]"
                style={{ fontFamily: "'JetBrains Mono', monospace", color: "rgba(107,107,116,0.5)" }}>
                no wallet needed
              </span>
            </div>
            <div className="relative mb-5">
              <h2 className="text-[22px] font-semibold leading-tight text-nyx-chalk">Browser ZK prover</h2>
              <p className="mt-2 max-w-lg text-[13px] leading-relaxed text-nyx-fog">One click to confirm the ZK pipeline is wired up.</p>
            </div>
            <div className="relative"><ProverSmokeTestPanel compact /></div>
          </div>
          */}

        </section>
      </main>

      <NyxFooter tone="ink" />

      <FlowModal
        open={modalOpen}
        onClose={() => setModalOpen(false)}
      />
    </div>
  );
}
