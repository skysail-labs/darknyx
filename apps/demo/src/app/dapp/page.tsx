"use client";

import { useConnection, useWallet } from "@solana/wallet-adapter-react";
import {
  WalletDisconnectButton,
  WalletMultiButton,
} from "@solana/wallet-adapter-react-ui";
import { LAMPORTS_PER_SOL } from "@solana/web3.js";
import { useEffect, useState } from "react";

import { NyxFooter } from "@/components/brand/nyx-footer";
import { NyxNav } from "@/components/brand/nyx-nav";
import { ProverSmokeTestPanel } from "@/components/dapp/prover-smoke-test-panel";
import { DappTradeFlowPanel } from "@/components/dapp/dapp-trade-flow-panel";
import { PrivateDepositWithdrawPanel } from "@/components/dapp/private-deposit-withdraw-panel";
// TODO(post-trade BASE withdraw): re-enable once we have an indexer (or in-process
// snapshot) so the VALID_SPEND witness is stable on a busy devnet. Today the
// Merkle reconstruction races other vault txs and the "Merkle witness root !=
// on-chain current_root" check fails. Component file is preserved verbatim.
// import { TradeBaseWithdrawPanel } from "@/components/dapp/trade-base-withdraw-panel";
import { WalletIdentityPanel } from "@/components/dapp/wallet-identity-panel";

export default function DappPage() {
  const { connection } = useConnection();
  const { publicKey, connected, connecting } = useWallet();

  const [solBalance, setSolBalance] = useState<number | null>(null);
  // `WalletMultiButton` from @solana/wallet-adapter-react-ui ships different
  // DOM on server vs. client (the `<i>` icon is added post-mount), causing a
  // React hydration warning. Defer rendering until after the first client
  // pass to silence it cleanly without disabling SSR for the whole route.
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setMounted(true);
  }, []);

  useEffect(() => {
    if (!publicKey) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setSolBalance(null);
      return;
    }
    let cancelled = false;
    void (async () => {
      try {
        const lamports = await connection.getBalance(publicKey, {
          commitment: "confirmed",
        });
        if (!cancelled) setSolBalance(lamports / LAMPORTS_PER_SOL);
      } catch {
        if (!cancelled) setSolBalance(null);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [publicKey, connection]);

  return (
    <div className="flex min-h-screen flex-1 flex-col bg-nyx-ink text-nyx-chalk">
      <NyxNav tone="ink" active="dapp" launchHref={null} />

      <main className="flex-1">
        {/* Banner header — branded, slim, with status pills */}
        <section className="relative isolate overflow-hidden border-b border-white/[0.06]">
          <div className="nyx-aurora" />
          <div className="nyx-grid absolute inset-0 -z-10 opacity-60" />
          <div className="mx-auto max-w-6xl px-5 py-10 sm:px-7 sm:py-12">
            <div className="flex flex-wrap items-start justify-between gap-5">
              <div className="max-w-2xl">
                <span className="font-mono text-[11px] uppercase tracking-[0.18em] text-nyx-fog">
                  Live dapp · devnet
                </span>
                <h1 className="nyx-display mt-2 text-[34px] leading-[1.05] sm:text-[42px]">
                  Connect, deposit, trade — privately.
                </h1>
                <p className="mt-3 max-w-xl text-[14px] text-nyx-fog">
                  Phantom wallet on Solana devnet. Derive darkpool keys, airdrop
                  test tokens, deposit shielded notes, place an ER-private
                  order, and finally withdraw your fill — every step gives you
                  an explorer link.
                </p>
                <div className="mt-5 max-w-[220px]">
                  <StatusPill
                    label="balance"
                    value={
                      solBalance == null ? "—" : `${solBalance.toFixed(4)} SOL`
                    }
                    mono
                  />
                </div>
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
                      className="rounded-md border border-white/10 bg-white/5 px-4 py-2 text-[12px] font-semibold uppercase tracking-[0.12em] text-nyx-fog"
                    >
                      Loading wallet…
                    </button>
                  )}
                </div>
                <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-nyx-fog">
                  {!mounted
                    ? "initializing…"
                    : connecting
                      ? "connecting…"
                      : connected
                        ? "wallet connected"
                        : "wallet not connected"}
                </span>
              </div>
            </div>
          </div>
        </section>

        {/* Panels — kept as-is to preserve their working internals */}
        <section className="mx-auto w-full max-w-6xl space-y-6 px-5 py-10 sm:px-7">
          {connected ? (
            <>
              <WalletIdentityPanel />
              <DappTradeFlowPanel />
              <PrivateDepositWithdrawPanel />
              {/* <TradeBaseWithdrawPanel /> — temporarily hidden, see import comment above. */}
            </>
          ) : null}

          <ProverSmokeTestPanel />

          {!connected ? (
            <section className="rounded-md border border-dashed border-white/12 bg-white/[0.03] p-6 text-[13px] text-nyx-fog">
              <h2 className="text-[16px] font-semibold text-nyx-chalk">
                Get started
              </h2>
              <p className="mt-2">
                This page only works on Solana{" "}
                <span className="font-semibold">devnet</span>. Switch your
                Phantom wallet to devnet, then click <em>Select Wallet</em>{" "}
                above. Once connected we&rsquo;ll guide you through the full
                deposit → trade → withdraw flow.
              </p>
              <ol className="mt-3 list-inside list-decimal space-y-1 text-nyx-chalk/85">
                <li>Connect a Phantom wallet on devnet.</li>
                <li>
                  Sign a fixed message — your darkpool keys are derived from
                  that signature alone.
                </li>
                <li>
                  Register your Poseidon wallet commitment on-chain (verified
                  with a Groth16 proof).
                </li>
                <li>Get a small airdrop of demo BASE + QUOTE tokens.</li>
                <li>
                  Deposit into the shielded pool and place an encrypted bid on
                  the Ephemeral Rollup.
                </li>
                <li>
                  A counterparty fills it; settlement writes shielded buyer /
                  seller notes back to L1.
                </li>
              </ol>
            </section>
          ) : null}
        </section>
      </main>

      <NyxFooter tone="ink" />
    </div>
  );
}

function StatusPill({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: React.ReactNode;
  mono?: boolean;
}) {
  return (
    <div className="rounded-md border border-white/[0.08] bg-white/[0.04] px-3 py-2 backdrop-blur-sm">
      <div className="font-mono text-[10px] uppercase tracking-[0.16em] text-nyx-fog">
        {label}
      </div>
      <div
        className={`mt-1 truncate text-[13px] text-nyx-chalk ${mono ? "font-mono" : ""}`}
      >
        {value}
      </div>
    </div>
  );
}
