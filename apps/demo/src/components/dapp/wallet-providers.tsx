"use client";

import {
  ConnectionProvider,
  WalletProvider,
} from "@solana/wallet-adapter-react";
import { WalletModalProvider } from "@solana/wallet-adapter-react-ui";
import { clusterApiUrl } from "@solana/web3.js";
import { useMemo } from "react";

import "@solana/wallet-adapter-react-ui/styles.css";

/**
 * DappProviders — Solana wallet-adapter context for the live `/dapp` flow.
 *
 * - `ConnectionProvider` exposes a `Connection` to all hooks. The RPC URL
 *   comes from `NEXT_PUBLIC_DEVNET_RPC_URL`, falling back to the public
 *   devnet endpoint.
 *
 *   SECURITY: `NEXT_PUBLIC_*` env vars are inlined into the public JS bundle
 *   at build time. NEVER set `NEXT_PUBLIC_DEVNET_RPC_URL` to a provider URL
 *   that contains an API key (e.g. `https://devnet.helius-rpc.com/?api-key=…`)
 *   — the key would be readable by every visitor. Use one of:
 *     a) A public, unauthenticated devnet endpoint (the default fallback).
 *     b) A server-side proxy that injects the key (recommended for prod).
 *   The server-side `DEMO_L1_RPC_URL` is fine to be a keyed URL because it
 *   is only used by API routes.
 *
 * - `WalletProvider` enables auto-discovery of any wallet that implements
 *   the Wallet Standard (Phantom, Solflare, Backpack, etc.).
 * - `WalletModalProvider` powers `<WalletMultiButton />`.
 */
export function DappProviders({ children }: { children: React.ReactNode }) {
  const endpoint = useMemo(() => {
    const fromEnv = process.env.NEXT_PUBLIC_DEVNET_RPC_URL;
    if (fromEnv && fromEnv.length > 0) {
      // Cheap dev-time guardrail: if someone has accidentally pasted a keyed
      // URL into the public env var, scream in the dev console so they catch
      // it before pushing to production. In prod builds, the warning still
      // fires but only the operator's first visit will see it.
      if (
        typeof window !== "undefined" &&
        /[?&](api[-_]?key|apikey)=/i.test(fromEnv)
      ) {
        // eslint-disable-next-line no-console
        console.warn(
          "[DappProviders] NEXT_PUBLIC_DEVNET_RPC_URL appears to contain an api-key query " +
            "parameter. NEXT_PUBLIC_* env vars are inlined into the public bundle. Move " +
            "the keyed URL to a server-only DEMO_L1_RPC_URL and proxy browser RPC traffic.",
        );
      }
      return fromEnv;
    }
    return clusterApiUrl("devnet");
  }, []);

  return (
    <ConnectionProvider endpoint={endpoint}>
      <WalletProvider wallets={[]} autoConnect>
        <WalletModalProvider>{children}</WalletModalProvider>
      </WalletProvider>
    </ConnectionProvider>
  );
}
