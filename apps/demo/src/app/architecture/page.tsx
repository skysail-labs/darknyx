import type { Metadata } from "next";

import { ArchitecturePageShell } from "@/components/architecture/architecture-page-shell";
import { NyxNav } from "@/components/brand/nyx-nav";

export const metadata: Metadata = {
  title: "Nyx · architecture",
  description:
    "How the Nyx darkpool keeps order intent private without giving up on-chain auditability — three layers, two clusters, one verifiable settlement.",
};

export default function ArchitecturePage() {
  return (
    <div className="relative flex flex-col text-nyx-chalk" style={{ background: "#050506", height: "100dvh", overflow: "hidden" }}>
      <NyxNav tone="ink" active="architecture" launchHref="/dapp" />
      <ArchitecturePageShell />
    </div>
  );
}
