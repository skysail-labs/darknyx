import { NyxFooter } from "@/components/brand/nyx-footer";
import { NyxNav } from "@/components/brand/nyx-nav";
import { CtaSection } from "@/components/landing/cta-section";
import { FeatureGrid } from "@/components/landing/feature-grid";
import { FlowDiagram } from "@/components/landing/flow-diagram";
import { LandingHero } from "@/components/landing/hero";
export default function Home() {
  return (
    <div className="nyx-pixel-grid flex min-h-screen flex-1 flex-col text-nyx-chalk" style={{ background: "#050608" }}>
      <NyxNav tone="ink" active="home" launchHref="/dapp" />
      <main className="flex-1">
        <LandingHero />
        <FeatureGrid />
        <FlowDiagram />
        <CtaSection />
      </main>
      <NyxFooter tone="ink" />
    </div>
  );
}
