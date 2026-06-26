export function ArchitectureHero() {
  return (
    <section className="relative isolate overflow-hidden border-b border-white/[0.06]">
      <div className="nyx-aurora" />
      <div className="nyx-grid absolute inset-0 -z-10 opacity-60" />
      <div className="mx-auto max-w-6xl px-5 pt-24 pb-16 sm:px-7 sm:pt-28">
        <span className="nyx-eyebrow nyx-rise">Architecture</span>
        <h1 className="nyx-rise nyx-rise-delay-1 nyx-display mt-4 max-w-4xl text-[42px] leading-[1.04] sm:text-[64px]">
          <span className="text-nyx-chalk">Three layers.</span>{" "}
          <span className="text-nyx-fog">Two clusters.</span>{" "}
          <span className="text-nyx-chalk">One verifiable settlement.</span>
        </h1>
        <p className="nyx-rise nyx-rise-delay-2 mt-5 max-w-2xl text-[15px] text-nyx-fog">
          A condensed tour of how Nyx keeps order intent private without giving
          up on-chain auditability. Source-of-truth lives in{" "}
          <a
            className="text-nyx-chalk underline decoration-nyx-fog/40 underline-offset-4 hover:decoration-nyx-chalk"
            href="https://github.com/skysail-labs/darknyx/blob/main/docs/ARCHITECTURE.md"
          >
            <code className="font-mono text-[13px]">docs/ARCHITECTURE.md</code>
          </a>{" "}
          ,this page is the visual map.
        </p>
      </div>
    </section>
  );
}
