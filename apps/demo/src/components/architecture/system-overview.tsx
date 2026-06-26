interface Layer {
  tag: string;
  cluster: "L1" | "ER" | "Client";
  title: string;
  body: string;
  techs: string[];
}

const LAYERS: Layer[] = [
  {
    tag: "01",
    cluster: "L1",
    title: "Custody, Merkle tree, ZK verifier",
    body: "Anchor 0.32 vault program holds the depth-20 incremental Poseidon Merkle tree, 32-root ring buffer, TEE pubkey, and protocol-fee config. Withdrawals go through an on-chain Groth16 verifier (alt_bn128 syscall). The matching engine program owns the per-market PDAs.",
    techs: ["vault", "matching_engine", "groth16-solana"],
  },
  {
    tag: "02",
    cluster: "ER",
    title: "Hidden order intent + matching",
    body: "MagicBlock Ephemeral Rollup hosts the delegated PendingOrder PDAs. submit_order is signed by the user's seed-derived trading key and lives only in the rollup. run_batch executes uniform-clearing-price match with a Pyth circuit breaker and writes BatchResults.",
    techs: ["PendingOrder", "submit_order", "run_batch"],
  },
  {
    tag: "03",
    cluster: "Client",
    title: "Key derivation, proofs, ix builders",
    body: "@nyx/sdk hand-codes every Anchor instruction (no IDL parser at runtime). snarkjs runs in a Web Worker for VALID_WALLET_CREATE and VALID_SPEND. Key chain: Phantom signature → master seed → spending / viewing / trading keys.",
    techs: ["@nyx/sdk", "snarkjs", "darkpool-crypto"],
  },
];

export function SystemOverview() {
  return (
    <section className="border-b border-white/[0.06] py-20">
      <div className="mx-auto max-w-6xl px-5 sm:px-7">
        <div className="max-w-2xl">
          <span className="nyx-eyebrow">01 · System overview</span>
          <h2 className="nyx-display mt-3 text-[32px] leading-tight sm:text-[40px]">
            Three trust boundaries.
          </h2>
        </div>

        <div className="mt-10 grid grid-cols-1 gap-4 lg:grid-cols-3">
          {LAYERS.map((l, idx) => (
            <article
              key={l.tag}
              className={`group rounded-md border border-white/[0.08] bg-nyx-graphite p-6 transition hover:border-white/20 nyx-rise nyx-rise-delay-${idx + 1}`}
            >
              <div className="flex items-center justify-between">
                <span className="font-mono text-[28px] leading-none text-nyx-chalk">
                  {l.tag}
                </span>
                <span
                  className={`rounded-sm border px-2 py-0.5 font-mono text-[10px] uppercase tracking-[0.16em] ${
                    l.cluster === "L1"
                      ? "border-nyx-signal-green/45 text-nyx-signal-green"
                      : l.cluster === "ER"
                        ? "border-nyx-accent/55 text-nyx-accent"
                        : "border-nyx-fog/40 text-nyx-fog"
                  }`}
                >
                  {l.cluster}
                </span>
              </div>
              <h3 className="mt-5 text-[18px] font-semibold leading-snug text-nyx-chalk">
                {l.title}
              </h3>
              <p className="mt-2 text-[13px] leading-relaxed text-nyx-fog">
                {l.body}
              </p>
              <div className="mt-5 flex flex-wrap gap-1.5">
                {l.techs.map((t) => (
                  <code
                    key={t}
                    className="rounded-sm border border-white/[0.08] bg-white/[0.03] px-2 py-1 font-mono text-[10.5px] text-nyx-fog"
                  >
                    {t}
                  </code>
                ))}
              </div>
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}
