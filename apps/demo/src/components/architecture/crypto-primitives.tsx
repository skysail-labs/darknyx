interface Primitive {
  primitive: string;
  choice: string;
  where: string;
}

const PRIMITIVES: Primitive[] = [
  {
    primitive: "Curve",
    choice: "BN254 (alt_bn128)",
    where: "Groth16 verifier on-chain · snarkjs prover off-chain",
  },
  {
    primitive: "Hash · in-circuit",
    choice: "Poseidon2 / BN254 Fr",
    where: "Note commitments · nullifiers · Merkle · user commitments",
  },
  {
    primitive: "Hash · ambient",
    choice: "SHA-256 · SHA3",
    where: "Inclusion commitment · key derivation · payload hash",
  },
  {
    primitive: "Signature",
    choice: "Ed25519 (Solana precompile)",
    where: "TEE attestation in tee_forced_settle",
  },
  {
    primitive: "ZK proof system",
    choice: "Groth16",
    where: "VALID_WALLET_CREATE · VALID_SPEND",
  },
  {
    primitive: "Merkle tree",
    choice: "Incremental Poseidon · depth 20",
    where: "vault::merkle.rs · 32-root ring buffer",
  },
];

export function CryptoPrimitives() {
  return (
    <section className="border-b border-white/[0.06] bg-nyx-graphite-2/40 py-20">
      <div className="mx-auto max-w-6xl px-5 sm:px-7">
        <div className="max-w-2xl">
          <span className="nyx-eyebrow">04 · Cryptographic primitives</span>
          <h2 className="nyx-display mt-3 text-[32px] leading-tight sm:text-[40px]">
            Every choice is boring on purpose.
          </h2>
          <p className="mt-3 text-[14px] text-nyx-fog">
            Standard, well-audited primitives only. The on-chain Groth16
            verifier is{" "}
            <code className="font-mono text-nyx-chalk">groth16-solana</code>{" "}
            v0.2.0; the Poseidon implementation is light-protocol&apos;s
            reference (BN254 Fr).
          </p>
        </div>

        <div className="mt-10 grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {PRIMITIVES.map((p) => (
            <article
              key={p.primitive}
              className="rounded-md border border-white/[0.08] bg-nyx-graphite p-5"
            >
              <div className="nyx-eyebrow">{p.primitive}</div>
              <div className="mt-3 font-mono text-[14px] text-nyx-chalk">
                {p.choice}
              </div>
              <div className="mt-2 text-[12.5px] text-nyx-fog">{p.where}</div>
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}
