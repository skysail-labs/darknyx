interface Pill {
  label: string;
  detail: string;
}

const STACK: Pill[] = [
  { label: "Solana", detail: "L1 custody + ZK verifier" },
  { label: "Anchor 0.32", detail: "vault + matching engine" },
  { label: "TEE", detail: "delegated order PDAs" },
  { label: "Groth16 / BN254", detail: "VALID_WALLET_CREATE · VALID_SPEND" },
  { label: "Poseidon2", detail: "depth-20 incremental Merkle" },
  { label: "Ed25519 precompile", detail: "TEE-signed settlement" },
  { label: "snarkjs", detail: "browser-side prover" },
  { label: "@darknyx/sdk", detail: "no-Anchor-runtime client" },
];

export function StackStrip() {
  return (
    <section className="border-t py-14" style={{ borderColor: "rgba(255,255,255,0.06)" }}>
      <div className="mx-auto max-w-6xl px-5 sm:px-7">
        <div className="flex items-baseline justify-between">
          <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "10px", letterSpacing: "0.18em", textTransform: "uppercase", color: "#d96820" }}>Built on</span>
          <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "10px", color: "rgba(174,172,176,0.4)" }}>v1 · devnet</span>
        </div>
        <ul className="mt-5 grid grid-cols-2 gap-x-4 gap-y-3 sm:grid-cols-4">
          {STACK.map((s) => (
            <li
              key={s.label}
              className="group flex flex-col gap-0.5 pl-3 transition-colors hover:border-[#d96820]/60"
              style={{ borderLeft: "1px solid rgba(255,255,255,0.06)" }}
            >
              <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "12px", fontWeight: 500, color: "rgba(245,243,238,0.8)" }}>{s.label}</span>
              <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "10px", color: "rgba(174,172,176,0.5)" }}>{s.detail}</span>
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}
