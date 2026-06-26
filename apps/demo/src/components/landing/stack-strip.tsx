interface Pill {
  label: string;
  detail: string;
}

const STACK: Pill[] = [
  { label: "Solana", detail: "L1 custody + ZK verifier" },
  { label: "Anchor 0.32", detail: "vault + matching engine" },
  { label: "MagicBlock PER", detail: "delegated order PDAs" },
  { label: "Groth16 / BN254", detail: "VALID_WALLET_CREATE · VALID_SPEND" },
  { label: "Poseidon2", detail: "depth-20 incremental Merkle" },
  { label: "Ed25519 precompile", detail: "TEE-signed settlement" },
  { label: "snarkjs", detail: "browser-side prover" },
  { label: "@darknyx/sdk", detail: "no-Anchor-runtime client" },
];

export function StackStrip() {
  return (
    <section className="border-t border-white/[0.06] bg-nyx-ink py-14">
      <div className="mx-auto max-w-6xl px-5 sm:px-7">
        <div className="flex items-baseline justify-between">
          <span className="nyx-eyebrow">Built on</span>
          <span className="font-mono text-[10px] text-nyx-fog">
            v1 · devnet
          </span>
        </div>
        <ul className="mt-5 grid grid-cols-2 gap-x-4 gap-y-3 sm:grid-cols-4">
          {STACK.map((s) => (
            <li
              key={s.label}
              className="group flex flex-col gap-0.5 border-l border-white/[0.08] pl-3 transition-colors hover:border-nyx-accent/60"
            >
              <span className="text-[13px] font-medium text-nyx-chalk">
                {s.label}
              </span>
              <span className="font-mono text-[11px] text-nyx-fog">
                {s.detail}
              </span>
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}
