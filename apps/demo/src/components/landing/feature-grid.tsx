interface Feature {
  eyebrow: string;
  title: string;
  body: string;
  icon: "moon" | "shield" | "spark" | "ledger";
}

const FEATURES: Feature[] = [
  {
    eyebrow: "01 · Hidden intent",
    title: "Orders never touch the L1 mempool.",
    body: "submit_order is signed and stored exclusively inside MagicBlock's Ephemeral Rollup. Side, price, amount, and your collateral note commitment all stay off-chain until a batch matches.",
    icon: "moon",
  },
  {
    eyebrow: "02 · Verifiable settlement",
    title: "Every fill is a Groth16 proof.",
    body: "Withdrawals require a VALID_SPEND zk-SNARK proving you own a leaf in the vault's Merkle tree.",
    icon: "shield",
  },
  {
    eyebrow: "03 · Attested executor",
    title: "TEE-signed atomic settlement.",
    body: "Settlement is written by a TEE-attested Ed25519 key into vault::tee_forced_settle. The on-chain instruction enforces the conservation law `note.amount = trade + change + fee` exactly before any state mutation.",
    icon: "spark",
  },
  {
    eyebrow: "04 · UTXO accounting",
    title: "Shielded notes, public roots.",
    body: "Balances live as Poseidon-hashed UTXO leaves (mint, amount, owner_commitment, nonce, blinding). The tree's leaf-count and current_root are public; individual ownership stays cryptographically opaque.",
    icon: "ledger",
  },
];

export function FeatureGrid() {
  return (
    <section className="relative isolate border-t border-white/[0.06] bg-nyx-ink py-24">
      <div className="mx-auto max-w-6xl px-5 sm:px-7">
        <div className="max-w-2xl">
          <span className="nyx-eyebrow">What Nyx gives you</span>
          <h2 className="nyx-display mt-3 text-[34px] leading-tight sm:text-[44px]">
            A darkpool you can audit
            <span className="text-nyx-fog"> without compromising privacy.</span>
          </h2>
          <p className="mt-4 max-w-xl text-[15px] text-nyx-fog">
            Four properties define the system. Each one is verifiable on-chain
            today on Solana devnet — no off-protocol indexer required for
            correctness.
          </p>
        </div>

        <div className="mt-12 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {FEATURES.map((f, idx) => (
            <article
              key={f.eyebrow}
              className={`group relative overflow-hidden rounded-md border border-white/[0.08] bg-nyx-graphite-2 p-5 transition-colors hover:border-white/20 nyx-rise nyx-rise-delay-${idx + 1}`}
            >
              <div className="mb-5 flex h-10 w-10 items-center justify-center rounded-sm border border-white/10 bg-white/[0.04]">
                <FeatureIcon kind={f.icon} />
              </div>
              <div className="nyx-eyebrow">{f.eyebrow}</div>
              <h3 className="mt-2 text-[17px] font-semibold leading-snug text-nyx-chalk">
                {f.title}
              </h3>
              <p className="mt-2 text-[13px] leading-relaxed text-nyx-fog">
                {f.body}
              </p>
              <div
                className="absolute inset-x-0 bottom-0 h-px bg-gradient-to-r from-transparent via-nyx-accent/40 to-transparent opacity-0 transition-opacity group-hover:opacity-100"
                aria-hidden="true"
              />
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}

function FeatureIcon({ kind }: { kind: Feature["icon"] }) {
  const stroke = "currentColor";
  switch (kind) {
    case "moon":
      return (
        <svg
          width="20"
          height="20"
          viewBox="0 0 24 24"
          className="text-nyx-chalk"
        >
          <defs>
            <clipPath id="fgi-moon">
              <rect x="0" y="0" width="24" height="13" />
            </clipPath>
          </defs>
          <circle
            cx="12"
            cy="12"
            r="7"
            fill="currentColor"
            clipPath="url(#fgi-moon)"
          />
          <rect x="3" y="13" width="18" height="1.4" fill={stroke} />
          <rect
            x="3"
            y="16"
            width="12"
            height="1.4"
            fill={stroke}
            opacity="0.5"
          />
        </svg>
      );
    case "shield":
      return (
        <svg
          width="20"
          height="20"
          viewBox="0 0 24 24"
          fill="none"
          className="text-nyx-chalk"
        >
          <path
            d="M12 3l8 3v6c0 4.5-3.4 8.4-8 9.5C7.4 20.4 4 16.5 4 12V6l8-3z"
            stroke={stroke}
            strokeWidth="1.5"
            strokeLinejoin="round"
          />
          <path
            d="M9 12.5l2 2 4-4"
            stroke={stroke}
            strokeWidth="1.5"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </svg>
      );
    case "spark":
      return (
        <svg
          width="20"
          height="20"
          viewBox="0 0 24 24"
          fill="none"
          className="text-nyx-chalk"
        >
          <path
            d="M12 3v6m0 6v6m-9-9h6m6 0h6M5.6 5.6l4.2 4.2m4.4 4.4l4.2 4.2M5.6 18.4l4.2-4.2m4.4-4.4l4.2-4.2"
            stroke={stroke}
            strokeWidth="1.4"
            strokeLinecap="round"
          />
        </svg>
      );
    case "ledger":
      return (
        <svg
          width="20"
          height="20"
          viewBox="0 0 24 24"
          fill="none"
          className="text-nyx-chalk"
        >
          <rect
            x="4"
            y="4"
            width="16"
            height="16"
            rx="1.5"
            stroke={stroke}
            strokeWidth="1.4"
          />
          <path
            d="M8 9h8M8 12h8M8 15h5"
            stroke={stroke}
            strokeWidth="1.4"
            strokeLinecap="round"
          />
        </svg>
      );
  }
}
