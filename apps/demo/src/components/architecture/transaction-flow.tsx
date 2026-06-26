interface FlowRow {
  step: string;
  cluster: "L1" | "ER";
  ix: string;
  signer: string;
  privacy: string;
}

const FLOW: FlowRow[] = [
  {
    step: "1",
    cluster: "L1",
    ix: "vault::create_wallet (VALID_WALLET_CREATE)",
    signer: "user payer",
    privacy: "links user_commitment to a Solana payer; identity-only",
  },
  {
    step: "2",
    cluster: "L1",
    ix: "vault::deposit",
    signer: "user payer",
    privacy: "reveals deposit amount + mint (SPL transfer)",
  },
  {
    step: "3a",
    cluster: "L1",
    ix: "matching_engine::init_pending_order_slot",
    signer: "user trading_key",
    privacy: "empty PDA, zero order intent",
  },
  {
    step: "3b",
    cluster: "L1",
    ix: "matching_engine::delegate_pending_order",
    signer: "funder + user trading_key",
    privacy: "hand slot to ER validator",
  },
  {
    step: "5",
    cluster: "ER",
    ix: "matching_engine::submit_order",
    signer: "user trading_key",
    privacy: "HIDDEN — order intent never on L1",
  },
  {
    step: "6",
    cluster: "ER",
    ix: "matching_engine::run_batch",
    signer: "TEE / operator",
    privacy: "match all delegated slots in the rollup",
  },
  {
    step: "7",
    cluster: "ER",
    ix: "matching_engine::undelegate_market",
    signer: "TEE / operator",
    privacy: "commits BatchResults back to L1",
  },
  {
    step: "9a",
    cluster: "L1",
    ix: "vault::lock_note(note_a) + lock_note(note_b)",
    signer: "TEE",
    privacy: "references commitments already public from deposit",
  },
  {
    step: "9b",
    cluster: "L1",
    ix: "Ed25519 precompile + vault::tee_forced_settle",
    signer: "TEE",
    privacy: "atomic note_a/b consume + note_c/d/fee append",
  },
  {
    step: "10",
    cluster: "L1",
    ix: "vault::withdraw (VALID_SPEND)",
    signer: "recipient",
    privacy: "spends a note, reveals amount + mint + recipient ATA",
  },
];

export function TransactionFlow() {
  return (
    <section className="border-b border-white/[0.06] py-20">
      <div className="mx-auto max-w-6xl px-5 sm:px-7">
        <div className="max-w-2xl">
          <span className="nyx-eyebrow">03 · End-to-end flow</span>
          <h2 className="nyx-display mt-3 text-[32px] leading-tight sm:text-[40px]">
            One trade, ten transactions.
          </h2>
          <p className="mt-3 text-[14px] text-nyx-fog">
            The hot-path tx for users is step 5 — submit_order on the ER. The
            other steps are mostly one-time per user / per market.
          </p>
        </div>

        <div className="relative mt-10 overflow-hidden rounded-md border border-white/[0.08]">
          <table className="w-full border-collapse text-left">
            <thead className="bg-white/[0.025]">
              <tr className="font-mono text-[10.5px] uppercase tracking-[0.14em] text-nyx-fog">
                <th className="w-12 px-4 py-3">#</th>
                <th className="w-20 px-4 py-3">Cluster</th>
                <th className="px-4 py-3">Instruction</th>
                <th className="px-4 py-3">Signer</th>
                <th className="px-4 py-3">Privacy property</th>
              </tr>
            </thead>
            <tbody className="text-[12.5px]">
              {FLOW.map((row) => (
                <tr key={row.step} className="border-t border-white/[0.05]">
                  <td className="px-4 py-3 align-top font-mono text-nyx-chalk">
                    {row.step}
                  </td>
                  <td className="px-4 py-3 align-top">
                    <span
                      className={`rounded-sm border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-[0.14em] ${
                        row.cluster === "L1"
                          ? "border-nyx-signal-green/45 text-nyx-signal-green"
                          : "border-nyx-accent/55 text-nyx-accent"
                      }`}
                    >
                      {row.cluster}
                    </span>
                  </td>
                  <td className="px-4 py-3 align-top font-mono text-[12px] text-nyx-chalk">
                    {row.ix}
                  </td>
                  <td className="px-4 py-3 align-top text-nyx-fog">
                    {row.signer}
                  </td>
                  <td className="px-4 py-3 align-top text-nyx-fog">
                    {row.privacy}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  );
}
