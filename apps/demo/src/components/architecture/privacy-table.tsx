interface Row {
  object: string;
  l1Visible: boolean;
  notes: string;
}

const ROWS: Row[] = [
  {
    object: "Order side / price / amount",
    l1Visible: false,
    notes: "Stays in the ER until run_batch matches",
  },
  {
    object: "Order's collateral note commitment",
    l1Visible: false,
    notes: "Same — only inside the ER",
  },
  {
    object: "User's trading-key signature on submit_order",
    l1Visible: false,
    notes: "The whole submit tx lives in the ER",
  },
  {
    object: "note_commitment of the deposit note",
    l1Visible: true,
    notes: "Public on vault::deposit (always was)",
  },
  {
    object: "Deposit amount / mint",
    l1Visible: true,
    notes: "SPL transfer is on L1",
  },
  {
    object: "Match clearing price + matched volume",
    l1Visible: true,
    notes: "Surfaces in BatchResults after commit",
  },
  {
    object: "Settlement note commitments (note_c, note_d, note_fee)",
    l1Visible: true,
    notes: "TEE appends them in tee_forced_settle",
  },
  {
    object: "Withdrawal amount + recipient ATA",
    l1Visible: true,
    notes: "SPL transfer-out is on L1",
  },
];

export function PrivacyTable() {
  return (
    <section className="border-b border-white/[0.06] bg-nyx-graphite-2/40 py-20">
      <div className="mx-auto max-w-6xl px-5 sm:px-7">
        <div className="max-w-2xl">
          <span className="nyx-eyebrow">02 · Privacy boundary</span>
          <h2 className="nyx-display mt-3 text-[32px] leading-tight sm:text-[40px]">
            What stays hidden,{" "}
            <span className="text-nyx-fog">what surfaces.</span>
          </h2>
          <p className="mt-3 text-[14px] text-nyx-fog">
            Nyx hides individual <em>order intent</em>. Aggregate match data
            (clearing price, total matched volume, the two consumed note
            commitments) is public — that&apos;s by design, not an oversight.
          </p>
        </div>

        <div className="mt-10 overflow-hidden rounded-md border border-white/[0.08]">
          <table className="w-full border-collapse text-left text-[13px]">
            <thead className="bg-white/[0.025]">
              <tr>
                <th className="px-5 py-3 font-mono text-[10.5px] uppercase tracking-[0.14em] text-nyx-fog">
                  Object
                </th>
                <th className="w-[140px] px-5 py-3 font-mono text-[10.5px] uppercase tracking-[0.14em] text-nyx-fog">
                  L1 visible?
                </th>
                <th className="px-5 py-3 font-mono text-[10.5px] uppercase tracking-[0.14em] text-nyx-fog">
                  Notes
                </th>
              </tr>
            </thead>
            <tbody>
              {ROWS.map((r) => (
                <tr key={r.object} className="border-t border-white/[0.05]">
                  <td className="px-5 py-3 align-top text-nyx-chalk">
                    {r.object}
                  </td>
                  <td className="px-5 py-3 align-top">
                    {r.l1Visible ? (
                      <span className="inline-flex items-center gap-1.5 rounded-sm border border-nyx-signal-amber/45 bg-nyx-signal-amber/10 px-2 py-0.5 font-mono text-[10.5px] uppercase tracking-[0.14em] text-nyx-signal-amber">
                        <span className="h-1.5 w-1.5 rounded-full bg-nyx-signal-amber" />
                        Public
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1.5 rounded-sm border border-nyx-signal-green/45 bg-nyx-signal-green/10 px-2 py-0.5 font-mono text-[10.5px] uppercase tracking-[0.14em] text-nyx-signal-green">
                        <span className="h-1.5 w-1.5 rounded-full bg-nyx-signal-green" />
                        Hidden
                      </span>
                    )}
                  </td>
                  <td className="px-5 py-3 align-top text-nyx-fog">
                    {r.notes}
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
