const PROTECTS_AGAINST = [
  {
    title: "Front-running of unmatched orders",
    body: "Order intent lives in the ER, never on L1.",
  },
  {
    title: "Replay of TEE-signed settlements",
    body: "consumed_note PDAs lock both legs; a second identical settle collides at PDA allocation.",
  },
  {
    title: "Withdrawals without ownership",
    body: "VALID_SPEND requires the spending key; nullifier PDAs prevent double-spend.",
  },
  {
    title: "Conservation violations",
    body: "tee_forced_settle enforces note.amount = trade + change + fee exactly before any state mutation.",
  },
  {
    title: "Mismatched canonical hashes",
    body: "The Ed25519 precompile message must equal canonical_payload_hash(payload); a TEE that signs a different message is rejected.",
  },
];

const NOT_YET = [
  {
    title: "Real TDX/SEV TEE + remote attestation",
    body: "Today the TEE is a software Ed25519 keypair. Production deploys must pin the key inside an attested enclave.",
  },
  {
    title: "Browser prover replacing snarkjs shell-out",
    body: "WebProverSuite is wired in for VALID_WALLET_CREATE + VALID_SPEND in the dapp; SDK-level prover still shells out for tests.",
  },
  {
    title: "Off-chain indexer for shielded notes",
    body: "Without one, the dapp reconstructs the Merkle tree from RPC history every time. See apps/demo/ARCHITECTURE.md §2 for the eleven workarounds.",
  },
  // {
  //   title: "Partial-fill rotation on devnet",
  //   body: "The on-chain code paths and litesvm tests exist; no devnet test currently drives collateral rotation across two batches.",
  // },
  // {
  //   title: "undelegate_pending_order",
  //   body: "Let users release a slot back to L1 to refund rent. Today slots stay delegated forever.",
  // },
  {
    title: "Continuous ER ↔ L1 commit scheduler inside the TEE",
    body: "Production wants commit_market_state every N slots so settlement can pick up matches without a full undelegate cycle.",
  },
  {
    title: "Real protocol-owner keypair for fee withdrawal",
    body: "Fee notes accumulate but can't be spent until a real protocol-owner key is wired in.",
  },
  {
    title: "PER JWT session manager wired into the ER trade-flow test",
    body: "Network-side anonymity-set requires JWT-gated ingress to be effective.",
  },
];

export function SecurityAndRoadmap() {
  return (
    <section className="py-20">
      <div className="mx-auto max-w-6xl px-5 sm:px-7">
        <div className="grid grid-cols-1 gap-10 lg:grid-cols-2 lg:gap-14">
          <div>
            <span className="nyx-eyebrow">05 · Security model</span>
            <h2 className="nyx-display mt-3 text-[28px] leading-tight sm:text-[36px]">
              What the system protects against.
            </h2>
            <ul className="mt-7 space-y-3">
              {PROTECTS_AGAINST.map((item) => (
                <li
                  key={item.title}
                  className="rounded-md border border-white/[0.08] bg-nyx-graphite p-4"
                >
                  <div className="flex items-start gap-3">
                    <span className="mt-1 inline-flex h-4 w-4 shrink-0 items-center justify-center rounded-full border border-nyx-signal-green/55 text-nyx-signal-green">
                      <svg width="9" height="9" viewBox="0 0 11 11" fill="none">
                        <path
                          d="M2 5.5l2.4 2.4L9 3.4"
                          stroke="currentColor"
                          strokeWidth="1.6"
                          strokeLinecap="round"
                          strokeLinejoin="round"
                        />
                      </svg>
                    </span>
                    <div>
                      <div className="text-[14px] font-medium text-nyx-chalk">
                        {item.title}
                      </div>
                      <div className="mt-0.5 text-[12.5px] text-nyx-fog">
                        {item.body}
                      </div>
                    </div>
                  </div>
                </li>
              ))}
            </ul>
          </div>

          <div>
            <span className="nyx-eyebrow">06 · Roadmap</span>
            <h2 className="nyx-display mt-3 text-[28px] leading-tight sm:text-[36px]">
              What is <span className="text-nyx-fog">not</span> yet shipped.
            </h2>
            <ul className="mt-7 space-y-3">
              {NOT_YET.map((item, idx) => (
                <li
                  key={item.title}
                  className="rounded-md border border-white/[0.08] bg-nyx-graphite p-4"
                >
                  <div className="flex items-start gap-3">
                    <span className="font-mono text-[10.5px] uppercase tracking-[0.14em] text-nyx-fog">
                      {String(idx + 1).padStart(2, "0")}
                    </span>
                    <div>
                      <div className="text-[14px] font-medium text-nyx-chalk">
                        {item.title}
                      </div>
                      <div className="mt-0.5 text-[12.5px] text-nyx-fog">
                        {item.body}
                      </div>
                    </div>
                  </div>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>
    </section>
  );
}
