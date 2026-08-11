# Browser client product stack

Status: **implementation active; stacked PRs remain open for owner review.**

Darknyx is proceeding browser-first for ordinary trader flow under the accepted
hosted-dApp custody model: encrypted at-rest data and WebAuthn user verification
are protected, while the trusted Darknyx origin and its release pipeline remain
inside the custody boundary. This is an implementation direction, not a launch
qualification. Physical authenticators, wallet behavior under COOP/COEP, x86
proving, and the focused frontend/supply-chain review remain release gates.

The implementation is one linear stack. Every PR targets the branch immediately
below it, shows only its own layer, and stays open until explicitly approved.

No layer is launch-qualified until all cross-layer gates are recorded: the full
local/CI suite; physical platform-passkey and roaming-key coverage; Phantom and
at least one additional wallet under COOP/COEP; x86 proving distributions;
real devnet deposit/withdraw/merge/order/settle and interrupted-recovery runs;
immutable host/artifact provenance and rollback rehearsal; hostile-frontend and
supply-chain review; third-party license clearance; and the applicable external
audit, ceremony, governance, and mainnet controls tracked under `audits/`.

| Layer           | Scope                                                                             | Must prove before the next layer                                                                                                              |
| --------------- | --------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| 1. Foundation   | Typed public/core contracts, intent/inventory separation, stack-aware CI          | UI has no generic sign/prove, raw-seed, witness, or note-record capability; ambiguous submissions retain reservations                         |
| 2. Custody      | Production Worker, WebAuthn PRF wrapping, ciphertext-only IndexedDB, backup v2    | No spike test hooks or attack module in the product bundle; inactivity, tamper, restore, and unsupported-PRF tests pass                       |
| 3. Prover       | Browser Worker prover suite, signed/pinned artifact manifest, local verification  | All six client circuits prove and verify; artifact/version mismatch fails closed; UI thread stays responsive                                  |
| 4. Inventory    | Chain/tree sync, aggregate balances, note manager, proof cache, recovery          | Finalized-root verification, root-expiry refresh, reservation safety, and seed-plus-chain recovery pass                                       |
| 5. Trader shell | Dedicated-origin UI, attestation, external wallet, order/fill lifecycle           | Physical passkey matrix, Phantom under COOP/COEP, CSP/Trusted Types, reconnect/recovery, and adversarial frontend review pass                 |
| 6. Account UX   | Typed deposit, exact-note withdrawal, consolidation, and encrypted backup UX      | Public-input substitution fails closed; uncertain wallet broadcasts retain reservations; signed-but-unfinalized transactions remain ambiguous |
| 7. Release host | Same-origin session broker, immutable assets, production headers and release pins | No long-lived CVM secret reaches the browser; deploy/header tests and the launch qualification matrix pass                                    |

## Layer evidence

- **Layer 1 — code complete, review pending:** the platform-neutral contracts
  and intent coordinator are in the bottom stack PR. Unit and compile-time
  boundary tests cover proof readiness, authorization, definite rejection, and
  ambiguous transport outcomes.
- **Layer 2 — code complete, review pending:** `@darknyx/browser-client` bundles
  the Worker and pinned scrypt implementation into one static artifact. Its
  product test runs that bundle in Chrome with PRF-capable and PRF-incapable
  virtual authenticators. It covers provision/lock/unlock, ciphertext tamper
  rejection, absolute inactivity despite status polling, backup-v2 recovery
  across Node and browser implementations, ciphertext-only IndexedDB, CSP,
  Trusted Types, and fail-closed unsupported-PRF behavior. This is qualification
  evidence for the implementation mechanism, not the still-open physical-device
  or hostile-origin launch gates.
- **Layer 3 — code complete, review pending:** the internal prover Worker covers
  all six client circuits from SHA-256-verified bytes described by an
  Ed25519-signed, release-pinned manifest. It verifies every proof locally and
  keeps the generic prove channel out of the public package entrypoint. A local
  Chrome 151 product-bundle pass proved and verified wallet-create, deposit,
  input, spend, merge K=2, and merge K=4 sequentially with a 26.75 ms maximum
  UI-thread heartbeat stall. First-use timings (including artifact fetch,
  hashing, initialisation, witness, prove, and verify) were 0.69 s, 0.25 s,
  0.86 s, 0.92 s, 1.51 s, and 2.79 s respectively on the Apple M3 host. These
  are integration evidence, not replacements for the decision-grade warm/cold
  distributions or the still-open physical x86 gate.
- **Layer 4 — code complete, review pending:** the encrypted inventory plane
  reconstructs deposit/trade/change/merge notes from seed plus finalized chain
  data inside the custody Worker, rejects unresolved owned outputs, and checks
  tag-keyed consumed PDAs before exposing balances. Finalized root rings are
  parsed newest-first; proof cache keys bind note, tag, shard, root, circuit and
  proving-key versions; ageing roots refresh in the background and evicted or
  version-mismatched proofs become stale. Reservations are serialized and
  persisted before authorization, so reload and ambiguous transport cannot
  double-allocate a note. A Chrome product-bundle test restores a Node-created
  backup, recovers a real seed-derived deposit fixture, round-trips encrypted
  inventory, rejects ciphertext tampering, and proves that vault lock revokes
  inventory decrypt access.
- **Layer 5a — code complete, review pending:** browser venue boot now starts
  from finalized `VaultConfig`, verifies the DCAP quote against the
  release-pinned compose hash and governed shard-0 signer, requires exact
  quote/on-chain signer-set equality, and binds every advertised instrument to
  its finalized `MarketConfig`. Browser attestation no longer relies on Node
  crypto polyfills. The browser obtains only a short-lived token from a
  same-origin, opaque-venue session broker; long-lived CVM credentials stay
  server-side. Wallet Standard discovery and sign-and-send are constrained to
  bounded Solana transaction bytes. The visual workspace and typed
  order/lifecycle composition remain stacked above it.
- **Layer 5b — code complete, launch qualification pending:** the Warm Horizon trader
  workspace now exposes attestation, venue-local readiness, external wallet,
  vault, aggregate private balances, proof readiness, order entry, and durable
  settlement lifecycle states at desktop/tablet/mobile breakpoints. It imports
  only page-safe view/action contracts; decimal-to-atom conversion and typed
  intent authorization stay behind the action adapter. Failed trust and paused
  markets disable submission with a durable explanation, while ambiguous
  transport remains “Reconciling.” Layer 5c below wires these actions to the
  encrypted inventory, custody Worker, authenticated stream, and chain
  reconciliation before physical-device qualification.
  Exact Chromium emulation at 375, 768, and 1280 CSS pixels confirms no
  page-level horizontal overflow; the narrow lifecycle table alone remains an
  intentional swipe/scroll region.
- **Layer 5c — code complete, launch qualification pending:** the observable
  controller now boots the finalized-governance/TDX trust chain before opening
  private state, converts human decimals to exact governed atomic units, and
  composes the custody Worker, encrypted inventory, background VALID_INPUT
  cache, authenticated `/v1/stream`, typed intent coordinator, and finalized
  chain recovery. HD order indices are persisted before signing and are never
  reused. Order and cancel signatures are created inside the Worker; the React
  bridge receives only snapshots and narrow actions. Order and fill messages
  share one reconnecting stream, but remain notifications: malformed frames,
  unknown orders, fills, sequence gaps, and lag closures invoke a deduplicated
  finalized-chain reconciliation. Recovery checks both tag-keyed
  `ConsumedNoteEntry` and `NoteLock` PDAs, so a relocked continuation or failed
  input cannot reappear as spendable collateral. Chrome product qualification
  restored a known backup, recovered a seed-derived deposit, cached an input
  proof, and produced canonical order/cancel signatures inside the Worker under
  COOP/COEP, CSP, Trusted Types, and WebAuthn PRF. Physical-device, real-wallet,
  hostile-delivery, and live-venue checks remain launch gates, not implied by
  this local result.
- **Layer 6 — code complete, launch qualification pending:** deposit,
  withdrawal, and note consolidation are typed account operations behind the
  trusted composition entrypoint. Seed-derived deposit secrets and spend/merge
  witnesses are prepared in the custody Worker; every locally produced proof's
  public inputs are checked against the exact transaction fields before the
  bounded versioned transaction reaches Wallet Standard. Deposits allocate a
  durable, never-reused recovery index. Withdrawals require one exact spendable
  note; users consolidate two to four same-mint, same-shard notes when they need
  a combined amount. Finalized transactions update encrypted inventory,
  an uncertain wallet broadcast retains preflight reservations, and a returned
  signature whose finality cannot be established remains reserved and visible
  as ambiguous. Backup v2 export/restore is present in the account surface, but
  plaintext seed material and generic prove/sign APIs remain absent from React.
  This code is not qualified until the complete everything-green gate, real
  wallet/passkey matrix, live devnet/CVM account flows, reconnect/recovery drill,
  and focused frontend/supply-chain review have all produced recorded evidence.
- **Layer 7 — pending:** the deployable dedicated-origin host, server-held
  session broker, immutable release manifest, production security headers, and
  launch-qualification record are the final implementation slice. Physical
  authenticators, real wallet behavior, x86 proving and external review remain
  evidence gates even after that code is complete.

The production Worker currently bundles snarkjs, whose package declares
GPL-3.0. Before distributing the browser application, obtain a focused license-
compatibility review against Darknyx's source-available project license and ship
all required third-party notices/source obligations. The implementation and
performance choice in this stack is not a legal conclusion; an incompatible
distribution result is a release blocker or a prover-backend replacement
trigger.

No product PR in this stack is auto-merged. If a lower layer changes during
review, fix that branch and rebase its up-stack dependants. Merge the reviewed
stack only on explicit owner direction.

## Deliberate boundaries

- The browser UI sees aggregate balances and opaque readiness/results, not note
  openings or witnesses.
- Order submission consumes a ready proof; it cannot trigger proving.
- Authorization is a typed intent operation, never `sign(bytes)`.
- A transport exception after submission starts is ambiguous. It is reconciled;
  its collateral is not automatically released or rebooked.
- A compromised enclave can repeatedly select a colluding market maker. Launch
  qualification therefore requires publishing per-MM execution-quality
  statistics so persistent adverse selection is observable.
- The market-maker daemon remains native/headless. Browser-first applies to the
  ordinary trader product, not persistent MM or flags-only block-flow liveness.
- Tauri remains the compatible fallback if launch qualification rejects the
  hosted-origin threat model; the public contracts do not change.
