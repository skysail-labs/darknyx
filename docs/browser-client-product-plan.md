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

| Layer           | Scope                                                                            | Must prove before the next layer                                                                                              |
| --------------- | -------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| 1. Foundation   | Typed public/core contracts, intent/inventory separation, stack-aware CI         | UI has no generic sign/prove, raw-seed, witness, or note-record capability; ambiguous submissions retain reservations         |
| 2. Custody      | Production Worker, WebAuthn PRF wrapping, ciphertext-only IndexedDB, backup v2   | No spike test hooks or attack module in the product bundle; inactivity, tamper, restore, and unsupported-PRF tests pass       |
| 3. Prover       | Browser Worker prover suite, signed/pinned artifact manifest, local verification | All six client circuits prove and verify; artifact/version mismatch fails closed; UI thread stays responsive                  |
| 4. Inventory    | Chain/tree sync, aggregate balances, note manager, proof cache, recovery         | Finalized-root verification, root-expiry refresh, reservation safety, and seed-plus-chain recovery pass                       |
| 5. Trader shell | Dedicated-origin UI, attestation, external wallet, order/fill lifecycle          | Physical passkey matrix, Phantom under COOP/COEP, CSP/Trusted Types, reconnect/recovery, and adversarial frontend review pass |

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
