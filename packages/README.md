# Darknyx package map and lifecycle decisions

This directory contains both deployable Darknyx software and development-only
qualification tooling. A package being private or not deployed does not by
itself make it obsolete: some packages preserve cross-language contracts or
repeatable performance evidence that production changes still depend on.

## Current packages

| Package                        | Role                                                                                                                              | Lifecycle                                                                                                     |
| ------------------------------ | --------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `@darknyx/sdk`                 | Shared TypeScript protocol, crypto, proof, Solana instruction, CVM transport, attestation, and recovery surface.                  | Production dependency; keep.                                                                                  |
| `@darknyx/client-core`         | Platform-neutral trader contracts and intent coordination. It keeps secret-bearing capabilities behind narrow adapters.           | Production dependency; keep.                                                                                  |
| `@darknyx/browser-client`      | Browser trader, including custody, proving, inventory, wallet flows, venue verification, recovery, and UI.                        | Production application; keep.                                                                                 |
| `@darknyx/trader-host`         | Serves reviewed browser releases and provides the same-origin session, CVM, and read-only RPC boundary.                           | Production service; keep.                                                                                     |
| `@darknyx/daemon`              | Headless non-custodial client for market makers and automated traders.                                                            | Production reference client; keep.                                                                            |
| `@darknyx/indexer`             | Optional by-order-ID settlement locator and independent settlement-payload decoder. It is not currently deployed or load-bearing. | Dormant accelerator/reference; keep until measured chain-recovery costs justify either deployment or removal. |
| `@darknyx/client-prover-bench` | Reproducible Node, browser, and native proving measurements over the real six client circuits.                                    | Qualification tooling; keep through the gates below.                                                          |

## Browser custody spike retirement

The former `@darknyx/browser-custody-spike` package was removed on 2026-08-15.
It answered the WebAuthn-PRF mechanism question and established the accepted
same-origin trust ceiling. Its production successor now lives in
`@darknyx/browser-client`, whose CI covers the real custody implementation:
provisioning, lock/unlock, inactivity locking, tamper rejection, backup
interoperability, and fail-closed behavior without PRF support.

The spike is not copied into an archive directory. Git history preserves its
source, while the reviewed result and conclusion remain under
`docs/benchmarks/browser-custody/`. The deliberate same-origin compromise was
a threat-model experiment, not a property that production code can or should
make fail under the accepted hosted-browser model.

## Why the prover benchmark remains separate

`@darknyx/client-prover-bench` is not shipped in the browser application. It
owns a distinct measurement concern spanning three environments:

- Chrome Worker plus snarkjs, including cold/warm loads, network throttling,
  main-thread responsiveness, memory, and stability soaks;
- Node plus snarkjs;
- native Circom witness generation plus rapidsnark.

Folding this into `@darknyx/browser-client` would put Node/native qualification
machinery beside production browser code without reducing the machinery or its
maintenance. Moving it under `tools/` could make the directory taxonomy look
cleaner, but would not remove code and is not worth the churn before its
remaining evidence is collected.

Do not delete, fold, or relocate the benchmark package until all of the
following are true:

1. The decision-grade physical x86 measurement has been run for all six client
   circuits and its reviewed results are committed under
   `docs/benchmarks/client-proving/`.
2. The initial browser launch qualification has a reviewed proving baseline,
   including latency, peak RSS, responsiveness, and soak behavior.
3. The current circuit/proving-artifact set is frozen, or another owner and
   harness are explicitly assigned to remeasure performance after changes.
4. `@darknyx/browser-client` no longer imports the benchmark package's
   deterministic fixture builder, or that shared fixture contract has been
   moved without duplication and retains parity coverage.

After those gates, reassess rather than automatically delete it. If circuit,
browser, snarkjs, or proving-artifact changes remain plausible, keeping the
small isolated harness is cheaper and safer than reconstructing it after a
performance regression. If `packages/` is later reserved strictly for shipped
software, move the harness intact to `tools/client-prover-bench`; do not fold
it into the browser product.

## Retirement checklist

An experimental package may be removed when its decision is closed, a
production successor owns every still-required regression, retained evidence
does not depend on the executable prototype, and workspace/CI/documentation
references are removed in the same change. Historical source belongs in Git
history, not a second in-tree archive.
