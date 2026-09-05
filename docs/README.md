# Internal documentation map

`docs/` contains current engineering contracts, operational runbooks, active
decision records, and measured evidence. Public user documentation lives only
in `docs/mintlify/`.

Use these sources instead of creating a new implementation tracker for a topic
that already has one:

| Topic | Current source of truth |
|---|---|
| System and cryptography | `ARCHITECTURE.md`, `tee-architecture.md`, `tee-attestation-flow.md`, and root `CRYPTOGRAPHY.md` |
| TEE API | `tee-api-openapi.yaml` |
| CVM operation and recovery | `cvm-run-runbook.md`, `settlement-recovery-drill.md`, and `protocol-fee-recovery-runbook.md` |
| Settlement performance | `throughput-roadmap.md` and `benchmarks/` |
| Local Surfpool testing | `rpc-environment-switching.md` and `scripts/surfpool/` |
| Privacy remediation | `privacy-architecture/remediation-plan.md`, its tracker, and phase reports |
| Transport integrity | `transport-integrity-remediation-plan.md` |
| Browser client | Package READMEs plus `browser-client-launch-qualification.md`; the product remains deferred |
| Browser UI extraction | `browser-ui-extraction-plan.md` until the repository-direction decision is resolved |
| Open audit/release work | `audits/residual-backlog.md` |

Completed migration plans and closed work trackers do not stay here merely as
history. Git history preserves them, while immutable security findings and
their closure evidence stay under `audits/`. Delete a completed plan once its
lasting behavior is represented by current architecture, a runbook, tests, or
the residual backlog.

## Deferred product decisions

- Browser trading remains implemented but not launch-qualified. Reopen it only
  through `browser-client-launch-qualification.md` and the T-03B/R-01 entries in
  `audits/residual-backlog.md`.
- Moving the trader UI to another repository remains undecided; preserve the
  interface and synchronization rules in `browser-ui-extraction-plan.md` until
  an owner chooses a direction.
- Dense market-maker ladders or mass quote/cancel-replace require a design that
  can collateralize several simultaneous intents without reusing one note.
  Oracle-pegged and post-only orders do not map cleanly onto a uniform batch
  auction. Revisit these only when real liquidity demand justifies changing the
  collateral or auction model; `liquidity-mm-and-block-matching-design-record.md`
  holds the broader decision framework.

Before deleting a document, update every tracked incoming link and preserve any
still-open gate in the appropriate source above. Do not move internal migration
history into Mintlify: hosted docs describe the product users can use today.
