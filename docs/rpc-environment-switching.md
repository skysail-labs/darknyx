# Local Surfpool and real-CVM environment switching

This runbook selects the validation environment without changing protocol
code. It keeps local Surfpool state and real Solana devnet state deliberately
separate so a successful run cannot accidentally depend on accounts, keys, or
history from the other environment.

## Environment contract

| Mode | RPC | TEE | State namespace | Evidence produced |
| --- | --- | --- | --- | --- |
| Routine local | `http://127.0.0.1:18899` | Production `darknyx-tee` binary with pinned dstack simulator | `.surfpool/` | Protocol/process integration only |
| Release or demo | Dedicated real-devnet RPC from `DEVNET_RPC_URL` | Digest-pinned Phala CPU CVM | `.devnet/` plus GitHub Actions secrets | Real TDX, DCAP, RA-TLS, cluster, and devnet evidence |

Never copy mints, ALTs, keypairs, slot floors, program configuration, or
transaction signatures between `.surfpool/` and `.devnet/`. The two modes may
use the same source and image, but never the same ledger state.

## Enter routine local mode

Prepare the pinned binaries as described in
[`scripts/surfpool/README.md`](../scripts/surfpool/README.md), then run either
the bounded hosted-equivalent smoke or the full matrix:

```sh
# Two fresh ledgers: deposit/withdraw and one real TEE settlement.
DSTACK_REPO=/path/to/dstack bash scripts/surfpool/hosted-smoke.sh

# Six fresh ledgers: all maintained client and settlement flows.
bash scripts/surfpool/local-tee-matrix.sh all
```

Success requires the explicit matrix/pass, exact K-root restart, simulator
quote rejection, loopback guard, and teardown markers. A local run is never
reported as CVM evidence.

For interactive diagnosis only:

```sh
bash scripts/surfpool/foundation.sh up local-manual
bash scripts/surfpool/local-tee.sh up local-manual
bash scripts/surfpool/local-tee.sh status
# Run selected SDK commands against the generated loopback env.
bash scripts/surfpool/local-tee.sh down
bash scripts/surfpool/foundation.sh down
```

Before leaving local mode, both supervisors must be down and ports
`18080`, `18899`, `18900`, and `19488` must be closed. Ephemeral signing
material is removed by teardown; retained `.surfpool/**/evidence/` logs stay
local and must not be treated as secrets-safe artifacts.

## Enter real Phala/devnet release mode

This is an explicit paid operation. Configure these repository values without
printing them:

- variable `DARKNYX_NIGHTLY_CVM_ID`;
- secrets `PHALA_CLOUD_API_KEY`, `DEVNET_RPC_URL`,
  `DEVNET_ADMIN_KEYPAIR_B64`, `DEVNET_FUNDER_KEYPAIR_B64`,
  `DEVNET_E2E_CONFIG_B64`, and `DARKNYX_NIGHTLY_FEE_EPOCH_KEY`.

`DEVNET_RPC_URL` is a provider-neutral interface. The selected service must
support the real release suite's request volume and
`getTransactionsForAddress`; public devnet is not a release dependency.

Dispatch the retained release gate from the exact branch or commit under test:

```sh
gh workflow run cvm-e2e.yml --ref <branch-or-commit>
gh run watch <run-id> --repo skysail-labs/darknyx --exit-status
```

With no `image_tag` override, the workflow builds the current ref and converts
the result to an immutable `ghcr.io/...@sha256:...` reference before deploy.
An override is accepted only in that immutable digest form. The workflow
resets every real-devnet tree, records a post-reset sync floor, deploys, rotates
and funds all K signers, and runs DCAP, RA-TLS, settlement, recovery, and daemon
lifecycle checks. Each empty-tree suite receives its own reset and cold boot.

The final workflow step always requests CVM stop. The independent sweeper runs
after workflow completion and shares its concurrency group. Still verify the
dashboard or CLI after every run:

```sh
phala cvms get "$DARKNYX_NIGHTLY_CVM_ID"
```

Do not leave release mode until the CVM is stopped and no plaintext deploy env
or generated `packages/sdk/.env` remains on the runner.

## Rollback and return

Returning from local validation to real evidence is configuration-only:
restore a suitable `DEVNET_RPC_URL` secret and dispatch the manual workflow.
Returning to local development requires no real-network rollback: stop the CVM
and run the Surfpool supervisor, which creates a fresh local ledger.

If the local path fails, do not copy `.devnet/` material into it. Drop the
ephemeral `.surfpool/` run, rebuild from the immutable pin, and retry. If the
real release path fails, keep the CVM stopped and preserve the real-devnet
foundation; restore or change only the dedicated RPC configuration unless the
failure specifically requires a governed program/configuration migration.
