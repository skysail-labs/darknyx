# Surfpool qualification and local foundation

These tools prove that one immutable Surfpool build can host Darknyx's local
Solana boundary, then create the repeatable offline foundation used by local
integration. Neither result is evidence from a Phala CVM.

`pin.json` records the upstream repository, commit, build run, toolchain,
upstream build command, and SHA-256 values for the Apple Silicon and Linux
amd64 artifacts. It also pins the Studio UI release asset and SHA-256 because
Surfpool's build script otherwise downloads that input from a mutable `latest`
URL. The temporary pin must move to an official release once that release
contains native `getTransactionsForAddress`; never replace the commit with
moving `main`.

## What the qualification proves

- `qualify-rpc.mjs` creates nonempty same-slot history and checks the exact
  successful/full/ascending/slot-filtered/paginated gTFA request Darknyx uses.
  It includes a failed-transaction negative control, a real Ed25519 precompile,
  a v0 transaction whose observed address exists only in an ALT, and a v1
  inline-account transaction with explicit message resource limits.
- `install-vault.mjs` installs the fingerprinted devnet-admin SBF at the
  canonical Darknyx program ID and verifies the executable account owner.
- `packages/sdk/tests/surfpool-qualification.test.ts` sends the committed N=16
  proof fixture through the production verifier and records transaction bytes
  and compute units.
- `packages/sdk/tests/devnet-deposit-withdraw.test.ts` generates deposit,
  input, and spend proofs during the run.
- `crates/darknyx-tee/tests/surfpool_merkle_sync.rs` runs the production cold
  mirror and compares every K-shard leaf count and root with chain state.

The v1 sentinel is a real signed submit, execution, and version-1 RPC read. It
qualifies the transaction format independently of the vault foundation; the
full production Tx D flow remains a separate local-TEE settlement test.

The deterministic worst-case settle CU and v1 4096-byte transaction sentinels run
beside these Surfpool checks. They do not claim that a full TEE settlement ran
inside Surfpool; that belongs to Phase 3.

## Reproduce

Use the clean Linux recipe in
`.github/workflows/surfpool-qualification.yml`. It fetches only the immutable
upstream commit, verifies the pinned Studio UI input, and reproduces the
upstream release build with Rust 1.95.0. The source-built ELF's SHA-256 is
recorded separately from the upstream artifact hash: absolute build paths make
those binaries non-byte-reproducible even when source and locked inputs match.
It then builds `vault.so`, starts an offline in-memory Surfnet on loopback,
creates ephemeral `.surfpool/qualification/` keys and state, runs every check,
and tears down the process with an `always()` step. No provider credential,
persistent Solana keypair, external RPC, or artifact upload is used.

CI caches the nested Surfpool release target by the complete `pin.json` hash,
so changing the upstream commit, toolchain, feature command, or Studio input
invalidates it. The workflow saves that cache immediately after a successful
source compile, rather than discarding the build if a later qualification
assertion fails. The vault SBF step deliberately reuses the same source-hashed
cache contract as `pr-checks`. The generated proof lifecycle similarly restores
the exact circuit-artifact cache keyed by every Circom source, committed zkey,
compiler version, build script, and JavaScript lockfile; a miss rebuilds and is
saved before protocol tests begin. Neither cache can turn a changed input into
a stale qualification binary or proof artefact.

For a local Apple Silicon run, download the `surfpool-darwin-arm64` artifact
from the build run recorded in `pin.json`, verify both recorded checksums, and
follow the same workflow commands. Keep generated material under `.surfpool/`;
the directory is gitignored and must never be copied into `.devnet/`.

Every local run must bind the RPC to loopback. The scripts refuse a remote
endpoint, and a local pass must be reported as Surfpool evidence only.

## One-command foundation lifecycle

`foundation.sh` owns the Phase 2 process and state boundary. It always starts
Surfpool with `--offline`, explicitly binds RPC, WebSocket, and Studio to
`127.0.0.1`, installs the canonical fingerprinted vault, creates fresh local
admin/root/TEE keys, and writes the K=2 mints, market, trees, and fee config
under `.surfpool/foundation/current/`. It refuses datasource
configuration, non-loopback URLs, missing SBF fingerprints, and an already
occupied RPC port.

Build or install the exact binary pinned in `pin.json`, build the vault SBF,
and install JavaScript dependencies first. Then:

```sh
# Create the process and canonical protocol foundation.
bash scripts/surfpool/foundation.sh up manual-1

# Exercise the production Pyth push-account poller against fresh and mutated
# Surfnet accounts. This is a real RPC/account test, not a duplicate decoder.
bash scripts/surfpool/foundation.sh verify

# Stop the recorded process, prove all three ports closed, delete ephemeral
# signing/mint secrets, and archive logs, redacted config, PID metadata, and
# teardown status under evidence/manual-1/.
bash scripts/surfpool/foundation.sh down

# Or run all three operations with failure/signal cleanup.
bash scripts/surfpool/foundation.sh cycle manual-1
```

`verify` injects exact `PriceUpdateV2` fixtures using Surfpool's local-only
account control. The production Rust sync must accept a fresh, fully verified
fixture and reject wrong PDA, owner, write authority, feed, verification level,
time, exponent, price, posted slot, discriminator, trailing data, and truncated
data. Every rejected case is then replaced with a valid account and must
recover, which prevents a stopped poller from producing a vacuous green test.

The hosted workflow runs two complete cycles from empty in-memory ledgers. All
generated material remains below the gitignored `.surfpool/` namespace;
`.devnet/` remains reserved for a real Solana devnet and is never read as local
state. `loopback.test.mjs` pins the negative control for wildcard, LAN,
internet, credentialed, and TLS URLs. There is deliberately no remote override
for the Surfpool mutation helpers.

## Production TEE process on Surfpool

Phase 3 adds a second supervisor around the same foundation. It runs the
production `darknyx-tee` process against the pinned dstack v0.5.9 simulator and
the loopback Surfnet. The simulator supplies only the guest API shape and
deterministic development keys. The TEE still uses its production RPC client,
governance reads, K-shard mirror, matcher, prover, settlement journal, and vault
transactions; there is no simulator-only protocol fork.

Build the optimized host binary first. The Ark proving-key load is several
minutes in an unoptimized build and seconds in release mode:

```sh
cargo build --release -p darknyx-tee

# Run one crossing settlement plus cold restart/root reconciliation.
bash scripts/surfpool/local-tee-matrix.sh settle

# Run every Phase 3 flow, each on a separately created empty ledger.
bash scripts/surfpool/local-tee-matrix.sh all
```

`all` covers deposit/withdraw/lock expiry, K=2 merge, crossing settlement with
seed-plus-chain recovery, multimatch, self-trade policy, and merge-then-order.
The settlement case then cold-restarts the TEE, requires a different boot
session ID, and compares every shard's mirror root and count with the on-chain
`MerkleTree` account. An empty shard may correctly retain `on_chain_slot = 0`;
every nonempty shard must report the replay slot that reconstructed it.
The venue-wide Merkle-readiness pause remains set until this exact reconcile,
so an early HTTP request cannot trade against an uninitialized mirror.

For interactive diagnosis, start a foundation and TEE separately:

```sh
bash scripts/surfpool/foundation.sh up local-tee-manual
bash scripts/surfpool/local-tee.sh up local-tee-manual
bash scripts/surfpool/local-tee.sh status
source .surfpool/local-tee/current/env.sh
# Run a selected SDK test here.
bash scripts/surfpool/local-tee.sh restart
bash scripts/surfpool/local-tee.sh down
bash scripts/surfpool/foundation.sh down
```

The supervisor requires the dstack checkout's exact v0.5.9 commit and defaults
to `target/release/darknyx-tee`. `DSTACK_REPO` and
`DARKNYX_LOCAL_TEE_BIN` may select equivalent local paths. RPC and HTTP
listeners remain loopback-only. Generated API credentials, trader keypairs,
and TEE state are removed during teardown. Logs and result manifests are
archived under `.surfpool/*/evidence/<label>/`; the logs are not automatically
redacted, so that gitignored evidence directory must remain local.

This evidence is deliberately named `Surfpool` or `local-tee`, never CVM
evidence. It does not test Intel TDX isolation, an Intel-valid DCAP quote,
Phala KMS durability or access control, RA-TLS passthrough, or real-validator
confirmation/finality/timing. The production DCAP verifier must reject the
dstack simulator quote, and the Phase 3 test records that rejection as
`quote_invalid`.

## Hosted cadence

The scheduled Linux amd64 workflow runs the foundation qualification followed
by `hosted-smoke.sh`. The bounded smoke deliberately selects two cases from the
six-case local matrix: deposit/withdraw/expiry exercises client proofs and
note lifecycle, while settle exercises the production TEE, N=16 proof,
transactions, cold gTFA replay, exact K-root reconciliation, and simulator
quote rejection. Every case gets a fresh in-memory ledger.

The wrapper requires explicit execution markers and independently checks that
the TEE, Surfpool RPC/WebSocket/Studio, and simulator-facing process boundary
have been torn down. A skipped env-gated suite or a surviving listener is a
failure. Run the exact hosted cadence locally, after preparing the pinned
Surfpool and dstack binaries, with:

```sh
DSTACK_REPO=/path/to/dstack bash scripts/surfpool/hosted-smoke.sh
```

Run `local-tee-matrix.sh all` before changes that affect a flow omitted from the
scheduled subset. Real TDX, KMS, RA-TLS, and cluster/finality evidence remains a
separately dispatched Phala release gate.
