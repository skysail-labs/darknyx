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
  and a v0 transaction whose observed address exists only in an ALT.
- `install-vault.mjs` installs the fingerprinted devnet-admin SBF at the
  canonical Darknyx program ID and verifies the executable account owner.
- `packages/sdk/tests/surfpool-qualification.test.ts` sends the committed N=16
  proof fixture through the production verifier and records transaction bytes
  and compute units.
- `packages/sdk/tests/devnet-deposit-withdraw.test.ts` generates deposit,
  input, and spend proofs during the run.
- `crates/darknyx-tee/tests/surfpool_merkle_sync.rs` runs the production cold
  mirror and compares every K-shard leaf count and root with chain state.

The deterministic worst-case settle CU and 1232-byte transaction sentinels run
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
admin/root/TEE keys, and writes the K=2 mints, market, trees, fee config, and
settlement ALT under `.surfpool/foundation/current/`. It refuses datasource
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
