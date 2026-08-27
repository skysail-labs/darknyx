# Surfpool qualification tools

These tools prove that one immutable Surfpool build can host Darknyx's local
Solana boundary. They are a narrow Phase 1 qualification surface, not the
Phase 2 one-command local foundation and not evidence from a Phala CVM.

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

For a local Apple Silicon run, download the `surfpool-darwin-arm64` artifact
from the build run recorded in `pin.json`, verify both recorded checksums, and
follow the same workflow commands. Keep generated material under `.surfpool/`;
the directory is gitignored and must never be copied into `.devnet/`.

Every local run must bind the RPC to loopback. The scripts refuse a remote
endpoint, and a local pass must be reported as Surfpool evidence only.
