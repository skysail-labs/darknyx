# CLAUDE.md — agent onboarding for Nyx Darkpool

> This file is the contract between you (the agent) and the project.
> Read it before touching code. It also doubles as `AGENTS.md` — same
> rules, just routed by name.
>
> If you only read one section, read **[§2 — The unbreakable
> build/deploy/validate cycle](#2-the-unbreakable-builddeployvalidate-cycle)**.

---

## 0. What this repo is, in 60 seconds

Nyx is a privacy-preserving CLOB-like darkpool on Solana with three
tightly-coupled layers:

* **L1 (Solana)** — `programs/vault/` (custody + Merkle tree + ZK
  verifier + atomic settlement) and `programs/matching_engine/` (CLOB
  + ER session driver). Anchor 0.32.
* **ER (MagicBlock Ephemeral Rollup)** — hidden order intent +
  uniform-clearing-price matching. `submit_order` lives inside the
  rollup; `BatchResults` commits back to L1.
* **Client (TypeScript SDK + snarkjs prover)** — `packages/sdk/` is
  the integration surface. `crates/darkpool-crypto/` is the host-side
  Rust crypto crate with byte-identical Poseidon / nullifier / note /
  key derivation that the TS SDK has parity tests against.

Currency: the live branch is `nyx-v2-onchain-hardening` through the
**v3.5 batched-validity migration**. Layered hardenings:

| Phase | What it added |
|---|---|
| v2 | VALID_INPUT proof + `NoteLock.token_mint` binding + `MAX_LOCK_TTL_SLOTS` + `outstanding[mint]` counter |
| v3 | VALID_CREATE proof + `ValidCreateMarker` PDA |
| v3.1 | VALID_PRICE proof + `ValidPriceMarker` PDA + v0 tx + ALT migration |
| v3.5 (current) | VALID_MATCH_BATCH (N=16) + `BatchValidityMarker` (1:N) + `tee_forced_settle_batched` + `close_batch_validity_marker` |

**Phase 1c-hard is DONE.** v3.5 is the only on-chain settle path —
`verify_valid_create`, `verify_valid_price`, the per-match
`tee_forced_settle`, their `ValidCreateMarker` / `ValidPriceMarker`
state, the matching VK consts + circom circuits, and the SDK
builders that targeted them have all been removed. The detailed
do-not-resurrect list is in [§10](#10-phase-1c-hard-cutover--done-v35-is-the-only-settle-path).
The migration log is in `docs/v3.5-migration.md`.

---

## 1. Stop. Read these first.

You will not write correct code in this repo without internalising the
mental model. Required reading before any change:

* **[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)** — system-level
  overview. ASCII flow at the top, PDA table in
  [§6](docs/ARCHITECTURE.md#account--pda-reference), deployment
  runbook in
  [§"Deployment runbook"](docs/ARCHITECTURE.md#deployment-runbook).
* **[`CRYPTOGRAPHY.md`](CRYPTOGRAPHY.md)** — cryptographer's tour:
  key model ([§4](CRYPTOGRAPHY.md#4-the-key-model)), note system
  ([§5](CRYPTOGRAPHY.md#5-the-note-system)), Merkle tree
  ([§6](CRYPTOGRAPHY.md#6-the-incremental-merkle-tree)), all six ZK
  circuits ([§7](CRYPTOGRAPHY.md#7-the-five-zk-circuits)),
  lifecycle ([§8](CRYPTOGRAPHY.md#8-lifecycle-walkthrough)),
  settlement size analysis
  ([§9](CRYPTOGRAPHY.md#9-settlement-mechanics)), replay protection
  ([§11](CRYPTOGRAPHY.md#11-replay-protection)).
* **[`scripts/dev-commands.md`](scripts/dev-commands.md)** —
  command cheat sheet. §5 is the "everything is green" pre-commit
  gate; §10/§11/§11A/§11B are the devnet flows; §12 is the failure
  catalogue. Run commands from this file verbatim — they have the
  right env vars baked in.
* **[`docs/v3.5-migration.md`](docs/v3.5-migration.md)** — Phase 1c
  soft- vs hard-cutover, ALT rotation strategy, 256-addresses-per-ALT
  cap analysis. Read this before deleting any v3.1 code.

By domain, additionally:

| If you're touching | Read first |
|---|---|
| A circom circuit | `CRYPTOGRAPHY.md` §7 (the relevant subsection), then the existing circuit + its `vk_*.rs` + its `*-prover.test.ts`. See [§4 of this file](#4-touching-circuits-the-failure-mode-thats-bitten-us) — the disaster section. |
| A `vault` instruction | `CRYPTOGRAPHY.md` §8 step covering that ix, `programs/vault/src/state.rs` (PDA layout), the litesvm test in `programs/vault/tests/` or `programs/matching_engine/tests/settle.rs`. |
| A `matching_engine` instruction | `programs/matching_engine/tests/common/mod.rs` (the test harness — it's 1500 lines of "what the on-chain ix expects"), then the existing litesvm test for the ix. |
| `crates/darkpool-crypto` | The matching `*-parity.test.ts` file under `packages/sdk/tests/`. **Every host-side primitive has a byte-equality contract with TS.** Break the contract → parity test fails → CI fails. |
| The SDK | The corresponding `tests/*-transport.test.ts` or wire-format unit test. `idl/vault-client.ts` + `idl/matching-engine-client.ts` hand-code every discriminator + Borsh layout (no Anchor IDL runtime) — you must keep them in sync with the on-chain structs by hand. |
| Settlement plumbing | `CRYPTOGRAPHY.md` §9 (size analysis + ALT story). The 1232-byte cap is tight. See [§5 of this file](#5-the-1232-byte-transaction-size-budget). |

---

## 2. The unbreakable build/deploy/validate cycle

Everything in this section runs from the repo root
. The order matters — skipping a
step breaks downstream steps in ways that look unrelated.

### 2.1 One-time host setup (per workstation)

```sh
npm install                                        # SDK + snarkjs + circomlib
bash scripts/download-ptau.sh                      # pot16 (~80 MB) + pot18 (~288 MB)
bash scripts/build-circuits.sh                     # compile all 6 circom circuits;
                                                   #   regenerates vk_*.rs Rust consts
cargo build --examples -p darkpool-crypto          # TS↔Rust parity helper binaries
```

`build-circuits.sh` writes verifier-key Rust consts directly into
`programs/vault/src/zk/vk_*.rs`. If you skip this step the vault
program will fail to compile on a freshly-cloned checkout.

### 2.2 Touched circuit code? Rebuild + commit BOTH artifacts in lockstep

This is the most common foot-gun. See [§4](#4-touching-circuits-the-failure-mode-thats-bitten-us)
for the full rule. Short version:

```sh
bash scripts/build-circuits.sh                     # recompiles .wasm + .zkey + vk_*.rs
git add circuits/<name>/circuit.circom \
        circuits/build/<name>/circuit_final.zkey \
        programs/vault/src/zk/vk_<name>.rs
git commit ...
```

If you commit `circuit.circom` without the new `.zkey` + `vk_*.rs`,
the deployed program will reject every proof made by the new
circuit — and the test failures will look like "Groth16
verification failed" not "you forgot to commit the VK."

### 2.3 Touched on-chain code? Rebuild BPF + redeploy

```sh
# 1. BPF (required for litesvm tests AND for devnet deploy)
cargo build-sbf --manifest-path programs/vault/Cargo.toml
cargo build-sbf --manifest-path programs/matching_engine/Cargo.toml

# 2. Pre-commit gate — Rust workspace, host-side
cargo clippy --workspace --all-targets -- -D warnings   # MUST pass with no warnings
cargo fmt --all -- --check
cargo test --workspace                                  # 80+ tests across crates

# 3. Devnet upgrade (idempotent in place — keeps the same program IDs)
bash scripts/deploy-devnet.sh
```

The `deploy-devnet.sh` script uses your local
`~/.config/solana/id.json` as the upgrade authority + fee payer
(need ≥ 5 SOL on devnet). Devnet program IDs:

* vault: `C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx`
* matching_engine: `6EasFxo6RCWrK4KAwcdUJqL4KjReLC3rtah8EtHgHSqe`

**Never regenerate the program-id keypairs unless you mean to.** If
you do, `declare_id!()` in `programs/{vault,matching_engine}/src/lib.rs`
AND `[programs.localnet]` + `[programs.devnet]` in `Anchor.toml` must
all match — the `consistency` job in `.github/workflows/pr-checks.yml`
will fail if they diverge.

### 2.4 Re-initialise devnet state when the Merkle tree diverges

The on-chain incremental Merkle tree accumulates leaves across every
deposit + settlement. The SDK's in-memory `MerkleShadow` (in
`packages/sdk/tests/helpers/merkle-shadow.ts`) starts empty, so after
a few runs they drift and every `VALID_SPEND` withdraw fails with
`StaleMerkleRoot (6004)`. Cure:

```sh
RUN_DEVNET_E2E=1 \
  ADMIN_KEYPAIR=.devnet/keypairs/admin.json \
  TEE_AUTHORITY_KEYPAIR=.devnet/keypairs/tee_authority.json \
  ROOT_KEY_KEYPAIR=.devnet/keypairs/root_key.json \
  ( cd packages/sdk && ../../node_modules/.bin/vitest run tests/devnet-setup.test.ts )
```

This calls `vault::reset_merkle_tree` under the hood. Also writes
`.devnet/e2e-config.json` (mints, market PDA, ALT pubkey,
protocol config) that every other test reads.

Other symptoms that you need to re-run setup:
* `Allocate: account already in use` on `lock_note` (persona reused
  identical note commitments — `seed_note_lock` collides).
* `OracleUnrecognisedLayout (6063)` (Pyth pull-v2 mock got blown away).

### 2.5 Validate end-to-end

```sh
# Pure-L1 happy path (~50 s)
RUN_DEVNET_E2E=1 FUNDER_KEYPAIR=~/.config/solana/id.json \
  ADMIN_KEYPAIR=.devnet/keypairs/admin.json \
  TEE_AUTHORITY_KEYPAIR=.devnet/keypairs/tee_authority.json \
  ROOT_KEY_KEYPAIR=.devnet/keypairs/root_key.json \
  ( cd packages/sdk && ../../node_modules/.bin/vitest run tests/devnet-trade-flow.test.ts )

# Change-note edge cases (~3 min, 5 scenarios A/B/C/D/E)
RUN_CN_E2E=1 FUNDER_KEYPAIR=~/.config/solana/id.json \
  ADMIN_KEYPAIR=.devnet/keypairs/admin.json \
  TEE_AUTHORITY_KEYPAIR=.devnet/keypairs/tee_authority.json \
  ( cd packages/sdk && ../../node_modules/.bin/vitest run tests/change-note-flow.test.ts )

# Ephemeral-rollup hidden-order path
RUN_ER_E2E=1 FUNDER_KEYPAIR=~/.config/solana/id.json \
  ADMIN_KEYPAIR=.devnet/keypairs/admin.json \
  TEE_AUTHORITY_KEYPAIR=.devnet/keypairs/tee_authority.json \
  ( cd packages/sdk && ../../node_modules/.bin/vitest run tests/er-trade-flow.test.ts )
```

The `USE_BATCHED_PROOF` env var no longer exists — every devnet
test takes the v3.5 batched path unconditionally after Phase
1c-hard.

### 2.6 The "everything green" pre-PR checklist (no devnet needed)

**Run every line below before pushing or opening a PR.** This is the
same set CI runs on every PR via `.github/workflows/pr-checks.yml` —
if it passes here, CI will pass. If you skip any line, CI will
block on something dumb (the most common skip is `cargo fmt`).

```sh
set -e

# 1. Formatter — CI's pr-checks/rust job runs this with -- --check
#    and fails the whole pipeline on a single un-reformatted line.
#    Run WITHOUT --check locally to fix in place; the verify line
#    underneath will exit non-zero if anything was left to do.
cargo fmt --all
cargo fmt --all -- --check

# 2. BPF builds (required by litesvm tests + by deploy)
cargo build-sbf --manifest-path programs/vault/Cargo.toml
cargo build-sbf --manifest-path programs/matching_engine/Cargo.toml

# 3. Host-side example binaries (parity tests shell out to them)
cargo build --examples -p darkpool-crypto

# 4. Clippy — workspace, all targets, no warnings tolerated
cargo clippy --workspace --all-targets -- -D warnings

# 5. Rust tests — workspace unit + litesvm integration
cargo test --workspace

# 6. TS typecheck (separate from vitest — vitest doesn't fail on
#    missing types by default)
./node_modules/.bin/tsc -p packages/sdk/tsconfig.json --noEmit

# 7. SDK suite — devnet/ER/CN tests auto-skip without RUN_* env vars
( cd packages/sdk && ../../node_modules/.bin/vitest run )

echo "ALL GREEN — safe to push"
```

Expected: ~82 Rust workspace tests + 110 SDK tests pass; 17 env-gated
SDK tests skip (they need `RUN_DEVNET_E2E=1` etc. + devnet
connectivity).

#### Pre-PR mini-checklist (read once per PR)

- [ ] `cargo fmt --all` ran and the verify (`-- --check`) is clean
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` is clean
- [ ] `cargo test --workspace` passes
- [ ] `./node_modules/.bin/tsc -p packages/sdk/tsconfig.json --noEmit` passes
- [ ] `vitest run --root packages/sdk` passes (≈ 110 / 17 skipped)
- [ ] If a circom circuit / Poseidon arity / leaf-hash / canonical-hash
      shape changed: see [§4](#4-touching-circuits-the-failure-mode-thats-bitten-us)
      — regenerated zkey + vk_*.rs are committed in the same commit
- [ ] If a settle ix's account list or ix data changed: see
      [§5](#5-the-1232-byte-transaction-size-budget) — measured tx size
      stays under 1232 B including the worst-case change-note variant
- [ ] If a PDA / seed was added: SDK `seeds.ts` + `*Pda()` helpers
      mirror it (§7.3)
- [ ] **If ANY file was deleted (Rust test, circuit, vault ix, SDK
      module): grep for stale references in `.github/workflows/` and
      `scripts/` BEFORE pushing.** See [§2.7](#27-deletion-checklist--things-the-workspace-gate-doesnt-catch).
- [ ] If new files reference cross-doc paths: `find` / read-check
      every referenced path exists
- [ ] Commit signed with `git commit -s` and amended with the
      `Co-Authored-By` trailer (§11)
- [ ] If anything load-bearing changed: gated through
      `/test-devnet --batched` on the PR before merge (§3.7)

### 2.7 Deletion checklist — things the workspace gate doesn't catch

**The single most-likely-to-burn-CI mistake in this repo is deleting
a file and not noticing that something OUTSIDE the cargo/npm file
tree still references it by name.**

`cargo test --workspace` (in §2.6) auto-discovers tests from the
filesystem. It runs whatever exists; it does NOT error on "missing
test target." But `cargo test --test <name>` (which CI uses to
control which tests run per job) errors hard with
`error: no test target named '<name>'`. Same for circom — the local
`scripts/build-circuits.sh` and the CI `scripts/ci-build-circuits.sh`
have their own hard-coded circuit lists. Same for the GitHub
workflow YAMLs that hard-code job-specific test selections.

Whenever you delete a file under `programs/*/tests/`, `circuits/`,
`packages/sdk/tests/helpers/`, or `programs/vault/src/instructions/`,
run this BEFORE pushing:

```sh
# Replace <name> with the deleted file's basename, e.g.
# zk_price_roundtrip, valid_create, verify_valid_create.
NAME=<name>
grep -nE "$NAME" \
    .github/workflows/*.yml \
    .github/workflows/*.yaml \
    scripts/*.sh \
    scripts/*.md \
    || echo "no stale references in CI / scripts"
```

If anything matches, the workflow / script needs updating in the
SAME commit as the deletion. Two real incidents:

* CI Failure #1 (after the Phase 1c-hard commit):
  `scripts/ci-build-circuits.sh` still listed `build_wasm valid_create`
  + `build_wasm valid_price`. `cargo test --workspace` didn't catch
  it because the script lives outside cargo's purview. Fix lived in
  a separate follow-up commit; could have been folded into the
  deletion commit.
* CI Failure #2 (right after):
  `pr-checks.yml`'s `vault-zk` job ran
  `cargo test -p vault --test zk_price_roundtrip` after that test
  file was deleted. Cargo errors with `no test target named …`. Same
  root cause: the workflow YAML wasn't on the deletion radar.

The §2.6 pre-PR gate is necessary but not sufficient. **A deletion
without a CI-reference audit is one CI run away from breaking.**

---

## 3. Test surface — what runs where, when to re-run

This repo has FIVE distinct test surfaces, each catching a different
class of bug. Touching almost any code requires you to figure out
which surfaces will fail and re-run the relevant ones.

### 3.1 Rust workspace unit tests (`cargo test --workspace`)

* **`crates/darkpool-crypto`** — Poseidon round-trips, note
  commitment determinism, nullifier sensitivity, key derivation
  chain, field-element strictness. **If you change a Poseidon
  domain tag, a key-derivation label, or a commitment field order,
  these fail first.**
* **`programs/vault/src/lib.rs`** — `canonical_payload_hash_fixed_vector`
  pins the TEE-signed hash byte-for-byte against a fixture. If
  `MatchResultPayload` field order changes, this fails first.
* `programs/matching_engine/src/lib.rs` — `test_id` smoke + matching
  algorithm unit tests.

Cost: ~10 s. Run on every Rust change.

### 3.2 Rust litesvm integration tests (`cargo test -p {vault,matching_engine}`)

These boot LiteSVM, load the BPF `.so`, and drive end-to-end
scenarios. **Require `cargo build-sbf` to have run first** — they
load `target/deploy/{vault,matching_engine}.so` from disk.

Vault: `programs/vault/tests/`
* `zk_roundtrip.rs` — VALID_WALLET_CREATE: snarkjs prove → on-chain verify
* `zk_spend_roundtrip.rs` — VALID_SPEND end-to-end + Poseidon parity vs circomlib for the Merkle tree
* `zk_price_roundtrip.rs` — v3.1 VALID_PRICE round-trip
* `user_commitment_registration.rs` — `create_wallet` flow with real proof
* `set_protocol_config.rs` — admin-gated fee config + rejection of fee_rate > 10000
* `reset_merkle_tree.rs` — admin tree-reset ix
* `merkle_host.rs` — pure-Rust Merkle invariants (poseidon2, zero-subtree, append)

Matching engine: `programs/matching_engine/tests/`
* `settle.rs` — 15 v3.1 settlement scenarios (exact-fill, partial,
  conservation rejection, fee handling, ed25519 sig checks, …)
* `tee_forced_settle_batched.rs` — **v3.5 regression test (3
  cases). MUST keep passing.** Drives two real matches through one
  shared `BatchValidityMarker` (catches the "close marker after each
  match" class of bug — see [§7.4](#74-batchvaliditymarker-is-1n-do-not-close-it-per-match)).
* `run_batch.rs` — uniform-clearing-price matching, circuit
  breaker, FIFO tie-break, fee accumulator drain
* `submit_order.rs` — order-intent validation (size limits, mint
  binding, side checks)

The shared harness is `programs/matching_engine/tests/common/mod.rs`
— **1700+ lines of helpers**. If you add a new vault ix that needs
to be testable from this harness, add `pub fn build_xxx_ix(...)` +
`pub fn seed_xxx_marker(...)` here following the existing patterns
(see `seed_batch_validity_marker` + `build_settle_batched_ix` for a
recent example). The harness fabricates PDAs via
`litesvm.set_account()` to bypass real Groth16 proofs — that's how
settle-handler behaviour is tested without the snarkjs cost.

Cost: ~30-90 s per test file. Run after any vault / matching_engine
code change.

### 3.3 SDK parity tests (TS ↔ Rust byte equality)

These shell out to the `cargo build --examples -p darkpool-crypto`
binaries via Node's `spawnSync` and compare byte fixtures with the TS
implementation. **They guarantee that the SDK and the host-side Rust
crate agree byte-for-byte on every Poseidon hash, every key
derivation, every commitment.**

| `packages/sdk/tests/*.test.ts` | Pins |
|---|---|
| `poseidon-parity.test.ts` | Poseidon arities 2, 3, 5, 6 + user-commitment shape |
| `keys-parity.test.ts` | spending / viewing / trading / root key derivation + distinctness asserts |
| `user-commitment-parity.test.ts` | Fixed-input + varied-blinding cases |
| `note-commitment-parity.test.ts` | Fixed canonical inputs, witness-sensitivity, amount edges (0, 1, u64::MAX) |
| `nullifier-parity.test.ts` | Fixed sk+commitment, sk/commitment sensitivity |

**If you change a Poseidon hash arity / order / domain tag in EITHER
language, ALWAYS change both, then re-run these tests.**

### 3.4 SDK ZK prover tests (shell out to snarkjs CLI)

* `valid-input-prover.test.ts` — VALID_INPUT proof + negative case
* `valid-create-prover.test.ts` — VALID_CREATE proof + 3 cases (exact-fill, with-change, misroute-rejection where snarkjs correctly fails to satisfy constraints)
* `valid-price-prover.test.ts` — v3.1 VALID_PRICE prover
* `match-batch-prototype.test.ts` — **v3.5 batched circuit, N=2 / N=4 / N=16** + leaf-byte parity vs on-chain `compute_match_leaf`
* `helpers/snarkjs-prover.test.ts` — generic snarkjs-fullprove smoke

These require `bash scripts/build-circuits.sh` to have generated the
`.wasm` + `.zkey` artifacts under `circuits/build/`. Skipped if
artifacts missing (the CI workflow downloads them as artifacts —
they're not committed except for `.zkey`).

### 3.5 SDK unit tests (offline / RPC-free)

These cover ix builders, payload serialisation, ALT pubkey
derivation, batch decoding — the wire-format layer.

| `packages/sdk/tests/*.test.ts` | What it pins |
|---|---|
| `settle-builder.test.ts` | v3.1 `buildSettleIx`: 14-account layout, 448-byte Borsh payload, canonical hash byte-equality vs Rust fixed-vector |
| `settle-builder-batched.test.ts` | **v3.5** `buildSettleBatchedIx` + `buildCloseBatchValidityMarkerIx`: 13-account layout, 585-byte ix.data, Merkle siblings `[[u8;32];4]` encoding, match_index boundary `[0, 15]`, marker PDA derivation |
| `orders-submit.test.ts` | submit_order ix wire format + PER session glue |
| `cancel-order.test.ts` | cancel flow + slot state transitions |
| `batch-watcher.test.ts` + `settlement-watcher.test.ts` | BatchResults ring decode + settle event decoding |
| `inclusion-proof.test.ts` | MatchResult extraction from BatchResults |
| `deposit-transport.test.ts` + `withdraw-transport.test.ts` | deposit / withdraw ix builders |
| `helpers/merkle-shadow.test.ts` | shadow tree empty-root parity + witness shape |

### 3.6 SDK end-to-end tests (env-gated, real devnet)

The big ones. Each runs the full pipeline (deposit → ER match → lock
→ verify → settle → close → withdraw) against the live devnet
deployment. Gated on env vars so they don't run in the default `cargo
test` / `vitest run`:

| `packages/sdk/tests/*.test.ts` | Gate | What |
|---|---|---|
| `devnet-setup.test.ts` | `RUN_DEVNET_E2E=1` | Fresh mints + market + ALT + `reset_merkle_tree`. **Run this first.** Writes `.devnet/e2e-config.json`. |
| `devnet-trade-flow.test.ts` | `RUN_DEVNET_E2E=1` | L1-only happy path |
| `er-trade-flow.test.ts` | `RUN_ER_E2E=1` | ER round-trip via MagicBlock devnet |
| `change-note-flow.test.ts` | `RUN_CN_E2E=1` | 5 cases: change notes, partial fill + re-lock, privacy regression, multi-batch continuation, real protocol-fee withdraw |
| `orders-submit.devnet.test.ts` | `RUN_DEVNET_E2E=1` | submit_order against the real ER RPC |

All four devnet flows always take the v3.5 batched path now —
Phase 1c-hard removed the v3.1 alternative.

### 3.7 CI workflows

| Workflow | Trigger | Gates |
|---|---|---|
| `.github/workflows/pr-checks.yml` | every PR + push to base | Rust workspace tests + clippy + all 6 circuits compile + SDK unit suite + litesvm integration tests (`vault-zk` + `vault-litesvm` + `matching-engine-litesvm`) + program-ID consistency + SBF build |
| `.github/workflows/nightly-devnet.yml` | cron + `/test-devnet` PR comment | Full devnet E2E. Default exercises v3.1; append `--batched` to gate v3.5. `--partial-fill` / `--skip-er` available. |

If your PR touches anything load-bearing (circuit, vault ix, marker
PDA, settle handler, anchor accounts), gate it through
`/test-devnet --batched` before merging.

> **GitHub gotcha — `/test-devnet` silently does nothing unless
> the workflow file is on the repo's *default* branch.** GitHub
> Actions reads `issue_comment` workflows ONLY from the workflow
> file on whatever branch is currently configured as the repo's
> default (Settings → Branches → "Default branch"). It does NOT
> matter which branch the PR is against; it does NOT matter which
> branch the comment came from. Only the default-branch copy of
> the workflow file is loaded for `issue_comment` events. Posting
> `/test-devnet` when that copy is missing yields **no run, no
> error, no log** — looks exactly like the comment was ignored.
>
> **This repo's setup:** PRs route into `nyx-v2-onchain-hardening`
> (the active integration branch), but `main` is preserved as the
> v1 hackathon-submission snapshot. If `main` is still the default
> branch and the workflow file lives only on
> `nyx-v2-onchain-hardening`, every `/test-devnet` comment fails
> silently.
>
> **To verify locally:**
> ```sh
> # What's the default branch on origin?
> git remote show origin | grep 'HEAD branch'
> # Does the default branch have the workflow file?
> git show $(git remote show origin | sed -n 's/^.*HEAD branch: //p'):.github/workflows/nightly-devnet.yml | head -1
> #   → ok if a normal first line prints; failing if you see
> #     `fatal: path '...' exists on disk, but not in '<branch>'`
> ```
>
> **Fix options (pick one):**
>
> 1. **Recommended for this repo:** flip the default branch to
>    `nyx-v2-onchain-hardening` so the workflow file (which
>    already lives there) becomes the one GitHub reads.
>    ```sh
>    gh repo edit Nyx-Privacy/nyx --default-branch nyx-v2-onchain-hardening
>    ```
>    `main` stays intact — it just stops being the default. The
>    workflow's preflight job already handles cross-branch PR
>    head SHAs correctly, so `/test-devnet` on any PR (against
>    any base branch) will check out the PR's head and run.
> 2. **No repo-settings change:** use `workflow_dispatch`. The
>    Actions UI "Run workflow" button (or `gh workflow run`)
>    can fire the workflow against any branch without the
>    default-branch constraint.
>    ```sh
>    gh workflow run nightly-devnet.yml --ref <pr-branch> \
>      -f batched=true -f skip_er=false -f run_partial_fill=false
>    ```
> 3. **If you really want `/test-devnet` from `main`:** land a
>    tiny PR onto `main` containing just
>    `.github/workflows/nightly-devnet.yml`. Heavier-touch but
>    keeps `main` as default.
>
> Documented at <https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows#issue_comment>.

---

## 4. Touching circuits — the failure mode that's bitten us

> A colleague audited / changed circuit code and broke the deployed
> program. This section exists so it doesn't happen again.

### 4.1 The chain that has to stay consistent

A change in any **one** of these requires regenerating the others —
otherwise the deployed program rejects proofs it should accept (and
vice versa):

```
circuits/<name>/circuit.circom              ← source
        │
        │  scripts/build-circuits.sh
        ▼
circuits/build/<name>/circuit.wasm          ← witness generation (TS prover uses this)
circuits/build/<name>/circuit_final.zkey    ← proving key
circuits/build/<name>/verification_key.json ← snarkjs VK json
        │
        │  scripts/parse-vk-to-rust.js
        ▼
programs/vault/src/zk/vk_<name>.rs          ← Rust VK consts compiled into the on-chain verifier
```

If you change `circuit.circom` AND DON'T regenerate `vk_<name>.rs`,
the program compiles fine, but every proof made by the new circuit
fails on-chain because the verifier is still using the old VK. This
fails silently in `cargo build` and only surfaces at runtime as
`InvalidProof (6000)`.

### 4.2 The rule

If you touch ANY of:

* `circuits/<name>/circuit.circom`
* `circuits/templates/*.circom` (parameterised templates — touch one,
  every consumer regenerates)
* `crates/darkpool-crypto/src/poseidon.rs` (anything that changes the
  Poseidon hash arity, the constants, or the absorb order)
* The leaf-hash construction in
  `programs/vault/src/instructions/tee_forced_settle_batched.rs::compute_match_leaf`
  (must stay in lockstep with the circuit's `MatchSlot()` template
  and the TS-side `helpers/match-batch-prover.ts::computeBatchLeaf`)

…you MUST in the same commit:

1. Run `bash scripts/build-circuits.sh` to regenerate `.zkey` +
   `.wasm` + `vk_*.rs`.
2. Run `cargo build-sbf` on both programs (the new VK consts are
   compiled in).
3. Run **all four** of these test suites and verify they pass:
   - `cargo test --workspace` (Rust unit + parity)
   - `cargo test -p vault --test zk_roundtrip --test zk_spend_roundtrip --test zk_price_roundtrip` (on-chain proof verification round-trip)
   - `cargo test -p matching_engine --test tee_forced_settle_batched` (v3.5 marker lifecycle — depends on `compute_match_leaf` byte-stability)
   - SDK prover suites: `vitest run --root packages/sdk tests/valid-*-prover.test.ts tests/match-batch-prototype.test.ts`
4. Commit `circuit.circom` + the regenerated `circuit_final.zkey` +
   the regenerated `vk_*.rs` **together**. Splitting them across
   commits leaves the tree in a state where the program won't
   accept proofs.
5. After merging, run `bash scripts/deploy-devnet.sh` to push the
   new BPF to devnet, then validate via `/test-devnet --batched`.
   Without redeploy, devnet integration tests will fail with
   `InvalidProof`.

### 4.3 v3.5-specific traps

* **Leaf-hash arity cap.** `light-poseidon` (the on-chain
  Poseidon implementation) has `MAX_X5_LEN = 13`, capping
  Poseidon to 12 inputs. The v3.5 leaf hash uses **two stages** —
  Poseidon12 + Poseidon9 — for exactly this reason. Don't refactor
  to a single Poseidon over all slot fields; it would silently
  break on-chain.
* **Domain tags.** `DOMAIN_LEAF_INNER = 20`, `DOMAIN_LEAF_TOP =
  21`, `DOMAIN_BATCH_ROOT = 22`. These appear in three places
  (Rust handler, TS prover helper, circom template) — keep them
  in lockstep.
* **Parameterised N.** The `MatchBatch(N)` template in
  `circuits/templates/match_batch.circom` is instantiated at N=2 /
  4 / 16. Only N=16 is wired on-chain (`vk_match_batch_n16.rs`); N=2
  and N=4 are dev/test instances for `match-batch-prototype.test.ts`.
  If you add a new N, you also need a new instantiation circuit + a
  new VK consts file + an on-chain ix referencing it. Don't.
* **PTAU file.** N=16 needs `pot18` (~288 MB). `scripts/download-ptau.sh`
  fetches both pot16 and pot18 — don't manually edit it to skip pot18.

---

## 5. The 1232-byte transaction-size budget

Solana caps a single tx at 1232 bytes. Several of our flows are
right at the edge:

| Tx | Size | Headroom |
|---|---|---|
| lock_note ×2 (Tx A) | ~1050 B | ~180 B |
| verify_match_batch (Tx B) | ~640 B | comfortable |
| per-batch ALT create+extend (Tx C) | ~250 B | comfortable |
| tee_forced_settle_batched (Tx D, v0 + 2 ALTs) | ~1130 B | **~100 B** |
| close_batch_validity_marker (Tx E, once per batch) | ~250 B | comfortable |

Anything that adds bytes to the settle path — a new account, an
extra ix parameter, a longer payload field — risks pushing the
tx over the cap.

### 5.1 Rules to avoid blowing the cap

* **Read `CRYPTOGRAPHY.md` §9 before changing any settle ix's
  accounts or data.** It has the byte-level breakdown.
* **Static accounts go in the settle ALT.** Created once at
  devnet-setup time and stored in `.devnet/e2e-config.json` as
  `settleLookupTable`. Candidates: anything that's the same across
  all settles + non-signer (signers can't be ALT'd). Currently
  hoisted: `vault_config`, `instructions_sysvar`, `system_program`.
* **v3.5 per-batch ALT.** `settleViaBatched` creates a per-batch
  ALT holding 5 derivable PDAs that vary per-match but are
  derivable from the payload alone (`note_lock_a/b/e/f` +
  `batch_validity_marker`). Saves ~155 B per settle. Don't refactor
  the helper to land these inline.
* **`createLookupTable` `recentSlot` gotcha.** Must come from
  `getLatestBlockhashAndContext().context.slot`, NOT
  `getSlot("confirmed")`. The latter can return a leader-skipped
  slot which the runtime rejects as "is not a recent slot". The
  v3.5 helper got bitten by this; the fix is committed.
* **VersionedTransaction + ALT mechanics.** ALT deactivation has
  a 512-slot (~3.5 min) cooldown. For production matchers running
  multiple batches per minute, plan a rolling-ALT pool — see
  `docs/v3.5-migration.md` for the analysis.
* **Lock_note's account-key dedup.** In exact-fill paths,
  `note_lock_e` and `note_lock_f` derive from `[0;32]` and
  therefore collide on the same PDA. The legacy tx encoder dedups
  to one slot in the keys list, saving 32 bytes. The MOMENT a
  change-note is non-zero, the dedup disappears and the tx grows.
  **Don't assume an exact-fill tx size generalises.** Test with
  `change-note-flow.test.ts` Test B (the largest variant) when
  changing settle-tx contents.

---

## 6. Cross-language byte-equality contracts

This is the most fragile invariant in the repo. **The SDK and the
on-chain code MUST agree byte-for-byte on every cryptographic
primitive.** If they don't, the canonical-payload-hash signature
verification fails, or the binding-hash marker check fails, or
proofs don't verify.

### 6.1 What's pinned

| Contract | Rust side | TS side | Pinned by |
|---|---|---|---|
| Poseidon arities | `crates/darkpool-crypto/src/poseidon.rs` | `packages/sdk/src/zk/poseidon.ts` | `poseidon-parity.test.ts` |
| Note commitment | `crates/darkpool-crypto/src/note.rs` | `packages/sdk/src/utxo/note.ts` | `note-commitment-parity.test.ts` |
| Nullifier | `crates/darkpool-crypto/src/nullifier.rs` | `packages/sdk/src/utxo/nullifier.ts` | `nullifier-parity.test.ts` |
| Key derivation chain | `crates/darkpool-crypto/src/keys.rs` | `packages/sdk/src/keys/key-generators.ts` | `keys-parity.test.ts` |
| User commitment | `crates/darkpool-crypto/src/user_commitment.rs` | `packages/sdk/src/keys/user-commitment.ts` | `user-commitment-parity.test.ts` |
| Canonical payload hash | `programs/vault/src/instructions/tee_forced_settle.rs::canonical_payload_hash` (shared file, NOT a v3.1-only handler — see §10) | `packages/sdk/src/settlement/settle-builder.ts::canonicalPayloadHash` | `tests::canonical_payload_hash_fixed_vector` (Rust unit) + `settle-builder-batched.test.ts` (TS) |
| Match leaf hash (v3.5) | `programs/vault/src/instructions/tee_forced_settle_batched.rs::compute_match_leaf` (`pub fn`) | `packages/sdk/tests/helpers/match-batch-prover.ts::computeBatchLeaf` | `match-batch-prototype.test.ts` includes a leaf-byte parity assert |
| MatchResultPayload Borsh shape | `vault::instructions::tee_forced_settle::MatchResultPayload` (24 fields, 448 bytes) | `packages/sdk/src/settlement/settle-builder.ts::serializePayload` | `settle-builder-batched.test.ts::settle_batched_payload_relock_passthrough` |
| Anchor discriminator (`sha256("global:<name>")[..8]`) | derived by Anchor macros from the fn name | `packages/sdk/src/idl/vault-client.ts::anchorDiscriminator` | every `*-transport.test.ts` |

### 6.2 BN254 Fr safety (the silent killer)

Every value Poseidon-hashes MUST fit in BN254 Fr (top byte ≤ 0x30).
Raw `[0xFFu8; 32]` will pass through almost everything in this codebase
WITHOUT triggering an obvious error, but **light-poseidon's
`hash_bytes_be` fails on values ≥ the modulus**, surfacing as
`PoseidonFailed (6030)` or `InvalidBatchBinding`.

Rules:

* **Note commitments fed to Poseidon must be Fr-safe.** Test
  fixtures should use `fr_safe(seed, salt)` (defined in
  `programs/matching_engine/tests/common/mod.rs`) for any 32-byte
  field that gets hashed.
* **Mint pubkeys are split into two 128-bit halves (lo, hi)** for
  this exact reason — a 256-bit pubkey can't fit in one Fr element.
  See `darkpool-crypto::field::pubkey_to_fr_pair` and the matching
  TS function.
* **Owner commitments** are guaranteed safe because they're already
  Poseidon outputs (Poseidon2(spending_key, r_owner)).
* **Nullifiers** are Poseidon outputs too — Fr-safe by construction.

The v3.5 regression test (`tee_forced_settle_batched.rs`) initially
failed because the test fixtures used raw `[0xA0u8; 32]` for
`note_a` / `note_b` — fine for the v3.1 path (which only uses these
as PDA seeds) but rejected by the v3.5 `compute_match_leaf`. The
fix was to switch to `fr_safe(0xA0, 0x01)` etc. Don't repeat this.

---

## 7. Marker / PDA lifecycle conventions

### 7.1 Per-leaf PDAs are the replay-protection backbone

Every note that gets touched produces a PDA whose existence locks
out a second touch:

* `WalletEntry` — registered user commitment
* `NullifierEntry` — VALID_SPEND-consumed note
* `ConsumedNoteEntry` — TEE-settle-consumed note
* `NoteLock` — TEE pin between match and settle

The `init` constraint on these PDAs is the actual replay guard.
**Don't change the `init` to `init_if_needed` without thinking
about replay** — it silently allows replays.

### 7.2 Validity markers are 1:1 in v3.1 and 1:N in v3.5

* `ValidCreateMarker` (v3) — seeded by binding hash. 1:1 with the
  match. Closed by `tee_forced_settle`.
* `ValidPriceMarker` (v3.1) — seeded by price commitment. 1:1.
  Closed by `tee_forced_settle`.
* `BatchValidityMarker` (v3.5) — seeded by **batch Merkle root**.
  **1:N** — one PDA covers all matches in the batch. Closed by
  `close_batch_validity_marker`, NOT by per-match settles.

### 7.3 SDK seed constants are wire-mirrored from Rust

`packages/sdk/src/idl/seeds.ts` hand-mirrors every `SEED` byte
literal in `programs/vault/src/state.rs`. If you add a new PDA in
Rust, **you must** add the matching seed const to `seeds.ts` AND
a `xxxPda()` helper to `packages/sdk/src/idl/vault-client.ts`.
The CI doesn't catch this — only the integration tests do, and
only when they fail with "AccountNotFound" or
"ConstraintSeeds (2006)".

### 7.4 `BatchValidityMarker` is 1:N. Do NOT close it per-match.

The v3.5 carry-over of "close the marker at the end of settle"
worked for the 1:1 v3.1 markers but breaks the 1:N v3.5 marker —
closing it after match 0 bricks every subsequent match in the
same batch. The bug was caught by an external PR-reviewer; the
fix lives in `tee_forced_settle_batched.rs` (the marker is
deliberately left open) + a separate `close_batch_validity_marker`
ix for rent reclaim.

If you see `try_borrow_mut_lamports` against
`batch_validity_marker` in `tee_forced_settle_batched.rs`, you
have re-introduced the bug. The litesvm regression test
(`test_two_matches_share_one_marker`) will fail.

The doc comment on the account itself (`tee_forced_settle_batched.rs::TeeForcedSettleBatched`)
spells out the rule. Don't remove it.

---

## 8. Common pitfalls + their failure signatures

| You did | Failure surface | Fix |
|---|---|---|
| Committed without running `cargo fmt` | pr-checks `rust` job fails immediately at `cargo fmt --all -- --check` | Run `cargo fmt --all` locally, commit the diff. See [§2.6 pre-PR checklist](#26-the-everything-green-pre-pr-checklist-no-devnet-needed) — this is exactly what that gate exists to catch |
| Deleted a Rust test file (`programs/*/tests/<name>.rs`) | pr-checks fails at `cargo test -p <crate> --test <name>` with `error: no test target named '<name>'`. Local `cargo test --workspace` did NOT catch this. | Grep the workflow YAMLs for the deleted basename + remove the `--test <name>` line in the same commit. See [§2.7](#27-deletion-checklist--things-the-workspace-gate-doesnt-catch) |
| Deleted a circom circuit | pr-checks `circuits` job fails at `scripts/ci-build-circuits.sh` with `Input file does not exist: …/circuit.circom`. Local `cargo test` / `vitest run` did NOT catch this because the script lives outside cargo/npm. | Update BOTH `scripts/build-circuits.sh` (local dev) AND `scripts/ci-build-circuits.sh` (CI, wasm-only) — they have separate hard-coded circuit lists. See [§2.7](#27-deletion-checklist--things-the-workspace-gate-doesnt-catch) |
| Changed a Poseidon arity / domain tag in Rust only | Parity test fails (`poseidon-parity.test.ts`) | Mirror the change in `packages/sdk/src/zk/poseidon.ts` |
| Changed a Poseidon arity / domain tag in TS only | Devnet flow fails with `InvalidProof` or `InvalidBatchBinding` | Mirror the change in `crates/darkpool-crypto/src/poseidon.rs` AND in any on-chain handler that hashes these inputs |
| Changed a circom circuit | Devnet flow fails with `InvalidProof (6000)` | Re-run `bash scripts/build-circuits.sh`; commit the regenerated `.zkey` + `vk_*.rs` in the same commit; redeploy |
| Bumped `MatchResultPayload` field order | `canonical_payload_hash_fixed_vector` Rust unit fails | Mirror the change in TS `serializePayload` + recompute the fixed-vector hash and update both |
| Added a vault PDA without updating the SDK | Integration test fails with `AccountNotFound` or `ConstraintSeeds (2006)` | Add the SEED const + the `xxxPda()` helper to the SDK; update every `build*Ix` that needs the PDA in its account list |
| Changed an account list order in a vault ix | Test fails with `ConstraintSeeds` or `AnchorError` | Update the matching `build*Ix` in `packages/sdk/src/idl/vault-client.ts` — accounts are positional |
| Added an account to a settle ix without expanding the ALT | Tx size exceeds 1232 — `TransactionTooLarge` | Add the account to `settleLookupTable` (static) or the per-batch ALT (derivable); re-run devnet-setup to pick up the new static ALT |
| Used `getSlot("confirmed")` for ALT `recentSlot` | Intermittent `InvalidInstructionData` ("is not a recent slot") | Switch to `getLatestBlockhashAndContext().context.slot` |
| Used raw `[0xA0u8; 32]` for a Poseidon-hashed commitment | `PoseidonFailed (6030)` or `InvalidBatchBinding` | Use `fr_safe(seed, salt)` (test harness) or any Poseidon output |
| Forgot to re-run `devnet-setup.test.ts` after a tree wipe | `StaleMerkleRoot (6004)` on first withdraw | See §2.4 |
| Re-ran a devnet test back-to-back with the same persona | `Allocate: account already in use` on lock_note | Delete the persona keypair under `.devnet/keypairs/` (e.g. `alice-cn-payer.json`) or re-run setup |
| Closed `BatchValidityMarker` in `tee_forced_settle_batched` | `test_two_matches_share_one_marker` fails; multi-match batches break | See [§7.4](#74-batchvaliditymarker-is-1n-do-not-close-it-per-match) |

A longer error catalogue lives in
[`scripts/dev-commands.md` §12](scripts/dev-commands.md#12-troubleshooting-common-failures).

---

## 9. Working with the SDK tests

`packages/sdk/tests/` houses 110 passing tests + 17 env-gated. The
naming convention:

* `*-parity.test.ts` — TS↔Rust byte equality (Poseidon, keys,
  commitments, nullifier). Run on every code change.
* `*-prover.test.ts` — snarkjs round-trips for each circuit. Need
  built circuit artifacts.
* `*-transport.test.ts` — wire-format unit tests for ix builders.
* `*-builder.test.ts` — discriminator + Borsh layout for settle ixs.
* `*-watcher.test.ts` — event / batch decoding.
* `helpers/` — utilities shared across tests:
  - `e2e-helpers.ts` — keypair loaders, env helpers, byte conv
  - `merkle-shadow.ts` — in-memory tree mirror
  - `match-batch-prover.ts` — v3.5 batched Groth16 helper
  - `valid-{input,create,price}-prover.ts` — per-circuit prover wrappers
  - `verify-valid-price.ts`, `verify-match-batch.ts` — land-the-verify-tx helpers
  - `batched-settle.ts` — **v3.5 5-step `settleViaBatched` helper** (verify_match_batch → Merkle path → per-batch ALT → settle_batched → close) + the production-shape sibling `settleBatchViaBatched` that takes N≤16 matches and fires the settles concurrently. Existing tests use the single-match form; the multi-match form is dormant until a production matcher imports it (see dev-commands.md §11B.6).
  - `settle-v0.ts` — v0 tx sender that stacks ALTs
  - `snarkjs-prover.ts` — shell-out to `node_modules/.bin/snarkjs`
* `devnet-*.test.ts` / `er-*.test.ts` / `change-note-*.test.ts` —
  env-gated devnet flows. Add new e2e scenarios here using the
  existing harness, not in isolation.

When adding a new test:

1. If it's wire-format (ix builder, payload shape), follow the
   `*-transport` / `*-builder` pattern — no network, fast.
2. If it's prover-related, add a `helpers/<name>-prover.ts` (if it
   doesn't exist) + a `<name>-prover.test.ts`.
3. If it's a devnet flow, drive the settle through
   `settleViaBatched(...)` (one real match) or
   `settleBatchViaBatched(...)` (≤ 16 real matches per batch). See
   `devnet-trade-flow.test.ts` for the canonical pattern. There's
   no longer an environment toggle — v3.5 is the only path.

---

## 10. Phase 1c-hard cutover — DONE; v3.5 is the only settle path

The soft-cutover rule that used to live here ("do not remove the
v3.1 path") was retired when Phase 1c-hard landed. v3.5 is now the
only on-chain settle path. The following are GONE — do not try to
re-import them, do not write code that assumes they exist:

* Vault ixs: `verify_valid_create`, `verify_valid_price`,
  `tee_forced_settle` (the v3.1 per-match one). `tee_forced_settle.rs`
  still exists as a SHARED file holding `MatchResultPayload`,
  `canonical_payload_hash`, `verify_tee_signature`,
  `create_relock_pda`, and `TradeSettled` — these are reused by
  `tee_forced_settle_batched`.
* Vault state: `ValidCreateMarker`, `ValidPriceMarker`,
  `MAX_CREATE_MARKER_TTL_SLOTS`, `MAX_PRICE_MARKER_TTL_SLOTS`.
* Vault VK consts: `vk_valid_create.rs`, `vk_valid_price.rs`.
* Circuits: `circuits/valid_create/`, `circuits/valid_price/`.
* SDK builders: `buildSettleIx`, `buildVerifyValidCreateInstruction`,
  `buildVerifyValidPriceInstruction`, `validCreateMarkerPda`,
  `validPriceMarkerPda`, `validCreateBindingHash`.
* SDK helper-test files: `tests/helpers/valid-create-prover.ts`,
  `tests/helpers/valid-price-prover.ts`,
  `tests/helpers/verify-valid-price.ts`.
* SDK test files: `tests/settle-builder.test.ts` (12 v3.1
  wire-format tests), `tests/valid-create-prover.test.ts` (3 v3.1
  prover tests).
* The `USE_BATCHED_PROOF` env-var gate — every devnet test now
  takes the batched path unconditionally. `nightly-devnet.yml`
  still has a `batched` workflow input + `--batched` PR-comment
  flag, but they're vestigial and can be removed when the workflow
  is next touched.

What remains shared by the batched path (so don't try to "clean
these up" either):

* `MatchResultPayload` Borsh struct + `canonical_payload_hash` —
  identical to v3.1 by design (the TEE signature format didn't
  change).
* `create_relock_pda` — called by `tee_forced_settle_batched` to
  allocate fresh `NoteLock` PDAs for change notes.
* The static settle ALT created at devnet-setup time (`vault_config`,
  `instructions_sysvar`, `system_program`). Still needed; v3.5
  stacks a per-batch ALT on top.

---

## 11. Committing

Every commit on this branch must use `git commit -s` so both
trailers appear:

```
Signed-off-by: arnabnandikgp <arnabnandi2002@gmail.com>
Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
```

`git commit -s` adds the `Signed-off-by` automatically (from
`user.email`). The `Co-Authored-By` line is added via
`git commit --amend --no-edit --trailer "Co-Authored-By: ..."`
immediately after the initial commit, since git's `-s` doesn't
emit it.

Commit message style (look at recent commits for examples):

* Subject: `<type>(<scope>): <imperative summary>` — e.g.
  `feat(vault,v3.5): close_batch_validity_marker ix + multi-match regression test`.
* Body: explain the **why** (constraint, prior incident, design
  tradeoff), not the **what** (the diff is the what).
* Bullet specific files / line numbers when calling out concrete
  changes.
* If validation was performed, list the commands you ran and what
  passed.

**Never commit:**

* `.devnet/keypairs/*.json` (gitignored — these hold real devnet
  SOL).
* `.devnet/e2e-config.json` (gitignored — environment-specific).
* Anything under `target/`, `node_modules/`, `circuits/build/`
  except `circuit_final.zkey` (gitignored — generated).
* `verification_key.json` files (gitignored — the canonical form is
  `vk_*.rs`).

**Never push to main without explicit user direction.** The branch
is `nyx-v2-onchain-hardening`; merges to `main` are a separate
decision.

---

## 12. When in doubt

1. Re-read [§4](#4-touching-circuits-the-failure-mode-thats-bitten-us)
   if you're touching anything ZK-adjacent.
2. Re-read [§5](#5-the-1232-byte-transaction-size-budget) if you're
   adding to the settle ix's account list or ix data.
3. Re-read [§6](#6-cross-language-byte-equality-contracts) if you're
   touching cryptography in EITHER language.
4. Re-read [§7](#7-marker--pda-lifecycle-conventions) if you're
   touching marker PDAs or the settle handler.
5. Ask the user before:
   - Regenerating program-ID keypairs
   - Deleting v3.1 ixs / VK consts / SDK builders
   - Force-pushing or rewriting committed history
   - Running anything against mainnet (this repo is devnet-only as
     of now)
   - Modifying CI workflows in a way that loosens gates

Run the [§2.6 "everything green" pre-commit gate](#26-the-everything-green-pre-commit-gate-no-devnet-needed)
before every commit. If it doesn't pass, don't commit.

---

*Last updated: 2026-05-23 — covers v3.5 batched-validity migration
(VALID_MATCH_BATCH, `tee_forced_settle_batched`,
`close_batch_validity_marker`, per-batch ALT pattern, multi-match
regression test). Snapshot of `nyx-v2-onchain-hardening`.*
