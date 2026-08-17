# Anchor v1 baseline — measured BEFORE the v2 migration

Branch `experiment/anchor-v2-rc1`, measured at `origin/main` (`29c9b12`) with the
Anchor **1.1.2** dependency set untouched. This is the control arm of the
experiment; the v2 arm must be measured with the *same* instrumentation, on the
same machine, or the comparison is meaningless.

## Toolchain

| | |
|---|---|
| solana-cli | v3.1.12 (matches `pr-checks.yml::SOLANA_CLI_VERSION`) |
| platform-tools | v1.52 |
| SBF rustc | 1.89.0 |
| host rustc | 1.91.0 (`rust-toolchain.toml`) |
| anchor-lang / anchor-spl | 1.1.2 |

The machine was previously on solana-cli 2.1.0 (platform-tools v1.43, rustc
1.79.0), which **cannot build this workspace at all** — `anchor-syn 1.1.2` pulls
`sha2 0.11.0`, which requires `edition2024` (stabilized in Rust 1.85). Upgraded
to match CI.

## Binary size

| Artifact | Bytes | KB |
|---|---|---|
| `target/deploy/vault.so` (features=`devnet-admin`) | **598,272** | 584 |

Fingerprint `90bbb9e1a65c430d1009539ba5ffc4315dc4c368385d0f37b8d40cacb65412e7`.

Built with `bash scripts/build-vault-sbf.sh devnet-admin`, **not** a bare
`cargo build-sbf` — the bare form exits 0 while producing no binary (it did so
twice during setup). The script's `test -f "$SO" || exit 1` is the only thing
that fails closed.

## Compute units (litesvm)

| Instruction | v1 CU |
|---|---|
| `deposit` (VALID_DEPOSIT proof) | 154,645 |
| `merge` (VALID_MERGE k=2) | 150,237 |
| `withdraw` (VALID_SPEND proof) | 147,868 |
| `verify_match_batch` (N=16) | 101,823 |
| `tee_forced_settle_batched` (6-leaf + 2-relock, worst case) | 79,677 |
| `tee_forced_settle_batched` (2-leaf) | 64,462 |
| `close_batch_validity_marker` | 4,260 |

Reproduce:

```sh
cargo test -p vault \
  --test match_batch_verify --test tee_forced_settle_batched \
  --test deposit_with_proof --test withdraw_lock_lifecycle --test merge_verify \
  -- --nocapture 2>&1 | grep CU_PROFILE
```

### Caveats — read before quoting these numbers

1. **litesvm, not on-chain.** These are the local VM's accounting. They are the
   right basis for a v1-vs-v2 A/B, but they are not a mainnet CU quote.
2. **Single sample each.** litesvm CU is deterministic for a fixed input, so
   repetition adds nothing — but these are *specific* inputs (one batch shape,
   one merge arity), not a distribution.
3. **The three proof-verifying instructions dominate**, and their cost is mostly
   Groth16 verification inside `groth16-solana`, which Anchor does not touch.
   Expect v2's savings to land on the *account validation and (de)serialization*
   fraction, not the pairing check. A large headline speedup on `deposit` would
   be surprising and worth distrusting.
4. `close_batch_validity_marker` at 4,260 CU is nearly pure Anchor overhead —
   almost no program logic. **It is the cleanest single read on what v2's account
   model actually buys**, and the best sanity check that the migration did what
   the guide claims.

## Instrumentation

Four `CU_PROFILE <name> consumed=<n>` markers already existed
(`verify_match_batch`, both settle shapes, `close_batch_validity_marker`). Three
were added on this branch following the same convention, deliberately *before*
any dependency change so both arms are measured identically:

- `deposit_with_proof.rs` — `deposit`
- `withdraw_lock_lifecycle.rs` — `withdraw`
- `merge_verify.rs` — `merge_k2`

## Worktree provisioning (not obvious, cost real time)

`git worktree add` copies **tracked files only**. Everything gitignored was
absent and had to be provisioned:

| Missing | Symptom | Resolution |
|---|---|---|
| `third_party/*` submodules | `cargo metadata` failed on `icicle-snark` | `git submodule update --init --recursive` |
| `node_modules` | `snarkjs missing — run npm install` | symlinked from the main checkout |
| `circuits/build/*/circuit_js` | proof-backed tests failed | symlinked per-circuit from the main checkout |

The nine `circuit_final.zkey` files ARE tracked and came across with the branch;
only the gitignored `circuit_js/` witness generators needed linking. Sharing them
read-only is safe here because this experiment does not touch circuits — if that
ever changes, the symlinks must become copies or main's artifacts get mutated.
