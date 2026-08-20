# Anchor v2-rc.1 migration — Step 0 recon inventory

Branch `experiment/anchor-v2-rc1`, developed in a separate git worktree so the
port never disturbs the main checkout.
Written before any edit, per the migration guide §12 Step 0.

Baseline: **anchor-lang / anchor-spl 1.1.2**, solana-program 3, one program crate.
(CLAUDE.md §0 still says "Anchor 0.32" — stale, corrected here.)

---

## 1. Program crates

One: `programs/vault`. `crate-type = ["cdylib", "lib"]`, so integration tests can
import `vault::ID` — see §5.

There is no second on-chain program.

---

## 2. `#[account]` structs — all nine

| Struct | v1 form | Fields | v2 target |
|---|---|---|---|
| `VaultConfig` | `zero_copy` | Pubkey, [Pubkey; K], Pubkey, [[u8;32]; D], [u8;32], u16, u8×3, `_padding:[u8;3]` | `#[account]` |
| `MerkleTree` | `zero_copy` | fixed | `#[account]` |
| `WalletEntry` | `zero_copy` | fixed | `#[account]` |
| `DepositedNoteEntry` | `zero_copy` | fixed | `#[account]` |
| `ConsumedNoteEntry` | `zero_copy` | fixed | `#[account]` |
| `NoteLock` | `zero_copy` | fixed | `#[account]` |
| `MarketConfig` | borsh | Pubkey×2, u64×4, u8×2, bool, u8 | `#[account]` (Pod) |
| `OutstandingMint` | borsh | Pubkey, u64, u8 | `#[account]` (Pod) |
| `BatchValidityMarker` | borsh | Pubkey, u64, u8 | `#[account]` (Pod) |

**The headline finding: no account struct contains `Vec`, `String`, or `Option`.**
Every field is a fixed-size scalar or a fixed-size array.

Two consequences, both large:

1. **No struct needs `BorshAccount<T>`.** All nine become zero-copy `Account<T>`,
   which is where the guide says the CU savings live (§4.3).
2. **The on-wire layout should not change.** Guide §9.2: for fixed-size scalar
   fields in unchanged order, borsh and alignment-1 `repr(C)` are byte-identical.
   `u64 → PodU64` and `bool → PodBool` are both same-width LE. So the hand-rolled
   TS/Rust decoders should keep working untouched.

`VaultConfig` already carries an explicit `_padding: [u8; 3]` tail with the comment
"so the zero-copy struct has no implicit padding" — exactly what v2's no-padding
assertion wants (guide §5.4). The six already-`zero_copy` structs are therefore
expected to satisfy the assertion as-is.

**This does not make the migration safe by inspection.** Guide §13: a Pod cast makes
wrong-but-well-formed bytes decode into a valid-looking struct. Every one of these
nine claims must be asserted by a byte-layout test (§6 below), not assumed.

`#[account(zero_copy)]` → `#[account]` and `AccountLoader<'info,T>` → `Account<T>`
(32 references). The `.load()?` / `.load_mut()?` calls at those sites all disappear.

---

## 3. Instruction surface

- **20 `#[derive(Accounts)]` structs** across 19 files in `programs/vault/src/instructions/`.
- **4 `has_one`** usages — deprecated in v2, become `address = parent.field`.
  Guide §7.2: this can force a field reorder, and a reorder changes the client's
  required `keys` order. Any reorder must be recorded and mirrored in
  `packages/sdk/src/idl/vault-client.ts`.
- **4 CPIs**, all SPL `transfer_checked`: `deposit`, `withdraw`, `merge`,
  `tee_forced_settle`. All operate on `Account<TokenAccount>`, which per guide §6.2
  does **not** need `release_borrow()` / `reacquire_borrow_mut()` — that is a
  `BorshAccount` requirement only.
  - Note `deposit.rs:156` re-reads the SPL account after the CPI ("because the
    `transfer_checked` CPI mutated it"). Under zero-copy that re-read may be
    redundant, but changing it is a correctness question — verify, don't assume.
- **0 optional accounts.** So the known `2.0.0-rc.1` duplicate-mutable defect with
  two-or-more omitted optionals (guide §7.4) **does not apply to this program**.
  No test needed for it; record the reason.
- **Duplicate-mutable (§7.3)**: v2 rejects aliased `mut` slots by default. The settle
  path passes many PDAs; `lock_note` deliberately dedups `note_lock_e`/`note_lock_f`
  to the same PDA in exact-fill paths (CLAUDE.md §6). **That dedup is on the client
  side (one account meta), not two mut slots** — but it must be checked, because if
  any ix does receive one account in two `mut` slots it now fails at runtime.

---

## 4. Error codes — must preserve

`#[error_code]` with the **default 6000 offset**. The client decodes `Custom(u32)`
numerically and the codes are load-bearing across docs and tests:
`InvalidProof (6000)`, `StaleMerkleRoot (6004)`, `PoseidonFailed (6030)`.

Guide §11.1: v2 has **no runtime `AnchorError`** — `#[msg(...)]` becomes IDL-only
metadata and this project has no IDL, so on-chain the client sees only the numeric
code. Preserve the offset and the variant **ordering**; adding or reordering a
variant silently renumbers everything after it.

---

## 5. Program-id surface (the de-hardcoding work)

~40 literal occurrences of `C63vKvys…`. Already parameterized, no work needed:

- `packages/sdk/src/idl/vault-client.ts` — `programId` is an argument throughout.
- `scripts/reset-merkle-tree.mjs`, `close-vault-config.mjs`, `run-indexer-local.sh`
  — already `process.env.VAULT_PROGRAM_ID ?? <default>`.

Needs changing:

| Where | n | Action |
|---|---|---|
| `programs/vault/src/lib.rs::declare_id!` + `Anchor.toml` ×2 | 3 | New id on this branch; the `consistency` CI job enforces parity |
| `crates/darknyx-tee/src/settle/vault.rs` | 1 | `vault_program_id()` is a single chokepoint — env override behind `OnceLock` |
| `crates/darknyx-tee-loadgen/src/real_settle/vault.rs` | 1 | Same |
| `rotate-tee-pubkey.mjs`, `set-matching-config.mjs` | 2 | Add the env override the sibling scripts already have |
| litesvm test consts (5 files + `settle_harness/mod.rs`) | 6 | **Use `vault::ID`, not a literal** |

The test constants are the real modularity win. `settle_harness/mod.rs:158` does
`svm.add_program_from_file(vault_id, &vault_so)` against a hand-copied literal;
change `declare_id!` without it and all 11 settle-path tests fail at once with
`DeclaredProgramIdMismatch`. Importing `vault::ID` makes them track automatically.

**The TEE's program id being a compile-time `const` is what gates the CVM test
tier** — without the env override you cannot point a CVM at the experimental
program without rebuilding the image.

Docs (`README`, `CLAUDE.md`, `CRYPTOGRAPHY.md`, `ARCHITECTURE.md`, openapi) and
`audits/**` trackers also carry the literal. Audit trackers are immutable
point-in-time records — **do not edit them**.

---

## 6. Test surface to re-run after migration

The program is the core of the protocol, so the whole tree runs, in tiers:

**Tier 1 — offline (must be green before anything else)**
- `cargo nextest run --workspace`, including all **16** `programs/vault/tests/*.rs`
  targets. CI hard-codes these in **two separate lists** in `pr-checks.yml`
  (5 in the ZK job, 11 in the LiteSVM job) — both must stay complete.
- The rest of the CLAUDE.md §2.5 gate: fmt, clippy `-D warnings`, SBF build,
  the guard scripts, three `tsc` test-configs, three vitest packages.
- **New, required by guide §13:** a byte-layout assertion per account struct.
  `account_layout_fixture.rs` already exists — extend it to all nine.

**Tier 2 — artifact-required**
- `REQUIRE_CIRCUIT_ARTIFACTS=1 cargo nextest run -p darknyx-tee --tests`

**Tier 3 — devnet, no CVM**
- Fresh foundation under the new program id (`devnet-setup`), then
  `devnet-deposit-withdraw`, `devnet-merge`, `devnet-leaf-index`.

**Tier 4 — second CVM** (user-chosen scope)
- `cvm-api-surface`, `cvm-settle-e2e`, `cvm-self-trade`, `cvm-multimatch-settle`,
  `cvm-merge-then-order`, `cvm-attestation-e2e`, `cvm-ratls-transport`,
  `cvm-daemon-lifecycle`.

**A new program id means a fresh devnet foundation**, not a tree reset: every PDA
is program-derived, so `VaultConfig`, the K `MerkleTree` shards, and the settle ALT
are all new, producing a new `.devnet/e2e-config.json`.

---

## 7. Measurement — what the experiment is actually for

Binary size is easy: `.so` size before/after.

**Per-instruction CU is not currently measurable.** Only three tests assert CU at
all — `deposit_with_proof` (gate const), `match_batch_verify` (<115k),
`tee_forced_settle_batched` (<85k). There is no systematic report. Building a
harness that records `meta.compute_units_consumed` for every instruction on both
branches is part of this experiment, and it must run on **v1 first** to produce the
baseline — a v2-only number compares against nothing.

---

## 8. Open items requiring a decision

1. **Second CVM provisioning** — billable, needs the owner's Phala account.
2. **`anchor-cli` bump** — guide §1.5 warns `cargo install anchor-cli --version
   2.0.0-rc.1` overwrites the `anchor` binary on PATH including an AVM-managed one.
   Confirm before running. (Note the repo builds with `cargo build-sbf`, not
   `anchor build`, so a CLI bump may not be needed at all — verify.)
3. **Worktree disk** — a second `target/` for this branch; the main one already
   reaches ~28 GB.
