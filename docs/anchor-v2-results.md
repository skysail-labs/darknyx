# Anchor v1 → v2-rc.1: port completion record

Branch `experiment/anchor-v2-rc1`, split into the stacked PRs #169 → #170 →
#171 → #172 → #174 → #175.

Validated on devnet under program
`DtSR7WELiAJMSMsPSLmDmA9ai5Q4715vooH8vderTvX7`, deliberately separate from
production `C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx` so nothing here
touched live state.

---

## 1. Results

### Binary

| | v1 (anchor 1.1.2) | v2 (2.0.0-rc.1) | Δ |
|---|---|---|---|
| `vault.so` (devnet-admin) | 598,272 B | **278,504 B** | **−53.4%** |
| `vault.so` (mainnet shape) | — | 272,472 B | — |

### Compute units — measured ON-CHAIN, both arms

Same SDK, same suites, same chain. v1 from the production program's history,
v2 from the experimental deployment. Two capture sessions: the client-path
instructions came from the Tier-3 devnet run, the settle-path instructions from
the Tier-4 CVM run (they need a TEE to drive them).

**Client path (Tier 3, matched v1/v2 pairs):**

| Instruction | v1 CU | v2 CU | Δ |
|---|---|---|---|
| `reset_merkle_tree` | 6,118 | 2,268 | **−62.9%** |
| `deposit` (VALID_DEPOSIT) | 165,176 | 141,950 | −14.1% |
| `withdraw` (VALID_SPEND) | 145,018 | 133,762 | −7.8% |
| `merge` (VALID_MERGE k=2) | 151,877 | 144,403 | −4.9% |

**Settle path (Tier 4).** The v1 column is the on-chain reference range recorded
in the baseline before the port; it is a *range* because these instructions vary
with batch shape, so read these deltas as approximate, not as matched pairs the
way the table above is.

| Instruction | v1 CU (ref) | v2 CU | ≈Δ |
|---|---|---|---|
| `close_batch_validity_marker` | 4,260 | **1,264** | **−70%** |
| `tee_forced_settle_batched` | 75,038–78,927 | **53,222** | **−29%** |
| `lock_note` | 111,936–113,507 | 101,643 | −9% |
| `verify_match_batch` (N=16) | 101,973 | 94,090 | −7.7% |

**Read the spread, not the average.** The saving tracks how much of an
instruction is Anchor overhead:

- `close_batch_validity_marker` and `reset_merkle_tree` are almost pure account
  validation — they show the guide's claimed magnitude.
- `tee_forced_settle_batched` at ≈−29% is the one that matters commercially: it
  is the settle hot path, it runs N=16 per batch, and it sits against a 1.4 M CU
  ceiling.
- `deposit` / `withdraw` / `merge` are dominated by Groth16 verification inside
  `groth16-solana`, which Anchor never touches, so v2 can only shrink the
  wrapper around the pairing check.

The guide's headline "2.8×–50.4× compute" comes from bench programs that are
mostly Anchor overhead. Quoting it for this program would be misleading.

**Caveat on `close_batch_validity_marker`:** part of that −70% is this port
dropping an account from the instruction (3 → 2, §3.1), not v2 alone.

v2-only, no comparable v1 tx captured: `initialize` 19,999, `initialize_tree`
5,243, `initialize_market` 3,256, `set_protocol_config` 1,105.

### Test coverage

| Tier | Result |
|---|---|
| Offline (16 vault targets, 74 tests) | pass |
| `darknyx-tee` lib (468 tests) | pass |
| `clippy --workspace --all-targets -D warnings` | pass, both feature shapes |
| Devnet round-trips (deposit/withdraw/merge) | pass |
| `cvm-api-surface` | 10/10 over RA-TLS |
| `cvm-settle-e2e` | pass (leaf_count 2→7 verified on-chain) |
| `cvm-multimatch-settle` | pass |
| `cvm-self-trade` | pass |
| `cvm-merge-then-order` | pass |
| `cvm-ratls-transport` | 6 pass, 1 skip |
| `cvm-attestation-e2e` | 6/6, real DCAP |
| `cvm-daemon-lifecycle` | pass — **first successful live run ever**, v1 included |

---

## 2. Layout identity — proven, not assumed

All nine `#[account]` structs became zero-copy `Account<T>`; none needed
`BorshAccount`, because every field was already fixed-size. v2's compile-time
no-padding assertion passed for all nine — `VaultConfig` already carried an
explicit `_padding: [u8; 3]` tail for exactly that reason.

The committed `programs/vault/account-layout.json` is **byte-identical to v1**
and the fixture passes under v2: the repr(C) Pod layout reproduces the borsh
field offsets exactly, which is what keeps the hand-rolled TS and Rust decoders
valid. Independently corroborated by `MarketConfig::SPACE` (a v1-era borsh
constant) still equalling `8 + size_of::<T>()`, and by `VaultConfig` reading
1264 bytes on chain.

The fixture covered only 5 of 9 structs before this port. The four it missed
(`WalletEntry`, `DepositedNoteEntry`, `ConsumedNoteEntry`, `OutstandingMint`)
are the ones where a shift is hardest to notice — nothing reads them
field-by-field, so a shifted guard PDA still derives fine and decodes to
garbage. All nine are covered now.

---

## 3. Behaviour changes — read before adopting

### 3.1 `close_batch_validity_marker` lost permissionless cleanup

v2 rejects a transaction that passes one account into two slots when either is
`mut` (`ConstraintDuplicateMutableAccount`, 2040). The marker sweeper closes
with `authority == payer == the primary shard key`, so **every marker close
would have failed** — rent never reclaimed, sweeper retrying each tick and
paying a fee each time, because the tx lands before failing.

Reproduced against a deployed program, not only in litesvm.

Fixed by collapsing the `payer` slot into `authority`, which removes the alias
structurally rather than waiving the check with `unsafe(dup)`. **Cost: only the
recorded payer can close now; any signer could previously sweep on the payer's
behalf.** The property CLAUDE.md §8.2 actually rests on — nobody, payer
included, can close before expiry — is unchanged.

### 3.2 `unsafe(dup)` implies mutable

Adding `unsafe(dup)` to satisfy the v2 compile silently makes a field
**required-writable**, because waiving the duplicate-*mutable* check is its
purpose. On `note_lock_f` that would have write-locked the shared
`PDA(["note_lock", [0;32]])` sentinel across every concurrent exact-fill settle
— serialising exactly what tree-sharding exists to parallelise. Removed; the
check cannot fire anyway, since neither field carries `mut`.

### 3.3 Mainnet artifact: absent → unreachable

v2's `#[program]` emits `pub use super::__client_accounts_<name>` for every
instruction **without propagating that instruction's `#[cfg]`**, so gating the
devnet-admin modules broke the featureless build. Worked around by ungating the
Accounts-struct modules while the `#[program]` fns stay gated.

audit_1 F-01/F-02 previously guaranteed the dev instructions were **absent**
from a mainnet artifact. What still holds is that they are **not dispatchable**
— no `#[program]` fn, so no discriminator. Whether the linker strips the
now-compiled handlers is **not verified**; the mainnet artifact being 5,120 B
smaller is the only evidence, and two attempts to assert absence directly were
vacuous (a discriminator scan reports `deposit` absent too; a symbol scan finds
nothing because the binary is stripped).

### 3.4 `ProgramData` is gone

v2 removed both `Account<ProgramData>` and `programdata_address()`. The
mainnet-only upgrade-authority guard on `initialize` is reimplemented against
the raw account (PDA identity, loader ownership, enum tag, authority present,
signer match). The byte parser is unit-tested and mutation-verified, but the
**end-to-end guard is unexercised** — nothing in this repo deploys
upgradeably-with-authority.

### 3.5 No runtime error names

`#[msg(...)]` is IDL-only in v2; on-chain you get `ProgramError::Custom(code)`.
Any test matching an error NAME in logs can never pass regardless of behaviour.
Error-code offsets and variant ORDER are now load-bearing for the client.

---

## 4. Upstream defects worth reporting

1. **anchor-lang 2.0.0-rc.1 declares a dependency range it does not support.**
   `solana-address "^2.0"` + `wincode "^0.5"`, but solana-address only uses
   wincode 0.5 in its **2.6.x** line (2.2–2.5 → 0.4.x, 2.7 → 0.6). Anything
   else puts two wincodes in the graph and `Address` implements the Schema
   traits from the wrong one. Surfaces as ~60 copies of "the trait `SchemaWrite`
   is not implemented for `Pubkey`" — a type absent from the source — with the
   real cause buried in a note.
2. **anchor-spl 2.0.0-rc.1 does not build for SBF out of the box.** It depends
   unconditionally on `spl-token-2022-interface`, which pulls
   `solana-instructions-sysvar 3.0.0`, which fails to compile for the SBF
   target. Fixed by forcing the 3.0.1 patch.
3. **`#[program]` does not propagate `#[cfg]`** onto its generated
   client-accounts re-exports (§3.3).
4. **`wincode` and `pinocchio` must be DIRECT dependencies** — the re-exported
   derives emit absolute paths that resolve only from the extern prelude. Not
   in the migration guide.
5. **agave 4.2.1 broke `ExecutionRecord`** and therefore litesvm 0.15.2, despite
   litesvm requesting `^4.1.1` — a semver break inside a minor release.

---

## 5. What adoption costs beyond the program

- **litesvm 0.13 → 0.15.2**, plus `solana-transaction`/`solana-message` 3.x → 4.x
  workspace-wide. The 4.x move turned out to be a **one-line feature rename**
  (`bincode` → `wincode`) and needed **no source changes in `darknyx-tee`.**
- **Rust floor 1.91 → 1.93** (`solana-syscalls` uses `maybe_uninit_write_slice`),
  which also required the TEE Dockerfile base to move in lockstep.
- Several `solana-*` pins relaxed or re-pinned; `solana-address` fixed at 2.6.1.

---

## 6. Standing hazards this port surfaced

Recorded because each cost real time and each will recur.

- **`cargo build-sbf` exits 0 while producing no binary.** Only
  `scripts/build-vault-sbf.sh` fails closed. A failed build also leaves the
  PREVIOUS `.so` in place, so a size measurement reads plausibly while
  describing the wrong artifact. This happened three times.
- **A deployed program can be stale while the source is fixed.** The 2040 fix
  looked validated until the deployed binary was probed with the new account
  shape. Verify the artifact, not the deploy exit code.
- **Wrong-program lookups surface as errors naming healthy subsystems.** Twice:
  a missing compose passthrough became "MarketConfig missing/malformed", and a
  test reading `DARKNYX_VAULT_PROGRAM_ID` instead of `VAULT_PROGRAM_ID` became
  `AttestationError: pubkey_mismatch`.
- **`.gitignore` rules ending in `/` match directories only.** Nine absolute
  symlinks into a developer's home directory were committed past
  `circuits/build/**/*_js/` and broke CI on five PRs.
- **litesvm 0.15 no longer starts near slot 0.** Absolute expiries in fixtures
  silently became past slots, and failed as vault errors
  (`InvalidExpirySlot`, `NoteLockExpired`) rather than as harness drift.
