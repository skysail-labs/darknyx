# Anchor v1 → v2-rc.1: measured results

Branch `experiment/anchor-v2-rc1`. Program deployed to devnet as
`DtSR7WELiAJMSMsPSLmDmA9ai5Q4715vooH8vderTvX7`, entirely separate from the
production vault `C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx`.

## Headline

| Metric | v1 (anchor 1.1.2) | v2 (2.0.0-rc.1) | Δ |
|---|---|---|---|
| `vault.so` | 598,272 B | **278,504 B** | **−53.4%** |

## Compute units — measured ON-CHAIN on devnet, not in litesvm

Same SDK, same test files, same chain, same session. v1 numbers come from the
production devnet program; v2 from the experimental deployment.

| Instruction | v1 CU | v2 CU | Δ | Δ% |
|---|---|---|---|---|
| `reset_merkle_tree` | 6,118 | 2,268 | −3,850 | **−62.9%** |
| `deposit` (VALID_DEPOSIT) | 165,176 | 141,950 | −23,226 | **−14.1%** |
| `withdraw` (VALID_SPEND) | 145,018 | 133,762 | −11,256 | **−7.8%** |
| `merge` (VALID_MERGE k=2) | 151,877 | 144,403 | −7,474 | **−4.9%** |

v2-only (no directly comparable v1 tx captured): `initialize` 19,999,
`initialize_tree` 5,243, `initialize_market` 3,256, `set_protocol_config` 1,105.

### What the shape means

The spread is the whole result, and it is not noise:

- **`reset_merkle_tree` −62.9%.** Almost no program logic; the cost is account
  validation and (de)serialization. This is the closest thing here to a
  measurement of what v2's account model actually buys, and it matches the
  guide's claimed range.
- **`deposit` / `withdraw` / `merge`, −4.9% to −14.1%.** These are dominated by
  Groth16 verification inside `groth16-solana`, which Anchor never touches. v2
  can only shrink the wrapper around the pairing check, and it does — but the
  pairing check is most of the bill.

So the honest summary: **v2's savings are real and large in proportion to the
Anchor overhead in an instruction, and this program has comparatively little of
it on its hot paths.** The guide's headline "2.8×–50.4× compute" comes from
bench programs that are mostly Anchor overhead. Applied here it would be
misleading.

**Settle-path instructions were NOT measured on v2.** `lock_note`,
`verify_match_batch` and `tee_forced_settle_batched` need a TEE to drive them.
v1 on-chain references for later comparison: `lock_note` 111,936–113,507,
`verify_match_batch` 101,973, `tee_forced_settle_batched` 75,038–78,927,
`close_batch_validity_marker` 4,260. `close_batch_validity_marker` is the one
most likely to show a large win, being nearly pure Anchor overhead.

## What the migration costs

This is the part that decides whether to adopt, and it is not small.

1. **A litesvm major bump, and it does not currently work.** anchor-lang
   2.0.0-rc.1 needs wincode ^0.5 → solana-address 2.6.x → litesvm ≥ 0.15.
   litesvm 0.15.2 requires `solana-message ^4.2.4` / `solana-transaction ^4.1.5`;
   this workspace (and `darknyx-tee`'s settle path) is on the 3.x line. The vault
   tests build a 3.x `Transaction`, litesvm wants a 4.x `VersionedTransaction`,
   and there is no conversion. **Finishing the litesvm path means migrating the
   transaction crates to 4.x across the workspace, including the enclave.**
   That is a second migration.
2. **Rust toolchain floor 1.91 → 1.93**, workspace-wide. `solana-syscalls 4.2.x`
   uses `maybe_uninit_write_slice`, stable only from 1.93. Downgrading
   solana-syscalls is blocked by a `solana-program-runtime` conflict.
3. **Four pinned `solana-*` crates relaxed or re-pinned**, all shared with
   `darknyx-tee` through `{ workspace = true }`.

The CU numbers above were obtained by **bypassing litesvm entirely** and
measuring on devnet, which is both cheaper and more authoritative.

## Upstream defects found (worth reporting)

1. **anchor-lang 2.0.0-rc.1 declares a dependency range it does not support.**
   `solana-address "^2.0"` + `wincode "^0.5"`, but solana-address only uses
   wincode 0.5 at 2.6.x (2.2–2.5 → 0.4.x, 2.7 → 0.6). Any other pick puts two
   wincodes in the graph and `Address` implements the Schema traits from the
   wrong one. It surfaces as ~60 copies of "the trait `SchemaWrite` is not
   implemented for `Pubkey`" — a type absent from the source — with the real
   cause buried in a note.
2. **anchor-spl 2.0.0-rc.1 does not build for SBF out of the box.** It depends
   unconditionally (no feature gate) on `spl-token-2022-interface`, which pulls
   `solana-instructions-sysvar 3.0.0`, which fails to compile for the SBF
   target. Fixed by forcing the 3.0.1 patch.
3. **agave 4.2.1 broke `ExecutionRecord`'s fields** and therefore litesvm 0.15.2,
   despite litesvm requesting `^4.1.1` — a semver break inside a minor release.
4. **`wincode` must be a DIRECT dependency.** Anchor re-exports the derive
   macros, but they emit absolute `::wincode` paths that only resolve from the
   extern prelude. Same for `pinocchio`. Not mentioned in the migration guide.

## Migration facts worth keeping

- **All nine `#[account]` structs became zero-copy `Account<T>`; none needed
  `BorshAccount`.** Every field was already fixed-size. v2's compile-time
  no-padding assertion passed for all nine, which `VaultConfig`'s pre-existing
  explicit `_padding: [u8; 3]` tail made free.
- **Layout is expected byte-identical** and the deployment is evidence for it:
  the TS SDK hand-codes the v1 borsh layout, and it successfully drove
  `initialize`, `deposit`, `merge` and `withdraw` against the v2 program on
  chain. That is stronger than a unit fixture, though a fixture should still be
  added (guide §13 — a Pod cast decodes wrong-but-well-formed bytes into a
  valid-looking struct).
- **Zero optional accounts**, so the known rc.1 duplicate-mutable defect
  (guide §7.4) does not apply here.
- **The `reload()` calls after the SPL CPIs in `deposit`/`withdraw` are now
  meaningless**, not merely redundant: `Account<T>` reads the live buffer.
- **`#[account(dup)]` → `#[account(unsafe(dup))]`** on `note_lock_f`. The safety
  condition is met by inspection: neither `note_lock_e` nor `note_lock_f` carries
  `mut`, and the alias only arises on exact-fill where both are read-only.

## Recommendation

Adopt only if the binary-size halving is worth a transaction-crate migration of
the enclave. The CU win on the paths that dominate settle cost is single-digit
to low-teens percent, because those paths are Groth16-bound. If binary size is
not currently a constraint, the cost/benefit does not favour rc.1 today —
revisit at v2 stable, when litesvm and the solana 4.x line have settled.
