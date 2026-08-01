# 🔒 Security Audit Report — Nyx Darkpool `vault` + crypto boundary

## 1. Executive Summary

**Repository:** skysail-labs/darknyx (nyx-monorepo)
**Commit:** `1cc1bf1` · **Branch:** `main`
**Date:** 2026-06-27
**Auditor:** Claude Opus 4.8 (AUDITOR skill v4.4, inline/checkpointed)
**Scope:** PROGRAM + crypto boundary — `programs/vault` (on-chain, checklists 01-07/16) plus the off-chain code sharing its byte-equality / settle-auth contracts (`crates/darkpool-crypto`, `crates/darkpool-matcher`, `crates/nyx-tee/src/settle`+`prover`, `packages/sdk` crypto). **Excludes** ZK circuit soundness (separate external track) and `apps/demo`.
**Program ID:** `C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx` (devnet) · **Anchor:** 0.32.1 · **Languages:** Rust (Solana/Anchor), TypeScript
**Repository Risk Score:** **6 — MEDIUM** (devnet posture). **Escalates to 7-8 / HIGH if shipped to mainnet without gating the devnet-only destructive instructions + multisig-ing the admin authority.**

### What We Found

The on-chain `vault` program is **well-engineered and hardened**. Every value-moving path follows checks-effects-interactions, uses `checked_*` arithmetic, and is defended by per-leaf replay PDAs (`init`-as-guard), an explicit per-mint solvency invariant (`outstanding <= SPL balance`, re-asserted after each CPI), and a multi-layer settle-binding chain (lock VALID_INPUT proof → batch leaf → marker PDA → `init` consumed/nullifier). The Ed25519 TEE-signature check is **not** vulnerable to the classic precompile-introspection bypass, the 1:N `BatchValidityMarker` lifecycle is correct, and cross-language cryptographic primitives are Fr-safety-enforced and domain-separated. **No critical or high-severity exploit was found in the on-chain program at the current (devnet) trust assumptions.**

The most material findings are two **DEV-NET-ONLY destructive admin instructions** (`reset_merkle_tree`, `close_vault_config`) that compile into every build: a malicious or compromised admin key can **freeze all user funds** (zero a tree shard → all pre-reset notes unspendable) or **brick the config**. They are admin-gated and documented as devnet-only, but must be compile-gated out (or placed behind multisig + timelock) before mainnet. This, plus a first-caller-wins `initialize` and a single-signature admin authority, makes **admin-key governance the dominant residual risk**.

One structural dependency: on-chain settlement solvency/mint-consistency rests **entirely** on the soundness of the off-chain VALID_MATCH_BATCH circuit (conservation + range + fee-floor proven in-circuit over private amounts). The on-chain bindings that anchor the proof are correct; the circuit itself requires the **planned external circuit audit** before mainnet.

**Safe to continue on devnet. NOT safe to deploy to mainnet until the F-01/F-02 dev instructions are gated, the admin authority is a multisig, and the external circuit audit completes.**

### Severity Distribution

| Score | Label | Count |
|-------|-------|-------|
| 10 | 🔴 CRITICAL | 0 |
| 9 | 🔴 CRITICAL | 0 |
| 8 | 🟠 HIGH | 0 |
| 7 | 🟠 HIGH | 0 |
| 6 | 🟡 MEDIUM | 2 |
| 5 | 🟡 MEDIUM | 0 |
| 4 | 🔵 LOW | 1 |
| 3 | 🔵 LOW | 4 |
| 2 | ⚪ INFO | 5 |
| 1 | ⚪ INFO | 0 |
| **Total Findings** | | **12** |

> Note: F-01/F-02 are scored 6 at the current devnet posture; both escalate to 7-8 (HIGH) under a mainnet deployment with a non-multisig admin. The Repository Risk Score reflects the devnet posture.

### Items Verified

| Metric | Count |
|--------|-------|
| On-chain instructions deep-reviewed | 16 / 16 (all) |
| Core modules deep-reviewed | state, errors, merkle, zk/verifier, zk/mod |
| Crypto-boundary files deep-reviewed | note, nullifier, field, fill_encryption (darkpool-crypto); ed25519, fill_recovery, payload (nyx-tee/settle) |
| Applicable checklist domains | 01-07, 11-13, 16-17 (program + crypto) |
| Known vectors evaluated | crypto/on-chain set (KV-001..030, 101-109) + relevant devops (078/079/091) |

---

## 2. Corpus Coverage

| AUDITOR file | Loaded |
|---|---|
| SKILL.md, README.md, FULL-AUDIT.md, OUTPUT-RULES.md | Yes |
| COSTS.md, discovery/file-map.md, known-vectors/INDEX.md, templates/report-template.md | Yes |
| checklists/01-07, 16 (program + verification) | Yes (applied as reference per-instruction) |
| checklists/08-15, 17-18 | Partially — applied to the in-scope TS crypto + devops surfaces; non-applicable sections marked N/A |
| known-vectors/001-030, 101-109 (crypto/on-chain) | Yes (evaluated, §6) |
| known-vectors/031-100 (backend/frontend/devops detail bodies) | Index-level (out of primary scope; relevant ones — 078/079/091 — evaluated) |

> Honesty note (OUTPUT-RULES Rule 10): this is a **focused fund-safety audit** of the on-chain program + its cryptographic trust boundary, not a line-by-line sweep of the entire monorepo. The full `crates/darkpool-matcher` algorithm, the complete `crates/nyx-tee` HTTP/WS/orchestration surface, the `packages/sdk` TypeScript transport layer, and the `packages/indexer` were **not** line-by-line reviewed — they are off-chain and liveness-bounded (the on-chain program validates or rejects everything they produce; a buggy off-chain component cannot mint value the chain didn't authorize). ZK circuit soundness is explicitly out of scope (external track).

---

## 3. Scope & Methodology

### Files Audited (deep review)

| Domain | Language | Files | LOC (approx) |
|---|---|---|---|
| `vault` program | Rust | 18 ix + state/errors/merkle/zk (24 files) | 3,769 |
| `darkpool-crypto` primitives | Rust | note, nullifier, field, fill_encryption | ~700 of 1,702 |
| `nyx-tee` settle boundary | Rust | ed25519, fill_recovery, payload | ~600 |
| **Total deep-reviewed** | | | **~5,000** |

### Methodology

Per-instruction walk (read full file → account-validation / access-control / arithmetic / CPI-PDA / state-machine / economic checks) → cross-cutting state-machine + economic review → cryptographic primitive parity/Fr-safety review → automated scans (`unsafe`, panic surface, `invoke` vs `invoke_signed`, `init_if_needed`, committed-secret/keypair scan) → known-vector evaluation. Checkpoints persisted to `audit_1/audit-checkpoint.md`.

---

## 4. Findings

#### [F-01] `reset_merkle_tree` — admin can freeze all user funds

| Field | Value |
|---|---|
| **Severity** | 6 — 🟡 MEDIUM (→ 7-8 HIGH on mainnet) |
| **Checklist Item** | OPS / KV-008 (admin backdoor), KV-024 |
| **Category** | Centralization / Governance backdoor |
| **File** | `programs/vault/src/instructions/reset_merkle_tree.rs:44` |
| **Status** | Open |

**Description:** `reset_merkle_tree` zeroes a shard's `leaf_count`, `right_path`, `roots[]` and resets `current_root` to the empty root. It is admin-gated (`address = vault_config.admin`) and documented DEVNET-ONLY, but compiles into every build with no feature gate.

**Impact:** A malicious or key-compromised admin can wipe a shard. Every note already inserted into that shard becomes **permanently unspendable** — `withdraw`/`merge`/`lock_note` all require `merkle_tree.contains_root(proof_root)`, and the proof roots no longer exist. Funds are not stolen (SPL balance + `outstanding` are untouched) but are **frozen** with no recovery. This is a total-loss-of-availability backdoor controllable by a single admin signature.

**Recommendation:** Compile-gate the instruction behind a non-default cargo feature (e.g. `#[cfg(feature = "devnet-admin")]`) so mainnet artifacts cannot contain it; OR require a governance multisig + timelock. Never ship the bare admin-only form to mainnet (the file's own header says as much — enforce it in the build).

---

#### [F-02] `close_vault_config` — admin can brick the protocol + enable an init front-run

| Field | Value |
|---|---|
| **Severity** | 6 — 🟡 MEDIUM (→ 7-8 HIGH on mainnet) |
| **Checklist Item** | OPS / KV-008 |
| **Category** | Centralization / Governance backdoor |
| **File** | `programs/vault/src/instructions/close_vault_config.rs:39` |
| **Status** | Open |

**Description:** Drains lamports + zeroes the `VaultConfig` PDA (layout-agnostic; checks `owner == program` + the `admin` field at offset 8). DEVNET-ONLY, admin-gated, always compiled.

**Impact:** A compromised admin can wipe the global config, halting every instruction (each does `bump = vault_config.load()?.bump`). Worse, because `initialize` uses `init` on a now-nonexistent PDA, **anyone** can re-`initialize` afterward and become the new `admin` (then set their own `tee_pubkeys` / `protocol_owner_commitment` / fee rate). Funds in proof-gated paths still can't be directly drained (withdraw/settle need real ZK proofs), but the protocol is bricked and fee/governance capture becomes possible.

**Recommendation:** Same as F-01 — feature-gate out of mainnet builds or multisig+timelock. If kept, pair `initialize` with an authority check (see F-03) so a re-init after close cannot be hijacked.

---

#### [F-03] `initialize` is first-caller-wins (no upgrade-authority binding)

| Field | Value |
|---|---|
| **Severity** | 3 — 🔵 LOW |
| **Checklist Item** | AC / KV-004, KV-014 |
| **Category** | Access Control / Initialization |
| **File** | `programs/vault/src/instructions/initialize.rs:29` |
| **Status** | Open |

**Description:** `initialize` sets `cfg.admin = signer` with no check that the signer is the program's upgrade authority. Whoever calls it first owns the protocol.

**Impact:** A front-runner in the window between program deploy and the legitimate `initialize` tx becomes admin. Compounds F-02 (re-init after `close_vault_config`).

**Recommendation:** Bind the initializer to the program's `ProgramData` upgrade authority (pass the program-data account and `require_keys_eq!(signer, upgrade_authority)`), or perform deploy + initialize atomically and accept the documented risk on devnet.

---

#### [F-04] On-chain settlement solvency depends entirely on circuit soundness (documented dependency)

| Field | Value |
|---|---|
| **Severity** | 4 — 🔵 LOW (audit-scope boundary, not an on-chain defect) |
| **Checklist Item** | ECON / KV-011, KV-012 |
| **Category** | Economic / Trust boundary |
| **File** | `programs/vault/src/instructions/tee_forced_settle_batched.rs:369-390` |
| **Status** | Open (tracked under external circuit audit) |

**Description:** Conservation, amount range-checks, and the fee floor are proven **in-circuit** (VALID_MATCH_BATCH) over private amounts; the chain no longer re-derives them. The on-chain handler verifies the binding chain (lock VALID_INPUT, leaf→marker, replay PDAs) correctly, but a soundness bug in the circuit (e.g. a non-conserving match or a mint-substitution that still satisfies the constraints) would let the per-mint `outstanding` counter desync and the vault become insolvent on withdraw.

**Impact:** No on-chain mitigation exists by design — this is the cost of amount privacy. Bounded by circuit correctness.

**Recommendation:** Complete the **external ZK circuit audit** (already on the roadmap) before mainnet. Keep the committed N=16 proof fixture + parity tests green. Consider an optional on-chain per-mint invariant cross-check at settle as defense-in-depth (cost: re-introduces some amount data — weigh against privacy).

---

#### [F-05] TEE lock blocks withdraw until expiry (bounded censorship window)

| Field | Value |
|---|---|
| **Severity** | 3 — 🔵 LOW |
| **Checklist Item** | SM / liveness |
| **Category** | Liveness / Censorship |
| **File** | `programs/vault/src/instructions/lock_note.rs`, `withdraw.rs:127-139` |
| **Status** | Open (inherent to the lock model) |

**Description:** `withdraw` rejects any note with a live `NoteLock` (even an expired one, until `release_lock` is called). A registered TEE can `lock_note` a note (relaying the owner's VALID_INPUT proof) and the owner cannot withdraw until expiry + `release_lock`. Bounded by `MAX_LOCK_TTL_SLOTS` (~24h).

**Impact:** A misbehaving TEE can delay (not steal) a withdrawal by up to ~24h. Inherent to the order-lock design; the TEE cannot lock without the owner's proof.

**Recommendation:** Accept as a documented design trade-off; consider shortening `MAX_LOCK_TTL_SLOTS` for production if 24h is longer than the matcher needs.

#### Lower-severity items (INFO, severity 2)

- **[F-06] Committed devnet demo keypairs** — `apps/demo/.demo-keypairs/{maker,taker}.json` are tracked Solana keypairs. Devnet/demo, low value, but the `.gitignore` `*-keypair.json` pattern misses these filenames. *Fix:* rename/relocate under an ignored path or generate at runtime; **never reuse on mainnet.** (`apps/demo` is out of primary scope; flagged for completeness. `apps/demo/.env.local` is also tracked — verify it holds only `NEXT_PUBLIC_*` demo config.)
- **[F-07] `create_wallet` passes an unused `vault_config` account** (`create_wallet.rs:14,60`) — dead, unvalidated account; remove to shrink the tx and drop the unused-account smell.
- **[F-08] Batched-settle marker read via raw bytes without a discriminator check** (`tee_forced_settle_batched.rs:331-346`) — safe today (PDA address bound by `require_keys_eq!` to the unique `b"batch_validity"` seed + `owner == program`), but a defense-in-depth Anchor discriminator check would harden against any future account-type reuse of that seed prefix.
- **[F-09] `set_tee_pubkey` does not reject zero / duplicate keys** (`set_tee_pubkey.rs`) — admin-trusted and not exploitable (no one can sign as the all-zero key), but validating non-zero + dedup is cheap hygiene.
- **[F-10] Single-signature admin / root authority on devnet** — `set_tee_pubkey`/`set_protocol_config`/`rotate_root_key` are single-sig. Documented; mainnet requires a multisig (and attestation-gated TEE-key rotation per `docs/tee-attestation-flow.md`).

---

## 5. Detailed Item Results (by domain)

> Verdicts are given at the checklist-domain level with the load-bearing items called out, per the focused-audit methodology in §2. `[PASS]` = verified against cited code; `[N/A]` = domain not present in scope.

### Checklist 01 — Account Validation — **PASS** (strong)
- `[PASS]` Typed `Account<T>` / `AccountLoader<T>` everywhere; `UncheckedAccount` only with `seeds`+`bump` constraints or explicit handler validation (`withdraw.rs` consumed/lock slots; `tee_forced_settle_batched.rs` marker/relock; all `require_keys_eq!`-checked).
- `[PASS]` `init` used as the replay guard on every per-leaf PDA (nullifier/consumed/wallet/note-lock); manual `create_account` paths (`create_relock_pda`, `create_nullifier_pda`) re-derive the canonical PDA + assert empty.
- `[PASS]` `instructions_sysvar` address-validated (`address = sysvar::instructions::ID`) — closes KV-101.
- `[PARTIAL→OK]` `init_if_needed` (deposit vault-token + outstanding-mint) — reviewed safe (token-account constraints re-checked; data account loads-not-reinits; fields set idempotently).
- `[FAIL-2]` F-07 unused `vault_config` in `create_wallet`.

### Checklist 02 — Access Control — **PASS**
- `[PASS]` TEE paths gate on `is_authorized_tee` (set membership over `tee_pubkeys[..num_tee_keys]`). Admin paths gate on `admin == vault_config.admin`. Root rotation is self-signed.
- `[PASS]` Value movement is ZK-gated, not signer-gated (`withdraw`/`merge` authorize via proof; any signer pays rent) — correct for a shielded pool.
- `[FAIL-3]` F-03 first-caller-wins `initialize`.

### Checklist 03 — Arithmetic Safety — **PASS**
- `[PASS]` `checked_add`/`checked_sub` on all balance + counter math (`deposit`, `withdraw`, `merge`, `append_leaf`, lamport moves in `close_vault_config`). Solvency check guards the one bare `-=` in `withdraw`. `fee_rate_bps` clamped ≤ 10000. No truncating `as` casts on financial values found.

### Checklist 04 — CPI & PDA — **PASS**
- `[PASS]` All CPIs are `invoke_signed`/Anchor helpers (no raw `invoke`); SPL `transfer_checked` (decimals-checked) with the `vault_config` PDA as authority; checks-effects-interactions ordered (state mutated before transfer-out). PDA seeds canonical; manual creations sign with derived bump.

### Checklist 05 — State Machine & Lifecycle — **PASS**
- `[PASS]` Note lifecycle (deposit→lock→settle/withdraw→consumed) has no stuck states; locks expire + `release_lock` GCs them. `BatchValidityMarker` is 1:N and correctly **not** closed in settle (§8.2 invariant upheld — `tee_forced_settle_batched.rs:500`); separate `close_batch_validity_marker` with payer/expiry GC paths.

### Checklist 06 — Economic & Logic — **PASS** (with F-04 boundary)
- `[PASS]` Per-mint `outstanding <= SPL balance` solvency invariant; settle is conservation-preserving and correctly leaves `outstanding` untouched; merge conserves; duplicate-note / duplicate-nullifier rejected by `init` PDA collisions. First-depositor / donation / rounding vectors N/A (no share math, no AMM).
- `[FAIL-4]` F-04 circuit-soundness dependency.

### Checklist 07 — OpSec & Governance — **PARTIAL**
- `[PASS]` No `unsafe`, no raw pointers, no hardcoded backdoor keys in the program. `declare_id!` matches `Anchor.toml`.
- `[FAIL-6]` F-01/F-02 destructive devnet admin ix in the build.
- `[FAIL-2]` F-10 single-sig admin; upgrade-authority custody is an operational item (verify `solana program show` → multisig before mainnet).

### Checklists 08-10 (TS / backend / frontend) — **scoped PASS / N/A**
- `[PASS]` In-scope TS crypto (`fill-encryption.ts`, `key-generators.ts`, `settle-builder.ts`) is parity-pinned to the Rust side by fixed-vector tests. Full SDK transport / `apps/demo` frontend / backend HTTP not in scope (§2). `[N/A]` backend-server checklist — the only server surface is the in-TEE HTTP, out of this pass.

### Checklists 11-13 (supply chain / secrets / deploy) — **PARTIAL PASS**
- `[PASS]` `.gitignore` covers `.env*`, `*-keypair.json`, `.devnet/`; no real secrets tracked; only `*.example` env files committed.
- `[FAIL-2]` F-06 committed demo keypairs (ignore-pattern gap). `cargo audit` / `npm audit` not run this pass — recommend wiring into CI (see roadmap).

### Checklist 14 (Python) — **N/A** — no Python in scope.

### Checklist 16 — Formal Verification & Testing — **PASS**
- `[PASS]` Strong fixed-vector + parity test discipline (`canonical_payload_hash_fixed_vector`, `fill_encryption` fixed vector, `compute_match_leaf` byte-asserts, committed N=16 proof fixture). The §7 cross-language byte-equality contracts are each test-pinned. Recommend adding `cargo audit`/`npm audit` + a fuzz target for `append_leaf`/`walk_merkle_path_n16` index handling.

### Checklist 17 — Logging/Monitoring — **PASS (program)**
- `[PASS]` Every state-changing instruction emits an event (`NoteCreated`/`Withdrawn`/`NoteLocked`/`TradeSettled`/`NoteMerged`/`MatchBatchVerified`/rotations). Amount-privacy correctly removed amounts from events.

---

## 6. Known Vector Results (crypto / on-chain set + relevant devops)

```
[PASS]    KV-001 Private key leak — no keys in program/crypto scope; F-06 demo keypairs (devnet, INFO) flagged.
[PASS]    KV-002 Flash-loan price manip — N/A (no AMM/oracle-priced pool); matcher price proven in-circuit.
[PASS]    KV-003 Reentrancy (CPI) — CEI ordered; only SPL/system CPIs; no untrusted callback surface.
[PASS]    KV-004 Missing access control — TEE set-membership + admin/root gates on every privileged ix (F-03 init = LOW).
[PASS]    KV-005 Oracle manipulation — N/A; no on-chain oracle.
[PASS]    KV-006 First-depositor/share inflation — N/A; no share accounting.
[PASS]    KV-007 MEV sandwich — order intake is off-chain in the TEE (hidden); settle is TEE-driven, not a public AMM.
[FAIL-6]  KV-008 Rug pull / admin backdoor — F-01/F-02 destructive devnet admin ix. (see Findings)
[PASS]    KV-009 Unchecked CPI target — token/system programs are typed (Program<Token>/System).
[PASS]    KV-010 PDA confusion / type cosplay — typed AccountLoader + canonical seeds; manual reads check owner==program.
[PASS]    KV-011 Integer overflow/underflow — checked math throughout; solvency-guarded subtraction.
[PASS]    KV-012 Rounding exploit — no on-chain division on amounts (fee floor proven in-circuit).
[PASS]    KV-013 Missing signer check — Signer types on all authorities; ZK gates value movement.
[PASS]    KV-014 Account reinitialization — init guards; init_if_needed reviewed safe (F-03 init front-run = LOW).
[PASS]    KV-015 Unchecked account owner — owner==program checks on raw AccountInfo reads (consumed/lock/marker).
[PASS]    KV-016 Token account mismatch — vault_token is a PDA (seeds=[b"vault_token",mint]) with token::mint/authority constraints; deposit checks depositor ATA mint+owner.
[PASS]    KV-017 Vault donation attack — solvency uses `outstanding`, not a balance-delta; a raw token donation cannot inflate claims.
[PASS]    KV-018 Fee-on-transfer token — transfer_checked + post-CPI reload + solvency assert catch under-credit; mints are protocol-curated.
[N/A]     KV-019 Freeze-authority griefing — mints are devnet-curated; document the requirement that listed mints have no hostile freeze authority.
[PASS]    KV-020 Program upgrade hijack — verify upgrade authority is multisig pre-mainnet (operational; F-10).
[PASS]    KV-021/022 Governance/bridge — N/A (no on-chain voting/bridge).
[PASS]    KV-023 Token-2022 transfer hook — uses classic Token program (anchor_spl::token); document if Token-2022 mints are ever listed.
[PASS]    KV-024 Stale/missing close — markers/locks have explicit close + GC paths; F-01 reset is the destructive case.
[PASS]    KV-025 Compute-budget DoS — fixed-depth loops (20-level Merkle, depth-4 path, ≤16 batch); no unbounded user-controlled iteration (merge remaining_accounts bounded to k≤4).
[PASS]    KV-026 PDA seed collision — distinct seed prefixes per account type; commitment/nullifier are 32-byte Poseidon outputs.
[PASS]    KV-027 Missing discriminator check — Anchor-typed accounts checked; F-08 (raw marker read) is the one defense-in-depth gap (safe via seed-prefix uniqueness).
[PASS]    KV-028 Front-running — order content hidden in TEE; on-chain settle replay-blocked by init PDAs (F-03 init = the one front-run, LOW).
[PASS]    KV-029 Withdraw-before-update race — nullifier set + outstanding decremented before transfer-out; atomic.
[PASS]    KV-030 Infinite mint — no mint authority held by the program; output notes are conservation-bound (circuit, F-04).
[PASS]    KV-101 Sysvar spoofing — instructions sysvar address-validated.
[PASS]    KV-102 Precompile sig bypass — verify_tee_signature requires inlined pk+msg (ix_index==0xFFFF), reads them from the precompile ix's own data, scans full sysvar; a passing precompile ⇒ runtime verified TEE-key sig over expected msg. NOT vulnerable.
[PASS]    KV-103 ALT manipulation — settle ALT holds only derivable PDAs/static accounts; bindings re-derived on-chain (marker PDA from computed_root), not trusted from ALT.
[PASS]    KV-104 Non-canonical bump — Anchor canonical bumps; stored bumps used for re-derivation; find_program_address for manual creates.
[N/A]     KV-105 Token-2022 extension abuse — classic Token program only (see KV-023).
[PASS]    KV-106 Account revival/zombie — closed accounts (lock/marker) are seed-deterministic and re-creatable only via the gated ix; consumed/nullifier never closed (permanent).
[PASS]    KV-107 Fake ATA — vault token account is a program PDA, not an ATA assumption; depositor ATA validated by mint+owner.
[PASS]    KV-108 Token decimals confusion — transfer_checked passes mint.decimals; amounts are per-mint; mint split bound in commitments.
[N/A]     KV-109 Pinocchio/p-token — Anchor program, not native zero-copy p-token.
[FAIL-2]  KV-078/079 Secrets in git / .env committed — F-06 demo keypairs + apps/demo/.env.local (devnet, INFO).
[PASS]    KV-091 Upgrade authority not secured — operational; multisig before mainnet (F-10).
```

---

## 7. Instruction Matrix

| Instruction | Signer / Auth | Key constraints | CPIs | State changes | Findings |
|---|---|---|---|---|---|
| initialize | admin (first-caller) | init singleton | — | create VaultConfig | F-03 |
| initialize_tree | admin==cfg.admin | tree_id<num_trees | — | create MerkleTree shard | — |
| create_wallet | owner(root) | VALID_WALLET_CREATE proof; init | — | WalletEntry | F-07 |
| deposit | depositor | ATA mint+owner; init_if_needed vault/outstanding | transfer_checked(in) | append leaf; outstanding+= ; solvency | — |
| withdraw | any (rent) | VALID_SPEND proof; consumed/lock guards; nullifier init; root recency | transfer_checked(out, PDA auth) | nullifier; outstanding-=; solvency | — |
| merge | any (rent) | VALID_MERGE(k) proof; nullifier PDAs (manual); root recency | create_account×k | nullifiers; append output | — |
| lock_note | TEE (authorized) | VALID_INPUT proof; expiry bounds; note_lock init | — | NoteLock | F-05 |
| release_lock | any (rent) | slot≥expiry; close | — | close NoteLock | — |
| verify_match_batch | any (rent) | VALID_MATCH_BATCH proof (3 pub inputs bound to cfg); marker init; expiry bound | — | BatchValidityMarker | — |
| tee_forced_settle_batched | TEE (authorized) | ed25519 sig; leaf→marker binding; order_id match; init consumed/nullifier; relock canonical-PDA | create_account (relocks) | consumed×2; nullifier×2; append c/d/e/f/fees; relock | F-04, F-08 |
| close_batch_validity_marker | payer or post-expiry | has_one=payer; close=payer | — | close marker | — |
| set_protocol_config | admin==cfg.admin | fee≤10000 | — | fee/owner config | F-10 |
| set_tee_pubkey | admin==cfg.admin | 1≤len≤16 | — | tee_pubkeys set | F-09, F-10 |
| rotate_root_key | current root (self) | new≠0 | — | root_key | F-10 |
| reset_merkle_tree | admin==cfg.admin | DEVNET | — | zero a shard | **F-01** |
| close_vault_config | admin (offset-8) | DEVNET | — | wipe config | **F-02** |

---

## 8. State Model Verification

| Account | Seeds | Replay/lifecycle role | Verdict |
|---|---|---|---|
| VaultConfig | `[b"vault_config"]` | singleton config; tee_pubkeys[16] set | ✅ (F-02 close is the risk) |
| MerkleTree (×K) | `[b"merkle_tree", tree_id]` | per-shard append-only + 64-root ring | ✅ (F-01 reset is the risk) |
| WalletEntry | `[b"wallet", commitment]` | one-time registration | ✅ init-guard |
| NullifierEntry | `[b"nullifier", nullifier]` | spend/settle/merge consume — permanent | ✅ init-guard |
| ConsumedNoteEntry | `[b"consumed_note", commitment]` | settle consume — permanent | ✅ init-guard |
| NoteLock | `[b"note_lock", commitment]` | order pin; expires; closeable | ✅ |
| OutstandingMint | `[b"outstanding_mint", mint]` | per-mint solvency counter | ✅ invariant asserted |
| BatchValidityMarker | `[b"batch_validity", root]` | 1:N batch proof marker | ✅ §8.2 upheld |

**Invariants verified:** per-mint `outstanding <= vault_token.amount` (✅ asserted post-CPI in deposit+withdraw); settle/merge conservation leaves `outstanding` unchanged (✅ by design, contingent on circuit — F-04); double-spend/double-settle/double-merge blocked by `init` PDA collisions (✅); 1:N marker not closed per-match (✅).

---

## 9. Remediation Roadmap

### Before mainnet — block deploy
| Finding | Sev | Fix |
|---|---|---|
| F-01 reset_merkle_tree | 6→HIGH | Cargo-feature-gate out of mainnet build OR multisig+timelock |
| F-02 close_vault_config | 6→HIGH | Same; + bind initialize authority (F-03) |
| F-04 circuit soundness | 4 | Complete external ZK circuit audit (already planned) |
| F-10 single-sig admin | 2→HIGH | Move admin + root + upgrade authority to multisig; attestation-gate TEE rotation |

### Next sprint — LOW
| Finding | Sev | Fix |
|---|---|---|
| F-03 initialize front-run | 3 | Bind to program upgrade authority or atomic deploy+init |
| F-05 lock censorship window | 3 | Consider shorter MAX_LOCK_TTL_SLOTS for prod |
| F-06 committed demo keypairs | 2 | Relocate under ignored path / runtime-generate; verify .env.local |

### Backlog — INFO / hardening
| Finding | Sev | Fix |
|---|---|---|
| F-07 unused vault_config in create_wallet | 2 | Remove the account |
| F-08 marker raw-byte read | 2 | Add Anchor discriminator check |
| F-09 set_tee_pubkey key validation | 2 | Reject zero/dup keys |
| CI hardening | — | Wire `cargo audit` + `npm audit` + a fuzz target for append_leaf/walk_merkle_path index handling |

### CU / efficiency (see separate §10)

---

## 10. CU / Efficiency Findings (user-requested)

| # | Location | Observation | Estimated win |
|---|---|---|---|
| CU-1 | `tee_forced_settle_batched` appends | Up to **6 sequential `append_leaf`**, each walking 20 levels = up to **~120 Poseidon hashes / settle**. Each append independently re-hashes the right-path from leaf to root. | **Largest lever.** A multi-leaf batch-append (insert all outputs, recompute shared path prefixes once) can cut redundant Poseidon work materially on full settles. Poseidon dominates settle CU. |
| CU-2 | `tee_forced_settle_batched` | `vault_config.load()` called twice (auth check; then zsr+protocol_owner) and `note_lock_a/b` loaded twice (mints; then order_id). | Minor — combine into single loads. AccountLoader load is cheap, but tidy. |
| CU-3 | `create_wallet` | Unused `vault_config` account (F-07) | Smaller tx (one fewer account) + clarity. |
| CU-4 | `withdraw`/`merge`/`lock`/`verify_match_batch` | Groth16 pairing verify dominates CU. | Inherent to Groth16; not reducible on-chain. The batched proof (1 verify for N=16) is already the right design — keep batching. |
| CU-5 | Merkle appends generally | Depth-20 tree → 20 Poseidon/append everywhere (deposit, merge, each settle output). | Inherent to the tree depth; only CU-1 (batching within one ix) is actionable without a tree-design change. |

> See the standalone answer below the report for the prioritized efficiency recommendation.

---

## 11. Appendix

- **Anchor:** 0.32.1 · **Solana:** workspace-pinned · **groth16-solana / light-poseidon / solana-poseidon** for on-chain verification + hashing.
- **Not reviewed this pass (honest scope):** full `darkpool-matcher` algorithm, complete `nyx-tee` HTTP/WS orchestration, `packages/sdk` transport, `packages/indexer`, ZK circuits (external track), `apps/demo`.
- **Disclaimer:** Point-in-time review at `1cc1bf1`. AI-assisted audit — not a substitute for the planned external circuit audit and a human review of the governance/key-custody operational plan before mainnet.
