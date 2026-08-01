# Remediation Roadmap — audit_1 (commit 1cc1bf1)

Prioritized fix list. Full detail in `REPORT.md`. Repo Risk Score: **6 / MEDIUM** (devnet) → HIGH if mainnet-deployed unchanged.

## 🔴 Before mainnet — BLOCK DEPLOY
1. ~~**F-01 `reset_merkle_tree`** (admin can freeze all funds).~~ **DONE** — `#[cfg(feature="devnet-admin")]`-gated OFF by default; a mainnet `cargo build-sbf` (no feature) has no such discriminator. Branch `vault-mainnet-hardening`.
2. ~~**F-02 `close_vault_config`** (admin can brick + init-hijack).~~ **DONE** — same `devnet-admin` gate; gone from mainnet builds (so the close→re-init hijack is impossible on mainnet). Residual "bind `initialize` authority" belongs to F-03.
3. **F-10 single-sig admin/root/upgrade authority** (→HIGH) — move all three to a governance multisig; attestation-gate TEE-key rotation. **CODE + RUNBOOK DONE** → `docs/governance.md` (Squads v4 target, bootstrap/transfer runbook, F-03 interaction, verification; attestation gate = process control per `tee-attestation-flow.md` §5). Vault needs **no** code change — `admin`/`root_key`/upgrade authority are opaque pubkeys, so a multisig vault PDA drops in. **Remaining = operational**: stand up the multisig + transfer the authorities at mainnet deploy (needs keyholder pubkeys; devnet stays single-key).
4. **F-04 circuit soundness** (4) — complete the external ZK circuit audit (conservation/range/fee-floor live in VALID_MATCH_BATCH). On-chain bindings for those are correct — price fairness is deliberately NOT bound (accepted decision, see "Accepted decisions" below).

## ✅ Accepted decisions (deliberate trust assumptions — not TODOs)
- **F-11 — price fairness is TEE-trusted (DECIDED 2026-07-08: accept, option b).** `VALID_MATCH_BATCH` proves output-note construction + per-leg conservation + range + fee floor, but NOT execution price (only the definitional `quote == base·price`); no trader limit price or oracle band is bound on-chain. A compromised TEE colluding with a counterparty leg could clear a victim outside its limit and extract up to the order size — but the proof still bounds it to **no value inflation + liveness**. We evaluated closing it and rejected both on-chain paths: in-circuit Ed25519 limit-binding is infeasible (~tens of millions of constraints); committing limits on L1 erodes the "orders never touch L1" design; and an on-chain oracle band adds Pyth infra + CU + settle-tx account pressure + a T0(match)→T1(verify) staleness problem that causes either a weak band or liveness failures — and a payload-claimed `pyth_at_match` is circular. **Compensating controls:** enclave attestation (F-10 / tee-attestation track), client fill-memo detection, bounded loss. Full defense: `CRYPTOGRAPHY.md` §2 "Accepted design decision — price fairness is TEE-trusted" + `docs/tee-architecture.md`. **Revisit only if** institutional counterparties require prevention (not detection) → a deliberate deposit/lock redesign, not a VK bump.

## 🔵 Next sprint — LOW
6. ~~**F-03 `initialize` front-run** (3) — bind initializer to program upgrade authority.~~ **DONE** — the mainnet `initialize` variant binds the signer to the program upgrade authority (`program` + `program_data` account constraints: `program_data.upgrade_authority_address == admin`), `#[cfg(not(feature = "devnet-admin"))]`. Dev/test/devnet build keeps the plain-signer variant (litesvm loads the program non-upgradeably → no ProgramData to bind; front-run isn't a threat where we control the deploy) — same gate philosophy as F-01/F-02. CI `sbf-build` now also compiles the mainnet artifact so the binding is guarded. Runbook + bootstrap order in `docs/governance.md` §3-4.
7. **F-05 lock censorship window** (3) — consider a shorter `MAX_LOCK_TTL_SLOTS` for prod.
8. **F-06 committed demo keypairs** (2) — relocate `apps/demo/.demo-keypairs/*.json` under an ignored path / runtime-generate; never reuse on mainnet; verify `apps/demo/.env.local`.

## ⚪ Backlog — INFO / hardening
9. ~~**F-07** remove unused `vault_config` account from `create_wallet`.~~ **DONE** (CU-3, merged PR #20; `create_wallet.rs` no longer takes `vault_config`).
10. ~~**F-08** add Anchor discriminator check on the raw marker read in `tee_forced_settle_batched`.~~ **DONE** (commit df41f72; `require!(&marker_data[..8] == BatchValidityMarker::DISCRIMINATOR, InvalidBatchBinding)` + regression `settle_rejects_marker_with_tampered_discriminator`).
11. ~~**F-09** `set_tee_pubkey`: reject zero/duplicate keys.~~ **DONE** (commit df41f72; rejects `Pubkey::default()` + dups via `InvalidTeeKey` + regressions `set_tee_pubkey_rejects_zero_key`/`_rejects_duplicate_keys`).
12. **CI**: wire `cargo audit` + `npm audit`; ~~add a fuzz target for `append_leaf` / `walk_merkle_path_n16` index handling.~~ **FUZZ DONE** — `programs/vault/tests/merkle_fuzz.rs` (proptest): differential `append_leaves` vs sequential `append_leaf` (oracle), `walk_merkle_path_n16` index-bounds + never-panic + round-trip vs a naive N16 reference tree (host Poseidon), + inclusive tree-full boundary. ~14s, wired into the vault-zk CI job. **STILL TODO: `cargo audit` + `npm audit` CI gates.**

## 📦 Dependency advisories — Dependabot / `cargo audit` / `npm audit` triage (2026-07-07)

GitHub Dependabot flagged ~29 (1 crit / 11 high). Triaged against actual reachability
+ the byte-equality / Groth16 contracts. Most are transitive noise in the
Solana-web3 / ark / wasmer / litesvm stacks.

**FIXED (commit `c26c384`, validated + pushed):**
- `openssl 0.10.78 → 0.10.81` (+ `openssl-sys`) — the ONLY production-reachable Rust
  vuln (`nyx-tee` TLS via `reqwest → native-tls`). Closes the 3 rust-openssl GHSAs.
- `crossbeam-epoch 0.9.18 → 0.9.20` (RUSTSEC-2026-0204) — cheap transitive patch.

**VERIFIED SAFE — no action (do not re-litigate):**
- `jsonwebtoken 9.3.1` "Type Confusion → authz bypass" — NOT exploitable in `nyx-tee`:
  `api/auth.rs` pins HS256 via `Validation::default()` (rejects `alg:none`/RS256), uses
  a SYMMETRIC `from_secret` key (dstack-sealed, no public key to confuse), validates
  signature + `exp`, has `jti` revocation + short TTL. Confirmed against the v9 source.
- `ed25519-dalek 1.0.1` / `curve25519-dalek 3.2.0` / `cmov` — TEST-ONLY (pulled only via
  `litesvm → agave-precompiles` dev-deps); never in the shipped program or TEE binary
  (production ed25519 = 2.2.0, curve25519 = 4.x). `cmov` is aarch64-only; CVM is amd64.
  Un-bumpable without upstream litesvm/agave.
- `tracing-subscriber 0.2.25` (ANSI log injection) — pinned by the `ark-relations 0.5.x`
  ecosystem; a 0.2→0.3 major bump would drag the Groth16 `ark-*` stack. Operator-only log.
- `quinn-proto 0.11.14` (high) — `cargo tree` finds no reachable path (unused feature/target).

**ACCEPTED / deferred (upstream-blocked):**
- `ws` (high — mem-DoS `GHSA-96hv-2xvq-fx4p` + uninit-disclosure). Two instances, neither
  cleanly fixable: (1) `ws@8.18.0` via `circomlibjs → ethers → @ethersproject/providers` —
  UNREACHABLE (circomlibjs is used for Poseidon hashing; no workspace source imports ethers,
  so its WebSocket provider is never instantiated); (2) `ws@7.5.10` via `@solana/web3.js` —
  the DoS has NO 7.x patch, and forcing ws 8.x risks web3.js's runtime WS (can't validate
  offline — WS tests are env-gated). Both are ws CLIENTS to a trusted RPC over TLS → low
  practical exposure (needs a malicious/MITM'd WS peer). **DEFER to the `@solana/web3.js` →
  `@solana/kit` migration**, which rebuilds this whole subtree (drop ws 7.x there). `npm audit
  fix` is DESTRUCTIVE here (wants `web3.js@0.0.3` / `spl-token@0.1.8`) — do NOT run it.
- The rest of the npm prod tree (`uuid`, `jayson`, `bigint-buffer`, `tmp`, `underscore`,
  `uuid`) is deep `@solana/web3.js` transitive — same kit-migration disposition.

**OUT OF SCOPE:** `apps/demo/package-lock.json` (the `shell-quote` critical, `postcss`,
`js-yaml`, `@babel`, etc.) — a SEPARATE demo lockfile, not production; not touched.

## ⚙️ CU / efficiency (separate track)
- **CU-1 (top lever)**: `tee_forced_settle_batched` does up to 6 sequential `append_leaf` (~120 Poseidon/ix). A multi-leaf batch-append sharing path recomputation is the biggest on-chain CU saving.
- **CU-2**: dedupe `vault_config` / `note_lock_a/b` loads in settle (minor).
- **CU-3**: drop unused account in `create_wallet` (tx size).
- Groth16 verify + depth-20 Merkle hashing are inherent; batching (N=16 proof, batch-append) is the right lever.

## Re-audit checklist
- [x] F-01/F-02 gated behind `devnet-admin` (default OFF); CI guard asserts the lib.rs handlers stay gated. Rigorous verify (mainnet artifact): `anchor idl build -p vault -o /tmp/idl.json` then assert `reset_merkle_tree`/`close_vault_config` absent — confirmed 2026-07-08 (14 instructions, neither present).
- [~] Admin/root/upgrade authority = multisig — model + bootstrap/transfer runbook documented (`docs/governance.md`, Squads v4); F-03 initialize-binding shipped. **Live transfer is a mainnet-deploy step** (then verify `solana program show` "Authority" + `VaultConfig.admin`/`root_key` == multisig vault PDA). Devnet stays single-key.
- [ ] External circuit audit complete + N=16 fixture green
- [x] F-11 price fairness: DECIDED — accepted as TEE-trusted (option b); docs defend the decision (CRYPTOGRAPHY.md §2 + ARCHITECTURE.md + tee-architecture.md, 2026-07-08). Re-audit action: confirm the compensating controls are live — attestation pinning (F-10) + client fill-memo enforcement.
- [ ] Deps: re-run `cargo audit` + `npm audit` after the `@solana/web3.js` → `@solana/kit` migration (clears the `ws` / web3-transitive advisories); confirm openssl stays patched
- [ ] Then re-run this audit on the Anchor-1.0-upgrade diff (next workstream)
