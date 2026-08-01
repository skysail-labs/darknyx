# Audit Checkpoint — nyx vault + crypto boundary

**Commit:** 1cc1bf1 (main) · **Scope:** vault program (01-07,16) + crypto boundary (darkpool-crypto/matcher, nyx-tee settle, sdk crypto) · **Anchor:** 0.32.1

## Progress
- Phase: 1 (on-chain program)
- Corpus: SKILL/README/FULL-AUDIT/OUTPUT-RULES/COSTS/file-map/KV-INDEX/report-template read. Checklists 01-07/16 + KV bodies = reference as I go.

## Files reviewed
- lib.rs (16 ix entrypoints), state.rs (PDAs), errors.rs, merkle.rs, zk/verifier.rs
- deposit.rs ✅ , withdraw.rs ✅

## Files remaining (vault)
- lock_note, release_lock, create_wallet, merge
- verify_match_batch, tee_forced_settle_batched, tee_forced_settle, close_batch_validity_marker
- initialize, initialize_tree, rotate_root_key, set_protocol_config, set_tee_pubkey
- reset_merkle_tree, close_vault_config
- zk/mod.rs + vk_*.rs (spot)
- Then crypto boundary crates + tee settle + sdk crypto

## Findings so far
- (none ≥4 yet) deposit/withdraw clean: CEI order, init nullifier replay guard, solvency invariant, note_commitment bound as VALID_SPEND wire-1, canonical-bump seed guards on consumed/lock AccountInfo.
- INFO: init_if_needed on vault_token/outstanding_mint — verified safe (token-acct constraint re-check; data-acct load-not-reinit).
- WATCH: withdraw rejects even EXPIRED note locks (needs release_lock first) — liveness/censorship window bounded by MAX_LOCK_TTL_SLOTS; revisit after lock_note authz.

## Files reviewed (update)
- lock_note ✅, release_lock ✅, verify_match_batch ✅, close_batch_validity_marker ✅
- tee_forced_settle_batched ✅ (settle), tee_forced_settle ✅ (shared: payload/hash/sig/relock)

## Findings so far (still none ≥7)
- INFO: batched-settle marker existence read via raw bytes — owner==program + seed-prefix uniqueness make it safe, but no Anchor discriminator check (defense-in-depth could add).
- LOW(design): on-chain settle solvency/mint-consistency depends ENTIRELY on VALID_MATCH_BATCH circuit conservation/range soundness (out-of-scope external circuit audit — already planned). On-chain bindings (lock VALID_INPUT, leaf→marker, init replay PDAs) are correct.
- LOW: TEE can lock a note (note owner's VALID_INPUT proof) → withdraw blocked until expiry+release_lock; censorship window bounded by MAX_LOCK_TTL_SLOTS (24h). Inherent to lock model.
- verify_tee_signature: KV-102 precompile bypass — NOT vulnerable (inlined pk/msg required, sysvar address-validated).

## CU / EFFICIENCY track (user-requested)
- settle: vault_config.load() ×2 + note_lock_a/b load ×2 — combinable (minor; AccountLoader load is cheap).
- settle: up to 6 sequential append_leaf, each 20 Poseidon2 = up to ~120 Poseidon/ix. Biggest CU lever — a multi-leaf batch-append sharing path recomputation would cut redundant hashing. INVESTIGATE.
- deposit: 1 append_leaf (20 Poseidon) + commitment Poseidon6. Inherent.

## VAULT PROGRAM COMPLETE (all 18 ix + state/merkle/verifier/zk-wiring)
create_wallet ✅ (unused vault_config acct = INFO), merge ✅, initialize ✅, initialize_tree ✅,
set_tee_pubkey ✅, set_protocol_config ✅, rotate_root_key ✅, reset_merkle_tree ✅, close_vault_config ✅, zk/mod ✅

## FINDINGS (vault program)
- F-01 MED(6→HIGH on mainnet): reset_merkle_tree — admin zeroes a shard → ALL pre-reset notes unspendable (total fund FREEZE). Devnet-only+documented but compiled into every build. Fix: cfg-feature-gate out of mainnet build OR multisig+timelock.
- F-02 MED(6→HIGH on mainnet): close_vault_config — admin wipes config (brick); then initialize is first-caller-wins → admin-hijack front-run. Same fix (gate out / multisig).
- F-03 LOW(3): initialize first-caller-wins (no upgrade-authority gate) — front-run window between deploy+init. Mitigate: init atomically post-deploy / check program upgrade authority.
- F-04 LOW(3-design): on-chain settle solvency/mint-consistency depends on VALID_MATCH_BATCH circuit soundness (external circuit audit — planned). On-chain bindings correct.
- F-05 LOW(3): TEE lock → withdraw blocked until expiry+release_lock; censorship window ≤ MAX_LOCK_TTL_SLOTS (24h). Inherent to lock model.
- INFO: create_wallet passes unused vault_config (remove). set_tee_pubkey doesn't reject zero/dup keys (admin-trusted, unsignable). batched-settle marker read raw (no disc check; seed-prefix-unique → safe). Admin/root single-sig on devnet — mainnet needs multisig (documented).
- POSITIVE: deposit/withdraw/merge conservation+replay guards solid; verify_tee_signature not KV-102-vulnerable; 1:N marker lifecycle correct (§8.2); CEI order respected; checked arithmetic throughout.

## CU/EFFICIENCY (vault)
- settle: up to 6 sequential append_leaf (each 20 Poseidon2) = up to ~120 Poseidon/ix — BIGGEST lever. Multi-leaf batch-append sharing path recomputation would cut redundant hashing materially.
- settle: vault_config.load() ×2 + note_lock_a/b load ×2 → combinable (minor).
- create_wallet: drop unused vault_config account (tx size).
- Groth16 verify (pairing) dominates verify_match_batch/withdraw/lock/merge — inherent.

## STATUS: COMPLETE
REPORT.md + roadmap.md written. Crypto boundary reviewed: note/nullifier/field (Fr-safety+parity ✅), fill_encryption (ECIES sound, fresh OsRng ephemeral/nonce per fill ✅), ed25519 precompile builder (parity ✅), payload.rs (canonical-hash fixed-vector parity ✅). Scans: no unsafe, no raw invoke, init_if_needed safe, secrets ok except F-06 demo keypairs.
Final: 12 findings, 0 critical/high (devnet), Risk 6/MED. Top = F-01/F-02 devnet admin backdoors (gate before mainnet), F-04 circuit-soundness dependency.
NOT line-reviewed (honest scope): full matcher algo, nyx-tee HTTP/WS orchestration, sdk TS transport, indexer, circuits (external track), apps/demo.
