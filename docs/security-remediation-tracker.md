# Darknyx security remediation tracker

This is the closure ledger for the independently validated findings in the
2026-07-14 cryptography/systems review and residual sweep. A finding is not
closed by code alone: the closing PR must link the invariant restored, wire or
circuit impact, tests, devnet/CVM evidence where applicable, and rollback
instructions.

Status values are `Open`, `In progress`, `Code complete`, and `Closed`. `Closed`
requires merged code and the evidence named in the row. Mainnet process gates
remain open until their external evidence exists even if supporting code and
runbooks have landed.

## Cryptography and systems findings

| ID | Severity | Owner | Planned remediation slice | Invariant / required evidence | Status |
|---|---|---|---|---|---|
| CS-01 | Critical | ZK + vault + TEE | `remediation/match-batch-v3` | Every fee note is per-match and issued atomically with consumption of that match's real inputs; negative phantom-slot proof; regenerated zkey/VK/N=16 fixture; live settle | Closed |
| CS-02 | High | ZK + vault | `remediation/governance-markets`, `remediation/match-batch-v3` | Every active slot is bound to one enabled on-chain market, its mint halves, and price scale; mixed-market proof rejected | Closed |
| CS-03 | High | ZK + SDK + TEE | `remediation/match-batch-v3` | User and fee output inners are constrained, deterministic, and recoverable from consumed inputs; arbitrary-inner witness rejected | Closed |
| CS-04 | High | TEE + matcher | `remediation/canonical-order-v2` | Settlement IDs include boot session and counter; reboot/page collision tests; output safety does not rely on identifier uniqueness | Closed |
| CS-05 | High | SDK + daemon | `remediation/client-custody` | Wallet-signature seed mode removed; versioned encrypted CSPRNG seed export/import and migration tests | Closed |
| CS-06 | High | Matcher + TEE | `remediation/fee-identifier` then `remediation/match-batch-v3` | Matcher-recorded identifier is used by commitment and witness; no consumer re-samples a Solana slot | Closed |
| CS-07 | Medium | ZK + vault + SDK | `remediation/input-merge-v3` | Lock amount is a private 64-bit witness and absent from instruction/event data; artifacts regenerated | Closed |
| CS-08 | Medium | Matcher + ZK | `remediation/match-batch-v3` | Per-match fees cannot reuse an inner/nullifier across pages or reboots; collision regression tests | Closed |
| CS-09 | Medium | Vault | `remediation/vault-lifecycle` | Tx D rejects at and after either input lock's expiry; boundary litesvm and live settle tests | Closed |
| CS-10 | Medium | Matcher + TEE + SDK | `remediation/canonical-order-v2` | Viewing key is signed; non-contributory X25519 points rejected; low-order KATs | Closed |
| CS-11 | Medium | TEE | `remediation/canonical-order-v2` | Exact idempotency is handled before a durable strictly-increasing per-trading-key nonce check | Closed |
| CS-12 | Medium | SDK + daemon + ZK | `remediation/input-merge-v3` | Merge output inner derives from consumed commitments; no restart-sensitive merge counter | Closed |
| CS-13 | Medium | Daemon | `remediation/daemon-trust` | Strict startup fails closed; finalized TEE keys refresh each minute; mismatch/staleness pauses placement while reconciliation continues | Closed |
| CS-14 | Low | Crypto + SDK | `remediation/client-custody` | Existing bytes retained under `nyxShakeKdfV1`; fixed Rust/TS KATs; no NIST KMAC claim | Closed |

## Performance findings

| ID | Severity | Owner | Planned remediation slice | Invariant / required evidence | Status |
|---|---|---|---|---|---|
| P-01 | Perf | Vault + SDK + TEE | `remediation/vault-lifecycle` | Batch marker is read-only in every Tx D builder and live Tx D; distinct-shard Tx Ds share no writable key | Closed |
| P-02 | Perf | TEE | `remediation/settlement-efficiency` | Build the N=16 tree once and extract every path; hash-count regression/benchmark | Closed |
| P-03 | Perf | Matcher | `remediation/matcher-performance` | Price-level aggregates and reusable demand curves preserve FIFO, tie-breaking, IOC/FOK/AON under differential properties | Closed |
| P-04 | Perf | TEE RPC | `remediation/settlement-efficiency` | Poll all pending signatures in one RPC request; remove confirmed entries; rebroadcast only overdue transactions | Closed |

## Residual findings

| ID | Severity | Owner | Planned remediation slice | Invariant / required evidence | Status |
|---|---|---|---|---|---|
| N-01 | High | TEE | `remediation/tee-intake` | Production exits on dstack/KMS probe failure; test auth requires explicit simulator mode; production rejects test credentials | Closed |
| N-02 | High | Matcher + TEE | `remediation/settlement-outcomes`, `remediation/finality-gated-book` | Book/fills commit only after per-match settlement outcome; ambiguous results reconcile/redrive; rejected matches are terminal and never auto-rebooked | Closed |
| N-03 | High | Matcher | `remediation/matcher-correctness` | Zero-limit market asks remain eligible but are not price candidates; bid@150/ask@0 clears positively | Closed |
| N-04 | High liveness | Vault + SDK | `remediation/vault-lifecycle` | Merge proves every active input's NoteLock PDA absent; negative tests plus live merge-to-settle | Closed |
| N-05 | Medium privacy | TEE | `remediation/tee-intake` | Order reads enforce account ownership and return indistinguishable 404s | Closed |
| N-06 | Medium | TEE | `remediation/tee-intake` | One collateral commitment reserves at most one live or pending order; lifecycle release tests | Closed |
| N-07 | Medium | Matcher | `remediation/matcher-correctness` | Matcher output construction uses note-bound `owner_commitment`; randomized assembler parity | Closed |
| N-08 | Medium | TEE + SDK + daemon | `remediation/stream-consolidation` | Only in-band-authenticated `/v1/stream` remains; gap detection, refresh, reconnect, and cancel-on-disconnect preserved | Closed |
| N-09 | Medium privacy | TEE | `remediation/tee-intake` | Clearing prices are absent from production info logs | Closed |
| N-10 | Medium ops | Vault | `remediation/governance-markets` | Initialization rejects default root and TEE keys; negative litesvm tests | Closed |
| N-11 | Medium ops | Vault | `remediation/governance-markets` | Authorized TEE key count equals tree count at initialization and rotation | Closed |
| N-12 | Medium | Vault | `remediation/vault-lifecycle` | Marker closes only after expiry; rent returns to recorded payer; boundary tests and live async sweep | Closed |
| N-13 | Medium | ZK | `remediation/input-merge-v3` | VALID_INPUT amount is range-constrained to 64 bits while private | Closed |
| N-14 | Medium | ZK + vault | `remediation/input-merge-v3` | Merge has at least one active positive input/output; all-dummy/zero proofs and on-chain calls rejected | Closed |
| N-15 | Low-Medium | SDK + daemon | `remediation/daemon-trust` | On-chain Merkle-root-ring verification is default-on in daemon proving | Closed |
| N-16 | Low | SDK | `remediation/client-custody` | Commitment equality is byte-based; mixed-case encoding regression | Closed |
| N-17 | Perf | Vault + TEE + SDK | `remediation/settlement-payload-v9` | Dead nullifiers removed; canonical domain bumped; worst-case Tx D <=1120 bytes with >=112 bytes headroom | Closed |
| N-18 | Critical mainnet gate | Governance + ZK | `remediation/release-assurance` | Public Phase-2 ceremony with at least five independent contributors, transcript/hashes, random beacon, reproducible verify, auditor sign-off, post-ceremony settle | Open |
| N-19 | High mainnet gate | Governance | `remediation/governance-markets`, `remediation/release-assurance` | Split Squads rehearsal: operations 3-of-5 admin and cold root/upgrade 4-of-7; independent attestation verification before rotations | In progress |

## Unique findings — 2026-07-18 delta pass

Delta backlog from the 2026-07-18 defensive self-audit
(`docs/audit-2026-07-18-unique-findings.md`), remediated first on
`remediation/audit-2026-07-18-unique` and then revalidated/followed up on
`remediation/audit-2026-07-18-residuals`. All were validated genuine against
the relevant `main` before fixing.

| ID | Severity | Owner | Planned remediation slice | Invariant / required evidence | Status |
|---|---|---|---|---|---|
| U-01 | Medium (in-model) | Vault + docs | `remediation/audit-2026-07-18-unique` | `MarketConfig.tick_size`/`min_order_size`/`circuit_breaker_bps` documented as TEE/matcher-enforced only (not proof-bound), same trust class as price fairness; no false "on-chain-enforced" claim remains | Closed |
| U-02 | Low | Vault + SDK + TEE | `remediation/audit-2026-07-18-unique` | `lock_note` rejects an already-consumed commitment via a must-be-absent commitment-keyed `ConsumedNoteEntry` account (`NoteAlreadyConsumed`); differential litesvm test (consumed → reject, unconsumed → past guard); account order lockstep across on-chain/SDK/TEE builders | Closed |
| U-03 | Low | ZK + vault | `remediation/audit-2026-07-18-unique` | VALID_MATCH_BATCH constrains `quote_amount ≠ 0` on active slots (no unspendable zero-amount `note_d` leaf); regenerated zkey + `vk_match_batch_n16.rs` + N=16 fixture; negative prover test; live settle | Closed |
| U-04 | Low (in-model) | Vault + docs | `remediation/audit-2026-07-18-unique` | `fill_recovery` documented as a TEE-honesty (not cryptographic) assumption; live-stream + history backfill are the redundancy; no on-chain change | Closed |
| U-05 | Low | Vault | `remediation/audit-2026-07-18-unique` | Settle fee-note comments rewritten to the per-match model (each active slot appends its own fee notes; no slot-0-aggregate language) | Closed |
| U-06 | Perf-Nit | Matcher | `remediation/audit-2026-07-18-unique` | `generate_matches` skips zero-quote clears (companion front-line to U-03); unit test (zero-quote → no match, positive-quote → match) | Closed |
| U-07 | Perf-Nit | — | — | Ed25519 precompile full-instruction scan is intentional (replaced a buggy `+8` window); bounded by the TEE-built tx's ix count; declined | Won't Fix |
| U-08 | Medium | TEE + matcher | `remediation/audit-2026-07-18-residuals` | Shared REST/WS intake rejects unknown symbols and off-tick nonzero limits; pure matcher independently excludes bypassed off-tick orders; tick=10 negative and zero-limit market-ask positive regressions | Code complete |
| U-09 | Medium ops | TEE | `remediation/audit-2026-07-18-residuals` | Governed real-market boot requires finalized Vault/Market config and adopts owner+fee+market atomically; one-minute finalized refresh pauses place/modify+matching on RPC/drift/key mismatch while cancel/reconcile continue; placeholder loadgen cannot settle | Code complete |
| U-10 | Low | TEE + vault + docs | `remediation/audit-2026-07-18-residuals` | Active comments and protocol diagrams describe exact fees, per-match fee notes, Poseidon11 leaves, and already-shipped eight-input market binding | Code complete |

## Cross-cutting release deliverables

These are architectural/mainnet-readiness commitments from the remediation
plan, not additional audit finding IDs.

| ID | Owner | Planned remediation slice | Required evidence | Status |
|---|---|---|---|---|
| DR-01 | SDK + TEE + indexer | `remediation/durable-recovery` | The unchanged 128-byte field encrypts two u64s per side; seed + finalized chain reconstructs deposit, trade, change/continuation, and merge openings with commitment and leaf-position verification; exact-fill unit coverage plus a live partial-settle recovery drill | Closed |
| PERF-INV-01 | TEE + Operations | `perf-inv-01-host-diagnostic` | Boot-time in-binary host-CPU profile (no `phala ssh` needed) captures cgroup cpu.max/cpu.stat, cpuinfo model/MHz, visible cores, and a single-thread throughput microbench; root cause is node-specific host contention on prod5 (not the circuit, not a cgroup quota), verified by a real settle on prod9 restoring proving ~5.3×. Production placement on a good node before release certification remains an operational step | Closed |
| PRIV-01 | ZK + vault + SDK | `remediation/deposit-privacy` | VALID_DEPOSIT binds commitment, mint, gross amount, and a recovery nonce while keeping owner commitment + inner hash private; altered public/private fields fail before custody or tree mutation; seed + chain cold recovery remains complete; proof latency, CU, and signed transaction size meet the recorded gates | Closed |

## Pull request evidence template

Every remediation PR must record:

- Finding IDs and the invariant restored.
- Wire, account-layout, canonical-domain, circuit, and compatibility impact.
- Exact validation commands and negative/adversarial cases.
- Devnet transaction signatures and CVM image/attestation evidence when required.
- Rollback instructions, including whether rollback invalidates notes, roots,
  orders, payloads, proofs, or deployed circuit artifacts.
- Tracker rows moved only as far as the available evidence supports.

## Remediation PR evidence

### `remediation/audit-2026-07-18-residuals` — U-08, U-09, U-10

- **Invariant restored.** Every advertised nonzero limit is aligned to the
  finalized market tick at shared REST/WebSocket intake, with an independent
  pure-matcher exclusion for bypassed orders; zero-limit market asks retain
  their intended semantics. A real-mint CVM cannot accept trading from env
  fallback governance: it requires finalized, exact-layout `VaultConfig` and
  `MarketConfig`, adopts proof/policy inputs atomically, and revalidates them
  every minute. Missing/invalid state, parameter drift, disabled markets,
  unauthorized shard signers, or an unavailable settle driver pause place,
  modify, and matching while cancellation and settlement reconciliation keep
  running. Active protocol text now describes exact per-match fees and the
  shipped eight-public-input market binding.
- **Wire/config impact.** Adds stable validation error `1009` for an off-tick
  nonzero limit and rejects unknown symbols instead of routing them into the
  process's sole market. `/system/status.matcher_running` is false during a
  governance pause. `DARKNYX_TEE_BASE_MINT` and `_QUOTE_MINT` must now be set
  together: both select governed real-settlement mode; neither selects explicit
  placeholder-loadgen mode with settlement disabled. No account layout,
  instruction payload, canonical signature domain, circuit, zkey, VK, proof,
  note, root, or settlement transaction layout changes. The CPU CVM image pin
  advances from `tee-v3-hardening-64` to `tee-v3-hardening-65`.
- **Local evidence (2026-07-19).** `cargo fmt --all -- --check`,
  `cargo build-sbf --manifest-path programs/vault/Cargo.toml --features
  devnet-admin`, `cargo build --examples -p darkpool-crypto`,
  `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test
  --workspace` pass. The workspace run includes the in-process loadgen smoke,
  264 TEE library tests (one manual diagnostic ignored), every TEE integration
  target, all matcher properties, all vault/litesvm suites, and proof
  round-trips. Targeted U-02/U-03 revalidation passes
  `lock_note_consumed_guard`, `match_batch_verify`, the SDK lock transport, and
  `match-batch-prototype` (17 tests). SDK/indexer TypeScript compilation passes;
  SDK Vitest reports 264 passed / 23 environment-gated skips and indexer Vitest
  reports 20 passed. U-08 negatives cover tick=10/off-tick rejection plus the
  zero-limit ask exception. U-09 negatives cover unavailable settle state,
  signer and immutable-parameter drift, enabled-fee/zero-owner rejection,
  market disable, paused place/modify, paused matcher ticks, and cancellation
  availability.
- **Live CVM evidence (2026-07-19).** GitHub Actions packaging run
  `29696896207` built and published
  `ghcr.io/skysail-labs/darknyx-tee:tee-v3-hardening-65` (the optional artifact
  upload exhausted the organization quota, but the image-build job succeeded
  and the GHCR manifest returned HTTP 200). A real-mint cold boot on Phala
  prod9 (`tdx.xlarge`, 8 vCPU/16 GB) adopted finalized tick size 5, minimum size
  1,000, breaker 5,000 bps, decimals 6/6, fee 30 bps, and the protocol owner;
  the Merkle mirror started empty and `/system/status` reported healthy trading
  with settlement enabled. The flagship `cvm-settle-e2e` passed in 42.92 s and
  settled Tx D
  `3yZaC1Hx7e32ZMhfKwDVZjRWVtL7dQ1LPMTGqfMBhzayrJZP9BddSWDRDgETMce5L8ZAWHkibPk1KfWnTYLCP21j`
  at slot `477432274`, with one confirmed / zero rejected / zero ambiguous
  outcomes. Internal timings were native witness 219 ms, rapidsnark proof 1,967
  ms, aggregate proof 2,215 ms, lock 1,387 ms, verify 1,325 ms, ALT transaction
  1,271 ms, ALT wait 283 ms, parallel phase 3,540 ms, Tx-D confirmation 10,644
  ms (four rebroadcasts), settlement 10,741 ms, and total pipeline 14,321 ms.
  The boot CPU probe showed unlimited `cpu.max`, zero throttling, and 356.5
  single-thread Mops/s; five auth canaries took 1,586/1,407/1,320/1,338/1,338
  ms. A second cold boot reconstructed all seven leaves. Rotating finalized
  governance to the test signer in tx
  `67R6ghRtsWJPen11b1m6KRubn48GLDfYW7RVEN9F4F95qWqbnDYD6Lx7mQib5YpGMyaFHXQF7W7PpoQmDFmz6zMb`
  produced `params_match=true`, `signers_match=false`, paused matching, and
  changed status to `degraded=true` / `matcher_running=false`. Restoring the
  enclave signer in tx
  `22VAiuTukozXyGwWHGpZ4DzoMv77we1sYr64vyAuHPNaVZfPgjGL6T8e87kXF7jihQpdmgcNH5YNv98PTu2ELvAY`
  resumed trading at the next finalized refresh and returned status to healthy.
  This boot's short CPU probe measured 187.4 Mops/s with the same unlimited,
  zero-throttle cgroup, documenting host variance without affecting the control
  transition. The protected deploy env was securely deleted and the CVM was
  confirmed stopped after both sessions. Rows remain `Code complete` only until
  this PR merges.
- **Rollback.** Revert this PR and redeploy image 64. No notes, roots, orders,
  payloads, signatures, proofs, accounts, or circuit artifacts are invalidated,
  but rollback reopens U-08/U-09/U-10 and restores fail-open env governance plus
  settlement-capable placeholder mode.

### `remediation/tee-intake` — N-01, N-05, N-06, N-09

- **Invariant restored.** Production startup exits before serving HTTP when any
  dstack/KMS probe fails. Test-state auth fallback requires both
  `NYX_TEE_ALLOW_TEST_AUTH=1` and `DSTACK_SIMULATOR_ENDPOINT`; production
  rejects public test credentials and scrubs the historical test API key from
  persisted auth snapshots. `GET /orders/{id}` checks the authenticated account
  and gives byte-identical 404 bodies for foreign and absent ids. Collateral
  commitments are reserved under the matcher write lock through pending
  settlement and released on cancellation; modify checks conflicts before
  cancelling the old order. Matcher info logs no longer include clearing price.
- **Wire/config impact.** Adds stable API error `1204` for reserved collateral;
  foreign order reads change from `200` to indistinguishable `404`. Bootstrap
  credentials move from compose literals to encrypted env substitutions. No
  account-layout, canonical-domain, circuit, proof, or on-chain change. CPU CVM
  image pin advances from `tee-v3-hardening-48` to `tee-v3-hardening-49`.
- **Local evidence.** `cargo build-sbf --manifest-path
  programs/vault/Cargo.toml --features devnet-admin`; `cargo test --workspace`;
  `cargo clippy --workspace --all-targets -- -D warnings`; `cargo fmt --all --
  --check`; SDK and indexer `tsc --noEmit`; SDK Vitest (214 passed, 22
  environment-gated skips) and indexer Vitest (23 passed). Executable negative
  boots for public test credentials, test-auth-without-simulator, and missing
  production dstack all exit 1 before bind. Adversarial order tests cover
  foreign-vs-unknown 404 equality, duplicate collateral while live and
  settlement-pending, release after cancel, and atomic modify conflict.
- **Live CVM evidence (2026-07-14).** GitHub Actions run `29328881299` built
  and pushed `ghcr.io/skysail-labs/nyx-tee:tee-v3-hardening-49` from commit
  `c2d9ab42f4d48bcbdb5fa23532b25bf97553d321`. After devnet tree reset tx
  `X5iMbnyp8mfMsgCRn31tY2Rv71xGF7GsUY9ssnJSfFzDq88Nm4wqUVKShkuj7ocvU83AjXTYVQrDDaCDEUSTgSf`,
  CVM `app_634b2ab4c250466311f0cf09f772b6fd60b5be11` cold-booted instance
  `f5cd2f294d1127d241d18e44dbb76b6910aa2a54` with compose hash
  `e9ec726e122ec1e27deac9cfe824143075fca5743bf57ca96b6311abb97d3a66`.
  Boot logs show successful dstack/KMS signer derivation, removal of the
  historical test account, Merkle cold boot, N=16 proving-key/native-witness
  load, and an enabled settle pipeline; no clearing-price field appears in the
  captured production logs. `/health` and `/info` returned 200, while the
  historical public credentials returned generic `1101`/401. The live
  API/WebSocket suite passed 9/9. Real Intel DCAP validation passed 5/5,
  including nonce freshness, tamper rejection, RTMR3 compose-hash replay,
  signer-set report-data binding, and equality with the finalized on-chain
  `tee_pubkeys`. The protected deploy/auth files were securely deleted and all
  Phala CVMs were confirmed `stopped` after the test window. This closing PR
  carries the code and every item of evidence required by these four rows.
- **Rollback.** Revert this PR and redeploy image 48. This does not invalidate
  notes, roots, orders, payloads, signatures, or proofs, but it reopens N-01,
  N-05, N-06, and N-09. The one-way snapshot scrub does not restore the public
  test account; provision fresh encrypted bootstrap credentials instead.

### `remediation/matcher-correctness` — N-03, N-07

- **Invariant restored.** Zero-limit market asks remain eligible supply at every
  positive price but no longer inject zero into the clearing-price candidate
  set; the pinned bid-at-150/ask-at-zero case clears 10 units at 150 and a
  nonzero quote amount. Buyer and seller change-note commitments now bind to
  the `owner_commitment` proven by each consumed note opening, never the
  client-asserted `user_commitment` metadata.
- **Wire/circuit impact.** No API, Borsh field order, account layout, canonical
  domain, circuit, proving key, verifier key, fixture, or transaction layout
  changes. Existing orders and notes remain compatible. Stale documentation
  for the deleted on-chain matching program was removed from the matcher crate.
- **Local evidence.** `cargo test -p darkpool-matcher` passes the full matcher
  suite, including the deterministic positive-price regression and a Proptest
  property over randomized prices, quantities, surplus amounts, and distinct
  metadata/owner commitments. `cargo test -p nyx-tee` passes the full TEE suite.
  A deterministic 256-case randomized parity test runs a real matcher output
  through `assemble_match` and asserts byte equality for both change-note
  commitments and the signed settlement payload. Formatting and clippy are
  included in the closing branch gate.
- **Devnet/CVM evidence.** Not applicable: this slice changes the pure matcher
  and adds consumer parity coverage without changing a deployed program,
  circuit artifact, transaction, API, boot path, dstack handshake, or transport
  surface. The next CVM image that contains this commit will inherit the same
  matcher tests in its build gate.
- **Rollback.** Revert this PR. No notes, roots, orders, payloads, canonical
  signatures, proofs, or deployed artifacts are invalidated, but reverting
  reopens N-03 and N-07 and again permits zero-price market-ask fills and
  matcher/assembler output divergence when user metadata differs from the
  note-bound owner.

### `remediation/fee-identifier` — CS-06

- **Invariant restored.** The fee-note commitments and proof witness now use
  the same identifier recorded in `RunBatchOutput.batch_slot`. Settlement
  assembly obtains that value directly from the matcher output. The scheduler
  no longer carries a slot source and `BatchAssemblyParams` deliberately has no
  caller-supplied fee identifier, removing the race by construction instead of
  relying on call-site discipline. CS-08 remains open for the v3 replacement of
  this interim slot-derived identifier with collision-resistant per-match fee
  derivation.
- **Wire/circuit impact.** Internal Rust naming changes `fee_slot` to
  `fee_identifier`; no API, Borsh field order, account layout, canonical domain,
  circuit, proving key, verifier key, proof fixture, or transaction layout
  changes. Existing devnet notes, orders, proofs, and deployed artifacts remain
  compatible.
- **Local evidence.** `cargo fmt --all -- --check` and `cargo clippy
  --workspace --all-targets -- -D warnings` pass. `cargo test -p
  darkpool-matcher`, `cargo test -p nyx-tee`, and `cargo test --workspace` all
  pass, including the real N=2 proof round-trip, committed N=16 assembler
  fixture, on-chain N=16 verifier, scheduler integration, load-generator smoke,
  and vault property tests. The adversarial regression constructs matcher fee
  commitments at slot S, identifies S+1 as the old scheduler race value, and
  proves that both witness inners and signed payload commitments remain bound
  to S. SBF and TypeScript gates were not rerun because this slice changes no
  on-chain or TypeScript source and those gates passed on the immediately
  preceding merged remediation branch.
- **Devnet/CVM evidence.** Not applicable: the fix is confined to host-side
  settlement assembly and its internal scheduler interface. It changes no
  deployed program, circuit artifact, API/transport, boot path, dstack/KMS
  handshake, or attestation surface, so a billable CVM run would add no distinct
  coverage beyond the local matcher-to-witness regression and proof tests.
- **Rollback.** Revert this PR. No notes, roots, orders, payloads, canonical
  signatures, proofs, or deployed artifacts are invalidated, but reverting
  restores the scheduler's ability to sample a later slot and can make every
  nonzero-fee match in an otherwise valid batch unprovable.

### `remediation/vault-lifecycle` — CS-09, P-01, N-04, N-12

- **Invariant restored.** Tx D rejects before mutation when the current slot is
  at or beyond either input lock's individual expiry. Merge requires the
  correct `NoteLock` PDA for every active input and proves each is absent before
  proof verification or consumption. `BatchValidityMarker` and inactive relock
  destinations are read-only in every Rust and TypeScript Tx D builder, so
  distinct-shard settles have no shared writable account. Every signer,
  including the recorded payer, is rejected before marker expiry; at the exact
  expiry boundary any signer may close and rent still returns to the payer. The
  durable TEE sweeper reads marker state and submits only expired closes.
- **Wire/account impact.** The merge instruction's `remaining_accounts` now
  contains two equal ordered runs for active inputs: writable
  `ConsumedNoteEntry` PDAs followed by read-only `NoteLock` PDAs. Tx D keeps its
  account order and instruction data but changes marker and inactive relock
  account metas to read-only. `NoteLockExpired` is appended to the vault error
  enum, preserving every existing error code. No Borsh payload, canonical
  domain, circuit, proving key, verifier key, N=16 fixture, or note construction
  changes; the clean devnet reset policy means no compatibility shim is added.
  The CPU CVM image pin advances from `tee-v3-hardening-49` to
  `tee-v3-hardening-51` so Phala cannot reuse the old cached builders/sweeper.
  Image-50 boot inspection found that the bootstrap warning still included the
  API-key identifier; image 51 removes API keys from bootstrap and account
  registration logs and rotates the short-lived rehearsal credentials.
- **Local evidence.** Both plain-mainnet and `devnet-admin` SBF builds pass;
  `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D
  warnings`, `cargo build --examples -p darkpool-crypto`, and `cargo test
  --workspace` pass. Targeted litesvm passes 13/13 batched-settle lifecycle
  tests and 4/4 merge-verifier tests, including exact lock/marker expiry
  boundaries, payer and third-party early-close rejection, rent refund,
  locked-input merge rejection before any consume/tree mutation, and an
  unlocked control using the same real K=2 proof. Rust Tx D layout tests pass
  9/9, including two distinct-shard transactions with no shared writable
  account; marker-sweeper tests pass 4/4. SDK and indexer TypeScript checks pass;
  full SDK Vitest passes 216 with 22 environment-gated skips and full indexer
  Vitest passes 23. The SDK's 18 affected transport tests include Rust/TS
  account-meta parity. The workspace run also covers the N=16 fixture/verifier,
  serialized Tx D cap assertion, and worst-case settle CU profile. After the
  boot-log regression was added, `cargo test -p nyx-tee` passes 254 unit tests
  plus every integration target, and the SDK TypeScript gate passes after the
  three environment-gated leaf-count fixtures were corrected to stay inside
  the production 4,500-slot order TTL.
- **Devnet program evidence.** The guarded deploy upgraded the canonical vault
  `C63v...VWZx` at finalized signature
  `4k3coLKTTsQzSjbaFcLW2mheLxodWmjopX1jjdvACFtQMKDSZKtmh4ffGyVKVQacfvNJ3vw2NPBHHwLUKbAyT7oN`
  (slot 476260803). A stale regenerated `target/deploy/vault-keypair.json` had
  first caused an accidental fresh `5SDF...` program deploy; that unused
  program was permanently closed and all 3.9767004 SOL reclaimed without
  touching `C63v...VWZx`. `deploy-devnet.sh` now fails before deployment when
  the keypair pubkey differs from `declare_id!()`. The final clean-tree reset is
  finalized as
  `3VmokGZTPhtoMdyRmmgZdccqbpKk6DLoyjxJrQnhTuGvVbD6Cjo2XwD4juwrbKAyGTp6ayWPVku9rGyXkt6DV1Ly`
  (slot 476265794).
- **CVM evidence.** GitHub Actions run `29359843816` built public-pullable CPU
  image `tee-v3-hardening-51` from commit `7d2c4417`; its GHCR manifest returned
  HTTP 200. CVM `app_634b2ab4c250466311f0cf09f772b6fd60b5be11`
  cold-booted instance `f5cd2f294d1127d241d18e44dbb76b6910aa2a54`
  with compose hash
  `6777498574d9f29e6257d699599d59e1594e4afb8ba2c19397ddc46e8e3b2c79`
  and signer `KgFs...1AAjsa`. Boot logs showed the N=16 rapidsnark/native
  proving path, empty Merkle cold boot, expiry-gated sweeper, and enabled live
  settle pipeline, with no API-key identifier/value attached to auth logs.
  Against test-harness commit `220886b`, `cvm-merge-then-order` passed 1/1 in
  36.82 s. Its K=2 merge finalized at
  `AUYBeQmAcAZQ5fSeJ4sUD6fhzKi4QrMumLLunga3NMyje8EAaW9uAxsf5AyUbgjUBMT9GQ5ZoX7Ljwv2aJFFTJF`
  (slot 476266196). Tx D finalized at
  `2fmeC9sDw4H2uQge7Z6BFNPsKpBPY2voHXpGVfdPx7Ueo9rVDrMFhTQd6EPXNmav2pHC4dpcocuYL1x2aSxsfH3Y`
  (slot 476266253, 71,930 CU); its per-batch ALT placed the marker in the
  read-only lookup run. The sweeper did not close in the settlement pipeline
  (`close_ms=0`) and later finalized the post-expiry close at
  `2SibncLQaDuEVGuTsg9SYU2Y7ucRevieWGg6KhzwMa7gZg1m1nyQLLwbs72cwziauDgnHvx5eXZWuL9L7zLFPewh`
  (slot 476266481). Both one-time CVM env files were securely deleted and every
  Phala CVM was confirmed stopped. A verbose Solana evidence command did echo
  the local Helius query credential; it was never committed, but that devnet
  key must be rotated before the next run.
- **Rollback.** Revert this PR and redeploy the preceding vault program and TEE
  image together. Existing notes, roots, orders, payloads, signatures, and
  proofs remain byte-compatible, but an in-flight merge assembled with the new
  extra accounts must be rebuilt for the old interface. Rollback reopens all
  four findings, restores payer early-close, and restores the batch-wide Tx D
  write conflict.

### `remediation/governance-markets` — CS-02 infrastructure, N-10, N-11, N-19 infrastructure

- **Invariant restored.** Initialization atomically installs exactly one
  non-default, unique TEE signer per Merkle-tree shard and rejects default
  operations/root keys or reuse of the operations admin as the root authority.
  Mainnet initialization remains bound to the current upgrade authority but
  accepts and enforces a distinct operations admin, supporting operations
  3-of-5 and cold root/upgrade 4-of-7 Squads vaults. Each ordered base/quote
  mint pair has an operations-admin-governed `MarketConfig` PDA with immutable
  mint identity and snapshotted decimals, nonzero price scale/tick/minimum,
  bounded circuit breaker, and an enabled kill switch. Rotation replaces the
  full signer set and must keep its cardinality equal to `num_trees`.
- **Wire/account impact.** `initialize` now serializes
  `operations_admin, Vec<tee_pubkeys>, root_key, num_trees`; the mainnet account
  list names the upgrade authority and includes the program/ProgramData proof.
  `set_protocol_config` shrinks to owner commitment plus fee bps. New
  `initialize_market` and `update_market_config` instructions create/update the
  108-byte `[b"market_config", base_mint, quote_mint]` account; moving matcher
  fields out restores the global `VaultConfig` to its exact 1264-byte layout.
  New governance/market errors are appended so prior error codes do not move.
  The clean reset policy intentionally provides no old initialization/config compatibility.
  `VALID_MATCH_BATCH` does not consume the account until the v3 circuit slice,
  so CS-02 remains in progress. The CPU image pin advances from 51 to 52 for
  the TEE's governed boot reader.
- **Local evidence.** Both plain-mainnet and `devnet-admin` SBF builds pass,
  as do `cargo fmt --all -- --check`, workspace clippy with warnings denied,
  the darkpool-crypto example build, and `cargo test --workspace`. Targeted
  litesvm passes 18/18 across split initialization,
  MarketConfig, protocol config, and signer rotation, including default,
  duplicate, partial-set, authority-reuse, invalid-mint, out-of-bounds, pause,
  and impostor cases. TEE fixed-layout account parsing rejects the old long
  layout, bad discriminators, and bad account ownership. SDK governance
  transport/account parsing passes 16/16; full SDK Vitest passes 226 with 22
  environment-gated skips, indexer Vitest passes 23, and both TypeScript
  no-emit checks and updated devnet helper syntax checks pass.
- **Devnet/CVM evidence.** Image 52 built and pushed successfully from commit
  `cdb80d4` in private workflow run `29366224503`; an anonymous GHCR manifest
  request returned HTTP 200. Its artifact-upload annotation is the known
  organization quota exhaustion and did not fail the image job. The reviewed
  devnet program deployed at slot 476283761
  (`5tZBgbeoD4pMiGb1pZNQ8JJug5nDGPCvSfUJEwk9fpyWgLZw9AeYdufovLv6fJdoz1rymRDFAibsQQmhZbcvsJd1`),
  then the stale 1288-byte VaultConfig was closed
  (`2YAunujYimGivxbso6PEGRtVggQeHWKiqvaBbNUwaHDaMf71tNZEp11YN8dqX3q2M9VckKpANLc7wVhXtmKbm6jL`)
  and cleanly re-founded; the final pre-boot tree reset confirmed as
  `2yLeYsxtFqpf8uwvWaUVDsAT3NiH3RY2UYAsxgL4pdmcr4VA6NFEPpV4bmrKrdiZJy9kQp7h82wBKMrHoykS1kM4`.
  Independent on-chain readback pinned the new VaultConfig to 1264
  bytes with `num_tee_keys == num_trees == 1`, and MarketConfig to 108 bytes
  with the intended mint pair, 6/6 decimals, scale 100000000, tick 5, minimum
  1000, breaker 5000, and `enabled = true`. Image 52 cold-booted with compose
  hash `f72d3bb022e061158eb8eb71d1eb8c478a1a0ec81640bd32a17367ce71bc694a`,
  adopted every governed market field plus the
  30-bps fee, and enabled the live settle pipeline. Exact K-key rotation
  confirmed
  (`v2fRkvgxrqHzv5yd5fD3kKv3PtfhiDghNnmCq9rcSpUcuG7PV59mgnr16jgdpaYueqm7JLHH129ZKXbEjCvtdyV`).
  The targeted real-mint `cvm-settle-e2e` passed 1/1 in 37.34 seconds: deposits
  `roQS4VWBK3JVRpgTjtM3VLztbTfkuCsqxd2mqUhw4HUWFznin5FrYpHShkAQh9X85f1bWWj4cCD5FbAhVpBJwyU`
  and `inqGmEW5RnN98xqKy6MB6SDChujXrbUuTmRDVYad6YcPGLiHrFj3o783T9JGZzexvAajcCvN8FxXCprFbUCVX77`;
  locks `2jTcoqAVTeawa2KQNK2trLhQg8Lfi1wNmEncXkJvQU76ajeujWZ7719JisMn5P3Gzgx4DXxwu2pEzDBtcu1xnY8W`
  and `31Qjy4s3gqFSvfT4sqsjwjYkboWUzbuSdUbsTxfFrQs3JvzJtXcmPVEmJJH7QwrpyMwnanoM6etLRNaKBqwzrL2j`;
  verification `2tD6J6jEWiZqV6xGLa4XsaR63SCmCXpJgHHZfvNyXgjQcJfxZYHdT2mvewzFykgvBUkYoVgeSgYvJc5VwF1eGFgR`;
  and Tx D `2SstKbUHFuEjxzvB82z6mQDaqN5jar5NbFnGHZ4poq3wBgh56GCGyGRDne2VJuZP2pQryUNUbZxYSLSrunUbjtPG`
  at slot 476286313 all confirmed with no error. Shard 0
  ended at leaf count 7. All three Phala CVMs were then confirmed stopped and
  the in-memory test credentials were unset. This closes N-10/N-11. CS-02
  remains in progress until VALID_MATCH_BATCH v3 consumes MarketConfig, and
  the split Squads 3-of-5/4-of-7 rehearsal remains the N-19 release gate.
- **Rollback.** Revert this PR and redeploy image 51 with the preceding vault
  binary. Because the initialization and account model intentionally changed,
  rollback requires another clean devnet re-foundation and invalidates the new
  MarketConfig account/config wire. No circuit artifact changed in this slice,
  but rollback reopens N-10/N-11 and removes CS-02/N-19 infrastructure.

### `remediation/daemon-trust` — CS-13, N-15

- **Invariant restored.** Strict daemon startup now requires a successful
  `finalized` read of the program-owned `VaultConfig` and exact equality between
  its complete signer set and the quote-bound enclave signer set. RPC failure,
  missing/malformed config, mismatch, or an attempt to disable the check in
  strict mode aborts startup. The finalized set refreshes every minute;
  missing/mismatched governance state pauses placement immediately, and RPC
  failure may use the last successful read for no more
  than five minutes. Exact recovery resumes trading. Streams, signed
  cancellation, settlement tracking, and on-chain merge stay active while
  paused. Order VALID_INPUT proving and auto-merge snapshots now require the
  reconstructed root to appear in the finalized on-chain shard root ring by
  default.
- **Wire/circuit impact.** No TEE API, order canonical bytes, Borsh payload,
  account layout, circuit, proving key, verifier key, N=16 fixture, or deployed
  program changes. The local daemon `GET /health` response gains
  `trading_enabled` and trust freshness fields. The SDK exports a `RootVerifier`
  type and hardens the existing on-chain verifier to require finalized data,
  exact account size/discriminator, program ownership, and the embedded shard
  id. Merge leaf pagination now rejects malformed/gapped leaves, changing page
  roots, and reconstructed-root mismatch before proving.
- **Local evidence.** Prettier and both SDK/daemon TypeScript no-emit checks
  pass. Full daemon Vitest passes 156 tests with 2 environment-gated skips;
  full SDK Vitest passes 229 tests with 22 environment-gated skips. Adversarial
  coverage includes startup RPC/null/mismatch failure, strict-check disable
  rejection, the exact one-minute refresh boundary, five-minute staleness and
  recovery, immediate placement pause with cancellation/merge
  continuity, finalized RPC commitment, wrong owner/layout/discriminator/shard,
  unknown/all-zero roots, changing paginated roots, and fabricated leaf
  snapshots.
- **Devnet/CVM evidence.** Not applicable. This slice changes the off-chain SDK
  and reference daemon only; it does not change a CVM image input, TEE boot or
  dstack/KMS path, enclave HTTP/WS surface, on-chain program, circuit artifact,
  transaction layout, or deployed state. A billable CVM run would exercise the
  same unchanged gateway/chain data sources without adding coverage beyond the
  deterministic fail-closed tests.
- **Rollback.** Revert this PR. No notes, roots, orders, signatures, proofs, or
  deployed artifacts are invalidated, but rollback reopens CS-13/N-15: strict
  startup again skips unavailable governance state and daemon proofs again
  trust TEE-supplied roots unless each caller remembers an optional hook.

### `remediation/client-custody` — CS-05, CS-14, N-16

- **Status.** Closed. PR #45 is merged into `main`; CS-05, CS-14, and N-16
  are closed with the local evidence recorded below.
- **Invariant restored.** The public SDK accepts only a securely persisted
  64-byte CSPRNG master seed; the fixed wallet-message signature mode, message,
  helper, and plaintext daemon seed import/export are removed. Recovery uses a
  versioned seed-only envelope with fixed scrypt parameters, fresh salt and IV,
  AES-256-GCM authentication, strict parsing, and a separately supplied backup
  passphrase. The historical raw-SHAKE construction is now exposed as
  `nyxShakeKdfV1` / `nyx_shake_kdf_v1`, explicitly disclaims NIST KMAC/cSHAKE,
  and retains byte-identical output under a shared fixed KAT. Fill-memo and
  chain-recovery commitment equality parse exact 32-byte encodings and compare
  bytes, accepting mixed-case hex while returning canonical lowercase.
- **Wire/circuit impact.** `MasterSeedMode` loses `wallet-signature` and
  `MasterSeedStorage` loses its redundant `generate` callback. The SDK adds the
  `nyx-master-seed-backup` version-1 JSON envelope and backup import/export
  helpers; `nyx-keystore-init` replaces plaintext `--seed` and stdout seed
  disclosure with mutually exclusive `--backup-out` / `--import-backup` flows.
  Rust and TypeScript KDF function names change without changing any derived
  bytes. No TEE API, order canonical, Borsh payload, account layout, circuit,
  proving/verifier key, N=16 fixture, transaction, note, or root changes.
- **Local evidence.** `cargo fmt --all -- --check`, workspace clippy with
  warnings denied, `cargo build --examples -p darkpool-crypto`, and `cargo test
--workspace` pass, including 37 darkpool-crypto unit tests and the fixed Rust
  KAT. SDK, daemon, and indexer TypeScript no-emit checks pass. Full SDK Vitest
  passes 236 tests with 22 environment-gated skips; full daemon Vitest passes
  157 with 2 skips; indexer Vitest passes 23. Adversarial tests cover corrupt
  stored seed length, fresh CSPRNG persistence, randomized backup salt/IV,
  object and JSON recovery, wrong passphrase, ciphertext tamper, unsafe scrypt
  parameters, malformed fields, short passphrases, same-identity daemon
  recovery, the shared Rust/TS KDF KAT, and mixed-case commitments in both live
  fill-memo and durable chain-recovery paths. A built `nyx-keystore-init` smoke
  generated a backup, restored a second keystore with byte-identical owner/user
  commitments, and confirmed both keystores and the backup were mode `0600`.
- **Devnet/CVM evidence.** Not applicable. This slice changes client/daemon
  custody interfaces, host-side naming, and SDK comparison logic only. It does
  not change the deployed vault, circuit artifacts, TEE image inputs, boot or
  dstack/KMS path, enclave API/transport, transaction layout, or devnet state;
  a billable CVM settle would execute unchanged settlement code and add no
  coverage beyond the local byte-parity and recovery tests.
- **Rollback.** Revert this PR to restore the prior API. Existing notes, roots,
  orders, payloads, signatures, proofs, and encrypted daemon keystores remain
  byte-compatible because KDF output did not change. Version-1 seed backup files
  require this PR's importer. Rollback reopens CS-05/CS-14/N-16 and must not be
  used for real-value clients because it restores the portable wallet-signature
  spend authority and case-sensitive commitment comparison.

### `remediation/stream-consolidation` — N-08

- **Status.** Closed. PR #46 contains the implementation and the local and
  live validation evidence recorded below.
- **Invariant restored.** `/v1/stream` is the sole WebSocket route. Bearer
  authentication and refresh happen in-band, every server frame shares one
  connection-global sequence, and one reconnecting SDK session carries order
  operations plus the `orders`, `fills`, and `tree` subscriptions. The daemon
  shares that session across placement and both account channels with
  cancel-on-disconnect enabled. A lag or sequence gap triggers reconciliation,
  reconnect, and resubscription; fills additionally re-run chain backfill.
- **Wire/circuit impact.** `GET /ws/fills`, `GET /ws/orders`, and
  `GET /ws/trading` are removed without compatibility aliases. `/v1/stream`
  gains enforced heartbeat/token expiry and a sequenced `auth_expired` warning.
  The SDK's injectable WebSocket interface is now bidirectional and its legacy
  fills/orders helpers are channel wrappers over `TradingClient`. The daemon
  accepts an optional refresh-token provider; its CLI can mint refreshed tokens
  from all-or-none API credential environment variables. No REST order shape,
  canonical signature, Borsh payload, account layout, circuit, proving/verifier
  key, N=16 fixture, transaction, note, or root changes.
- **Local evidence.** OpenAPI YAML parsing and the deleted-module reference
  check pass. `cargo fmt --all -- --check`, full workspace clippy with warnings
  denied, and `cargo test --workspace` pass, including 253 TEE library tests and
  the route regression proving all three legacy paths return 404 while
  `/v1/stream` remains mounted. SDK, SDK-test, daemon, and indexer TypeScript
  no-emit checks pass. Full SDK Vitest passes 239 tests with 23 environment-gated
  skips; daemon passes 158 with 2 skips; indexer passes 23. Adversarial transport
  coverage includes bearer exclusion from URLs, failed/missing sequencing,
  short-lived-token refresh on the same socket, reconnect + resubscribe,
  cancel-on-disconnect propagation, lag-triggered fill backfill, and shared
  daemon-session reuse.
- **Devnet/CVM evidence.** Image `tee-v3-hardening-53` booted successfully on
  Phala app `634b2ab4c250466311f0cf09f772b6fd60b5be11`, instance
  `f5cd2f294d1127d241d18e44dbb76b6910aa2a54`, with compose hash
  `f1478996a0a3a89fa87ed6da1d7badaf518d13567af3df6df6ec9016551982a2`,
  MRTD
  `f06dfda6dce1cf904d4e2bab1dc370634cf95cefa2ceb2de2eee127c9382698090d7a4a13e14c536ec6c9c3c8fa87077`,
  and primary TEE key `KgFsjoP9fDy78xgmEjn2DtRbPZ6G7t5AWDkPo1AAjsa`.
  The reset-free live API suite passed 10/10, including in-band stream login
  and 404 responses from every removed route. The real DCAP/attestation suite
  passed 5/5, including full attested-key-set comparison with on-chain state
  through the private Helius RPC. The CVM was stopped immediately after these
  checks and the temporary deploy environment was securely deleted.
  Settlement, circuits, vault instructions, and transaction layouts are
  unchanged, so a billable settlement run would add no relevant coverage.
- **Rollback.** Revert this PR and redeploy image 52. No notes, roots, orders,
  payloads, signatures, proofs, or deployed vault artifacts are invalidated,
  but rollback reopens N-08 and restores three token-in-query sockets plus the
  daemon's three-session transport.

### `remediation/settlement-payload-v9` — N-17

- **Status.** Closed. PR #47.
- **Invariant restored.** Tx D no longer serializes or signs two TEE-supplied
  nullifiers that the vault never reads. Commitment-keyed `ConsumedNoteEntry`
  PDAs remain the single replay guard shared by settlement and withdrawal.
- **Wire/circuit impact.** `MatchResultPayload` shrinks from 552 to 488 bytes;
  `tee_forced_settle_batched` instruction data shrinks from 690 to 626 bytes.
  The canonical signature domain moves from `nyx-match-v8` to
  `nyx-match-v9`, intentionally invalidating every v8 payload and signature.
  Rust/Anchor/TEE/SDK serializers, direct-chain and indexer decoders, fixed
  vectors, offsets, and size assertions move atomically. Account layouts, ALT
  address membership, REST/order shapes, circuits, zkeys, verifier keys, N=16
  fixtures, note commitments, nullifiers used by withdrawal, and Merkle roots
  are unchanged.
- **Local evidence.** Mainnet and `devnet-admin` SBF builds pass. Formatting,
  the host parity-example build, workspace clippy with warnings denied, and
  `cargo test --workspace` pass. The v9 cross-language fixed vector is
  `63a10a281ed28632d4fee9c71b38f926f2cda8be6f78850d4f7926655ec8cfa2`
  in the vault, TEE, and SDK. The production-shaped worst-case v0 Tx D is
  1109 bytes, leaving 123 bytes below Solana's 1232-byte cap. Litesvm measures
  63,172 CU for the two-leaf path and 78,388 CU for the six-leaf plus two-relock
  worst case against the unchanged 115,000-CU limit. SDK, SDK-test, indexer,
  and daemon TypeScript no-emit checks pass. Full Vitest passes SDK 240 tests
  with 23 environment-gated skips, indexer 23, and daemon 158 with 2 skips.
- **Devnet/CVM evidence.** The v9 vault was upgraded through the private Helius
  endpoint at signature
  `ogUEFzyBmft8xCP7atcwiZ9jLS74pS24yrczuBEho2SS2dfqQiAPUtTYdqczzNx6MoHo5YPJXFqmJdgr3nZVxbR`
  (deploy slot 476318833), then the single shard was reset at
  `5zjTy2vWadovXw6Qvm6b3x4fSLMZcLz8iC67eeAiGXb5fcuZipgFMRqJZUcibSctHv29LEakAhtaYXgRWBpbdpKu`.
  `tee-v3-hardening-54` cold-booted app
  `app_634b2ab4c250466311f0cf09f772b6fd60b5be11`, instance
  `f5cd2f294d1127d241d18e44dbb76b6910aa2a54`, compose hash
  `1220b1a548a6daf3321be88371373fa672bf10238c01e19d2b3955e91dee15be`,
  MRTD
  `f06dfda6dce1cf904d4e2bab1dc370634cf95cefa2ceb2de2eee127c9382698090d7a4a13e14c536ec6c9c3c8fa87077`,
  and signer `KgFsjoP9fDy78xgmEjn2DtRbPZ6G7t5AWDkPo1AAjsa` with an empty Merkle mirror
  and the settlement pipeline enabled. The isolated real-mint
  `cvm-settle-e2e` passed 1/1 in 40.26 seconds. Its successful on-chain path
  was lock A
  `BRAySrgjcZwsBb2eCkiu8g1t8Tm9ZVXk5KoLW5HcTTkPa3iYkopLXGE2oD6KvJ5T2xKs3BzKdyP68S3biXqMqF1`,
  lock B
  `57fuPdKHq8mXagN8xvTj7AFcwDGkaTzVhEo2zc14S6TdU3JwqeRFVnQeYAffuWX1zC8gmQzq3HBve7oCxQkA5YZR`,
  verify
  `4oUfji6Ajii1QDxUfWQsGG1HCjoRwyjgriiYfAgks3NdMk3mXe5cpYJZDsyG5eKGtP7VZozSKKJwW6o84jwDqBtL`,
  and v9 settle
  `43Jcio2Js71kEcSdD5pi72p9t9g43GkVXmejBBA7zCbTjepr3FwNDP8uQ9XYuuAk1xoM7mAwRhhJ8SqfTc3vuyMh`;
  the intervening signer transaction created the per-batch ALT. The billable
  CVM was confirmed stopped and the mode-0600 deployment environment was
  securely deleted immediately after the run.
- **Rollback.** Revert this PR and coordinate a vault downgrade with image 53
  and the v8 SDK. Notes, circuit proofs, roots, and account layouts remain
  valid, but v9 payloads/signatures and any in-flight settlement jobs are
  incompatible with v8 and must be discarded and resubmitted. Rolling back
  only one component fails closed at deserialization/signature verification.

### `remediation/input-merge-v3` — CS-07, CS-12, N-13, N-14

- **Status.** Closed by the coordinated devnet upgrade/reset and isolated
  billable CVM merge→order settlement recorded below.
- **Invariant restored.** VALID_INPUT binds `amount` only as a private witness,
  constrains it to `1..2^64-1`, and exposes four public signals: root,
  commitment, and two mint halves. The vault/TEE/SDK `lock_note` wire and
  `NoteLocked` event carry no amount. VALID_MERGE requires at least one active,
  positive-u64 input, canonical zero-amount dummy slots, and a positive u64
  sum. Its output inner is derived in-circuit as
  `Poseidon6(26, c0, c1, c2, c3, active_bitmap)`; the SDK, daemon, and Rust
  real-settle loadgen no longer use a restart-sensitive merge counter or a
  caller-selected output-inner witness. The vault independently rejects an
  all-dummy instruction before proof verification or tree mutation.
- **Wire/circuit impact.** `lock_note` instruction data shrinks by eight bytes,
  from 393 to 385 bytes including the Anchor discriminator. VALID_INPUT public
  signals move from five to four; VALID_MERGE keeps six/eight public signals but
  replaces its output-inner witness with commitment-derived logic and positive
  active-slot constraints. The VALID_INPUT, K=2, and K=4 circuit sources,
  zkeys, and Rust VK constants change atomically. `build-circuits.sh` now
  regenerates Rust verifier constants itself. Existing circuit proofs and old
  lock instruction payloads are intentionally incompatible; the devnet rollout
  uses a clean tree reset and a newly tagged CVM image.
- **Local evidence.** Deterministic generation completed for every circuit
  managed by `build-circuits.sh`, and all three changed zkeys pass independent
  `snarkjs zkey verify`. `snarkjs r1cs info` reports VALID_INPUT 12,058
  constraints/four public inputs, K=2 merge 25,532 constraints/six public
  signals, and K=4 merge 48,458 constraints/eight public signals. Focused
  snarkjs tests pass 13/13,
  including private-amount public-signal ordering, zero and `2^64` input
  rejection, all-dummy/active-zero/overflow merge rejection, and K=2/K=4
  round trips. Rust/TS merge-inner parity pins
  `1ed62782faeb9cd43f741e189ade09a0406a22f9c633cb9311b00e692c1458d5`.
  Mainnet and `devnet-admin` SBF builds pass. Formatting, the host parity-helper
  build, workspace clippy with warnings denied, and the full Rust workspace pass;
  the feature-gated real-settle loadgen adds 17/17 tests against the regenerated
  ark-circom artifacts. Targeted litesvm passes K=2/K=4/tamper/locked/all-dummy
  merge tests 5/5, batched settlement 13/13, N=16 verifier 2/2, and wallet/spend
  proof round trips. SDK, SDK-test, indexer, and daemon TypeScript no-emit checks
  pass. Full Vitest passes SDK 248 tests with 23 environment-gated skips, indexer
  23, and daemon 158 with 2 skips. Transport regressions pin the 385-byte lock
  instruction and a production-shaped signed lock transaction below 800 bytes.
- **Devnet/CVM evidence (2026-07-16).** The guarded deployment script verified
  that both the local program keypair and `declare_id!` were
  `C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx`, then upgraded that canonical
  program at slot 476508026 with signature
  `2Tko5Q6eTKa4J87SHvZZ9E712tbrCxGZNfBffHw3s9HdsaTJXfrs7BZRaSLCgwNX5AoZzRWpiDJh6nN2DdSVyoBf`
  through the private devnet RPC. The no-CVM `devnet-merge` round trip passed
  1/1 in 11.85 seconds: reset
  `4LFkr2xahkFrLhLyWThVTcHqEvAF8hXAp6QUr4YiiqugBpMwBYkaB93DLKE7NBNdg8KuH8s34vr6URtNBdegAS7s`,
  deposits
  `bkcTfoD92qW3e4gpCHyBBDZdASCYC1CY2euwCSKzt4Nt4YpjWC16P63ieUBS6f9W5pc5cTPgegfCDMNjt7z47H7`
  and
  `5kfVkhBpGkW25vxGcvcVZEbSPK1RFxhWpPBpwEXLAHBCZDnwm7n2kqcwN5B7Eyit96hhjvGEuyT9wRKWizaZqiQk`,
  K=2 merge
  `3QwwLKBEbHLMM4r84fWTkMTff6kRtLS8VRpAawKbpuP2c1KgkRfJvMbkaPWEfW5K3Jgei6fwJj5X1vDqEzmdCPWg`,
  and consolidated-note withdrawal
  `Z4D7snBka9sBRn9baL6tdQqRHkhnV7GUvtYt5KyowAjprGjr44DPDefKKtvFAHAWBPqSNvWSoLrPieFPfhXtp1E`.
  After final reset
  `4UefNvMYLyy4E13iH42UDLsFvCh8JJmTKVMERpn5HpEpwD3GJTdWqsnPf76gTKFCZQwph5cLtYYWxiNQQsdgTTV8`,
  public GHCR manifest `tee-v3-hardening-55` cold-booted CVM
  `app_634b2ab4c250466311f0cf09f772b6fd60b5be11` from floor slot 476508505.
  Boot logs show signer
  `KgFsjoP9fDy78xgmEjn2DtRbPZ6G7t5AWDkPo1AAjsa`, an empty one-shard mirror,
  the rapidsnark N=16 proving key loaded, and the live settlement pipeline
  enabled; signer rotation was confirmed by
  `4EoojjwXL2k6LoBxnBAEftHahcgfCbZRiec3YfqVaa4wrGSdbQSEsHEGCamq2LG6m1HBkt3qhBpoGAomYAVm5kZQ`.
  The isolated real-mint `cvm-merge-then-order` passed 1/1 in 37.65 seconds.
  Its on-chain path was deposits
  `2yu43zJb9YimW7KtTf6tzo4p7DH33wV5baK9SvCmtE1rMvyScNUpewJHYH5wqFCVngiJeboUE9UYRgqJVbGARCJ`,
  `JaTW2qnnXSgpf98bjzxfAXgt4Ej1Zsnw4ZCGwnMm6wKnr9EaVyFJJC7Eh6mUrVV4KmTV1KcNytvuezkY9DELxoQ`,
  and
  `29haBQqBsHp8zqTfmVCcRfkDxQJWNz77GFV3z72FuZG2xPKidHeXiB8aGHruoqUWbCDPUG4DFEwNrr5DGgXSBVJR`;
  K=2 merge
  `5NYzMsYUZaPcHKU639V5n4jPip6uTziQjoehCfoyQCxUuzzXpwzUNKfS5ku9aJ31MxmNFeA2HWTkq7dENmm2k8Kq`;
  locks
  `5te7XBqfkXcXpKzGGtFZVYBtfh9gwvHKwuSg5kFrHgUBv4aGhNYxMahp5M5j8vX17p2hVzt2K8UucjwqsyQqsNbt`
  and
  `4Qso2rUXq2UvZ4GC5M1ksMxfYNBfMQtqR35SZJpP4T1SJEUevesDyxLZbLXtfsHfxkPGjqN31snTR2NMx4bZuh8q`;
  N=16 verify
  `3F5QGXnSf6LxiecCJcXWQT3GimuEUpA55JCXYMNRfNRTn9XX8CvB8PSY7CHd1dointGvGoNBrqBAvozUH4T3HkiH`;
  and settle
  `2ebhrAvpc3orvDb3zYx5cTEoKBbHVrHUK373vsdCwdTXqvXkQFACLwvNq4Aa9nP5HUrEurApW3jJ5swoH6WKHFvB`.
  The protected deploy environment was securely deleted and all three Phala
  CVMs were confirmed stopped. During rollout rehearsal, an unguarded manual
  command briefly created an unused program after `cargo clean` regenerated a
  random target keypair; it never touched the canonical vault, was immediately
  closed permanently, and 4.28060184 SOL was reclaimed. This PR hardens the
  deployment script to honor the private RPC while retaining the canonical-id
  guard that prevented recurrence.
- **Rollback.** Revert this PR and coordinate a vault downgrade with the prior
  CVM image and SDK. The old/new lock wire and all three proving/verifier keys
  are incompatible, so discard in-flight orders/proofs and perform another
  clean devnet reset. Do not mix v2 and v3 circuit artifacts.

### `remediation/match-batch-v3` — CS-01, CS-02, CS-03, CS-08

- **Status.** Closed by the code, artifact, adversarial, devnet, and isolated
  real-mint CVM evidence below. This closing PR carries the implementation and
  evidence atomically.
- **Invariant restored.** Every active match derives its user-output inners as
  `Poseidon3(24, consumed_input_inner, role)` and its fee inners as
  `Poseidon3(25, consumed_input_commitment, role)`. Each match's Tx D appends
  its nonzero base/quote fee notes atomically with the consumption of those
  exact inputs; aggregate fee flushes and slot/reboot identifiers are gone.
  Private boolean activation bits make padding canonical and un-settleable.
  All active slots share the enabled governed market's mint halves and nonzero
  price scale, and prove
  `base * price = quote * price_scale + remainder` with
  `0 <= remainder < price_scale`.
- **Wire/circuit impact.** VALID_MATCH_BATCH moves from three to eight public
  inputs in the exact order root, fee rate, protocol owner, base mint lo/hi,
  quote mint lo/hi, and price scale. Its commitment-only leaf moves from
  Poseidon10 to Poseidon11 by adding `is_active`. Tx B gains one read-only
  `MarketConfig` account while retaining its 304-byte instruction data. Tx D,
  payload v9, canonical signature domain, account layout, and ALT membership do
  not change; its worst-case transaction remains 1109 bytes. Match prices and
  bid collateral adopt governed fixed-point floor semantics. N=2/N=4/N=16
  zkeys, the N=16 Rust VK, and the committed real N=16 proof fixture change
  atomically, intentionally invalidating old batch proofs. CPU image pin moves
  from `tee-v3-hardening-55` to `tee-v3-hardening-56`. Legacy anchor fields
  remain only as transitional order-wire data; they no longer select or gate a
  v3 output and are deleted by canonical order v2.
- **Local evidence.** Independent `snarkjs zkey verify` passes for N=2, N=4,
  and N=16. The production R1CS has 232,806 constraints, 232,284 wires, 384
  private inputs, and eight public inputs. Real snarkjs proofs pass at N=2/4/16;
  the regenerated N=16 ark proof verifies both host-side and in LiteSVM, where
  Tx B measures 132,519 CU under the raised 180,000-CU limit. Adversarial tests
  reject an inactive phantom fee slot, mixed-market commitments, an arbitrary
  output inner, a disabled market, and a proof made for the wrong price scale;
  scaled-floor remainder and all-dummy padding cases are pinned. Rust/TS KATs
  pin output-inner
  `13e02ab830905bd6a94bbf1c9c1d231150db9ee480d9cd2b596a1fc425c6dde0`
  and fee-inner
  `18b28713db5e2e0ebd3a8382ca32d363811d5d2bf4244e916330204be6484c74`.
  Mainnet and `devnet-admin` SBF builds, formatting, parity-helper build,
  workspace clippy with warnings denied, and the full Rust workspace pass.
  SDK, SDK-test, indexer, and daemon TypeScript no-emit checks pass. Full
  Vitest passes SDK 256 tests with 23 environment-gated skips, indexer 23, and
  daemon 158 with 2 skips. The full Rust gate includes 254 TEE library tests,
  4/4 N=16 verifier tests, 13/13 batched-settlement tests, the feature-gated
  real-settle loadgen smoke, and the 1109-byte Tx D regression (123 bytes of
  headroom).
- **Devnet program evidence (2026-07-16).** The canonical vault
  `C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx` was upgraded in place from
  the locally validated 615,680-byte `devnet-admin` binary (SHA-256
  `560e321d3fae047578a989dcca7f275dcc1b6629b33e850817ef3cfff307094f`)
  at finalized signature
  `3kGuNwaguY6XAb8SLj6BfNHFxymRCsmkZqJVM8qiiB9FfGGeCjWPd2GbnvSK8hbQRfg5HEmwDtBSW7EwMQYRnqew`
  (slot 476523752). The clean one-shard tree reset finalized at
  `e46RHfnrfgMoGNP4KE69WBsqSCnBAzY2LYtsmmhDrkbFpVbFvpCR49HL9eMRrp24mh9D4aXMrbsVQiBSFSMGiqp`.
- **CVM evidence (2026-07-16).** GitHub Actions run `29451691084` built and
  pushed public-pullable CPU image `tee-v3-hardening-56` from commit
  `ebe7ce6b31f13a046b68d699b5392470b3acb9f8`; its GHCR manifest returned HTTP
  200. CVM `app_634b2ab4c250466311f0cf09f772b6fd60b5be11` cold-booted instance
  `f5cd2f294d1127d241d18e44dbb76b6910aa2a54` with compose hash
  `c8ce6e69abc34d9a52fb067b9e6ad8bd27a57bcda78757e7a5d777a23e961f39`,
  MRTD
  `f06dfda6dce1cf904d4e2bab1dc370634cf95cefa2ceb2de2eee127c9382698090d7a4a13e14c536ec6c9c3c8fa87077`,
  and signer `KgFsjoP9fDy78xgmEjn2DtRbPZ6G7t5AWDkPo1AAjsa`. Boot logs showed a
  successful dstack/KMS handshake, adoption of the enabled 6/6-decimal market
  at price scale 100,000,000, empty Merkle cold boot, N=16 rapidsnark/native
  witness loading, and an enabled live settle pipeline. The signer matched the
  finalized on-chain K=1 set and already held 2.460691280 devnet SOL, so no key
  rotation or funding transaction was sent.
- **Live settlement evidence.** The isolated real-mint `cvm-settle-e2e` passed
  1/1 in 44.30 seconds using only devnet test-mint deposits. The per-batch ALT
  finalized at
  `2juC7cP13WFXGCBpThr8mKQ9R8JkN8ZvEjCJSA7acbKEasjxFjZHNroiPXZT1WqXxGakX4JKwuWDjwnacXEFHzRP`;
  the two locks finalized at
  `2NN4R83wcxMUDrYvxYSpKtwwGAQ2Vt6uRN6g9oKfeLY4NQcvyewHJqPnnKcT2WqezYgXf3r6HM1iwhX2GwTYuj8s`
  and
  `5UrzYUZnq7kjxMgYKnBSFsb3svDQV2atDfLfNm7LeMMEAosPXGN7aBUAMdCMcR3aGgHgpdcCXfFzcwbnVz9n6chv`
  (108,338 CU each); N=16 verification finalized at
  `2mJy1mw9rLN5raC8d7JSuanu8DUdTUtqjvLPQAXaSBmRcLxdexY48FPJZidSepTq9GfVLaECeH6XqTpyiFC3bXVZ`
  (134,000 CU); and atomic Tx D finalized at
  `NumV16wTbsg6yi4D2iMTMuk1dbchAfS91Z1quxxjuteyhzx4rKgi9d7Depk1ArQNys1uooH4NddEBhXgvJcGmXk`
  (70,364 CU). Every transaction has `err=null`; shard 0 ended at the expected
  seven leaves (two deposits plus five settlement outputs). The protected
  deployment environment was securely deleted, credentials were unset, and
  all three Phala CVMs were confirmed stopped immediately after the test.
- **Rollback.** Revert the PR and coordinate the prior vault, image, SDK, and
  N=16 artifact set. Old and v3 batch proofs/VKs are incompatible; discard all
  in-flight orders/proofs and clean-reset devnet before restarting the prior
  image. Generic note commitments remain VALID_SPEND-compatible, but no mixed
  old/new matching deployment is supported.

### `remediation/canonical-order-v2` — CS-04, CS-10, CS-11

- **Status.** Closed by PR #50 with local, devnet, and live CVM evidence.
- **Invariant restored.** Settlement ids are the first 16 bytes of a
  domain-separated SHA-256 over the boot session, monotonic match counter, and
  both order ids. Output inners and commitments remain exclusively
  input-and-role-derived, so identifier uniqueness is not a soundness
  assumption. The signed order now binds a required contributory X25519 viewing
  key and the current 32-byte boot session. Intake performs exact-idempotency
  handling before a linearizable, strictly increasing per-trading-key nonce
  high-water check; high-water marks are never evicted, and reboot rotates the
  signed session so old signatures cannot exploit a process restart.
- **Wire/circuit impact.** The canonical signature domain moves from
  `nyx-order-v2` to `nyx-order-v3`; order requests delete `anchors` and add
  required signed `viewing_pubkey` and `session_id`. The anchor top-up API and
  SDK/daemon anchor-pool state are deleted. Live fill memos replace
  `anchor_index` with `consumed_note_commitment` and `output_role`; clients
  accept an output only after resolving that exact input and recomputing the
  v3 inner and commitment byte-for-byte. `/info` adds `boot_session_id`.
  There is no account-layout, Borsh payload, circuit, zkey, VK, N=16 fixture,
  or on-chain program change. Existing orders and signatures are intentionally
  invalidated. The CPU image pin moves from `tee-v3-hardening-56` to
  `tee-v3-hardening-57`.
- **Local evidence.** Formatting, the `devnet-admin` SBF build, Rust/TS parity
  helper build, workspace clippy with warnings denied, and the full Rust
  workspace pass. The final Rust run includes 253 TEE library tests, 38 order
  surface tests, six private fill-routing tests, three WebSocket trading tests,
  and every LiteSVM/ZK target. SDK, SDK-test, indexer, and daemon TypeScript
  no-emit checks pass. Full Vitest passes SDK 250 tests with 23
  environment-gated skips, indexer 23 tests, and daemon 144 tests with two
  environment-gated skips. Adversarial cases cover stale sessions, exact retry
  before nonce rejection, concurrent/replayed nonces, all seven low-order
  X25519 encodings, substituted self-consistent output inners,
  missing/mismatched consumed openings, terminal-update/final-fill routing
  races, reboot/counter/order-id settlement collisions, and identical outputs
  under deliberately different settlement ids.
- **Devnet/CVM evidence (2026-07-16).** The isolated real-mint run reset shard
  0, cold-booted public image `tee-v3-hardening-57`, and logged an empty Merkle
  mirror, loaded N=16 proving key/native witness generator, and enabled live
  settlement. `/info` advertised compose hash
  `8f0bfaa17de298676bdba849b44bd737c259206c455dc1a53ab86ce99d3343c8`,
  MRTD
  `f06dfda6dce1cf904d4e2bab1dc370634cf95cefa2ceb2de2eee127c9382698090d7a4a13e14c536ec6c9c3c8fa87077`,
  a fresh 32-byte boot session
  `41081c373727a0bbb1c314f4237440de93b7be51e51f8c07bae55b262efb338a`,
  and signer `KgFsjoP9fDy78xgmEjn2DtRbPZ6G7t5AWDkPo1AAjsa`. Signer rotation finalized at
  `3FdyRK6Q3F6gbX5cDVQGn8s1Zjf3zLh3tGowoC2Q7ZCbB8mirw2orpeExwPCU4Qv8h4RE9r7CVrScV4BfWQ3zr39`;
  it already held 2.455 devnet SOL. The SDK fetched that boot session, signed
  two canonical-v3 crossing orders, and the flagship deposit → match → settle
  test passed in 39.76 seconds. Atomic Tx D finalized with `err=null` at slot
  476547417 as
  `2LAa3PvvadqENACsFZzczDT8QynRsxvhRLjv1Zk4X6GxeMafwD2PUacGxSVGk2ycxaNjTBWUHuXyxAMcStjwDoSc`;
  the shard ended at the expected seven leaves. The reset-free API/stream and
  real-DCAP suites then passed 15/15 checks, including compose-hash replay,
  quote tamper rejection, report-data key-set binding, and equality with the
  finalized on-chain signer set. The protected deploy environment was securely
  deleted, temporary credentials were removed, and the CVM was stopped
  immediately after validation. No program upgrade was needed because this
  slice changes no on-chain code or verifier artifact.
- **Rollback.** Revert the PR and redeploy image 56 with its matching SDK and
  daemon. Do not mix v2/v3 order clients: canonical bodies, live fill memos,
  and in-memory order state are incompatible. Notes, roots, vault accounts,
  settlement payloads, circuits, and proofs remain valid; discard all in-flight
  orders and reconnect against the new boot session.

### `remediation/durable-recovery` — DR-01

- **Status.** Closed by the image-58 partial-settlement recovery drill. The
  associated prover-latency investigation remains independently open as
  PERF-INV-01 because Phala's unstable SSH API did not expose the requested
  host/container cgroup files during the billable window.
- **Invariant restored.** Every fill side permanently encrypts both private
  amounts needed to rebuild its outputs: buyer `(trade_base, change_quote)` and
  seller `(trade_quote, change_base)`. Recovery resolves the exact consumed
  commitment, re-verifies its opening, derives trade/change inners from that
  input and role, and compares recomputed commitments as bytes. A seed-plus-
  finalized-chain fixed-point scan restores seed-owned deposits, exact and
  partial trade outputs, continuation chains, and merge outputs, including
  their shard and Anchor-event leaf positions. Live stream history and mutable
  merge/deposit counters are not recovery dependencies.
- **Wire/circuit impact.** `fill_recovery` remains exactly 128 bytes and the
  v9 settle payload remains 488 bytes, so Tx D size/headroom and the canonical
  signature domain do not change. Its internal clean-cutover layout becomes
  `ephemeral_pubkey(32) || buyer_enc(44) || seller_enc(44) || "NYXREC02"`;
  the HKDF domain becomes `nyx-fill-enc-v2`. The explicit trailer rejects
  legacy 36-byte blobs instead of ambiguously decrypting them. Locator rows now
  include the finalized transaction slot plus consumed-input and trade-output
  commitments and rename `change_enc` to `output_enc`; exact fills are retained.
  The Solana slot, not the circuit's `batch_slot`, drives incremental cursors.
  No circuit, zkey, VK, N=16 fixture,
  account layout, or on-chain instruction framing changes. The CPU image pin
  moves from `tee-v3-hardening-57` to `tee-v3-hardening-58`.
- **Local evidence.** Rust/TS fixed vectors pin the 44-byte ECIES construction;
  low-order, wrong-key, and tamper cases fail closed. TEE unit coverage proves
  buyer/seller tuples, exact-fill trade recovery, one-sided keys, versioned
  packing, and assembly into the signed payload. SDK/indexer round trips cover
  uppercase byte normalization, exact fills, both market sides, continuation
  chains, legacy-layout rejection, and settle encoder → locator decoder → SDK
  recovery. The cold drill deliberately reverses transaction order and rebuilds
  a deposit → trade/change → merge graph to a fixed point with exact leaf
  indices. Both mainnet and `devnet-admin` SBF builds, the Rust/TS parity-helper
  build, workspace clippy with warnings denied, and the full Rust workspace pass
  locally (including 254 TEE library tests, N=16/prover round trips, and every
  LiteSVM target). SDK source + test, indexer, and daemon TypeScript no-emit
  checks pass. Full Vitest passes SDK 251 tests with 23 environment-gated skips,
  indexer 20 tests, and daemon 144 tests with two environment-gated skips. The
  closing harness correction also passes SDK test TypeScript and the targeted
  cold/fill recovery suites (7/7): `NYX_CVM_CHAIN_RECOVERY=1` makes the buyer
  order partial and invokes the finalized-chain scanner without an indexer or
  live memo. It also corrects the partial-fill trade assertion to the matched
  seller quantity rather than the buyer's original larger order quantity.
- **Devnet/CVM evidence (2026-07-16).** GitHub Actions run `29465041954`
  built and pushed private image
  `ghcr.io/skysail-labs/nyx-tee:tee-v3-hardening-58` from commit
  `63d431362c8c35072bf959cde56c09e64efde7c2`; the manifest returned 200.
  (The workflow succeeded despite the expected non-fatal artifact-quota
  annotation.) Reset tx
  `5roKBo1efYHnEkcoQfTfciUuUn1jWiYVw9W2epYi3PWwkihHs8yzAUEFJYokTEhiSqLJWXESnTVaCGe6HHdHaHYK`
  cold-booted CVM `app_634b2ab4c250466311f0cf09f772b6fd60b5be11`,
  instance `f5cd2f294d1127d241d18e44dbb76b6910aa2a54`, with compose hash
  `8f67f068f3878d6d903a9d172eb180a3ded84b4290bf2024703101c294ef2070`,
  MRTD
  `f06dfda6dce1cf904d4e2bab1dc370634cf95cefa2ceb2de2eee127c9382698090d7a4a13e14c536ec6c9c3c8fa87077`,
  boot session
  `4a79d0e65bed0fa1f217bb3d1af19cd20d83593de2ae3de7685c4ffcd2b282ec`,
  and finalized signer
  `KgFsjoP9fDy78xgmEjn2DtRbPZ6G7t5AWDkPo1AAjsa`. Boot logs showed an empty
  one-shard mirror, native witness generation, and the live settle pipeline.
  The ordinary flagship passed in 39.65 seconds; Tx D confirmed at slot
  476569460 as
  `2Y862q8WisA547vb8FwxX7YYagw8LGkFBxJFc4kaWUWpjdhwwet4NwPeeQzmtqxpaHMYPNz9x3eiUA4FmingtBpn`
  with `err=null` and 66,014 CU.

  A second clean reset tx
  `94FSR2cPamFF536YTgAx4dHDjiPGsRc6zVpGStAUnRQEepukyqr6kYd4qZVQsdyx4DSwJBCp5qvdJxuZaAUi4jY`
  and cold boot (session
  `b4de3c3bcdd7c77216fb7a4582e32f84c40297cb95a202fa25a1b57bbb63c7ce`)
  ran the corrected indexer-free partial drill with deterministic quantity
  42,000 and buyer multiplier 2. It passed in 51.74 seconds, grew the tree from
  two deposit leaves to seven leaves, and reconstructed the buyer deposit,
  42,000-unit trade output, and positive 5,185,364-unit continuation output
  from seed plus finalized chain only in 10.98 seconds. Tx D confirmed at slot
  476571554 as
  `5TMd8joTPWa1M8iT3UUwPT3AssMAHs2cXZkZ8VPVzgKozbEUWHaoQ49bfoxYEFbRmU1igWeAxxU2WKSDTqBeRPGx`
  with `err=null` and 76,573 CU. Both one-time deploy/test env files were
  securely deleted and every Phala CVM was confirmed stopped. No program
  upgrade was needed because this slice changes no on-chain code or verifier.
- **PERF-INV-01 evidence (still open).** The same image-58 window measured five
  sequential `/auth/token` calls at 2,110, 2,206, 2,140, 1,952, and 1,838 ms.
  Enclave logs reported native `witness_ms=992`, rapidsnark
  `prove_step_ms=10857`, aggregate `prove_ms=11928`, and total settle-pipeline
  time 14,896 ms; Phala reported an 8-vCPU/16-GB allocation. `phala ssh` v1.1.19
  returned `Unknown API error` before both requested container snapshots, so
  `cpu.max`, `cpu.stat`, cpuset/affinity, CPU model/frequency, and OpenMP
  placement were not observable. These timings confirm the anomaly persists
  but do not identify its host-level cause; PERF-INV-01 therefore remains open.
- **Rollback.** Revert the slice and redeploy image 57 with its matching SDK and
  locator schema. Recovery-v1/v2 envelopes are intentionally incompatible;
  discard in-flight orders and locator DB state and clean-reset devnet before
  using the prior image. The on-chain payload width, accounts, note commitment
  formula, circuits, and existing generic VALID_SPEND notes are unchanged.

### `remediation/settlement-efficiency` — P-02, P-04

- **Status.** Closed by PR #52 with local and image-59 live multi-match
  evidence.
- **Invariant restored.** The TEE constructs the batch Merkle levels once and
  extracts every fixed-width inclusion path from retained stack-backed storage.
  A production N=16 batch therefore computes exactly 15 internal Poseidon
  hashes instead of rebuilding the same tree for every match (240 hashes).
  Tx D initial sends remain independent and bounded, but one confirmation state
  machine polls the complete pending signature set per backoff round. It removes
  confirmed entries immediately, reports reverts against the caller's original
  match index, and rebroadcasts only overdue transactions still pending.
- **Wire/circuit impact.** No HTTP/stream, order canonical, payload, account
  layout, instruction data, ALT membership, circuit, zkey, VK, N=16 fixture,
  note, root, or program change. This is an in-enclave computation/RPC
  scheduling change only. Existing devnet state and in-flight wire artifacts
  remain compatible. The CPU image pin advances from
  `tee-v3-hardening-58` to `tee-v3-hardening-59`.
- **Local evidence.** The optimized path builder matches the removed reference
  algorithm byte-for-byte for every leaf at N=1/2/4/8/16, reconstructs the
  public-input root, rejects N above the circuit maximum, and pins the N=16
  internal hash count to 15 (versus the former 16 × 15 = 240). The in-process
  RPC regression confirms the exact pending polls `[A,B,C] -> [B,C] -> [C]`,
  proves A is never rebroadcast after confirmation, pins B/C rebroadcast counts
  to one/two, and checks that a B revert is attributed to its original
  transaction index. `cargo test -p nyx-tee` passes 256 library tests and every
  integration target, including the new two-case batched-submit target and the
  existing worker, real N=2 prover, N=16 fixture, transaction-size, scheduler,
  HTTP, and stream coverage. `cargo test --workspace`, workspace clippy with
  warnings denied, formatting, and diff hygiene pass. SBF and TypeScript gates
  are not rerun because this slice changes no program or TypeScript source;
  their relevant wire layouts remain covered by the Rust workspace regressions.
- **Devnet/CVM evidence (2026-07-16).** GitHub Actions run `29467718694`
  built and pushed public-pullable image `tee-v3-hardening-59` from commit
  `6d7087cdf5dd055076032497ac83924b2c48049c`; the GHCR manifest returned HTTP
  200. Reset transaction
  `fbu6Q2d42xCqyU46BvQmqLSbsFimyUeHbi51qk7KtP48amocP1bUGtQwdF6T5r4i7hGZVdbgnL7yAP24sUpSbed`
  cold-booted CVM `app_634b2ab4c250466311f0cf09f772b6fd60b5be11`
  with compose hash
  `dbc25797d16c9c89ecea799b29d705f28111a74d32353acef3368fc0330d9e8a`,
  MRTD
  `f06dfda6dce1cf904d4e2bab1dc370634cf95cefa2ceb2de2eee127c9382698090d7a4a13e14c536ec6c9c3c8fa87077`,
  boot session
  `85cb425969a4fadcca8b54cf2a5ec54068f80958baf092d5fbe0d7fd09dd63ad`,
  and signer `KgFsjoP9fDy78xgmEjn2DtRbPZ6G7t5AWDkPo1AAjsa`. Signer rotation finalized at
  `35Qp9cuDbTXsNZkTALikMyYh62xTZjw8JJGJBaJkVJhQuL2v9BAPrRqerZzhDGzFW2tYiJhJhfvWcpmxCFimzjL`;
  it already held 2.436 devnet SOL, so funding was skipped.

  The isolated four-pair `cvm-multimatch-settle` passed 1/1 in 51.89 seconds.
  One N=16 batch reached `done` for every match; its four Tx Ds all confirmed
  in slot 476581061 in 1,275–1,276 ms with zero application rebroadcasts and a
  co-inclusion factor of four. The signatures and independently read Helius
  results were: match 0
  `5hfB8WzpTJSe7SMX3QGiU7vERrowuG9vTBMdu6QPTRCTAKhjLRqtgdrYtpzEYx8VFziX5TmoBv8dUKYy8iQA5KAe`
  (`err=null`, 76,514 CU); match 1
  `EDHe1eWiXJ9WMTX7Ac26hTbpDD8Lqd3diZQB6Eea4bszjaDxYC8zRU85XieSnhezTMMip2th5YmQKKseGbpjebg`
  (`err=null`, 72,310 CU); match 2
  `CdaGmddXZBN3nHoxhuhV46mBPjmbruWXQjCZYxvUn1cSVCBZndqaFA11rKnrQofgqrb6UGjVyDMn1bCtz52twKJ`
  (`err=null`, 69,879 CU); and match 3
  `dXrQKQZoUDNjv61nxgTXXxqoE6sCXuvprHuSqQAAvqGS8vByCSRBUV6p1HRKdiQq1DUkspEQZM2EGT4SniUaPD8`
  (`err=null`, 67,501 CU). Tx B was shared at
  `4vtJitiTmCkQrSTNwmaioXy7XJBz2zUybeB3FPoayko51aNU7uaEinwfeGB82mh18wAUfqojAbmMV3PQmvnvR1od`.
  The settle phase took 1,386 ms and the full pipeline 16,786 ms; the shard
  ended at 28 leaves with root
  `2192b2dbeecf60d2b62ac5d7a3692bed93b31f4d09ce9553a6d68872275c8732`.

  The bundled PERF-INV-01 sample still shows host-sensitive latency:
  `witness_ms=1070`, `prove_step_ms=12854`, aggregate `prove_ms=13977`, and
  five sequential auth calls at 2,016, 1,779, 2,536, 2,000, and 1,859 ms.
  Both requested pre/post snapshots reached the Phala SSH gateway but failed
  with `Permission denied (publickey)`, so `cpu.max`, `cpu.stat`, cpuset,
  affinity, CPU model/frequency, and OpenMP placement remain unavailable and
  PERF-INV-01 stays open. The protected deploy environment was securely
  deleted, credentials were unset, and all three Phala CVMs were confirmed
  stopped. No vault upgrade was needed because the on-chain program and proof
  artifacts are unchanged.
- **Rollback.** Revert this PR and redeploy image 58. No notes, roots, orders,
  signatures, payloads, proofs, accounts, or devnet program state are
  invalidated. Rollback reopens P-02/P-04 and restores 240 per-batch path hashes
  plus one signature-status RPC loop per Tx D.

### `remediation/settlement-outcomes` — N-02

- **Status.** Closed by the image-60 implementation, local adversarial gates,
  and the isolated four-match devnet/CVM validation below.
- **Invariant restored.** A matcher tick reserves both participants as
  `pending_settlement` without changing quantities, rotating collateral, or
  publishing a fill. Tx D sends return an indexed `confirmed`, `rejected`, or
  `ambiguous` result for every match instead of aborting at the first failure.
  Each final result streams back to the matcher immediately, so a confirmed
  sibling commits its book update, continuation opening, and recovery memo
  without waiting for another match's reconciliation loop. Ambiguous results
  require both atomic, vault-owned `ConsumedNoteEntry` PDAs for durable
  confirmation and otherwise redrive with a fresh blockhash while the marker
  and both NoteLocks remain valid. A definitive rejection removes the order,
  preserves its collateral reservation through lock expiry, emits terminal
  `settlement_failed(reason, lock_expiry_slot)`, and never auto-rebooks it.
- **Wire/circuit impact.** The authenticated `orders` stream gains
  `pending_settlement` and terminal `settlement_failed`; the latter carries a
  reason and unlock slot. `GET /orders/{id}` exposes reserved matches as
  `pending_settlement`, and per-match settlement status gains the tagged
  `outcome` object. The SDK and daemon persist/route the new lifecycle states,
  with a distinct confirmed-partial event so a late placement acknowledgement
  cannot reopen a reserved order. No order-canonical bytes, settlement payload,
  instruction data/accounts, note/root construction, circuit, zkey, VK, N=16
  fixture, or vault program changes. The CPU image advances from 59 to 60.
- **Local evidence.** `cargo fmt --all -- --check`, workspace clippy with
  warnings denied, `cargo test -p nyx-tee`, and `cargo test --workspace` pass.
  The TEE run covers 259 library tests and every integration target; the
  adversarial cases retain confirmed siblings across a reverted or timed-out
  Tx D, classify timeouts as ambiguous, require the complete consumed-PDA
  pair, reserve atomically without fill mutation, exclude reservations from
  subsequent snapshots/cancellation, preserve failed collateral until unlock,
  route continuations to the actual settle shard, and make channel failure
  terminal. SDK TypeScript and full Vitest pass 252 tests with 23 environment-
  gated skips. Daemon TypeScript and full Vitest pass 147 tests with 2 skips,
  including lifecycle persistence and the stale-placement-ack race. The first
  daemon run's localhost control-API cases were sandbox-blocked with `EPERM`;
  the permitted rerun passed all 147 tests.
- **Devnet/CVM evidence (2026-07-16).** GitHub Actions run `29471439242`
  built and pushed public-pullable image `tee-v3-hardening-60` from commit
  `9f317a5b225ae4d547dc2430a2642421deb76555`; the GHCR manifest returned HTTP
  200. Reset transaction
  `4X4kUGVYVofJW3CK1ZuNndeWVnHMvhXtWDMucwkL4Hj61ChPLuBTXTMVWgnea1aCdfKuXrdvvsW5FN16am78STk9`
  cold-booted CVM `app_634b2ab4c250466311f0cf09f772b6fd60b5be11`
  with compose hash
  `f58535fa97a15a030f7b1fdf89af6ade2a6f912b6be9c574e38d8cddc8ea5a93`,
  MRTD
  `f06dfda6dce1cf904d4e2bab1dc370634cf95cefa2ceb2de2eee127c9382698090d7a4a13e14c536ec6c9c3c8fa87077`,
  and signer `KgFsjoP9fDy78xgmEjn2DtRbPZ6G7t5AWDkPo1AAjsa`. Signer rotation finalized at
  `2PSoBdBwNd66divNYjXEP4PMstzxco8gBCet5nFPrpbhrm4uHJAjGzUP9njr6JG2mKkNa27F4TE7oU2dG8PL44ud`;
  it already held 2.419 devnet SOL, so funding was skipped.

  The corrected isolated four-pair `cvm-multimatch-settle` passed 1/1 in 49.05
  seconds. The harness observed `pending_settlement` before finality, then all
  confirmed exact-fill orders left the live book. One N=16 batch finalized
  `confirmed=4`, `rejected=0`, `ambiguous=0`; every Tx D confirmed in slot
  476596608 in 971 ms with zero application rebroadcasts. Independently read
  finalized results were: match 0
  `5LAHPK1d2GfhfvKmkoMKKvaK5Upec9czkw2AzjTDDNi5gZcVwsmg1CyMpYYBueanFtHewcYeoaaKgSPYt8RD4ZPS`
  (`err=null`, 66,877 CU); match 1
  `3xHLPchp4LiDJMLWMi3aMv7XQE6hU5AgroxgheJy1doJPXv3VVgWwayKwAgvmzcstfBse9duRxrCkHaCEXgiJEMN`
  (`err=null`, 69,016 CU); match 2
  `5tABs1sZ9xtQpQ4eXvoyx2SPQtus9o1A6KYmLnsFkXPoimdQsqHDtYDgowxc992z3rGpEFoof2MLNiLDF5e6uRcd`
  (`err=null`, 65,999 CU); and match 3
  `39YBXJGkF591McFTMYx4xjRpX1f4GGvz2RrHhuzTDXx5LQMQi8AjfPVgFvnMeqB7xsKtGhSMDeXv1MNeChz9gRqD`
  (`err=null`, 64,812 CU). The shard progressed from 0 to 8 deposit leaves and
  finalized at 28 leaves. Native proving measured `witness_ms=1283`,
  `prove_step_ms=10873`, aggregate `prove_ms=12208`, and total pipeline time
  14,690 ms.

  The first live attempt exposed and corrected a stale test-only two-leaf
  lower bound: at 30 bps this exact-fill fixture deterministically emits five
  leaves per match, so the lower bound could query a later independently-driven
  sibling before it finalized. Its four Tx Ds also ultimately finalized
  `confirmed` with no rejection or ambiguity. PERF-INV-01 remains open: five
  auth canaries measured 2,087, 2,213, 2,058, 2,452, and 1,882 ms, while both
  pre/post diagnostic attempts reached the Phala SSH gateway but failed with
  `Permission denied (publickey)`, leaving `cpu.max`, `cpu.stat`, cpuset,
  affinity, CPU model/frequency, and OpenMP placement unavailable. Both
  protected deploy environments and both temporary credential files were
  securely deleted, and all three organization CVMs were confirmed stopped.
  No vault upgrade was needed because on-chain code and proof artifacts are
  unchanged.
- **Rollback.** Revert this PR and redeploy image 59 with the preceding SDK and
  daemon. No notes, roots, canonical signatures, payloads, proofs, accounts, or
  devnet program state are invalidated, but in-flight client lifecycle state
  should be reconciled from chain. Rollback reopens N-02 and again permits
  optimistic fills/book mutation before Tx D finality.

### `remediation/matcher-performance` — P-03

- **Status.** Closed by the image-61 placeholder-mint CVM loadgen after the
  complete local Rust gate and differential performance suite passed.
- **Invariant restored.** A matching tick freezes one book snapshot, partitions
  and sorts it once, and retains exact u128 bid/ask totals by ordered price
  level. Each settlement page computes its uniform price in one ascending
  suffix-demand/prefix-supply sweep. Every matched, cancelled, or otherwise
  touched order becomes inactive and subtracts its original quantity from the
  reusable levels before the next page. Per-page price recomputation, FIFO,
  lowest-price ties, zero-limit market asks, IOC/FOK/min-fill behavior,
  single-fill-per-order, match IDs, lifecycle updates, and inclusion-root order
  remain byte-identical. New orders arriving mid-page enter the next tick's
  deterministic snapshot.
- **Wire/circuit impact.** No API, order canonical, Borsh output, settlement
  payload, instruction accounts/data, note/root construction, circuit, zkey,
  VK, N=16 fixture, or vault program change. Existing notes, roots, signed
  orders, and proofs remain compatible. The CPU image pin advances from
  `tee-v3-hardening-60` to `tee-v3-hardening-61` so a live loadgen cannot reuse
  the old matcher binary.
- **Local evidence.** A 256-case property compares the level sweep against an
  independent copy of the removed O(prices × orders) algorithm, including u64
  saturation, inactive orders, zero prices, and lowest-price ties. A separate
  192-case property compares every page's complete Borsh bytes against repeated
  legacy `run_batch_capped` calls over randomized sides, order types, statuses,
  limits, quantities, minimum fills, FIFO slots, expiry, and page caps. A
  deterministic multi-page case and the TEE's 5-fill/2-cap integration pin
  paging and finality reservations. On the local release build, the exact
  clearing hotspot measured 69.927 ms versus 0.997 ms for 80,000 orders across
  512 levels (70.17×); the portable operation-count regression pins more than
  three orders of magnitude fewer visits. A 149-page cryptography-inclusive
  run remained byte-identical and measured 850.224 ms versus 760.322 ms
  (1.12×), with Poseidon output construction dominating the remainder.
  `cargo fmt --all -- --check`, workspace clippy with warnings denied, and
  `cargo test --workspace` pass. The first sandboxed workspace run's localhost
  mock-RPC tests failed with `Operation not permitted`; the permitted rerun
  passed all 259 TEE library tests, every TEE integration target, matcher/loadgen
  coverage, and all vault litesvm/proof tests. SBF and TypeScript gates are not
  rerun because this slice changes no program, circuit, transaction builder, or
  TypeScript source.
- **Devnet/CVM evidence.** GitHub image run `29474020305` built commit
  `663f5f170e3fac7f21744d3e2ca86c829a94fb7e`; its functional image job passed
  in 4m57s and the anonymous GHCR manifest probe returned HTTP 200 for
  `tee-v3-hardening-61`. GitHub also emitted the known exhausted-artifact-quota
  annotation, which did not fail or invalidate the image job. A short billable
  run on CVM `app_634b2ab4c250466311f0cf09f772b6fd60b5be11` cold-booted that
  exact image with instance
  `f5cd2f294d1127d241d18e44dbb76b6910aa2a54`, compose hash
  `dfccd5c0ddef2a9f385cfa7b991e4795ab4bdcb5f89a5642eb5e15f25cbca9ba`,
  one shard, native witness generation, rapidsnark, and the settle pipeline
  enabled. The authenticated status preflight reported `degraded=false`,
  `matcher_running=true`, and `settle_enabled=true`.

  The 25-second exact-match loadgen targeted 50 orders/s with 10 traders. It
  submitted 523 orders: 487 were accepted (93.12%), all 36 rejects were HTTP
  429 rate limits, and there were no 5xx or network errors. The matcher emitted
  deterministic multi-page ticks throughout the run, including 16/7/1 and
  16/6/1 page sequences. Submit latency was 316.67 ms p50, 627.71 ms p95,
  945.66 ms p99, and 1,233.92 ms maximum. Synthetic loadgen notes intentionally
  carry stub proofs; two attempted settlement batches therefore failed safely
  at `lock_note` with `InvalidProof (6000)` and moved no assets. This slice
  performed no program upgrade, tree reset, or real-value deposit.

  The same window retained PERF-INV-01 evidence without closing it: five
  sequential authenticated canaries measured 1,911, 2,012, 2,078, 1,818, and
  1,792 ms; two synthetic batch proofs measured native witness generation at
  1,315/1,066 ms and rapidsnark at 11,184/10,478 ms. Both requested pre/post
  host snapshots reached the Phala SSH gateway but failed with
  `Permission denied (publickey)`, so `cpu.max`, `cpu.stat`, cpuset/affinity,
  CPU model/frequency, and OpenMP placement remain unavailable. Deploy
  credentials existed only in process memory and were unset on exit; no env
  file was written. The guarded cleanup completed, and all three organization
  CVMs were independently confirmed `stopped` after the run.
- **Rollback.** Revert this PR and redeploy image 60. No notes, roots, orders,
  signatures, payloads, proofs, accounts, or devnet program state are
  invalidated. Rollback reopens P-03 and restores repeated full-book
  clone/partition/sort plus quadratic clearing scans across matcher pages.

### `perf-inv-01-host-diagnostic` — PERF-INV-01

- **Finding restated.** Across images 58–61 the CVM's proving pipeline ran ~10×
  slower than the historical baseline (rapidsnark `prove_step_ms` ~10,478–11,184
  vs ~1,300; native `witness_ms` ~1,066–1,315 vs ~201; `/auth/token` ~1.8–2.5s).
  The bigger post-#49 circuit (+63% constraints) was suspected but cannot
  explain 10×, and the investigation was blocked because `phala ssh` reaches the
  host but rejects the key, so `cpu.max` / `cpu.stat` / `cpuinfo` could never be
  read from outside the enclave.
- **Root cause.** Node-specific **host CPU contention on prod5** — NOT the
  circuit, NOT our build, and NOT a cgroup bandwidth quota. Three independent
  lines of evidence exonerate the code: (1) the current post-#49 N=16 circuit
  proves in ~1.7s locally on an 8-core laptop with the *slower* ark backend
  (`prove_throughput_bench`, `RUN_PROVE_BENCH=1`), versus ~11s on the CVM with
  the faster rapidsnark; the +63% constraint growth cost only +23% locally;
  (2) `/auth/token` is `Argon2::default()` (unchanged, circuit-independent) yet
  regressed ~10× — only a per-core throughput collapse slows a fixed-cost KDF;
  (3) single-threaded native witness generation regressed ~5×, which thread
  count cannot explain. The unifying cause is per-core throughput, and it is
  host-placement-dependent, so it correlated with redeploys landing on a busy
  node rather than with any commit.
- **The fix / how it was solved.** Rather than wait on Phala SSH, the TEE binary
  — which runs *inside* the CVM — now reads the host CPU picture itself and logs
  one INFO line at boot, before the dstack handshake:
  `crates/nyx-tee/src/boot.rs::log_host_cpu_profile()` (called from `main.rs`)
  emits `logical_cpus`, `/proc/cpuinfo` model/MHz/proc-count, cgroup v2
  `cpu.max` (+ derived `effective_cpus`), `cpu.stat` `nr_throttled`/
  `throttled_usec`, and a time-boxed (~100 ms) single-thread integer microbench
  reported as `singlethread_mops_per_s`. Reads are best-effort (all null
  off-Linux) and add ~100 ms to boot. This converts the blocked investigation
  into a `phala logs … | grep "host-cpu profile"` on every boot. The image pin
  advances from `tee-v3-hardening-61` to `-62`. No circuit, zkey, VK, N=16
  fixture, payload, account-layout, on-chain program, API, or transport change;
  the boot log gains one line and startup is otherwise identical.
- **Evidence (2026-07-16).** Image `tee-v3-hardening-62` (branch
  `perf-inv-01-host-diagnostic`) built + pushed (GHCR manifest HTTP 200) and
  cold-booted on the existing CVM `app_634b…` (node **prod5**): the profile line
  read `logical_cpus=8 cpu_model=06/af cpu_mhz=2400 cgroup_cpu_max="max 100000"
  nr_throttled=0 throttled_usec=0 singlethread_mops_per_s=49.2` — i.e. no cgroup
  throttling and full core visibility, so the slowdown is real per-core
  throughput, not a quota. A fresh throwaway CVM on node **prod9** (`--node-id
  18`), same image and identical nominal CPU (`06/af`, 2400 MHz, `cpu.max=max`,
  `nr_throttled=0`), read `singlethread_mops_per_s=308.7` at 2 vCPU and `269.4`
  at 8 vCPU — **~5.5–6.3× prod5's per-core throughput on the same silicon**,
  proving the gap is host contention, not model/clock. A real-mint
  `cvm-settle-e2e` on a prod9 `tdx.xlarge` (8 vCPU/16 GB, tree reset, signer
  rotated + funded) then passed 1/1 in 37.9s with CVM-logged **`witness_ms=267`,
  `prove_step_ms=2053`, `prove_ms=2364`** — a **~5.3× proving speedup** back to
  the historical fast baseline (`witness ~201`, `prove_ms ~2.9–3.7s`), with the
  pipeline now dominated by on-chain `settle_ms` (~11s devnet confirm) rather
  than proving. The 8-vCPU microbench (269.4 vs 49.2 = 5.5×) predicted the
  measured 5.3× prove speedup almost exactly, validating the probe as a
  pre-flight host check. Local gate: `cargo +1.89.0 fmt`; `cargo clippy -p
  nyx-tee --all-targets -- -D warnings` (clean); `cargo test -p nyx-tee boot::`
  (3 passed) plus a manual `host_cpu_profile_smoke` printing 747.8 mops/s on the
  dev host as a reference. Both throwaway CVMs were stopped + deleted, every
  one-time deploy env was written `umask 077` and securely removed, and
  `vault_config.tee_pubkeys` was restored to the persistent CVM's signer after
  the run.
- **Residual operational action.** The diagnostic and root cause are closed, but
  the production CVM still lives on the contended prod5 node. Restoring the fast
  proving path in production is an operational placement step: deploy on a good
  node (`phala deploy --node-id 18` today) or have Phala migrate / rebalance
  prod5, then confirm via the boot `singlethread_mops_per_s` line before
  certification. A new node yields a new `app_id` and new deterministic K-shard
  signers, so it requires the standard `vault_config.tee_pubkeys` rotation + fund
  step. GPU (ICICLE) proving remains the independent lever that removes the
  dependence on CPU host quality entirely.
- **Rollback.** Revert this PR and redeploy image 61. No notes, roots, orders,
  signatures, payloads, proofs, accounts, circuits, or devnet program state are
  invalidated; the only loss is the boot host-CPU log line.

### `remediation/deposit-privacy` — PRIV-01 / audit C-06

- **Status.** Closed by the proof-before-custody implementation, measured local
  gates, and isolated devnet deposit/withdraw round trip below.
- **Invariant restored.** A deposit commitment must prove
  `owner = Poseidon3(1, spending_key, r_owner)`,
  `inner = Poseidon3(27, owner, recovery_nonce)`, and the canonical v2 note
  construction for the account mint and instruction amount. The wallet-wide
  owner commitment and per-note inner hash are private witnesses, so the
  depositing Solana signer no longer reveals the identity field shared by its
  shielded notes. Proof verification precedes SPL transfer, outstanding-counter
  mutation, and Merkle append. Seed-plus-finalized-chain recovery reconstructs
  the hidden opening from the public pseudorandom nonce and accepts it only
  after recomputing the commitment byte-for-byte.
- **Wire/circuit impact.** `deposit(tree_id, amount, owner_commitment,
  inner_hash)` becomes `deposit(tree_id, amount, note_commitment,
  recovery_nonce, proof)`. The new five-public-input `VALID_DEPOSIT` circuit,
  pot16 proving key, embedded verifier key, Node/browser prover adapters, demo,
  daemon, SDK builders, cold-recovery decoder, and devnet/CVM deposit helpers
  land atomically. Existing note commitments and VALID_SPEND semantics are
  unchanged, but old deposit instructions and clients are intentionally
  rejected; the devnet tree is clean-reset after the verifier cutover. No TEE
  binary, enclave API, order canonical domain, settlement payload, match
  circuit, or N=16 fixture changes.
- **Local evidence.** The generated circuit has 2,501 constraints. Ten measured
  warm proofs give 50.86 ms p95 witness generation, 212.89 ms p95 proving, and
  263.75 ms p95 end-to-end, below the 3-second spike gate. LiteSVM verifies a
  real proof in a signed 845-byte transaction (including a 300k-CU budget ix)
  at 150,910 CU, below the 900-byte and 240k-CU gates. The same test alters the
  amount, commitment, recovery nonce, and mint and proves custody, outstanding,
  and tree state remain unchanged; SDK full-prove negatives alter the private
  key/blinding and every public field. Both mainnet and `devnet-admin` SBF
  builds, `cargo test --workspace`, strict Clippy for the touched
  `darkpool-crypto` and `vault` packages, formatting, SDK/daemon/indexer
  TypeScript, full SDK Vitest (259 passed; 23 environment-gated skips), daemon
  Vitest (147 passed; 2 skips), indexer Vitest (20 passed), Rust/TS deposit-inner
  parity, and the explicit vault/circuit regression suites pass. Full-workspace
  Clippy on the current Rust 1.91 host is blocked only by the pre-existing
  `items_after_test_module` lint in unchanged `nyx-tee/src/boot.rs`; the touched
  packages pass with warnings denied.
- **Devnet evidence (2026-07-17).** The guarded upgrade of canonical program
  `C63v...VWZx` finalized at slot 476749834 with signature
  `4r25ovsoivmX8sFpNntJERAGGe5rwbVmfwfZBoNJtjpvUVo7vVfZiCKM7M1rxofqWgxnGAoak3uyd6QdgVwUpXaB`.
  The mandatory verifier-cutover reset finalized as
  `5uCq3nw9MoZFf4khMkSXyzAyvZh5wEX3BgsCEcSkXxGv3eninhZhdu6jnj5XuVHXHNYbe77kua3FRGMi6mD8humM`.
  The isolated private-deposit-to-VALID_SPEND round trip then passed 1/1 in
  7.25 seconds against the private Helius endpoint: its evidence reset was
  `4F2p7xQyc4C62Pi5N298W6c2JqduAvBbg8mNxug4qqwyXrT74tafAf83vUUHBszeFCBZsrUvnHy2a6UdrQ4mZ7LA`,
  proof-bound deposit
  `5zUMcU6MwST6MipcsZ2TaA8pipRrixP5nEcWc2KTPE1hdaMjGNrNf6P4ADz15biDN5ncwBC1JMf1PFJ3bxhoSECf`,
  and on-chain VALID_SPEND withdrawal
  `5tmCL54XXFYQcsUsESBKTuugXVaXQNeo5n9gLfHewP3fnq9HNG6WXHgEsxTeAdKa4ZnHHC1apiCyq3T6oZS4Aqh3`.
  A billable CVM run is not applicable because this slice changes neither the
  TEE image nor its intake, matching, settlement, dstack/KMS, attestation, or
  transport surfaces.
- **Rollback.** Revert this PR and redeploy the preceding vault and clients
  together, followed by a clean devnet reset. Notes already created through
  VALID_DEPOSIT remain canonical v2 notes and are spendable by VALID_SPEND,
  but new clients cannot use the reverted deposit wire and reverted cold
  recovery cannot reconstruct the domain-27 deposit inner. Rollback therefore
  reopens audit C-06 and must not be used for a privacy-preserving launch.

## Mainnet release gates

- No real-value deposits before CS-01/02/03 and their dependent v3 circuit
  cutover are closed and independently audited with no unresolved Critical or
  High findings.
- Mainnet artifacts omit `devnet-admin`; destructive instructions must be
  absent from the deployed binary and the program hash/authorities independently
  verified.
- The external circuit audit, Phase-2 ceremony, split-governance rehearsal,
  recovery drill, transaction/CU headroom measurements, and live CVM evidence
  must all be attached before N-18/N-19 and the release gate can close.
