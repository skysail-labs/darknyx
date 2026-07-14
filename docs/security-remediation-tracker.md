# Nyx security remediation tracker

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
| CS-01 | Critical | ZK + vault + TEE | `remediation/match-batch-v3` | Every fee note is per-match and issued atomically with consumption of that match's real inputs; negative phantom-slot proof; regenerated zkey/VK/N=16 fixture; live settle | Open |
| CS-02 | High | ZK + vault | `remediation/governance-markets`, `remediation/match-batch-v3` | Every active slot is bound to one enabled on-chain market, its mint halves, and price scale; mixed-market proof rejected | Open |
| CS-03 | High | ZK + SDK + TEE | `remediation/match-batch-v3` | User and fee output inners are constrained, deterministic, and recoverable from consumed inputs; arbitrary-inner witness rejected | Open |
| CS-04 | High | TEE + matcher | `remediation/canonical-order-v2` | Settlement IDs include boot session and counter; reboot/page collision tests; output safety does not rely on identifier uniqueness | Open |
| CS-05 | High | SDK + daemon | `remediation/client-custody` | Wallet-signature seed mode removed; versioned encrypted CSPRNG seed export/import and migration tests | Open |
| CS-06 | High | Matcher + TEE | `remediation/fee-identifier` then `remediation/match-batch-v3` | Matcher-recorded identifier is used by commitment and witness; no consumer re-samples a Solana slot | Closed |
| CS-07 | Medium | ZK + vault + SDK | `remediation/input-merge-v3` | Lock amount is a private 64-bit witness and absent from instruction/event data; artifacts regenerated | Open |
| CS-08 | Medium | Matcher + ZK | `remediation/match-batch-v3` | Per-match fees cannot reuse an inner/nullifier across pages or reboots; collision regression tests | Open |
| CS-09 | Medium | Vault | `remediation/vault-lifecycle` | Tx D rejects at and after either input lock's expiry; boundary litesvm tests | In progress |
| CS-10 | Medium | Matcher + TEE + SDK | `remediation/canonical-order-v2` | Viewing key is signed; non-contributory X25519 points rejected; low-order KATs | Open |
| CS-11 | Medium | TEE | `remediation/canonical-order-v2` | Exact idempotency is handled before a durable strictly-increasing per-trading-key nonce check | Open |
| CS-12 | Medium | SDK + daemon + ZK | `remediation/input-merge-v3` | Merge output inner derives from consumed commitments; no restart-sensitive merge counter | Open |
| CS-13 | Medium | Daemon | `remediation/daemon-trust` | Strict startup fails closed; finalized TEE keys refresh each minute; mismatch/staleness pauses placement while reconciliation continues | Open |
| CS-14 | Low | Crypto + SDK | `remediation/client-custody` | Existing bytes retained under `nyxShakeKdfV1`; fixed Rust/TS KATs; no NIST KMAC claim | Open |

## Performance findings

| ID | Severity | Owner | Planned remediation slice | Invariant / required evidence | Status |
|---|---|---|---|---|---|
| P-01 | Perf | Vault + SDK + TEE | `remediation/vault-lifecycle` | Batch marker is read-only in every Tx D builder; distinct-shard Tx Ds share no writable key | In progress |
| P-02 | Perf | TEE | `remediation/settlement-efficiency` | Build the N=16 tree once and extract every path; hash-count regression/benchmark | Open |
| P-03 | Perf | Matcher | `remediation/matcher-performance` | Price-level aggregates and reusable demand curves preserve FIFO, tie-breaking, IOC/FOK/AON under differential properties | Open |
| P-04 | Perf | TEE RPC | `remediation/settlement-efficiency` | Poll all pending signatures in one RPC request; remove confirmed entries; rebroadcast only overdue transactions | Open |

## Residual findings

| ID | Severity | Owner | Planned remediation slice | Invariant / required evidence | Status |
|---|---|---|---|---|---|
| N-01 | High | TEE | `remediation/tee-intake` | Production exits on dstack/KMS probe failure; test auth requires explicit simulator mode; production rejects test credentials | Closed |
| N-02 | High | Matcher + TEE | `remediation/settlement-outcomes`, `remediation/finality-gated-book` | Book/fills commit only after per-match settlement outcome; ambiguous results reconcile/redrive; rejected matches are terminal and never auto-rebooked | Open |
| N-03 | High | Matcher | `remediation/matcher-correctness` | Zero-limit market asks remain eligible but are not price candidates; bid@150/ask@0 clears positively | Closed |
| N-04 | High liveness | Vault + SDK | `remediation/vault-lifecycle` | Merge proves every active input's NoteLock PDA absent; locked-note negative tests | In progress |
| N-05 | Medium privacy | TEE | `remediation/tee-intake` | Order reads enforce account ownership and return indistinguishable 404s | Closed |
| N-06 | Medium | TEE | `remediation/tee-intake` | One collateral commitment reserves at most one live or pending order; lifecycle release tests | Closed |
| N-07 | Medium | Matcher | `remediation/matcher-correctness` | Matcher output construction uses note-bound `owner_commitment`; randomized assembler parity | Closed |
| N-08 | Medium | TEE + SDK + daemon | `remediation/stream-consolidation` | Only in-band-authenticated `/v1/stream` remains; gap detection, refresh, reconnect, and cancel-on-disconnect preserved | Open |
| N-09 | Medium privacy | TEE | `remediation/tee-intake` | Clearing prices are absent from production info logs | Closed |
| N-10 | Medium ops | Vault | `remediation/governance-markets` | Initialization rejects default root and TEE keys; negative litesvm tests | Open |
| N-11 | Medium ops | Vault | `remediation/governance-markets` | Authorized TEE key count equals tree count at initialization and rotation | Open |
| N-12 | Medium | Vault | `remediation/vault-lifecycle` | Marker is closable only after expiry; rent returns to recorded payer; early-close tests reject every signer | In progress |
| N-13 | Medium | ZK | `remediation/input-merge-v3` | VALID_INPUT amount is range-constrained to 64 bits while private | Open |
| N-14 | Medium | ZK + vault | `remediation/input-merge-v3` | Merge has at least one active positive input/output; all-dummy/zero proofs and on-chain calls rejected | Open |
| N-15 | Low-Medium | SDK + daemon | `remediation/daemon-trust` | On-chain Merkle-root-ring verification is default-on in daemon proving | Open |
| N-16 | Low | SDK | `remediation/client-custody` | Commitment equality is byte-based; mixed-case encoding regression | Open |
| N-17 | Perf | Vault + TEE + SDK | `remediation/settlement-payload-v9` | Dead nullifiers removed; canonical domain bumped; worst-case Tx D <=1120 bytes with >=112 bytes headroom | Open |
| N-18 | Critical mainnet gate | Governance + ZK | `remediation/release-assurance` | Public Phase-2 ceremony with at least five independent contributors, transcript/hashes, random beacon, reproducible verify, auditor sign-off, post-ceremony settle | Open |
| N-19 | High mainnet gate | Governance | `remediation/governance-markets`, `remediation/release-assurance` | Split Squads rehearsal: operations 3-of-5 admin and cold root/upgrade 4-of-7; independent attestation verification before rotations | Open |

## Pull request evidence template

Every remediation PR must record:

- Finding IDs and the invariant restored.
- Wire, account-layout, canonical-domain, circuit, and compatibility impact.
- Exact validation commands and negative/adversarial cases.
- Devnet transaction signatures and CVM image/attestation evidence when required.
- Rollback instructions, including whether rollback invalidates notes, roots,
  orders, payloads, proofs, or deployed circuit artifacts.
- Tracker rows moved only as far as the available evidence supports.

## Remediation evidence in progress

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
  serialized Tx D cap assertion, and worst-case settle CU profile.
- **Devnet/CVM evidence.** Pending the post-local-gate deploy and live CVM
  rehearsal. The four tracker rows remain in progress until that evidence is
  attached and the PR is merged.
- **Rollback.** Revert this PR and redeploy the preceding vault program and TEE
  image together. Existing notes, roots, orders, payloads, signatures, and
  proofs remain byte-compatible, but an in-flight merge assembled with the new
  extra accounts must be rebuilt for the old interface. Rollback reopens all
  four findings, restores payer early-close, and restores the batch-wide Tx D
  write conflict.

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
