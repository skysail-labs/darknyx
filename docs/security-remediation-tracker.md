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
| CS-06 | High | Matcher + TEE | `remediation/fee-identifier` then `remediation/match-batch-v3` | Matcher-recorded identifier is used by commitment and witness; no consumer re-samples a Solana slot | Open |
| CS-07 | Medium | ZK + vault + SDK | `remediation/input-merge-v3` | Lock amount is a private 64-bit witness and absent from instruction/event data; artifacts regenerated | Open |
| CS-08 | Medium | Matcher + ZK | `remediation/match-batch-v3` | Per-match fees cannot reuse an inner/nullifier across pages or reboots; collision regression tests | Open |
| CS-09 | Medium | Vault | `remediation/vault-lifecycle` | Tx D rejects at and after either input lock's expiry; boundary litesvm tests | Open |
| CS-10 | Medium | Matcher + TEE + SDK | `remediation/canonical-order-v2` | Viewing key is signed; non-contributory X25519 points rejected; low-order KATs | Open |
| CS-11 | Medium | TEE | `remediation/canonical-order-v2` | Exact idempotency is handled before a durable strictly-increasing per-trading-key nonce check | Open |
| CS-12 | Medium | SDK + daemon + ZK | `remediation/input-merge-v3` | Merge output inner derives from consumed commitments; no restart-sensitive merge counter | Open |
| CS-13 | Medium | Daemon | `remediation/daemon-trust` | Strict startup fails closed; finalized TEE keys refresh each minute; mismatch/staleness pauses placement while reconciliation continues | Open |
| CS-14 | Low | Crypto + SDK | `remediation/client-custody` | Existing bytes retained under `nyxShakeKdfV1`; fixed Rust/TS KATs; no NIST KMAC claim | Open |

## Performance findings

| ID | Severity | Owner | Planned remediation slice | Invariant / required evidence | Status |
|---|---|---|---|---|---|
| P-01 | Perf | Vault + SDK + TEE | `remediation/vault-lifecycle` | Batch marker is read-only in every Tx D builder; batch Tx Ds share no writable key | Open |
| P-02 | Perf | TEE | `remediation/settlement-efficiency` | Build the N=16 tree once and extract every path; hash-count regression/benchmark | Open |
| P-03 | Perf | Matcher | `remediation/matcher-performance` | Price-level aggregates and reusable demand curves preserve FIFO, tie-breaking, IOC/FOK/AON under differential properties | Open |
| P-04 | Perf | TEE RPC | `remediation/settlement-efficiency` | Poll all pending signatures in one RPC request; remove confirmed entries; rebroadcast only overdue transactions | Open |

## Residual findings

| ID | Severity | Owner | Planned remediation slice | Invariant / required evidence | Status |
|---|---|---|---|---|---|
| N-01 | High | TEE | `remediation/tee-intake` | Production exits on dstack/KMS probe failure; test auth requires explicit simulator mode; production rejects test credentials | Open |
| N-02 | High | Matcher + TEE | `remediation/settlement-outcomes`, `remediation/finality-gated-book` | Book/fills commit only after per-match settlement outcome; ambiguous results reconcile/redrive; rejected matches are terminal and never auto-rebooked | Open |
| N-03 | High | Matcher | `remediation/matcher-correctness` | Zero-limit market asks remain eligible but are not price candidates; bid@150/ask@0 clears positively | Open |
| N-04 | High liveness | Vault + SDK | `remediation/vault-lifecycle` | Merge proves every active input's NoteLock PDA absent; locked-note negative tests | Open |
| N-05 | Medium privacy | TEE | `remediation/tee-intake` | Order reads enforce account ownership and return indistinguishable 404s | Open |
| N-06 | Medium | TEE | `remediation/tee-intake` | One collateral commitment reserves at most one live or pending order; lifecycle release tests | Open |
| N-07 | Medium | Matcher | `remediation/matcher-correctness` | Matcher output construction uses note-bound `owner_commitment`; randomized assembler parity | Open |
| N-08 | Medium | TEE + SDK + daemon | `remediation/stream-consolidation` | Only in-band-authenticated `/v1/stream` remains; gap detection, refresh, reconnect, and cancel-on-disconnect preserved | Open |
| N-09 | Medium privacy | TEE | `remediation/tee-intake` | Clearing prices are absent from production info logs | Open |
| N-10 | Medium ops | Vault | `remediation/governance-markets` | Initialization rejects default root and TEE keys; negative litesvm tests | Open |
| N-11 | Medium ops | Vault | `remediation/governance-markets` | Authorized TEE key count equals tree count at initialization and rotation | Open |
| N-12 | Medium | Vault | `remediation/vault-lifecycle` | Marker is closable only after expiry; rent returns to recorded payer; early-close tests reject every signer | Open |
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
