# Pre-Formal-Audit Readiness Assessment — Nyx Darkpool (audit_2)

**Repository:** skysail-labs/darknyx (nyx-monorepo) · **Commit:** `fcdaf60` · **Branch:** `main`
**Date:** 2026-07-11 · **Reviewer:** Claude Opus 4.8 (self-directed survey)
**Predecessor:** `audit_1/REPORT.md` (commit `1cc1bf1`, 2026-06-27) — on-chain `vault` + crypto boundary, 12 findings, all remediated or accepted.

> **Purpose.** audit_1 deliberately scoped itself to the on-chain program and its
> cryptographic trust boundary. This pass answers a different question: *across
> the whole protocol — the parts audit_1 explicitly did NOT review, plus the code
> merged after it — what still needs a decision or a fix before we hand this to an
> external formal auditor?* It is a **readiness map + judgment**, not a line-by-line
> re-audit. Where I could substantiate a concern by reading the code, it is a
> Finding below with a file:line. Where a whole surface is simply un-reviewed, it
> is listed in §4 as scope the formal audit MUST cover, with the threat model to
> hand the auditors.

> **Honest scope (what this pass actually did).** Targeted sampling of the
> highest-risk un-audited surfaces: the oracle guardian-signature path, the
> client-side attestation verifier, the on-chain-config byte parser, the matcher
> clearing-price/circuit-breaker core, order-intake logging, and the post-audit
> consumed-note guard. It did **not** exhaustively read the ~180-test `nyx-tee`
> HTTP/WS/auth surface, the full matcher algorithm, the SDK/daemon transport, or
> the ZK circuits. Severities are my own judgment and should be treated as inputs
> to the auditor's scoping, not a substitute for it. (The `advisor` second-opinion
> model was unavailable during this pass — flagged for transparency; a human or
> second-model review of §3-A is warranted given its weight.)

---

## 1. Verdict

**Posture: sound engineering, but the protocol's headline guarantees are not yet
*enforced* end-to-end — they are *designed* and partially stubbed.** Nothing here
is an exploitable on-chain fund-theft bug (audit_1 already established the vault is
well-defended, and the surfaces this pass sampled either verified clean or contained
honestly-documented gaps). The gap is different in kind: **the privacy and
price-fairness guarantees both rest on "order flow really is processed inside a
genuine, audited TDX enclave," and that root fact is currently unverified against a
malicious operator** (Finding A-1). Until that is closed — or explicitly accepted
in writing the way F-11 was — a formal audit of the on-chain program alone would
certify a component whose security assumption is not met by the deployed system.

**Recommended gate before formal audit:** resolve A-1 (enforce or formally accept),
decide A-2 (oracle price binding), and hand §4's surface map to the auditors as
explicit scope. A-3 and the §4 items are auditor-scope, not blockers.

---

## 2. What verified clean (so it isn't re-litigated)

These were sampled and hold up — worth recording so the formal audit can deprioritise:

- **VAA guardian-signature verification** (`crates/nyx-tee/src/oracle/vaa.rs`) — correct
  double-keccak signing digest, strictly-increasing guardian-index enforcement,
  duplicate rejection, 13/19 quorum, recovery-id bounds, address derivation. No bypass
  found in the signature check itself. (The *price-inclusion* gap above this layer is
  A-2 — a different concern.)
- **Order-intake / matcher logging** — a targeted scan of `api/orders.rs`,
  `matcher/*.rs`, and `settle/*.rs` found **no** logging of order price, amount, owner
  commitment, or nullifier. The privacy-in-logs discipline the compose file demands
  (`docker-compose.yaml` §logs) is being kept on the paths sampled. *(Formal audit
  should still sweep the full crate for `Debug` derives that could reach a log sink.)*
- **Consumed-note guard** (post-audit, `withdraw.rs`) — the July 2 change is implemented
  as designed: `withdraw` now `init`s the commitment-keyed `ConsumedNoteEntry`
  (`withdraw.rs:71-77, 199-203`) as the shared consume-once guard, keeping the
  `NullifierEntry` init as the double-spend guard. The withdraw→settle double-spend the
  plan targeted is closed by construction.
- **Clearing-price + circuit-breaker core** (`darkpool-matcher/src/algorithm.rs`) —
  uniform-clearing-price maximising matched volume, deterministic lowest-price tie-break,
  saturating arithmetic, `reference == 0 ⇒ always-deviates` fail-safe. Correct.
- **Attestation `report_data` binding design** (`api/attestation.rs`,
  `daemon/src/attestation.ts`) — the nonce (freshness) + `SHA-256(tee_pubkey)`
  (key-binding) layout is well-designed. It is the right primitive; it just needs the
  DCAP signature check *under* it to carry weight (A-1).

---

## 3. Findings

### A-1 — The attestation trust anchor is not enforced end-to-end (DCAP never wired)

| | |
|---|---|
| **Severity** | HIGH *for the trust model* (design/deliverable gap; not an on-chain exploit) |
| **Files** | `packages/daemon/src/attestation.ts:19-22,212-221`; `packages/daemon/src/daemon.ts:164,223`; on-chain: no attestation verify exists |
| **Category** | Trust root / attestation |
| **Status** | **RESOLVED (client-side)** — real DCAP enforced in the daemon + browser SDK (branch `attestation-dcap-enforcement`). On-chain trustless gating (zkDCAP) deferred to a tracked Phase 3. |

> **Remediation (2026-07 — commits `9ec68f8`, `ac5b999`, `4ab5bfe`).** The client now
> verifies the TDX quote with the **pure-JS `@phala/dcap-qvl`** (>= 0.3.9; the WASM
> `-node`/`-web` builds are unpatched per CVE-2026-22696 — QE-identity verification
> missing — so we deliberately use the pure-JS package) before trusting the gateway.
> `packages/sdk/src/tee/verify-core.ts` runs the parts DCAP doesn't: `report_data`
> binding, **event-log RTMR3 replay** (compose-hash bound to the *verified quote*, not
> self-reported `/info`), and a secure-by-default TCB allowlist. The daemon enforces
> **strict by default** (`packages/daemon/src/attestation.ts`) — no DCAP or missing pins
> ⇒ refuses to trade; the browser gets `verifyTeeAttestation()`
> (`packages/sdk/src/tee/attestation.ts`). `/info` now advertises the full K-shard
> `tee_pubkeys` set. **Residual (tracked):** the quote binds only shard-0's key (1/K of
> the settle keys) and there's no automated on-chain `vault_config.tee_pubkeys`
> cross-check yet; full closure = bind the whole set in `report_data` and/or the on-chain
> check, plus the deferred on-chain zkDCAP gate. The findings below describe the
> pre-remediation state.

**What I found.** The client-side verifier (`verifyAttestation`, described in its own
header as "the non-custody trust anchor") checks three things from the gateway's JSON:
nonce freshness, `report_data[32:64] == SHA-256(tee_pubkey)`, and that
`compose_hash`/`mrtd`/`tee_pubkey` match operator-pinned expected values. It verifies
Intel's signature over the TDX quote **only if an optional `quoteVerifier` (a DCAP
backend) is injected** — and there is **none anywhere in the repo** (`dcap-qvl` →
zero hits; `daemon.ts` threads `quoteVerifier?` through but never constructs one).

**Why it matters.** Without the DCAP signature check, *every field the verifier
inspects is self-reported by the gateway.* A malicious operator can run an ordinary
(non-enclave) server that returns a fabricated `/info` and `/attestation`: any
`compose_hash`/`mrtd` the client pins, a `report_data` that echoes the client's nonce,
and a `tee_pubkey` the operator holds the private key for. **All three checks pass.**
The measurement-pinning is only meaningful once the measurements are extracted from a
signature-verified quote. So today the anchor defeats *passive* threats
(replay, key-substitution, wrong build) against an *otherwise-honest* enclave, but does
**not** defeat an operator who simply doesn't run the enclave and fabricates the JSON —
which is the exact adversary the whole "TEE-trusted" model (privacy + F-11 price
fairness) is built to exclude.

This is the load-bearing assumption for the entire protocol: audit_1's F-04 (solvency
rests on circuit soundness) and F-11 (price fairness is TEE-trusted) both name enclave
attestation as the compensating control. If attestation isn't enforced, those
compensating controls are not yet real.

**Recommendation (before formal audit — pick one, in writing):**
1. **Enforce it.** Ship a real DCAP verifier: server-side/client-side via the Rust
   `dcap-qvl` (the daemon can shell to a small Rust helper or WASM build), and/or the
   deferred on-chain `dcap-qvl-bpf` port so the *vault* only accepts settle payloads from
   an attested key. Bind `mrtd`/`compose_hash` to the governance-pinned set. This is the
   real fix and matches the roadmap's on-chain-attestation deferral.
2. **Formally accept it**, exactly as F-11 was accepted: write the threat model, name
   the residual (operator can run a fake gateway → total privacy + fairness loss, bounded
   only by no-on-chain-value-inflation from the ZK proofs), name the compensating process
   controls (who vets the operator, out-of-band DCAP audit of the raw quote the verifier
   already returns), and the revisit trigger. **Do not let a formal auditor discover this
   is unenforced without a written decision** — it will otherwise dominate their report.

Either way, the auditor must be told which of the two is the intended posture.

---

### A-2 — Oracle price is not bound to the guardian-signed accumulator root

| | |
|---|---|
| **Severity** | MEDIUM |
| **File** | `crates/nyx-tee/src/oracle/vaa.rs:34-41` (documented); `oracle/cache.rs`, `oracle/hermes.rs` (consume `parsed[]`) |
| **Category** | Oracle integrity |
| **Status** | Open — documented as "closed in v3" |

**What I found.** The VAA layer verifies guardian signatures over the Pyth accumulator
root, but by its own admission does **not** verify the Merkle-proof that the specific
SOL/USD price the matcher uses is actually committed by that signed root — it trusts the
`parsed[].price` value Hermes returns alongside the VAA.

**Why it matters.** A malicious or MITM'd Hermes endpoint can return a genuinely
guardian-signed VAA (real root, real signatures) paired with a **fabricated** `parsed[]`
price. Guardian verification passes; the price is attacker-chosen. The matcher's circuit
breaker (`deviates_by_more_than_bps(p_star, twap, cb_bps)`) uses that price as its
reference band — so a fake oracle price **defeats the circuit breaker**, which is the
one automated compensating control that would otherwise bound a mispriced clear. The
threat actor here is the network/RPC path, not necessarily the operator, so it is
partly orthogonal to A-1 and not covered by attestation.

**Recommendation.** Verify the Pyth accumulator Merkle inclusion of the feed against the
signed root inside the TEE (the payload bytes are already parsed into
`ParsedVaa.payload`), so the price the matcher trusts is end-to-end bound to the guardian
signatures. If deferring to "v3 on-chain Pyth," record it as an accepted decision with
the circuit-breaker-defeat consequence stated. Low-cost interim: pin the Hermes endpoint
over TLS with cert-pinning and treat a single-source oracle as an explicit assumption.

---

### A-3 — Cross-language account-layout drift (hand-mirrored fixed offsets)

| | |
|---|---|
| **Severity** | LOW (hardening) |
| **Files** | `crates/nyx-tee/src/solana_rpc/vault_config.rs`; `crates/nyx-tee/src/merkle/sync.rs` (`parse_merkle_tree_root`) |
| **Category** | Correctness / maintainability |
| **Status** | Open |

**What I found.** The TEE reads on-chain `VaultConfig` (fee floor + the three matcher
params) and `MerkleTree` roots by **hardcoded byte offsets** hand-mirrored from the Rust
structs, pinned only by a per-side unit test that asserts the constants equal literals
(`offsets_match_vault_layout` checks `1256/1264/1272/1280` against hand-computed values,
not against the actual on-chain struct). CLAUDE.md §7 already treats this drift class as
"the most fragile invariant in the repo" for crypto primitives; here it extends to
account layouts, where the enforcement is weaker (two independent tests, no shared
source, no CI cross-check that the vault struct still lays out as the TEE assumes).

**Why it matters.** If a future `VaultConfig`/`MerkleTree` field is inserted before these
offsets (or padding changes under a compiler/Anchor bump), the TEE silently reads garbage
— adopting a wrong fee floor (→ every settle rejects, a liveness break) or a wrong matcher
param (→ wrong circuit-breaker band). It fails safe-ish (settles reject) but is a silent
correctness landmine. Not exploitable for theft.

**Recommendation.** Add a CI check that reconciles the TEE offsets against the vault
struct (e.g. a shared const module, a generated layout fixture the vault emits and the TEE
test consumes, or a `std::mem::offset_of!` assertion compiled against the real struct).
Cheap; removes a whole silent-breakage class. Auditor-scope, not a blocker.

---

## 4. Un-audited surface map — explicit scope to hand the formal auditor

audit_1 and this pass together have **not** line-by-line reviewed the following. Each is
listed with the threat model the auditor should carry into it. This is the single most
useful artifact to give the external team.

| # | Surface | Files | Threat model the auditor should apply |
|---|---|---|---|
| S-1 | **ZK circuit soundness** (the F-04 external track — the big one) | `circuits/**` (VALID_MATCH_BATCH, VALID_INPUT, VALID_MERGE, VALID_WALLET_CREATE) | Conservation / range / fee-floor are proven *in-circuit* over private amounts; on-chain solvency depends **entirely** on their soundness. A non-conserving or mint-substituting witness that still satisfies constraints → silent insolvency. Also: is amount privacy actually sound (no under-constrained signal leaks an amount)? Trusted-setup ceremony integrity. |
| S-2 | **TEE HTTP/WS/auth surface** | `crates/nyx-tee/src/api/**` (auth 834 LOC, rate_limit, orders, trading, stream, ws, order_router, fills_router) | authz bypass (JWT `alg`/claims — deps note pins HS256, re-verify), order-intent **privacy leak** (Debug/serde reaching logs, error messages, `/account` disclosure), cross-account fill/order routing (can A read B's fills?), rate-limit/DoS + intake flooding, WS cancel-on-disconnect correctness, order idempotency/replay. |
| S-3 | **Attestation + key management + dstack handshake** | `boot.rs`, `keys/`, `api/attestation.rs`, `docs/tee-attestation-flow.md` | A-1 (DCAP enforcement); determinism + secrecy of the per-`app_id` shard signer derivation; the sealed-key/volume model; TEE-key rotation being attestation-gated end-to-end; report_data domain-separation. |
| S-4 | **Matcher fairness / economics** | `darkpool-matcher/src/**` (algorithm, book, fee, order_canonical) | price-time-priority fairness under paging (`run_batch_capped` — can order splitting starve/reorder?), self-trade prevention completeness (`selftrade.rs` keyed on owner_commitment — bypass via multiple commitments?), fee conservation vs the on-chain floor, canonical-signing replay across order/cancel/topup, FOK/min-fill edge cases. |
| S-5 | **Client-side crypto (SDK + daemon)** | `packages/sdk/src/utxo`, `keys`, `fills/recover.ts`, `settlement`, `packages/daemon/src` | change-amount decryption + self-verify correctness (the Vuln-4 memo-integrity guard), viewing-key & wallet-signature-seed derivation (deterministic ⇒ recoverable but also ⇒ compromise-once = forever?), fill-memo integrity enforcement actually wired in the daemon, key storage in the keystore. |
| S-6 | **Amount-privacy side channels** (beyond the circuit) | settle tx shape, event timing, ALT/PDA patterns | Even with amounts off-chain: can an on-chain observer correlate a settle's leaf-count delta, tx timing, per-shard fee-payer, or ALT contents back to an amount/counterparty? Does exact-fill vs change-note tx-size (CLAUDE.md §6 dedup note) leak fill/no-fill? Timing between order POST and settle. |
| S-7 | **Governance / upgrade / multisig** (operational, already tracked) | `docs/governance.md`, F-10 | admin/root/upgrade authority → Squads multisig at mainnet (code-ready, operational step); attestation-gated TEE rotation; verify `solana program show` authority post-transfer. Tracked in audit_1 roadmap; auditor should confirm the runbook. |
| S-8 | **Supply chain / deps** (tracked) | `Cargo.lock`, `package-lock.json` | `cargo audit`/`npm audit` CI gates still TODO; the `ws`/web3-transitive advisories deferred to the `@solana/kit` migration. Re-run post-migration. |

---

## 5. Readiness checklist (go / no-go for formal audit)

**Resolve before handing off (decisions, not necessarily full fixes):**
- [x] **A-1** — DCAP attestation ENFORCED client-side (daemon strict-by-default + browser `verifyTeeAttestation`), commits `9ec68f8`/`ac5b999`/`4ab5bfe`. Remaining: bind the full K-shard set / on-chain cross-check, and the deferred on-chain zkDCAP gate (Phase 3) — track, not a formal-audit blocker.
- [ ] **A-2** — decide oracle price-inclusion binding (fix in-TEE, or accept with circuit-breaker-defeat stated).
- [ ] Confirm F-04 external **circuit audit** is booked — it is the largest single risk (S-1) and is the natural centre of the formal engagement.
- [ ] Confirm F-10 governance multisig plan is the auditor's operational-scope (S-7).

**Hand to the auditor as explicit scope:** §4 S-1…S-8 with the threat models above.

**Auditor-scope hardening (not blockers):** A-3 (layout-drift CI check), S-8 (`cargo/npm audit` gates), a full log-sink sweep for order-intent Debug output.

**Already solid (audit_1 + this pass):** the on-chain `vault` program, the crypto
byte-equality contracts, the consumed-note guard, the VAA signature check, the
clearing-price core, the attestation binding *design*.

---

*Point-in-time survey at `fcdaf60`. AI-assisted, sampling-based — a scoping aid for the
external formal audit, not a substitute for it. The `advisor` second-opinion model was
unavailable during this pass; §3-A in particular warrants a human/second-model sanity
check given its weight on the whole trust model.*
