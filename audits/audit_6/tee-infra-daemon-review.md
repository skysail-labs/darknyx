<!-- audit-record -->
> **Audit:** TEE, infrastructure + daemon review  
> **Date:** 2026-07-25  
> **Engagement:** `audits/audit_6/`  
> **ID prefix:** `T-`, `PF-08…PF-10`  
> **Cross-audit status:** see [`residual-backlog.md`](../residual-backlog.md) — the canonical index of what is still open.

---

# Darknyx TEE infrastructure, oracle, and client-daemon review — 2026-07-25 (pass 2)

> **Scope.** Second pass, covering the surfaces the same-day
> `../audit_5/withdraw-intake-boundary-review.md` §5 listed as **not
> audited**: the oracle stack (`oracle/*`), the auth surface (`api/auth.rs`),
> prover FFI (`prover/rapidsnark_sys.rs`), persistence, the Merkle mirror/sync,
> the Solana RPC client, stream/rate-limit transports, deployment
> infrastructure (`deploy/`, `.github/workflows/`), and the client daemon
> (`packages/daemon/`).
>
> **ID prefix:** `T-01…` (TEE/infra/daemon, 2026-07-25 pass 2). Distinct from
> `S-`/`PF-` (pass 1), `D-` (07-20), `U-` (07-18), `CS-`/`N-`/`P-` (07-14),
> `C-` (07-12), `F-` (audit_1).
>
> **Addendum 2026-07-27 — `T-11…T-15` (§7).** A verification pass over
> `audits/audit_5/tracker.md` confirmed every `S-`/`PF-`/`AU-`
> fix is genuinely implemented and passing, and surfaced five **assurance** gaps:
> the remediation tests exist but several of them are not durably gated. These
> are recorded here rather than in the tracker because they are defects in the
> validation apparatus, not in the remediations themselves.
>
> **Severity:** Critical / High / Medium / Low / Perf-Nit / Info

---

## 1. Executive summary

Pass 1 audited the value-movement path — circuits, vault, intake, settle
binding. This pass audits everything the enclave depends on to be *correct* and
*private* rather than merely solvent, plus the client that talks to it.

**The two most serious results are not in the cryptography — they are in the
gap between the documented deployment and the actual one.**

1. **The enclave terminates no TLS (T-03).** There is no `rustls`, no
   `axum-server`, no TLS acceptor anywhere in the TEE binary; the compose
   publishes plaintext `0.0.0.0:8080` and the dstack-ingress sidecar that would
   provide RA-TLS is listed as "Phase 2+ (not enabled yet)". Every order —
   side, price, size, note commitment, trading key — is therefore decrypted at
   the Phala gateway before it reaches the enclave. The protocol's central
   privacy claim is that order intent lives only in enclave memory. Today it
   lives in the operator's gateway first.
2. **`compose_hash` does not bind the binary (T-04).** The compose pins the
   image by mutable tag (`:tee-v3-hardening-72`), not by digest — the TODO on
   line 23 says so. Anyone able to re-point that tag changes the code the
   enclave runs while `compose_hash`, RTMR3, the governance allowlist entry,
   and every client's pin stay **byte-identical**. Combined with GitHub Actions
   pinned by mutable major tag and no dependency-audit gate (T-08), there is a
   complete supply-chain path to the enclave binary that attestation does not
   detect.

The oracle stack contributes two independent breaks of the C-05 remediation.
`vaa.rs` is a careful, well-tested implementation of *guardian signature
verification* — duplicate-index rejection, strictly-increasing ordering,
recovery-id bounds, correct double-keccak digest, quorum. But the VAA's
**emitter is parsed and never checked** (T-01), so it proves "the Wormhole
guardians signed *some* message", not "Pyth published this price". And
staleness is measured against local arrival time rather than the signed
`publish_time` (T-02), so a genuine hour-old VAA replays as fresh.

**What verified clean.** `api/auth.rs` is the strongest module in the
repository — argon2id with per-field salts, deliberately non-short-circuiting
two-factor verify, `spawn_blocking` behind a `try_acquire` limiter that sheds
rather than queues, a login rate bucket keyed on the *resolved* account (so it
cannot be grown by inventing keys), zero expiry leeway with the revocation
prune derived from the same constant, and immediate-effect suspension via
registry re-read. The rapidsnark FFI correctly keeps the zkey buffer alive for
the prover's lifetime and is structurally `!Sync`. Pass-1 findings S-01, S-02,
S-07, S-10 and the S-03 lock sweeper are all already implemented in the tree.

| Bucket | Count |
|---|---|
| High | 4 |
| Medium | 6 |
| Low | 5 |
| Perf-Nit | 3 |

Counts include the `T-11…T-15` assurance addendum from the 2026-07-27
verification pass (§7).

### Severity-ranked backlog

| ID | Severity | Category | Finding |
|---|---|---|---|
| T-01 | High | Oracle / soundness | VAA emitter parsed but never validated — any guardian-signed message is accepted as Pyth |
| T-02 | High | Oracle / replay | Staleness uses local arrival time, not the signed `publish_time`; no `sequence` monotonicity |
| T-03 | High | Privacy / infra | No in-enclave TLS — order intent is plaintext at the operator's gateway |
| T-04 | High | Supply chain / TEE-trust | `compose_hash` pins a mutable image tag, so attestation does not bind the binary |
| T-05 | Medium | Correctness / availability | Merkle mirror ingests at `confirmed` but is append-only with no rewind |
| T-06 | Medium | Availability | `persistence/snapshot.rs` is a 3-line stub — book + openings do not survive restart |
| T-07 | Medium | Correctness / interop | `user_commitment[0] == 0` intake check rejects ~98% of valid values; the daemon works around it by corrupting the commitment |
| T-08 | Medium | Supply chain | No `cargo audit` / `npm audit` gate; Actions pinned by mutable major tag |
| T-11 | Medium | Assurance / CI | No workflow runs the `darknyx-tee` test suite — every Phase A and `AU-` regression test is local-gate-only |
| T-12 | Medium | Test integrity | S-02's positive verification test silently **passes** when circuit artifacts are absent, and they are gitignored |
| T-09 | Low | Client custody | Daemon keystore scrypt parameters ~8× below current guidance |
| T-10 | Low | Client custody | Keystore KDF parameters read from the unauthenticated file header |
| T-13 | Low | Test integrity | A stale `target/deploy/vault.so` makes every litesvm test validate the wrong binary, silently |
| T-14 | Low | Dead code / interop | PF-04 left `NULLIFIER_SEED` + `nullifierEntryPda()` on the public SDK surface for an account the program no longer creates |
| T-15 | Low | Coverage | S-03's withdraw-side expiry path and `release_lock` have zero litesvm coverage, though the tracker row claims it |
| PF-08 | Perf-Nit | Client CPU | Trading keypair re-derived on every signature and every pubkey read |
| PF-09 | Perf-Nit | Prover | Unbounded `SHORT_BUFFER` retry loop in the rapidsnark FFI |
| PF-10 | Perf-Nit | Dead weight | `user_commitment` is carried through the whole pipeline and consumed by nothing |

---

## 2. Verified clean

### 2.1 `api/auth.rs` — no findings

This module was flagged in pass 1 §5 as needing its own review because it is
the only gate in front of S-02. It holds up:

- **Argon2id, per-field salt, PHC strings.** No plaintext at rest
  (`auth.rs:257-261`).
- **Non-short-circuiting two-factor verify** (`auth.rs:248-252`). The `&`
  rather than `&&` is deliberate and documented: `&&` would skip the second
  Argon2 when the first fails, leaking via timing whether `api_secret` alone
  was correct.
- **Argon2 runs off the reactor and sheds under load** (`auth.rs:631-656`).
  `try_acquire` rather than `acquire` — the comment correctly identifies that
  awaiting a permit bounds concurrency but not queue depth, so a burst would
  otherwise starve the matcher and settle worker sharing the runtime.
- **Login rate bucket keyed on the *resolved* account** (`auth.rs:607-624`),
  so the bucket map is bounded by registered accounts and cannot be grown by a
  caller inventing keys — and an abusive account throttles only itself.
- **Unknown `api_key` refused before any hashing** (`auth.rs:595-599`), with
  the resulting timing oracle explicitly reasoned about and accepted (128-bit
  random keys make enumeration infeasible).
- **Zero expiry leeway** (`auth.rs:74`), with the revocation-prune margin
  derived from the same constant so the two cannot drift — closing the window
  where a prune could un-revoke a token inside the leeway.
- **Both transports converge on `validate_token`** (`auth.rs:723-780`), which
  re-reads the registry rather than trusting signed claims, so suspension
  (`disabled`) and bulk invalidation (`tokens_valid_from`) take effect on the
  next request. The comment notes this placement is deliberate because a check
  in the HTTP middleware alone would not cover the WebSocket — which is how the
  WebSocket once escaped the rate limiter.
- **`Validation::default()`** pins `algorithms = [HS256]`, so `alg: none` and
  RS256 confusion are both rejected; the key is symmetric and dstack-derived
  (`main.rs:118`).
- The JWT denylist **is** persisted (`persistence::auth`), so **D-07
  ("revoke denylist is memory-only across restart") is closed** at HEAD.

### 2.2 `prover/rapidsnark_sys.rs` — no security findings

- The `_zkey: Vec<u8>` field is kept alive for the prover's lifetime with a
  precise comment explaining why the `_zkey_file` variant would dangle
  (rapidsnark's `BinFile` references rather than copies). This is exactly the
  kind of FFI lifetime bug that is usually present and is not.
- `unsafe impl Send` without `Sync` is correct and load-bearing: `prove` takes
  `&self`, and `!Sync` makes `&RawProver` non-`Send`, so the compiler prevents
  concurrent use even if a caller forgot the Mutex.
- `Drop` nulls the handle after destroy; error buffers are NUL-bounded before
  UTF-8 conversion.

### 2.3 Other confirmations

- **`vaa.rs` signature verification is correct**: double-keccak digest matching
  Wormhole's `SigningDigest`, strictly-increasing guardian index (blocks
  duplicate counting), explicit `seen` array (blocks duplicates a second way),
  `recovery_id > 1` rejection, guardian-index bounds check, quorum 13/19 pinned
  by a test that re-derives it from the set size.
- **`api/rate_limit.rs`** applies weighted per-account costs, and
  `stream.rs:826-834` has a test asserting the WebSocket op costs *mirror* the
  HTTP route costs — the right way to keep two transports from diverging.
- **`stream.rs`** enforces token expiry mid-session (`:334-346`), warns 60 s
  ahead, requires re-login to refresh, refuses to switch identity on a live
  socket, and handles `RecvError::Lagged` by closing rather than silently
  dropping.
- **Daemon attestation** (`packages/daemon/src/attestation.ts`) is strict by
  default, requires a real DCAP verifier, binds the **full K-shard key set**
  (not just shard 0) into the quote check, and cross-checks `/info` against
  `/attestation`. The `strict: false` path is clearly labelled as
  not-a-guarantee.

---

## 3. Findings

### T-01 — VAA emitter is parsed but never validated

| | |
|---|---|
| **Severity** | **High** |
| **Category** | Oracle / soundness |
| **Status** | New. Breaks the stated goal of the C-05 remediation. |

**Anchors**

- `crates/darknyx-tee/src/oracle/vaa.rs:256-259` — `emitter_chain_id` and
  `emitter_address` are parsed into `ParsedVaa`.
- `crates/darknyx-tee/src/oracle/vaa.rs:293-374` — `verify_signatures` checks
  the guardian set index, the digest, per-signature recovery, and quorum. It
  never reads either emitter field.
- `crates/darknyx-tee/src/oracle/vaa.rs:376-382` — the `verify` wrapper is
  `parse` + `verify_signatures`. Nothing more.
- `crates/darknyx-tee/src/oracle/sync.rs:101-106` — the consumer calls
  `vaa::verify` and immediately takes the Merkle root from the payload.
- Repo-wide: the only non-parser reference to `emitter_*` is a **test**
  assertion (`crates/darknyx-tee/tests/oracle_vaa.rs:76`). No production path
  checks it.

**The problem in plain terms**

`verify_signatures` proves *the Wormhole guardians signed this message*. It
does **not** prove *Pyth published it*. Wormhole guardians sign VAAs for every
connected application on the network — token bridge, NFT bridge, governance,
generic messaging, other oracles. The emitter `(chain_id, address)` pair is the
only thing that distinguishes "a Pyth price attestation" from "a token
transfer", and it is discarded.

The module header states the intended division of labour precisely:

> This module proves *the guardians signed a VAA*; `oracle::accumulator` proves
> *the price we use is committed under that VAA's root*.

Both halves are true, and together they are still insufficient, because the
*root* is read from the payload of whatever VAA was supplied
(`sync.rs:105`). If the attacker chooses the emitter, the attacker chooses the
root, and the Merkle inclusion proof then verifies correctly against an
attacker-controlled tree.

**Failure scenario**

1. The attacker emits a message through any Wormhole application that lets a
   user supply arbitrary payload bytes — the token bridge's
   transfer-with-payload is the canonical example. The guardians sign it
   legitimately; it is a real, valid VAA.
2. The payload is crafted to parse as a Pyth accumulator update: correct
   envelope, an attacker-chosen Merkle root, and a price message for the
   SOL/USD feed id with an attacker-chosen `ema_price`, plus a valid inclusion
   proof under that root.
3. The attacker delivers this VAA to the enclave — by MITM'ing
   `hermes.pyth.network`, compromising it, or hijacking DNS. (Which is exactly
   the threat guardian verification was added to defend against; without it the
   price was simply taken from Hermes's untrusted JSON.)
4. `vaa::verify` passes — the signatures are genuine. `merkle_root_from_vaa_payload`
   returns the attacker's root. `verify_inclusion` passes against it.
   `ema_price > 0` passes. The Hermes JSON cross-check (`sync.rs:156-164`)
   passes because the same hostile source serves both halves — the comment
   already concedes this only catches decode bugs.
5. The poisoned price is cached and becomes the matcher's TWAP anchor, so the
   circuit breaker — the only price-sanity control outside pure TEE trust —
   bands against an attacker-chosen number.

**Recommended fixes**

| Option | Description | Trade-off |
|---|---|---|
| **A — Pin the Pyth emitter (recommended)** | Add `PYTH_EMITTER_CHAIN: u16 = 26` (Pythnet) and the 32-byte `PYTH_PRICE_EMITTER` address as constants beside `MAINNET_GUARDIANS`, and reject in `verify` when either differs. | Two comparisons. Restores the property the whole guardian-verification track was built for. Must be updated if Pyth ever re-emits from another chain — same maintenance shape as the guardian table already has. |
| **B — Check in `sync::refresh_one`** | Same check, at the consumer. | Works, but leaves `vaa::verify` returning something whose name over-promises. A future second consumer would repeat the mistake. Prefer A. |
| **C — Allowlist a set of emitters** | Accept a configured set rather than one constant. | Only if multi-source oracles are planned. Adds governance surface for no current benefit. |

Take **A**, and rename or document `verify` so its contract reads "verified
Pyth VAA", not "verified VAA".

**Lockstep:** None. Local to the oracle module.

**Cost of the fix**

| Item | Estimate |
|---|---|
| Constants + rejection in `vaa::verify` | ~0.5 day |
| Negative test: a real non-Pyth mainnet VAA fixture must be rejected | ~0.5 day |
| Re-verify against the existing `sol_usd_vaa.bin` fixture | ~0.25 day |
| **Total** | **~1.25 days** |

---

### T-02 — Oracle staleness uses local arrival time, not the signed `publish_time`

| | |
|---|---|
| **Severity** | **High** |
| **Category** | Oracle / replay |
| **Status** | New. Independent of T-01; either alone poisons the TWAP anchor. |

**Anchors**

- `crates/darknyx-tee/src/oracle/cache.rs:92` — the staleness test is
  `now_ms().saturating_sub(entry.last_updated_ms) > max_age_ms`.
- `crates/darknyx-tee/src/oracle/cache.rs:68-70` — `upsert` stamps
  `last_updated_ms = now_ms()`, i.e. the moment *this process* accepted the
  update.
- `crates/darknyx-tee/src/oracle/cache.rs:30` — `publish_time_ms`, the
  guardian-signed timestamp, is stored…
- `crates/darknyx-tee/src/oracle/sync.rs:166-179` — …and never compared to
  anything. The field is written into the cache entry and dropped.
- `crates/darknyx-tee/src/oracle/vaa.rs:184` — `sequence` is likewise parsed
  and never used for monotonicity.

**The problem in plain terms**

The cache's own doc comment (`cache.rs:33-35`) says `last_updated_ms` exists so
staleness can be checked "independently of Pyth's `publish_time_ms`". That is
backwards for an adversarial input: `last_updated_ms` measures *how recently we
were told something*, which an attacker controls completely by choosing when to
deliver. `publish_time_ms` measures *when Pyth actually signed it*, which is
the only timestamp an attacker cannot forge.

**Failure scenario**

1. The attacker captures a genuine SOL/USD VAA at a moment when the price is
   favourable to them — correct emitter, correct guardians, correct feed,
   correct Merkle inclusion. Nothing about it is forged.
2. An hour later they replay that exact VAA to the enclave (MITM, hostile
   Hermes, DNS).
3. Every check in `refresh_one` passes — signatures, root, inclusion,
   positivity, and the JSON cross-check (the attacker replays the matching JSON
   from the same capture).
4. `upsert` stamps `last_updated_ms = now`. `snapshot()` sees age ≈ 0 ms and
   serves it as fresh.
5. The matcher's circuit breaker bands the clearing price against an hour-old
   anchor. Under a fast move, the band is centred where the market *was*,
   which is precisely when a manipulated clear is most profitable.

Because there is also no `sequence` monotonicity check, the same VAA can be
replayed indefinitely, and an *older* VAA can be replayed after a newer one has
been accepted.

**Recommended fixes**

| Option | Description | Trade-off |
|---|---|---|
| **A — Gate on signed publish time + monotonic sequence (recommended)** | In `refresh_one`, reject when `now - msg.publish_time > MAX_PUBLISH_AGE` (a few seconds), and reject a `sequence` (or `publish_time`) not strictly greater than the cached entry's. | Closes both replay and staleness with two comparisons on values the attacker cannot forge. Needs a small clock-skew allowance since `publish_time` comes from Pythnet. |
| **B — Change the staleness metric only** | Make `snapshot()` use `publish_time_ms` instead of `last_updated_ms`. | Simplest, and closes the *stale-price* half. Does not stop repeated replay of a *recent* VAA, which matters much less. Good immediate mitigation. |
| **C — Keep both metrics** | Require both `last_updated_ms` and `publish_time_ms` to be fresh. | The most conservative: catches a stalled sync task *and* a stale payload. Slightly more code than A; worth it since the two failure modes are genuinely different. |

Take **C** (it strictly contains A and B), and add the sequence check.

**Lockstep:** None.

**Cost of the fix**

| Item | Estimate |
|---|---|
| Freshness + monotonicity gates in `refresh_one`, plumbed into `CachedPrice` | ~0.5 day |
| `snapshot()` dual-metric staleness | ~0.25 day |
| Tests: replayed fixture rejected; out-of-order sequence rejected; skew tolerance | ~1 day |
| **Total** | **~1.75 days** |

---

### T-03 — No in-enclave TLS: order intent is plaintext at the operator's gateway

| | |
|---|---|
| **Severity** | **High** |
| **Category** | Privacy / infrastructure |
| **Status** | New. Contradicts the documented threat model. |

**Anchors**

- The TEE binary contains **no TLS server**: no `rustls`, no `axum-server`, no
  `TlsAcceptor` anywhere in `crates/darknyx-tee/src/`. The single TLS reference
  in `Cargo.toml:33` ("Rustls-only TLS (no OpenSSL on the host)") concerns the
  **outbound** `reqwest` client used for Hermes and Solana RPC.
- `deploy/docker-compose.yaml` — `DARKNYX_TEE_HTTP_BIND: "0.0.0.0:8080"` and
  `ports: ["8080:8080"]`, with the comment "dstack-ingress fronts this on :443
  once that container is added (**Phase 2+**)".
- The same file's roadmap section lists "dstack-ingress sidecar for the custom
  domain + ACME" as not enabled.
- `CRYPTOGRAPHY.md` §2 non-goals: "Network-level traffic analysis | Partially
  mitigated by **TLS to the CVM**".
- `CRYPTOGRAPHY.md` §8 step 4: "Alice submits her order **over TLS directly to
  the enclave's HTTP surface**".

**The problem in plain terms**

The documentation describes TLS terminating *at the enclave*. The deployment
terminates it at the **Phala gateway**, and the enclave speaks plaintext HTTP
behind it. The consequence is precise and material: the order body — `side`,
`price_limit`, `amount`, `note_commitment`, `owner_commitment`,
`note_inner_hash`, `trading_key`, and (until T-07/S-09 land) the `nullifier` —
is in the operator's process memory in cleartext before the enclave ever sees
it.

The protocol's headline privacy property is that order intent never becomes
public and lives only inside the attested enclave. The anonymity set is
described as "every order in the book that didn't settle". Neither statement
holds against the party running the gateway.

This is not a hypothetical adversary: the entire attestation apparatus —
DCAP, MRTD pinning, compose-hash governance — exists precisely to remove the
need to trust the operator. Terminating TLS outside the enclave reintroduces
that trust for the most sensitive data in the system.

**Failure scenario**

The Phala gateway (or anyone who compromises it, or a lawful-access request
against it) observes complete order flow in real time: every price, size, and
side, joined to a stable `trading_key` and `owner_commitment`. That is enough
to front-run the book, deanonymise participants across orders, and reconstruct
the very information the darkpool exists to hide — with no on-chain trace and
no client-detectable signal.

**Recommended fixes**

| Option | Description | Trade-off |
|---|---|---|
| **A — RA-TLS terminating inside the enclave (recommended)** | Serve HTTPS from the TEE binary with a certificate whose key is dstack-derived and whose quote binds the public key, so the client's existing attestation check also authenticates the transport. | The correct end state; it is what `docs/tee-attestation-flow.md` already describes. Changes `compose_hash` (governance rotation) and adds a cert-lifecycle path. |
| **B — dstack-ingress sidecar** | Enable the sidecar already sketched in the compose roadmap, terminating TLS inside the CVM boundary. | Less code than A and uses the platform's supported path. Still changes `compose_hash`. Trust boundary is the CVM rather than the process — acceptable. |
| **C — Application-layer encryption of the order body** | Encrypt the order to an enclave-held X25519 key (the `viewing_pubkey` machinery already exists), leaving the gateway with only ciphertext. | Works without changing the transport, and composes with A/B. But it needs a canonical-body change and client rollout, and leaves metadata (timing, size, peer) exposed. Best as defence-in-depth, not the primary fix. |
| **D — Document the gateway as trusted** | Amend `CRYPTOGRAPHY.md` §2 to state that the operator sees plaintext order flow. | Not a fix, but **mandatory immediately** if A/B will not land before any real-value use. Shipping the current text alongside the current deployment is the part that is not acceptable. |

Take **B** now (fastest path to the property), **A** as the end state, and
**D** in the same change as whichever ships.

**Lockstep:** No cryptographic contract changes, but any of A/B alters
`compose_hash` → new governance allowlist entry + client pin update + TEE-key
rotation ceremony per `docs/tee-attestation-flow.md` §5.

**Cost of the fix**

| Item | Estimate |
|---|---|
| B: enable + configure dstack-ingress, verify RA-HTTPS end to end | ~2 days |
| A: in-process RA-TLS (cert from dstack key, quote binds SPKI), client verification | ~4 days |
| Client/SDK: pin the transport identity to the attested key | ~1.5 days |
| Governance: compose-hash rotation + allowlist + signer ceremony | ~0.5 day + ceremony window |
| D: documentation correction | ~0.25 day |
| **Total** | **~2.75 days for B + doc**, ~6 days for the full A path |

---

### T-04 — `compose_hash` pins a mutable image tag, so attestation does not bind the binary

| | |
|---|---|
| **Severity** | **High** |
| **Category** | Supply chain / TEE-trust |
| **Status** | New. Acknowledged as a TODO in the compose but not tracked as a security item. |

**Anchors**

- `deploy/docker-compose.yaml:26` —
  `image: ghcr.io/skysail-labs/darknyx-tee:tee-v3-hardening-72`.
- `deploy/docker-compose.yaml:23-25` — the standing TODO: "replace with a
  pinned `ghcr.io/<org>/darknyx-tee@sha256:...` digest once we set up the build
  pipeline."
- `deploy/docker-compose.yaml:3-9` — the file's own header states the stakes:
  "This file gets hashed … into the `compose_hash` baked into RTMR3. Every byte
  here is load-bearing."

**The problem in plain terms**

`compose_hash` is a hash of the compose **text**. The compose text names a
**mutable tag**. Therefore `compose_hash` binds *the intent to run whatever is
currently at that tag* — not the code.

An adversary who can push to `ghcr.io/skysail-labs/darknyx-tee` (a leaked CI
token, a compromised maintainer account, a malicious dependency in the image
build) re-points `tee-v3-hardening-72` at their own image. On the next CVM
restart or migration, dstack pulls it. `compose_hash` is unchanged, so:

- RTMR3 is unchanged.
- The governance allowlist entry still matches.
- Every client's `expected.composeHash` pin still matches.
- `verifyReportAgainstExpected` returns no failure.
- The daemon trades against a substituted enclave and reports `dcapVerified: true`.

The attestation chain is intact and attesting to the wrong thing. This is
exactly the "TEE-binary substitution" row that `CRYPTOGRAPHY.md` §2 lists as
**Open**, but the mitigation recorded there ("Production must pin them to an
attested enclave") does not address it — pinning the *signer* to an attested
enclave does not help when the enclave's *code* can change underneath a stable
measurement.

**Recommended fixes**

| Option | Description | Trade-off |
|---|---|---|
| **A — Pin by digest (recommended)** | `image: ghcr.io/skysail-labs/darknyx-tee@sha256:<digest>`. | One line. Makes `compose_hash` transitively bind the exact image bytes, which is what everyone already believes it does. Requires the release process to resolve tag → digest and commit it — a runbook step, not engineering. |
| **B — Digest + registry immutability** | A, plus enabling GHCR immutable tags / a tag-protection policy. | Defence in depth; A alone is sufficient for the attestation property. Cheap to add. |
| **C — Reproducible builds + published attestation** | Publish the image digest and a build attestation alongside each governance rotation so a third party can independently confirm digest ↔ source. | The end state for a system asking users to trust a measurement. Larger effort; schedule after A. |

Take **A** immediately — it is a one-line change that closes a High-severity
supply-chain hole — then **B**, then **C** as the release process matures.

**Lockstep:** Changing the compose changes `compose_hash` → governance
allowlist entry + client pins + signer rotation ceremony. Bundle with T-03's
compose change so one ceremony covers both.

**Cost of the fix**

| Item | Estimate |
|---|---|
| A: digest pin + runbook step in `docs/cvm-run-runbook.md` | ~0.5 day |
| B: registry tag-immutability policy | ~0.5 day |
| Ceremony (shared with T-03) | one window |
| **Total** | **~1 day** + a shared ceremony |

---

### T-05 — The Merkle mirror ingests at `confirmed` but is append-only with no rewind

| | |
|---|---|
| **Severity** | Medium |
| **Category** | Correctness / availability |
| **Status** | New. |

**Anchors**

- `crates/darknyx-tee/src/solana_rpc/client.rs:33-38` — `Commitment` defaults
  to `Confirmed`.
- `crates/darknyx-tee/src/main.rs:490-504` — the client handed to
  `MerkleSync::new` is constructed with plain `SolanaRpcClient::new(...)`, so
  it keeps the `Confirmed` default.
- `crates/darknyx-tee/src/main.rs:1055` — by contrast, the governance snapshot
  reader explicitly upgrades: `.with_commitment(Commitment::Finalized)`.
- `CLAUDE.md` §3.4 — "the CVM Merkle mirror is append-only — it can't rewind —
  so a fresh tree needs a reset **+ a CVM cold-boot**".

**The problem in plain terms**

The codebase already knows finality matters — it reaches for `Finalized` when
reading governance, where a wrong read is *recoverable* on the next poll. It
uses the weaker `Confirmed` default for the Merkle mirror, where a wrong read
is **not** recoverable, because the mirror has no rewind path.

A `confirmed` transaction is not final. If a reorg drops a `deposit` or
`tee_forced_settle_batched` whose leaf the mirror has already appended, the
mirror holds a leaf the chain does not, and **every subsequent leaf index is
off by one**.

**Failure scenario**

1. A settle confirms and the mirror appends its output leaves at indices
   `n…n+5`.
2. A reorg drops that transaction. On-chain `leaf_count` returns to `n`. The
   next real append lands at `n`.
3. The mirror still believes index `n` is the dropped settle's `note_c`, and
   every later leaf is shifted.
4. `GET /tree/inclusion` now returns sibling paths that fold to a root the
   vault has never had. Clients build `VALID_INPUT` proofs from them; every
   `lock_note` fails `StaleMerkleRoot`, and every `VALID_SPEND` withdraw built
   from a mirror witness fails the same way. Trading halts for everyone using
   the mirror as their witness source — which is the documented default, since
   the off-TEE indexer is optional.
5. There is no in-process recovery: the mirror cannot rewind. Restoring
   service requires a CVM cold-boot with a corrected
   `DARKNYX_TEE_SYNC_FROM_SLOT`.

**Recommended fixes**

| Option | Description | Trade-off |
|---|---|---|
| **A — Ingest at `finalized` (recommended)** | `.with_commitment(Commitment::Finalized)` on the mirror's client, matching the governance reader. | One line. Removes the class entirely. Costs ~1–2 slots of extra latency before a new leaf is visible — acceptable, and it shrinks further under Alpenglow. |
| **B — Rewind buffer for the unfinalized tail** | Track confirmed-but-unfinalized leaves separately and only commit them to the append-only structure at finality. | Keeps the low-latency view for reads that tolerate it, at the cost of real complexity in the hottest correctness path. Only worth it if the finality latency proves to hurt. |
| **C — Detect and self-heal** | Periodically compare mirror `leaf_count`/root against on-chain and trigger an automatic re-sync on divergence. | Good defence in depth regardless of A/B — it also catches bugs, not just reorgs. Does not remove the corruption window on its own. |

Take **A** now; add **C** as a health check. Note **A** also removes the
mirror's contribution to D-03's root-ring pressure, since finalized appends
arrive at a lower rate.

**Lockstep:** None.

**Cost of the fix**

| Item | Estimate |
|---|---|
| A: commitment change + re-validate cold-boot timing on devnet | ~0.5 day |
| C: divergence health check + `/tree/root` exposure of mirror-vs-chain skew | ~1.5 days |
| **Total** | **~2 days** |

---

### T-06 — The book and note openings do not survive a restart

| | |
|---|---|
| **Severity** | Medium |
| **Category** | Availability |
| **Status** | New. Compounds S-02/S-03 and D-01. |

**Anchors**

- `crates/darknyx-tee/src/persistence/snapshot.rs` — **the entire file is
  three lines of doc comment.** No types, no functions.
- `crates/darknyx-tee/src/persistence/mod.rs:11-13` — describes it as
  "(scaffold): the higher-churn order book + Merkle leaves + settle outbox, 5 s
  periodic. Lands in a later PR."
- Persisted today: `auth` (accounts + revoked jtis), `markers`
  (pending marker roots), and `pending_locks.db` (the S-03(B) lock sweeper).
  The **book** and the **`OpeningStore`** are not.

**The problem in plain terms**

`OpeningStore` holds the only copy of each order's note opening — the
`owner_commitment`, `inner_hash`, amount, `viewing_pubkey`, and the relayed
`VALID_INPUT` proof. It is in-memory only. On any CVM restart, redeploy, crash,
or migration, all of it is gone.

The consequence is asymmetric in a way that matters: **the on-chain `NoteLock`
survives, and the enclave's ability to use or release it does not.** After a
restart the enclave has no record that it locked those notes, cannot assemble a
settle for them, and cannot resume the order.

The `pending_locks.db` sweeper (added for S-03) is the right shape and does
recover the *rent* and the *lock*, but it can only release a lock **after
expiry** — so the user's collateral is still frozen for up to
`MAX_LOCK_TTL_SLOTS` (~30 min) for every in-flight order at restart time.

**Failure scenario**

A redeploy — a routine operation, and the documented way to change env or roll
an image — lands while N orders are locked and mid-settle. Every one of those
users has collateral frozen until expiry, receives no fill, no cancel, and no
order-update. The book is empty on the other side, so they cannot re-place
against the same note (the on-chain lock blocks a fresh `lock_note`). Under
S-02's fake-order griefing or an RPC incident, the same window opens without an
operator action at all.

**Recommended fixes**

| Option | Description | Trade-off |
|---|---|---|
| **A — Persist the opening store (recommended first step)** | Snapshot `OpeningStore` to the LUKS volume with the same best-effort bincode + atomic-rename pattern `persistence::auth` and `markers` already use. On boot, reload and reconcile against on-chain `NoteLock` PDAs. | Directly restores the ability to settle or cleanly release in-flight orders. Much smaller than persisting the whole book, and it is the part that holds funds hostage. Note it persists secrets (note openings) — the volume is LUKS-sealed by dstack-kms, so this matches the existing trust model, but it should be an explicit decision. |
| **B — Persist the full book too** | The scaffold's stated plan: book + leaves + settle outbox on a 5 s cadence. | Restores resting orders as well. Larger, and a 5 s cadence means a lossy tail — acceptable for orders, less so for openings, which argues for A being synchronous-on-change and B periodic. |
| **C — Drain before restart** | An operational pre-stop hook that cancels resting orders and waits for in-flight settles. | Cheap, and worth having regardless. Does nothing for a crash or an involuntary migration. |

Do **A** (write-on-change) + **C** now; schedule **B**.

**Lockstep:** None, but persisting openings writes user secrets to disk —
confirm the LUKS/dstack sealing model is acceptable for that class of data and
record the decision.

**Cost of the fix**

| Item | Estimate |
|---|---|
| A: `OpeningStore` snapshot + boot reconcile against on-chain locks | ~3 days |
| C: pre-stop drain hook | ~1 day |
| Crash-recovery tests (restart mid-settle, restart with locks held) | ~2 days |
| B: full book + outbox snapshot | ~4 days |
| **Total** | **~6 days for A+C+tests**; ~10 days including B |

---

### T-07 — The `user_commitment` Fr-safety check rejects ~98% of valid values, and the daemon works around it by corrupting the commitment

| | |
|---|---|
| **Severity** | Medium |
| **Category** | Correctness / interoperability |
| **Status** | New. |

**Anchors**

- `crates/darknyx-tee/src/api/orders.rs:376-380` — intake rejects any order
  whose `user_commitment[0] != 0`, justified as: "BN254 Fr-safety. Matcher
  Poseidon-hashes this during change-note construction; non-zero top byte means
  light-poseidon's `hash_bytes_be` will fail at tick time."
- `crates/darkpool-matcher/src/algorithm.rs:513` — contradicts it directly:
  "`user_commitment` is client-asserted metadata".
- Repo-wide grep: **`user_commitment` is never passed to Poseidon anywhere.**
  The only "hashed" references are stale comments
  (`crates/darknyx-tee-loadgen/src/auth.rs:264,270`).
- `packages/daemon/src/keystore.ts:133-144` — the client-side workaround:
  computes the real commitment, then `uc[0] = 0;` before returning it.

**The problem in plain terms**

Three defects compounding:

1. **The stated reason is false at HEAD.** The v3 change-note construction
   derives from the consumed input inner and `owner_commitment`; it never
   touches `user_commitment`. The check guards a hash that no longer happens.
2. **The check is wrong even on its own terms.** "Fr-safe" means "less than the
   BN254 scalar modulus". The modulus's top byte is `0x30`, so a valid Fr
   element's top byte lies in `[0x00, 0x30]` — 49 possible values. Requiring it
   to be exactly `0x00` rejects roughly **98%** of legitimate field elements. A
   correct check compares against the modulus.
3. **The client hides the bug by corrupting data.** The daemon zeroes the top
   byte, so its `user_commitment` is no longer
   `userCommitmentFromKeys(...)`. The keystore comment concedes the
   consequence: "this value is NOT a raw `create_wallet` Poseidon output". It
   can therefore never be matched against a `WalletEntry` registered on-chain,
   permanently severing the daemon's orders from the wallet-registration
   identity the field exists to carry.

Any independent client implementing to the documented spec — computing a real
`user_commitment` — is rejected ~98% of the time with an `fr_unsafe` error that
does not describe the real constraint.

**Recommended fixes**

| Option | Description | Trade-off |
|---|---|---|
| **A — Remove the field (recommended)** | `user_commitment` is consumed by nothing (see PF-10). Drop it from `PlaceOrderRequest`, `OrderCanonical`, `Order`, and `MatchPair`; delete the check and the daemon's zeroing. | Removes the defect, a wire field, 32 bytes from the signed body, and dead plumbing through four structs. Changes the canonical body → parity-fixture regeneration. |
| **B — Fix the check, keep the field** | Replace `[0] != 0` with a real `< modulus` comparison, and delete the daemon's `uc[0] = 0`. | Keeps the field for a future `WalletEntry` cross-check. No canonical-body change, so much cheaper. But it leaves a field nothing reads. |
| **C — Fix the check and start using the field** | B, plus actually verifying `user_commitment` against a registered `WalletEntry` at intake. | The only option that makes the field earn its place. Meaningful new work, and it would make wallet registration mandatory — a product decision, not just an engineering one. |

Take **A** if wallet registration is not on the near roadmap; **B** as a
one-day stopgap in either case, since it un-breaks spec-conforming clients
immediately.

**Lockstep:** A changes `OrderCanonical` → `order_canonical.rs` ↔
`packages/sdk/src/orders/canonical.ts` ↔ both pinned fixture digests ↔
`order-canonical-parity.test.ts`. B is lockstep-free.

**Cost of the fix**

| Item | Estimate |
|---|---|
| B (stopgap): correct modulus check + remove daemon zeroing + test | ~1 day |
| A: field removal across wire, canonical, matcher structs, SDK, fixtures | ~2.5 days |
| **Total** | **~1 day** now, **~2.5 days** for the full removal |

---

### T-08 — No dependency-audit gate; GitHub Actions pinned by mutable tag

| | |
|---|---|
| **Severity** | Medium |
| **Category** | Supply chain |
| **Status** | Reopens `audit_1` roadmap item 12 (recorded as "STILL TODO"), with the Actions-pinning half newly noted. |

**Anchors**

- `.github/workflows/` — no workflow references `cargo audit` or `npm audit`.
  Seven workflows: `cvm-e2e`, `cvm-ghcr-cleanup`, `cvm-sweeper`,
  `nightly-devnet`, `pr-checks`, `tee-image`, `witness-bench`.
- `.github/workflows/tee-image.yml:82,92,95,143,190` — every action is pinned
  by **mutable major tag** (`actions/checkout@v5`,
  `docker/setup-buildx-action@v4`, `docker/login-action@v4`,
  `actions/setup-node@v5`, `docker/build-push-action@v7`).
- The same workflow holds `permissions:` sufficient to push to GHCR.

**The problem in plain terms**

Two gaps that compose with T-04 into one path:

1. **No dependency audit in CI.** `audit_1` found a genuinely
   production-reachable `openssl` CVE in the TEE's TLS path; it was fixed
   manually. Nothing prevents the next one from shipping silently. The project
   pins PTAU files by SHA-256 and worries carefully about byte-equality
   contracts, so the absence of a dependency gate is an outlier.
2. **Actions pinned by tag.** A mutable major tag means the code running in the
   job that holds GHCR push rights can change without any repository change.

Chained with T-04: compromised action → GHCR push token → re-point the mutable
image tag → CVM pulls a substituted binary → `compose_hash` unchanged →
attestation passes. Each link is individually unremarkable; together they are a
complete, attestation-invisible path to the enclave binary.

**Recommended fixes**

| Option | Description | Trade-off |
|---|---|---|
| **A — Both (recommended)** | Add `cargo audit` + `npm audit --production` to `pr-checks.yml` with an explicit allowlist for the triaged-and-accepted advisories already documented in `audit_1`. Pin every action to a full commit SHA. | Standard hardening. The allowlist matters — `audit_1` already did the reachability triage, so encode that work rather than repeating it or drowning in noise. |
| **B — Audit gate only** | Dependency scanning without SHA pinning. | Half the value; leaves the T-04 chain intact. |
| **C — Dependabot only** | Rely on the existing alerts. | Already in place and already producing findings nobody is gated on. Alerts without a gate is how the current state arose. |

Take **A**, and pin `tee-image.yml` first since it is the workflow with push
rights.

**Cost of the fix**

| Item | Estimate |
|---|---|
| `cargo audit` + `npm audit` jobs with a documented allowlist | ~1.5 days |
| SHA-pin all actions across 7 workflows | ~0.5 day |
| **Total** | **~2 days** |

---

### T-09 — Daemon keystore scrypt parameters are ~8× below current guidance

| | |
|---|---|
| **Severity** | Low |
| **Category** | Client custody |

**Anchors**

- `packages/daemon/src/keystore.ts:185` — `const SCRYPT = { n: 16384, r: 8, p: 1 }`.
- `packages/daemon/src/keystore.ts:219-243` — this seals the
  `AccountIdentity`, which contains the **64-byte master seed** — the root
  secret from which the spending key, and therefore access to all funds,
  derives.

**Assessment.** `N = 2^14, r = 8, p = 1` is ~16 MiB and ~50–100 ms. Current
OWASP guidance for scrypt is `N = 2^17, r = 8, p = 1` (~128 MiB) as a floor.
For a file whose compromise yields total, irreversible fund loss — and where
the honest user pays the cost exactly once per daemon start — the parameters
should sit at or above that floor. AES-256-GCM, the random 16-byte salt, the
12-byte IV, and `0600` file mode are all correct; only the work factor is
light.

**Options:** (a) raise to `N = 2^17` with a version bump and transparent
re-seal on next unlock; (b) migrate to Argon2id, which the TEE already depends
on, giving one KDF across the codebase and better GPU resistance. Either is
small; (b) is tidier but adds a dependency to the daemon.

**Cost:** ~1 day including the versioned re-seal path.

---

### T-10 — Keystore KDF parameters are read from the unauthenticated file header

| | |
|---|---|
| **Severity** | Low |
| **Category** | Client custody |

**Anchors**

- `packages/daemon/src/keystore.ts:246-255` — `loadKeystore` reads `file.n`,
  `file.r`, `file.p` from the JSON and passes them straight to `scryptSync`.
- These fields sit **outside** the AEAD: only the identity JSON is
  authenticated by the GCM tag.

**Assessment.** Confidentiality is not directly at risk — tampering with the
parameters yields a different key, so the GCM tag fails and `loadKeystore`
throws. The realistic impact is **resource exhaustion**: an attacker (or a
corrupt file) with `n = 2^30` causes `scryptSync` to attempt a ~128 GiB
allocation, crashing or wedging the daemon at startup. There is also no bound
on `r` or `p`.

**Options:** (a) clamp the parameters to a sane range before use and reject
outside it; (b) ignore the file's values entirely and pin them by `version`
(cleanest — the version field already exists and is checked); (c) authenticate
the header by passing it as GCM AAD, which also makes downgrade detection
explicit. (b) + (c) together is the tidy answer.

**Cost:** ~0.5 day.

---

## 4. Performance findings

### PF-08 — The daemon re-derives a trading keypair on every signature and every pubkey read

**Severity:** Perf-Nit · **Category:** Client CPU

**Anchors:** `packages/daemon/src/keystore.ts:148-164`

`tradingKeypair(index)` runs `deriveTradingKeyAtOffset` (HKDF-SHA256) followed
by `nacl.sign.keyPair.fromSeed` (an Ed25519 scalar multiplication, ~0.5–1 ms in
pure JS). It is called by **both** `tradingPublicKey` and `signWithTradingKey`,
so building and signing one order does the full derivation at least twice.

For a market-maker daemon — the stated purpose of this package — placing and
repricing continuously, this is a measurable per-order cost on the latency path
and is entirely avoidable with a small bounded cache keyed on `index`.

**Trade-off worth stating:** caching keypairs extends the in-memory lifetime of
secret key material. Given the module's own trust boundary ("in memory the seed
is plaintext … the process is the trust boundary"), that is not a new exposure
— the seed that derives them is already resident. A small LRU (say 32 entries)
is the right shape.

**Cost:** ~0.5 day.

### PF-09 — Unbounded `SHORT_BUFFER` retry loop in the rapidsnark FFI

**Severity:** Perf-Nit · **Category:** Prover

**Anchor:** `crates/darknyx-tee/src/prover/rapidsnark_sys.rs:110-155`

On `PROVER_ERROR_SHORT_BUFFER` the loop grows the buffers to
`max(returned_len, cap + 1)` and retries **forever**. If rapidsnark ever
returns `SHORT_BUFFER` without writing a useful required size, the `+ 1`
guarantees progress of one byte per iteration — an effectively infinite loop
that also grows allocations, on the thread the settle worker is blocked on.

Not currently reachable (the library reports sizes correctly, and proof/public
sizes for two public inputs are small and fixed), which is why this is a nit.
But the settle worker has no timeout around `prove`, so the failure mode is a
silently stuck pipeline rather than an error. Bound the loop to 2–3 attempts
and return `Err` beyond that.

**Cost:** ~0.25 day.

### PF-10 — `user_commitment` is plumbed through the entire pipeline and consumed by nothing

**Severity:** Perf-Nit · **Category:** Dead weight (see T-07)

**Anchors:** `crates/darkpool-matcher/src/book.rs:97` ·
`crates/darkpool-matcher/src/algorithm.rs:125,157,559-560` ·
`crates/darkpool-matcher/src/match_result.rs:57,59`

The field is carried in the signed canonical body, stored on `Order`, copied
into `PreparedMatch`, and emitted on `MatchPair` as
`user_commitment_buyer` / `user_commitment_seller`. A repo-wide grep finds
**no production consumer** of either `MatchPair` field — every reference
outside the struct definitions is a test fixture.

Cost is 32 bytes in the signed body, 32 bytes per `Order`, and 64 bytes per
`MatchPair`, plus the copies through the matcher's hot path. Small, but it is
also the field behind T-07's correctness defect, which is the real reason to
remove it. Fold this into T-07 option A rather than treating it as separate
work.

---

## 5. What I still could **not** rule out

Carried forward from pass 1 §5 where still open, plus new gaps from this pass.

1. **`settle/worker.rs` crash recovery (1,810 lines) — still not audited.**
   Pass 1 named it the highest-risk untested path; this pass established the
   *precondition* for the risk (T-06: openings are not persisted) but did not
   audit the reconciliation state machine, ALT pool recycling, or the durable
   marker queue's replay logic. **This remains the single most valuable
   remaining review target.**
2. **`oracle/accumulator.rs` (393 lines) — parser not line-by-line reviewed.**
   T-01 and T-02 were found at the boundaries around it (`vaa.rs`, `sync.rs`,
   `cache.rs`). The PNAU envelope parser, the Keccak160 sorted-pair Merkle
   verification, and `parse_price_feed_message` still deserve their own pass —
   hand-rolled binary parsing over attacker-influenced input is exactly where
   the next bug lives.
3. **`solana_rpc/client.rs` (1,000 lines)** — only the commitment model was
   examined (yielding T-05). Retry/backoff behaviour, response validation, and
   error classification were not reviewed.
4. **`merkle/mirror.rs` + `events.rs` (~1,150 lines)** — the event decoder and
   the mirror's internal consistency were not audited beyond establishing the
   commitment level and the no-rewind property.
5. **`api/stream.rs` (775 lines)** — spot-checked for auth, expiry, rate
   parity, and lag handling (all correct). Not reviewed for subscription
   authorization per channel, or for whether `fills`/`orders` routing can leak
   across accounts under the archive/`recent_order_owner` race.
6. **Client-side DCAP internals.** `packages/sdk/src/tee/verify-core.ts`,
   `parseEventLog`, and the RTMR3 replay were treated as correct based on the
   daemon's call pattern; the SDK implementations themselves were not read.
7. **`packages/indexer`** (~765 lines) and the daemon's `store.ts`,
   `order-lifecycle.ts`, `merge-runner.ts`, `lifecycle-engine.ts` were not
   reviewed. Note CS-12 (daemon merge counter resets to zero) was a finding in
   this area; whether the current `merge-runner` still derives from a mutable
   counter was **not** re-verified this pass.
8. **`config.rs` (576 lines) and `boot.rs` (284 lines)** — the boot fail-open
   posture (U-09's subject) was not re-derived.
9. **No dynamic testing.** No CVM deploy, no live attestation, no reorg
   simulation, no fuzzing of the VAA/accumulator parsers. T-01 and T-02 are
   derived statically and should be confirmed with a crafted-fixture test
   before and after the fix.
10. **Third-party primitives** — `k256` ecrecover, `sha3`, `argon2`,
    `chacha20poly1305`, `jsonwebtoken`, `dcap-qvl`, rapidsnark, and ICICLE were
    treated as correct.

---

## 6. Suggested remediation order

1. **T-01 and T-02 together** (~3 days, no ceremony). Both are local to the
   oracle module, both defeat the circuit breaker, and the fixes touch adjacent
   code. Do them as one change with one fixture-based negative test suite.
2. **T-04** (~0.5 day for the digest pin). One line, closes a High supply-chain
   hole. Bundle the compose change with T-03(B) so a single governance
   ceremony covers both.
3. **T-03** — decide immediately between shipping the fix and shipping the
   documentation correction (option D). The current combination of the deployed
   plaintext transport and the documented "TLS to the CVM" claim should not
   persist, and D costs a quarter-day.
4. **T-05** (~0.5 day for the commitment change). One line, removes a
   corruption class from the mirror.
5. **T-07 option B** (~1 day). Un-breaks spec-conforming third-party clients
   immediately; defer option A's field removal to the next canonical-body
   change so the parity fixtures are regenerated once.
6. **T-08** (~2 days). Pin `tee-image.yml` first — it is the workflow holding
   push rights, and it is the middle link in the T-04 chain.
7. **T-06** (~6 days). The largest item here and the one that most needs a
   design decision first (persisting note openings writes user secrets to the
   LUKS volume — confirm that is acceptable before building it).
8. **T-09, T-10, PF-08, PF-09** — bundle as one daemon/prover hygiene pass
   (~2 days total).
9. **Commission the deferred reviews in §5**, in this order:
   `settle/worker.rs` crash recovery → `oracle/accumulator.rs` parser →
   `solana_rpc/client.rs` → `merkle/mirror.rs`.

Insert **T-11 and T-12 between steps 2 and 3** — together ~1 day, and until they
land the remediation suite that protects every other item on this list is not
durably gated. See §7.

---

## 7. Verification-pass addendum — 2026-07-27

A pass over `audits/audit_5/tracker.md` to confirm the rows
marked complete are actually complete. Each finding was re-derived from the
code rather than read from the tracker prose, then the full gate was run.

**Result: every `S-`, `PF-`, and `AU-` fix is genuinely implemented and
passing.** No remediation was found to be missing, partial, or regressed. The
five findings below are defects in the *validation apparatus* — the tests exist
and pass, but several are not durably gated, so nothing would catch their
regression on a future change.

### 7.1 What was verified green at `30f1b6b`

| Gate | Result |
|---|---|
| `cargo fmt --all -- --check` | pass |
| `cargo clippy --workspace --all-targets -- -D warnings` | pass, zero warnings |
| `cargo build-sbf … --features devnet-admin` | pass |
| `cargo test --workspace` | **303 passed, 0 failed, 2 ignored** |
| `cargo test -p darknyx-tee --lib` | 286 passed, 1 ignored |
| `tsc --noEmit` sdk / indexer / daemon | pass / pass / pass |
| `vitest` sdk / indexer / daemon | 270+24 skip / 20 / 147+2 skip |

Named remediation tests confirmed to **execute** rather than skip:
`real_valid_input_proof_is_accepted_at_intake` (18.24 s — a genuine proving
run), `proof_is_rejected_when_the_declared_note_does_not_match`,
`duplicate_commitment_deposit_is_rejected`,
`verify_ix_carries_no_caller_chosen_expiry`,
`merge_rejects_duplicate_active_inputs`,
`merge_allows_an_input_whose_lock_has_expired`, `valid_spend_roundtrip`
(carrying S-01's substituted-destination negatives on both the lo and hi
halves), `idempotency_eviction_is_fifo_not_arbitrary`,
`nonce_marks_are_pruned_once_stale_but_fresh_ones_survive`,
`ws_order_costs_match_the_http_route_costs`.

S-01's VK lockstep is intact: the circuit declares `recipient[2]`, the built
`verification_key.json` reports `nPublic = 8` with `IC` length 9, the committed
`vk_valid_spend.rs` declares `VALID_SPEND_NR_PUBLIC_INPUTS = 8` and
`VALID_SPEND_IC: [[u8; 64]; 9]`, and `circuit_final.zkey` is committed.

### T-11 — No workflow runs the `darknyx-tee` test suite

| | |
|---|---|
| **Severity** | Medium |
| **Category** | Assurance / CI |

**Anchors**

- `.github/workflows/pr-checks.yml:154` — `cargo test -p darkpool-crypto --lib`
- `.github/workflows/pr-checks.yml:159` — `cargo test -p vault --lib`
- `.github/workflows/pr-checks.yml:565`, `:639` — `cargo test -p vault …`
  (the `vault-zk` and `vault-litesvm` jobs)
- Those four are **every** `cargo test` invocation across all seven workflow
  files. No `cargo test -p darknyx-tee`, no `cargo test --workspace`.

**The problem in plain terms**

`CLAUDE.md` §2.5 puts `cargo test --workspace` in the pre-PR gate, and that
gate does cover the TEE crate — but CI does not. So the ~286 library tests plus
every integration target in `crates/darknyx-tee/tests/` run only when a human
remembers to run them locally.

Concretely, the tests that will not re-run on any future PR include: S-02's
intake-verification suite, AU-01's WS/HTTP rate-cost parity test, the AU-02 /
AU-04 / AU-06 auth-control tests, S-10's eviction and prune tests, and the
S-03(B) lock-sweeper tests. That is the majority of the 2026-07-25 remediation.

This also sharpens the seven tracker rows reading "Code complete — offline gate
only": that gate is one developer's working copy, not a reproducible check.

**Note on the current policy.** `CLAUDE.md` records a temporary private-repo
validation policy (organization artifact quota exhausted) directing the team to
run the `pr-checks.yml` equivalents locally. That explains why hosted gates are
not being waited on; it does not explain why the TEE crate is absent from the
workflow definition itself, which is what will still be missing when the quota
is restored.

**Recommended fixes**

| Option | Description | Trade-off |
|---|---|---|
| **A — Add a `tee` job (recommended)** | A `cargo test -p darknyx-tee` job in `pr-checks.yml`, gated on the same `changes` filter the `rust` job uses. Needs `submodules: recursive` (the icicle-snark path dep) — the existing jobs already do this. | The direct fix. Runtime is dominated by a few proving tests; gate the slow ones behind the `circuits` job like `vault-zk` already is. |
| **B — Switch the `rust` job to `--workspace`** | Replace the two `--lib` invocations with `cargo test --workspace`. | One line, covers everything including future crates. Slower single job and loses the current per-crate failure attribution. |
| **C — Nightly only** | Run the TEE suite in `nightly-devnet.yml` rather than per-PR. | Cheapest, but a regression then lands on `main` before anything notices — which is the shape of the problem, not a fix for it. |

Take **A**. Prefer it over **B** so the slow proving tests can be gated
independently of the fast unit tests.

**Cost:** ~0.5 day, including tuning the `changes` filter and confirming
runtime.

### T-12 — S-02's positive verification test silently passes when artifacts are absent

| | |
|---|---|
| **Severity** | Medium |
| **Category** | Test integrity |

**Anchors**

- `crates/darknyx-tee/tests/valid_input_intake_verify.rs:52-65` —
  `prove_fixture()` checks for `circuit_js/circuit.wasm`, `circuit.r1cs`, and
  `circuit_final.zkey`; on any miss it prints `SKIP: …` and returns `None`.
- `crates/darknyx-tee/tests/valid_input_intake_verify.rs:201` (and `:217` for
  the negative twin) — `let Some(f) = prove_fixture() else { return };` — the
  test **returns successfully**, so the harness records it as `ok`.
- `.gitignore:43` (`circuits/**/*.r1cs`) and `.gitignore:45`
  (`circuits/**/*_js/`) — two of the three required artifacts are **not
  tracked**. Only `circuit_final.zkey` is (`git ls-files circuits/build/valid_input/`).

**The problem in plain terms**

On a fresh clone, or in any environment that has not run
`scripts/build-circuits.sh`, `real_valid_input_proof_is_accepted_at_intake`
reports **PASSED** without verifying anything.

That test is load-bearing. The tracker's own implementation notes credit it with
catching a fixture that proved under ark's default `LibsnarkReduction` instead
of `CircomReduction` — a bug that would have made intake reject **every
legitimate order in production**, and which a negative-only suite would have
sailed past. It is the single test standing between S-02 and a total
availability failure, and its skip path is indistinguishable from success.

Combined with T-11, it currently has no reliable gate in any environment.

(It ran for real during this pass — 18.24 s of actual proving — because the
local working copy has built artifacts. That is exactly the condition that makes
the gap invisible to whoever last ran it.)

**Recommended fixes**

| Option | Description | Trade-off |
|---|---|---|
| **A — Fail instead of skip under an env flag (recommended)** | Keep the skip for casual local runs, but `panic!` with the "run `build-circuits.sh`" message when a marker such as `REQUIRE_CIRCUIT_ARTIFACTS=1` is set. Set that marker in the T-11 CI job. | Preserves the friendly local default while making the gate real where it counts. Matches how the repo already gates `RUN_N16_PROVE` / `RUN_DEVNET_*`. |
| **B — Always fail on missing artifacts** | Drop the skip entirely. | Strictest and simplest to reason about, but breaks `cargo test --workspace` for anyone who has not run the ~5-minute circuit build — including the `cargo test -p vault --lib` path that does not otherwise need it. |
| **C — Track the artifacts** | Commit `circuit.r1cs` and `circuit.wasm` alongside the zkey. | Removes the condition, but adds tens of MB of regenerable binaries to the repo and creates a second lockstep surface of exactly the kind CLAUDE.md §5 warns about. Rejected. |

Take **A**, and apply the same treatment to any other `else { return }` skip
in the test tree — this is a pattern, not a one-off.

**Cost:** ~0.5 day including a sweep for sibling cases.

### T-13 — A stale `vault.so` makes litesvm validate the wrong binary, silently

| | |
|---|---|
| **Severity** | Low |
| **Category** | Test integrity |

**Anchors**

- Observed during this pass: `target/deploy/vault.so` was older than ten files
  under `programs/vault/src/`, including `withdraw.rs`, `deposit.rs`,
  `merge.rs`, `verify_match_batch.rs`, and `vk_valid_spend.rs` — every file the
  Phase B remediation touched.
- `cargo test --workspace` loads whatever `.so` is on disk. It neither rebuilds
  it nor warns, so the first run of this pass exercised the **pre-remediation**
  program and still reported all-green.
- `CLAUDE.md` §2.5 does list `cargo build-sbf` before `cargo test --workspace`,
  so the documented gate is correct — the hazard is that skipping that one line
  produces a confident false pass rather than an error.

**The problem in plain terms**

Every litesvm assertion in the S-04 / S-05 / S-11 / PF-01 / PF-02 / PF-04 set
is only as current as the artifact. A green run proves nothing about the working
tree unless the `.so` was rebuilt from it, and nothing in the tooling enforces
or reports that.

The 303-passing figure in §7.1 is from a run **after** an explicit rebuild.

**Recommended fixes**

| Option | Description | Trade-off |
|---|---|---|
| **A — Staleness assertion in the harness (recommended)** | Have the litesvm harness compare the `.so` mtime against the newest file under `programs/vault/src/` and panic with "run `cargo build-sbf`" when it is older. | ~15 lines in `settle_harness`, in one place every litesvm test already goes through. Turns a silent false pass into an actionable error. |
| **B — Rebuild from `build.rs`** | Invoke `cargo build-sbf` automatically. | Removes the failure mode entirely, but nests a cargo invocation inside a cargo build and slows every unrelated test run. |
| **C — Document only** | Reinforce the ordering in `CLAUDE.md` §2.5. | Already documented; the incident happened anyway. Insufficient alone. |

Take **A**. This is the same failure class as
`litesvm_test_harness_traps` — tests that pass while proving nothing.

**Cost:** ~0.5 day.

### T-14 — PF-04 left dead nullifier-PDA helpers on the public SDK surface

| | |
|---|---|
| **Severity** | Low |
| **Category** | Dead code / interoperability |

**Anchors**

- `packages/sdk/src/idl/seeds.ts:14` — `export const NULLIFIER_SEED`.
- `packages/sdk/src/idl/vault-client.ts:161-168` — `export function
  nullifierEntryPda(…)`, whose only remaining reference is its own definition.
- `packages/sdk/src/index.ts:18-19` — `export * from "./idl/vault-client.js"`
  and `"./idl/seeds.js"`, so both are on the **public** API surface.
- `crates/darknyx-tee/src/settle/vault.rs:37,96-97` — `NULLIFIER_SEED` and
  `nullifier_pda()`, with zero callers repo-wide.
- `programs/vault/src/instructions/withdraw.rs:198` — the account itself is
  correctly gone; the comment records why.

**The problem in plain terms**

PF-04 removed `NullifierEntry` from `withdraw`, so the program no longer creates
that PDA anywhere. The helpers that compute its address survived, and one of
them is exported from the SDK's public index. A consumer who reaches for
`nullifierEntryPda()` gets the address of an account that will never exist.

This is the same hazard shape as **S-06**, which the same remediation effort
fixed: an exported symbol that describes something the chain does not produce.
S-06 established that a doc comment on an exported symbol is not a deprecation;
that reasoning applies here unchanged.

**Recommended fixes**

| Option | Description | Trade-off |
|---|---|---|
| **A — Delete (recommended)** | Remove `nullifierEntryPda`, both `NULLIFIER_SEED` constants, and `nullifier_pda()`. | Clean. Follow CLAUDE.md §2.6 and grep the workflow YAMLs and scripts for the names in the same commit. `scripts/dev-commands.md` and `scripts/fund-tee-keys.mjs` still mention them in prose. |
| **B — Un-export, keep internal** | Drop from `index.ts`, retain for tooling. | Only worth it if something off-repo derives the address of historical entries. Pre-cutover PDAs from before PF-04 do still exist on devnet, so confirm before deleting. |

Take **A** unless a tool needs to read historical entries, in which case **B**.

**Cost:** ~0.5 day.

### T-15 — S-03's withdraw-side and `release_lock` paths have no litesvm coverage

| | |
|---|---|
| **Severity** | Low |
| **Category** | Coverage |

**Anchors**

- The tracker's S-03 row names as required evidence: "Litesvm `lock → expire →
  withdraw` and `→ release_lock → withdraw` (currently zero coverage)", and
  marks the row **Validated**.
- Present: `programs/vault/tests/merge_verify.rs:512` —
  `merge_allows_an_input_whose_lock_has_expired`, which covers both directions
  at the exact CS-09 boundary (live blocks at `expiry - 1`, expired proceeds at
  `expiry`). This is a good test.
- Absent: no test seeds a `NoteLock` and then withdraws.
  `grep -rn NoteAlreadyLocked programs/vault/tests/` returns nothing.
- Absent: `release_lock` has **no** litesvm test. Every reference in
  `programs/vault/tests/` is a comment.

**Assessment.** The residual risk is low: `withdraw.rs:124` and `merge.rs:122`
call the *same* `crate::state::note_lock_is_live()` helper, and the merge test
pins that helper's boundary behaviour precisely. The withdraw path also has live
devnet evidence (`devnet-deposit-withdraw` PASS), though with no lock present,
so it does not exercise the guard.

What is wrong is narrower and worth fixing on its own terms: **the row claims
evidence that does not exist.** A future refactor that gives `withdraw` its own
lock check would silently lose all coverage.

**Recommended fix.** Add two litesvm tests mirroring the merge one:
`withdraw_allows_a_note_whose_lock_has_expired` (live blocks, expired proceeds)
and `release_lock_then_withdraw` (seed lock → warp past expiry → `release_lock`
→ withdraw succeeds, rent returns to the caller). Reuse `seed_note_lock` from
`merge_verify.rs` and `build_withdraw_tx` from `settle_harness`. Then correct
the tracker row.

**Cost:** ~1 day.

### 7.2 Tracker record corrections

Bookkeeping in `audits/audit_5/tracker.md`, separate from the
findings above. Each was verified against the code or the merge history.

| # | Row | Says | Actually | Action |
|---|---|---|---|---|
| 1 | `S-03` | **Validated** with litesvm `lock → expire → withdraw` and `→ release_lock → withdraw` | Merge half covered; withdraw half and `release_lock` have zero coverage | Land T-15, then the row is accurate. Until then, qualify it |
| 2 | `S-03(B)` in **Declined** | "Moved to the Phase B slice… building it now would produce a liveness-critical component" | **Shipped.** `crates/darknyx-tee/src/settle/lock_sweep.rs` exists with 5 tests, is spawned at `main.rs:845` (`spawn_lock_sweeper`), and the devnet section records its boot log | Remove from Declined; add a row with the shipped evidence |
| 3 | `AU-06` | "**Code complete** — PR #72, offline gate green" | PR #72 merged 2026-07-26 (`19ae2a4`) | Move to **Closed** |
| 4 | Release gates, lines 347-353 | "`api/auth.rs` … is no longer in the uncommissioned list below" — then lists it in that list | Self-contradiction; the complete pass did happen (and §2.1 of this document is its result) | Delete the stale bullet |
| 5 | `PF-04` | **Validated** | Correct on-chain, but left the dead exports in T-14 | Note T-14 as follow-through |

None of these change a security conclusion. They matter because this tracker is
the artifact an external auditor will read to decide what was actually done.

### 7.3 Confirmed still open

`AU-07` (no WebSocket connection cap — verified absent from `api/stream.rs`),
the `D-01…D-09` backfill, `PF-03` and `PF-07` (deferred with recorded re-entry
conditions), and the `N-18` / `F-04` release gates. All correctly represented.
