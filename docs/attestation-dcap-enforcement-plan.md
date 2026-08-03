# Client-Side DCAP Attestation Enforcement — Implementation Plan

> **Audience:** engineering + external/model review. Code-verified against the
> monorepo as of the verification date below. Pair with
> [`tee-attestation-flow.md`](./tee-attestation-flow.md) (design) and
> [`../audits/audit_2/READINESS.md`](../audits/audit_2/READINESS.md) finding **A-1** (gap).
>
> **Not yet implemented** — this is a plan for critique, not a shipped feature.

**Status:** Design / cross-model review  
**Repo:** `nyx-monorepo` (Nyx / darknyx)  
**Primary finding:** `audits/audit_2/READINESS.md` **A-1** — attestation trust anchor not enforced end-to-end  
**Date of code verification:** 2026-07-12 (against current `main` tree)

---

## 1. Context — why this work exists

Nyx’s privacy and execution-price fairness guarantees are **TEE-trusted by design** (see `CRYPTOGRAPHY.md` accepted decision on price fairness). Those guarantees are only meaningful if a client can prove it is talking to a **genuine Intel TDX enclave** running a **governance-approved measured image**, not a normal server that fabricates JSON.

Today the daemon runs a partial connect-time check (`packages/daemon/src/attestation.ts`) that:

1. Checks nonce freshness in `report_data[0..32]`
2. Checks key binding `report_data[32..64] == SHA-256(tee_pubkey)`
3. Optionally pins `compose_hash` / `mrtd` / `tee_pubkey` from env
4. **Optionally** calls an injected `QuoteVerifier` for Intel DCAP — **never constructed in the stock binary**

Without DCAP, steps 1–3 operate on **self-reported** gateway fields. A malicious operator can echo the client nonce, bind their own Ed25519 key, copy the expected pins, and pass “attestation.” That is A-1.

**This plan does not claim DCAP fixes vault fund-theft.** On-chain ZK + PDAs still bound value inflation. DCAP closes the **operator / fake-gateway** hole for privacy + fairness trust.

**Explicitly out of scope of this epic:**

| Item | Track |
|---|---|
| On-chain DCAP / `dcap-qvl` BPF in `vault` | v3 / `tee-attestation-flow.md` §11 |
| Merge↔settle double-spend (C-01), relock TTL (C-02) | Separate fund-safety PRs |
| Circuit fee ceiling | Separate circuit lockstep |
| Oracle price↔VAA root (A-2) | Separate oracle work |

---

## 2. As-built reality (code-verified — do not trust docs alone)

### 2.1 Server (already sufficient for client DCAP inputs)

| Surface | Path | Behavior |
|---|---|---|
| `GET /attestation?reportData=` | `crates/nyx-tee/src/api/attestation.rs` | Builds `report_data = nonce(≤32) ‖ SHA-256(raw 32B pubkey)`; calls `dstack.get_quote(64)`; returns `{ quote, event_log, report_data, tee_pubkey }` |
| `GET /info` | `crates/nyx-tee/src/api/info.rs` | Boot snapshot: `compose_hash` top-level; **`mrtd` under `tcb_info.mrtd`**; `tee_pubkey` = **shard 0 only** |
| `GET /transparency` | `crates/nyx-tee/src/api/transparency.rs` | Public reserves + `tee.{compose_hash,mrtd,signer_pubkey}` — **no quote** |
| K shard keys | `crates/nyx-tee/src/keys/ed25519.rs`, boot/main | Derived `nyx/ed25519-signer/v1/{0..K-1}`; only key 0 advertised on HTTP |
| dstack | `dstack-sdk` path dep | Real CVM: Intel-signed quote; simulator: well-formed **stub-signed** quote (DCAP must fail) |
| `dcap-qvl` in Nyx app crates | **Absent** | Exists under vendored `dstack/` (`dcap-qvl = 0.3.10`) for dstack-verifier / RA-TLS — **not used by daemon/SDK** |

### 2.2 Client (only real verifier)

| Surface | Path | Behavior |
|---|---|---|
| Verifier | `packages/daemon/src/attestation.ts` | `verifyAttestation({ gatewayUrl, token, expected?, quoteVerifier?, fetchImpl? })` |
| Start gate | `packages/daemon/src/daemon.ts:215–226` | Runs verifier before WS; failure aborts start |
| Config pins | `packages/daemon/src/config.ts:110–119` | `NYX_DAEMON_EXPECT_{COMPOSE_HASH,MRTD,TEE_PUBKEY}` — **all optional** |
| Skip | `packages/daemon/bin/daemon.ts:133–136` | `NYX_DAEMON_SKIP_ATTEST=1` → `verifyAttestation: false` |
| DCAP wiring | **None** | `quoteVerifier` never constructed in `bin/daemon.ts` |
| SDK | `packages/sdk/src/` | **No** `tee/` module, **no** `verifyTeeAttestation`, **no** `EXPECTED_COMPOSE_HASH` |
| Tests | `packages/daemon/tests/attestation.test.ts` | Unit tests with fake `quote: "deadbeef"`; injected `quoteVerifier` reject path exists |
| Live smoke | `cvm-daemon-smoke.test.ts` | Real `/attestation` without pins or DCAP |

### 2.3 Bugs / mismatches found during deep dive (must fix in this work)

| ID | Issue | Evidence |
|---|---|---|
| **B-1** | Daemon reads **top-level** `mrtd` from `/info`; server returns **`tcb_info.mrtd`** | `attestation.ts:117–125` vs `info.rs:44–60` |
| **B-2** | Daemon **ignores** `event_log` even though server returns it | `fetchAttestation` type omits `event_log`; `AttestationResponse` includes it |
| **B-3** | Without any `NYX_DAEMON_EXPECT_*`, “verified” means only nonce + binding + self-consistency — **no governance pin** | `parseExpected` returns `undefined` if all unset |
| **B-4** | Stock binary never injects DCAP → A-1 stands | `bin/daemon.ts` |
| **B-5** | Docs invent SDK module that does not exist | `docs/tee-attestation-flow.md` §4.3; OpenAPI; site/portal |
| **B-6** | OpenAPI requires `vm_config` on quote response; handler **does not** return it | openapi vs `attestation.rs` |
| **B-7** | `event_log` described as “hex-encoded”; dstack returns **JSON string** | `attestation.rs` comment vs dstack types |
| **B-8** | Doc §2 sometimes describes `report_data` as TLS-cert binding; **as-built** is `SHA-256(tee_pubkey)` | code + OpenAPI + daemon align with tee_pubkey |

### 2.4 What a correct client must verify (target algorithm)

```
1. nonce ← CSPRNG(32)
2. GET /attestation?reportData=hex(nonce)
     → quote, event_log (JSON string), report_data (64B hex), tee_pubkey (b58)
3. R = decode(report_data); len == 64
4. R[0:32] == nonce                                    // freshness
5. R[32:64] == SHA256(bs58decode(tee_pubkey))          // key bind (raw 32B)
6. DCAP_VERIFY(quote) → extract report_data', measurements, TCB status
7. report_data' from quote == R                        // hardware binds same R
8. GET /info → compose_hash, tcb_info.mrtd, tee_pubkey
9. info.tee_pubkey == attestation.tee_pubkey
10. pins (REQUIRED in strict): compose_hash, tee_pubkey; optional mrtd
11. v1.1: replay event_log → RTMR3; compose-hash event == pin
12. optional: on-chain vault_config.tee_pubkeys contains tee_pubkey
13. only then open order streams
```

Today: steps **1–5 + partial 8–10** (with B-1 bug on mrtd); **6–7, 11 missing**.

---

## 3. Goals and non-goals

### Goals (definition of done)

1. **Strict mode default for production daemon:** trading requires successful DCAP + measurement pins.
2. **One reusable verifier** (CLI and/or library) wrapping real Intel quote verification, fixture-tested offline.
3. **Simulator fails strict** (by design); local-dev has explicit skip/simulator modes.
4. **Docs flipped to as-built truth** — no claim of SDK/DCAP that code does not implement.
5. **A-1 closed** in `audits/audit_2/READINESS.md` with PR references (or formal acceptance if product chooses option B — not recommended).

### Non-goals

- On-chain quote verification  
- Browser WASM DCAP in this epic (can be phase-later)  
- Automatically verifying all K shard keys in v1 (document gap; extend `/info` later)  
- Replacing Phala KMS boot attestation (already out-of-band)

---

## 4. Recommended approach (locked recommendations for critique)

### Decision R1 — Where does the verifier live?

**Recommendation: implement DCAP in a small Rust binary/crate `nyx-attestation` (or `crates/nyx-attestation`), called from the daemon via `QuoteVerifier` adapter.**

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| A. Shell out to `dcap-qvl` / new Rust CLI | Mature crypto; reuse dstack ecosystem knowledge; offline fixtures | Process spawn; packaging | **Preferred for v1** |
| B. Pure TS/WASM in Node | Single language | Weak/immature DCAP ecosystem; hard collateral | Later browser path |
| C. Phala HTTP verify API as sole trust | Fast to ship | Trust + availability of third party; not fail-closed offline | **Ops fallback only, never sole prod root** |
| D. Move verifier into `packages/sdk` first | Matches docs | SDK has no need yet; daemon is real consumer | Extract **shared TS glue** after Rust works |

### Decision R2 — Production policy

**Recommendation: three modes**

| Mode | Env | Behavior |
|---|---|---|
| `strict` | default when not skipped | DCAP required + compose_hash + tee_pubkey pins required |
| `skip` | `NYX_DAEMON_SKIP_ATTEST=1` (keep) | No verify; loud warning; **forbidden in “prod profile” docs** |
| `dev-partial` (optional) | explicit | Current behavior: nonce+binding only — **tests only**, or remove after migration |

### Decision R3 — Measurement binding depth

| Phase | Requirement |
|---|---|
| **v1.0 ship** | DCAP + pin `compose_hash` + `tee_pubkey` from `/info` after quote signature OK; fix `tcb_info.mrtd` parse; optional `mrtd` pin from `/info` |
| **v1.1** | Replay `event_log` → bind compose-hash from RTMR3 events (so `/info` cannot lie after a real quote for a different app) |
| **v1.2** | Expose all K `tee_pubkeys` on `/info`; pin set or cross-check on-chain |

### Decision R4 — Do not block on TLS `/evidences/*` for v1

dstack-ingress RA-TLS evidence is valuable but separate (proxy/domain binding). **Quote DCAP + compose pin is the A-1 close.** Document RA-TLS as Phase 2 stretch.

### Decision R5 — SDK vs daemon

**v1: harden daemon (real production path).**  
**v1.x: extract shared module** (`packages/sdk/src/tee/attestation.ts` or `packages/attestation`) so portal docs become true. Do not invent a second divergent verifier.

---

## 5. Implementation plan (phased)

### Phase 0 — Policy freeze (docs only, 0.5 day)

**Deliverable:** short “Attestation policy” subsection (new or in `docs/tee-attestation-flow.md`):

- Adversary: malicious operator / fake gateway  
- Residual after DCAP (compromised TDX / malicious Phala KMS / bad pin governance)  
- Modes: `strict` / `skip`  
- Explicit: Phala verify API not sole root  

**No code.** Enables auditors to know intended posture.

---

### Phase 1 — Spec of verification algorithm (1 day)

**New file:** `docs/attestation-verification-spec.md` (or § in attestation-flow)

Must include:

- Exact byte layouts (`report_data`, pubkey hash = raw 32 bytes not base58)  
- Field paths: `tcb_info.mrtd` not top-level  
- `event_log` is JSON string  
- Error taxonomy mapping to existing `AttestationFailure` + new codes (`tcb_outdated`, `event_log_invalid`, `pin_required`, `mode_forbidden`)  
- Simulator must fail strict  
- Fixture strategy (no secrets; quote hex only)

**Gate:** review by someone other than author before Phase 2.

---

### Phase 2 — DCAP verifier crate + fixtures (3–5 days)

**New crate (suggested):** `crates/nyx-attestation`

| Task | Detail |
|---|---|
| 2.1 | Spike `dcap-qvl` (version aligned with vendored dstack `0.3.10` if possible) against a **real** Phala quote captured to `crates/nyx-attestation/testdata/` |
| 2.2 | CLI: `nyx-attestation verify --quote-hex FILE --expect-report-data-hex HEX [--json]` → exit 0/1 |
| 2.3 | Collateral: document cache path; offline fixture path for CI; prod refresh strategy (fail closed default) |
| 2.4 | Negative tests: truncated quote, wrong report_data, **simulator fixture must fail** |
| 2.5 | README: how to capture fixtures from live CVM without secrets |

**Workspace:** add to `Cargo.toml` members; do **not** force `nyx-tee` to depend on it for server path.

**Acceptance:**

```bash
cargo run -p nyx-attestation -- verify --quote-hex testdata/phala_ok.hex --expect-report-data-hex …  # 0
cargo run -p nyx-attestation -- verify --quote-hex testdata/sim_stub.hex …  # 1
```

---

### Phase 3 — Daemon strict wiring + bugfixes (2–3 days)

#### 3.1 Fix B-1 / B-2 in `packages/daemon/src/attestation.ts`

- Parse `/info` as `{ compose_hash, tcb_info?: { mrtd }, tee_pubkey, … }` and set `mrtd = tcb_info?.mrtd`  
- Accept legacy top-level `mrtd` if present (forward-compat)  
- Parse `event_log` from attestation response; store on result for later  
- Keep existing nonce + binding tests; add mrtd path test

#### 3.2 Enforce policy in `verifyAttestation`

```ts
// conceptual
mode: 'strict' | 'skip'  // skip handled by not calling
// strict:
//  - require expected.composeHash && expected.teePubkey
//  - require quoteVerifier
//  - DCAP must pass
//  - then pins
```

#### 3.3 Config (`config.ts` + `bin/daemon.ts`)

| Env | Purpose |
|---|---|
| `NYX_DAEMON_SKIP_ATTEST=1` | Keep for local sim |
| `NYX_DAEMON_EXPECT_COMPOSE_HASH` | **Required unless skip** |
| `NYX_DAEMON_EXPECT_TEE_PUBKEY` | **Required unless skip** |
| `NYX_DAEMON_EXPECT_MRTD` | Optional pin |
| `NYX_DAEMON_ATTEST_BIN` | Path to `nyx-attestation` (default: on PATH) |
| `NYX_DAEMON_DCAP_COLLATERAL` | Optional collateral dir |

**Construct** `createDcapQuoteVerifier({ bin, collateral })` in `bin/daemon.ts` when not skipping.

#### 3.4 Control API

- Optionally expose `dcap_verified: true` on `GET /attestation` (local control)  
- Do **not** leak full quote to untrusted LAN without auth (already local control API)

#### 3.5 Tests

| Test | Expected |
|---|---|
| Unit: mrtd from `tcb_info` | pin works |
| Unit: strict without pins throws `pin_required` | |
| Unit: strict without quoteVerifier throws | |
| Unit: quoteVerifier false → `quote_invalid` | already exists |
| Unit: Daemon start refuses on fail | already exists |
| Integration: mock CLI exit 1/0 | |
| Live: `RUN_CVM_ATTESTATION=1` with real pins + real DCAP | nightly/manual |

**Blast radius code (Phase 3):**

```
packages/daemon/src/attestation.ts      # core
packages/daemon/src/config.ts
packages/daemon/bin/daemon.ts
packages/daemon/src/daemon.ts           # minor if mode threaded
packages/daemon/src/control-api.ts      # optional field
packages/daemon/tests/attestation.test.ts
packages/daemon/tests/cvm-daemon-smoke.test.ts  # may need pins or SKIP
packages/daemon/tests/cvm-daemon-lifecycle.test.ts
packages/daemon/tests/daemon.test.ts    # already skips
```

**Does not require** vault, circuits, matcher, or SDK crypto changes.

---

### Phase 4 — Event-log / compose binding (v1.1, 2–4 days)

| Task | Detail |
|---|---|
| 4.1 | Parse dstack `event_log` JSON schema used on Phala |
| 4.2 | Replay RTMR3; match quote field |
| 4.3 | Extract compose-hash event; require == pin |
| 4.4 | Tests with real event_log fixture |

Closes “valid TDX quote for wrong app + forged `/info.compose_hash`.”

May live in `nyx-attestation` (preferred) with daemon only checking CLI JSON output.

---

### Phase 5 — K-shard pubkey surface (v1.2, 1–2 days)

| Task | Detail |
|---|---|
| 5.1 | Extend `/info` (and optionally `/attestation`) with `tee_pubkeys: string[]` in shard order |
| 5.2 | OpenAPI + tests in `http_surface.rs` |
| 5.3 | Client: pin primary or full set; optional RPC check vs `vault_config` |

**Blast:** `info.rs`, `ApiState`, boot wiring, OpenAPI, daemon pins, rotate runbook.

---

### Phase 6 — Shared SDK module + portal truth (1–2 days)

| Task | Detail |
|---|---|
| 6.1 | Move/re-export `verifyAttestation` types to `packages/sdk/src/tee/attestation.ts` **or** `@nyx/attestation` package |
| 6.2 | Daemon imports shared module |
| 6.3 | SDK error stage `"attestation-verify"` actually used |
| 6.4 | Update portal SDK docs to real import path |

---

### Phase 7 — Ops ceremony (1–2 days)

| Task | Detail |
|---|---|
| 7.1 | `scripts/verify-cvm-attestation.mjs` wrapping same CLI as daemon |
| 7.2 | Update `docs/cvm-run-runbook.md`: **devnet shortcut** vs **prod ceremony** with DCAP before `rotate-tee-pubkey.mjs` |
| 7.3 | Align `docs/governance.md` §5 with script |

---

### Phase 8 — Documentation blast radius (required with Phase 3 ship)

See §7 inventory. Rule: **same PR series that enables strict DCAP must flip overclaims** or site continues to lie.

---

## 6. Suggested PR stack

| PR | Contents | Risk |
|---|---|---|
| **PR0** | Attestation policy + verification spec (docs) | None |
| **PR1** | `nyx-attestation` crate + fixtures + CLI | Low |
| **PR2** | Daemon: fix mrtd path, event_log parse, strict pins, wire QuoteVerifier | Medium — breaks unpinned smoke until env set |
| **PR3** | Event-log compose binding | Medium |
| **PR4** | `/info` multi-key + client pin optional | Low–medium |
| **PR5** | SDK extract + portal/site doc truth-up + close A-1 | Low |

---

## 7. Documentation blast radius (for other models to audit)

### Must rewrite when client DCAP becomes mandatory

| Path | Why |
|---|---|
| `docs/tee-attestation-flow.md` | Canonical design; §4.3 invents missing SDK; §2 report_data drift; mark as-built |
| `docs/tee-api-openapi.yaml` | Client steps claim DCAP; schema requires `vm_config` not returned; event_log encoding |
| `docs/portal/api/03-transport-and-attestation.md` | Primary portal claim of DCAP |
| `docs/portal/how-it-works/03-privacy-and-attestation.md` | Same |
| `docs/portal/sdk/01-typescript-client.md` | “SDK ships helper” is false |
| `docs/site/06-trust-model.md` | States Intel TCB verify as fact |
| `docs/site/08-integration.md` | “not optional theater” overclaim |
| `docs/site/01-introduction.md`, `02-architecture-overview.md`, `09-api-reference.md` | Trust path claims |
| `docs/ARCHITECTURE.md` | `verifyTeeAttestation()` claim |
| `audits/audit_2/READINESS.md` | Close A-1 |
| `CLAUDE.md` / `AGENTS.md` | Ceremony language |
| `docs/tee-architecture.md` | Planned test + ceremony rows |
| `CRYPTOGRAPHY.md` | F-11 compensating control “enforced” vs aspirational |

### Process alignment

| Path | Why |
|---|---|
| `docs/governance.md` | Multisig DCAP vs client DCAP duties |
| `docs/cvm-run-runbook.md` | Today has no DCAP step; label as devnet |
| `deploy/README.md` | compose_hash allowlist + client pin note |

### Explicitly separate from this epic

| Path | Topic |
|---|---|
| `docs/tee-attestation-flow.md` §11 | On-chain DCAP |
| `docs/site/11-roadmap.md` | On-chain port triggers |

### Stale code comments to fix

| Path | Claim |
|---|---|
| `crates/nyx-tee/src/api/info.rs:4–11` | References SDK `verifyTeeAttestation` |
| `crates/nyx-tee/src/keys/ed25519.rs:25–26` | Claims mirror in missing SDK file |
| `crates/nyx-tee/src/api/attestation.rs` | “hex-encoded” event_log |

---

## 8. Blast radius summary (code)

```
IN SCOPE (client DCAP epic)
├── crates/nyx-attestation/          NEW
├── Cargo.toml (workspace members)
├── packages/daemon/src/attestation.ts
├── packages/daemon/src/config.ts
├── packages/daemon/bin/daemon.ts
├── packages/daemon/src/daemon.ts    (minor)
├── packages/daemon/src/control-api.ts (optional)
├── packages/daemon/tests/*
├── packages/sdk/src/tee/*           (Phase 6)
├── crates/nyx-tee/src/api/info.rs   (Phase 5 multi-key only)
├── docs/*                           (truth-up)
└── scripts/verify-cvm-attestation.* (Phase 7)

OUT OF SCOPE (do not touch in this epic)
├── programs/vault/**
├── circuits/**
├── crates/darkpool-matcher/**
├── crates/nyx-tee settle/matcher/prover (except info multi-key)
└── packages/indexer/**
```

**Runtime blast:** existing daemon users without `EXPECT_*` pins will **fail to start** once strict is default — intentional. Migration: set pins from `/info` after operator-vetted deploy, or temporary `SKIP_ATTEST` for local sim only.

**CI blast:** unit tests that assume unpinned happy path need pin fixtures; CVM smoke needs either pins from env or documented skip for non-attestation goals.

---

## 9. Verification plan

### Local / CI

```bash
# Unit (daemon)
( cd packages/daemon && ../../node_modules/.bin/vitest run tests/attestation.test.ts )

# Attestation crate
cargo test -p nyx-attestation
cargo run -p nyx-attestation -- verify --quote-hex … # fixture

# Workspace gate (if crate added)
cargo clippy -p nyx-attestation --all-targets -- -D warnings
cargo fmt --all -- --check
```

### Negative product test (required)

1. Run a **fake gateway** that echoes nonce + binds attacker key + returns expected compose_hash in `/info` with garbage `quote`.  
2. **Without DCAP (old):** would pass.  
3. **With strict DCAP:** must fail `quote_invalid`.  

Automate as daemon integration test with mock CLI returning exit 1 / or mock quoteVerifier.

### Live CVM (manual / nightly)

```bash
# Capture pins from live CVM
curl -s "$GW/info" | jq '{compose_hash, tee_pubkey, mrtd: .tcb_info.mrtd}'

# Set EXPECT_* + run daemon WITHOUT SKIP_ATTEST
# Assert start succeeds only when DCAP CLI green
```

### Ceremony dry-run

Run `scripts/verify-cvm-attestation` before a dummy rotate; ensure red path blocks checklist.

---

## 10. Risks and mitigations

| Risk | Mitigation |
|---|---|
| Collateral fetch breaks prod daemons | Offline cache; fail closed; ops override only via explicit skip |
| Phala quote format / TDX version drift | Pin dcap-qvl version; capture new fixtures on platform upgrade |
| Strict breaks all local sim workflows | Keep `SKIP_ATTEST`; document; never default in prod compose |
| Only shard-0 attested; other keys malicious | Phase 5 multi-key; interim: ops register keys from boot log only after same CVM DCAP |
| Docs continue to overclaim | Phase 8 same release train as PR2 |
| Other models re-propose on-chain DCAP as “the fix” | On-chain is complementary; does not replace client connect-time verify |

---

## 11. Effort estimate

| Phase | Effort |
|---|---|
| 0–1 Policy + spec | 1–1.5 d |
| 2 DCAP CLI + fixtures | 3–5 d |
| 3 Daemon strict + B-1/B-2 | 2–3 d |
| 4 Event-log bind | 2–4 d |
| 5 Multi-key /info | 1–2 d |
| 6 SDK extract | 1–2 d |
| 7 Ceremony script | 1 d |
| 8 Docs blast | 1–2 d |
| **Core A-1 close (0–3 + 8)** | **~1.5–2.5 weeks** |
| **Full plan through 7** | **~3–4 weeks** |

---

## 12. Acceptance checklist (ship gate for “A-1 closed”)

- [ ] Stock daemon without `SKIP_ATTEST` **cannot** start without successful DCAP  
- [ ] `EXPECT_COMPOSE_HASH` + `EXPECT_TEE_PUBKEY` required in that path  
- [ ] Fake gateway with valid nonce/binding/pins and invalid quote **fails**  
- [ ] Simulator quote **fails** strict  
- [ ] Real Phala fixture **passes** offline  
- [ ] `/info` `tcb_info.mrtd` correctly parsed (B-1 fixed)  
- [ ] Unit tests cover inject quoteVerifier true/false + pin failures  
- [ ] Docs no longer claim non-existent SDK helper as shipped  
- [ ] `audits/audit_2/READINESS.md` A-1 marked remediated with links  
- [ ] OpenAPI corrected for response fields (`event_log` type; drop or optional `vm_config`)  

---

## 13. Critique guide for other models

When reviewing this plan, please specifically challenge:

1. **Is Rust CLI the right v1 vs pure WASM?** Trade packaging vs crypto maturity.  
2. **Is pinning `/info.compose_hash` after DCAP enough for v1.0**, or is event_log replay (Phase 4) required for A-1 close? (Author view: v1.0 DCAP+pins closes *fake non-TDX gateway*; Phase 4 closes *forged /info after real TDX*.)  
3. **Should strict be default immediately** or feature-flagged one release?  
4. **Multi-key gap:** is advertising only shard-0 an acceptable residual until Phase 5?  
5. **Should `SKIP_ATTEST` be compile-time gated** out of production builds?  
6. **Did we miss any consumer** of attestation beyond daemon (demo app, portal, indexer)? Deep dive found only daemon + docs.  
7. **Is B-1 (mrtd path) correctly characterized?** Confirm against live `/info` JSON from a real CVM if available.  
8. **Collateral operational model** — fail closed vs stale-allow window under Intel CDN outage.  
9. **Any Solana/tx-budget impact?** (Author: none for client-only DCAP.)  
10. **Conflict with simulator-first TEE dev loop** in CLAUDE.md §4 — plan must preserve iterate-on-simulator without breaking prod strict.

---

## 14. One-line summary

**Ship a real DCAP verifier, make the stock daemon fail-closed without it, fix the `/info` mrtd parse bug, require measurement pins, and rewrite docs that currently claim a full attestation path the code does not implement — without touching the vault/circuits.**
