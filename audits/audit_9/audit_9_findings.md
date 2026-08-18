<!-- audit-record -->
> **Audit:** Post-audit_8 surface review — the RA-TLS transport stack (T-03P, PRs #143–#152, #157–#159) plus the audit_7 carry-forward settle/crypto files
> **Date:** 2026-08-17
> **Engagement:** `audits/audit_9/`
> **ID prefix:** `TR-` (round 9). Performance continues the shared `PF-` series at `PF-31`.
> **Cross-audit status:** see [`../residual-backlog.md`](../residual-backlog.md) — the canonical index of what is still open.
> **Baseline:** `main` @ `d5e4656` (PR #159 merged). Prior engagement baseline was `fc88040` (audit_8).

---

# Darknyx audit 9 — 2026-08-17

> **Scope.** First-party defensive audit of the surfaces that landed after
> `audit_8`, read as one boundary-crossing batch per the onboarding method:
> *does what the client verifies match what the enclave serves, and where does
> the verification gate stop?* That covers the whole RA-TLS transport stack —
> the TEE side (`transport/{manifest,identity,server}.rs`,
> `api/transport_attestation.rs`, `config.rs`, `main.rs` wiring), the SDK side
> (`tee/{verify-transport,transport-manifest,transport-agent.node,transport-ws.node,transport.node}.ts`),
> the daemon and trader-host adoption, the nightly CI and the two new gate
> scripts — plus the `audit_7` §12 carry-forward files
> (`settle/{lock_note,alt,marker_sweep}.rs`, the remaining `darkpool-crypto`
> modules) and the `valid-input-prover.ts` root-ring change.
>
> **ID prefix:** `TR-01…`. Distinct from `R-` / `SW-` / `CA-` / `T-` / `S-` /
> `D-` / `PF-01…PF-30`. Performance items continue `PF-31…`.
>
> **Severity:** Critical / High / Medium / Low / Perf-Nit / Info

---

## 1. Executive summary

**No new Critical. The RA-TLS core is clean.** The manifest contract, the
boot-scoped identity, the verification core, the WebSocket gate, and the
Rust↔TypeScript lockstep are all correctly built and correctly pinned — the
detailed negative results in §3 are the strongest evidence in this engagement.
The T-03P closure's own live evidence is corroborated by source: nothing in
the manifest path takes caller-influenced input beyond the nonce, and the
attested SPKI is provably the SPKI inside the served certificate.

**The findings are where the gate stops, not where it is wrong.** One High:
trader-host relays the browser's `/v1/stream` upstream over a plain, ungated
`ws` client (`TR-01`) — a leg the Phase 2 adoption (#152) covered for HTTP and
missed for WS, in exactly the shape `check-cvm-suites-use-transport.sh` was
written to catch in test code. One Medium: a check-then-dispatch race in the
verified fetch (`TR-02`) that an on-path actor (the untrusted gateway
qualifies by design) can theoretically exploit to capture one authenticated
request per won race. The rest are Low/Info: a `/info` field the config doc
promises and the API never shipped (`TR-03`), the boot-session pin and
staleness signal missing on the trader-host path (`TR-04`, `TR-05`), a
destroy-on-failure contract the adapter doesn't implement on three early
paths (`TR-06`), and public docs still describing the pre-cutover transport
(`TR-07`).

| ID | Severity | One line |
|---|---|---|
| **TR-01** | **High** | Browser `/v1/stream` relays over an ungated plain `ws` upstream that cannot even handshake with the RA-TLS enclave cert |
| **TR-02** | Medium | Verified fetch has a check-then-dispatch socket race; a forced reconnect can carry one request unverified |
| TR-03 | Low | `transport_mode` promised on `/info` in `config.rs`, absent from every API surface |
| TR-04 | Low | trader-host's verified fetch omits the boot-session pin and `isStale()` the daemon path has |
| TR-05 | Low | `VerifiedTransport.isStale()` has no consumer; a CVM restart degrades every request instead of tripping a lifecycle path |
| TR-06 | Info | `verifyTransportOnSocket` doesn't destroy the socket on three early failure paths its own contract covers |
| TR-07 | Low | Public GitBook transport page still describes gateway-terminated TLS as current for programmatic clients |
| TR-08 | Low | Marker-sweep ingress is an unbounded channel into an unbounded set (C3 class, bounded only by close-path health) |
| TR-09 | Info | Three comment-vs-code drifts on the carry-forward settle files (account counts, ALT size, stale proof narrative) |
| PF-31 | Perf-Nit | Marker sweep does one `get_account_info` per pending root per tick; `get_multiple_accounts` exists (C4 class) |

**Part B supplement (same engagement, added after the owner asked for the
funds/privacy/intent-leak lenses on the Solana program and the TEE trust
surfaces — see §6):**

| ID | Severity | One line |
|---|---|---|
| **TR-10** | **High** | GPU compose never got the RA-TLS cutover — the whole API rides plaintext `:8080` through the gateway, and the cutover guard only checks the CPU compose |
| TR-11 | Medium | The icicle prover bypasses the SW-14 witness fix: full private witness to a 0755 `/tmp` dir, ignoring `DARKNYX_TEE_WITNESS_DIR` |
| TR-12 | Medium | Fee/owner rotation has no timelock and a 100% ceiling — a captured ops admin taxes all subsequent trading to 100% in one tx |
| TR-13 | Medium | TEE-key rotation is admin-instantaneous and gates every settle — a captured ops admin halts settlement venue-wide in one tx |
| TR-14 | Low | `create_wallet` is front-runnable (one public input); no authority impact today since nothing reads `WalletEntry.owner` |
| TR-15 | Low | Settlement-failure diagnostics (`{e:?}`) reach the client orders channel, contradicting `worker.rs`'s "never served to a client" |
| TR-16 | Info | Privacy-lens emission notes: `NoteLocked` discloses the mint, `Withdrawn` publishes an unconsumed nullifier, settle txs pair order_ids |
| TR-17 | Low | `CRYPTOGRAPHY.md`'s threat table still says the TEE "terminates no TLS" and defers all of T-03 — stale since the cutover, in the canonical threat-model doc |

`audit_8`'s `R-01…R-04` remain the open High queue for the browser product;
`TR-01` joins them and should land in the same browser/host slice.

A clean generalist read of the circuits is **not** a substitute for `F-04`.
Findings are not fixes.

---

## 2. Findings

### TR-01 — The browser stream relay's upstream WebSocket is outside the verified transport, and cannot handshake with the enclave's certificate

**Severity:** High
**Category:** Security / transport integrity (T-03P Phase 2 gap)
**Lockstep:** no

**Anchors:**
`packages/trader-host/src/live-proxy.ts:382-388` (the relay's upstream
`new WebSocket(websocketUrl(target), { headers, perMessageDeflate, maxPayload,
handshakeTimeout })` — no TLS options, no agent, no gate),
`packages/trader-host/src/live-proxy.ts:289-293` (`websocketUrl` rewrites
https→wss only),
`packages/trader-host/src/live-proxy.ts:583-586` (the `/api/darknyx/venue/v1/stream`
route feeding it),
`packages/trader-host/src/live-proxy.ts:528-531` (the HTTP leg *is* verified —
`isRpc ? fetch : cvmFetch`),
`scripts/check-cvm-suites-use-transport.sh:9-12` (the repo's own record that a
bare client "cannot complete a TLS handshake against the enclave's
self-signed certificate").

**Problem.** Phase 2 of the RA-TLS adoption threaded `cvmFetch` through the
trader-host's HTTP paths — the proxy, the token issuer, and account
provisioning. The WebSocket relay was not converted. Its upstream connection
is a stock `ws` client:

1. **It is ungated.** Nothing checks the upgrade socket's SPKI against an
   attested value, so the stream leg — the bearer-token login frame, order
   updates, and the fill memos that carry change-note openings — crosses
   whatever peer answers. The cuckoo-proxy/relay hole T-03P closes on the
   HTTP leg stays open on the stream leg. This is precisely the
   "half-protected reads as protected" failure the daemon's own transport
   module refuses to run as (`packages/daemon/src/transport.ts:10-16`), and
   the daemon *does* refuse — `buildDaemonTransport` throws rather than
   verify HTTP while streaming unverified. trader-host has no such pairing.

2. **It is also broken, not merely unverified.** The enclave's RA-TLS
   certificate is self-signed by design, and Node's default TLS validation
   rejects it — verified mechanically on this box: a default `ws` client
   against a self-signed server fails with `self-signed certificate`. So
   against a cutover CVM (`8443s` passthrough, `:8080` unpublished) the
   relay's upstream handshake fails and the browser trader has **no working
   stream at all** while its HTTP path reports verified. The repo already
   hit and documented this exact failure mode in test code —
   `check-cvm-suites-use-transport.sh` exists because `cvm-attestation-e2e`
   "used global `fetch`, which cannot complete a TLS handshake against the
   enclave's self-signed certificate" — but the guard covers only
   `packages/**/cvm-*.test.ts`, and the production relay has the same shape.

**Failure scenario.** (a) Today, functional: browser connects
`wss://<origin>/api/darknyx/venue/v1/stream`, trader-host accepts the
downgrade, dials `wss://<cvm>-8443s.…/v1/stream`, the TLS handshake fails,
and the stream is permanently down. (b) The operator "fixes" it the way this
failure invites — `NODE_TLS_REJECT_UNAUTHORIZED=0` or a
`rejectUnauthorized:false` agent — and now the relay accepts *any*
certificate while the logs still say `trader-host transport: ra-tls`. That is
the exact anti-pattern CLAUDE.md §3.4b names ("it accepts any certificate
from anyone while still reporting as RA-TLS"). (c) Even a correctly-built
plain `wss` relay (e.g. against a gateway-terminated route, if one were
republished) remains an unverified leg for the most sensitive channel the
host carries.

A regression test writes itself from the repo's own suite: point the relay's
upstream at a TLS server with a genuinely distinct certificate and assert the
relay refuses (the SDK's `transport-relay-attack.test.ts` already builds this
shape); then, against the RA-TLS CVM, assert the stream comes up with **no**
global TLS bypass set anywhere in the process.

**Fix options.**

| Option | Trade-off |
|---|---|
| **A (recommended).** Route the relay's upstream through the SDK gate: `verifyTransportOnSocket` once at startup for the pins, then wrap the upstream `new WebSocket(...)` in `createVerifiedWebSocketFactory` (it takes a `createSocket` injector, so the relay's existing `ws` client drops straight in; `ws` v8 emits the `upgrade` event the gate keys on). | ~0.5–1 day. The neighbour is in-repo and live-tested (the T-03P closure proved WS-over-passthrough with this gate). Failure of the check must close the downstream socket — the relay already has `closeBoth`. |
| B. Verify the upgrade SPKI inline in the relay (read `res.socket` on `upgrade`, compare against the startup-verified SPKI) without adopting the SDK factory. | Less code moved, but re-implements the gate — including its terminal-state and queued-send subtleties the SDK module already encoded after live failures. Copy the neighbour instead. |
| C. Land A together with the trader-host half of R-01's release pinning and R-18, as one browser/host slice. | Sequencing choice; TR-01 should not wait on R-01, but they touch the same files. |

---

### TR-02 — Check-then-dispatch socket race in the verified fetch

**Severity:** Medium
**Category:** Security / TOCTOU on the transport gate
**Lockstep:** no

**Anchors:**
`packages/sdk/src/tee/transport-agent.node.ts:405-413` (`ensureVerified`
checks `agent.isVerified(agent.currentSocket())`),
`:440-447` (the dispatch that follows, on the same agent),
`:118-148` (the connector: `rejectUnauthorized: false`, SPKI recorded at
connect, `current` cleared on `close`),
`packages/sdk/src/tee/transport-agent.node.ts:339-341` (the code's own honest
note that the single-connection pin — not per-response attribution — is the
mechanism).

**Problem.** Verification is keyed to the *most recently connected* socket,
checked **before** the request is dispatched. If the pooled socket dies
between the check and undici's dispatch, undici transparently dials a
replacement through the custom connector — which accepts any certificate
(`rejectUnauthorized: false`, correct for the SPKI model but fatal here
because no SPKI comparison runs for this request) — and the request rides the
new socket unverified. `current` is only cleared by the socket's `close`
event; the race is exactly the gap where the socket is dead, the close has
not been processed, and the dispatch needs a connection.

The attacker this matters for is on-path, and the threat model names one by
design: the dstack gateway, which T-03P exists to defend against. It can
terminate the client's TCP connection at an instant of its choosing and then
answer the replacement itself with its own certificate. It cannot pass the
full re-verification (its SPKI is not the manifest's), so the *next* request
fails loudly with `spki_mismatch` — but the request that triggered the
replacement has already crossed, leaking its `Authorization` bearer token and
body (order intent). One request per won race; the race is narrow but
repeatable, since the attacker controls when every connection dies and the
client re-verifies after each kill.

Mitigating factors, stated honestly: the single-socket pin means there is no
pool-wide confusion; benign reconnects land on the genuine enclave; and the
subsequent request's loud failure makes a sustained campaign visible. I could
not measure the practical window without an on-path lab; see §5.

**Failure scenario / regression test.** Stub the agent's connector so the
pooled socket dies after `ensureVerified` resolves but before dispatch, with
the replacement presenting a distinct SPKI; assert the wrapper notices and
refuses (or destroys) rather than returning the impostor's response. Today it
returns it.

**Fix options.**

| Option | Trade-off |
|---|---|
| **A (strongest).** Gate at socket-adoption: inside the custom `connect`, hold the new socket back from undici until the attestation exchange has been completed *on that socket* and its SPKI matched. No request can then be dispatched on an unverified socket by construction. | Hardest version: the attestation exchange must ride the raw socket before undici owns it (hand-rolled HTTP/1.1 request bytes, or a two-phase connector). ~2–3 days. |
| B. Post-response assertion: pin the expected socket (identity, not just liveness) before dispatch and, after the response resolves, assert the current socket is still that verified one; treat a swap as a compromised exchange — destroy, rotate the session credential, surface loudly. | ~0.5 day. Detects and contains rather than prevents: the one raced request's bytes still cross, so it needs a credential-rotation story to be worth anything. |
| C. Both: B now (cheap tripwire), A as the structural close. | The pattern this repo's trackers already use — mitigation ahead of the real fix (cf. SW-11). |

---

### TR-03 — `transport_mode` is promised on `/info` and shipped nowhere

**Severity:** Low
**Category:** Comment-vs-code drift (C6) + missing client pinning surface
**Lockstep:** no

**Anchors:**
`crates/darknyx-tee/src/config.rs:66-70` ("explicitly reported on `/info` so
a client can tell which one it is talking to rather than inferring it from
absence"),
`crates/darknyx-tee/src/api/info.rs:33-57` (`InfoResponse` — no
transport field),
`crates/darknyx-tee/src/api/system.rs:28,46` (`/system/status` reports
`oracle_mode`, the exact shape this would mirror, but not the transport).

**Problem.** The config type's doc states the mode is reported on `/info`; it
is not, on `/info`, `/system/status`, or the OpenAPI's `/info` schema. The
only place a client learns the mode is `/transport-attestation`'s manifest —
which 503s on a legacy boot, so a legacy-path client cannot distinguish
"gateway-terminated by choice" from "RA-TLS instance whose dstack socket is
degraded". This also removes the out-of-band pin the daemon-style hardening
(R-06 pins `oracle_mode` the same way) would key on: a client cannot refuse
to start unless the venue reports the transport it expects.

**Fix.** Add `transport_mode` to `InfoResponse` (+ OpenAPI), correct or
fulfil the `config.rs` comment, and have the daemon's startup pin mirror
R-06's `oracle_mode` check. ~2 hours. Not lockstep — additive wire field.

---

### TR-04 — trader-host's verified fetch omits the boot-session pin and the staleness signal

**Severity:** Low
**Category:** Security / inconsistent adoption
**Lockstep:** no

**Anchors:**
`packages/trader-host/src/cvm-transport.ts:73-90` (builds
`createVerifiedFetch` directly, no `expectedBootSessionId`, no
`isStale`),
`packages/sdk/src/tee/transport.node.ts:117-130` (the daemon path's pin,
with its own rationale: without it "a RESTARTED enclave would pass and start
receiving this session's private request bytes"),
`packages/sdk/src/tee/transport.node.ts:157-167` (`isStale`, unused here).

**Problem.** The daemon's transport binds one boot: after the first
verification, reconnect re-verification carries `expectedBootSessionId`, so a
restarted enclave fails `boot_session_mismatch`. The trader-host path
re-verifies with compose hash + signer set only — both survive a restart — so
after a CVM restart it silently re-verifies and keeps proxying browser
traffic to a different boot, with no `isStale()` consumer to notice. Impact is
bounded (the new boot is still a governed enclave with the same signer set,
and browser clients sign fresh sessions per `/info`), but it contradicts the
SDK's own stated binding rationale and removes the only restart signal the
host has.

**Fix.** Use `createVerifiedTransport` in `buildCvmFetch` (it returns the
gated fetch plus `isStale`), or pass `expectedBootSessionId` on the reconnect
options and surface staleness in `bin.ts`. ~2 hours. Pairs with TR-05.

---

### TR-05 — `VerifiedTransport.isStale()` has no consumer

**Severity:** Low
**Category:** Liveness / operability
**Lockstep:** no

**Anchors:**
`packages/sdk/src/tee/transport.node.ts:157-167` (definition),
`packages/daemon/src/transport.ts:20-21,38,149` (exposed through
`DaemonTransport`, with the module doc deferring reaction to "the daemon's
lifecycle concern"),
`packages/daemon/bin/daemon.ts` (grep: no `isStale` call).

**Problem.** Nothing reads it. After a CVM restart under `ra-tls`, every
request throws `boot_session_mismatch` and every WS gate rejects; the daemon
has no path that maps a transport staleness/violation to *pause placement,
rebuild transport, re-attest, resume* — the reaction the module doc assumes
exists. Fail-closed, so funds are safe; the cost is an opaque degradation
(the T-03P closure row itself carries a carry-forward note that the daemon's
live business-flow run was deferred).

**Fix.** Poll `isStale()` on the existing attestation refresh cadence (the
daemon already refreshes TEE keys every minute and pauses on mismatch);
on stale: pause placement, tear down and rebuild the transport, re-run
attestation. Regression: restart the CVM under a live daemon; assert
placement pauses and resumes instead of erroring per request. ~0.5 day.

---

### TR-06 — `verifyTransportOnSocket` does not destroy the socket on three early failure paths its contract claims to cover

**Severity:** Info
**Category:** Hygiene / doc-contract drift
**Lockstep:** no

**Anchors:**
`packages/sdk/src/tee/transport-agent.node.ts:287-289` ("Throws … and
destroys the connection **on any failure**"),
`:318-344` (non-OK status, oversize body, JSON parse failure — the `catch`
rethrows via `fail` without `destroySocket`),
`:365` (`parseObservedManifest` outside any destroy path — malformed hex or
unknown `transport_mode` throws with the socket still pooled).

**Problem.** Stated contract says any failure destroys the connection; three
early paths don't. No credential crosses on those paths and the socket can
never be marked verified, so the impact is a lingering pooled socket to a
hostile peer — hygiene, not exposure. Worth closing only so the contract
stays true where the next reader trusts it.

**Fix.** Wrap the body of the fetch/parse phase so every `fail(...)` after a
socket exists passes through `destroySocket`, or move the `parseObservedManifest`
call inside the guarded section. ~1 hour including the malformed-manifest test.

---

### TR-07 — Public GitBook transport page describes the pre-cutover programmatic transport as current

**Severity:** Low
**Category:** Public docs drift (R-12 class, new half)
**Lockstep:** no

**Anchors:**
`docs/gitbook/api/transport-and-attestation.md:10-19` (TL;DR: "TLS terminates
at the **dstack gateway** … your client verifies the measurement of only one
of them"),
`:22-46` (the trust-boundary section and diagram, same claim),
grep: zero occurrences of `ra-tls` / `8443s` / `transport-attestation` /
`passthrough` in the file.

**Problem.** The page was edited during this window (the browser-trader
section it gained is accurate and appropriately blunt), but its programmatic
half still describes gateway-terminated TLS — the architecture the 2026-08-16
cutover replaced. A reader gets a weaker *and* outdated model, and the page
makes security claims ("plaintext order intent therefore exists only inside
hardware-protected memory, on both hops") whose justification has changed
shape: for programmatic clients the answer is now *better* (the enclave
terminates TLS with a quote-bound key) and should be said. Same class as
R-12; CLAUDE.md §0 requires GitBook to be edited directly and `SUMMARY.md`
kept in step (no nav change needed here).

**Fix.** Rewrite the programmatic half around the RA-TLS route (`8443s`,
`/transport-attestation`, boot-scoped certificate, the SPKI check), keep the
two-enclave discussion as the legacy/regime note. ~2 hours.

---

### TR-08 — Marker-sweep ingress is an unbounded channel into an unbounded set

**Severity:** Low
**Category:** Resource bounds (C3 class)
**Lockstep:** no

**Anchors:**
`crates/darknyx-tee/src/settle/marker_sweep.rs:88`
(`mpsc::UnboundedReceiver<[u8; 32]>`),
`crates/darknyx-tee/src/persistence/markers.rs:53-57` (unbounded `HashSet`
of pending roots).

**Problem.** One root is enqueued per settled batch and entries drain via
successful closes, so steady-state growth is proportional to throughput, not
to an attacker. But a persistently failing close path (unfunded fee key, RPC
outage) accumulates roots without bound for the process lifetime while
simultaneously paying PF-31's per-root RPC on every 5 s tick. The C3
question — *what removes an entry?* — has an answer only on the success path.

**Fix.** Bound the set (insertion-ordered eviction past a cap that exceeds
the realistic in-flight marker count, dropping the oldest *expired* root and
logging its marker PDA for manual reclaim), or bound the channel and make the
producer (settle completion) retry on full. Do not evict unexpired roots —
they hold rent. ~0.5 day.

---

### TR-09 — Comment-vs-code drift on the carry-forward settle files

**Severity:** Info
**Category:** C6 class, three new instances
**Lockstep:** no

**Anchors and claims:**
`crates/darknyx-tee/src/settle/lock_note.rs:7` — module doc says "5
accounts"; the builder emits 6 (the `consumed_note` U-02 guard at index [4],
`lock_note.rs:135-142`), the fn-level doc at `:115-127` correctly says 6, and
the test asserts 6.
`crates/darknyx-tee/src/settle/lock_note.rs:24-28` and
`settle/submit_lock.rs:44-45` — describe a "missing valid_input_proof"
failure mode that no code implements (grep: the string exists only in the
comments; `valid_input_proof` is a non-Option field and intake verifies the
relayed proof on every settle-enabled boot).
`crates/darknyx-tee/src/settle/alt.rs:3-5` and `settle/settle_batched.rs:171`
— say the per-batch ALT holds "the five derivable PDAs"; it holds seven
(`settle_batched.rs:152-160`: 4 locks + 2 consumed + 1 marker, matching
CLAUDE.md §6).

**Fix.** One doc-accuracy pass over these headers — fold into the C6 pass
that R-11 already schedules, *after* any code fixes touching the same files.

---

## 2b. Performance findings

### PF-31 — Marker sweep pays one `get_account_info` per pending root per tick

**Severity:** Perf-Nit (Low)
**Category:** C4 — sequential per-item RPC, new site
**Anchors:** `crates/darknyx-tee/src/settle/marker_sweep.rs:156-175`;
`crates/darknyx-tee/src/solana_rpc/client.rs:544` (`get_multiple_accounts`,
100/call, already exists).

Every 5 s tick, the sweep checks each pending root's marker account with an
individual RPC round trip — including every pre-expiry root it polls for the
marker's whole TTL (300 slots ≈ 2 min, so each root costs ~24 reads before it
is even closeable). `get_multiple_accounts` collapses N round trips to one;
`lock_sweep.rs`/`recover.rs` were converted under PF-27 and the same
positional-zip-vs-index reasoning applies (the sweep's use is a membership
check per root — a short response must fail closed, as PF-27's client
already does). Attribute to path: this is background, not boot-critical, so
it sits below PF-27 in priority; it compounds with TR-08 under a failing
close path. ~0.5 day.

No other new performance findings: the transport stack's hot paths are
bounded by design (single-socket agent; 512 KiB body cap; 15 s budget;
512-entry event-log cap; the endpoint's own 20/s limiter on top of the
venue-wide 10.0-weight bucket). The `hexToBytes`/`match(/../g)` decoders in
`cvm-transport.ts` run once at startup.

---

## 3. Verified clean — with reasoning

**The manifest contract (`transport/manifest.rs`, `tee/transport-manifest.ts`).**
Every field is independently bound — the Rust test perturbs each field and
asserts the digest moves, including `protocol_version` and `transport_mode`;
the encoding is fixed-width (164 B) with a reserved byte pinned to zero; the
domain tag is versioned and the test proves a v2 domain cannot replay a v1
digest. The cross-language pin is real: Rust's `FIXED_VECTOR_DIGEST`
`d04907e5…27c1` equals the TS parity test's constant, so both suites fail on
a drift. The TS mirror routes both its server-side and verifier-side encoders
through one `canonicalBytesFromHashed` and range-checks the two fields whose
bit-packing would otherwise truncate (`protocolVersion: 65536` and
`transportMode: 257` would both collide) — the collision class this repo
keeps rediscovering is closed here by construction. The nonce is exactly
32 bytes on both sides, and `report_data` is nonce-left / digest-right as
documented.

**The boot-scoped identity (`transport/identity.rs`).** The key is generated
from the OS CSPRNG per boot, never persisted, never derived from a stable
KDF — the module documents *why* with the dstack gateway's persisted-key
defect as the counter-example, and the distinctness tests (10 identities, 10
SPKIs) would catch a deterministic regression. The SPKI-containment check is
real, not vacuous: a DER SPKI is a contiguous substring of the TBSCertificate
and the helper's degenerate cases are tested. `Debug` cannot render key
material; the `Zeroizing` wrap happens before any early return could skip
scrubbing. The 397-day `notAfter` is correctly framed as non-security
(the boot session is the lifetime).

**The endpoint (`api/transport_attestation.rs`).** The manifest is built
from server state only (`app_info`, `boot_session_id`, the shared identity's
SPKI, `signer_set_hash`); the caller's nonce is the sole input and only ever
lands in the left half. Nonce shape is validated **before** the limiter is
charged (a flood of malformed nonces costs nothing), the limiter fails closed
on a poisoned lock, `get_quote` is timeout-bounded (15 s) so a hung dstack
socket cannot pin admitted handler tasks, and error strings never echo caller
input. Layering with SW-02's venue-wide bucket is correct: the route costs
10.0 there (same as `/attestation`, with the test asserting the pair) *and*
has its own 20/s process-wide ceiling.

**The TLS server (`transport/server.rs` + `main.rs`).** TLS 1.3 only, no
client auth (the right direction — client auth is the bearer layer's job),
one identity object shared between `ApiState` and the server config with
fail-closed startup if either construction fails. The both-listeners design
is deliberate and the security boundary (port publication) is enforced on
the committed compose by `check-ratls-cutover.sh` in both directions;
`TransportModeConfig::from_env` fails closed on typos and on
non-UTF-8, and the compose default (`gateway-terminated`) is the documented
migration choice, not a silent downgrade.

**The verification core (`tee/verify-transport.ts`).** Check ordering is
right where order matters: shape first (a short nonce would weaken the
freshness check), protocol version and mode refusal before anything
expensive, the impossible-entry guard **before** the RTMR3 replay (the
CA-01 lesson, carried over), strict pins required, and the SPKI comparison
is the culmination rather than one of many. Digest recomputation from the
*returned* manifest fields means a tampered body cannot match the quote.
`eq` is constant-time-shaped.

**The WebSocket gate (`tee/transport-ws.node.ts`).** Per-upgrade SPKI
equality against the attested value; sends queued until verified **and**
writable (the verified-but-CONNECTING case is handled); inbound frames
before verification are dropped; `close` is terminal and discards the queue
(a queued bearer token is never delivered late); the handshake timeout
bounds a never-upgrading peer; late listeners get terminal states replayed
but `open` only ever from `surfaceOpen`, which refuses to run unverified.
An `open` without an `upgrade` (plain `ws://`) is refused outright.

**The consumer entry point (`tee/transport.node.ts`).** The verifier's own
output is the single source of truth for SPKI and boot session; the
reconnect path carries `expectedBootSessionId` so a restarted enclave fails
`boot_session_mismatch` (the omission's consequences are spelled out in the
comment that fixed it); stream-transport refusals surface loudly via
`onTransportViolation` (the daemon wires this).

**The adoption modules.** The daemon refuses `ra-tls` without the compose
pin, the signer-set pin, or a WebSocket constructor ("half-protected is
worse than unprotected"), and threads one transport through the token
issuer, provisioning, and proxy. trader-host fails closed on an
unrecognised `DARKNYX_TRADER_CVM_TRANSPORT` value and on missing pins, keeps
the RPC upstream off the enclave-pinned transport (correct — Helius is not
the enclave), and its Dockerfile now builds the SDK in-image to verify
rather than trusting the origin. The daemon config requires the pins at
load time (`config.ts:154+`).

**The nightly (`cvm-e2e.yml`).** Pins are harvested from the live enclave
but enforced by suites that do the real DCAP + RTMR3 replay, so a lying
endpoint cannot use harvested pins to pass; the image-ref normalisation
keeps digest-pinning strict (full-shape match, not a glob); the cold-boot
budget was raised with the failure that justified it, and the timeout now
dumps the enclave boot log plus both route probes before failing.

**`valid-input-prover.ts` root-ring read at `confirmed` (not `finalized`).**
The stated security argument holds: the on-chain `contains_root` check runs
against live state at landing time, a fabricated root is in the ring at *no*
commitment level, and the `finalized` read only rejected roots that were
already valid (the ~30-slot devnet lag broke prove-after-deposit). No
finding.

**Carry-forward settle/crypto files** (read in this engagement; anchors in
TR-08/TR-09/PF-31): PDA seed namespaces in `lock_note.rs` are tag-keyed and
the tag cannot arrive unvalidated (intake derives it from the verified
opening and binds it into the relayed VALID_INPUT check; the on-chain handler
re-verifies); no `unwrap`/`expect` on external input outside infallible
conversions; no secret-bearing error strings (`RpcError`'s reqwest `From`
strips the URL per the SW-01 fix, with the regression test proving it);
`marker_sweep`'s account parsing is the model case (owner + discriminator +
length before field reads, offsets pinned against the generated layout);
`alt.rs`'s no-owner-check parse is mitigated by its only caller reading an
ALT PDA the worker itself created, with an in-memory fallback; and the
reduce-vs-reject parity class stays closed in `field.rs`/`merge.rs`/
`user_commitment.rs` (strict rejects round-trip-checked, the two deliberate
reductions are TS-matched, `merge.rs` rejects invalid bitmaps and
out-of-mask bits with the TS mirror enforcing the same 2-or-4 shape).

---

## 4. Coverage

**Read fully in this engagement (mine):** the four TEE transport modules +
endpoint + `config.rs`/`main.rs`/`api/state.rs`/`api/mod.rs`/`rate_limit.rs`
diffs; all five SDK transport production files + `transport-node.ts`; daemon
`transport.ts` + the `bin/daemon.ts`/`config.ts` transport sections;
trader-host `cvm-transport.ts`, `bin.ts`/`runtime-config.ts`/`types.ts`/
`live-proxy.ts` (WS relay + HTTP proxy paths in full) + Dockerfile diff;
`scripts/check-ratls-cutover.sh` and `check-cvm-suites-use-transport.sh`;
the `cvm-e2e.yml` diff; `valid-input-prover.ts` diff; the GitBook transport
page. ≈ 3.4k new production lines from the transport stack.

**Read via a delegated pass, anchors spot-checked against files I know:**
`settle/lock_note.rs`, `settle/alt.rs`, `settle/marker_sweep.rs`,
`persistence/markers.rs` (relevant section),
`darkpool-crypto/{field,merge,user_commitment}.rs` (+ their TS mirrors).
≈ 950 non-test lines. Its TR-08/TR-09/PF-31 conclusions are consistent with
everything I read around them; the "verified clean" items it produced are
folded into §3.

**Not read:** the new test files' internals beyond targeted greps
(`cvm-ratls-transport`, `transport-{agent,ws,relay-attack,factory,
selection,late-listener}`, `cvm-harness.ts`'s transport routing — test
tooling, and the suites' own comments were used as evidence *about*
production behaviour only where they record live outcomes);
`pr-checks.yml`'s new lines beyond confirming the two scripts are wired into
the §2.5 gate; the loadgen's `real_settle/` (descoped in `audit_7` §12);
`packages/indexer` (owner-descoped). The `ws`-vs-self-signed behaviour in
TR-01 was verified mechanically on this box (default client → `REJECTED:
self-signed certificate`).

**Part B coverage (§6):** two delegated full sweeps — all 20 files under
`programs/vault/src/instructions/` plus `state.rs`/`merkle.rs`/`zk/` (~2.6k
non-test lines), and the TEE intake/journal/persistence/prover/logging/
admin surfaces (~3k non-test lines) — with first-hand re-verification of
every load-bearing new claim before recording it: the circuit owner/fee
constraints (`match_batch.circom:194-227,407,424`), both governance
handlers (`set_protocol_config.rs`, `set_tee_pubkey.rs`), the GPU compose +
guard failure (run on this box), the icicle scratch path
(`icicle_prover.rs:361-378` vs `scratch.rs`), the `create_wallet` public
input (`create_wallet.rs:34,44` + reader grep), and the reason-string flow
(`worker.rs:626-628` vs `scheduler.rs:577` → `order_router.rs:44-60`).
`CRYPTOGRAPHY.md` §2/§5/§7.5 were re-read against the code. Not covered in
Part B: a constraint-by-constraint re-derivation of all nine circuits
(F-04's external audit remains the assurance artifact for that), and the
litesvm test files beyond the behaviours the handlers cite.

---

## 5. What I could not rule out

1. **TR-02's practical exploitability.** The mechanism follows from the
   adapter's own state model (`current` cleared only on `close`; undici
   redials transparently under dispatch; the connector accepts any
   certificate), but the window width depends on undici-internal dispatch
   ordering I did not source-read, and on whether an on-path TCP actor can
   reliably land a kill inside it. A lab PoC (two local TLS peers, one
   killing connections at controlled offsets) would settle both. Until then
   TR-02 stays Medium on mechanism, not on measurement.
2. **Whether any live trader-host deployment currently points its stream
   upstream at the `8443s` route** (making TR-01 a live outage) or at a
   still-gateway-terminated URL (making it a latent one). That is deployment
   state, not repo state; the repo's own `check-cvm-suites-use-transport.sh`
   comments imply the cutover left non-SDK clients stranded once already.
3. **dstack gateway mid-stream behaviour on passthrough connections** —
   whether it can splice or only forward/cut. Affects TR-02's attacker model
   and nothing else in this engagement.
4. **F-04 remains the standing caveat**: a clean generalist read of the
   circuits is not an assurance artifact, and this engagement did not
   re-open the circuits at all.

---

## 6. Part B — supplement: vault program + TEE trust surfaces (funds / privacy / intent-leak)

> Added the same day, after the owner asked whether the engagement had
> covered the Solana program surface and the TEE trust assumptions under the
> three lenses. Part A had deliberately deferred to audit_1…audit_8's
> conclusions there; this supplement re-derives them. Method: two full
> delegated sweeps (all 20 vault instruction files + state; the TEE
> intake/journal/prover/logging/admin surfaces), with every load-bearing
> new claim re-verified first-hand before being recorded here (the circuit
> constraints, both governance handlers, the GPU compose, the icicle scratch
  path, and the reason-string flow were each opened and read).

### 6.1 Findings

#### TR-10 — The GPU compose never got the RA-TLS cutover

**Severity:** High
**Category:** Security / intent leak in transit (C13 class — the cutover stopped at the CPU compose)
**Lockstep:** no

**Anchors:** `deploy/docker-compose.gpu.yaml:129-130` (publishes `"8080:8080"`),
`:85` (`DARKNYX_TEE_HTTP_BIND` only), no `DARKNYX_TEE_TRANSPORT_MODE` and no
`:8443` anywhere in the file; `crates/darknyx-tee/src/config.rs` (unset mode ⇒
`gateway-terminated`); `.github/workflows/pr-checks.yml:231`
(`bash scripts/check-ratls-cutover.sh` — no argument, so only
`deploy/docker-compose.yaml` is checked). **Mechanically verified on this
box:** `bash scripts/check-ratls-cutover.sh deploy/docker-compose.gpu.yaml`
fails with "does not set DARKNYX_TEE_TRANSPORT_MODE" — the guard catches this
exact defect when pointed at the file, and CI never points it there.

**Problem.** The T-03P cutover was applied to the CPU compose only. A GPU CVM
deployed from `docker-compose.gpu.yaml` — the documented H200 proving path —
serves the entire API as plaintext HTTP through the dstack gateway: order
bodies (openings, VALID_INPUT proofs, viewing pubkeys) and the fills-channel
memos (amounts, inners, commitments) cross the one party RA-TLS exists to
defend against. This is the largest single intent-leak surface in the repo
today, and it is invisible in CI because the cutover guard's default argument
mirrors the CPU file.

**Failure scenario.** Operator runs an H200 window per
`docs/gpu-tee-runbook.md` with the GPU compose; the gateway relays raw HTTP
for the whole prepaid session; every order and fill of that window is
readable by the gateway operator.

**Fix.** (a) Apply the cutover to the GPU compose (mode `ra-tls`, publish
`8443:8443`, unpublish `8080`). (b) Make the guard loop over *every*
`deploy/docker-compose*.yaml` — one line — so the next compose file cannot
repeat this. Regression: the guard fails on a compose with published-8080 and
no mode, for each file. ~1 hour.

#### TR-11 — The icicle prover bypasses the SW-14 witness fix

**Severity:** Medium (same calculus as SW-14: the dstack overlay is on the
LUKS data disk, per the SW-14 closure note — otherwise High)
**Category:** Security / private-witness confidentiality (C7 class)
**Lockstep:** no

**Anchors:** `crates/darknyx-tee/src/prover/icicle_prover.rs:361-378`
(`std::env::temp_dir()` + plain `create_dir_all` ⇒ 0755, writes
`witness.wtns`), vs the fix it bypasses: `prover/scratch.rs:48,86`
(`witness_scratch_base` honoring `DARKNYX_TEE_WITNESS_DIR`, and
`create_private_dir` 0700) used by the rapidsnark path
(`snarkjs.rs:113-137`); `deploy/docker-compose.gpu.yaml:83` sets
`DARKNYX_TEE_WITNESS_DIR=/witness` (tmpfs) — which icicle ignores.

**Problem.** SW-14's fix landed on the native/rapidsnark witness path only.
The icicle backend — the one the GPU compose selects for `DARKNYX_TEE_PROVER=icicle`
— writes the full private witness (per-slot amounts, both owner commitments,
inners, clearing price; the module's own header says so) to a world-readable
`/tmp` directory on the container overlay. The cleanup Drop runs on normal
exits only; a crash (the case the recovery drill deliberately induces) leaves
it. `scratch.rs`'s own module doc describes precisely this defect as the
thing it fixed — this is the fourth backend, added after the fix.

**Fix.** Route `icicle_prove_wtns` through `scratch::witness_scratch_base()`
+ `create_private_dir` like its sibling. ~1 hour + the mutation test
(oss-mode check on the created dir). Also greppable guard: no
`env::temp_dir()` in `prover/` outside `scratch.rs`.

#### TR-12 — Fee / protocol-owner rotation has no timelock and a 100% ceiling

**Severity:** Medium (governance hardening; consequence is a full
trading-value drain, prerequisite is a captured ops admin)
**Category:** Loss of funds (via governance)
**Lockstep:** no

**Anchors:** `programs/vault/src/instructions/set_protocol_config.rs:31-47`
(admin-only; arbitrary `[u8;32]` owner commitment; any
`fee_rate_bps ≤ 10_000`; effective immediately), read live by
`verify_match_batch` (`verify_match_batch.rs:106-121` recomputes the config
digest from current `VaultConfig`), so every batch verified *after* the
change proves its exact fee against the new rate and `tee_forced_settle_batched`
mints the fee notes to the new owner commitment (`:500-556`). The 100%
ceiling is acknowledged at `set_protocol_config.rs:14-16`.

**Problem.** Not a code bug — a governance power without a brake. A captured
`vault_config.admin` (the operations 3-of-5 in the N-19 model) converts
itself into the fee recipient at a 100% rate in a single transaction with no
delay window; users' only defense is noticing `ProtocolConfigUpdated` and
stopping trading. The circuit guarantees outputs ≥ 0 — i.e. the drain is
capped at exactly everything.

**Fix options.** (a) Timelock on `set_protocol_config` (a governance PDA
with an enforceable delay, or a two-tx activate pattern). (b) A sane
on-chain ceiling well below 10_000 bps. (c) Require the root key to
co-sign fee/owner changes (it exists, is distinct, and signs nothing today
besides its own rotation) — dual authority for the two fields that move
value. Any of these is small; (c) is the cheapest structural brake.

#### TR-13 — TEE-key rotation is instantaneous and gates every settle

**Severity:** Medium (venue-wide settlement halt; custody is NOT lost)
**Category:** Liveness (via governance)

**Anchors:** `programs/vault/src/instructions/set_tee_pubkey.rs:36-63`
(admin-only whole-set replace, no delay), consumed at
`tee_forced_settle_batched.rs:310-318` and `lock_note.rs:104-109`.

**Problem.** A captured ops admin replaces the authorized TEE signer set in
one tx; every settle and lock stops authorizing immediately. Custody is safe
— withdraw/merge stay permissionless, locks expire permissionlessly within
`MAX_LOCK_TTL_SLOTS` — but combined with TR-12 this is the complete
"tax + halt" governance power, neither arm timelocked. The module's own doc
says operators "must independently verify the new TEE attestation before
that multisig approves" — nothing enforces a window in which anyone else
could.

**Fix.** Same timelock mechanism as TR-12 (they should share it), plus an
emit-and-wait rotation ceremony if the split-governance rehearsal (N-19)
wants an off-chain checkpoint rather than an on-chain delay.

#### TR-14 — `create_wallet` is front-runnable

**Severity:** Low (no authority impact — verified)
**Category:** Loss of funds lens (rent nuisance + registry misattribution)
**Lockstep:** **yes** — the fix is a circuit change

**Anchors:** `programs/vault/src/instructions/create_wallet.rs:34,44`
(exactly one public input: the commitment), `:48` (`w.owner = signer`);
grep confirms **no instruction reads `WalletEntry.owner`** — the only
references are the writer and `state.rs`.

**Problem.** Anyone can copy a pending `(commitment, proof)` from the
mempool and register the `WalletEntry` with themselves as owner. Today that
is rent-burn and a misattributed registry row, nothing more — no handler
consumes the field. It is recorded because the field is *presented* as an
ownership registration, and one future reader of it converts this into an
authority bug.

**Fix.** Add the owner pubkey as a second public input to `VALID_WALLET_CREATE`
and constrain the commitment's derived owner binding to it — a lockstep
circuit + VK + SDK change (§5 of CLAUDE.md), cheap now that the circuit is
tiny, or delete the field if it serves no planned purpose.

#### TR-15 — Settlement-failure diagnostics reach the client orders channel

**Severity:** Low
**Category:** C5 class (detail through free-form strings) + comment-vs-code
**Lockstep:** no

**Anchors:** `crates/darknyx-tee/src/settle/worker.rs:626-628` (the comment:
`format!("{e}")` "is never served to a client"), vs
`settle/scheduler.rs:577` (`reject_batch(output, &format!("settlement
pipeline failed: {e:?}")` — the *Debug* render, richer than `{e}`) →
`matcher/interval.rs:545-552` (`OrderLifecycleKind::SettlementFailed{reason}`)
→ `api/order_router.rs:44-60` (forwarded verbatim on the per-account
channel). SW-01's redaction keeps credentials out; RPC error bodies and
`AssembleError` debug strings (with hex commitments — public values, but
diagnostics) flow to the order owner.

**Fix.** Close the set at the matcher boundary the same way `JobStatus` did:
`SettlementFailed{reason: &'static str}` with the detail logged. ~2 hours.

#### TR-16 — Privacy-lens emission notes (Info, three items)

`programs/vault/src/instructions/lock_note.rs:164-182` — the `NoteLocked`
event publishes `token_mint`; the note-use tag is mint-independent by
construction, so the event teaches an observer "a note of mint X locked",
which the tag alone would not. `withdraw.rs:253-258` — `Withdrawn` still
publishes the `nullifier`, which nothing on-chain consumes since PF-04 (an
event field beyond on-chain need). `tee_forced_settle.rs:64-65` — one settle
tx pairs `order_id_a`/`order_id_b`, so counterparties are linked at order
granularity (inherent to atomic pair settlement; order_ids are HD-derived,
not identity-derived). Also noted: `deposit` accepts any mint (dust/spam at
the depositor's rent cost; per-mint `OutstandingMint` accounting prevents
cross-mint confusion) — `deposit.rs:31,42-50`.

#### TR-17 — The canonical threat-model doc still describes the pre-cutover transport

**Severity:** Low (docs — but this is `CRYPTOGRAPHY.md`, the document every
agent and auditor is told to trust first)
**Category:** C6 class
**Lockstep:** no

**Anchors:** `CRYPTOGRAPHY.md:114` — the threat-table row for "Order intent
in transit (T-03)" states the TEE "terminates no TLS: it serves plaintext
HTTP on `0.0.0.0:8080`" and defers T-03 wholesale to a mainnet gate.
Stale on two counts since 2026-08-16: the enclave now terminates TLS itself
with a boot-random, quote-bound key and `:8080` is unpublished (T-03P
closed for programmatic clients), and the browser half (T-03B) is the part
that remains open. A reader of the canonical doc gets a weaker *and*
outdated model — and TR-10 shows the doc's assumption ("the gateway
terminates TLS") is literally true again on any GPU deployment.

**Fix.** Rewrite the row for the two-regime reality (RA-TLS cutover state +
T-03B open + the GPU-compose exception until TR-10 closes). Pairs with
TR-07 (the GitBook page) — same pass.

### 6.2 Malicious / compromised-TEE capability matrix (the trust-assumption answer)

**Cannot — bounded by circuit + chain, verified first-hand:**

- **Divert outputs or fees to itself.** `circuits/templates/match_batch.circom`
  constrains every output note to its input's owner commitment
  (`:194,203,214,227` — `hashC/D/E/F.inputs[4] <== a/b_owner_commit`) and
  both fee notes to `protocol_owner_commitment` (`:407,424`), which the
  on-chain recomputed `config_digest` pins from live `VaultConfig`. A
  substituted owner changes the commitment, which changes the tag, which
  fails the NoteLock/consumed-PDA lookups.
- **Inflate value.** Conservation + `Num2Bits(64)` on all amounts are
  proof-enforced; `outstanding[mint] ≤ vault balance` is asserted on-chain
  after every deposit/withdraw.
- **Settle a fabricated batch.** Tx D needs an authorized-TEE Ed25519
  signature over the canonical payload hash, live NoteLocks on both consumed
  tags (which require user-relayed VALID_INPUT proofs the enclave cannot
  forge — it holds no spending keys), and a non-expired `BatchValidityMarker`
  seeded by exactly this batch root, which only exists after Groth16
  verification on-chain.
- **Double-spend.** One tag-keyed `ConsumedNoteEntry` namespace is shared by
  settle / withdraw / merge via `init` collision; verified consistent in all
  three handlers.
- **Spend or withdraw user funds, or swap a victim's viewing key** —
  withdraw/merge are user-proof paths; `viewing_pubkey` is inside the signed
  canonical order and contributory-checked at intake.

**Can — TEE-trusted (documented, accepted) or inherent:** see all order
intent (amounts, price, side, openings, viewing pubkey) — the tag system
bounds *chain observers*, not the enclave; match within the breaker band at
any price (price fairness is the recorded accepted trust); censor/reorder/
cancel orders and delay settles within lock/marker windows (liveness only);
corrupt or zero the fill-recovery ciphertext (recoverability DoS —
detection via the memo-integrity guard, not theft); re-lock an unconsumed
note against an arbitrary `order_id` (S-08, documented — bounded by note
size, declined fix); burn its own SOL.

**Where intent actually leaks today (the honest map):** the enclave always
sees intent (inherent); the durable amount channel is the on-chain
X25519-ECIES `fill_recovery` ciphertext (encrypted to the signature-bound
viewing key — sound); the live fills memo is plaintext JSON protected by
per-account JWT-keyed routing and, since the cutover, by in-enclave TLS —
**except on the GPU compose (TR-10), where the gateway reads everything**;
the journal persists tags/output-commitments/recovery-ciphertext but no
amounts, inners, openings, or viewing keys; the witness crosses disk only
via the prover backends — fixed on rapidsnark, **not on icicle (TR-11)**.

### 6.3 Verified clean (Part B additions)

- **Known findings hold in their fixed state**: F-01/F-02 (`devnet-admin`
  double-gated: feature + admin), S-01 (withdraw destination is two public
  inputs), S-04 (marker TTL derived, not caller-supplied), SW-21 on-chain
  side (bounded by PDA existence; `initialize_tree` enforces
  `tree_id < num_trees`), BatchValidityMarker 1:N (non-`mut` unchecked
  account, closed only at/after expiry to the original payer), D-09
  (permissionless post-expiry release only).
- **Per-instruction hygiene** (signer, writability, seeds, checked
  arithmetic, init-vs-init_if_needed) verified across all 20 instructions;
  the consume-once namespace discipline (tags vs commitments) is consistent
  in every handler; `withdraw`'s live-lock check fails closed on unparseable
  program-owned data; `merge` rejects pre-existing consumed-account
  substitution (`data_is_empty && lamports == 0`).
- **Fill-memo isolation**: channels keyed on the JWT-authenticated
  `account_id`; `route_fill` resolves ownership from the intake-time map;
  re-login cannot switch identity — account A cannot receive B's fills.
- **Journal / disk / logs / metrics**: no amounts, inners, openings, or
  viewing keys reach disk; `settle/metrics.rs`'s no-order-id claim holds
  under grep; the K-shard signers are never serialized; `/admin/*` is
  bearer + live-registry admin-checked; SW-01's redaction verified present
  with its regression test.
- **Event inventory**: amounts appear only where the SPL transfer is public
  anyway (`NoteCreated`/`Withdrawn`); `TradeSettled` carries leaf indices +
  relock flags only (P3b honored).
