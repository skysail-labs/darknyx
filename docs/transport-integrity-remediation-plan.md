# Transport integrity — architecture, evidence, and remediation plan

**Status:** CPU RA-TLS is deployed and live-tested. D1 is merged. D2/D3 are
implemented together and locally verified; their CPU restart drill and merge
remain open. Browser transport and GPU parity are deferred by product/resource
decision.

- **Canonical record since:** 2026-08-23
- **Last code baseline reviewed:** `main` at `a9a2a04b` plus the combined D2/D3 branch
- **Primary finding:** T-03
- **Active follow-ups:** audit_9 TR-03 and TR-05 (TR-02 merged in PR #199)
- **Deferred follow-ups:** T-03B/R-01 (browser); TR-10/R-22 (GPU)
- **Source ledgers:** `audits/audit_6/tracker.md`,
  `audits/audit_8/audit_8_findings.md`,
  `audits/audit_9/audit_9_findings.md`, and
  `audits/residual-backlog.md`

This is the single source of truth for Darknyx transport integrity. It replaces
the former research record, original phased remediation tracker, and separate
daemon-hardening plan. Those files were consolidated because their overlapping
status blocks had begun to disagree.

The historical record is retained here only where it changes an architectural
decision, prevents a known mistake from recurring, or supplies closure
evidence. Point-in-time audit reports remain immutable; finding status moves in
their trackers and the residual backlog.

---

## 1. Current product decision

### 1.1 Programmatic access is the active path

The Node SDK and reference daemon connect to `darknyx-tee` over in-process
RA-TLS:

```text
SDK / daemon ═════ TLS encrypted end-to-end ═════► dstack passthrough ═════► darknyx-tee
                                                                              │
                                                                     plaintext only here
```

At every process boot, `darknyx-tee` generates a random TLS private key in
memory. It is never persisted and is never derived with `dstack.get_key()`. A
separate transport quote binds:

- a fresh caller nonce;
- protocol version and transport mode;
- hashed app and instance identities;
- the current boot session;
- SHA-256 of the served certificate SPKI; and
- SHA-256 of the complete ordered settlement-signer set.

The dstack `-8443s` route passes this TLS stream through without terminating it.
The client verifies the certificate on the connection it uses against the
quote, the independently approved compose hash, and the signer set derived from
finalized `VaultConfig.tee_pubkeys`.

### 1.2 Browser access is deferred

The browser implementation remains in the repository for testing and future
product evaluation, but it is not an active or launch-qualified access path.
Its ordinary `trader-host` sees browser orders and stream frames in plaintext.
An RA-TLS connection from trader-host to the CVM protects only that upstream
hop; it does not hide plaintext from trader-host itself.

T-03B and R-01 re-enter before any external browser user or real value, unless
the owner formally removes browser access from the product. At re-entry, choose
and re-review one end-to-end browser design; do not infer that the earlier B2
HPKE direction is still automatically correct.

### 1.3 GPU transport parity is deferred, not an active phase

There is currently no confidential-GPU allocation with which to build and
validate a production-equivalent CUDA image. TR-10/R-22 therefore remain
explicitly deferred in `audits/residual-backlog.md` and the GPU runbook. They
are **not** part of the active PR sequence below.

Until the gap is closed, a GPU compose or pre-cutover CUDA image is not a
production transport and must not receive external credentials, private order
flow, or real value. When GPU access returns, re-enter from the residual
finding and `docs/gpu-tee-runbook.md`; do not silently append GPU work to a CPU
daemon PR.

---

## 2. Verified facts and corrected assumptions

These findings changed the design. Future agents must not rediscover them from
documentation alone.

### 2.1 `report_data` is per request

dstack's `get_quote(report_data)` accepts caller-selected data on every call.
The legacy `/attestation` layout (`nonce || signer_set_hash`) is an application
choice, not a platform-wide 64-byte allocation. Transport attestation can and
does use a separate versioned quote without breaking `/attestation`.

### 2.2 Gateway certificate evidence is not fresh process identity

The dstack gateway persists certificate material, including the private key, in
its distributed KV store and can reload it on a later node or boot without
minting a new quote. Its evidence proves certificate provenance, not that the
process currently holding the key has the approved measurement.

Gateway evidence may still help against ordinary CA mis-issuance on a
gateway-terminated route. It is not T-03 closure and is irrelevant to the
programmatic route once the gateway passes enclave TLS through.

### 2.3 Transport keys must be boot-random

`dstack.get_key()` is deterministic for an app identity and can survive the
kind of workload change transport identity is meant to detect. The RA-TLS key
must come from the OS CSPRNG, remain memory-only, and rotate on every engine
process boot.

### 2.4 Verification must cover the actual connection

Opening a probe socket, verifying its certificate, and then using ordinary
`fetch` or WebSocket on another connection proves nothing about the second
peer. DNS, routing, pooling, reconnect, or a relay may send it elsewhere.

The certificate observed on the HTTP socket and WebSocket upgrade must match
the quote-bound SPKI before credentials or private frames leave.

### 2.5 Browser code distribution and transport are separate findings

A browser can verify a quote-bound application channel, so browser transport is
not impossible in principle. But code delivered from an ordinary origin is a
more frequent software-distribution trust event than an installed daemon
binary. That belongs to R-01; it must not be used to claim T-03B is inherently
unclosable, nor may a transport fix be presented as release-integrity closure.

### 2.6 Passthrough works on the deployed platform

The `-8443s` dstack route was verified live on prod9. The certificate served to
the client was `CN=darknyx-tee ra-tls (boot-scoped)`, proving TLS terminated in
the enclave rather than at the gateway. WebSocket upgrade also survived the
passthrough route.

---

## 3. As-built CPU transport

### 3.1 Enclave

`crates/darknyx-tee/src/transport/` provides:

- a boot-random, memory-only TLS identity;
- the canonical transport-attestation manifest;
- a TLS 1.3 listener on port 8443;
- `GET /transport-attestation?nonce=<32-byte-hex>`; and
- separate application `/attestation`, `/info`, REST, and `/v1/stream`
  surfaces.

The transport quote domain is versioned. Its manifest encoding is mirrored in
Rust and TypeScript and must remain byte-identical.

### 3.2 SDK

`@darknyx/sdk/transport-node` is the only supported Node assembly entry point.
`createVerifiedTransport` returns:

- a verified `fetch` implementation;
- a gated WebSocket factory;
- the verified SPKI and boot session; and
- an `isStale()` signal.

Consumers must inject that HTTP/WebSocket pair everywhere. Global `fetch`, a
stock WebSocket, or `NODE_TLS_REJECT_UNAUTHORIZED=0` is not a fallback.

### 3.3 Daemon

The daemon constructs transport before authentication and injects the returned
HTTP/WebSocket pair into its venue clients. It separately verifies application
attestation and reconciles the quote-bound signer set with finalized Solana
governance.

One supervisor now owns the daemon's HTTP and WebSocket generation. A boot or
socket verdict pauses placement, verifies a new immutable generation, checks
application attestation plus finalized governance, refreshes the stream, and
reconciles before placement resumes. The remaining work is live restart
evidence, not another daemon architecture change.

### 3.4 Deployment

The CPU production compose publishes the RA-TLS port and does not publish
plaintext port 8080. `scripts/check-ratls-cutover.sh` enforces this CPU shape.
The public route is:

```text
https://<app-id>-8443s.dstack-pha-<node>.phala.network
wss://<app-id>-8443s.dstack-pha-<node>.phala.network/v1/stream
```

The certificate is self-signed by design. Clients authenticate it with the
transport quote, not a public CA.

---

## 4. Historical CPU cutover evidence

The 2026-08-16 cutover on `nightly-test-cvm` (prod9, image 89) established:

- the actual socket SPKI matched `manifest.tls_spki_sha256`;
- the transport signer-set hash matched all finalized on-chain shard signers;
- relayed-quote, wrong-certificate, wrong-signer, and old-boot negatives were
  rejected;
- the public plaintext route returned HTTP 000 on three attempts while 8443s
  served successfully;
- WebSocket upgrade used the enclave's boot-scoped certificate;
- `cvm-api-surface` passed 10/10 over RA-TLS;
- `cvm-settle-e2e` completed over RA-TLS;
- a daemon business flow attested, deposited, observed the leaf, and placed an
  accepted order through the verified transport;
- median cold transport establishment was approximately 1.4 seconds; and
- no client RSS growth was observed across 25 sequential transports.

Representative settle timing from that window:

```text
witness_ms=304
prove_step_ms=3054
prove_ms=3395
lock_ms=1292
verify_ms=1787
settle_ms=5140
total_ms=10383
```

This evidence remains the CPU baseline. T-03P was later reopened because
audit_9 identified post-cutover gaps; reopening does not erase evidence that
passthrough, certificate binding, settlement, and the core verification
contract worked.

---

## 5. Active closure invariants

The remaining daemon work must preserve all of these properties.

1. **No pre-verification application bytes.** Credentials, bearer tokens,
   order intent, cancellation, stream login, and fill subscriptions never cross
   a socket whose boot SPKI has not been accepted.
2. **Verification applies to the connection used.** Probe success cannot
   authorize a replacement connection.
3. **A boot change is a lifecycle transition.** Placement pauses, a fresh
   transport and application identity are verified, state reconciles, then
   placement resumes.
4. **Security verdicts are terminal for a generation.** SPKI, compose, signer,
   boot, DCAP, or encoding mismatches are never retried into acceptance.
5. **HTTP and WebSocket move together.** One generation owns both adapters.
6. **Production has one safe policy.** Omission selects RA-TLS; legacy transport
   is explicit and limited to development/simulator use.
7. **Recovery never auto-rebooks.** Existing order and settlement state may be
   reconciled, but a new signed order requires an explicit user strategy action.

---

## 6. Active phase and PR map

| Phase | Branch / PR | Finding | Result | Live requirement | Status |
|---|---|---|---|---|---|
| D1 | `remediation/ratls-socket-adoption` / PR #199 | TR-02 | Every replacement HTTP socket is SPKI-refused before undici can dispatch bytes | Local adversarial TLS peers; no CVM | Merged 2026-08-23 |
| D2 + D3 | `remediation/daemon-ratls-lifecycle-policy` | TR-03 + TR-05 + legacy-default gap | One supervised restart lifecycle; production RA-TLS default; server mode and transport boot pinned | One CPU CVM restart drill | Code complete; live evidence and merge pending |

There is deliberately no GPU phase. TR-10/R-22 remain deferred as described in
§1.3.

---

## 7. D1 — authenticate replacement sockets before dispatch

### 7.1 Defect

Before D1, `createVerifiedFetch` verified the agent's live socket, returned from
the gate, and only then asked undici to dispatch the application request. If the
verified socket closes in that interval, undici may create a replacement
through a connector whose WebPKI check is disabled for the self-signed RA-TLS
certificate. The request can leave before the new socket is verified.

A post-response assertion is not closure: it detects a confidentiality failure
after the request body has crossed.

### 7.2 Required design

Retain the first connection as a bootstrap channel. It may accept the
self-signed certificate only to obtain nonce-bound transport evidence and
compare the socket SPKI with the quote.

After successful bootstrap, arm `TransportAgent` with that exact SPKI. Every
later connector handshake must inspect the peer SPKI and reject any mismatch
**before invoking undici's connection callback**. A rejected socket is destroyed
and never enters the pool.

Constraints:

- the expected SPKI becomes immutable once armed;
- arming twice with a different SPKI fails;
- the bootstrap socket must equal the value used to arm the connector;
- a rejection returns a typed transport failure without secret material;
- `connections: 1` and `pipelining: 1` remain until separately benchmarked;
- no global TLS-verification bypass is introduced; and
- the WebSocket gate continues checking its own upgrade connection.

An exact replacement SPKI match is sufficient within one transport generation:
the key is boot-random and the full quote already proved it belongs to the
approved boot. A new boot presents a different key and is refused before bytes
leave.

### 7.3 Tests and closure

- Force the verified socket closed between the gate and dispatch; route the
  replacement to a different certificate; assert the malicious peer receives
  zero requests and zero body bytes.
- Repeat with the same boot certificate; the request succeeds.
- Confirm a connector rejection cannot leave the socket pooled.
- Confirm compose, signer, boot, DCAP, and malformed-evidence verdicts remain
  terminal.
- Preserve bounded retry only for genuine bootstrap socket loss.
- Keep relay, origin-substitution, WebSocket, late-listener, and Rust/TS
  manifest-parity suites green.
- Mutation test by removing connector refusal and proving the unique request
  marker reaches the malicious peer.

D1's merged implementation arms `TransportAgent` with the bootstrap quote's SPKI.
The connector destroys a different-SPKI replacement before invoking undici's
connection callback, preserves the typed `spki_mismatch` verdict through
undici's `TypeError.cause`, and marks an exact-SPKI replacement as belonging to
the verified transport generation before dispatch.

The adversarial test swaps the peer after the preflight gate but before the
application dispatch. The wrong-certificate peer receives zero requests and
zero body bytes; the same-certificate peer succeeds. Removing the connector
guard makes the unique private marker cross to the substituted peer, so the
test is mutation-proven. D1 merged in PR #199. No CVM was required.

---

## 8. D2 — supervise restart, re-attestation, and reconciliation

### 8.1 Objective

Turn a CVM restart from a permanent fail-closed outage into a bounded,
observable recovery sequence without weakening refusal.

`isStale()` alone is insufficient: no live socket yields no identity evidence,
and the first useful signal may be a typed failure from a replacement
connection. The daemon needs a lifecycle owner.

### 8.2 State machine

Introduce one supervisor above the daemon that owns an atomic transport
generation:

```text
Ready(N)
   │ boot / SPKI / session violation
   ▼
Paused ─► Verify transport ─► Verify app + governance ─► Reconcile ─► Ready(N+1)
```

Requirements:

- HTTP and WebSocket delegates read the same atomically swapped generation.
- The first typed violation pauses new placement and closes the old stream.
- Concurrent violations collapse into one recovery attempt.
- Recovery builds a new `VerifiedTransport`; it never mutates old boot pins.
- Re-run DCAP, event-log, compose, boot, signer, and finalized
  `VaultConfig.tee_pubkeys` verification.
- Refresh bearer and stream sessions only after transport trust is restored.
- Reconcile persisted orders, reservations, notes, and ambiguous settlement
  before allowing placement.
- Continue safe cancellation and reconciliation when possible.
- Never auto-rebook an order missing after restart.
- Security verdicts keep the daemon paused until external state changes.
- Network-only failures use bounded exponential backoff with jitter and an
  operator-visible next-attempt time.
- `stop()` cancels recovery and closes timers, sockets, and queued frames.

### 8.3 Tests

- Boot A serves HTTP/WS; restart to B; no old-generation application bytes
  reach B before verification.
- The daemon pauses, verifies B, reconciles, obtains B's boot session, and
  resumes.
- Wrong compose, signer set, SPKI, DCAP report, boot, and malformed evidence
  each keep placement paused.
- Ten simultaneous failures start one rebuild.
- HTTP and WebSocket violations enter the same state machine.
- A reserved order is reconciled and never automatically rebooked.
- Stop during backoff or verification leaves no live resource.
- Control/status output exposes `ready`, `reverifying`, `reconciling`, and
  `paused` with closed-set reasons rather than raw diagnostics.

### 8.4 CPU CVM closure drill

1. Start the daemon over RA-TLS and complete attestation.
2. Deposit and place one bounded order; record order and boot session.
3. Restart/redeploy the same reviewed image so boot identity rotates.
4. Assert placement pauses before any request reaches the new boot.
5. Observe transport, application, and finalized-governance verification.
6. Observe reconciliation and prove no order was silently rebooked.
7. Place and cancel one fresh order after recovery.
8. Record recovery duration, attempts, stream reconnects, and RSS.
9. Drain and stop using the CPU CVM runbook.

### 8.5 Implementation status

The daemon now uses stable HTTP and WebSocket delegates backed by one atomic
generation. Typed HTTP or WebSocket refusals and cadence-detected staleness
enter the same single-flight recovery. The stream is suspended while a fresh
candidate is transport-verified; `/info` mode and boot are pinned to local
policy and the quote-bound transport boot; application attestation and
finalized signer governance are rechecked; then the stream resumes and durable
state reconciles. Security verdicts stay paused, while only typed network
failures receive bounded jittered backoff. Status exposes the closed-set
lifecycle state, reason, attempt count, and next retry time.

Local tests cover ten concurrent violations collapsing to one build, atomic
HTTP/WebSocket swap, boot disagreement, application and governance rejection,
network-only retry, reconciliation gating, no automatic placement, and stop
during verification. The live CPU drill above remains mandatory before
closure.

---

## 9. D3 — production policy and observable transport mode

### 9.1 Policy

There are no external compatibility obligations, so omission selects the safe
path:

- daemon default: `ra-tls`;
- production: `gateway-terminated` is rejected;
- development/simulator: legacy mode requires an explicit allow flag and loud
  warning;
- RA-TLS refuses startup without compose and signer-set pins;
- a typo or missing pin never falls back to global fetch; and
- examples, service definitions, and nightly jobs use the same variables.

If the daemon has no deployment-tier concept, add a small explicit enum rather
than inferring security policy from unrelated flags such as `SKIP_ATTEST`.

### 9.2 API truth and pinning

Add `transport_mode` to `/info` and the internal/public OpenAPI schemas. The
value comes from server state, not an unchecked environment echo.

The quote-bound transport manifest remains authoritative. `/info.transport_mode`
is an operational surface: the daemon rejects disagreement and requires
`ra-tls` before authenticating and after every D2 recovery.

### 9.3 Tests

- Unset production mode selects RA-TLS and requires its pins.
- Explicit production legacy mode is rejected.
- Explicit simulator legacy mode needs the allow flag.
- Typos are hard failures.
- `/info`, the transport manifest, OpenAPI, Rust, and TypeScript agree.
- A verified endpoint whose `/info` mode disagrees is rejected before auth.
- Nightly environment-parity and no-global-fetch guards remain green.

### 9.4 Implementation status

Omission now selects `ra-tls` and a `production` deployment tier. Production
rejects `gateway-terminated`; development and simulator deployments need both
the explicit legacy mode and `DARKNYX_DAEMON_ALLOW_LEGACY_TRANSPORT=1`.
`/info.transport_mode` is emitted from boot-selected server state, appears in
both OpenAPI contracts, and is pinned at startup and after every supervised
recovery. These changes ship with D2 so policy and restart behavior cannot
drift between PRs.

---

## 10. Validation gates

Run the affected subset on each PR and the repository's complete pre-PR gate
before merge. The minimum transport set is:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p darknyx-tee --test transport_attestation_surface \
  --test transport_tls_handshake

./node_modules/.bin/tsc -p packages/sdk/tsconfig.json
./node_modules/.bin/tsc -p packages/daemon/tsconfig.test.json --noEmit

( cd packages/sdk && ../../node_modules/.bin/vitest run \
    tests/transport-agent.test.ts \
    tests/transport-relay-attack.test.ts \
    tests/transport-factory.test.ts \
    tests/transport-ws.test.ts \
    tests/transport-ws-late-listener.test.ts )

( cd packages/daemon && ../../node_modules/.bin/vitest run )

bash scripts/check-ratls-cutover.sh deploy/docker-compose.yaml
bash scripts/check-cvm-suites-use-transport.sh
```

D1 needs no billable infrastructure. D2/D3 need one CPU CVM restart drill after
their local and hosted gates pass. Use the private configured Solana endpoint,
never `https://api.devnet.solana.com`.

---

## 11. PR discipline and rollback

### 11.1 PR order

1. D1 landed independently because it is the confidentiality boundary the
   lifecycle supervisor uses.
2. D2 and D3 ship in one PR; each invariant and test remains independently
   visible within it.
3. Do not add browser or GPU changes to this PR.

Every PR records finding IDs, invariant restored, affected wire behavior,
tests, live evidence where required, and rollback.

### 11.2 Rollback

- D1 may be reverted only while external trading is paused; the prior adapter
  has a known pre-dispatch gap.
- D2 rollback restores fail-closed outage behavior, never legacy fallback.
- D3 permits an explicit development rollback only; production cannot select
  legacy transport by omission.

---

## 12. Definition of done

Programmatic T-03P may return to `Closed` when:

- D1 proves no wrong-SPKI replacement peer receives application bytes;
- D2 proves a real boot rotation pauses, re-verifies, reconciles, and resumes;
- D3 proves production defaults and observed mode are fail-closed;
- full local/hosted checks are green;
- the CPU restart drill is recorded; and
- public/internal docs and the residual backlog cite this document as the sole
  transport record.

GPU deferral does not disappear at that point. The mainnet release checklist
must either close TR-10/R-22 with confidential-GPU evidence or explicitly ship
without a GPU deployment surface. Browser launch remains independently gated
by T-03B/R-01.

---

## 13. Continuation directive

Any agent continuing this work must:

1. read `AGENTS.md`, this document, audit_9 TR-02/TR-03/TR-05, and the relevant
   package source before editing;
2. inspect the dirty worktree and preserve unrelated changes;
3. move a phase only as far as evidence supports;
4. mutation-test the guard carrying each security claim;
5. never accept a post-response detector as D1 closure;
6. never reconnect to a new boot without transport, application, governance,
   and reconciliation checks;
7. never weaken WebSocket verification while fixing HTTP;
8. keep deferred browser and GPU work outside the active PRs;
9. never start a billable CVM for a locally provable property; and
10. wait for explicit owner approval before merging when requested.

Handoff block:

```text
Transport integrity handoff

Main commit reviewed:
Active phase: D1 | D2 | D3
Phase status: Open | In progress | Code complete | Closed | Blocked
Branch / PR / base:
Latest commit:

Invariant implemented:
Files changed:
Unrelated worktree changes preserved:

Local tests and results:
Mutation performed and expected failing test:
Hosted CI/review status:

Live CPU evidence, if required:
- CVM ID / node / image digest / compose hash:
- SPKI / signer-set hash / boot session:
- restart/recovery timings:
- order IDs / signatures:

Outstanding blocker:
Next exact action:
User approval required before:
```
