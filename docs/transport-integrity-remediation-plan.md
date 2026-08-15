# Transport integrity remediation — phased execution plan

**Status:** Approved architecture; implementation has not started.

- **Created:** 2026-08-15
- **Primary finding:** T-03
- **Adjacent finding:** R-01
- **Upstream baseline:** dstack v0.5.9 (`282eeb27`), the version currently used
  by Darknyx CVMs
- **Research record:**
  [`transport-integrity-plan.md`](transport-integrity-plan.md)

This document is the implementation tracker and handoff contract for closing
Darknyx transport integrity. It is intentionally separate from
[`transport-integrity-plan.md`](transport-integrity-plan.md): that document
preserves the investigation and measured evidence, including conclusions that
were later disproved during review. This document contains the corrected
architecture and the ordered PR plan.

The parent T-03 finding remains open until both active client classes have a
defensible transport:

- **T-03P — programmatic clients:** Node SDK, daemon, load generator, and any
  trader-host-to-CVM connection.
- **T-03B — browser clients:** the browser's sensitive order and stream traffic.
- **R-01 — browser release integrity:** the application code and security pins
  the browser receives. R-01 is a separate software-distribution problem, but it
  must close before the browser can present a launch-qualified “Attested” state.

Splitting the work does not weaken the parent invariant. T-03 is not `Closed`
until T-03P and T-03B are both closed, or the owner formally removes one client
class from the product.

---

## 1. Executive decision

### 1.1 Programmatic clients

Use **in-process RA-TLS terminated by `darknyx-tee`**, reached through dstack's
TLS-passthrough route if the preflight proves that route works on the production
gateway version.

The RA-TLS private key must be:

- generated from a CSPRNG at every `darknyx-tee` process boot;
- held only in process memory;
- never derived with deterministic `dstack.get_key()`;
- never written to a volume, journal, environment variable, log, or API;
- replaced on every process restart.

A fresh TDX quote must bind the peer certificate SPKI, full ordered TEE signer
set, boot session, protocol version, and caller nonce. A client must verify this
against the **certificate on the actual HTTP/WebSocket connection** before it
sends credentials, order intent, fill subscriptions, or any other sensitive
payload.

The existing `/attestation` contract does **not** need to change. dstack
`get_quote(report_data)` is a per-call API, so RA-TLS can use a separate,
versioned transport-attestation contract while the current
`nonce || signer_set_hash` endpoint remains compatible.

### 1.2 Browser clients

Choose exactly one browser transport after Phase 0 establishes the supported
ingress's real key lifecycle:

- **Path B1 — directly connected attested WebPKI ingress.** The browser sends
  sensitive REST and WebSocket traffic directly to a digest-pinned ingress
  inside the governed CVM. The ordinary trader host serves application assets
  and performs only explicitly retained non-sensitive provisioning work. It
  does not proxy plaintext orders or stream frames.
- **Path B2 — quote-bound application secure channel.** The browser verifies a
  fresh quote over a boot-random enclave KEM key and protects sensitive REST and
  WebSocket messages end to end. The trader host and dstack gateway may relay
  ciphertext but cannot recover or modify the protected plaintext.

Path B1 is preferred only if the exact ingress image and deployment can prove
that the key serving the current TLS session is controlled by the approved
current workload. Persistent “this key was once generated in a TEE” evidence is
not sufficient. If that property cannot be established, choose B2 or build a
small governed ingress that can establish it.

### 1.3 Gateway certificate evidence

Do not implement gateway `quoted_hist_keys` verification as an unconditional
first step. It proves certificate provenance and is useful against ordinary CA
mis-issuance, but it does not authenticate the gateway process currently
holding a persisted key.

If RA-TLS passthrough is the final programmatic route, the gateway no longer
terminates that TLS session and its certificate evidence becomes irrelevant to
that path. Retain it only as a deployment monitor or for a deliberately retained
legacy route; do not call it T-03 closure.

---

## 2. Why the earlier plan changed

The following facts are now source-verified and must not be rediscovered by a
future agent:

1. **Gateway certificate evidence is historical.** dstack v0.5.9 generates a
   quote when a certificate key is issued or renewed, stores `key_pem` in its
   distributed KV store, and reloads an unexpired certificate and key on later
   boots without making a fresh key quote.
2. **Gateway `/app-info` is not authenticated freshness evidence.** It is JSON
   returned by the gateway after `dstack_agent().info()` and is not
   nonce-bound, signed, or tied to the active TLS session.
3. **App-ID routing is meaningful but narrower than exact-instance binding.**
   KMS verifies the registering CVM quote and binds its verified `app_id` into
   the client certificate. An `app_id` can nevertheless survive upgrades and
   cover multiple instances; it is not the current matcher compose or boot
   session.
4. **`report_data` is per quote.** The current Darknyx
   `nonce || signer_set_hash` layout is an API choice, not a global platform
   allocation. A separate transport quote can coexist without invalidating old
   clients.
5. **A deterministic application key is not fresh.** dstack `get_key()` is
   deliberately stable for an application identity. Reusing it for RA-TLS would
   recreate the persistence failure this remediation is intended to remove.
6. **Browser origin integrity and transport integrity are distinct.** A browser
   trusts the application it loads just as a daemon operator trusts the binary
   they install. The browser's higher-frequency origin trust belongs to R-01;
   it does not make T-03B cryptographically impossible.
7. **RA-TLS on the trader-host upstream is not browser closure.** It protects
   only `trader-host -> CVM`; the trader host still sees plaintext unless the
   browser bypasses it or encrypts through it.
8. **dstack-ingress persists its key, but the persistence may be governed.**
   The documented compose mounts `cert-data:/etc/letsencrypt` (certificates *and*
   private keys) and `evidences:/evidences`, with the app mounting evidences
   read-only — so ingress evidence is a **static file written at issuance**, not
   a live challenge-response. That is the same freshness class as fact 1.
   **However**, `kms/src/main_service.rs:262-270` releases the disk-encryption
   key only through `ensure_app_boot_allowed` →
   `auth_api.is_app_allowed(&boot_info)`, and `boot_info` carries the
   **compose_hash**. So an unapproved build cannot decrypt `cert-data` and cannot
   obtain the key. See fact 10.

9. **TLS passthrough is source-confirmed on the gateway's own wildcard domain.**
   `gateway/src/proxy.rs:151-165` dispatches to `tls_passthough::proxy_to_app`
   when `parse_dst_info` (`:85-130`) sees a trailing `s`; SNI is peeked from the
   ClientHello before any termination. **No custom domain is required** — the
   docs' "custom domain (for production use)" prerequisite is a soft
   recommendation. App-ID routing is unchanged because it is the same SNI parse.
   Only the **live** probe (§6.2) remains open.

10. **Freshness is not the only remedy for key persistence.** There are two:
    *freshness* (quote the key at every boot — what boot-random RA-TLS does) and
    *governed key release* (the key cannot reach an unapproved measurement, so a
    historical quote stays meaningful). This re-ranks the candidate paths by
    **whose governance they depend on**:

    | Path | Key persistence | Governed by |
    |---|---|---|
    | RA-TLS, boot-random key | none | n/a — strongest |
    | Ingress inside our CVM | yes | **our** on-chain compose allowlist |
    | Phala gateway evidence | yes | **Phala's** allowlist, opaque to us |

    Option B1 is therefore stronger than the first review credited: its lifecycle
    gap may be closable by governance we already control rather than by a
    freshness property Phala would have to build. This is conditional on the new
    §6.3.1 question.

The mutable T-03 tracker and residual backlog must be corrected during Phase 0.
In particular, the old Option-A cost table incorrectly labels RA-TLS as requiring
a breaking change to the existing `/attestation` layout.

---

## 3. Scope and non-scope

### In scope

- A quote-to-actual-socket binding for every Node/programmatic transport.
- A boot-random, memory-only RA-TLS server key.
- HTTP and `/v1/stream` WebSocket transport, including reconnects.
- Removal or encryption of the browser's plaintext trader-host hop.
- Browser release-pin integrity where R-01 intersects transport selection.
- dstack gateway passthrough validation on the production platform version.
- dstack-ingress source, key-lifecycle, and current-boot evidence validation.
- Deployment compose, image digest, release pins, OpenAPI, internal architecture
  docs, GitBook security claims, and operational runbooks.
- Local, adversarial, measured, and live-CVM validation.

### Out of scope

- Vault program or circuit changes.
- Order canonical bytes, proof public inputs, note commitments, custody keys, or
  Solana account layouts.
- Changing matching, pricing, settlement, recovery, or oracle semantics.
- Protecting a user who deliberately installs a malicious daemon binary.
- Protecting a browser from malicious application code before R-01's selected
  independent release-integrity mechanism has authenticated that code.
- Treating availability as confidentiality. A forwarding component may always
  drop packets; the goal is that it cannot silently read or alter protected
  intent while still passing authentication.

---

## 4. Closure invariants

### 4.1 Shared invariants

1. **Actual-socket binding.** Verification uses the certificate from the exact
   socket that carries the protected HTTP request or WebSocket session. A
   separate `tls.connect()` probe followed by ordinary `fetch()` is forbidden.
2. **No secret before verification.** API credentials, bearer tokens, account
   identifiers where sensitive, order bodies, and stream login frames are not
   sent until the channel has passed its transport verification.
3. **Current boot.** A process restart changes the RA-TLS or application-channel
   key and invalidates prior transport evidence.
4. **Instance linkage.** The transport evidence binds one canonical manifest
   containing the certificate/KEM key, complete ordered signer set,
   `boot_session_id`, and protocol version. Clients do not accept two unrelated
   valid quotes and infer they came from the same instance.
5. **Measured workload.** DCAP verification and RTMR/event-log replay recover
   the governed Darknyx compose hash. App-ID membership alone is insufficient.
6. **Governed custody authority.** The quote-bound signer set equals the ordered
   on-chain `VaultConfig.tee_pubkeys` set for the configured vault.
7. **Downgrade resistance.** Production configuration has no silent fallback to
   gateway-terminated plaintext. Legacy mode, if retained for local development,
   is explicit, prominently reported, and rejected by production release
   assembly.
8. **Reconnect means reverify.** Every new HTTP connection and every WebSocket
   reconnect repeats verification. Pool reuse is allowed only for an already
   verified live socket.
9. **No redirect escape.** Sensitive requests never follow redirects to another
   origin or to an unverified connection.
10. **Honest user claims.** The UI and public documentation say “Attested” only
    after the active browser transport and release integrity meet their closure
    criteria.

### 4.2 T-03P closure

T-03P is closed only when:

- `darknyx-tee` terminates RA-TLS itself with a boot-random key;
- the dstack gateway passes the TLS stream through without terminating it;
- the Node SDK verifies certificate possession, transport quote, nonce,
  manifest, compose, boot session, and signer set on the actual connection;
- daemon, loadgen, and trader-host upstream use the shared verified adapter;
- the public plaintext application route is unreachable;
- HTTP and WebSocket adversarial tests pass;
- the digest-pinned CVM run and transport measurements are recorded; and
- the implementation and evidence PRs are merged.

### 4.3 T-03B closure

T-03B is closed only when one of these is true:

- **B1:** the browser connects directly to a WebPKI endpoint whose active key is
  governed as belonging to the approved current CVM, and no ordinary host sees
  sensitive plaintext; or
- **B2:** all sensitive browser traffic is protected by a quote-bound,
  replay-safe application channel terminating inside `darknyx-tee`, so every
  intermediate sees ciphertext only.

In both cases:

- sensitive `/orders`, cancellation/modification, fill/order stream, recovery,
  and session data are inventoried and routed consistently;
- R-01's release pins cannot be independently retargeted by replacing
  `/release.json`;
- a real browser-to-CVM deposit/order/cancel or order/settle flow passes; and
- packet/proxy instrumentation demonstrates that the ordinary trader host does
  not receive sensitive plaintext.

---

## 5. Branch, PR, and status discipline

Each phase is one independently reviewable PR. Use the branch names in the
phase table unless an already-open branch owns that exact work.

| Phase | Branch / PR topic | Depends on | Result | Status |
|---|---|---|---|---|
| 0 | `remediation/transport-preflight` | none | External assumptions resolved; trackers corrected; browser path selected or explicitly blocked | Open |
| 1 | `remediation/transport-ratls-server` | Phase 0 passthrough GO | RA-TLS server + versioned transport evidence in TEE | Open |
| 2 | `remediation/transport-ratls-node-clients` | Phase 1 | Shared actual-socket verifier used by SDK/daemon/loadgen/trader-host | Open |
| 3 | `remediation/transport-ratls-deploy` | Phases 1–2 | Passthrough deployment, live evidence, and T-03P closure | Open |
| 4 | `remediation/browser-release-integrity` | Phase 0; can overlap 1–3 | R-01 release pins made non-retargetable under the selected distribution model | Open |
| 5A | `remediation/browser-attested-ingress` | Phase 0 B1 GO + Phase 4 | Direct attested browser ingress | Open — decision-gated |
| 5B | `remediation/browser-attested-channel` | Phase 0 B1 NO-GO + Phase 4 | Quote-bound browser application channel | Open — decision-gated |
| 6 | `remediation/browser-transport-cutover` | Phase 5A **or** 5B | Plaintext proxy retired; live browser evidence; T-03B closure | Open |
| 7 | `remediation/transport-closure-assurance` | Phases 3, 4, 6 | Cross-surface assurance, final docs, tracker and parent T-03 closure | Open |

Only one of Phase 5A or 5B is implemented. Do not build both “for flexibility”
without a new product requirement and cost review.

Branches may be developed as a stack for review, but every PR must state its
base PR and remain independently understandable. Do not merge the next phase
merely because its predecessor is green; wait for the owner's review when
requested. After a predecessor merges, rebase the dependent branch onto the
new `main` and rerun its affected gates.

Every PR description must include:

- finding IDs and phase number;
- invariant restored;
- threat actor stopped and residual trust retained;
- API/wire/deployment compatibility impact;
- exact local tests and results;
- hosted CI and review disposition;
- measured cost where required;
- CVM image tag, immutable digest, compose hash, and signatures where required;
- rollback instructions;
- tracker/status changes; and
- the handoff block from §15.

Do not include unrelated dirty or untracked files. Do not add model-name or
model-generated trailers to commit messages.

---

## 6. Phase 0 — external preflight and tracker correction

- **Branch:** `remediation/transport-preflight`
- **CVM:** source work is non-billable; the production passthrough spot-check
  may need a short CPU-CVM session and must be combined with an already-planned
  window where possible.
- **Code risk:** none; this phase must not ship a transport implementation.

### 6.1 Objective

Resolve the remaining external facts before selecting implementation details.
Source inspection for both questions was completed on 2026-08-15; what remains is
listed against each.

1. **Passthrough.** Source: **GO** (§6.2) — `s`-suffix passthrough works on the
   gateway's own wildcard domain, no custom domain needed. *Remaining:* a live
   probe on the production node class, which needs a CVM window.
2. **Ingress key lifecycle.** Source/docs: the key **does** persist (§6.3).
   *Remaining:* §6.3.1 — whether the allowlist gating its release is governed by
   us. **Non-billable; answer this first**, because it decides B1/B2 and the
   lifecycle matrix is largely moot if the answer is "not ours."

Do the non-billable item (2) before spending a window on (1).

### 6.2 Passthrough source and live probe

**Source inspection is DONE (2026-08-15, v0.5.9) — do not redo it.** Results in
`transport-integrity-plan.md` §5.1:

- **SNI syntax:** `<app-id>[-[<port>][s|g]].<base_domain>`; `parse_dst_info`
  (`gateway/src/proxy.rs:85-130`) strips a trailing `s` → `is_tls = true`
  (`g` → h2; `gs` rejected).
- **How `s` selects passthrough:** `proxy.rs:151-165` — SNI is peeked from the
  ClientHello *before* any termination; `is_tls` dispatches to
  `tls_passthough::proxy_to_app`, which bridges raw TCP.
- **Custom domain NOT required** on the gateway's own wildcard domain. The
  documented prerequisite is a soft recommendation.
- **App-ID routing still applies** — same SNI parse, so the §2 fact-3 chain
  carries over. Port policy still applies (`filter_allowed_addresses`).
- **Supported contract:** documented in `phala-docs` and in `dstack/CLAUDE.md`
  ("`s` suffix: TLS passthrough"), not an undocumented detail.

Still open from source, to confirm during the live probe rather than by reading:

- whether HTTP/1.1 and WebSocket upgrades survive unchanged end-to-end;
- proxy-protocol header / client-IP behavior; and
- connection, idle, frame, and body limits on the passthrough path.

The live probe must use a disposable boot-random self-signed TLS endpoint and
record:

- the backend SPKI before deployment;
- the SPKI observed through the prod9 public route;
- proof that the gateway wildcard certificate was not presented;
- successful HTTP request and WebSocket echo through the route;
- failure of the non-passthrough hostname to authenticate as the backend;
- certificate rotation after process restart; and
- gateway/node/app identifiers and exact time of the test.

Do not send Darknyx credentials or orders during this probe. If the CVM must be
started solely for this test, record billing start/end and stop the CPU CVM as
soon as evidence is captured.

**Passthrough GO:** the actual public connection presents and proves possession
of the backend's boot-random certificate and carries both HTTP and WebSocket.

**Passthrough NO-GO:** the gateway terminates or replaces TLS, the route is not
available on the production node class, or Phala will not support it as a
stable interface. A NO-GO blocks Phases 1–3 and triggers a revised programmatic
design—most likely direct custom ingress or application-layer encryption.

### 6.3 dstack-ingress evidence

**Partially resolved (2026-08-15).** Confirmed from the documented compose
(`setup-custom-domain.mdx:48-75`): `cert-data:/etc/letsencrypt` persists
certificates **and private keys**; `evidences:/evidences` persists evidence
files, mounted read-only by the app. **Ingress evidence is therefore written at
issuance, not on demand.** Source is not public (`Dstack-TEE/dstack-ingress` and
`Phala-Network/dstack-ingress` both 404); the image is
`dstacktee/dstack-ingress:2.2@sha256:d05a7b34…` on Docker Hub.

The mitigating fact is §2 fact 10: the volume's disk key is released only to a
compose_hash on the KMS allowlist. **So the remaining question is not "does the
key persist" — it does — but "who governs the allowlist that gates it."**

#### 6.3.1 The question that now decides B1

**Does our Phala Cloud deployment use on-chain KMS governance, and do we control
our own app's compose-hash allowlist?**

`dstack/CLAUDE.md` documents `DstackApp` as a "per-app authorization contract
controlling device IDs and compose hash whitelist", and
`phala-docs/dstack-cloud/register-enclave-measurement.mdx:12` states KMS checks
measurements against an on-chain allowlist before dispatching keys. **But the
`dstack-cloud/` documentation may describe a different product line (GCP/Nitro)
than our `phala-cloud` deployment.** Determine, for the CVM we actually run:

- which key provider is in effect (`key_provider_info` in `/.dstack/app-info`);
- whether the compose allowlist is an on-chain `DstackApp` contract or a
  Phala-operated API;
- who holds the authority to add a compose hash; and
- what happens to the disk key across a compose change under the same `app_id`.

This is cheap, non-billable, and it gates the B1/B2 decision. **Answer it before
the lifecycle matrix below** — if we do not govern the allowlist, B1 inherits the
same "somebody else's governance" weakness as the gateway path and the matrix is
largely moot.

Obtain the exact source commit, build recipe, SBOM/provenance, and image digest
corresponding to the recommended ingress image. A digest without reviewable
source is not enough for a mainnet TCB addition.

Trace these paths in source:

- TLS and ACME private-key generation;
- certificate and key persistence;
- volume encryption and key-release policy;
- startup after a normal process restart;
- startup after a CVM reboot;
- startup after a compose/image change under the same app ID;
- evidence generation and renewal;
- CAA account creation/update;
- request forwarding and plaintext visibility; and
- whether `/evidences/` is generated by, signed by, or merely served by the
  process holding the active key.

If source is unavailable, use a disposable domain/CVM and run a lifecycle
matrix:

| Transition | Observe |
|---|---|
| Fresh deployment | SPKI, quote measurement, compose hash, evidence time |
| Process restart, same compose | whether SPKI persists; whether evidence refreshes |
| CVM cold boot, same compose | same observations |
| Redeploy with changed compose/image under same app ID | whether old key is readable and served |
| Certificate renewal | key rotation, evidence rotation, CAA and CT state |

**B1 GO** requires a defensible chain from the active browser TLS key to the
approved current workload. Two routes qualify, and the second is now the likely
one:

- a fresh current-boot quote over the active key; **or**
- **governed key release** — the persisted key is decryptable only by a
  compose_hash on an allowlist **we** govern, with an explicitly governed upgrade
  path. §6.3.1 decides whether this route is available to us.

**B1 NO-GO** if a differently measured current workload can serve the persisted
key while replaying historical evidence — including the case where the allowlist
that would prevent it is operated by someone else — or if the exact image cannot
be reviewed/reproduced. Select Phase 5B unless the team elects to build/fork an
ingress that restores the missing property.

### 6.4 Documentation and tracker corrections

This PR must correct, without claiming implementation:

- `docs/transport-integrity-plan.md`: mark the historical gateway-evidence
  recommendation as superseded and record the key-persistence finding.
- `audits/audit_6/tracker.md`: correct the false statement that Option A must
  break the existing `/attestation` layout; record boot-random rather than
  deterministic RA-TLS keys.
- `audits/residual-backlog.md`: split execution evidence into T-03P and T-03B
  while keeping parent T-03 open.
- `docs/tee-attestation-flow.md` and relevant internal architecture docs:
  distinguish the current gateway path, proposed RA-TLS path, and browser path.
- User-facing GitBook only where it currently makes a false security claim. Do
  not publish internal preflight uncertainty or implementation minutiae.

### 6.5 Tests and deliverables

- A checked-in preflight evidence section or companion report with commands,
  timestamps, versions, and results.
- Source links pinned to commits/digests, not mutable branches or tags alone.
- Mutation/check showing the tracker no longer calls the existing
  `/attestation` migration mandatory.
- Markdown link and formatting checks.
- No product dependency, protocol, or compose change.
- Explicit GO/NO-GO for passthrough and B1.

### 6.6 Rollback

Documentation-only. Revert the PR if evidence is disproved, but preserve the raw
commands/results and explain the correction rather than deleting inconvenient
evidence.

---

## 7. Phase 1 — in-process RA-TLS server

- **Branch:** `remediation/transport-ratls-server`
- **Prerequisite:** passthrough GO
- **CVM:** not required for code-complete status; required in Phase 3.

### 7.1 Objective

Add an RA-TLS listener to `darknyx-tee` whose key is unique to the current
process and whose transport attestation binds the exact endpoint identity to
the same boot, signer set, and governed compose.

### 7.2 Canonical transport manifest

Define one versioned Rust/TypeScript wire contract, for example:

```text
TransportAttestationManifestV1 {
  protocol_version,
  app_id,
  instance_id,
  boot_session_id,
  tls_spki_sha256,
  signer_set_sha256,
  transport_mode,
}

report_data[0..32]  = caller_nonce
report_data[32..64] = SHA256(
  "darknyx/transport-attestation/v1" || canonical_manifest_bytes
)
```

The final field list must be frozen in a short ADR inside this PR. Do not rely
on JSON object ordering. Use a fixed canonical byte encoding with a domain tag
and pinned Rust/TS vectors.

The quote event log remains the source of the measured compose hash; the
manifest does not replace RTMR replay. The manifest links the values clients
otherwise might obtain from unrelated valid responses.

### 7.3 Server requirements

- Generate an Ed25519 or ECDSA TLS key with the process CSPRNG at boot.
- Construct a self-signed certificate with a short validity appropriate for a
  boot-scoped identity.
- Never persist or deterministically rederive the key.
- Zeroize temporary private-key buffers where the selected library permits.
- Serve TLS 1.3 with a narrow modern cipher configuration.
- Provide an unauthenticated, tightly rate-limited transport-attestation route
  that accepts exactly one 32-byte nonce and returns manifest, quote, event log,
  and required metadata.
- Generate the quote from the server's in-memory SPKI, current
  `boot_session_id`, and current full signer set; never accept those fields from
  the request.
- Ensure the route is available before authentication but no privileged or
  sensitive route bypasses existing auth after TLS verification.
- Keep the existing plaintext listener only for an explicitly internal path
  during migration. Production compose cutover happens in Phase 3.
- Fail production startup if RA-TLS mode is selected and key/certificate/quote
  initialization fails.
- Emit only public fingerprints and protocol versions in logs—never private key
  material or full credentials.

### 7.4 API and compatibility

- Add the transport-attestation schema to `docs/tee-api-openapi.yaml`.
- Preserve `/attestation` byte-for-byte unless a separate, independently
  justified change is approved.
- Version the transport contract from its first release.
- If a temporary `legacy` transport mode exists, it must be explicit in `/info`
  and production release assembly must reject it.
- No order canonical, circuit, vault, or settlement payload change.

### 7.5 Required tests

Unit/parity:

- Rust/TS canonical manifest byte equality and fixed hash vector.
- Every manifest field perturbed independently changes the bound digest.
- Domain/version substitution is rejected.
- Signer ordering changes the digest.
- An empty, duplicate, or malformed signer set is rejected.
- Nonce must be exactly 32 bytes.

Server lifecycle:

- Two connections in one boot see the same SPKI and boot session.
- A process restart produces a different SPKI and boot session.
- No key file is created in the state directory or container filesystem.
- Quote failure prevents production RA-TLS readiness.
- Rate and response-size bounds apply to the new public route.
- TLS versions/ciphers outside policy fail.

Adversarial:

- Manifest names a different SPKI.
- Quote is valid for a different boot/session.
- Quote is valid for the right SPKI but a different signer set.
- Quote/event log recovers an unapproved compose.
- Old boot evidence replayed after restart.
- A gateway or test proxy relays a genuine transport-attestation response behind
  a different self-signed certificate.

Mutation-test the SPKI, nonce, boot-session, and signer-set guards before
accepting the test suite.

### 7.6 Validation and rollback

Run the relevant Rust workspace, artifact-required TEE tests, OpenAPI parse, and
dependency audit. Measure local handshake and quote-generation latency so Phase
3 has a pre-CVM expectation.

Rollback is the prior digest in devnet only. A production fallback to legacy
gateway termination reopens T-03P and must pause external trading rather than
silently downgrade.

---

## 8. Phase 2 — actual-socket verification for Node clients

- **Branch:** `remediation/transport-ratls-node-clients`
- **Prerequisite:** Phase 1 contract frozen
- **CVM:** not required for code-complete status; required in Phase 3.

### 8.1 Objective

Implement the verified transport once in the Node-capable SDK layer and consume
it from every programmatic client. Do not create four subtly different
certificate verifiers.

### 8.2 Transport adapter requirements

The adapter must:

- open the real TLS socket used by HTTP or WebSocket;
- capture that socket's peer certificate/SPKI;
- obtain and verify transport evidence without releasing the socket to callers
  that can send secrets first;
- perform DCAP verification, RTMR/event-log replay, compose allowlist check,
  nonce check, manifest hash check, SPKI comparison, boot-session check, and
  full on-chain signer-set comparison;
- mark only that socket verified;
- verify every newly created pooled connection;
- reverify every WebSocket reconnect;
- disable redirects on sensitive requests;
- close immediately on certificate/evidence mismatch;
- expose typed failure reasons without leaking credentials or untrusted bodies;
  and
- cap time, body size, event-log entries, and certificate/evidence sizes before
  expensive parsing.

Do not implement “probe then fetch.” DNS rebinding, load balancing, or a relay
can make the probe and request reach different peers.

Node-only code must not enter the browser bundle. Use an explicit Node export or
adapter boundary and keep browser-compatible SDK modules free of `node:tls`,
filesystem, and Node-only certificate types.

### 8.3 Consumers

- **Daemon:** startup, finalized attestation refresh, place/modify/cancel,
  recovery reads, and `/v1/stream` all use the verified transport. Mismatch
  pauses new trading while preserving cancellation/reconciliation policy.
- **Loadgen:** uses the same adapter so load tests exercise the production
  connection and reconnect path. It may expose an explicit insecure local-test
  flag, but the report must label it and production endpoints must reject it.
- **Trader-host upstream:** uses the adapter for any retained CVM request. This
  secures only the upstream hop; it is not T-03B closure.
- **Direct Node SDK consumers:** receive a supported construction API rather
  than copying daemon internals.

### 8.4 Required tests

Local real-socket tests must cover:

- valid HTTP request after verification;
- credentials are absent from the wire before verification completes;
- valid `/v1/stream` login and message flow;
- wrong peer SPKI with relayed genuine quote;
- right SPKI with wrong manifest;
- stale boot and stale certificate;
- unapproved compose;
- signer-set order, member, and cardinality mismatch;
- quote corruption and DCAP failure;
- malformed/oversized certificate, manifest, quote, and event log;
- redirect to another origin;
- DNS target change between connections;
- HTTP pool opening a second connection;
- WebSocket reconnect to a substituted endpoint;
- timeout during verification;
- simultaneous connections and bounded verification work; and
- no Node-only module in the browser build graph.

Include a cuckoo-proxy test that can relay every HTTP response from a genuine
test enclave but cannot pass because its socket certificate differs.

### 8.5 Measurements

Record locally, using the same harness that Phase 3 will run:

- TLS handshake p50/p95;
- transport-attestation p50/p95;
- cold HTTP first-request p50/p95;
- warm verified HTTP p50/p95;
- WebSocket connect/login/reconnect p50/p95;
- RSS at 1, 100, and configured-limit sockets;
- CPU under idle/ping-only connections; and
- verifier CPU/time split from network time.

Set regression thresholds before the CVM run, from these baselines—not after
seeing the live result. Any threshold exception requires a written disposition.

### 8.6 Rollback

The adapter may retain an explicitly named dev-only legacy connector until
Phase 3. Production daemon/trader-host configuration must fail closed if asked
to use it after cutover.

---

## 9. Phase 3 — programmatic deployment cutover and T-03P closure

- **Branch:** `remediation/transport-ratls-deploy`
- **Prerequisites:** Phases 1 and 2 merged or reviewed as a stable stack
- **CVM:** mandatory, CPU unless a separate GPU objective is explicitly added.

### 9.1 Deployment changes

- Build a fresh TEE image from the exact reviewed commit.
- Pin the image by immutable digest in every relevant compose.
- Publish only the RA-TLS application port through the supported passthrough
  route.
- Make plaintext HTTP reachable only inside the CVM network if it remains at
  all; prove the public plaintext route is closed.
- Update release/runtime configuration to the passthrough endpoint.
- Add the RA-TLS compose hash to the governed client/release allowlist.
- Rebuild no circuit and redeploy no Solana program unless an unrelated explicit
  requirement appears—transport does not change either.
- Recheck K shard signers. Do not assume they changed; rotate/fund only if the
  derived set differs from `VaultConfig.tee_pubkeys`.

### 9.2 Live choreography

Follow `docs/cvm-run-runbook.md` and discover the CVM/app/gateway dynamically.
Use the private Helius endpoint from encrypted environment, never the public
Solana devnet endpoint.

1. Record billing start, current CVM ID/node, deployed source, image digest,
   compose hash, and K signer set.
2. Deploy and confirm the plaintext listener is not publicly reachable.
3. Capture the peer certificate through the `s` route and match it to the
   enclave's boot SPKI.
4. Run the Node SDK transport negative suite against a deliberate relay/wrong
   certificate.
5. Run daemon startup and attestation refresh through RA-TLS.
6. Run trader-host live-CVM transport tests through RA-TLS.
7. Run the loadgen in the correct mint regime, collecting accepted/rejected
   latency separately.
8. On a fresh tree/cold boot, run one real `cvm-settle-e2e` test so an accepted
   order and `/v1/stream` lifecycle traverse RA-TLS and settle on-chain.
9. Capture witness, prove-step, full-prove, settle-stage, and total timings even
   though the transport change should not affect proving.
10. Run the required connection/RSS/latency measurements.
11. Exercise restart: verify old certificate/evidence is rejected and the
    client reconnects only after validating the new boot.
12. Drain if settlement state exists, verify safe-to-stop, then stop the CPU CVM
    and record billing end.

Run only one leaf-count test per freshly reset tree and cold boot, as required by
the CVM runbook.

### 9.3 Pass criteria

- Actual peer SPKI equals the quote-bound manifest SPKI.
- DCAP, event-log compose, boot session, and full signer-set checks pass.
- A relayed genuine quote behind another certificate fails before credentials.
- Old-boot reconnect fails and fresh-boot reconnect succeeds.
- Public plaintext port is unreachable.
- Daemon, trader-host upstream, loadgen, and real settle succeed.
- No unexplained regression beyond the thresholds frozen in Phase 2.
- Image digest, compose hash, signatures, logs, and timings are attached to the
  tracker.

T-03P moves `Open -> In progress -> Code complete -> Closed` only as evidence
permits. Green local code without the live run is `Code complete`, not `Closed`.

### 9.4 Rollback

Keep the prior digest and compose. A rollback to it is allowed for devnet
recovery but restores the T-03P exposure; external trading must remain paused.
Never automatically retry through the legacy gateway-terminated endpoint.

---

## 10. Phase 4 — browser release integrity (R-01)

- **Branch:** `remediation/browser-release-integrity`
- **Can overlap:** Phases 1–3 after Phase 0
- **CVM:** no, unless the selected release design explicitly requires one.

### 10.1 Objective

Prevent `/release.json` from independently retargeting the compose hash, vault
program, artifact key, oracle mode, or trading endpoint while the content-hashed
application remains unchanged.

At minimum, bake the security-critical release configuration into the
content-addressed application build or authenticate it through a release root
that is independent of the mutable file being verified. A signature checked
only by a key delivered through the same mutable origin is not, by itself, an
independent origin-authenticity guarantee.

The PR must explicitly state the selected distribution trust model—for example
an independently pinned bootstrap, governed immutable deployment, signed
release transparency log, native wrapper/extension, or another reviewed
mechanism. Do not let ambiguous “signed” wording hide a circular verifier.

### 10.2 Requirements

- Compose hash, vault program ID, artifact-signing key, oracle mode, transport
  mode/version, and allowed origins/endpoints move atomically with the app
  release.
- Replacing only `/release.json` cannot retarget the application.
- The UI cannot show “Attested” unless release integrity and active transport
  verification both pass.
- Rollback is an explicit signed/governed release, not a mutable endpoint edit.
- CSP, SRI, cache policy, service-worker behavior, and content-addressed asset
  names agree with the release model.
- Document which actor can publish a release and the approval quorum.

### 10.3 Required tests

- Security pin changed without rebuilding/authorizing the app -> refuse.
- Endpoint changed alone -> refuse.
- Artifact key, program ID, oracle mode, or transport version changed alone ->
  refuse.
- Stale but valid older release follows the explicit rollback/version policy.
- Cache mixing HTML, JS, and release metadata from different versions -> refuse.
- Offline/reload/service-worker paths preserve the same pins.
- “Attested” UI remains false during release or transport failure.

### 10.4 Closure

R-01 can close after its independent review, hosted browser tests, and merge.
Closing R-01 does not close T-03B; it establishes that the browser code enforcing
T-03B is the release the user intended to run.

---

## 11. Phase 5A — direct attested browser ingress

- **Branch:** `remediation/browser-attested-ingress`
- **Choose only if:** Phase 0 records B1 GO
- **Prerequisite:** Phase 4 release contract.

### 11.1 Objective

Make the browser's sensitive connection terminate at a governed ingress inside
the approved CVM, with no ordinary host handling plaintext order or stream
traffic.

### 11.2 Requirements

- Exact ingress source is reviewable and the image is reproducibly digest-pinned.
- Active TLS key has the current-workload binding approved in Phase 0.
- Use a dedicated subdomain, not the apex.
- DNS credentials are least-privilege encrypted inputs and never enter compose
  hash or logs.
- CAA restricts issuance to the intended CA/account; verify the literal DNS
  record after propagation.
- CT monitoring alerts on every unexpected certificate/key.
- Certificate renewal and CVM restart have tested evidence transitions.
- Browser REST and `/v1/stream` connect directly to the ingress.
- Strict CORS allows only the governed application origin and required methods,
  headers, and WebSocket behavior.
- Session provisioning gives the browser only the minimum scoped capability;
  retained trader-host code cannot use it to recover order/fill plaintext.
- Trader-host sensitive proxy routes are removed or return a permanent error.
- Internal plaintext forwarding from ingress to matcher remains inside the same
  attested CVM network and is unreachable from the public route. If the chosen
  threat model requires process-level isolation inside the compose, use local
  RA-TLS rather than plaintext between sidecar and matcher.

### 11.3 Required tests

- Real browser WebPKI connection and WebSocket upgrade.
- Wrong origin, wildcard origin, `null` origin, preflight confusion, and racing
  origin changes rejected.
- Direct `/orders`, cancel/modify, recovery reads, and stream login work.
- Old/foreign certificate and evidence rejected by the external release gate or
  monitor before route publication.
- Renewal succeeds without accepting an unbound key.
- Restart/compose-change lifecycle matches Phase 0's approved policy.
- Trader-host logs and instrumented proxy contain no sensitive request/stream
  plaintext.
- Public gateway/plaintext matcher routes are not usable by the browser release.

### 11.4 Rollback

Rollback only to an earlier governed ingress release with still-valid DNS and
certificate evidence. Never repoint the browser release to the old plaintext
trader-host proxy as an automatic fallback.

---

## 12. Phase 5B — quote-bound browser application channel

- **Branch:** `remediation/browser-attested-channel`
- **Choose if:** Phase 0 records B1 NO-GO, or the owner chooses cryptographic
  end-to-end protection over ingress governance
- **Prerequisite:** Phase 4 release contract.

### 12.1 Objective

Protect browser-sensitive traffic end to end between the authentic browser
release and `darknyx-tee`, even while trader-host and gateway relay it.

### 12.2 Cryptographic contract

Use a reviewed HPKE implementation and a versioned protocol. The enclave KEM
private key must be boot-random, memory-only, and distinct from custody, signing,
TLS, and account-authentication keys.

A fresh quote binds a canonical channel manifest containing at least:

- protocol and ciphersuite version;
- KEM public key;
- full signer-set hash;
- `boot_session_id`;
- app/instance identity as needed; and
- expiry/rotation policy.

The channel must define:

- separate client-to-server and server-to-client keys/nonces;
- monotonic counters with no nonce reuse;
- replay and out-of-order policy;
- method, normalized route, direction, account/session, boot session, protocol
  version, and counter in AEAD associated data;
- authentication token placement so relays cannot steal a reusable credential;
- reconnect and rekey behavior;
- explicit key expiry and old-boot refusal;
- bounded ciphertext/plaintext/frame sizes;
- padding policy sufficient to avoid claiming size privacy that is not provided;
- generic external errors that do not create a decryption oracle; and
- protected server-to-client fills/order updates as well as order submission.

Inventory every sensitive REST and stream message. A partial implementation that
encrypts `POST /orders` while leaving fill frames, cancellations, recovery data,
or bearer tokens visible is not closure.

### 12.3 Browser/trader-host boundaries

- Key agreement and encryption live in the custody/crypto Worker, not mutable UI
  component state.
- Plaintext never crosses the Worker boundary except the minimum data needed for
  rendering and user confirmation.
- Trader-host is a bounded blind relay with no decrypt capability.
- Relay logs contain route-independent metadata only where possible.
- Backpressure, reconnect, and cancel-on-disconnect semantics remain correct
  through the encrypted framing layer.

### 12.4 Required tests

KAT/parity:

- Rust/browser HPKE vectors for setup, request, response, and rekey.
- Canonical associated-data vectors.

Adversarial:

- wrong attested KEM key;
- genuine quote relayed with another key;
- replayed request or response;
- duplicate, skipped, wrapped, or reordered counter;
- direction reflection;
- route or HTTP-method substitution;
- account/session/token substitution;
- old boot and post-reconnect ciphertext;
- truncated, extended, oversized, and bit-flipped ciphertext;
- malformed encapsulated key;
- concurrent stream and request counter handling;
- server error timing/body uniformity; and
- chosen-ciphertext attempts never expose distinct decrypt errors.

End-to-end:

- instrument trader-host and assert a unique plaintext marker from an order and
  fill never appears in request bodies, WS frames, logs, errors, or crash output;
- valid deposit/order/cancel and order/fill lifecycle;
- forced reconnect establishes a fresh channel and rejects old frames;
- cancel-on-disconnect retains its intended semantics.

### 12.5 Rollback

The release and enclave must negotiate an exact allowed protocol version. Do not
fall back to plaintext if negotiation fails. Rollback requires a governed prior
release in which both sides support the same protected protocol.

---

## 13. Phase 6 — browser cutover, live validation, and T-03B closure

- **Branch:** `remediation/browser-transport-cutover`
- **Prerequisite:** Phase 5A or 5B, plus Phase 4
- **CVM:** mandatory.

### 13.1 Cutover

- Assemble one immutable browser/trader-host/CVM release set.
- Pin all images and security configuration.
- Delete or disable the old sensitive plaintext proxy routes.
- Update OpenAPI and GitBook from the user's perspective, without exposing
  internal operational secrets.
- Make the UI's attestation indicator reflect both release and transport state.
- Preserve wallet/custody Worker isolation.

### 13.2 Live browser choreography

Use a fresh controlled devnet account and the private Helius RPC endpoint.

1. Load the exact production browser build.
2. Verify release integrity before enabling wallet/private-vault actions.
3. Establish the selected browser transport and display verified status.
4. Connect the wallet and unlock the private vault.
5. Deposit a small devnet test amount and confirm the on-chain leaf increment.
6. Submit an order through the browser and confirm acceptance through the
   authenticated order stream/API state.
7. Refresh the page and verify open-order persistence/recovery.
8. Cancel the order, or place a controlled crossing counter-order and confirm
   settlement/fill delivery.
9. Exercise a transport reconnect and confirm fresh verification/key agreement.
10. Attempt the old trader-host sensitive proxy endpoints; they must fail.
11. Inspect trader-host and gateway-visible captures/logs for the unique
    plaintext markers; none may appear.
12. Record leaf counts, order IDs, transaction signatures, relevant stream
    sequence numbers, attestation identity, image digest, compose hash, and
    timings.

For B1, additionally capture current certificate, evidence, CAA, and CT state.
For B2, capture protocol version, attested KEM fingerprint, reconnect/rekey
result, and ciphertext-only relay evidence.

### 13.3 Measurements

- Browser cold transport establishment p50/p95.
- Wallet-to-ready and vault-unlock-to-ready latency.
- Order click-to-TEE-accept p50/p95.
- Stream reconnect-to-resynchronised p50/p95.
- Browser Worker CPU and peak memory during channel setup.
- Additional bytes per REST request and stream frame.
- Trader-host CPU/RSS and connection counts.
- Existing client proof-generation timings, to prove transport did not distort
  the previously measured proving path.

### 13.4 Closure

T-03B is `Closed` only after source, local/hosted tests, CodeRabbit disposition,
digest-pinned live evidence, and merge. Parent T-03 remains open until Phase 7
confirms T-03P, T-03B, and the required R-01 evidence together.

### 13.5 Rollback

Rollback to a prior protected browser release only. If no protected version is
available, pause browser trading; never silently re-enable the plaintext proxy.

---

## 14. Phase 7 — release assurance and parent closure

- **Branch:** `remediation/transport-closure-assurance`
- **Prerequisites:** T-03P Closed, T-03B Closed, R-01 Closed.

### 14.1 Cross-surface audit

Trace every production network path from caller to `darknyx-tee`:

- Node SDK and daemon REST;
- daemon `/v1/stream`;
- loadgen;
- trader-host upstream;
- browser REST and WebSocket;
- session/account provisioning;
- recovery and inclusion reads;
- admin/operator surfaces, explicitly separated from public clients; and
- any fallback, health-check, debug, or legacy endpoint.

For every path, record:

- TLS/application-channel terminator;
- components seeing plaintext;
- identity verified;
- key lifecycle and persistence;
- downgrade/fallback behavior;
- authentication sent before/after verification;
- reconnect behavior; and
- closure test/evidence.

Any unexplained production path blocks closure.

### 14.2 Final adversarial matrix

- Cuckoo proxy relaying genuine matcher evidence.
- Gateway certificate mis-issuance.
- Old gateway or ingress key replay.
- Wrong app ID, right app ID/wrong compose, and right compose/wrong boot.
- Multi-instance routing under one app ID.
- Signer-set substitution/reordering.
- HTTP redirect and WebSocket endpoint substitution.
- DNS change between connections.
- Certificate/channel rotation during reconnect.
- Plaintext legacy endpoint discovery.
- Browser release metadata retargeting.
- Trader-host compromise under B1 or B2's stated threat model.
- Oversized/slow evidence and connection exhaustion.

### 14.3 Documentation and tracker closure

Update:

- `audits/audit_6/tracker.md` with T-03P/T-03B evidence and parent closure;
- `audits/residual-backlog.md` canonical status;
- `docs/transport-integrity-plan.md` with a link to the implemented outcome;
- `docs/tee-attestation-flow.md` and `docs/tee-architecture.md` as-built paths;
- `docs/ARCHITECTURE.md` deployment boundary;
- `docs/tee-api-openapi.yaml` final transport surfaces;
- `docs/cvm-run-runbook.md` deployment, verification, and rollback;
- package READMEs for Node/browser construction; and
- `docs/gitbook/` user-facing security model and recovery behavior.

Do not preserve superseded claims merely to avoid editing them. Do preserve the
historical research record and clearly label what was disproved.

### 14.4 Final closure evidence

- All local gates from `AGENTS.md` appropriate to the touched surfaces.
- Hosted CI green and every review comment disposition recorded.
- Dependency audits green or explicitly blocked with no false success claim.
- Exact source commit, image digest, compose hash, signer set, and release ID.
- T-03P and T-03B live evidence.
- R-01 release evidence.
- Latency/RSS/image-size report from the audit requirement.
- Rollback drill that fails closed rather than falling back to plaintext.
- Independent security review recommended before mainnet/external users.

Only then move parent T-03 to `Closed`.

---

## 15. Continuation directive and handoff template

### 15.1 Rules for any continuing agent

1. Read `AGENTS.md`, this document, `docs/transport-integrity-plan.md`, the T-03
   sections of `audits/audit_6/tracker.md`, R-01 in
   `audits/audit_8/audit_8_findings.md`, and the current residual backlog.
2. Verify the current branch, `main` commit, dirty files, open PR stack, CVM
   status, and billing state before acting.
3. Take only the earliest phase whose prerequisites are met. Do not start Phase
   1 before passthrough GO or choose 5A before B1 GO.
4. Preserve unrelated dirty/untracked files. The `dstack/` and `phala-docs/`
   working copies are evidence trees unless the owner explicitly asks to commit
   them.
5. Update the execution-state table below whenever a phase changes state.
6. Move a phase only as far as evidence supports. `Code complete` is not
   `Closed` when CVM or browser evidence remains.
7. Use the user's private Helius endpoint for devnet/CVM work. Do not fall back
   to `https://api.devnet.solana.com`.
8. Do not start a billable CVM merely to avoid thinking through a local test.
   When a CPU CVM is required, work continuously, drain safely if necessary,
   capture evidence, and stop it promptly. Never apply the CPU stop rule to a
   prepaid on-demand GPU window.
9. Do not implement gateway certificate evidence as T-03 closure.
10. Do not use deterministic dstack-derived keys for boot-fresh transport
    identity.
11. Do not send any credential on an unverified provisional TLS connection.
12. Do not mark the browser secure merely because trader-host verifies its own
    upstream RA-TLS connection.

### 15.2 Execution state

| Field | Current value |
|---|---|
| Last verified `main` | `fc88040` on 2026-08-15 |
| Active phase | none — plan authored, implementation not started |
| Active branch / PR | none |
| Next phase | Phase 0 — external preflight and tracker correction |
| Passthrough decision | **Source GO** (v0.5.9, §6.2). Live probe OPEN — needs one CVM window |
| Browser path decision | OPEN — gated on §6.3.1 (do we govern our own compose allowlist?), which is non-billable and should be answered first |
| Ingress lifecycle | Persistence CONFIRMED; governance of the gating allowlist UNKNOWN — see §6.3.1 |
| T-03P | Open |
| T-03B | Open |
| R-01 | Open |
| Parent T-03 | Open |
| CVM/billing state | Must be discovered live; do not infer from this document |
| Last updated | 2026-08-15 |

### 15.3 Handoff block

Copy this block into the tracker/PR before switching agents:

```text
Transport remediation handoff

Main commit reviewed:
Active phase:
Phase status: Open | In progress | Code complete | Closed | Blocked
Branch:
PR and base PR:
Latest commit:

Decisions already proven:
- Passthrough: OPEN | GO | NO-GO
- Browser path: OPEN | B1 | B2
- Exact dstack version:
- Exact ingress source/image digest, if applicable:

Changes made:
Files intentionally changed:
Unrelated dirty/untracked files preserved:

Local commands and results:
Hosted CI status:
Review comments and dispositions:

Live evidence:
- CVM ID/name/node:
- Billing started/stopped:
- Image tag and digest:
- Compose hash:
- K signer set:
- Gateway/ingress endpoint:
- Transactions/order IDs/stream sequences:
- Latency/RSS/proving measurements:

Secrets/environment cleanup performed:
Rollback tested/documented:

Outstanding blocker or next exact action:
User approval required before:
```

---

## 16. Definition of done

The remediation is finished only when all of the following are true:

- Programmatic clients use current-boot RA-TLS bound to the actual socket.
- Browser-sensitive traffic either terminates at a verified governed ingress or
  is protected end to end by an attested application channel.
- Trader-host cannot observe sensitive browser plaintext under the selected
  architecture.
- The public plaintext matcher route is gone.
- Every reconnect repeats the relevant verification.
- Browser release pins cannot be independently retargeted.
- All negative/cuckoo/replay/downgrade tests pass.
- CVM and real-browser evidence is attached to immutable release artifacts.
- Performance and memory costs are measured and accepted.
- Public and internal documentation describe the as-built design accurately.
- T-03P, T-03B, R-01, and parent T-03 are closed with evidence—not merely marked
  code complete.
