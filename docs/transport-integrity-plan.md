# Transport integrity (T-03) — research record

**Status: research record. Superseded as a plan.** The architecture and PR
sequence now live in
[`transport-integrity-remediation-plan.md`](transport-integrity-remediation-plan.md).
This document preserves the investigation, the measured evidence, and — as an
explicit part of its value — **the conclusions that were disproved during
review**.

- **Created:** 2026-08-15. **Revision 3.**
- **Upstream baseline:** `dstack` at tag **`v0.5.9`** (`282eeb27`), the release
  Darknyx CVMs run; `phala-docs` at **`55ecaa3`** (2026-08-10).
- **Repository baseline:** `main` at `fc88040`.
- **Findings:** T-03 (parent), split into T-03P / T-03B; adjacent `R-01`
  (`audits/audit_8/audit_8_findings.md`).

> **Read this first.** Revision 1 of this document recommended gateway
> certificate-evidence verification as the primary fix and asserted it "closes
> both halves of T-03's residual." **That conclusion was wrong** and was
> reversed in revision 2 after review. The reasoning is preserved in §6 because
> the *way* it failed is the most transferable lesson here: the analysis read the
> certificate **issuance** path and the **verification** path, and never asked
> what happens on the next boot.

---

## 0. How to review this document

Claims are tagged so each can be rejected independently:

| Tag | Meaning |
|---|---|
| **[MEASURED]** | Reproduced against live infrastructure. Commands included. |
| **[CODE]** | Read from source at the pinned version. Line numbers drift between dstack releases; the surrounding assertion is the claim. |
| **[INFERRED]** | Reasoning on top of the above. |
| **[OPEN]** | Not established. Listed so it is not mistaken for a conclusion. |

Two rounds of adversarial review have already run (§7). Both found substantive
errors. A third reviewer should assume the same and start at §5 — the preflight
results are the newest material and have had the least scrutiny.

---

## 1. Why T-03 was reopened

`audits/residual-backlog.md:385` records the trigger as fired on 2026-08-15 when
`packages/browser-client` and `packages/trader-host` shipped —
`audits/audit_6/tracker.md:438` trigger 2, "a browser-based client enters scope."

The audit deferred T-03 in 2026-07 because the fix depended on an unmade product
decision. Shipping the browser made that decision. **But both options the audit
costed were evaluated against an architecture that no longer describes the
system**, and one of the two cost-table entries was factually wrong (§6.2).

---

## 2. What the browser actually changed

### 2.1 The browser never contacts the enclave **[CODE]**

`packages/browser-client/scripts/assemble-production-release.mjs:184-185` pins
the release to same-origin endpoints:

```js
gateway_url: new URL("/api/darknyx/venue/", origin).toString(),
rpc_url:     new URL("/api/darknyx/rpc",    origin).toString(),
```

`trader-host/src/security.ts` emits `connect-src 'self'
https://pccs.phala.network`, and `live-proxy.ts:331-336` fails startup unless the
release endpoints are exactly those same-origin paths. The browser's only network
peers are its own origin and Intel's PCCS.

```
browser ──TLS──► reverse proxy ──► trader-host ──HTTPS──► dstack gateway ──WG──► matcher CVM
                                  (ordinary Node process)    (TDX CVM)          (TDX CVM)
                                   plaintext order intent
```

`deploy/trader-host/README.md` states this plainly: *"one ordinary host process
proxies the browser to the separately deployed CVM."*

### 2.2 What that hop can and cannot do **[CODE]**

`live-proxy.ts:234` allowlists `GET /attestation`; `venueRoute:257` relays
`POST /orders`; `install():580` relays `/v1/stream`. No in-band envelope exists,
so order bodies and stream frames transit trader-host in plaintext.

| Preserved | Broken |
|---|---|
| Cannot forge orders — client-signed, intake-verified | Sees all order intent in plaintext, in real time |
| Cannot fabricate durable state — chain reconciliation is authority | Can withhold, delay, or reorder |
| Cannot touch custody — seed never leaves the Worker | Can substitute the matching backend behind a relayed genuine quote |

**[INFERRED]** T-03's stated residual — *"a party holding a valid gateway-domain
certificate can front a different backend"* — previously required a mis-issued
certificate. For browser users the precondition is now the normal deployment
topology.

### 2.3 The published security claim is false for browser users **[CODE]**

`docs/gitbook/api/transport-and-attestation.md:13` states *"No ordinary server or
cloud operator sees your order intent"*; `:41` captions its diagram *"no
untrusted hop."* `audit_6` slice 3 corrected this exact page in 2026-07 and
treated it as mandatory-immediately. The browser client made it false again.

`trader-host` appears in **zero** security documents — not `CRYPTOGRAPHY.md`, the
design record, `docs/tee-attestation-flow.md`, or `docs/gitbook/`.

---

## 3. Live evidence: the gateway publishes cert-bound attestation

All **[MEASURED]** on 2026-08-15 against prod9. No CVM started; non-billable.

```sh
GW=gateway.dstack-pha-prod9.phala.network
curl -s "https://$GW/.dstack/index"     # {"type":"dstack gateway","paths":[...]}
curl -s "https://$GW/.dstack/acme-info" -o acme-info.json    # 104,558 B, HTTP 200
```

**The binding reproduces exactly** — `report_data == sha512("zt-cert:" ‖ SPKI_DER)`
on the full 64 bytes, for both quoted keys:

```sh
for i in 0 1; do
  PK=$(jq -r ".quoted_hist_keys[$i].public_key" acme-info.json)
  H=$( { printf 'zt-cert:'; echo "$PK" | xxd -r -p; } | shasum -a 512 | awk '{print $1}')
  RD=$(jq -r ".quoted_hist_keys[$i].quote" acme-info.json | jq -r '.report_data')
  [ "$H" = "$RD" ] && echo "key[$i] MATCH"
done            # both MATCH
```

**The served certificate is in the quoted set**, and it is a wildcard
(`CN=*.dstack-pha-prod9.phala.network`), so it also covers
`<app-id>-8080.dstack-pha-prod9…` — the daemon's real endpoint.

Confirmed in source at v0.5.9: `gateway/src/distributed_certbot.rs:443` uses
`QuoteContentType::Custom("zt-cert")`, and `ct_monitor/src/main.rs:150-157`
recomputes the same digest.

### 3.1 Two upstream documentation defects **[MEASURED] + [CODE]**

**The documented verification recipe cannot be executed.** Live `acme-info` has
no `active_cert`, no `hist_keys`, no `base_domain`.
`gateway/rpc/proto/gateway_rpc.proto:134-143` defines `AcmeInfoResponse` with
exactly `account_uri = 1`, `quoted_hist_keys = 3`, `account_quote = 4`,
`account_attestation = 5`; `main_service.rs:391-396` constructs those.
**Field number 2 is absent** — the wire-level fingerprint of a removed field. The
docs (re-synced 2026-08-10) still describe the old schema, including a Step 2
that diffs against `active_cert`. Any implementation written from the published
guide will not work.

**prod9 has no CAA record at any level** — two resolvers, `NOERROR` + SOA, a
definitive absence. prod7 has one. So the "only the TEE-controlled ACME account
can issue" property is unenforced on the node fronting our CVM. Additionally,
**prod7's `issuewild` value is misspelled** (`"etsencrypt.org"`, byte-verified via
raw `TYPE257`); per RFC 8659 §4.3 `issuewild` governs wildcard issuance, so
strictly no CA should be able to renew that wildcard.

*Partial compensating control:* `ct_monitor` polls CT logs and errors on
*"certificate has issued to unknown pubkey."* Whether Phala runs it for prod9 is
unknown. It is **detective, not preventive**.

---

## 4. The finding that reversed the recommendation

**Gateway certificate evidence is historical, not current-boot. [CODE]**

At v0.5.9:

- `distributed_certbot.rs:63-75` — `init_domain` first tries the KV store; if
  `cert_data.not_after > now` it loads the certificate **and key** and returns,
  logging *"loaded from KvStore (issued by node {})"*. **No fresh quote.**
- `save_cert_to_kvstore(domain, cert_pem, **key_pem**, not_after)` — the
  **private key** is persisted.
- `main_service.rs:230-245` — startup loads all certificates from KV after
  *"WaveKV: bootstrapping from peers."*
- Quote generation lives only in `do_request_new`, i.e. issuance/renewal.

So the TLS key is generated once, quoted once, then distributed across gateway
nodes and reloaded on later boots without re-attestation. **The quote proves the
key was born in a TEE with measurement X at time T. It does not prove the process
serving TLS now has measurement X** — and the log line concedes the issuing node
need not be the serving node.

**`/.dstack/app-info` is plain unsigned JSON** (`proxy/tls_terminate.rs:188-192`,
`agent.info()`) — no quote, no nonce, no signature. It cannot authenticate
anything.

**Consequence:** revision 1's claim that gateway verification "closes both halves
of T-03's residual," and its claim that measurement-pinning detects a gateway
running `debug.insecure_skip_attestation`, are both **withdrawn**. What survives
is narrower and still useful: an attacker *without* KV access cannot produce a
certificate in `quoted_hist_keys`, so this defeats ordinary CA mis-issuance and
external MITM — which matters given §3.1's missing CAA. It is **certificate
provenance verification**, not T-03 closure.

---

## 5. Preflight results

Both external unknowns that gated the design were investigated on 2026-08-15.

### 5.1 TLS passthrough — source-confirmed GO, live-unverified **[CODE]**

`gateway/src/proxy.rs:151-165`:

```rust
let (subdomain, base_domain) = sni.split_once('.')?;
if state.cert_resolver.get().contains_wildcard(base_domain) {
    let dst = parse_dst_info(subdomain)?;
    if dst.is_tls { tls_passthough::proxy_to_app(...) }   // s-suffix
    else          { state.proxy(...) }                     // gateway terminates
} else {
    tls_passthough::proxy_with_sni(...)                    // custom domain, TXT lookup
}
```

`parse_dst_info:85-130` strips a trailing `s` → `is_tls = true` (and `g` → h2;
`gs` rejected). SNI is peeked from the ClientHello **before** any termination, so
with `s` the gateway bridges raw TCP and our enclave performs the handshake.

**Passthrough works on the gateway's own wildcard domain; no custom domain is
required.** The docs' *"Custom domain configured (for production use)"*
prerequisite is a soft recommendation, not a technical constraint. `dstack/CLAUDE.md`
independently documents the ingress pattern `<id>[-[<port>][s|g]].<base_domain>`
with *"`s` suffix: TLS passthrough."* App-ID routing is unchanged, because it is
the same SNI parse — so §6.1's routing result carries over to this path.

**[OPEN] Live confirmation.** With the CVM stopped, `-8080.` and `-8080s.` fail
identically at backend resolution and cannot be distinguished. Confirming
requires a running CVM. This is the remediation plan's Phase 0 passthrough probe;
the source questions it lists are answered above, so the live probe is all that
remains.

### 5.2 dstack-ingress — persistence confirmed, but governed **[MEASURED] + [CODE]**

Source is not public (`Dstack-TEE/dstack-ingress` and
`Phala-Network/dstack-ingress` both 404); the image is
`dstacktee/dstack-ingress:2.2@sha256:d05a7b34…` on Docker Hub. From the
documented compose (`setup-custom-domain.mdx:48-75`):

```yaml
volumes:
  - cert-data:/etc/letsencrypt   # certificates AND private keys
  - evidences:/evidences         # attestation evidence files
```

with the app mounting `evidences:/evidences:ro`. **So ingress evidence is a static
file generated at issuance and served read-only — not a live challenge-response.**
Same freshness class as §4, arguably worse: there is no live quote endpoint at
all.

**But the conclusion inverts on a fact neither review caught.** What can decrypt
that volume? `kms/src/main_service.rs:262-270` — the disk-encryption-key path
calls `ensure_app_boot_allowed(&request.vm_config)` →
`ensure_app_attestation_allowed` → `auth_api.is_app_allowed(&boot_info)`, and
`boot_info` carries the **compose_hash**.
`phala-docs/dstack-cloud/register-enclave-measurement.mdx:12`: *"KMS checks these
measurements against an on-chain allowlist before dispatching keys"* — and
changing your compose requires registering the new measurement first.
`dstack/CLAUDE.md` confirms the mechanism: *"DstackApp: Per-app authorization
contract controlling device IDs and compose hash whitelist."*

**So for ingress inside our CVM, an unapproved build cannot decrypt `cert-data`
and therefore cannot obtain the TLS key.** The persistence gap is closed by
**governed key release** rather than by fresh attestation.

### 5.3 The framing correction this produces **[INFERRED]**

Both prior analyses — mine and the reviewer's — assumed **fresh attestation is
the only remedy** for key persistence. It is not. There are two:

1. **Freshness** — quote the key at every boot. What RA-TLS with a boot-random
   key does.
2. **Governed key release** — the key cannot reach an unapproved measurement, so
   a historical quote remains meaningful.

This re-ranks the three candidate paths by **whose governance they depend on**:

| Path | Key persistence | Governed by |
|---|---|---|
| RA-TLS, boot-random key | none | n/a — strongest |
| Ingress inside our CVM | yes | **our** on-chain compose allowlist |
| Phala gateway evidence | yes | **Phala's** allowlist, opaque to us |

The gateway path is weakest, and now for a nameable reason. Option B is stronger
than either review credited: its lifecycle gap may be closable by governance we
already control, rather than requiring a freshness property Phala would have to
build.

---

## 6. Claims: what survived, what was disproved

### 6.1 Survived — gateway routing is attestation-bound **[CODE]**

Verified at v0.5.9, and unchanged by everything above:

1. `gateway/src/main_service.rs:92` — routing is `apps: BTreeMap<app_id,
   BTreeSet<instance_id>>`, resolved from the SNI hostname
   (`proxy.rs:85`, `tls_terminate.rs:290`, `tls_passthough.rs:193`).
2. `main_service.rs:1434-1449` — `register_cvm` derives `app_id` from the RA-TLS
   peer certificate's `app_info` extension, or from a *verified* attestation, or
   bails. Never from a caller parameter.
3. `ra-tls/src/traits.rs:37-48` — `get_app_id`/`get_app_info` are bare extension
   reads with **no verification**, so the extension is only as good as its CA.
   `gateway/src/main.rs:132` sets `tls.mutual.ca_certs` from the dstack KMS chain.
4. `kms/src/main_service.rs:414-426` — the KMS verifies the quote and binds it to
   the CSR key (`verify_with_ra_pubkey`), takes `app_id` from the **verified**
   `app_info`, and derives the signing CA per-app from that attested id.

**An approved gateway routes an app-ID hostname to a KMS-authorized member of
that app-ID's instance set.** That is meaningful but **narrower than
exact-instance binding** — an `app_id` survives upgrades and spans instances, so
it is not the current matcher compose or boot session.

Caveats: the trust root is the **dstack KMS root CA**, not the matcher quote
alone (step 3 is a delegation); `mandatory = false` for client certs
(`entrypoint.sh:70`) is safe only because the no-certificate path reaches the
`bail!`; and `ensure_app_authorized` (`auth_client.rs:23-34`) delegates to a
Phala-operated allowlist that can restrict registration but not forge an
`app_id`.

### 6.2 Disproved — three claims withdrawn

| Claim (rev. 1) | Status | Why |
|---|---|---|
| Gateway verification closes both halves of T-03's residual | **Withdrawn** | §4 — evidence is issuance-time, key is portable across nodes and boots |
| Measurement-pinning detects a debug-configured gateway | **Withdrawn** | §4 — `/app-info` is unsigned self-reported JSON |
| RA-TLS requires a breaking `report_data` migration | **Withdrawn** | §6.3 |
| Browser T-03 can never close | **Withdrawn** | §7.2 — category error |
| Signing the app bundle raises the malicious-origin ceiling | **Withdrawn** | §7.2 — circular verifier |

### 6.3 The `report_data` correction **[CODE]**

`sdk/rust/src/dstack_client.rs:145` — `get_quote(report_data: Vec<u8>)` is a
**per-call** API accepting any caller-selected data up to 64 bytes;
`guest-agent/src/rpc_service.rs:326-328` pads and returns. There is no single
global `report_data`. Our `/attestation` layout (`nonce ‖ signer_set_hash`,
`crates/darknyx-tee/src/api/attestation.rs:105-107`) is **our endpoint's choice,
not a platform constraint.**

RA-TLS can mint a separate versioned transport quote and leave `/attestation`
untouched. This also means **`audits/audit_6/tracker.md`'s Option-A cost table is
wrong** where it lists the attestation contract as "**Breaking**" — that entry has
been suppressing Option A since 2026-07 on a false premise, and correcting it is
Phase 0 work.

---

## 7. Review history

This document has been through two adversarial reviews by an independent agent.
Both found substantive errors. Recording them because the corrections are more
useful than the draft they corrected.

### 7.1 Review 1 — the persistence finding

Correctly identified that the gateway certificate quote attests the process that
**generated** the key, not the one **serving** it — §4. This inverted the
recommendation. Also correctly flagged that Tier 1 was mis-scoped as "SDK-only":
the check must run on the socket carrying each request via `checkServerIdentity`,
never a standalone `tls.connect()` probe, and it needs a live CVM smoke.

### 7.2 Review 2 — three corrections

- **`report_data` is per-quote** — accepted, verified independently at §6.3.
- **Browser T-03 is not inherently impossible** — accepted. The draft made a
  category error, importing application-distribution integrity into a transport
  finding. *"Every client, including a daemon, ultimately trusts the software
  installed on it."* With a quote-bound HPKE channel the browser **does**
  self-verify. The origin-trust residual belongs to `R-01`, not T-03. One nuance
  retained: a browser re-fetches code from the venue operator on every load, a
  materially higher-frequency trust event than a daemon install — that raises
  `R-01`'s severity, not T-03's closability.
- **RA-TLS on the trader-host upstream is not browser closure** — accepted as a
  clarity fix; the draft said so in prose but its table invited misreading.
- **Boot-random keys, never `dstack.get_key()`** — accepted. `get_key()` is
  deterministic per app identity, and `app_id` survives upgrades while
  `compose_hash` changes, so a later differently-measured build derives the same
  key. This is §4's failure mode generalized.

### 7.3 What this document contributed after those reviews

§5 — the preflight results — and specifically §5.3's observation that **governed
key release is a second, equally valid remedy for key persistence**, which
neither review identified and which materially strengthens Option B.

---

## 8. Where this landed

The architecture, closure invariants, and PR sequence are in
[`transport-integrity-remediation-plan.md`](transport-integrity-remediation-plan.md).
In brief:

- **T-03P (programmatic)** — in-process RA-TLS terminated by `darknyx-tee`, over
  the passthrough route, boot-random key, separate versioned transport quote,
  verified against the certificate on the actual socket.
- **T-03B (browser)** — either a directly-connected governed ingress (B1) or a
  quote-bound HPKE application channel (B2). Decided after Phase 0.
- **Gateway evidence** — retained as an optional deployment monitor. Not closure.
- **Parent T-03** stays open until both halves close.

---

## 9. Open questions

1. ~~Live passthrough confirmation~~ **ANSWERED 2026-08-16: GO. [MEASURED]**
   A TLS 1.3 handshake through `<app-id>-8443s.dstack-pha-prod9.phala.network`
   completes against the enclave's own boot-scoped certificate
   (`CN=darknyx-tee ra-tls (boot-scoped)`), not the gateway wildcard. The
   gateway passed the stream through untouched. Details, including what else the
   same window proved and one false positive worth remembering, are in
   `transport-integrity-remediation-plan.md` §6.2.

   Note what it took: the question was **unanswerable** against the pre-existing
   plaintext image, because "passthrough forwarded to a backend that cannot
   speak TLS" and "the gateway refused the `s` route" produce identical
   observations from outside. It needed a TLS-speaking backend — i.e. the
   RA-TLS build itself.
2. ~~Does our Phala Cloud deployment use on-chain KMS governance?~~
   **ANSWERED 2026-08-15: NO. [MEASURED]** `phala cvms get` reports, for **both**
   our CVMs (`nightly-test-cvm` and `darknyx-image-builder-73`):

   ```
   kms_type                     = phala
   kms_info.dstack_app_address  = null
   kms_info.chain_id            = null
   kms_info.dstack_kms_address  = ""
   kms_info.rpc_endpoint        = https://kms.dstack-pha-prod7.phala.network
   ```

   There is **no `DstackApp` contract for our app**. The on-chain path exists in
   dstack (`kms/auth-eth/contracts/DstackApp.sol:25,131,167-180` — `onlyOwner`
   `addComposeHash`, enforced in `isAppAllowed`) but our deployment does not use
   it. `phala-cloud/cvm/replicating-cvms.mdx:39` states the distinction plainly:
   *"Onchain KMS adds gates because the DstackApp contract — **not Phala Cloud** —
   decides which compose hashes and devices are allowed to run under the app's
   identity."*

   **Therefore §5.3's "governed key release" remedy is NOT available to us today**:
   our compose allowlist is Phala's, so ingress key persistence would be gated by
   the same third party whose opacity disqualified the gateway path. §5.3's
   ranking table stands as a general result, but on the current deployment the
   middle row collapses into the bottom one.

   **Consequences.** B1 is NO-GO as deployed. Two ways forward: **B2**, which
   depends on no one else's allowlist; or **migrate to Onchain KMS** (supported —
   `/phala-cloud/key-management/deploying-with-onchain-kms`) and then reconsider
   B1, at the cost of a real migration and a chain dependency in the boot path.
   Note this also strengthens the T-03P choice: **RA-TLS with a boot-random key
   depends on KMS governance not at all.**

   *Pre-existing property worth recording, not introduced by this work:* our CVM's
   persistent state (journal, Merkle mirror) is already encrypted under a key
   released by Phala's KMS on Phala's allowlist. That bounds what any
   "governed persistence" argument can claim for Darknyx today.
3. **[OPEN] Exact dstack-ingress source.** Image digest without reviewable source
   is not sufficient for a mainnet TCB addition.
4. **[OPEN] Full DCAP verification of the gateway quote** was not performed; only
   the `report_data` binding and structural shape were checked.
5. **[OPEN] Whether Phala runs `ct_monitor` for prod9** (§3.1).
6. **[OPEN] Tier 2 (HPKE) has no cost estimate.** It touches intake, the stream,
   and the browser proving/inventory boundary. Both reviews rated it a real
   protocol, not a wrapper.

---

## 10. Provenance and process notes

- Live measurements: 2026-08-15 against `gateway.dstack-pha-prod9.phala.network`.
  No CVM started; nothing billable.
- Source: `dstack` **`v0.5.9`** (`282eeb27`; `gateway-v0.5.9`, `kms-v0.5.9`,
  `verifier-v0.5.9`). Documentation: `phala-docs` **`55ecaa3`** (2026-08-10).
  Revision 1 was written against a different `dstack` checkout; four citations
  drifted and were corrected with no change of conclusion.
- **Three upstream defects to report to Phala:** the `acme-info` schema mismatch
  (§3.1), prod9's absent CAA, and prod7's misspelled `issuewild`.
- **`browser-client`, `trader-host`, and `client-core` were unaudited when this
  began.** `audits/audit_8` now covers them (`R-01`…`R-05`).
- **Process note for the next agent.** Three substantive errors in this document
  came from the same cause: reasoning over documentation instead of reading
  source. The docs were wrong about the `acme-info` schema, silent about key
  persistence, and misleading about `report_data`. **Read the source at the pinned
  version.** A related trap: macOS has no GNU `timeout`, and a command wrapped in
  it fails silently with empty output that reads like a negative result.
