# Nyx TEE — Attestation Flow

> End-to-end attestation deep-dive for the in-CVM matching/settlement
> layer. Read after `docs/tee-architecture.md` (the in-TEE design).

---

## 0. TL;DR — the mental model

There is no single "attestation step." Attestation in dstack is a
**chain of five separate verifications**, each with a different
verifier, different cadence, and different consequence on failure:

| # | Verifier | Verifies | Failure | Cadence |
|---|---|---|---|---|
| 1 | **dstack-kms** | The CVM's TDX quote (cert chain + RTMR3 + compose-hash whitelist) | KMS refuses to derive app keys; CVM cannot start | Once per CVM boot |
| 2 | **Our admin multisig** | A specific new CVM's TDX quote, before signing `set_tee_pubkey` | Multisig refuses to sign rotation; new image cannot settle | Once per image upgrade |
| 3 | **Solana vault program** | Ed25519 signature on `MatchResultPayload` canonical hash matches `vault_config.tee_pubkey` | Settle ix reverts | Every settle tx |
| 4 | **Client (browser/SDK)** | RA-TLS evidence + TDX quote behind the API endpoint | Client refuses to send orders | Once per session start |
| 5 | **External observer** | All of the above, via the public `/transparency` endpoint | Public trust signal degrades; nothing breaks technically | Continuous |

**Crucially: there is no on-chain TDX quote verification in v2.** The
trust chain leans on the multisig + dstack-kms to do quote
verification off-chain. v3 may add on-chain verification via Solana's
`secp256r1` precompile + a BPF port of `dcap-qvl`; design space
covered in §11.

---

## 1. The keys at play

Five distinct keys appear in the v2 design. Keeping these separate
in your head is the single most important prerequisite to
understanding the flow.

| Key | Lives in | Used for | Lifecycle |
|---|---|---|---|
| **dstack-kms RootKey** | dstack-kms's TEE (Phala-managed). Multi-party in their MPC topology. | Master KDF input for *every* application's keys. | Rotated only on KMS-level security incidents. RootPubKey published on-chain in the EVM `DstackKms` contract. |
| **Nyx App Root** | dstack-kms TEE, derived per `(app_hash, deployer_id)`. | KDF input for our per-purpose keys. | New value each time our `compose_hash` changes. |
| **Ed25519 signer** | Our CVM's memory (TDX-encrypted). Derived via `getKey("nyx/ed25519-signer/v1")` → seed → Ed25519 key. | Signs `canonical_payload_hash(MatchResultPayload)` for `tee_forced_settle_batched`. | Stable for the lifetime of our `compose_hash`. |
| **TLS cert private key** | dstack-ingress container's memory inside the CVM. Derived from our App Root via the TLS path. | TLS termination on `api.nyx.example.com`. | Rotated automatically on each Let's Encrypt renewal (every ~60 days). |
| **Admin multisig signing keys** | The 3-of-5 signers' hardware wallets / Ledgers / Yubikeys. **Outside the TEE.** | Sign `set_tee_pubkey` + governance txs. | Rotated per multisig membership changes (organisational, not technical). |

What about the `root_key` field in `vault_config`? That's a long-lived
**protocol governance authority**, distinct from `admin` and unrelated
to the TEE signer — rotatable only by a self-signed `rotate_root_key`.

---

## 2. The Intel TDX quote — fields we care about

Reference: `phala-docs/phala-cloud/attestation/attestation-fields.mdx`.
Concrete example from a real Phala-deployed CVM:

```json
{
  "tee_tcb_svn": "06010300000000000000000000000000",
  "mr_seam":  "5b38e3...",        // TDX module measurement (must match Intel's published value)
  "mr_td":    "c68518...",        // MRTD: virtual firmware (OVMF)
  "rt_mr0":   "85e0855...",       // virtual hardware config (CPU count, RAM)
  "rt_mr1":   "9b43f9f...",       // Linux kernel image
  "rt_mr2":   "7cc2da...",        // initrd + RootFs
  "rt_mr3":   "2c482b5b...",      // application: compose-hash + key-provider + instance-id
  "report_data": "afab979...",    // 64 bytes; we control this — see §4
  "td_attributes": "0000001000000000",
  "xfam": "e702060000000000"      // AVX2/AVX512 enabled by default
}
```

The hash chain that produces `rt_mr3`:

```
RTMR3 = 0_48
RTMR3 = SHA384(RTMR3 || SHA384(event_compose-hash))
RTMR3 = SHA384(RTMR3 || SHA384(event_instance-id))
RTMR3 = SHA384(RTMR3 || SHA384(event_key-provider))
```

The full RTMR3 event log is fetched alongside the quote, as
`event_log`. The verifier replays the chain to confirm the events
are authentic.

**For Nyx specifically**, the value we want to bind to `report_data`
when fetching a quote for client-side verification is:

```
report_data[0..32]  = client-supplied nonce (replay protection)
report_data[32..64] = SHA-256 of the served TLS cert's pubkey
                      (auto-populated by dstack-ingress)
```

For the admin-side rotation verification (§5), we additionally bind
the Ed25519 signer pubkey:

```
report_data[0..32]  = signer_pubkey_ed25519
report_data[32..64] = 0_32
```

This is what gets compared against `new_pubkey` argument to
`set_tee_pubkey` — proves the quote was issued for THIS specific
signer.

---

## 3. Verification #1 — dstack-kms verifies our CVM (boot time)

Out of band of our codebase, but worth understanding.

```
[Our CVM boots]
    │
    │ TDX hardware records MRTD + RTMR0-2 during firmware/kernel boot.
    │ dstack-guest-agent extends RTMR3 with compose-hash + key-provider
    │ + instance-id events.
    │
    ▼
[dstack-guest-agent requests app keys from dstack-kms via RA-TLS]
    │
    │ Both ends present TDX quotes during the TLS handshake.
    │ Quotes are signed by Intel's TCB cert chain (ECDSA P-256).
    │
    ▼
[dstack-kms verifies our quote off-chain]
    │ 1. Intel cert chain → confirms genuine TDX
    │ 2. mr_td against Phala's allowed-OS-image list
    │ 3. compose-hash extracted from RTMR3 events → allowlisted?
    │      - In Cloud-KMS mode (v2 choice): Phala dashboard allowlist
    │      - In Onchain-KMS mode (future): DstackApp on Base
    │ 4. tee_tcb_svn matches latest; debug mode disabled
    │
    ▼
[KMS derives our app keys and returns over RA-TLS]
    │ keys = KDF(RootKey, (deployer_id, app_hash, paths…))
    │ Returned over an attested channel — both parties verified.
    │
    ▼
[Our CVM has its disk encryption key, env-decryption key,
 TLS cert key (via dstack-ingress), and our signer seed.]
```

If any check fails: KMS refuses to release keys → our CVM never
gets its Ed25519 seed → cannot sign settles → effectively, cannot
operate. **This is the dstack-side enforcement of "only authorised
code runs."**

We do not need to write any code for this verification — it's
internal to dstack. We do need to:

1. Allowlist our compose-hash in the Phala Cloud dashboard before
   first deploy.
2. On every image upgrade: re-allowlist the new compose-hash.

Both happen through Phala's UI (or CLI) signed by our Phala-account
admin, not by the Solana multisig.

---

## 4. Verification #4 — clients verify the TEE

This is the verification the SDK and a curious end-user perform.

### 4.1 What dstack-ingress publishes

When the CVM is up, dstack-ingress publishes four files at
`https://api.nyx.example.com/evidences/`:

| File | Contents | Why |
|---|---|---|
| `quote.json` | TDX quote (full hex) + event_log | The hardware-signed attestation |
| `cert.pem` | Current TLS certificate | What's being served to clients |
| `acme-account.json` | `{ "uri": "https://…/acct/12345" }` | The Let's Encrypt account that owns this cert |
| `sha256sum.txt` | SHA-256 of `cert.pem` + `acme-account.json` | Authenticator: this exact bundle was issued together |

Plus, on the same domain:

- `GET /attestation?reportData=<hex>` — returns a fresh TDX quote
  with caller-supplied 64 bytes of `report_data`. Used for live
  challenge-response (not just the static snapshot under `/evidences/`).
- `GET /info` — `{ app_id, instance_id, app_compose, tcb_info, … }`
  — used to recompute the expected compose-hash client-side.

### 4.2 The client-side verification chain

```
[Client opens wss://api.nyx.example.com/v1/stream]
    │
    │ TLS handshake → cert presented by dstack-ingress
    │
    ▼
[Client (before sending any sensitive op) fetches]
    GET https://api.nyx.example.com/evidences/sha256sum.txt
    GET https://api.nyx.example.com/evidences/cert.pem
    GET https://api.nyx.example.com/evidences/acme-account.json
    GET https://api.nyx.example.com/evidences/quote.json
    │
    │ Step A: verify TLS-cert binding to the served session:
    │   served_cert_pubkey == sha256sum.txt's referenced cert.pubkey
    │
    │ Step B: verify evidence integrity:
    │   sha256(cert.pem || acme-account.json) == sha256sum.txt
    │
    │ Step C: verify quote includes the evidence hash:
    │   sha256(sha256sum.txt) ∈ quote.report_data
    │
    │ Step D: verify quote signature (Intel TCB cert chain):
    │   - Either via dcap-qvl-wasm in the browser
    │   - Or via Phala's public verify API:
    │       POST https://cloud-api.phala.com/api/v1/attestations/verify
    │           { "hex": quote.quote }
    │   - Or via a locally-run dcap-qvl CLI
    │
    │ Step E: verify expected compose-hash:
    │   - Recompute SHA-256 of canonicalised app_compose JSON
    │     (or use @phala/dstack-sdk getComposeHash())
    │   - Replay RTMR3 events → confirm rt_mr3 in the quote
    │   - Confirm the compose-hash event matches the
    │     SDK-baked-in expected value (committed in source).
    │
    │ Step F: verify CAA + CT (optional, paranoid):
    │   - dig CAA api.nyx.example.com → only Let's Encrypt
    │   - crt.sh log query → only certs from our ACME account
    │
    ▼
[Client now trusts the TEE; sends order intent over TLS]
```

All five steps run **outside** the TEE (in the browser or SDK). The
SDK ships a helper that does steps A-E in ~300 ms first-connect,
caches the result, re-verifies on cert renewal.

### 4.3 What the SDK actually ships

New module `packages/sdk/src/tee/attestation.ts`:

```ts
export interface TeeAttestation {
  // The TEE's Ed25519 signer pubkey (also published in
  // vault_config.tee_pubkey).
  signerPubkey: Uint8Array; // 32 bytes

  // The compose-hash recorded in RTMR3.
  composeHash: string; // hex

  // The full TDX quote, for callers that want to verify deeper.
  quote: Uint8Array;
  eventLog: string;
}

/**
 * Verifies the TEE is running our expected compose-hash and that the
 * served TLS certificate is bound to a TEE-held key. Throws on any
 * mismatch.
 *
 * Pinned expectedComposeHash MUST be committed to source — that's
 * how clients know which version they're trusting.
 */
export async function verifyTeeAttestation(
  apiBaseUrl: string,
  expectedComposeHash: string,
): Promise<TeeAttestation>;
```

The SDK exports a constant `EXPECTED_COMPOSE_HASH` updated in lockstep
with our deployed image (a const in TS, regenerated and committed in
the same PR that bumps the Docker image). Mainnet clients pin THIS
exact hash; devnet clients pin the devnet hash; both ship in the same
SDK.

### 4.4 Failure modes

| Failure | Diagnosis | Client action |
|---|---|---|
| Step A fails | LB or MITM swapping certs | Refuse session, alert |
| Step B fails | Evidence files tampered | Refuse, possibly stale cache — refresh and retry once |
| Step C fails | Quote re-issued under a different cert | Refuse, alert |
| Step D fails | Quote signature invalid → fake TDX or Intel cert revoked | Refuse, alert |
| Step E fails | compose-hash mismatch → unexpected image deployed | Refuse, alert (very loud — this is "wrong version of Nyx is running") |
| Step F fails | CAA changed, or unauthorised cert in CT logs | Warning, not block; investigate |

---

## 5. Verification #2 — admin multisig before rotation

Triggered manually on every image upgrade. The procedure encoded in
`docs/tee-architecture.md` §7, expanded:

### 5.1 The ceremony

```
T+0    Deploy team builds the new Docker image. Computes new
       compose_hash. Tags as nyx-tee:v0.x.y. Pushes to a registry
       that's PINNED-by-digest in our docker-compose.yaml. The new
       app-compose.json embeds the new image digest, so the SHA-256
       of canonicalised app-compose is exactly new_compose_hash.

T+5m   Deploy team allowlists new_compose_hash in the Phala Cloud
       dashboard (admin-level action; outside the multisig). Deploys
       the new image. Old CVM (under old_compose_hash) keeps running.

T+30m  New CVM is healthy. New CVM's Ed25519 signer pubkey,
       new_pubkey, is derived from the dstack-kms KDF over the new
       app_hash.

T+35m  Multisig signer #1 (call them Alice) runs the verification:

       # 1. Fetch fresh quote with new_pubkey as report_data
       NONCE=$(head -c 32 /dev/urandom | xxd -p -c 64)
       PUBKEY_HEX=$(curl -s https://api.nyx.example.com/info |
                    jq -r '.tee_pubkey')
       REPORT_DATA="${PUBKEY_HEX}${NONCE:0:64}"
       curl -s "https://api.nyx.example.com/attestation?reportData=$REPORT_DATA" \
         > quote.json

       # 2. Verify via dstack-verifier (off-chain Docker)
       docker run --rm -p 8080:8080 dstacktee/dstack-verifier:latest &
       sleep 3
       curl -s -d @quote.json localhost:8080/verify | jq

       # The verifier output must show:
       #   - is_valid: true
       #   - mr_td matches the expected dstack OS image hash
       #     (registered with Phala or, in Onchain-KMS mode, on Base)
       #   - rtmr3's compose-hash event == expected new_compose_hash
       #   - report_data starts with new_pubkey (the binding)

       # 3. Confirm compose-hash matches what the deploy team
       #    announced — read it from the deploy team's commit
       #    message + source tree, not from a Phala API.

T+40m  Alice posts the set_tee_pubkey(new_pubkey) proposal to the
       Squads multisig. Adds her signature.

T+1h   Bob, Charlie, Dave, Eve each independently repeat Alice's
       verification at T+35m (different machines, different network
       paths). Each posts their signature to Squads.

T+2h   Three of five signatures collected. Squads auto-executes:
       set_tee_pubkey(new_pubkey)  →  vault_config.tee_pubkey
                                       updated on-chain.

T+2h   Old CVM is now signing payloads with the OLD key — vault
       rejects them. Phala Cloud's gradual rollout drains the old
       CVM's traffic to zero. Old CVM is shut down.
```

### 5.2 What the multisig is actually attesting to

Each signer, by signing, is asserting: *"I have independently
verified that:*

1. *The TDX quote is signed by Intel's TCB cert chain.*
2. *The OS image hash is one we approve of.*
3. *The compose-hash matches commit `<sha>` of `Nyx-Privacy/nyx`.*
4. *The Ed25519 pubkey I'm registering is the one bound to that
   quote (via `report_data`)."*

If a signer signs without doing this verification, they're abdicating
their trust role — the security of v2 depends on this not happening.
Make it impossibly clear in the runbook that **a multisig signature
is a verification claim, not a rubber-stamp.**

### 5.3 Why this isn't on-chain (yet)

Cost: porting `dcap-qvl` to Solana BPF is multi-week work + ongoing
TCB-update maintenance. Solana's `secp256r1` precompile (~25-50k CU
per signature, instructions-sysvar offsets, up to 8 sigs per ix)
makes the *math* feasible, but the cert-chain walk + RTMR3 event log
replay + TCB-info parsing is non-trivial BPF code. We defer to v3.

For v2, the trust assumption is "the multisig honestly does the
off-chain verification." That's the same trust assumption every
TEE-on-Solana project today uses (Marlin, Soon Network, etc.).

---

## 6. Verification #3 — on-chain Ed25519 sig check (every settle)

Already implemented and shipped (since v2 / before v3.5). Just
recapping the flow for completeness.

```
[TEE constructs MatchResultPayload (24 fields, 448 B Borsh)]
    │
    │ msg = canonical_payload_hash(payload)
    │     = SHA-256("nyx-match-v5" || field_bytes...)
    │
    ▼
[TEE signs with Ed25519 signer key]
    sig = Ed25519::sign(signer_seed, msg)
    │
    ▼
[TEE submits tx with TWO ixs:]
    Ix 0: Ed25519Program::verify(msg_hash, sig, signer_pubkey)
    Ix 1: vault::tee_forced_settle_batched(payload, match_index, merkle_proof)
    │
    ▼
[On-chain in Ix 1:]
    vault::verify_tee_signature(payload, &instructions_sysvar)
        – Reads Ix 0's data via the instructions sysvar
        – Confirms Ix 0 invoked the Ed25519Program
        – Confirms Ix 0's pubkey == vault_config.tee_pubkey
        – Confirms Ix 0's message == canonical_payload_hash(payload)
        – Confirms Ix 0's signature is the one Ed25519Program just
          verified
    │ Passes →
    ▼
[vault applies state mutation: spend notes A+B, mint notes E+F+fee]
```

The only thing changing in v2 vs v3.5: `vault_config.tee_pubkey` is
now a key derived inside an attested TEE rather than a key from a
local `tee_authority.json` file. The on-chain code path is unchanged.

---

## 7. Verification #5 — public observability

The `/transparency` endpoint (unauthenticated) lets anyone — users,
auditors, ourselves — perform spot-checks without an account. It
returns:

- The full attestation chain (latest quote + signer pubkey)
- The current Merkle root + leaf count
- Per-mint outstanding totals + vault token balance (solvency)
- 24h aggregate stats: settles, failures, avg finality

This is *not* a verification by the consumer; it's a publication
that *enables* the consumer to verify. The consumer still runs
verification #4 against the published quote.

We also expect to publish:

- The `EXPECTED_COMPOSE_HASH` constant we ship in the SDK, plus the
  commit hash + git tag it corresponds to. Anyone can recompute
  compose-hash from source and verify the published value.
- An RSS feed of multisig rotation events (set_tee_pubkey txs +
  human-readable signer-claim text). So everyone sees when keys
  change.

---

## 8. Failure mode catalogue

What happens when each verification fails:

### 8.1 Verification #1 fails (KMS refuses keys at CVM boot)

- Cause: compose-hash not allowlisted at Phala, quote signature
  fails (compromised TDX firmware? Intel revoked cert?), OS image
  rejected, debug mode enabled (shouldn't happen, but).
- Symptom: dstack-guest-agent logs `KMS refused key delivery`; the
  CVM container never starts; Phala dashboard shows "Failed"
  status.
- Recovery: re-allowlist the compose-hash, or fix the underlying
  issue (TCB update, etc.), then redeploy.

### 8.2 Verification #2 fails (multisig refuses to sign rotation)

- Cause: a signer's verification step caught a mismatch.
- Symptom: the rotation proposal sits in Squads with insufficient
  signatures; the new CVM is up but can't settle because the on-chain
  `tee_pubkey` is still the old one; old CVM continues to serve.
- Recovery: investigate the mismatch. Either the new image was
  built/deployed incorrectly (rebuild + redeploy + re-verify) or the
  governance trust is broken (escalate; do NOT force-sign).

### 8.3 Verification #3 fails (settle ix reverts)

- Cause: TEE's payload signature doesn't match
  `vault_config.tee_pubkey`. Most likely scenarios:
  - Image rolled but multisig hasn't rotated yet.
  - Bug in canonical-payload-hash serialisation in TS / Rust
    (cross-language byte-equality contract broken — see CLAUDE.md
    §6).
  - Memory corruption inside the TEE (unlikely but possible).
- Symptom: `tee_forced_settle_batched` ix returns
  `Ed25519SigVerifyError`. The vault state is unchanged.
- Recovery: identify which case. Cases 1 and 2 are bug-fix paths.
  Case 3 means restart the CVM; if persistent, escalate.

### 8.4 Verification #4 fails (client refuses to send orders)

- Cause: any of steps A-E in §4.2.
- Symptom: SDK throws `TEE_ATTESTATION_FAILED`; UI shows a clear
  message. Browser client may see a normal-looking TLS connection
  succeed (TLS termination is in the TEE, looks normal) but the
  evidence verification fails.
- Recovery: For genuine attacks (DNS hijack, CT log shows unauthorised
  cert), alert. For false positives (cert just renewed and the cached
  evidence is stale), refresh and retry once.

### 8.5 Verification #5 fails (transparency shows insolvency, etc.)

- Cause: massive bug (vault balance < outstanding per mint), data
  corruption, or someone trying to manipulate the public stats.
- Symptom: external auditors raise the alarm.
- Recovery: emergency response. This shouldn't be possible if the
  on-chain `outstanding[mint]` invariant holds — but worth
  monitoring.

---

## 9. Rotation matrix — full reference

Which events require which on-chain action:

| Event | KMS-side action | On-chain action |
|---|---|---|
| CVM crash/restart (same compose-hash) | Auto: KMS hands the same key to the new CVM instance | None |
| CVM migrated to a new TDX host (same compose-hash) | Auto: KMS hands the same key to the new host | None |
| Image upgrade (new compose-hash) | Manual: allowlist new compose-hash in Phala dashboard | Multisig signs `set_tee_pubkey(new_pubkey)` |
| dstack-kms internal key-share rotation | Auto, transparent | None |
| dstack-kms full RootKey rotation (rare) | Manual: confirm new RootKey, re-bootstrap our app | All apps re-derive — signer pubkey changes; multisig signs `set_tee_pubkey` |
| Multisig membership change | n/a | Out-of-band: Squads governance |
| KMS migration (Phala-hosted → self-hosted) | One-time: stand up our own KMS, re-bootstrap | All apps re-derive — signer pubkey changes; multisig signs `set_tee_pubkey` |
| Intel cert chain revocation / TCB update | KMS rejects old measurements | None on Solana (KMS handles); we may need to rebuild the dstack OS image, which is a compose-hash change |

The crucial property: **only the image-upgrade path requires an
on-chain action in the steady state.** Hardware swaps, restarts,
KMS internals — invisible to Solana.

---

## 10. Anchoring the trust assumptions

Honest assessment of what the v2 design trusts:

1. **Intel TDX hardware** is genuine and not exploit-vulnerable for
   the current TCB level. (Same trust assumption as everyone using
   TDX.)
2. **dstack-kms** correctly verifies TDX quotes and enforces the
   compose-hash allowlist. (Trust Phala here; mitigated by being
   open-source + auditable.)
3. **Phala's compose-hash allowlist** is correctly managed. (Trust
   their dashboard auth.)
4. **Our admin multisig signers** honestly verify TDX quotes
   off-chain before signing. (Trust each individual signer, but
   only 3 of 5 need to be honest.)
5. **`dstack-ingress`'s ACME implementation** does not leak the TLS
   private key. (Trust Phala's code; auditable + open-source.)
6. **Let's Encrypt** does not issue certificates outside our CAA
   policy. (Trust LE; mitigated by CT log monitoring.)
7. **Our SDK's `EXPECTED_COMPOSE_HASH` constant** is correct and
   pins the right version. (Trust that a malicious commit replacing
   this constant would be caught in code review — same as any
   security-critical const.)

What we do NOT trust:

- The cloud provider (GCP / Phala's hardware operator) — TDX
  hardware encryption prevents memory snooping.
- The network — RA-TLS terminates inside the enclave.
- An individual multisig signer — 3-of-5 threshold.
- An individual KMS node — Phala's KMS uses multiple nodes (MPC
  capable).
- **The TEE for read queries** — `/tree/*` + `/transparency` are
  convenience reads, not trust assertions. A malicious or
  compromised TEE serving `/tree/inclusion` cannot fool clients
  who verify the returned inclusion proof against the on-chain
  Merkle root they fetch directly from Solana. See
  `docs/tee-architecture.md` §5.5. This is the property that
  makes the TEE-as-indexer design defensible: we get the
  ergonomics of a single attested service without the security
  weakness of trusting it for arbitrary reads.

What we don't yet have:

- Distributed enforcement of compose-hash policy. (Would require
  Onchain KMS on Base. Cheap, ~1 week, considered for post-v2.)
- On-chain TDX quote verification. (Requires `dcap-qvl` BPF port.
  v3 work.)
- A formal threat-model write-up signed by an external auditor.
  (Pre-mainnet ask.)

---

## 11. The path to v3 — on-chain quote verification

For when we decide to remove the multisig from the rotation trust
path.

### 11.1 The plan

- **Port `dcap-qvl` to no-std + Solana BPF.** The crate is already
  no-std-friendly (per Phala docs, supports WASM+NEAR target). Port
  scope:
  - Replace `ring` crypto backend with the `solana_program::secp256r1_program`
    precompile via instructions-sysvar inspection (same pattern as
    our Ed25519 verification today).
  - Replace `rustcrypto` SHA-384 with `solana_program::hash::hash`
    (Solana provides SHA-256; SHA-384 is BPF-friendly).
  - Replace `rustls` X.509 parser with `x509-parser` (no-std-compatible).
  - Ship Intel TCB info as a baked-in const updated periodically via
    a governance ix.
- **New ix `set_tee_pubkey_attested(quote_bytes, eventlog_bytes, new_pubkey)`:**
  - Verifies the quote on-chain using the new dcap-qvl-bpf crate.
  - Replays RTMR3 event log; extracts compose-hash.
  - Checks compose-hash against a new `vault_config.allowed_compose_hashes`
    set (governed by multisig or DAO).
  - Confirms `new_pubkey ∈ quote.report_data`.
  - Rotates `vault_config.tee_pubkey`.
- **Estimated CU cost**: ~600-900k. Within Solana's 1.4M ceiling but
  tight. May need ix-data-only mode (no account writes other than
  vault_config) to stay under.
- **Estimated effort**: 4-6 weeks engineering. Worth doing once,
  then maintenance cost is the periodic TCB-update ix.

### 11.2 What v3 changes about the rotation ceremony

- Steps T+35m through T+1h (off-chain verification by each multisig
  signer) become a single on-chain tx. Signer just trusts the BPF
  verifier.
- Or: drop the multisig entirely. Whoever can pay rent for the
  rotation tx can rotate — because the on-chain verifier enforces
  policy, the multisig is redundant.

### 11.3 When to do it

After v2 ships AND:
- We've seen at least 2-3 rotation ceremonies happen smoothly under
  multisig — so we know the off-chain verification is reproducible.
- A user/auditor specifically demands on-chain verification.
- Or: a Solana-ecosystem `dcap-qvl-bpf` port lands publicly (saves
  us most of the work).

---

## 12. Glossary (just the dstack-specific terms)

- **CVM** — Confidential Virtual Machine. The Intel-TDX-encrypted
  VM where our Docker containers run.
- **MRTD** — Measurement Register for Trust Domain. SHA-384 hash of
  the initial VM state (OVMF firmware). Set once at VM boot.
- **RTMR0-3** — Runtime Measurement Registers. SHA-384 hash chains
  extended by software during boot. RTMR3 is where our
  application's compose-hash lives.
- **compose-hash** — SHA-256 of canonicalised `app-compose.json`
  (which embeds the docker-compose.yaml + dstack manifest fields).
  Pinned per app version.
- **app-id** — Deterministic identifier of an application. Includes
  the deployer's identity.
- **instance-id** — Identifier of a specific CVM instance. Two
  identical compose-hashes scheduled on two hosts get different
  instance-ids.
- **dstack-kms** — Key Management Service. Runs in its own TEE.
  Derives all app keys from a RootKey using deterministic KDFs.
- **DstackApp** — Per-application EVM contract (Ethereum / Base)
  storing `allowedComposeHashes` + `allowedDeviceIds` for Onchain
  KMS mode. Not used in our v2; would be used if we move to
  Onchain KMS later.
- **dstack-ingress** — Reverse proxy + ACME client running inside
  the CVM. Manages TLS certs whose private keys never leave the TEE.
- **RA-TLS** — Remote-Attestation-TLS. TLS handshake that includes
  a TDX quote, mutually verified by both ends.
- **RA-HTTPS** — RA-TLS-served HTTPS. Standard HTTPS to the browser,
  but the cert was generated inside an attested TEE.
- **`/evidences/`** — Standard endpoint exposed by dstack-ingress
  publishing the four-file evidence bundle (quote + cert + ACME
  account + checksum) for clients to verify RA-TLS binding.
- **dcap-qvl** — Phala's Rust crate for verifying Intel DCAP
  attestation quotes (SGX + TDX). Used off-chain in v2; potentially
  ported to Solana BPF in v3.
- **dstack-verifier** — Phala's HTTP service that wraps dcap-qvl +
  reference-value comparison. Docker image, runs locally for the
  multisig ceremony.

---

## 13. What this document is NOT covering

- **The TEE-internal binary design** → `docs/tee-architecture.md`
- **Wire contract** → `docs/tee-api-openapi.yaml`
- **Cryptographic invariants of our note system / circuits** →
  `CRYPTOGRAPHY.md`
- **PR / commit / CI hygiene** → `CLAUDE.md`

---

*Maintained as the single source of truth for what is attested,
who attests it, and what each verifier accepts as proof. Update on
every TEE pubkey rotation procedure change, every new endpoint
that exposes attestation data, and every decision to expand or
shrink the trust assumptions in §10.*
