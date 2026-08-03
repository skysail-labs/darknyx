# Client-Side DCAP Attestation Enforcement — AS-BUILT

> **Status: SHIPPED and live-CVM validated.** This was an implementation plan
> for work that has since landed. It is kept as the **decision record** — the
> threat model, the verification algorithm, and the *why* behind the design —
> not as a to-do list.
>
> Pair with [`tee-attestation-flow.md`](./tee-attestation-flow.md) (design).
> Original finding: `audits/audit_2/READINESS.md` **A-1**.
>
> **Last verified against the tree: 2026-08-04.**

---

## Why this file was rewritten

It sat here as a 538-line forward-looking plan whose premise had become false.
It stated that the daemon *"**optionally** calls an injected `QuoteVerifier` for
Intel DCAP — **never constructed in the stock binary**"*, that the SDK had
*"**No** `tee/` module, **no** `verifyTeeAttestation`, **no**
`EXPECTED_COMPOSE_HASH`"*, and it addressed crate paths and environment-variable
prefixes from before the Darknyx rename (see
[`brand-namespace.md`](./brand-namespace.md) for the translation table).

Every one of those is false today, and false in the **dangerous direction**. A
security document that *understates* what is implemented invites someone to
rebuild shipped work — or, worse, to reason about mainnet readiness as though a
live control were absent. CLAUDE.md §0 also requires surviving pre-rename
references to be fixed rather than preserved — and `check-brand-namespace.sh`
enforces that, so the old names cannot be quoted here even to describe them.

Its acceptance checklist is satisfied too, so leaving it as an open plan made a
closed gap look open.

---

## The gap this closed (A-1)

Darknyx's privacy and execution-price fairness guarantees are **TEE-trusted by
design** (see `CRYPTOGRAPHY.md` on price fairness). They mean nothing unless a
client can prove it is talking to a genuine Intel TDX enclave running a
governance-approved measured image, rather than an ordinary server returning
plausible JSON.

The original hole: nonce freshness, key binding, and pin comparison all operated
on **self-reported gateway fields**. A malicious operator could echo the
client's nonce, bind their own Ed25519 key, copy the expected pins, and pass
every check. Nothing forced a real Intel signature into the path.

**This never claimed to prevent fund theft.** On-chain ZK and the PDA guards
bound value inflation regardless of who runs the gateway. DCAP closes the
**operator / fake-gateway** hole for *privacy and fairness* trust specifically.
The distinction is worth keeping, because collapsing it is what leads to
on-chain DCAP being re-proposed as though it replaced connect-time verification.

---

## What a correct client verifies

Kept because it is the specification the implementation is checked against, not
a description of it.

```
1.  nonce ← CSPRNG(32)
2.  GET /attestation?reportData=hex(nonce)
      → quote, event_log (JSON string), report_data (64B hex), tee_pubkey (b58)
3.  R = decode(report_data); len == 64
4.  R[0:32]  == nonce                              // freshness
5.  R[32:64] == SHA256(signer set)                 // key binding
6.  DCAP_VERIFY(quote) → report_data', measurements, TCB status
7.  report_data' == R                              // hardware binds the same R
8.  GET /info → compose_hash, tcb_info.mrtd, tee_pubkey
9.  info.tee_pubkey == attestation.tee_pubkey
10. pins (REQUIRED in strict): compose_hash; optional mrtd
11. replay event_log → RTMR3; compose-hash event == pin
12. only then open order streams
```

Note step 5: `report_data`'s second half binds the **whole K-shard signer set**,
not shard 0 alone — a change from the original plan, which assumed a single key.

---

## As-built

| Concern | Where it lives |
|---|---|
| Client verifier | `packages/sdk/src/tee/attestation.ts::verifyTeeAttestation` |
| DCAP quote verification | `packages/sdk/src/tee/dcap.ts` |
| Daemon enforcement | `packages/daemon/src/attestation.ts` |
| Stock-binary wiring | `packages/daemon/bin/daemon.ts` — `createDcapQuoteVerifier({ pccsUrl })` |
| Live-CVM coverage | `packages/sdk/tests/cvm-attestation-e2e.test.ts` |

Two properties are load-bearing, and both are enforced in code rather than by
convention — which is the difference between a control and a habit:

* **Strict is the default, and unpinned is refused.** `strict` defaults to
  `true`, and a strict run without a quote verifier is an *error*, not a silent
  downgrade: *"strict attestation requires a DCAP quote verifier"*.
  `verifyTeeAttestation` separately refuses an empty `expectedComposeHash` —
  *"refusing to trust an unpinned build"* — because a client that verifies a
  quote but pins nothing has authenticated *an* enclave, not *the* enclave.
* **The escape hatch is loud and narrow.** `DARKNYX_DAEMON_SKIP_ATTEST=1` exists
  for the local `dstack-simulator`, whose stub quotes cannot verify by design,
  and it logs a warning naming production explicitly. That asymmetry is the
  design, not a compromise: the simulator keeps the dev loop fast *because* a
  stub attestation cannot fool a real client (CLAUDE.md §4).

---

## Deliberately out of scope

Out of scope when the plan was written, still out of scope, and none of it
blocked on the work above.

| Item | Tracked in |
|---|---|
| On-chain DCAP / `dcap-qvl` in `vault` (zkDCAP) | [`tee-attestation-flow.md`](./tee-attestation-flow.md) §11 |
| Populating `EXPECTED_COMPOSE_HASH` with the release bundle | `audits/residual-backlog.md` — **CA-04** |
| Oracle price ↔ VAA root binding (A-2) | separate oracle work |

**On-chain verification is complementary, not a replacement.** It binds what the
*vault* will accept; it tells a *client* nothing about whether the gateway it
just opened a socket to is genuine. Connect-time verification is the only thing
that does, which is why it shipped first.

---

## The residual limit, carried forward

`report_data` is **full** at 64 bytes — `nonce ‖ SHA-256(signer_set)` — leaving
no room to bind anything further into the quote.

That is not a detail; it is why two other items look the way they do.
`bootSessionId` is documented as **NOT ATTESTED** in both
`packages/daemon/src/attestation.ts` and `packages/sdk/src/tee/attestation.ts`
(SW-18), and the **T-03** transport work is deferred rather than merely
unscheduled. Any future proposal to bind another value into the quote has to
start by resolving that budget, not by assuming there is room in it.
