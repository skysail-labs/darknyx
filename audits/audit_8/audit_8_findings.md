<!-- audit-record -->
> **Audit:** Post-audit_7 surface review — browser trader, oracle source switch, note-use-tag lockstep
> **Date:** 2026-08-15
> **Engagement:** `audits/audit_8/`
> **ID prefix:** `R-` (round 8). Performance continues the shared `PF-` series at `PF-28`.
> **Cross-audit status:** see [`residual-backlog.md`](../residual-backlog.md) — the canonical index of what is still open.
> **Baseline:** `main` @ `fc88040` (PR #140 merged). Prior sweep baseline was `d69248b`.

---

# Darknyx audit 8 — 2026-08-15

> **Scope.** First-party defensive audit of the surfaces that landed after
> `audit_7`, plus a lockstep re-read of the note-use-tag migration (PR #113)
> and a targeted check that closed `audit_7` remediations still hold.
>
> The August 2 sweep left ~12.9k unread lines, most of them descoped
> (`packages/indexer`) or test tooling. Since then the tree grew a full
> browser trader (`packages/browser-client`, `packages/trader-host`,
> `packages/client-core`), a second Pyth producer (`pyth-solana-push-v1`),
> and the v11 note-use-tag cutover. Those are this engagement.
>
> **ID prefix:** `R-01…`. Distinct from `SW-` / `CA-` / `T-` / `S-` / `D-` /
> `PF-01…PF-27`. Performance items continue `PF-28…`.
>
> **Severity:** Critical / High / Medium / Low / Perf-Nit / Info

---

## 1. Executive summary

**No new Critical, and no custody-inflation or double-spend path in the
note-use-tag cutover.** The most valuable negative result is that PR #113
kept every consume/lock PDA in one tag namespace, bound the published tag
to a membership-proven commitment in VALID_INPUT / VALID_SPEND / VALID_MERGE,
and took consumed input commitments off Tx D. That work is clean.

**Four High findings, all on the new browser/oracle path.** The team
committed to a browser client while `T-03` was still a deferred mainnet
gate, then put the pins that make "Attested" mean anything in an unsigned
`/release.json` served by the same unmeasured origin that terminates TLS
(`R-01`). The default oracle producer replaced in-enclave Pyth
authentication with RPC-reported account bytes (`R-02`). The custody
worker leaks the wallet-wide `spendingKey` onto the page for proving
(`R-03`). Restoring a seed backup resets the HD order index to zero
(`R-04`) — SW-10, on a new client.

The worst findings are not in the vault or the matcher. They are in the
new client that talks to them.

| ID | Severity | One line |
|---|---|---|
| **R-01** | **High** | Unsigned `/release.json` is the whole venue TCB; T-03's trigger has fired |
| **R-02** | **High** | Push-oracle mode accepts an unsigned price whose only provenance is RPC JSON |
| **R-03** | **High** | Vault worker returns `spendingKey` / `noteSecret` to page JS |
| **R-04** | **High** | Backup restore / inventory wipe resets `nextOrderIndex` to 0 |
| R-05 | Medium | `fetchBounded` follows 307/308 with admin and session CVM secrets |
| R-06 | Medium | Reference daemon does not pin `oracle_mode`; compose defaults to the weak source |
| R-07 | Medium | Empty recovery scan advances the cursor to chain tip |
| R-08 | Medium | Host mints durable CVM accounts for anyone who can set `Origin` |
| R-09 | Medium | Wallet Standard chain is hardcoded `solana:devnet` |
| R-10 | Low | Compose default pair (`mainnet` + push) is internally illegal |
| R-11 | Info | Comment-vs-code cluster on lockstep-critical files |
| R-12 | Low | Public GitBook oracle docs describe a different source than the wire |
| R-13 | Info | Loadgen helper freshness is 90 s; TEE push policy is 420 s |
| R-14 | Low | Browser attestation `getJson` has no abort and no body cap (SW-17 twin) |
| R-15 | Medium | Start-cookie turns the host into a billed Helius amplifier (SW-02 class) |
| R-16 | Medium | Proxied `/attestation` can drain the venue-wide public bucket |
| R-17 | Medium | `normalizeCommitments` recurses without a depth cap |
| R-18 | Medium | Image default listen is `0.0.0.0` (SW-19-class default) |
| R-19 | Low | Proxy forwards `Authorization` to the RPC upstream |
| R-20 | Low | HTTP proxy omits the Origin check the session endpoints already do |
| PF-28 | Perf-Nit | Encrypted inventory is rewritten in full on every mutation |
| PF-29 | Perf-Nit | Browser recovery walks the vault's entire signature history |
| PF-30 | Perf-Nit | Recovery does sequential `getAccountInfo` per note |

**Closed `audit_7` properties that still hold:** CA-01's `event_type ===
DSTACK_RUNTIME_EVENT_TYPE` check is on the browser path; SW-07-style
instruction scoping is present in the indexer watcher; consume-once PDAs
did not fork namespaces under v11.

A clean generalist read of the circuits is **not** a substitute for
`F-04`. Findings are not fixes.

---

## 2. Findings

### R-01 — Unsigned `/release.json` is the venue TCB (T-03 trigger fired)

**Severity:** High
**Category:** Security / attestation
**Lockstep:** no

**Anchors:**
`packages/browser-client/src/app/release.ts:148-171`,
`packages/browser-client/scripts/build-production-app.mjs` (SRI only on hashed JS/CSS),
`packages/browser-client/scripts/assemble-production-release.mjs` (writes `gateway_url` / compose hash / artifact key after the hashed bundle exists),
`packages/browser-client/src/venue/trusted-venue.ts:135-173`,
`packages/sdk/src/tee/verify-core.ts:259-269,294-299`.

**Problem.** Production HTML SRI-pins the JS/CSS bundle. Every pin that
makes "Attested" mean anything — `expected_compose_hash`,
`vault_program_id`, artifact Ed25519 key, `expected_oracle_mode`,
`gateway_url` — is loaded from `/release.json`, which is `no-store`,
unsigned, and assembled *after* the hashed app. The app then runs a real
DCAP + CA-01-strict compose-hash check against whatever that file names,
and opens order flow to the same-origin proxy that served it.

TLS terminates at the trader origin. The quote authenticates the CVM
*behind* the proxy, not the proxy and not this TLS session. `T-03`
recorded that residual and said to re-enter before committing to a
browser client. The browser client shipped.

**Failure scenario.** An operator (or anyone who can PUT one object on
the static host) replaces `/release.json` and leaves the SRI-pinned JS
alone. Users still see "Attested". The hashed app will verify whatever
enclave the new file names, accept whatever zkeys the new artifact key
signs, and deposit into whatever program id is listed. A party holding a
valid certificate for the origin reads every signed order, fill frame,
inclusion witness, and bearer token.

A regression test: serve a release whose `expected_compose_hash` and
`gateway_url` disagree with the hashed-app build inputs; the app must
refuse. Today it accepts.

**Fix options.**

| Option | Trade-off |
|---|---|
| **A (recommended).** Bake compose hash, vault program id, artifact key, oracle mode, and origin into the hashed JS at `build:app` time. `release.json` becomes debug-only. Rotation = new content-addressed bundle. | ~1 day. Loses late-binding of pins; that is the point. |
| **B.** Sign `release.json` with a key **embedded in the hashed bundle** (same domain-separation style as the artifact manifest). Reject unsigned or key-id-mismatched releases. | ~1 day. Keeps late-binding, adds a second signed envelope. |
| **C.** Close T-03 for browsers: attested ingress or in-enclave RA-TLS whose quote binds the TLS SPKI. Do not ship the "Attested" label until the fetch/WS session is that binding. | The costed T-03 designs. Days, not hours. Required before external users regardless of A/B. |

Do **not** treat SRI on the JS bundle as covering `release.json`. The
assembler writes it afterwards on purpose.

---

### R-02 — Push-oracle mode accepts an unsigned price whose only provenance is RPC JSON

**Severity:** High (any CVM that matches in `pyth-solana-push-v1`)
**Category:** Security / provenance
**Lockstep:** no circuit change; docs + client pins should describe the trust drop

**Anchors:**
`crates/darknyx-tee/src/oracle/push.rs:99-178,257-298`,
`crates/darknyx-tee/src/oracle/source.rs:14-18,41-48`,
`crates/darknyx-tee/src/main.rs:409-421`,
`crates/darknyx-tee/src/solana_rpc/client.rs` (`owner` is RPC-supplied),
contrast `crates/darknyx-tee/src/oracle/sync.rs:318-407` (router still verifies VAA + inclusion).

**Problem.** The router path still does in-enclave crypto: Hermes bytes →
`vaa::verify_for_profile(RouterQuorumV1)` → Merkle inclusion under that
VAA root. The new push path does not re-verify a VAA, Merkle proof, or
router signature. After deriving the official shard-0 PDA it trusts:

1. `getMultipleAccounts` at `finalized`
2. RPC-reported `owner == rec2HHDD…`
3. the 8-byte `PriceUpdateV2` discriminator and Borsh layout
4. `write_authority == derived PDA`, `VerificationLevel::Full`, feed-id match, `posted_slot ≤ context.slot`

`CachedPrice.evidence` is empty; the comment says the Solana account
*is* the evidence. Owner, discriminator, Full-verification, and EMA are
all fields a lying RPC chooses. Structural checks answer "does this
*look like* a Pyth account?" They do not answer "did Pyth publish this
price?"

This is the same provenance class as `SW-07`: the decoder parses
correctly and accepts input whose origin was never established. Price
fairness is already TEE-trusted; the new fact is that push **drops the
in-enclave Pyth proof that T-01 / C-05 added**, while still feeding the
same matcher, with a **420 s** freshness window.

**Failure scenario.** CVM booted with
`DARKNYX_TEE_ORACLE_MODE=pyth-solana-push-v1` (compose default, runbook,
every current real-settle CVM). Attacker controls
`DARKNYX_TEE_SOLANA_RPC_URL` (stolen Helius key, malicious URL in
encrypted env, or a TLS peer the rustls client still accepts). On the
next 2 s poll they return a well-formed `PriceUpdateV2` at the derived
PDA with `ema_price` of their choosing, `publish_time` within 420 s, and
`posted_slot` ≤ the `context.slot` they also invent. `decode_price_account`
accepts it. Matching and place stay open. Clearing runs against the
forged EMA for up to seven minutes.

The same bytes are rejected on the router path: no 3-of-5 VAA.

A regression test: feed `getMultipleAccounts` a structurally valid
`PriceUpdateV2` whose EMA is not the one a guardian-signed VAA would
authorize; push mode must not be the producer that can open a trading
gate when real mints are configured. Today it is.

**Fix options.**

| Option | Trade-off |
|---|---|
| **A (recommended).** Keep push as a rehearsal adapter only. `governed_market == true` / real mints ⇒ force `PythRouterQuorumV1`. | Restores "unsigned price cannot clear" for value-bearing boots. Breaks `cvm-settle-e2e` until Hermes creds are on that path. |
| **B.** In push mode, require a VAA (or Hermes binary) and run `verify_for_profile` + inclusion before `apply_verified_batch`. Account fields become a locator. | Same provenance as router; depends on what the sponsored account actually stores. |
| **C.** If RPC-trust is accepted, record it as an explicit trust-boundary change: refuse push unless `deployment_tier=development` **and** every client pins the mode (R-06). Document that `compose_hash` does not cover this. | Honest; does not stop a hostile RPC. |

Do **not** "fix" this by tightening discriminator/owner checks. Those are
already present and are not a signature.

---

### R-03 — Vault worker returns `spendingKey` / `noteSecret` to page JS

**Severity:** High
**Category:** Security / client custody
**Lockstep:** no

**Anchors:**
`packages/browser-client/src/custody/browser-vault.ts:111-116` (claims the seed exists only in the Worker),
`packages/browser-client/src/custody/vault.worker.ts:614-623` (`prepareDeposit` returns `spendingKey`, `ownerCommitmentBlinding`, `noteSecret`),
`:675-689` (`prepareSpend`),
`:799-817` (`prepareMerge`),
`:935-945` (`validInputWitness` stringifies `spendingKey`),
`packages/browser-client/src/account/account-operations.ts:278-288`,
`packages/browser-client/src/inventory/input-proof-producer.ts:126`,
`packages/browser-client/src/inventory/inventory-store.ts:50-62` (openings decoded on the page).

**Problem.** The module comment is precise about XSS, then the product
surface claims page code receives aggregate balances and opaque handles
only. What actually crosses `postMessage` into the main thread on the
first deposit, withdraw, merge, or background VALID_INPUT refresh is the
wallet-wide spending key and the per-note secret. `BrowserInventory`
also holds every opening (`innerHash`, amounts, tags) in main-thread
memory for the unlocked lifetime.

The 64-byte master seed stays in the worker. The spending key is
sufficient to nullify and spend every current note.

**Failure scenario.** A compromised main-bundle dependency (React, a
wallet-standard helper, any future analytics) does not need WebAuthn and
does not need the seed. On the first prove it reads `spendingKey` +
openings from the worker response or from `#snapshot` and can spend
every note. No user prompt.

A regression test: after `prepareDeposit` / `validInputWitness`, the
object that lands in the page must not contain `spendingKey`,
`noteSecret`, or `ownerCommitmentBlinding`. Today it does.

**Fix options.**

| Option | Trade-off |
|---|---|
| **A (recommended).** Prove inside the vault worker, or have the vault worker own a child prover worker and never `postMessage` witnesses to the page. Return only `{piA,piB,piC,publicInputs}`. | ~2 days. Correct isolation. Larger worker bundle. |
| **B.** If openings must live on the page for UX, never return `spendingKey` / `noteSecret` / `ownerCommitmentBlinding`. Those three are sufficient to steal. | ~0.5 day. Leaves openings on the page (amounts, inners). |
| **C.** Document the page as the TCB and drop the worker-isolation claim. | Honest; not a confidentiality boundary. |

---

### R-04 — Backup restore / inventory wipe resets `nextOrderIndex` to 0

**Severity:** High
**Category:** Security / recovery (SW-10 class, new client)
**Lockstep:** no

**Anchors:**
`packages/browser-client/src/trader/controller.ts:496-512` (`restoreBackup` clears the inventory store then `#openRuntime`),
`packages/browser-client/src/inventory/browser-inventory.ts:36-46` (empty snapshot starts at `nextOrderIndex: 0`),
`:475-485` (`allocateOrderIndex` persists-then-returns — correct *after* a healthy snapshot),
`:1086-1096` (`recover` rebuilds notes, not the HD high-water),
`packages/browser-client/src/custody/vault.worker.ts:531` (`arrivalNonce: 1n` always),
`packages/sdk/src/fills/chain-history.ts` (`backfillHistoryFromChain` already computes `highestUsedIndex` and is unused here).

**Problem.** SW-10 exists because the order-id sequence is not
rebuildable from seed + chain unless someone actually scans it. The
daemon now has a mode-0600 sidecar. The browser persists the high-water
only in the encrypted inventory DB. Restore (and any wipe of
`darknyx-browser-inventory` that keeps the vault) loads an empty
snapshot. Chain recovery rebuilds note openings. It does not HD-gap-scan
historical `order_id`s.

**Failure scenario.**

1. User exports a backup, restores on a new browser, or clears the inventory DB.
2. First new order reuses historical `order_id` + trading key 0, `arrivalNonce = 1`.
3. If the CVM replay map still has that id with a different digest → hard reject.
4. After a CVM restart the maps are empty → **intake accepts** the colliding id.
5. `BrowserInventory.recover` then walks continuations by `orderId` +
   `consumedCommitment` and can attach **old** fill outputs to the **new**
   journal row, locking or consuming the wrong notes.

A regression test: provision, allocate index 0, export, restore, allocate
again; the new index must be `>= 1` after a chain scan that saw the
original order. Today it is 0.

**Fix options.**

| Option | Trade-off |
|---|---|
| **A (recommended).** On every full recovery, HD-gap-scan `deriveOrderId` against decoded settle/place history (or at least recovered notes' `orderId`s) and persist `nextOrderIndex = highestUsed + 1` **before** enabling place. `backfillHistoryFromChain` already exists. | ~1 day. Copy the neighbour. |
| **B.** Persist the high-water in the vault ciphertext (same lifetime as the seed), not only in the inventory DB. | ~0.5 day. Survives inventory wipe; still needs A after a seed-only restore onto a fresh vault. |
| **C.** Both. | Matches the daemon's "sidecar + refuse implicit zero" bar. |

---

### R-05 — `fetchBounded` follows 307/308 with admin and session CVM secrets

**Severity:** Medium
**Category:** Security / credential containment
**Lockstep:** no

**Anchors:**
`packages/trader-host/src/http.ts:3-18` (`fetchBounded` — no `redirect` option),
`packages/trader-host/src/cvm-issuer.ts:30-46` (POST `api_key` / `api_secret` / `passphrase`),
`packages/trader-host/src/account-store.ts:164-178,321-337` (admin token exchange + `POST /admin/accounts`),
counter-example: `packages/trader-host/src/live-proxy.ts:533` (`redirect: "manual"`),
`packages/browser-client/src/app/release.ts:154` and
`packages/browser-client/src/prover/artifact-manifest.ts:343` (`redirect: "error"`).

**Problem.** Node `fetch` follows 307/308 with method and body intact.
The host POSTs the **admin** CVM credential and every per-session
credential to `DARKNYX_TRADER_CVM_GATEWAY_UPSTREAM`. That URL is not
quote-bound (T-03). The live proxy already refuses redirects; the
credential path does not.

**Failure scenario.** A 307 from the configured gateway (compromised
ingress, misconfigured reverse proxy, or an unpinned gateway change)
replays `api_key` / `api_secret` / `passphrase` — including the
server-held **admin** account — to `Location`. The attacker then
registers admin accounts, drains `/admin/drain`, or impersonates every
provisioned browser session.

A regression test: `fetchImpl` that returns 307 to `https://evil.example`
with the original body; issuer and resolver must throw and must not
follow. Mutation-test against the current `fetchBounded`.

**Fix options.**

| Option | Trade-off |
|---|---|
| **A (recommended).** Pass `redirect: "error"` (or `"manual"` + treat 3xx as failure) inside `fetchBounded`. One change covers every caller. | ~1 h. Copy the neighbour. |
| **B.** Set it only on credential POSTs. | Easy to miss the next caller. |
| **C.** Pin the gateway's measurement / SPKI (T-03). | Complements A; does not replace it. |

---

### R-06 — Reference daemon does not pin `oracle_mode`; compose defaults to the weak source

**Severity:** Medium
**Category:** Security / software engineering
**Lockstep:** yes — TEE compose, daemon config, public docs

**Anchors:**
`deploy/docker-compose.yaml:105-108` (defaults `DEPLOYMENT_TIER=mainnet` **and** `ORACLE_MODE=pyth-solana-push-v1`),
`crates/darknyx-tee/src/config.rs:296-312` (that pair fails boot),
`packages/daemon/src/daemon.ts:565-594` (attests compose/quote/keys, then `resumeTrading()`; never reads `oracle_mode`),
`packages/sdk/src/system/system-client.ts:20,34-42`,
contrast `packages/browser-client/src/venue/trusted-venue.ts:200-211,279-283` (already pins).

**Problem.** The source is boot-selected and not attacker-selectable on
the wire — good. Encrypted env is outside `compose_hash`, so a same-image
redeploy can move `router + 5 s + in-enclave 3-of-5` → `push + 420 s +
RPC-trusted EMA` with no attestation event. The compose defaults are
internally illegal (unset env → boot fail, not router). The documented
escape is `DEPLOYMENT_TIER=development`, which is every current CVM
runbook, and which **allows** push with no Pyth key.

The browser pins `expectedOracleMode`. The reference market-maker
daemon does not.

**Failure scenario.** Venue advertised as router. Someone with deploy-env
rights flips mode to push, same image. Browser release pin refuses.
**Daemon keeps placing.** Matcher now clears on RPC-trusted 7-minute
prices. `/system/status` will honestly say `pyth-solana-push-v1` /
`420000` — nothing in the daemon looks.

**Fix options.**

| Option | Trade-off |
|---|---|
| **A (recommended).** Compose default `ORACLE_MODE` to `pyth-router-quorum-v1` to match `:-mainnet`. Development runbooks must set **both** `development` and `push` explicitly. Daemon: after attestation, `fetchSystemStatus` and refuse start unless `oracle_mode === expected`. | ~0.5 day. Closes the path of least resistance and the unpinned MM. |
| **B.** `governed_market == true` ⇒ force router in `from_env`. | Makes real-settle + push a boot impossibility. Same `cvm-settle-e2e` cost as R-02-A. |
| **C.** Bind mode into something clients already verify. `report_data` is full (SW-18). | Stronger; likely blocked by the 64-byte cap. |

---

### R-07 — Empty recovery scan advances the cursor to chain tip

**Severity:** Medium
**Category:** Security / recovery (C2 / SW-11 class, new client)
**Lockstep:** no

**Anchors:**
`packages/browser-client/src/app/recovery.ts:59-64`,
`packages/browser-client/src/inventory/browser-inventory.ts:1086-1096`
(incremental `recover` does not re-run consume checks on notes absent
from the delta).

**Problem.** If `scan({ sinceSlot })` returns no transactions (quiet
epoch, RPC lag, or all hits filtered), the in-memory cursor jumps to
`finalized + 1`. A deposit or settle that lands in that skipped window
is invisible until a full reload (reload resets to
`recoveryStartSlot`). Incremental recover also does not re-check
`isConsumed` on notes the delta did not mention, so a missed consume
leaves collateral looking spendable.

Combined with R-04 this is the browser SW-11 analogue: the stream is
only a hint (good), but the chain cursor can skip the txs the hint was
supposed to be replaced by.

**Failure scenario.** Tab is open across a quiet period. RPC returns an
empty page. Cursor jumps over a settle that consumed the user's note.
UI still shows the note as spendable; a subsequent place/withdraw fails
on-chain as `NoteAlreadyConsumed` or races a lock.

A regression test: `scan` returns `[]` while `getSlot` is 100 slots
ahead; `sinceSlot` must not move. Today it does.

**Fix options.**

| Option | Trade-off |
|---|---|
| **A (recommended).** On empty scan, do not move `sinceSlot`. | ~1 h. |
| **B.** On every refresh, re-verify `isConsumed` / `isLocked` for all local notes, not only the delta. | ~0.5 day. Complements A. |
| **C.** Persist the cursor in encrypted inventory and never use `getSlot()` as a floor. | Avoids the class, not just the instance. |

---

### R-08 — Host mints durable CVM accounts for anyone who can set `Origin`

**Severity:** Medium
**Category:** Security / admission
**Lockstep:** no

**Anchors:**
`packages/trader-host/src/session.ts:179-215` (Origin + JSON body; no proof of possession),
`packages/trader-host/src/account-store.ts:262-369` (creates a durable
non-admin CVM account per session; 409 recovery path),
`packages/trader-host/README.md:16-20,54-57` (claims the browser attests
first; admits a public deployment still needs an admission policy),
`crates/darknyx-tee/src/api/auth.rs:301-306` (`register()` has **no**
account cap),
`packages/trader-host/tests/live-cvm.test.ts:31-48` (a non-browser
`fetch` with a spoofed `Origin` is the documented happy path).

**Problem.** `POST /api/darknyx/session/start` then `POST
/api/darknyx/session` with `Origin: <configured origin>` provisions a
persistent CVM account. Origin is CSRF protection, not authentication.
The browser *does* attest first (`trusted-venue.ts:149-174`). The host
does not, and nothing binds “this cookie completed DCAP.” Rate limit is
5 new sessions/min per `remoteAddress` (one IP behind a reverse proxy)
and host `maxAccounts` defaults to 10_000. The TEE `AccountRegistry`
has no cap at all. Accounts are Argon2-hashed into enclave state and
cannot be deleted.

The README names the gap. The shipped default *is* the provisioning
resolver, and the live CVM test encodes it.

**Failure scenario.** Attacker scripts `Origin: https://trader.example`
and mints accounts up to `maxAccounts`. Each costs an Argon2id hash and
a durable `accounts.db` row. The venue's account namespace fills; honest
visitors get `browser CVM account capacity reached`. There is no
retention lever short of wiping the LUKS volume.

A regression test: N unauthenticated `session/start` + `session` pairs
from one peer must stop at a documented admission cap *before* the
enclave's `maxAccounts`, or require a wallet/passkey binding.

**Fix options.**

| Option | Trade-off |
|---|---|
| **A (recommended).** Bind provision to a WebAuthn credential or a wallet signature over the session id. Origin becomes CSRF defense, not identity. | ~1.5 days. Correct for a public host. |
| **B.** Lower default `maxAccounts`, require an invite token, expose TEE account deletion. | ~1 day. Operational, not identity. |
| **C.** Keep the factory, refuse to listen on `0.0.0.0` unless an admission hook is configured. | Fail-closed default. Breaks a careless public deploy, which is the point. |

---

### R-09 — Wallet Standard chain is hardcoded `solana:devnet`

**Severity:** Medium
**Category:** Security / client
**Lockstep:** no

**Anchors:**
`packages/browser-client/src/wallet/wallet-standard.ts:55`
(`options.chain ?? "solana:devnet"`),
`packages/browser-client/src/app/main.tsx` (never passes `chain`),
`packages/browser-client/src/trader/controller.ts` (constructs the
controller with no chain).

**Problem.** A mainnet release still asks the wallet for a **devnet**
account and a devnet send. Blockhashes come from `release.rpcUrl`.
Wallets that honor `chain` refuse or use the wrong cluster; wallets
that ignore it broadcast a tx whose recent blockhash was fetched from
whatever the origin proxy points at.

**Failure scenario.** Production release, Phantom/Solflare honors
`chain: solana:devnet`, user approves a deposit from a devnet account
against a mainnet vault (fails) — or a wallet that ignores `chain`
signs a mainnet spend the UI labelled as the attested venue while the
wallet UI said devnet.

A regression test: construct the production controller; advertised
`chain` must equal the release network pin. Today it is always
`solana:devnet`.

**Fix options.**

| Option | Trade-off |
|---|---|
| **A (recommended).** Put `solana:devnet` \| `solana:mainnet` in the hashed release pins (R-01-A) and pass it into the controller. Refuse to start on disagreement. | ~0.5 day. |
| **B.** Prefer `signTransaction` + app-side send to the pinned RPC. | Stops the wallet choosing another cluster; still needs a correct `chain` label. |

---

### R-10 — Compose default pair is internally illegal

**Severity:** Low
**Category:** Software engineering
**Lockstep:** yes — both compose files + runbooks

**Anchors:**
`deploy/docker-compose.yaml:105-108`,
`deploy/docker-compose.gpu.yaml` (same pair),
`crates/darknyx-tee/src/config.rs:296-312,688-701`.

**Problem.** Unset env is `mainnet` + `pyth-solana-push-v1`. The binary
rejects that pair. The "fix" every runbook uses is
`DEPLOYMENT_TIER=development`, which is how R-02 becomes the path of
least resistance for real-settle CVMs.

**Failure scenario.** A new operator copies compose, does not read the
comment, hits a boot fail, then sets `development` to "make it start"
and ships push mode with real mints.

**Fix.** Default `ORACLE_MODE` to `pyth-router-quorum-v1`. Make
development + push an explicit two-variable choice. Same change as
R-06-A.

---

### R-11 — Comment-vs-code cluster on lockstep-critical files

**Severity:** Info
**Category:** Software engineering (C6)
**Lockstep:** comments only

This is the finding-generator `AUDIT_AGENT_ONBOARDING.md` named. None of
these is a runtime hole today. Several describe the *pre-migration*
double-spend or leaf shape as current.

| Comment claimed | Reality | File |
|---|---|---|
| `ConsumedNoteEntry` is "keyed on the note COMMITMENT" | seeds `[b"consumed_note", note_use_tag]` | `programs/vault/src/instructions/merge.rs:224-226` vs `:234` |
| Leaf is `Poseidon11(DOMAIN_LEAF_V2=23, … note_a, note_b, …)` | v3 `Poseidon12(31, … tag_a, tag_b, … relock_digest)` | `crates/darknyx-tee/src/prover/leaf.rs:15-21` vs `:83-120`; same drift in `packages/sdk/tests/helpers/match-batch-prover.ts:17-28` |
| `withdraw` "rejects while a NoteLock exists, even an expired one" | S-03: rejects only a **live** lock | `programs/vault/src/instructions/lock_note.rs:130-131` vs `withdraw.rs:121-128` |
| Recover "payload names the exact consumed commitment" | body: "The chain no longer publishes the consumed commitment" | `packages/sdk/src/fills/recover.ts:5-6` vs `:88-91` |
| VALID_INPUT: withdraw via `NullifierEntry` | `NullifierEntry` removed; withdraw is tag-keyed `ConsumedNoteEntry` | `circuits/valid_input/circuit.circom:53-54` |
| Batched settle "coexists with `tee_forced_settle`" | non-batched handler is gone from `lib.rs` | `tee_forced_settle_batched.rs:27-30` |
| `bootSessionId` "bound by the verified TDX quote" | SW-18: `/info` only; `report_data` is full | `packages/browser-client/src/trader/intent-authorizer.ts:26-27` |

**Failure scenario.** A later edit "aligns" merge (or a new consume
path) with the merge comment and re-keys `ConsumedNoteEntry` on the
commitment. That reopens C-01: merge consumes `ConsumedNoteEntry[C]`,
settle/withdraw consume `ConsumedNoteEntry[tag]`.

**Fix.** One doc-accuracy pass *after* the code fixes in this
engagement land, same as C6 last time. Rename the merge loop binding
and harness parameters to `note_use_tag`. Replace the two leaf headers
with the v3 formula already in `match_batch.circom:483-487`.

---

### R-12 — Public GitBook oracle docs describe a different source than the wire

**Severity:** Low
**Category:** Software engineering
**Lockstep:** yes — `docs/gitbook/**` is the public SoT

**Anchors:**
`docs/gitbook/reference-data/instruments.md` (example has only
`oracle.type` + `pubkey`; table omits `source` / `account` / `age_ms` /
`max_age_ms`; prose says "authenticated oracle" for every venue),
`docs/gitbook/reference/system-status.md` (omits `oracle_mode` /
`oracle_max_age_ms`),
contrast `crates/darknyx-tee/src/api/instruments.rs:36-50,101-109` and
`docs/tee-api-openapi.yaml:398-423`.
`crates/darknyx-tee/src/oracle/hermes.rs:31-33` cites an on-chain
`read_oracle_price` the vault does not have.

**Problem.** Operators and integrators reading the public portal will
believe every venue authenticates Pyth in-enclave and will not see the
mode they must pin (R-06).

**Fix.** Update GitBook examples/tables to the OpenAPI object; say push
is finalized-RPC provenance and not guardian-verified; delete the
fictional on-chain reader. `docs/tee-architecture.md` §6 is already
accurate — copy it.

---

### R-13 — Loadgen helper freshness is 90 s; TEE push policy is 420 s

**Severity:** Info
**Category:** Software engineering / measurement fidelity
**Lockstep:** yes — `scripts/read-pyth-push-price.mjs` ↔ `source.rs`

**Anchors:**
`scripts/read-pyth-push-price.mjs` (`publishTime >= now - 90s`),
`crates/darknyx-tee/src/oracle/source.rs:14-18` (`SOLANA_PUSH_MAX_AGE_MS = 420_000`).

The helper pins the same program ids, discriminator, write-authority,
Full level, feed, trailing zeros, and `posted_slot` bound — good. A
sponsored feed at the measured 314 s cadence is valid for the matcher
and **rejected by the script**, so `--oracle-twap` is missing while the
CVM is happily matching.

**Fix.** Use 420 (or share the constant). Do not leave 90 vs 420 as two
"official" heartbeats.

---

### R-14 — Browser attestation `getJson` has no abort and no body cap

**Severity:** Low
**Category:** Security / availability (SW-17 twin, new caller)
**Lockstep:** no

**Anchors:**
`packages/sdk/src/tee/attestation.ts:111-129` (`res.json()` of
`event_log`, no `AbortSignal`, no size cap),
closed neighbour: daemon `attestation.ts` after SW-17 (15 s abort, 4 MiB
cap).

**Problem.** The browser's default verifier is this helper. A stalling
or oversized `/attestation` hangs `bootstrapTrustedVenue` with no
diagnostic and will buffer an arbitrarily large `event_log` that
`replayEventLogRtmr` then walks. It cannot make a gateway *pass*
attestation.

**Failure scenario.** Hostile gateway (the T-03 adversary) returns a
multi-hundred-MB `event_log`. The tab OOMs during the trust bootstrap
the UI labelled "Attested".

**Fix.** Copy the daemon's 15 s abort + 4 MiB cap, enforced on the body
actually read. ~1 h.

---

### R-15 — Start-cookie turns the host into a billed Helius amplifier

**Severity:** Medium
**Category:** Security / availability (SW-02 class, new instance)
**Lockstep:** no

**Anchors:**
`packages/trader-host/src/live-proxy.ts:19-32` (allowlist includes
`getMultipleAccounts`, `getTransaction`, `getSignaturesForAddress`),
`:165-166` (batch up to 50),
`:337-338,348-368` (default 600 req/min/session; no per-method cost),
`:484-510` (cookie-only; `/session/start` is enough),
`packages/trader-host/src/session.ts:266-273`.

**Problem.** After a start-cookie the client spends the **operator
Helius key**. No `sendTransaction` (good), and upstream errors are not
interpolated with the RPC URL (not SW-01). The leak is *use* of the
secret: 50-wide batches, `getMultipleAccounts` with no pubkey cap,
16 MiB responses, 5 sessions/min/IP × 600 rpm.

**Failure scenario.** `POST /session/start` then 50×`getMultipleAccounts`
of 100 pubkeys at 600 rpm. Helius bills the operator; a 429 storm on
that key also starves the CVM settle path that shares it.

A regression test: cookie from `/session/start` only; assert 429 well
before that volume, and that `getMultipleAccounts` keys are capped.

**Fix options.** Weighted method costs + key-count caps (copy the CVM
`public_route_cost` idea). Require the post-attest bearer even for RPC.
Separate cheap public RPC (slot/blockhash) from history methods.

---

### R-16 — Proxied `/attestation` can drain the venue-wide public bucket

**Severity:** Medium
**Category:** Security / availability
**Lockstep:** no

**Anchors:**
`packages/trader-host/src/live-proxy.ts:231-235,268-284`,
`crates/darknyx-tee/src/api/rate_limit.rs:68-74` (`/attestation` cost
10.0),
`crates/darknyx-tee/src/api/state.rs:439-450` (capacity 200, refill
100/s).

**Problem.** SW-02's public bucket is venue-wide because every CVM
client appears as one WireGuard peer. The host is another firehose:
10 proxy req/s of `/attestation` is ~100 cost/s, the entire refill.
One start-cookie session can 429 the daemon's and every other
browser's attestation.

**Failure scenario.** Loop
`GET /api/darknyx/venue/attestation?reportData=<64 hex>` from one host
session; a second client's `/attestation` (or daemon verify) starts
getting 429.

**Fix.** Host-side attestation cap (e.g. 2/min/session) and/or
cache-and-refuse duplicate nonces. A CVM bucket keyed by a
host-injected account is harder and not required.

---

### R-17 — `normalizeCommitments` recurses without a depth cap

**Severity:** Medium
**Category:** Security / availability
**Lockstep:** no

**Anchors:**
`packages/trader-host/src/live-proxy.ts:148-159,187`.
Counter-example: `packages/client-core/src/intent-validation.ts:6-7,31-32`
(depth 8 + `__proto__` reject).

**Problem.** After `JSON.parse` of up to 2 MiB, the walker recurses on
every object/array. A session-holder can stack-overflow the Node
process (one process = all visitors).

**Failure scenario.** POST `/api/darknyx/rpc` with nesting depth 10k;
process dies instead of returning 400.

**Fix.** Depth/key caps; iterative walk; or only rewrite
`params[configIndex].commitment` instead of walking the whole tree.
The last is the smallest and matches what the function is *for*.

---

### R-18 — Image default listen is `0.0.0.0`

**Severity:** Medium
**Category:** Security (SW-19-class default)
**Lockstep:** no

**Anchors:**
`packages/trader-host/Dockerfile:17-18`
(`DARKNYX_TRADER_LISTEN_HOST=0.0.0.0`),
`packages/trader-host/src/runtime-config.ts:195-199` (library default
`127.0.0.1`),
`deploy/trader-host/docker-compose.devnet.yaml:11-12,29` (compose
publishes `127.0.0.1:8080` — the good neighbour).

**Problem.** Running the published image without the compose port
mapping exposes R-08 / R-15 / R-16 on the public internet, on
plaintext HTTP. The library default is loopback; the image overrides
it.

**Failure scenario.** `docker run` the image on a VPS; R-08's curl
factory is reachable from the world on port 8080.

**Fix.** Drop the Dockerfile override; refuse `0.0.0.0` unless
`DARKNYX_TRADER_ALLOW_WILDCARD_BIND=1` is explicit.

---

### R-19 — Proxy forwards `Authorization` to the RPC upstream

**Severity:** Low
**Category:** Security
**Lockstep:** no

**Anchors:**
`packages/trader-host/src/live-proxy.ts:517-524` (auth copied for
**all** targets, including RPC).

**Problem.** A confused client or XSS
`fetch('/api/darknyx/rpc', { headers: { authorization }})` sends the
CVM JWT to the RPC vendor.

**Failure scenario.** Browser XSS posts the session bearer to
`/api/darknyx/rpc`; Helius logs see `Authorization: Bearer <jwt>`.

**Fix.** Forward `Authorization` only for venue URLs. Cap
`getMultipleAccounts` keys in the same change (R-15).

---

### R-20 — HTTP proxy omits the Origin check the session endpoints already do

**Severity:** Low
**Category:** Security
**Lockstep:** no

**Anchors:**
session: `packages/trader-host/src/session.ts:188-193`,
WS: `packages/trader-host/src/live-proxy.ts:552-554`,
HTTP proxy: `packages/trader-host/src/live-proxy.ts:484-486`
(`admit()` = cookie only).

**Problem.** Mutations still need a CVM bearer (not a CORS simple
header), and the cookie is `SameSite=Strict`, so classic CSRF is weak
today. The inconsistency is the SW-19 lesson: the hardened path is not
the proxy. WebViews that mishandle SameSite, or a future cookie-flag
slip, reopen GET data exfil (`/account`, `/tree/leaves`) with only
the cookie.

**Failure scenario.** Cookie present, `Origin: https://evil.example` →
proxy HTTP currently 200/401 on auth, not 403. Session endpoints
would 403.

**Fix.** Reuse the session Origin + optional `Sec-Fetch-Site` check
on `handleHttp`. Cheap.

---

## 2b. Performance findings

### PF-28 — Encrypted inventory is rewritten in full on every mutation

**Severity:** Perf-Nit
**Category:** Performance (C12 / PF-12 class, client)

**Anchors:**
`packages/browser-client/src/inventory/browser-inventory.ts:384-389`
(`#mutate` clones the snapshot, runs the op, `#save`s),
`packages/browser-client/src/inventory/inventory-store.ts:251-273`
(JSON-encode entire snapshot, AES-GCM, one IndexedDB `put`).

Every `allocateOrderIndex`, reserve, and recover writes the full note +
proof + order set. Fine for a handful of notes. A long-lived browser
session with dozens of proofs (256 B each) and recovered openings pays
O(n) seal+write per click.

**Fix.** When it binds: delta-encode, or keep proofs in a second store
keyed by commitment. Do not pre-emptively restructure.

### PF-29 — Browser recovery walks the vault's entire signature history

**Severity:** Perf-Nit
**Category:** Performance

**Anchors:**
`packages/sdk/src/fills/chain-history.ts` (`makeConnectionScan` walks
signatures since the epoch),
`packages/browser-client/src/app/recovery.ts` (posts the full
`RawSettleTx[]` into the worker).

Mainnet settle volume will OOM the tab; `refreshTimeoutMs` (30 s) then
fails the whole runtime. Same scan also feeds R-07's cursor.

**Fix.** Bound pages and worker payload size; persist a cursor that
only moves on a non-empty page (R-07-A). Schedule with R-07.

### PF-30 — Recovery does sequential `getAccountInfo` per note

**Severity:** Perf-Nit
**Category:** Performance (C4 class, new client)

**Anchors:**
`packages/browser-client/src/inventory/browser-inventory.ts:1028-1056`,
`packages/browser-client/src/inventory/finalized-root-source.ts:51-82`.
The host already allowlists `getMultipleAccounts`
(`live-proxy.ts:21`).

**Problem.** Each recovered note does 1–2 finalized account reads
through the host. A used account (hundreds of historical notes) is
hundreds of sequential RPCs on every `refresh()`. Owner checks on
those reads are correct (provenance-clean). The hot path is not.

**Fix.** Batch + bound concurrency (16–32). Watch R-15's key-count
caps.

---

## 3. Verified clean

Recorded so the next audit does not re-derive them.

**Note-use-tag consume namespace (PR #113).** Every consume/lock path
keys on the tag: `lock_note`, `withdraw`, `merge`,
`tee_forced_settle_batched`. `DepositedNoteEntry` stays
commitment-keyed (creation guard; a depositor has no tag yet).
`init_if_needed` is not used on consume/lock PDAs. Passing a
commitment where a tag is required fails closed (`InvalidProof` /
`InvalidBatchBinding` / `AccountNotFound`). Rust / TS / circom agree
on `Poseidon3(29, commitment, inner_hash)`. VALID_INPUT recomputes the
commitment from the private opening, range-checks amount, binds
`noteUseTag === Poseidon3(29, C, inner)`, and Merkle-proves **C**, not
the tag.

**Input commitments off Tx D.** Payload v11 carries `note_a/b_use_tag`
and `note_e/f_use_tag`. Output/fee fields stay commitments (they are
leaves). Domain `b"darknyx-match-v11"`, 552-byte Borsh, hash order
matches vault / TEE / harness / SDK. `cvm-settle-e2e` asserts the two
consumed Merkle commitments are absent from the serialized Tx D.

**Merkle leaf v3 lockstep.**
`relock_digest = Poseidon3(30, tag_e, tag_f)`;
`leaf = Poseidon12(31, active, tag_a, tag_b, C_c…C_f, C_fee_base,
C_fee_quote, batch_slot, relock_digest)` in the circuit, on-chain
`compute_match_leaf`, TEE `leaf.rs`, and the TS prover helper. (The
*headers* of the last two are stale — R-11 — the functions are not.)

**BatchValidityMarker is still 1:N and read-only in Tx D.**
`UncheckedAccount`, not `mut`; TEE builder `new_readonly`; SDK
`isWritable: false`. Close is a separate ix, only at/after expiry.

**Tx D size after v11.** Payload spent the 64 bytes v9 freed. Measured
1173 / 1232, 59 B headroom, guard at 1180. The
`tx_d_stays_within_the_size_budget` test is the tripwire.

**CA-01 still held on the browser path.**
`composeHashFromEventLog` requires `event_type ===
DSTACK_RUNTIME_EVENT_TYPE` and exactly one match;
`hasImpossibleEventLogEntry` rejects digest+payload;
`verifyTeeAttestation` calls `verifyReportAgainstExpected({ strict:
true })`. No `event`/`imr`-only fallback.

**Router oracle provenance still holds.** Production pins
`TrustProfile::RouterQuorumV1`. JSON/binary split aborts the whole
batch. Duplicate / missing requested feeds fail. Boot never constructs
`LegacyWormholeV1`. Stale/missing prices pause place/modify; they do
not fail open. Debug seed stays `#[cfg(feature = "debug_endpoints")]`
(SW-33).

**Push structural checks (as checks).** Official SOL PDA is pinned.
Partial verification, wrong owner, feed substitution, future
`posted_slot`, executable accounts, and `posted_slot == 0` are
rejected. These do not substitute for a signature (R-02).

**Trader-host session cookie.** `__Host-` prefix, `Secure`,
`SameSite=Strict`, `HttpOnly`, HMAC-SHA-256 over `session.issuedAt`,
`timingSafeEqual`. Origin + `Sec-Fetch-Site` + JSON content-type on
the session endpoints. Proxy admit requires that cookie. Venue routes
are an allowlist; RPC methods are an allowlist and force
`commitment: "finalized"`; no `sendTransaction`. WS auth is in-band
(`op: login`); stripping `Authorization` on upgrade is correct.
Account-store is AES-256-GCM with bindable AAD, `wx` temp files,
`0600`, directory fsync. Cookie key ≠ account-store key. Unknown
`DARKNYX_TRADER_*` env fails boot.

**Browser wrapping crypto.** WebAuthn PRF → HKDF → non-extractable
AES-GCM; AAD binds format/version/credential/prf/salt; 12-byte IV;
64+16 ciphertext length check; output buffers zeroed. Backup is scrypt
N=2^17 with allowlist `{2^14, 2^17}` and a 12-character passphrase
floor. Artifact manifest is domain-separated Ed25519 with path-escape
reject, `redirect: "error"`, SHA-256 + length.

**Fill-memo integrity on the browser path.** The fills channel ignores
payload and reconciles (`lifecycle-stream.ts:113-116`). Openings come
from `recoverFillFromChain`, which re-derives
`Poseidon3(24, input_inner, role)` and checks the chain commitment.
Live `fill-memo.ts` is not used here.

**Indexer instruction scoping.** `extractFills` keeps only
`ix.programId === programId` (`packages/indexer/src/watcher.ts:55-62`).
That is the SW-07 neighbour, applied.

**`api/auth.rs` comments** about snapshot compatibility and the
denylist are now accurate (SW-30's fourth instance was fixed).
`settle/recover.rs` still correctly documents that the enclave does
not restore resting orders.

---

## 4. Coverage

Non-test lines, this engagement.

| Surface | Approx. LOC | Status |
|---|---|---|
| `packages/trader-host/src/**` | ~2,100 | **Audited.** R-05, R-08. Session/cookie/proxy/CSP/account-store verified clean (§3). |
| `packages/browser-client/src/**` | ~8,300 | **Audited.** R-01, R-03, R-04, R-07, R-09, R-14, PF-28, PF-29. |
| `packages/browser-client/scripts/**` | ~1,100 | **Audited** for the release/SRI/artifact question (R-01). |
| `packages/client-core/src/**` | ~350 | **Audited.** Intent coordinator fail-closed verified. |
| `crates/darknyx-tee/src/oracle/**` | ~2,600 | **Audited** as the source-switch cluster. R-02, R-06, R-10, R-12, R-13. Parsers not re-litigated. |
| `programs/vault/src/instructions/{lock_note,withdraw,merge,deposit,tee_forced_settle,tee_forced_settle_batched,verify_match_batch}.rs` | ~2,400 | **Audited** for the tag lockstep. Clean; R-11 comments only. |
| `circuits/{valid_input,valid_spend,valid_deposit}` + `templates/{valid_merge,match_batch}.circom` | ~1,400 | **Read** for tag + leaf constraints. Clean. **Not F-04.** |
| `crates/darkpool-crypto/src/note_use.rs`, SDK `utxo/note-use.ts`, `settlement/settle-builder.ts`, TEE `settle/payload.rs` + `prover/leaf.rs` | ~1,200 | **Audited** as the v11 lockstep. Clean. |
| `packages/sdk/src/tee/{verify-core,attestation}.ts` | ~500 | **Audited** on the browser call path. CA-01 holds; R-14 on `getJson`. |
| `packages/sdk/src/fills/recover.ts` | ~220 | **Audited.** Body clean; header stale (R-11). |
| `packages/indexer/src/{decode,watcher}.ts` | ~400 | **Skimmed** for provenance. Instruction-scoped. Descoped remainder. |
| `packages/daemon/src/daemon.ts` attestation → resume | ~80 | **Audited** for the oracle-pin question (R-06). |

**Not read, still carry-forward:**

- `packages/indexer` beyond decode/watcher (owner-descoped locator).
- Loadgen `real_settle/` (measurement lens only; R-13 is the helper).
- Vault admin/governance ixs (`initialize*`, `rotate_root_key`, `set_*`,
  `close_*`) — audit_1 covered; unchanged in shape.
- GPU prover FFI beyond the SW-32 gate.
- A line-by-line re-read of `settle/worker.rs` / matcher algorithm /
  circuits for underconstrained signals. Those were audit_7-clean; this
  pass did not repeat them.
- Dynamic testing: still no fuzz harness (`FUZZ-01`). Still no reorg
  simulation.

**Reading is not assurance.** The circuit result in §3 closes a
*coverage* gap, not the *assurance* gap `F-04` names.

---

## 5. What I could not rule out

These are not open findings. They are questions where reading this
repository cannot produce the answer.

| Question | Why it matters | Who can answer |
|---|---|---|
| **Is `/release.json` ever written to a live origin after the hashed app is already served?** The assembler uses `wx` against a fresh dir, not against a CDN object. | Decides whether R-01 is "operator rotation hazard" or "anyone with a PUT". | Whoever operates the trader origin. |
| **Will any value-bearing CVM boot `pyth-solana-push-v1`?** Every current runbook does, under `development`. | Decides whether R-02 is High on the live path or only on rehearsals. | Whoever sets `DARKNYX_TEE_ORACLE_MODE` on the next billed CVM. |
| **Does a dstack overlay encrypt `/tmp` and the container writable layer?** audit_7 §5; SW-14 stayed Medium on a later `dstack-prepare.sh` read. | Independent of this pass; do not re-open SW-14 on that answer alone. | Phala/dstack. |
| **Does my clean circuit read substitute for F-04?** **No.** | External circuit audit remains a mainnet gate. | An external circuit auditor. |
| **Does `backfillHistoryFromChain` see enough history on a restored browser to recover `highestUsedIndex`?** Devnet Helius retains ~2 weeks. | Caps R-04-A if the user restores after that window. | Measure against the production RPC retention. |

---

## Two things to state honestly

1. **Reading is not assurance.** §3's circuit result is a generalist
   read for known bug classes. `F-04` remains an open mainnet gate.
2. **Findings are not fixes.** Several of these (R-01-C, R-02 on a live
   CVM, T-03) need a ceremony or a billed CVM to verify, not a green
   local gate. The browser trader is not launch-qualified until R-01
   and T-03 move.

---

*Last updated: 2026-08-15 — engagement `audit_8`, prefix `R-` /
`PF-28…`. Status moves in `residual-backlog.md` and, once remediation
starts, `audits/audit_8/tracker.md`. This file is point-in-time
evidence.*
