# Darknyx TEE — Internal Architecture

> As-built design of `crates/darknyx-tee`, the matching/proving/settlement
> binary deployed in a Phala Intel TDX CVM. The wire contract is
> [`tee-api-openapi.yaml`](tee-api-openapi.yaml); client verification is in
> [`tee-attestation-flow.md`](tee-attestation-flow.md); operations are in
> [`cvm-run-runbook.md`](cvm-run-runbook.md) and
> [`gpu-tee-runbook.md`](gpu-tee-runbook.md).
>
> **Last reviewed:** 2026-07-26.

## 0. Locked decisions

| # | Decision | Current choice |
|---|---|---|
| D1 | Hosting | Phala Cloud Intel TDX CVM; the container remains portable to compatible dstack deployments |
| D2 | Signer rotation | Multisig-gated off-chain attestation review; on-chain DCAP verification deferred |
| D3 | API edge | RA-HTTPS through the dstack/Phala gateway; order intent terminates inside the measured CVM |
| D4 | Prover | Witness and Groth16 proof generation stay inside the confidential boundary |
| D5 | Matching cadence | One 2,000 ms frequent-batch driver per configured market |
| D6 | read/index surface | K Merkle mirrors and account/order reads share the TEE process; chain reads remain the trustless fallback |
| D7 | multi-market | 1..16 boot-static markets per CVM, one market per proof batch |
| D8 | settlement gating | Book quantities/fills commit only after Tx D reaches the configured confirmation commitment |

These choices separate custody soundness from execution fairness. The vault and
proofs enforce conservation, asset identity, ownership, fees, and output
recoverability. The measured matcher enforces signed limits, uniform clearing,
tick/minimum rules, oracle guardrails, and liveness.

## 1. Process and trust boundaries

```text
SDK / daemon
  CSPRNG seed, spending key, client proofs, order signatures
  quote/RTMR verification + finalized chain key/config checks
                         │ HTTPS / WSS
                         ▼
dstack gateway → Intel TDX CVM
  darknyx-tee (single multithreaded Tokio process)
    public/protected HTTP routers + /v1/stream
    account auth + per-account routing/rate limits
    one MatcherState + driver per market
    shared oracle cache
    VALID_MATCH_BATCH prover
    K Merkle mirrors
    shared ALT pool + RPC client
    K dstack-derived settlement signers
                         │ HTTPS RPC + signed txs
                         ▼
Solana vault
```

The gateway address and TLS presentation are deployment-specific. Clients do
not infer trust from the hostname or certificate alone; they verify the
attestation payload and its relationship to finalized on-chain governance.

Production startup is fail-closed. Failure to contact dstack/KMS, read governed
state, initialize RPC, or reconcile the configured market/signer set aborts the
process. Test auth/state is available only when both an explicit simulator
endpoint and `DARKNYX_TEE_ALLOW_TEST_AUTH=1` are present. Known
`darknyx-test-*` credentials are rejected in production configuration.

## 2. Source structure and byte contracts

The live module tree is:

```text
crates/darknyx-tee/src/
├── main.rs, boot.rs, config.rs
├── api/
│   ├── auth.rs, rate_limit.rs, account.rs
│   ├── orders.rs, order_router.rs, fills_router.rs
│   ├── stream.rs, tree.rs, settlement.rs, metrics.rs
│   └── health.rs, info.rs, attestation.rs, instruments.rs,
│       system.rs, transparency.rs
├── keys/                 dstack key derivation
├── matcher/              book, interval driver, lifecycle, fill/opening state
├── oracle/               boot-selected Pyth source verification and shared cache
├── merkle/               K cold-boot/live mirrors
├── prover/               witness, leaf/constraint guards, ark/rapidsnark/icicle
├── settle/               lock, proof, ALT, Tx D, outcomes, metrics, sweepers
├── persistence/          auth + pending marker/lock snapshots
└── solana_rpc/           RPC transport and transaction reconciliation
```

Two workspace crates are load-bearing:

- `darkpool-matcher` is the single source of truth for matching,
  canonical order/cancel digests, FIFO/tie rules, and continuation derivation.
- `darkpool-crypto` is the Rust source for Poseidon, note/use-tag, key, and
  match-config primitives that must remain byte-identical to the TypeScript SDK.

There is no `darknyx-tee-types` crate. On-chain Borsh layouts are hand-mirrored
in `packages/sdk/src/idl/vault-client.ts`; parity and fixed-vector tests are the
schema contract.

## 3. Boot sequence

A governed real-settlement boot:

1. Parse strict environment configuration.
2. Contact dstack over `/var/run/dstack.sock`.
3. Derive a fresh process boot-session ID and K Ed25519 signers:
   `darknyx/ed25519-signer/v2/{0..K-1}`.
4. Export `/info` metadata and nonce-fresh `/attestation` evidence. Quote
   `report_data` binds the complete ordered signer set; the process-local boot
   session is separately signed into every order/cancel intent.
5. Connect to Solana RPC and read finalized `VaultConfig`.
6. Require non-default keys, `num_tee_keys == num_trees`, exact K signer
   equality, fee/protocol-owner validity, and configuration agreement.
7. Read every configured `MarketConfig` by base/quote mint, require it enabled,
   and replace environment economics with the finalized governed values.
8. Cold-boot K Merkle mirrors from `DARKNYX_TEE_SYNC_FROM_SLOT`, then begin
   live reconciliation.
9. Load the N=16 proving key/backend and rolling ALT state.
10. Restore auth and pending sweeper snapshots from the dstack-encrypted volume.
11. Spawn oracle, slot, priority-fee, governance, mirror, sweeper, and per-market
    matcher/scheduler tasks.
12. Serve HTTP on the configured bind address (default `0.0.0.0:8080`).

Placeholder mode is for simulator/loadgen development. It uses deterministic
placeholder mints and keeps real settlement disabled. It must not be confused
with a governed real-mint deployment.

### Signer lifecycle

Signer derivation is stable for the dstack app identity and derivation path.
Changing from K to K' requires:

1. initialize/deploy the matching number of Merkle shards;
2. derive the full v2 signer vector;
3. independently attest the new image/config;
4. rotate the full `tee_pubkeys` vector in shard order;
5. fund each signer, because it is both Tx fee payer and `tee_authority`.

`/info` surfaces the primary signer and the quote binds the full set. Boot logs
also print all K public keys for rotation/funding operations.

## 4. Multi-market runtime

`DARKNYX_TEE_MARKETS_JSON` is a strict 1..16-entry routing table:

```json
[
  {
    "symbol": "SOL-USDC",
    "base_mint": "<base58>",
    "quote_mint": "<base58>",
    "oracle_feed_id": "<64 hex chars>"
  }
]
```

Unknown fields, duplicate symbols/pairs, invalid mints, or malformed feed
IDs fail startup. The singular base/quote/symbol/feed environment path is a
one-market compatibility input and cannot be mixed with the JSON table.

For every market the process creates:

- an independent `MatcherState`;
- an order-route/lifecycle publisher keyed by symbol;
- a 2,000 ms matcher driver;
- a settlement scheduler that always assembles a single-market N=16 proof.

The markets share authentication, oracle cache, prover artifacts, K mirrors,
K signer keys, RPC, ALT pool, and a venue-wide whole-batch semaphore.
`DARKNYX_TEE_SETTLE_BATCH_CONCURRENCY` is clamped to 1..8 and defaults to 1.
Within one batch, `DARKNYX_TEE_SETTLE_SEND_CONCURRENCY` controls concurrent Tx D
sends (default 16).

`/instruments` lists the boot-static markets and their finalized governed
economics plus dynamic `trading_enabled` readiness. Cross-market modify is
rejected because a replacement would change the collateral mint and proof
context; clients cancel and place a fresh order.

Any configured market missing/disabled at finalized governance refresh, any
signer/config mismatch, or an untrustworthy finalized governance/configuration
refresh state pauses **new trading venue-wide**. Cancellation, outcome
reconciliation, and cleanup continue. Oracle refresh failures are scoped
to markets bound to the affected feed; healthy markets continue.

The current on-chain `VaultConfig.tee_pubkeys` is global, so one vault assumes
one authorized TEE cluster. A multi-CVM endpoint registry and seamless
cross-CVM routing are deliberately deferred; see
[`multi-market-architecture.md`](multi-market-architecture.md).

## 5. Order intake and book state

### Canonical intent

The current order domain is `darknyx-order-v5`. The canonical bytes sign:

- symbol, side, type, amount, limit, minimum fill, and expiry;
- 16-byte deterministic order ID;
- collateral note commitment;
- strictly increasing arrival nonce;
- 32-byte contributory X25519 viewing pubkey;
- 32-byte boot session ID.

The request additionally carries the private collateral opening
(`owner_commitment`, `note_inner_hash`, amount), tree/root, and VALID_INPUT
proof. It does not carry or reveal the spending key.

Intake performs, before mutating the book:

1. Layer-A bearer authorization and per-account rate limiting.
2. Exact body/wire validation and market lookup.
3. Canonical trading-key signature verification.
4. Boot-session and contributory-X25519 checks.
5. Exact-idempotency handling, then strict per-trading-key nonce monotonicity.
6. Order expiry, tick/minimum, collateral, and market-rule checks.
7. Re-derive the commitment from the supplied opening and expected side mint.
8. Require the selected shard root in the local 64-root mirror.
9. Verify VALID_INPUT against the four public signals.
10. Reserve the collateral commitment once across all live/pending venue orders.
11. Insert the order into that market's book and account/order router.

The chain repeats VALID_INPUT verification only when a matched order is locked.
Verifying at intake prevents unauthenticated or invalid proofs from occupying
the private book until settle time.

Ownership-sensitive misses return an indistinguishable 404. No log includes
clearing prices or private openings.

### Book and matching

Each book uses price/time indices plus expiry and ownership/reservation maps.
The matcher builds price-level aggregates and prefix/suffix demand curves once
per tick/page set instead of repeatedly cloning and sorting the full book.
Differential property tests pin behavior against the reference algorithm.

A tick:

1. removes expired/cancelled orders;
2. freezes a consistent snapshot;
3. selects a uniform clearing price with defined volume/imbalance/tie rules;
4. applies IOC/FOK/AON/min-fill/FIFO/self-trade constraints;
5. pages at most 16 matches per proof batch;
6. reserves matched quantities as pending settlement without publishing fills;
7. derives continuation openings from consumed input inners.

Market asks with a zero limit are eligible to trade but are excluded from
clearing-price candidates, so they cannot force a zero clearing price.
Self-trade prevention compares both the note-bound `owner_commitment` and the
trading key.

Cancel uses `darknyx-cancel-v2`, signs the order ID, trading key, strictly
increasing cancel nonce, and current boot session. PUT modify is atomic
cancel-and-replace within the same market. Cancel-on-disconnect is an
account/session setting served through `/v1/stream`.

## 6. Oracle model

Each market names a Pyth feed. Exactly one versioned source owns the shared
cache for a CVM boot:

- `pyth-router-quorum-v1` is the mainnet low-latency path. It uses the upgraded
  authenticated Pyth router, independently verifies the pinned 3-of-5 signer
  set, emitter, and Merkle-included price message, polls once per second, and
  fails closed when signed price age exceeds 5 seconds.
- `pyth-solana-push-v1` is the development path. It reads upgraded sponsored
  `PriceUpdateV2` accounts through the configured private Solana RPC at
  finalized commitment, derives every feed PDA, and checks receiver ownership,
  write authority, feed identity, full verification, and finalized posted slot.
  The sponsored devnet accounts were measured at a 314-second heartbeat, so a
  seven-minute signed-age budget covers that cadence plus finalized/RPC jitter
  while still pausing before a second expected update can be missed. It is not
  the launch configuration for the two-second product.

The cache preserves the signed Pyth publish time and source sequence. It rejects
stale, future-dated, replay-conflicting, or non-monotonic batches atomically;
an exact replay cannot refresh local health. The raw Pyth mantissa/exponent is
converted with checked integer arithmetic into each governed market's atomic
base/quote units and `price_scale` before circuit-breaker comparison. Both
signed freshness and local refresh health are checked again at the matcher
boundary.

Oracle failure sets an independent, market-local fail-closed trading-gate
reason. New place/modify and matching pause only for markets bound to the
affected feed, while healthy markets, cancellation, and settlement
reconciliation continue. Recovery of governance health cannot clear an oracle
pause (or vice versa), and a healthy market cannot clear another's oracle
reason. Router mode batches feeds and can isolate a bad feed with bounded
fallbacks. Push mode reads all derived accounts in one finalized RPC request
and applies each independently. In either mode, a transient fetch failure never
evicts the last verified value or blocks proving/settlement work; new matching
continues only while that value remains within the mode's signed-age budget.

The oracle, signed limits, tick size, minimum size, and circuit-breaker band are
not VALID_MATCH_BATCH inputs. They are attested-matcher policy. The proof binds:

- base/quote mint and fixed-point `price_scale`;
- exact governed fee and protocol fee owner;
- private amounts and `quote = floor(base × clearing_price / price_scale)`;
- per-leg conservation/ranges and deterministic output commitments.

Before enabling `pyth-router-quorum-v1` for launch, check every configured feed
through live `GET /instruments` responses. Each row must report
`oracle.source=pyth-router-quorum-v1`, a non-null publish time still within the
five-second signed-age budget, and `trading_enabled=true`. A non-empty API key
does not prove authorization for the required feed grant: an unauthorized key
cannot refresh the cache, so the affected market must remain paused.

| Threat | Limit and compensating control |
|---|---|
| A compromised enclave repeatedly selects a colluding market maker when several counterparties are eligible. | ZK settlement prevents theft and conservation failures but cannot prove fair counterparty selection. Publish per-MM execution-quality statistics—selection share, price improvement, rejection/failure rate, and settlement latency—so persistent preferential routing is externally detectable and governable. |

No Pyth payload or plaintext clearing price is sent to L1. A malicious
authorized enclave can choose an unfair but conserved price; it cannot use that
freedom to inflate value or change output ownership.

## 7. Settlement pipeline

Each market scheduler emits at most 16 active matches. `assemble_batch` pads
dummy slots and constructs one proof witness. The venue semaphore bounds whole
batches in flight; rolling ALT mutations remain serialized.

```text
A  lock buyer/seller notes in independent transactions
B  prove N=16 and verify_match_batch → read-only marker
C  create/extend a per-batch ALT and wait until it is usable
D  send each active tee_forced_settle_batched independently
E  sweep the marker only at/after its derived expiry
```

Important properties:

- `lock_note` re-verifies VALID_INPUT, caps order/lock lifetime to 4,500 slots,
  and refuses a note-use tag already consumed.
- `verify_match_batch` requires a finalized authorized TEE payer because that
  signature authenticates the encrypted fee-recovery record. Marker expiry is
  derived on-chain as `current_slot + 300`.
- Tx D verifies the Ed25519 canonical v12 digest, recomputes the Poseidon12 v3 slot
  leaf, walks the depth-4 batch path, and reads (never mutates) the marker.
- Tx D rejects at or after either input-lock expiry or marker expiry.
- Settle, withdraw, and merge initialize the same tag-keyed
  `ConsumedNoteEntry`.
- User-output inners derive from private consumed inners. Fee inners derive
  from the governed epoch key, consumed use tag, and role.
- The 128-byte recovery envelope is signed but opaque to L1.
- A worst-case v0 Tx D stacks the static settle ALT and a per-batch ALT; the
  committed size regression keeps it below the 1,232-byte cap.

### Outcomes and confirmation

The worker gathers every Tx D result rather than aborting the batch on the
first failure. It classifies matches as:

- `confirmed`: signature/chain state proves settlement;
- `rejected`: a definitive program or precondition failure;
- `ambiguous`: RPC state cannot yet distinguish confirmation from failure.

Transient/ambiguous transactions are reconciled through signatures and
consumed PDAs and redriven while the marker is valid. Pending signatures are
polled together; confirmed entries are removed; only overdue transactions are
rebroadcast.

The book commits each confirmed match independently after the configured RPC
commitment is reached. Ambiguous matches remain pending. Definitive failure
emits `settlement_failed` with a reason and lock expiry. Failed orders are
terminal; they are never auto-rebooked.

### Cleanup and crash recovery

`release_lock` is permissionless at/after lock expiry and refunds the recorded
payer. The lock sweeper records pending commitments in `pending_locks.db`.
Batch markers remain read-only through Tx D and are permissionlessly closed
only at/after expiry; roots are recorded in `pending_markers.db`.

Both snapshots are bincode/versioned and written atomically
temp → fsync → rename on the dstack LUKS volume. Corruption or version mismatch
falls back to an empty pending set; it affects rent cleanup, not custody or
settlement finality.

## 8. Merkle mirrors and read APIs

There is one mirror per on-chain tree shard. Cold boot replays program
transactions/events from `DARKNYX_TEE_SYNC_FROM_SLOT`; live pollers append new
leaves and reconcile current roots. The configured floor must move to the reset
slot after a devnet tree reset, or the mirror would replay obsolete leaves.

Reads:

- `GET /tree/root` — public current mirror state;
- `GET /tree/inclusion` — bearer-authenticated inclusion path;
- `GET /tree/leaves` — bearer-authenticated pagination;
- `GET /account` — the caller's open orders only, not client-owned balances;
- `GET /settlement/status/{batch_id}` — settlement lifecycle;
- `tree` subscription on `/v1/stream` — live root/leaf progress.

The mirror is a convenience and intake gate, not a replacement for L1 truth.
Strict clients cross-check chain roots/config. The daemon remains independent
of the off-TEE indexer.

## 9. Prover architecture

The `Prover` trait fixes the circuit size to N=16 in production and returns a
Groth16 proof plus timing metadata:

- backend/device;
- witness backend and `witness_ms`;
- proof step and total prove time.

### Backends

| Backend | Selection | Witness path | Use |
|---|---|---|---|
| arkworks/ark-circom | `DARKNYX_TEE_PROVER=ark` | cached Wasmer calculator | portable reference/correctness |
| rapidsnark | `DARKNYX_TEE_PROVER=rapidsnark` | native C++ by default; Wasmer fallback | production CPU baseline |
| ICICLE | `DARKNYX_TEE_PROVER=icicle`, feature-built | native C++ by default; Wasmer fallback | CPU/CUDA performance path |

For rapidsnark/ICICLE, `DARKNYX_TEE_WITNESS=wasm` explicitly forces Wasmer.
Otherwise the image uses the native Circom C++ generator when present and logs
a fallback if absent. Native and Wasmer witness bytes are parity-tested.

`DARKNYX_TEE_ICICLE_DEVICE=CPU|CUDA` selects the ICICLE device. CUDA proof
correctness has passed on a real H200: a GPU-produced N=16 proof was accepted by
the deployed Solana verifier. The first window produced no defensible steady-
state speedup because it measured one cache-warming proof on a different host.
The next window must run same-box rapidsnark/ICICLE-CPU/CUDA legs and exclude
warmup proves; see [`gpu-tee-runbook.md`](gpu-tee-runbook.md).

### Confidential GPU requirement

The witness contains private amounts, clearing prices, owner commitments, and
note openings. A malicious GPU cannot forge a sound proof but can exfiltrate
the witness. Production CUDA proving therefore requires NVIDIA Confidential
Computing mode and GPU attestation tied into the TDX trust decision. A
non-confidential commodity GPU is acceptable only for synthetic/local
performance experiments, never real order data.

## 10. API and stream surface

The exact schemas are OpenAPI-owned. The route map is:

### Public

- `GET /health`, `/info`, `/attestation`
- `POST /auth/token`
- `GET /tree/root`
- `GET /instruments`, `/instruments/{symbol}`
- `GET /transparency`, `/system/status`, `/time`
- `GET /v1/stream` (authentication occurs in-band)

### Bearer protected

- `POST /orders`
- `GET|PUT|DELETE /orders/{order_id}`
- `GET /settlement/status/{batch_id}`
- `GET /tree/inclusion`, `/tree/leaves`
- `GET /account`
- `GET|PUT /account/settings`
- `POST /auth/token/revoke`

### Admin protected

- `POST /admin/accounts`
- `POST /admin/accounts/{api_key}/disable`
- `POST /admin/accounts/{api_key}/enable`
- `POST /admin/accounts/{api_key}/revoke-tokens`
- `GET /admin/metrics/settlement`

`/__debug/oracle/seed` exists only in a `debug_endpoints` feature build and must
not be in production.

`/v1/stream` is the sole WebSocket. A client sends `login`, then subscribes to
`orders`, `fills`, and/or `tree` and may perform supported trading operations
over the same session. Per-account routers prevent fill/order leakage.
Sequence numbers support gap detection; clients refresh tokens and reconnect.
The retired `/ws/fills`, `/ws/orders`, and `/ws/trading` routes do not exist.

## 11. Authentication and identity

Three identities must not be conflated:

1. API account: rate limiting, routing, and operational suspension.
2. Trading key: signs order/cancel intent; rotatable by seed offset.
3. Shielded owner/spending key: proves note authority; never sent to the CVM.

Layer A exchanges API key/secret/passphrase for a short-lived JWT. Credentials
are stored as Argon2id hashes; production rejects test defaults. Unknown keys
are rejected before expensive hashing, a bounded hash pool sheds overload as
503, and per-account rate limiting applies to HTTP and stream operations.

JWTs have exact expiry with no grace window. Revoked JTIs are retained only
until token expiry. Admin disable/enable/revoke actions invalidate account
access across HTTP and streaming; the last enabled admin cannot disable itself.

Layer B is the trading-key signature over canonical intent. It authorizes
orders and cancellation but cannot spend notes. The VALID_INPUT proof is the
collateral-ownership capability; the CVM verifies it without learning the
spending key.

Auth state persists in `accounts.db` as a versioned `AuthSnapshot` containing
hashed account records and expiring JTI revocations. Schema changes to nested
account records require an outer snapshot-version bump. Writes are atomic and
best-effort; production credentials remain deploy/config controlled if a
snapshot cannot be read.

## 12. Attestation and governance monitoring

Clients verify:

1. the DCAP quote with `@phala/dcap-qvl`;
2. RTMR3 event-log replay;
3. expected compose hash/MRTD;
4. the complete K signer set and boot session;
5. exact equality with finalized `VaultConfig.tee_pubkeys`;
6. the relevant finalized `MarketConfig`.

The reference daemon performs strict startup checks, refreshes finalized keys
and markets every minute, pauses place/modify immediately on mismatch, and
pauses after five minutes without a successful finalized refresh. It continues
cancellation, reconciliation, and recovery while paused.

On-chain DCAP verification remains deferred. The accepted production model is
independent verification by a cold 4-of-7 root/upgrade Squads before key
rotation, while a distinct 3-of-5 operations Squads controls ordinary
`VaultConfig.admin` actions.

Every image/code/config change that changes the measured compose hash requires
a new tag, reproducible image evidence, independent attestation review, full K
key rotation if keys change, and a live settlement check.

## 13. Settlement telemetry and capacity

`GET /admin/metrics/settlement` exposes bounded, privacy-preserving server
records, counters, queue state, and histograms—not order content:

- batches enqueued/started/completed and confirmed/rejected/ambiguous matches;
- current queue depth/age per market and queue-wait distributions;
- witness, prove-step, full-prove, and stage latency;
- settle/pipeline latency, confirmed-slot co-inclusion, and rebroadcast count;
- configured concurrency and prover/witness backend/device.

The load generator combines those server records with offer rate,
accepted/rejected/retry counts, client VALID_INPUT proving percentiles,
steady-state confirmed matches/s, packing efficiency, and environment metadata.
Real throughput requires proof-backed deposits/orders; placeholder-mint
synthetic orders validate intake and paging but their stub proofs cannot
establish real settlement capacity.

CPU baselines and future GPU legs use:

- matched pairs/s and confirmed pairs/s;
- p50/p95/p99 order-to-match and order-to-confirm latency;
- queue wait, witness, prove-step, and full prove separately;
- Tx D confirmation/finality and full pipeline latency;
- resource/RPC saturation and error/outcome rates.

Do not infer GPU speedup from a single warmup proof or compare different host
CPUs. Run same-box A/B and report steady-state proves 2..N.

For multi-market packing, the parser's 16-market maximum is not a target. Stop
adding markets before queue p95 reaches 2 s/p99 4 s, p95 end-to-end regresses
over 10%, confirmed capacity loses 20% headroom, sustained CPU/memory exceeds
70%, or settlement/RPC errors exceed 0.1%.

## 14. Persistence boundaries

Live persistence consists of:

- `accounts.db`: credential hashes, account flags, token revocations;
- `pending_markers.db`: marker roots awaiting expiry-gated close;
- `pending_locks.db`: note commitments awaiting expiry-gated release.

The higher-churn order-book/Merkle/outbox snapshot module is still only a
scaffold. Do not claim that resting orders survive arbitrary CVM loss. Durable
user custody/recovery comes from the seed and Solana history, not from enclave
disk. Failed settlements are terminal and require fresh signed orders after
unlock.

The dstack volume is LUKS encrypted with app-derived key material. Snapshot
confidentiality still depends on correct dstack/KMS identity and measurement.

## 15. Development and validation

Use three loops:

| Loop | Target | Proves |
|---|---|---|
| iterate | local binary + dstack simulator | handlers, matcher, auth, oracle parsing, deterministic keys |
| spot-check | Phala CPU CVM | real dstack/KMS boot, gateway, compose hash, live RPC |
| ceremony | Phala CVM + governance | quote/measurement review, key rotation, client verification, real settle |

Simulator quotes are intentionally not accepted as production DCAP evidence.

The minimum local gate for TEE changes is:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p darknyx-tee
cargo test -p darkpool-matcher
cargo test -p darknyx-tee-loadgen
```

Run the complete repository gate from `CLAUDE.md §2.5` before a PR. The TEE
suite covers HTTP/auth/account lifecycle, stream routing, intake proof
verification, matcher/parity, oracle VAA/accumulator verification, Merkle
mirrors, settlement submission/outcomes/telemetry, prover round trips, and the
N=16 fixture. Optional rapidsnark/ICICLE/CUDA tests require their respective
features/artifacts/hardware.

For a live CVM:

1. bump the immutable image tag and wait for the registry image;
2. reset the tree before boot so the mirrors start from the intended floor;
3. deploy the correct real-mint or placeholder-mint regime;
4. rotate/fund all K signers;
5. run one leaf-count test per reset + cold boot;
6. capture stage telemetry and signatures.

Stop a billable **CPU** CVM when the planned window ends. Never stop a prepaid
on-demand GPU CVM: stopping deallocates it permanently. Follow the runbooks,
including their encrypted-env cleanup, verbatim.

## 16. Revisit triggers

- **D2:** on-chain DCAP becomes viable within CU/account budgets or required by
  institutional governance.
- **D4:** steady-state same-box GPU/CPU results justify a confidential GPU
  production path and GPU attestation is closed.
- **D5:** measured queue and finality distributions justify changing 2,000 ms;
  do not tune from proof time alone.
- **D6:** mirror memory/RPC load or independent scaling needs justify splitting
  the read plane.
- **D7:** a single CVM crosses the capacity gates, or the global signer-set
  constraint is redesigned to support multiple independently attested clusters.
- **D8:** Solana confirmation/finality semantics change; never restore optimistic public
  fills without a new failure model.

Historical design proposals belong in decision records, not in this as-built
file. Throughput work gated on GPU, Alpenglow, or real volume belongs in
[`throughput-roadmap.md`](throughput-roadmap.md).
