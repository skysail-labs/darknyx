# CVM run runbook — build → deploy → rotate → fund → reset → test → STOP

> The copy-paste runbook for a full Phala CVM validation cycle. CLAUDE.md §3
> is the conceptual version; this is the operational checklist with the exact
> commands and the gotchas that have each cost a wasted deploy. Read §0 first.
>
> **Testing crash recovery or drain?** Use
> [`settlement-recovery-drill.md`](settlement-recovery-drill.md) instead of
> improvising. It carries the timing trap (`phala cvms stop` is slower than the
> ~10 s settle phase, so the kill must be triggered off the journal itself), the
> reset trap (a tree reset does NOT empty the Merkle mirror without a fresh
> `DARKNYX_TEE_SYNC_FROM_SLOT`), and the pass criteria.

A billable CVM matches AND settles a real crossing pair on devnet. The CVM
binary IS the in-TEE matcher+settler, so any change under `crates/darknyx-tee/`,
`Dockerfile`, `deploy/docker-compose.yaml`, or the circuits needs a **rebuilt
image** — deploying the old tag runs stale code.

---

## 0. Gotchas that have each burned a deploy — internalise these first

1. **Secrets live in `packages/sdk/.env`, NOT `/tmp`.** The Helius RPC key goes
   in the gitignored `packages/sdk/.env` (`SOLANA_RPC_URL=…`, see
   `packages/sdk/.env.example`); the SDK tests load it via `tests/setup-env.ts`.
   For the deploy `-e` file (§3) build it from that env var under the gitignored
   `.devnet/` directory, never commit it, and securely delete it after deploy.
   Never paste the key into a CLI arg or a `/tmp/*.env` you forget to delete.

2. **The git remote redirects.** `origin` (`Darknyx-Privacy/darknyx`) **redirects to the
   canonical `skysail-labs/darknyx`**. CI runs there and publishes the public
   image `ghcr.io/skysail-labs/darknyx-tee:<tag>`. Watch CI on
   `skysail-labs/darknyx`, not `origin`.

3. **Bootstrap credentials are encrypted per deploy.** The compose references
   `${DARKNYX_TEE_API_KEY}`, `${DARKNYX_TEE_API_SECRET}`, and
   `${DARKNYX_TEE_PASSPHRASE}`. Generate fresh values in the protected `-e` file
   and export the same values for the CVM harness/loadgen. The public
   `darknyx-test-*` fixtures are rejected by a production boot.

   > **Reusing an api_key with a NEW secret does not rotate it.** The recipe
   > below generates a fresh random `api_key` per deploy, so boot sees a key it
   > has never stored and simply adds the account — which works, and is why a
   > long-lived CVM accumulates one stale admin account per deploy. But if you
   > pin the api_key and change only the secret or passphrase, the persisted
   > registry wins and the env values are ignored. Boot logs a warning when it
   > detects exactly that; rotate through the account API, or clear the state
   > volume so the environment re-seeds.

4. **The nvm shim can shadow `node`.** If `_load_nvm` recursion errors appear
   (followed by `maximum nested function level reached`), invoke `node`/`phala`
   by the absolute path **`command -v` reports** — resolve it, do not copy one
   from a doc. On the 2026-08 dev box both are `/opt/homebrew/bin/{node,phala}`;
   this file previously named an `~/.nvm/versions/node/<ver>/bin/` path that no
   longer exists. GNU `timeout` is also absent on macOS.

5. **Two mutually-exclusive mint regimes (§3).** Real-mint for
   `cvm-settle-e2e`/`cvm-multimatch`/`cvm-api-surface`/`cvm-merge-then-order`;
   placeholder-mint (omit the mint vars) for the loadgen. Wrong regime → 100% 4xx.

6. **Bump the image tag for ANY code change.** `phala deploy` only re-pulls on a
   changed tag; a same-tag deploy reuses the cached image (you test stale code).

7. **Rotate + fund ALL K shard signers, not just the primary** (§4). `/info`
   surfaces only shard-0; grab the full set from the boot log.

---

## 1. Build a new image (only if code/compose/circuits changed)

```sh
# 1. commit the source state, then tag + push it:
git tag tee-v3-hardening-<N+1> && git push origin tee-v3-hardening-<N+1>
# 2. watch the required image build (this is deployment production, not a
#    substitute for the local pre-PR validation gate):
gh run watch "$(gh run list --repo skysail-labs/darknyx --limit 1 --json databaseId -q '.[0].databaseId')" \
  --repo skysail-labs/darknyx --exit-status
# 3. confirm the manifest landed (want 200):
#    The Accept header MUST include the single-manifest media types. CI builds
#    linux/amd64 ONLY, so the tag resolves to an image manifest, NOT an OCI
#    index — asking for the index alone returns 404 on a perfectly good push
#    and reads exactly like a failed build.
TOK=$(curl -s "https://ghcr.io/token?scope=repository:skysail-labs/darknyx-tee:pull" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer $TOK" \
  -H "Accept: application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.index.v1+json" \
  "https://ghcr.io/v2/skysail-labs/darknyx-tee/manifests/tee-v3-hardening-<N+1>"

# 4. resolve and record the immutable digest. Cross-check it against the one
#    the image build logged ("pushing manifest for …@sha256:…"):
curl -sI -H "Authorization: Bearer $TOK" \
  -H "Accept: application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json" \
  "https://ghcr.io/v2/skysail-labs/darknyx-tee/manifests/tee-v3-hardening-<N+1>" \
  | grep -i docker-content-digest

# 5. pin deploy/docker-compose.yaml to the returned immutable identity:
#    image: ghcr.io/skysail-labs/darknyx-tee@sha256:<digest>
# Commit the digest pin and record source SHA + tag + digest together in the
# remediation/release evidence. Never deploy a mutable tag.
```

If only env/regime changed (no code), skip §1 — an env-only `phala deploy -e` is
enough.

---

## 2. Foundation: load secrets + (re)build the devnet config

```sh
# One-time: drop the Helius key into the gitignored env (NOT /tmp):
cp packages/sdk/.env.example packages/sdk/.env   # then edit SOLANA_RPC_URL=<helius>
set -a; . packages/sdk/.env; set +a               # export SOLANA_RPC_URL for the scripts below
```

Rebuild mints + the settle ALT + protocol config only if missing/stale (writes
`.devnet/e2e-config.json` that every devnet/cvm test reads):

```sh
RUN_DEVNET_E2E=1 \
  ADMIN_KEYPAIR=.devnet/keypairs/admin.json \
  TEE_AUTHORITY_KEYPAIR=.devnet/keypairs/tee_authority.json \
  ROOT_KEY_KEYPAIR=.devnet/keypairs/root_key.json \
  ( cd packages/sdk && ../../node_modules/.bin/vitest run --project devnet tests/devnet-setup.test.ts )
```

---

## 3. The encrypted `-e` env + the REGIME

`docker-compose.yaml` references per-deploy secrets as `${VAR}`; build the file
fresh each deploy under the gitignored `.devnet/` directory, `umask 077`,
**securely delete after, never commit.**

```sh
umask 077
export DARKNYX_TEE_API_KEY="darknyx-$(openssl rand -hex 16)"
export DARKNYX_TEE_API_SECRET="$(openssl rand -hex 32)"
export DARKNYX_TEE_PASSPHRASE="$(openssl rand -base64 32 | tr -d '\n')"
BASE=$(jq -r .baseMint.pubkey  .devnet/e2e-config.json)
QUOTE=$(jq -r .quoteMint.pubkey .devnet/e2e-config.json)
ALT=$(jq -r .settleLookupTable  .devnet/e2e-config.json)
OWNER=$(jq -r .protocol.ownerCommitmentHex .devnet/e2e-config.json)
K=$(jq -r '.numTrees // 1' .devnet/e2e-config.json)
node scripts/reset-merkle-tree.mjs     # FIRST — so the mirror cold-boots an empty tree (all K shards)
FLOOR=$(solana slot --url "$SOLANA_RPC_URL")
cat > .devnet/darknyx-deploy.env <<EOF
DARKNYX_TEE_API_KEY=$DARKNYX_TEE_API_KEY
DARKNYX_TEE_API_SECRET=$DARKNYX_TEE_API_SECRET
DARKNYX_TEE_PASSPHRASE=$DARKNYX_TEE_PASSPHRASE
DARKNYX_TEE_DEPLOYMENT_TIER=development
DARKNYX_TEE_ORACLE_MODE=pyth-solana-push-v1
DARKNYX_TEE_SOLANA_RPC_URL=$SOLANA_RPC_URL
DARKNYX_TEE_SYNC_FROM_SLOT=$FLOOR
DARKNYX_TEE_BASE_MINT=$BASE          # OMIT these two lines for the loadgen (placeholder-mint) regime
DARKNYX_TEE_QUOTE_MINT=$QUOTE
DARKNYX_TEE_MARKET_SYMBOL=SOL-USDC
DARKNYX_TEE_SETTLE_LOOKUP_TABLE=$ALT
DARKNYX_TEE_FEE_RATE_BPS=30
DARKNYX_TEE_PROTOCOL_OWNER_COMMITMENT=$OWNER
DARKNYX_TEE_NUM_TREES=$K
DARKNYX_TEE_SETTLE_BATCH_CONCURRENCY=1
EOF
```

This rehearsal intentionally selects `pyth-solana-push-v1`: it reads upgraded
Pyth sponsored push accounts through `DARKNYX_TEE_SOLANA_RPC_URL` at finalized
commitment and needs no Pyth API key. A launch release instead selects
`pyth-router-quorum-v1`, supplies `DARKNYX_TEE_PYTH_API_KEY` only through this
encrypted env, and pins that source in the browser release manifest.

Omitting both mint variables selects the explicit placeholder-mint loadgen mode:
intake and matcher paging remain available, but the on-chain settlement driver is
disabled. Supplying only one mint is a startup error. With both real mints set,
the CVM requires finalized, well-formed `VaultConfig` and `MarketConfig` accounts;
it will not fall back to env market/fee values.

> Keep the three API/auth credential variables exported in the shell that runs
> the CVM tests/loadgen. In router mode, keep the Pyth bearer credential
> available for deployment. Push mode ignores the Pyth API key. The API/auth
> harness credentials fail fast when missing. In router mode, missing, invalid,
> or unauthorized Pyth auth leaves the affected market's independent oracle pause reason set:
> place/modify and matching remain closed for markets bound to that feed while
> healthy markets, cancel, and settlement reconciliation continue.
> In real-market mode, the CVM and e2e harness must use the finalized on-chain
> fee rate (the CVM ignores the fee/owner env defaults after adopting governance).
> In placeholder-loadgen mode, `DARKNYX_TEE_FEE_RATE_BPS` (default 30) must equal
> the loadgen's fee rate. A mismatch changes fee-inclusive collateral and makes
> every synthetic note fail `verify_commitment`. `DARKNYX_TEE_NUM_TREES` must
> equal the on-chain `numTrees` in real-market mode.

### 3.1 Mainnet oracle and governance preflight

Mainnet deploy envs must set
`DARKNYX_TEE_DEPLOYMENT_TIER=mainnet`,
`DARKNYX_TEE_ORACLE_MODE=pyth-router-quorum-v1`, and a non-empty
`DARKNYX_TEE_PYTH_API_KEY`. Both CPU and GPU images reject any other mainnet
combination at boot. A syntactically present credential is not evidence of the
required feed grant; after deploy, verify every configured row from
`GET /instruments` reports `oracle.source=pyth-router-quorum-v1`, a non-null
publish time within the five-second budget, and `trading_enabled=true`.

Before launch, execute and record both Squads paths from
[`governance.md` §§4–6](governance.md):

1. Through the operations 3-of-5 vault, propose, approve, and execute a bounded
   staging `MarketConfig` update or TEE-key rotation; independently read the
   finalized account and confirm the intended change only.
2. Through the cold root/upgrade 4-of-7 vault, rehearse the documented upgrade
   authority plus `initialize`/root bootstrap sequence and independently verify
   the resulting program authority, `VaultConfig.admin`, and root key.
3. Before either vault approves a TEE-key rotation, every signer independently
   verifies the fresh TDX quote, MRTD, compose hash, report-data signer set, and
   finalized on-chain key proposal as specified in
   [`tee-attestation-flow.md` §5](tee-attestation-flow.md). Record the Squads
   proposal/execution signatures and each verifier's evidence.

---

## 4. Deploy + rotate + fund all K shard signers

```sh
CVM=app_<id>      # phala cvms list
phala deploy --cvm-id "$CVM" -c deploy/docker-compose.yaml -e .devnet/darknyx-deploy.env --wait
# GNU/Linux has shred; macOS has rm -P. Confirm the file is gone either way.
if command -v shred >/dev/null 2>&1; then
  shred -u .devnet/darknyx-deploy.env
else
  rm -P .devnet/darknyx-deploy.env
fi
test ! -e .devnet/darknyx-deploy.env

# The gateway's node suffix is assigned PER CVM — probe, never hardcode. A wrong
# suffix returns HTTP 000, which reads like a dead enclave rather than a bad URL.
for n in prod9 prod5 prod7; do
  U="https://$CVM-8443s.dstack-pha-$n.phala.network"
  [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 "$U/info")" = 200 ] \
    && { GW="$U"; break; }
done
test -n "$GW" || { echo "no gateway answered — is the CVM running?"; exit 1; }
phala ps "$CVM"                     # find the darknyx-tee container name (normally dstack-darknyx-tee-1)
phala logs dstack-darknyx-tee-1 --cvm-id "$CVM" --stderr -n 60
# Watch for: proving key load, "merkle cold-boot complete … shards=K",
# "derived K-shard TEE signer set" (COPY ALL K keys), "settle pipeline ENABLED".
```

Register ALL K signers in shard order (`keys[j]` settles shard j) + fund each
(one-time per CVM — deterministic per `app_id`):

```sh
SOLANA_RPC_URL="$SOLANA_RPC_URL" ADMIN_KEYPAIR=.devnet/keypairs/admin.json \
  node scripts/rotate-tee-pubkey.mjs <key0> <key1> … <keyK-1>
SOLANA_RPC_URL="$SOLANA_RPC_URL" FUNDER_KEYPAIR=~/.config/solana/id.json \
  node scripts/fund-tee-keys.mjs <key0> <key1> … <keyK-1>
```

> **gTFA 100 cap:** the Merkle sync paginates `getTransactionsForAddress` at
> `GTFA_PAGE_LIMIT = 100` (Helius caps `transactionDetails: full` at 100/call).
> A clean cold-boot logs `merkle cold-boot complete applied=… shards=K` with no
> "Invalid limit" error.

---

## 4.1 Prover-latency baseline and evidence capture

The July 2026 runs exposed a split timing regression that must not be hidden by
the end-to-end total. It was ultimately traced to slow prod5 host placement;
prod9 restored the expected proof range. Keep capturing the internal phases on
image-required runs so a future host regression is distinguished from circuit
growth:

- the previously observed flagship duration was about 24–26 seconds, while
  recent runs are about 40–44 seconds;
- the more serious anomaly is internal: witness/prove timing was reported near
  1.3 seconds before and about 12–13 seconds in a slow run;
- the match circuit grew from 142,808 to 232,806 constraints, but same-machine
  measurements moved only about 23–25%, so circuit growth alone does not explain
  a roughly 10× internal compute jump;
- one historical slow run also moved `/auth/token` from roughly 0.4 seconds to
  5.7 seconds with identical auth/prover code, making host CPU scheduling,
  cgroup throttling, effective-core count, or OpenMP placement the leading
  hypotheses.

Do not spend a standalone CVM session on this. Bundle the capture with an
image-required settle run. Set the actual container name from `phala ps`:

```sh
CONTAINER=dstack-darknyx-tee-1
STAMP=$(date -u +%Y%m%dT%H%M%SZ)

snapshot_cvm_cpu() {
  phala ssh "$CVM" -- docker exec "$CONTAINER" sh -lc '
    echo "utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "nproc=$(nproc)"
    for f in cpu.max cpu.stat cpuset.cpus.effective; do
      echo "[$f]"
      sed -n "1,80p" "/sys/fs/cgroup/$f" 2>/dev/null || echo unavailable
    done
    grep -E "^(Cpus_allowed_list|Mems_allowed_list):" /proc/1/status || true
    command -v lscpu >/dev/null && lscpu | grep -E "^(CPU\(s\)|Model name|Thread|Core|Socket|CPU max MHz|CPU min MHz):" || true
    grep -m1 -E "^(model name|Hardware|cpu MHz|flags)[[:space:]]*:" /proc/cpuinfo || true
    tr "\000" "\n" </proc/1/environ | grep -E "^(OMP|GOMP|OPENBLAS|MKL)_[A-Z_]+=" || true
  '
}

snapshot_cvm_cpu | tee ".devnet/cvm-perf-${STAMP}-pre.txt"
```

Use five sequential token issuances as a cheap Argon2/CPU canary. The script
prints only status and duration; it never prints credentials or bearer tokens:

```sh
export DARKNYX_TEE_GATEWAY="$GW"
for i in 1 2 3 4 5; do
  node -e '
    const started = performance.now();
    const body = {api_key: process.env.DARKNYX_TEE_API_KEY,
      api_secret: process.env.DARKNYX_TEE_API_SECRET,
      passphrase: process.env.DARKNYX_TEE_PASSPHRASE};
    fetch(`${process.env.DARKNYX_TEE_GATEWAY}/auth/token`, {
      method: "POST", headers: {"content-type": "application/json"},
      body: JSON.stringify(body),
    }).then(r => console.log(`status=${r.status} auth_ms=${Math.round(performance.now()-started)}`));
  '
done
```

Then run exactly one freshly reset `cvm-settle-e2e` (§5), capture the detailed
native prover line and aggregate worker timing, and take the post-proof cgroup
snapshot:

```sh
phala logs "$CONTAINER" --cvm-id "$CVM" --stderr -n 400 \
  | grep -E "witness_ms|prove_step_ms|settle pipeline timing" \
  | tee ".devnet/cvm-perf-${STAMP}-prover.txt"
snapshot_cvm_cpu | tee ".devnet/cvm-perf-${STAMP}-post.txt"
```

Compare `cpu.stat` pre/post deltas, especially `nr_throttled` and
`throttled_usec`, alongside `cpu.max`, `cpuset.cpus.effective`,
`Cpus_allowed_list`, `nproc`, CPU model/frequency, OpenMP settings,
`witness_ms`, `prove_step_ms`, and aggregate `prove_ms`.

Image-58 capture (2026-07-16): the 8-vCPU/16-GB CVM completed the ordinary
flagship in 39.65 seconds with native `witness_ms=992`, rapidsnark
`prove_step_ms=10857`, and aggregate `prove_ms=11928`. Five sequential auth
canaries took 2,110, 2,206, 2,140, 1,952, and 1,838 ms. This confirms the slow
host behavior persists even though native witness generation itself was under
one second. Phala CLI v1.1.19 returned `Unknown API error` before both
`phala ssh` snapshots, so the run did not obtain `cpu.max`, `cpu.stat`, cpuset,
affinity, CPU model/frequency, or OpenMP placement. That historical sample alone
did not justify attributing the ~10.9-second prove step to circuit growth.

Image-65 prod9 baseline (2026-07-19): `cvm-settle-e2e` passed in 42.92 seconds.
The enclave reported native `witness_ms=219`, rapidsnark
`prove_step_ms=1967`, aggregate `prove_ms=2215`, lock 1,387 ms, verify 1,325 ms,
ALT transaction/wait 1,271/283 ms, parallel phase 3,540 ms, Tx-D confirmation
10,644 ms (four rebroadcasts), settlement 10,741 ms, and total pipeline 14,321
ms. The boot probe saw 8 logical CPUs, model `06/af` at 2,400 MHz, unlimited
`cpu.max`, zero `nr_throttled`/`throttled_usec`, and 356.5 single-thread Mops/s.
Five sequential auth canaries took 1,586, 1,407, 1,320, 1,338, and 1,338 ms.
This restored proof latency and confirmed the remaining wall-clock time was
mostly client preparation/matching and devnet confirmation, not proving. A
second cold boot measured 187.4 Mops/s under the same unlimited, zero-throttle
cgroup; preserve such per-boot variance instead of treating one 100-ms probe as
a stable host benchmark.

Image-83 note-use-tag/pot19 capture (2026-08-04): the N=16 circuit grew to
285,401 constraints and crossed the pot18 capacity, so this image carries the
pot19 proving key. On a healthy prod9 `tdx.xlarge` placement (model `06/af` at
2,400 MHz, unlimited `cpu.max`, zero `nr_throttled`, 355.9 Mops/s), the cold
`cvm-settle-e2e` proof measured `witness_ms=383`, `prove_step_ms=2975`, and
aggregate `prove_ms=3386`; total settle-pipeline time was 14,435 ms. Relative to
the image-65 sample above, those proof phases increased 74.9%, 51.2%, and 52.9%,
respectively, while total pipeline time increased only 0.8% because devnet
confirmation remained dominant. A separately reset and cold-booted
`cvm-merge-then-order` corroborated the range at `witness_ms=367`,
`prove_step_ms=3090`, aggregate `prove_ms=3516`, and 14,882 ms total pipeline.
These are two cold single-proof samples, not steady-state percentiles; preserve
the ranges (367–383 ms witness, 2,975–3,090 ms prove step) as the IMAGE-83
figures.

**Superseded for the current image by the 2026-08-09 image-84 multimatch run.**
`cvm-multimatch-settle` with `DARKNYX_CVM_MATCHES=4` on prod9 measured
`witness_ms=324`, `prove_step_ms=2761`, aggregate `prove_ms=3153`, and
`total_ms=12780` — faster than image-83 across every proof phase, consistent
with the audit-7 settlement-efficiency slice landing in between. Note this is
still ONE proof: a batch is N=16 with `active_matches=4` and `padded_slots=16`,
so four matches share a single Groth16. It therefore does NOT yet give warm
*repeated* proofs on one boot; that needs a run whose matches span several
matcher ticks. Full stage split: `lock_ms=1629`, `verify_ms=1815`,
`alt_tx_ms=1202`, `alt_wait_ms=846`, `parallel_ms=4969`, `settle_ms=7789`,
`close_ms=0`, `rebroadcasts=8`, `distinct_confirmed_slots=2`.

That run's PRIMARY purpose was correctness, not timing. `cvm-settle-e2e` only
ever lands on shard 0 with one active slot, so until this run nothing had
exercised the note-use-tag path (VALID_INPUT public input 1) on non-zero shards
or with several real leaves in one batch Merkle root. Result: leaf counts
**7/7/7/7 = 28** across all four shards, `confirmed=4`, `rejected=0`,
`ambiguous=0`, `pipeline_failed=false`. Evidence:
`.devnet/cvm-multimatch-20260809-image84.txt` (gitignored).

- Healthy CPU metadata and expected proof timing: continue the planned CVM
  validation window.
- Slow auth/proof with throttling or a reduced cpuset: stop validation, restart
  or reschedule once, repeat the canary, preserve both captures, and report the
  Phala node/instance metadata.
- Healthy cgroups but slow native proof: do not certify the image; investigate
  rapidsnark/OpenMP thread placement before further billable tests.

---

## 5. Run the tests (real-mint regime)

`DARKNYX_TEE_GATEWAY` + `SOLANA_RPC_URL` come from `.env`; export the run flag inline.

> ### ⚠️ ONE fresh tree per leaf-count test — do NOT run the whole bucket in one shot
>
> Every `cvm-*` leaf-count test (`cvm-settle-e2e`,
> `cvm-multimatch-settle`, `cvm-multi-market-settle`, `cvm-self-trade`,
> `cvm-merge-then-order`) **deposits into the single shared on-chain Merkle
> tree and asserts an absolute leaf_count from an EMPTY start**
> (`cvm-multimatch-settle` literally asserts `startCount === 0` — "trees not
> empty — reset the merkle trees first"). So:
>
> - **They cannot share a tree.** The 2nd test in a run sees the 1st's leaves and
>   fails the empty-start check — this is by design, not a flake.
> - **A mid-run reset does NOT rescue it**: the CVM's Merkle mirror is
>   append-only and can't rewind, so resetting the on-chain tree under a running
>   CVM desyncs the mirror. A fresh tree needs a reset **+ a CVM cold-boot**
>   (an env-only `phala deploy` restart, §3–§4).
> - The `cvm` vitest project is pinned to `fileParallelism: false`
>   (`packages/sdk/vitest.config.ts`) so a bucket run at least fails
>   deterministically with the "reset first" message instead of a race — but
>   that only removes the race, it does NOT make the bucket pass.
>
> **Correct loop for each leaf-count test:** reset tree (§3) → env-only redeploy
> (§4, cold-boots the mirror empty) → run that ONE test file → repeat.
>
> The **non-leaf** tests (`cvm-api-surface`, `cvm-attestation-e2e`) don't touch
> the tree, so those can run against any live CVM without a reset.

Run ONE leaf-count test file against a freshly-reset + cold-booted CVM:

```sh
# after: reset tree (§3) + env-only `phala deploy` (§4) so the mirror cold-boots empty
(
  cd packages/sdk
  RUN_CVM_E2E=1 DARKNYX_TEE_GATEWAY="$GW" \
    FUNDER_KEYPAIR="$HOME/.config/solana/id.json" \
    ADMIN_KEYPAIR=.devnet/keypairs/admin.json \
    ../../node_modules/.bin/vitest run --project cvm tests/cvm-settle-e2e.test.ts
)
```

Bucket contents: `cvm-settle-e2e` (deposit→match→settle, leaf +5),
`cvm-multimatch-settle` (M pairs across K shards), `cvm-merge-then-order`
(deposit→merge→order off the merged note), `cvm-self-trade` (no self-match then a
cross-owner settle), `cvm-api-surface` (error envelope + x-request-id,
/system/status, /time, rate-limit 429, min_notional, idempotency, /account +
settings, `/v1/stream` login/sequence + legacy-route deletion). **Re-run after every
image bump.**

### 5.1 Focused two-market correctness rehearsal

This is not a routine image-bump gate. Run it when changing the multi-market
configuration, routing, governance monitor, or shared settlement resources. It
creates/reuses a second test-only base mint and governed `MarketConfig`, then
boots exactly two markets at C2:

```sh
set -a
. packages/sdk/.env
set +a
# Creates/reuses the second market and writes public, gitignored fixture data.
ADMIN_KEYPAIR=.devnet/keypairs/admin.json \
  node scripts/setup-second-devnet-market.mjs

# The harness needs an empty on-chain tree and an empty cold-boot mirror.
ADMIN_KEYPAIR=.devnet/keypairs/admin.json \
  node scripts/reset-merkle-tree.mjs

# Generates fresh auth credentials and a sourceable, mode-0600 encrypted-env
# input. It deliberately selects native + rapidsnark + C2.
node scripts/prepare-multi-market-cvm-env.mjs

phala deploy --cvm-id "$CVM" -c deploy/docker-compose.yaml \
  -e .devnet/darknyx-multimarket-deploy.env --wait
```

Verify the boot log contains two adopted enabled `MarketConfig` accounts, two
matcher drivers, `native witness generator ENABLED`, C2 schedulers, and a
zero-leaf cold boot. Then source the same fresh credentials and run:

```sh
set -a
. .devnet/darknyx-multimarket-deploy.env
set +a
export SOLANA_RPC_URL="$DARKNYX_TEE_SOLANA_RPC_URL"

(
  cd packages/sdk
  RUN_CVM_E2E=1 DARKNYX_TEE_GATEWAY="$GW" \
    FUNDER_KEYPAIR="$HOME/.config/solana/id.json" \
    ADMIN_KEYPAIR=.devnet/keypairs/admin.json \
    DARKNYX_CVM_SETTLE_TIMEOUT_MS=300000 \
    ../../node_modules/.bin/vitest run --project cvm \
      tests/cvm-multi-market-settle.test.ts
)
```

The test verifies one endpoint/two instruments, cross-market modify rejection,
original-book cancel routing, simultaneous real settlement on both market
PDAs, the `pending_settlement` lifecycle, and venue-wide pause/resume when one
governed market is disabled/restored. That is the global governance gate; a
market-local oracle failure must leave the other market tradable and is covered
by the T-17 regression suite. Record both `settlement benchmark record` log
lines; one pass is a correctness result, not the sustained capacity test defined
in [`multi-market-architecture.md`](multi-market-architecture.md) §7.

The loadgen needs the placeholder-mint regime (omit the mint vars, §3) — see
`crates/darknyx-tee-loadgen/BENCHMARK.md`.

For **real settlement throughput** (not synthetic intake), use the real-mint
regime and the metrics-driven `--real-settle` load rig. It reads the admin-only
`/admin/metrics/settlement` cursor, excludes first-batch prover warm-up, drains
on terminal matched-pair outcomes, and can write raw JSON plus Markdown:

```sh
# Paid-run preflight: build the mandatory native C++ generators, then prove the
# complete 160-deposit + 160-input fixture. There is no WASM/Wasmer fallback.
bash scripts/build-native-client-witnesses.sh
cargo test -p darknyx-tee-loadgen --release --lib \
  --features real-settle-chain \
  native_client_proofs_sustain_full_fixture -- --ignored

cargo run -p darknyx-tee-loadgen --features real-settle-chain -- \
  --real-settle --endpoint "$GW" --rpc-url "$HELIUS" \
  --admin-keypair .devnet/keypairs/admin.json \
  --base-mint "$BASE_HEX" --quote-mint "$QUOTE_HEX" \
  --traders 16 --real-mix partial-fill:100 --real-partial-fill-asks 9 \
  --real-submit-rate 15 --min-measured-batches 8 \
  --client-prove-concurrency 1 \
  --settle-drain-timeout-secs 600 \
  --benchmark-label prod9-rapidsnark-c1 --warmup-batches 1 \
  --report /tmp/prod9-rapidsnark-c1.md \
  --metrics-json /tmp/prod9-rapidsnark-c1.json
```

The mint flags are raw 32-byte hex, not base58. Full metric definitions,
warm-up rules, CPU/GPU matrices, and capacity thresholds are in
[`benchmarks/settlement-throughput-methodology.md`](benchmarks/settlement-throughput-methodology.md).

---

## 6. STOP THE CVM

It bills while running.

```sh
phala cvms stop "$CVM"   # preserves app_id / signer / volume; halts billing
unset DARKNYX_TEE_API_KEY DARKNYX_TEE_API_SECRET DARKNYX_TEE_PASSPHRASE

# If §5.1 was run, securely remove its sourceable secret bundle.
if command -v shred >/dev/null 2>&1; then
  shred -u .devnet/darknyx-multimarket-deploy.env
else
  rm -P .devnet/darknyx-multimarket-deploy.env
fi
```

**Never leave a billable CVM up.** The no-CVM half of devnet validation
(`--project devnet`: `devnet-deposit-withdraw`, `devnet-merge`,
`devnet-leaf-index`) tests vault crypto cheaply without a CVM.
