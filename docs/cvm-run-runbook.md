# CVM run runbook — build → deploy → rotate → fund → reset → test → STOP

> The copy-paste runbook for a full Phala CVM validation cycle. CLAUDE.md §3
> is the conceptual version; this is the operational checklist with the exact
> commands and the gotchas that have each cost a wasted deploy. Read §0 first.

A billable CVM matches AND settles a real crossing pair on devnet. The CVM
binary IS the in-TEE matcher+settler, so any change under `crates/nyx-tee/`,
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

2. **The git remote redirects.** `origin` (`Nyx-Privacy/nyx`) **redirects to the
   canonical `skysail-labs/darknyx`**. CI runs there and publishes the public
   image `ghcr.io/skysail-labs/nyx-tee:<tag>`. Watch CI on
   `skysail-labs/darknyx`, not `origin`.

3. **Bootstrap credentials are encrypted per deploy.** The compose references
   `${NYX_TEE_API_KEY}`, `${NYX_TEE_API_SECRET}`, and
   `${NYX_TEE_PASSPHRASE}`. Generate fresh values in the protected `-e` file
   and export the same values for the CVM harness/loadgen. The public
   `nyx-test-*` fixtures are rejected by a production boot.

4. **The nvm shim can shadow `node`.** If `_load_nvm` recursion errors appear,
   invoke `node`/`phala` by absolute path, e.g.
   `/Users/<you>/.nvm/versions/node/<ver>/bin/{node,phala}`.

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
# 1. bump the tag the compose pins:
#    deploy/docker-compose.yaml → image: …nyx-tee:tee-v3-hardening-<N+1>
# 2. commit, then tag + push (the tag carries your commits):
git tag tee-v3-hardening-<N+1> && git push origin tee-v3-hardening-<N+1>
# 3. watch CI (lives on skysail-labs/darknyx; origin redirects there):
gh run watch "$(gh run list --repo skysail-labs/darknyx --limit 1 --json databaseId -q '.[0].databaseId')" \
  --repo skysail-labs/darknyx --exit-status
# 4. confirm the manifest landed (want 200):
TOK=$(curl -s "https://ghcr.io/token?scope=repository:skysail-labs/nyx-tee:pull" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer $TOK" \
  -H "Accept: application/vnd.oci.image.index.v1+json" \
  "https://ghcr.io/v2/skysail-labs/nyx-tee/manifests/tee-v3-hardening-<N+1>"
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
export NYX_TEE_API_KEY="nyx-$(openssl rand -hex 16)"
export NYX_TEE_API_SECRET="$(openssl rand -hex 32)"
export NYX_TEE_PASSPHRASE="$(openssl rand -base64 32 | tr -d '\n')"
BASE=$(jq -r .baseMint.pubkey  .devnet/e2e-config.json)
QUOTE=$(jq -r .quoteMint.pubkey .devnet/e2e-config.json)
ALT=$(jq -r .settleLookupTable  .devnet/e2e-config.json)
OWNER=$(jq -r .protocol.ownerCommitmentHex .devnet/e2e-config.json)
K=$(jq -r '.numTrees // 1' .devnet/e2e-config.json)
node scripts/reset-merkle-tree.mjs     # FIRST — so the mirror cold-boots an empty tree (all K shards)
FLOOR=$(solana slot --url "$SOLANA_RPC_URL")
cat > .devnet/nyx-deploy.env <<EOF
NYX_TEE_API_KEY=$NYX_TEE_API_KEY
NYX_TEE_API_SECRET=$NYX_TEE_API_SECRET
NYX_TEE_PASSPHRASE=$NYX_TEE_PASSPHRASE
NYX_TEE_SOLANA_RPC_URL=$SOLANA_RPC_URL
NYX_TEE_SYNC_FROM_SLOT=$FLOOR
NYX_TEE_BASE_MINT=$BASE          # OMIT these two lines for the loadgen (placeholder-mint) regime
NYX_TEE_QUOTE_MINT=$QUOTE
NYX_TEE_SETTLE_LOOKUP_TABLE=$ALT
NYX_TEE_FEE_RATE_BPS=30
NYX_TEE_PROTOCOL_OWNER_COMMITMENT=$OWNER
NYX_TEE_NUM_TREES=$K
EOF
```

> Keep the three credential variables exported in the shell that runs the CVM
> tests/loadgen; live harnesses now fail fast when they are missing.
> `NYX_TEE_FEE_RATE_BPS` (default 30) must equal the cvm-harness/loadgen fee rate
> (intake derives fee-inclusive collateral; a mismatch → every note fails
> `verify_commitment`). `NYX_TEE_NUM_TREES` must equal the on-chain `numTrees`.

---

## 4. Deploy + rotate + fund all K shard signers

```sh
CVM=app_<id>      # phala cvms list
phala deploy --cvm-id "$CVM" -c deploy/docker-compose.yaml -e .devnet/nyx-deploy.env --wait
# GNU/Linux has shred; macOS has rm -P. Confirm the file is gone either way.
if command -v shred >/dev/null 2>&1; then
  shred -u .devnet/nyx-deploy.env
else
  rm -P .devnet/nyx-deploy.env
fi
test ! -e .devnet/nyx-deploy.env

GW="https://<app_id>-8080.dstack-pha-prod5.phala.network"
phala ps "$CVM"                     # find the nyx-tee container name (normally dstack-nyx-tee-1)
phala logs dstack-nyx-tee-1 --cvm-id "$CVM" --stderr -n 60
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

## 4.1 Prover-latency evidence capture (mandatory on the next live run)

The July 2026 runs exposed a split timing regression that must not be hidden by
the end-to-end total:

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

Do not spend a standalone CVM session on this. Bundle the capture with the next
image-required settle run. Set the actual container name from `phala ps`:

```sh
CONTAINER=dstack-nyx-tee-1
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
export NYX_TEE_GATEWAY="$GW"
for i in 1 2 3 4 5; do
  node -e '
    const started = performance.now();
    const body = {api_key: process.env.NYX_TEE_API_KEY,
      api_secret: process.env.NYX_TEE_API_SECRET,
      passphrase: process.env.NYX_TEE_PASSPHRASE};
    fetch(`${process.env.NYX_TEE_GATEWAY}/auth/token`, {
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

- Healthy CPU metadata and expected proof timing: continue the planned CVM
  validation window.
- Slow auth/proof with throttling or a reduced cpuset: stop validation, restart
  or reschedule once, repeat the canary, preserve both captures, and report the
  Phala node/instance metadata.
- Healthy cgroups but slow native proof: do not certify the image; investigate
  rapidsnark/OpenMP thread placement before further billable tests.

---

## 5. Run the tests (real-mint regime)

`NYX_TEE_GATEWAY` + `SOLANA_RPC_URL` come from `.env`; export the run flag inline.

> ### ⚠️ ONE fresh tree per leaf-count test — do NOT run the whole bucket in one shot
>
> Every `cvm-*` leaf-count test (`cvm-settle-e2e`, `cvm-multimatch-settle`,
> `cvm-self-trade`, `cvm-merge-then-order`) **deposits into the single shared
> on-chain Merkle tree and asserts an absolute leaf_count from an EMPTY start**
> (`cvm-multimatch-settle` literally asserts `startCount === 0` — "trees not
> empty — reset the merkle trees first"). So:
>
> * **They cannot share a tree.** The 2nd test in a run sees the 1st's leaves and
>   fails the empty-start check — this is by design, not a flake.
> * **A mid-run reset does NOT rescue it**: the CVM's Merkle mirror is
>   append-only and can't rewind, so resetting the on-chain tree under a running
>   CVM desyncs the mirror. A fresh tree needs a reset **+ a CVM cold-boot**
>   (an env-only `phala deploy` restart, §3–§4).
> * The `cvm` vitest project is pinned to `fileParallelism: false`
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
  RUN_CVM_E2E=1 NYX_TEE_GATEWAY="$GW" \
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

The loadgen needs the placeholder-mint regime (omit the mint vars, §3) — see
`crates/nyx-tee-loadgen/BENCHMARK.md`.

---

## 6. STOP THE CVM

It bills while running.

```sh
phala cvms stop "$CVM"   # preserves app_id / signer / volume; halts billing
unset NYX_TEE_API_KEY NYX_TEE_API_SECRET NYX_TEE_PASSPHRASE
```

**Never leave a billable CVM up.** The no-CVM half of devnet validation
(`--project devnet`: `devnet-deposit-withdraw`, `devnet-merge`,
`devnet-leaf-index`) tests vault crypto cheaply without a CVM.
