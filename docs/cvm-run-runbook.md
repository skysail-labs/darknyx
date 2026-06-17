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
   For the deploy `-e` file (§3) build it from that env var, never commit it,
   and `shred -u` it after deploy. Never paste the key into a CLI arg or a
   `/tmp/*.env` you forget to delete.

2. **The git remote redirects.** `origin` (`Nyx-Privacy/nyx`) **redirects to the
   canonical `skysail-labs/darknyx`**. CI runs there and publishes the public
   image `ghcr.io/skysail-labs/nyx-tee:<tag>`. Watch CI on
   `skysail-labs/darknyx`, not `origin`.

3. **The bootstrap creds are HARDCODED in `docker-compose.yaml`, not `${VAR}`.**
   `NYX_TEE_API_KEY=nyx-test-api-key`, `NYX_TEE_API_SECRET=nyx-test-secret`,
   `NYX_TEE_PASSPHRASE=nyx-test-passphrase` are literals (they bake into
   `compose_hash`). A `-e NYX_TEE_API_KEY=…` is **ignored** — auth with these
   exact values (the cvm-harness defaults already match).

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
fresh each deploy, `umask 077`, **shred after, never commit.**

```sh
umask 077
BASE=$(jq -r .baseMint.pubkey  .devnet/e2e-config.json)
QUOTE=$(jq -r .quoteMint.pubkey .devnet/e2e-config.json)
ALT=$(jq -r .settleLookupTable  .devnet/e2e-config.json)
OWNER=$(jq -r .protocol.ownerCommitmentHex .devnet/e2e-config.json)
K=$(jq -r '.numTrees // 1' .devnet/e2e-config.json)
node scripts/reset-merkle-tree.mjs     # FIRST — so the mirror cold-boots an empty tree (all K shards)
FLOOR=$(solana slot --url "$SOLANA_RPC_URL")
cat > .deploy.env <<EOF
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

> `NYX_TEE_FEE_RATE_BPS` (default 30) must equal the cvm-harness/loadgen fee rate
> (intake derives fee-inclusive collateral; a mismatch → every note fails
> `verify_commitment`). `NYX_TEE_NUM_TREES` must equal the on-chain `numTrees`.

---

## 4. Deploy + rotate + fund all K shard signers

```sh
CVM=app_<id>      # phala cvms list
phala deploy --cvm-id "$CVM" -c deploy/docker-compose.yaml -e .deploy.env --wait
shred -u .deploy.env

GW="https://<app_id>-8080.dstack-pha-prod5.phala.network"
phala cvms logs "$CVM" | tail -60   # watch: proving key load, "merkle cold-boot complete … shards=K",
                                     #   "derived K-shard TEE signer set" (← COPY ALL K keys), "settle pipeline ENABLED"
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

## 5. Run the tests (real-mint regime)

`NYX_TEE_GATEWAY` + `SOLANA_RPC_URL` come from `.env`; export the run flag inline.

```sh
RUN_CVM_E2E=1 NYX_TEE_GATEWAY="$GW" \
  FUNDER_KEYPAIR=~/.config/solana/id.json ADMIN_KEYPAIR=.devnet/keypairs/admin.json \
  ( cd packages/sdk && ../../node_modules/.bin/vitest run --project cvm )
```

This runs the whole `cvm` bucket: `cvm-settle-e2e` (deposit→match→settle, leaf
+5), `cvm-multimatch-settle` (M pairs across K shards), `cvm-merge-then-order`
(deposit→merge→order off the merged note), `cvm-api-surface` (error envelope +
x-request-id, /system/status, /time, rate-limit 429, min_notional, idempotency,
/account + settings, WS seq + /ws/trading + cancel-on-disconnect). Target one
file by appending its path. **Re-run after every image bump** — the tree must be
freshly reset (§3) so each shard's shadow cold-boots empty.

The loadgen needs the placeholder-mint regime (omit the mint vars, §3) — see
`crates/nyx-tee-loadgen/BENCHMARK.md`.

---

## 6. STOP THE CVM

It bills while running.

```sh
phala cvms stop "$CVM"   # preserves app_id / signer / volume; halts billing
```

**Never leave a billable CVM up.** The no-CVM half of devnet validation
(`--project devnet`: `devnet-deposit-withdraw`, `devnet-merge`,
`devnet-leaf-index`) tests vault crypto cheaply without a CVM.
