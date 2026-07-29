# Darknyx Darkpool — developer command cheat sheet (TEE architecture)

> **What this covers.** Matching and settlement run **inside a TDX CVM**
> (`crates/darknyx-tee/`) on Phala Cloud, driving the on-chain `vault` program
> (the only on-chain program) over real devnet. There is no legacy
> matching_engine / Ephemeral-Rollup path anymore.

All commands assume the repo root as the working directory:

```sh
cd /path/to/repo/root
```

> **⚠️ note-construction v2 (`inner_hash`) — read before any devnet run.**
> The note commitment + nullifier were re-anchored on a single `inner_hash`
> (Poseidon6 commitment; nullifier over `inner_hash`, not the commitment).
> VALID_MATCH_BATCH v3 derives every user output inner from the consumed input
> inner, so partial-fill continuations need no client-supplied anchor pool.
> Two operational consequences:
>
> 1. **A `reset_merkle_tree` is MANDATORY before the first v2 devnet run.** The
>    migration UNIFIED all notes onto the arity-6 construction, so every
>    pre-existing (arity-7) leaf is unspendable under v2 — a stale tree makes
>    every `lock_note` / settle fail with `InvalidProof`. Run
>    `node scripts/reset-merkle-tree.mjs` (§4.5 / §9.2), then redeploy the BPF
>    (the circuits + `vk_*.rs` changed — `cargo build-sbf` + `deploy-devnet.sh`).
> 2. **The `POST /orders` body changed.** `note_nonce` + `note_blinding` became
>    `note_inner_hash`; canonical order v5 (`darknyx-order-v5` domain) removes
>    `anchors`, requires a signed contributory X25519 `viewing_pubkey`, and
>    requires the signed 32-byte `/info.boot_session_id`. After exact-body
>    idempotency, `arrival_nonce` must strictly increase per trading key. The
>    anchor top-up endpoint no longer exists. Fills stream over `/v1/stream`.
>    `cvm-settle-e2e.test.ts` fetches and signs the live boot session.

> **⚠️ tree-sharding (settle-throughput scaling) — read before any K>1 run.**
> The Merkle-tree STATE was split out of `VaultConfig` into **K per-shard
> `MerkleTree` accounts** (PDA `[b"merkle_tree", &[tree_id]]`). The settle worker
> derives **K fee-payer keys** (`darknyx/ed25519-signer/v2/{0..K-1}`) and
> round-robins each match across `(key[j], merkle_tree[j])` so the concurrent
> settle Tx D's share no writable account → the leader co-includes them in one
> block (8-match → 1 slot, vs the single-tree ~3/slot plateau). Operational
> consequences:
>
> 1. **`leaf_count` moved.** It is NO LONGER in `vault_config` (old offset 104);
>    it's a `u64` at offset **8** of each `MerkleTree[tree_id]` account
>    (`current_root` at offset **16**). Per-shard; the pool total is the SUM.
> 2. **Every leaf-touching ix gained a `tree_id` (first arg) + the
>    `merkle_tree[tree_id]` account.** `vault_config` is read-only on the settle
>    hot path. `tee_pubkey` → `tee_pubkeys[16]` + `num_tee_keys`;
>    `set_tee_pubkey` now installs a `Vec<Pubkey>`. New ixs: `initialize_tree`,
>    and (devnet-only) `close_vault_config` for the layout migration.
> 3. **A `VaultConfig` layout change needs `close_vault_config` BEFORE re-init.**
>    A program upgrade leaves the old-layout PDA in place (wrong size → every ix
>    fails `ConstraintSeeds`, and `initialize`'s `init` can't recreate it). Run
>    `node scripts/close-vault-config.mjs` once, then `devnet-setup` rebuilds it.
> 4. **Config is `DARKNYX_TEE_NUM_TREES` (CVM) / `DARKNYX_NUM_TREES` (devnet-setup),
>    default 1.** Keep it at 1 for a single-shard run; set both to the same K
>    (e.g. 4) for the sharded path. New scripts: `fund-tee-keys.mjs` (fund the K
>    signers), `close-vault-config.mjs`; `reset-merkle-tree.mjs` takes
>    `--all`(default)/`--tree <id>`; `rotate-tee-pubkey.mjs` registers all K.

**Contents**
- §0 One-time setup
- §1 Unit + integration tests (no devnet, no CVM)
- §2 The "everything green" pre-commit gate
- §3 Circuits
- §4 Devnet foundation — CLI, Helius RPC, deploy, fresh state, mints
- §5 The CVM (Phala TEE) — build image, deploy, env, signer rotation
- §6 Devnet E2E #1 — CVM-driven settle (`cvm-settle-e2e`)
- §7 Devnet E2E #2 — loadgen against a CVM
- §8 SDK-only settle path (no CVM) + legacy flows
- §9 Resetting state
- §10 Troubleshooting
- §11 Reference constants

---

## 0. One-time environment setup

```sh
npm install                                            # SDK + snarkjs + circomlib
bash scripts/download-ptau.sh                          # pot16 (~80 MB) + pot18 (~288 MB)
bash scripts/build-circuits.sh                         # compile 9 circom circuits; writes vk_*.rs
cargo build --examples -p darkpool-crypto              # TS↔Rust parity helper binaries
cargo build-sbf --manifest-path programs/vault/Cargo.toml --features devnet-admin  # BPF (litesvm + devnet deploy; F-01/F-02 admin ixs OFF by default for mainnet)
```

The CVM image build (§5) is **amd64-only via CI** — never built locally on
Apple Silicon (QEMU cross-build fails to link wasmer's `__rust_probestack`).

CVM tooling (only needed for §5–§7):

```sh
phala --version          # Phala Cloud CLI (npm i -g phala); you must be logged in
solana --version         # Solana CLI; point it at devnet (§4.1)
gh --version             # GitHub CLI, for triggering/ watching the image build
```

---

## 1. Unit + integration tests (no devnet, no CVM)

These need **no network**. Run them on every change.

### 1.1 Rust workspace (host-side crypto, matcher, vault litesvm)

```sh
cargo test --workspace                            # everything (~80+ tests)

# By crate
cargo test -p darkpool-crypto                     # Poseidon / note / nullifier / key parity
cargo test -p darkpool-matcher                    # uniform-price matching + parity.rs scenarios
cargo test -p vault                               # vault unit + litesvm integration

# Key litesvm integration files (need `cargo build-sbf` first)
cargo test -p vault --test zk_roundtrip                       # VALID_WALLET_CREATE on-chain verify
cargo test -p vault --test zk_spend_roundtrip                 # VALID_SPEND + Merkle parity
cargo test -p vault --test merge_verify                       # VALID_MERGE(K=2/4) verify roundtrip
cargo test -p vault --test set_tee_pubkey                     # admin-gated tee_pubkeys (Vec) rotation
cargo test -p vault --test tee_forced_settle_batched          # 1:N marker + sharding (distinct-shard / multi-key auth / per-shard reset)
cargo test -p vault --test match_batch_verify                 # N=16 VALID_MATCH_BATCH verify (committed proof fixture)
cargo test -p vault --test user_commitment_registration       # WalletEntry registration
cargo test -p vault --test set_protocol_config

# Tree-sharding litesvm coverage lives in tee_forced_settle_batched.rs:
#   test_settles_to_distinct_shards_advance_independently       (round-robin output shards)
#   test_settle_signed_by_registered_key_succeeds_unregistered_fails  (K-key authorized set)
#   test_reset_one_shard_leaves_others_untouched                (per-shard reset)

# Single test by substring
cargo test -p vault canonical_payload_hash_fixed_vector
```

### 1.2 `darknyx-tee` (the in-TEE binary)

The TEE crate has the densest unit + integration coverage — matcher tick,
order intake, settle assembler/worker, ALT pool, Merkle mirror, the HTTP
surface, the RPC client, auth.

```sh
cargo test -p darknyx-tee --lib                       # ~180 unit tests (fast)

# Focused module runs
cargo test -p darknyx-tee --lib settle::              # settle worker + ALT pool + assemble + pipeline
cargo test -p darknyx-tee --lib merkle::              # mirror (O(depth) inclusion proof) + sync + events
cargo test -p darknyx-tee --lib api::auth             # argon2 + JWT + revocation + admin-gate
cargo test -p darknyx-tee --lib matcher::             # book + interval + openings

# Integration tests (crates/darknyx-tee/tests/, each boots the axum surface or
# a mock RPC; no devnet)
cargo test -p darknyx-tee --test http_surface         # /health /info /auth/* end-to-end
cargo test -p darknyx-tee --test orders_surface       # POST /orders intake (opening verify, fee-incl collateral)
cargo test -p darknyx-tee --test tree_surface         # /tree/root|inclusion|leaves
cargo test -p darknyx-tee --test transparency_surface # /transparency reserves + stale flag
cargo test -p darknyx-tee --test settle_status        # /settlement/status
cargo test -p darknyx-tee --test n16_assemble_prove_verify   # N=16 assemble → prove → verify (slow)
cargo test -p darknyx-tee --test matcher_tick         # single-order matcher smoke
cargo test -p darknyx-tee --test solana_rpc           # RPC client envelope parsing (incl null-result)
```

### 1.3 SDK (TypeScript)

```sh
( cd packages/sdk && ../../node_modules/.bin/vitest run )                 # all (~110 pass, ~17 env-gated skip)

# Parity (TS↔Rust byte-equality — shell out to the darkpool-crypto examples)
( cd packages/sdk && ../../node_modules/.bin/vitest run tests/poseidon-parity.test.ts )
( cd packages/sdk && ../../node_modules/.bin/vitest run tests/note-commitment-parity.test.ts )

# batched settle wire-format (no RPC)
( cd packages/sdk && ../../node_modules/.bin/vitest run tests/settle-builder-batched.test.ts )
( cd packages/sdk && ../../node_modules/.bin/vitest run tests/match-batch-prototype.test.ts )  # needs circuit artifacts

# Typecheck (vitest does NOT fail on missing types)
./node_modules/.bin/tsc -p packages/sdk/tsconfig.json --noEmit
```

The `RUN_*`-gated tests (`devnet-setup`, `devnet-deposit-withdraw`,
`cvm-settle-e2e`) auto-skip without their env var. They're the devnet /
CVM flows in §6–§8.

### 1.4 Loadgen (`darknyx-tee-loadgen`)

```sh
cargo test -p darknyx-tee-loadgen                     # smoke.rs: in-process TEE + matcher, fee-free
cargo build -p darknyx-tee-loadgen --release          # the binary you run against a CVM (§7)
```

### 1.5 Lint / format

```sh
cargo clippy --workspace --all-targets -- -D warnings    # zero warnings tolerated
cargo fmt --all                                          # apply
cargo fmt --all -- --check                               # verify
```

---

## 2. The "everything green" pre-commit gate

Run before every commit / PR. Mirrors `.github/workflows/pr-checks.yml`.

```sh
set -e
cargo fmt --all && cargo fmt --all -- --check
cargo build-sbf --manifest-path programs/vault/Cargo.toml --features devnet-admin  # devnet-admin: litesvm reset/close tests need it (mainnet build omits it)
cargo build --examples -p darkpool-crypto
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test -p darknyx-tee                                     # lib + integration (separate workspace member)
./node_modules/.bin/tsc -p packages/sdk/tsconfig.json --noEmit
( cd packages/sdk && ../../node_modules/.bin/vitest run )
echo "ALL GREEN — safe to push"
```

> **Deletion audit.** If you delete a file under `programs/*/tests/`,
> `circuits/`, `crates/darknyx-tee/**`, or `packages/sdk/tests/helpers/`, grep
> `.github/workflows/*.yml` + `scripts/*.sh` for the basename before
> pushing — `cargo test --workspace` won't catch a stale `--test <name>`
> reference, but CI's per-job `cargo test --test <name>` will.

---

## 3. Circuits (circom / snarkjs)

```sh
bash scripts/build-circuits.sh                    # compile all 9, run ceremony, write vk_*.rs
ls circuits/build/valid_deposit/                  # proof-bound private-owner deposit
ls circuits/build/match_batch_n16/                # the production N=16 batched-validity circuit
ls circuits/build/valid_merge_k2 valid_merge_k4   # in-pool note merge (K=2/4)

# Regenerate just the Rust VK consts (if you tweaked the parser)
node scripts/parse-vk-to-rust.js \
  circuits/build/valid_wallet_create/verification_key.json \
  programs/vault/src/zk/vk_valid_wallet_create.rs
```

If you touch any circuit, Poseidon arity, or the `compute_match_leaf`
shape, you MUST regenerate + commit the `.zkey` + `vk_*.rs` together and
redeploy the vault — see CLAUDE.md §5. Only a TEE-proved circuit change
(`match_batch_*`) also requires a rebuilt CVM image.

---

## 4. Devnet foundation — CLI, Helius RPC, deploy, fresh state, mints

### 4.1 Point the Solana CLI at devnet + fund your local wallet

```sh
solana config set --url https://api.devnet.solana.com
solana address                                    # your local payer (funds everything)
solana balance                                    # need a few SOL; faucet or a funded wallet
```

The local wallet (`~/.config/solana/id.json`) is the upgrade authority +
fee payer for deploys and the funder for test personas / the CVM signer.

### 4.2 Helius RPC (why, and how to use it)

The public `api.devnet.solana.com` **429s** the heavy paths — the e2e
harness's many reads — AND the TEE Merkle sync + the fills indexer now use
Helius' **`getTransactionsForAddress`** (gTFA), which is **Helius-exclusive**
(not a standard Solana RPC method), so a private RPC (Helius) is **required**,
not just nice-to-have:

```text
https://devnet.helius-rpc.com/?api-key=<YOUR_KEY>
```

Rules:
- **Never commit the key.** It goes into the CVM via the encrypted `-e`
  env file (§5.3) and into test runs via the `SOLANA_RPC_URL` env var.
- The light path (deploys, the reset/rotate scripts, faucet transfers) is
  fine on the public devnet URL.
- A handy alias for the rest of this doc:
  ```sh
  HELIUS="https://devnet.helius-rpc.com/?api-key=<YOUR_KEY>"
  ```

### 4.3 Deploy the programs

```sh
bash scripts/setup-devnet.sh        # one-time: generate + fund .devnet/keypairs/{admin,tee_authority,root_key,trader}
bash scripts/deploy-devnet.sh       # (re)deploy target/deploy/vault.so in place
```

`deploy-devnet.sh` is idempotent (reuses the program IDs / upgrades in
place). Run `cargo build-sbf` first if you touched a program.

> **Stale BPF.** `DeclaredProgramIdMismatch (0x1004)` ⇒ `touch
> programs/<prog>/src/lib.rs && cargo build-sbf … && bash scripts/deploy-devnet.sh`.

### 4.4 Fresh devnet state — `devnet-setup.test.ts`

This is the canonical "start clean" step. It: creates a **fresh BASE +
QUOTE SPL mint pair**, `vault::initialize(operationsAdmin, teePubkeys, rootKey,
numTrees)`, initializes the mint-pair **`MarketConfig`**, loops
**`initialize_tree(j)`** for j∈0..K, **`reset_merkle_tree(j)`** per shard,
`set_protocol_config` (owner commitment + 30 bps fee), creates the **static
settle ALT** (`[vault_config, sysvar, system, merkle_tree(0..K-1)]` — the
`settleLookupTable` the CVM needs), and writes everything to
**`.devnet/e2e-config.json`** (mints, settle ALT, protocol config,
**`numTrees`**, **`merkleTreePdas[]`**, and governed market fields).

```sh
SOLANA_RPC_URL="$HELIUS" \
RUN_DEVNET_E2E=1 \
  DARKNYX_NUM_TREES=4 \                                # shard count (default 1); must equal the CVM's DARKNYX_TEE_NUM_TREES
  ADMIN_KEYPAIR=.devnet/keypairs/admin.json \
  TEE_AUTHORITY_KEYPAIR=.devnet/keypairs/tee_authority.json \
  ROOT_KEY_KEYPAIR=.devnet/keypairs/root_key.json \
  bash -c 'cd packages/sdk && ../../node_modules/.bin/vitest run tests/devnet-setup.test.ts'
```

> **Layout migration.** If you redeployed a `VaultConfig` layout change (e.g.
> the tree-sharding split) over an existing init, `initialize`'s `init` fails
> (the old PDA exists, wrong size). Run `node scripts/close-vault-config.mjs`
> (admin-gated, devnet-only) ONCE first, then `devnet-setup` rebuilds it fresh.

Run it: **the first time**, **after `change the mints`** (§4.6), or whenever
the SDK shadow tree drifts (`StaleMerkleRoot 6004`).

### 4.5 Reset the tree between runs (fast path)

The CVM e2e harness (§6) asserts the tree starts **empty**. Between runs you
only need the reset, not a full setup:

```sh
SOLANA_RPC_URL="$HELIUS" ADMIN_KEYPAIR=.devnet/keypairs/admin.json \
  node scripts/reset-merkle-tree.mjs                 # --all (default): reads num_trees, resets every shard
# or a single shard:
SOLANA_RPC_URL="$HELIUS" ADMIN_KEYPAIR=.devnet/keypairs/admin.json \
  node scripts/reset-merkle-tree.mjs --tree 2
```

(`devnet-setup.test.ts` also resets every shard; this script is the standalone
fast path — see `scripts/reset-merkle-tree.mjs`.)

### 4.6 Changing the market mints

The mints live in `.devnet/e2e-config.json` (`baseMint.pubkey` /
`quoteMint.pubkey`), created by `devnet-setup.test.ts`. To rotate them:

1. Re-run `devnet-setup.test.ts` (§4.4) — it mints a **fresh pair** and
   rewrites `e2e-config.json` + a new settle ALT.
2. Re-deploy the CVM with the new mints (§5.3) — the `DARKNYX_TEE_BASE_MINT` /
   `DARKNYX_TEE_QUOTE_MINT` env values must equal the on-chain mints the
   deposited notes use, or **intake rejects every order** on a mint
   mismatch (the commitment is re-derived with the configured mint).

There are two mint regimes:
- **Real e2e mints** (`e2e-config.json`) → the **settle e2e** (§6), where
  real notes are deposited and settled.
- **Placeholder dev mints** (`base[31]=0xb1` / `quote[31]=0x9e`, the
  `dev_match_config` defaults) → the **loadgen** (§7), whose synthetic
  orders hardcode those. You select the placeholder regime by simply
  **omitting** `DARKNYX_TEE_BASE_MINT`/`DARKNYX_TEE_QUOTE_MINT` from the deploy
  env (empty `${VAR}` → config default).

---

## 5. The CVM (Phala TEE) — build image, deploy, env, signer

The CVM runs the `darknyx-tee` binary: matcher, prover, settle scheduler,
Merkle-sync indexer, and the HTTP/auth surface. One long-lived dev CVM is
reused across sessions; stop it (don't delete) between sessions to preserve
its app_id (→ deterministic signer) and stop billing.

### 5.1 Build a CVM image (git tag → CI → ghcr)

The image is built by the `tee-image` GitHub workflow, triggered by pushing
a `tee-v3-hardening-N` **git tag**. It builds linux/amd64 and pushes to
`ghcr.io/skysail-labs/darknyx-tee:tee-v3-hardening-N` with a **registry-backed
layer cache** (`:buildcache`), so a fresh tag builds in ~4–5 min.

```sh
TAG=tee-v3-hardening-<N>
# 1. Commit, then use a fresh tag to trigger the exact source build:
git tag "$TAG" && git push origin "$TAG"
# 2. Watch THE tee-image run for THIS tag — not the repo's latest run, which can
#    be pr-checks or a scheduled sweeper that happened to start after your push.
RUN=$(gh run list --repo skysail-labs/darknyx --workflow tee-image.yml \
        --branch "$TAG" --limit 1 --json databaseId -q '.[0].databaseId')
test -n "$RUN" || { echo "no tee-image run for $TAG yet"; exit 1; }
gh run watch "$RUN" --repo skysail-labs/darknyx --exit-status
# 3. Resolve the immutable digest, failing closed on a missing/short digest —
#    `grep`ing the headers succeeds silently when the tag was never published.
TOK=$(curl -s "https://ghcr.io/token?scope=repository:skysail-labs/darknyx-tee:pull" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
CODE=$(curl -sI -o /dev/null -w '%{http_code}' -D /tmp/hdrs \
  -H "Authorization: Bearer $TOK" \
  -H "Accept: application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json" \
  "https://ghcr.io/v2/skysail-labs/darknyx-tee/manifests/$TAG")
test "$CODE" = 200 || { echo "manifest for $TAG not found (HTTP $CODE)"; exit 1; }
DIGEST=$(tr -d '\r' < /tmp/hdrs | sed -n 's/^[Dd]ocker-[Cc]ontent-[Dd]igest: //p')
echo "$DIGEST" | grep -qE '^sha256:[0-9a-f]{64}$' \
  || { echo "malformed or absent digest: '$DIGEST'"; exit 1; }
echo "pin this: ghcr.io/skysail-labs/darknyx-tee@$DIGEST"
# 4. Pin deploy/docker-compose.yaml to:
#    image: ghcr.io/skysail-labs/darknyx-tee@sha256:<digest>
```

> **Always use a fresh build tag and deploy the resolved digest** for a code
> change. Tags are audit labels, not deployment identities. Compose env-only
> changes (`-e`) take effect without a rebuild.

### 5.2 Deploy / start / stop a CVM

```sh
phala cvms list                                   # find the CVM id + app id
CVM=34fbcace-899b-4fa0-a008-d257f80d6592           # the dev CVM (example)

phala cvms start "$CVM"                            # resume a stopped CVM
phala deploy --cvm-id "$CVM" -c deploy/docker-compose.yaml -e /tmp/darknyx.env   # update (compose pins immutable digest)
phala cvms stop  "$CVM"                            # stop (preserves app_id/signer/volume; stops billing)
phala cvms logs  "$CVM" 2>&1 | tail -40            # logs
phala cvms get   "$CVM"                            # status / app id
```

Gateway URL (no custom domain yet): `https://<app_id>-8080.dstack-pha-prod5.phala.network`.
For the dev CVM:

```sh
GW="https://634b2ab4c250466311f0cf09f772b6fd60b5be11-8080.dstack-pha-prod5.phala.network"
curl -s "$GW/info" | jq .                          # signer (tee_pubkey), app_id, RTMRs
```

### 5.3 The encrypted env (`-e` file) — RPC, mints, fee, owner, sync

`deploy/docker-compose.yaml` references secret/per-deploy values as
`${VAR}`; `phala deploy -e <file>` injects them as **encrypted env** (the
reference is in `compose_hash`, the value never is). Build the file fresh
each deploy (the Helius key is secret — write it `umask 077`, **shred it
after**):

```sh
umask 077
BASE=$(jq -r .baseMint.pubkey  .devnet/e2e-config.json)
QUOTE=$(jq -r .quoteMint.pubkey .devnet/e2e-config.json)
ALT=$(jq -r .settleLookupTable  .devnet/e2e-config.json)
OWNER=$(jq -r .protocol.ownerCommitmentHex .devnet/e2e-config.json)
FLOOR=$(solana slot --url "$HELIUS")              # cold-boot floor (so the sync rebuilds the CURRENT tree)
cat > /tmp/darknyx.env <<EOF
DARKNYX_TEE_SOLANA_RPC_URL=$HELIUS
DARKNYX_TEE_PYTH_API_KEY=$DARKNYX_TEE_PYTH_API_KEY
DARKNYX_TEE_SYNC_FROM_SLOT=$FLOOR
DARKNYX_TEE_BASE_MINT=$BASE
DARKNYX_TEE_QUOTE_MINT=$QUOTE
DARKNYX_TEE_MARKET_SYMBOL=SOL-USDC
DARKNYX_TEE_SETTLE_LOOKUP_TABLE=$ALT
DARKNYX_TEE_FEE_RATE_BPS=30
DARKNYX_TEE_PROTOCOL_OWNER_COMMITMENT=$OWNER
DARKNYX_TEE_NUM_TREES=4                              # shard count; MUST equal e2e-config numTrees (1 = single-shard)
DARKNYX_TEE_SETTLE_SEND_CONCURRENCY=16               # concurrent settle Tx D's (co-inclusion lever)
DARKNYX_TEE_SETTLE_BATCH_CONCURRENCY=1                # whole batches in flight (1..=8; benchmark before raising)
DARKNYX_TEE_PROVER=ark                               # ark (default) | rapidsnark (both ship in the image)
EOF
# ... deploy ... then:
shred -u /tmp/darknyx.env
```

Every CVM env var (`crates/darknyx-tee/src/config.rs`):

| Var | Used by | Notes |
|---|---|---|
| `DARKNYX_TEE_SOLANA_RPC_URL` | Merkle sync + settle txs | **Helius** (public devnet 429s). Empty → public devnet default. |
| `DARKNYX_TEE_PYTH_TRUST_PROFILE` | oracle trust root | Strict versioned profile: `legacy-wormhole-v1` or `router-quorum-v1`. Production compose selects the upgraded router 3-of-5 profile; no profile is inferred from a VAA. |
| `DARKNYX_TEE_HERMES_ENDPOINT` | oracle transport | Profile-dependent default. Production compose pins `https://pyth.dourolabs.app/hermes`. |
| `DARKNYX_TEE_PYTH_API_KEY` | authenticated Hermes | Bearer credential supplied only through encrypted deploy env. Missing/invalid auth keeps new trading paused; never log or commit it. |
| `DARKNYX_TEE_SYNC_FROM_SLOT` | Merkle cold-boot floor | Set to the current slot (or a reset slot) so the mirror rebuilds the live tree, not pre-reset leaves. |
| `DARKNYX_TEE_BASE_MINT` / `_QUOTE_MINT` | order intake | base58; supply both or neither. **Omit both → placeholder dev mints with settlement disabled** (loadgen regime). Real e2e settle MUST set the `e2e-config` mints and have finalized `VaultConfig` + `MarketConfig` available. |
| `DARKNYX_TEE_MARKET_SYMBOL` | API + signed order routing | Display/canonical order symbol for the configured mint pair (default `SOL-USDC`; 1–32 bytes). |
| `DARKNYX_TEE_MARKETS_JSON` | multi-market boot + routing | Preferred governed config: JSON array of 1–16 `{symbol,base_mint,quote_mint,oracle_feed_id}` entries. Symbols and ordered pairs must be unique. Do not also set the singular mint envs. Every pair needs an enabled finalized `MarketConfig`. |
| `DARKNYX_TEE_SETTLE_LOOKUP_TABLE` | settle worker | the `settleLookupTable` ALT. Without it the settle v0 tx exceeds 1232 B. |
| `DARKNYX_TEE_FEE_RATE_BPS` | matcher | Simulator/loadgen default only (30; 0 disables fees there). Governed real-market boot adopts finalized `VaultConfig.fee_rate_bps`. Charged on BOTH legs → 2 fee notes. |
| `DARKNYX_TEE_PROTOCOL_OWNER_COMMITMENT` | matcher fee notes | Simulator/loadgen default only (32-byte hex). Governed real-market boot adopts finalized `VaultConfig.protocol_owner_commitment`. |
| `DARKNYX_TEE_NUM_TREES` | settle worker + K mirrors | shard count (1..=16, default 1). MUST equal the on-chain `num_trees` (`e2e-config.numTrees`). K>1 derives K fee-payer keys + K mirrors. |
| `DARKNYX_TEE_SETTLE_SEND_CONCURRENCY` | settle worker | max settle Tx D's (+ lock txs + ALT extends) fired CONCURRENTLY (default 16). Lets the leader co-include them in one block. |
| `DARKNYX_TEE_SETTLE_BATCH_CONCURRENCY` | settle scheduler | whole batches driven concurrently across the **entire CVM** (not per market; 1..=8, default 1). Raise only under the benchmark methodology; CPU proof contention can erase the IO overlap. |
| `DARKNYX_TEE_PROVER` | prover | `ark` (default) \| `rapidsnark`. The image ships both (`--features rapidsnark`); flip to A/B prove on the SAME image (no rebuild). |
| `DARKNYX_TEE_FEED_IDS` | oracle | Legacy one-market comma-separated Pyth ids. Multi-market deploys take each feed from `DARKNYX_TEE_MARKETS_JSON`; all unique feeds share one authenticated Hermes batch request per refresh. |

A **malformed** (non-empty) value now **fails startup** (config fail-fast);
an **empty** `${VAR}` falls back to the default.

### 5.4 Register the CVM's K signer(s) in `vault.tee_pubkeys` + fund them

Every TEE-authority ix gates on `tee_authority ∈ vault_config.tee_pubkeys`.
A new CVM (new app_id) derives new dstack signers, so register them and fund
each. Each is the fee-payer for the settle Tx D's it pays, so ALL K need SOL.
Signers are deterministic per app_id → survives stop/start; redo only for a
brand-new app_id (or a new K).

With **K=1** (single shard) the CVM derives one signer; with **K>1** it derives
K (`darknyx/ed25519-signer/v2/{0..K-1}`), logged at boot as
`derived K-shard TEE signer set … shard_pubkeys=[…]` (also `GET /info`).

```sh
# Grab the K shard signers from the CVM boot log (shard order matters: key[j]
# settles shard j):
phala cvms logs "$CVM" | grep "derived K-shard TEE signer set"
K0=…; K1=…; K2=…; K3=…

# Install the FULL authorized set (admin-gated set_tee_pubkey(Vec<Pubkey>)):
SOLANA_RPC_URL="$HELIUS" ADMIN_KEYPAIR=.devnet/keypairs/admin.json \
  node scripts/rotate-tee-pubkey.mjs $K0 $K1 $K2 $K3      # one key still works for K=1

# Fund each shard signer (default 2 SOL/key; idempotent, skips if already ≥target):
SOLANA_RPC_URL="$HELIUS" FUNDER_KEYPAIR=~/.config/solana/id.json \
  node scripts/fund-tee-keys.mjs $K0 $K1 $K2 $K3
```

---

## 6. Devnet E2E #1 — CVM-driven settle (`cvm-settle-e2e`)

The flagship TEE test: the **CVM** does the matching AND the settle. The
harness (`packages/sdk/tests/cvm-settle-e2e.test.ts`) deposits two real
notes, generates VALID_INPUT proofs, POSTs a crossing bid+ask to the CVM's
`POST /orders`, and the CVM's scheduler runs
`lock → prove(N=16) → verify_match_batch → per-batch ALT → tee_forced_settle_batched → close`,
signed by its dstack key. It asserts the on-chain `VaultConfig.leaf_count`
grows.

**Prereqs (in order):**

```sh
HELIUS="https://devnet.helius-rpc.com/?api-key=<YOUR_KEY>"
GW="https://634b2ab4c250466311f0cf09f772b6fd60b5be11-8080.dstack-pha-prod5.phala.network"

# 1. Fresh devnet state (mints + settle ALT + reset + e2e-config.json):  §4.4
# 2. CVM deployed with the REAL mints + fee 30 + owner + Helius + sync floor:  §5.1–5.3
# 3. vault.tee_pubkey rotated to the CVM signer + signer funded:  §5.4
# 4. Tree reset right before the run:
SOLANA_RPC_URL="$HELIUS" ADMIN_KEYPAIR=.devnet/keypairs/admin.json node scripts/reset-merkle-tree.mjs
```

**Run:**

```sh
RUN_CVM_E2E=1 DARKNYX_TEE_GATEWAY="$GW" \
  SOLANA_RPC_URL="$HELIUS" \
  DARKNYX_CVM_SETTLE_TIMEOUT_MS=150000 \
  FUNDER_KEYPAIR="$HOME/.config/solana/id.json" \
  ADMIN_KEYPAIR=.devnet/keypairs/admin.json \
  bash -c 'cd packages/sdk && ../../node_modules/.bin/vitest run tests/cvm-settle-e2e.test.ts'
```

**Expect:** test passes; on-chain `leaf_count` jumps by **5** — `note_c`
(buyer base out), `note_d` (seller quote out), `note_e` (buyer change from
price improvement), and **both fee notes** (`note_fee_base` +
`note_fee_quote`). CVM logs show `settle: batch settled; openings evicted`.

**Knobs:** `DARKNYX_CVM_BASE_QTY` (per-run-unique trade size — defaults to
`Date.now()%900000+1000` so re-runs don't collide on a NoteLock PDA),
`DARKNYX_CVM_PRICE` (override the Hermes anchor), `DARKNYX_CVM_FEE_RATE_BPS` (must
match the CVM's `DARKNYX_TEE_FEE_RATE_BPS`), `DARKNYX_CVM_SETTLE_TIMEOUT_MS`.

**Confirm on-chain afterwards** (post-sharding `leaf_count` is a u64 at offset
**8** of each `MerkleTree[tree_id]` account — NOT `vault_config`; deposits go to
shard 0, settle outputs round-robin so sum across shards for the pool total):

```sh
node -e 'import("@solana/web3.js").then(async ({Connection,PublicKey})=>{const c=new Connection(process.env.SOLANA_RPC_URL,"confirmed");const P=new PublicKey("C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx");const[t0]=PublicKey.findProgramAddressSync([Buffer.from("merkle_tree"),Buffer.from([0])],P);const i=await c.getAccountInfo(t0);console.log("shard0 leaf_count",new DataView(i.data.buffer,i.data.byteOffset+8,8).getBigUint64(0,true))})'
```

**Teardown:** `phala cvms stop "$CVM"` + `shred -u /tmp/darknyx.env`.

### 6.2 Multi-match settle profiler — `cvm-multimatch-settle.test.ts`

The throughput profiler: deposits **M** crossing pairs and submits them
together so the CVM settles a multi-match batch, then reads the **co-inclusion**
(`distinct_slots`) + per-stage timing from the CVM logs. With K=4 shards, an
8-match batch confirms all 8 settles in **one slot** (8× co-inclusion vs the
single-tree ~2.67×). Same real-mint regime as §6.

```sh
# Reset all shards first (the test asserts trees start empty), then:
RUN_CVM_E2E=1 DARKNYX_CVM_MATCHES=16 DARKNYX_TEE_GATEWAY="$GW" SOLANA_RPC_URL="$HELIUS" \
  FUNDER_KEYPAIR=~/.config/solana/id.json ADMIN_KEYPAIR=.devnet/keypairs/admin.json \
  bash -c 'cd packages/sdk && ../../node_modules/.bin/vitest run tests/cvm-multimatch-settle.test.ts'

# Read the levers from the CVM logs:
phala cvms logs "$CVM" | grep -E "settle co-inclusion|settle pipeline timing"
#   distinct_slots = blocks the settles spanned (co-inclusion = n ÷ distinct_slots)
#   lock_ms / prove_ms / alt_tx_ms / settle_ms = per-stage wall time
```

### 6.1 Validate fills delivery — the off-TEE indexer + per-account stream channel

The same settle that mints `note_e` (above) is a **continuation fill**: the CVM
emits a `FillMemo` over `/v1/stream`'s `fills` channel (live) and the on-chain settle tx carries
the change note's `order_id` + amount + commitment (durable). `cvm-settle-e2e`
asserts BOTH automatically when `DARKNYX_INDEXER_URL` is set — order ids are
deterministic (`deriveOrderId`), so the test queries the indexer by the exact id
it used and matches the WS memo to it. The indexer runs **locally**, reads the
same devnet RPC, and the CVM never talks to it.

```sh
# 1. Start the local indexer (temp SQLite, reads devnet read-only) in another shell.
INDEXER_RPC_URL="$HELIUS" scripts/run-indexer-local.sh    # serves :8090 — GET /fills, /health

# 2. Run cvm-settle-e2e with fills mode on. It mints note_e → asserts the buyer's
#    change note over (a) the indexer GET /fills and (b) the live per-account WS,
#    and reconstructs the spendable opening from the seed (the integrity check).
RUN_CVM_E2E=1 DARKNYX_TEE_GATEWAY="$GW" DARKNYX_INDEXER_URL="http://127.0.0.1:8090" \
  SOLANA_RPC_URL="$HELIUS" DARKNYX_CVM_SETTLE_TIMEOUT_MS=150000 \
  FUNDER_KEYPAIR="$HOME/.config/solana/id.json" ADMIN_KEYPAIR=.devnet/keypairs/admin.json \
  bash -c 'cd packages/sdk && ../../node_modules/.bin/vitest run tests/cvm-settle-e2e.test.ts'
```

> **The WS half needs a CVM built from the fills commit** (per-account `fills` channel,
> un-gated). The **indexer half works against any deployed CVM** — it only reads the
> chain. Without `DARKNYX_INDEXER_URL` the test runs exactly as before (settle only).
> In the SDK the equivalent client one-liner is `startFillsSync({ indexerBaseUrl,
> gatewayWsUrl, token, masterSeed, ownerCommitment, baseMint, quoteMint, store })`
> (`packages/sdk/src/fills/`) — backfill history from the indexer, then tail the WS,
> deduping by commitment.

**Over-collateralization scenario:** add `DARKNYX_CVM_BUYER_SURPLUS=<quote units>` to
deposit a buyer note larger than the order needs. The order auto-declares its
`collateral_amount`, intake accepts `note ≥ required`, and the test asserts the
indexer change-note's `changeAmount ≥ the surplus` (the surplus came back). Default
0 = exact collateral. (Works against a CVM built from the over-collateral commit.)

---

## 7. Devnet E2E #2 — loadgen against a CVM

`crates/darknyx-tee-loadgen/` is a host binary that hammers the CVM's
`POST /orders` with cryptographically-valid synthetic orders. It validates
**intake throughput + matcher behaviour** (NOT settle finality — synthetic
orders carry no real VALID_INPUT proof, so their settles fail gracefully at
`lock_note`; that's by design).

**Prereqs:** deploy the CVM with the **placeholder dev mints** (omit
`DARKNYX_TEE_BASE_MINT`/`_QUOTE_MINT` from `-e`) + `DARKNYX_TEE_FEE_RATE_BPS=30` +
Helius:

```sh
umask 077
cat > /tmp/darknyx-lg.env <<EOF
DARKNYX_TEE_SOLANA_RPC_URL=$HELIUS
DARKNYX_TEE_SYNC_FROM_SLOT=$(solana slot --url "$HELIUS")
DARKNYX_TEE_FEE_RATE_BPS=30
EOF
phala deploy --cvm-id "$CVM" -c deploy/docker-compose.yaml -e /tmp/darknyx-lg.env
# /instruments should now show the placeholder mints (…ioiQ / …ioi5).
```

**Run** — price the orders at the **live oracle** (else the clearing price
drifts far from the matcher's Hermes feed and the circuit breaker trips → 0
matches), and `--fee-rate-bps` MUST equal the CVM's rate:

```sh
RAW=$(curl -s "https://hermes.pyth.network/v2/updates/price/latest?ids[]=ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d" | jq -r '.parsed[0].price.price')

cargo run -q -p darknyx-tee-loadgen -- \
  --endpoint "$GW" \
  --fee-rate-bps 30 \
  --oracle-twap "$RAW" \
  --traders 10 \
  --orders-per-trader-per-sec 5 \
  --duration-secs 25 \
  --cancel-rate 0.1
```

**Expect:** ~100% 2xx; CVM logs show `matcher tick: produced matches` paged
into `≤16`-match settle batches (`enqueued batch match_count=…`), and the
synthetic settles fail gracefully at `lock_note` (no crash). Throughput is
RTT-bound (~25–30 ord/s from a laptop; run from the CVM's region to measure
the true intake ceiling).

**Useful flags** (`crates/darknyx-tee-loadgen/src/config.rs`):
`--traders`, `--orders-per-trader-per-sec`, `--duration-secs`,
`--cancel-rate`, `--workload uniform`, `--oracle-twap <hermes raw>`,
`--fee-rate-bps <= CVM rate>`, `--expiry-slot` (default 2e9 — must exceed
the live Solana slot or the matcher sweeps orders as expired),
`--api-key/--api-secret/--passphrase` (default to the compose bootstrap
creds), `--report <path.md>`.

**Teardown:** `phala cvms stop "$CVM"` + `shred -u /tmp/darknyx-lg.env`.

---

## 8. Vault crypto on devnet (no CVM)

`devnet-deposit-withdraw.test.ts` exercises the **VALID_DEPOSIT-gated vault
deposit + VALID_SPEND withdraw round-trip on devnet in isolation** — no CVM,
no TEE authority. It resets the tree, mints, proves and deposits a v2 note,
then withdraws it with a VALID_SPEND proof and asserts the round-trip. Use it
to test vault crypto changes without spending on a CVM.

```sh
SOLANA_RPC_URL="$HELIUS" RUN_DEVNET_DW=1 \
  ADMIN_KEYPAIR=.devnet/keypairs/admin.json \
  FUNDER_KEYPAIR=~/.config/solana/id.json \
  bash -c 'cd packages/sdk && ../../node_modules/.bin/vitest run tests/devnet-deposit-withdraw.test.ts'
```

Run `devnet-setup.test.ts` first if `.devnet/e2e-config.json` is missing
(it writes the mints + settle ALT + protocol config every other devnet
test reads).

`devnet-merge.test.ts` is the sibling for the **in-pool note merge** ix
(`VALID_MERGE`) — also no CVM, no TEE (merge is a pure vault tx). It resets
the tree, deposits two notes, merges them (K=2) into one, then withdraws the
merged note with a VALID_SPEND proof and asserts the consolidated amount
round-trips (and `leaf_count` 2 → 3: two inputs nullified, one output leaf).

```sh
SOLANA_RPC_URL="$HELIUS" RUN_DEVNET_MERGE=1 \
  ADMIN_KEYPAIR=.devnet/keypairs/admin.json \
  FUNDER_KEYPAIR=~/.config/solana/id.json \
  bash -c 'cd packages/sdk && ../../node_modules/.bin/vitest run tests/devnet-merge.test.ts'
```

Build the merge circuits first if `circuits/build/valid_merge_k{2,4}/` is
missing (`bash scripts/build-circuits.sh` — they're in the list; pot16, no
new ptau). The deployed vault must carry the `merge` ix + the
`vk_valid_merge_k{2,4}.rs` consts.

`devnet-leaf-index.test.ts` validates the **race-proof leaf-index read**
(`utxo/leaf-index.ts`) against real RPC: it drives the HIGH-LEVEL
`getDepositFunction` + `getMergeFunction` (full `DarkPoolClient` with devnet
providers + a snarkjs `VALID_MERGE` prover adapter), so the
`getTransaction → parse NoteCreated/NoteMerged event` path is exercised
end-to-end (the unit tests can only mock it). Resets shard 0 (sole appender),
deposits 2 notes (asserts each event-read index == 0,1), merges them (asserts
the `NoteMerged` index == 2). Requires the redeployed vault whose `NoteMerged`
event carries `tree_id` + `leaf_index`.

```sh
RUN_DEVNET_LEAF=1 \
  bash -c 'cd packages/sdk && ../../node_modules/.bin/vitest run tests/devnet-leaf-index.test.ts'
```

(Reads `l1RpcUrl` + `baseMint` from `.devnet/e2e-config.json` and signs with
`.devnet/keypairs/admin.json` — the mint authority.)

---

## 9. Resetting state

### 9.1 Local disk

```sh
cargo clean
rm -rf node_modules packages/sdk/dist circuits/build
# Light: cargo clean -p vault -p darknyx-tee && rm -rf packages/sdk/dist
```

### 9.2 On-chain Merkle tree (devnet only)

```sh
SOLANA_RPC_URL="$HELIUS" ADMIN_KEYPAIR=.devnet/keypairs/admin.json node scripts/reset-merkle-tree.mjs
```

Symptom that you need it: `StaleMerkleRoot (6004 / 0x1774)` on withdraw, or
the CVM e2e harness asserting `tree not empty`. Wipes `leaf_count` /
`right_path` / `roots[]`; leaves nullifier / wallet / note-lock PDAs intact.
`devnet-setup.test.ts` does this too (plus fresh mints + ALT).

---

## 10. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| CVM e2e: `tree not empty` | tree has stale leaves | `node scripts/reset-merkle-tree.mjs` before the run (§4.5) |
| Intake **all 4xx** (`opening does not match note_commitment`) | CVM mints ≠ the deposited notes' mints, OR the order's `note_amount` ≠ intake's fee-inclusive derivation | redeploy CVM with the `e2e-config` mints; ensure `--fee-rate-bps` / `DARKNYX_CVM_FEE_RATE_BPS` match `DARKNYX_TEE_FEE_RATE_BPS` |
| Loadgen: **0 matches**, logs show `swept expired orders` | `--expiry-slot` below the live Solana slot | use the default 2e9 (or `>` the live slot) |
| Loadgen: **0 matches**, no sweep | orders mispriced vs the live oracle → circuit breaker | set `--oracle-twap` to the live Hermes raw price (§7) |
| Settle: `InvalidMarkerExpiry (6018)` | marker expiry outside `clock.slot < e <= clock.slot+300` | margin is 250 in the worker; ensure the CVM's RPC slot is fresh (slot poller) |
| Settle: `<slot> is not a recent slot` (CreateLookupTable) | ALT `recent_slot` ahead of the simulating replica | the worker backs off 32 slots; transient — retry |
| Settle: `did not confirm … [None]` | ALT not active yet, or tx dropped | the worker waits a slot + rebroadcasts; a hard timeout now errors `AltNotActive` (retryable) |
| Settle: `Transaction too large: …` (settle Tx D) | settle v0 tx > 1232 B | ensure `DARKNYX_TEE_SETTLE_LOOKUP_TABLE` is set (static ALT stacked). The per-batch ALT also hoists the consumed-note PDAs; the worker logs the inline-account breakdown on overflow. |
| Settle: `Transaction too large: …5224 B…` (ALT extend) | per-batch ALT extend not chunked for a big batch | fixed: extends chunk at ≤25 addr/tx + fire concurrently (image ≥ `tee-v3-hardening-26`) |
| Settle stage ~13s wall despite co-inclusion | per-batch ALT activation finality wait (Tx D rebroadcasts until the freshly-extended ALT is loadable) | inherent pre-Alpenglow; concurrent extends collapse it to ONE activation window |
| All ixs fail `ConstraintSeeds (2006)` after a redeploy | old-layout `VaultConfig` PDA (size/offset mismatch) | `node scripts/close-vault-config.mjs` then `devnet-setup` (§4.4) |
| Settle signed by an unregistered key → `Unauthorized` | the CVM's K shard signers aren't all registered | `rotate-tee-pubkey.mjs <K0..Kn>` (the full set); `fund-tee-keys.mjs` |
| `merkle reconcile DIVERGED` in CVM logs | trees reset on-chain underneath the append-only mirror (dev resets without CVM restart) | cosmetic for settle; restart the CVM (or bump `DARKNYX_TEE_SYNC_FROM_SLOT`). Logged once per shard. |
| Matcher: `conservation broken … in=N out=N+fee` | order under-collateralized for its own fee | each side must lock `nominal + fee` (intake derives this; the e2e harness `withFee()` + loadgen do too) |
| `phala deploy` didn't pick up code changes | same image tag (cached) | bump `tee-v3-hardening-N`, push the tag, rebuild (§5.1) |
| Auth: 401 after a CVM restart | runtime-registered account lost (persistence volume perms) | use the env bootstrap admin; check `DARKNYX_TEE_STATE_DIR` is a writable volume |
| `solana transfer`/faucet rate-limited | devnet faucet 429 | use a pre-funded local wallet; fund the CVM signer via `solana transfer` (not airdrop) |
| `npm`/`node` not found in a non-interactive shell | nvm lazy-load shim | use the full path, e.g. `~/.nvm/versions/node/<v>/bin/node` |

---

## 11. Reference constants

| Thing | Value |
|---|---|
| Vault program id | `C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx` |
| Matching-engine program id (retiring) | `6EasFxo6RCWrK4KAwcdUJqL4KjReLC3rtah8EtHgHSqe` |
| CVM image | `ghcr.io/skysail-labs/darknyx-tee:tee-v3-hardening-<N>` (built by the `tee-image` workflow on a `tee-v3-hardening-*` tag; GH repo `skysail-labs/darknyx`) |
| Gateway URL form | `https://<app_id>-8080.dstack-pha-prod5.phala.network` |
| Pyth Hermes SOL/USD feed id | `ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d` |
| Placeholder dev mints | base `[1,0…,0xb1]`, quote `[1,0…,0x9e]` (loadgen regime) |
| Test keypair dir (gitignored) | `.devnet/keypairs/` |
| Runtime config (gitignored) | `.devnet/e2e-config.json` (now incl. `numTrees` + `merkleTreePdas[]`) |
| Merkle-tree shard PDA | `[b"merkle_tree", &[tree_id]]` under the vault program |
| Helper scripts | `reset-merkle-tree.mjs` (`--all`/`--tree`), `rotate-tee-pubkey.mjs` (Vec), `fund-tee-keys.mjs`, `close-vault-config.mjs`, `setup-devnet.sh`, `deploy-devnet.sh` |

Post-sharding, `leaf_count` is a `u64` at byte offset **8** of each
`MerkleTree[tree_id]` account; `current_root` is the 32 bytes at offset **16**.
(The old `vault_config` offsets 104/112 are gone — the tree state moved out.)

---

*Architecture deep-dives: `docs/tee-architecture.md` (§11 auth, §13 the
iterate/spot-check/ceremony loop), `docs/tee-attestation-flow.md`,
`docs/ARCHITECTURE.md`, `CRYPTOGRAPHY.md`, `CLAUDE.md`.*
