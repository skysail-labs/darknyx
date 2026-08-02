# CLAUDE.md — agent onboarding for Darknyx Darkpool

> This file is the contract between you (the agent) and the project.
> Read it before touching code. `AGENTS.md` is a **symlink to this file** —
> edit here, never there (they can never diverge).
>
> If you only read one section, read **[§2 — the build/validate
> cycle](#2-the-buildvalidate-cycle)** and **[§3 — the Phala CVM:
> build → deploy → test](#3-the-phala-cvm--build--deploy--test)**.

---

## 0. What this repo is, in 60 seconds

Darknyx (aka **darknyx**) is a privacy-preserving CLOB-style darkpool on
Solana. Matching and settlement run **inside an Intel TDX confidential
VM (a "CVM") on Phala Cloud**. Three layers:

* **L1 (Solana)** — `programs/vault/` is the only on-chain program
  (Anchor 0.32). It owns custody, the incremental Merkle tree of note
  commitments (now **sharded into K per-shard `MerkleTree` accounts** —
  `VaultConfig` holds the global state incl. the K-key `tee_pubkeys` set
  + `num_trees`), the nullifier / consumed-note sets, the Groth16
  verifier, the **note-merge** path (`merge`, VALID_MERGE K=2/4), and the
  **atomic batched settlement** path
  (`lock_note → verify_match_batch → tee_forced_settle_batched →
  close_batch_validity_marker`, N=16 matches per batch, `tree_id`-routed).
  Deposits are gated by `VALID_DEPOSIT`, which keeps the wallet-wide owner
  commitment + per-note inner private while binding mint, gross amount,
  commitment, and a public recovery nonce.
  Devnet program id: `C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx`.
* **TEE (`crates/darknyx-tee/`)** — the in-enclave engine. It owns hidden
  order intake (`POST /orders`), uniform-clearing-price matching, the
  full settle pipeline (lock → prove N=16 VALID_MATCH_BATCH [ark or
  rapidsnark backend, `DARKNYX_TEE_PROVER`] → verify → per-batch ALT →
  `tee_forced_settle_batched` → close, **concurrent sends round-robined
  across K shard fee-payer keys + K trees** so the leader co-includes a
  batch's settles in one block), K Merkle-mirror indexers, deterministic
  consumed-input-derived continuation outputs, and the auth'd HTTP/WS surface. Order
  intent never touches an L1 tx; the enclave drives the vault settle ixs
  directly.
* **Client (TypeScript SDK + snarkjs prover)** — `packages/sdk/` is the
  integration surface: clients build VALID_INPUT proofs and `POST`
  orders to the CVM. `packages/daemon/` (`darknyx-daemon`) is the reference
  **non-custodial market-maker daemon** built on the SDK (keys + proving
  on-device; drives order lifecycle off the `fills` + `orders` channels on the
  shared `/v1/stream` session and on-chain reads, with auto-merge). It is
  deliberately **lean — it does NOT depend on the off-TEE indexer**; live TEE
  streams + chain reads are its source of truth (merged, live-CVM smoke-tested).
  `crates/darkpool-crypto/` is the host-side Rust crypto crate with
  byte-identical Poseidon / nullifier / note / key derivation that the TS SDK
  has parity tests against.

Supporting crates: `crates/darkpool-matcher/` (the matching algorithm +
the order/cancel canonical signing — single source of truth, used by the
in-TEE matcher)
and `crates/darknyx-tee-loadgen/` (a host
binary that load-tests the CVM's intake).

> **Public docs live in `docs/gitbook/` — edit it directly.** `docs/gitbook/`
> is the **single source of truth** for the public documentation portal, hosted
> on GitBook via git-sync. It is GitBook-flavored Markdown: YAML frontmatter with
> a quoted `description`, `{% hint style="info|warning|success" %}` callouts, a
> root `SUMMARY.md` table of contents, `.md`-suffixed relative links, and a
> `.gitbook.yaml` config. Edit these files directly; when you add, remove, rename,
> or reorder a page, **update `SUMMARY.md` in the same change** (it drives the
> nav). GitBook git-sync is **bidirectional** — edits made in the GitBook UI are
> committed back here, so this directory is the canonical copy; never keep a
> parallel generated source. (The former Docusaurus source `docs/portal/` and its
> `scripts/convert-portal-to-gitbook.py` generator were retired 2026-07 in favor
> of editing GitBook directly.)

**The note model (v2 / `inner_hash`).** Every note commitment AND its
nullifier are anchored on a single amount-independent `inner_hash`:

```
commitment = Poseidon6(DOMAIN_NOTE, mint_lo, mint_hi, amount, owner_commitment, inner_hash)
nullifier  = Poseidon3(DOMAIN_NULL, spending_key, inner_hash)
```

VALID_MATCH_BATCH v3 derives user-output inners as
`Poseidon3(24, consumed_input_inner, role)` and fee inners as
`Poseidon3(25, consumed_input_commitment, role)`. This removes caller-selected
output randomness and lets the matcher rotate partial-fill residuals without a
client roundtrip or anchor-dependent liveness.

> **There is no legacy CLOB / MagicBlock-ER / `matching_engine` program
> anymore.** It was deleted. If you find a reference to `matching_engine`,
> `run_batch`, `submit_order` (on-chain), PER sessions, or ER delegation
> in any doc or comment, it is stale — fix it. The only on-chain program
> is `vault`; the only matcher is the in-TEE one.

---

## 1. Stop. Read these first.

You will not write correct code here without the mental model. Required:

* **[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)** — system overview +
  the account / PDA table + the deployment runbook.
* **[`CRYPTOGRAPHY.md`](CRYPTOGRAPHY.md)** — key model, the note system
  (v2 inner_hash), the Merkle tree, the ZK circuits, the settlement size
  analysis, replay protection.
* **[`scripts/dev-commands.md`](scripts/dev-commands.md)** — the command
  cheat sheet: every test surface, the everything-green gate, the devnet
  foundation, the CVM lifecycle (build image → deploy → env → signer
  rotation), the `cvm-settle-e2e` flow, the loadgen. Run commands
  verbatim. Helper scripts: `scripts/reset-merkle-tree.mjs`,
  `scripts/rotate-tee-pubkey.mjs`, `scripts/deploy-devnet.sh`.
* **[`docs/fills-history-architecture.md`](docs/fills-history-architecture.md)**
  — the fills-delivery + trade-history design, now **implemented**
  (deterministic HD order_ids + the per-account `/v1/stream` fills channel).
  Recovery v3 restores deposit, trade, change/continuation, and merge openings
  from seed + chain; the off-TEE `packages/indexer`
  is an **OPTIONAL by-order_id commitment LOCATOR** with no consumer today (the
  daemon uses live streams instead) — the durable amount source is the chain.
  Read the top-of-doc as-built deltas; the lower half is the superseded original
  decision record.
* **[`docs/settlement-recovery-drill.md`](docs/settlement-recovery-drill.md)** —
  how to prove on a real CVM that an interrupted settlement recovers and a
  planned stop leaves nothing behind (T-06). **Use this instead of improvising**
  whenever the settle pipeline, the journal schema, or the persistence layer
  changes. It carries the two traps that cost attempts: `phala cvms stop` is an
  API request the container outlives, so it cannot land inside the ~10 s settle
  phase and the kill must be triggered off the journal's own `/admin/drain`
  reading; and a tree reset does NOT empty the Merkle mirror, which replays from
  `DARKNYX_TEE_SYNC_FROM_SLOT` and needs an env-only redeploy with a post-reset
  floor.
* **[`audits/`](audits/)** — every security/performance engagement, its
  findings, and its closure tracker. **[`audits/residual-backlog.md`](audits/residual-backlog.md)**
  is the canonical index of what is still open across all of them (with the
  recurring structural classes worth fixing as patterns);
  **[`audits/AUDIT_AGENT_ONBOARDING.md`](audits/AUDIT_AGENT_ONBOARDING.md)**
  seeds the next auditing agent, and **[`audits/README.md`](audits/README.md)**
  tells an implementing agent how to build a tracker. Findings documents are
  immutable point-in-time evidence — status moves in the tracker and the
  backlog, never by editing the report.
* **[`docs/throughput-roadmap.md`](docs/throughput-roadmap.md)** — the log of
  settle/throughput optimizations deliberately DEFERRED behind platform gates
  (🟢 GPU proving, 🔵 Alpenglow finality) + 🟡 real volume, with the measured
  cost model they're reasoned against. Pull items from here (don't re-derive)
  when a gate lifts; add new gated work there, not just in a code comment.
* **[`docs/multi-market-architecture.md`](docs/multi-market-architecture.md)** —
  the as-built N-books-per-CVM model, strict JSON market config, routing and
  settlement-isolation invariants, venue-wide capacity gates, and the deferred
  cross-CVM discovery design. The circuit still fixes one market per BATCH and
  `vault_config.tee_pubkeys` still authorizes one TEE cluster per vault, so a
  second CVM cluster needs an on-chain signer/shard model change first.

By domain, additionally:

| If you're touching | Read first |
|---|---|
| A circom circuit | `CRYPTOGRAPHY.md` §7, then the circuit + its `vk_*.rs` + its `*-prover.test.ts`. **See [§5](#5-touching-circuits-the-failure-mode-thats-bitten-us) — the disaster section.** |
| A `vault` instruction | `CRYPTOGRAPHY.md` §8, `programs/vault/src/state.rs` (PDA layout), the litesvm test in `programs/vault/tests/`. |
| `crates/darkpool-crypto` | The matching `*-parity.test.ts` under `packages/sdk/tests/`. **Every host-side primitive has a byte-equality contract with TS.** |
| `crates/darkpool-matcher` | `tests/parity.rs` + `change_note_parity.rs` + `order_canonical.rs`'s tests. The matcher algorithm is the single source of truth. **The enclave calls `PreparedMatchTick::next_page` (`single_fill_per_order: true`), NOT `run_batch`** — `run_batch` chains partial fills within a batch and exists for tests and legacy callers (SW-28); naming both here read as an endorsement of an entry point production does not use. A change to `change_note::derive_inner` triggers a triple-port (matcher Rust ↔ TS in `e2e-helpers.ts` ↔ the on-chain hashers). |
| `crates/darknyx-tee` (the in-TEE binary) | `docs/tee-architecture.md` (§11 auth model, §13 the iterate/spot-check/ceremony dev loop), `docs/tee-attestation-flow.md`, `docs/tee-api-openapi.yaml`. See [§4 of this file](#4-tee-development-workflow--iterate--spot-check--ceremony). |
| The settle pipeline / journal / persistence | `docs/settlement-recovery-drill.md` — the crash-recovery + drain drill and its pass criteria. Re-run it when any of these change. |
| The SDK | The corresponding `tests/*-transport.test.ts` / parity test. `idl/vault-client.ts` hand-codes every discriminator + Borsh layout (no Anchor IDL runtime) — keep it in sync with the on-chain structs by hand. |
| Settlement plumbing | `CRYPTOGRAPHY.md` §9 (size analysis + ALT story). The 1232-byte cap is tight — see [§6](#6-the-1232-byte-transaction-size-budget). |

---

## 2. The build/validate cycle

Everything runs from the repo root.

### 2.1 One-time host setup

```sh
npm install                                        # SDK + snarkjs + circomlib
bash scripts/download-ptau.sh                      # pot16 (~80 MB) + pot18 (~288 MB)
bash scripts/build-circuits.sh                     # compile all 9 circom circuits;
                                                   #   regenerates vk_*.rs Rust consts
cargo build --examples -p darkpool-crypto          # TS↔Rust parity helper binaries
```

`build-circuits.sh` writes verifier-key Rust consts into
`programs/vault/src/zk/vk_*.rs`. Skip it and the vault program fails to
compile on a fresh checkout.

### 2.2 Touched circuit code? Rebuild + commit BOTH artifacts in lockstep

The most common foot-gun. See [§5](#5-touching-circuits-the-failure-mode-thats-bitten-us).
Short version:

```sh
bash scripts/build-circuits.sh                     # recompiles .wasm + .zkey + vk_*.rs
git add circuits/<name>/circuit.circom \
        circuits/build/<name>/circuit_final.zkey \
        programs/vault/src/zk/vk_<name>.rs
```

Commit `circuit.circom` without the regenerated `.zkey` + `vk_*.rs` and
the deployed program rejects every proof the new circuit makes — surfacing
as `InvalidProof (6000)`, not "you forgot the VK."

### 2.3 Touched on-chain code? Rebuild BPF + redeploy

```sh
# 1. BPF (required for litesvm tests AND for devnet deploy)
#    `--features devnet-admin` compiles the dev/devnet admin ixs
#    (`reset_merkle_tree` + `close_vault_config`) the litesvm suite +
#    reset-merkle-tree.mjs use. OFF by default (audit_1 F-01/F-02) so a MAINNET
#    build (plain `cargo build-sbf`, no feature) ships neither backdoor.
cargo build-sbf --manifest-path programs/vault/Cargo.toml --features devnet-admin

# 2. Pre-commit gate (host-side)
cargo clippy --workspace --all-targets -- -D warnings   # MUST pass, zero warnings
cargo fmt --all -- --check
cargo test --workspace

# 3. Devnet upgrade (idempotent in place — keeps the same program id)
bash scripts/deploy-devnet.sh
```

`deploy-devnet.sh` uses your local `~/.config/solana/id.json` as upgrade
authority + fee payer (need ≥ 5 SOL on devnet). **Never regenerate the
program-id keypair for an initial deployment** unless you mean to —
`declare_id!()` in `programs/vault/src/lib.rs` and `[programs.*]` in
`Anchor.toml` must match, and the `consistency` CI job fails if they diverge.
Existing upgrades use the compiled program address and require only the upgrade
authority; `deploy-devnet.sh` verifies the program exists before taking that path.

### 2.4 Re-initialise devnet state when the Merkle tree diverges

The on-chain incremental Merkle tree accumulates leaves across every
deposit + settlement. The SDK's in-memory `MerkleShadow` starts empty, so
after a few runs they drift and every `VALID_SPEND` withdraw fails with
`StaleMerkleRoot (6004)`. Cure — a tree-only reset (keeps mints/ALT/config):

```sh
SOLANA_RPC_URL="$HELIUS" ADMIN_KEYPAIR=.devnet/keypairs/admin.json \
  node scripts/reset-merkle-tree.mjs
```

To rebuild mints + the settle ALT + protocol config from scratch (writes
`.devnet/e2e-config.json` that every other devnet test reads):

```sh
RUN_DEVNET_E2E=1 \
  ADMIN_KEYPAIR=.devnet/keypairs/admin.json \
  TEE_AUTHORITY_KEYPAIR=.devnet/keypairs/tee_authority.json \
  ROOT_KEY_KEYPAIR=.devnet/keypairs/root_key.json \
  ( cd packages/sdk && ../../node_modules/.bin/vitest run tests/devnet-setup.test.ts )
```

> **Tree reset is MANDATORY after the v2 (`inner_hash`) migration** and
> after any circuit/VK change: pre-existing leaves were built with the
> old construction and are unspendable under the new VK. A stale tree →
> `InvalidProof` on every `lock_note`/settle.

### 2.5 The "everything green" pre-PR gate (no devnet, no CVM)

**Run every line before pushing or opening a PR.** This mirrors
`.github/workflows/pr-checks.yml` — pass here, CI passes.

```sh
set -e
cargo fmt --all && cargo fmt --all -- --check       # CI fails on one un-fmt'd line
bash scripts/check-compose-image-digests.sh          # CPU/GPU compose must use @sha256
bash scripts/check-icicle-cuda-arch-env.sh           # every CUDA build.rs reads the var the Dockerfile forwards
bash scripts/check-brand-namespace.sh                # no stale pre-Darknyx namespaces
bash scripts/build-vault-sbf.sh devnet-admin        # NOT a bare build-sbf: writes the fingerprint
                                                    #   manifest the litesvm suite checks (T-13), so a
                                                    #   stale .so can't be validated silently
cargo build --examples -p darkpool-crypto           # parity tests shell out to these
cargo clippy --workspace --all-targets -- -D warnings
bash scripts/check-no-debug-endpoints.sh            # /__debug must stay off by default (SW-33)
bash scripts/check-no-doctests.sh                   # nextest skips doctests; this
                                                    #   fails if one ever appears
cargo nextest run --workspace                       # unit + litesvm integration.
                                                    #   ~41% faster than `cargo test`
                                                    #   (266s -> 156s on 8 cores).
                                                    #   `cargo test --workspace` is
                                                    #   equivalent and still correct.
                                                    #   Without nextest, substitute
                                                    #   `cargo test` in BOTH this line
                                                    #   and the artifact-required one
                                                    #   below, and skip the doctest
                                                    #   guard (cargo test runs them).
# T-12: needs circuit artifacts — §2.1's `bash scripts/build-circuits.sh` must have run.
# Under this flag a missing .wasm/.r1cs/.zkey is a hard FAILURE, not a silent skip,
# so a proof-backed test can never report success without proving.
REQUIRE_CIRCUIT_ARTIFACTS=1 cargo nextest run -p darknyx-tee --tests   # or `cargo test`
bash scripts/check-dependency-audits.sh             # cargo audit + npm audit vs the recorded baseline
# Typecheck with the TESTS-INCLUSIVE config. The build tsconfig includes only
# `src/`, so `-p packages/<pkg>/tsconfig.json` never sees tests/ — which is how
# 23 type errors sat on main unnoticed. CI runs exactly these three lines.
./node_modules/.bin/tsc -p packages/sdk/tsconfig.test.json --noEmit
./node_modules/.bin/tsc -p packages/daemon/tsconfig.test.json --noEmit
./node_modules/.bin/tsc -p packages/indexer/tsconfig.test.json --noEmit
( cd packages/sdk && ../../node_modules/.bin/vitest run )   # devnet/CVM tests auto-skip
( cd packages/indexer && ../../node_modules/.bin/vitest run ) # fills indexer; DB tests need Node 22+ (node:sqlite)
( cd packages/daemon && ../../node_modules/.bin/vitest run ) # market-maker daemon
echo "ALL GREEN — safe to push"
```

`cargo nextest run --workspace` already includes `darknyx-tee`; the extra
`REQUIRE_CIRCUIT_ARTIFACTS=1` line re-runs its integration tests in
artifact-required mode, where a missing circuit artifact FAILS instead of
silently skipping the proof-backed intake tests.

**Why nextest, and the one thing it does not do.** It runs each test in its own
process and parallelises across the ~48 test binaries, where `cargo test` runs
them one binary at a time — measured 266 s → 156 s on 8 cores. It does **not**
run doctests. The workspace has none, and `scripts/check-no-doctests.sh` fails
the gate if one is ever added, so the omission cannot become a silent gap. CI
still runs `cargo test`: nextest's advantage comes from spare cores, so it is
much smaller on a 2-core runner. Install with
`cargo install cargo-nextest --locked`; `.config/nextest.toml` caps
`test-threads` because ~50 tests each load a proving key (the N=16 key is 97 MB)
and process-per-test would otherwise multiply peak memory.

Expected: ~workspace Rust tests pass; ~94 SDK tests pass + a few env-gated
ones skip (they need `RUN_DEVNET_E2E=1` / `RUN_CVM_E2E=1` / `RUN_DEVNET_DW=1`
+ devnet connectivity).

### 2.6 Deletion checklist — what the workspace gate doesn't catch

`cargo test --workspace` auto-discovers tests from the filesystem and does
NOT error on a "missing test target." But `cargo test -p vault --test <name>`
(which CI uses) errors hard with `no test target named '<name>'`, and the
circuit scripts + workflow YAMLs hard-code their own lists.

Whenever you delete a file under `programs/vault/tests/`, `circuits/`,
`packages/sdk/tests/helpers/`, or `programs/vault/src/instructions/`, run:

```sh
NAME=<deleted-basename>
grep -nE "$NAME" .github/workflows/*.yml scripts/*.sh scripts/*.md \
    || echo "no stale references"
```

If anything matches, fix it in the SAME commit as the deletion.

---

## 3. The Phala CVM — build → deploy → test

This is the flagship real-settle path: a deployed CVM matches AND settles
a real crossing pair on devnet. The CVM binary is the **in-TEE matcher +
settler**, so any change under `crates/darknyx-tee/`, `Dockerfile`,
`deploy/docker-compose.yaml`, or a TEE-proved circuit (`match_batch_*`) requires a **rebuilt image**
— `phala cvms start` on the old image runs stale code.

**The copy-paste runbook is [`docs/cvm-run-runbook.md`](docs/cvm-run-runbook.md)**
— the exact build→deploy→rotate→fund→reset→test→STOP commands plus the
gotchas that have each burned a deploy (the origin→`skysail-labs/darknyx`
remote redirect, the hardcoded compose creds, the nvm-shim `node` path, the
gTFA 100 cap, the two mint regimes, secrets-via-`.env`-not-`/tmp`, and
rotating/funding all K shard signers). Start there for any CVM run.
`scripts/dev-commands.md §5–§7` is the longer reference; this section is the
conceptual summary.

### 3.0 Tooling

The `phala` CLI is a Node binary; if a broken nvm shim shadows `node`,
invoke it (and `node`) by absolute path:
`/Users/<you>/.nvm/versions/node/<ver>/bin/{node,phala}`. `phala cvms list`
shows the CVM (`app_id`, name, status). `--cvm-id` accepts the `app_id`
form (`app_<id>`).

### 3.1 Build a new image (tag → CI → ghcr)

The `tee-image` GitHub workflow builds `linux/amd64` and pushes to
`ghcr.io/skysail-labs/darknyx-tee:tee-v3-hardening-<N>` (registry-cached, ~4–5 min).
**Always build under a fresh tag for a code change, then deploy its resolved
digest.** Reusing a tag risks building or measuring stale content; deploying
`@sha256:<digest>` makes the attested compose bind the exact image.

```sh
TAG=tee-v3-hardening-<N+1>
# 1. commit, then tag + push the exact source state:
git tag "$TAG" && git push origin "$TAG"
# 2. watch THE run for tee-image.yml on THIS tag. Do NOT take `--limit 1` off the
#    repo-wide list: any other workflow (pr-checks, a scheduled sweeper) can land
#    in between, and you would then watch — and green-light — an unrelated run.
RUN=$(gh run list --repo skysail-labs/darknyx --workflow tee-image.yml \
        --branch "$TAG" --limit 1 --json databaseId -q '.[0].databaseId')
test -n "$RUN" || { echo "no tee-image run for $TAG yet"; exit 1; }
gh run watch "$RUN" --repo skysail-labs/darknyx --exit-status
# 3. resolve Docker-Content-Digest, FAILING CLOSED. A missing tag returns a
#    non-200 with no digest header; printing the headers and eyeballing them is
#    how a compose ends up pinned to an image that was never built.
TOK=$(curl -s "https://ghcr.io/token?scope=repository:skysail-labs/darknyx-tee:pull" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
HDRS=$(curl -sI -o /dev/null -w '%{http_code}' -D /dev/stderr \
  -H "Authorization: Bearer $TOK" \
  -H "Accept: application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json" \
  "https://ghcr.io/v2/skysail-labs/darknyx-tee/manifests/$TAG" 2>/tmp/hdrs)
test "$HDRS" = 200 || { echo "manifest for $TAG not found (HTTP $HDRS)"; exit 1; }
DIGEST=$(tr -d '\r' < /tmp/hdrs | sed -n 's/^[Dd]ocker-[Cc]ontent-[Dd]igest: //p')
echo "$DIGEST" | grep -qE '^sha256:[0-9a-f]{64}$' \
  || { echo "malformed or absent digest: '$DIGEST'"; exit 1; }
echo "pin this: ghcr.io/skysail-labs/darknyx-tee@$DIGEST"
# 4. pin compose to that digest and commit it. `scripts/check-compose-image-digests.sh`
#    enforces the shape on every PR.
```

The tag is a build label and audit cross-reference only. Deployment compose
must use `@sha256:<digest>` so the attested `compose_hash` binds immutable image
content.

### 3.2 The encrypted env (`-e` file) — and the REGIME you're deploying

`deploy/docker-compose.yaml` references secrets as `${VAR}`; `phala deploy
-e <file>` injects them as encrypted env (the value never enters the
`compose_hash`). Build the file fresh each deploy — the Helius key is a
secret: write it `umask 077` under the gitignored `.devnet/` directory,
**securely delete it after deploy, never commit it.**

> **⚠️ The two CVM regimes are mutually exclusive — this is the loadgen
> hiccup that wasted a deploy.** Whether you set the mint env vars decides
> which test the CVM can serve:
>
> * **Real-settle regime (`cvm-settle-e2e`)** — SET `DARKNYX_TEE_BASE_MINT` +
>   `DARKNYX_TEE_QUOTE_MINT` to the `.devnet/e2e-config.json` mints. Intake
>   re-derives each order's commitment against these, so real deposits
>   match.
> * **Loadgen regime (`darknyx-tee-loadgen`)** — OMIT both mint vars. The CVM
>   falls back to `dev_match_config()` placeholder mints (`…0x9e` quote /
>   `…0xb1` base) that the loadgen hardcodes. **If you run the loadgen
>   against a real-mint CVM you get 100% 4xx** (commitment mismatch) — and
>   vice-versa. Switching is an env-only `phala deploy -e` (no rebuild).

```sh
umask 077
HELIUS="https://devnet.helius-rpc.com/?api-key=<key>"
export DARKNYX_TEE_API_KEY="darknyx-$(openssl rand -hex 16)"
export DARKNYX_TEE_API_SECRET="$(openssl rand -hex 32)"
export DARKNYX_TEE_PASSPHRASE="$(openssl rand -base64 32 | tr -d '\n')"
test -n "$DARKNYX_TEE_PYTH_API_KEY"  # upgraded authenticated Hermes credential
BASE=$(jq -r .baseMint.pubkey  .devnet/e2e-config.json)
QUOTE=$(jq -r .quoteMint.pubkey .devnet/e2e-config.json)
ALT=$(jq -r .settleLookupTable  .devnet/e2e-config.json)
OWNER=$(jq -r .protocol.ownerCommitmentHex .devnet/e2e-config.json)
K=$(jq -r '.numTrees // 1' .devnet/e2e-config.json)
node scripts/reset-merkle-tree.mjs   # FIRST — so the mirror cold-boots an empty tree
FLOOR=$(solana slot --url "$HELIUS")
cat > .devnet/darknyx-deploy.env <<EOF
DARKNYX_TEE_API_KEY=$DARKNYX_TEE_API_KEY
DARKNYX_TEE_API_SECRET=$DARKNYX_TEE_API_SECRET
DARKNYX_TEE_PASSPHRASE=$DARKNYX_TEE_PASSPHRASE
DARKNYX_TEE_PYTH_API_KEY=$DARKNYX_TEE_PYTH_API_KEY
DARKNYX_TEE_SOLANA_RPC_URL=$HELIUS
DARKNYX_TEE_SYNC_FROM_SLOT=$FLOOR
DARKNYX_TEE_BASE_MINT=$BASE          # OMIT these two lines for the loadgen regime
DARKNYX_TEE_QUOTE_MINT=$QUOTE
DARKNYX_TEE_MARKET_SYMBOL=SOL-USDC
DARKNYX_TEE_SETTLE_LOOKUP_TABLE=$ALT
DARKNYX_TEE_FEE_RATE_BPS=30
DARKNYX_TEE_PROTOCOL_OWNER_COMMITMENT=$OWNER
DARKNYX_TEE_NUM_TREES=$K
DARKNYX_TEE_SETTLE_BATCH_CONCURRENCY=1
EOF
```

A production boot rejects the public `darknyx-test-*` credentials. Keep the fresh
credential variables exported for the CVM harness/loadgen. A **malformed**
(non-empty) value fails startup (fail-fast); an **empty**
`${VAR}` falls back to the default. `DARKNYX_TEE_FEE_RATE_BPS` (default 30) must
equal the loadgen's `--fee-rate-bps` (intake derives fee-inclusive
collateral; a mismatch → every synthetic note fails `verify_commitment`).

### 3.3 Deploy + rotate the signer + fund it

```sh
CVM=app_634b2ab4c250466311f0cf09f772b6fd60b5be11   # phala cvms list
phala deploy --cvm-id "$CVM" -c deploy/docker-compose.yaml -e .devnet/darknyx-deploy.env --wait
if command -v shred >/dev/null 2>&1; then
  shred -u .devnet/darknyx-deploy.env
else
  rm -P .devnet/darknyx-deploy.env  # macOS
fi
test ! -e .devnet/darknyx-deploy.env

GW="https://<app_id>-8080.dstack-pha-prod5.phala.network"
curl -s "$GW/info" | jq -r .tee_pubkey          # the PRIMARY (shard-0) Ed25519 signer
phala ps "$CVM"                                 # find the container name (normally dstack-darknyx-tee-1)
phala logs dstack-darknyx-tee-1 --cvm-id "$CVM" --stderr -n 40
# Watch for proving key load, merkle cold-boot, "derived K-shard TEE signer set",
# and "settle pipeline ENABLED".
```

Under tree-sharding the CVM derives **K = `num_trees`** shard signers
(`darknyx/ed25519-signer/v2/{0..K-1}`), each the Solana fee-payer for its
shard's settle Tx D. `/info` surfaces only the primary; grab the full
set from the boot log line "derived K-shard TEE signer set". Register
ALL K in shard order (`keys[j]` settles shard j) + fund each
(one-time per CVM — they're deterministic per `app_id`):

```sh
SOLANA_RPC_URL="$HELIUS" ADMIN_KEYPAIR=.devnet/keypairs/admin.json \
  node scripts/rotate-tee-pubkey.mjs <key0> <key1> <key2> <key3>   # set the whole tee_pubkeys Vec
SOLANA_RPC_URL="$HELIUS" FUNDER_KEYPAIR=~/.config/solana/id.json \
  node scripts/fund-tee-keys.mjs <key0> <key1> <key2> <key3>       # tops each to FUND_TARGET_SOL (default 2)
# settle path needs SOL per shard for lock/verify/ALT/settle/close
```

### 3.4 Run the flagship + the loadgen

```sh
# cvm-settle-e2e: deposit 2 real notes → POST a crossing bid+ask → the CVM
# matches AND settles on devnet → assert leaf_count grows +5 (note_c/d +
# buyer change + base+quote fee notes). Needs the REAL-MINT regime.
# Run ONE leaf-count cvm test per fresh tree — see the note below.
(
  cd packages/sdk
  RUN_CVM_E2E=1 DARKNYX_TEE_GATEWAY="$GW" SOLANA_RPC_URL="$HELIUS" \
    FUNDER_KEYPAIR="$HOME/.config/solana/id.json" \
    ADMIN_KEYPAIR=.devnet/keypairs/admin.json \
    ../../node_modules/.bin/vitest run --project cvm tests/cvm-settle-e2e.test.ts
)

# loadgen: intake throughput + matcher paging (≤16/batch). Needs the
# PLACEHOLDER-MINT regime. Synthetic orders carry stub proofs, so their
# settles fail gracefully (and under a flood you'll see Helius 429s — an RPC
# capacity limit, not a code bug). Validates intake + paging, NOT settle.
RAW=$(curl -s "https://hermes.pyth.network/v2/updates/price/latest?ids[]=ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d" | jq -r '.parsed[0].price.price')
cargo run -q -p darknyx-tee-loadgen -- --endpoint "$GW" --oracle-twap "$RAW" \
  --fee-rate-bps 30 --traders 10 --duration-secs 25
```

> **Run each leaf-count cvm test ONE AT A TIME against a freshly-reset tree — do
> NOT `vitest run --project cvm` the whole bucket.** Every leaf-count test
> (`cvm-settle-e2e`, `cvm-multimatch-settle`, `cvm-self-trade`,
> `cvm-merge-then-order`) deposits into the single shared on-chain tree and
> asserts an absolute `leaf_count` from an EMPTY start, so the 2nd test in a run
> fails the empty-start check (by design). And the CVM Merkle mirror is
> append-only — it can't rewind — so a fresh tree needs a reset **+ a CVM
> cold-boot** (env-only `phala deploy` restart), not just a reset. The loop is:
> reset tree → env-only redeploy → run ONE test file → repeat. The `cvm` vitest
> project is pinned `fileParallelism: false` (`packages/sdk/vitest.config.ts`) so
> a bucket run fails deterministically (with the "reset first" message) instead
> of racing. Only the non-leaf tests (`cvm-api-surface`, `cvm-attestation-e2e`)
> are reset-free. Full workflow: **[`docs/cvm-run-runbook.md`](docs/cvm-run-runbook.md) §5**.

### 3.5 STOP THE CVM when done — **CPU CVMs ONLY**

It bills while running. `phala cvms stop "$CVM"` (preserves
`app_id`/signer/volume; halts billing). **Never leave a billable CPU CVM up.**

> 🛑 **NEVER stop an on-demand GPU CVM.** GPU instances (`h200.*`,
> `dstack-nvidia-*`, `resource.gpus >= 1`) are provisioned as a **fixed-duration
> window billed in full up front**, and **stopping DEALLOCATES the instance
> permanently** — it disappears from `phala cvms list`, the GPU returns to the
> pool, and every remaining prepaid hour is forfeited. There is no restart. This
> cost most of a paid 24 h H200 window on 2026-07-21 by applying the CPU rule
> above. Idle time inside a prepaid GPU window is free; destroying it is not.
>
> **Check before stopping anything:**
> `phala cvms get <app_id> --json | grep -E '"instance_type"|"gpus"'`
> GPU ⇒ leave it running and plan the whole window's work up front. See
> **[`docs/gpu-tee-runbook.md`](docs/gpu-tee-runbook.md)**.

After the test window, also `unset DARKNYX_TEE_API_KEY DARKNYX_TEE_API_SECRET
DARKNYX_TEE_PASSPHRASE`. The no-CVM half of devnet validation:
`devnet-deposit-withdraw.test.ts`
(`RUN_DEVNET_DW=1`) verifies the v2 deposit + VALID_SPEND withdraw round-trip
on devnet in isolation — no CVM, no TEE authority. Use it to test vault
crypto changes cheaply before spending on a CVM.

---

## 4. TEE development workflow — iterate / spot-check / ceremony

TEE work runs across three targets; using the wrong one wastes money or trust.

| Slice | Where | Cost/cycle | Validates |
|---|---|---|---|
| **Iterate** (~90%) | `darknyx-tee` binary + `dstack-simulator` locally | ~5–15 s | handler logic, matcher tick, oracle parsing, HTTP shape, key determinism |
| **Spot-check** (~5%) | Phala devnet CVM | ~3 min, ~$0.003 | real `compose_hash`, real dstack-kms key delivery, gateway latency, RA-HTTPS |
| **Ceremony** (~5%) | Phala CVM + multisig | ~10 min | real Intel TCB sig, MRTD vs governance set, client `verifyTeeAttestation()`, rotation |

* **Iterate locally** for handler/matcher/oracle/OpenAPI changes. The
  simulator (`dstack/sdk/simulator/dstack-simulator`) exposes the same
  Unix-socket API; `info()` + `get_key()` are byte-identical, `get_quote()`
  returns a well-formed but **stub-signed** quote. Real TCB verification
  (`dcap-qvl`, the SDK's `verifyTeeAttestation()`) **fails** against
  simulator quotes by design — that's the lever that keeps the dev loop
  fast without letting a stub attestation fool a client.
* **Spot-check on Phala** before a PR that touches the boot path
  (`src/boot.rs`, `src/keys/`), the dstack handshake, or the HTTP/WS surface.
* **Ceremony** only when `compose_hash` meaningfully changed (Dockerfile,
  compose, `Cargo.toml`, `crates/darknyx-tee/src/`).

`crates/darknyx-tee` has ~180 lib + integration tests (`cargo test -p darknyx-tee`)
covering the matcher / settle pipeline / continuation derivation / Merkle mirror /
HTTP+auth / RPC client — run them on any `crates/darknyx-tee` change.

---

## 5. Touching circuits — the failure mode that's bitten us

> A colleague changed circuit code and broke the deployed program. This
> section exists so it doesn't recur.

### 5.1 The chain that must stay consistent

```
circuits/<name>/circuit.circom                       ← source
        │  scripts/build-circuits.sh
        ▼
circuits/build/<name>/circuit.wasm                   ← witness gen (TS prover)
circuits/build/<name>/circuit_final.zkey             ← proving key
circuits/build/<name>/verification_key.json
        │  scripts/parse-vk-to-rust.js
        ▼
programs/vault/src/zk/vk_<name>.rs                   ← Rust VK consts in the verifier
```

Change `circuit.circom` and DON'T regenerate `vk_<name>.rs` → the program
compiles fine but rejects every proof the new circuit makes, surfacing at
runtime as `InvalidProof (6000)`, not at `cargo build`.

### 5.2 The rule

If you touch ANY of: `circuits/<name>/circuit.circom`,
`circuits/templates/*.circom`, `crates/darkpool-crypto/src/poseidon.rs`
(arity / constants / absorb order), or the leaf-hash construction in
`tee_forced_settle_batched.rs::compute_match_leaf` (must stay in lockstep
with the circuit's `MatchSlot()` template + `match-batch-prover.ts::computeBatchLeaf`)
— in the **same commit**:

1. `bash scripts/build-circuits.sh` (regenerate `.zkey` + `.wasm` + `vk_*.rs`).
2. `cargo build-sbf --manifest-path programs/vault/Cargo.toml --features devnet-admin`.
3. Pass all four:
   - `cargo test --workspace`
   - `cargo test -p vault --test zk_roundtrip --test zk_spend_roundtrip`
   - `cargo test -p vault --test tee_forced_settle_batched --test match_batch_verify` (depend on `compute_match_leaf` byte-stability + the committed N=16 proof fixture)
   - `vitest run --root packages/sdk tests/valid-*-prover.test.ts tests/match-batch-prototype.test.ts`
4. Commit `circuit.circom` + `circuit_final.zkey` + `vk_*.rs` together.
5. After merge: `deploy-devnet.sh` and reset the tree. If the changed circuit
   is TEE-proved (`match_batch_*`), also redeploy the CVM image (the matcher
   embeds that proving key) and validate via `cvm-settle-e2e`. Client-only
   circuits such as VALID_DEPOSIT use the no-CVM devnet deposit/withdraw gate.

### 5.3 Specific traps

* **Leaf-hash arity cap.** `light-poseidon` (on-chain) caps Poseidon at 12
  inputs (`MAX_X5_LEN = 13`). The leaf is a **single `Poseidon11`** —
  `Poseidon11(DOMAIN_LEAF_V2=23, active, note_a..note_f, note_fee_base,
  note_fee_quote, batch_slot)` — **commitment-only** (amount-privacy P1b): the
  six note commitments + two fee notes bind the amounts/mints/price
  transitively, so the leaf no longer hashes plaintext amounts. 11 inputs ≤ 12,
  so no split is needed. **Keep it ≤ 12** — re-introducing bound fields (e.g.
  plaintext amounts) would force the old two-stage Poseidon12+Poseidon9 split
  back (that's why it used to be two-stage).
* **Domain tags.** `DOMAIN_LEAF_V2 = 23` (the active leaf tag),
  `DOMAIN_MATCH_OUTPUT_INNER = 24`, `DOMAIN_MATCH_FEE_INNER = 25`,
  `DOMAIN_DEPOSIT_INNER = 27`, `DOMAIN_MATCH_CONFIG = 28`,
  `DOMAIN_BATCH_ROOT = 22`, `DOMAIN_NOTE = 2`, `DOMAIN_NULL = 3` — each
  appears in Rust + TS + circom; keep them in lockstep. (`DOMAIN_LEAF_INNER =
  20` / `DOMAIN_LEAF_TOP = 21` are the **retired** two-stage-leaf tags — dead
  constants, no longer hashed.)
* **Parameterised N.** `MatchBatch(N)` is instantiated at N=2/4/16. Only
  N=16 is wired on-chain (`vk_match_batch_n16.rs`); N=2/4 are dev/test. The
  N=16 proving key needs `pot18` (~288 MB) — don't edit `download-ptau.sh`
  to skip it.
* **The committed N=16 proof fixture** lives at
  `programs/vault/tests/fixtures/match_batch_n16_proof.bin`; regenerate it
  with `RUN_N16_PROVE=1 DUMP_N16_FIXTURE=1 cargo test -p darknyx-tee --test
  n16_assemble_prove_verify` after any circuit/converter change, then re-run
  `cargo test -p vault --test match_batch_verify`.

---

## 6. The 1232-byte transaction-size budget

Solana caps a tx at 1232 bytes. The settle path is right at the edge:

| Tx | ~Size | Headroom |
|---|---|---|
| lock_note buyer/seller (two Tx A) | <800 B each | >430 B each |
| verify_match_batch (Tx B) | ~640 B | comfortable |
| per-batch ALT create+extend (Tx C) | ~250 B | comfortable |
| tee_forced_settle_batched (Tx D, v0 + 2 ALTs) | **1109 B** | **123 B** |
| close_batch_validity_marker (Tx E) | ~250 B | comfortable |

Anything that adds bytes to the settle path — a new account, an extra ix
param, a longer payload field — risks the cap.

* **Read `CRYPTOGRAPHY.md` §9 before changing any settle ix's accounts/data.**
* **Static accounts go in the settle ALT** (created at devnet-setup,
  `.devnet/e2e-config.json::settleLookupTable`): `vault_config`,
  `instructions_sysvar`, `system_program`.
* **Per-batch ALT** holds the 7 PDAs derivable from the payload
  (`note_lock_a/b/e/f` + `consumed_a/b` + `batch_validity_marker`). The CVM
  settle worker builds a rolling pool of these (ALT deactivation has a ~512-slot
  cooldown).
* **`createLookupTable` `recentSlot`** must come from
  `getLatestBlockhashAndContext().context.slot`, NOT `getSlot("confirmed")`
  (which can return a leader-skipped slot → "is not a recent slot").
* **lock_note key dedup.** In exact-fill paths, `note_lock_e`/`note_lock_f`
  derive from `[0;32]` → same PDA → the encoder dedups to one slot (saves 32 B).
  The moment a change note is non-zero the dedup disappears and the tx grows —
  don't assume an exact-fill tx size generalises.

---

## 7. Cross-language byte-equality contracts

The most fragile invariant in the repo. **The SDK, the host crates, and the
on-chain code MUST agree byte-for-byte on every cryptographic primitive.**
Disagree and the TEE-signature check fails, or the batch-binding marker
check fails, or proofs don't verify.

### 7.1 What's pinned

| Contract | Rust | TS | Pinned by |
|---|---|---|---|
| Poseidon arities | `darkpool-crypto/src/poseidon.rs` | `sdk/src/zk/poseidon.ts` | `poseidon-parity.test.ts` |
| Note commitment (v2) | `darkpool-crypto/src/note.rs::commitment_from_fields_v2` | `sdk/src/utxo/note.ts::noteCommitmentV2` | `note-commitment-parity.test.ts` |
| Nullifier (v2) | `darkpool-crypto/src/nullifier.rs` | `sdk/src/utxo/note.ts::nullifierV2` | `nullifier-parity.test.ts` |
| Deposit inner | `darkpool-crypto/src/deposit.rs::deposit_inner_hash` | `sdk/src/utxo/deposit-inner.ts::deriveDepositInnerHash` | `deposit-inner-parity.test.ts` + `valid-deposit-prover.test.ts` |
| `inner_hash` (change/trade/fee) | `darkpool-matcher/src/change_note.rs::derive_inner` | `tests/helpers/e2e-helpers.ts::deriveInner` | `change-note-inner-parity.test.ts` + `inner-hash-parity.test.ts` |
| Key derivation | `darkpool-crypto/src/keys.rs` | `sdk/src/keys/key-generators.ts` | `keys-parity.test.ts` |
| User commitment | `darkpool-crypto/src/user_commitment.rs` | `sdk/src/keys/user-commitment.ts` | `user-commitment-parity.test.ts` |
| Merge output inner | `darkpool-crypto/src/merge.rs::merge_output_inner_hash` | `sdk/src/utxo/merge.ts::deriveMergeOutputInnerHash` | `merge-inner-parity.test.ts` + `merge-prover.test.ts` |
| Order/cancel canonical | `darkpool-matcher/src/order_canonical.rs` | `sdk/src/orders/canonical.ts` | `order-canonical-parity.test.ts` |
| Canonical payload hash | `vault::tee_forced_settle.rs::canonical_payload_hash` (shared) + `darknyx-tee/src/settle/payload.rs` | `sdk/src/settlement/settle-builder.ts::canonicalPayloadHash` | Rust fixed-vector unit + `settle-builder-batched.test.ts` |
| Match leaf hash | `tee_forced_settle_batched.rs::compute_match_leaf` | `tests/helpers/match-batch-prover.ts::computeBatchLeaf` | `match-batch-prototype.test.ts` leaf-byte assert |
| Anchor discriminator | Anchor macro `sha256("global:<name>")[..8]` | `sdk/src/idl/vault-client.ts` | every `*-transport.test.ts` |

**Change a hash arity / domain tag / field order in ONE language → change
both, then re-run the parity test.** A Rust-only change fails the parity
test; a TS-only change fails on devnet with `InvalidProof`/`InvalidBatchBinding`.

### 7.2 BN254 Fr safety (the silent killer)

Every value Poseidon-hashes MUST fit in BN254 Fr (be < the modulus). Raw
`[0xFFu8; 32]` passes through almost everything WITHOUT an obvious error,
but `light-poseidon`'s `hash_bytes_be` rejects values ≥ the modulus →
`PoseidonFailed (6030)` / `InvalidBatchBinding`.

* **Test fixtures fed to Poseidon must be Fr-safe** — use `fr_safe(seed, salt)`
  (in the test harnesses) for any hashed 32-byte field.
* **Mint pubkeys split into two 128-bit halves** (`pubkey_to_fr_pair`) — a
  256-bit pubkey can't fit one Fr element.
* **Owner commitments + nullifiers are Poseidon outputs** → Fr-safe by
  construction. Intake Fr-validates the order's consumed input `inner_hash`.
  Match/merge output inners are Poseidon-derived. The nullifier is used by the withdraw path;
  payload v9 removed it from Tx D because settlement replay protection is
  commitment-keyed.

---

## 8. Marker / PDA lifecycle conventions

### 8.1 Per-leaf PDAs are the replay-protection backbone

Durable note transitions use PDAs whose existence locks out replay:
`WalletEntry` registers a user commitment, `DepositedNoteEntry` prevents an
exact commitment from being deposited twice, `ConsumedNoteEntry` is the shared
withdraw/settle/merge consume-once guard, and `NoteLock` pins an input between
match and settlement. **The `init` constraint is the replay guard — don't
change it to `init_if_needed` without thinking about replay.**

### 8.2 `BatchValidityMarker` is 1:N. Do NOT close it per-match.

`verify_match_batch` writes ONE `BatchValidityMarker` (seeded by the batch
Merkle root) covering all N matches in the batch. `tee_forced_settle_batched`
**must leave it open and read-only**; a separate
`close_batch_validity_marker` ix reclaims the rent once, only at or after
expiry. No signer—including the recorded payer—has an early-close path.

If a Tx D builder marks `batch_validity_marker` writable, or you see
`try_borrow_mut_lamports` against it in `tee_forced_settle_batched.rs`, you've
re-introduced a cross-shard write conflict or the bug that bricks every match
after the first. The regression test
`vault/tests/tee_forced_settle_batched.rs::test_two_matches_share_one_marker`
catches it — keep it passing.

### 8.3 SDK seed constants are wire-mirrored from Rust

`packages/sdk/src/idl/seeds.ts` hand-mirrors every `SEED` literal in
`programs/vault/src/state.rs`. Add a PDA in Rust → add the seed const to
`seeds.ts` AND a `xxxPda()` helper to `vault-client.ts`. CI doesn't catch
this — only the integration tests do, with `AccountNotFound` /
`ConstraintSeeds (2006)`.

---

## 9. Common pitfalls + failure signatures

| You did | Surface | Fix |
|---|---|---|
| Committed without `cargo fmt` | pr-checks `rust` fails at `cargo fmt -- --check` | `cargo fmt --all`, commit the diff |
| Deleted a `vault/tests/<name>.rs` | pr-checks `cargo test -p vault --test <name>` → `no test target named '<name>'` | grep the workflow YAMLs for the basename, fix in the same commit (§2.6) |
| Deleted a circom circuit | pr-checks `circuits` → `Input file does not exist` | update BOTH `build-circuits.sh` + `ci-build-circuits.sh` (separate hard-coded lists) |
| Changed a Poseidon arity / domain tag in one language | parity test fails / devnet `InvalidProof` | mirror in the other language, re-run the parity test |
| Changed a circom circuit | devnet `InvalidProof (6000)` | regenerate `.zkey` + `vk_*.rs` same commit; redeploy; reset tree |
| Bumped `MatchResultPayload` field order | `canonical_payload_hash_fixed_vector` fails | mirror in TS `serializePayload` + recompute the fixed vector |
| Added a vault PDA without the SDK | integration test `AccountNotFound` / `ConstraintSeeds` | add the SEED + `xxxPda()` to the SDK; update every `build*Ix` (§8.3) |
| Added an account to a settle ix without the ALT | `TransactionTooLarge` | add it to the static ALT (re-run devnet-setup) or the per-batch ALT (§6) |
| Raw `[0xA0u8; 32]` for a Poseidon-hashed field | `PoseidonFailed (6030)` / `InvalidBatchBinding` | `fr_safe(seed, salt)` or any Poseidon output (§7.2) |
| Forgot the tree reset after a wipe/migration | `StaleMerkleRoot (6004)` on first withdraw | §2.4 |
| Loadgen run is 100% 4xx | CVM is in the wrong mint regime | match the regime: real mints for `cvm-settle-e2e`, omit mints for loadgen (§3.2) |
| `phala cvms start` on a code change | CVM runs stale code | bump the tag + `phala deploy` re-pulls (§3.1) |
| Closed `BatchValidityMarker` in the settle | `test_two_matches_share_one_marker` fails | §8.2 |

A longer error catalogue is in `scripts/dev-commands.md §10`.

---

## 10. Working with the SDK tests

`packages/sdk/tests/` naming:

* `*-parity.test.ts` — TS↔Rust byte equality (run on every crypto change).
* `*-prover.test.ts` — snarkjs round-trips (need built circuit artifacts).
* `*-transport.test.ts` / `*-builder.test.ts` — wire-format / discriminator / Borsh.
* `*-watcher.test.ts` — event decoding (`settlement-watcher` = vault `TradeSettled`).
* `settle-memo-integrity` — the v3 fill-memo integrity check (the Vuln-4
  guard): the client resolves the exact consumed input, derives
  `Poseidon3(24, input_inner, role)`, and rejects substituted inners or
  commitments.
* `helpers/` — `e2e-helpers.ts` (keypairs, `deriveInner`, byte conv),
  `merkle-shadow.ts`, `match-batch-prover.ts`, `valid-input-prover.ts`,
  `snarkjs-prover.ts`.
* env-gated devnet/CVM flows: `devnet-setup` (`RUN_DEVNET_E2E`),
  `devnet-deposit-withdraw` (`RUN_DEVNET_DW`), `devnet-merge` (`RUN_DEVNET_MERGE`),
  `devnet-leaf-index` (`RUN_DEVNET_LEAF` — drives the high-level
  `getDepositFunction`/`getMergeFunction` so the event-based leaf-index read in
  `utxo/leaf-index.ts` is exercised against real RPC), `cvm-settle-e2e`
  (`RUN_CVM_E2E`). Add new e2e scenarios alongside these using the existing harness.

---

## 11. Committing

Every commit uses `git commit -s` (adds `Signed-off-by` from `user.email`).
Do not add model, agent, or AI co-author trailers.

```
git commit -s ...
```

Subject: `<type>(<scope>): <imperative summary>`. Body: the **why** (the
constraint, prior incident, tradeoff), not the what. List the validation
commands you ran. Bullet concrete files/lines.

**Never commit:** `.devnet/keypairs/*.json`, `.devnet/e2e-config.json`, the
`-e` env / Helius key, anything under `target/` / `node_modules/` /
`circuits/build/` except `circuit_final.zkey`, or `verification_key.json`
(the canonical form is `vk_*.rs`). All gitignored — keep it that way.

**Ask the user before:** regenerating the program-id keypair; force-pushing
or rewriting history; running anything against mainnet (devnet-only for
now); loosening a CI gate; **deploying/starting a billable Phala CVM (stop
it after; never commit a secret).**

---

## 12. When in doubt

1. Touching anything ZK-adjacent → re-read [§5](#5-touching-circuits-the-failure-mode-thats-bitten-us).
2. Adding to a settle ix's accounts/data → re-read [§6](#6-the-1232-byte-transaction-size-budget).
3. Touching cryptography in either language → re-read [§7](#7-cross-language-byte-equality-contracts).
4. Touching markers / the settle handler → re-read [§8](#8-marker--pda-lifecycle-conventions).
5. Deploying/testing on a CVM → [§3](#3-the-phala-cvm--build--deploy--test) + stop it after.

> **Fee model.** Both legs pay their own protocol fee and BOTH fee notes
> (base + quote) mint. Each order locks `nominal + its own fee` collateral —
> intake derives this (`orders.rs`); the loadgen + e2e harness mirror it — or
> the matcher rejects the match as conservation-breaking. The CVM fee rate is
> `DARKNYX_TEE_FEE_RATE_BPS` (default 30); fees-on without
> `DARKNYX_TEE_PROTOCOL_OWNER_COMMITMENT` warns (unclaimable).

> **On-chain governance config.** Global authority and fee state lives in
> `VaultConfig`: `fee_rate_bps` (an exact fee
> enforced IN-CIRCUIT by VALID_MATCH_BATCH — it is bound through the public
> config digest recomputed by `verify_match_batch`; `tee_forced_settle_batched` no longer re-derives it
> from plaintext amounts, which is what let those amounts leave the payload
> (amount-privacy P1b). NOT vestigial; the C-04 audit fix tightens the circuit
> constraint from a floor to an EXACT fee) and `protocol_owner_commitment`, set
> through `set_protocol_config`. Mint-pair identity, mint decimals,
> `price_scale`, tick, minimum size, circuit-breaker bounds, and the trading kill
> switch live in the `[b"market_config", base_mint, quote_mint]` `MarketConfig`
> PDA, initialized and updated by the operations admin. The TEE reads both
> accounts at boot and refuses an explicitly disabled market. The daemon
> refreshes finalized TEE keys every minute and pauses placement on mismatch or
> stale attestation state. Keep the
> Rust/TypeScript account parsers and instruction builders byte-identical to the
> on-chain layouts; a `VaultConfig` layout change requires a clean devnet
> re-foundation (`close_vault_config` → `initialize`).

> **Temporary private-repo validation policy (2026-07).** Organization artifact
> quota and private CodeRabbit review are unavailable. Run the reasonable
> `.github/workflows/pr-checks.yml` equivalents locally before merging; do not
> wait for, poll, or treat missing GitHub checks/CodeRabbit reviews as a blocker.
> Resume those hosted gates only after the owner restores the plans.

---

*Last updated: 2026-07-16 — current architecture: vault (only on-chain
program) + the in-CVM matcher/settler (`crates/darknyx-tee`) on Phala, validated
end-to-end on devnet (`cvm-settle-e2e` real settle + loadgen). The
`matching_engine` / MagicBlock-ER / PER path has been removed. Note model is
v2 `inner_hash`; canonical orders sign the viewing key, boot session, and a
strictly increasing per-trading-key nonce. Output inners derive from consumed
input inners, with no continuation anchor pool.*
