# CLAUDE.md — agent onboarding for Nyx Darkpool

> This file is the contract between you (the agent) and the project.
> Read it before touching code. It also doubles as `AGENTS.md`.
>
> If you only read one section, read **[§2 — the build/validate
> cycle](#2-the-buildvalidate-cycle)** and **[§3 — the Phala CVM:
> build → deploy → test](#3-the-phala-cvm--build--deploy--test)**.

---

## 0. What this repo is, in 60 seconds

Nyx (aka **darknyx**) is a privacy-preserving CLOB-style darkpool on
Solana. Matching and settlement run **inside an Intel TDX confidential
VM (a "CVM") on Phala Cloud**. Three layers:

* **L1 (Solana)** — `programs/vault/` is the only on-chain program
  (Anchor 0.32). It owns custody, the incremental Merkle tree of note
  commitments, the nullifier / consumed-note sets, the Groth16 verifier,
  and the **atomic batched settlement** path
  (`lock_note → verify_match_batch → tee_forced_settle_batched →
  close_batch_validity_marker`, N=16 matches per batch). Devnet program
  id: `C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx`.
* **TEE (`crates/nyx-tee/`)** — the in-enclave engine. It owns hidden
  order intake (`POST /orders`), uniform-clearing-price matching, the
  full settle pipeline (lock → prove N=16 VALID_MATCH_BATCH → verify →
  per-batch ALT → `tee_forced_settle_batched` → close, signed by its
  dstack-derived Ed25519 key), a Merkle-mirror indexer, the per-order
  continuation **anchor pool**, and the auth'd HTTP/WS surface. Order
  intent never touches an L1 tx; the enclave drives the vault settle ixs
  directly.
* **Client (TypeScript SDK + snarkjs prover)** — `packages/sdk/` is the
  integration surface: clients build VALID_INPUT proofs and `POST`
  orders to the CVM. `crates/darkpool-crypto/` is the host-side Rust
  crypto crate with byte-identical Poseidon / nullifier / note / key
  derivation that the TS SDK has parity tests against.

Supporting crates: `crates/darkpool-matcher/` (the matching algorithm +
the order/cancel/anchor-topup canonical signing — single source of
truth, used by the in-TEE matcher) and `crates/nyx-tee-loadgen/` (a host
binary that load-tests the CVM's intake).

**The note model (v2 / `inner_hash`).** Every note commitment AND its
nullifier are anchored on a single amount-independent `inner_hash`:

```
commitment = Poseidon6(DOMAIN_NOTE, mint_lo, mint_hi, amount, owner_commitment, inner_hash)
nullifier  = Poseidon3(DOMAIN_NULL, spending_key, inner_hash)
```

Decoupling the nullifier from the (amount-dependent) commitment is what
lets a client **pre-supply** the nullifiers for its future change notes
(a 10-entry "anchor pool" submitted with each order), so the matcher can
settle partial-fill continuations — rotate the residual in place and
re-match it — without a per-fill client roundtrip.

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
  — the decided-but-unbuilt fills-delivery + trade-history design
  (deterministic HD order_ids + per-account WS + off-TEE indexer).

By domain, additionally:

| If you're touching | Read first |
|---|---|
| A circom circuit | `CRYPTOGRAPHY.md` §7, then the circuit + its `vk_*.rs` + its `*-prover.test.ts`. **See [§5](#5-touching-circuits-the-failure-mode-thats-bitten-us) — the disaster section.** |
| A `vault` instruction | `CRYPTOGRAPHY.md` §8, `programs/vault/src/state.rs` (PDA layout), the litesvm test in `programs/vault/tests/`. |
| `crates/darkpool-crypto` | The matching `*-parity.test.ts` under `packages/sdk/tests/`. **Every host-side primitive has a byte-equality contract with TS.** |
| `crates/darkpool-matcher` | `tests/parity.rs` + `change_note_parity.rs` + `order_canonical.rs`'s tests. The matcher's `run_batch`/`run_batch_capped` is the single source of truth. A change to `change_note::derive_inner` triggers a triple-port (matcher Rust ↔ TS in `e2e-helpers.ts` ↔ the on-chain hashers). |
| `crates/nyx-tee` (the in-TEE binary) | `docs/tee-architecture.md` (§11 auth model, §13 the iterate/spot-check/ceremony dev loop), `docs/tee-attestation-flow.md`, `docs/tee-api-openapi.yaml`. See [§4 of this file](#4-tee-development-workflow--iterate--spot-check--ceremony). |
| The SDK | The corresponding `tests/*-transport.test.ts` / parity test. `idl/vault-client.ts` hand-codes every discriminator + Borsh layout (no Anchor IDL runtime) — keep it in sync with the on-chain structs by hand. |
| Settlement plumbing | `CRYPTOGRAPHY.md` §9 (size analysis + ALT story). The 1232-byte cap is tight — see [§6](#6-the-1232-byte-transaction-size-budget). |

---

## 2. The build/validate cycle

Everything runs from the repo root.

### 2.1 One-time host setup

```sh
npm install                                        # SDK + snarkjs + circomlib
bash scripts/download-ptau.sh                      # pot16 (~80 MB) + pot18 (~288 MB)
bash scripts/build-circuits.sh                     # compile all 6 circom circuits;
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
cargo build-sbf --manifest-path programs/vault/Cargo.toml

# 2. Pre-commit gate (host-side)
cargo clippy --workspace --all-targets -- -D warnings   # MUST pass, zero warnings
cargo fmt --all -- --check
cargo test --workspace

# 3. Devnet upgrade (idempotent in place — keeps the same program id)
bash scripts/deploy-devnet.sh
```

`deploy-devnet.sh` uses your local `~/.config/solana/id.json` as upgrade
authority + fee payer (need ≥ 5 SOL on devnet). **Never regenerate the
program-id keypair** unless you mean to — `declare_id!()` in
`programs/vault/src/lib.rs` and `[programs.*]` in `Anchor.toml` must match,
and the `consistency` CI job fails if they diverge.

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
cargo build-sbf --manifest-path programs/vault/Cargo.toml   # litesvm + deploy need it
cargo build --examples -p darkpool-crypto           # parity tests shell out to these
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace                              # unit + litesvm integration
./node_modules/.bin/tsc -p packages/sdk/tsconfig.json --noEmit
./node_modules/.bin/tsc -p packages/indexer/tsconfig.json --noEmit
( cd packages/sdk && ../../node_modules/.bin/vitest run )   # devnet/CVM tests auto-skip
( cd packages/indexer && ../../node_modules/.bin/vitest run ) # fills indexer; DB tests need Node 22+ (node:sqlite)
echo "ALL GREEN — safe to push"
```

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
settler**, so any change under `crates/nyx-tee/`, `Dockerfile`,
`deploy/docker-compose.yaml`, or the circuits requires a **rebuilt image**
— `phala cvms start` on the old image runs stale code.

The full step-by-step lives in `scripts/dev-commands.md §5–§7`; this is the
operational summary plus the gotchas that cost real time.

### 3.0 Tooling

The `phala` CLI is a Node binary; if a broken nvm shim shadows `node`,
invoke it (and `node`) by absolute path:
`/Users/<you>/.nvm/versions/node/<ver>/bin/{node,phala}`. `phala cvms list`
shows the CVM (`app_id`, name, status). `--cvm-id` accepts the `app_id`
form (`app_<id>`).

### 3.1 Build a new image (tag → CI → ghcr)

The `tee-image` GitHub workflow builds `linux/amd64` and pushes to
`ghcr.io/skysail-labs/nyx-tee:tee-v3-hardening-<N>` (registry-cached, ~4–5 min).
**Always bump the tag for a code change** — `phala deploy` only re-pulls on
a changed tag; a same-tag deploy reuses the cached image (you'd test stale
code).

```sh
# 1. bump the tag the compose pins:
#    deploy/docker-compose.yaml → image: ...nyx-tee:tee-v3-hardening-<N+1>
# 2. commit, then tag + push (the tag carries your commits):
git tag tee-v3-hardening-<N+1> && git push origin tee-v3-hardening-<N+1>
# 3. watch it (CI lives on skysail-labs/darknyx; origin redirects there):
gh run watch "$(gh run list --repo skysail-labs/darknyx --limit 1 --json databaseId -q '.[0].databaseId')" --repo skysail-labs/darknyx --exit-status
# 4. confirm it landed (want 200):
TOK=$(curl -s "https://ghcr.io/token?scope=repository:skysail-labs/nyx-tee:pull" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer $TOK" \
  -H "Accept: application/vnd.oci.image.index.v1+json" \
  "https://ghcr.io/v2/skysail-labs/nyx-tee/manifests/tee-v3-hardening-<N+1>"
```

### 3.2 The encrypted env (`-e` file) — and the REGIME you're deploying

`deploy/docker-compose.yaml` references secrets as `${VAR}`; `phala deploy
-e <file>` injects them as encrypted env (the value never enters the
`compose_hash`). Build the file fresh each deploy — the Helius key is a
secret: write it `umask 077`, **shred it after deploy, never commit it.**

> **⚠️ The two CVM regimes are mutually exclusive — this is the loadgen
> hiccup that wasted a deploy.** Whether you set the mint env vars decides
> which test the CVM can serve:
>
> * **Real-settle regime (`cvm-settle-e2e`)** — SET `NYX_TEE_BASE_MINT` +
>   `NYX_TEE_QUOTE_MINT` to the `.devnet/e2e-config.json` mints. Intake
>   re-derives each order's commitment against these, so real deposits
>   match.
> * **Loadgen regime (`nyx-tee-loadgen`)** — OMIT both mint vars. The CVM
>   falls back to `dev_match_config()` placeholder mints (`…0x9e` quote /
>   `…0xb1` base) that the loadgen hardcodes. **If you run the loadgen
>   against a real-mint CVM you get 100% 4xx** (commitment mismatch) — and
>   vice-versa. Switching is an env-only `phala deploy -e` (no rebuild).

```sh
umask 077
HELIUS="https://devnet.helius-rpc.com/?api-key=<key>"
BASE=$(jq -r .baseMint.pubkey  .devnet/e2e-config.json)
QUOTE=$(jq -r .quoteMint.pubkey .devnet/e2e-config.json)
ALT=$(jq -r .settleLookupTable  .devnet/e2e-config.json)
OWNER=$(jq -r .protocol.ownerCommitmentHex .devnet/e2e-config.json)
node scripts/reset-merkle-tree.mjs   # FIRST — so the mirror cold-boots an empty tree
FLOOR=$(solana slot --url "$HELIUS")
cat > /tmp/nyx.env <<EOF
NYX_TEE_SOLANA_RPC_URL=$HELIUS
NYX_TEE_SYNC_FROM_SLOT=$FLOOR
NYX_TEE_BASE_MINT=$BASE          # OMIT these two lines for the loadgen regime
NYX_TEE_QUOTE_MINT=$QUOTE
NYX_TEE_SETTLE_LOOKUP_TABLE=$ALT
NYX_TEE_FEE_RATE_BPS=30
NYX_TEE_PROTOCOL_OWNER_COMMITMENT=$OWNER
EOF
```

A **malformed** (non-empty) value fails startup (fail-fast); an **empty**
`${VAR}` falls back to the default. `NYX_TEE_FEE_RATE_BPS` (default 30) must
equal the loadgen's `--fee-rate-bps` (intake derives fee-inclusive
collateral; a mismatch → every synthetic note fails `verify_commitment`).

### 3.3 Deploy + rotate the signer + fund it

```sh
CVM=app_634b2ab4c250466311f0cf09f772b6fd60b5be11   # phala cvms list
phala deploy --cvm-id "$CVM" -c deploy/docker-compose.yaml -e /tmp/nyx.env --wait
shred -u /tmp/nyx.env

GW="https://<app_id>-8080.dstack-pha-prod5.phala.network"
curl -s "$GW/info" | jq -r .tee_pubkey          # the enclave's Ed25519 signer
phala cvms logs "$CVM" | tail -40               # watch boot: proving key load, merkle cold-boot, "settle pipeline ENABLED"
```

The CVM signer is **also the Solana fee-payer** for settle txs. Rotate the
vault's `tee_pubkey` to it + fund it (one-time per CVM signer):

```sh
SOLANA_RPC_URL="$HELIUS" ADMIN_KEYPAIR=.devnet/keypairs/admin.json \
  node scripts/rotate-tee-pubkey.mjs <tee_pubkey_from_/info>
solana transfer <tee_pubkey> 2 --url "$HELIUS" --allow-unfunded-recipient \
  --keypair ~/.config/solana/id.json     # settle path needs SOL for lock/verify/ALT/settle/close
```

### 3.4 Run the flagship + the loadgen

```sh
# cvm-settle-e2e: deposit 2 real notes → POST a crossing bid+ask → the CVM
# matches AND settles on devnet → assert leaf_count grows +5 (note_c/d +
# buyer change + base+quote fee notes). Needs the REAL-MINT regime.
RUN_CVM_E2E=1 NYX_TEE_GATEWAY="$GW" SOLANA_RPC_URL="$HELIUS" \
  FUNDER_KEYPAIR=~/.config/solana/id.json ADMIN_KEYPAIR=.devnet/keypairs/admin.json \
  ( cd packages/sdk && ../../node_modules/.bin/vitest run tests/cvm-settle-e2e.test.ts )

# loadgen: intake throughput + matcher paging (≤16/batch). Needs the
# PLACEHOLDER-MINT regime. Synthetic orders carry stub proofs, so their
# settles fail gracefully (and under a flood you'll see Helius 429s — an RPC
# capacity limit, not a code bug). Validates intake + paging, NOT settle.
RAW=$(curl -s "https://hermes.pyth.network/v2/updates/price/latest?ids[]=ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d" | jq -r '.parsed[0].price.price')
cargo run -q -p nyx-tee-loadgen -- --endpoint "$GW" --oracle-twap "$RAW" \
  --fee-rate-bps 30 --traders 10 --duration-secs 25
```

### 3.5 STOP THE CVM when done

It bills while running. `phala cvms stop "$CVM"` (preserves
`app_id`/signer/volume; halts billing). **Never leave a billable CVM up.**

The no-CVM half of devnet validation: `devnet-deposit-withdraw.test.ts`
(`RUN_DEVNET_DW=1`) verifies the v2 deposit + VALID_SPEND withdraw round-trip
on devnet in isolation — no CVM, no TEE authority. Use it to test vault
crypto changes cheaply before spending on a CVM.

---

## 4. TEE development workflow — iterate / spot-check / ceremony

TEE work runs across three targets; using the wrong one wastes money or trust.

| Slice | Where | Cost/cycle | Validates |
|---|---|---|---|
| **Iterate** (~90%) | `nyx-tee` binary + `dstack-simulator` locally | ~5–15 s | handler logic, matcher tick, oracle parsing, HTTP shape, key determinism |
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
  compose, `Cargo.toml`, `crates/nyx-tee/src/`).

`crates/nyx-tee` has ~180 lib + integration tests (`cargo test -p nyx-tee`)
covering the matcher / settle pipeline / anchor pool / Merkle mirror /
HTTP+auth / RPC client — run them on any `crates/nyx-tee` change.

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
2. `cargo build-sbf --manifest-path programs/vault/Cargo.toml`.
3. Pass all four:
   - `cargo test --workspace`
   - `cargo test -p vault --test zk_roundtrip --test zk_spend_roundtrip`
   - `cargo test -p vault --test tee_forced_settle_batched --test match_batch_verify` (depend on `compute_match_leaf` byte-stability + the committed N=16 proof fixture)
   - `vitest run --root packages/sdk tests/valid-*-prover.test.ts tests/match-batch-prototype.test.ts`
4. Commit `circuit.circom` + `circuit_final.zkey` + `vk_*.rs` together.
5. After merge: `deploy-devnet.sh`, reset the tree, redeploy the CVM image
   (the matcher embeds the proving key), validate via `cvm-settle-e2e`.

### 5.3 Specific traps

* **Leaf-hash arity cap.** `light-poseidon` (on-chain) caps Poseidon at 12
  inputs (`MAX_X5_LEN = 13`). The leaf hash uses **two stages** (Poseidon12
  + Poseidon9) for exactly this. Don't refactor to one big Poseidon.
* **Domain tags.** `DOMAIN_LEAF_INNER = 20`, `DOMAIN_LEAF_TOP = 21`,
  `DOMAIN_BATCH_ROOT = 22`, `DOMAIN_NOTE = 2`, `DOMAIN_NULL = 3` — each
  appears in Rust + TS + circom; keep them in lockstep.
* **Parameterised N.** `MatchBatch(N)` is instantiated at N=2/4/16. Only
  N=16 is wired on-chain (`vk_match_batch_n16.rs`); N=2/4 are dev/test. The
  N=16 proving key needs `pot18` (~288 MB) — don't edit `download-ptau.sh`
  to skip it.
* **The committed N=16 proof fixture** lives at
  `programs/vault/tests/fixtures/match_batch_n16_proof.bin`; regenerate it
  with `RUN_N16_PROVE=1 DUMP_N16_FIXTURE=1 cargo test -p nyx-tee --test
  n16_assemble_prove_verify` after any circuit/converter change, then re-run
  `cargo test -p vault --test match_batch_verify`.

---

## 6. The 1232-byte transaction-size budget

Solana caps a tx at 1232 bytes. The settle path is right at the edge:

| Tx | ~Size | Headroom |
|---|---|---|
| lock_note ×2 (Tx A) | ~1050 B | ~180 B |
| verify_match_batch (Tx B) | ~640 B | comfortable |
| per-batch ALT create+extend (Tx C) | ~250 B | comfortable |
| tee_forced_settle_batched (Tx D, v0 + 2 ALTs) | ~1130 B | **~100 B** |
| close_batch_validity_marker (Tx E) | ~250 B | comfortable |

Anything that adds bytes to the settle path — a new account, an extra ix
param, a longer payload field — risks the cap.

* **Read `CRYPTOGRAPHY.md` §9 before changing any settle ix's accounts/data.**
* **Static accounts go in the settle ALT** (created at devnet-setup,
  `.devnet/e2e-config.json::settleLookupTable`): `vault_config`,
  `instructions_sysvar`, `system_program`.
* **Per-batch ALT** holds the 5 PDAs derivable from the payload
  (`note_lock_a/b/e/f` + `batch_validity_marker`). The CVM settle worker
  builds a rolling pool of these (ALT deactivation has a ~512-slot cooldown).
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
| `inner_hash` (change/trade/fee) | `darkpool-matcher/src/change_note.rs::derive_inner` | `tests/helpers/e2e-helpers.ts::deriveInner` | `change-note-inner-parity.test.ts` + `inner-hash-parity.test.ts` |
| Key derivation | `darkpool-crypto/src/keys.rs` | `sdk/src/keys/key-generators.ts` | `keys-parity.test.ts` |
| User commitment | `darkpool-crypto/src/user_commitment.rs` | `sdk/src/keys/user-commitment.ts` | `user-commitment-parity.test.ts` |
| Order/cancel/topup canonical | `darkpool-matcher/src/order_canonical.rs` | `sdk/src/orders/canonical.ts` | `order-canonical-parity.test.ts` |
| Canonical payload hash | `vault::tee_forced_settle.rs::canonical_payload_hash` (shared) + `nyx-tee/src/settle/payload.rs` | `sdk/src/settlement/settle-builder.ts::canonicalPayloadHash` | Rust fixed-vector unit + `settle-builder-batched.test.ts` |
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
  construction. Intake Fr-validates the order's `inner_hash` + every anchor
  `inner_hash` (they're hashed); the nullifier is NOT hashed by the TEE (it's
  a PDA seed + a SHA-256 payload field) so it's only length-checked.

---

## 8. Marker / PDA lifecycle conventions

### 8.1 Per-leaf PDAs are the replay-protection backbone

Every touched note produces a PDA whose existence locks out a second touch:
`WalletEntry` (registered user commitment), `NullifierEntry` (VALID_SPEND
consume), `ConsumedNoteEntry` (TEE-settle consume), `NoteLock` (the pin
between match and settle). **The `init` constraint is the replay guard —
don't change it to `init_if_needed` without thinking about replay.**

### 8.2 `BatchValidityMarker` is 1:N. Do NOT close it per-match.

`verify_match_batch` writes ONE `BatchValidityMarker` (seeded by the batch
Merkle root) covering all N matches in the batch. `tee_forced_settle_batched`
**must leave it open**; a separate `close_batch_validity_marker` ix reclaims
the rent once, after all matches settle.

If you see `try_borrow_mut_lamports` against `batch_validity_marker` in
`tee_forced_settle_batched.rs`, you've re-introduced the bug that bricks
every match after the first. The regression test
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
* `anchor-pool-build` / `settle-memo-integrity` — the v2 client anchor-pool +
  fill-memo integrity check (the Vuln-4 guard: the client recomputes the
  change-note commitment from the memo's `inner_hash` and rejects a TEE that
  substituted one).
* `helpers/` — `e2e-helpers.ts` (keypairs, `deriveInner`, byte conv),
  `merkle-shadow.ts`, `match-batch-prover.ts`, `valid-input-prover.ts`,
  `snarkjs-prover.ts`.
* env-gated devnet/CVM flows: `devnet-setup` (`RUN_DEVNET_E2E`),
  `devnet-deposit-withdraw` (`RUN_DEVNET_DW`), `cvm-settle-e2e` (`RUN_CVM_E2E`).
  Add new e2e scenarios alongside these using the existing harness.

---

## 11. Committing

Every commit uses `git commit -s` (adds `Signed-off-by` from `user.email`),
then amend the AI co-author trailer:

```
git commit -s ...
git commit --amend --no-edit --trailer "Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
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
> `NYX_TEE_FEE_RATE_BPS` (default 30); fees-on without
> `NYX_TEE_PROTOCOL_OWNER_COMMITMENT` warns (unclaimable). `VaultConfig.fee_rate_bps`
> is vestigial for the TEE settle path.

> **CodeRabbit** reviews via `.coderabbit.yaml` (path instructions encode the
> §5/§6/§7/§8 invariants). Treat its findings like any review — verify each
> against the code before acting.

---

*Last updated: 2026-06-04 — current architecture: vault (only on-chain
program) + the in-CVM matcher/settler (`crates/nyx-tee`) on Phala, validated
end-to-end on devnet (`cvm-settle-e2e` real settle + loadgen). The
`matching_engine` / MagicBlock-ER / PER path has been removed. Note model is
v2 `inner_hash` with the per-order continuation anchor pool.*
