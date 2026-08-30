# GPU-TEE Runbook — ICICLE CUDA prover on a Phala H200 (Phase 2a perf + 2b attestation)

> ## ✅ Status (2026-07-21): the correctness GO/NO-GO **PASSED** on a real H200.
>
> A CUDA-produced Groth16 proof was **verified ON-CHAIN** by `verify_match_batch`
> against the committed `vk_match_batch_n16` (`cvm-settle-e2e` green, `device=CUDA`,
> image `tee-v3-hardening-68-cuda`, `h200.small` / node `gpu-use1`). **GPU proving is
> correctness-validated — that question is closed and needs no further GPU time.**
>
> **⚠️ No valid performance number yet.** See [§10](#10-session-log-2026-07-21--results-and-what-is-still-open).
> Do not quote a speedup from that session.
>
> **🛑 The previous version of this doc said "STOP the CVM at the end". That advice
> destroyed most of a prepaid 24 h window. See [§7](#7-do-not-stop-the-cvm--on-demand-gpu-windows-are-forfeited).**
>
> This is the GPU analogue of [`docs/cvm-run-runbook.md`](cvm-run-runbook.md). The CPU/rapidsnark
> CVM flow is unchanged and unaffected — keep using it (see the last section).

---

## 0. What is already done (no re-work needed)

The whole CUDA build + packaging track is committed on `revamp_proving` and **CI-validated with no
GPU** (commit `0400776` + the `git`/`libatomic1` fixups):

- **ICICLE backend** wired as a third prover (`DARKNYX_TEE_PROVER=icicle`, device via
  `DARKNYX_TEE_ICICLE_DEVICE`). CPU byte-parity already proven (Phase 1, commit `4c9558c`).
- **CUDA image** — the last validated image is
  `ghcr.io/skysail-labs/darknyx-tee:tee-v3-hardening-68-cuda`; the
  observability-ready candidate is `tee-v3-hardening-69-cuda` and must pass the
  image-build check before the next allocation,
  and is the image that passed the first real H200 settle (2026-07-21). The 3 backend `.so` ship
  under `/opt/icicle/lib/backend/**` and the binary's links resolve. (The earlier planned
  `-63-cuda` tag was never built — ignore references to it.)
- **`deploy/docker-compose.gpu.yaml`** — the GPU variant (nvidia device reservation + CUDA device
  + `user: root` for the /dev/nvidia* permissions). **Always deploy GPU runs with
  `-c deploy/docker-compose.gpu.yaml`** — using the base compose silently yields `InvalidDevice`.
- Build knobs: **`DARKNYX_ICICLE_CUDA_ARCH`** → cmake `-DCUDA_ARCH`; darknyx-tee feature
  `icicle-cuda`; `deploy/Dockerfile` `ARG ENABLE_CUDA`; CI builds the CUDA image on a
  `-cuda`-suffixed tag. The vendored fork accepts `DARKNYX_ICICLE_CUDA_ARCH` (canonical) and
  `NYX_ICICLE_CUDA_ARCH` (deprecated, warns), and `scripts/check-icicle-cuda-arch-env.sh` fails CI
  if the Dockerfile ever forwards a name the pinned submodule does not read — see §10.2.

✅ **Correctness (2a settle) is DONE** — see §10. Remaining: the **performance measurement**
(§10.4, and note §10.5 — most of it does not need a *confidential* GPU) and the **2b GPU
attestation** work (§6). **Do NOT end the session by stopping the CVM — see §7.**

**Tooling note:** an nvm `node`/`phala` shim can shadow the real binary (the tell is
`command not found: _load_nvm`, then `maximum nested function level reached`). Resolve the real
paths rather than assuming an install layout — the binaries may come from Homebrew or from nvm:
```
PHALA="$(command -v phala)"   # /opt/homebrew/bin/phala on the 2026-08 dev box
NODE="$(command -v node)"     # /opt/homebrew/bin/node
```
If `command -v` returns the shim itself, fall back to an explicit install path
(`ls /opt/homebrew/bin/node "$HOME/.nvm/versions/node"`). GNU `timeout` is not present on macOS.

---

## 1. Confirm GPU capacity (the gate)

```sh
"$PHALA" status                       # logged in as the right workspace
"$PHALA" instance-types | grep -i h200
```
The dashboard at <https://cloud.phala.com/gpu-tee> is the ground truth for availability — look for
**H200 … On-Demand Available**. If the CLI `deploy` returns `ERR-02-002: No teepod found matching
h200.small`, capacity is still out (this is exactly what blocked us on 2026-06-19; **no CVM is
created and nothing bills** when this happens).

H200 spec we target: **1× H200 SXM 141 GB, 24 vCPU, 192 GB RAM, $3.80/GPU/hr, sm_90**.

---

## 2. Deploy

Two equivalent paths. **Path A (dashboard)** is what worked around the CLI capacity matching;
**Path B (CLI)** is faster if the CLI can match a GPU teepod.

### Per-session values to refresh first

```sh
cd "$DARKNYX_REPO"   # the darknyx-monorepo checkout root
RPC=$(grep '^SOLANA_RPC_URL=' packages/sdk/.env | head -1 | cut -d= -f2- | tr -d '"'\'' \r')
# Reset the on-chain Merkle tree (all 4 shards) so the mirror cold-boots empty:
SOLANA_RPC_URL="$RPC" ADMIN_KEYPAIR=.devnet/keypairs/admin.json "$NODE" scripts/reset-merkle-tree.mjs
# Fresh sync-floor slot (put this in DARKNYX_TEE_SYNC_FROM_SLOT below):
solana slot --url "$RPC"
# Your SSH pubkey (paste into the dashboard / used by `phala ssh`):
cat ~/.ssh/id_ed25519.pub
```

Devnet config values (from `.devnet/e2e-config.json`, stable unless devnet-setup is re-run):

| var | value |
|---|---|
| `DARKNYX_TEE_BASE_MINT` | `sGzG6XyTiHiY9G2dC18GXoV7W4YKPXcM8soDS79jPjn` |
| `DARKNYX_TEE_QUOTE_MINT` | `FEzPrxcwgYvwWYceZdJEMwWj9tB4hcR7iXmkZTunVoX6` |
| `DARKNYX_TEE_SETTLE_LOOKUP_TABLE` | `FpxZ3kts77NkR9sBja2eMujcXCdMDnfrWj6EEVKpcyRE` |
| `DARKNYX_TEE_PROTOCOL_OWNER_COMMITMENT` | `0079782d70726f746f636f6c2d6f776e65722d76310000000000000000000000` |
| `DARKNYX_TEE_NUM_TREES` | `4` |
| `DARKNYX_TEE_FEE_RATE_BPS` | `30` |

> If `.devnet/e2e-config.json` ever changes, re-read these with
> `jq -r '.baseMint.pubkey, .quoteMint.pubkey, .settleLookupTable, .protocol.ownerCommitmentHex, .numTrees' .devnet/e2e-config.json`.

### Path A — Dashboard (Custom Configuration)

1. **GPU type:** H200, **1 GPU**.
2. **OS image:** `dstack-nvidia-dev-*` (the **nvidia** image = GPU passthrough; the **dev** suffix =
   SSH access — required for the CC-mode check + the 2b spike).
3. **Template:** Custom Configuration. Paste the compose below (devnet values inlined; the **only**
   `${...}` reference is the dedicated RPC, supplied as an encrypted secret). Refresh
   `DARKNYX_TEE_SYNC_FROM_SLOT` to the slot printed above.

```yaml
version: '3.8'
services:
  darknyx-tee:
    image: ghcr.io/skysail-labs/darknyx-tee:tee-v3-hardening-69-cuda
    restart: unless-stopped
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: all
              capabilities: [gpu]
    volumes:
      - /var/run/dstack.sock:/var/run/dstack.sock
      - darknyx_state:/var/lib/darknyx-tee
    environment:
      DARKNYX_TEE_LOG: "info,darknyx_tee::settle=debug,darknyx_tee::oracle=info,darknyx_tee::merkle=info"
      DARKNYX_TEE_HTTP_BIND: "0.0.0.0:8080"
      DARKNYX_TEE_FEED_IDS: "ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d"
      DARKNYX_TEE_STATE_DIR: "/var/lib/darknyx-tee"
      DARKNYX_TEE_API_KEY: ${DARKNYX_TEE_API_KEY}
      DARKNYX_TEE_API_SECRET: ${DARKNYX_TEE_API_SECRET}
      DARKNYX_TEE_PASSPHRASE: ${DARKNYX_TEE_PASSPHRASE}
      DARKNYX_TEE_SOLANA_RPC_URL: ${DARKNYX_TEE_SOLANA_RPC_URL}
      DARKNYX_TEE_SYNC_FROM_SLOT: "<REFRESH: solana slot>"
      DARKNYX_TEE_BASE_MINT: "sGzG6XyTiHiY9G2dC18GXoV7W4YKPXcM8soDS79jPjn"
      DARKNYX_TEE_QUOTE_MINT: "FEzPrxcwgYvwWYceZdJEMwWj9tB4hcR7iXmkZTunVoX6"
      DARKNYX_TEE_MARKET_SYMBOL: "SOL-USDC"
      DARKNYX_TEE_SETTLE_LOOKUP_TABLE: "FpxZ3kts77NkR9sBja2eMujcXCdMDnfrWj6EEVKpcyRE"
      DARKNYX_TEE_FEE_RATE_BPS: "30"
      DARKNYX_TEE_PROTOCOL_OWNER_COMMITMENT: "0079782d70726f746f636f6c2d6f776e65722d76310000000000000000000000"
      DARKNYX_TEE_NUM_TREES: "4"
      DARKNYX_TEE_PROVER: "icicle"
      DARKNYX_TEE_WITNESS: "native"
      DARKNYX_TEE_ICICLE_DEVICE: "CUDA"
      DARKNYX_TEE_SETTLE_SEND_CONCURRENCY: "16"
      DARKNYX_TEE_SETTLE_BATCH_CONCURRENCY: "1"
    ports:
      - "8080:8080"
volumes:
  darknyx_state:
```

4. **Advanced → Encrypted Secrets:** add the dedicated RPC URL plus fresh
   `DARKNYX_TEE_API_KEY`, `DARKNYX_TEE_API_SECRET`, and `DARKNYX_TEE_PASSPHRASE` values.
   These are E2E-encrypted in the browser and never enter the compose hash. The
   public `darknyx-test-*` fixtures are rejected outside explicit simulator mode.
5. **Advanced → SSH Authorization → Public Key:** paste `~/.ssh/id_ed25519.pub`.
6. Deploy.

### Path B — CLI (if a GPU teepod matches)

```sh
umask 077
export DARKNYX_TEE_API_KEY="darknyx-$(openssl rand -hex 16)"
export DARKNYX_TEE_API_SECRET="$(openssl rand -hex 32)"
export DARKNYX_TEE_PASSPHRASE="$(openssl rand -base64 32 | tr -d '\n')"
BASE=$(jq -r .baseMint.pubkey .devnet/e2e-config.json)
QUOTE=$(jq -r .quoteMint.pubkey .devnet/e2e-config.json)
ALT=$(jq -r .settleLookupTable .devnet/e2e-config.json)
OWNER=$(jq -r .protocol.ownerCommitmentHex .devnet/e2e-config.json)
FLOOR=$(solana slot --url "$RPC")
cat > .env.deploy <<EOF      # .env.deploy matches gitignored .env.* — never commit
DARKNYX_TEE_API_KEY=$DARKNYX_TEE_API_KEY
DARKNYX_TEE_API_SECRET=$DARKNYX_TEE_API_SECRET
DARKNYX_TEE_PASSPHRASE=$DARKNYX_TEE_PASSPHRASE
DARKNYX_TEE_SOLANA_RPC_URL=$RPC
DARKNYX_TEE_SYNC_FROM_SLOT=$FLOOR
DARKNYX_TEE_BASE_MINT=$BASE
DARKNYX_TEE_QUOTE_MINT=$QUOTE
DARKNYX_TEE_MARKET_SYMBOL=SOL-USDC
DARKNYX_TEE_SETTLE_LOOKUP_TABLE=$ALT
DARKNYX_TEE_FEE_RATE_BPS=30
DARKNYX_TEE_PROTOCOL_OWNER_COMMITMENT=$OWNER
DARKNYX_TEE_NUM_TREES=4
DARKNYX_TEE_PROVER=icicle
DARKNYX_TEE_ICICLE_DEVICE=CUDA
EOF
"$PHALA" deploy -n darknyx-gpu -c deploy/docker-compose.gpu.yaml -e .env.deploy \
  -t h200.small --kms phala --dev-os --ssh-pubkey ~/.ssh/id_ed25519.pub --wait
rm -P .env.deploy            # erase the RPC credential off disk (macOS has no `shred`)
```

> **Image must be public:** Phala pulls `ghcr.io/skysail-labs/darknyx-tee` anonymously. It was public
> for the CPU runs (same package) — if a deploy errors on image pull, flip the ghcr package to
> public (GitHub org → Packages → darknyx-tee → visibility).

---

## 3. Post-deploy wiring

```sh
"$PHALA" cvms list                                  # → APP_ID + status
CVM=app_<id>
GW="https://<app_id>-8080.dstack-pha-<node>.phala.network"   # exact host from cvms list / dashboard
"$PHALA" cvms logs --cvm-id "$CVM" | tail -80       # boot: CUDA backend load, "derived K-shard TEE
                                                    #   signer set" (copy ALL 4), "settle pipeline ENABLED"
```

Confirm Confidential-Compute mode is actually ON (this is the GPU-hardware privacy gate):
```sh
"$PHALA" ssh --cvm-id "$CVM" -- nvidia-smi conf-compute -q   # want: ConfComputeMode : ON
"$PHALA" ssh --cvm-id "$CVM" -- nvidia-smi                   # H200 visible to the container
```

---

## 4. Rotate + fund the 4 shard signers (new app_id ⇒ new deterministic keys)

```sh
# <key0..3> = the 4 pubkeys from the "derived K-shard TEE signer set" boot log line
SOLANA_RPC_URL="$RPC" ADMIN_KEYPAIR=.devnet/keypairs/admin.json \
  "$NODE" scripts/rotate-tee-pubkey.mjs <key0> <key1> <key2> <key3>
SOLANA_RPC_URL="$RPC" FUNDER_KEYPAIR=~/.config/solana/id.json \
  "$NODE" scripts/fund-tee-keys.mjs <key0> <key1> <key2> <key3>
```

---

## 5. Phase 2a — GPU prove perf + real settle + A/B

The headline measurement. Run the flagship settle e2e against the GPU CVM:

```sh
RUN_CVM_E2E=1 DARKNYX_TEE_GATEWAY="$GW" SOLANA_RPC_URL="$RPC" \
  FUNDER_KEYPAIR=~/.config/solana/id.json ADMIN_KEYPAIR=.devnet/keypairs/admin.json \
  ( cd packages/sdk && ../../node_modules/.bin/vitest run tests/cvm-settle-e2e.test.ts )
```
- **Expect:** deposits → crossing bid+ask → the CVM matches AND settles on devnet on the **GPU**;
  `leaf_count` grows (+5 for the exact-fill: note_c/d + buyer change + base+quote fee notes).
- **Capture the prove breakdown** from the CVM log:
  ```sh
  "$PHALA" cvms logs --cvm-id "$CVM" | grep -E "prove breakdown|settle pipeline timing"
  # icicle/CUDA line: backend="icicle" device=CUDA witness="native" witness_ms=.. prove_step_ms=..
  ```
  The number that matters is **`prove_step_ms`** — target tens of ms vs the rapidsnark-CPU ~1.5 s.

**A/B on the SAME image** (no rebuild — just flip the prover and restart). Update the env (dashboard
"Encrypted Secrets"/env edit, or `phala envs`/redeploy with `DARKNYX_TEE_PROVER=rapidsnark`), re-run the
same test, and compare `prove_step_ms`:
- `DARKNYX_TEE_PROVER=rapidsnark` → the CPU baseline.
- `DARKNYX_TEE_PROVER=icicle DARKNYX_TEE_ICICLE_DEVICE=CPU` → icicle-CPU (sanity; should ≈ ark/rapidsnark).
- `DARKNYX_TEE_PROVER=icicle DARKNYX_TEE_ICICLE_DEVICE=CUDA` → the GPU win.

Record the table in `crates/darknyx-tee-loadgen/BENCHMARK.md` (the ICICLE section already has the
Phase-1 CPU rows; add the CVM GPU row + the speedup).

### 5.1 The full throughput run (do not use single-pair e2e timings)

`cvm-settle-e2e` remains the correctness ceremony, but it proves only one
batch—the first/warm-up prove. Throughput and steady-state latency come from
`darknyx-tee-loadgen --real-settle`, which now consumes the admin settlement
metrics cursor and stops on terminal match outcomes rather than estimating from
Merkle leaf growth.

Read [`benchmarks/settlement-throughput-methodology.md`](benchmarks/settlement-throughput-methodology.md)
before the window. Use at least eight completed batches after excluding warm-up:

```sh
# Run locally before the paid GPU window. This builds mandatory native C++
# client witnesses and proves the complete 160-deposit + 160-input fixture.
# The real-settle loadgen never invokes WASM/Wasmer and has no fallback.
bash scripts/build-native-client-witnesses.sh
cargo test -p darknyx-tee-loadgen --release --lib \
  --features real-settle-chain \
  native_client_proofs_sustain_full_fixture -- --ignored

cargo run -p darknyx-tee-loadgen --features real-settle-chain -- \
  --real-settle --endpoint "$GW" --rpc-url "$RPC" \
  --admin-keypair .devnet/keypairs/admin.json \
  --base-mint "$BASE_HEX" --quote-mint "$QUOTE_HEX" \
  --fee-rate-bps 30 --price-scale 100000000 \
  --traders 16 --real-mix partial-fill:100 --real-partial-fill-asks 9 \
  --real-submit-rate 15 --min-measured-batches 8 \
  --client-prove-concurrency 1 \
  --settle-drain-timeout-secs 600 --warmup-batches 1 \
  --benchmark-label h200-icicle-cuda-c1 \
  --report docs/benchmarks/runs/h200-icicle-cuda-c1.md \
  --metrics-json docs/benchmarks/runs/h200-icicle-cuda-c1.json
```

`BASE_HEX`/`QUOTE_HEX` are the raw 32-byte mint pubkeys in hex; do not pass the
base58 display values used in the compose file.

Run this same-box sequence, resetting the tree and cold-booting the CVM between
legs while **never stopping/deallocating the GPU instance**:

1. rapidsnark CPU, batch concurrency 1;
2. icicle CPU, batch concurrency 1;
3. icicle CUDA, batch concurrency 1;
4. icicle CUDA, batch concurrency 2;
5. icicle CUDA, batch concurrency 4.

Only the prover/device and
`DARKNYX_TEE_SETTLE_BATCH_CONCURRENCY` change. Keep image, machine, workload,
RPC tier, shard count, send concurrency, and market config fixed. For each leg
capture the JSON/Markdown artifacts, `cpu.max`, `cpu.stat`, `nvidia-smi`,
gateway/host latency, app/compose/boot identity, and the exact Phala instance
metadata. Reject a run if the metrics endpoint reports a cursor gap, any
unexplained terminal rejection/ambiguity, or fewer terminal matches than the
known workload.

The prod9 rapidsnark control is already complete:
[`benchmarks/runs/prod9-rapidsnark-cpu-comparison-2026-07-23.md`](benchmarks/runs/prod9-rapidsnark-cpu-comparison-2026-07-23.md).
Concurrency 2 was slower than 1, so do not spend a CPU leg on concurrency 4.
That setting remains useful only in the icicle-CUDA same-box sweep above.

---

## 6. Phase 2b — GPU attestation (the full trust model)

**Goal:** prove to a client that order intent runs on **genuine, CC-mode** GPU silicon — i.e. fold
the NVIDIA GPU attestation into our existing `/attestation` (which today returns only the Intel TDX
quote) and build the client verifier.

### What we already know
- Our `GET /attestation?reportData=<hex>` (`crates/darknyx-tee/src/api/attestation.rs`) returns the TDX
  quote with `report_data = [caller nonce | 0..32][SHA-256(tee_pubkey) | 32..64]`. This is
  **already nonce-compatible** with the dual-attestation binding (the TDX quote and the NVIDIA
  payload must bind the same fresh nonce).
- It works **unchanged** on the GPU CVM. The GPU device block shifts `compose_hash` → re-allowlist +
  (for prod) the `vault_config.tee_pubkey` multisig rotation; for devnet, just rotate (step 4).
- Phala's verification model (from their docs): client verifies the GPU via **NRAS**
  (`https://nras.attestation.nvidia.com/v3/attest/gpu` → JWT verdict, `x-nvidia-overall-att-result
  == true`), the TDX via **dcap-qvl** (or Phala's verify API), freshness via the report_data nonce,
  and the code via `compose_hash` in `mr_config_id` (`0x01<sha256(app_compose)>`).

### Step 2b.1 — the spike (do this on the live H200, it can't be resolved offline)
Find how a **custom dstack app** obtains the NVIDIA GPU attestation **bound to our nonce**:
```sh
"$PHALA" ssh --cvm-id "$CVM"
#  - is NVIDIA's local GPU attestation tooling present? (nvidia-smi conf-compute -q;
#    look for /opt/nvidia/** , nvtrust, the GPU local verifier / attestation SDK)
#  - does the dstack socket expose a GPU-quote call? (our vendored dstack/sdk/rust has only
#    info/get_key/get_quote — a newer dstack or NVIDIA tooling is likely needed)
#  - does `phala cvms attestation --cvm-id "$CVM" --json` return a combined TDX+GPU payload, and
#    can we inject our own nonce into the GPU evidence?
"$PHALA" cvms attestation --cvm-id "$CVM" --json | jq .   # inspect the shape
```
The answer decides whether we (a) gather GPU evidence in-process via NVIDIA tooling, or (b) proxy a
dstack/Phala attestation API. Either way it likely needs a **second image build + redeploy** to ship
the `/attestation` change.

### Step 2b.2 — implement (off-session, then a short re-validate session)
- **TEE side** (`crates/darknyx-tee/src/api/attestation.rs` + `state.rs`): add a `nvidia_payload` field
  to `AttestationResponse`, gathered via the mechanism from 2b.1, bound to the **same** caller nonce.
- **SDK client verifier** (`packages/sdk/src/...`, per `docs/tee-attestation-flow.md` §4 — currently
  spec-only): `verifyTeeAttestation(apiBaseUrl, expectedComposeHash)` that checks, against a fresh
  nonce: NRAS verdict ✔ + the TDX and NVIDIA streams bind the same nonce ✔ + dcap-qvl verifies the
  TDX quote ✔ + `compose_hash` matches ✔ + `tee_pubkey` binds ✔.
- Rebuild a fresh `tee-v3-hardening-<N>-cuda` image (bump the tag), redeploy, and run the verifier
  end-to-end against the live GPU CVM → single PASS.

---

## 7. 🛑 DO NOT stop the CVM — on-demand GPU windows are forfeited

> **This section previously said the opposite, and that advice cost us most of a
> paid 24 h H200 window on 2026-07-21.**

**NEVER run `phala cvms stop` on an on-demand GPU CVM.** GPU instances are
provisioned as a **fixed-duration window billed in full up front**. Stopping
**DEALLOCATES the instance permanently** — it disappears from `phala cvms list`,
the GPU returns to the pool, and every remaining prepaid hour is forfeited.
**There is no restart.** (Unlike a CPU CVM, where stop/start is free and correct.)

| CVM type | How to tell | Rule |
|---|---|---|
| **CPU** | `dstack-pha-*`, `resource.gpus == 0` | **Stop when done** — bills per running hour |
| **GPU** | `h200.*` / `dstack-nvidia-*`, `resource.gpus >= 1` | **LEAVE IT RUNNING** the whole window — idle time is already paid for; stopping destroys it |

**Check before stopping anything:**
```sh
phala cvms get <app_id> --json | grep -E '"instance_type"|"gpus"'
```

Practical consequence: **plan the entire window's work up front** (see §10's
"next session" list) — you cannot pause and resume. When the window expires the
instance is reclaimed automatically; just shred the deploy env and `unset` the
credential vars.

---

## 8. Gotchas + troubleshooting

| Symptom | Cause / fix |
|---|---|
| `ERR-02-002: No teepod found matching h200.small` | GPU capacity out (our 2026-06-19 blocker). No CVM created, no billing. Use the dashboard / wait. |
| Deploy errors on image pull | ghcr `darknyx-tee` package not public → make it public. |
| `set_device(CUDA)` fails at runtime | GPU driver (`libcuda.so.1`) not injected (GPU passthrough not wired) OR the CUDA-toolkit minor (12.6 baked) is newer than the H200 host driver. Check `nvidia-smi`; if a driver-version mismatch, rebuild the image pinning a CUDA minor within the host driver's window (`deploy/Dockerfile` `cuda-*-12-6` → adjust). |
| CC mode `ConfComputeMode : OFF` | The instance isn't in CC mode — the privacy guarantee is void. Re-provision a CC-enabled H200 (this is the whole point; do not run real order intent on a non-CC GPU). |
| Witness/settle errors but prove works | unrelated to GPU — same settle pipeline as CPU; check the mint regime + tree reset (step 2). |
| `StaleMerkleRoot (6004)` | tree drifted — re-run `scripts/reset-merkle-tree.mjs` + bump `DARKNYX_TEE_SYNC_FROM_SLOT`. |
| Want to A/B without a rebuild | flip `DARKNYX_TEE_PROVER` / `DARKNYX_TEE_ICICLE_DEVICE` via env + restart — the image ships rapidsnark + icicle(CPU+CUDA). |

---

## 9. Re-validate the CUDA image only if these change

Use an observability-enabled CUDA image (currently
`tee-v3-hardening-69-cuda`) for the next window. Rebuild with a new `-cuda` tag
whenever you touch:
`crates/darknyx-tee/src/**`, the circuits, `deploy/Dockerfile`, `third_party/icicle-snark/**`, or
`Cargo.lock`. Trigger: `git tag tee-v3-hardening-<N>-cuda && git push origin tee-v3-hardening-<N>-cuda`
(CI builds the CUDA image on any `-cuda`-suffixed tag, no GPU runner needed), then point the compose
`image:` at the new tag. The CI verify step re-checks the backend `.so` + linking.

---

## 10. Session log 2026-07-21 — results and what is still open

First real GPU session. **Correctness passed; performance is still unmeasured.**

### 10.1 What passed

`cvm-settle-e2e` green end-to-end on `h200.small` with `device=CUDA`: deposit →
match → **GPU prove** → `verify_match_batch` → `tee_forced_settle_batched` → leaf
growth. Because the on-chain verifier holds the committed VK, this is a stronger
parity gate than the unit test: **CUDA introduces no proof-format or public-input
drift.**

### 10.2 Three blockers hit (all now encoded in the configs)

| # | Symptom | Root cause | Fix |
|---|---|---|---|
| 1 | Build: `CUDA_ARCHITECTURES is set to "native", but no GPU was detected` | Dockerfile forwarded `DARKNYX_ICICLE_CUDA_ARCH`, but the vendored fork's `build.rs` only read `NYX_ICICLE_CUDA_ARCH` → `-DCUDA_ARCH`. The rename skipped the submodule, so the two drifted silently and the arch was never passed. | **Fixed at the source, not worked around.** The fork now reads `DARKNYX_ICICLE_CUDA_ARCH` (canonical) with the old spelling as a deprecated warning fallback (`icicle-snark@fb4797f`), the Dockerfile forwards the canonical name, and `scripts/check-icicle-cuda-arch-env.sh` fails CI on any future mismatch. |
| 2 | Runtime: `InvalidDevice` | **Deployed with the wrong compose.** `deploy/docker-compose.gpu.yaml` (with the nvidia reservation) already existed; the base `docker-compose.yaml` was used instead, so the container got no GPU. | Always deploy GPU runs with `-c deploy/docker-compose.gpu.yaml`. Self-inflicted — check for existing GPU tooling before improvising. |
| 3 | Runtime: `PermissionDenied` in icicle `pre_compute_keys` (`cache.rs:226`) | Image drops to `USER darknyx`; `/dev/nvidia*` is root-owned → EACCES. Surfaces **after** `set_device` succeeds, so it reads like a CUDA bug. | `user: root` in the GPU compose. **TODO(prod):** add the runtime user to `video`/`render` groups in the `-cuda` image and drop this. |

> **Shared failure signature:** in all three runtime cases **intake and matching look
> perfectly healthy** — orders accept, the matcher ticks, a batch is enqueued — and
> only the prove stage dies. `cvm-settle-e2e` surfaces it as a flat `leaf_count`,
> not an obvious error. When a settle silently fails to land, grep the CVM logs for
> `icicle` / `panic` first.

### 10.3 ⚠️ Why the timing from this session is NOT usable

Logged: `witness_ms=180`, `prove_step_ms=1843` (`device=CUDA`). Against the prod9
CPU baseline (`297` / `2214`) that looks like ~1.2× — **but the comparison is
invalid** for two independent reasons:

1. **Only one prove ran** (exactly one `prove breakdown` line). icicle builds its
   preprocessed-zkey cache on the *first* prove, so this is **warmup**, not steady
   state. `cvm-settle-e2e` runs a single batch, so it can only ever show warmup.
2. **Two variables changed.** The GPU box's CPU benchmarks **466 Mops/s**
   single-thread vs prod9's **131** — ~3.5× faster — so GPU *and* CPU moved at once.

1843 ms is also implausibly slow for steady-state H200 Groth16 on a ~233k-constraint
circuit, which is consistent with cache-build cost rather than compute.
**The roadmap's ~8× estimate remains unvalidated in both directions.**

### 10.4 Next session — run these, in this order

1. **Correctness ceremony:** run `cvm-settle-e2e` once after confirming the
   image/device. Do not use its one warm-up proof as a performance result.
2. **Steady-state same-box A/B:** run the §5.1 real-settle loadgen for
   rapidsnark CPU, icicle CPU, and icicle CUDA at concurrency 1, then icicle
   CUDA at 2 and 4. It excludes warm-up and requires at least eight measured
   batches. Holding the host constant separates backend, device, and scheduler
   effects.
3. **Confirm CC mode** (`nvidia-smi conf-compute -q` → `ConfComputeMode : ON`) —
   §6/§8 already cover this and it was NOT verified in the 2026-07-21 session.
4. Capture `cpu.max`, before/after `cpu.stat`, `nvidia-smi`, host latency, and
   Phala instance identity for every leg. Guest-agent load/memory metrics are a
   fallback, not a substitute for cgroup throttling and GPU utilization.
5. Only then update `throughput-roadmap.md` item 5 / the 🟢 gate with a real number.

### 10.5 💡 Most of the remaining work does not need a *confidential* GPU

**Measuring `prove_step` needs *a* GPU, not a TEE.** `crates/darknyx-tee/tests/icicle_cuda_parity.rs`
is a plain `cargo test` that already reports warmup vs steady **and** an ark-CPU A/B
on the same box — exactly the isolation §10.4 asks for:

```sh
RUN_ICICLE_CUDA_PROVE=1 cargo test -p darknyx-tee --release \
  --features icicle-cuda --test icicle_cuda_parity -- --nocapture
```

Run that on any commodity H100/H200 (RunPod / Lambda / vast.ai, a few $/hr) to get
the performance answer cheaply. Reserve scarce **confidential**-GPU windows for what
genuinely needs the TEE: end-to-end settle, CC-mode confirmation, GPU attestation
(§6), and production deployment.

### 10.6 Reference data

| Item | Value |
|---|---|
| Instance | `h200.small` — 24 vCPU, 192 GB, 1 GPU, **$4.80/hr** (not the $3.80 quoted above) |
| Node / OS | `gpu-use1` (US-EAST-1) / `dstack-nvidia-dev-0.5.9` |
| Gateway | `https://<app_id>-8080.dstack-pha-use1.phala.network` — read `gateway.base_domain` from `phala cvms get --json`; do **not** assume the prod5/prod9 pattern |
| Host CPU | `06/cf` @ 1900 MHz, 466 Mops/s single-thread, `nr_throttled=0` |
| Settle stages | lock 1132 · prove 2032 · verify 1056 · alt 1340+585 · settle 10546 · **total 13644** |
