# GPU-TEE Runbook — ICICLE CUDA prover on a Phala H200 (Phase 2a perf + 2b attestation)

> **Status (2026-06-19): SHELVED on Phala GPU capacity.** Phala support confirmed they are
> out of GPU compute. Everything on our side is built + CI-validated and waiting. When H200
> capacity returns (dashboard shows *On-Demand Available*, or `phala instance-types` matches a
> GPU teepod), execute this runbook top-to-bottom in **one focused billable session** (~$3.80/
> GPU/hr) and **STOP the CVM at the end**.
>
> This is the GPU analogue of [`docs/cvm-run-runbook.md`](cvm-run-runbook.md). The CPU/rapidsnark
> CVM flow is unchanged and unaffected — keep using it (see the last section).

---

## 0. What is already done (no re-work needed)

The whole CUDA build + packaging track is committed on `revamp_proving` and **CI-validated with no
GPU** (commit `0400776` + the `git`/`libatomic1` fixups):

- **ICICLE backend** wired as a third prover (`NYX_TEE_PROVER=icicle`, device via
  `NYX_TEE_ICICLE_DEVICE`). CPU byte-parity already proven (Phase 1, commit `4c9558c`).
- **CUDA image** `ghcr.io/skysail-labs/nyx-tee:tee-v3-hardening-36-cuda` — built, pushed, and
  CI-verified: the 3 backend `.so` ship under `/opt/icicle/lib/backend/**` and the binary's links
  resolve. Cross-compiled for `sm_90` (H200/Hopper) **with no GPU on the builder**.
- **`deploy/docker-compose.gpu.yaml`** — the GPU variant (nvidia device reservation + CUDA device).
- Build knobs: `NYX_ICICLE_CUDA_ARCH` → cmake `-DCUDA_ARCH`; nyx-tee feature `icicle-cuda`;
  `deploy/Dockerfile` `ARG ENABLE_CUDA`; CI builds the CUDA image on a `-cuda`-suffixed tag.

So the **only** remaining work is the live GPU session: deploy → confirm CC mode → measure the GPU
prove speedup + settle on-chain (2a) → wire the GPU attestation (2b) → stop.

**Tooling note:** an nvm `node`/`phala` shim can shadow the real binary — if so, point these at the
absolute nvm path for YOUR node version (find it with `ls "$HOME/.nvm/versions/node"`):
```
NVM_BIN="$HOME/.nvm/versions/node/<your-version>/bin"   # e.g. v24.2.0
PHALA="$NVM_BIN/phala"
NODE="$NVM_BIN/node"
```

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
cd "$NYX_REPO"   # the nyx-monorepo checkout root
RPC=$(grep '^SOLANA_RPC_URL=' packages/sdk/.env | head -1 | cut -d= -f2- | tr -d '"'\'' \r')
# Reset the on-chain Merkle tree (all 4 shards) so the mirror cold-boots empty:
SOLANA_RPC_URL="$RPC" ADMIN_KEYPAIR=.devnet/keypairs/admin.json "$NODE" scripts/reset-merkle-tree.mjs
# Fresh sync-floor slot (put this in NYX_TEE_SYNC_FROM_SLOT below):
solana slot --url "$RPC"
# Your SSH pubkey (paste into the dashboard / used by `phala ssh`):
cat ~/.ssh/id_ed25519.pub
```

Devnet config values (from `.devnet/e2e-config.json`, stable unless devnet-setup is re-run):

| var | value |
|---|---|
| `NYX_TEE_BASE_MINT` | `sGzG6XyTiHiY9G2dC18GXoV7W4YKPXcM8soDS79jPjn` |
| `NYX_TEE_QUOTE_MINT` | `FEzPrxcwgYvwWYceZdJEMwWj9tB4hcR7iXmkZTunVoX6` |
| `NYX_TEE_SETTLE_LOOKUP_TABLE` | `FpxZ3kts77NkR9sBja2eMujcXCdMDnfrWj6EEVKpcyRE` |
| `NYX_TEE_PROTOCOL_OWNER_COMMITMENT` | `0079782d70726f746f636f6c2d6f776e65722d76310000000000000000000000` |
| `NYX_TEE_NUM_TREES` | `4` |
| `NYX_TEE_FEE_RATE_BPS` | `30` |

> If `.devnet/e2e-config.json` ever changes, re-read these with
> `jq -r '.baseMint.pubkey, .quoteMint.pubkey, .settleLookupTable, .protocol.ownerCommitmentHex, .numTrees' .devnet/e2e-config.json`.

### Path A — Dashboard (Custom Configuration)

1. **GPU type:** H200, **1 GPU**.
2. **OS image:** `dstack-nvidia-dev-*` (the **nvidia** image = GPU passthrough; the **dev** suffix =
   SSH access — required for the CC-mode check + the 2b spike).
3. **Template:** Custom Configuration. Paste the compose below (devnet values inlined; the **only**
   `${...}` reference is the Helius RPC, supplied as an encrypted secret). Refresh
   `NYX_TEE_SYNC_FROM_SLOT` to the slot printed above.

```yaml
version: '3.8'
services:
  nyx-tee:
    image: ghcr.io/skysail-labs/nyx-tee:tee-v3-hardening-36-cuda
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
      - nyx_state:/var/lib/nyx-tee
    environment:
      NYX_TEE_LOG: "info,nyx_tee::settle=debug,nyx_tee::oracle=info,nyx_tee::merkle=info"
      NYX_TEE_HTTP_BIND: "0.0.0.0:8080"
      NYX_TEE_FEED_IDS: "ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d"
      NYX_TEE_STATE_DIR: "/var/lib/nyx-tee"
      NYX_TEE_API_KEY: "nyx-test-api-key"
      NYX_TEE_API_SECRET: "nyx-test-secret"
      NYX_TEE_PASSPHRASE: "nyx-test-passphrase"
      NYX_TEE_SOLANA_RPC_URL: ${NYX_TEE_SOLANA_RPC_URL}   # the ONLY secret (encrypted-secrets UI)
      NYX_TEE_SYNC_FROM_SLOT: "<REFRESH: solana slot>"
      NYX_TEE_BASE_MINT: "sGzG6XyTiHiY9G2dC18GXoV7W4YKPXcM8soDS79jPjn"
      NYX_TEE_QUOTE_MINT: "FEzPrxcwgYvwWYceZdJEMwWj9tB4hcR7iXmkZTunVoX6"
      NYX_TEE_SETTLE_LOOKUP_TABLE: "FpxZ3kts77NkR9sBja2eMujcXCdMDnfrWj6EEVKpcyRE"
      NYX_TEE_FEE_RATE_BPS: "30"
      NYX_TEE_PROTOCOL_OWNER_COMMITMENT: "0079782d70726f746f636f6c2d6f776e65722d76310000000000000000000000"
      NYX_TEE_NUM_TREES: "4"
      NYX_TEE_PROVER: "icicle"
      NYX_TEE_WITNESS: "native"
      NYX_TEE_ICICLE_DEVICE: "CUDA"
      NYX_TEE_SETTLE_SEND_CONCURRENCY: "16"
    ports:
      - "8080:8080"
volumes:
  nyx_state:
```

4. **Advanced → Encrypted Secrets:** add **one** — KEY `NYX_TEE_SOLANA_RPC_URL`, value = the Helius
   URL (`SOLANA_RPC_URL=...` line in `packages/sdk/.env`). E2E-encrypted in the browser; never
   enters the compose hash.
5. **Advanced → SSH Authorization → Public Key:** paste `~/.ssh/id_ed25519.pub`.
6. Deploy.

### Path B — CLI (if a GPU teepod matches)

```sh
umask 077
BASE=$(jq -r .baseMint.pubkey .devnet/e2e-config.json)
QUOTE=$(jq -r .quoteMint.pubkey .devnet/e2e-config.json)
ALT=$(jq -r .settleLookupTable .devnet/e2e-config.json)
OWNER=$(jq -r .protocol.ownerCommitmentHex .devnet/e2e-config.json)
FLOOR=$(solana slot --url "$RPC")
cat > .env.deploy <<EOF      # .env.deploy matches gitignored .env.* — never commit
NYX_TEE_SOLANA_RPC_URL=$RPC
NYX_TEE_SYNC_FROM_SLOT=$FLOOR
NYX_TEE_BASE_MINT=$BASE
NYX_TEE_QUOTE_MINT=$QUOTE
NYX_TEE_SETTLE_LOOKUP_TABLE=$ALT
NYX_TEE_FEE_RATE_BPS=30
NYX_TEE_PROTOCOL_OWNER_COMMITMENT=$OWNER
NYX_TEE_NUM_TREES=4
NYX_TEE_PROVER=icicle
NYX_TEE_ICICLE_DEVICE=CUDA
EOF
"$PHALA" deploy -n nyx-gpu -c deploy/docker-compose.gpu.yaml -e .env.deploy \
  -t h200.small --kms phala --dev-os --ssh-pubkey ~/.ssh/id_ed25519.pub --wait
rm -P .env.deploy            # shred the Helius key off disk (macOS has no `shred`)
```

> **Image must be public:** Phala pulls `ghcr.io/skysail-labs/nyx-tee` anonymously. It was public
> for the CPU runs (same package) — if a deploy errors on image pull, flip the ghcr package to
> public (GitHub org → Packages → nyx-tee → visibility).

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
RUN_CVM_E2E=1 NYX_TEE_GATEWAY="$GW" SOLANA_RPC_URL="$RPC" \
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
"Encrypted Secrets"/env edit, or `phala envs`/redeploy with `NYX_TEE_PROVER=rapidsnark`), re-run the
same test, and compare `prove_step_ms`:
- `NYX_TEE_PROVER=rapidsnark` → the CPU baseline.
- `NYX_TEE_PROVER=icicle NYX_TEE_ICICLE_DEVICE=CPU` → icicle-CPU (sanity; should ≈ ark/rapidsnark).
- `NYX_TEE_PROVER=icicle NYX_TEE_ICICLE_DEVICE=CUDA` → the GPU win.

Record the table in `crates/nyx-tee-loadgen/BENCHMARK.md` (the ICICLE section already has the
Phase-1 CPU rows; add the CVM GPU row + the speedup).

---

## 6. Phase 2b — GPU attestation (the full trust model)

**Goal:** prove to a client that order intent runs on **genuine, CC-mode** GPU silicon — i.e. fold
the NVIDIA GPU attestation into our existing `/attestation` (which today returns only the Intel TDX
quote) and build the client verifier.

### What we already know
- Our `GET /attestation?reportData=<hex>` (`crates/nyx-tee/src/api/attestation.rs`) returns the TDX
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
- **TEE side** (`crates/nyx-tee/src/api/attestation.rs` + `state.rs`): add a `nvidia_payload` field
  to `AttestationResponse`, gathered via the mechanism from 2b.1, bound to the **same** caller nonce.
- **SDK client verifier** (`packages/sdk/src/...`, per `docs/tee-attestation-flow.md` §4 — currently
  spec-only): `verifyTeeAttestation(apiBaseUrl, expectedComposeHash)` that checks, against a fresh
  nonce: NRAS verdict ✔ + the TDX and NVIDIA streams bind the same nonce ✔ + dcap-qvl verifies the
  TDX quote ✔ + `compose_hash` matches ✔ + `tee_pubkey` binds ✔.
- Rebuild a `tee-v3-hardening-37-cuda` image (bump the tag), redeploy, and run the verifier
  end-to-end against the live GPU CVM → single PASS.

---

## 7. STOP the CVM (billing!)

```sh
"$PHALA" cvms stop --cvm-id "$CVM"     # or delete via the dashboard
"$PHALA" cvms list                     # confirm stopped
```
**Never leave the H200 running** — it bills at ~$3.80/GPU/hr. Stopping preserves the app_id / signer
/ volume; deleting reclaims everything.

---

## 8. Gotchas + troubleshooting

| Symptom | Cause / fix |
|---|---|
| `ERR-02-002: No teepod found matching h200.small` | GPU capacity out (our 2026-06-19 blocker). No CVM created, no billing. Use the dashboard / wait. |
| Deploy errors on image pull | ghcr `nyx-tee` package not public → make it public. |
| `set_device(CUDA)` fails at runtime | GPU driver (`libcuda.so.1`) not injected (GPU passthrough not wired) OR the CUDA-toolkit minor (12.6 baked) is newer than the H200 host driver. Check `nvidia-smi`; if a driver-version mismatch, rebuild the image pinning a CUDA minor within the host driver's window (`deploy/Dockerfile` `cuda-*-12-6` → adjust). |
| CC mode `ConfComputeMode : OFF` | The instance isn't in CC mode — the privacy guarantee is void. Re-provision a CC-enabled H200 (this is the whole point; do not run real order intent on a non-CC GPU). |
| Witness/settle errors but prove works | unrelated to GPU — same settle pipeline as CPU; check the mint regime + tree reset (step 2). |
| `StaleMerkleRoot (6004)` | tree drifted — re-run `scripts/reset-merkle-tree.mjs` + bump `NYX_TEE_SYNC_FROM_SLOT`. |
| Want to A/B without a rebuild | flip `NYX_TEE_PROVER` / `NYX_TEE_ICICLE_DEVICE` via env + restart — the image ships rapidsnark + icicle(CPU+CUDA). |

---

## 9. Re-validate the CUDA image only if these change

The image `tee-v3-hardening-36-cuda` is current. Rebuild (new `-cuda` tag → CI) only if you touch:
`crates/nyx-tee/src/**`, the circuits, `deploy/Dockerfile`, `third_party/icicle-snark/**`, or
`Cargo.lock`. Trigger: `git tag tee-v3-hardening-<N>-cuda && git push origin tee-v3-hardening-<N>-cuda`
(CI builds the CUDA image on any `-cuda`-suffixed tag, no GPU runner needed), then point the compose
`image:` at the new tag. The CI verify step re-checks the backend `.so` + linking.
