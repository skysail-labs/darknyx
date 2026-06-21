# `deploy/` — Phala Cloud deployment artifacts for `nyx-tee`

Three files here, all of which are hashed into the `compose_hash`
recorded in RTMR3 inside the CVM:

| File | Purpose |
|---|---|
| `Dockerfile` | Multi-stage Rust build → slim Debian runtime. |
| `docker-compose.yaml` | The dstack manifest — services, volumes, env-var whitelist. |
| `.dockerignore` | Keeps the build context tight + reproducible. |

## Cardinal rule

**Every byte in these files affects `compose_hash`.** Changing the
base image tag, adding an env var, reordering services — all change
`compose_hash`. A new `compose_hash` requires:

1. A new image authorization in Phala Cloud (dashboard or CLI).
2. A new TDX quote whose RTMR3 contains the new hash.
3. A multisig-signed `set_tee_pubkey` Solana tx, because the
   dstack-kms-derived signing key changes when `app_hash` changes.

The full rotation ceremony lives in
[`docs/tee-attestation-flow.md`](../docs/tee-attestation-flow.md) §5.

## Build + deploy

Once you've authenticated the CLI (`phala login`):

```sh
# Smoke-deploy under a disposable name (Phase 1 only — no real
# liquidity, no rotation ceremony):
phala deploy -c deploy/docker-compose.yaml -n nyx-tee-spike

# Check status:
phala cvms get nyx-tee-spike

# Live logs:
phala logs --cvm-id nyx-tee-spike

# Tear down when done (saves storage credits):
phala cvms delete nyx-tee-spike
```

For local iteration without burning credits, use the dstack
simulator instead — see `scripts/dstack-simulator-start.sh`.

## Why are env vars not in the file?

Operational secrets (Helius RPC URL + API key, DNS provider token,
etc.) get encrypted client-side via the Phala dashboard and decrypted
inside the CVM at start. **Never** commit a plaintext secret to this
file — even a placeholder. Same goes for default RPC URLs that
look "harmless": the convenience leak compounds.

## Pinning by digest (Phase 2 work)

For mainnet, every image in this file must use `@sha256:<digest>`
not a tag. The `phala-cloud/attestation/verify-your-application.mdx`
docs explain why: tags are mutable, digests are not, and a digest
mismatch is detectable at boot. Phase 1 we use tags for iteration
speed.
