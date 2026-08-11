# Separate trader-host deployment

The browser origin is deliberately **not** a service in the Phala compose. It
serves public code, terminates browser sessions, retains the private Helius URL,
and provisions isolated non-admin CVM accounts. Putting it inside the CVM would
couple frontend releases to the attested matcher image and expand the enclave's
internet-facing attack surface without protecting users from a malicious web
release.

`docker-compose.devnet.yaml` preserves the production topology on devnet: one
ordinary host process proxies the browser to the separately deployed CVM. A TLS
reverse proxy should terminate the public origin and forward to
`127.0.0.1:8080`; it must preserve `Origin`, `Sec-Fetch-Site`, WebSocket upgrade,
and `Set-Cookie` headers.

## Required release and secret mounts

The static mount is an assembled, reviewed release containing `index.html`,
`release.json`, hashed application assets, and the signed proving-artifact set.
The runtime never builds or signs assets at startup.

Build and assemble that directory offline before deployment. The assembly step
requires the six circuit build outputs and an Ed25519 PKCS#8 signing key; the
example leaves the deployment-specific pins explicit:

```sh
npm -w @darknyx/browser-client run build:app
DARKNYX_CLIENT_ARTIFACT_SIGNING_KEY_PKCS8_B64="$OFFLINE_RELEASE_KEY" \
  npm -w @darknyx/browser-client run assemble:release -- \
    --origin=https://trade.example \
    --release-id=<reviewed-release-id> \
    --venue-id=<opaque-venue-id> \
    --vault-program-id=<deployed-vault-program> \
    --expected-compose-hash=<64-lowercase-hex> \
    --artifact-key-id=<reviewed-key-id> \
    --circuit-version=<reviewed-circuit-version> \
    --proving-key-version=<reviewed-proving-key-version>
```

The signer is an offline release key, not the wallet, vault upgrade authority,
or CVM signer. Do not place it in the runtime environment or secrets mount.

Create the secret directory with mode `0700`; every file must be a regular,
non-symlink file with mode `0600` and owned by the runtime UID (`1101` in the
container):

- `cookie.key`: one independent 32-byte canonical base64url key.
- `account-store.key`: a different 32-byte canonical base64url key.
- `admin.json`: exactly `api_key`, `api_secret`, and `passphrase` for the CVM
  bootstrap admin.
- `rpc.url`: the complete private Helius URL, including its query credential.

The encrypted browser-account mapping is written beneath the state mount. Do
not place it on ephemeral storage: losing it can strand existing browser
sessions from their CVM accounts, while restoring an old copy can resurrect
revoked credentials.

Run a fail-closed configuration check before opening traffic:

```sh
docker compose -f deploy/trader-host/docker-compose.devnet.yaml run --rm \
  trader-host node packages/trader-host/dist/bin.js --check-config
```

Then start it independently of the CVM:

```sh
docker compose -f deploy/trader-host/docker-compose.devnet.yaml up -d trader-host
curl -fsS http://127.0.0.1:8080/healthz
```

For a live devnet rehearsal, first run the env-gated host integration test. It
creates one isolated CVM account and proves the same-origin cookie, token
exchange, finalized RPC proxy, instrument/status reads, and `/v1/stream` login
round trip:

```sh
RUN_CVM_BROWSER_E2E=1 DARKNYX_TRADER_LIVE_ORIGIN=http://localhost:8080 \
  npm -w @darknyx/trader-host test -- --run tests/live-cvm.test.ts
```

Then run the production Chrome gate documented in
`packages/browser-client/README.md`. Both are intentionally opt-in and require
the separately deployed CVM to be running.

For production, build `packages/trader-host/Dockerfile` from the repository
root, publish it under a unique release tag, resolve the manifest digest, and
deploy only `image@sha256:…`. The development compose's local `build:` is not a
production image-identity policy.
