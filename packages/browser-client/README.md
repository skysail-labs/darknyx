# `@darknyx/browser-client`

Production browser implementation of Darknyx's narrow custody lifecycle.

The UI can provision, unlock, lock, back up, and restore the note credential.
The 64-byte seed remains in a dedicated bundled Worker; IndexedDB receives only
AES-256-GCM ciphertext wrapped by a WebAuthn-PRF-derived, non-extractable key.
The portable backup is the existing version-2 scrypt envelope.

This boundary reduces accidental secret exposure to UI components. It does not
protect against malicious JavaScript delivered by the trusted application
origin; origin and release integrity remain part of the browser custody model.

The package deliberately exports no raw seed, generic signing, arbitrary
proving, note-opening, or witness API.

The trusted product-composition entrypoint establishes venue identity before it
requests a trading token. It reads `VaultConfig` and every advertised
`MarketConfig` at finalized commitment, verifies the TDX quote against the
release-pinned compose hash and finalized shard-0 key, requires exact equality
between the quote-bound and governed signer sets, and rejects instrument fields
that differ from governance. The SDK attestation core uses environment-neutral
noble SHA-256/SHA-384 primitives; this is a real browser path, not a Node crypto
polyfill.

The browser never receives a CVM API secret or passphrase. A relative,
same-origin `/api/darknyx/session` broker maps the release's opaque `venue_id`
to server-held credentials and returns only a short-lived bearer token. The
broker endpoint cannot be configured cross-origin. External wallets are
discovered through Wallet Standard and are used only for bounded, explicitly
user-approved Solana transactions; they are not the Darknyx note seed or a
generic message signer.

The `@darknyx/browser-client/ui` entrypoint is the product-owned trader
workspace. It consumes page-safe snapshots and narrow actions only: formatted
aggregate balances, opaque proof readiness, explicit venue/vault/wallet state,
and durable order-lifecycle states. It cannot import inventory internals or
initiate proving. A disabled ticket always names the blocking trust, market,
vault, or proof condition; ambiguous settlement remains visible as
“Reconciling” and is never presented as a failed or reusable order.

Import `@darknyx/browser-client/ui.css` once at the dedicated application root.
The stylesheet carries the Warm Horizon tokens and responsive 1280/768/375
layouts but performs no third-party font fetch. Production should self-host the
OFL-licensed Newsreader, Inter, and IBM Plex Mono files on the same origin; the
system fallbacks are usable during integration. The root `brand.md` records the
product rules. The reference-only `design-system/` directory is not a package
dependency and must not be committed with this stack.

Run `npm -w @darknyx/browser-client run build:preview`, then serve the package
directory and open `/tests/ui-preview.html` to inspect the exact standalone
workspace fixture. The preview build emits both `dist/ui-preview.js` and
`dist/ui-preview.css`; production consumers still import the separate
`@darknyx/browser-client/ui` and `@darknyx/browser-client/ui.css` exports.

The internal composition bundle now also contains the inventory plane. It
reconstructs notes from finalized chain transactions inside the custody Worker,
checks every recovered opening and tag, filters historical ancestors through
the finalized `ConsumedNoteEntry` PDA, and persists notes, ready proofs, roots,
and reservations as one authenticated ciphertext. Inventory encryption and
decryption stay inside the custody Worker, so explicit or inactivity lock also
revokes note-database access. Page code receives aggregate balances and opaque
proof/reservation handles only.

`VALID_INPUT` proofs are cached by the exact
`(commitment, note-use tag, shard, root, circuit version, proving-key version)`
tuple. The root synchronizer reads the finalized on-chain ring in newest-first
order; evicted roots become stale, ageing roots trigger background refresh, and
the TEE inclusion response must equal the finalized refresh target before any
private witness is built. Reservation writes are serialized and durable before
authorization, including across reloads and ambiguous transport outcomes.

The `@darknyx/browser-client/internal` entrypoint is for the trusted product
composition only. It persists a never-reused HD order index before asking the
custody Worker for a typed order or cancel signature, then stores the order
lifecycle in the same encrypted inventory. The React-facing `TraderProduct`
observes only `TraderShellSnapshot` plus narrow actions; it never receives the
inventory, prover, note openings, witnesses, or signing keys.

The same trusted composition owns account operations. Deposit recovery indices
are persisted before use, and the custody Worker derives the deposit opening;
withdraw and merge witnesses are likewise prepared there. The adapter compares
all Groth16 public inputs with the exact instruction fields before giving a
bounded versioned transaction to Wallet Standard. A withdrawal intentionally
consumes one exact note. If no note equals the requested amount, the account UI
asks the user to consolidate two to four notes on one Merkle shard first. A
wallet rejection releases the reservation, while any transaction for which the
wallet returned a signature remains reserved until finalized reconciliation
decides it. The UI therefore never treats an RPC timeout as proof of failure.

Account recovery uses the existing encrypted version-2 seed envelope. Export
downloads ciphertext JSON only; restore is available only for an unprovisioned
browser vault and is followed by finalized seed-plus-chain inventory recovery.

Orders and fills use one in-band-authenticated `/v1/stream` connection with
short-lived token refresh and cancel-on-disconnect. Stream updates are treated
as notifications rather than durable authority: fills, unknown updates,
sequence gaps, and lag closures trigger a deduplicated finalized-chain
reconciliation. Recovery checks both `ConsumedNoteEntry` and `NoteLock` PDAs in
the note-use-tag namespace. This keeps confirmed ancestors consumed and keeps
partial-fill continuations or failed-settlement inputs unavailable until their
on-chain locks are actually gone.

The internal product-composition bundle also supplies all six client Groth16
provers. It accepts only an Ed25519-signed artifact manifest matching the exact
release-pinned signer key, artifact-set ID, protocol version, circuit set, and
public-input arities. WASM, zkey, and verification-key bytes are bounded and
SHA-256 checked before entering snarkjs; cached bytes are rechecked. Proofs are
locally verified before their on-chain byte encoding leaves the Worker.

The serving origin must use `COOP: same-origin`, `COEP: require-corp`, and a CSP
that allows its static scripts plus `wasm-unsafe-eval`. The latter permits
WebAssembly compilation, not JavaScript eval. snarkjs's generated curve Workers
also require `worker-src 'self' blob:` and the
`darknyx-snarkjs-worker` Trusted Types policy installed inside the pinned prover
Worker. Nested concurrency is capped at four.

The same CSP should set `default-src 'none'`, `script-src 'self'
'wasm-unsafe-eval'`, `worker-src 'self' blob:`, `connect-src 'self'
https://<pinned-gateway> https://<pinned-rpc>`, `style-src 'self'`, `font-src
'self'`, `img-src 'self' data:`, `form-action 'none'`, `base-uri 'none'`,
`object-src 'none'`, `frame-ancestors 'none'`, and
`require-trusted-types-for 'script'`. Deployment must replace the endpoint
placeholders with the reviewed release pins; a wildcard is not an acceptable
substitute.

`artifacts/client-artifacts.v1.payload.json` is the reviewed release payload.
`scripts/verify-artifact-payload.mjs` checks it against all six local build
outputs. The release pipeline signs those exact payload bytes with
`scripts/sign-artifact-manifest.mjs`; the private Ed25519 key is supplied only
through `DARKNYX_CLIENT_ARTIFACT_SIGNING_KEY_PKCS8_B64` and is never stored in
the repository.
