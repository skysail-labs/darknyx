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

`artifacts/client-artifacts.v1.payload.json` is the reviewed release payload.
`scripts/verify-artifact-payload.mjs` checks it against all six local build
outputs. The release pipeline signs those exact payload bytes with
`scripts/sign-artifact-manifest.mjs`; the private Ed25519 key is supplied only
through `DARKNYX_CLIENT_ARTIFACT_SIGNING_KEY_PKCS8_B64` and is never stored in
the repository.
