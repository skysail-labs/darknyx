# `@darknyx/trader-host`

Production-origin boundary for the Darknyx browser trader. It serves a reviewed
static build and `release.json`, applies the required cross-origin isolation,
CSP/Trusted Types, HSTS and browser capability headers, and owns the same-origin
session plus live-data boundary.

The public release points the browser at same-origin `/api/darknyx/venue/` and
`/api/darknyx/rpc` URLs. The host proxies only an explicit allowlist of user CVM
routes, finalized/read-only Solana JSON-RPC methods, the shared `/v1/stream`
WebSocket, and signature-status subscriptions. The private Helius query key and
the assigned CVM endpoint remain server-side; admin CVM routes and transaction
submission through the RPC proxy are rejected. Configure both upstreams or
neither—there is no partial proxy mode.

`POST /api/darknyx/session/start` creates only a signed HttpOnly browser
session, allowing finalized governance and attestation reads through those
proxies. It does not provision a CVM account. The browser calls
`POST /api/darknyx/session` for a bearer token only after those trust checks
pass.

The host intentionally does **not** accept one CVM API key/secret/passphrase
from environment variables. TEE order and fill streams are account-scoped, so a
shared credential would leak lifecycle notifications between visitors and let
one visitor exhaust another's rate/connection allowance. Callers must provide
an `IsolatedTokenIssuer` backed by a durable server-side mapping from the signed
HttpOnly browser session to one CVM account. Within one running host process,
the host detects and refuses an issuer that reuses one account ID across two
live browser sessions. This bounded runtime tripwire resets on restart and does
not span load-balanced instances; the durable guarantee comes from the issuer.
The issuer
may call the CVM's `/auth/token`, but long-lived credentials never enter the
public release manifest or browser response.

`createCvmTokenIssuer` implements the final `/auth/token` exchange once the
deployment supplies `resolveCredentials(sessionId, venueId)`. That resolver is
the deliberately explicit integration seam for an encrypted database or
managed secret store; it must durably return a different CVM account for each
browser session. There is no environment-variable shortcut that could silently
collapse all visitors into one account.

New signed `__Host-` sessions are throttled per trusted client key (remote
address by default, or a proxy-normalized identity supplied by the deployer).
The issuer must apply its own authenticated account-creation limits as well;
the edge throttle is defense in depth, not an identity system.

`createProvisioningCredentialResolver` is the deployable reference resolver.
It creates one deterministic account name with fresh random credentials per
signed browser session, registers it as a non-admin account through a
server-held admin credential, and persists the mapping in an AES-256-GCM file
written with owner-only permissions. A pending-before-register state makes an
interrupted provision resumable without silently replacing credentials. The
file and its parent directory are synchronized before a provision succeeds, so
an acknowledged mapping survives a host crash on supported production filesystems. Set a
finite `maxAccounts`; a public deployment still needs an authenticated or
rate-limited admission policy and an operator retention process because the TEE
does not currently expose account deletion.

Static build filenames should contain at least 16 lowercase hex characters of
their content hash. Those assets receive one-year immutable caching;
`index.html` is revalidated and `release.json` is always `no-store`. Deploy only
behind TLS with the configured canonical origin, and make the reverse proxy
preserve `Origin`, `Sec-Fetch-Site`, and `Set-Cookie` semantics.

This package is the host contract, not a claim of launch qualification. A
release still needs physical-passkey coverage, the real wallet matrix under
COOP/COEP, x86 proving distributions, an external frontend/supply-chain review,
and a live venue recovery drill.
