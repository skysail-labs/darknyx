# Darknyx namespace contract

Darknyx is the sole current product name. Use these spellings consistently:

| Surface | Canonical form |
|---|---|
| Product prose | `Darknyx` |
| Machine names, paths, crates, binaries and images | `darknyx` |
| Rust module prefix | `darknyx_` |
| npm scope | `@darknyx/` |
| Environment-variable prefix | `DARKNYX_` |

The July 2026 rename is an intentional clean break made before active users or
value-bearing deposits existed. There are no runtime aliases for the former
configuration, package, binary or API names. Development notes, roots, orders,
signatures, recovery envelopes, seed backups, API tokens and CVM signer keys
from before the cutover are invalid.

## Protocol namespace versions

Cross-language consumers must use the current domains byte-for-byte:

| Contract | Current domain |
|---|---|
| Order signature | `darknyx-order-v5` |
| Cancel signature | `darknyx-cancel-v2` |
| Settlement signature | `darknyx-match-v10` |
| Settlement ID | `darknyx-settlement-id-v2` |
| Match-derived inner | `darknyx-change-inner-v2` |
| Fill encryption | `darknyx-fill-enc-v3` |
| HD order ID | `darknyx-order-id-v2` |
| Viewing encryption key | `darknyx-viewing-enc-v2` |
| Recovery trailer | `DNYXREC3` |
| Seed-backup format/AAD | `darknyx-master-seed-backup`, version 2 |
| CVM shard signer | `darknyx/ed25519-signer/v2/{tree_id}` |
| CVM JWT secret | `darknyx/jwt-secret/v2` |

Changing any row is a protocol migration. Update every Rust, TypeScript and
on-chain consumer, regenerate fixed vectors, rebuild the vault program and CVM
image, and reset the development deployment.

## Historical exclusions

Original audit reports, the security-remediation evidence ledger, the captured
pre-cutover dstack event-log fixture, and the external `icicle-snark` submodule
branch retain their historical spelling.
They are evidence or external identifiers, not current product surfaces.
`scripts/check-brand-namespace.sh` excludes only those locations and rejects the
former prefix everywhere else.

> **⚠️ The submodule exclusion is narrow — it covers the fork's BRANCH NAME and
> genuinely upstream identifiers, NOT interfaces we ourselves added to the fork.**
> Anything we invented (env vars, build knobs, patches) is a current product
> surface and **does follow the rename**, even though it lives under
> `third_party/`.
>
> This distinction was not spelled out, and it cost a GPU image build on
> 2026-07-21: `NYX_ICICLE_CUDA_ARCH` — a knob *we* added to the fork
> (`build.rs`, "darknyx-monorepo addition over upstream icicle") — was treated as
> an excluded external identifier and left un-renamed, while the Dockerfile that
> feeds it was renamed. The name silently stopped matching, cmake fell back to
> probing for a GPU, and the build failed.
>
> That var is now `DARKNYX_ICICLE_CUDA_ARCH` (the fork accepts the old spelling
> as a deprecated, warning fallback so a stale submodule pointer cannot silently
> break), and `scripts/check-icicle-cuda-arch-env.sh` fails CI if the Dockerfile
> and the pinned `build.rs` ever disagree again. **When excluding a path from the
> rename, exclude upstream identifiers — not your own interfaces.**
