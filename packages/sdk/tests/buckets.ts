/**
 * Test-bucket manifest — the single source of truth for which SDK tests run
 * where. Consumed by `vitest.config.ts` (the three `test.projects`) and
 * mirrored, one line per file, in `TESTS.md`.
 *
 * Three buckets, by required infrastructure:
 *   - LOCAL  : pure unit / parity / prover / wire-format tests. No network,
 *              no env gate. The default `vitest run` and `test:local` target.
 *   - DEVNET : need a Solana devnet RPC (Helius) + the `.devnet/` foundation
 *              (e2e-config + keypairs). Gated by their own `RUN_DEVNET_*` env
 *              flag (they `describe.skip` themselves when unset).
 *   - CVM    : need a *running* Phala CVM gateway in addition to devnet.
 *              Gated by `RUN_CVM_E2E=1` + `NYX_TEE_GATEWAY`.
 *
 * The convention is encoded as globs so a new `devnet-*.test.ts` /
 * `cvm-*.test.ts` is auto-classified; everything else is LOCAL. The per-file
 * `RUN_*` self-skip stays as the backstop, so a mis-targeted run is safe (it
 * skips), never a hard failure.
 */

/** Devnet-only tests — filename prefix `devnet-`. Gates (per file):
 *   devnet-setup            → RUN_DEVNET_E2E
 *   devnet-deposit-withdraw → RUN_DEVNET_DW
 *   devnet-merge            → RUN_DEVNET_MERGE
 *   devnet-leaf-index       → RUN_DEVNET_LEAF
 */
export const DEVNET_GLOBS = ["tests/devnet-*.test.ts"];

/** Devnet + a running CVM — filename prefix `cvm-`. Gate: RUN_CVM_E2E=1 +
 *  NYX_TEE_GATEWAY. (cvm-settle-e2e, cvm-multimatch-settle, cvm-merge-then-order,
 *  cvm-api-surface.) */
export const CVM_GLOBS = ["tests/cvm-*.test.ts"];

/** Local unit/parity/prover/wire tests — everything that is neither devnet
 *  nor cvm (including `tests/helpers/*.test.ts`). */
export const LOCAL_INCLUDE = ["tests/**/*.test.ts"];
export const LOCAL_EXCLUDE = [...DEVNET_GLOBS, ...CVM_GLOBS];
