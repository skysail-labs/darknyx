# SDK test index

Tests are classified into three buckets by required infrastructure
(`tests/buckets.ts` is the machine-readable source; this file is the
human-readable mirror). Run a bucket with:

```sh
npm run -w packages/sdk test:local    # no infra, no env — the default gate
npm run -w packages/sdk test:devnet   # needs Helius RPC + .devnet/ foundation
npm run -w packages/sdk test:cvm       # needs a RUNNING Phala CVM + devnet
# bare `vitest run` runs all three; devnet/cvm files self-skip without their RUN_* flag

npm run -w packages/sdk typecheck:tests  # type-checks the WHOLE suite (tsconfig.test.json)
                                          # — the static safety net for the CVM tests,
                                          #   which can only RUN against a live enclave.
```

Secrets/config (Helius key, CVM gateway, RUN\_\* flags) load from a gitignored
`packages/sdk/.env` via `tests/setup-env.ts` — see `.env.example`.

## local — pure unit / parity / prover / wire-format (no network, no env gate)

| File                               | Asserts                                                  |
| ---------------------------------- | -------------------------------------------------------- |
| `poseidon-parity.test.ts`          | Poseidon arities TS↔Rust byte-equality                   |
| `note-commitment-parity.test.ts`   | v2 note commitment TS↔Rust                               |
| `nullifier-parity.test.ts`         | v2 nullifier TS↔Rust                                     |
| `keys-parity.test.ts`              | key derivation TS↔Rust                                   |
| `user-commitment-parity.test.ts`   | user commitment TS↔Rust                                  |
| `inner-hash-parity.test.ts`        | change/trade/fee `inner_hash` TS↔Rust                    |
| `change-note-inner-parity.test.ts` | `derive_inner` TS↔Rust                                   |
| `order-canonical-parity.test.ts`   | order/cancel/topup canonical digest TS↔Rust              |
| `build-order-parity.test.ts`       | `buildOrder` canonical digest vs Rust fixture            |
| `valid-input-prover.test.ts`       | VALID_INPUT snarkjs round-trip (needs circuit artifacts) |
| `merge-prover.test.ts`             | VALID_MERGE snarkjs round-trip (needs artifacts)         |
| `match-batch-prototype.test.ts`    | N=2/4 match-batch proof + leaf-byte assert               |
| `deposit-transport.test.ts`        | deposit ix wire/discriminator/Borsh                      |
| `withdraw-transport.test.ts`       | VALID_SPEND withdraw ix wire format                      |
| `settle-builder-batched.test.ts`   | batched settle payload + canonical hash                  |
| `settlement-watcher.test.ts`       | `TradeSettled` event decode                              |
| `settle-memo-integrity.test.ts`    | Vuln-4 client change-note memo guard                     |
| `order-builders.test.ts`           | ExecutionPolicy / order builder helpers                  |
| `order-canonical-parity.test.ts`   | (see above)                                              |
| `order-id.test.ts`                 | deterministic HD order_id derivation                     |
| `order-submission.test.ts`         | order-client / trading-ws-client submit path             |
| `leaf-index.test.ts`               | `leafIndexFromLogs` / `noteCreatedFromLogs` pure parsing |
| `wallet.test.ts`                   | wallet/note-store behaviour                              |
| `helpers/merkle-shadow.test.ts`    | in-memory Merkle shadow witness                          |
| `helpers/snarkjs-prover.test.ts`   | snarkjs prover helper                                    |

## devnet — needs a devnet RPC (Helius) + `.devnet/` foundation

| File                              | Gate                 | Asserts                                                          |
| --------------------------------- | -------------------- | ---------------------------------------------------------------- |
| `devnet-setup.test.ts`            | `RUN_DEVNET_E2E=1`   | rebuilds mints + settle ALT + config → `.devnet/e2e-config.json` |
| `devnet-deposit-withdraw.test.ts` | `RUN_DEVNET_DW=1`    | v2 deposit + VALID_SPEND withdraw round-trip (no CVM)            |
| `devnet-merge.test.ts`            | `RUN_DEVNET_MERGE=1` | deposit → merge(K=2) → withdraw                                  |
| `devnet-leaf-index.test.ts`       | `RUN_DEVNET_LEAF=1`  | event-based leaf-index read vs real RPC                          |

## cvm — needs a RUNNING Phala CVM gateway + devnet (`RUN_CVM_E2E=1` + `NYX_TEE_GATEWAY`)

| File                            | Asserts                                                                                                                                                   |
| ------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cvm-settle-e2e.test.ts`        | deposit 2 real notes → crossing bid+ask → CVM matches + settles → leaf_count +5 (shard-aware)                                                             |
| `cvm-multimatch-settle.test.ts` | N crossing pairs settle across K shards (shard-aware)                                                                                                     |
| `cvm-merge-then-order.test.ts`  | deposit 2 → merge → `buildOrder` off merged note → CVM accepts/settles                                                                                    |
| `cvm-api-surface.test.ts`       | error envelope + X-Request-Id, /system/status, /time, rate-limit 429, /account(+settings), `/v1/stream` in-band login + sequencing, legacy-route deletion |

See `docs/cvm-run-runbook.md` for the full CVM bring-up (build→deploy→rotate→fund→reset→test→stop).
