//! Pipeline driver: builds the 4 txs (verify_match_batch +
//! per-batch ALT create/extend + N concurrent settles + close)
//! and submits via solana-client. Mirrors
//! `packages/sdk/tests/helpers/batched-settle.ts::settleBatchViaBatched`.
