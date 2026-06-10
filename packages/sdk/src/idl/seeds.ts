/**
 * PDA seed constants mirroring `programs/vault/src/state.rs::SEED`.
 * Keep these in lock-step with the on-chain program.
 */

const enc = (s: string) => new TextEncoder().encode(s);

export const VAULT_CONFIG_SEED = enc("vault_config");
/** Per-shard `MerkleTree` account seed: `[b"merkle_tree", &[tree_id]]`. */
export const MERKLE_TREE_SEED = enc("merkle_tree");
export const WALLET_SEED = enc("wallet");
export const NULLIFIER_SEED = enc("nullifier");
export const CONSUMED_NOTE_SEED = enc("consumed_note");
export const NOTE_LOCK_SEED = enc("note_lock");
export const VAULT_TOKEN_SEED = enc("vault_token");
export const OUTSTANDING_MINT_SEED = enc("outstanding_mint");
// v3.1 `valid_create` + `valid_price` per-match seeds were removed in
// Phase 1c-hard. Both markers got subsumed by a single
// `BatchValidityMarker` (one per batch, keyed by Merkle root).
export const BATCH_VALIDITY_MARKER_SEED = enc("batch_validity");

export const DARK_CLOB_SEED = enc("dark_clob");
export const MATCHING_CONFIG_SEED = enc("matching_config");
export const BATCH_RESULTS_SEED = enc("batch_results");
export const PENDING_ORDER_SEED = enc("pending_order");
