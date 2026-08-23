/**
 * PDA seed constants mirroring `programs/vault/src/state.rs::SEED`.
 * Keep these in lock-step with the on-chain program.
 */

const enc = (s: string) => new TextEncoder().encode(s);

export const VAULT_CONFIG_SEED = enc("vault_config");
/** Mint-pair market seed: `[b"market_config", base_mint, quote_mint]`. */
export const MARKET_CONFIG_SEED = enc("market_config");
/** Per-shard `MerkleTree` account seed: `[b"merkle_tree", &[tree_id]]`. */
export const MERKLE_TREE_SEED = enc("merkle_tree");
export const WALLET_SEED = enc("wallet");
export const CONSUMED_NOTE_SEED = enc("consumed_note");
/** S-05 deposit-once guard: `[b"deposited_note", note_commitment]`. */
export const DEPOSITED_NOTE_SEED = enc("deposited_note");
export const NOTE_LOCK_SEED = enc("note_lock");
export const VAULT_TOKEN_SEED = enc("vault_token");
export const OUTSTANDING_MINT_SEED = enc("outstanding_mint");
// There are no per-match validity seeds. Batch validity is a single
// `BatchValidityMarker`, one per batch, keyed by the batch's Merkle root.
export const BATCH_VALIDITY_MARKER_SEED = enc("batch_validity");

// A seed belongs here only while `programs/vault/src/state.rs` still declares
// it (SW-25). If one looks "missing", check there before adding it back: a seed
// with no owning program derives an address nothing will ever own, and the
// mistake surfaces far away as `AccountNotFound` / `ConstraintSeeds (2006)`
// rather than at build time.
