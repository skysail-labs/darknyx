/**
 * PDA seed constants mirroring `programs/vault/src/state.rs::SEED`.
 * Keep these in lock-step with the on-chain program.
 */

const enc = (s: string) => new TextEncoder().encode(s);

export const VAULT_CONFIG_SEED = enc("vault_config");
export const WALLET_SEED = enc("wallet");
export const NULLIFIER_SEED = enc("nullifier");
export const CONSUMED_NOTE_SEED = enc("consumed_note");
export const NOTE_LOCK_SEED = enc("note_lock");
export const VAULT_TOKEN_SEED = enc("vault_token");
export const OUTSTANDING_MINT_SEED = enc("outstanding_mint");
export const VALID_CREATE_MARKER_SEED = enc("valid_create");
export const VALID_PRICE_MARKER_SEED = enc("valid_price");

export const DARK_CLOB_SEED = enc("dark_clob");
export const MATCHING_CONFIG_SEED = enc("matching_config");
export const BATCH_RESULTS_SEED = enc("batch_results");
export const PENDING_ORDER_SEED = enc("pending_order");
