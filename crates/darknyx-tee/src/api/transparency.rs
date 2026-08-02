//! `GET /transparency` — public, unauthenticated proof-of-reserves +
//! engine identity + aggregate stats. Wire contract:
//! `docs/tee-api-openapi.yaml`.
//!
//! The headline is **reserves**: for each market mint, the on-chain
//! `OutstandingMint.outstanding` (sum of un-spent note value) vs the
//! vault's actual SPL `vault_balance`. The v2 solvency invariant is
//! `vault_balance >= outstanding`; anyone can verify it here without
//! trusting the TEE (and can re-derive both directly from Solana). The
//! Merkle `merkle_root` + `leaf_count` come from the in-memory mirror.
//!
//! `tee` carries the engine's attestation IDENTITY (app/compose/mrtd +
//! signer pubkey) — enough to tie this response to a measured image;
//! the full challenge-response quote lives at `/attestation`. `stats`
//! reports the settle-scheduler counters tracked today (24h windows +
//! finality timing are a later addition).
//!
//! Best-effort: a missing Solana RPC client in isolated tests
//! yields empty `per_mint` reserves rather than failing the endpoint —
//! the mirror + identity + stats are still served.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{extract::State, Json};
use serde::Serialize;

use super::state::ApiState;
use crate::settle::vault::{outstanding_mint_pda, vault_token_account_pda};
use crate::solana_rpc::SolanaRpcClient;

/// How long a reserve snapshot is reused before the chain is read again.
///
/// SW-02: this route is **public and unauthenticated** and issued
/// `2 x N_mints` Solana RPC calls on **every** request, against the same
/// provider quota the settle pipeline depends on. That turned cheap HTTP into
/// metered upstream consumption — and exhausting that quota is the first link
/// in the chain the sweep describes (settle failures -> SW-03's unbounded loop
/// -> SW-01's credential in an error string).
///
/// The underlying values change at most once per slot (~400 ms), so a TTL at
/// roughly one slot removes the amplification entirely without making the
/// answer meaningfully staler than it already was: the response was never
/// atomic across mints, and a client that needs a point-in-time guarantee reads
/// the two accounts from Solana itself, which the module header already tells
/// it to do.
const RESERVE_CACHE_TTL: Duration = Duration::from_millis(400);

/// Cached reserve snapshot: the rendered per-mint rows plus when they were read.
#[derive(Debug, Clone)]
pub struct ReserveCache {
    per_mint: Vec<PerMintReserve>,
    read_at: Instant,
}

impl ReserveCache {
    fn is_fresh(&self) -> bool {
        self.read_at.elapsed() < RESERVE_CACHE_TTL
    }
}

/// SPL `TokenAccount.amount` lives at byte 64 (mint@0 + owner@32).
const SPL_AMOUNT_OFFSET: usize = 64;
/// `OutstandingMint.outstanding` lives at byte 40 (8 disc + 32 mint).
const OUTSTANDING_OFFSET: usize = 8 + 32;

#[derive(Debug, Clone, Serialize)]
pub struct PerMintReserve {
    pub mint: String,
    /// Sum of un-spent note value for this mint (decimal string).
    pub outstanding: String,
    /// Actual SPL balance in the vault's PDA for this mint (decimal
    /// string). MUST be >= `outstanding` (v2 solvency invariant).
    pub vault_balance: String,
    /// `true` if either on-chain read was DEGRADED (RPC error or a
    /// malformed account) — the `outstanding` / `vault_balance` `0`s are
    /// then "unknown", NOT a real zero. Consumers checking solvency MUST
    /// ignore the numbers when this is set rather than reading a
    /// fabricated 0 as a healthy/empty reserve.
    pub stale: bool,
}

#[derive(Debug, Serialize)]
pub struct Reserves {
    pub merkle_root: String,
    pub leaf_count: u64,
    pub per_mint: Vec<PerMintReserve>,
}

/// Engine attestation identity. The full quote is at `/attestation`.
#[derive(Debug, Serialize)]
pub struct TeeIdentity {
    pub app_id: String,
    pub compose_hash: String,
    pub mrtd: String,
    pub signer_pubkey: String,
}

#[derive(Debug, Serialize)]
pub struct Stats {
    /// Number of settle batches the scheduler has tracked.
    pub batches: usize,
    /// Number of per-match settle jobs tracked.
    pub jobs: usize,
}

#[derive(Debug, Serialize)]
pub struct TransparencySnapshot {
    pub reserves: Reserves,
    pub tee: TeeIdentity,
    pub stats: Stats,
}

/// Read a little-endian `u64` at `offset` from account data.
fn read_u64_le(data: &[u8], offset: usize) -> Option<u64> {
    let end = offset.checked_add(8)?;
    let slice = data.get(offset..end)?;
    let mut b = [0u8; 8];
    b.copy_from_slice(slice);
    Some(u64::from_le_bytes(b))
}

/// Fetch `(outstanding, vault_balance)` for one mint. A missing account
/// (mint never deposited) is a TRUE 0; an RPC error or malformed account
/// reads as 0 too (logged) so the endpoint still renders, but sets
/// `stale` so a consumer can tell that 0 apart from a real zero.
/// Reserves for `mints`, reusing a snapshot no older than [`RESERVE_CACHE_TTL`].
///
/// Concurrency note: the lock is held across the RPC reads on purpose. Under a
/// flood that is exactly the desired behaviour — the first request in a window
/// does the work and the rest wait for it and share the result, so N concurrent
/// requests cost ONE round of RPC rather than N. Holding a `tokio::Mutex` across
/// an await is safe (it is not the std mutex), and the alternative — dropping
/// the lock to read, then re-acquiring — reintroduces the stampede this exists
/// to prevent.
async fn read_reserves_cached(state: &Arc<ApiState>, mints: &[[u8; 32]]) -> Vec<PerMintReserve> {
    let Some(rpc) = &state.solana_rpc else {
        // No RPC wired (isolated tests): serve the rest of the response with
        // empty reserves, as the module header promises.
        return Vec::new();
    };

    let mut cache = state.reserve_cache.lock().await;
    if let Some(cached) = cache.as_ref() {
        // A mint-set change (a market added at boot) must not serve a snapshot
        // that is missing rows.
        if cached.is_fresh() && cached.per_mint.len() == mints.len() {
            return cached.per_mint.clone();
        }
    }

    let mut per_mint = Vec::with_capacity(mints.len());
    for mint in mints {
        per_mint.push(read_reserve(rpc, mint).await);
    }
    *cache = Some(ReserveCache {
        per_mint: per_mint.clone(),
        read_at: Instant::now(),
    });
    per_mint
}

async fn read_reserve(rpc: &SolanaRpcClient, mint: &[u8; 32]) -> PerMintReserve {
    let (om_pda, _) = outstanding_mint_pda(mint);
    let (vt_pda, _) = vault_token_account_pda(mint);

    let mut stale = false;
    let outstanding = match rpc.get_account_info(&om_pda).await {
        Ok(Some(acc)) => match read_u64_le(&acc.data, OUTSTANDING_OFFSET) {
            Some(v) => v,
            None => {
                tracing::warn!("transparency: outstanding_mint account too short");
                stale = true;
                0
            }
        },
        Ok(None) => 0, // counter PDA not yet created for this mint — TRUE 0
        Err(e) => {
            tracing::warn!(error = %e, "transparency: outstanding_mint read failed");
            stale = true;
            0
        }
    };
    let vault_balance = match rpc.get_account_info(&vt_pda).await {
        Ok(Some(acc)) => match read_u64_le(&acc.data, SPL_AMOUNT_OFFSET) {
            Some(v) => v,
            None => {
                tracing::warn!("transparency: vault_token_account too short");
                stale = true;
                0
            }
        },
        Ok(None) => 0,
        Err(e) => {
            tracing::warn!(error = %e, "transparency: vault_token_account read failed");
            stale = true;
            0
        }
    };

    PerMintReserve {
        mint: bs58::encode(mint).into_string(),
        outstanding: outstanding.to_string(),
        vault_balance: vault_balance.to_string(),
        stale,
    }
}

/// `GET /transparency` — public.
pub async fn get_transparency(State(state): State<Arc<ApiState>>) -> Json<TransparencySnapshot> {
    // Reserves: mirror root/count + per-mint on-chain reads. Post-sharding
    // `leaf_count` is the SUM across all shard mirrors (total notes in the
    // pool); `merkle_root` is shard 0's root (there is no single global root —
    // each shard has its own; clients fetch per-shard roots via /tree/root).
    let (merkle_root, leaf_count) = {
        let root = hex::encode(state.merkle_mirror(0).read().await.root());
        let mut total = 0u64;
        for shard in &state.merkle_mirrors {
            total += shard.read().await.leaf_count();
        }
        (root, total)
    };

    // Unique market mints across all instruments.
    let mut mints: Vec<[u8; 32]> = Vec::new();
    for inst in &state.instruments {
        for m in [inst.base_mint, inst.quote_mint] {
            if !mints.contains(&m) {
                mints.push(m);
            }
        }
    }

    let per_mint = read_reserves_cached(&state, &mints).await;

    let tee = TeeIdentity {
        app_id: state.app_info.app_id.clone(),
        compose_hash: state.app_info.compose_hash.clone(),
        mrtd: state.app_info.mrtd.clone(),
        signer_pubkey: state.signer_pubkey_base58.clone(),
    };

    let stats = match &state.settle_state {
        Some(ss) => {
            let s = ss.read().await;
            Stats {
                batches: s.batch_count(),
                jobs: s.job_count(),
            }
        }
        None => Stats {
            batches: 0,
            jobs: 0,
        },
    };

    Json(TransparencySnapshot {
        reserves: Reserves {
            merkle_root,
            leaf_count,
            per_mint,
        },
        tee,
        stats,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_u64_le_extracts_at_offset() {
        let mut data = vec![0u8; 80];
        data[OUTSTANDING_OFFSET..OUTSTANDING_OFFSET + 8].copy_from_slice(&1234u64.to_le_bytes());
        data[SPL_AMOUNT_OFFSET..SPL_AMOUNT_OFFSET + 8].copy_from_slice(&5678u64.to_le_bytes());
        assert_eq!(read_u64_le(&data, OUTSTANDING_OFFSET), Some(1234));
        assert_eq!(read_u64_le(&data, SPL_AMOUNT_OFFSET), Some(5678));
    }

    #[test]
    fn read_u64_le_rejects_short() {
        // Exactly 8 bytes at offset 0 fits → Some(0).
        assert_eq!(read_u64_le(&[0u8; 8], 0), Some(0));
        // Fewer than 8 bytes available from the offset → None.
        assert_eq!(read_u64_le(&[0u8; 4], 0), None);
        assert_eq!(read_u64_le(&[0u8; 64], 64), None);
    }
}
