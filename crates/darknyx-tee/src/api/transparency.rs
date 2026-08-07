//! `GET /transparency` — public, unauthenticated proof-of-reserves +
//! engine identity + aggregate stats. Wire contract:
//! `docs/tee-api-openapi.yaml`.
//!
//! The headline is **reserves**: for each market mint, the on-chain
//! `OutstandingMint.outstanding` (sum of un-spent note value) vs the
//! vault's actual SPL `vault_balance`. The v2 solvency invariant is
//! `vault_balance >= outstanding`; anyone can verify it here without
//! trusting the TEE (and can re-derive both directly from Solana). The
//! Merkle shard roots + counts come from the in-memory mirror.
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
use futures_util::future::join_all;
use serde::Serialize;

use sha2::{Digest, Sha256};
use solana_address::Address;
use std::sync::LazyLock;

use super::state::ApiState;
use crate::settle::vault::{outstanding_mint_pda, vault_program_id, vault_token_account_pda};
use crate::solana_rpc::SolanaRpcClient;

/// SPL Token program — the owner every vault token account must have.
fn spl_token_program_id() -> Address {
    Address::from_str_const("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
}

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
pub const RESERVE_CACHE_TTL: Duration = Duration::from_millis(400);

/// Cached reserve snapshot: the rendered per-mint rows plus when they were read.
#[derive(Debug, Clone)]
pub struct ReserveCache {
    per_mint: Vec<PerMintReserve>,
    read_at: Instant,
}

impl ReserveCache {
    fn is_fresh(&self, ttl: Duration) -> bool {
        self.read_at.elapsed() < ttl
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

/// One shard's mirror state.
#[derive(Debug, Clone, Serialize)]
pub struct ShardRoot {
    pub tree_id: u8,
    pub merkle_root: String,
    pub leaf_count: u64,
}

#[derive(Debug, Serialize)]
pub struct Reserves {
    /// Per-shard roots + counts. There is no single global root — each shard
    /// has its own — so this is the only lossless form.
    ///
    /// SW-06: this used to be a bare `merkle_root` (shard 0's) sitting beside a
    /// `leaf_count` (the all-shard SUM). The code comment said so, but as two
    /// adjacent public fields they read as a matched pair, and a consumer that
    /// folded the count against that root would get a root the tree never had.
    /// The names now say which is which.
    pub shards: Vec<ShardRoot>,
    /// Shard 0's root, kept for pre-sharding consumers. Prefer `shards`.
    pub shard0_merkle_root: String,
    /// Total notes across ALL shards — not the leaf count under
    /// `shard0_merkle_root`.
    pub total_leaf_count: u64,
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
        if cached.is_fresh(state.reserve_cache_ttl) && cached.per_mint.len() == mints.len() {
            return cached.per_mint.clone();
        }
    }

    // Preserve caller order while allowing every mint's independent account
    // reads to share one network-latency window (PF-14).
    let per_mint = join_all(mints.iter().map(|mint| read_reserve(rpc, mint))).await;
    *cache = Some(ReserveCache {
        per_mint: per_mint.clone(),
        read_at: Instant::now(),
    });
    per_mint
}

/// `sha256("account:OutstandingMint")[..8]`.
static OUTSTANDING_MINT_DISCRIMINATOR: LazyLock<[u8; 8]> = LazyLock::new(|| {
    let hash = Sha256::digest(b"account:OutstandingMint");
    let mut d = [0u8; 8];
    d.copy_from_slice(&hash[..8]);
    d
});

/// Whether an account really is the vault-owned Anchor account we think it is
/// (SW-05).
///
/// The addresses here are PDA-derived, so this is not currently exploitable —
/// but the endpoint publishes a **solvency claim**, and `stale` is documented
/// to mean "these numbers are unknown, do not read the 0 as a healthy empty
/// reserve". Reading offsets out of whatever bytes came back, without checking
/// the account is the vault's and carries the right discriminator, is how a 0
/// from some other account would be published as a real balance. This is the
/// same F-08 check the vault applies to its own raw marker reads.
fn owned_and_tagged(
    acc: &crate::solana_rpc::RpcAccountInfo,
    expected_discriminator: Option<&[u8; 8]>,
    expected_owner: &Address,
) -> bool {
    if acc.owner != *expected_owner {
        return false;
    }
    match expected_discriminator {
        Some(d) => acc.data.len() >= 8 && &acc.data[..8] == d.as_slice(),
        // SPL token accounts carry no Anchor discriminator; ownership by the
        // token program plus the fixed layout is the whole check available.
        None => true,
    }
}

async fn read_reserve(rpc: &SolanaRpcClient, mint: &[u8; 32]) -> PerMintReserve {
    let (om_pda, _) = outstanding_mint_pda(mint);
    let (vt_pda, _) = vault_token_account_pda(mint);
    let (outstanding_account, vault_account) =
        tokio::join!(rpc.get_account_info(&om_pda), rpc.get_account_info(&vt_pda));

    let mut stale = false;
    let outstanding = match outstanding_account {
        Ok(Some(acc))
            if !owned_and_tagged(
                &acc,
                Some(&OUTSTANDING_MINT_DISCRIMINATOR),
                &vault_program_id(),
            ) =>
        {
            tracing::warn!(
                "transparency: outstanding_mint is not a vault-owned OutstandingMint account"
            );
            stale = true;
            0
        }
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
    let vault_balance = match vault_account {
        Ok(Some(acc)) if !owned_and_tagged(&acc, None, &spl_token_program_id()) => {
            tracing::warn!("transparency: vault_token_account is not SPL-token-owned");
            stale = true;
            0
        }
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
    let (shards, shard0_merkle_root, total_leaf_count) = {
        let mut shards = Vec::with_capacity(state.merkle_mirrors.len());
        let mut total = 0u64;
        for (tree_id, shard) in state.merkle_mirrors.iter().enumerate() {
            let m = shard.read().await;
            let count = m.leaf_count();
            total += count;
            shards.push(ShardRoot {
                tree_id: tree_id as u8,
                merkle_root: hex::encode(m.root()),
                leaf_count: count,
            });
        }
        let shard0 = shards
            .first()
            .map(|s| s.merkle_root.clone())
            .unwrap_or_default();
        (shards, shard0, total)
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
            shards,
            shard0_merkle_root,
            total_leaf_count,
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
