//! Cold-boot + live sync of the Merkle mirror against on-chain state.
//!
//! Cold boot walks the vault program's transaction history
//! (`getSignaturesForAddress`, paged backward to genesis), decodes the
//! leaf-append events of each tx ([`super::events`]), applies them to
//! the mirror in `leaf_index` order, and reconciles the resulting root
//! against `VaultConfig.current_root`. The live loop then polls for new
//! signatures on an interval and applies their leaves as settles +
//! deposits confirm.
//!
//! Best-effort, like all TEE persistence (`docs/tee-architecture.md`
//! §8): on-chain is canonical. A reconcile mismatch or an RPC error is
//! logged and retried, never fatal — the `/tree/*` endpoints simply
//! serve a slightly-stale (or, on a hard gap, last-good) view until the
//! next successful sync.

use std::sync::Arc;
use std::time::Duration;

use solana_address::Address;
use tokio::sync::RwLock;

use super::events::extract_appended_leaves;
use super::mirror::{MerkleMirror, MirrorError};
use super::AppendedLeaf;
use crate::settle::settle_batched::SETTLE_BATCHED_DISCRIMINATOR;
use crate::solana_rpc::{RpcError, SolanaRpcClient};

/// `VaultConfig` zero-copy layout offsets (after the 8-byte Anchor
/// discriminator): admin(32) + tee_pubkey(32) + root_key(32) =>
/// leaf_count at 104, current_root at 112.
const VAULT_LEAF_COUNT_OFFSET: usize = 8 + 32 + 32 + 32;
const VAULT_CURRENT_ROOT_OFFSET: usize = VAULT_LEAF_COUNT_OFFSET + 8;

/// RPC page size for `getSignaturesForAddress` (the RPC hard-caps at
/// 1000).
const SIG_PAGE_LIMIT: usize = 1000;

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("rpc: {0}")]
    Rpc(#[from] RpcError),
    #[error("mirror: {0}")]
    Mirror(#[from] MirrorError),
    #[error("leaf gap: mirror expected index {expected} next, got {got} (incomplete history?)")]
    LeafGap { expected: u64, got: u64 },
}

/// Configuration for the sync task.
#[derive(Debug, Clone)]
pub struct MerkleSyncConfig {
    /// Live-poll cadence. ~2 s tracks settle confirmation closely
    /// without hammering the RPC.
    pub poll_interval: Duration,
    /// Cold-boot floor slot — transactions older than this are
    /// skipped. `0` replays from genesis. Set to the program's deploy
    /// slot (or a `reset_merkle_tree` slot on devnet) so the mirror
    /// reconstructs the CURRENT tree instead of double-counting
    /// pre-reset leaves whose indices repeat. See
    /// `Config::sync_from_slot`.
    pub from_slot: u64,
}

impl Default for MerkleSyncConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(2),
            from_slot: 0,
        }
    }
}

/// Drives the Merkle mirror from on-chain state.
pub struct MerkleSync {
    rpc: SolanaRpcClient,
    mirror: Arc<RwLock<MerkleMirror>>,
    vault_program_id: Address,
    vault_config_pda: Address,
    cfg: MerkleSyncConfig,
    /// Newest signature already applied — the live poll stops paging
    /// when it reaches this. `None` until the first sync completes.
    newest_seen: Option<String>,
}

impl MerkleSync {
    pub fn new(
        rpc: SolanaRpcClient,
        mirror: Arc<RwLock<MerkleMirror>>,
        vault_program_id: Address,
        vault_config_pda: Address,
        cfg: MerkleSyncConfig,
    ) -> Self {
        Self {
            rpc,
            mirror,
            vault_program_id,
            vault_config_pda,
            cfg,
            newest_seen: None,
        }
    }

    /// Cold boot: page the full vault history oldest→newest, apply all
    /// leaves, reconcile. Sets `newest_seen` so the live loop continues
    /// from here. Returns the number of leaves applied.
    pub async fn cold_boot(&mut self) -> Result<usize, SyncError> {
        // 1. Page backward toward the `from_slot` floor (or genesis),
        //    collecting (newest-first).
        let mut all_sigs: Vec<(String, u64, bool)> = Vec::new();
        let mut before: Option<String> = None;
        loop {
            let page = self
                .rpc
                .get_signatures_for_address(
                    &self.vault_program_id,
                    before.as_deref(),
                    SIG_PAGE_LIMIT,
                )
                .await?;
            let short = page.len() < SIG_PAGE_LIMIT;
            // Oldest entry of this page (newest-first → last).
            let oldest_slot = page.last().map(|s| s.slot);
            if let Some(last) = page.last() {
                before = Some(last.signature.clone());
            }
            for s in page {
                all_sigs.push((s.signature, s.slot, s.err.is_some()));
            }
            if short {
                break; // short page → history exhausted
            }
            // Early-stop: once a page's oldest slot drops below the
            // floor, every older page is below it too — stop paging.
            if self.cfg.from_slot > 0 && oldest_slot.is_some_and(|s| s < self.cfg.from_slot) {
                break;
            }
        }
        if all_sigs.is_empty() {
            tracing::info!("merkle cold-boot: vault has no transaction history yet");
            return Ok(0);
        }
        let newest = all_sigs.first().map(|(s, _, _)| s.clone());

        // 2. Oldest-first so leaf indices arrive in order.
        all_sigs.reverse();
        let applied = self.apply_signatures(&all_sigs).await?;

        self.newest_seen = newest;
        self.reconcile().await;
        let leaf_count = self.mirror.read().await.leaf_count();
        tracing::info!(applied, leaf_count, "merkle cold-boot complete");
        Ok(applied)
    }

    /// One live-poll step: fetch signatures newer than `newest_seen`,
    /// apply their leaves, advance `newest_seen`. Returns the count
    /// applied this step.
    pub async fn poll_once(&mut self) -> Result<usize, SyncError> {
        let until = self.newest_seen.clone();
        let mut new_sigs: Vec<(String, u64, bool)> = Vec::new();
        let mut before: Option<String> = None;
        loop {
            let page = self
                .get_signatures_until(before.as_deref(), until.as_deref())
                .await?;
            let short = page.len() < SIG_PAGE_LIMIT;
            if let Some(last) = page.last() {
                before = Some(last.0.clone());
            }
            new_sigs.extend(page);
            if short {
                break;
            }
        }
        if new_sigs.is_empty() {
            return Ok(0);
        }
        let newest = new_sigs.first().map(|(s, _, _)| s.clone());
        new_sigs.reverse(); // oldest-first
        let applied = self.apply_signatures(&new_sigs).await?;
        if newest.is_some() {
            self.newest_seen = newest;
        }
        if applied > 0 {
            self.reconcile().await;
        }
        Ok(applied)
    }

    /// Run the live loop forever, polling every `poll_interval`. Errors
    /// are logged and the loop continues (best-effort).
    pub async fn run(mut self) {
        let interval = self.cfg.poll_interval;
        loop {
            tokio::time::sleep(interval).await;
            match self.poll_once().await {
                Ok(n) if n > 0 => tracing::debug!(applied = n, "merkle live-sync applied leaves"),
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "merkle live-sync poll failed; will retry"),
            }
        }
    }

    /// Page `getSignaturesForAddress` with an `until` floor, returning
    /// `(signature, slot, is_err)` newest-first for this page (stopping
    /// when `until` is reached).
    async fn get_signatures_until(
        &self,
        before: Option<&str>,
        until: Option<&str>,
    ) -> Result<Vec<(String, u64, bool)>, SyncError> {
        let page = self
            .rpc
            .get_signatures_for_address(&self.vault_program_id, before, SIG_PAGE_LIMIT)
            .await?;
        let mut out = Vec::with_capacity(page.len());
        for s in page {
            if Some(s.signature.as_str()) == until {
                break;
            }
            out.push((s.signature, s.slot, s.err.is_some()));
        }
        Ok(out)
    }

    /// Fetch + decode each signature's leaves and apply them to the
    /// mirror. `sigs` MUST be oldest-first. Stamps the mirror's
    /// `on_chain_slot` with the highest slot applied.
    async fn apply_signatures(&self, sigs: &[(String, u64, bool)]) -> Result<usize, SyncError> {
        let mut leaves: Vec<AppendedLeaf> = Vec::new();
        let mut max_slot = 0u64;
        for (sig, slot, is_err) in sigs {
            if *slot < self.cfg.from_slot {
                continue; // below the cold-boot floor (pre-deploy / pre-reset)
            }
            if *is_err {
                continue; // reverted tx — its leaves never landed
            }
            let Some(tx) = self.rpc.get_transaction(sig).await? else {
                continue;
            };
            if tx.err.is_some() {
                continue;
            }
            let settle_ix_data = tx
                .instructions
                .iter()
                .map(|ix| ix.data.as_slice())
                .find(|d| d.len() >= 8 && d[..8] == *SETTLE_BATCHED_DISCRIMINATOR);
            let mut tx_leaves = extract_appended_leaves(&tx.log_messages, settle_ix_data);
            if !tx_leaves.is_empty() {
                max_slot = max_slot.max(*slot);
                leaves.append(&mut tx_leaves);
            }
        }

        let mut mirror = self.mirror.write().await;
        let applied = apply_leaves(&mut mirror, leaves)?;
        if max_slot > mirror.on_chain_slot() {
            mirror.set_on_chain_slot(max_slot);
        }
        Ok(applied)
    }

    /// Compare the mirror's root to `VaultConfig.current_root`. Logged,
    /// never fatal — a mismatch flags an incomplete sync (the live loop
    /// will catch up) without taking the indexer down.
    async fn reconcile(&self) {
        let chain = match self.rpc.get_account_info(&self.vault_config_pda).await {
            Ok(Some(acc)) => acc,
            Ok(None) => {
                tracing::warn!("merkle reconcile: vault_config account not found");
                return;
            }
            Err(e) => {
                tracing::warn!(error = %e, "merkle reconcile: vault_config read failed");
                return;
            }
        };
        let Some((chain_count, chain_root)) = parse_vault_root(&chain.data) else {
            tracing::warn!(
                len = chain.data.len(),
                "merkle reconcile: vault_config data too short to parse"
            );
            return;
        };
        let mirror = self.mirror.read().await;
        if mirror.root() == chain_root && mirror.leaf_count() == chain_count {
            tracing::info!(
                leaf_count = chain_count,
                "merkle reconcile OK — mirror root matches VaultConfig.current_root"
            );
        } else {
            tracing::warn!(
                mirror_leaves = mirror.leaf_count(),
                chain_leaves = chain_count,
                mirror_root = %hex::encode(mirror.root()),
                chain_root = %hex::encode(chain_root),
                "merkle reconcile MISMATCH — mirror behind / incomplete; will retry"
            );
        }
    }
}

/// Apply decoded leaves to the mirror in strict `leaf_index` order.
/// Sorts + dedups by index, skips already-applied indices (idempotent),
/// and requires the next index to equal `mirror.leaf_count()` —
/// returning [`SyncError::LeafGap`] on a hole (signals an incomplete
/// fetch). Returns the number actually appended.
pub fn apply_leaves(
    mirror: &mut MerkleMirror,
    mut leaves: Vec<AppendedLeaf>,
) -> Result<usize, SyncError> {
    leaves.sort_by_key(|l| l.leaf_index);
    leaves.dedup_by_key(|l| l.leaf_index);

    let mut applied = 0;
    for leaf in leaves {
        let expected = mirror.leaf_count();
        if leaf.leaf_index < expected {
            continue; // already applied — idempotent re-run
        }
        if leaf.leaf_index != expected {
            return Err(SyncError::LeafGap {
                expected,
                got: leaf.leaf_index,
            });
        }
        mirror.append_leaf(leaf.value)?;
        applied += 1;
    }
    Ok(applied)
}

/// Extract `(leaf_count, current_root)` from raw `VaultConfig` account
/// data. `None` if the buffer is too short.
pub fn parse_vault_root(data: &[u8]) -> Option<(u64, [u8; 32])> {
    if data.len() < VAULT_CURRENT_ROOT_OFFSET + 32 {
        return None;
    }
    let mut lc = [0u8; 8];
    lc.copy_from_slice(&data[VAULT_LEAF_COUNT_OFFSET..VAULT_LEAF_COUNT_OFFSET + 8]);
    let mut root = [0u8; 32];
    root.copy_from_slice(&data[VAULT_CURRENT_ROOT_OFFSET..VAULT_CURRENT_ROOT_OFFSET + 32]);
    Some((u64::from_le_bytes(lc), root))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fr_safe(seed: u8) -> [u8; 32] {
        let mut b = [seed; 32];
        b[0] = 0;
        b
    }

    fn leaf(i: u64, seed: u8) -> AppendedLeaf {
        AppendedLeaf {
            leaf_index: i,
            value: fr_safe(seed),
        }
    }

    #[test]
    fn apply_leaves_appends_in_order_regardless_of_input_order() {
        let mut m = MerkleMirror::new();
        let leaves = vec![leaf(2, 3), leaf(0, 1), leaf(1, 2)];
        let n = apply_leaves(&mut m, leaves).unwrap();
        assert_eq!(n, 3);
        assert_eq!(m.leaf_count(), 3);
        assert_eq!(m.leaf_index_of(&fr_safe(1)), Some(0));
        assert_eq!(m.leaf_index_of(&fr_safe(3)), Some(2));
    }

    #[test]
    fn apply_leaves_is_idempotent_on_overlap() {
        let mut m = MerkleMirror::new();
        apply_leaves(&mut m, vec![leaf(0, 1), leaf(1, 2)]).unwrap();
        let n = apply_leaves(&mut m, vec![leaf(0, 1), leaf(1, 2), leaf(2, 3)]).unwrap();
        assert_eq!(n, 1);
        assert_eq!(m.leaf_count(), 3);
    }

    #[test]
    fn apply_leaves_detects_gap() {
        let mut m = MerkleMirror::new();
        apply_leaves(&mut m, vec![leaf(0, 1)]).unwrap();
        let err = apply_leaves(&mut m, vec![leaf(2, 3)]).unwrap_err();
        assert!(matches!(
            err,
            SyncError::LeafGap {
                expected: 1,
                got: 2
            }
        ));
    }

    #[test]
    fn apply_leaves_dedups_duplicate_index() {
        let mut m = MerkleMirror::new();
        let n = apply_leaves(&mut m, vec![leaf(0, 1), leaf(0, 1)]).unwrap();
        assert_eq!(n, 1);
        assert_eq!(m.leaf_count(), 1);
    }

    #[test]
    fn parse_vault_root_extracts_offsets() {
        let mut data = vec![0u8; 200];
        data[VAULT_LEAF_COUNT_OFFSET..VAULT_LEAF_COUNT_OFFSET + 8]
            .copy_from_slice(&42u64.to_le_bytes());
        let root = fr_safe(0x77);
        data[VAULT_CURRENT_ROOT_OFFSET..VAULT_CURRENT_ROOT_OFFSET + 32].copy_from_slice(&root);
        let (count, got) = parse_vault_root(&data).unwrap();
        assert_eq!(count, 42);
        assert_eq!(got, root);
    }

    #[test]
    fn parse_vault_root_rejects_short_buffer() {
        assert!(parse_vault_root(&[0u8; 100]).is_none());
    }
}
