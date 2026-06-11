//! Cold-boot + live sync of the Merkle mirror against on-chain state.
//!
//! Cold boot walks the vault program's transaction history via Helius'
//! `getTransactionsForAddress` (gTFA) — one call returns up to 1000 FULL
//! transactions, oldest-first, filtered to `status: succeeded` and floored at
//! `from_slot`, paged forward by `paginationToken`. This collapses the old
//! `getSignaturesForAddress` + per-signature `getTransaction` fan-out (1 + N
//! calls) into ≈1 call per 1000 txs. It decodes the leaf-append events of each
//! tx ([`super::events`]), applies them to the mirror in `leaf_index` order,
//! and reconciles each shard's root against its on-chain `MerkleTree`. The live
//! loop then re-scans gTFA from the last-seen slot on an interval and applies
//! new leaves as settles + deposits confirm (idempotent: the mirror skips
//! already-applied indices, so re-including the boundary slot is harmless).
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
use crate::solana_rpc::{RpcAddressTx, RpcError, SolanaRpcClient, TxSortOrder};

/// `MerkleTree` zero-copy shard-account layout offsets (after the 8-byte Anchor
/// discriminator): `leaf_count: u64` at 8, `current_root: [u8;32]` at 16.
/// (Post-sharding the tree STATE moved out of `VaultConfig` into one
/// `MerkleTree` account per shard — `programs/vault/src/state.rs::MerkleTree`.)
const TREE_LEAF_COUNT_OFFSET: usize = 8;
const TREE_CURRENT_ROOT_OFFSET: usize = TREE_LEAF_COUNT_OFFSET + 8;

/// Page size for `getTransactionsForAddress` (Helius caps at 1000 full txs).
const GTFA_PAGE_LIMIT: usize = 1000;

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

/// Drives the K per-shard Merkle mirrors from on-chain state. One sync task
/// pages the vault's whole tx history once and routes each appended leaf to
/// `mirrors[leaf.tree_id]` (a deposit/settle event carries its shard), so the
/// shards stay independent + correct even as settles round-robin across them.
pub struct MerkleSync {
    rpc: SolanaRpcClient,
    /// One mirror per shard, indexed by `tree_id`. `mirrors.len() == num_trees`.
    mirrors: Vec<Arc<RwLock<MerkleMirror>>>,
    vault_program_id: Address,
    /// The K `MerkleTree` shard PDAs, indexed by `tree_id` — read at reconcile
    /// to compare each mirror's root against its shard's on-chain root.
    merkle_tree_pdas: Vec<Address>,
    cfg: MerkleSyncConfig,
    /// Highest slot scanned so far — the live poll re-scans gTFA from here
    /// (`slot >= last_slot`, idempotent), advancing as new txs land. `0` until
    /// the first sync runs.
    last_slot: u64,
    /// Per-shard "currently flagged as diverged" latch, so reconcile WARNs
    /// once on divergence (not every ~2s poll) and logs once on recovery.
    /// Indexed by `tree_id`; length == `mirrors.len()`.
    diverged: Vec<bool>,
}

impl MerkleSync {
    pub fn new(
        rpc: SolanaRpcClient,
        mirrors: Vec<Arc<RwLock<MerkleMirror>>>,
        vault_program_id: Address,
        merkle_tree_pdas: Vec<Address>,
        cfg: MerkleSyncConfig,
    ) -> Self {
        assert_eq!(
            mirrors.len(),
            merkle_tree_pdas.len(),
            "one MerkleTree PDA per mirror shard"
        );
        let diverged = vec![false; mirrors.len()];
        Self {
            rpc,
            mirrors,
            vault_program_id,
            merkle_tree_pdas,
            cfg,
            last_slot: 0,
            diverged,
        }
    }

    /// Cold boot: scan the vault history oldest→newest from the `from_slot`
    /// floor via gTFA (full txs, paged by `paginationToken`), apply every
    /// leaf, reconcile. Sets `last_slot` so the live loop continues from here.
    /// Returns the number of leaves applied.
    pub async fn cold_boot(&mut self) -> Result<usize, SyncError> {
        let floor = (self.cfg.from_slot > 0).then_some(self.cfg.from_slot);
        let applied = self.scan_and_apply(floor).await?;
        if applied.txs_seen == 0 {
            tracing::info!("merkle cold-boot: vault has no transaction history in range yet");
            return Ok(0);
        }
        self.last_slot = applied.max_slot.max(self.last_slot);
        self.reconcile().await;
        let total_leaves = self.total_leaf_count().await;
        tracing::info!(
            applied = applied.leaves_applied,
            total_leaves,
            shards = self.mirrors.len(),
            "merkle cold-boot complete"
        );
        Ok(applied.leaves_applied)
    }

    /// Sum of leaf counts across all shard mirrors.
    async fn total_leaf_count(&self) -> u64 {
        let mut total = 0u64;
        for m in &self.mirrors {
            total += m.read().await.leaf_count();
        }
        total
    }

    /// One live-poll step: re-scan gTFA from `last_slot` (the boundary slot is
    /// re-included; the mirror's idempotent append skips already-applied
    /// indices), apply new leaves, advance `last_slot`. Returns the count
    /// applied this step.
    pub async fn poll_once(&mut self) -> Result<usize, SyncError> {
        let floor = Some(self.last_slot.max(self.cfg.from_slot)).filter(|s| *s > 0);
        let result = self.scan_and_apply(floor).await?;
        self.last_slot = result.max_slot.max(self.last_slot);
        if result.leaves_applied > 0 {
            self.reconcile().await;
        }
        Ok(result.leaves_applied)
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

    /// Scan the vault history via gTFA from `slot_gte` (oldest-first, full txs,
    /// `status: succeeded`), paging by `paginationToken`, and apply each page's
    /// leaves to the mirrors as it arrives (bounds memory — no need to buffer
    /// the whole history). Returns aggregate counts + the highest slot seen.
    async fn scan_and_apply(&self, slot_gte: Option<u64>) -> Result<ScanResult, SyncError> {
        let mut token: Option<String> = None;
        let mut out = ScanResult::default();
        loop {
            let page = self
                .rpc
                .get_transactions_for_address(
                    &self.vault_program_id,
                    TxSortOrder::Asc,
                    slot_gte,
                    token.as_deref(),
                    GTFA_PAGE_LIMIT,
                )
                .await?;
            if !page.txs.is_empty() {
                out.txs_seen += page.txs.len();
                if let Some(max) = page.txs.iter().map(|t| t.slot).max() {
                    out.max_slot = out.max_slot.max(max);
                }
                out.leaves_applied += self.apply_address_txs(&page.txs).await?;
            }
            match page.pagination_token {
                Some(t) => token = Some(t),
                None => break, // last page
            }
        }
        Ok(out)
    }

    /// Decode the leaves from a page of FULL gTFA transactions (no follow-up
    /// `getTransaction`) and apply them, routed per shard. `txs` MUST be
    /// oldest-first. Stamps each touched mirror's `on_chain_slot` with the
    /// highest slot applied.
    async fn apply_address_txs(&self, txs: &[RpcAddressTx]) -> Result<usize, SyncError> {
        let mut leaves: Vec<AppendedLeaf> = Vec::new();
        let mut max_slot = 0u64;
        for tx in txs {
            if tx.err.is_some() {
                continue; // defensive — `status: succeeded` already excludes reverts
            }
            let settle_ix_data = tx
                .instructions
                .iter()
                .map(|ix| ix.data.as_slice())
                .find(|d| d.len() >= 8 && d[..8] == *SETTLE_BATCHED_DISCRIMINATOR);
            let mut tx_leaves = extract_appended_leaves(&tx.log_messages, settle_ix_data);
            if !tx_leaves.is_empty() {
                max_slot = max_slot.max(tx.slot);
                leaves.append(&mut tx_leaves);
            }
        }

        // Route each leaf to its shard's mirror. Group by tree_id so we take
        // each shard's write lock once.
        let num_shards = self.mirrors.len();
        let by_shard = group_by_shard(leaves, num_shards);

        let mut applied = 0;
        for (tree_id, shard_leaves) in by_shard.into_iter().enumerate() {
            if shard_leaves.is_empty() {
                continue;
            }
            let mut mirror = self.mirrors[tree_id].write().await;
            applied += apply_leaves(&mut mirror, shard_leaves)?;
            if max_slot > mirror.on_chain_slot() {
                mirror.set_on_chain_slot(max_slot);
            }
        }
        Ok(applied)
    }

    /// Compare each shard mirror's root to its `MerkleTree[j].current_root` and
    /// classify the outcome — never fatal. Three cases:
    ///
    /// * **OK** (count + root match): healthy. Logged `debug`; logs `info` once
    ///   when recovering from a previously-flagged divergence.
    /// * **Behind** (`chain_count > mirror_count`): the mirror is mid-catch-up
    ///   (normal sync lag). `debug` — the next poll applies the new leaves.
    /// * **Diverged** (`mirror_count > chain_count`, or equal counts with
    ///   different roots): the mirror holds leaves no longer on chain — i.e. an
    ///   on-chain `reset_merkle_tree` ran underneath it (a DEVNET op; production
    ///   never resets). The append-only mirror can't roll back from the event
    ///   stream (a reset emits no event), so it stays stale until the CVM is
    ///   restarted (or `NYX_TEE_SYNC_FROM_SLOT` is bumped past the reset). WARN
    ///   ONCE per shard (latched in `self.diverged`) so this doesn't flood the
    ///   log every poll.
    async fn reconcile(&mut self) {
        for tree_id in 0..self.merkle_tree_pdas.len() {
            let tree_pda = self.merkle_tree_pdas[tree_id];
            let chain = match self.rpc.get_account_info(&tree_pda).await {
                Ok(Some(acc)) => acc,
                Ok(None) => {
                    tracing::warn!(tree_id, "merkle reconcile: merkle_tree account not found");
                    continue;
                }
                Err(e) => {
                    tracing::warn!(tree_id, error = %e, "merkle reconcile: merkle_tree read failed");
                    continue;
                }
            };
            let Some((chain_count, chain_root)) = parse_merkle_tree_root(&chain.data) else {
                tracing::warn!(
                    tree_id,
                    len = chain.data.len(),
                    "merkle reconcile: merkle_tree data too short to parse"
                );
                continue;
            };
            let (mirror_count, mirror_root) = {
                let m = self.mirrors[tree_id].read().await;
                (m.leaf_count(), m.root())
            };

            match classify_reconcile(mirror_count, &mirror_root, chain_count, &chain_root) {
                ReconcileState::Ok => {
                    if self.diverged[tree_id] {
                        tracing::info!(
                            tree_id,
                            leaf_count = chain_count,
                            "merkle reconcile RECOVERED — shard mirror matches chain again"
                        );
                        self.diverged[tree_id] = false;
                    } else {
                        tracing::debug!(tree_id, leaf_count = chain_count, "merkle reconcile OK");
                    }
                }
                ReconcileState::Behind => {
                    // Normal sync lag; the next poll applies the new leaves.
                    tracing::debug!(
                        tree_id,
                        mirror_leaves = mirror_count,
                        chain_leaves = chain_count,
                        "merkle reconcile: shard mirror behind chain; catching up"
                    );
                }
                ReconcileState::Diverged => {
                    if !self.diverged[tree_id] {
                        // Mirror AHEAD of chain (or equal count, different root):
                        // it holds leaves the chain no longer has → an on-chain
                        // reset ran underneath us. Warn ONCE; the append-only
                        // mirror needs a restart to re-cold-boot post-reset.
                        tracing::warn!(
                            tree_id,
                            mirror_leaves = mirror_count,
                            chain_leaves = chain_count,
                            mirror_root = %hex::encode(mirror_root),
                            chain_root = %hex::encode(chain_root),
                            "merkle reconcile DIVERGED — shard mirror holds leaves no longer on \
                             chain (on-chain reset_merkle_tree underneath the mirror?). \
                             Append-only mirror can't roll back; restart the CVM or bump \
                             NYX_TEE_SYNC_FROM_SLOT past the reset. (DEVNET only — production \
                             never resets.) Suppressing until recovered."
                        );
                        self.diverged[tree_id] = true;
                    }
                }
            }
        }
    }
}

/// Aggregate outcome of one [`MerkleSync::scan_and_apply`] pass.
#[derive(Debug, Default)]
struct ScanResult {
    /// Total txs returned by gTFA this scan (leaf-bearing or not).
    txs_seen: usize,
    /// Leaves actually appended to the mirrors.
    leaves_applied: usize,
    /// Highest slot observed in the scan (`0` if none).
    max_slot: u64,
}

/// Reconcile outcome for one shard — the mirror vs its on-chain `MerkleTree`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReconcileState {
    /// Counts + roots match.
    Ok,
    /// Chain ahead of the mirror — normal sync lag, resolves next poll.
    Behind,
    /// Mirror ahead of chain, or equal count with a different root — the mirror
    /// holds leaves no longer on chain (an on-chain reset underneath it).
    Diverged,
}

/// Pure classification of a shard's reconcile (no RPC / locks).
fn classify_reconcile(
    mirror_count: u64,
    mirror_root: &[u8; 32],
    chain_count: u64,
    chain_root: &[u8; 32],
) -> ReconcileState {
    if mirror_count == chain_count && mirror_root == chain_root {
        ReconcileState::Ok
    } else if chain_count > mirror_count {
        ReconcileState::Behind
    } else {
        ReconcileState::Diverged
    }
}

/// Partition leaves by `tree_id` into `num_shards` buckets (bucket `j` holds
/// shard `j`'s leaves, in arrival order). A leaf naming a shard ≥ `num_shards`
/// is a decode/config mismatch — dropped (logged) rather than panicking.
pub fn group_by_shard(leaves: Vec<AppendedLeaf>, num_shards: usize) -> Vec<Vec<AppendedLeaf>> {
    let mut by_shard: Vec<Vec<AppendedLeaf>> = vec![Vec::new(); num_shards.max(1)];
    for leaf in leaves {
        let t = leaf.tree_id as usize;
        if t < by_shard.len() {
            by_shard[t].push(leaf);
        } else {
            tracing::warn!(
                tree_id = leaf.tree_id,
                num_shards,
                "merkle sync: leaf names a shard beyond num_trees; skipped"
            );
        }
    }
    by_shard
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

/// Extract `(leaf_count, current_root)` from raw `MerkleTree` shard-account
/// data. `None` if the buffer is too short.
pub fn parse_merkle_tree_root(data: &[u8]) -> Option<(u64, [u8; 32])> {
    if data.len() < TREE_CURRENT_ROOT_OFFSET + 32 {
        return None;
    }
    let mut lc = [0u8; 8];
    lc.copy_from_slice(&data[TREE_LEAF_COUNT_OFFSET..TREE_LEAF_COUNT_OFFSET + 8]);
    let mut root = [0u8; 32];
    root.copy_from_slice(&data[TREE_CURRENT_ROOT_OFFSET..TREE_CURRENT_ROOT_OFFSET + 32]);
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
            tree_id: 0,
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

    fn leaf_on(tree_id: u8, i: u64, seed: u8) -> AppendedLeaf {
        AppendedLeaf {
            tree_id,
            leaf_index: i,
            value: fr_safe(seed),
        }
    }

    #[test]
    fn group_by_shard_routes_each_leaf_to_its_tree() {
        // Interleaved leaves for shards 0 and 1 → each shard's bucket holds
        // ONLY its own leaves, in arrival order, with per-shard indices intact.
        let leaves = vec![
            leaf_on(0, 0, 1),
            leaf_on(1, 0, 2),
            leaf_on(0, 1, 3),
            leaf_on(1, 1, 4),
        ];
        let buckets = group_by_shard(leaves, 2);
        assert_eq!(buckets.len(), 2);
        assert_eq!(buckets[0], vec![leaf_on(0, 0, 1), leaf_on(0, 1, 3)]);
        assert_eq!(buckets[1], vec![leaf_on(1, 0, 2), leaf_on(1, 1, 4)]);

        // Applied to separate per-shard mirrors, each advances independently.
        let mut m0 = MerkleMirror::new();
        let mut m1 = MerkleMirror::new();
        assert_eq!(apply_leaves(&mut m0, buckets[0].clone()).unwrap(), 2);
        assert_eq!(apply_leaves(&mut m1, buckets[1].clone()).unwrap(), 2);
        assert_eq!(m0.leaf_count(), 2);
        assert_eq!(m1.leaf_count(), 2);
        assert_eq!(m0.leaf_index_of(&fr_safe(3)), Some(1));
        assert_eq!(m1.leaf_index_of(&fr_safe(2)), Some(0));
    }

    #[test]
    fn group_by_shard_drops_out_of_range_shard() {
        // A leaf naming shard 5 when only 2 shards exist is dropped, not a panic.
        let leaves = vec![leaf_on(0, 0, 1), leaf_on(5, 0, 2)];
        let buckets = group_by_shard(leaves, 2);
        assert_eq!(buckets[0].len(), 1);
        assert_eq!(buckets[1].len(), 0);
    }

    #[test]
    fn apply_leaves_dedups_duplicate_index() {
        let mut m = MerkleMirror::new();
        let n = apply_leaves(&mut m, vec![leaf(0, 1), leaf(0, 1)]).unwrap();
        assert_eq!(n, 1);
        assert_eq!(m.leaf_count(), 1);
    }

    #[test]
    fn parse_merkle_tree_root_extracts_offsets() {
        let mut data = vec![0u8; 200];
        data[TREE_LEAF_COUNT_OFFSET..TREE_LEAF_COUNT_OFFSET + 8]
            .copy_from_slice(&42u64.to_le_bytes());
        let root = fr_safe(0x77);
        data[TREE_CURRENT_ROOT_OFFSET..TREE_CURRENT_ROOT_OFFSET + 32].copy_from_slice(&root);
        let (count, got) = parse_merkle_tree_root(&data).unwrap();
        assert_eq!(count, 42);
        assert_eq!(got, root);
    }

    #[test]
    fn parse_merkle_tree_root_rejects_short_buffer() {
        assert!(parse_merkle_tree_root(&[0u8; 4]).is_none());
    }

    /// End-to-end of the gTFA cold-boot path against a mock RPC: one
    /// `getTransactionsForAddress` page carrying a deposit's NoteCreated event
    /// is decoded + applied to the mirror — no per-signature `getTransaction`.
    #[tokio::test]
    async fn cold_boot_applies_leaves_from_gtfa_full_txs() {
        use axum::{routing::post, Json, Router};
        use base64::Engine as _;
        use serde_json::{json, Value};
        use sha2::{Digest, Sha256};

        // A NoteCreated event for a deposit landing at leaf 0.
        let commitment = fr_safe(0xAB);
        let mut event = Sha256::digest(b"event:NoteCreated")[..8].to_vec();
        event.push(0u8); // tree_id
        event.extend_from_slice(&0u64.to_le_bytes()); // leaf_index
        event.extend_from_slice(&commitment); // commitment
        event.extend_from_slice(&[0u8; 32]); // token_mint
        event.extend_from_slice(&1000u64.to_le_bytes()); // amount
        event.extend_from_slice(&[0u8; 32]); // new_root
        let log_line = format!(
            "Program data: {}",
            base64::engine::general_purpose::STANDARD.encode(&event)
        );

        // One gTFA page: a single deposit tx, no next page.
        let page = Arc::new(json!({
            "data": [{
                "slot": 100,
                "transaction": {
                    "signatures": ["sig1"],
                    "message": { "accountKeys": [], "instructions": [] }
                },
                "meta": { "logMessages": [log_line], "err": null }
            }],
            "paginationToken": Value::Null
        }));

        async fn handle(
            axum::extract::State(page): axum::extract::State<Arc<Value>>,
            Json(req): Json<Value>,
        ) -> Json<Value> {
            let id = req.get("id").cloned().unwrap_or(json!(1));
            let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
            let result = match method {
                "getTransactionsForAddress" => (*page).clone(),
                // reconcile reads the merkle_tree account → null (warns, non-fatal).
                "getAccountInfo" => json!({ "context": { "slot": 100 }, "value": null }),
                _ => json!(null),
            };
            Json(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
        }

        let app = Router::new().route("/", post(handle)).with_state(page);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let rpc = SolanaRpcClient::new(format!("http://{addr}")).unwrap();
        let mirror = Arc::new(RwLock::new(MerkleMirror::new()));
        let mut sync = MerkleSync::new(
            rpc,
            vec![mirror.clone()],
            Address::new_from_array([1u8; 32]),
            vec![Address::new_from_array([2u8; 32])],
            MerkleSyncConfig::default(),
        );

        let applied = sync.cold_boot().await.unwrap();
        assert_eq!(applied, 1, "the deposit's leaf was decoded from the gTFA full tx");
        let m = mirror.read().await;
        assert_eq!(m.leaf_count(), 1);
        assert_eq!(m.leaf_index_of(&commitment), Some(0));
    }

    #[test]
    fn classify_reconcile_distinguishes_behind_from_diverged() {
        let r1 = fr_safe(0x11);
        let r2 = fr_safe(0x22);
        // Match → Ok.
        assert_eq!(classify_reconcile(5, &r1, 5, &r1), ReconcileState::Ok);
        // Chain ahead → Behind (normal lag).
        assert_eq!(classify_reconcile(3, &r1, 5, &r2), ReconcileState::Behind);
        // Mirror ahead of chain → Diverged (on-chain reset signature).
        assert_eq!(classify_reconcile(8, &r1, 0, &r2), ReconcileState::Diverged);
        // Equal count, different root → Diverged (post-reset refill at same idx).
        assert_eq!(
            classify_reconcile(24, &r1, 24, &r2),
            ReconcileState::Diverged
        );
    }
}
