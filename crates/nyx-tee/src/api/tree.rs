//! `/tree/*` — read-only views over the in-memory Merkle mirror
//! (`crate::merkle::MerkleMirror`). The indexer surface that replaces
//! the SDK's `MerkleShadow` rebuild (D6, `docs/tee-architecture.md`
//! §5.5). Wire contract: `docs/tee-api-openapi.yaml`.
//!
//! - `GET /tree/root` — public. Current root + leaf count + last
//!   on-chain sync slot.
//! - `GET /tree/inclusion?commitment=…` — bearer. 20-level sibling
//!   path for a note commitment; the client re-hashes it against the
//!   returned root and cross-checks that root on Solana, so the TEE
//!   can't forge an inclusion proof undetected.
//! - `GET /tree/leaves?from=&to=` — bearer. Leaf pagination for
//!   cold-syncing clients.
//!
//! Every response is eventually-consistent with on-chain
//! `VaultConfig.current_root` (it lags a sync interval); these are a
//! fast convenience path, not a trust layer — clients verify against
//! Solana directly when they need certainty.

use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};

use super::state::ApiState;
use crate::merkle::MERKLE_DEPTH;

/// Max leaves returned by a single `GET /tree/leaves` page. Bounds the
/// response (and the memory to build it) so one bearer request can't
/// materialise a large mirror into a single JSON body. Clients paginate
/// with successive `from` cursors.
const MAX_LEAF_PAGE: u64 = 10_000;

/// `GET /tree/root` response. Mirrors the openapi `TreeRoot` schema.
#[derive(Debug, Serialize)]
pub struct TreeRootResponse {
    pub tree_id: u8,
    pub merkle_root: String,
    pub leaf_count: u64,
    pub on_chain_slot: u64,
}

/// Shared `?tree_id=` selector for the `/tree/*` reads. Defaults to shard 0
/// (the single-shard / pre-sharding view) when omitted.
#[derive(Debug, Deserialize, Default)]
pub struct TreeIdQuery {
    #[serde(default)]
    pub tree_id: u8,
}

/// `GET /tree/inclusion` response. Mirrors the openapi `InclusionProof`
/// schema: a 20-entry sibling path (hex) + the root it folds up to.
#[derive(Debug, Serialize)]
pub struct InclusionProofResponse {
    pub note_commitment: String,
    pub leaf_index: u64,
    pub merkle_root: String,
    pub siblings: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct InclusionQuery {
    pub commitment: String,
    #[serde(default)]
    pub tree_id: u8,
}

#[derive(Debug, Serialize)]
pub struct LeafEntry {
    pub leaf_index: u64,
    pub value: String,
}

#[derive(Debug, Serialize)]
pub struct LeavesResponse {
    pub leaves: Vec<LeafEntry>,
    pub merkle_root: String,
}

#[derive(Debug, Deserialize)]
pub struct LeavesQuery {
    pub from: u64,
    pub to: u64,
    #[serde(default)]
    pub tree_id: u8,
}

/// Parse a 32-byte hex string (with or without a `0x` prefix) into a
/// fixed array, returning a 400-shaped error on any malformation.
fn parse_hex32(s: &str) -> Result<[u8; 32], (StatusCode, String)> {
    let trimmed = s.strip_prefix("0x").unwrap_or(s);
    let bytes =
        hex::decode(trimmed).map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid hex: {e}")))?;
    bytes.try_into().map_err(|v: Vec<u8>| {
        (
            StatusCode::BAD_REQUEST,
            format!("expected 32 bytes, got {}", v.len()),
        )
    })
}

/// `GET /tree/root?tree_id=` — public. Defaults to shard 0.
pub async fn get_root(
    State(state): State<Arc<ApiState>>,
    Query(q): Query<TreeIdQuery>,
) -> Json<TreeRootResponse> {
    let mirror = state.merkle_mirror(q.tree_id as usize).read().await;
    Json(TreeRootResponse {
        tree_id: q.tree_id,
        merkle_root: hex::encode(mirror.root()),
        leaf_count: mirror.leaf_count(),
        on_chain_slot: mirror.on_chain_slot(),
    })
}

/// `GET /tree/inclusion?commitment=…` — bearer.
///
/// `400` on a malformed commitment, `404` when the commitment isn't in
/// the tree, `500` only if Poseidon fails (never for real leaves).
pub async fn get_inclusion(
    State(state): State<Arc<ApiState>>,
    Query(q): Query<InclusionQuery>,
) -> Result<Json<InclusionProofResponse>, (StatusCode, String)> {
    let commitment = parse_hex32(&q.commitment)?;

    let proof = {
        let mirror = state.merkle_mirror(q.tree_id as usize).read().await;
        mirror.inclusion_proof(&commitment).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("inclusion proof failed: {e}"),
            )
        })?
    }
    .ok_or((
        StatusCode::NOT_FOUND,
        "commitment not found in tree".to_string(),
    ))?;

    debug_assert_eq!(proof.siblings.len(), MERKLE_DEPTH);
    Ok(Json(InclusionProofResponse {
        note_commitment: hex::encode(proof.note_commitment),
        leaf_index: proof.leaf_index,
        merkle_root: hex::encode(proof.merkle_root),
        siblings: proof.siblings.iter().map(hex::encode).collect(),
    }))
}

/// `GET /tree/leaves?from=&to=` — bearer. Half-open `[from, to)`,
/// clamped to the available range.
pub async fn get_leaves(
    State(state): State<Arc<ApiState>>,
    Query(q): Query<LeavesQuery>,
) -> Result<Json<LeavesResponse>, (StatusCode, String)> {
    if q.to < q.from {
        return Err((
            StatusCode::BAD_REQUEST,
            "`to` must be >= `from`".to_string(),
        ));
    }
    // Cap the page so one request can't materialise a huge tree into a
    // single JSON response (`leaves_range` clamps to the leaf COUNT, not
    // a span — without this `?from=0&to=<huge>` would dump the whole
    // mirror). Clients page with successive `from`.
    let capped_to = q.to.min(q.from.saturating_add(MAX_LEAF_PAGE));
    let mirror = state.merkle_mirror(q.tree_id as usize).read().await;
    let (start, leaves) = mirror.leaves_range(q.from, capped_to);
    Ok(Json(LeavesResponse {
        leaves: leaves
            .into_iter()
            .enumerate()
            .map(|(i, v)| LeafEntry {
                leaf_index: start + i as u64,
                value: hex::encode(v),
            })
            .collect(),
        merkle_root: hex::encode(mirror.root()),
    }))
}
