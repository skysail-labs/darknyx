//! Opt-in qualification of the production Merkle cold-boot path against a
//! non-empty local Surfpool ledger.

use std::fs;
use std::sync::Arc;
use std::time::Duration;

use darknyx_tee::merkle::{MerkleMirror, MerkleSync, MerkleSyncConfig};
use darknyx_tee::solana_rpc::SolanaRpcClient;
use reqwest::Url;
use serde::Deserialize;
use solana_address::Address;
use tokio::sync::RwLock;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct QualificationConfig {
    vault_program_id: String,
    num_trees: usize,
    merkle_tree_pdas: Vec<String>,
}

#[tokio::test]
async fn cold_boot_reconstructs_exact_surfpool_shard_roots() {
    if std::env::var("RUN_SURFPOOL_QUALIFICATION").ok().as_deref() != Some("1") {
        return;
    }

    let rpc_url = std::env::var("SOLANA_RPC_URL").expect("SOLANA_RPC_URL");
    let parsed_url = Url::parse(&rpc_url).expect("valid SOLANA_RPC_URL");
    assert!(
        matches!(
            parsed_url.host_str(),
            Some("127.0.0.1" | "localhost" | "::1" | "[::1]")
        ),
        "qualification refuses a non-loopback RPC"
    );
    let config_path = std::env::var("DARKNYX_E2E_CONFIG_PATH").expect("DARKNYX_E2E_CONFIG_PATH");
    let config: QualificationConfig =
        serde_json::from_slice(&fs::read(config_path).expect("read qualification config"))
            .expect("parse qualification config");
    assert_eq!(config.num_trees, config.merkle_tree_pdas.len());

    let vault_program_id: Address = config.vault_program_id.parse().expect("vault program id");
    let tree_pdas: Vec<Address> = config
        .merkle_tree_pdas
        .iter()
        .map(|value| value.parse().expect("merkle tree PDA"))
        .collect();
    let mirrors: Vec<Arc<RwLock<MerkleMirror>>> = (0..config.num_trees)
        .map(|_| Arc::new(RwLock::new(MerkleMirror::new())))
        .collect();
    let rpc = SolanaRpcClient::new(&rpc_url).expect("Surfpool RPC client");
    let mut sync = MerkleSync::new(
        rpc.clone(),
        mirrors.clone(),
        vault_program_id,
        tree_pdas.clone(),
        MerkleSyncConfig {
            poll_interval: Duration::from_secs(1),
            from_slot: 0,
        },
    );

    let applied = sync
        .cold_boot()
        .await
        .expect("cold boot through native gTFA");
    assert!(applied > 0, "empty history is not qualification evidence");

    let mut total_chain_leaves = 0u64;
    for (tree_id, (tree_pda, mirror)) in tree_pdas.iter().zip(&mirrors).enumerate() {
        let account = rpc
            .get_account_info(tree_pda)
            .await
            .expect("tree account RPC")
            .expect("tree account exists");
        assert!(account.data.len() >= 48, "tree account layout");
        let chain_count = u64::from_le_bytes(account.data[8..16].try_into().unwrap());
        let chain_root: [u8; 32] = account.data[16..48].try_into().unwrap();
        let mirror = mirror.read().await;
        assert_eq!(
            mirror.leaf_count(),
            chain_count,
            "shard {tree_id} leaf count"
        );
        assert_eq!(mirror.root(), chain_root, "shard {tree_id} root");
        assert!(!mirror.is_diverged(), "shard {tree_id} diverged");
        total_chain_leaves += chain_count;
    }
    assert!(total_chain_leaves > 0, "all shard histories are empty");

    eprintln!(
        "SURFPOOL_MERKLE_SYNC applied={applied} total_chain_leaves={total_chain_leaves} shards={}",
        config.num_trees
    );
}
