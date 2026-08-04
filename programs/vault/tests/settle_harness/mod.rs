//! Shared helpers for vault litesvm integration tests.
#![allow(dead_code)]

use std::path::PathBuf;

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use borsh::BorshSerialize;
use litesvm::LiteSVM;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;

pub type Pubkey = Address;
pub const SYSTEM_PROGRAM_ID: Pubkey = solana_system_interface::program::ID;

// Must match `declare_id!` in the vault. LiteSVM's
// `add_program_from_file` reads the declared id baked into the ELF and
// rejects loads under a different id with InvalidAccountData.
pub const VAULT_PROGRAM_ID: &str = "C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx";

pub fn repo_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

/// Defer to the ONE staleness guard in `common` rather than reimplementing it —
/// a second copy of the check is how the two drift until one silently stops
/// guarding. Every test binary that pulls in this harness therefore also
/// declares `mod common;` (path-including `common/mod.rs` from here instead
/// would load the same file as a module twice in the tests that declare both,
/// which rustc rejects).
pub fn vault_so_path() -> PathBuf {
    crate::common::vault_program_so()
}

pub fn anchor_disc(name: &str) -> [u8; 8] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"global:");
    h.update(name.as_bytes());
    let out = h.finalize();
    let mut d = [0u8; 8];
    d.copy_from_slice(&out[..8]);
    d
}

/// Anchor account discriminator = first 8 bytes of sha256("account:<TypeName>").
pub fn anchor_acct_disc(name: &str) -> [u8; 8] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"account:");
    h.update(name.as_bytes());
    let out = h.finalize();
    let mut d = [0u8; 8];
    d.copy_from_slice(&out[..8]);
    d
}

// ============================================================================
// Ix arg structs
// ============================================================================

/// Number of Merkle-tree shards the harness initializes. ≥2 so multi-tree
/// settle tests can route matches to distinct shards (tree 0 and tree 1).
pub const HARNESS_NUM_TREES: u8 = 2;

#[derive(BorshSerialize)]
pub struct InitializeArgs {
    pub operations_admin: [u8; 32],
    pub tee_pubkeys: Vec<[u8; 32]>,
    pub root_key: [u8; 32],
    pub num_trees: u8,
}

// ============================================================================
// PDA helpers
// ============================================================================

pub fn vault_config_pda(program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"vault_config"], program_id)
}

pub fn test_market_config_pda(
    program_id: &Pubkey,
    base_mint: &Pubkey,
    quote_mint: &Pubkey,
) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[b"market_config", base_mint.as_ref(), quote_mint.as_ref()],
        program_id,
    )
}

/// Per-shard Merkle-tree PDA. Seed `[b"merkle_tree", &[tree_id]]` — mirrors
/// `vault::state::MerkleTree::SEED`.
pub fn merkle_tree_pda(program_id: &Pubkey, tree_id: u8) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[b"merkle_tree", core::slice::from_ref(&tree_id)],
        program_id,
    )
}

pub fn wallet_entry_pda(program_id: &Pubkey, commitment: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"wallet", commitment.as_ref()], program_id)
}

pub fn note_lock_pda(program_id: &Pubkey, commitment: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"note_lock", commitment.as_ref()], program_id)
}

pub fn consumed_note_pda(program_id: &Pubkey, commitment: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"consumed_note", commitment.as_ref()], program_id)
}

/// S-05 deposit-once guard PDA.
pub fn deposited_note_pda(program_id: &Pubkey, note_commitment: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"deposited_note", note_commitment], program_id)
}

// ============================================================================
// Harness
// ============================================================================

/// Bundle of programs + funded keys + initialised vault.
pub struct Harness {
    pub svm: LiteSVM,
    pub vault_id: Pubkey,
    pub admin: Keypair,
    pub tee: Keypair,
    pub root: Keypair,
    pub trader: Keypair,
    /// Dummy SPL mint used by `seed_note_lock` to populate `NoteLock.token_mint`
    /// (the v2 addition that binds locked notes to a specific mint). Both
    /// sides of every settle test use this single mint — the on-chain handler
    /// accepts same-mint settles (the conservation laws still hold), and no
    /// existing test exercises distinct base/quote mints.
    pub test_mint: Pubkey,
}

impl Harness {
    pub fn setup() -> Self {
        let vault_so = vault_so_path();
        if !vault_so.exists() {
            panic!(
                "vault binary missing — run `cargo build-sbf --manifest-path programs/vault/Cargo.toml`. Expected: {:?}",
                vault_so
            );
        }

        let mut svm = LiteSVM::new();
        let vault_id: Pubkey = VAULT_PROGRAM_ID.parse().unwrap();
        svm.add_program_from_file(vault_id, &vault_so).unwrap();

        let admin = Keypair::new();
        let tee = Keypair::new();
        let root = Keypair::new();
        let trader = Keypair::new();
        for kp in [&admin, &tee, &root, &trader] {
            svm.airdrop(&kp.pubkey(), 10_000_000_000).unwrap();
        }

        // Initialize the global vault config.
        let (vault_pda, _) = vault_config_pda(&vault_id);
        let mut init_data = anchor_disc("initialize").to_vec();
        InitializeArgs {
            operations_admin: admin.pubkey().to_bytes(),
            tee_pubkeys: vec![tee.pubkey().to_bytes(), Keypair::new().pubkey().to_bytes()],
            root_key: root.pubkey().to_bytes(),
            num_trees: HARNESS_NUM_TREES,
        }
        .serialize(&mut init_data)
        .unwrap();
        let init_ix = Instruction {
            program_id: vault_id,
            accounts: vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(vault_pda, false),
                AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            ],
            data: init_data,
        };
        let tx = Transaction::new(
            &[&admin],
            Message::new(&[init_ix], Some(&admin.pubkey())),
            svm.latest_blockhash(),
        );
        svm.send_transaction(tx).expect("vault initialize failed");

        // Initialize each Merkle-tree shard.
        for tree_id in 0..HARNESS_NUM_TREES {
            let (tree_pda, _) = merkle_tree_pda(&vault_id, tree_id);
            let mut data = anchor_disc("initialize_tree").to_vec();
            data.push(tree_id);
            let ix = Instruction {
                program_id: vault_id,
                accounts: vec![
                    AccountMeta::new(admin.pubkey(), true),
                    AccountMeta::new_readonly(vault_pda, false),
                    AccountMeta::new(tree_pda, false),
                    AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
                ],
                data,
            };
            let tx = Transaction::new(
                &[&admin],
                Message::new(&[ix], Some(&admin.pubkey())),
                svm.latest_blockhash(),
            );
            svm.send_transaction(tx)
                .unwrap_or_else(|e| panic!("initialize_tree({tree_id}) failed: {e:?}"));
        }

        // v2: NoteLock now carries token_mint. A fresh dummy keypair is fine
        // for tests — the on-chain handler only uses it for the VALID_CREATE
        // binding-hash recomputation and per-mint conservation, both of which
        // are byte-equality checks the test harness mirrors.
        let test_mint = Keypair::new().pubkey();

        Self {
            svm,
            vault_id,
            admin,
            tee,
            root,
            trader,
            test_mint,
        }
    }

    /// Create a WalletEntry PDA for a user_commitment.
    pub fn create_wallet_stub(&mut self, user_commitment: &[u8; 32], owner: &Pubkey) {
        use solana_account::Account as SolAccount;
        let (pda, bump) = wallet_entry_pda(&self.vault_id, user_commitment);
        let mut data = vec![0u8; 88];
        data[0..8].copy_from_slice(&anchor_disc("WalletEntry"));
        data[8..40].copy_from_slice(user_commitment);
        data[40..72].copy_from_slice(&owner.to_bytes());
        data[72..80].copy_from_slice(&0u64.to_le_bytes());
        data[80] = bump;
        let acct = SolAccount {
            lamports: self.svm.minimum_balance_for_rent_exemption(data.len()),
            data,
            owner: self.vault_id,
            executable: false,
            rent_epoch: 0,
        };
        self.svm.set_account(pda, acct).unwrap();
    }
}

/// `ComputeBudget::SetComputeUnitLimit(cu)` instruction used by proof-backed
/// vault tests whose Poseidon and Groth16 verification exceed the default.
pub fn compute_budget_ix(cu: u32) -> Instruction {
    // ComputeBudget program id (hardcoded Solana builtin).
    let program_id = Pubkey::from([
        3, 6, 70, 111, 229, 33, 23, 50, 255, 236, 173, 186, 114, 195, 155, 231, 188, 140, 229, 187,
        197, 247, 18, 107, 44, 67, 155, 58, 64, 0, 0, 0,
    ]);
    // Discriminator 0x02 = SetComputeUnitLimit.
    let mut data = vec![0x02u8];
    data.extend_from_slice(&cu.to_le_bytes());
    Instruction {
        program_id,
        accounts: vec![],
        data,
    }
}

// ============================================================================
// Phase-5 settlement helpers (tee_forced_settle)
// ============================================================================

/// Byte-for-byte mirror of the on-chain `MatchResultPayload` Borsh shape.
/// When this diverges the settle test panics early rather than at the
/// program's deserializer.
#[derive(BorshSerialize, Clone)]
pub struct MatchResultPayload {
    pub match_id: [u8; 16],
    pub note_a_use_tag: [u8; 32],
    pub note_b_use_tag: [u8; 32],
    pub note_c_commitment: [u8; 32],
    pub note_d_commitment: [u8; 32],
    pub note_e_commitment: [u8; 32],
    pub note_f_commitment: [u8; 32],
    pub order_id_a: [u8; 16],
    pub order_id_b: [u8; 16],
    pub note_fee_base_commitment: [u8; 32],
    pub note_fee_quote_commitment: [u8; 32],
    pub buyer_relock_order_id: [u8; 16],
    pub buyer_relock_expiry: u64,
    pub seller_relock_order_id: [u8; 16],
    pub seller_relock_expiry: u64,
    pub note_e_use_tag: [u8; 32],
    pub note_f_use_tag: [u8; 32],
    pub batch_slot: u64,
    // Amount-privacy (P3b): the seven plaintext amount fields (base/quote/
    // buyer_change/seller_change/buyer_fee/seller_fee/clearing_price) were
    // dropped — they're proven in-circuit + bound by the note commitments.
    // Change-amount recovery (Proposal B, v8): the 128-byte encrypted
    // change_amount bundle was appended.
    // Mirror of `vault::instructions::tee_forced_settle::MatchResultPayload`.
    pub fill_recovery: [u8; 128],
}

/// Sentinel used by on-chain code.
pub const RELOCK_ORDER_ID_NONE: [u8; 16] = [0u8; 16];

/// Build a 32-byte "commitment" whose integer value fits inside the BN254
/// scalar field (top byte zero). Use for note_c/d/e/f/fee when Poseidon
/// will process them during Merkle append — arbitrary 0xFFs would cause
/// `InvalidProof` inside light-poseidon.
pub fn fr_safe(seed: u8, salt: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[1] = seed; // byte 0 stays zero → value < 2^248 < Fr modulus
    out[31] = salt;
    out
}

impl MatchResultPayload {
    /// A sane zero-ish default that tests mutate selectively.
    #[allow(clippy::too_many_arguments)]
    pub fn exact_fill(
        match_id: [u8; 16],
        note_a: [u8; 32],
        note_b: [u8; 32],
        note_c: [u8; 32],
        note_d: [u8; 32],
        order_id_a: [u8; 16],
        order_id_b: [u8; 16],
        // Amount-privacy (P3b): amounts no longer ride the payload. Kept as
        // params so the call sites (which still read as "this trade is 100 base
        // for 5000 quote") stay untouched; they don't affect on-chain behavior.
        _base_amount: u64,
        _quote_amount: u64,
    ) -> Self {
        Self {
            match_id,
            note_a_use_tag: note_a,
            note_b_use_tag: note_b,
            note_c_commitment: note_c,
            note_d_commitment: note_d,
            note_e_commitment: [0u8; 32],
            note_f_commitment: [0u8; 32],
            order_id_a,
            order_id_b,
            note_fee_base_commitment: [0u8; 32],
            note_fee_quote_commitment: [0u8; 32],
            buyer_relock_order_id: RELOCK_ORDER_ID_NONE,
            buyer_relock_expiry: 0,
            seller_relock_order_id: RELOCK_ORDER_ID_NONE,
            seller_relock_expiry: 0,
            note_e_use_tag: [0u8; 32],
            note_f_use_tag: [0u8; 32],
            batch_slot: 0,
            fill_recovery: [0u8; 128],
        }
    }
}

/// Mirror of `tee_forced_settle::canonical_payload_hash`. Byte-identical
/// output or signature verification fails.
pub fn canonical_payload_hash(p: &MatchResultPayload) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"darknyx-match-v11");
    h.update(p.match_id);
    h.update(p.note_a_use_tag);
    h.update(p.note_b_use_tag);
    h.update(p.note_c_commitment);
    h.update(p.note_d_commitment);
    h.update(p.note_e_commitment);
    h.update(p.note_f_commitment);
    h.update(p.note_fee_base_commitment);
    h.update(p.note_fee_quote_commitment);
    h.update(p.order_id_a);
    h.update(p.order_id_b);
    h.update(p.buyer_relock_order_id);
    h.update(p.buyer_relock_expiry.to_le_bytes());
    h.update(p.seller_relock_order_id);
    h.update(p.seller_relock_expiry.to_le_bytes());
    h.update(p.note_e_use_tag);
    h.update(p.note_f_use_tag);
    h.update(p.batch_slot.to_le_bytes());
    h.update(p.fill_recovery); // v8: encrypted output-recovery bundle
    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

/// Solana Ed25519Program ID as a raw pubkey. Uses the canonical Solana
/// constant — do NOT hardcode bytes; LiteSVM enforces the real program.
pub fn ed25519_program_id() -> Pubkey {
    // base58 decode of "Ed25519SigVerify111111111111111111111111111".
    Pubkey::from([
        3, 125, 70, 214, 124, 147, 251, 190, 18, 249, 66, 143, 131, 141, 64, 255, 5, 112, 116, 73,
        39, 244, 138, 100, 252, 202, 112, 68, 128, 0, 0, 0,
    ])
}

/// Build an Ed25519Program precompile ix with inlined pubkey + msg + sig.
/// Layout per Solana SDK:
///   1  num_signatures = 1
///   1  padding = 0
///   2  signature_offset
///   2  signature_instruction_index = 0xFFFF (same ix)
///   2  public_key_offset
///   2  public_key_instruction_index = 0xFFFF
///   2  message_data_offset
///   2  message_data_size
///   2  message_instruction_index = 0xFFFF
/// Then inline: pubkey (32) || signature (64) || message (N).
pub fn build_ed25519_verify_ix(
    pubkey: &[u8; 32],
    signature: &[u8; 64],
    message: &[u8],
) -> Instruction {
    let header_len: u16 = 16;
    let pk_off: u16 = header_len;
    let sig_off: u16 = pk_off + 32;
    let msg_off: u16 = sig_off + 64;
    let msg_len: u16 = message.len() as u16;

    let mut data = Vec::with_capacity(header_len as usize + 32 + 64 + message.len());
    data.push(1u8); // num_signatures
    data.push(0u8); // padding
    data.extend_from_slice(&sig_off.to_le_bytes());
    data.extend_from_slice(&0xFFFFu16.to_le_bytes()); // signature_instruction_index
    data.extend_from_slice(&pk_off.to_le_bytes());
    data.extend_from_slice(&0xFFFFu16.to_le_bytes()); // public_key_instruction_index
    data.extend_from_slice(&msg_off.to_le_bytes());
    data.extend_from_slice(&msg_len.to_le_bytes());
    data.extend_from_slice(&0xFFFFu16.to_le_bytes()); // message_instruction_index
    data.extend_from_slice(pubkey);
    data.extend_from_slice(signature);
    data.extend_from_slice(message);

    Instruction {
        program_id: ed25519_program_id(),
        accounts: vec![],
        data,
    }
}

/// Directly seed a NoteLock PDA (bypasses the `lock_note` ix — the Phase-5
/// settle tests focus on *settlement* not lock mechanics). The PDA is
/// writable and owned by the vault program so the real handler can close
/// it via `close = tee_authority`.
pub fn seed_note_lock(
    h: &mut Harness,
    note_commitment: &[u8; 32],
    order_id: &[u8; 16],
    expiry_slot: u64,
    // Amount-privacy (P3b): NoteLock.amount was removed. The param is kept so
    // the many call sites stay untouched, but it's no longer written anywhere.
    _amount: u64,
) {
    use solana_account::Account as SolAccount;
    let (pda, bump) = note_lock_pda(&h.vault_id, note_commitment);
    // P3b layout: 8 disc + 32 commit + 32 token_mint + 16 order_id + 8 expiry
    //          + 32 locked_by + 1 bump + 7 pad = 136 bytes (was 144 with the
    // now-removed 8-byte amount). token_mint sits between note_commitment and
    // order_id (matches `vault::state::NoteLock` exactly; keep in sync if
    // NoteLock ever moves fields). Uses `h.test_mint` so the marker / settle ix
    // compute a consistent binding hash from the same mint.
    let mut data = vec![0u8; 136];
    data[0..8].copy_from_slice(&anchor_acct_disc("NoteLock"));
    data[8..40].copy_from_slice(note_commitment);
    data[40..72].copy_from_slice(&h.test_mint.to_bytes());
    data[72..88].copy_from_slice(order_id);
    data[88..96].copy_from_slice(&expiry_slot.to_le_bytes());
    data[96..128].copy_from_slice(&h.tee.pubkey().to_bytes());
    data[128] = bump;
    let acct = SolAccount {
        lamports: h.svm.minimum_balance_for_rent_exemption(data.len()),
        data,
        owner: h.vault_id,
        executable: false,
        rent_epoch: 0,
    };
    h.svm.set_account(pda, acct).unwrap();
}

/// Read the `token_mint` field back out of a seeded `NoteLock` PDA. Mirrors
/// the on-chain handler's `lock_a_mint = lock_a.token_mint` access so the
/// VALID_CREATE binding-hash recomputation in `build_settle_ix` sees the
/// same bytes the program will.
pub fn read_note_lock_mint(h: &Harness, note_commitment: &[u8; 32]) -> Pubkey {
    let (pda, _) = note_lock_pda(&h.vault_id, note_commitment);
    let acct = h.svm.get_account(&pda).expect("note_lock not seeded");
    let mut mint = [0u8; 32];
    mint.copy_from_slice(&acct.data[40..72]);
    Pubkey::from(mint)
}

/// Read the current `leaf_count` out of a per-shard `MerkleTree` account.
/// `MerkleTree` layout: 8 disc + 8 leaf_count + ... (leaf_count at offset 8).
pub fn tree_leaf_count(h: &Harness, tree_id: u8) -> u64 {
    let (pda, _) = merkle_tree_pda(&h.vault_id, tree_id);
    let acct = h.svm.get_account(&pda).expect("merkle_tree");
    u64::from_le_bytes(acct.data[8..16].try_into().unwrap())
}

/// Back-compat: leaf_count of shard 0 (the default tree single-tree settle
/// tests route to).
pub fn vault_leaf_count(h: &Harness) -> u64 {
    tree_leaf_count(h, 0)
}

/// Read protocol_owner_commitment out of VaultConfig.
pub fn vault_protocol_owner(h: &Harness) -> [u8; 32] {
    use vault_layout::PROTOCOL_OWNER_OFFSET;
    let (pda, _) = vault_config_pda(&h.vault_id);
    let acct = h.svm.get_account(&pda).expect("vault_config");
    let mut out = [0u8; 32];
    out.copy_from_slice(&acct.data[PROTOCOL_OWNER_OFFSET..PROTOCOL_OWNER_OFFSET + 32]);
    out
}

/// Offsets inside the (post-sharding) VaultConfig — the Merkle-tree STATE
/// moved out to per-shard `MerkleTree` accounts; only the tree-independent
/// config + the global `zero_subtree_roots` remain.
/// Layout (matches programs/vault/src/state.rs::VaultConfig — keep in sync):
///   8  disc
///   32 admin
///   32 * 16  tee_pubkeys (MAX_TEE_KEYS)
///   32 root_key
///   32 * 20  zero_subtree_roots
///   32 protocol_owner_commitment
///   2  fee_rate_bps (u16)
///   1  num_tee_keys (u8)
///   1  num_trees (u8)
///   1  bump (u8)
///   3  _padding
///   8  tick_size (u64)            ← appended (matcher governance)
///   8  min_order_size (u64)       ← appended
///   8  circuit_breaker_bps (u64)  ← appended
/// The three appended u64s don't shift PROTOCOL_OWNER_OFFSET (computed from the
/// start), so this helper is layout-stable.
pub mod vault_layout {
    pub const MAX_TEE_KEYS: usize = 16;
    pub const MERKLE_DEPTH: usize = 20;
    pub const PROTOCOL_OWNER_OFFSET: usize = 8
        + 32                  // admin
        + 32 * MAX_TEE_KEYS   // tee_pubkeys
        + 32                  // root_key
        + 32 * MERKLE_DEPTH; // zero_subtree_roots
}

/// Overwrite `protocol_owner_commitment` + `fee_rate_bps` directly in the
/// VaultConfig account. The on-chain program exposes no setter yet —
/// tests use this to simulate governance having set the fee rate.
pub fn set_vault_fee_config(h: &mut Harness, owner_commitment: [u8; 32], fee_rate_bps: u16) {
    use vault_layout::PROTOCOL_OWNER_OFFSET;
    let (pda, _) = vault_config_pda(&h.vault_id);
    let mut acct = h.svm.get_account(&pda).expect("vault_config");
    acct.data[PROTOCOL_OWNER_OFFSET..PROTOCOL_OWNER_OFFSET + 32].copy_from_slice(&owner_commitment);
    acct.data[PROTOCOL_OWNER_OFFSET + 32..PROTOCOL_OWNER_OFFSET + 34]
        .copy_from_slice(&fee_rate_bps.to_le_bytes());
    h.svm.set_account(pda, acct).unwrap();
}

/// Directly seed a `ConsumedNoteEntry` PDA for `note_commitment` (bypasses the
/// real settle/withdraw path). Mimics a note that has already been consumed so
/// tests can assert the U-02 `lock_note` re-lock guard. Layout mirrors
/// `vault::state::ConsumedNoteEntry`: 8 disc + 32 commitment + 16 match_id
/// + 8 consumed_slot + 1 bump + 7 pad = 72 bytes.
pub fn seed_consumed_note(h: &mut Harness, note_commitment: &[u8; 32]) {
    use solana_account::Account as SolAccount;
    let (pda, bump) = consumed_note_pda(&h.vault_id, note_commitment);
    let mut data = vec![0u8; 72];
    data[0..8].copy_from_slice(&anchor_acct_disc("ConsumedNoteEntry"));
    data[8..40].copy_from_slice(note_commitment);
    // match_id (16) + consumed_slot (8) left zero — the sentinel a withdraw uses.
    data[64] = bump;
    let acct = SolAccount {
        lamports: h.svm.minimum_balance_for_rent_exemption(data.len()),
        data,
        owner: h.vault_id,
        executable: false,
        rent_epoch: 0,
    };
    h.svm.set_account(pda, acct).unwrap();
}

/// True if the `consumed_note` PDA for `note_commitment` has been initialised.
pub fn consumed_note_exists(h: &Harness, note_commitment: &[u8; 32]) -> bool {
    let (pda, _) = consumed_note_pda(&h.vault_id, note_commitment);
    h.svm
        .get_account(&pda)
        .map(|a| !a.data.is_empty() && a.lamports > 0)
        .unwrap_or(false)
}

/// True if a `note_lock` PDA exists for the commitment (unclosed lock).
pub fn note_lock_exists(h: &Harness, note_commitment: &[u8; 32]) -> bool {
    let (pda, _) = note_lock_pda(&h.vault_id, note_commitment);
    h.svm
        .get_account(&pda)
        .map(|a| !a.data.is_empty() && a.lamports > 0)
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// v3.5 — batched-validity marker scaffolding
// ---------------------------------------------------------------------------

/// Mirrors `vault::state::BatchValidityMarker::SEED`.
pub const BATCH_VALIDITY_MARKER_SEED: &[u8] = b"batch_validity";

/// Domain tag used by the on-chain `walk_merkle_path_n16` when hashing
/// inner Merkle nodes. Must match `DOMAIN_BATCH_ROOT` (= 22) in
/// `tee_forced_settle_batched.rs`.
const DOMAIN_BATCH_ROOT: u64 = 22;

pub fn batch_validity_marker_pda(h: &Harness, merkle_root: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[BATCH_VALIDITY_MARKER_SEED, merkle_root.as_ref()],
        &h.vault_id,
    )
}

/// Pre-seed a `BatchValidityMarker` PDA so `tee_forced_settle_batched`
/// finds one at the merkle-root-derived address. Same pattern as
/// `seed_valid_create_marker` — bypasses `verify_match_batch`'s Groth16
/// check so settle-handler behaviour can be tested without proof
/// orchestration.
///
/// Layout (matches `vault::state::BatchValidityMarker`):
///   8 disc + 32 payer + 8 expiry_slot + 1 bump = 49 bytes
pub fn seed_batch_validity_marker(h: &mut Harness, merkle_root: &[u8; 32], expiry_slot: u64) {
    use solana_account::Account as SolAccount;

    let (pda, bump) = batch_validity_marker_pda(h, merkle_root);
    let mut data = vec![0u8; 49];
    data[0..8].copy_from_slice(&anchor_acct_disc("BatchValidityMarker"));
    data[8..40].copy_from_slice(&h.tee.pubkey().to_bytes());
    data[40..48].copy_from_slice(&expiry_slot.to_le_bytes());
    data[48] = bump;

    let acct = SolAccount {
        lamports: h.svm.minimum_balance_for_rent_exemption(data.len()),
        data,
        owner: h.vault_id,
        executable: false,
        rent_epoch: 0,
    };
    h.svm.set_account(pda, acct).unwrap();
}

/// Seed a governed MarketConfig for proof-verifier fixtures. This avoids
/// requiring real SPL mint accounts in tests that exercise only Groth16.
pub fn seed_market_config(
    h: &mut Harness,
    base_mint: &Pubkey,
    quote_mint: &Pubkey,
    price_scale: u64,
    enabled: bool,
) {
    use solana_account::Account as SolAccount;

    let (pda, bump) = test_market_config_pda(&h.vault_id, base_mint, quote_mint);
    let mut data = vec![0u8; 108];
    data[..8].copy_from_slice(&anchor_acct_disc("MarketConfig"));
    data[8..40].copy_from_slice(base_mint.as_ref());
    data[40..72].copy_from_slice(quote_mint.as_ref());
    data[72..80].copy_from_slice(&price_scale.to_le_bytes());
    data[80..88].copy_from_slice(&1u64.to_le_bytes());
    data[88..96].copy_from_slice(&1u64.to_le_bytes());
    data[96..104].copy_from_slice(&1u64.to_le_bytes());
    data[106] = u8::from(enabled);
    data[107] = bump;
    let account = SolAccount {
        lamports: h.svm.minimum_balance_for_rent_exemption(data.len()),
        data,
        owner: h.vault_id,
        executable: false,
        rent_epoch: 0,
    };
    h.svm.set_account(pda, account).unwrap();
}

/// Whether the marker PDA still has any data — used to assert that
/// `close_batch_validity_marker` actually wiped it.
pub fn batch_validity_marker_exists(h: &Harness, merkle_root: &[u8; 32]) -> bool {
    let (pda, _) = batch_validity_marker_pda(h, merkle_root);
    match h.svm.get_account(&pda) {
        Some(a) => !a.data.is_empty() && a.lamports > 0,
        None => false,
    }
}

/// Bridge from the test-side payload (its own BorshSerialize struct
/// purely so we can drive Anchor without depending on the on-chain
/// type's serde quirks) into the on-chain
/// `vault::instructions::MatchResultPayload`. Field-by-field copy;
/// the two structs are byte-identical Borsh shapes.
fn to_onchain_payload(
    p: &MatchResultPayload,
) -> vault::instructions::tee_forced_settle::MatchResultPayload {
    use vault::instructions::tee_forced_settle::MatchResultPayload as OnP;
    OnP {
        match_id: p.match_id,
        note_a_use_tag: p.note_a_use_tag,
        note_b_use_tag: p.note_b_use_tag,
        note_c_commitment: p.note_c_commitment,
        note_d_commitment: p.note_d_commitment,
        note_e_commitment: p.note_e_commitment,
        note_f_commitment: p.note_f_commitment,
        order_id_a: p.order_id_a,
        order_id_b: p.order_id_b,
        note_fee_base_commitment: p.note_fee_base_commitment,
        note_fee_quote_commitment: p.note_fee_quote_commitment,
        buyer_relock_order_id: p.buyer_relock_order_id,
        buyer_relock_expiry: p.buyer_relock_expiry,
        seller_relock_order_id: p.seller_relock_order_id,
        seller_relock_expiry: p.seller_relock_expiry,
        note_e_use_tag: p.note_e_use_tag,
        note_f_use_tag: p.note_f_use_tag,
        batch_slot: p.batch_slot,
        fill_recovery: p.fill_recovery,
    }
}

/// Recompute the per-slot Merkle leaf the on-chain handler expects.
/// Wraps `vault::instructions::tee_forced_settle_batched::compute_match_leaf`
/// (exposed for this exact purpose) so the leaf can never drift from
/// the on-chain implementation.
pub fn compute_match_leaf_for(
    payload: &MatchResultPayload,
    // Commitment-only leaf (amount-privacy, P1b) no longer hashes the mints;
    // kept in the signature so the many call sites stay untouched.
    _quote_mint: &Pubkey,
    _base_mint: &Pubkey,
) -> [u8; 32] {
    vault::instructions::tee_forced_settle_batched::compute_match_leaf(&to_onchain_payload(payload))
        .expect("compute_match_leaf")
}

/// Build the depth-4 Merkle tree over 16 leaves and return the root +
/// the inclusion path (4 siblings) for the supplied `target_index`.
/// Mirrors the TS-side `merkleInclusionPath` exactly so the same
/// (leaves, idx) input produces the same proof in both languages.
pub fn build_merkle_root_and_path_n16(
    leaves: &[[u8; 32]; 16],
    target_index: u8,
) -> ([u8; 32], [[u8; 32]; 4]) {
    use darkpool_crypto::poseidon_hash_bytes;

    assert!(target_index < 16, "target_index out of range");
    let domain_be = {
        let mut b = [0u8; 32];
        b[24..32].copy_from_slice(&DOMAIN_BATCH_ROOT.to_be_bytes());
        b
    };

    // Build the tree level-by-level from the bottom up.
    // level0 = leaves (16) → level1 (8) → level2 (4) → level3 (2) → root (1).
    let mut current: Vec<[u8; 32]> = leaves.to_vec();
    let mut siblings = [[0u8; 32]; 4];
    let mut idx = target_index as usize;
    for sibling_slot in siblings.iter_mut() {
        let sibling_idx = idx ^ 1;
        *sibling_slot = current[sibling_idx];
        let mut next = Vec::with_capacity(current.len() / 2);
        for pair in current.chunks_exact(2) {
            let hashed =
                poseidon_hash_bytes(&[domain_be, pair[0], pair[1]]).expect("poseidon_hash_bytes");
            next.push(hashed);
        }
        current = next;
        idx /= 2;
    }
    let root = current[0];
    (root, siblings)
}

/// Build a `tee_forced_settle_batched` ix with the supplied inclusion
/// proof. Mirrors `build_settle_ix` but for the v3.5 ix variant: one
/// extra `match_index` byte + 4 contiguous 32-byte siblings appended
/// to ix.data; the two per-match marker accounts collapse to a single
/// `batch_validity_marker`.
pub fn build_settle_batched_ix(
    h: &Harness,
    tree_id: u8,
    payload: &MatchResultPayload,
    match_index: u8,
    merkle_proof: &[[u8; 32]; 4],
    merkle_root: &[u8; 32],
) -> Instruction {
    build_settle_batched_ix_for(
        h,
        &h.tee.pubkey(),
        tree_id,
        payload,
        match_index,
        merkle_proof,
        merkle_root,
    )
}

/// Like [`build_settle_batched_ix`] but with an explicit `authority` as the
/// `tee_authority` signer + rent payer. Used by the multi-key auth test, where
/// a settle is signed by `tee_pubkeys[1]` (or an unregistered key) rather than
/// the default `h.tee`.
#[allow(clippy::too_many_arguments)]
pub fn build_settle_batched_ix_for(
    h: &Harness,
    authority: &Pubkey,
    tree_id: u8,
    payload: &MatchResultPayload,
    match_index: u8,
    merkle_proof: &[[u8; 32]; 4],
    merkle_root: &[u8; 32],
) -> Instruction {
    let (vault_pda, _) = vault_config_pda(&h.vault_id);
    let (tree_pda, _) = merkle_tree_pda(&h.vault_id, tree_id);
    let (lock_a, _) = note_lock_pda(&h.vault_id, &payload.note_a_use_tag);
    let (lock_b, _) = note_lock_pda(&h.vault_id, &payload.note_b_use_tag);
    let (consumed_a, _) = consumed_note_pda(&h.vault_id, &payload.note_a_use_tag);
    let (consumed_b, _) = consumed_note_pda(&h.vault_id, &payload.note_b_use_tag);
    // The relock PDAs are seeded with the TAGS, not the commitments. Both are
    // [u8;32], so getting this wrong compiles and then fails on-chain as an
    // opaque `Unauthorized` from create_relock_pda's address check.
    let (lock_e, _) = note_lock_pda(&h.vault_id, &payload.note_e_use_tag);
    let (lock_f, _) = note_lock_pda(&h.vault_id, &payload.note_f_use_tag);

    let instructions_sysvar: Pubkey = Pubkey::from([
        // Sysvar1nstructions1111111111111111111111111
        6, 167, 213, 23, 24, 123, 209, 102, 53, 218, 212, 4, 85, 253, 194, 192, 193, 36, 198, 143,
        33, 86, 117, 165, 219, 186, 203, 95, 8, 0, 0, 0,
    ]);

    let (marker_pda, _) = batch_validity_marker_pda(h, merkle_root);

    // ix data = disc + tree_id (u8) + payload (Borsh) + match_index (u8)
    //         + 4 × 32-byte siblings.
    let mut data = anchor_disc("tee_forced_settle_batched").to_vec();
    data.push(tree_id);
    payload.serialize(&mut data).unwrap();
    data.push(match_index);
    for s in merkle_proof.iter() {
        data.extend_from_slice(s);
    }

    Instruction {
        program_id: h.vault_id,
        accounts: vec![
            AccountMeta::new(*authority, true),
            AccountMeta::new_readonly(vault_pda, false),
            AccountMeta::new(tree_pda, false),
            AccountMeta::new(lock_a, false),
            AccountMeta::new(lock_b, false),
            AccountMeta::new(consumed_a, false),
            AccountMeta::new(consumed_b, false),
            if payload.buyer_relock_order_id != [0u8; 16] {
                AccountMeta::new(lock_e, false)
            } else {
                AccountMeta::new_readonly(lock_e, false)
            },
            if payload.seller_relock_order_id != [0u8; 16] {
                AccountMeta::new(lock_f, false)
            } else {
                AccountMeta::new_readonly(lock_f, false)
            },
            AccountMeta::new_readonly(instructions_sysvar, false),
            AccountMeta::new_readonly(marker_pda, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ],
        data,
    }
}

/// Build a REAL `verify_match_batch` ix — the on-chain Groth16 verify
/// (groth16-solana against `vk_match_batch_n16`) that creates the
/// `BatchValidityMarker` iff the proof is valid. Unlike
/// [`seed_batch_validity_marker`] (which fabricates the marker to
/// bypass proving), this drives the actual verifier.
///
/// `proof_bytes` is the 256-byte Borsh `Groth16Proof`
/// (`pi_a ‖ pi_b ‖ pi_c`); ix data = disc + merkle_root(32) +
/// expiry_slot(u64 LE) + proof(256).
pub fn build_verify_match_batch_ix(
    h: &Harness,
    payer: &Pubkey,
    base_mint: &Pubkey,
    quote_mint: &Pubkey,
    merkle_root: &[u8; 32],
    proof_bytes: &[u8; 256],
) -> Instruction {
    // S-04: no expiry_slot argument — the program derives the marker TTL.
    let (marker_pda, _) = batch_validity_marker_pda(h, merkle_root);
    let (vault_pda, _) = vault_config_pda(&h.vault_id);
    let (market_pda, _) = test_market_config_pda(&h.vault_id, base_mint, quote_mint);
    let mut data = anchor_disc("verify_match_batch").to_vec();
    data.extend_from_slice(merkle_root);
    data.extend_from_slice(proof_bytes);
    Instruction {
        program_id: h.vault_id,
        // Order: payer, vault_config, market_config, marker, system.
        accounts: vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new_readonly(vault_pda, false),
            AccountMeta::new_readonly(market_pda, false),
            AccountMeta::new(marker_pda, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ],
        data,
    }
}

/// (ed25519_verify, tee_forced_settle_batched) tx — mirror of
/// `build_settle_tx` for the v3.5 path.
pub fn build_settle_batched_tx(
    h: &Harness,
    tree_id: u8,
    payload: &MatchResultPayload,
    match_index: u8,
    merkle_proof: &[[u8; 32]; 4],
    merkle_root: &[u8; 32],
) -> Transaction {
    let msg_hash = canonical_payload_hash(payload);
    let sig = h.tee.sign_message(&msg_hash);
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(sig.as_ref());
    let tee_pk = h.tee.pubkey().to_bytes();
    let ed_ix = build_ed25519_verify_ix(&tee_pk, &sig_bytes, &msg_hash);
    let settle_ix =
        build_settle_batched_ix(h, tree_id, payload, match_index, merkle_proof, merkle_root);
    Transaction::new(
        &[&h.tee],
        Message::new(
            &[compute_budget_ix(1_400_000), ed_ix, settle_ix],
            Some(&h.tee.pubkey()),
        ),
        h.svm.latest_blockhash(),
    )
}

/// Like [`build_settle_batched_tx`] but signed (ed25519 precompile + tx
/// fee-payer + `tee_authority`) by an arbitrary `signer`. Used to exercise the
/// multi-key authorized-set: a settle signed by `tee_pubkeys[1]` must succeed,
/// one signed by an unregistered key must be rejected `Unauthorized`.
pub fn build_settle_batched_tx_signed_by(
    h: &Harness,
    signer: &Keypair,
    tree_id: u8,
    payload: &MatchResultPayload,
    match_index: u8,
    merkle_proof: &[[u8; 32]; 4],
    merkle_root: &[u8; 32],
) -> Transaction {
    let msg_hash = canonical_payload_hash(payload);
    let sig = signer.sign_message(&msg_hash);
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(sig.as_ref());
    let pk = signer.pubkey().to_bytes();
    let ed_ix = build_ed25519_verify_ix(&pk, &sig_bytes, &msg_hash);
    let settle_ix = build_settle_batched_ix_for(
        h,
        &signer.pubkey(),
        tree_id,
        payload,
        match_index,
        merkle_proof,
        merkle_root,
    );
    Transaction::new(
        &[signer],
        Message::new(
            &[compute_budget_ix(1_400_000), ed_ix, settle_ix],
            Some(&signer.pubkey()),
        ),
        h.svm.latest_blockhash(),
    )
}

/// Build a `set_tee_pubkey` ix that installs the full authorized-key set
/// (`keys: Vec<Pubkey>`). Admin-signed. Mirrors `set_tee_pubkey.rs`'s Borsh
/// shape: a length-prefixed vec of 32-byte pubkeys.
pub fn build_set_tee_pubkeys_ix(h: &Harness, keys: &[Pubkey]) -> Instruction {
    let (vault_pda, _) = vault_config_pda(&h.vault_id);
    let mut data = anchor_disc("set_tee_pubkey").to_vec();
    data.extend_from_slice(&(keys.len() as u32).to_le_bytes());
    for k in keys {
        data.extend_from_slice(&k.to_bytes());
    }
    Instruction {
        program_id: h.vault_id,
        accounts: vec![
            AccountMeta::new_readonly(h.admin.pubkey(), true),
            AccountMeta::new(vault_pda, false),
        ],
        data,
    }
}

/// Build a `reset_merkle_tree(tree_id)` ix. Admin-signed; targets the single
/// shard `tree_id` (the other shards are untouched).
pub fn build_reset_merkle_tree_ix(h: &Harness, tree_id: u8) -> Instruction {
    let (vault_pda, _) = vault_config_pda(&h.vault_id);
    let (tree_pda, _) = merkle_tree_pda(&h.vault_id, tree_id);
    let mut data = anchor_disc("reset_merkle_tree").to_vec();
    data.push(tree_id);
    Instruction {
        program_id: h.vault_id,
        accounts: vec![
            AccountMeta::new_readonly(h.admin.pubkey(), true),
            AccountMeta::new_readonly(vault_pda, false),
            AccountMeta::new(tree_pda, false),
        ],
        data,
    }
}

/// One-shot: compute the v3.5 leaf + Merkle root for a single-match
/// "batch" (slot 0, all other slots zero-padded), seed the
/// `BatchValidityMarker` PDA at far-future expiry, and return a
/// ready-to-send (compute_budget + ed25519 + tee_forced_settle_batched)
/// tx. The migrated `settle.rs` scenarios use this to keep each
/// happy-path test a one-liner; failure-path tests that need a
/// custom precompile call [`seed_marker_and_build_settle_batched_ix`]
/// instead and build their own tx.
pub fn seed_marker_and_build_settle_batched_tx(
    h: &mut Harness,
    p: &MatchResultPayload,
) -> Transaction {
    let mint = read_note_lock_mint(h, &p.note_a_use_tag);
    let leaf = compute_match_leaf_for(p, &mint, &mint);
    let mut leaves = [[0u8; 32]; 16];
    leaves[0] = leaf;
    let (root, proof) = build_merkle_root_and_path_n16(&leaves, 0);
    seed_batch_validity_marker(h, &root, u64::MAX / 2);
    // Single-tree default: settle outputs append to shard 0.
    build_settle_batched_tx(h, 0, p, 0, &proof, &root)
}

/// Companion to [`seed_marker_and_build_settle_batched_tx`] — returns
/// just the settle ix. Caller is responsible for the Ed25519
/// precompile + the `Transaction::new` wrapping. Tests that need to
/// strip the precompile, use a different signing key, or sign a
/// bogus message use this variant.
pub fn seed_marker_and_build_settle_batched_ix(
    h: &mut Harness,
    p: &MatchResultPayload,
) -> Instruction {
    let mint = read_note_lock_mint(h, &p.note_a_use_tag);
    let leaf = compute_match_leaf_for(p, &mint, &mint);
    let mut leaves = [[0u8; 32]; 16];
    leaves[0] = leaf;
    let (root, proof) = build_merkle_root_and_path_n16(&leaves, 0);
    seed_batch_validity_marker(h, &root, u64::MAX / 2);
    // Single-tree default: settle outputs append to shard 0.
    build_settle_batched_ix(h, 0, p, 0, &proof, &root)
}

/// Build a `close_batch_validity_marker` ix.
/// Any authority may sweep at or after expiry; rent always flows to payer.
pub fn build_close_batch_validity_marker_ix(
    h: &Harness,
    merkle_root: &[u8; 32],
    authority: &Pubkey,
    payer: &Pubkey,
) -> Instruction {
    let (marker_pda, _) = batch_validity_marker_pda(h, merkle_root);
    let mut data = anchor_disc("close_batch_validity_marker").to_vec();
    data.extend_from_slice(merkle_root);

    Instruction {
        program_id: h.vault_id,
        accounts: vec![
            AccountMeta::new_readonly(*authority, true),
            AccountMeta::new(*payer, false),
            AccountMeta::new(marker_pda, false),
        ],
        data,
    }
}

// ============================================================================
// Real SPL + deposit/withdraw harness — for the withdraw⇄settle consume-guard
// double-spend PoC.
//
// Unlike the settle scaffolding above (which fabricates PDAs via `set_account`
// to skip proving), the withdraw path here is END-TO-END: a real SPL mint +
// funded token accounts, a real on-chain `deposit` that appends the note leaf,
// and a REAL snarkjs VALID_SPEND proof driving `withdraw`. This is the ONLY
// faithful way to reproduce the double-spend, because withdraw's on-chain
// `ConsumedNoteEntry` footprint (the guard the fix adds) only persists if the
// whole withdraw tx — Groth16 verify + SPL `transfer_checked` — succeeds; a
// garbage-proof withdraw would revert the inits along with everything else.
//
// The proof-generation + Merkle-witness plumbing mirrors `zk_spend_roundtrip.rs`
// (the pure-verifier round-trip) but drives it through the on-chain `withdraw`
// instruction inside LiteSVM. Requires the `valid_spend` circuit artefacts
// (CI's vault-litesvm job downloads them + has snarkjs via `npm ci`).
// ============================================================================

const TREE_DEPTH: usize = 20;

/// Classic SPL Token program id (loaded into LiteSVM by `with_default_programs`).
pub fn spl_token_id() -> Pubkey {
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
        .parse()
        .unwrap()
}

fn rent_sysvar_id() -> Pubkey {
    "SysvarRent111111111111111111111111111111111"
        .parse()
        .unwrap()
}

fn vault_token_pda(h: &Harness, mint: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"vault_token", mint.as_ref()], &h.vault_id)
}

fn outstanding_mint_pda(h: &Harness, mint: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"outstanding_mint", mint.as_ref()], &h.vault_id)
}

/// SPL Mint (82 bytes): `mint_authority = Some(authority)`, `decimals`, initialised.
fn pack_spl_mint(authority: &Pubkey, decimals: u8) -> Vec<u8> {
    let mut d = vec![0u8; 82];
    d[0..4].copy_from_slice(&1u32.to_le_bytes()); // COption::Some(mint_authority)
    d[4..36].copy_from_slice(&authority.to_bytes());
    // supply (36..44) = 0
    d[44] = decimals;
    d[45] = 1; // is_initialized
               // freeze_authority COption::None (46..82) = 0
    d
}

/// SPL token Account (165 bytes): `state = Initialized`, no delegate/native/close.
fn pack_spl_token_account(mint: &Pubkey, owner: &Pubkey, amount: u64) -> Vec<u8> {
    let mut d = vec![0u8; 165];
    d[0..32].copy_from_slice(&mint.to_bytes());
    d[32..64].copy_from_slice(&owner.to_bytes());
    d[64..72].copy_from_slice(&amount.to_le_bytes());
    // delegate COption::None (72..108) = 0
    d[108] = 1; // AccountState::Initialized
                // is_native COption::None (109..121), delegated_amount (121..129),
                // close_authority COption::None (129..165) all zero.
    d
}

fn set_spl_account(h: &mut Harness, addr: &Pubkey, data: Vec<u8>) {
    use solana_account::Account as SolAccount;
    let lamports = h.svm.minimum_balance_for_rent_exemption(data.len());
    let acct = SolAccount {
        lamports,
        data,
        owner: spl_token_id(),
        executable: false,
        rent_epoch: 0,
    };
    h.svm.set_account(*addr, acct).unwrap();
}

/// Create a real SPL mint (authority = `h.admin`). Returns the mint pubkey.
pub fn create_spl_mint(h: &mut Harness, decimals: u8) -> Pubkey {
    let mint = Keypair::new().pubkey();
    let data = pack_spl_mint(&h.admin.pubkey(), decimals);
    set_spl_account(h, &mint, data);
    mint
}

/// Create a real SPL token account for `owner`/`mint` prefunded with `amount`.
pub fn create_spl_token_account(
    h: &mut Harness,
    mint: &Pubkey,
    owner: &Pubkey,
    amount: u64,
) -> Pubkey {
    let ta = Keypair::new().pubkey();
    let data = pack_spl_token_account(mint, owner, amount);
    set_spl_account(h, &ta, data);
    ta
}

/// The secret openings behind a note — everything the VALID_SPEND circuit needs.
/// `owner_commitment = Poseidon3(DOMAIN_OWNER=1, spending_key, r_owner)`.
pub struct NoteSecret {
    pub spending_key: Fr,
    pub r_owner: Fr,
    pub recovery_nonce: Fr,
    /// Seed-derived in the real client; a deterministic stand-in here. It is a
    /// PRIVATE VALID_DEPOSIT witness and the reason the deposit inner is not a
    /// function of on-chain data plus the wallet-wide owner commitment.
    pub note_secret: Fr,
    pub inner_hash: Fr,
    pub owner_commitment: Fr,
}

impl NoteSecret {
    pub fn from_seeds(sk_seed: u8, r_owner_seed: u8, inner_seed: u8) -> Self {
        use darkpool_crypto::field::fr_from_uniform_bytes;
        use darkpool_crypto::poseidon::poseidon_hash;
        let spending_key = fr_from_uniform_bytes(&[sk_seed; 32]);
        let r_owner = fr_from_uniform_bytes(&[r_owner_seed; 32]);
        let recovery_nonce = fr_from_uniform_bytes(&[inner_seed; 32]);
        let note_secret = fr_from_uniform_bytes(&[inner_seed ^ 0x5A; 32]);
        let owner_commitment = poseidon_hash(&[Fr::from(1u64), spending_key, r_owner]).unwrap();
        // Poseidon4 now — see darkpool-crypto/src/deposit.rs for why the
        // fourth input exists.
        let inner_hash = poseidon_hash(&[
            Fr::from(27u64),
            owner_commitment,
            recovery_nonce,
            note_secret,
        ])
        .unwrap();
        Self {
            spending_key,
            r_owner,
            recovery_nonce,
            note_secret,
            inner_hash,
            owner_commitment,
        }
    }
}

/// A note deposited on-chain via a real `deposit` ix, carrying everything the
/// subsequent real `withdraw` needs (its commitment, nullifier, and the
/// single-leaf Merkle witness + root).
pub struct DepositedNote {
    pub commitment: [u8; 32],
    /// The PUBLIC consume handle: `Poseidon3(29, commitment, inner_hash)`.
    /// Every consume path — settle, withdraw, merge — must key on THIS, not on
    /// the commitment. A path left on the commitment would let the same note be
    /// consumed once under each scheme, which is a double-spend; the two
    /// cross-path tests in `tee_forced_settle_batched.rs` are what catch that.
    pub use_tag: [u8; 32],
    pub nullifier: [u8; 32],
    pub amount: u64,
    pub mint: Pubkey,
    pub tree_id: u8,
    pub secret: NoteSecret,
    pub merkle_root: [u8; 32],
    pub siblings: Vec<[u8; 32]>,
    pub path_indices: Vec<u8>,
}

/// Deposit a note into a FRESH shard (must be empty → the note lands at leaf
/// index 0, giving a trivial single-leaf inclusion witness). Sends a real
/// `deposit` ix signed by `depositor` (funds a prefunded token account for it),
/// then returns the on-chain-anchored `DepositedNote`.
pub fn deposit_note(
    h: &mut Harness,
    depositor: &Keypair,
    tree_id: u8,
    secret: NoteSecret,
    mint: &Pubkey,
    amount: u64,
) -> DepositedNote {
    use darkpool_crypto::field::fr_to_be_bytes;
    use darkpool_crypto::note::commitment_from_fields_v2;
    use darkpool_crypto::poseidon::poseidon_hash;

    let owner_commitment_bytes = fr_to_be_bytes(&secret.owner_commitment);
    let inner_hash_bytes = fr_to_be_bytes(&secret.inner_hash);
    let mint_bytes = mint.to_bytes();
    let commitment = commitment_from_fields_v2(
        &mint_bytes,
        amount,
        &owner_commitment_bytes,
        &inner_hash_bytes,
    )
    .expect("note fields are Fr-safe (Poseidon outputs)");
    // nullifier = Poseidon3(DOMAIN_NULL=3, spending_key, inner_hash)
    let nullifier = fr_to_be_bytes(
        &poseidon_hash(&[Fr::from(3u64), secret.spending_key, secret.inner_hash]).unwrap(),
    );

    assert_eq!(
        tree_leaf_count(h, tree_id),
        0,
        "deposit_note expects a fresh (empty) shard so the note is leaf 0",
    );

    let depositor_ta = create_spl_token_account(h, mint, &depositor.pubkey(), amount);

    let (vault_pda, _) = vault_config_pda(&h.vault_id);
    let (tree_pda, _) = merkle_tree_pda(&h.vault_id, tree_id);
    let (vault_token, _) = vault_token_pda(h, mint);
    let (outstanding, _) = outstanding_mint_pda(h, mint);

    let proof = build_valid_deposit_proof(&secret, mint, amount, &commitment);

    // deposit(tree_id, amount, note_commitment, recovery_nonce, proof)
    let mut data = anchor_disc("deposit").to_vec();
    data.push(tree_id);
    data.extend_from_slice(&amount.to_le_bytes());
    data.extend_from_slice(&commitment);
    data.extend_from_slice(&fr_to_be_bytes(&secret.recovery_nonce));
    proof.serialize(&mut data).unwrap();

    let ix = Instruction {
        program_id: h.vault_id,
        accounts: vec![
            AccountMeta::new(depositor.pubkey(), true),
            AccountMeta::new_readonly(vault_pda, false),
            AccountMeta::new(tree_pda, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new(depositor_ta, false),
            AccountMeta::new(vault_token, false),
            AccountMeta::new(outstanding, false),
            AccountMeta::new(deposited_note_pda(&h.vault_id, &commitment).0, false),
            AccountMeta::new_readonly(spl_token_id(), false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            AccountMeta::new_readonly(rent_sysvar_id(), false),
        ],
        data,
    };
    let tx = Transaction::new(
        &[depositor],
        Message::new(&[ix], Some(&depositor.pubkey())),
        h.svm.latest_blockhash(),
    );
    h.svm.send_transaction(tx).expect("deposit failed");

    // Single-leaf inclusion witness (index 0) → root matches the on-chain append.
    let (siblings, path_indices, root) = merkle_witness(&[commitment], 0);
    assert_eq!(
        root,
        tree_current_root(h, tree_id),
        "witness root diverged from the on-chain post-deposit root",
    );

    let use_tag = darkpool_crypto::note_use_tag(
        &commitment,
        &darkpool_crypto::fr_to_be_bytes(&secret.inner_hash),
    )
    .expect("note-use tag is field-safe");

    DepositedNote {
        commitment,
        use_tag,
        nullifier,
        amount,
        mint: *mint,
        tree_id,
        secret,
        merkle_root: root,
        siblings,
        path_indices,
    }
}

fn build_valid_deposit_proof(
    secret: &NoteSecret,
    mint: &Pubkey,
    amount: u64,
    commitment: &[u8; 32],
) -> vault::zk::verifier::Groth16Proof {
    use darkpool_crypto::field::pubkey_to_fr_pair;
    use std::fs;
    use std::process::Command;

    let root = repo_root();
    let build = root.join("circuits/build/valid_deposit");
    let wasm = build.join("circuit_js/circuit.wasm");
    let zkey = build.join("circuit_final.zkey");
    assert!(
        wasm.exists(),
        "missing {wasm:?} — run scripts/build-circuits.sh"
    );
    assert!(
        zkey.exists(),
        "missing {zkey:?} — run scripts/build-circuits.sh"
    );

    let [mint_lo, mint_hi] = pubkey_to_fr_pair(&mint.to_bytes());
    let input_json = format!(
        "{{\n\
           \"noteCommitment\": \"{commitment}\",\n\
           \"tokenMint\": [\"{mint_lo}\", \"{mint_hi}\"],\n\
           \"amount\": \"{amount}\",\n\
           \"recoveryNonce\": \"{nonce}\",\n\
           \"spendingKey\": \"{spending}\",\n\
           \"ownerCommitmentBlinding\": \"{r_owner}\",\n\
           \"noteSecret\": \"{note_secret}\"\n\
         }}",
        commitment = fr_to_dec(&Fr::from_be_bytes_mod_order(commitment)),
        mint_lo = fr_to_dec(&mint_lo),
        mint_hi = fr_to_dec(&mint_hi),
        nonce = fr_to_dec(&secret.recovery_nonce),
        spending = fr_to_dec(&secret.spending_key),
        r_owner = fr_to_dec(&secret.r_owner),
        note_secret = fr_to_dec(&secret.note_secret),
    );
    let tag: String = commitment[..6].iter().map(|b| format!("{b:02x}")).collect();
    let tmp = std::env::temp_dir().join(format!("darknyx_valid_deposit_{tag}"));
    fs::create_dir_all(&tmp).unwrap();
    let input_path = tmp.join("input.json");
    let proof_path = tmp.join("proof.json");
    let public_path = tmp.join("public.json");
    fs::write(&input_path, input_json).unwrap();

    let status = Command::new(root.join("node_modules/.bin/snarkjs"))
        .arg("groth16")
        .arg("fullprove")
        .arg(&input_path)
        .arg(&wasm)
        .arg(&zkey)
        .arg(&proof_path)
        .arg(&public_path)
        .status()
        .expect("failed to spawn snarkjs (run `npm install` at repo root)");
    assert!(
        status.success(),
        "snarkjs fullprove failed for VALID_DEPOSIT"
    );

    let proof_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&proof_path).unwrap()).unwrap();
    let pi_a = negate_g1(&groth16_g1_bytes(&proof_json["pi_a"]));
    let pi_b = groth16_g2_bytes(&proof_json["pi_b"]);
    let pi_c = groth16_g1_bytes(&proof_json["pi_c"]);
    vault::zk::verifier::Groth16Proof { pi_a, pi_b, pi_c }
}

/// Read the `current_root` field out of a per-shard `MerkleTree` account.
/// Layout: 8 disc + 8 leaf_count + 32 current_root + ...
pub fn tree_current_root(h: &Harness, tree_id: u8) -> [u8; 32] {
    let (pda, _) = merkle_tree_pda(&h.vault_id, tree_id);
    let acct = h.svm.get_account(&pda).expect("merkle_tree");
    let mut root = [0u8; 32];
    root.copy_from_slice(&acct.data[16..48]);
    root
}

/// Build a real `withdraw` tx driving a snarkjs VALID_SPEND proof for `note`,
/// paid + signed by `payer`, crediting `destination_ta`.
///
/// NOTE on the `consumed_note` account writability: it's passed WRITABLE
/// unconditionally. Pre-fix the handler reads it as a non-mut `UncheckedAccount`
/// (extra writability is harmless); post-fix it is `init`'d (writability is
/// required). One builder therefore serves both sides of the fix.
pub fn build_withdraw_tx(
    h: &Harness,
    note: &DepositedNote,
    payer: &Keypair,
    destination_ta: &Pubkey,
) -> Transaction {
    let proof = build_valid_spend_proof(note, destination_ta);

    let (vault_pda, _) = vault_config_pda(&h.vault_id);
    let (tree_pda, _) = merkle_tree_pda(&h.vault_id, note.tree_id);
    let (vault_token, _) = vault_token_pda(h, &note.mint);
    let (consumed, _) = consumed_note_pda(&h.vault_id, &note.use_tag);
    let (note_lock, _) = note_lock_pda(&h.vault_id, &note.use_tag);
    let (outstanding, _) = outstanding_mint_pda(h, &note.mint);

    // withdraw(tree_id, note_use_tag, nullifier, merkle_root, amount, proof)
    let mut data = anchor_disc("withdraw").to_vec();
    data.push(note.tree_id);
    data.extend_from_slice(&note.use_tag);
    data.extend_from_slice(&note.nullifier);
    data.extend_from_slice(&note.merkle_root);
    data.extend_from_slice(&note.amount.to_le_bytes());
    // Groth16Proof Borsh = pi_a[64] ‖ pi_b[128] ‖ pi_c[64] (fixed arrays, no len prefix).
    data.extend_from_slice(&proof.pi_a);
    data.extend_from_slice(&proof.pi_b);
    data.extend_from_slice(&proof.pi_c);

    let ix = Instruction {
        program_id: h.vault_id,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new_readonly(vault_pda, false),
            AccountMeta::new_readonly(tree_pda, false),
            AccountMeta::new_readonly(note.mint, false),
            AccountMeta::new(vault_token, false),
            AccountMeta::new(*destination_ta, false),
            AccountMeta::new(consumed, false),
            AccountMeta::new_readonly(note_lock, false),
            AccountMeta::new(outstanding, false),
            AccountMeta::new_readonly(spl_token_id(), false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ],
        data,
    };
    Transaction::new(
        &[payer],
        Message::new(&[ix], Some(&payer.pubkey())),
        h.svm.latest_blockhash(),
    )
}

// ── snarkjs VALID_SPEND proof generation (lifted from zk_spend_roundtrip.rs) ──

/// `destination_ta` is a PUBLIC input of VALID_SPEND (S-01), so the proof is
/// only valid for a withdraw crediting that exact token account.
fn build_valid_spend_proof(
    note: &DepositedNote,
    destination_ta: &Pubkey,
) -> vault::zk::verifier::Groth16Proof {
    use darkpool_crypto::field::pubkey_to_fr_pair;
    use std::fs;
    use std::process::Command;

    let root = repo_root();
    let [dest_lo, dest_hi] = pubkey_to_fr_pair(&destination_ta.to_bytes());
    let build = root.join("circuits/build/valid_spend");
    let wasm = build.join("circuit_js/circuit.wasm");
    let zkey = build.join("circuit_final.zkey");
    assert!(
        wasm.exists(),
        "missing {wasm:?} — run scripts/build-circuits.sh"
    );
    assert!(
        zkey.exists(),
        "missing {zkey:?} — run scripts/build-circuits.sh"
    );

    let [mint_lo, mint_hi] = pubkey_to_fr_pair(&note.mint.to_bytes());

    let tag: String = note.commitment[..6]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let tmp = std::env::temp_dir().join(format!("darknyx_ds_poc_{tag}"));
    fs::create_dir_all(&tmp).unwrap();
    let input_path = tmp.join("input.json");
    let proof_path = tmp.join("proof.json");
    let public_path = tmp.join("public.json");

    let siblings_dec: Vec<String> = note
        .siblings
        .iter()
        .map(|s| fr_to_dec(&Fr::from_be_bytes_mod_order(s)))
        .collect();
    let indices_dec: Vec<String> = note.path_indices.iter().map(|i| i.to_string()).collect();

    let input_json = format!(
        "{{\n\
           \"merkleRoot\": \"{mr}\",\n\
           \"nullifier\": \"{nl}\",\n\
           \"tokenMint\": [\"{mlo}\", \"{mhi}\"],\n\
           \"amount\": \"{amt}\",\n\
           \"spendingKey\": \"{sk}\",\n\
           \"ownerCommitmentBlinding\": \"{ocb}\",\n\
           \"innerHash\": \"{ih}\",\n\
           \"merklePath\": [{sibs}],\n\
           \"merkleIndices\": [{idxs}],\n\
           \"recipient\": [\"{dlo}\", \"{dhi}\"]\n\
         }}",
        mr = fr_to_dec(&Fr::from_be_bytes_mod_order(&note.merkle_root)),
        nl = fr_to_dec(&Fr::from_be_bytes_mod_order(&note.nullifier)),
        mlo = fr_to_dec(&mint_lo),
        mhi = fr_to_dec(&mint_hi),
        dlo = fr_to_dec(&dest_lo),
        dhi = fr_to_dec(&dest_hi),
        amt = note.amount,
        sk = fr_to_dec(&note.secret.spending_key),
        ocb = fr_to_dec(&note.secret.r_owner),
        ih = fr_to_dec(&note.secret.inner_hash),
        sibs = siblings_dec
            .iter()
            .map(|s| format!("\"{s}\""))
            .collect::<Vec<_>>()
            .join(", "),
        idxs = indices_dec
            .iter()
            .map(|s| format!("\"{s}\""))
            .collect::<Vec<_>>()
            .join(", "),
    );
    fs::write(&input_path, &input_json).unwrap();

    let snarkjs = root.join("node_modules/.bin/snarkjs");
    let status = Command::new(&snarkjs)
        .arg("groth16")
        .arg("fullprove")
        .arg(&input_path)
        .arg(&wasm)
        .arg(&zkey)
        .arg(&proof_path)
        .arg(&public_path)
        .status()
        .expect("failed to spawn snarkjs (run `npm ci` at repo root)");
    assert!(status.success(), "snarkjs fullprove failed for VALID_SPEND");

    let proof_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&proof_path).unwrap()).unwrap();
    let pi_a = negate_g1(&groth16_g1_bytes(&proof_json["pi_a"]));
    let pi_b = groth16_g2_bytes(&proof_json["pi_b"]);
    let pi_c = groth16_g1_bytes(&proof_json["pi_c"]);
    vault::zk::verifier::Groth16Proof { pi_a, pi_b, pi_c }
}

/// Build a single-leaf-aware Merkle inclusion witness for `target_index` in a
/// tree populated with `leaves`, padded with zero-subtree roots at deeper
/// levels. Returns (siblings[TREE_DEPTH], path_indices[TREE_DEPTH], root).
/// Byte-identical to `zk_spend_roundtrip.rs::merkle_witness`.
fn merkle_witness(leaves: &[[u8; 32]], target_index: usize) -> (Vec<[u8; 32]>, Vec<u8>, [u8; 32]) {
    assert!(target_index < leaves.len());
    let zero_subtree = vault::merkle::compute_zero_subtree_roots().unwrap();
    let mut siblings = vec![[0u8; 32]; TREE_DEPTH];
    let mut path_indices = vec![0u8; TREE_DEPTH];

    let n = leaves.len();
    let small_depth: usize = {
        let mut d = 0;
        while (1usize << d) < n {
            d += 1;
        }
        d.max(1)
    };
    let padded_len = 1usize << small_depth;

    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    level.resize(padded_len, [0u8; 32]);

    let mut idx = target_index;
    for (d, sib) in siblings.iter_mut().enumerate().take(small_depth) {
        let sibling_idx = idx ^ 1;
        *sib = level[sibling_idx];
        path_indices[d] = (idx & 1) as u8;
        idx >>= 1;

        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            next.push(vault::merkle::poseidon2(&pair[0], &pair[1]).unwrap());
        }
        level = next;
    }

    let mut current = level[0];
    for d in small_depth..TREE_DEPTH {
        siblings[d] = zero_subtree[d];
        path_indices[d] = 0;
        current = vault::merkle::poseidon2(&current, &zero_subtree[d]).unwrap();
    }

    (siblings, path_indices, current)
}

fn fr_to_dec(fr: &Fr) -> String {
    let bytes = fr.into_bigint().to_bytes_be();
    num_bigint_decstring(&bytes)
}

fn num_bigint_decstring(bytes: &[u8]) -> String {
    let mut n: Vec<u32> = Vec::new();
    for &b in bytes {
        let mut carry = b as u64;
        for limb in n.iter_mut() {
            let v = (*limb as u64) * 256 + carry;
            *limb = (v % 1_000_000_000) as u32;
            carry = v / 1_000_000_000;
        }
        while carry > 0 {
            n.push((carry % 1_000_000_000) as u32);
            carry /= 1_000_000_000;
        }
    }
    if n.is_empty() {
        return "0".into();
    }
    let mut out = String::new();
    for (i, limb) in n.iter().rev().enumerate() {
        if i == 0 {
            out.push_str(&limb.to_string());
        } else {
            out.push_str(&format!("{limb:09}"));
        }
    }
    out
}

fn dec_to_be32(s: &str) -> [u8; 32] {
    let mut digits: Vec<u8> = s.bytes().map(|b| b - b'0').collect();
    let mut out = [0u8; 32];
    let mut byte_idx = 32;
    while !digits.is_empty() && byte_idx > 0 {
        let mut rem: u32 = 0;
        let mut new_digits: Vec<u8> = Vec::with_capacity(digits.len());
        for d in &digits {
            let cur = rem * 10 + *d as u32;
            let q = cur / 256;
            rem = cur % 256;
            if !(new_digits.is_empty() && q == 0) {
                new_digits.push(q as u8);
            }
        }
        byte_idx -= 1;
        out[byte_idx] = rem as u8;
        digits = new_digits;
    }
    out
}

fn groth16_g1_bytes(v: &serde_json::Value) -> [u8; 64] {
    let x = dec_to_be32(v[0].as_str().unwrap());
    let y = dec_to_be32(v[1].as_str().unwrap());
    let mut out = [0u8; 64];
    out[0..32].copy_from_slice(&x);
    out[32..64].copy_from_slice(&y);
    out
}

fn groth16_g2_bytes(v: &serde_json::Value) -> [u8; 128] {
    let x0 = dec_to_be32(v[0][0].as_str().unwrap());
    let x1 = dec_to_be32(v[0][1].as_str().unwrap());
    let y0 = dec_to_be32(v[1][0].as_str().unwrap());
    let y1 = dec_to_be32(v[1][1].as_str().unwrap());
    let mut out = [0u8; 128];
    out[0..32].copy_from_slice(&x1);
    out[32..64].copy_from_slice(&x0);
    out[64..96].copy_from_slice(&y1);
    out[96..128].copy_from_slice(&y0);
    out
}

fn negate_g1(point: &[u8; 64]) -> [u8; 64] {
    const P_BYTES: [u8; 32] = [
        0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58,
        0x5d, 0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c,
        0xfd, 0x47,
    ];
    let mut out = [0u8; 64];
    out[0..32].copy_from_slice(&point[0..32]);
    let mut y = [0u8; 32];
    y.copy_from_slice(&point[32..64]);
    let y_neg = sub_be(&P_BYTES, &y);
    out[32..64].copy_from_slice(&y_neg);
    out
}

fn sub_be(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow: i16 = 0;
    for i in (0..32).rev() {
        let diff = a[i] as i16 - b[i] as i16 - borrow;
        if diff < 0 {
            out[i] = (diff + 256) as u8;
            borrow = 1;
        } else {
            out[i] = diff as u8;
            borrow = 0;
        }
    }
    out
}
