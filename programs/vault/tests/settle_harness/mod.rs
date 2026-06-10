//! Shared helpers for matching_engine integration tests.
#![allow(dead_code)]

use std::path::PathBuf;

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

// Must match `declare_id!` in the respective lib.rs files. LiteSVM's
// `add_program_from_file` reads the declared id baked into the ELF and
// rejects loads under a different id with InvalidAccountData.
pub const VAULT_PROGRAM_ID: &str = "C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx";
pub const ME_PROGRAM_ID: &str = "6EasFxo6RCWrK4KAwcdUJqL4KjReLC3rtah8EtHgHSqe";

pub fn repo_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

pub fn vault_so_path() -> PathBuf {
    repo_root().join("target/deploy/vault.so")
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
    pub tee_pubkey: [u8; 32],
    pub root_key: [u8; 32],
    pub num_trees: u8,
}

#[derive(BorshSerialize)]
pub struct InitMarketArgs {
    pub market: [u8; 32],
    pub base_mint: [u8; 32],
    pub quote_mint: [u8; 32],
    pub pyth_account: [u8; 32],
    pub batch_interval_slots: u64,
    pub circuit_breaker_bps: u64,
    pub tick_size: u64,
    pub min_order_size: u64,
}

/// Borsh shape of the privacy-fix `submit_order` args. Mirrors
/// `programs/matching_engine/src/instructions/submit_order.rs::SubmitOrderArgs`.
#[derive(BorshSerialize, Clone, Copy)]
pub struct SubmitOrderArgs {
    pub market: [u8; 32],
    pub slot_idx: u8,
    pub side: u8,
    pub order_type: u8,
    pub _padding: [u8; 5],
    pub amount: u64,
    pub min_fill_qty: u64,
    pub price_limit: u64,
    pub note_amount: u64,
    pub expiry_slot: u64,
    pub order_id: [u8; 16],
    pub note_commitment: [u8; 32],
    pub user_commitment: [u8; 32],
}

// ============================================================================
// PDA helpers
// ============================================================================

pub fn vault_config_pda(program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"vault_config"], program_id)
}

/// Per-shard Merkle-tree PDA. Seed `[b"merkle_tree", &[tree_id]]` — mirrors
/// `vault::state::MerkleTree::SEED`.
pub fn merkle_tree_pda(program_id: &Pubkey, tree_id: u8) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[b"merkle_tree", core::slice::from_ref(&tree_id)],
        program_id,
    )
}

pub fn dark_clob_pda(program_id: &Pubkey, market: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"dark_clob", market.as_ref()], program_id)
}

pub fn matching_config_pda(program_id: &Pubkey, market: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"matching_config", market.as_ref()], program_id)
}

pub fn batch_results_pda(program_id: &Pubkey, market: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"batch_results", market.as_ref()], program_id)
}

pub fn wallet_entry_pda(program_id: &Pubkey, commitment: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"wallet", commitment.as_ref()], program_id)
}

pub fn note_lock_pda(program_id: &Pubkey, commitment: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"note_lock", commitment.as_ref()], program_id)
}

pub fn pending_order_pda(
    program_id: &Pubkey,
    market: &Pubkey,
    trading_key: &Pubkey,
    slot_idx: u8,
) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[
            b"pending_order",
            market.as_ref(),
            trading_key.as_ref(),
            core::slice::from_ref(&slot_idx),
        ],
        program_id,
    )
}

pub fn consumed_note_pda(program_id: &Pubkey, commitment: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"consumed_note", commitment.as_ref()], program_id)
}

pub fn nullifier_pda(program_id: &Pubkey, nullifier: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"nullifier", nullifier.as_ref()], program_id)
}

// ============================================================================
// Harness
// ============================================================================

/// Bundle of programs + funded keys + initialised vault.
pub struct Harness {
    pub svm: LiteSVM,
    pub vault_id: Pubkey,
    pub me_id: Pubkey,
    pub admin: Keypair,
    pub tee: Keypair,
    pub root: Keypair,
    pub trader: Keypair,
    pub pyth_account: Pubkey,
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
        let me_id: Pubkey = ME_PROGRAM_ID.parse().unwrap();
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
            tee_pubkey: tee.pubkey().to_bytes(),
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

        // Create a mock Pyth oracle account holding a TWAP of 150 (arbitrary).
        let pyth_account = Keypair::new().pubkey();
        Self::write_mock_oracle(&mut svm, &pyth_account, 150);

        // v2: NoteLock now carries token_mint. A fresh dummy keypair is fine
        // for tests — the on-chain handler only uses it for the VALID_CREATE
        // binding-hash recomputation and per-mint conservation, both of which
        // are byte-equality checks the test harness mirrors.
        let test_mint = Keypair::new().pubkey();

        Self {
            svm,
            vault_id,
            me_id,
            admin,
            tee,
            root,
            trader,
            pyth_account,
            test_mint,
        }
    }

    /// Write a mock oracle account with the `NYXMKPTH` magic + u64 twap at offset 8.
    pub fn write_mock_oracle(svm: &mut LiteSVM, addr: &Pubkey, twap: u64) {
        use solana_account::Account as SolAccount;

        let mut data = vec![0u8; 16];
        data[0..8].copy_from_slice(b"NYXMKPTH");
        data[8..16].copy_from_slice(&twap.to_le_bytes());
        let acct = SolAccount {
            lamports: svm.minimum_balance_for_rent_exemption(data.len()),
            data,
            owner: Pubkey::new_from_array([0u8; 32]),
            executable: false,
            rent_epoch: 0,
        };
        svm.set_account(*addr, acct).unwrap();
    }

    pub fn update_mock_oracle(&mut self, twap: u64) {
        Self::write_mock_oracle(&mut self.svm, &self.pyth_account.clone(), twap);
    }

    pub fn init_market(&mut self, market: &Pubkey, batch_interval_slots: u64) {
        self.init_market_full(market, batch_interval_slots, self.pyth_account, 300, 1, 0);
    }

    pub fn init_market_full(
        &mut self,
        market: &Pubkey,
        batch_interval_slots: u64,
        pyth: Pubkey,
        circuit_breaker_bps: u64,
        tick_size: u64,
        min_order_size: u64,
    ) {
        let (clob_pda, _) = dark_clob_pda(&self.me_id, market);
        let (match_pda, _) = matching_config_pda(&self.me_id, market);
        let (batch_pda, _) = batch_results_pda(&self.me_id, market);
        let (vault_pda, _) = vault_config_pda(&self.vault_id);

        let base_mint = Keypair::new().pubkey();
        let quote_mint = Keypair::new().pubkey();

        let mut data = anchor_disc("init_market").to_vec();
        InitMarketArgs {
            market: market.to_bytes(),
            base_mint: base_mint.to_bytes(),
            quote_mint: quote_mint.to_bytes(),
            pyth_account: pyth.to_bytes(),
            batch_interval_slots,
            circuit_breaker_bps,
            tick_size,
            min_order_size,
        }
        .serialize(&mut data)
        .unwrap();

        let ix = Instruction {
            program_id: self.me_id,
            accounts: vec![
                AccountMeta::new(self.admin.pubkey(), true),
                AccountMeta::new_readonly(vault_pda, false),
                AccountMeta::new(clob_pda, false),
                AccountMeta::new(match_pda, false),
                AccountMeta::new(batch_pda, false),
                AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            ],
            data,
        };
        let tx = Transaction::new(
            &[&self.admin],
            Message::new(&[ix], Some(&self.admin.pubkey())),
            self.svm.latest_blockhash(),
        );
        self.svm.send_transaction(tx).expect("init_market failed");
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

    /// Build a privacy-fix `submit_order` ix. The signer (`trading_key`)
    /// is `self.trader`. The PendingOrder PDA seed is derived from the
    /// args' market + slot_idx and the trader pubkey.
    pub fn build_submit_order_ix(&self, args: SubmitOrderArgs) -> Instruction {
        self.build_submit_order_ix_for(args, &self.trader)
    }

    pub fn build_submit_order_ix_for(
        &self,
        args: SubmitOrderArgs,
        trader: &Keypair,
    ) -> Instruction {
        let market = Address::new_from_array(args.market);
        let (slot_pda, _) =
            pending_order_pda(&self.me_id, &market, &trader.pubkey(), args.slot_idx);

        let mut data = anchor_disc("submit_order").to_vec();
        args.serialize(&mut data).unwrap();

        Instruction {
            program_id: self.me_id,
            accounts: vec![
                AccountMeta::new(trader.pubkey(), true),
                AccountMeta::new(slot_pda, false),
            ],
            data,
        }
    }

    /// Build a privacy-fix `init_pending_order_slot` ix.
    pub fn build_init_pending_order_slot_ix(
        &self,
        market: &Pubkey,
        slot_idx: u8,
        trader: &Keypair,
    ) -> Instruction {
        let (slot_pda, _) = pending_order_pda(&self.me_id, market, &trader.pubkey(), slot_idx);

        let mut data = anchor_disc("init_pending_order_slot").to_vec();
        data.extend_from_slice(&market.to_bytes());
        data.push(slot_idx);

        Instruction {
            program_id: self.me_id,
            accounts: vec![
                AccountMeta::new(trader.pubkey(), true),
                AccountMeta::new(slot_pda, false),
                AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            ],
            data,
        }
    }
}

// ============================================================================
// PendingOrder direct-write helpers for run_batch tests.
//
// Mirrors the privacy-fix `PendingOrder` zero-copy layout. We seed the
// PDA account directly because in litesvm we don't have an ER session
// — the slot effectively starts pre-delegated for the program to read.
// ============================================================================

/// Layout MUST match
/// programs/matching_engine/src/state/pending_order.rs::PendingOrder.
pub const PENDING_ORDER_DATA_SIZE: usize = 32  // trading_key
    + 32  // market
    + 1   // status
    + 1   // side
    + 1   // order_type
    + 1   // slot_idx
    + 1   // bump
    + 3   // _padding_a
    + 8   // arrival_slot
    + 8   // expiry_slot
    + 8   // price_limit
    + 8   // amount
    + 8   // total_quantity
    + 8   // filled_quantity
    + 8   // min_fill_qty
    + 8   // note_amount
    + 32  // collateral_note
    + 32  // user_commitment
    + 16  // order_id
    + 8   // _padding_b
    + 32; // order_inclusion_commitment

#[derive(Clone, Copy, Debug)]
pub struct PendingSeed {
    pub trading_key: [u8; 32],
    pub slot_idx: u8,
    pub status: u8,
    pub side: u8,
    pub order_type: u8,
    pub arrival_slot: u64,
    pub expiry_slot: u64,
    pub price_limit: u64,
    pub amount: u64,
    pub total_quantity: u64,
    pub filled_quantity: u64,
    pub min_fill_qty: u64,
    pub note_amount: u64,
    pub collateral_note: [u8; 32],
    pub user_commitment: [u8; 32],
    pub order_id: [u8; 16],
    pub order_inclusion_commitment: [u8; 32],
}

/// Build a default PendingSeed (status = Pending, order_type = LIMIT).
pub fn make_pending_seed(
    trading_key: [u8; 32],
    slot_idx: u8,
    side: u8,
    price_limit: u64,
    amount: u64,
    expiry_slot: u64,
) -> PendingSeed {
    let mut collateral_note = [0u8; 32];
    collateral_note[0] = side;
    collateral_note[1..9].copy_from_slice(&(slot_idx as u64).to_le_bytes());
    collateral_note[9..17].copy_from_slice(&price_limit.to_le_bytes());
    let mut user_commitment = trading_key;
    user_commitment[0] = 0; // keep < BN254 Fr modulus for Poseidon
    let mut order_id = [0u8; 16];
    order_id[0] = side.wrapping_add(1);
    order_id[1] = slot_idx;
    order_id[2..10].copy_from_slice(&price_limit.to_le_bytes());
    let mut oic = [0u8; 32];
    oic[0] = side;
    oic[1] = slot_idx;
    oic[2..10].copy_from_slice(&price_limit.to_le_bytes());
    PendingSeed {
        trading_key,
        slot_idx,
        status: 1, // Pending
        side,
        order_type: 0, // LIMIT
        arrival_slot: 1,
        expiry_slot,
        price_limit,
        amount,
        total_quantity: amount,
        filled_quantity: 0,
        min_fill_qty: 0,
        note_amount: amount.saturating_mul(price_limit).max(amount).max(1),
        collateral_note,
        user_commitment,
        order_id,
        order_inclusion_commitment: oic,
    }
}

/// Write a PendingOrder PDA into litesvm's account store with the given
/// (market, trading_key, slot_idx). Returns the PDA pubkey for use as
/// remaining_accounts in `run_batch`.
pub fn seed_pending_order(h: &mut Harness, market: &Pubkey, seed: &PendingSeed) -> Pubkey {
    use solana_account::Account as SolAccount;

    let trading_key = Address::new_from_array(seed.trading_key);
    let (pda, bump) = pending_order_pda(&h.me_id, market, &trading_key, seed.slot_idx);

    let mut data = vec![0u8; 8 + PENDING_ORDER_DATA_SIZE];
    data[0..8].copy_from_slice(&anchor_acct_disc("PendingOrder"));
    let body = &mut data[8..];

    let mut off = 0;
    body[off..off + 32].copy_from_slice(&seed.trading_key);
    off += 32;
    body[off..off + 32].copy_from_slice(&market.to_bytes());
    off += 32;
    body[off] = seed.status;
    off += 1;
    body[off] = seed.side;
    off += 1;
    body[off] = seed.order_type;
    off += 1;
    body[off] = seed.slot_idx;
    off += 1;
    body[off] = bump;
    off += 1;
    off += 3; // _padding_a

    let put_u64 = |body: &mut [u8], off: &mut usize, v: u64| {
        body[*off..*off + 8].copy_from_slice(&v.to_le_bytes());
        *off += 8;
    };
    put_u64(body, &mut off, seed.arrival_slot);
    put_u64(body, &mut off, seed.expiry_slot);
    put_u64(body, &mut off, seed.price_limit);
    put_u64(body, &mut off, seed.amount);
    put_u64(body, &mut off, seed.total_quantity);
    put_u64(body, &mut off, seed.filled_quantity);
    put_u64(body, &mut off, seed.min_fill_qty);
    put_u64(body, &mut off, seed.note_amount);

    body[off..off + 32].copy_from_slice(&seed.collateral_note);
    off += 32;
    body[off..off + 32].copy_from_slice(&seed.user_commitment);
    off += 32;
    body[off..off + 16].copy_from_slice(&seed.order_id);
    off += 16;
    off += 8; // _padding_b
    body[off..off + 32].copy_from_slice(&seed.order_inclusion_commitment);
    off += 32;
    debug_assert_eq!(off, PENDING_ORDER_DATA_SIZE);

    let acct = SolAccount {
        lamports: h.svm.minimum_balance_for_rent_exemption(data.len()),
        data,
        owner: h.me_id,
        executable: false,
        rent_epoch: 0,
    };
    h.svm.set_account(pda, acct).unwrap();
    pda
}

/// Read just the `status` byte from a PendingOrder PDA.
pub fn read_pending_status(h: &Harness, pda: &Pubkey) -> u8 {
    let acct = h.svm.get_account(pda).expect("pending_order");
    // 8 (disc) + 32 trading_key + 32 market = offset of status.
    acct.data[8 + 64]
}

/// Read the current `amount` (remaining) from a PendingOrder PDA.
pub fn read_pending_amount(h: &Harness, pda: &Pubkey) -> u64 {
    let acct = h.svm.get_account(pda).expect("pending_order");
    // After 8 disc + 32 tk + 32 mkt + 5×u8 + 3 pad = 80 bytes; then
    // arrival_slot + expiry_slot + price_limit = 24, then amount.
    let off = 8 + 32 + 32 + 1 + 1 + 1 + 1 + 1 + 3 + 8 + 8 + 8;
    u64::from_le_bytes(acct.data[off..off + 8].try_into().unwrap())
}

// ============================================================================
// LEGACY DarkCLOB direct-write helpers (kept for compatibility — not used
// by privacy-fix tests).
// ============================================================================

/// Layout must match `OrderRecord` in
/// programs/matching_engine/src/state/order_record.rs — keep in sync.
/// Phase 5: +note_amount, +total_quantity, +filled_quantity, +user_commitment;
/// renamed note_commitment → collateral_note.
pub const ORDER_RECORD_SIZE: usize = 8    // seq_no
    + 8   // arrival_slot
    + 8   // expiry_slot
    + 8   // price_limit
    + 8   // amount
    + 8   // min_fill_qty
    + 8   // note_amount
    + 8   // total_quantity
    + 8   // filled_quantity
    + 32  // trading_key
    + 32  // collateral_note
    + 32  // user_commitment
    + 32  // order_inclusion_commitment
    + 16  // order_id
    + 1   // side
    + 1   // status
    + 1   // order_type
    + 5; // padding

pub const DARK_CLOB_CAPACITY: usize = 45;

/// Full DarkCLOB data size (no Anchor disc).
/// Layout: 32 market + 8 next_seq + 8 order_count + orders + 1 bump + 7 pad
pub const DARK_CLOB_DATA_SIZE: usize = 32 + 8 + 8 + ORDER_RECORD_SIZE * DARK_CLOB_CAPACITY + 1 + 7;

/// Encode a single OrderRecord as its zero-copy bytes (side-safe).
#[derive(Clone, Copy, Debug)]
pub struct OrderSeed {
    pub seq_no: u64,
    pub arrival_slot: u64,
    pub expiry_slot: u64,
    pub price_limit: u64,
    pub amount: u64,
    pub min_fill_qty: u64,
    pub note_amount: u64,
    pub total_quantity: u64,
    pub filled_quantity: u64,
    pub trading_key: [u8; 32],
    pub collateral_note: [u8; 32],
    pub user_commitment: [u8; 32],
    pub order_inclusion_commitment: [u8; 32],
    pub order_id: [u8; 16],
    pub side: u8,
    pub status: u8,
    pub order_type: u8,
}

impl OrderSeed {
    pub fn write_into(&self, out: &mut [u8]) {
        assert_eq!(out.len(), ORDER_RECORD_SIZE);
        let mut off = 0;
        let mut put_u64 = |off: &mut usize, v: u64| {
            out[*off..*off + 8].copy_from_slice(&v.to_le_bytes());
            *off += 8;
        };
        put_u64(&mut off, self.seq_no);
        put_u64(&mut off, self.arrival_slot);
        put_u64(&mut off, self.expiry_slot);
        put_u64(&mut off, self.price_limit);
        put_u64(&mut off, self.amount);
        put_u64(&mut off, self.min_fill_qty);
        put_u64(&mut off, self.note_amount);
        put_u64(&mut off, self.total_quantity);
        put_u64(&mut off, self.filled_quantity);
        out[off..off + 32].copy_from_slice(&self.trading_key);
        off += 32;
        out[off..off + 32].copy_from_slice(&self.collateral_note);
        off += 32;
        out[off..off + 32].copy_from_slice(&self.user_commitment);
        off += 32;
        out[off..off + 32].copy_from_slice(&self.order_inclusion_commitment);
        off += 32;
        out[off..off + 16].copy_from_slice(&self.order_id);
        off += 16;
        out[off] = self.side;
        off += 1;
        out[off] = self.status;
        off += 1;
        out[off] = self.order_type;
        off += 1;
        // 5 bytes padding — leave zero.
        off += 5;
        assert_eq!(off, ORDER_RECORD_SIZE);
    }
}

/// Stuff the given OrderSeeds into the DarkCLOB PDA starting at slot 0.
/// Clobbers next_seq to max(existing, highest seed seq_no + 1) so later
/// submit_order calls don't collide (not needed for Phase-4 tests yet).
pub fn seed_dark_clob(h: &mut Harness, market: &Pubkey, seeds: &[OrderSeed]) {
    let (pda, _) = dark_clob_pda(&h.me_id, market);
    let mut acct = h
        .svm
        .get_account(&pda)
        .expect("dark_clob PDA must exist — call init_market first");
    assert!(acct.data.len() == 8 + DARK_CLOB_DATA_SIZE);

    // Layout within account: 8 (disc) + 32 market + 8 next_seq + 8 order_count + orders...
    let orders_start = 8 + 32 + 8 + 8;
    let mut active_count: u64 = 0;
    let mut max_seq: u64 = 0;

    for (i, seed) in seeds.iter().enumerate() {
        assert!(i < DARK_CLOB_CAPACITY, "CLOB capacity exceeded");
        let start = orders_start + i * ORDER_RECORD_SIZE;
        let end = start + ORDER_RECORD_SIZE;
        seed.write_into(&mut acct.data[start..end]);
        if seed.status != 0 {
            active_count += 1;
        }
        if seed.seq_no >= max_seq {
            max_seq = seed.seq_no + 1;
        }
    }
    // Write order_count.
    acct.data[8 + 32 + 8..8 + 32 + 8 + 8].copy_from_slice(&active_count.to_le_bytes());
    // Bump next_seq forward.
    let existing_next = u64::from_le_bytes(acct.data[8 + 32..8 + 32 + 8].try_into().unwrap());
    let next_seq = existing_next.max(max_seq);
    acct.data[8 + 32..8 + 32 + 8].copy_from_slice(&next_seq.to_le_bytes());

    h.svm.set_account(pda, acct).unwrap();
}

/// Build a `run_batch` ix (no CPI, no vault account needed).
/// `ComputeBudget::SetComputeUnitLimit(cu)` ix. Phase-5's Poseidon calls
/// are expensive (~17k CU each) so run_batch can exceed the 200k default
/// when multiple matches produce change notes; tests should prepend this.
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

pub fn build_run_batch_ix(
    h: &Harness,
    market: &Pubkey,
    tee: &Keypair,
    pending_order_pdas: &[Pubkey],
) -> Instruction {
    let (match_pda, _) = matching_config_pda(&h.me_id, market);
    let (batch_pda, _) = batch_results_pda(&h.me_id, market);
    let (vault_pda, _) = vault_config_pda(&h.vault_id);

    let mut data = anchor_disc("run_batch").to_vec();
    data.extend_from_slice(&market.to_bytes());

    let mut accounts = vec![
        AccountMeta::new(tee.pubkey(), true),
        AccountMeta::new_readonly(match_pda, false),
        AccountMeta::new(batch_pda, false),
        AccountMeta::new_readonly(vault_pda, false),
        AccountMeta::new_readonly(h.pyth_account, false),
    ];
    for pda in pending_order_pdas {
        accounts.push(AccountMeta::new(*pda, false));
    }
    Instruction {
        program_id: h.me_id,
        accounts,
        data,
    }
}

/// Build a privacy-fix `cancel_order` ix.
pub fn build_cancel_order_ix(
    h: &Harness,
    market: &Pubkey,
    slot_idx: u8,
    signer: &Keypair,
) -> Instruction {
    let (slot_pda, _) = pending_order_pda(&h.me_id, market, &signer.pubkey(), slot_idx);

    let mut data = anchor_disc("cancel_order").to_vec();
    data.extend_from_slice(&market.to_bytes());
    data.push(slot_idx);

    Instruction {
        program_id: h.me_id,
        accounts: vec![
            AccountMeta::new(signer.pubkey(), true),
            AccountMeta::new(slot_pda, false),
        ],
        data,
    }
}

/// Decode BatchResults header fields (last_inclusion_root + stats).
pub struct BatchResultsView {
    pub last_inclusion_root: [u8; 32],
    pub last_batch_slot: u64,
    pub last_match_count: u64,
    pub last_clearing_price: u64,
    pub last_pyth_twap: u64,
    pub last_circuit_breaker_tripped: u8,
}

pub fn read_batch_results(h: &Harness, market: &Pubkey) -> BatchResultsView {
    let (pda, _) = batch_results_pda(&h.me_id, market);
    let acct = h.svm.get_account(&pda).expect("batch_results must exist");
    // Layout: 8 disc + 32 market + 32 last_inclusion_root + 8 last_batch_slot
    //       + 8 last_match_count + 8 last_clearing_price + 8 last_pyth_twap
    //       + 1 cb_tripped + 7 pad + ...
    let d = &acct.data;
    let mut off = 8 + 32;
    let mut last_inclusion_root = [0u8; 32];
    last_inclusion_root.copy_from_slice(&d[off..off + 32]);
    off += 32;
    let last_batch_slot = u64::from_le_bytes(d[off..off + 8].try_into().unwrap());
    off += 8;
    let last_match_count = u64::from_le_bytes(d[off..off + 8].try_into().unwrap());
    off += 8;
    let last_clearing_price = u64::from_le_bytes(d[off..off + 8].try_into().unwrap());
    off += 8;
    let last_pyth_twap = u64::from_le_bytes(d[off..off + 8].try_into().unwrap());
    off += 8;
    let last_circuit_breaker_tripped = d[off];
    BatchResultsView {
        last_inclusion_root,
        last_batch_slot,
        last_match_count,
        last_clearing_price,
        last_pyth_twap,
        last_circuit_breaker_tripped,
    }
}

/// Read the `status` byte of the OrderRecord at `slot` of the CLOB.
pub fn read_order_status(h: &Harness, market: &Pubkey, slot: usize) -> u8 {
    let (pda, _) = dark_clob_pda(&h.me_id, market);
    let acct = h.svm.get_account(&pda).expect("dark_clob");
    // inside data: 8 disc + 32 market + 8 next_seq + 8 order_count + orders*
    // status byte within an OrderRecord (Phase 5): 9 u64s + 4×32B + 16B + side+status.
    //   9×8 (u64s: seq/arr/exp/price/amt/minfill/note_amount/total_qty/filled_qty)
    //   + 32 tk + 32 collateral + 32 user_commit + 32 oic + 16 oid + 1 side + 1 status
    let off = 8 + 32 + 8 + 8 + slot * ORDER_RECORD_SIZE + 8 * 9 + 32 * 4 + 16 + 1;
    acct.data[off]
}

/// Build a default OrderSeed with deterministic collateral_note = [side,seq,0,...].
pub fn make_seed(
    seq_no: u64,
    side: u8,
    price_limit: u64,
    amount: u64,
    expiry_slot: u64,
    trading_key: [u8; 32],
) -> OrderSeed {
    let mut collateral_note = [0u8; 32];
    collateral_note[0] = side;
    collateral_note[1..9].copy_from_slice(&seq_no.to_le_bytes());
    let mut order_id = [0u8; 16];
    // Reserve byte 15 for uniqueness so the all-zero sentinel isn't hit.
    order_id[0..8].copy_from_slice(&seq_no.to_le_bytes());
    order_id[15] = side.wrapping_add(1);
    let mut oic = [0u8; 32];
    oic[0..8].copy_from_slice(&seq_no.to_le_bytes());
    oic[8] = side;
    // Phase 5: Poseidon (BN254) needs inputs < Fr modulus. Zero the top
    // byte so arbitrary 32-byte harness fixtures stay inside the field.
    let mut user_commitment = trading_key;
    user_commitment[0] = 0;
    OrderSeed {
        seq_no,
        arrival_slot: 1,
        expiry_slot,
        price_limit,
        amount,
        min_fill_qty: 0,
        note_amount: amount.saturating_mul(price_limit).max(1),
        total_quantity: amount,
        filled_quantity: 0,
        trading_key,
        collateral_note,
        user_commitment,
        order_inclusion_commitment: oic,
        order_id,
        side,
        status: 1,     // ACTIVE
        order_type: 0, // LIMIT
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
    pub note_a_commitment: [u8; 32],
    pub note_b_commitment: [u8; 32],
    pub note_c_commitment: [u8; 32],
    pub note_d_commitment: [u8; 32],
    pub note_e_commitment: [u8; 32],
    pub note_f_commitment: [u8; 32],
    pub nullifier_a: [u8; 32],
    pub nullifier_b: [u8; 32],
    pub order_id_a: [u8; 16],
    pub order_id_b: [u8; 16],
    pub base_amount: u64,
    pub quote_amount: u64,
    pub buyer_change_amt: u64,
    pub seller_change_amt: u64,
    pub buyer_fee_amt: u64,
    pub seller_fee_amt: u64,
    pub note_fee_base_commitment: [u8; 32],
    pub note_fee_quote_commitment: [u8; 32],
    pub buyer_relock_order_id: [u8; 16],
    pub buyer_relock_expiry: u64,
    pub seller_relock_order_id: [u8; 16],
    pub seller_relock_expiry: u64,
    pub clearing_price: u64,
    pub batch_slot: u64,
    // v3.1: price_proof + price_commitment were removed from the payload.
    // The VALID_PRICE proof now lives in a preceding `verify_valid_price`
    // ix that writes a marker PDA at [b"valid_price", price_commitment].
    // The settle handler recomputes price_commitment from
    // (clearing_price, batch_slot) and checks the marker exists.
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
        nullifier_a: [u8; 32],
        nullifier_b: [u8; 32],
        order_id_a: [u8; 16],
        order_id_b: [u8; 16],
        base_amount: u64,
        quote_amount: u64,
    ) -> Self {
        Self {
            match_id,
            note_a_commitment: note_a,
            note_b_commitment: note_b,
            note_c_commitment: note_c,
            note_d_commitment: note_d,
            note_e_commitment: [0u8; 32],
            note_f_commitment: [0u8; 32],
            nullifier_a,
            nullifier_b,
            order_id_a,
            order_id_b,
            base_amount,
            quote_amount,
            buyer_change_amt: 0,
            seller_change_amt: 0,
            buyer_fee_amt: 0,
            seller_fee_amt: 0,
            note_fee_base_commitment: [0u8; 32],
            note_fee_quote_commitment: [0u8; 32],
            buyer_relock_order_id: RELOCK_ORDER_ID_NONE,
            buyer_relock_expiry: 0,
            seller_relock_order_id: RELOCK_ORDER_ID_NONE,
            seller_relock_expiry: 0,
            clearing_price: 0,
            batch_slot: 0,
        }
    }
}

/// Mirror of `tee_forced_settle::canonical_payload_hash`. Byte-identical
/// output or signature verification fails.
pub fn canonical_payload_hash(p: &MatchResultPayload) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"nyx-match-v6");
    h.update(p.match_id);
    h.update(p.note_a_commitment);
    h.update(p.note_b_commitment);
    h.update(p.note_c_commitment);
    h.update(p.note_d_commitment);
    h.update(p.note_e_commitment);
    h.update(p.note_f_commitment);
    h.update(p.note_fee_base_commitment);
    h.update(p.note_fee_quote_commitment);
    h.update(p.nullifier_a);
    h.update(p.nullifier_b);
    h.update(p.order_id_a);
    h.update(p.order_id_b);
    h.update(p.base_amount.to_le_bytes());
    h.update(p.quote_amount.to_le_bytes());
    h.update(p.buyer_change_amt.to_le_bytes());
    h.update(p.seller_change_amt.to_le_bytes());
    h.update(p.buyer_fee_amt.to_le_bytes());
    h.update(p.seller_fee_amt.to_le_bytes());
    h.update(p.buyer_relock_order_id);
    h.update(p.buyer_relock_expiry.to_le_bytes());
    h.update(p.seller_relock_order_id);
    h.update(p.seller_relock_expiry.to_le_bytes());
    h.update(p.clearing_price.to_le_bytes());
    h.update(p.batch_slot.to_le_bytes());
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
    amount: u64,
) {
    use solana_account::Account as SolAccount;
    let (pda, bump) = note_lock_pda(&h.vault_id, note_commitment);
    // v2 layout: 8 disc + 32 commit + 32 token_mint + 16 order_id + 8 expiry
    //          + 32 locked_by + 8 amount + 1 bump + 7 pad = 144 bytes.
    // token_mint sits between note_commitment and order_id (matches
    // `vault::state::NoteLock` exactly; keep in sync if NoteLock ever moves
    // fields). Uses `h.test_mint` so seed_valid_create_marker / build_settle_ix
    // compute a consistent binding hash from the same mint.
    let mut data = vec![0u8; 144];
    data[0..8].copy_from_slice(&anchor_acct_disc("NoteLock"));
    data[8..40].copy_from_slice(note_commitment);
    data[40..72].copy_from_slice(&h.test_mint.to_bytes());
    data[72..88].copy_from_slice(order_id);
    data[88..96].copy_from_slice(&expiry_slot.to_le_bytes());
    data[96..128].copy_from_slice(&h.tee.pubkey().to_bytes());
    data[128..136].copy_from_slice(&amount.to_le_bytes());
    data[136] = bump;
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

/// True if the `consumed_note` PDA for `note_commitment` has been initialised.
pub fn consumed_note_exists(h: &Harness, note_commitment: &[u8; 32]) -> bool {
    let (pda, _) = consumed_note_pda(&h.vault_id, note_commitment);
    h.svm
        .get_account(&pda)
        .map(|a| !a.data.is_empty() && a.lamports > 0)
        .unwrap_or(false)
}

/// True if the `nullifier` PDA exists.
pub fn nullifier_exists(h: &Harness, nullifier: &[u8; 32]) -> bool {
    let (pda, _) = nullifier_pda(&h.vault_id, nullifier);
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
        note_a_commitment: p.note_a_commitment,
        note_b_commitment: p.note_b_commitment,
        note_c_commitment: p.note_c_commitment,
        note_d_commitment: p.note_d_commitment,
        note_e_commitment: p.note_e_commitment,
        note_f_commitment: p.note_f_commitment,
        nullifier_a: p.nullifier_a,
        nullifier_b: p.nullifier_b,
        order_id_a: p.order_id_a,
        order_id_b: p.order_id_b,
        base_amount: p.base_amount,
        quote_amount: p.quote_amount,
        buyer_change_amt: p.buyer_change_amt,
        seller_change_amt: p.seller_change_amt,
        buyer_fee_amt: p.buyer_fee_amt,
        seller_fee_amt: p.seller_fee_amt,
        note_fee_base_commitment: p.note_fee_base_commitment,
        note_fee_quote_commitment: p.note_fee_quote_commitment,
        buyer_relock_order_id: p.buyer_relock_order_id,
        buyer_relock_expiry: p.buyer_relock_expiry,
        seller_relock_order_id: p.seller_relock_order_id,
        seller_relock_expiry: p.seller_relock_expiry,
        clearing_price: p.clearing_price,
        batch_slot: p.batch_slot,
    }
}

/// Recompute the per-slot Merkle leaf the on-chain handler expects.
/// Wraps `vault::instructions::tee_forced_settle_batched::compute_match_leaf`
/// (exposed for this exact purpose) so the leaf can never drift from
/// the on-chain implementation.
pub fn compute_match_leaf_for(
    payload: &MatchResultPayload,
    quote_mint: &Pubkey,
    base_mint: &Pubkey,
) -> [u8; 32] {
    use anchor_lang::prelude::Pubkey as AnchorPubkey;
    let qm = AnchorPubkey::new_from_array(quote_mint.to_bytes());
    let bm = AnchorPubkey::new_from_array(base_mint.to_bytes());
    vault::instructions::tee_forced_settle_batched::compute_match_leaf(
        &to_onchain_payload(payload),
        &qm,
        &bm,
    )
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
    let (lock_a, _) = note_lock_pda(&h.vault_id, &payload.note_a_commitment);
    let (lock_b, _) = note_lock_pda(&h.vault_id, &payload.note_b_commitment);
    let (consumed_a, _) = consumed_note_pda(&h.vault_id, &payload.note_a_commitment);
    let (consumed_b, _) = consumed_note_pda(&h.vault_id, &payload.note_b_commitment);
    let (null_a, _) = nullifier_pda(&h.vault_id, &payload.nullifier_a);
    let (null_b, _) = nullifier_pda(&h.vault_id, &payload.nullifier_b);
    let (lock_e, _) = note_lock_pda(&h.vault_id, &payload.note_e_commitment);
    let (lock_f, _) = note_lock_pda(&h.vault_id, &payload.note_f_commitment);

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
            AccountMeta::new(null_a, false),
            AccountMeta::new(null_b, false),
            AccountMeta::new(lock_e, false),
            AccountMeta::new(lock_f, false),
            AccountMeta::new_readonly(instructions_sysvar, false),
            AccountMeta::new(marker_pda, false),
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
    merkle_root: &[u8; 32],
    expiry_slot: u64,
    proof_bytes: &[u8; 256],
) -> Instruction {
    let (marker_pda, _) = batch_validity_marker_pda(h, merkle_root);
    let mut data = anchor_disc("verify_match_batch").to_vec();
    data.extend_from_slice(merkle_root);
    data.extend_from_slice(&expiry_slot.to_le_bytes());
    data.extend_from_slice(proof_bytes);
    Instruction {
        program_id: h.vault_id,
        accounts: vec![
            AccountMeta::new(*payer, true),
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
    let mint = read_note_lock_mint(h, &p.note_a_commitment);
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
    let mint = read_note_lock_mint(h, &p.note_a_commitment);
    let leaf = compute_match_leaf_for(p, &mint, &mint);
    let mut leaves = [[0u8; 32]; 16];
    leaves[0] = leaf;
    let (root, proof) = build_merkle_root_and_path_n16(&leaves, 0);
    seed_batch_validity_marker(h, &root, u64::MAX / 2);
    // Single-tree default: settle outputs append to shard 0.
    build_settle_batched_ix(h, 0, p, 0, &proof, &root)
}

/// Build a `close_batch_validity_marker` ix.
/// `authority == payer` is the fast-path (matcher closes immediately
/// after the last settle); `authority != payer` is the expiry-GC path
/// (anyone can sweep an expired marker; rent still flows to payer).
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
