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
    pub operations_admin: [u8; 32],
    pub tee_pubkeys: Vec<[u8; 32]>,
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

/// Retired on-chain order-intake fixture retained only for old harness helpers.
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

    /// Write a mock oracle account with the `DNYXMPTH` magic + u64 twap at offset 8.
    pub fn write_mock_oracle(svm: &mut LiteSVM, addr: &Pubkey, twap: u64) {
        use solana_account::Account as SolAccount;

        let mut data = vec![0u8; 16];
        data[0..8].copy_from_slice(b"DNYXMPTH");
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

/// Retired PendingOrder fixture layout.
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

/// Retired on-chain OrderRecord fixture layout.
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
    pub order_id_a: [u8; 16],
    pub order_id_b: [u8; 16],
    pub note_fee_base_commitment: [u8; 32],
    pub note_fee_quote_commitment: [u8; 32],
    pub buyer_relock_order_id: [u8; 16],
    pub buyer_relock_expiry: u64,
    pub seller_relock_order_id: [u8; 16],
    pub seller_relock_expiry: u64,
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
            note_a_commitment: note_a,
            note_b_commitment: note_b,
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
    h.update(b"darknyx-match-v10");
    h.update(p.match_id);
    h.update(p.note_a_commitment);
    h.update(p.note_b_commitment);
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
        note_a_commitment: p.note_a_commitment,
        note_b_commitment: p.note_b_commitment,
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
    let (lock_a, _) = note_lock_pda(&h.vault_id, &payload.note_a_commitment);
    let (lock_b, _) = note_lock_pda(&h.vault_id, &payload.note_b_commitment);
    let (consumed_a, _) = consumed_note_pda(&h.vault_id, &payload.note_a_commitment);
    let (consumed_b, _) = consumed_note_pda(&h.vault_id, &payload.note_b_commitment);
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
    expiry_slot: u64,
    proof_bytes: &[u8; 256],
) -> Instruction {
    let (marker_pda, _) = batch_validity_marker_pda(h, merkle_root);
    let (vault_pda, _) = vault_config_pda(&h.vault_id);
    let (market_pda, _) = test_market_config_pda(&h.vault_id, base_mint, quote_mint);
    let mut data = anchor_disc("verify_match_batch").to_vec();
    data.extend_from_slice(merkle_root);
    data.extend_from_slice(&expiry_slot.to_le_bytes());
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
        let owner_commitment = poseidon_hash(&[Fr::from(1u64), spending_key, r_owner]).unwrap();
        let inner_hash =
            poseidon_hash(&[Fr::from(27u64), owner_commitment, recovery_nonce]).unwrap();
        Self {
            spending_key,
            r_owner,
            recovery_nonce,
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

    DepositedNote {
        commitment,
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
           \"ownerCommitmentBlinding\": \"{r_owner}\"\n\
         }}",
        commitment = fr_to_dec(&Fr::from_be_bytes_mod_order(commitment)),
        mint_lo = fr_to_dec(&mint_lo),
        mint_hi = fr_to_dec(&mint_hi),
        nonce = fr_to_dec(&secret.recovery_nonce),
        spending = fr_to_dec(&secret.spending_key),
        r_owner = fr_to_dec(&secret.r_owner),
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
    let proof = build_valid_spend_proof(note);

    let (vault_pda, _) = vault_config_pda(&h.vault_id);
    let (tree_pda, _) = merkle_tree_pda(&h.vault_id, note.tree_id);
    let (vault_token, _) = vault_token_pda(h, &note.mint);
    let (consumed, _) = consumed_note_pda(&h.vault_id, &note.commitment);
    let (note_lock, _) = note_lock_pda(&h.vault_id, &note.commitment);
    let (null_entry, _) = nullifier_pda(&h.vault_id, &note.nullifier);
    let (outstanding, _) = outstanding_mint_pda(h, &note.mint);

    // withdraw(tree_id, note_commitment, nullifier, merkle_root, amount, proof)
    let mut data = anchor_disc("withdraw").to_vec();
    data.push(note.tree_id);
    data.extend_from_slice(&note.commitment);
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
            AccountMeta::new(null_entry, false),
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

fn build_valid_spend_proof(note: &DepositedNote) -> vault::zk::verifier::Groth16Proof {
    use darkpool_crypto::field::pubkey_to_fr_pair;
    use std::fs;
    use std::process::Command;

    let root = repo_root();
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
           \"merkleIndices\": [{idxs}]\n\
         }}",
        mr = fr_to_dec(&Fr::from_be_bytes_mod_order(&note.merkle_root)),
        nl = fr_to_dec(&Fr::from_be_bytes_mod_order(&note.nullifier)),
        mlo = fr_to_dec(&mint_lo),
        mhi = fr_to_dec(&mint_hi),
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
