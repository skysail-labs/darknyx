//! Governed MarketConfig initialization/update regressions.

mod common;
mod settle_harness;

use borsh::BorshSerialize;
use settle_harness::{
    anchor_disc, create_spl_mint, vault_config_pda, Harness, Pubkey, SYSTEM_PROGRAM_ID,
};
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;

#[derive(BorshSerialize)]
struct InitializeMarketArgs {
    price_scale: u64,
    tick_size: u64,
    min_order_size: u64,
    circuit_breaker_bps: u64,
}

#[derive(BorshSerialize)]
struct UpdateMarketConfigArgs {
    enabled: bool,
    price_scale: u64,
    tick_size: u64,
    min_order_size: u64,
    circuit_breaker_bps: u64,
}

fn market_config_pda(program_id: &Pubkey, base: &Pubkey, quote: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[b"market_config", base.as_ref(), quote.as_ref()],
        program_id,
    )
}

fn initialize_market_ix(
    h: &Harness,
    base: Pubkey,
    quote: Pubkey,
    args: InitializeMarketArgs,
) -> Instruction {
    let (vault, _) = vault_config_pda(&h.vault_id);
    let (market, _) = market_config_pda(&h.vault_id, &base, &quote);
    let mut data = anchor_disc("initialize_market").to_vec();
    args.serialize(&mut data).unwrap();
    Instruction {
        program_id: h.vault_id,
        accounts: vec![
            AccountMeta::new(h.admin.pubkey(), true),
            AccountMeta::new_readonly(vault, false),
            AccountMeta::new_readonly(base, false),
            AccountMeta::new_readonly(quote, false),
            AccountMeta::new(market, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ],
        data,
    }
}

fn update_market_ix(
    h: &Harness,
    admin: Pubkey,
    market: Pubkey,
    args: UpdateMarketConfigArgs,
) -> Instruction {
    let (vault, _) = vault_config_pda(&h.vault_id);
    let mut data = anchor_disc("update_market_config").to_vec();
    args.serialize(&mut data).unwrap();
    Instruction {
        program_id: h.vault_id,
        accounts: vec![
            AccountMeta::new_readonly(admin, true),
            AccountMeta::new_readonly(vault, false),
            AccountMeta::new(market, false),
        ],
        data,
    }
}

fn send(h: &mut Harness, signer: &Keypair, ix: Instruction) -> Result<(), String> {
    let tx = Transaction::new(
        &[signer],
        Message::new(&[ix], Some(&signer.pubkey())),
        h.svm.latest_blockhash(),
    );
    h.svm
        .send_transaction(tx)
        .map(|_| ())
        .map_err(|e| format!("{e:?}"))
}

#[test]
fn initialize_market_snapshots_identity_decimals_and_bounds() {
    let mut h = Harness::setup();
    let base = create_spl_mint(&mut h, 9);
    let quote = create_spl_mint(&mut h, 6);
    let ix = initialize_market_ix(
        &h,
        base,
        quote,
        InitializeMarketArgs {
            price_scale: 100_000_000,
            tick_size: 5,
            min_order_size: 1_000,
            circuit_breaker_bps: 5_000,
        },
    );
    let admin = h.admin.insecure_clone();
    send(&mut h, &admin, ix).expect("initialize_market failed");

    let (market, _) = market_config_pda(&h.vault_id, &base, &quote);
    let account = h.svm.get_account(&market).expect("market config");
    assert_eq!(account.owner, h.vault_id);
    assert_eq!(account.data.len(), 108);
    assert_eq!(&account.data[8..40], base.as_ref());
    assert_eq!(&account.data[40..72], quote.as_ref());
    assert_eq!(
        u64::from_le_bytes(account.data[72..80].try_into().unwrap()),
        100_000_000
    );
    assert_eq!(
        u64::from_le_bytes(account.data[80..88].try_into().unwrap()),
        5
    );
    assert_eq!(
        u64::from_le_bytes(account.data[88..96].try_into().unwrap()),
        1_000
    );
    assert_eq!(
        u64::from_le_bytes(account.data[96..104].try_into().unwrap()),
        5_000
    );
    assert_eq!(account.data[104], 9);
    assert_eq!(account.data[105], 6);
    assert_eq!(account.data[106], 1);
}

#[test]
fn initialize_market_rejects_same_mint_and_invalid_parameters() {
    let mut h = Harness::setup();
    let base = create_spl_mint(&mut h, 6);
    let quote = create_spl_mint(&mut h, 6);
    let admin = h.admin.insecure_clone();

    let same = initialize_market_ix(
        &h,
        base,
        base,
        InitializeMarketArgs {
            price_scale: 1,
            tick_size: 1,
            min_order_size: 1,
            circuit_breaker_bps: 1,
        },
    );
    assert!(send(&mut h, &admin, same).is_err());

    let invalid = initialize_market_ix(
        &h,
        base,
        quote,
        InitializeMarketArgs {
            price_scale: 0,
            tick_size: 1,
            min_order_size: 1,
            circuit_breaker_bps: 10_001,
        },
    );
    assert!(send(&mut h, &admin, invalid).is_err());

    let impostor = Keypair::new();
    h.svm.airdrop(&impostor.pubkey(), 1_000_000_000).unwrap();
    let mut unauthorized = initialize_market_ix(
        &h,
        base,
        quote,
        InitializeMarketArgs {
            price_scale: 1,
            tick_size: 1,
            min_order_size: 1,
            circuit_breaker_bps: 1,
        },
    );
    unauthorized.accounts[0] = AccountMeta::new(impostor.pubkey(), true);
    assert!(send(&mut h, &impostor, unauthorized).is_err());
}

#[test]
fn operations_admin_can_update_and_pause_but_impostor_cannot() {
    let mut h = Harness::setup();
    let base = create_spl_mint(&mut h, 9);
    let quote = create_spl_mint(&mut h, 6);
    let admin = h.admin.insecure_clone();
    let init = initialize_market_ix(
        &h,
        base,
        quote,
        InitializeMarketArgs {
            price_scale: 100_000_000,
            tick_size: 5,
            min_order_size: 1_000,
            circuit_breaker_bps: 5_000,
        },
    );
    send(&mut h, &admin, init).unwrap();
    let (market, _) = market_config_pda(&h.vault_id, &base, &quote);

    let impostor = Keypair::new();
    h.svm.airdrop(&impostor.pubkey(), 1_000_000_000).unwrap();
    let bad = update_market_ix(
        &h,
        impostor.pubkey(),
        market,
        UpdateMarketConfigArgs {
            enabled: false,
            price_scale: 1,
            tick_size: 1,
            min_order_size: 1,
            circuit_breaker_bps: 1,
        },
    );
    assert!(send(&mut h, &impostor, bad).is_err());

    let update = update_market_ix(
        &h,
        admin.pubkey(),
        market,
        UpdateMarketConfigArgs {
            enabled: false,
            price_scale: 1_000_000,
            tick_size: 10,
            min_order_size: 2_000,
            circuit_breaker_bps: 250,
        },
    );
    send(&mut h, &admin, update).unwrap();
    let account = h.svm.get_account(&market).unwrap();
    assert_eq!(&account.data[8..40], base.as_ref());
    assert_eq!(&account.data[40..72], quote.as_ref());
    assert_eq!(account.data[104], 9);
    assert_eq!(account.data[105], 6);
    assert_eq!(
        u64::from_le_bytes(account.data[72..80].try_into().unwrap()),
        1_000_000
    );
    assert_eq!(account.data[106], 0, "market pause must persist");
}
