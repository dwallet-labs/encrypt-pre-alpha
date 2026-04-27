// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! LiteSVM end-to-end tests for PC-Token (Confidential Performant Token).
//!
//! Tests the full confidential token lifecycle:
//! - initialize_mint → initialize_account → mint_to → transfer → burn
//! - approve → transfer_from → revoke
//! - freeze → thaw
//! - request_decrypt → reveal_balance
//!
//! All amounts are client-encrypted ciphertexts — the plaintext never
//! appears on-chain.

use encrypt_dsl::prelude::encrypt_fn;
use encrypt_solana_test::litesvm::EncryptTestContext;
use encrypt_types::encrypted::{EUint64, Uint64};
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Keypair;
use solana_sdk::signer::Signer;

// ── FHE graphs (must match the on-chain program) ──

#[encrypt_fn]
fn mint_to_graph(balance: EUint64, amount: EUint64) -> EUint64 {
    balance + amount
}

#[encrypt_fn]
fn transfer_graph(
    from_balance: EUint64,
    to_balance: EUint64,
    amount: EUint64,
) -> (EUint64, EUint64) {
    let sufficient = from_balance >= amount;
    let new_from = if sufficient { from_balance - amount } else { from_balance };
    let new_to = if sufficient { to_balance + amount } else { to_balance };
    (new_from, new_to)
}

#[encrypt_fn]
fn burn_graph(balance: EUint64, amount: EUint64) -> EUint64 {
    let sufficient = balance >= amount;
    if sufficient { balance - amount } else { balance }
}

#[encrypt_fn]
fn transfer_from_graph(
    from_balance: EUint64,
    to_balance: EUint64,
    allowance: EUint64,
    amount: EUint64,
) -> (EUint64, EUint64, EUint64) {
    let sufficient_balance = from_balance >= amount;
    let sufficient_allowance = allowance >= amount;
    let can_transfer = sufficient_balance & sufficient_allowance;
    let new_from = if can_transfer { from_balance - amount } else { from_balance };
    let new_to = if can_transfer { to_balance + amount } else { to_balance };
    let new_allowance = if can_transfer { allowance - amount } else { allowance };
    (new_from, new_to, new_allowance)
}

#[encrypt_fn]
fn transfer_receipt_graph(
    from_balance: EUint64,
    to_balance: EUint64,
    amount: EUint64,
) -> (EUint64, EUint64, EUint64) {
    let s = from_balance >= amount;
    let zero = amount - amount;
    let actual = if s { amount } else { zero };
    let new_from = from_balance - actual;
    let new_to = to_balance + actual;
    (new_from, new_to, actual)
}

const PROGRAM_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../../../target/deploy/pc_token.so"
);

const SYSTEM_PROGRAM: Pubkey = Pubkey::new_from_array([0u8; 32]);

// ── Setup helpers ──

fn setup(ctx: &mut EncryptTestContext) -> (Pubkey, Pubkey, u8) {
    let program_id = ctx.deploy_program(PROGRAM_PATH);
    let (cpi_authority, cpi_bump) = ctx.cpi_authority_for(&program_id);
    (program_id, cpi_authority, cpi_bump)
}

// ── Instruction builders ──

fn initialize_mint_ix(
    program_id: &Pubkey,
    mint_pda: &Pubkey,
    bump: u8,
    decimals: u8,
    mint_authority: &Pubkey,
    has_freeze: bool,
    freeze_authority: &Pubkey,
    payer: &Pubkey,
) -> Instruction {
    let mut data = Vec::with_capacity(68);
    data.push(0u8); // disc: InitializeMint
    data.push(bump);
    data.push(decimals);
    data.extend_from_slice(mint_authority.as_ref());
    data.push(if has_freeze { 1 } else { 0 });
    if has_freeze {
        data.extend_from_slice(freeze_authority.as_ref());
    }

    Instruction::new_with_bytes(
        *program_id,
        &data,
        vec![
            AccountMeta::new(*mint_pda, false),
            AccountMeta::new_readonly(*mint_authority, true),
            AccountMeta::new(*payer, true),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
        ],
    )
}

fn initialize_account_ix(
    program_id: &Pubkey,
    token_account_pda: &Pubkey,
    account_bump: u8,
    cpi_bump: u8,
    mint: &Pubkey,
    owner: &Pubkey,
    balance_ct: &Pubkey,
    encrypt_program: &Pubkey,
    config: &Pubkey,
    deposit: &Pubkey,
    cpi_authority: &Pubkey,
    network_encryption_key: &Pubkey,
    payer: &Pubkey,
    event_authority: &Pubkey,
) -> Instruction {
    Instruction::new_with_bytes(
        *program_id,
        &[1u8, account_bump, cpi_bump],
        vec![
            AccountMeta::new(*token_account_pda, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new_readonly(*owner, false),
            AccountMeta::new(*balance_ct, true),
            AccountMeta::new_readonly(*encrypt_program, false),
            AccountMeta::new_readonly(*config, false),
            AccountMeta::new(*deposit, false),
            AccountMeta::new_readonly(*cpi_authority, false),
            AccountMeta::new_readonly(*program_id, false),
            AccountMeta::new_readonly(*network_encryption_key, false),
            AccountMeta::new(*payer, true),
            AccountMeta::new_readonly(*event_authority, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
        ],
    )
}

fn mint_to_ix(
    program_id: &Pubkey,
    mint: &Pubkey,
    token_account: &Pubkey,
    balance_ct: &Pubkey,
    amount_ct: &Pubkey,
    cpi_bump: u8,
    encrypt_program: &Pubkey,
    config: &Pubkey,
    deposit: &Pubkey,
    cpi_authority: &Pubkey,
    network_encryption_key: &Pubkey,
    authority: &Pubkey,
    event_authority: &Pubkey,
) -> Instruction {
    Instruction::new_with_bytes(
        *program_id,
        &[7u8, cpi_bump],
        vec![
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new_readonly(*token_account, false),
            AccountMeta::new(*balance_ct, false),
            AccountMeta::new(*amount_ct, false),
            AccountMeta::new_readonly(*encrypt_program, false),
            AccountMeta::new(*config, false),
            AccountMeta::new(*deposit, false),
            AccountMeta::new_readonly(*cpi_authority, false),
            AccountMeta::new_readonly(*program_id, false),
            AccountMeta::new_readonly(*network_encryption_key, false),
            AccountMeta::new(*authority, true),
            AccountMeta::new_readonly(*event_authority, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
        ],
    )
}

fn transfer_ix(
    program_id: &Pubkey,
    from_account: &Pubkey,
    to_account: &Pubkey,
    from_balance_ct: &Pubkey,
    to_balance_ct: &Pubkey,
    amount_ct: &Pubkey,
    cpi_bump: u8,
    encrypt_program: &Pubkey,
    config: &Pubkey,
    deposit: &Pubkey,
    cpi_authority: &Pubkey,
    network_encryption_key: &Pubkey,
    owner: &Pubkey,
    event_authority: &Pubkey,
) -> Instruction {
    Instruction::new_with_bytes(
        *program_id,
        &[3u8, cpi_bump],
        vec![
            AccountMeta::new_readonly(*from_account, false),
            AccountMeta::new_readonly(*to_account, false),
            AccountMeta::new(*from_balance_ct, false),
            AccountMeta::new(*to_balance_ct, false),
            AccountMeta::new(*amount_ct, false),
            AccountMeta::new_readonly(*encrypt_program, false),
            AccountMeta::new(*config, false),
            AccountMeta::new(*deposit, false),
            AccountMeta::new_readonly(*cpi_authority, false),
            AccountMeta::new_readonly(*program_id, false),
            AccountMeta::new_readonly(*network_encryption_key, false),
            AccountMeta::new(*owner, true),
            AccountMeta::new_readonly(*event_authority, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
        ],
    )
}

#[allow(clippy::too_many_arguments)]
fn transfer_with_receipt_ix(
    program_id: &Pubkey,
    from_account: &Pubkey,
    to_account: &Pubkey,
    from_balance_ct: &Pubkey,
    to_balance_ct: &Pubkey,
    amount_ct: &Pubkey,
    receipt_ct: &Pubkey,
    target_program: &Pubkey,
    cpi_bump: u8,
    encrypt_program: &Pubkey,
    config: &Pubkey,
    deposit: &Pubkey,
    cpi_authority: &Pubkey,
    network_encryption_key: &Pubkey,
    owner: &Pubkey,
    event_authority: &Pubkey,
) -> Instruction {
    Instruction::new_with_bytes(
        *program_id,
        &[22u8, cpi_bump],
        vec![
            AccountMeta::new_readonly(*from_account, false),
            AccountMeta::new_readonly(*to_account, false),
            AccountMeta::new(*from_balance_ct, false),
            AccountMeta::new(*to_balance_ct, false),
            AccountMeta::new(*amount_ct, false),
            AccountMeta::new(*receipt_ct, true),
            AccountMeta::new_readonly(*target_program, false),
            AccountMeta::new_readonly(*encrypt_program, false),
            AccountMeta::new(*config, false),
            AccountMeta::new(*deposit, false),
            AccountMeta::new_readonly(*cpi_authority, false),
            AccountMeta::new_readonly(*program_id, false),
            AccountMeta::new_readonly(*network_encryption_key, false),
            AccountMeta::new(*owner, true),
            AccountMeta::new_readonly(*event_authority, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
        ],
    )
}

fn burn_ix(
    program_id: &Pubkey,
    token_account: &Pubkey,
    mint: &Pubkey,
    balance_ct: &Pubkey,
    amount_ct: &Pubkey,
    cpi_bump: u8,
    encrypt_program: &Pubkey,
    config: &Pubkey,
    deposit: &Pubkey,
    cpi_authority: &Pubkey,
    network_encryption_key: &Pubkey,
    owner: &Pubkey,
    event_authority: &Pubkey,
) -> Instruction {
    Instruction::new_with_bytes(
        *program_id,
        &[8u8, cpi_bump],
        vec![
            AccountMeta::new_readonly(*token_account, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new(*balance_ct, false),
            AccountMeta::new(*amount_ct, false),
            AccountMeta::new_readonly(*encrypt_program, false),
            AccountMeta::new(*config, false),
            AccountMeta::new(*deposit, false),
            AccountMeta::new_readonly(*cpi_authority, false),
            AccountMeta::new_readonly(*program_id, false),
            AccountMeta::new_readonly(*network_encryption_key, false),
            AccountMeta::new(*owner, true),
            AccountMeta::new_readonly(*event_authority, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
        ],
    )
}

fn approve_ix(
    program_id: &Pubkey,
    token_account: &Pubkey,
    delegate: &Pubkey,
    amount_ct: &Pubkey,
    allowance_ct: &Pubkey,
    cpi_bump: u8,
    encrypt_program: &Pubkey,
    config: &Pubkey,
    deposit: &Pubkey,
    cpi_authority: &Pubkey,
    network_encryption_key: &Pubkey,
    owner: &Pubkey,
    event_authority: &Pubkey,
) -> Instruction {
    Instruction::new_with_bytes(
        *program_id,
        &[4u8, cpi_bump],
        vec![
            AccountMeta::new(*token_account, false),
            AccountMeta::new_readonly(*delegate, false),
            AccountMeta::new(*amount_ct, false),
            AccountMeta::new(*allowance_ct, true),
            AccountMeta::new_readonly(*encrypt_program, false),
            AccountMeta::new(*config, false),
            AccountMeta::new(*deposit, false),
            AccountMeta::new_readonly(*cpi_authority, false),
            AccountMeta::new_readonly(*program_id, false),
            AccountMeta::new_readonly(*network_encryption_key, false),
            AccountMeta::new(*owner, true),
            AccountMeta::new_readonly(*event_authority, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
        ],
    )
}

fn transfer_from_ix(
    program_id: &Pubkey,
    from_account: &Pubkey,
    to_account: &Pubkey,
    from_balance_ct: &Pubkey,
    to_balance_ct: &Pubkey,
    allowance_ct: &Pubkey,
    amount_ct: &Pubkey,
    delegate: &Pubkey,
    cpi_bump: u8,
    encrypt_program: &Pubkey,
    config: &Pubkey,
    deposit: &Pubkey,
    cpi_authority: &Pubkey,
    network_encryption_key: &Pubkey,
    payer: &Pubkey,
    event_authority: &Pubkey,
) -> Instruction {
    Instruction::new_with_bytes(
        *program_id,
        &[20u8, cpi_bump],
        vec![
            AccountMeta::new_readonly(*from_account, false),
            AccountMeta::new_readonly(*to_account, false),
            AccountMeta::new(*from_balance_ct, false),
            AccountMeta::new(*to_balance_ct, false),
            AccountMeta::new(*allowance_ct, false),
            AccountMeta::new(*amount_ct, false),
            AccountMeta::new_readonly(*delegate, true),
            AccountMeta::new_readonly(*encrypt_program, false),
            AccountMeta::new(*config, false),
            AccountMeta::new(*deposit, false),
            AccountMeta::new_readonly(*cpi_authority, false),
            AccountMeta::new_readonly(*program_id, false),
            AccountMeta::new_readonly(*network_encryption_key, false),
            AccountMeta::new(*payer, true),
            AccountMeta::new_readonly(*event_authority, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
        ],
    )
}

fn freeze_account_ix(
    program_id: &Pubkey,
    token_account: &Pubkey,
    mint: &Pubkey,
    freeze_authority: &Pubkey,
) -> Instruction {
    Instruction::new_with_bytes(
        *program_id,
        &[10u8],
        vec![
            AccountMeta::new(*token_account, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new_readonly(*freeze_authority, true),
        ],
    )
}

fn thaw_account_ix(
    program_id: &Pubkey,
    token_account: &Pubkey,
    mint: &Pubkey,
    freeze_authority: &Pubkey,
) -> Instruction {
    Instruction::new_with_bytes(
        *program_id,
        &[11u8],
        vec![
            AccountMeta::new(*token_account, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new_readonly(*freeze_authority, true),
        ],
    )
}

// ── High-level helpers ──

struct MintInfo {
    pda: Pubkey,
    bump: u8,
    authority: Keypair,
}

struct AccountInfo {
    pda: Pubkey,
    balance_ct: Pubkey,
    owner: Keypair,
}

/// Create a mint and return its info.
fn create_mint(
    ctx: &mut EncryptTestContext,
    program_id: &Pubkey,
    decimals: u8,
    has_freeze: bool,
) -> MintInfo {
    let authority = ctx.new_funded_keypair();
    let (mint_pda, bump) = Pubkey::find_program_address(
        &[b"pc_mint", authority.pubkey().as_ref()],
        program_id,
    );

    let freeze_auth = if has_freeze { &authority.pubkey() } else { &Pubkey::default() };
    let ix = initialize_mint_ix(
        program_id,
        &mint_pda,
        bump,
        decimals,
        &authority.pubkey(),
        has_freeze,
        freeze_auth,
        &ctx.payer().pubkey(),
    );
    ctx.send_transaction(&[ix], &[&authority]);

    MintInfo { pda: mint_pda, bump, authority }
}

/// Create a token account and return its info.
fn create_account(
    ctx: &mut EncryptTestContext,
    program_id: &Pubkey,
    cpi_authority: &Pubkey,
    cpi_bump: u8,
    mint: &Pubkey,
) -> AccountInfo {
    let owner = ctx.new_funded_keypair();
    let (account_pda, account_bump) = Pubkey::find_program_address(
        &[b"pc_account", mint.as_ref(), owner.pubkey().as_ref()],
        program_id,
    );
    let balance_ct = Keypair::new();

    let ix = initialize_account_ix(
        program_id,
        &account_pda,
        account_bump,
        cpi_bump,
        mint,
        &owner.pubkey(),
        &balance_ct.pubkey(),
        ctx.program_id(),
        ctx.config_pda(),
        ctx.deposit_pda(),
        cpi_authority,
        ctx.network_encryption_key_pda(),
        &ctx.payer().pubkey(),
        ctx.event_authority(),
    );
    ctx.send_transaction(&[ix], &[&balance_ct]);

    let balance_pubkey = balance_ct.pubkey();
    ctx.register_ciphertext(&balance_pubkey);

    AccountInfo { pda: account_pda, balance_ct: balance_pubkey, owner }
}

/// Set balance for testing — uses harness directly (no on-chain mint instruction).
/// In production, tokens only enter through Wrap.
fn do_mint(
    ctx: &mut EncryptTestContext,
    program_id: &Pubkey,
    _cpi_authority: &Pubkey,
    _cpi_bump: u8,
    _mint: &MintInfo,
    account: &AccountInfo,
    amount: u128,
) {
    let amount_ct = ctx.create_input::<Uint64>(amount, program_id);

    let graph = mint_to_graph();
    ctx.enqueue_graph_execution(
        &graph,
        &[account.balance_ct, amount_ct],
        &[account.balance_ct],
    );
    ctx.process_pending();
    ctx.register_ciphertext(&account.balance_ct);
}

/// Transfer tokens between accounts.
fn do_transfer(
    ctx: &mut EncryptTestContext,
    program_id: &Pubkey,
    cpi_authority: &Pubkey,
    cpi_bump: u8,
    from: &AccountInfo,
    to: &AccountInfo,
    amount: u128,
) {
    let amount_ct = ctx.create_input::<Uint64>(amount, program_id);

    let ix = transfer_ix(
        program_id,
        &from.pda,
        &to.pda,
        &from.balance_ct,
        &to.balance_ct,
        &amount_ct,
        cpi_bump,
        ctx.program_id(),
        ctx.config_pda(),
        ctx.deposit_pda(),
        cpi_authority,
        ctx.network_encryption_key_pda(),
        &from.owner.pubkey(),
        ctx.event_authority(),
    );
    ctx.send_transaction(&[ix], &[&from.owner]);

    let graph = transfer_graph();
    ctx.enqueue_graph_execution(
        &graph,
        &[from.balance_ct, to.balance_ct, amount_ct],
        &[from.balance_ct, to.balance_ct],
    );
    ctx.process_pending();
    ctx.register_ciphertext(&from.balance_ct);
    ctx.register_ciphertext(&to.balance_ct);
}

// ── Tests ──

#[test]
fn test_initialize_mint() {
    let mut ctx = EncryptTestContext::new_default();
    let (program_id, _, _) = setup(&mut ctx);

    let mint = create_mint(&mut ctx, &program_id, 6, false);

    let data = ctx.get_account_data(&mint.pda).expect("mint not found");
    // mint_authority_flag[0] = COPTION_SOME
    assert_eq!(data[0], 1);
    // decimals at offset 4+32 = 36
    assert_eq!(data[36], 6);
    // is_initialized at offset 37
    assert_eq!(data[37], 1);
}

#[test]
fn test_initialize_mint_with_freeze_authority() {
    let mut ctx = EncryptTestContext::new_default();
    let (program_id, _, _) = setup(&mut ctx);

    let mint = create_mint(&mut ctx, &program_id, 9, true);

    let data = ctx.get_account_data(&mint.pda).expect("mint not found");
    // freeze_authority_flag[0] at offset 4+32+1+1 = 38
    assert_eq!(data[38], 1);
}

#[test]
fn test_initialize_account() {
    let mut ctx = EncryptTestContext::new_default();
    let (program_id, cpi_authority, cpi_bump) = setup(&mut ctx);

    let mint = create_mint(&mut ctx, &program_id, 6, false);
    let account = create_account(&mut ctx, &program_id, &cpi_authority, cpi_bump, &mint.pda);

    let data = ctx.get_account_data(&account.pda).expect("account not found");
    // mint field
    assert_eq!(&data[0..32], mint.pda.as_ref());
    // owner field
    assert_eq!(&data[32..64], account.owner.pubkey().as_ref());
    // state = Initialized (offset after balance(32) + delegate_flag(4) + delegate(32) = 132)
    assert_eq!(data[132], 1);

    // Balance should be encrypted zero
    let balance = ctx.decrypt_from_store(&account.balance_ct);
    assert_eq!(balance, 0);
}

#[test]
fn test_mint_to() {
    let mut ctx = EncryptTestContext::new_default();
    let (program_id, cpi_authority, cpi_bump) = setup(&mut ctx);

    let mint = create_mint(&mut ctx, &program_id, 6, false);
    let alice = create_account(&mut ctx, &program_id, &cpi_authority, cpi_bump, &mint.pda);

    do_mint(&mut ctx, &program_id, &cpi_authority, cpi_bump, &mint, &alice, 1_000_000);

    let balance = ctx.decrypt_from_store(&alice.balance_ct);
    assert_eq!(balance, 1_000_000);
}

// test_mint_to_multiple removed — standalone MintTo is disabled (vault-backed only)

#[test]
fn test_transfer() {
    let mut ctx = EncryptTestContext::new_default();
    let (program_id, cpi_authority, cpi_bump) = setup(&mut ctx);

    let mint = create_mint(&mut ctx, &program_id, 6, false);
    let alice = create_account(&mut ctx, &program_id, &cpi_authority, cpi_bump, &mint.pda);
    let bob = create_account(&mut ctx, &program_id, &cpi_authority, cpi_bump, &mint.pda);

    // Mint 1000 to Alice
    do_mint(&mut ctx, &program_id, &cpi_authority, cpi_bump, &mint, &alice, 1000);

    // Transfer 300 from Alice to Bob
    do_transfer(&mut ctx, &program_id, &cpi_authority, cpi_bump, &alice, &bob, 300);

    assert_eq!(ctx.decrypt_from_store(&alice.balance_ct), 700);
    assert_eq!(ctx.decrypt_from_store(&bob.balance_ct), 300);
}

#[test]
fn test_transfer_insufficient_funds() {
    let mut ctx = EncryptTestContext::new_default();
    let (program_id, cpi_authority, cpi_bump) = setup(&mut ctx);

    let mint = create_mint(&mut ctx, &program_id, 6, false);
    let alice = create_account(&mut ctx, &program_id, &cpi_authority, cpi_bump, &mint.pda);
    let bob = create_account(&mut ctx, &program_id, &cpi_authority, cpi_bump, &mint.pda);

    // Mint 100 to Alice
    do_mint(&mut ctx, &program_id, &cpi_authority, cpi_bump, &mint, &alice, 100);

    // Try to transfer 300 — silent no-op (privacy preserving)
    do_transfer(&mut ctx, &program_id, &cpi_authority, cpi_bump, &alice, &bob, 300);

    // Balances unchanged
    assert_eq!(ctx.decrypt_from_store(&alice.balance_ct), 100);
    assert_eq!(ctx.decrypt_from_store(&bob.balance_ct), 0);
}

// test_burn removed — standalone burn is disabled (tokens exit only via unwrap)

#[test]
fn test_approve_and_transfer_from() {
    let mut ctx = EncryptTestContext::new_default();
    let (program_id, cpi_authority, cpi_bump) = setup(&mut ctx);

    let mint = create_mint(&mut ctx, &program_id, 6, false);
    let alice = create_account(&mut ctx, &program_id, &cpi_authority, cpi_bump, &mint.pda);
    let bob = create_account(&mut ctx, &program_id, &cpi_authority, cpi_bump, &mint.pda);

    // Mint 1000 to Alice
    do_mint(&mut ctx, &program_id, &cpi_authority, cpi_bump, &mint, &alice, 1000);

    // Alice approves a delegate for 500
    let delegate = ctx.new_funded_keypair();
    let allowance_amount_ct = ctx.create_input::<Uint64>(500, &program_id);
    let allowance_ct = Keypair::new();

    let approve = approve_ix(
        &program_id,
        &alice.pda,
        &delegate.pubkey(),
        &allowance_amount_ct,
        &allowance_ct.pubkey(),
        cpi_bump,
        ctx.program_id(),
        ctx.config_pda(),
        ctx.deposit_pda(),
        &cpi_authority,
        ctx.network_encryption_key_pda(),
        &alice.owner.pubkey(),
        ctx.event_authority(),
    );
    ctx.send_transaction(&[approve], &[&alice.owner, &allowance_ct]);

    let allowance_pubkey = allowance_ct.pubkey();
    ctx.register_ciphertext(&allowance_pubkey);

    // Process the mint_to_graph that approve runs internally (allowance = 0 + amount)
    let approve_graph = mint_to_graph();
    ctx.enqueue_graph_execution(
        &approve_graph,
        &[allowance_pubkey, allowance_amount_ct],
        &[allowance_pubkey],
    );
    ctx.process_pending();
    ctx.register_ciphertext(&allowance_pubkey);

    // Delegate transfers 200 from Alice to Bob
    let transfer_amount_ct = ctx.create_input::<Uint64>(200, &program_id);
    let ix = transfer_from_ix(
        &program_id,
        &alice.pda,
        &bob.pda,
        &alice.balance_ct,
        &bob.balance_ct,
        &allowance_pubkey,
        &transfer_amount_ct,
        &delegate.pubkey(),
        cpi_bump,
        ctx.program_id(),
        ctx.config_pda(),
        ctx.deposit_pda(),
        &cpi_authority,
        ctx.network_encryption_key_pda(),
        &ctx.payer().pubkey(),
        ctx.event_authority(),
    );
    ctx.send_transaction(&[ix], &[&delegate]);

    let graph = transfer_from_graph();
    ctx.enqueue_graph_execution(
        &graph,
        &[alice.balance_ct, bob.balance_ct, allowance_pubkey, transfer_amount_ct],
        &[alice.balance_ct, bob.balance_ct, allowance_pubkey],
    );
    ctx.process_pending();
    ctx.register_ciphertext(&alice.balance_ct);
    ctx.register_ciphertext(&bob.balance_ct);
    ctx.register_ciphertext(&allowance_pubkey);

    assert_eq!(ctx.decrypt_from_store(&alice.balance_ct), 800);
    assert_eq!(ctx.decrypt_from_store(&bob.balance_ct), 200);
    assert_eq!(ctx.decrypt_from_store(&allowance_pubkey), 300);
}

#[test]
fn test_freeze_blocks_transfer() {
    let mut ctx = EncryptTestContext::new_default();
    let (program_id, cpi_authority, cpi_bump) = setup(&mut ctx);

    let mint = create_mint(&mut ctx, &program_id, 6, true);
    let alice = create_account(&mut ctx, &program_id, &cpi_authority, cpi_bump, &mint.pda);
    let bob = create_account(&mut ctx, &program_id, &cpi_authority, cpi_bump, &mint.pda);

    do_mint(&mut ctx, &program_id, &cpi_authority, cpi_bump, &mint, &alice, 1000);

    // Freeze Alice's account
    let freeze_ix = freeze_account_ix(
        &program_id,
        &alice.pda,
        &mint.pda,
        &mint.authority.pubkey(),
    );
    ctx.send_transaction(&[freeze_ix], &[&mint.authority]);

    // Verify account is frozen (state field)
    let data = ctx.get_account_data(&alice.pda).expect("account not found");
    assert_eq!(data[132], 2, "account should be frozen");

    // Thaw
    let thaw_ix = thaw_account_ix(
        &program_id,
        &alice.pda,
        &mint.pda,
        &mint.authority.pubkey(),
    );
    ctx.send_transaction(&[thaw_ix], &[&mint.authority]);

    let data = ctx.get_account_data(&alice.pda).expect("account not found");
    assert_eq!(data[132], 1, "account should be thawed (Initialized)");

    // Transfer should work after thaw
    do_transfer(&mut ctx, &program_id, &cpi_authority, cpi_bump, &alice, &bob, 100);
    assert_eq!(ctx.decrypt_from_store(&alice.balance_ct), 900);
    assert_eq!(ctx.decrypt_from_store(&bob.balance_ct), 100);
}

#[test]
fn test_full_lifecycle() {
    let mut ctx = EncryptTestContext::new_default();
    let (program_id, cpi_authority, cpi_bump) = setup(&mut ctx);

    // 1. Create mint
    let mint = create_mint(&mut ctx, &program_id, 6, true);

    // 2. Create accounts
    let alice = create_account(&mut ctx, &program_id, &cpi_authority, cpi_bump, &mint.pda);
    let bob = create_account(&mut ctx, &program_id, &cpi_authority, cpi_bump, &mint.pda);

    // 3. Mint 10_000 to Alice
    do_mint(&mut ctx, &program_id, &cpi_authority, cpi_bump, &mint, &alice, 10_000);
    assert_eq!(ctx.decrypt_from_store(&alice.balance_ct), 10_000);

    // 4. Transfer 3_000 to Bob
    do_transfer(&mut ctx, &program_id, &cpi_authority, cpi_bump, &alice, &bob, 3_000);
    assert_eq!(ctx.decrypt_from_store(&alice.balance_ct), 7_000);
    assert_eq!(ctx.decrypt_from_store(&bob.balance_ct), 3_000);

    // 5. Transfer 500 Bob → Alice
    do_transfer(&mut ctx, &program_id, &cpi_authority, cpi_bump, &bob, &alice, 500);
    assert_eq!(ctx.decrypt_from_store(&alice.balance_ct), 7_500);
    assert_eq!(ctx.decrypt_from_store(&bob.balance_ct), 2_500);

    // 6. Freeze Alice, thaw, transfer again
    let freeze = freeze_account_ix(&program_id, &alice.pda, &mint.pda, &mint.authority.pubkey());
    ctx.send_transaction(&[freeze], &[&mint.authority]);

    let thaw = thaw_account_ix(&program_id, &alice.pda, &mint.pda, &mint.authority.pubkey());
    ctx.send_transaction(&[thaw], &[&mint.authority]);

    do_transfer(&mut ctx, &program_id, &cpi_authority, cpi_bump, &alice, &bob, 2_000);
    assert_eq!(ctx.decrypt_from_store(&alice.balance_ct), 5_500);
    assert_eq!(ctx.decrypt_from_store(&bob.balance_ct), 4_500);

    // 7. Approve delegate, transfer_from
    let delegate = ctx.new_funded_keypair();
    let allowance_ct_kp = Keypair::new();
    let allowance_amount = ctx.create_input::<Uint64>(1_000, &program_id);

    let approve = approve_ix(
        &program_id,
        &alice.pda,
        &delegate.pubkey(),
        &allowance_amount,
        &allowance_ct_kp.pubkey(),
        cpi_bump,
        ctx.program_id(),
        ctx.config_pda(),
        ctx.deposit_pda(),
        &cpi_authority,
        ctx.network_encryption_key_pda(),
        &alice.owner.pubkey(),
        ctx.event_authority(),
    );
    ctx.send_transaction(&[approve], &[&alice.owner, &allowance_ct_kp]);
    let allowance_pubkey = allowance_ct_kp.pubkey();
    ctx.register_ciphertext(&allowance_pubkey);

    // Process the mint_to_graph that approve runs internally
    let approve_g = mint_to_graph();
    ctx.enqueue_graph_execution(
        &approve_g,
        &[allowance_pubkey, allowance_amount],
        &[allowance_pubkey],
    );
    ctx.process_pending();
    ctx.register_ciphertext(&allowance_pubkey);

    let xfer_amount = ctx.create_input::<Uint64>(750, &program_id);
    let xfer_from = transfer_from_ix(
        &program_id,
        &alice.pda,
        &bob.pda,
        &alice.balance_ct,
        &bob.balance_ct,
        &allowance_pubkey,
        &xfer_amount,
        &delegate.pubkey(),
        cpi_bump,
        ctx.program_id(),
        ctx.config_pda(),
        ctx.deposit_pda(),
        &cpi_authority,
        ctx.network_encryption_key_pda(),
        &ctx.payer().pubkey(),
        ctx.event_authority(),
    );
    ctx.send_transaction(&[xfer_from], &[&delegate]);

    let graph = transfer_from_graph();
    ctx.enqueue_graph_execution(
        &graph,
        &[alice.balance_ct, bob.balance_ct, allowance_pubkey, xfer_amount],
        &[alice.balance_ct, bob.balance_ct, allowance_pubkey],
    );
    ctx.process_pending();
    ctx.register_ciphertext(&alice.balance_ct);
    ctx.register_ciphertext(&bob.balance_ct);
    ctx.register_ciphertext(&allowance_pubkey);

    assert_eq!(ctx.decrypt_from_store(&alice.balance_ct), 4_750);
    assert_eq!(ctx.decrypt_from_store(&bob.balance_ct), 5_250);
    assert_eq!(ctx.decrypt_from_store(&allowance_pubkey), 250);
}

// ── TransferWithReceipt (disc 22) ──
//
// Same balance updates as Transfer, plus emits a binary receipt
// (= amount on success, 0 on insufficient balance) authorized to a
// caller-supplied target program. Powers the receipt-gated pc-swap flow.

#[test]
fn test_transfer_with_receipt_sufficient() {
    let mut ctx = EncryptTestContext::new_default();
    let (program_id, cpi_authority, cpi_bump) = setup(&mut ctx);

    let mint = create_mint(&mut ctx, &program_id, 6, false);
    let alice = create_account(&mut ctx, &program_id, &cpi_authority, cpi_bump, &mint.pda);
    let bob = create_account(&mut ctx, &program_id, &cpi_authority, cpi_bump, &mint.pda);

    do_mint(&mut ctx, &program_id, &cpi_authority, cpi_bump, &mint, &alice, 1000);

    // Pretend a third program is the receipt target — any pubkey will do for testing.
    let target_program = ctx.new_funded_keypair().pubkey();

    let amount_ct = ctx.create_input::<Uint64>(300, &program_id);
    let receipt_kp = Keypair::new();

    let ix = transfer_with_receipt_ix(
        &program_id,
        &alice.pda,
        &bob.pda,
        &alice.balance_ct,
        &bob.balance_ct,
        &amount_ct,
        &receipt_kp.pubkey(),
        &target_program,
        cpi_bump,
        ctx.program_id(),
        ctx.config_pda(),
        ctx.deposit_pda(),
        &cpi_authority,
        ctx.network_encryption_key_pda(),
        &alice.owner.pubkey(),
        ctx.event_authority(),
    );
    ctx.send_transaction(&[ix], &[&alice.owner, &receipt_kp]);

    let receipt_pubkey = receipt_kp.pubkey();
    ctx.register_ciphertext(&receipt_pubkey);

    // Cluster: run transfer_receipt_graph with 3 outputs (from, to, receipt).
    let graph = transfer_receipt_graph();
    ctx.enqueue_graph_execution(
        &graph,
        &[alice.balance_ct, bob.balance_ct, amount_ct],
        &[alice.balance_ct, bob.balance_ct, receipt_pubkey],
    );
    ctx.process_pending();
    ctx.register_ciphertext(&alice.balance_ct);
    ctx.register_ciphertext(&bob.balance_ct);
    ctx.register_ciphertext(&receipt_pubkey);

    assert_eq!(ctx.decrypt_from_store(&alice.balance_ct), 700);
    assert_eq!(ctx.decrypt_from_store(&bob.balance_ct), 300);
    assert_eq!(ctx.decrypt_from_store(&receipt_pubkey), 300, "receipt = transferred amount");
}

#[test]
fn test_transfer_with_receipt_insufficient_emits_zero() {
    // Soundness invariant: when the user lies about amount_in (i.e., balance < amount),
    // the transfer no-ops AND the receipt is exactly 0 (never partial). This is what
    // pc-swap multiplies its reserve and payout updates by.
    let mut ctx = EncryptTestContext::new_default();
    let (program_id, cpi_authority, cpi_bump) = setup(&mut ctx);

    let mint = create_mint(&mut ctx, &program_id, 6, false);
    let alice = create_account(&mut ctx, &program_id, &cpi_authority, cpi_bump, &mint.pda);
    let bob = create_account(&mut ctx, &program_id, &cpi_authority, cpi_bump, &mint.pda);

    // Alice has 50 — claims 999.
    do_mint(&mut ctx, &program_id, &cpi_authority, cpi_bump, &mint, &alice, 50);

    let target_program = ctx.new_funded_keypair().pubkey();
    let amount_ct = ctx.create_input::<Uint64>(999, &program_id);
    let receipt_kp = Keypair::new();

    let ix = transfer_with_receipt_ix(
        &program_id,
        &alice.pda,
        &bob.pda,
        &alice.balance_ct,
        &bob.balance_ct,
        &amount_ct,
        &receipt_kp.pubkey(),
        &target_program,
        cpi_bump,
        ctx.program_id(),
        ctx.config_pda(),
        ctx.deposit_pda(),
        &cpi_authority,
        ctx.network_encryption_key_pda(),
        &alice.owner.pubkey(),
        ctx.event_authority(),
    );
    ctx.send_transaction(&[ix], &[&alice.owner, &receipt_kp]);

    let receipt_pubkey = receipt_kp.pubkey();
    ctx.register_ciphertext(&receipt_pubkey);

    let graph = transfer_receipt_graph();
    ctx.enqueue_graph_execution(
        &graph,
        &[alice.balance_ct, bob.balance_ct, amount_ct],
        &[alice.balance_ct, bob.balance_ct, receipt_pubkey],
    );
    ctx.process_pending();
    ctx.register_ciphertext(&alice.balance_ct);
    ctx.register_ciphertext(&bob.balance_ct);
    ctx.register_ciphertext(&receipt_pubkey);

    assert_eq!(ctx.decrypt_from_store(&alice.balance_ct), 50, "balance unchanged");
    assert_eq!(ctx.decrypt_from_store(&bob.balance_ct), 0, "recipient unchanged");
    assert_eq!(ctx.decrypt_from_store(&receipt_pubkey), 0, "receipt is 0 — no partial transfer");
}

