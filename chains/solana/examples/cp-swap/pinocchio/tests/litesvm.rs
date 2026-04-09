// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! LiteSVM end-to-end tests for CP-Swap (Confidential UniV2 AMM).
//!
//! Tests the full lifecycle:
//! - create_pool → add_liquidity → swap → verify reserves
//! - slippage protection (no-op on excessive min_amount_out)
//! - multiple swaps in sequence
//! - bidirectional swaps (A→B then B→A)

use encrypt_dsl::prelude::encrypt_fn;
use encrypt_solana_test::litesvm::EncryptTestContext;
use encrypt_types::encrypted::{EUint128, Uint128};
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Keypair;
use solana_sdk::signer::Signer;

// ── FHE graphs (must match the on-chain program) ──

#[encrypt_fn]
fn swap_graph(
    reserve_in: EUint128,
    reserve_out: EUint128,
    amount_in: EUint128,
    min_amount_out: EUint128,
) -> (EUint128, EUint128, EUint128) {
    let amount_in_with_fee = amount_in * 997;
    let numerator = amount_in_with_fee * reserve_out;
    let denominator = (reserve_in * 1000) + amount_in_with_fee;
    let amount_out = numerator / denominator;

    let new_reserve_in = reserve_in + amount_in;
    let new_reserve_out = reserve_out - amount_out;

    let old_k = reserve_in * reserve_out;
    let new_k = new_reserve_in * new_reserve_out;
    let k_ok = new_k >= old_k;
    let slippage_ok = amount_out >= min_amount_out;

    let valid = if k_ok { slippage_ok } else { k_ok };
    let final_out = if valid { amount_out } else { amount_in - amount_in };
    let final_reserve_in = if valid { new_reserve_in } else { reserve_in };
    let final_reserve_out = if valid { new_reserve_out } else { reserve_out };

    (final_out, final_reserve_in, final_reserve_out)
}

#[encrypt_fn]
fn add_liquidity_graph(
    reserve_a: EUint128,
    reserve_b: EUint128,
    amount_a: EUint128,
    amount_b: EUint128,
) -> (EUint128, EUint128) {
    let new_reserve_a = reserve_a + amount_a;
    let new_reserve_b = reserve_b + amount_b;
    (new_reserve_a, new_reserve_b)
}

#[encrypt_fn]
fn remove_liquidity_graph(
    reserve_a: EUint128,
    reserve_b: EUint128,
    share_bps: EUint128,
) -> (EUint128, EUint128, EUint128, EUint128) {
    let amount_a = (reserve_a * share_bps) / 10000;
    let amount_b = (reserve_b * share_bps) / 10000;
    let new_reserve_a = reserve_a - amount_a;
    let new_reserve_b = reserve_b - amount_b;
    (amount_a, amount_b, new_reserve_a, new_reserve_b)
}

const PROGRAM_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../../../target/deploy/cp_swap.so"
);

const SYSTEM_PROGRAM: Pubkey = Pubkey::new_from_array([0u8; 32]);

// ── Setup helpers ──

fn setup(ctx: &mut EncryptTestContext) -> (Pubkey, Pubkey, u8) {
    let program_id = ctx.deploy_program(PROGRAM_PATH);
    let (cpi_authority, cpi_bump) = ctx.cpi_authority_for(&program_id);
    (program_id, cpi_authority, cpi_bump)
}

// ── Instruction builders ──

fn create_pool_ix(
    program_id: &Pubkey,
    pool_pda: &Pubkey,
    pool_bump: u8,
    cpi_bump: u8,
    mint_a: &Pubkey,
    mint_b: &Pubkey,
    reserve_a_ct: &Pubkey,
    reserve_b_ct: &Pubkey,
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
        &[0u8, pool_bump, cpi_bump],
        vec![
            AccountMeta::new(*pool_pda, false),
            AccountMeta::new_readonly(*mint_a, false),
            AccountMeta::new_readonly(*mint_b, false),
            AccountMeta::new(*reserve_a_ct, true),
            AccountMeta::new(*reserve_b_ct, true),
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

fn swap_ix(
    program_id: &Pubkey,
    pool: &Pubkey,
    reserve_in_ct: &Pubkey,
    reserve_out_ct: &Pubkey,
    amount_in_ct: &Pubkey,
    min_amount_out_ct: &Pubkey,
    amount_out_ct: &Pubkey,
    cpi_bump: u8,
    direction: u8,
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
        &[1u8, cpi_bump, direction],
        vec![
            AccountMeta::new_readonly(*pool, false),
            AccountMeta::new(*reserve_in_ct, false),
            AccountMeta::new(*reserve_out_ct, false),
            AccountMeta::new(*amount_in_ct, false),
            AccountMeta::new(*min_amount_out_ct, false),
            AccountMeta::new(*amount_out_ct, false),
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

fn add_liquidity_ix(
    program_id: &Pubkey,
    pool: &Pubkey,
    reserve_a_ct: &Pubkey,
    reserve_b_ct: &Pubkey,
    amount_a_ct: &Pubkey,
    amount_b_ct: &Pubkey,
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
        &[2u8, cpi_bump],
        vec![
            AccountMeta::new_readonly(*pool, false),
            AccountMeta::new(*reserve_a_ct, false),
            AccountMeta::new(*reserve_b_ct, false),
            AccountMeta::new(*amount_a_ct, false),
            AccountMeta::new(*amount_b_ct, false),
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

// ── High-level helpers ──

struct PoolInfo {
    pda: Pubkey,
    reserve_a: Pubkey,
    reserve_b: Pubkey,
}

fn create_pool(
    ctx: &mut EncryptTestContext,
    program_id: &Pubkey,
    cpi_authority: &Pubkey,
    cpi_bump: u8,
) -> PoolInfo {
    let mint_a = Pubkey::new_unique();
    let mint_b = Pubkey::new_unique();
    let (pool_pda, pool_bump) = Pubkey::find_program_address(
        &[b"cp_pool", mint_a.as_ref(), mint_b.as_ref()],
        program_id,
    );

    let reserve_a_ct = Keypair::new();
    let reserve_b_ct = Keypair::new();

    let ix = create_pool_ix(
        program_id,
        &pool_pda,
        pool_bump,
        cpi_bump,
        &mint_a,
        &mint_b,
        &reserve_a_ct.pubkey(),
        &reserve_b_ct.pubkey(),
        ctx.program_id(),
        ctx.config_pda(),
        ctx.deposit_pda(),
        cpi_authority,
        ctx.network_encryption_key_pda(),
        &ctx.payer().pubkey(),
        ctx.event_authority(),
    );
    ctx.send_transaction(&[ix], &[&reserve_a_ct, &reserve_b_ct]);

    let ra = reserve_a_ct.pubkey();
    let rb = reserve_b_ct.pubkey();
    ctx.register_ciphertext(&ra);
    ctx.register_ciphertext(&rb);

    PoolInfo { pda: pool_pda, reserve_a: ra, reserve_b: rb }
}

fn do_add_liquidity(
    ctx: &mut EncryptTestContext,
    program_id: &Pubkey,
    cpi_authority: &Pubkey,
    cpi_bump: u8,
    pool: &PoolInfo,
    amount_a: u128,
    amount_b: u128,
) {
    let amount_a_ct = ctx.create_input::<Uint128>(amount_a, program_id);
    let amount_b_ct = ctx.create_input::<Uint128>(amount_b, program_id);

    let ix = add_liquidity_ix(
        program_id,
        &pool.pda,
        &pool.reserve_a,
        &pool.reserve_b,
        &amount_a_ct,
        &amount_b_ct,
        cpi_bump,
        ctx.program_id(),
        ctx.config_pda(),
        ctx.deposit_pda(),
        cpi_authority,
        ctx.network_encryption_key_pda(),
        &ctx.payer().pubkey(),
        ctx.event_authority(),
    );
    ctx.send_transaction(&[ix], &[]);

    let graph = add_liquidity_graph();
    ctx.enqueue_graph_execution(
        &graph,
        &[pool.reserve_a, pool.reserve_b, amount_a_ct, amount_b_ct],
        &[pool.reserve_a, pool.reserve_b],
    );
    ctx.process_pending();
    ctx.register_ciphertext(&pool.reserve_a);
    ctx.register_ciphertext(&pool.reserve_b);
}

fn do_swap(
    ctx: &mut EncryptTestContext,
    program_id: &Pubkey,
    cpi_authority: &Pubkey,
    cpi_bump: u8,
    pool: &PoolInfo,
    amount_in: u128,
    min_amount_out: u128,
    direction: u8, // 0 = A→B, 1 = B→A
) -> u128 {
    let (reserve_in, reserve_out) = if direction == 0 {
        (pool.reserve_a, pool.reserve_b)
    } else {
        (pool.reserve_b, pool.reserve_a)
    };

    let amount_in_ct = ctx.create_input::<Uint128>(amount_in, program_id);
    let min_out_ct = ctx.create_input::<Uint128>(min_amount_out, program_id);
    let amount_out_ct = ctx.create_input::<Uint128>(0, program_id); // pre-create output

    let ix = swap_ix(
        program_id,
        &pool.pda,
        &reserve_in,
        &reserve_out,
        &amount_in_ct,
        &min_out_ct,
        &amount_out_ct,
        cpi_bump,
        direction,
        ctx.program_id(),
        ctx.config_pda(),
        ctx.deposit_pda(),
        cpi_authority,
        ctx.network_encryption_key_pda(),
        &ctx.payer().pubkey(),
        ctx.event_authority(),
    );
    ctx.send_transaction(&[ix], &[]);

    let graph = swap_graph();
    ctx.enqueue_graph_execution(
        &graph,
        &[reserve_in, reserve_out, amount_in_ct, min_out_ct],
        &[amount_out_ct, reserve_in, reserve_out],
    );
    ctx.process_pending();
    ctx.register_ciphertext(&pool.reserve_a);
    ctx.register_ciphertext(&pool.reserve_b);
    ctx.register_ciphertext(&amount_out_ct);

    ctx.decrypt_from_store(&amount_out_ct)
}

// ── Tests ──

#[test]
fn test_create_pool() {
    let mut ctx = EncryptTestContext::new_default();
    let (program_id, cpi_authority, cpi_bump) = setup(&mut ctx);

    let pool = create_pool(&mut ctx, &program_id, &cpi_authority, cpi_bump);

    // Verify pool state
    let data = ctx.get_account_data(&pool.pda).expect("pool not found");
    assert_eq!(data[128], 1, "is_initialized");

    // Verify reserves are encrypted zero
    assert_eq!(ctx.decrypt_from_store(&pool.reserve_a), 0);
    assert_eq!(ctx.decrypt_from_store(&pool.reserve_b), 0);
}

#[test]
fn test_add_liquidity() {
    let mut ctx = EncryptTestContext::new_default();
    let (program_id, cpi_authority, cpi_bump) = setup(&mut ctx);

    let pool = create_pool(&mut ctx, &program_id, &cpi_authority, cpi_bump);
    do_add_liquidity(&mut ctx, &program_id, &cpi_authority, cpi_bump, &pool, 10_000, 20_000);

    assert_eq!(ctx.decrypt_from_store(&pool.reserve_a), 10_000);
    assert_eq!(ctx.decrypt_from_store(&pool.reserve_b), 20_000);
}

#[test]
fn test_swap_a_to_b() {
    let mut ctx = EncryptTestContext::new_default();
    let (program_id, cpi_authority, cpi_bump) = setup(&mut ctx);

    let pool = create_pool(&mut ctx, &program_id, &cpi_authority, cpi_bump);
    do_add_liquidity(&mut ctx, &program_id, &cpi_authority, cpi_bump, &pool, 10_000, 20_000);

    // Swap 1000 A → B, min_out = 0
    let amount_out = do_swap(
        &mut ctx, &program_id, &cpi_authority, cpi_bump,
        &pool, 1000, 0, 0,
    );

    assert!(amount_out > 0, "should receive tokens");

    // Verify reserves
    let ra = ctx.decrypt_from_store(&pool.reserve_a);
    let rb = ctx.decrypt_from_store(&pool.reserve_b);
    assert_eq!(ra, 11_000, "reserve_a = 10000 + 1000");
    assert_eq!(rb, 20_000 - amount_out, "reserve_b decreased by amount_out");

    // k invariant
    assert!(ra * rb >= 10_000 * 20_000, "k must not decrease");
}

#[test]
fn test_swap_b_to_a() {
    let mut ctx = EncryptTestContext::new_default();
    let (program_id, cpi_authority, cpi_bump) = setup(&mut ctx);

    let pool = create_pool(&mut ctx, &program_id, &cpi_authority, cpi_bump);
    do_add_liquidity(&mut ctx, &program_id, &cpi_authority, cpi_bump, &pool, 10_000, 20_000);

    // Swap 2000 B → A, min_out = 0
    let amount_out = do_swap(
        &mut ctx, &program_id, &cpi_authority, cpi_bump,
        &pool, 2000, 0, 1, // direction = 1 (B→A)
    );

    assert!(amount_out > 0, "should receive tokens");

    let ra = ctx.decrypt_from_store(&pool.reserve_a);
    let rb = ctx.decrypt_from_store(&pool.reserve_b);
    assert_eq!(ra, 10_000 - amount_out, "reserve_a decreased");
    assert_eq!(rb, 22_000, "reserve_b = 20000 + 2000");
    assert!(ra * rb >= 10_000 * 20_000, "k must not decrease");
}

#[test]
fn test_swap_slippage_rejection() {
    let mut ctx = EncryptTestContext::new_default();
    let (program_id, cpi_authority, cpi_bump) = setup(&mut ctx);

    let pool = create_pool(&mut ctx, &program_id, &cpi_authority, cpi_bump);
    do_add_liquidity(&mut ctx, &program_id, &cpi_authority, cpi_bump, &pool, 10_000, 20_000);

    // Swap 1000 A → B with absurd min_amount_out = 999999
    let amount_out = do_swap(
        &mut ctx, &program_id, &cpi_authority, cpi_bump,
        &pool, 1000, 999_999, 0,
    );

    assert_eq!(amount_out, 0, "slippage: output should be 0");

    // Reserves unchanged
    assert_eq!(ctx.decrypt_from_store(&pool.reserve_a), 10_000);
    assert_eq!(ctx.decrypt_from_store(&pool.reserve_b), 20_000);
}

#[test]
fn test_multiple_swaps() {
    let mut ctx = EncryptTestContext::new_default();
    let (program_id, cpi_authority, cpi_bump) = setup(&mut ctx);

    let pool = create_pool(&mut ctx, &program_id, &cpi_authority, cpi_bump);
    do_add_liquidity(&mut ctx, &program_id, &cpi_authority, cpi_bump, &pool, 10_000, 10_000);

    // 5 swaps A→B
    let mut total_out = 0u128;
    for _ in 0..5 {
        let out = do_swap(
            &mut ctx, &program_id, &cpi_authority, cpi_bump,
            &pool, 100, 0, 0,
        );
        assert!(out > 0);
        total_out += out;
    }

    let ra = ctx.decrypt_from_store(&pool.reserve_a);
    let rb = ctx.decrypt_from_store(&pool.reserve_b);
    assert_eq!(ra, 10_500, "reserve_a = 10000 + 5*100");
    assert_eq!(rb, 10_000 - total_out, "reserve_b decreased by total out");
    assert!(ra * rb >= 10_000 * 10_000, "k invariant holds after multiple swaps");
}

#[test]
fn test_bidirectional_swaps() {
    let mut ctx = EncryptTestContext::new_default();
    let (program_id, cpi_authority, cpi_bump) = setup(&mut ctx);

    let pool = create_pool(&mut ctx, &program_id, &cpi_authority, cpi_bump);
    do_add_liquidity(&mut ctx, &program_id, &cpi_authority, cpi_bump, &pool, 10_000, 10_000);

    // Swap 500 A → B
    let out_b = do_swap(
        &mut ctx, &program_id, &cpi_authority, cpi_bump,
        &pool, 500, 0, 0,
    );
    assert!(out_b > 0);

    // Swap 500 B → A
    let out_a = do_swap(
        &mut ctx, &program_id, &cpi_authority, cpi_bump,
        &pool, 500, 0, 1,
    );
    assert!(out_a > 0);

    let ra = ctx.decrypt_from_store(&pool.reserve_a);
    let rb = ctx.decrypt_from_store(&pool.reserve_b);

    // After bidirectional swaps, k should still hold
    assert!(ra * rb >= 10_000 * 10_000, "k invariant after bidirectional swaps");

    // Due to fees, reserves should be slightly higher than initial
    assert!(ra + rb > 20_000, "fees accumulate in reserves");
}

#[test]
fn test_add_liquidity_multiple() {
    let mut ctx = EncryptTestContext::new_default();
    let (program_id, cpi_authority, cpi_bump) = setup(&mut ctx);

    let pool = create_pool(&mut ctx, &program_id, &cpi_authority, cpi_bump);

    do_add_liquidity(&mut ctx, &program_id, &cpi_authority, cpi_bump, &pool, 5_000, 10_000);
    do_add_liquidity(&mut ctx, &program_id, &cpi_authority, cpi_bump, &pool, 3_000, 6_000);

    assert_eq!(ctx.decrypt_from_store(&pool.reserve_a), 8_000);
    assert_eq!(ctx.decrypt_from_store(&pool.reserve_b), 16_000);
}

#[test]
fn test_remove_liquidity() {
    let mut ctx = EncryptTestContext::new_default();
    let (program_id, cpi_authority, cpi_bump) = setup(&mut ctx);

    let pool = create_pool(&mut ctx, &program_id, &cpi_authority, cpi_bump);
    do_add_liquidity(&mut ctx, &program_id, &cpi_authority, cpi_bump, &pool, 10_000, 20_000);

    // Remove 50%
    let share_ct = ctx.create_input::<Uint128>(5000, &program_id); // 5000 bps = 50%
    let out_a_ct = ctx.create_input::<Uint128>(0, &program_id);
    let out_b_ct = ctx.create_input::<Uint128>(0, &program_id);

    let ix = Instruction::new_with_bytes(
        program_id,
        &[4u8, cpi_bump],
        vec![
            AccountMeta::new_readonly(pool.pda, false),
            AccountMeta::new(pool.reserve_a, false),
            AccountMeta::new(pool.reserve_b, false),
            AccountMeta::new(share_ct, false),
            AccountMeta::new(out_a_ct, false),
            AccountMeta::new(out_b_ct, false),
            AccountMeta::new_readonly(*ctx.program_id(), false),
            AccountMeta::new(*ctx.config_pda(), false),
            AccountMeta::new(*ctx.deposit_pda(), false),
            AccountMeta::new_readonly(cpi_authority, false),
            AccountMeta::new_readonly(program_id, false),
            AccountMeta::new_readonly(*ctx.network_encryption_key_pda(), false),
            AccountMeta::new(ctx.payer().pubkey(), true),
            AccountMeta::new_readonly(*ctx.event_authority(), false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
        ],
    );
    ctx.send_transaction(&[ix], &[]);

    let graph = remove_liquidity_graph();
    ctx.enqueue_graph_execution(
        &graph,
        &[pool.reserve_a, pool.reserve_b, share_ct],
        &[out_a_ct, out_b_ct, pool.reserve_a, pool.reserve_b],
    );
    ctx.process_pending();
    ctx.register_ciphertext(&pool.reserve_a);
    ctx.register_ciphertext(&pool.reserve_b);
    ctx.register_ciphertext(&out_a_ct);
    ctx.register_ciphertext(&out_b_ct);

    assert_eq!(ctx.decrypt_from_store(&out_a_ct), 5_000, "withdrew 50% of A");
    assert_eq!(ctx.decrypt_from_store(&out_b_ct), 10_000, "withdrew 50% of B");
    assert_eq!(ctx.decrypt_from_store(&pool.reserve_a), 5_000, "remaining A");
    assert_eq!(ctx.decrypt_from_store(&pool.reserve_b), 10_000, "remaining B");
}

#[test]
fn test_full_lifecycle() {
    let mut ctx = EncryptTestContext::new_default();
    let (program_id, cpi_authority, cpi_bump) = setup(&mut ctx);

    // Create + add liquidity
    let pool = create_pool(&mut ctx, &program_id, &cpi_authority, cpi_bump);
    do_add_liquidity(&mut ctx, &program_id, &cpi_authority, cpi_bump, &pool, 10_000, 10_000);

    let initial_k = 10_000u128 * 10_000u128;

    // Swap A→B
    let out1 = do_swap(&mut ctx, &program_id, &cpi_authority, cpi_bump, &pool, 1000, 0, 0);
    assert!(out1 > 0);

    // Swap B→A
    let out2 = do_swap(&mut ctx, &program_id, &cpi_authority, cpi_bump, &pool, 500, 0, 1);
    assert!(out2 > 0);

    // k still holds
    let ra = ctx.decrypt_from_store(&pool.reserve_a);
    let rb = ctx.decrypt_from_store(&pool.reserve_b);
    assert!(ra * rb >= initial_k, "k invariant after swaps");

    // Remove 100% liquidity
    let share_ct = ctx.create_input::<Uint128>(10000, &program_id);
    let out_a = ctx.create_input::<Uint128>(0, &program_id);
    let out_b = ctx.create_input::<Uint128>(0, &program_id);

    let ix = Instruction::new_with_bytes(
        program_id,
        &[4u8, cpi_bump],
        vec![
            AccountMeta::new_readonly(pool.pda, false),
            AccountMeta::new(pool.reserve_a, false),
            AccountMeta::new(pool.reserve_b, false),
            AccountMeta::new(share_ct, false),
            AccountMeta::new(out_a, false),
            AccountMeta::new(out_b, false),
            AccountMeta::new_readonly(*ctx.program_id(), false),
            AccountMeta::new(*ctx.config_pda(), false),
            AccountMeta::new(*ctx.deposit_pda(), false),
            AccountMeta::new_readonly(cpi_authority, false),
            AccountMeta::new_readonly(program_id, false),
            AccountMeta::new_readonly(*ctx.network_encryption_key_pda(), false),
            AccountMeta::new(ctx.payer().pubkey(), true),
            AccountMeta::new_readonly(*ctx.event_authority(), false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
        ],
    );
    ctx.send_transaction(&[ix], &[]);

    let graph = remove_liquidity_graph();
    ctx.enqueue_graph_execution(
        &graph,
        &[pool.reserve_a, pool.reserve_b, share_ct],
        &[out_a, out_b, pool.reserve_a, pool.reserve_b],
    );
    ctx.process_pending();
    ctx.register_ciphertext(&pool.reserve_a);
    ctx.register_ciphertext(&pool.reserve_b);
    ctx.register_ciphertext(&out_a);
    ctx.register_ciphertext(&out_b);

    // Withdrawn amounts should equal final reserves (100% removal)
    assert_eq!(ctx.decrypt_from_store(&out_a), ra, "withdrew all A");
    assert_eq!(ctx.decrypt_from_store(&out_b), rb, "withdrew all B");
    assert_eq!(ctx.decrypt_from_store(&pool.reserve_a), 0, "pool empty A");
    assert_eq!(ctx.decrypt_from_store(&pool.reserve_b), 0, "pool empty B");

    // Total withdrawn should be more than deposited (fees!)
    let total_withdrawn = ctx.decrypt_from_store(&out_a) + ctx.decrypt_from_store(&out_b);
    assert!(total_withdrawn > 20_000, "LP earned fees");
}
