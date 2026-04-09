// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! LiteSVM tests for CP-Swap with proper LP token tracking.

use encrypt_dsl::prelude::encrypt_fn;
use encrypt_solana_test::litesvm::EncryptTestContext;
use encrypt_types::encrypted::{EUint128, Uint128};
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Keypair;
use solana_sdk::signer::Signer;

#[encrypt_fn]
fn swap_graph(
    reserve_in: EUint128, reserve_out: EUint128,
    amount_in: EUint128, min_amount_out: EUint128,
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
    reserve_a: EUint128, reserve_b: EUint128, total_supply: EUint128,
    amount_a: EUint128, amount_b: EUint128,
) -> (EUint128, EUint128, EUint128, EUint128) {
    let new_reserve_a = reserve_a + amount_a;
    let new_reserve_b = reserve_b + amount_b;
    let initial_lp = amount_a * amount_b;
    let lp_from_a = (amount_a * total_supply) / (reserve_a + 1);
    let lp_from_b = (amount_b * total_supply) / (reserve_b + 1);
    let subsequent_lp = if lp_from_a >= lp_from_b { lp_from_b } else { lp_from_a };
    let is_first = total_supply >= 1;
    let lp_to_mint = if is_first { subsequent_lp } else { initial_lp };
    let new_total_supply = total_supply + lp_to_mint;
    (new_reserve_a, new_reserve_b, lp_to_mint, new_total_supply)
}

#[encrypt_fn]
fn remove_liquidity_graph(
    reserve_a: EUint128, reserve_b: EUint128,
    total_supply: EUint128, burn_amount: EUint128,
) -> (EUint128, EUint128, EUint128, EUint128, EUint128) {
    let amount_a = (reserve_a * burn_amount) / total_supply;
    let amount_b = (reserve_b * burn_amount) / total_supply;
    let new_reserve_a = reserve_a - amount_a;
    let new_reserve_b = reserve_b - amount_b;
    let new_total_supply = total_supply - burn_amount;
    (amount_a, amount_b, new_reserve_a, new_reserve_b, new_total_supply)
}

const PROGRAM_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../../../target/deploy/cp_swap.so"
);
const SYSTEM_PROGRAM: Pubkey = Pubkey::new_from_array([0u8; 32]);

fn setup(ctx: &mut EncryptTestContext) -> (Pubkey, Pubkey, u8) {
    let program_id = ctx.deploy_program(PROGRAM_PATH);
    let (cpi_authority, cpi_bump) = ctx.cpi_authority_for(&program_id);
    (program_id, cpi_authority, cpi_bump)
}

struct PoolInfo {
    pda: Pubkey,
    reserve_a: Pubkey,
    reserve_b: Pubkey,
    total_supply: Pubkey,
}

fn do_create_pool(
    ctx: &mut EncryptTestContext, pid: &Pubkey, cpi_auth: &Pubkey, cpi_bump: u8,
) -> PoolInfo {
    let mint_a = Pubkey::new_unique();
    let mint_b = Pubkey::new_unique();
    let (pool_pda, pool_bump) = Pubkey::find_program_address(
        &[b"cp_pool", mint_a.as_ref(), mint_b.as_ref()], pid,
    );
    let ra = Keypair::new();
    let rb = Keypair::new();
    let ts = Keypair::new();

    ctx.send_transaction(&[Instruction::new_with_bytes(
        *pid, &[0, pool_bump, cpi_bump],
        vec![
            AccountMeta::new(pool_pda, false),
            AccountMeta::new_readonly(mint_a, false),
            AccountMeta::new_readonly(mint_b, false),
            AccountMeta::new(ra.pubkey(), true),
            AccountMeta::new(rb.pubkey(), true),
            AccountMeta::new(ts.pubkey(), true),
            AccountMeta::new_readonly(*ctx.program_id(), false),
            AccountMeta::new_readonly(*ctx.config_pda(), false),
            AccountMeta::new(*ctx.deposit_pda(), false),
            AccountMeta::new_readonly(*cpi_auth, false),
            AccountMeta::new_readonly(*pid, false),
            AccountMeta::new_readonly(*ctx.network_encryption_key_pda(), false),
            AccountMeta::new(ctx.payer().pubkey(), true),
            AccountMeta::new_readonly(*ctx.event_authority(), false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
        ],
    )], &[&ra, &rb, &ts]);

    let info = PoolInfo {
        pda: pool_pda,
        reserve_a: ra.pubkey(),
        reserve_b: rb.pubkey(),
        total_supply: ts.pubkey(),
    };
    ctx.register_ciphertext(&info.reserve_a);
    ctx.register_ciphertext(&info.reserve_b);
    ctx.register_ciphertext(&info.total_supply);
    info
}

fn do_add_liq(
    ctx: &mut EncryptTestContext, pid: &Pubkey, cpi_auth: &Pubkey, cpi_bump: u8,
    pool: &PoolInfo, amt_a: u128, amt_b: u128,
) -> Pubkey {
    let a_ct = ctx.create_input::<Uint128>(amt_a, pid);
    let b_ct = ctx.create_input::<Uint128>(amt_b, pid);
    let lp_ct = ctx.create_input::<Uint128>(0, pid);

    ctx.send_transaction(&[Instruction::new_with_bytes(
        *pid, &[2, cpi_bump],
        vec![
            AccountMeta::new_readonly(pool.pda, false),
            AccountMeta::new(pool.reserve_a, false),
            AccountMeta::new(pool.reserve_b, false),
            AccountMeta::new(pool.total_supply, false),
            AccountMeta::new(a_ct, false),
            AccountMeta::new(b_ct, false),
            AccountMeta::new(lp_ct, false),
            AccountMeta::new_readonly(*ctx.program_id(), false),
            AccountMeta::new(*ctx.config_pda(), false),
            AccountMeta::new(*ctx.deposit_pda(), false),
            AccountMeta::new_readonly(*cpi_auth, false),
            AccountMeta::new_readonly(*pid, false),
            AccountMeta::new_readonly(*ctx.network_encryption_key_pda(), false),
            AccountMeta::new(ctx.payer().pubkey(), true),
            AccountMeta::new_readonly(*ctx.event_authority(), false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
        ],
    )], &[]);

    let graph = add_liquidity_graph();
    ctx.enqueue_graph_execution(
        &graph,
        &[pool.reserve_a, pool.reserve_b, pool.total_supply, a_ct, b_ct],
        &[pool.reserve_a, pool.reserve_b, lp_ct, pool.total_supply],
    );
    ctx.process_pending();
    ctx.register_ciphertext(&pool.reserve_a);
    ctx.register_ciphertext(&pool.reserve_b);
    ctx.register_ciphertext(&pool.total_supply);
    ctx.register_ciphertext(&lp_ct);
    lp_ct
}

fn do_swap(
    ctx: &mut EncryptTestContext, pid: &Pubkey, cpi_auth: &Pubkey, cpi_bump: u8,
    pool: &PoolInfo, amount_in: u128, min_out: u128, direction: u8,
) -> (Pubkey, u128) {
    let (rin, rout) = if direction == 0 {
        (pool.reserve_a, pool.reserve_b)
    } else {
        (pool.reserve_b, pool.reserve_a)
    };
    let in_ct = ctx.create_input::<Uint128>(amount_in, pid);
    let min_ct = ctx.create_input::<Uint128>(min_out, pid);
    let out_ct = ctx.create_input::<Uint128>(0, pid);

    ctx.send_transaction(&[Instruction::new_with_bytes(
        *pid, &[1, cpi_bump, direction],
        vec![
            AccountMeta::new_readonly(pool.pda, false),
            AccountMeta::new(rin, false),
            AccountMeta::new(rout, false),
            AccountMeta::new(in_ct, false),
            AccountMeta::new(min_ct, false),
            AccountMeta::new(out_ct, false),
            AccountMeta::new_readonly(*ctx.program_id(), false),
            AccountMeta::new(*ctx.config_pda(), false),
            AccountMeta::new(*ctx.deposit_pda(), false),
            AccountMeta::new_readonly(*cpi_auth, false),
            AccountMeta::new_readonly(*pid, false),
            AccountMeta::new_readonly(*ctx.network_encryption_key_pda(), false),
            AccountMeta::new(ctx.payer().pubkey(), true),
            AccountMeta::new_readonly(*ctx.event_authority(), false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
        ],
    )], &[]);

    let graph = swap_graph();
    ctx.enqueue_graph_execution(&graph, &[rin, rout, in_ct, min_ct], &[out_ct, rin, rout]);
    ctx.process_pending();
    ctx.register_ciphertext(&pool.reserve_a);
    ctx.register_ciphertext(&pool.reserve_b);
    ctx.register_ciphertext(&out_ct);

    let amount_out = ctx.decrypt_from_store(&out_ct);
    (out_ct, amount_out)
}

fn do_remove_liq(
    ctx: &mut EncryptTestContext, pid: &Pubkey, cpi_auth: &Pubkey, cpi_bump: u8,
    pool: &PoolInfo, burn_amount: u128,
) -> (u128, u128) {
    let burn_ct = ctx.create_input::<Uint128>(burn_amount, pid);
    let out_a = ctx.create_input::<Uint128>(0, pid);
    let out_b = ctx.create_input::<Uint128>(0, pid);

    ctx.send_transaction(&[Instruction::new_with_bytes(
        *pid, &[4, cpi_bump],
        vec![
            AccountMeta::new_readonly(pool.pda, false),
            AccountMeta::new(pool.reserve_a, false),
            AccountMeta::new(pool.reserve_b, false),
            AccountMeta::new(pool.total_supply, false),
            AccountMeta::new(burn_ct, false),
            AccountMeta::new(out_a, false),
            AccountMeta::new(out_b, false),
            AccountMeta::new_readonly(*ctx.program_id(), false),
            AccountMeta::new(*ctx.config_pda(), false),
            AccountMeta::new(*ctx.deposit_pda(), false),
            AccountMeta::new_readonly(*cpi_auth, false),
            AccountMeta::new_readonly(*pid, false),
            AccountMeta::new_readonly(*ctx.network_encryption_key_pda(), false),
            AccountMeta::new(ctx.payer().pubkey(), true),
            AccountMeta::new_readonly(*ctx.event_authority(), false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
        ],
    )], &[]);

    let graph = remove_liquidity_graph();
    ctx.enqueue_graph_execution(
        &graph,
        &[pool.reserve_a, pool.reserve_b, pool.total_supply, burn_ct],
        &[out_a, out_b, pool.reserve_a, pool.reserve_b, pool.total_supply],
    );
    ctx.process_pending();
    ctx.register_ciphertext(&pool.reserve_a);
    ctx.register_ciphertext(&pool.reserve_b);
    ctx.register_ciphertext(&pool.total_supply);
    ctx.register_ciphertext(&out_a);
    ctx.register_ciphertext(&out_b);

    (ctx.decrypt_from_store(&out_a), ctx.decrypt_from_store(&out_b))
}

// ── Tests ──

#[test]
fn test_create_pool() {
    let mut ctx = EncryptTestContext::new_default();
    let (pid, auth, bump) = setup(&mut ctx);
    let pool = do_create_pool(&mut ctx, &pid, &auth, bump);
    assert_eq!(ctx.decrypt_from_store(&pool.reserve_a), 0);
    assert_eq!(ctx.decrypt_from_store(&pool.reserve_b), 0);
    assert_eq!(ctx.decrypt_from_store(&pool.total_supply), 0);
}

#[test]
fn test_add_liquidity_first_deposit() {
    let mut ctx = EncryptTestContext::new_default();
    let (pid, auth, bump) = setup(&mut ctx);
    let pool = do_create_pool(&mut ctx, &pid, &auth, bump);
    let lp_ct = do_add_liq(&mut ctx, &pid, &auth, bump, &pool, 10_000, 20_000);

    assert_eq!(ctx.decrypt_from_store(&pool.reserve_a), 10_000);
    assert_eq!(ctx.decrypt_from_store(&pool.reserve_b), 20_000);
    let lp = ctx.decrypt_from_store(&lp_ct);
    assert_eq!(lp, 10_000 * 20_000, "first deposit: LP = a * b");
    assert_eq!(ctx.decrypt_from_store(&pool.total_supply), lp);
}

#[test]
fn test_swap_and_k_invariant() {
    let mut ctx = EncryptTestContext::new_default();
    let (pid, auth, bump) = setup(&mut ctx);
    let pool = do_create_pool(&mut ctx, &pid, &auth, bump);
    do_add_liq(&mut ctx, &pid, &auth, bump, &pool, 10_000, 10_000);

    let (_, out) = do_swap(&mut ctx, &pid, &auth, bump, &pool, 1000, 0, 0);
    assert!(out > 0);

    let ra = ctx.decrypt_from_store(&pool.reserve_a);
    let rb = ctx.decrypt_from_store(&pool.reserve_b);
    assert_eq!(ra, 11_000);
    assert!(ra * rb >= 10_000 * 10_000, "k invariant");
}

#[test]
fn test_slippage_rejection() {
    let mut ctx = EncryptTestContext::new_default();
    let (pid, auth, bump) = setup(&mut ctx);
    let pool = do_create_pool(&mut ctx, &pid, &auth, bump);
    do_add_liq(&mut ctx, &pid, &auth, bump, &pool, 10_000, 10_000);

    let (_, out) = do_swap(&mut ctx, &pid, &auth, bump, &pool, 1000, 999_999, 0);
    assert_eq!(out, 0);
    assert_eq!(ctx.decrypt_from_store(&pool.reserve_a), 10_000);
    assert_eq!(ctx.decrypt_from_store(&pool.reserve_b), 10_000);
}

#[test]
fn test_remove_liquidity_proportional() {
    let mut ctx = EncryptTestContext::new_default();
    let (pid, auth, bump) = setup(&mut ctx);
    let pool = do_create_pool(&mut ctx, &pid, &auth, bump);
    let lp_ct = do_add_liq(&mut ctx, &pid, &auth, bump, &pool, 10_000, 20_000);

    let total_lp = ctx.decrypt_from_store(&lp_ct);
    let half = total_lp / 2;

    let (a_out, b_out) = do_remove_liq(&mut ctx, &pid, &auth, bump, &pool, half);
    assert_eq!(a_out, 5_000, "50% of reserve A");
    assert_eq!(b_out, 10_000, "50% of reserve B");
    assert_eq!(ctx.decrypt_from_store(&pool.reserve_a), 5_000);
    assert_eq!(ctx.decrypt_from_store(&pool.reserve_b), 10_000);
    assert_eq!(ctx.decrypt_from_store(&pool.total_supply), total_lp - half);
}

#[test]
fn test_two_lps_fair_split() {
    let mut ctx = EncryptTestContext::new_default();
    let (pid, auth, bump) = setup(&mut ctx);
    let pool = do_create_pool(&mut ctx, &pid, &auth, bump);

    // Alice deposits first: 1000/1000
    let alice_lp_ct = do_add_liq(&mut ctx, &pid, &auth, bump, &pool, 1000, 1000);
    let alice_lp = ctx.decrypt_from_store(&alice_lp_ct);
    assert!(alice_lp > 0);

    // Bob deposits proportionally: 500/500
    let bob_lp_ct = do_add_liq(&mut ctx, &pid, &auth, bump, &pool, 500, 500);
    let bob_lp = ctx.decrypt_from_store(&bob_lp_ct);
    assert!(bob_lp > 0);

    // Alice should have ~2x Bob's LP (she deposited 2x)
    // Not exact due to +1 in denominator, but close
    assert!(alice_lp > bob_lp, "alice deposited more → more LP");

    let total = ctx.decrypt_from_store(&pool.total_supply);
    assert_eq!(total, alice_lp + bob_lp);

    // Bob removes all his LP
    let (b_a, b_b) = do_remove_liq(&mut ctx, &pid, &auth, bump, &pool, bob_lp);
    assert!(b_a > 0 && b_b > 0, "Bob gets tokens back");

    // Alice removes all her LP
    let (a_a, a_b) = do_remove_liq(&mut ctx, &pid, &auth, bump, &pool, alice_lp);
    assert!(a_a > 0 && a_b > 0, "Alice gets tokens back");
    assert!(a_a > b_a, "Alice gets more than Bob");
}

#[test]
fn test_lp_earns_fees() {
    let mut ctx = EncryptTestContext::new_default();
    let (pid, auth, bump) = setup(&mut ctx);
    let pool = do_create_pool(&mut ctx, &pid, &auth, bump);
    let lp_ct = do_add_liq(&mut ctx, &pid, &auth, bump, &pool, 10_000, 10_000);
    let lp_amount = ctx.decrypt_from_store(&lp_ct);

    // Do several swaps to accumulate fees
    for _ in 0..5 {
        do_swap(&mut ctx, &pid, &auth, bump, &pool, 1000, 0, 0);
        do_swap(&mut ctx, &pid, &auth, bump, &pool, 1000, 0, 1);
    }

    // Remove all liquidity
    let (a_out, b_out) = do_remove_liq(&mut ctx, &pid, &auth, bump, &pool, lp_amount);

    // Should get MORE than deposited (fees!)
    assert!(a_out + b_out > 20_000, "LP earned fees: {} + {} > 20000", a_out, b_out);
}

#[test]
fn test_full_lifecycle() {
    let mut ctx = EncryptTestContext::new_default();
    let (pid, auth, bump) = setup(&mut ctx);
    let pool = do_create_pool(&mut ctx, &pid, &auth, bump);

    // Add liquidity
    let lp = do_add_liq(&mut ctx, &pid, &auth, bump, &pool, 10_000, 10_000);
    let lp_amount = ctx.decrypt_from_store(&lp);

    // Swap A→B
    let (_, out1) = do_swap(&mut ctx, &pid, &auth, bump, &pool, 1000, 0, 0);
    assert!(out1 > 0);

    // Swap B→A
    let (_, out2) = do_swap(&mut ctx, &pid, &auth, bump, &pool, 500, 0, 1);
    assert!(out2 > 0);

    // Verify k
    let ra = ctx.decrypt_from_store(&pool.reserve_a);
    let rb = ctx.decrypt_from_store(&pool.reserve_b);
    assert!(ra * rb >= 10_000 * 10_000);

    // Remove all
    let (a_out, b_out) = do_remove_liq(&mut ctx, &pid, &auth, bump, &pool, lp_amount);
    assert_eq!(ctx.decrypt_from_store(&pool.reserve_a), 0);
    assert_eq!(ctx.decrypt_from_store(&pool.reserve_b), 0);
    assert_eq!(ctx.decrypt_from_store(&pool.total_supply), 0);
    assert!(a_out + b_out > 20_000, "LP earned fees");
}
