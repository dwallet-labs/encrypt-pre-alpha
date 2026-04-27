// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Comprehensive LiteSVM E2E tests for all vector operations and types.
//!
//! Tests every operation through the full on-chain CPI → off-chain graph eval → commit pipeline.

use encrypt_dsl::prelude::encrypt_fn;
use encrypt_solana_test::litesvm::EncryptTestContext;
use encrypt_types::encrypted::*;
use encrypt_types::types::FheType;
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signer::Signer;

// ── Re-declare all graph functions for off-chain evaluation ──

#[encrypt_fn] fn add_u32_graph(a: EUint32Vector, b: EUint32Vector) -> EUint32Vector { a + b }
#[encrypt_fn] fn sub_u32_graph(a: EUint32Vector, b: EUint32Vector) -> EUint32Vector { a - b }
#[encrypt_fn] fn mul_u32_graph(a: EUint32Vector, b: EUint32Vector) -> EUint32Vector { a * b }
#[encrypt_fn] fn div_u32_graph(a: EUint32Vector, b: EUint32Vector) -> EUint32Vector { a / b }
#[encrypt_fn] fn mod_u32_graph(a: EUint32Vector, b: EUint32Vector) -> EUint32Vector { a % b }
#[encrypt_fn] fn and_u32_graph(a: EUint32Vector, b: EUint32Vector) -> EUint32Vector { a & b }
#[encrypt_fn] fn or_u32_graph(a: EUint32Vector, b: EUint32Vector) -> EUint32Vector { a | b }
#[encrypt_fn] fn xor_u32_graph(a: EUint32Vector, b: EUint32Vector) -> EUint32Vector { a ^ b }
#[encrypt_fn] fn neg_u32_graph(a: EUint32Vector) -> EUint32Vector { -a }
#[encrypt_fn] fn not_u32_graph(a: EUint32Vector) -> EUint32Vector { !a }
#[encrypt_fn] fn add_scalar_u32_graph(a: EUint32Vector) -> EUint32Vector { a + 5 }
#[encrypt_fn] fn mul_scalar_u32_graph(a: EUint32Vector) -> EUint32Vector { a * 3 }
#[encrypt_fn] fn min_u32_graph(a: EUint32Vector, b: EUint32Vector) -> EUint32Vector { a.min(&b) }
#[encrypt_fn] fn max_u32_graph(a: EUint32Vector, b: EUint32Vector) -> EUint32Vector { a.max(&b) }
#[encrypt_fn] fn eq_u32_graph(a: EUint32Vector, b: EUint32Vector) -> EUint32Vector { a.is_equal(&b) }
#[encrypt_fn] fn lt_u32_graph(a: EUint32Vector, b: EUint32Vector) -> EUint32Vector { a.is_less_than(&b) }
#[encrypt_fn] fn select_u32_graph(cond: EBool, a: EUint32Vector, b: EUint32Vector) -> EUint32Vector { if cond { a } else { b } }
// Multi-op chained graphs
#[encrypt_fn] fn dot2_u32_graph(a: EUint32Vector, b: EUint32Vector, c: EUint32Vector, d: EUint32Vector) -> EUint32Vector { a * b + c * d }
#[encrypt_fn] fn linear_u32_graph(a: EUint32Vector, b: EUint32Vector) -> EUint32Vector { a * 5 + b * 3 + 7 }
#[encrypt_fn] fn mask_sum_u32_graph(a: EUint32Vector, b: EUint32Vector, mask: EUint32Vector) -> EUint32Vector { (a & mask) + (b | mask) }
#[encrypt_fn] fn cond_add_u32_graph(cond: EBool, acc: EUint32Vector, val: EUint32Vector) -> EUint32Vector { let added = acc + val; if cond { added } else { acc } }
#[encrypt_fn] fn chain4_u32_graph(a: EUint32Vector, b: EUint32Vector, c: EUint32Vector) -> EUint32Vector { (((a + b) * 2) - c) / 2 }
#[encrypt_fn] fn sum_diff_u32_graph(a: EUint32Vector, b: EUint32Vector) -> (EUint32Vector, EUint32Vector) { (a + b, a - b) }

#[encrypt_fn] fn add_u8_graph(a: EUint8Vector, b: EUint8Vector) -> EUint8Vector { a + b }
#[encrypt_fn] fn mul_scalar_u8_graph(a: EUint8Vector) -> EUint8Vector { a * 2 }

// Cross-Entry & Reduction graphs (REFHE refresh)
#[encrypt_fn] fn reduce_add_u32_graph(a: EUint32Vector) -> EUint32 { a.reduce_add() }
#[encrypt_fn] fn reduce_min_u32_graph(a: EUint32Vector) -> EUint32 { a.reduce_min() }
#[encrypt_fn] fn reduce_max_u32_graph(a: EUint32Vector) -> EUint32 { a.reduce_max() }
#[encrypt_fn] fn reduce_any_u8_graph(a: EUint8Vector) -> EBool { a.reduce_any() }
#[encrypt_fn] fn reduce_all_u8_graph(a: EUint8Vector) -> EBool { a.reduce_all() }
#[encrypt_fn] fn rotate_entries_u32_graph(a: EUint32Vector, n: EUint32) -> EUint32Vector { a.rotate_entries(&n) }
#[encrypt_fn] fn range_u32_graph(a: EUint32Vector) -> EUint32 { let mx = a.reduce_max(); let mn = a.reduce_min(); mx - mn }
#[encrypt_fn] fn add_u64_graph(a: EUint64Vector, b: EUint64Vector) -> EUint64Vector { a + b }
#[encrypt_fn] fn mul_scalar_u64_graph(a: EUint64Vector) -> EUint64Vector { a * 7 }
#[encrypt_fn] fn add_u128_graph(a: EUint128Vector, b: EUint128Vector) -> EUint128Vector { a + b }
#[encrypt_fn] fn mul_scalar_u128_graph(a: EUint128Vector) -> EUint128Vector { a * 11 }

// ── Constants ──

const EXAMPLE_PROGRAM_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../../../target/deploy/confidential_vector_ops.so"
);

// ── Helpers ──

fn make_u32_vec(elems: &[u32]) -> Vec<u8> {
    let mut b = vec![0u8; 8192];
    for (i, &v) in elems.iter().enumerate() { b[i*4..(i+1)*4].copy_from_slice(&v.to_le_bytes()); }
    b
}
fn read_u32(buf: &[u8], idx: usize) -> u32 {
    u32::from_le_bytes(buf[idx*4..(idx+1)*4].try_into().unwrap())
}

fn make_u8_vec(elems: &[u8]) -> Vec<u8> {
    let mut b = vec![0u8; 8192];
    for (i, &v) in elems.iter().enumerate() { b[i] = v; }
    b
}

fn make_u64_vec(elems: &[u64]) -> Vec<u8> {
    let mut b = vec![0u8; 8192];
    for (i, &v) in elems.iter().enumerate() { b[i*8..(i+1)*8].copy_from_slice(&v.to_le_bytes()); }
    b
}
fn read_u64(buf: &[u8], idx: usize) -> u64 {
    u64::from_le_bytes(buf[idx*8..(idx+1)*8].try_into().unwrap())
}

fn make_u128_vec(elems: &[u128]) -> Vec<u8> {
    let mut b = vec![0u8; 8192];
    for (i, &v) in elems.iter().enumerate() { b[i*16..(i+1)*16].copy_from_slice(&v.to_le_bytes()); }
    b
}
fn read_u128(buf: &[u8], idx: usize) -> u128 {
    u128::from_le_bytes(buf[idx*16..(idx+1)*16].try_into().unwrap())
}

fn setup(ctx: &mut EncryptTestContext) -> (Pubkey, Pubkey, u8) {
    let pid = ctx.deploy_program(EXAMPLE_PROGRAM_PATH);
    let (cpi, bump) = ctx.cpi_authority_for(&pid);
    (pid, cpi, bump)
}

fn encrypt_accounts(
    pid: &Pubkey, ctx: &EncryptTestContext, cpi_authority: &Pubkey,
) -> Vec<AccountMeta> {
    vec![
        AccountMeta::new_readonly(*ctx.program_id(), false),
        AccountMeta::new(*ctx.config_pda(), false),
        AccountMeta::new(*ctx.deposit_pda(), false),
        AccountMeta::new_readonly(*cpi_authority, false),
        AccountMeta::new_readonly(*pid, false),
        AccountMeta::new_readonly(*ctx.network_encryption_key_pda(), false),
        AccountMeta::new(ctx.payer().pubkey(), true),
        AccountMeta::new_readonly(*ctx.event_authority(), false),
        AccountMeta::new_readonly(Pubkey::new_from_array([0u8; 32]), false),
    ]
}

/// Run a binary op end-to-end: create inputs → on-chain CPI → off-chain eval → commit → verify
fn run_binary_e2e(
    ctx: &mut EncryptTestContext,
    pid: &Pubkey, cpi: &Pubkey, cpi_bump: u8,
    disc: u8,
    graph_fn: fn() -> Vec<u8>,
    fhe_type: FheType,
    a_bytes: &[u8], b_bytes: &[u8],
) -> Vec<u8> {
    let a_pk = ctx.create_input_bytes(fhe_type, a_bytes, pid);
    let b_pk = ctx.create_input_bytes(fhe_type, b_bytes, pid);
    let r_pk = ctx.create_input_bytes(fhe_type, &vec![0u8; fhe_type.byte_width()], pid);

    let mut accts = vec![
        AccountMeta::new(a_pk, false),
        AccountMeta::new(b_pk, false),
        AccountMeta::new(r_pk, false),
    ];
    accts.extend(encrypt_accounts(pid, ctx, cpi));

    let ix = Instruction::new_with_bytes(*pid, &[disc, cpi_bump], accts);
    ctx.send_transaction(&[ix], &[]);

    let graph = graph_fn();
    ctx.enqueue_graph_execution(&graph, &[a_pk, b_pk], &[r_pk]);
    ctx.process_pending();
    ctx.register_ciphertext(&r_pk);
    ctx.decrypt_bytes(&r_pk)
}

/// Run a unary/scalar op end-to-end
fn run_unary_e2e(
    ctx: &mut EncryptTestContext,
    pid: &Pubkey, cpi: &Pubkey, cpi_bump: u8,
    disc: u8,
    graph_fn: fn() -> Vec<u8>,
    fhe_type: FheType,
    a_bytes: &[u8],
) -> Vec<u8> {
    let a_pk = ctx.create_input_bytes(fhe_type, a_bytes, pid);
    let r_pk = ctx.create_input_bytes(fhe_type, &vec![0u8; fhe_type.byte_width()], pid);

    let mut accts = vec![
        AccountMeta::new(a_pk, false),
        AccountMeta::new(r_pk, false),
    ];
    accts.extend(encrypt_accounts(pid, ctx, cpi));

    let ix = Instruction::new_with_bytes(*pid, &[disc, cpi_bump], accts);
    ctx.send_transaction(&[ix], &[]);

    let graph = graph_fn();
    ctx.enqueue_graph_execution(&graph, &[a_pk], &[r_pk]);
    ctx.process_pending();
    ctx.register_ciphertext(&r_pk);
    ctx.decrypt_bytes(&r_pk)
}

// ════════════════════════════════════════════════════════════
// EUint32Vector — ALL operations E2E
// ════════════════════════════════════════════════════════════

#[test]
fn e2e_u32_add() {
    let mut ctx = EncryptTestContext::new_default();
    let (pid, cpi, bump) = setup(&mut ctx);
    let r = run_binary_e2e(&mut ctx, &pid, &cpi, bump, 1, add_u32_graph, FheType::EVectorU32,
        &make_u32_vec(&[10, 20, 30]), &make_u32_vec(&[1, 2, 3]));
    assert_eq!(read_u32(&r, 0), 11); assert_eq!(read_u32(&r, 1), 22); assert_eq!(read_u32(&r, 2), 33);
}

#[test]
fn e2e_u32_sub() {
    let mut ctx = EncryptTestContext::new_default();
    let (pid, cpi, bump) = setup(&mut ctx);
    let r = run_binary_e2e(&mut ctx, &pid, &cpi, bump, 2, sub_u32_graph, FheType::EVectorU32,
        &make_u32_vec(&[50, 20]), &make_u32_vec(&[10, 5]));
    assert_eq!(read_u32(&r, 0), 40); assert_eq!(read_u32(&r, 1), 15);
}

#[test]
fn e2e_u32_mul() {
    let mut ctx = EncryptTestContext::new_default();
    let (pid, cpi, bump) = setup(&mut ctx);
    let r = run_binary_e2e(&mut ctx, &pid, &cpi, bump, 3, mul_u32_graph, FheType::EVectorU32,
        &make_u32_vec(&[6, 7]), &make_u32_vec(&[7, 8]));
    assert_eq!(read_u32(&r, 0), 42); assert_eq!(read_u32(&r, 1), 56);
}

#[test]
fn e2e_u32_div() {
    let mut ctx = EncryptTestContext::new_default();
    let (pid, cpi, bump) = setup(&mut ctx);
    let r = run_binary_e2e(&mut ctx, &pid, &cpi, bump, 4, div_u32_graph, FheType::EVectorU32,
        &make_u32_vec(&[84, 100]), &make_u32_vec(&[2, 7]));
    assert_eq!(read_u32(&r, 0), 42); assert_eq!(read_u32(&r, 1), 14);
}

#[test]
fn e2e_u32_mod() {
    let mut ctx = EncryptTestContext::new_default();
    let (pid, cpi, bump) = setup(&mut ctx);
    let r = run_binary_e2e(&mut ctx, &pid, &cpi, bump, 5, mod_u32_graph, FheType::EVectorU32,
        &make_u32_vec(&[47, 100]), &make_u32_vec(&[5, 7]));
    assert_eq!(read_u32(&r, 0), 2); assert_eq!(read_u32(&r, 1), 2);
}

#[test]
fn e2e_u32_and() {
    let mut ctx = EncryptTestContext::new_default();
    let (pid, cpi, bump) = setup(&mut ctx);
    let r = run_binary_e2e(&mut ctx, &pid, &cpi, bump, 6, and_u32_graph, FheType::EVectorU32,
        &make_u32_vec(&[0xFF, 0x0F]), &make_u32_vec(&[0x0F, 0xFF]));
    assert_eq!(read_u32(&r, 0), 0x0F); assert_eq!(read_u32(&r, 1), 0x0F);
}

#[test]
fn e2e_u32_or() {
    let mut ctx = EncryptTestContext::new_default();
    let (pid, cpi, bump) = setup(&mut ctx);
    let r = run_binary_e2e(&mut ctx, &pid, &cpi, bump, 7, or_u32_graph, FheType::EVectorU32,
        &make_u32_vec(&[0xF0, 0x0F]), &make_u32_vec(&[0x0F, 0]));
    assert_eq!(read_u32(&r, 0), 0xFF); assert_eq!(read_u32(&r, 1), 0x0F);
}

#[test]
fn e2e_u32_xor() {
    let mut ctx = EncryptTestContext::new_default();
    let (pid, cpi, bump) = setup(&mut ctx);
    let r = run_binary_e2e(&mut ctx, &pid, &cpi, bump, 8, xor_u32_graph, FheType::EVectorU32,
        &make_u32_vec(&[0xFF, 0xFF]), &make_u32_vec(&[0xFF, 0x0F]));
    assert_eq!(read_u32(&r, 0), 0); assert_eq!(read_u32(&r, 1), 0xF0);
}

#[test]
fn e2e_u32_neg() {
    let mut ctx = EncryptTestContext::new_default();
    let (pid, cpi, bump) = setup(&mut ctx);
    let r = run_unary_e2e(&mut ctx, &pid, &cpi, bump, 9, neg_u32_graph, FheType::EVectorU32,
        &make_u32_vec(&[1, 42]));
    assert_eq!(read_u32(&r, 0), u32::MAX); // -1 wraps
    assert_eq!(read_u32(&r, 1), 0u32.wrapping_sub(42));
}

#[test]
fn e2e_u32_not() {
    let mut ctx = EncryptTestContext::new_default();
    let (pid, cpi, bump) = setup(&mut ctx);
    let r = run_unary_e2e(&mut ctx, &pid, &cpi, bump, 10, not_u32_graph, FheType::EVectorU32,
        &make_u32_vec(&[0, 0xFF]));
    assert_eq!(read_u32(&r, 0), u32::MAX);
    assert_eq!(read_u32(&r, 1), !0xFFu32);
}

#[test]
fn e2e_u32_add_scalar() {
    let mut ctx = EncryptTestContext::new_default();
    let (pid, cpi, bump) = setup(&mut ctx);
    let r = run_unary_e2e(&mut ctx, &pid, &cpi, bump, 11, add_scalar_u32_graph, FheType::EVectorU32,
        &make_u32_vec(&[10, 20, 0]));
    assert_eq!(read_u32(&r, 0), 15); assert_eq!(read_u32(&r, 1), 25); assert_eq!(read_u32(&r, 2), 5);
}

#[test]
fn e2e_u32_mul_scalar() {
    let mut ctx = EncryptTestContext::new_default();
    let (pid, cpi, bump) = setup(&mut ctx);
    let r = run_unary_e2e(&mut ctx, &pid, &cpi, bump, 12, mul_scalar_u32_graph, FheType::EVectorU32,
        &make_u32_vec(&[5, 10, 15]));
    assert_eq!(read_u32(&r, 0), 15); assert_eq!(read_u32(&r, 1), 30); assert_eq!(read_u32(&r, 2), 45);
}

#[test]
fn e2e_u32_min() {
    let mut ctx = EncryptTestContext::new_default();
    let (pid, cpi, bump) = setup(&mut ctx);
    let r = run_binary_e2e(&mut ctx, &pid, &cpi, bump, 13, min_u32_graph, FheType::EVectorU32,
        &make_u32_vec(&[10, 50]), &make_u32_vec(&[20, 5]));
    assert_eq!(read_u32(&r, 0), 10); assert_eq!(read_u32(&r, 1), 5);
}

#[test]
fn e2e_u32_max() {
    let mut ctx = EncryptTestContext::new_default();
    let (pid, cpi, bump) = setup(&mut ctx);
    let r = run_binary_e2e(&mut ctx, &pid, &cpi, bump, 14, max_u32_graph, FheType::EVectorU32,
        &make_u32_vec(&[10, 50]), &make_u32_vec(&[20, 5]));
    assert_eq!(read_u32(&r, 0), 20); assert_eq!(read_u32(&r, 1), 50);
}

#[test]
fn e2e_u32_eq() {
    let mut ctx = EncryptTestContext::new_default();
    let (pid, cpi, bump) = setup(&mut ctx);
    let r = run_binary_e2e(&mut ctx, &pid, &cpi, bump, 15, eq_u32_graph, FheType::EVectorU32,
        &make_u32_vec(&[10, 20]), &make_u32_vec(&[10, 5]));
    assert_eq!(read_u32(&r, 0), 1); assert_eq!(read_u32(&r, 1), 0);
}

#[test]
fn e2e_u32_lt() {
    let mut ctx = EncryptTestContext::new_default();
    let (pid, cpi, bump) = setup(&mut ctx);
    let r = run_binary_e2e(&mut ctx, &pid, &cpi, bump, 16, lt_u32_graph, FheType::EVectorU32,
        &make_u32_vec(&[5, 20]), &make_u32_vec(&[10, 5]));
    assert_eq!(read_u32(&r, 0), 1); assert_eq!(read_u32(&r, 1), 0);
}

#[test]
fn e2e_u32_select() {
    let mut ctx = EncryptTestContext::new_default();
    let (pid, cpi, bump) = setup(&mut ctx);
    let ft = FheType::EVectorU32;

    // Select(true, a, b) → a
    let cond_pk = ctx.create_input::<Bool>(1, &pid);
    let a_pk = ctx.create_input_bytes(ft, &make_u32_vec(&[100, 200]), &pid);
    let b_pk = ctx.create_input_bytes(ft, &make_u32_vec(&[1, 2]), &pid);
    let r_pk = ctx.create_input_bytes(ft, &vec![0u8; 8192], &pid);

    let mut accts = vec![
        AccountMeta::new(cond_pk, false),
        AccountMeta::new(a_pk, false),
        AccountMeta::new(b_pk, false),
        AccountMeta::new(r_pk, false),
    ];
    accts.extend(encrypt_accounts(&pid, &ctx, &cpi));
    ctx.send_transaction(&[Instruction::new_with_bytes(pid, &[17, bump], accts)], &[]);

    let graph = select_u32_graph();
    ctx.enqueue_graph_execution(&graph, &[cond_pk, a_pk, b_pk], &[r_pk]);
    ctx.process_pending();
    ctx.register_ciphertext(&r_pk);
    let r = ctx.decrypt_bytes(&r_pk);
    assert_eq!(read_u32(&r, 0), 100); assert_eq!(read_u32(&r, 1), 200);
}

// ════════════════════════════════════════════════════════════
// EUint8Vector — type coverage E2E
// ════════════════════════════════════════════════════════════

#[test]
fn e2e_u8_add() {
    let mut ctx = EncryptTestContext::new_default();
    let (pid, cpi, bump) = setup(&mut ctx);
    let r = run_binary_e2e(&mut ctx, &pid, &cpi, bump, 20, add_u8_graph, FheType::EVectorU8,
        &make_u8_vec(&[200, 10, 255]), &make_u8_vec(&[100, 5, 1]));
    assert_eq!(r[0], 44); // 300 & 0xFF = 44 (overflow)
    assert_eq!(r[1], 15);
    assert_eq!(r[2], 0); // 256 & 0xFF = 0
}

#[test]
fn e2e_u8_mul_scalar() {
    let mut ctx = EncryptTestContext::new_default();
    let (pid, cpi, bump) = setup(&mut ctx);
    let r = run_unary_e2e(&mut ctx, &pid, &cpi, bump, 21, mul_scalar_u8_graph, FheType::EVectorU8,
        &make_u8_vec(&[5, 10, 100]));
    assert_eq!(r[0], 10); assert_eq!(r[1], 20); assert_eq!(r[2], 200);
}

// ════════════════════════════════════════════════════════════
// EUint64Vector — type coverage E2E
// ════════════════════════════════════════════════════════════

#[test]
fn e2e_u64_add() {
    let mut ctx = EncryptTestContext::new_default();
    let (pid, cpi, bump) = setup(&mut ctx);
    let r = run_binary_e2e(&mut ctx, &pid, &cpi, bump, 30, add_u64_graph, FheType::EVectorU64,
        &make_u64_vec(&[1_000_000, 2_000_000]), &make_u64_vec(&[1, 2]));
    assert_eq!(read_u64(&r, 0), 1_000_001); assert_eq!(read_u64(&r, 1), 2_000_002);
}

#[test]
fn e2e_u64_mul_scalar() {
    let mut ctx = EncryptTestContext::new_default();
    let (pid, cpi, bump) = setup(&mut ctx);
    let r = run_unary_e2e(&mut ctx, &pid, &cpi, bump, 31, mul_scalar_u64_graph, FheType::EVectorU64,
        &make_u64_vec(&[100, 200]));
    assert_eq!(read_u64(&r, 0), 700); assert_eq!(read_u64(&r, 1), 1400);
}

// ════════════════════════════════════════════════════════════
// EUint128Vector — type coverage E2E
// ════════════════════════════════════════════════════════════

#[test]
fn e2e_u128_add() {
    let mut ctx = EncryptTestContext::new_default();
    let (pid, cpi, bump) = setup(&mut ctx);
    let big = u64::MAX as u128 + 1;
    let r = run_binary_e2e(&mut ctx, &pid, &cpi, bump, 40, add_u128_graph, FheType::EVectorU128,
        &make_u128_vec(&[big, 42]), &make_u128_vec(&[1, 0]));
    assert_eq!(read_u128(&r, 0), big + 1); assert_eq!(read_u128(&r, 1), 42);
}

#[test]
fn e2e_u128_mul_scalar() {
    let mut ctx = EncryptTestContext::new_default();
    let (pid, cpi, bump) = setup(&mut ctx);
    let r = run_unary_e2e(&mut ctx, &pid, &cpi, bump, 41, mul_scalar_u128_graph, FheType::EVectorU128,
        &make_u128_vec(&[100, 200]));
    assert_eq!(read_u128(&r, 0), 1100); assert_eq!(read_u128(&r, 1), 2200);
}

// ════════════════════════════════════════════════════════════
// Multi-operation chained graphs — value verification
// ════════════════════════════════════════════════════════════

/// Helper for quad-input ops
fn run_quad_e2e(
    ctx: &mut EncryptTestContext, pid: &Pubkey, cpi: &Pubkey, cpi_bump: u8,
    disc: u8, graph_fn: fn() -> Vec<u8>, fhe_type: FheType,
    a: &[u8], b: &[u8], c: &[u8], d: &[u8],
) -> Vec<u8> {
    let a_pk = ctx.create_input_bytes(fhe_type, a, pid);
    let b_pk = ctx.create_input_bytes(fhe_type, b, pid);
    let c_pk = ctx.create_input_bytes(fhe_type, c, pid);
    let d_pk = ctx.create_input_bytes(fhe_type, d, pid);
    let r_pk = ctx.create_input_bytes(fhe_type, &vec![0u8; fhe_type.byte_width()], pid);
    let mut accts = vec![
        AccountMeta::new(a_pk, false), AccountMeta::new(b_pk, false),
        AccountMeta::new(c_pk, false), AccountMeta::new(d_pk, false),
        AccountMeta::new(r_pk, false),
    ];
    accts.extend(encrypt_accounts(pid, ctx, cpi));
    ctx.send_transaction(&[Instruction::new_with_bytes(*pid, &[disc, cpi_bump], accts)], &[]);
    let graph = graph_fn();
    ctx.enqueue_graph_execution(&graph, &[a_pk, b_pk, c_pk, d_pk], &[r_pk]);
    ctx.process_pending(); ctx.register_ciphertext(&r_pk);
    ctx.decrypt_bytes(&r_pk)
}

/// Helper for ternary-input ops
fn run_ternary_e2e(
    ctx: &mut EncryptTestContext, pid: &Pubkey, cpi: &Pubkey, cpi_bump: u8,
    disc: u8, graph_fn: fn() -> Vec<u8>, fhe_type: FheType,
    a: &[u8], b: &[u8], c: &[u8],
) -> Vec<u8> {
    let a_pk = ctx.create_input_bytes(fhe_type, a, pid);
    let b_pk = ctx.create_input_bytes(fhe_type, b, pid);
    let c_pk = ctx.create_input_bytes(fhe_type, c, pid);
    let r_pk = ctx.create_input_bytes(fhe_type, &vec![0u8; fhe_type.byte_width()], pid);
    let mut accts = vec![
        AccountMeta::new(a_pk, false), AccountMeta::new(b_pk, false),
        AccountMeta::new(c_pk, false), AccountMeta::new(r_pk, false),
    ];
    accts.extend(encrypt_accounts(pid, ctx, cpi));
    ctx.send_transaction(&[Instruction::new_with_bytes(*pid, &[disc, cpi_bump], accts)], &[]);
    let graph = graph_fn();
    ctx.enqueue_graph_execution(&graph, &[a_pk, b_pk, c_pk], &[r_pk]);
    ctx.process_pending(); ctx.register_ciphertext(&r_pk);
    ctx.decrypt_bytes(&r_pk)
}

#[test]
fn e2e_multi_dot2() {
    // (a*b) + (c*d): [10,20]*[2,3] + [1,1]*[5,10] = [20,60]+[5,10] = [25,70]
    let mut ctx = EncryptTestContext::new_default();
    let (pid, cpi, bump) = setup(&mut ctx);
    let r = run_quad_e2e(&mut ctx, &pid, &cpi, bump, 50, dot2_u32_graph, FheType::EVectorU32,
        &make_u32_vec(&[10, 20]), &make_u32_vec(&[2, 3]),
        &make_u32_vec(&[1, 1]), &make_u32_vec(&[5, 10]));
    assert_eq!(read_u32(&r, 0), 25, "(10*2)+(1*5)=25");
    assert_eq!(read_u32(&r, 1), 70, "(20*3)+(1*10)=70");
    assert_eq!(read_u32(&r, 2), 0, "0*0+0*0=0");
}

#[test]
fn e2e_multi_linear() {
    // a*5 + b*3 + 7: [10,20]*5+[1,2]*3+7 = [50,100]+[3,6]+[7,7] = [60,113]
    let mut ctx = EncryptTestContext::new_default();
    let (pid, cpi, bump) = setup(&mut ctx);
    let r = run_binary_e2e(&mut ctx, &pid, &cpi, bump, 51, linear_u32_graph, FheType::EVectorU32,
        &make_u32_vec(&[10, 20]), &make_u32_vec(&[1, 2]));
    assert_eq!(read_u32(&r, 0), 60, "10*5+1*3+7=60");
    assert_eq!(read_u32(&r, 1), 113, "20*5+2*3+7=113");
    assert_eq!(read_u32(&r, 2), 7, "0*5+0*3+7=7");
}

#[test]
fn e2e_multi_mask_sum() {
    // (a & mask) + (b | mask)
    // a=[0xFF,0x0F], b=[0xF0,0x00], mask=[0x0F,0xFF]
    // (0xFF & 0x0F) + (0xF0 | 0x0F) = 0x0F + 0xFF = 0x10E = 270
    // (0x0F & 0xFF) + (0x00 | 0xFF) = 0x0F + 0xFF = 0x10E = 270
    let mut ctx = EncryptTestContext::new_default();
    let (pid, cpi, bump) = setup(&mut ctx);
    let r = run_ternary_e2e(&mut ctx, &pid, &cpi, bump, 52, mask_sum_u32_graph, FheType::EVectorU32,
        &make_u32_vec(&[0xFF, 0x0F]),
        &make_u32_vec(&[0xF0, 0x00]),
        &make_u32_vec(&[0x0F, 0xFF]));
    assert_eq!(read_u32(&r, 0), 0x10E, "(0xFF&0x0F)+(0xF0|0x0F)=270");
    assert_eq!(read_u32(&r, 1), 0x10E, "(0x0F&0xFF)+(0x00|0xFF)=270");
}

#[test]
fn e2e_multi_cond_add_true() {
    // if true { acc + val } else { acc }
    // acc=[100,200], val=[5,10] → [105,210]
    let mut ctx = EncryptTestContext::new_default();
    let (pid, cpi, bump) = setup(&mut ctx);
    let ft = FheType::EVectorU32;
    let cond_pk = ctx.create_input::<Bool>(1, &pid);
    let acc_pk = ctx.create_input_bytes(ft, &make_u32_vec(&[100, 200]), &pid);
    let val_pk = ctx.create_input_bytes(ft, &make_u32_vec(&[5, 10]), &pid);
    let r_pk = ctx.create_input_bytes(ft, &vec![0u8; 8192], &pid);
    let mut accts = vec![
        AccountMeta::new(cond_pk, false), AccountMeta::new(acc_pk, false),
        AccountMeta::new(val_pk, false), AccountMeta::new(r_pk, false),
    ];
    accts.extend(encrypt_accounts(&pid, &ctx, &cpi));
    ctx.send_transaction(&[Instruction::new_with_bytes(pid, &[53, bump], accts)], &[]);
    ctx.enqueue_graph_execution(&cond_add_u32_graph(), &[cond_pk, acc_pk, val_pk], &[r_pk]);
    ctx.process_pending(); ctx.register_ciphertext(&r_pk);
    let r = ctx.decrypt_bytes(&r_pk);
    assert_eq!(read_u32(&r, 0), 105, "if true: 100+5=105");
    assert_eq!(read_u32(&r, 1), 210, "if true: 200+10=210");
}

#[test]
fn e2e_multi_cond_add_false() {
    // if false { acc + val } else { acc }
    // acc=[100,200], val=[5,10] → [100,200] (unchanged)
    let mut ctx = EncryptTestContext::new_default();
    let (pid, cpi, bump) = setup(&mut ctx);
    let ft = FheType::EVectorU32;
    let cond_pk = ctx.create_input::<Bool>(0, &pid);
    let acc_pk = ctx.create_input_bytes(ft, &make_u32_vec(&[100, 200]), &pid);
    let val_pk = ctx.create_input_bytes(ft, &make_u32_vec(&[5, 10]), &pid);
    let r_pk = ctx.create_input_bytes(ft, &vec![0u8; 8192], &pid);
    let mut accts = vec![
        AccountMeta::new(cond_pk, false), AccountMeta::new(acc_pk, false),
        AccountMeta::new(val_pk, false), AccountMeta::new(r_pk, false),
    ];
    accts.extend(encrypt_accounts(&pid, &ctx, &cpi));
    ctx.send_transaction(&[Instruction::new_with_bytes(pid, &[53, bump], accts)], &[]);
    ctx.enqueue_graph_execution(&cond_add_u32_graph(), &[cond_pk, acc_pk, val_pk], &[r_pk]);
    ctx.process_pending(); ctx.register_ciphertext(&r_pk);
    let r = ctx.decrypt_bytes(&r_pk);
    assert_eq!(read_u32(&r, 0), 100, "if false: stays 100");
    assert_eq!(read_u32(&r, 1), 200, "if false: stays 200");
}

#[test]
fn e2e_multi_chain4() {
    // ((a+b)*2 - c) / 2
    // a=[10,20], b=[1,2], c=[4,8]
    // ((11,22)*2 - (4,8)) / 2 = (22,44)-(4,8) = (18,36) / 2 = (9,18)
    let mut ctx = EncryptTestContext::new_default();
    let (pid, cpi, bump) = setup(&mut ctx);
    let r = run_ternary_e2e(&mut ctx, &pid, &cpi, bump, 54, chain4_u32_graph, FheType::EVectorU32,
        &make_u32_vec(&[10, 20]), &make_u32_vec(&[1, 2]), &make_u32_vec(&[4, 8]));
    assert_eq!(read_u32(&r, 0), 9, "((10+1)*2-4)/2=9");
    assert_eq!(read_u32(&r, 1), 18, "((20+2)*2-8)/2=18");
    assert_eq!(read_u32(&r, 2), 0, "((0+0)*2-0)/2=0");
}

#[test]
fn e2e_multi_sum_diff_dual_output() {
    // (a+b, a-b): a=[50,30], b=[10,5] → sum=[60,35], diff=[40,25]
    let mut ctx = EncryptTestContext::new_default();
    let (pid, cpi, bump) = setup(&mut ctx);
    let ft = FheType::EVectorU32;
    let a_pk = ctx.create_input_bytes(ft, &make_u32_vec(&[50, 30]), &pid);
    let b_pk = ctx.create_input_bytes(ft, &make_u32_vec(&[10, 5]), &pid);
    let o0_pk = ctx.create_input_bytes(ft, &vec![0u8; 8192], &pid);
    let o1_pk = ctx.create_input_bytes(ft, &vec![0u8; 8192], &pid);
    let mut accts = vec![
        AccountMeta::new(a_pk, false), AccountMeta::new(b_pk, false),
        AccountMeta::new(o0_pk, false), AccountMeta::new(o1_pk, false),
    ];
    accts.extend(encrypt_accounts(&pid, &ctx, &cpi));
    ctx.send_transaction(&[Instruction::new_with_bytes(pid, &[55, bump], accts)], &[]);
    ctx.enqueue_graph_execution(&sum_diff_u32_graph(), &[a_pk, b_pk], &[o0_pk, o1_pk]);
    ctx.process_pending(); ctx.register_ciphertext(&o0_pk); ctx.register_ciphertext(&o1_pk);
    let sum = ctx.decrypt_bytes(&o0_pk);
    let diff = ctx.decrypt_bytes(&o1_pk);
    assert_eq!(read_u32(&sum, 0), 60, "50+10=60");
    assert_eq!(read_u32(&sum, 1), 35, "30+5=35");
    assert_eq!(read_u32(&diff, 0), 40, "50-10=40");
    assert_eq!(read_u32(&diff, 1), 25, "30-5=25");
}

// ════════════════════════════════════════════════════════════
// Cross-Entry & Reductions — E2E (REFHE refresh)
// ════════════════════════════════════════════════════════════

/// Reduction E2E: vector input → scalar output. The output ciphertext is allocated
/// with the scalar `out_type`, the graph carries the result-type re-tagging.
fn run_reduce_e2e(
    ctx: &mut EncryptTestContext,
    pid: &Pubkey, cpi: &Pubkey, cpi_bump: u8,
    disc: u8,
    graph_fn: fn() -> Vec<u8>,
    in_type: FheType, out_type: FheType,
    a_bytes: &[u8],
) -> Vec<u8> {
    let a_pk = ctx.create_input_bytes(in_type, a_bytes, pid);
    let r_pk = ctx.create_input_bytes(out_type, &vec![0u8; out_type.byte_width()], pid);

    let mut accts = vec![
        AccountMeta::new(a_pk, false),
        AccountMeta::new(r_pk, false),
    ];
    accts.extend(encrypt_accounts(pid, ctx, cpi));

    let ix = Instruction::new_with_bytes(*pid, &[disc, cpi_bump], accts);
    ctx.send_transaction(&[ix], &[]);

    let graph = graph_fn();
    ctx.enqueue_graph_execution(&graph, &[a_pk], &[r_pk]);
    ctx.process_pending();
    ctx.register_ciphertext(&r_pk);
    ctx.decrypt_bytes(&r_pk)
}

#[test]
fn e2e_reduce_add_u32() {
    let mut ctx = EncryptTestContext::new_default();
    let (pid, cpi, bump) = setup(&mut ctx);
    let r = run_reduce_e2e(
        &mut ctx, &pid, &cpi, bump, 70, reduce_add_u32_graph,
        FheType::EVectorU32, FheType::EUint32,
        &make_u32_vec(&[10, 20, 30, 40, 50]),
    );
    let sum = u32::from_le_bytes(r[..4].try_into().unwrap());
    assert_eq!(sum, 150, "reduce_add over [10,20,30,40,50] = 150");
}

#[test]
fn e2e_reduce_min_u32() {
    let mut ctx = EncryptTestContext::new_default();
    let (pid, cpi, bump) = setup(&mut ctx);
    // Reductions span all 2048 entries; fill every slot so unused positions
    // don't dominate the min.
    let mut values = vec![100u32; 2048];
    values[5] = 7;
    values[1000] = 3;
    let r = run_reduce_e2e(
        &mut ctx, &pid, &cpi, bump, 71, reduce_min_u32_graph,
        FheType::EVectorU32, FheType::EUint32,
        &make_u32_vec(&values),
    );
    let min = u32::from_le_bytes(r[..4].try_into().unwrap());
    assert_eq!(min, 3, "reduce_min should find smallest");
}

#[test]
fn e2e_reduce_max_u32() {
    let mut ctx = EncryptTestContext::new_default();
    let (pid, cpi, bump) = setup(&mut ctx);
    let r = run_reduce_e2e(
        &mut ctx, &pid, &cpi, bump, 72, reduce_max_u32_graph,
        FheType::EVectorU32, FheType::EUint32,
        &make_u32_vec(&[1, 5, 999, 42, 7]),
    );
    let max = u32::from_le_bytes(r[..4].try_into().unwrap());
    assert_eq!(max, 999, "reduce_max should find largest");
}

#[test]
fn e2e_reduce_any_finds_nonzero() {
    let mut ctx = EncryptTestContext::new_default();
    let (pid, cpi, bump) = setup(&mut ctx);
    let mut bytes = vec![0u8; 8192];
    bytes[3000] = 1; // single nonzero buried in zeros
    let r = run_reduce_e2e(
        &mut ctx, &pid, &cpi, bump, 73, reduce_any_u8_graph,
        FheType::EVectorU8, FheType::EBool,
        &bytes,
    );
    assert_eq!(r[0], 1, "reduce_any over a vector with any nonzero → 1");
}

#[test]
fn e2e_reduce_any_all_zero() {
    let mut ctx = EncryptTestContext::new_default();
    let (pid, cpi, bump) = setup(&mut ctx);
    let r = run_reduce_e2e(
        &mut ctx, &pid, &cpi, bump, 73, reduce_any_u8_graph,
        FheType::EVectorU8, FheType::EBool,
        &vec![0u8; 8192],
    );
    assert_eq!(r[0], 0, "reduce_any over all-zero vector → 0");
}

#[test]
fn e2e_reduce_all_nonzero() {
    let mut ctx = EncryptTestContext::new_default();
    let (pid, cpi, bump) = setup(&mut ctx);
    let r = run_reduce_e2e(
        &mut ctx, &pid, &cpi, bump, 74, reduce_all_u8_graph,
        FheType::EVectorU8, FheType::EBool,
        &vec![1u8; 8192],
    );
    assert_eq!(r[0], 1, "reduce_all over all-nonzero → 1");
}

#[test]
fn e2e_reduce_all_with_zero() {
    let mut ctx = EncryptTestContext::new_default();
    let (pid, cpi, bump) = setup(&mut ctx);
    let mut bytes = vec![1u8; 8192];
    bytes[42] = 0;
    let r = run_reduce_e2e(
        &mut ctx, &pid, &cpi, bump, 74, reduce_all_u8_graph,
        FheType::EVectorU8, FheType::EBool,
        &bytes,
    );
    assert_eq!(r[0], 0, "reduce_all when one entry is zero → 0");
}

#[test]
fn e2e_rotate_entries_u32() {
    let mut ctx = EncryptTestContext::new_default();
    let (pid, cpi, bump) = setup(&mut ctx);
    let ft = FheType::EVectorU32;
    let a_pk = ctx.create_input_bytes(ft, &make_u32_vec(&[10, 20, 30, 40, 50]), &pid);
    // Rotate amount: 1 entry. Stored as encrypted EUint32 scalar.
    let n_pk = ctx.create_input_bytes(FheType::EUint32, &1u32.to_le_bytes(), &pid);
    let r_pk = ctx.create_input_bytes(ft, &vec![0u8; 8192], &pid);

    let mut accts = vec![
        AccountMeta::new(a_pk, false),
        AccountMeta::new(n_pk, false),
        AccountMeta::new(r_pk, false),
    ];
    accts.extend(encrypt_accounts(&pid, &ctx, &cpi));
    ctx.send_transaction(&[Instruction::new_with_bytes(pid, &[75, bump], accts)], &[]);

    ctx.enqueue_graph_execution(&rotate_entries_u32_graph(), &[a_pk, n_pk], &[r_pk]);
    ctx.process_pending();
    ctx.register_ciphertext(&r_pk);
    let r = ctx.decrypt_bytes(&r_pk);

    // Rotate left by 1 → out[i] = in[i+1]
    assert_eq!(read_u32(&r, 0), 20);
    assert_eq!(read_u32(&r, 1), 30);
    assert_eq!(read_u32(&r, 2), 40);
    assert_eq!(read_u32(&r, 3), 50);
    assert_eq!(read_u32(&r, 4), 0); // wraps to zero region
}

#[test]
fn e2e_range_pipeline() {
    // Composition: max(v) - min(v) — chained reductions through one graph.
    let mut ctx = EncryptTestContext::new_default();
    let (pid, cpi, bump) = setup(&mut ctx);
    let mut values = vec![50u32; 2048];
    values[7] = 99;
    values[300] = 2;
    let r = run_reduce_e2e(
        &mut ctx, &pid, &cpi, bump, 76, range_u32_graph,
        FheType::EVectorU32, FheType::EUint32,
        &make_u32_vec(&values),
    );
    let diff = u32::from_le_bytes(r[..4].try_into().unwrap());
    assert_eq!(diff, 99 - 2, "max - min = 97");
}
