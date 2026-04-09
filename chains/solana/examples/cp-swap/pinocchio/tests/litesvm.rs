// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! LiteSVM tests for CP-Swap with enforced LP positions.

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
    let aif = amount_in * 997; let num = aif * reserve_out;
    let den = (reserve_in * 1000) + aif; let ao = num / den;
    let nri = reserve_in + amount_in; let nro = reserve_out - ao;
    let ok = nri * nro >= reserve_in * reserve_out;
    let sok = ao >= min_amount_out;
    let v = if ok { sok } else { ok };
    let fo = if v { ao } else { amount_in - amount_in };
    let fri = if v { nri } else { reserve_in };
    let fro = if v { nro } else { reserve_out };
    (fo, fri, fro)
}

#[encrypt_fn]
fn add_liquidity_graph(
    ra: EUint128, rb: EUint128, ts: EUint128,
    aa: EUint128, ab: EUint128, ulp: EUint128,
) -> (EUint128, EUint128, EUint128, EUint128) {
    let nra = ra + aa; let nrb = rb + ab;
    let ilp = aa * ab;
    let la = (aa * ts) / (ra + 1); let lb = (ab * ts) / (rb + 1);
    let slp = if la >= lb { lb } else { la };
    let is_sub = ts >= 1;
    let lm = if is_sub { slp } else { ilp };
    let nts = ts + lm; let nulp = ulp + lm;
    (nra, nrb, nts, nulp)
}

#[encrypt_fn]
fn remove_liquidity_graph(
    ra: EUint128, rb: EUint128, ts: EUint128,
    burn: EUint128, ulp: EUint128,
) -> (EUint128, EUint128, EUint128, EUint128, EUint128, EUint128) {
    let suf = ulp >= burn;
    let aa = (ra * burn) / ts; let ab = (rb * burn) / ts;
    let fao = if suf { aa } else { burn - burn };
    let fbo = if suf { ab } else { burn - burn };
    let nra = if suf { ra - aa } else { ra };
    let nrb = if suf { rb - ab } else { rb };
    let nts = if suf { ts - burn } else { ts };
    let nulp = if suf { ulp - burn } else { ulp };
    (fao, fbo, nra, nrb, nts, nulp)
}

const PROG: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../../../target/deploy/cp_swap.so");
const SYS: Pubkey = Pubkey::new_from_array([0u8; 32]);

fn setup(ctx: &mut EncryptTestContext) -> (Pubkey, Pubkey, u8) {
    let pid = ctx.deploy_program(PROG);
    let (auth, bump) = ctx.cpi_authority_for(&pid);
    (pid, auth, bump)
}

fn enc_accounts(ctx: &EncryptTestContext, pid: &Pubkey, auth: &Pubkey) -> Vec<AccountMeta> {
    vec![
        AccountMeta::new_readonly(*ctx.program_id(), false),
        AccountMeta::new(*ctx.config_pda(), false),
        AccountMeta::new(*ctx.deposit_pda(), false),
        AccountMeta::new_readonly(*auth, false),
        AccountMeta::new_readonly(*pid, false),
        AccountMeta::new_readonly(*ctx.network_encryption_key_pda(), false),
        AccountMeta::new(ctx.payer().pubkey(), true),
        AccountMeta::new_readonly(*ctx.event_authority(), false),
        AccountMeta::new_readonly(SYS, false),
    ]
}

struct PoolInfo { pda: Pubkey, ra: Pubkey, rb: Pubkey, ts: Pubkey }

fn mk_pool(ctx: &mut EncryptTestContext, pid: &Pubkey, auth: &Pubkey, bump: u8) -> PoolInfo {
    let ma = Pubkey::new_unique(); let mb = Pubkey::new_unique();
    let (pp, pb) = Pubkey::find_program_address(&[b"cp_pool", ma.as_ref(), mb.as_ref()], pid);
    let ra = Keypair::new(); let rb = Keypair::new(); let ts = Keypair::new();
    let mut keys = vec![
        AccountMeta::new(pp, false), AccountMeta::new_readonly(ma, false),
        AccountMeta::new_readonly(mb, false),
        AccountMeta::new(ra.pubkey(), true), AccountMeta::new(rb.pubkey(), true),
        AccountMeta::new(ts.pubkey(), true),
    ];
    keys.extend(enc_accounts(ctx, pid, auth));
    ctx.send_transaction(&[Instruction::new_with_bytes(*pid, &[0, pb, bump], keys)], &[&ra, &rb, &ts]);
    let p = PoolInfo { pda: pp, ra: ra.pubkey(), rb: rb.pubkey(), ts: ts.pubkey() };
    ctx.register_ciphertext(&p.ra); ctx.register_ciphertext(&p.rb); ctx.register_ciphertext(&p.ts);
    p
}

fn mk_lp(ctx: &mut EncryptTestContext, pid: &Pubkey, auth: &Pubkey, bump: u8,
          pool: &PoolInfo, owner: &Pubkey) -> Pubkey {
    let (lp_pda, lp_bump) = Pubkey::find_program_address(
        &[b"cp_lp", pool.pda.as_ref(), owner.as_ref()], pid);
    let bal_ct = Keypair::new();
    let mut keys = vec![
        AccountMeta::new(lp_pda, false), AccountMeta::new_readonly(pool.pda, false),
        AccountMeta::new_readonly(*owner, false), AccountMeta::new(bal_ct.pubkey(), true),
    ];
    keys.extend(enc_accounts(ctx, pid, auth));
    ctx.send_transaction(&[Instruction::new_with_bytes(*pid, &[5, lp_bump, bump], keys)], &[&bal_ct]);
    ctx.register_ciphertext(&bal_ct.pubkey());
    bal_ct.pubkey()
}

fn add_liq(ctx: &mut EncryptTestContext, pid: &Pubkey, auth: &Pubkey, bump: u8,
           pool: &PoolInfo, user_lp_ct: &Pubkey, a: u128, b: u128) {
    let ac = ctx.create_input::<Uint128>(a, pid);
    let bc = ctx.create_input::<Uint128>(b, pid);
    let mut keys = vec![
        AccountMeta::new_readonly(pool.pda, false),
        AccountMeta::new_readonly(Pubkey::find_program_address(&[b"cp_lp", pool.pda.as_ref(), &[0;32]], pid).0, false), // dummy, we use user_lp_ct directly
        AccountMeta::new(pool.ra, false), AccountMeta::new(pool.rb, false),
        AccountMeta::new(pool.ts, false), AccountMeta::new(ac, false),
        AccountMeta::new(bc, false), AccountMeta::new(*user_lp_ct, false),
    ];
    keys.extend(enc_accounts(ctx, pid, auth));

    // Need proper lp_position account. Let me fix this.
    // Actually the instruction expects: [pool, lp_position, ra, rb, ts, amt_a, amt_b, user_lp_ct, encrypt...]
    // Let me rebuild keys properly.
    drop(keys);

    // Find the lp_position PDA - we need the owner. Since we're using payer as owner:
    let owner = ctx.payer().pubkey();
    let (lp_pda, _) = Pubkey::find_program_address(&[b"cp_lp", pool.pda.as_ref(), owner.as_ref()], pid);
    let mut keys2 = vec![
        AccountMeta::new_readonly(pool.pda, false),
        AccountMeta::new_readonly(lp_pda, false),
        AccountMeta::new(pool.ra, false), AccountMeta::new(pool.rb, false),
        AccountMeta::new(pool.ts, false), AccountMeta::new(ac, false),
        AccountMeta::new(bc, false), AccountMeta::new(*user_lp_ct, false),
    ];
    keys2.extend(enc_accounts(ctx, pid, auth));
    ctx.send_transaction(&[Instruction::new_with_bytes(*pid, &[2, bump], keys2)], &[]);

    let g = add_liquidity_graph();
    ctx.enqueue_graph_execution(&g,
        &[pool.ra, pool.rb, pool.ts, ac, bc, *user_lp_ct],
        &[pool.ra, pool.rb, pool.ts, *user_lp_ct]);
    ctx.process_pending();
    ctx.register_ciphertext(&pool.ra); ctx.register_ciphertext(&pool.rb);
    ctx.register_ciphertext(&pool.ts); ctx.register_ciphertext(user_lp_ct);
}

fn do_swap(ctx: &mut EncryptTestContext, pid: &Pubkey, auth: &Pubkey, bump: u8,
           pool: &PoolInfo, amt: u128, min: u128, dir: u8) -> u128 {
    let (ri, ro) = if dir == 0 { (pool.ra, pool.rb) } else { (pool.rb, pool.ra) };
    let ic = ctx.create_input::<Uint128>(amt, pid);
    let mc = ctx.create_input::<Uint128>(min, pid);
    let oc = ctx.create_input::<Uint128>(0, pid);
    let mut keys = vec![
        AccountMeta::new_readonly(pool.pda, false),
        AccountMeta::new(ri, false), AccountMeta::new(ro, false),
        AccountMeta::new(ic, false), AccountMeta::new(mc, false), AccountMeta::new(oc, false),
    ];
    keys.extend(enc_accounts(ctx, pid, auth));
    ctx.send_transaction(&[Instruction::new_with_bytes(*pid, &[1, bump, dir], keys)], &[]);
    let g = swap_graph();
    ctx.enqueue_graph_execution(&g, &[ri, ro, ic, mc], &[oc, ri, ro]);
    ctx.process_pending();
    ctx.register_ciphertext(&pool.ra); ctx.register_ciphertext(&pool.rb); ctx.register_ciphertext(&oc);
    ctx.decrypt_from_store(&oc)
}

fn rm_liq(ctx: &mut EncryptTestContext, pid: &Pubkey, auth: &Pubkey, bump: u8,
          pool: &PoolInfo, user_lp_ct: &Pubkey, burn: u128) -> (u128, u128) {
    let bc = ctx.create_input::<Uint128>(burn, pid);
    let oa = ctx.create_input::<Uint128>(0, pid);
    let ob = ctx.create_input::<Uint128>(0, pid);
    let owner = ctx.payer().pubkey();
    let (lp_pda, _) = Pubkey::find_program_address(&[b"cp_lp", pool.pda.as_ref(), owner.as_ref()], pid);
    let mut keys = vec![
        AccountMeta::new_readonly(pool.pda, false), AccountMeta::new_readonly(lp_pda, false),
        AccountMeta::new(pool.ra, false), AccountMeta::new(pool.rb, false),
        AccountMeta::new(pool.ts, false), AccountMeta::new(bc, false),
        AccountMeta::new(*user_lp_ct, false),
        AccountMeta::new(oa, false), AccountMeta::new(ob, false),
    ];
    keys.extend(enc_accounts(ctx, pid, auth));
    ctx.send_transaction(&[Instruction::new_with_bytes(*pid, &[4, bump], keys)], &[]);
    let g = remove_liquidity_graph();
    ctx.enqueue_graph_execution(&g,
        &[pool.ra, pool.rb, pool.ts, bc, *user_lp_ct],
        &[oa, ob, pool.ra, pool.rb, pool.ts, *user_lp_ct]);
    ctx.process_pending();
    ctx.register_ciphertext(&pool.ra); ctx.register_ciphertext(&pool.rb);
    ctx.register_ciphertext(&pool.ts); ctx.register_ciphertext(user_lp_ct);
    ctx.register_ciphertext(&oa); ctx.register_ciphertext(&ob);
    (ctx.decrypt_from_store(&oa), ctx.decrypt_from_store(&ob))
}

#[test] fn test_create_pool() {
    let mut ctx = EncryptTestContext::new_default();
    let (pid, auth, bump) = setup(&mut ctx);
    let pool = mk_pool(&mut ctx, &pid, &auth, bump);
    assert_eq!(ctx.decrypt_from_store(&pool.ra), 0);
    assert_eq!(ctx.decrypt_from_store(&pool.ts), 0);
}

#[test] fn test_add_and_remove() {
    let mut ctx = EncryptTestContext::new_default();
    let (pid, auth, bump) = setup(&mut ctx);
    let pool = mk_pool(&mut ctx, &pid, &auth, bump);
    let payer_pk = ctx.payer().pubkey();
    let lp_ct = mk_lp(&mut ctx, &pid, &auth, bump, &pool, &payer_pk);

    add_liq(&mut ctx, &pid, &auth, bump, &pool, &lp_ct, 10000, 20000);
    assert_eq!(ctx.decrypt_from_store(&pool.ra), 10000);
    assert_eq!(ctx.decrypt_from_store(&pool.rb), 20000);
    let user_lp = ctx.decrypt_from_store(&lp_ct);
    assert!(user_lp > 0, "got LP tokens");

    // Remove half
    let (a, b) = rm_liq(&mut ctx, &pid, &auth, bump, &pool, &lp_ct, user_lp / 2);
    assert_eq!(a, 5000); assert_eq!(b, 10000);
    assert_eq!(ctx.decrypt_from_store(&lp_ct), user_lp - user_lp / 2);
}

#[test] fn test_remove_more_than_owned() {
    let mut ctx = EncryptTestContext::new_default();
    let (pid, auth, bump) = setup(&mut ctx);
    let pool = mk_pool(&mut ctx, &pid, &auth, bump);
    let payer_pk = ctx.payer().pubkey();
    let lp_ct = mk_lp(&mut ctx, &pid, &auth, bump, &pool, &payer_pk);

    add_liq(&mut ctx, &pid, &auth, bump, &pool, &lp_ct, 10000, 10000);
    let user_lp = ctx.decrypt_from_store(&lp_ct);

    // Try to burn 2x what we have → no-op
    let (a, b) = rm_liq(&mut ctx, &pid, &auth, bump, &pool, &lp_ct, user_lp * 2);
    assert_eq!(a, 0, "no-op: no withdrawal");
    assert_eq!(b, 0);
    assert_eq!(ctx.decrypt_from_store(&pool.ra), 10000, "reserves unchanged");
    assert_eq!(ctx.decrypt_from_store(&lp_ct), user_lp, "LP unchanged");
}

#[test] fn test_swap_then_remove_earns_fees() {
    let mut ctx = EncryptTestContext::new_default();
    let (pid, auth, bump) = setup(&mut ctx);
    let pool = mk_pool(&mut ctx, &pid, &auth, bump);
    let payer_pk = ctx.payer().pubkey();
    let lp_ct = mk_lp(&mut ctx, &pid, &auth, bump, &pool, &payer_pk);

    add_liq(&mut ctx, &pid, &auth, bump, &pool, &lp_ct, 10000, 10000);
    let lp_amount = ctx.decrypt_from_store(&lp_ct);

    // Swap back and forth to accumulate fees
    for _ in 0..3 {
        do_swap(&mut ctx, &pid, &auth, bump, &pool, 1000, 0, 0);
        do_swap(&mut ctx, &pid, &auth, bump, &pool, 1000, 0, 1);
    }

    let (a, b) = rm_liq(&mut ctx, &pid, &auth, bump, &pool, &lp_ct, lp_amount);
    assert!(a + b > 20000, "LP earned fees: {} + {} > 20000", a, b);
}

#[test] fn test_swap_k_invariant() {
    let mut ctx = EncryptTestContext::new_default();
    let (pid, auth, bump) = setup(&mut ctx);
    let pool = mk_pool(&mut ctx, &pid, &auth, bump);
    let payer_pk = ctx.payer().pubkey();
    let lp_ct = mk_lp(&mut ctx, &pid, &auth, bump, &pool, &payer_pk);

    add_liq(&mut ctx, &pid, &auth, bump, &pool, &lp_ct, 10000, 10000);
    let out = do_swap(&mut ctx, &pid, &auth, bump, &pool, 1000, 0, 0);
    assert!(out > 0);
    let ra = ctx.decrypt_from_store(&pool.ra);
    let rb = ctx.decrypt_from_store(&pool.rb);
    assert!(ra * rb >= 10000 * 10000, "k invariant");
}
