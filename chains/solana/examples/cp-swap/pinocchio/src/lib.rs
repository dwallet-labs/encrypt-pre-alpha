// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#![allow(unexpected_cfgs)]

/// CP-Swap — Confidential UniV2 AMM built on Encrypt FHE.
///
/// LP ownership is enforced in FHE: each user has an LpPosition account
/// with an encrypted LP balance. AddLiquidity atomically updates reserves,
/// total supply, AND the user's LP balance in a single FHE graph.
/// RemoveLiquidity checks `user_lp >= burn_amount` in FHE — if
/// insufficient, the entire operation is a no-op.
///
/// ## Instructions
///
/// 0. CreatePool — create pool with reserves + LP supply
/// 1. Swap — constant product with 0.3% fee + slippage check
/// 2. AddLiquidity — deposit tokens, mint LP to user (FHE enforced)
/// 3. RequestDecrypt — decrypt any pool-owned ciphertext
/// 4. RemoveLiquidity — burn LP, withdraw proportional reserves (FHE enforced)
/// 5. CreateLpPosition — create user's LP position account
use encrypt_dsl::prelude::encrypt_fn;
use encrypt_pinocchio::EncryptContext;
use encrypt_types::encrypted::{EUint128, Uint128};
use pinocchio::{
    cpi::{Seed, Signer},
    entrypoint,
    error::ProgramError,
    AccountView, Address, ProgramResult,
};
use pinocchio_system::instructions::CreateAccount;

entrypoint!(process_instruction);

pub const ID: Address = Address::new_from_array([6u8; 32]);

// ── Account layouts ──

/// Pool state — PDA: `["cp_pool", mint_a, mint_b]`
/// Pool state — PDA: `["cp_pool", mint_a, mint_b]`
///
/// `price_ct` is a PUBLIC ciphertext (authorized = [0; 32]).
/// Anyone can read the price off-chain via gRPC `readCiphertext`.
/// Reserves, LP supply, and individual positions stay encrypted.
#[repr(C)]
pub struct Pool {
    pub mint_a: [u8; 32],
    pub mint_b: [u8; 32],
    pub reserve_a: [u8; 32],     // encrypted reserve A ciphertext
    pub reserve_b: [u8; 32],     // encrypted reserve B ciphertext
    pub total_supply: [u8; 32],  // encrypted LP total supply ciphertext
    pub price_ct: [u8; 32],      // PUBLIC ciphertext: B per A (6 decimal precision)
    pub is_initialized: u8,
    pub bump: u8,
}

impl Pool {
    pub const LEN: usize = core::mem::size_of::<Self>();
    pub fn from_bytes(d: &[u8]) -> Result<&Self, ProgramError> {
        if d.len() < Self::LEN { return Err(ProgramError::InvalidAccountData); }
        Ok(unsafe { &*(d.as_ptr() as *const Self) })
    }
    pub fn from_bytes_mut(d: &mut [u8]) -> Result<&mut Self, ProgramError> {
        if d.len() < Self::LEN { return Err(ProgramError::InvalidAccountData); }
        Ok(unsafe { &mut *(d.as_mut_ptr() as *mut Self) })
    }
}

/// LP position — PDA: `["cp_lp", pool, owner]`
/// Stores the user's encrypted LP token balance.
#[repr(C)]
pub struct LpPosition {
    pub pool: [u8; 32],
    pub owner: [u8; 32],
    pub balance: [u8; 32],  // encrypted LP balance ciphertext
    pub bump: u8,
}

impl LpPosition {
    pub const LEN: usize = core::mem::size_of::<Self>();
    pub fn from_bytes(d: &[u8]) -> Result<&Self, ProgramError> {
        if d.len() < Self::LEN { return Err(ProgramError::InvalidAccountData); }
        Ok(unsafe { &*(d.as_ptr() as *const Self) })
    }
    pub fn from_bytes_mut(d: &mut [u8]) -> Result<&mut Self, ProgramError> {
        if d.len() < Self::LEN { return Err(ProgramError::InvalidAccountData); }
        Ok(unsafe { &mut *(d.as_mut_ptr() as *mut Self) })
    }
}

fn minimum_balance(s: usize) -> u64 { (s as u64 + 128) * 6960 }

// ── FHE Graphs ──

/// Swap: x * y = k, 0.3% fee, slippage check. No-op if invalid.
/// Outputs the new price (B per A, 6 decimal precision) as a public ciphertext.
#[encrypt_fn]
fn swap_graph(
    reserve_in: EUint128, reserve_out: EUint128,
    amount_in: EUint128, min_amount_out: EUint128,
    current_price: EUint128,
) -> (EUint128, EUint128, EUint128, EUint128) {
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
    // Price: B per A with 6 decimal precision. On no-op, keep current price.
    let new_price = (final_reserve_out * 1_000_000) / (final_reserve_in + 1);
    let final_price = if valid { new_price } else { current_price };
    (final_out, final_reserve_in, final_reserve_out, final_price)
}

/// Add liquidity: updates reserves, total supply, AND user's LP balance atomically.
/// First deposit: lp = amount_a * amount_b. Subsequent: proportional.
#[encrypt_fn]
fn add_liquidity_graph(
    reserve_a: EUint128, reserve_b: EUint128,
    total_supply: EUint128,
    amount_a: EUint128, amount_b: EUint128,
    user_lp: EUint128,
) -> (EUint128, EUint128, EUint128, EUint128) {
    let new_reserve_a = reserve_a + amount_a;
    let new_reserve_b = reserve_b + amount_b;

    // First deposit: LP = amount_a * amount_b
    let initial_lp = amount_a * amount_b;
    // Subsequent: LP = min(a * supply / (ra+1), b * supply / (rb+1))
    let lp_from_a = (amount_a * total_supply) / (reserve_a + 1);
    let lp_from_b = (amount_b * total_supply) / (reserve_b + 1);
    let subsequent_lp = if lp_from_a >= lp_from_b { lp_from_b } else { lp_from_a };

    let is_subsequent = total_supply >= 1;
    let lp_to_mint = if is_subsequent { subsequent_lp } else { initial_lp };

    let new_total_supply = total_supply + lp_to_mint;
    let new_user_lp = user_lp + lp_to_mint;

    (new_reserve_a, new_reserve_b, new_total_supply, new_user_lp)
}

/// Remove liquidity: checks user_lp >= burn_amount in FHE.
/// If insufficient LP, entire operation is a no-op.
#[encrypt_fn]
fn remove_liquidity_graph(
    reserve_a: EUint128, reserve_b: EUint128,
    total_supply: EUint128,
    burn_amount: EUint128,
    user_lp: EUint128,
) -> (EUint128, EUint128, EUint128, EUint128, EUint128, EUint128) {
    let sufficient = user_lp >= burn_amount;

    let amount_a = (reserve_a * burn_amount) / total_supply;
    let amount_b = (reserve_b * burn_amount) / total_supply;

    // If sufficient → apply removal. Else → no-op.
    let final_a_out = if sufficient { amount_a } else { burn_amount - burn_amount };
    let final_b_out = if sufficient { amount_b } else { burn_amount - burn_amount };
    let new_ra = if sufficient { reserve_a - amount_a } else { reserve_a };
    let new_rb = if sufficient { reserve_b - amount_b } else { reserve_b };
    let new_supply = if sufficient { total_supply - burn_amount } else { total_supply };
    let new_user_lp = if sufficient { user_lp - burn_amount } else { user_lp };

    (final_a_out, final_b_out, new_ra, new_rb, new_supply, new_user_lp)
}

// ── Dispatch ──

fn process_instruction(
    program_id: &Address, accounts: &[AccountView], data: &[u8],
) -> ProgramResult {
    match data.split_first() {
        Some((&0, rest)) => create_pool(program_id, accounts, rest),
        Some((&1, rest)) => swap(accounts, rest),
        Some((&2, rest)) => add_liquidity(accounts, rest),
        Some((&4, rest)) => remove_liquidity(accounts, rest),
        Some((&5, rest)) => create_lp_position(program_id, accounts, rest),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

// ── 0: CreatePool ──

fn create_pool(
    program_id: &Address, accounts: &[AccountView], data: &[u8],
) -> ProgramResult {
    let [pool_acct, mint_a, mint_b, ra_ct, rb_ct, ts_ct, price_ct, encrypt_program, config, deposit, cpi_authority, caller_program, network_encryption_key, payer, event_authority, system_program, ..] =
        accounts
    else { return Err(ProgramError::NotEnoughAccountKeys); };
    if !payer.is_signer() { return Err(ProgramError::MissingRequiredSignature); }
    if data.len() < 2 { return Err(ProgramError::InvalidInstructionData); }

    let (pool_bump, cpi_bump) = (data[0], data[1]);

    let bump_byte = [pool_bump];
    let seeds = [Seed::from(b"cp_pool" as &[u8]), Seed::from(mint_a.address().as_ref()),
        Seed::from(mint_b.address().as_ref()), Seed::from(&bump_byte)];
    CreateAccount { from: payer, to: pool_acct, lamports: minimum_balance(Pool::LEN),
        space: Pool::LEN as u64, owner: program_id }.invoke_signed(&[Signer::from(&seeds)])?;

    let ctx = EncryptContext { encrypt_program, config, deposit, cpi_authority, caller_program,
        network_encryption_key, payer, event_authority, system_program, cpi_authority_bump: cpi_bump };
    ctx.create_plaintext_typed::<Uint128>(&0u128, ra_ct)?;
    ctx.create_plaintext_typed::<Uint128>(&0u128, rb_ct)?;
    ctx.create_plaintext_typed::<Uint128>(&0u128, ts_ct)?;
    ctx.create_plaintext_typed::<Uint128>(&0u128, price_ct)?;
    // Make price ciphertext public — anyone can read it off-chain
    ctx.make_public(price_ct)?;

    let d = unsafe { pool_acct.borrow_unchecked_mut() };
    let pool = Pool::from_bytes_mut(d)?;
    pool.mint_a.copy_from_slice(mint_a.address().as_ref());
    pool.mint_b.copy_from_slice(mint_b.address().as_ref());
    pool.reserve_a.copy_from_slice(ra_ct.address().as_ref());
    pool.reserve_b.copy_from_slice(rb_ct.address().as_ref());
    pool.total_supply.copy_from_slice(ts_ct.address().as_ref());
    pool.price_ct.copy_from_slice(price_ct.address().as_ref());
    pool.is_initialized = 1;
    pool.bump = pool_bump;
    Ok(())
}

// ── 5: CreateLpPosition ──

fn create_lp_position(
    program_id: &Address, accounts: &[AccountView], data: &[u8],
) -> ProgramResult {
    let [lp_acct, pool_acct, owner, balance_ct, encrypt_program, config, deposit, cpi_authority, caller_program, network_encryption_key, payer, event_authority, system_program, ..] =
        accounts
    else { return Err(ProgramError::NotEnoughAccountKeys); };
    if !payer.is_signer() { return Err(ProgramError::MissingRequiredSignature); }
    if data.len() < 2 { return Err(ProgramError::InvalidInstructionData); }

    let (lp_bump, cpi_bump) = (data[0], data[1]);

    // Verify pool
    let pd = unsafe { pool_acct.borrow_unchecked() };
    let pool = Pool::from_bytes(pd)?;
    if pool.is_initialized != 1 { return Err(ProgramError::UninitializedAccount); }

    let bump_byte = [lp_bump];
    let seeds = [Seed::from(b"cp_lp" as &[u8]), Seed::from(pool_acct.address().as_ref()),
        Seed::from(owner.address().as_ref()), Seed::from(&bump_byte)];
    CreateAccount { from: payer, to: lp_acct, lamports: minimum_balance(LpPosition::LEN),
        space: LpPosition::LEN as u64, owner: program_id }.invoke_signed(&[Signer::from(&seeds)])?;

    let ctx = EncryptContext { encrypt_program, config, deposit, cpi_authority, caller_program,
        network_encryption_key, payer, event_authority, system_program, cpi_authority_bump: cpi_bump };
    ctx.create_plaintext_typed::<Uint128>(&0u128, balance_ct)?;

    let d = unsafe { lp_acct.borrow_unchecked_mut() };
    let lp = LpPosition::from_bytes_mut(d)?;
    lp.pool.copy_from_slice(pool_acct.address().as_ref());
    lp.owner.copy_from_slice(owner.address().as_ref());
    lp.balance.copy_from_slice(balance_ct.address().as_ref());
    lp.bump = lp_bump;
    Ok(())
}

// ── 1: Swap ──

fn swap(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [pool_acct, rin_ct, rout_ct, amt_in_ct, min_out_ct, amt_out_ct, price_ct, encrypt_program, config, deposit, cpi_authority, caller_program, network_encryption_key, payer, event_authority, system_program, ..] =
        accounts
    else { return Err(ProgramError::NotEnoughAccountKeys); };
    if !payer.is_signer() { return Err(ProgramError::MissingRequiredSignature); }
    if data.len() < 2 { return Err(ProgramError::InvalidInstructionData); }
    let (cpi_bump, direction) = (data[0], data[1]);

    let pd = unsafe { pool_acct.borrow_unchecked() };
    let pool = Pool::from_bytes(pd)?;
    if pool.is_initialized != 1 { return Err(ProgramError::UninitializedAccount); }
    let (ein, eout) = if direction == 0 { (&pool.reserve_a, &pool.reserve_b) }
        else { (&pool.reserve_b, &pool.reserve_a) };
    if rin_ct.address().as_ref() != ein { return Err(ProgramError::InvalidArgument); }
    if rout_ct.address().as_ref() != eout { return Err(ProgramError::InvalidArgument); }
    if price_ct.address().as_ref() != &pool.price_ct { return Err(ProgramError::InvalidArgument); }

    let ctx = EncryptContext { encrypt_program, config, deposit, cpi_authority, caller_program,
        network_encryption_key, payer, event_authority, system_program, cpi_authority_bump: cpi_bump };
    // swap_graph now takes current_price as input and outputs new_price
    ctx.swap_graph(rin_ct, rout_ct, amt_in_ct, min_out_ct, price_ct,
        amt_out_ct, rin_ct, rout_ct, price_ct)?;
    Ok(())
}

// ── 2: AddLiquidity ──
// accounts: [pool, lp_position, reserve_a_ct(w), reserve_b_ct(w),
//            total_supply_ct(w), amount_a_ct, amount_b_ct, user_lp_ct(w),
//            encrypt accounts...]

fn add_liquidity(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [pool_acct, lp_pos_acct, ra_ct, rb_ct, ts_ct, amt_a_ct, amt_b_ct, user_lp_ct, encrypt_program, config, deposit, cpi_authority, caller_program, network_encryption_key, payer, event_authority, system_program, ..] =
        accounts
    else { return Err(ProgramError::NotEnoughAccountKeys); };
    if !payer.is_signer() { return Err(ProgramError::MissingRequiredSignature); }
    if data.is_empty() { return Err(ProgramError::InvalidInstructionData); }
    let cpi_bump = data[0];

    let pd = unsafe { pool_acct.borrow_unchecked() };
    let pool = Pool::from_bytes(pd)?;
    if pool.is_initialized != 1 { return Err(ProgramError::UninitializedAccount); }
    if ra_ct.address().as_ref() != &pool.reserve_a { return Err(ProgramError::InvalidArgument); }
    if rb_ct.address().as_ref() != &pool.reserve_b { return Err(ProgramError::InvalidArgument); }
    if ts_ct.address().as_ref() != &pool.total_supply { return Err(ProgramError::InvalidArgument); }

    // Verify LP position: must belong to this pool AND to the payer
    let lpd = unsafe { lp_pos_acct.borrow_unchecked() };
    let lp_pos = LpPosition::from_bytes(lpd)?;
    if &lp_pos.pool != pool_acct.address().as_array() { return Err(ProgramError::InvalidArgument); }
    if &lp_pos.owner != payer.address().as_array() { return Err(ProgramError::InvalidArgument); }
    if user_lp_ct.address().as_ref() != &lp_pos.balance { return Err(ProgramError::InvalidArgument); }

    let ctx = EncryptContext { encrypt_program, config, deposit, cpi_authority, caller_program,
        network_encryption_key, payer, event_authority, system_program, cpi_authority_bump: cpi_bump };

    // (new_ra, new_rb, new_supply, new_user_lp)
    ctx.add_liquidity_graph(
        ra_ct, rb_ct, ts_ct, amt_a_ct, amt_b_ct, user_lp_ct,
        ra_ct, rb_ct, ts_ct, user_lp_ct,
    )?;
    Ok(())
}

// ── 4: RemoveLiquidity ──
// accounts: [pool, lp_position, reserve_a_ct(w), reserve_b_ct(w),
//            total_supply_ct(w), burn_amount_ct, user_lp_ct(w),
//            amount_a_out_ct(w), amount_b_out_ct(w),
//            encrypt accounts...]

fn remove_liquidity(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [pool_acct, lp_pos_acct, ra_ct, rb_ct, ts_ct, burn_ct, user_lp_ct, out_a_ct, out_b_ct, encrypt_program, config, deposit, cpi_authority, caller_program, network_encryption_key, payer, event_authority, system_program, ..] =
        accounts
    else { return Err(ProgramError::NotEnoughAccountKeys); };
    if !payer.is_signer() { return Err(ProgramError::MissingRequiredSignature); }
    if data.is_empty() { return Err(ProgramError::InvalidInstructionData); }
    let cpi_bump = data[0];

    let pd = unsafe { pool_acct.borrow_unchecked() };
    let pool = Pool::from_bytes(pd)?;
    if pool.is_initialized != 1 { return Err(ProgramError::UninitializedAccount); }
    if ra_ct.address().as_ref() != &pool.reserve_a { return Err(ProgramError::InvalidArgument); }
    if rb_ct.address().as_ref() != &pool.reserve_b { return Err(ProgramError::InvalidArgument); }
    if ts_ct.address().as_ref() != &pool.total_supply { return Err(ProgramError::InvalidArgument); }

    let lpd = unsafe { lp_pos_acct.borrow_unchecked() };
    let lp_pos = LpPosition::from_bytes(lpd)?;
    if &lp_pos.pool != pool_acct.address().as_array() { return Err(ProgramError::InvalidArgument); }
    if &lp_pos.owner != payer.address().as_array() { return Err(ProgramError::InvalidArgument); }
    if user_lp_ct.address().as_ref() != &lp_pos.balance { return Err(ProgramError::InvalidArgument); }

    let ctx = EncryptContext { encrypt_program, config, deposit, cpi_authority, caller_program,
        network_encryption_key, payer, event_authority, system_program, cpi_authority_bump: cpi_bump };

    // (a_out, b_out, new_ra, new_rb, new_supply, new_user_lp)
    ctx.remove_liquidity_graph(
        ra_ct, rb_ct, ts_ct, burn_ct, user_lp_ct,
        out_a_ct, out_b_ct, ra_ct, rb_ct, ts_ct, user_lp_ct,
    )?;
    Ok(())
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use encrypt_types::graph::{get_node, parse_graph, GraphNodeKind};
    use encrypt_types::identifier::*;
    use encrypt_types::types::FheType;
    use super::{add_liquidity_graph, remove_liquidity_graph, swap_graph};

    fn run_mock(graph_fn: fn() -> Vec<u8>, inputs: &[u128], fhe_types: &[FheType]) -> Vec<u128> {
        let data = graph_fn();
        let pg = parse_graph(&data).unwrap();
        let num = pg.header().num_nodes() as usize;
        let mut digests: Vec<[u8; 32]> = Vec::with_capacity(num);
        let mut inp = 0usize;
        for i in 0..num {
            let n = get_node(pg.node_bytes(), i as u16).unwrap();
            let ft = FheType::from_u8(n.fhe_type()).unwrap_or(FheType::EUint128);
            let d = match n.kind() {
                k if k == GraphNodeKind::Input as u8 => {
                    let v = inputs[inp]; let t = fhe_types[inp]; inp += 1;
                    encode_mock_digest(t, v)
                }
                k if k == GraphNodeKind::Constant as u8 => {
                    let bw = ft.byte_width().min(16);
                    let off = n.const_offset() as usize;
                    let mut buf = [0u8; 16];
                    buf[..bw].copy_from_slice(&pg.constants()[off..off + bw]);
                    encode_mock_digest(ft, u128::from_le_bytes(buf))
                }
                k if k == GraphNodeKind::Op as u8 => {
                    let (a, b, c) = (n.input_a() as usize, n.input_b() as usize, n.input_c() as usize);
                    if n.op_type() == 60 { mock_select(&digests[a], &digests[b], &digests[c]) }
                    else if b == 0xFFFF {
                        mock_unary_compute(unsafe { core::mem::transmute(n.op_type()) }, &digests[a], ft)
                    } else {
                        mock_binary_compute(unsafe { core::mem::transmute(n.op_type()) }, &digests[a], &digests[b], ft)
                    }
                }
                k if k == GraphNodeKind::Output as u8 => digests[n.input_a() as usize],
                _ => panic!("bad node"),
            };
            digests.push(d);
        }
        (0..num).filter(|&i| get_node(pg.node_bytes(), i as u16).unwrap().kind() == GraphNodeKind::Output as u8)
            .map(|i| decode_mock_identifier(&digests[i])).collect()
    }

    const T: FheType = FheType::EUint128;

    // ── Swap ──
    #[test] fn swap_basic() {
        // inputs: reserve_in, reserve_out, amount_in, min_out, current_price
        let r = run_mock(swap_graph, &[1000, 2000, 100, 0, 2_000_000], &[T,T,T,T,T]);
        assert!(r[0] > 0); assert_eq!(r[1], 1100); assert!(r[1]*r[2] >= 1000*2000);
        assert!(r[3] > 0, "price output should be non-zero");
    }
    #[test] fn swap_slippage() {
        let r = run_mock(swap_graph, &[1000, 2000, 100, 999, 2_000_000], &[T,T,T,T,T]);
        assert_eq!(r[0], 0); assert_eq!(r[1], 1000); assert_eq!(r[2], 2000);
        assert_eq!(r[3], 2_000_000, "price unchanged on no-op");
    }
    #[test] fn swap_k_preserved() {
        let mut ra = 100_000u128; let mut rb = 100_000u128; let ik = ra*rb;
        let mut price = 1_000_000u128;
        for (i, &a) in [500,300,1000,2000,100].iter().enumerate() {
            let (ri,ro) = if i%2==0 {(ra,rb)} else {(rb,ra)};
            let r = run_mock(swap_graph, &[ri,ro,a,0,price], &[T,T,T,T,T]);
            if i%2==0 { ra=r[1]; rb=r[2]; } else { rb=r[1]; ra=r[2]; }
            price = r[3];
        }
        assert!(ra*rb >= ik);
    }

    // ── Add liquidity with LP tracking ──
    #[test] fn add_liq_first() {
        // reserve_a=0, reserve_b=0, supply=0, amt_a=1000, amt_b=2000, user_lp=0
        let r = run_mock(add_liquidity_graph, &[0,0,0,1000,2000,0], &[T,T,T,T,T,T]);
        assert_eq!(r[0], 1000); assert_eq!(r[1], 2000);
        assert_eq!(r[2], 1000*2000, "new supply = a*b");
        assert_eq!(r[3], 1000*2000, "user LP = minted");
    }
    #[test] fn add_liq_second_deposit() {
        let supply = 2_000_000u128;
        let r = run_mock(add_liquidity_graph, &[1000, 2000, supply, 500, 1000, 0], &[T,T,T,T,T,T]);
        assert_eq!(r[0], 1500); assert_eq!(r[1], 3000);
        assert!(r[2] > supply, "supply increased");
        assert!(r[3] > 0, "user got LP");
    }

    // ── Remove liquidity with enforcement ──
    #[test] fn remove_liq_sufficient() {
        let supply = 100u128;
        // user has 50 LP, burns 50
        let r = run_mock(remove_liquidity_graph, &[10000, 20000, supply, 50, 50], &[T,T,T,T,T]);
        assert_eq!(r[0], 5000, "50% of A"); assert_eq!(r[1], 10000, "50% of B");
        assert_eq!(r[2], 5000); assert_eq!(r[3], 10000);
        assert_eq!(r[4], 50, "remaining supply");
        assert_eq!(r[5], 0, "user LP = 0");
    }
    #[test] fn remove_liq_insufficient() {
        // user has 30 LP, tries to burn 50 → no-op
        let r = run_mock(remove_liquidity_graph, &[10000, 20000, 100, 50, 30], &[T,T,T,T,T]);
        assert_eq!(r[0], 0, "no withdrawal A");
        assert_eq!(r[1], 0, "no withdrawal B");
        assert_eq!(r[2], 10000, "reserve A unchanged");
        assert_eq!(r[3], 20000, "reserve B unchanged");
        assert_eq!(r[4], 100, "supply unchanged");
        assert_eq!(r[5], 30, "user LP unchanged");
    }
    #[test] fn remove_liq_full() {
        let r = run_mock(remove_liquidity_graph, &[5000, 8000, 100, 100, 100], &[T,T,T,T,T]);
        assert_eq!(r[0], 5000); assert_eq!(r[1], 8000);
        assert_eq!(r[2], 0); assert_eq!(r[3], 0); assert_eq!(r[4], 0); assert_eq!(r[5], 0);
    }

    // ── Graph shapes ──
    #[test] fn graph_shapes() {
        let g = swap_graph(); let pg = parse_graph(&g).unwrap();
        assert_eq!(pg.header().num_inputs(), 5); assert_eq!(pg.header().num_outputs(), 4);
        let g = add_liquidity_graph(); let pg = parse_graph(&g).unwrap();
        assert_eq!(pg.header().num_inputs(), 6); assert_eq!(pg.header().num_outputs(), 4);
        let g = remove_liquidity_graph(); let pg = parse_graph(&g).unwrap();
        assert_eq!(pg.header().num_inputs(), 5); assert_eq!(pg.header().num_outputs(), 6);
    }
}
