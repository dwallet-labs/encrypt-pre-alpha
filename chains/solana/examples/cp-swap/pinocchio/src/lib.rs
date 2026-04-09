// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#![allow(unexpected_cfgs)]

/// CP-Swap — Confidential UniV2 AMM built on Encrypt FHE.
///
/// All reserves, swap amounts, and LP positions are encrypted.
/// LP shares are tracked via an encrypted `total_supply` ciphertext —
/// add_liquidity mints proportional LP tokens, remove_liquidity burns
/// them to withdraw reserves. Nobody can see TVL, trade sizes, or
/// individual LP positions.
///
/// ## Instructions
///
/// 0. `CreatePool` — create pool with two token reserves + LP supply
/// 1. `Swap` — constant product swap with 0.3% fee + slippage protection
/// 2. `AddLiquidity` — deposit both tokens, receive proportional LP shares
/// 3. `RequestDecrypt` — decrypt any ciphertext owned by the pool
/// 4. `RemoveLiquidity` — burn LP shares, withdraw proportional reserves
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

// ── Account layout ──

/// Pool state — PDA seeds: `["cp_pool", mint_a, mint_b]`
#[repr(C)]
pub struct Pool {
    pub mint_a: [u8; 32],         // token A identifier
    pub mint_b: [u8; 32],         // token B identifier
    pub reserve_a: [u8; 32],      // encrypted reserve A ciphertext pubkey
    pub reserve_b: [u8; 32],      // encrypted reserve B ciphertext pubkey
    pub total_supply: [u8; 32],   // encrypted LP total supply ciphertext pubkey
    pub is_initialized: u8,
    pub bump: u8,
}

impl Pool {
    pub const LEN: usize = core::mem::size_of::<Self>();

    pub fn from_bytes(data: &[u8]) -> Result<&Self, ProgramError> {
        if data.len() < Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(unsafe { &*(data.as_ptr() as *const Self) })
    }

    pub fn from_bytes_mut(data: &mut [u8]) -> Result<&mut Self, ProgramError> {
        if data.len() < Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(unsafe { &mut *(data.as_mut_ptr() as *mut Self) })
    }
}

fn minimum_balance(size: usize) -> u64 {
    (size as u64 + 128) * 6960
}

// ── FHE Graphs ──

/// Swap: x * y = k with 0.3% fee.
/// Self-settling — if slippage or k-check fails, reserves unchanged (no-op).
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

/// Add liquidity: deposit tokens, compute LP shares to mint.
///
/// For the first deposit (total_supply == 0), LP = amount_a * amount_b
/// (simplified from sqrt — avoids needing sqrt in FHE).
/// For subsequent deposits: LP = min(a * supply / ra, b * supply / rb).
///
/// Since we can't branch on `total_supply == 0` in FHE (it's encrypted),
/// we compute BOTH formulas and select based on whether total_supply > 0.
///
/// Returns (new_reserve_a, new_reserve_b, lp_to_mint, new_total_supply).
#[encrypt_fn]
fn add_liquidity_graph(
    reserve_a: EUint128,
    reserve_b: EUint128,
    total_supply: EUint128,
    amount_a: EUint128,
    amount_b: EUint128,
) -> (EUint128, EUint128, EUint128, EUint128) {
    let new_reserve_a = reserve_a + amount_a;
    let new_reserve_b = reserve_b + amount_b;

    // First deposit: LP = amount_a * amount_b (proxy for sqrt(a*b))
    let initial_lp = amount_a * amount_b;

    // Subsequent: LP = min(amount_a * supply / reserve_a, amount_b * supply / reserve_b)
    // Use reserve + 1 to avoid division by zero when reserves are 0
    let lp_from_a = (amount_a * total_supply) / (reserve_a + 1);
    let lp_from_b = (amount_b * total_supply) / (reserve_b + 1);
    let subsequent_lp = if lp_from_a >= lp_from_b { lp_from_b } else { lp_from_a };

    // Select: if total_supply > 0 → subsequent, else → initial
    let is_first = total_supply >= 1;
    let lp_to_mint = if is_first { subsequent_lp } else { initial_lp };

    let new_total_supply = total_supply + lp_to_mint;

    (new_reserve_a, new_reserve_b, lp_to_mint, new_total_supply)
}

/// Remove liquidity: burn LP shares, withdraw proportional reserves.
///
/// amount_a = reserve_a * burn_amount / total_supply
/// amount_b = reserve_b * burn_amount / total_supply
///
/// Returns (amount_a_out, amount_b_out, new_reserve_a, new_reserve_b, new_total_supply).
#[encrypt_fn]
fn remove_liquidity_graph(
    reserve_a: EUint128,
    reserve_b: EUint128,
    total_supply: EUint128,
    burn_amount: EUint128,
) -> (EUint128, EUint128, EUint128, EUint128, EUint128) {
    let amount_a = (reserve_a * burn_amount) / total_supply;
    let amount_b = (reserve_b * burn_amount) / total_supply;
    let new_reserve_a = reserve_a - amount_a;
    let new_reserve_b = reserve_b - amount_b;
    let new_total_supply = total_supply - burn_amount;
    (amount_a, amount_b, new_reserve_a, new_reserve_b, new_total_supply)
}

// ── Instruction dispatch ──

fn process_instruction(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    match data.split_first() {
        Some((&0, rest)) => create_pool(program_id, accounts, rest),
        Some((&1, rest)) => swap(accounts, rest),
        Some((&2, rest)) => add_liquidity(accounts, rest),
        Some((&3, rest)) => request_decrypt(accounts, rest),
        Some((&4, rest)) => remove_liquidity(accounts, rest),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

// ── 0: CreatePool ──
// data: pool_bump(1) | cpi_authority_bump(1)
// accounts: [pool_pda(w), mint_a, mint_b,
//            reserve_a_ct(w,s), reserve_b_ct(w,s), total_supply_ct(w,s),
//            encrypt_program, config, deposit(w), cpi_authority,
//            caller_program, network_encryption_key, payer(s,w),
//            event_authority, system_program]

fn create_pool(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    let [pool_acct, mint_a, mint_b, reserve_a_ct, reserve_b_ct, total_supply_ct, encrypt_program, config, deposit, cpi_authority, caller_program, network_encryption_key, payer, event_authority, system_program, ..] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !payer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if data.len() < 2 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let pool_bump = data[0];
    let cpi_authority_bump = data[1];

    let bump_byte = [pool_bump];
    let seeds = [
        Seed::from(b"cp_pool" as &[u8]),
        Seed::from(mint_a.address().as_ref()),
        Seed::from(mint_b.address().as_ref()),
        Seed::from(&bump_byte),
    ];
    let signer = [Signer::from(&seeds)];

    CreateAccount {
        from: payer,
        to: pool_acct,
        lamports: minimum_balance(Pool::LEN),
        space: Pool::LEN as u64,
        owner: program_id,
    }
    .invoke_signed(&signer)?;

    let ctx = EncryptContext {
        encrypt_program, config, deposit, cpi_authority, caller_program,
        network_encryption_key, payer, event_authority, system_program,
        cpi_authority_bump,
    };

    ctx.create_plaintext_typed::<Uint128>(&0u128, reserve_a_ct)?;
    ctx.create_plaintext_typed::<Uint128>(&0u128, reserve_b_ct)?;
    ctx.create_plaintext_typed::<Uint128>(&0u128, total_supply_ct)?;

    let d = unsafe { pool_acct.borrow_unchecked_mut() };
    let pool = Pool::from_bytes_mut(d)?;
    pool.mint_a.copy_from_slice(mint_a.address().as_ref());
    pool.mint_b.copy_from_slice(mint_b.address().as_ref());
    pool.reserve_a.copy_from_slice(reserve_a_ct.address().as_ref());
    pool.reserve_b.copy_from_slice(reserve_b_ct.address().as_ref());
    pool.total_supply.copy_from_slice(total_supply_ct.address().as_ref());
    pool.is_initialized = 1;
    pool.bump = pool_bump;

    Ok(())
}

// ── 1: Swap ──
// data: cpi_authority_bump(1) | direction(1)
// accounts: [pool, reserve_in_ct(w), reserve_out_ct(w),
//            amount_in_ct, min_amount_out_ct, amount_out_ct(w),
//            encrypt_program, config, deposit(w), cpi_authority,
//            caller_program, network_encryption_key, payer(s,w),
//            event_authority, system_program]

fn swap(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [pool_acct, reserve_in_ct, reserve_out_ct, amount_in_ct, min_amount_out_ct, amount_out_ct, encrypt_program, config, deposit, cpi_authority, caller_program, network_encryption_key, payer, event_authority, system_program, ..] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !payer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if data.len() < 2 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let cpi_authority_bump = data[0];
    let direction = data[1];

    let pool_data = unsafe { pool_acct.borrow_unchecked() };
    let pool = Pool::from_bytes(pool_data)?;
    if pool.is_initialized != 1 {
        return Err(ProgramError::UninitializedAccount);
    }

    let (expected_in, expected_out) = if direction == 0 {
        (&pool.reserve_a, &pool.reserve_b)
    } else {
        (&pool.reserve_b, &pool.reserve_a)
    };
    if reserve_in_ct.address().as_ref() != expected_in {
        return Err(ProgramError::InvalidArgument);
    }
    if reserve_out_ct.address().as_ref() != expected_out {
        return Err(ProgramError::InvalidArgument);
    }

    let ctx = EncryptContext {
        encrypt_program, config, deposit, cpi_authority, caller_program,
        network_encryption_key, payer, event_authority, system_program,
        cpi_authority_bump,
    };

    ctx.swap_graph(
        reserve_in_ct, reserve_out_ct, amount_in_ct, min_amount_out_ct,
        amount_out_ct, reserve_in_ct, reserve_out_ct,
    )?;

    Ok(())
}

// ── 2: AddLiquidity ──
// data: cpi_authority_bump(1)
// accounts: [pool, reserve_a_ct(w), reserve_b_ct(w), total_supply_ct(w),
//            amount_a_ct, amount_b_ct, lp_minted_ct(w),
//            encrypt_program, config, deposit(w), cpi_authority,
//            caller_program, network_encryption_key, payer(s,w),
//            event_authority, system_program]
//
// lp_minted_ct receives the number of LP tokens minted for this deposit.
// The caller tracks this as the user's LP position.

fn add_liquidity(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [pool_acct, reserve_a_ct, reserve_b_ct, total_supply_ct, amount_a_ct, amount_b_ct, lp_minted_ct, encrypt_program, config, deposit, cpi_authority, caller_program, network_encryption_key, payer, event_authority, system_program, ..] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !payer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }

    let cpi_authority_bump = data[0];

    let pool_data = unsafe { pool_acct.borrow_unchecked() };
    let pool = Pool::from_bytes(pool_data)?;
    if pool.is_initialized != 1 {
        return Err(ProgramError::UninitializedAccount);
    }
    if reserve_a_ct.address().as_ref() != &pool.reserve_a {
        return Err(ProgramError::InvalidArgument);
    }
    if reserve_b_ct.address().as_ref() != &pool.reserve_b {
        return Err(ProgramError::InvalidArgument);
    }
    if total_supply_ct.address().as_ref() != &pool.total_supply {
        return Err(ProgramError::InvalidArgument);
    }

    let ctx = EncryptContext {
        encrypt_program, config, deposit, cpi_authority, caller_program,
        network_encryption_key, payer, event_authority, system_program,
        cpi_authority_bump,
    };

    // (new_ra, new_rb, lp_minted, new_supply) = add_liq(ra, rb, supply, amt_a, amt_b)
    ctx.add_liquidity_graph(
        reserve_a_ct, reserve_b_ct, total_supply_ct, amount_a_ct, amount_b_ct,
        reserve_a_ct, reserve_b_ct, lp_minted_ct, total_supply_ct,
    )?;

    Ok(())
}

// ── 3: RequestDecrypt ──
// data: cpi_authority_bump(1)
// accounts: [request_acct(w,s), ciphertext,
//            encrypt_program, config, deposit(w), cpi_authority,
//            caller_program, network_encryption_key, payer(s,w),
//            event_authority, system_program]

fn request_decrypt(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [request_acct, ciphertext, encrypt_program, config, deposit, cpi_authority, caller_program, network_encryption_key, payer, event_authority, system_program, ..] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !payer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }

    let cpi_authority_bump = data[0];

    let ctx = EncryptContext {
        encrypt_program, config, deposit, cpi_authority, caller_program,
        network_encryption_key, payer, event_authority, system_program,
        cpi_authority_bump,
    };

    ctx.request_decryption(request_acct, ciphertext)?;
    Ok(())
}

// ── 4: RemoveLiquidity ──
// data: cpi_authority_bump(1)
// accounts: [pool, reserve_a_ct(w), reserve_b_ct(w), total_supply_ct(w),
//            burn_amount_ct, amount_a_out_ct(w), amount_b_out_ct(w),
//            encrypt_program, config, deposit(w), cpi_authority,
//            caller_program, network_encryption_key, payer(s,w),
//            event_authority, system_program]
//
// burn_amount_ct is the number of LP tokens to burn (client-encrypted).
// amount_a_out_ct and amount_b_out_ct receive the withdrawn amounts.

fn remove_liquidity(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [pool_acct, reserve_a_ct, reserve_b_ct, total_supply_ct, burn_amount_ct, amount_a_out_ct, amount_b_out_ct, encrypt_program, config, deposit, cpi_authority, caller_program, network_encryption_key, payer, event_authority, system_program, ..] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !payer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }

    let cpi_authority_bump = data[0];

    let pool_data = unsafe { pool_acct.borrow_unchecked() };
    let pool = Pool::from_bytes(pool_data)?;
    if pool.is_initialized != 1 {
        return Err(ProgramError::UninitializedAccount);
    }
    if reserve_a_ct.address().as_ref() != &pool.reserve_a {
        return Err(ProgramError::InvalidArgument);
    }
    if reserve_b_ct.address().as_ref() != &pool.reserve_b {
        return Err(ProgramError::InvalidArgument);
    }
    if total_supply_ct.address().as_ref() != &pool.total_supply {
        return Err(ProgramError::InvalidArgument);
    }

    let ctx = EncryptContext {
        encrypt_program, config, deposit, cpi_authority, caller_program,
        network_encryption_key, payer, event_authority, system_program,
        cpi_authority_bump,
    };

    // (amt_a, amt_b, new_ra, new_rb, new_supply) = remove_liq(ra, rb, supply, burn)
    ctx.remove_liquidity_graph(
        reserve_a_ct, reserve_b_ct, total_supply_ct, burn_amount_ct,
        amount_a_out_ct, amount_b_out_ct, reserve_a_ct, reserve_b_ct, total_supply_ct,
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
                    let v = inputs[inp];
                    let t = fhe_types[inp];
                    inp += 1;
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
                    let (a, b, c) = (
                        n.input_a() as usize,
                        n.input_b() as usize,
                        n.input_c() as usize,
                    );
                    if n.op_type() == 60 {
                        mock_select(&digests[a], &digests[b], &digests[c])
                    } else if b == 0xFFFF {
                        mock_unary_compute(
                            unsafe { core::mem::transmute::<u8, encrypt_types::types::FheOperation>(n.op_type()) },
                            &digests[a], ft,
                        )
                    } else {
                        mock_binary_compute(
                            unsafe { core::mem::transmute::<u8, encrypt_types::types::FheOperation>(n.op_type()) },
                            &digests[a], &digests[b], ft,
                        )
                    }
                }
                k if k == GraphNodeKind::Output as u8 => digests[n.input_a() as usize],
                _ => panic!("bad node"),
            };
            digests.push(d);
        }

        (0..num)
            .filter(|&i| get_node(pg.node_bytes(), i as u16).unwrap().kind() == GraphNodeKind::Output as u8)
            .map(|i| decode_mock_identifier(&digests[i]))
            .collect()
    }

    const T: FheType = FheType::EUint128;

    // ── Swap tests ──

    #[test]
    fn swap_basic() {
        let r = run_mock(swap_graph, &[1000, 2000, 100, 0], &[T, T, T, T]);
        assert!(r[0] > 0, "should produce output");
        assert_eq!(r[1], 1100);
        assert!(r[1] * r[2] >= 1000 * 2000, "k invariant");
    }

    #[test]
    fn swap_slippage_rejection() {
        let r = run_mock(swap_graph, &[1000, 2000, 100, 999], &[T, T, T, T]);
        assert_eq!(r[0], 0);
        assert_eq!(r[1], 1000);
        assert_eq!(r[2], 2000);
    }

    #[test]
    fn swap_zero() {
        let r = run_mock(swap_graph, &[1000, 2000, 0, 0], &[T, T, T, T]);
        assert_eq!(r[0], 0);
    }

    #[test]
    fn swap_exact_slippage_boundary() {
        let r1 = run_mock(swap_graph, &[10000, 10000, 1000, 0], &[T, T, T, T]);
        let exact_out = r1[0];
        let r2 = run_mock(swap_graph, &[10000, 10000, 1000, exact_out], &[T, T, T, T]);
        assert_eq!(r2[0], exact_out);
        let r3 = run_mock(swap_graph, &[10000, 10000, 1000, exact_out + 1], &[T, T, T, T]);
        assert_eq!(r3[0], 0);
    }

    #[test]
    fn swap_k_across_many() {
        let mut ra: u128 = 100_000;
        let mut rb: u128 = 100_000;
        let initial_k = ra * rb;
        let amounts = [500, 300, 1000, 50, 2000, 100, 800, 1500, 200, 3000];
        for (i, &amt) in amounts.iter().enumerate() {
            let (rin, rout) = if i % 2 == 0 { (ra, rb) } else { (rb, ra) };
            let r = run_mock(swap_graph, &[rin, rout, amt, 0], &[T, T, T, T]);
            if i % 2 == 0 { ra = r[1]; rb = r[2]; } else { rb = r[1]; ra = r[2]; }
        }
        assert!(ra * rb >= initial_k, "k never decreases after 10 swaps");
    }

    // ── Add liquidity tests ──

    #[test]
    fn add_liq_first_deposit() {
        // First deposit: supply=0, so LP = amount_a * amount_b
        let r = run_mock(add_liquidity_graph, &[0, 0, 0, 1000, 2000], &[T, T, T, T, T]);
        assert_eq!(r[0], 1000, "new reserve A");
        assert_eq!(r[1], 2000, "new reserve B");
        assert_eq!(r[2], 1000 * 2000, "LP = a * b for first deposit");
        assert_eq!(r[3], 1000 * 2000, "total supply = LP minted");
    }

    #[test]
    fn add_liq_subsequent() {
        // Pool has 1000/2000, supply=2000000. Add 500/1000 (proportional).
        // LP = min(500*2000000/1000, 1000*2000000/2000) = min(1000000, 1000000) = 1000000
        let r = run_mock(add_liquidity_graph, &[1000, 2000, 2_000_000, 500, 1000], &[T, T, T, T, T]);
        assert_eq!(r[0], 1500);
        assert_eq!(r[1], 3000);
        // LP from A: 500*2000000/(1000+1) ≈ 999000
        // LP from B: 1000*2000000/(2000+1) ≈ 999500
        // min = ~999000
        assert!(r[2] > 0, "should mint LP");
        assert_eq!(r[3], 2_000_000 + r[2], "new supply = old + minted");
    }

    #[test]
    fn add_liq_zero_amounts() {
        let r = run_mock(add_liquidity_graph, &[1000, 2000, 100, 0, 0], &[T, T, T, T, T]);
        assert_eq!(r[0], 1000);
        assert_eq!(r[1], 2000);
        assert_eq!(r[2], 0, "zero deposit = zero LP");
    }

    // ── Remove liquidity tests ──

    #[test]
    fn remove_liq_half() {
        // Pool: 10000/20000, supply=200000000. Burn half.
        let supply = 200_000_000u128;
        let burn = supply / 2;
        let r = run_mock(remove_liquidity_graph, &[10000, 20000, supply, burn], &[T, T, T, T]);
        assert_eq!(r[0], 5000, "withdraw half of A");
        assert_eq!(r[1], 10000, "withdraw half of B");
        assert_eq!(r[2], 5000, "remaining A");
        assert_eq!(r[3], 10000, "remaining B");
        assert_eq!(r[4], supply - burn, "remaining supply");
    }

    #[test]
    fn remove_liq_full() {
        let supply = 100u128;
        let r = run_mock(remove_liquidity_graph, &[5000, 8000, supply, supply], &[T, T, T, T]);
        assert_eq!(r[0], 5000);
        assert_eq!(r[1], 8000);
        assert_eq!(r[2], 0);
        assert_eq!(r[3], 0);
        assert_eq!(r[4], 0, "supply = 0");
    }

    #[test]
    fn remove_liq_partial() {
        let supply = 1000u128;
        // Burn 250 out of 1000 = 25%
        let r = run_mock(remove_liquidity_graph, &[10000, 20000, supply, 250], &[T, T, T, T]);
        assert_eq!(r[0], 2500, "25% of A");
        assert_eq!(r[1], 5000, "25% of B");
        assert_eq!(r[2], 7500);
        assert_eq!(r[3], 15000);
        assert_eq!(r[4], 750);
    }

    // ── Graph shapes ──

    #[test]
    fn graph_shapes() {
        let g = swap_graph();
        let pg = parse_graph(&g).unwrap();
        assert_eq!(pg.header().num_inputs(), 4);
        assert_eq!(pg.header().num_outputs(), 3);

        let g = add_liquidity_graph();
        let pg = parse_graph(&g).unwrap();
        assert_eq!(pg.header().num_inputs(), 5);
        assert_eq!(pg.header().num_outputs(), 4);

        let g = remove_liquidity_graph();
        let pg = parse_graph(&g).unwrap();
        assert_eq!(pg.header().num_inputs(), 4);
        assert_eq!(pg.header().num_outputs(), 5);
    }
}
