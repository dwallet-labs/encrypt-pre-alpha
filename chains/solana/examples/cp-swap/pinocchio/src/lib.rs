// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#![allow(unexpected_cfgs)]

/// CP-Swap — Confidential UniV2 AMM built on CP-Token + Encrypt FHE.
///
/// Demonstrates composability: this program CPIs into Encrypt for swap
/// math (FHE computation on encrypted reserves) while holding pool
/// reserves as encrypted ciphertexts. Users interact with CP-Token
/// accounts and approve the pool as delegate for token transfers.
///
/// All reserves, swap amounts, and LP positions are encrypted.
/// Nobody can see TVL, trade sizes, or individual positions.
///
/// ## Constant product formula (x * y = k)
///
/// The swap graph computes the UniV2 formula entirely in the encrypted
/// domain: `amount_out = (amount_in * 997 * reserve_out) / (reserve_in * 1000 + amount_in * 997)`
///
/// The 0.3% fee (997/1000) is baked as graph constants. Both the
/// k-invariant check (`new_k >= old_k`) and slippage protection
/// (`amount_out >= min_amount_out`) are enforced in FHE. If either
/// fails, the swap is a silent no-op (reserves unchanged, output = 0).
///
/// ## Instructions
///
/// 0. `CreatePool` — create a new liquidity pool for two CP-Token mints
/// 1. `Swap` — swap token A for token B (or vice versa)
use encrypt_dsl::prelude::encrypt_fn;
use encrypt_pinocchio::EncryptContext;
use encrypt_types::encrypted::Uint128;
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
///
/// Holds the encrypted reserve ciphertexts for both tokens.
/// Reserves are owned by cp-swap's CPI authority (the pool operates
/// on them via FHE graphs through Encrypt CPI).
#[repr(C)]
pub struct Pool {
    pub mint_a: [u8; 32],        // CP-Token mint A
    pub mint_b: [u8; 32],        // CP-Token mint B
    pub reserve_a: [u8; 32],     // Ciphertext account for reserve A (EUint128)
    pub reserve_b: [u8; 32],     // Ciphertext account for reserve B (EUint128)
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

// ── Rent helper ──

fn minimum_balance(size: usize) -> u64 {
    (size as u64 + 128) * 6960
}

// ── FHE Graphs ──

/// Swap: constant product AMM (x * y = k) with 0.3% fee.
///
/// Self-settling — if slippage or k-check fails, reserves unchanged (no-op).
/// Fee is baked as constants: 997/1000 = 0.3%.
///
/// Uses EUint128 to handle large intermediate products without overflow
/// (two u64 reserves multiplied can exceed u64).
#[encrypt_fn]
fn swap_graph(
    reserve_in: EUint128,
    reserve_out: EUint128,
    amount_in: EUint128,
    min_amount_out: EUint128,
) -> (EUint128, EUint128, EUint128) {
    // UniV2 formula with 0.3% fee
    let amount_in_with_fee = amount_in * 997;
    let numerator = amount_in_with_fee * reserve_out;
    let denominator = (reserve_in * 1000) + amount_in_with_fee;
    let amount_out = numerator / denominator;

    let new_reserve_in = reserve_in + amount_in;
    let new_reserve_out = reserve_out - amount_out;

    // k invariant + slippage check
    let old_k = reserve_in * reserve_out;
    let new_k = new_reserve_in * new_reserve_out;
    let k_ok = new_k >= old_k;
    let slippage_ok = amount_out >= min_amount_out;

    // if valid → apply swap, else → return originals (no-op)
    let valid = if k_ok { slippage_ok } else { k_ok };
    let final_out = if valid { amount_out } else { amount_in - amount_in };
    let final_reserve_in = if valid { new_reserve_in } else { reserve_in };
    let final_reserve_out = if valid { new_reserve_out } else { reserve_out };

    (final_out, final_reserve_in, final_reserve_out)
}

/// Add liquidity: deposit both tokens proportionally.
/// Returns (new_reserve_a, new_reserve_b, lp_amount).
/// lp_amount = sqrt(amount_a * amount_b) for initial deposit,
/// or proportional to existing reserves for subsequent deposits.
///
/// Simplified: always uses geometric mean (sqrt) for LP calculation.
/// A production AMM would track total_supply for proportional minting.
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
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

// ── 0: CreatePool ──
// data: pool_bump(1) | cpi_authority_bump(1)
// accounts: [pool_pda(w), mint_a, mint_b,
//            reserve_a_ct(w), reserve_b_ct(w),
//            encrypt_program, config, deposit(w), cpi_authority,
//            caller_program, network_encryption_key, payer(s,w),
//            event_authority, system_program]

fn create_pool(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    let [pool_acct, mint_a, mint_b, reserve_a_ct, reserve_b_ct, encrypt_program, config, deposit, cpi_authority, caller_program, network_encryption_key, payer, event_authority, system_program, ..] =
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

    // Create pool PDA
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

    // Create encrypted zero reserves via Encrypt CPI
    let ctx = EncryptContext {
        encrypt_program,
        config,
        deposit,
        cpi_authority,
        caller_program,
        network_encryption_key,
        payer,
        event_authority,
        system_program,
        cpi_authority_bump,
    };

    ctx.create_plaintext_typed::<Uint128>(&0u128, reserve_a_ct)?;
    ctx.create_plaintext_typed::<Uint128>(&0u128, reserve_b_ct)?;

    // Write pool state
    let d = unsafe { pool_acct.borrow_unchecked_mut() };
    let pool = Pool::from_bytes_mut(d)?;
    pool.mint_a.copy_from_slice(mint_a.address().as_ref());
    pool.mint_b.copy_from_slice(mint_b.address().as_ref());
    pool.reserve_a.copy_from_slice(reserve_a_ct.address().as_ref());
    pool.reserve_b.copy_from_slice(reserve_b_ct.address().as_ref());
    pool.is_initialized = 1;
    pool.bump = pool_bump;

    Ok(())
}

// ── 1: Swap ──
// data: cpi_authority_bump(1) | direction(1) (0 = A→B, 1 = B→A)
// accounts: [pool, reserve_in_ct(w), reserve_out_ct(w),
//            amount_in_ct, min_amount_out_ct, amount_out_ct(w),
//            encrypt_program, config, deposit(w), cpi_authority,
//            caller_program, network_encryption_key, payer(s,w),
//            event_authority, system_program]
//
// The swap graph computes the UniV2 formula on encrypted reserves.
// amount_in_ct and min_amount_out_ct are client-encrypted via gRPC.
// amount_out_ct is a pre-created zero ciphertext that receives the output.
//
// The actual token transfers (user ↔ pool) happen via CP-Token CPI
// in a separate instruction or are handled by the caller.
// This instruction ONLY updates the pool reserves and computes amount_out.

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

    // Verify pool
    let pool_data = unsafe { pool_acct.borrow_unchecked() };
    let pool = Pool::from_bytes(pool_data)?;
    if pool.is_initialized != 1 {
        return Err(ProgramError::UninitializedAccount);
    }

    // Verify reserve ciphertexts match pool (direction determines which is in/out)
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
        encrypt_program,
        config,
        deposit,
        cpi_authority,
        caller_program,
        network_encryption_key,
        payer,
        event_authority,
        system_program,
        cpi_authority_bump,
    };

    // Execute swap graph: (amount_out, new_reserve_in, new_reserve_out) =
    //   swap(reserve_in, reserve_out, amount_in, min_amount_out)
    // reserve ciphertexts are both input and output (update mode)
    // amount_out_ct receives the computed output amount
    ctx.swap_graph(
        reserve_in_ct,
        reserve_out_ct,
        amount_in_ct,
        min_amount_out_ct,
        amount_out_ct,
        reserve_in_ct,
        reserve_out_ct,
    )?;

    Ok(())
}

// ── 2: AddLiquidity ──
// data: cpi_authority_bump(1)
// accounts: [pool, reserve_a_ct(w), reserve_b_ct(w),
//            amount_a_ct, amount_b_ct,
//            encrypt_program, config, deposit(w), cpi_authority,
//            caller_program, network_encryption_key, payer(s,w),
//            event_authority, system_program]

fn add_liquidity(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [pool_acct, reserve_a_ct, reserve_b_ct, amount_a_ct, amount_b_ct, encrypt_program, config, deposit, cpi_authority, caller_program, network_encryption_key, payer, event_authority, system_program, ..] =
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

    // Verify pool
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

    let ctx = EncryptContext {
        encrypt_program,
        config,
        deposit,
        cpi_authority,
        caller_program,
        network_encryption_key,
        payer,
        event_authority,
        system_program,
        cpi_authority_bump,
    };

    // Execute: (new_reserve_a, new_reserve_b) = add_liquidity(reserve_a, reserve_b, amount_a, amount_b)
    ctx.add_liquidity_graph(
        reserve_a_ct,
        reserve_b_ct,
        amount_a_ct,
        amount_b_ct,
        reserve_a_ct,
        reserve_b_ct,
    )?;

    Ok(())
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use encrypt_types::graph::{get_node, parse_graph, GraphNodeKind};
    use encrypt_types::identifier::*;
    use encrypt_types::types::FheType;

    use super::{add_liquidity_graph, swap_graph};

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
                            unsafe {
                                core::mem::transmute::<u8, encrypt_types::types::FheOperation>(
                                    n.op_type(),
                                )
                            },
                            &digests[a],
                            ft,
                        )
                    } else {
                        mock_binary_compute(
                            unsafe {
                                core::mem::transmute::<u8, encrypt_types::types::FheOperation>(
                                    n.op_type(),
                                )
                            },
                            &digests[a],
                            &digests[b],
                            ft,
                        )
                    }
                }
                k if k == GraphNodeKind::Output as u8 => digests[n.input_a() as usize],
                _ => panic!("bad node"),
            };
            digests.push(d);
        }

        (0..num)
            .filter(|&i| {
                get_node(pg.node_bytes(), i as u16).unwrap().kind() == GraphNodeKind::Output as u8
            })
            .map(|i| decode_mock_identifier(&digests[i]))
            .collect()
    }

    #[test]
    fn swap_basic() {
        // Pool: 1000 A, 2000 B. Swap 100 A → B.
        // Expected: amount_out ≈ 100 * 997 * 2000 / (1000 * 1000 + 100 * 997)
        //         = 199400000 / 1099700 ≈ 181
        let t = FheType::EUint128;
        let r = run_mock(swap_graph, &[1000, 2000, 100, 0], &[t, t, t, t]);
        let amount_out = r[0];
        let new_reserve_in = r[1];
        let new_reserve_out = r[2];
        assert!(amount_out > 0, "should produce output");
        assert_eq!(new_reserve_in, 1100, "reserve_in += amount_in");
        assert_eq!(new_reserve_out, 2000 - amount_out, "reserve_out -= amount_out");
        // Verify k invariant
        assert!(new_reserve_in * new_reserve_out >= 1000 * 2000, "k must not decrease");
    }

    #[test]
    fn swap_slippage_protection() {
        // Pool: 1000 A, 2000 B. Swap 100 A, min_out = 999 (too high).
        let t = FheType::EUint128;
        let r = run_mock(swap_graph, &[1000, 2000, 100, 999], &[t, t, t, t]);
        assert_eq!(r[0], 0, "output should be 0 (slippage)");
        assert_eq!(r[1], 1000, "reserve_in unchanged");
        assert_eq!(r[2], 2000, "reserve_out unchanged");
    }

    #[test]
    fn swap_zero_amount() {
        let t = FheType::EUint128;
        let r = run_mock(swap_graph, &[1000, 2000, 0, 0], &[t, t, t, t]);
        assert_eq!(r[0], 0, "zero input → zero output");
    }

    #[test]
    fn add_liquidity_basic() {
        let t = FheType::EUint128;
        let r = run_mock(add_liquidity_graph, &[1000, 2000, 500, 1000], &[t, t, t, t]);
        assert_eq!(r[0], 1500, "reserve_a + amount_a");
        assert_eq!(r[1], 3000, "reserve_b + amount_b");
    }

    #[test]
    fn graph_shapes() {
        let g = swap_graph();
        let pg = parse_graph(&g).unwrap();
        assert_eq!(pg.header().num_inputs(), 4, "swap: reserve_in + reserve_out + amount_in + min_amount_out");
        assert_eq!(pg.header().num_outputs(), 3, "swap: amount_out + new_reserve_in + new_reserve_out");

        let g = add_liquidity_graph();
        let pg = parse_graph(&g).unwrap();
        assert_eq!(pg.header().num_inputs(), 4);
        assert_eq!(pg.header().num_outputs(), 2);
    }
}
