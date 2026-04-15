// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#![allow(unexpected_cfgs)]

/// Confidential Vector Ops — comprehensive FHE vector operation test program.
///
/// Tests all operations across multiple vector element types.
/// Vector ciphertexts are created off-chain via gRPC CreateInput.
///
/// ## Instructions
///
/// 0.  create_state
/// --- EUint32Vector operations ---
/// 1.  add_u32           (a + b)
/// 2.  sub_u32           (a - b)
/// 3.  mul_u32           (a * b)
/// 4.  div_u32           (a / b)
/// 5.  mod_u32           (a % b)
/// 6.  and_u32           (a & b)
/// 7.  or_u32            (a | b)
/// 8.  xor_u32           (a ^ b)
/// 9.  neg_u32           (-a)
/// 10. not_u32           (!a)
/// 11. add_scalar_u32    (a + 5)
/// 12. mul_scalar_u32    (a * 3)
/// 13. min_u32           (a.min(b))
/// 14. max_u32           (a.max(b))
/// 15. eq_u32            (a == b)
/// 16. lt_u32            (a < b)
/// 17. select_u32        (if cond { a } else { b })
/// --- EUint8Vector operations ---
/// 20. add_u8
/// 21. mul_scalar_u8
/// --- EUint64Vector operations ---
/// 30. add_u64
/// 31. mul_scalar_u64
/// --- EUint128Vector operations ---
/// 40. add_u128
/// 41. mul_scalar_u128
use encrypt_dsl::prelude::encrypt_fn;
use encrypt_pinocchio::EncryptContext;
use pinocchio::{
    cpi::{Seed, Signer},
    entrypoint,
    error::ProgramError,
    AccountView, Address, ProgramResult,
};
use pinocchio_system::instructions::CreateAccount;

entrypoint!(process_instruction);

pub const ID: Address = Address::new_from_array([5u8; 32]);

const VECTOR_STATE: u8 = 1;

#[repr(C)]
pub struct VectorState {
    pub discriminator: u8,
    pub authority: [u8; 32],
    pub state_id: [u8; 32],
    pub vector_a: [u8; 32],
    pub vector_b: [u8; 32],
    pub result: [u8; 32],
    pub bump: u8,
}

impl VectorState {
    pub const LEN: usize = core::mem::size_of::<Self>();

    pub fn from_bytes(data: &[u8]) -> Result<&Self, ProgramError> {
        if data.len() < Self::LEN || data[0] != VECTOR_STATE {
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

// ════════════════════════════════════════════════════════════
// EUint32Vector graphs — all operations
// ════════════════════════════════════════════════════════════

#[encrypt_fn]
fn add_u32_graph(a: EUint32Vector, b: EUint32Vector) -> EUint32Vector { a + b }

#[encrypt_fn]
fn sub_u32_graph(a: EUint32Vector, b: EUint32Vector) -> EUint32Vector { a - b }

#[encrypt_fn]
fn mul_u32_graph(a: EUint32Vector, b: EUint32Vector) -> EUint32Vector { a * b }

#[encrypt_fn]
fn div_u32_graph(a: EUint32Vector, b: EUint32Vector) -> EUint32Vector { a / b }

#[encrypt_fn]
fn mod_u32_graph(a: EUint32Vector, b: EUint32Vector) -> EUint32Vector { a % b }

#[encrypt_fn]
fn and_u32_graph(a: EUint32Vector, b: EUint32Vector) -> EUint32Vector { a & b }

#[encrypt_fn]
fn or_u32_graph(a: EUint32Vector, b: EUint32Vector) -> EUint32Vector { a | b }

#[encrypt_fn]
fn xor_u32_graph(a: EUint32Vector, b: EUint32Vector) -> EUint32Vector { a ^ b }

#[encrypt_fn]
fn neg_u32_graph(a: EUint32Vector) -> EUint32Vector { -a }

#[encrypt_fn]
fn not_u32_graph(a: EUint32Vector) -> EUint32Vector { !a }

#[encrypt_fn]
fn add_scalar_u32_graph(a: EUint32Vector) -> EUint32Vector { a + 5 }

#[encrypt_fn]
fn mul_scalar_u32_graph(a: EUint32Vector) -> EUint32Vector { a * 3 }

#[encrypt_fn]
fn min_u32_graph(a: EUint32Vector, b: EUint32Vector) -> EUint32Vector { a.min(&b) }

#[encrypt_fn]
fn max_u32_graph(a: EUint32Vector, b: EUint32Vector) -> EUint32Vector { a.max(&b) }

#[encrypt_fn]
fn eq_u32_graph(a: EUint32Vector, b: EUint32Vector) -> EUint32Vector { a.is_equal(&b) }

#[encrypt_fn]
fn lt_u32_graph(a: EUint32Vector, b: EUint32Vector) -> EUint32Vector { a.is_less_than(&b) }

#[encrypt_fn]
fn select_u32_graph(cond: EBool, a: EUint32Vector, b: EUint32Vector) -> EUint32Vector {
    if cond { a } else { b }
}

// ════════════════════════════════════════════════════════════
// Vector-specific structural ops (EUint32Vector)
// ════════════════════════════════════════════════════════════

#[encrypt_fn]
fn gather_u32_graph(a: EUint32Vector, indices: EUint32Vector) -> EUint32Vector { a.gather(&indices) }

#[encrypt_fn]
fn scatter_u32_graph(a: EUint32Vector, indices: EUint32Vector) -> EUint32Vector { a.scatter(&indices) }

#[encrypt_fn]
fn copy_u32_graph(a: EUint32Vector, src: EUint32Vector) -> EUint32Vector { a.copy(&src) }

#[encrypt_fn]
fn assign_u32_graph(a: EUint32Vector, indices: EUint32Vector, values: EUint32Vector) -> EUint32Vector { a.assign(&indices, &values) }

// ════════════════════════════════════════════════════════════
// Multi-operation chained graphs (EUint32Vector)
// ════════════════════════════════════════════════════════════

/// dot-product-like: (a * b) + (c * d) — 2 multiplies + 1 add
#[encrypt_fn]
fn dot2_u32_graph(a: EUint32Vector, b: EUint32Vector, c: EUint32Vector, d: EUint32Vector) -> EUint32Vector {
    a * b + c * d
}

/// linear transform: a * 5 + b * 3 + 7 — 2 scalar muls + 1 add + 1 scalar add
#[encrypt_fn]
fn linear_u32_graph(a: EUint32Vector, b: EUint32Vector) -> EUint32Vector {
    a * 5 + b * 3 + 7
}

/// mask-and-sum: (a & mask) + (b | mask) — bitwise + arithmetic mixed
#[encrypt_fn]
fn mask_sum_u32_graph(a: EUint32Vector, b: EUint32Vector, mask: EUint32Vector) -> EUint32Vector {
    (a & mask) + (b | mask)
}

/// conditional accumulate: if cond { acc + val } else { acc } — select + add
#[encrypt_fn]
fn cond_add_u32_graph(cond: EBool, acc: EUint32Vector, val: EUint32Vector) -> EUint32Vector {
    let added = acc + val;
    if cond { added } else { acc }
}

/// chained arithmetic: ((a + b) * 2 - c) / 2 — 4 ops deep
#[encrypt_fn]
fn chain4_u32_graph(a: EUint32Vector, b: EUint32Vector, c: EUint32Vector) -> EUint32Vector {
    (((a + b) * 2) - c) / 2
}

/// multi-output: (a + b, a - b) — 2 outputs from same inputs
#[encrypt_fn]
fn sum_diff_u32_graph(a: EUint32Vector, b: EUint32Vector) -> (EUint32Vector, EUint32Vector) {
    (a + b, a - b)
}

// ════════════════════════════════════════════════════════════
// EUint8Vector graphs
// ════════════════════════════════════════════════════════════

#[encrypt_fn]
fn add_u8_graph(a: EUint8Vector, b: EUint8Vector) -> EUint8Vector { a + b }

#[encrypt_fn]
fn mul_scalar_u8_graph(a: EUint8Vector) -> EUint8Vector { a * 2 }

// ════════════════════════════════════════════════════════════
// EUint64Vector graphs
// ════════════════════════════════════════════════════════════

#[encrypt_fn]
fn add_u64_graph(a: EUint64Vector, b: EUint64Vector) -> EUint64Vector { a + b }

#[encrypt_fn]
fn mul_scalar_u64_graph(a: EUint64Vector) -> EUint64Vector { a * 7 }

// ════════════════════════════════════════════════════════════
// EUint128Vector graphs
// ════════════════════════════════════════════════════════════

#[encrypt_fn]
fn add_u128_graph(a: EUint128Vector, b: EUint128Vector) -> EUint128Vector { a + b }

#[encrypt_fn]
fn mul_scalar_u128_graph(a: EUint128Vector) -> EUint128Vector { a * 11 }

// ════════════════════════════════════════════════════════════
// Instruction dispatch
// ════════════════════════════════════════════════════════════

fn process_instruction(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    match data.split_first() {
        Some((&0, rest)) => create_state(program_id, accounts, rest),
        // u32 ops
        Some((&1, rest)) => exec_binary(accounts, rest, |ctx, a, b, o| ctx.add_u32_graph(a, b, o)),
        Some((&2, rest)) => exec_binary(accounts, rest, |ctx, a, b, o| ctx.sub_u32_graph(a, b, o)),
        Some((&3, rest)) => exec_binary(accounts, rest, |ctx, a, b, o| ctx.mul_u32_graph(a, b, o)),
        Some((&4, rest)) => exec_binary(accounts, rest, |ctx, a, b, o| ctx.div_u32_graph(a, b, o)),
        Some((&5, rest)) => exec_binary(accounts, rest, |ctx, a, b, o| ctx.mod_u32_graph(a, b, o)),
        Some((&6, rest)) => exec_binary(accounts, rest, |ctx, a, b, o| ctx.and_u32_graph(a, b, o)),
        Some((&7, rest)) => exec_binary(accounts, rest, |ctx, a, b, o| ctx.or_u32_graph(a, b, o)),
        Some((&8, rest)) => exec_binary(accounts, rest, |ctx, a, b, o| ctx.xor_u32_graph(a, b, o)),
        Some((&9, rest)) => exec_unary(accounts, rest, |ctx, a, o| ctx.neg_u32_graph(a, o)),
        Some((&10, rest)) => exec_unary(accounts, rest, |ctx, a, o| ctx.not_u32_graph(a, o)),
        Some((&11, rest)) => exec_unary(accounts, rest, |ctx, a, o| ctx.add_scalar_u32_graph(a, o)),
        Some((&12, rest)) => exec_unary(accounts, rest, |ctx, a, o| ctx.mul_scalar_u32_graph(a, o)),
        Some((&13, rest)) => exec_binary(accounts, rest, |ctx, a, b, o| ctx.min_u32_graph(a, b, o)),
        Some((&14, rest)) => exec_binary(accounts, rest, |ctx, a, b, o| ctx.max_u32_graph(a, b, o)),
        Some((&15, rest)) => exec_binary(accounts, rest, |ctx, a, b, o| ctx.eq_u32_graph(a, b, o)),
        Some((&16, rest)) => exec_binary(accounts, rest, |ctx, a, b, o| ctx.lt_u32_graph(a, b, o)),
        Some((&17, rest)) => exec_select(accounts, rest),
        // multi-op chained graphs
        Some((&50, rest)) => exec_quad(accounts, rest, |ctx, a, b, c, d, o| ctx.dot2_u32_graph(a, b, c, d, o)),
        Some((&51, rest)) => exec_binary(accounts, rest, |ctx, a, b, o| ctx.linear_u32_graph(a, b, o)),
        Some((&52, rest)) => exec_ternary(accounts, rest, |ctx, a, b, c, o| ctx.mask_sum_u32_graph(a, b, c, o)),
        Some((&53, rest)) => exec_cond_add(accounts, rest),
        Some((&54, rest)) => exec_ternary(accounts, rest, |ctx, a, b, c, o| ctx.chain4_u32_graph(a, b, c, o)),
        Some((&55, rest)) => exec_binary_dual_out(accounts, rest),
        // vector-specific structural ops
        Some((&60, rest)) => exec_binary(accounts, rest, |ctx, a, b, o| ctx.gather_u32_graph(a, b, o)),
        Some((&61, rest)) => exec_binary(accounts, rest, |ctx, a, b, o| ctx.scatter_u32_graph(a, b, o)),
        Some((&62, rest)) => exec_binary(accounts, rest, |ctx, a, b, o| ctx.copy_u32_graph(a, b, o)),
        Some((&63, rest)) => exec_ternary(accounts, rest, |ctx, a, b, c, o| ctx.assign_u32_graph(a, b, c, o)),
        // u8 ops
        Some((&20, rest)) => exec_binary(accounts, rest, |ctx, a, b, o| ctx.add_u8_graph(a, b, o)),
        Some((&21, rest)) => exec_unary(accounts, rest, |ctx, a, o| ctx.mul_scalar_u8_graph(a, o)),
        // u64 ops
        Some((&30, rest)) => exec_binary(accounts, rest, |ctx, a, b, o| ctx.add_u64_graph(a, b, o)),
        Some((&31, rest)) => exec_unary(accounts, rest, |ctx, a, o| ctx.mul_scalar_u64_graph(a, o)),
        // u128 ops
        Some((&40, rest)) => exec_binary(accounts, rest, |ctx, a, b, o| ctx.add_u128_graph(a, b, o)),
        Some((&41, rest)) => exec_unary(accounts, rest, |ctx, a, o| ctx.mul_scalar_u128_graph(a, o)),
        // utility: make_public via CPI
        Some((&99, rest)) => exec_make_public(accounts, rest),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

// ════════════════════════════════════════════════════════════
// Instruction handlers
// ════════════════════════════════════════════════════════════

fn create_state(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    let [state_acct, authority, vector_a_ct, vector_b_ct, result_ct, payer, _system_program, ..] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !authority.is_signer() || !payer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if data.len() < 34 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let state_bump = data[0];
    let _cpi_authority_bump = data[1];
    let state_id: [u8; 32] = data[2..34].try_into().unwrap();

    let bump_byte = [state_bump];
    let seeds = [
        Seed::from(b"vector_state" as &[u8]),
        Seed::from(state_id.as_ref()),
        Seed::from(&bump_byte),
    ];
    let signer = [Signer::from(&seeds)];

    CreateAccount {
        from: payer,
        to: state_acct,
        lamports: minimum_balance(VectorState::LEN),
        space: VectorState::LEN as u64,
        owner: program_id,
    }
    .invoke_signed(&signer)?;

    let d = unsafe { state_acct.borrow_unchecked_mut() };
    let state = VectorState::from_bytes_mut(d)?;
    state.discriminator = VECTOR_STATE;
    state.authority.copy_from_slice(authority.address().as_ref());
    state.state_id.copy_from_slice(&state_id);
    state.vector_a.copy_from_slice(vector_a_ct.address().as_ref());
    state.vector_b.copy_from_slice(vector_b_ct.address().as_ref());
    state.result.copy_from_slice(result_ct.address().as_ref());
    state.bump = state_bump;
    Ok(())
}

/// Execute a binary op graph: (a, b) → output
/// accounts: [a_ct, b_ct, out_ct, encrypt_program, config, deposit, cpi_authority,
///            caller_program, network_encryption_key, payer, event_authority, system_program]
fn exec_binary<F>(accounts: &[AccountView], data: &[u8], f: F) -> ProgramResult
where
    F: FnOnce(&EncryptContext, &AccountView, &AccountView, &AccountView) -> ProgramResult,
{
    let [a_ct, b_ct, out_ct, encrypt_program, config, deposit, cpi_authority, caller_program, network_encryption_key, payer, event_authority, system_program, ..] =
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
    let ctx = EncryptContext {
        encrypt_program, config, deposit, cpi_authority, caller_program,
        network_encryption_key, payer, event_authority, system_program,
        cpi_authority_bump: data[0],
    };
    f(&ctx, a_ct, b_ct, out_ct)
}

/// Execute a unary/scalar op graph: (a) → output
/// accounts: [a_ct, out_ct, encrypt_program, config, deposit, cpi_authority,
///            caller_program, network_encryption_key, payer, event_authority, system_program]
fn exec_unary<F>(accounts: &[AccountView], data: &[u8], f: F) -> ProgramResult
where
    F: FnOnce(&EncryptContext, &AccountView, &AccountView) -> ProgramResult,
{
    let [a_ct, out_ct, encrypt_program, config, deposit, cpi_authority, caller_program, network_encryption_key, payer, event_authority, system_program, ..] =
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
    let ctx = EncryptContext {
        encrypt_program, config, deposit, cpi_authority, caller_program,
        network_encryption_key, payer, event_authority, system_program,
        cpi_authority_bump: data[0],
    };
    f(&ctx, a_ct, out_ct)
}

/// Execute select graph: (cond, a, b) → output
/// accounts: [cond_ct, a_ct, b_ct, out_ct, encrypt_program, config, deposit, cpi_authority,
///            caller_program, network_encryption_key, payer, event_authority, system_program]
fn exec_select(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [cond_ct, a_ct, b_ct, out_ct, encrypt_program, config, deposit, cpi_authority, caller_program, network_encryption_key, payer, event_authority, system_program, ..] =
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
    let ctx = EncryptContext {
        encrypt_program, config, deposit, cpi_authority, caller_program,
        network_encryption_key, payer, event_authority, system_program,
        cpi_authority_bump: data[0],
    };
    ctx.select_u32_graph(cond_ct, a_ct, b_ct, out_ct)
}

fn exec_ternary<F>(accounts: &[AccountView], data: &[u8], f: F) -> ProgramResult
where F: FnOnce(&EncryptContext, &AccountView, &AccountView, &AccountView, &AccountView) -> ProgramResult {
    let [a, b, c, out, encrypt_program, config, deposit, cpi_authority, caller_program, network_encryption_key, payer, event_authority, system_program, ..] = accounts
    else { return Err(ProgramError::NotEnoughAccountKeys); };
    if !payer.is_signer() { return Err(ProgramError::MissingRequiredSignature); }
    if data.is_empty() { return Err(ProgramError::InvalidInstructionData); }
    let ctx = EncryptContext { encrypt_program, config, deposit, cpi_authority, caller_program, network_encryption_key, payer, event_authority, system_program, cpi_authority_bump: data[0] };
    f(&ctx, a, b, c, out)
}

fn exec_quad<F>(accounts: &[AccountView], data: &[u8], f: F) -> ProgramResult
where F: FnOnce(&EncryptContext, &AccountView, &AccountView, &AccountView, &AccountView, &AccountView) -> ProgramResult {
    let [a, b, c, d, out, encrypt_program, config, deposit, cpi_authority, caller_program, network_encryption_key, payer, event_authority, system_program, ..] = accounts
    else { return Err(ProgramError::NotEnoughAccountKeys); };
    if !payer.is_signer() { return Err(ProgramError::MissingRequiredSignature); }
    if data.is_empty() { return Err(ProgramError::InvalidInstructionData); }
    let ctx = EncryptContext { encrypt_program, config, deposit, cpi_authority, caller_program, network_encryption_key, payer, event_authority, system_program, cpi_authority_bump: data[0] };
    f(&ctx, a, b, c, d, out)
}

fn exec_cond_add(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [cond, acc, val, out, encrypt_program, config, deposit, cpi_authority, caller_program, network_encryption_key, payer, event_authority, system_program, ..] = accounts
    else { return Err(ProgramError::NotEnoughAccountKeys); };
    if !payer.is_signer() { return Err(ProgramError::MissingRequiredSignature); }
    if data.is_empty() { return Err(ProgramError::InvalidInstructionData); }
    let ctx = EncryptContext { encrypt_program, config, deposit, cpi_authority, caller_program, network_encryption_key, payer, event_authority, system_program, cpi_authority_bump: data[0] };
    ctx.cond_add_u32_graph(cond, acc, val, out)
}

fn exec_binary_dual_out(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [a, b, out0, out1, encrypt_program, config, deposit, cpi_authority, caller_program, network_encryption_key, payer, event_authority, system_program, ..] = accounts
    else { return Err(ProgramError::NotEnoughAccountKeys); };
    if !payer.is_signer() { return Err(ProgramError::MissingRequiredSignature); }
    if data.is_empty() { return Err(ProgramError::InvalidInstructionData); }
    let ctx = EncryptContext { encrypt_program, config, deposit, cpi_authority, caller_program, network_encryption_key, payer, event_authority, system_program, cpi_authority_bump: data[0] };
    ctx.sum_diff_u32_graph(a, b, out0, out1)
}

/// make_public via CPI: disc=99, data=[cpi_authority_bump]
/// accounts: [ct(w), encrypt_program, cpi_authority, caller_program]
fn exec_make_public(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [ct, encrypt_program, cpi_authority, caller_program, ..] = accounts
    else { return Err(ProgramError::NotEnoughAccountKeys); };
    if data.is_empty() { return Err(ProgramError::InvalidInstructionData); }
    let cpi_bump = data[0];
    let bump_byte = [cpi_bump];
    let seeds = [pinocchio::cpi::Seed::from(b"__encrypt_cpi_authority" as &[u8]), pinocchio::cpi::Seed::from(&bump_byte)];
    let signer = [pinocchio::cpi::Signer::from(&seeds)];
    // CPI: make_public (disc=10), accounts=[ciphertext(w), caller_program, cpi_authority(signer)]
    use pinocchio::instruction::{InstructionAccount, InstructionView};
    let accts = [
        InstructionAccount { address: ct.address(), is_writable: true, is_signer: false },
        InstructionAccount { address: caller_program.address(), is_writable: false, is_signer: false },
        InstructionAccount { address: cpi_authority.address(), is_writable: false, is_signer: true },
    ];
    let ix_data = [10u8];
    let ix = InstructionView { program_id: encrypt_program.address(), accounts: &accts, data: &ix_data };
    pinocchio::cpi::invoke_signed(&ix, &[ct, caller_program, cpi_authority, encrypt_program], &signer)
}
