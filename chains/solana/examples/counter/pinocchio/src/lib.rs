// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#![allow(unexpected_cfgs)]

/// Confidential Counter — A Solana program using the Encrypt DSL.
///
/// An on-chain counter whose value is encrypted via FHE. Nobody can see the
/// current count, but anyone can increment or decrement it. The authority can
/// request decryption and reveal the plaintext value on-chain.
///
/// ## Accounts
///
/// - `Counter` PDA (`["counter", counter_id]`): counter state with encrypted value
///
/// ## Instructions
///
/// 0. `create_counter` — create a new counter initialized to encrypted zero
/// 1. `increment` — add 1 to the counter via FHE
/// 2. `decrement` — subtract 1 from the counter via FHE
/// 3. `request_value_decryption` — authority requests decryption of the counter
/// 4. `reveal_value` — authority writes the decrypted plaintext to the counter
///
/// ## FHE Design
///
/// The counter value is kept as an EUint64. Increment and decrement each use a
/// simple graph that adds or subtracts the constant 1.
use encrypt_dsl::prelude::encrypt_fn;
use encrypt_pinocchio::accounts;
use encrypt_pinocchio::EncryptContext;
use encrypt_types::encrypted::{EUint64, Uint64};
use pinocchio::{
    cpi::{Seed, Signer},
    entrypoint,
    error::ProgramError,
    AccountView, Address, ProgramResult,
};
use pinocchio_system::instructions::CreateAccount;

entrypoint!(process_instruction);

pub const ID: Address = Address::new_from_array([4u8; 32]);

// ── Account discriminator ──

const COUNTER: u8 = 1;

// ── Account layout ──

/// Counter state — PDA seeds: `["counter", counter_id]`
///
/// `value` is an encrypted counter (EUint64).
/// The chain never sees the actual count until decryption.
#[repr(C)]
pub struct Counter {
    pub discriminator: u8,        // [0]
    pub authority: [u8; 32],      // [1..33]
    pub counter_id: [u8; 32],     // [33..65]
    pub value: EUint64,           // [65..97] — encrypted counter value
    pub pending_digest: [u8; 32], // [97..129] — for decryption verification
    pub revealed_value: [u8; 8],  // [129..137] — plaintext after decryption
    pub bump: u8,                 // [137]
}

impl Counter {
    pub const LEN: usize = core::mem::size_of::<Self>();

    pub fn from_bytes(data: &[u8]) -> Result<&Self, ProgramError> {
        if data.len() < Self::LEN || data[0] != COUNTER {
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

/// Increment: value + 1
#[encrypt_fn]
fn increment_graph(value: EUint64) -> EUint64 {
    value + 1
}

/// Decrement: value - 1
#[encrypt_fn]
fn decrement_graph(value: EUint64) -> EUint64 {
    value - 1
}

// ── Instruction dispatch ──

fn process_instruction(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    match data.split_first() {
        Some((&0, rest)) => create_counter(program_id, accounts, rest),
        Some((&1, rest)) => increment(accounts, rest),
        Some((&2, rest)) => decrement(accounts, rest),
        Some((&3, rest)) => request_value_decryption(accounts, rest),
        Some((&4, _rest)) => reveal_value(accounts),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

// ── 0: create_counter ──
// data: counter_bump(1) | cpi_authority_bump(1) | counter_id(32)
// accounts: [counter_pda(w), authority(s), value_ct(w),
//            encrypt_program, config, deposit(w), cpi_authority,
//            caller_program, network_encryption_key, payer(s,w),
//            event_authority, system_program]

fn create_counter(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    let [counter_acct, authority, value_ct, encrypt_program, config, deposit, cpi_authority, caller_program, network_encryption_key, payer, event_authority, system_program, ..] =
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

    let counter_bump = data[0];
    let cpi_authority_bump = data[1];
    let counter_id: [u8; 32] = data[2..34].try_into().unwrap();

    // Create counter PDA
    let bump_byte = [counter_bump];
    let seeds = [
        Seed::from(b"counter" as &[u8]),
        Seed::from(counter_id.as_ref()),
        Seed::from(&bump_byte),
    ];
    let signer = [Signer::from(&seeds)];

    CreateAccount {
        from: payer,
        to: counter_acct,
        lamports: minimum_balance(Counter::LEN),
        space: Counter::LEN as u64,
        owner: program_id,
    }
    .invoke_signed(&signer)?;

    // Create encrypted zero via CPI
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

    ctx.create_plaintext_typed::<Uint64>(&0u64, value_ct)?;

    // Write counter state
    let d = unsafe { counter_acct.borrow_unchecked_mut() };
    let ctr = Counter::from_bytes_mut(d)?;
    ctr.discriminator = COUNTER;
    ctr.authority.copy_from_slice(authority.address().as_ref());
    ctr.counter_id.copy_from_slice(&counter_id);
    ctr.value = EUint64::from_le_bytes(*value_ct.address().as_array());
    ctr.pending_digest = [0u8; 32];
    ctr.revealed_value = [0u8; 8];
    ctr.bump = counter_bump;
    Ok(())
}

// ── 1: increment ──
// data: cpi_authority_bump(1)
// accounts: [counter(w), value_ct(w),
//            encrypt_program, config, deposit(w), cpi_authority,
//            caller_program, network_encryption_key, payer(s,w),
//            event_authority, system_program]

fn increment(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [counter_acct, value_ct, encrypt_program, config, deposit, cpi_authority, caller_program, network_encryption_key, payer, event_authority, system_program, ..] =
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

    // Verify counter account and value_ct matches stored value
    let ctr_data = unsafe { counter_acct.borrow_unchecked() };
    let ctr = Counter::from_bytes(ctr_data)?;
    if value_ct.address().as_array() != ctr.value.id() {
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

    ctx.increment_graph(value_ct, value_ct)?;

    Ok(())
}

// ── 2: decrement ──
// data: cpi_authority_bump(1)
// accounts: [counter(w), value_ct(w),
//            encrypt_program, config, deposit(w), cpi_authority,
//            caller_program, network_encryption_key, payer(s,w),
//            event_authority, system_program]

fn decrement(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [counter_acct, value_ct, encrypt_program, config, deposit, cpi_authority, caller_program, network_encryption_key, payer, event_authority, system_program, ..] =
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

    // Verify counter account and value_ct matches stored value
    let ctr_data = unsafe { counter_acct.borrow_unchecked() };
    let ctr = Counter::from_bytes(ctr_data)?;
    if value_ct.address().as_array() != ctr.value.id() {
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

    ctx.decrement_graph(value_ct, value_ct)?;

    Ok(())
}

// ── 3: request_value_decryption ──
// data: cpi_authority_bump(1)
// accounts: [counter(w), request_acct(w), ciphertext,
//            encrypt_program, config, deposit(w), cpi_authority,
//            caller_program, network_encryption_key, payer(s,w),
//            event_authority, system_program]

fn request_value_decryption(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [counter_acct, request_acct, ciphertext, encrypt_program, config, deposit, cpi_authority, caller_program, network_encryption_key, payer, event_authority, system_program, ..] =
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

    // Verify authority
    let ctr_data = unsafe { counter_acct.borrow_unchecked() };
    let ctr = Counter::from_bytes(ctr_data)?;
    if payer.address().as_array() != &ctr.authority {
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

    // request_decryption returns the ciphertext_digest — store for reveal verification
    let digest = ctx.request_decryption(request_acct, ciphertext)?;

    let ctr_data_mut = unsafe { counter_acct.borrow_unchecked_mut() };
    let ctr_mut = Counter::from_bytes_mut(ctr_data_mut)?;
    ctr_mut.pending_digest = digest;

    Ok(())
}

// ── 4: reveal_value ──
// data: (none)
// accounts: [counter(w), request_acct, authority(s)]

fn reveal_value(accounts: &[AccountView]) -> ProgramResult {
    let [counter_acct, request_acct, authority, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Verify authority
    let ctr_data = unsafe { counter_acct.borrow_unchecked() };
    let ctr = Counter::from_bytes(ctr_data)?;
    if authority.address().as_array() != &ctr.authority {
        return Err(ProgramError::InvalidArgument);
    }

    // Verify against the digest stored at request_decryption time
    let req_data = unsafe { request_acct.borrow_unchecked() };
    let value: &u64 = accounts::read_decrypted_verified::<Uint64>(req_data, &ctr.pending_digest)?;

    // Write plaintext to counter
    let ctr_data_mut = unsafe { counter_acct.borrow_unchecked_mut() };
    let ctr_mut = Counter::from_bytes_mut(ctr_data_mut)?;
    ctr_mut.revealed_value = value.to_le_bytes();

    Ok(())
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use encrypt_types::graph::{get_node, parse_graph, GraphNodeKind};
    use encrypt_types::identifier::*;
    use encrypt_types::types::FheType;

    use super::{decrement_graph, increment_graph};

    fn run_mock(graph_fn: fn() -> Vec<u8>, inputs: &[u128], fhe_types: &[FheType]) -> Vec<u128> {
        let data = graph_fn();
        let pg = parse_graph(&data).unwrap();
        let num = pg.header().num_nodes() as usize;
        let mut digests: Vec<[u8; 32]> = Vec::with_capacity(num);
        let mut inp = 0usize;

        for i in 0..num {
            let n = get_node(pg.node_bytes(), i as u16).unwrap();
            let ft = FheType::from_u8(n.fhe_type()).unwrap_or(FheType::EUint64);

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
    fn increment_from_zero() {
        let r = run_mock(
            increment_graph,
            &[0],
            &[FheType::EUint64],
        );
        assert_eq!(r[0], 1, "0 + 1 = 1");
    }

    #[test]
    fn increment_from_ten() {
        let r = run_mock(
            increment_graph,
            &[10],
            &[FheType::EUint64],
        );
        assert_eq!(r[0], 11, "10 + 1 = 11");
    }

    #[test]
    fn decrement_from_ten() {
        let r = run_mock(
            decrement_graph,
            &[10],
            &[FheType::EUint64],
        );
        assert_eq!(r[0], 9, "10 - 1 = 9");
    }

    #[test]
    fn graph_shapes() {
        let inc = increment_graph();
        let pg = parse_graph(&inc).unwrap();
        assert_eq!(pg.header().num_inputs(), 1, "increment has 1 input");
        assert_eq!(pg.header().num_outputs(), 1, "increment has 1 output");

        let dec = decrement_graph();
        let pg = parse_graph(&dec).unwrap();
        assert_eq!(pg.header().num_inputs(), 1, "decrement has 1 input");
        assert_eq!(pg.header().num_outputs(), 1, "decrement has 1 output");
    }
}
