// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Confidential Counter — Native solana-program version.
//!
//! Same FHE counter logic as the Pinocchio example, but uses solana-program's
//! `AccountInfo` and `EncryptContext` for CPI.

use encrypt_dsl::prelude::encrypt_fn;
use encrypt_native::EncryptContext;
use encrypt_types::encrypted::{EUint64, Uint64};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    msg,
    program::invoke_signed,
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::Rent,
    sysvar::Sysvar,
};
use solana_system_interface::instruction as system_instruction;

entrypoint!(process_instruction);

// ── Account discriminator ──

const COUNTER: u8 = 1;

// ── Account layout ──
//
// Counter PDA seeds: ["counter", counter_id]
//
// discriminator(1) | authority(32) | counter_id(32) | value(32) |
// pending_digest(32) | revealed_value(8) | bump(1)
// Total: 138 bytes

const COUNTER_LEN: usize = 1 + 32 + 32 + 32 + 32 + 8 + 1; // 138

// Field offsets
const OFF_DISC: usize = 0;
const OFF_AUTHORITY: usize = 1;
const OFF_COUNTER_ID: usize = 33;
const OFF_VALUE: usize = 65;
const OFF_PENDING_DIGEST: usize = 97;
const OFF_REVEALED_VALUE: usize = 129;
const OFF_BUMP: usize = 137;

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

// ── Entrypoint ──

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    match data.first() {
        Some(&0) => create_counter(program_id, accounts, &data[1..]),
        Some(&1) => increment(accounts, &data[1..]),
        Some(&2) => decrement(accounts, &data[1..]),
        Some(&3) => request_value_decryption(accounts, &data[1..]),
        Some(&4) => reveal_value(accounts),
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
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    let iter = &mut accounts.iter();
    let counter_acct = next_account_info(iter)?;
    let authority = next_account_info(iter)?;
    let value_ct = next_account_info(iter)?;
    let encrypt_program = next_account_info(iter)?;
    let config = next_account_info(iter)?;
    let deposit = next_account_info(iter)?;
    let cpi_authority = next_account_info(iter)?;
    let caller_program = next_account_info(iter)?;
    let network_encryption_key = next_account_info(iter)?;
    let payer = next_account_info(iter)?;
    let event_authority = next_account_info(iter)?;
    let system_program = next_account_info(iter)?;

    if !authority.is_signer || !payer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if data.len() < 34 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let counter_bump = data[0];
    let cpi_authority_bump = data[1];
    let counter_id: [u8; 32] = data[2..34].try_into().unwrap();

    let seeds = &[b"counter".as_ref(), counter_id.as_ref(), &[counter_bump]];
    let rent = Rent::get()?;
    let lamports = rent.minimum_balance(COUNTER_LEN);

    invoke_signed(
        &system_instruction::create_account(
            payer.key,
            counter_acct.key,
            lamports,
            COUNTER_LEN as u64,
            program_id,
        ),
        &[payer.clone(), counter_acct.clone(), system_program.clone()],
        &[seeds],
    )?;

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
    let mut d = counter_acct.try_borrow_mut_data()?;
    d[OFF_DISC] = COUNTER;
    d[OFF_AUTHORITY..OFF_COUNTER_ID].copy_from_slice(authority.key.as_ref());
    d[OFF_COUNTER_ID..OFF_VALUE].copy_from_slice(&counter_id);
    d[OFF_VALUE..OFF_PENDING_DIGEST].copy_from_slice(value_ct.key.as_ref());
    // pending_digest, revealed_value already zeroed
    d[OFF_BUMP] = counter_bump;

    msg!("Counter created");
    Ok(())
}

// ── 1: increment ──
// data: cpi_authority_bump(1)
// accounts: [counter(w), value_ct(w),
//            encrypt_program, config, deposit(w), cpi_authority,
//            caller_program, network_encryption_key, payer(s,w),
//            event_authority, system_program]

fn increment(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let iter = &mut accounts.iter();
    let counter_acct = next_account_info(iter)?;
    let value_ct = next_account_info(iter)?;
    let encrypt_program = next_account_info(iter)?;
    let config = next_account_info(iter)?;
    let deposit = next_account_info(iter)?;
    let cpi_authority = next_account_info(iter)?;
    let caller_program = next_account_info(iter)?;
    let network_encryption_key = next_account_info(iter)?;
    let payer = next_account_info(iter)?;
    let event_authority = next_account_info(iter)?;
    let system_program = next_account_info(iter)?;

    if !payer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }

    let cpi_authority_bump = data[0];

    // Verify value_ct matches stored value
    let ctr_data = counter_acct.try_borrow_data()?;
    if ctr_data[OFF_DISC] != COUNTER {
        return Err(ProgramError::InvalidAccountData);
    }
    if value_ct.key.as_ref() != &ctr_data[OFF_VALUE..OFF_PENDING_DIGEST] {
        return Err(ProgramError::InvalidArgument);
    }
    drop(ctr_data);

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

    ctx.increment_graph(value_ct.clone(), value_ct.clone())?;

    Ok(())
}

// ── 2: decrement ──
// data: cpi_authority_bump(1)
// accounts: [counter(w), value_ct(w),
//            encrypt_program, config, deposit(w), cpi_authority,
//            caller_program, network_encryption_key, payer(s,w),
//            event_authority, system_program]

fn decrement(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let iter = &mut accounts.iter();
    let counter_acct = next_account_info(iter)?;
    let value_ct = next_account_info(iter)?;
    let encrypt_program = next_account_info(iter)?;
    let config = next_account_info(iter)?;
    let deposit = next_account_info(iter)?;
    let cpi_authority = next_account_info(iter)?;
    let caller_program = next_account_info(iter)?;
    let network_encryption_key = next_account_info(iter)?;
    let payer = next_account_info(iter)?;
    let event_authority = next_account_info(iter)?;
    let system_program = next_account_info(iter)?;

    if !payer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }

    let cpi_authority_bump = data[0];

    // Verify value_ct matches stored value
    let ctr_data = counter_acct.try_borrow_data()?;
    if ctr_data[OFF_DISC] != COUNTER {
        return Err(ProgramError::InvalidAccountData);
    }
    if value_ct.key.as_ref() != &ctr_data[OFF_VALUE..OFF_PENDING_DIGEST] {
        return Err(ProgramError::InvalidArgument);
    }
    drop(ctr_data);

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

    ctx.decrement_graph(value_ct.clone(), value_ct.clone())?;

    Ok(())
}

// ── 3: request_value_decryption ──
// data: cpi_authority_bump(1)
// accounts: [counter(w), request_acct(w), ciphertext,
//            encrypt_program, config, deposit(w), cpi_authority,
//            caller_program, network_encryption_key, payer(s,w),
//            event_authority, system_program]

fn request_value_decryption(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let iter = &mut accounts.iter();
    let counter_acct = next_account_info(iter)?;
    let request_acct = next_account_info(iter)?;
    let ciphertext = next_account_info(iter)?;
    let encrypt_program = next_account_info(iter)?;
    let config = next_account_info(iter)?;
    let deposit = next_account_info(iter)?;
    let cpi_authority = next_account_info(iter)?;
    let caller_program = next_account_info(iter)?;
    let network_encryption_key = next_account_info(iter)?;
    let payer = next_account_info(iter)?;
    let event_authority = next_account_info(iter)?;
    let system_program = next_account_info(iter)?;

    if !payer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }

    let cpi_authority_bump = data[0];

    // Verify authority
    let ctr_data = counter_acct.try_borrow_data()?;
    if ctr_data[OFF_DISC] != COUNTER {
        return Err(ProgramError::InvalidAccountData);
    }
    if payer.key.as_ref() != &ctr_data[OFF_AUTHORITY..OFF_COUNTER_ID] {
        return Err(ProgramError::InvalidArgument);
    }
    drop(ctr_data);

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

    let mut ctr_data = counter_acct.try_borrow_mut_data()?;
    ctr_data[OFF_PENDING_DIGEST..OFF_REVEALED_VALUE].copy_from_slice(&digest);

    Ok(())
}

// ── 4: reveal_value ──
// data: (none)
// accounts: [counter(w), request_acct, authority(s)]

fn reveal_value(accounts: &[AccountInfo]) -> ProgramResult {
    let iter = &mut accounts.iter();
    let counter_acct = next_account_info(iter)?;
    let request_acct = next_account_info(iter)?;
    let authority = next_account_info(iter)?;

    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Verify authority
    let ctr_data = counter_acct.try_borrow_data()?;
    if ctr_data[OFF_DISC] != COUNTER {
        return Err(ProgramError::InvalidAccountData);
    }
    if authority.key.as_ref() != &ctr_data[OFF_AUTHORITY..OFF_COUNTER_ID] {
        return Err(ProgramError::InvalidArgument);
    }

    // Read digest stored at request_decryption time
    let expected_digest: [u8; 32] = ctr_data[OFF_PENDING_DIGEST..OFF_REVEALED_VALUE]
        .try_into()
        .unwrap();
    drop(ctr_data);

    let req_data = request_acct.try_borrow_data()?;
    let value =
        encrypt_native::accounts::read_decrypted_verified::<Uint64>(&req_data, &expected_digest)?;

    // Write plaintext to counter
    let mut ctr_data = counter_acct.try_borrow_mut_data()?;
    ctr_data[OFF_REVEALED_VALUE..OFF_BUMP].copy_from_slice(&value.to_le_bytes());

    msg!("Value revealed: {}", value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use encrypt_dsl::prelude::*;
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
                get_node(pg.node_bytes(), i as u16).unwrap().kind()
                    == GraphNodeKind::Output as u8
            })
            .map(|i| decode_mock_identifier(&digests[i]))
            .collect()
    }

    #[test]
    fn increment_from_zero() {
        let r = run_mock(increment_graph, &[0], &[FheType::EUint64]);
        assert_eq!(r[0], 1, "0 + 1 = 1");
    }

    #[test]
    fn increment_from_ten() {
        let r = run_mock(increment_graph, &[10], &[FheType::EUint64]);
        assert_eq!(r[0], 11, "10 + 1 = 11");
    }

    #[test]
    fn decrement_from_ten() {
        let r = run_mock(decrement_graph, &[10], &[FheType::EUint64]);
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
