// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Confidential Voting — Native solana-program version.
//!
//! Same FHE voting logic as the Pinocchio example, but uses solana-program's
//! `AccountInfo` and `EncryptContext` for CPI.

use encrypt_dsl::prelude::encrypt_fn;
use encrypt_native::EncryptContext;
use encrypt_types::encrypted::{EBool, EUint64, Uint64};
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

// ── Account discriminators ──

const PROPOSAL: u8 = 1;
const VOTE_RECORD: u8 = 2;

// ── Account sizes ──

const PROPOSAL_LEN: usize = 1 + 32 + 32 + 32 + 32 + 1 + 8 + 8 + 8 + 32 + 32 + 1; // 219
const VOTE_RECORD_LEN: usize = 1 + 32 + 1; // 34

// ── FHE Graph ──

#[encrypt_fn]
fn cast_vote_graph(
    yes_count: EUint64,
    no_count: EUint64,
    vote: EBool,
) -> (EUint64, EUint64) {
    let new_yes = if vote { yes_count + 1 } else { yes_count };
    let new_no = if vote { no_count } else { no_count + 1 };
    (new_yes, new_no)
}

// ── Entrypoint ──

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    match data.first() {
        Some(&0) => create_proposal(program_id, accounts, &data[1..]),
        Some(&1) => cast_vote(program_id, accounts, &data[1..]),
        Some(&2) => close_proposal(accounts),
        Some(&3) => request_tally_decryption(accounts, &data[1..]),
        Some(&4) => reveal_tally(accounts, &data[1..]),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

// ── 0: create_proposal ──

fn create_proposal(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    let iter = &mut accounts.iter();
    let proposal = next_account_info(iter)?;
    let authority = next_account_info(iter)?;
    let yes_ct = next_account_info(iter)?;
    let no_ct = next_account_info(iter)?;
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

    let proposal_bump = data[0];
    let cpi_authority_bump = data[1];
    let proposal_id: [u8; 32] = data[2..34].try_into().unwrap();

    let seeds = &[b"proposal".as_ref(), proposal_id.as_ref(), &[proposal_bump]];
    let rent = Rent::get()?;
    let lamports = rent.minimum_balance(PROPOSAL_LEN);

    invoke_signed(
        &system_instruction::create_account(payer.key, proposal.key, lamports, PROPOSAL_LEN as u64, program_id),
        &[payer.clone(), proposal.clone(), system_program.clone()],
        &[seeds],
    )?;

    // Create encrypted zeros via CPI
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

    ctx.create_plaintext_typed::<Uint64>(&0u64, yes_ct)?;
    ctx.create_plaintext_typed::<Uint64>(&0u64, no_ct)?;

    // Write proposal state — store ciphertext account pubkeys
    let mut d = proposal.try_borrow_mut_data()?;
    d[0] = PROPOSAL;
    d[1..33].copy_from_slice(authority.key.as_ref());
    d[33..65].copy_from_slice(&proposal_id);
    d[65..97].copy_from_slice(yes_ct.key.as_ref());
    d[97..129].copy_from_slice(no_ct.key.as_ref());
    d[129] = 1; // is_open
    d[130..138].copy_from_slice(&0u64.to_le_bytes()); // total_votes
    // revealed_yes(138..146), revealed_no(146..154) already zeroed
    // pending_yes_digest(154..186), pending_no_digest(186..218) already zeroed
    d[218] = proposal_bump;

    msg!("Proposal created");
    Ok(())
}

// ── 1: cast_vote ──

fn cast_vote(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let iter = &mut accounts.iter();
    let proposal = next_account_info(iter)?;
    let vote_record = next_account_info(iter)?;
    let voter = next_account_info(iter)?;
    let vote_ct = next_account_info(iter)?;
    let yes_ct = next_account_info(iter)?;
    let no_ct = next_account_info(iter)?;
    let encrypt_program = next_account_info(iter)?;
    let config = next_account_info(iter)?;
    let deposit = next_account_info(iter)?;
    let cpi_authority = next_account_info(iter)?;
    let caller_program = next_account_info(iter)?;
    let network_encryption_key = next_account_info(iter)?;
    let payer = next_account_info(iter)?;
    let event_authority = next_account_info(iter)?;
    let system_program = next_account_info(iter)?;

    if !voter.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if data.len() < 2 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let vote_record_bump = data[0];
    let cpi_authority_bump = data[1];

    // Read proposal state
    let prop_data = proposal.try_borrow_data()?;
    if prop_data[0] != PROPOSAL || prop_data[129] == 0 {
        return Err(ProgramError::InvalidArgument);
    }
    let proposal_id: [u8; 32] = prop_data[33..65].try_into().unwrap();
    let total_votes = u64::from_le_bytes(prop_data[130..138].try_into().unwrap());
    drop(prop_data);

    // Create vote record (prevents double-voting)
    let vr_seeds = &[
        b"vote".as_ref(),
        proposal_id.as_ref(),
        voter.key.as_ref(),
        &[vote_record_bump],
    ];
    let rent = Rent::get()?;
    invoke_signed(
        &system_instruction::create_account(
            payer.key,
            vote_record.key,
            rent.minimum_balance(VOTE_RECORD_LEN),
            VOTE_RECORD_LEN as u64,
            program_id,
        ),
        &[payer.clone(), vote_record.clone(), system_program.clone()],
        &[vr_seeds],
    )?;
    {
        let mut vr = vote_record.try_borrow_mut_data()?;
        vr[0] = VOTE_RECORD;
        vr[1..33].copy_from_slice(voter.key.as_ref());
        vr[33] = vote_record_bump;
    }

    // Execute FHE computation via CPI
    // Remaining accounts: inputs [yes_ct, no_ct, vote_ct] + outputs [yes_ct, no_ct] (update mode)
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

    ctx.cast_vote_graph(
        yes_ct.clone(), no_ct.clone(), vote_ct.clone(),
        yes_ct.clone(), no_ct.clone(),
    )?;

    // Increment total votes — yes/no ciphertext accounts are unchanged (same pubkeys)
    let mut prop_data = proposal.try_borrow_mut_data()?;
    prop_data[130..138].copy_from_slice(&(total_votes + 1).to_le_bytes());

    msg!("Vote cast, total: {}", total_votes + 1);
    Ok(())
}

// ── 2: close_proposal ──

fn close_proposal(accounts: &[AccountInfo]) -> ProgramResult {
    let iter = &mut accounts.iter();
    let proposal = next_account_info(iter)?;
    let authority = next_account_info(iter)?;

    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let mut d = proposal.try_borrow_mut_data()?;
    if d[0] != PROPOSAL {
        return Err(ProgramError::InvalidAccountData);
    }
    if &d[1..33] != authority.key.as_ref() {
        return Err(ProgramError::InvalidArgument);
    }
    if d[129] == 0 {
        return Err(ProgramError::InvalidArgument);
    }
    d[129] = 0;

    msg!("Proposal closed");
    Ok(())
}

// ── 3: request_tally_decryption ──

fn request_tally_decryption(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let iter = &mut accounts.iter();
    let proposal = next_account_info(iter)?;
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

    if data.len() < 2 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let cpi_authority_bump = data[0];
    let is_yes = data[1] != 0;

    let prop_data = proposal.try_borrow_data()?;
    if prop_data[0] != PROPOSAL || prop_data[129] != 0 {
        return Err(ProgramError::InvalidArgument); // must be closed
    }

    drop(prop_data);

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

    // request_decryption returns the ciphertext_digest — store it for reveal verification
    let digest = ctx.request_decryption(request_acct, ciphertext)?;

    let mut prop_data = proposal.try_borrow_mut_data()?;
    if is_yes {
        prop_data[155..187].copy_from_slice(&digest);
    } else {
        prop_data[187..219].copy_from_slice(&digest);
    }

    Ok(())
}

// ── 4: reveal_tally ──

fn reveal_tally(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let iter = &mut accounts.iter();
    let proposal = next_account_info(iter)?;
    let request_acct = next_account_info(iter)?;
    let authority = next_account_info(iter)?;

    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }

    let is_yes = data[0] != 0;

    let prop_data = proposal.try_borrow_data()?;
    if prop_data[0] != PROPOSAL {
        return Err(ProgramError::InvalidAccountData);
    }
    if &prop_data[1..33] != authority.key.as_ref() {
        return Err(ProgramError::InvalidArgument);
    }
    if prop_data[129] != 0 {
        return Err(ProgramError::InvalidArgument); // must be closed
    }

    // Read digest stored at request_decryption time
    let expected_digest: [u8; 32] = if is_yes {
        prop_data[155..187].try_into().unwrap()
    } else {
        prop_data[187..219].try_into().unwrap()
    };
    drop(prop_data);

    let req_data = request_acct.try_borrow_data()?;
    use encrypt_types::encrypted::Uint64;
    let value = encrypt_native::accounts::read_decrypted_verified::<Uint64>(&req_data, &expected_digest)?;

    let mut prop_data = proposal.try_borrow_mut_data()?;
    if is_yes {
        prop_data[138..146].copy_from_slice(&value.to_le_bytes());
    } else {
        prop_data[146..154].copy_from_slice(&value.to_le_bytes());
    }

    msg!("Tally revealed: {}", value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use encrypt_dsl::prelude::*;
    use encrypt_types::graph::{get_node, parse_graph, GraphNodeKind};
    use encrypt_types::identifier::*;
    use encrypt_types::types::FheType;

    use super::cast_vote_graph;

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

    #[test]
    fn vote_yes_increments_yes_count() {
        let r = run_mock(cast_vote_graph, &[10, 5, 1],
            &[FheType::EUint64, FheType::EUint64, FheType::EBool]);
        assert_eq!(r[0], 11);
        assert_eq!(r[1], 5);
    }

    #[test]
    fn vote_no_increments_no_count() {
        let r = run_mock(cast_vote_graph, &[10, 5, 0],
            &[FheType::EUint64, FheType::EUint64, FheType::EBool]);
        assert_eq!(r[0], 10);
        assert_eq!(r[1], 6);
    }

    #[test]
    fn vote_from_zero() {
        let r = run_mock(cast_vote_graph, &[0, 0, 1],
            &[FheType::EUint64, FheType::EUint64, FheType::EBool]);
        assert_eq!(r[0], 1);
        assert_eq!(r[1], 0);
    }

    #[test]
    fn graph_shape() {
        let d = cast_vote_graph();
        let pg = parse_graph(&d).unwrap();
        assert_eq!(pg.header().num_inputs(), 3);
        assert_eq!(pg.header().num_outputs(), 2);
    }
}
