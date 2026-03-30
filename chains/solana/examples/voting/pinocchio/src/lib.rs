// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#![allow(unexpected_cfgs)]

/// Confidential Voting — A Solana program using the Encrypt DSL.
///
/// On-chain voting where individual votes are encrypted. Nobody can see
/// how anyone voted, but the final tally is computed via FHE and can be
/// decrypted by the proposal authority.
///
/// ## Accounts
///
/// - `Proposal` PDA (`["proposal", proposal_id]`): proposal state with encrypted tallies
/// - `VoteRecord` PDA (`["vote", proposal_id, voter]`): prevents double-voting
///
/// ## Instructions
///
/// 0. `create_proposal` — create a new proposal with zeroed encrypted tallies
/// 1. `cast_vote` — add an encrypted vote (1 or 0) to the tally
/// 2. `close_proposal` — authority closes voting
///
/// ## FHE Design
///
/// Each vote is an encrypted boolean (EBool): 1 = yes, 0 = no.
/// The tally is kept as two EUint64 counters: `yes_count` and `no_count`.
/// When a voter casts a vote, the graph conditionally increments one counter:
///   - If vote == 1: yes_count += 1, no_count unchanged
///   - If vote == 0: no_count += 1, yes_count unchanged
///
/// After closing, the authority can request decryption of the tallies.
use encrypt_dsl::prelude::encrypt_fn;
use encrypt_pinocchio::accounts::{self, DecryptionRequestStatus};
use encrypt_pinocchio::EncryptContext;
use encrypt_types::encrypted::{EBool, EUint64, Uint64};
use pinocchio::{
    cpi::{Seed, Signer},
    entrypoint,
    error::ProgramError,
    AccountView, Address, ProgramResult,
};
use pinocchio_system::instructions::CreateAccount;

entrypoint!(process_instruction);

pub const ID: Address = Address::new_from_array([3u8; 32]);

// ── Account discriminators ──

const PROPOSAL: u8 = 1;
const VOTE_RECORD: u8 = 2;

// ── Account layouts ──

/// Proposal state — PDA seeds: `["proposal", proposal_id]`
///
/// `yes_count` and `no_count` are encrypted counters (EUint64).
/// The chain never sees the actual tallies until decryption.
#[repr(C)]
pub struct Proposal {
    pub discriminator: u8,
    pub authority: [u8; 32],
    pub proposal_id: [u8; 32],
    pub yes_count: EUint64,
    pub no_count: EUint64,
    pub is_open: u8,
    pub total_votes: [u8; 8],          // plaintext total (yes+no) for transparency
    pub revealed_yes: [u8; 8],         // plaintext yes count (written after decryption)
    pub revealed_no: [u8; 8],          // plaintext no count (written after decryption)
    pub pending_yes_digest: [u8; 32],  // digest stored at request_decryption time
    pub pending_no_digest: [u8; 32],   // digest stored at request_decryption time
    pub bump: u8,
}

impl Proposal {
    pub const LEN: usize = core::mem::size_of::<Self>();

    pub fn from_bytes(data: &[u8]) -> Result<&Self, ProgramError> {
        if data.len() < Self::LEN || data[0] != PROPOSAL {
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

    pub fn total_votes(&self) -> u64 {
        u64::from_le_bytes(self.total_votes)
    }

    pub fn set_total_votes(&mut self, val: u64) {
        self.total_votes = val.to_le_bytes();
    }
}

/// Vote record — PDA seeds: `["vote", proposal_id, voter]`
///
/// Existence of this account proves the voter already voted.
/// Contains no vote data — the vote is only in the encrypted tally.
#[repr(C)]
pub struct VoteRecord {
    pub discriminator: u8,
    pub voter: [u8; 32],
    pub bump: u8,
}

impl VoteRecord {
    pub const LEN: usize = core::mem::size_of::<Self>();
}

// ── Rent helper ──

fn minimum_balance(size: usize) -> u64 {
    (size as u64 + 128) * 6960
}

// ── FHE Graphs ──

/// Cast vote: conditionally increment yes or no counter.
///
/// Cast vote: conditionally increment yes or no counter.
///
/// If vote is true: yes += 1, no unchanged.
/// If vote is false: no += 1, yes unchanged.
///
/// The literal `1` is auto-promoted to an encrypted constant in the graph.
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

// ── Instruction dispatch ──

fn process_instruction(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    match data.split_first() {
        Some((&0, rest)) => create_proposal(program_id, accounts, rest),
        Some((&1, rest)) => cast_vote(program_id, accounts, rest),
        Some((&2, _rest)) => close_proposal(accounts),
        Some((&3, rest)) => request_tally_decryption(accounts, rest),
        Some((&4, rest)) => reveal_tally(accounts, rest),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

// ── 0: create_proposal ──
// data: proposal_bump(1) | cpi_authority_bump(1) | proposal_id(32)
// accounts: [proposal_pda(w), authority(s),
//            yes_ct(w), no_ct(w),
//            encrypt_program, config, deposit(w), cpi_authority,
//            caller_program, network_encryption_key, payer(s,w),
//            event_authority, system_program]
//
// Creates the proposal and two encrypted-zero ciphertexts (yes_count, no_count)
// in a single transaction via create_plaintext CPI.

fn create_proposal(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    let [proposal_acct, authority, yes_ct, no_ct, encrypt_program, config, deposit, cpi_authority, caller_program, network_encryption_key, payer, event_authority, system_program, ..] =
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

    let proposal_bump = data[0];
    let cpi_authority_bump = data[1];
    let proposal_id: [u8; 32] = data[2..34].try_into().unwrap();

    // Create proposal PDA
    let bump_byte = [proposal_bump];
    let seeds = [
        Seed::from(b"proposal" as &[u8]),
        Seed::from(proposal_id.as_ref()),
        Seed::from(&bump_byte),
    ];
    let signer = [Signer::from(&seeds)];

    CreateAccount {
        from: payer,
        to: proposal_acct,
        lamports: minimum_balance(Proposal::LEN),
        space: Proposal::LEN as u64,
        owner: program_id,
    }
    .invoke_signed(&signer)?;

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
    let d = unsafe { proposal_acct.borrow_unchecked_mut() };
    let prop = Proposal::from_bytes_mut(d)?;
    prop.discriminator = PROPOSAL;
    prop.authority.copy_from_slice(authority.address().as_ref());
    prop.proposal_id.copy_from_slice(&proposal_id);
    prop.yes_count = EUint64::from_le_bytes(*yes_ct.address().as_array());
    prop.no_count = EUint64::from_le_bytes(*no_ct.address().as_array());
    prop.is_open = 1;
    prop.set_total_votes(0);
    prop.revealed_yes = [0u8; 8];
    prop.revealed_no = [0u8; 8];
    prop.bump = proposal_bump;
    Ok(())
}

// ── 1: cast_vote ──
// data: vote_record_bump(1) | cpi_authority_bump(1)
// accounts: [proposal(w), vote_record_pda(w), voter(s), vote_ct,
//            yes_ct(w), no_ct(w),
//            encrypt_program, config, deposit(w), cpi_authority,
//            caller_program, network_encryption_key, payer(s,w),
//            event_authority, system_program]
//
// The voter provides their encrypted vote ciphertext account.
// yes_ct and no_ct are passed as both inputs and outputs (update mode).

fn cast_vote(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [proposal_acct, vote_record_acct, voter, vote_ct, yes_ct, no_ct, encrypt_program, config, deposit, cpi_authority, caller_program, network_encryption_key, payer, event_authority, system_program, ..] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !voter.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if data.len() < 2 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let vote_record_bump = data[0];
    let cpi_authority_bump = data[1];

    // Verify proposal is open
    let prop_data = unsafe { proposal_acct.borrow_unchecked() };
    let prop = Proposal::from_bytes(prop_data)?;
    if prop.is_open == 0 {
        return Err(ProgramError::InvalidArgument);
    }
    let proposal_id = prop.proposal_id;

    // Create vote record PDA (prevents double-voting — CreateAccount fails if exists)
    let vr_bump_byte = [vote_record_bump];
    let vr_seeds = [
        Seed::from(b"vote" as &[u8]),
        Seed::from(proposal_id.as_ref()),
        Seed::from(voter.address().as_ref()),
        Seed::from(&vr_bump_byte),
    ];
    let vr_signer = [Signer::from(&vr_seeds)];

    CreateAccount {
        from: payer,
        to: vote_record_acct,
        lamports: minimum_balance(VoteRecord::LEN),
        space: VoteRecord::LEN as u64,
        owner: program_id,
    }
    .invoke_signed(&vr_signer)?;

    let vr_data = unsafe { vote_record_acct.borrow_unchecked_mut() };
    vr_data[0] = VOTE_RECORD;
    vr_data[1..33].copy_from_slice(voter.address().as_ref());
    vr_data[33] = vote_record_bump;

    // Execute encrypted vote computation via CPI
    // Remaining accounts: inputs [yes_ct, no_ct, vote_ct] + outputs [yes_ct, no_ct]
    // yes_ct and no_ct appear as both input and output (update mode — resets digest/status)
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

    ctx.cast_vote_graph(yes_ct, no_ct, vote_ct, yes_ct, no_ct)?;

    // Increment total votes — yes_count/no_count accounts are unchanged (same pubkeys)
    let prop_data_mut = unsafe { proposal_acct.borrow_unchecked_mut() };
    let prop_mut = Proposal::from_bytes_mut(prop_data_mut)?;
    prop_mut.set_total_votes(prop_mut.total_votes() + 1);

    Ok(())
}

// ── 2: close_proposal ──
// accounts: [proposal(w), authority(s)]

fn close_proposal(accounts: &[AccountView]) -> ProgramResult {
    let [proposal_acct, authority, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let prop_data = unsafe { proposal_acct.borrow_unchecked_mut() };
    let prop = Proposal::from_bytes_mut(prop_data)?;

    if authority.address().as_array() != &prop.authority {
        return Err(ProgramError::InvalidArgument);
    }
    if prop.is_open == 0 {
        return Err(ProgramError::InvalidArgument); // already closed
    }

    prop.is_open = 0;
    Ok(())
}

// ── 3: request_tally_decryption ──
// data: cpi_authority_bump(1) | is_yes(1)
// accounts: [proposal(w), request_acct(w), ciphertext,
//            encrypt_program, config, deposit(w), cpi_authority,
//            caller_program, network_encryption_key, payer(s,w),
//            event_authority, system_program]
//
// Authority requests decryption of yes_count or no_count after closing.
// Stores the ciphertext_digest in the proposal for verification at reveal time.

fn request_tally_decryption(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [proposal_acct, request_acct, ciphertext, encrypt_program, config, deposit, cpi_authority, caller_program, network_encryption_key, payer, event_authority, system_program, ..] =
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
    let is_yes = data[1] != 0;

    // Verify proposal is closed
    let prop_data = unsafe { proposal_acct.borrow_unchecked() };
    let prop = Proposal::from_bytes(prop_data)?;
    if prop.is_open != 0 {
        return Err(ProgramError::InvalidArgument); // must be closed first
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

    // request_decryption returns the ciphertext_digest — store it for reveal verification
    let digest = ctx.request_decryption(request_acct, ciphertext)?;

    let prop_data_mut = unsafe { proposal_acct.borrow_unchecked_mut() };
    let prop_mut = Proposal::from_bytes_mut(prop_data_mut)?;
    if is_yes {
        prop_mut.pending_yes_digest = digest;
    } else {
        prop_mut.pending_no_digest = digest;
    }

    Ok(())
}

// ── 4: reveal_tally ──
// data: is_yes(1) (1=write to revealed_yes, 0=write to revealed_no)
// accounts: [proposal(w), request_acct, authority(s)]
//
// Authority reads the completed decryption result and writes the plaintext
// value to the proposal. Verifies digest against the one stored at request time.

fn reveal_tally(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [proposal_acct, request_acct, authority, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }

    let is_yes = data[0] != 0;

    // Verify authority
    let prop_data = unsafe { proposal_acct.borrow_unchecked() };
    let prop = Proposal::from_bytes(prop_data)?;
    if authority.address().as_array() != &prop.authority {
        return Err(ProgramError::InvalidArgument);
    }
    if prop.is_open != 0 {
        return Err(ProgramError::InvalidArgument);
    }

    // Verify against the digest stored at request_decryption time
    let expected_digest = if is_yes {
        &prop.pending_yes_digest
    } else {
        &prop.pending_no_digest
    };

    let req_data = unsafe { request_acct.borrow_unchecked() };
    let value: &u64 = accounts::read_decrypted_verified::<Uint64>(req_data, expected_digest)?;

    // Write plaintext to proposal
    let prop_data_mut = unsafe { proposal_acct.borrow_unchecked_mut() };
    let prop_mut = Proposal::from_bytes_mut(prop_data_mut)?;
    if is_yes {
        prop_mut.revealed_yes = value.to_le_bytes();
    } else {
        prop_mut.revealed_no = value.to_le_bytes();
    }

    Ok(())
}

// ── Tests ──

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
    fn vote_yes_increments_yes_count() {
        // yes=10, no=5, vote=1 (true)
        let r = run_mock(
            cast_vote_graph,
            &[10, 5, 1],
            &[FheType::EUint64, FheType::EUint64, FheType::EBool],
        );
        assert_eq!(r[0], 11, "yes_count should be 11 after voting yes");
        assert_eq!(r[1], 5, "no_count should remain 5");
    }

    #[test]
    fn vote_no_increments_no_count() {
        // yes=10, no=5, vote=0 (false)
        let r = run_mock(
            cast_vote_graph,
            &[10, 5, 0],
            &[FheType::EUint64, FheType::EUint64, FheType::EBool],
        );
        assert_eq!(r[0], 10, "yes_count should remain 10 after voting no");
        assert_eq!(r[1], 6, "no_count should be 6");
    }

    #[test]
    fn vote_from_zero() {
        // yes=0, no=0, vote=1
        let r = run_mock(
            cast_vote_graph,
            &[0, 0, 1],
            &[FheType::EUint64, FheType::EUint64, FheType::EBool],
        );
        assert_eq!(r[0], 1, "first yes vote");
        assert_eq!(r[1], 0, "no count stays 0");
    }

    #[test]
    fn graph_shape() {
        let d = cast_vote_graph();
        let pg = parse_graph(&d).unwrap();
        assert_eq!(pg.header().num_inputs(), 3, "yes_count + no_count + vote");
        assert_eq!(pg.header().num_outputs(), 2, "new_yes + new_no");
    }
}
