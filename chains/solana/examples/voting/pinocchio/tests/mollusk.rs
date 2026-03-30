// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Mollusk instruction-level tests for the confidential voting pinocchio example.
//!
//! Tests close_proposal and reveal_tally in isolation (no CPI needed).

use confidential_voting_pinocchio::Proposal;
use mollusk_svm::Mollusk;
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

const PROGRAM_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../../../target/deploy/confidential_voting_pinocchio"
);

const SYSTEM_PROGRAM: Pubkey = Pubkey::new_from_array([0u8; 32]);

fn setup() -> (Mollusk, Pubkey) {
    let program_id = Pubkey::new_unique();
    let mollusk = Mollusk::new(&program_id, PROGRAM_PATH);
    (mollusk, program_id)
}

fn funded_account() -> Account {
    Account {
        lamports: 10_000_000_000,
        data: vec![],
        owner: SYSTEM_PROGRAM,
        executable: false,
        rent_epoch: 0,
    }
}

fn program_account(owner: &Pubkey, data: Vec<u8>) -> Account {
    Account {
        lamports: 1_000_000,
        data,
        owner: *owner,
        executable: false,
        rent_epoch: 0,
    }
}

/// Build proposal account data.
fn build_proposal_data(
    authority: &Pubkey,
    proposal_id: &[u8; 32],
    yes_ct: &Pubkey,
    no_ct: &Pubkey,
    is_open: bool,
    total_votes: u64,
    bump: u8,
) -> Vec<u8> {
    let mut data = vec![0u8; Proposal::LEN];
    data[0] = 1; // discriminator = PROPOSAL
    data[1..33].copy_from_slice(authority.as_ref());
    data[33..65].copy_from_slice(proposal_id);
    data[65..97].copy_from_slice(yes_ct.as_ref());
    data[97..129].copy_from_slice(no_ct.as_ref());
    data[129] = is_open as u8;
    data[130..138].copy_from_slice(&total_votes.to_le_bytes());
    data[218] = bump;
    data
}

// ── close_proposal tests ──

#[test]
fn test_close_proposal_success() {
    let (mollusk, program_id) = setup();
    let authority = Pubkey::new_unique();
    let proposal_id = [1u8; 32];

    let proposal_data = build_proposal_data(
        &authority, &proposal_id, &Pubkey::new_unique(), &Pubkey::new_unique(), true, 5, 0,
    );
    let proposal_key = Pubkey::new_unique();

    let result = mollusk.process_instruction(
        &Instruction::new_with_bytes(
            program_id,
            &[2u8],
            vec![
                AccountMeta::new(proposal_key, false),
                AccountMeta::new_readonly(authority, true),
            ],
        ),
        &[
            (proposal_key, program_account(&program_id, proposal_data)),
            (authority, funded_account()),
        ],
    );

    assert!(result.program_result.is_ok(), "close_proposal should succeed");
    assert_eq!(result.resulting_accounts[0].1.data[129], 0, "is_open should be 0");
}

#[test]
fn test_close_proposal_rejects_wrong_authority() {
    let (mollusk, program_id) = setup();
    let authority = Pubkey::new_unique();
    let wrong = Pubkey::new_unique();

    let data = build_proposal_data(
        &authority, &[2u8; 32], &Pubkey::new_unique(), &Pubkey::new_unique(), true, 0, 0,
    );
    let key = Pubkey::new_unique();

    let result = mollusk.process_instruction(
        &Instruction::new_with_bytes(
            program_id,
            &[2u8],
            vec![
                AccountMeta::new(key, false),
                AccountMeta::new_readonly(wrong, true),
            ],
        ),
        &[
            (key, program_account(&program_id, data)),
            (wrong, funded_account()),
        ],
    );

    assert!(result.program_result.is_err(), "should reject wrong authority");
}

#[test]
fn test_close_proposal_rejects_missing_signer() {
    let (mollusk, program_id) = setup();
    let authority = Pubkey::new_unique();

    let data = build_proposal_data(
        &authority, &[3u8; 32], &Pubkey::new_unique(), &Pubkey::new_unique(), true, 0, 0,
    );
    let key = Pubkey::new_unique();

    let result = mollusk.process_instruction(
        &Instruction::new_with_bytes(
            program_id,
            &[2u8],
            vec![
                AccountMeta::new(key, false),
                AccountMeta::new_readonly(authority, false), // NOT signer
            ],
        ),
        &[
            (key, program_account(&program_id, data)),
            (authority, funded_account()),
        ],
    );

    assert!(result.program_result.is_err(), "should reject missing signer");
}

#[test]
fn test_close_proposal_rejects_already_closed() {
    let (mollusk, program_id) = setup();
    let authority = Pubkey::new_unique();

    let data = build_proposal_data(
        &authority, &[4u8; 32], &Pubkey::new_unique(), &Pubkey::new_unique(), false, 5, 0,
    );
    let key = Pubkey::new_unique();

    let result = mollusk.process_instruction(
        &Instruction::new_with_bytes(
            program_id,
            &[2u8],
            vec![
                AccountMeta::new(key, false),
                AccountMeta::new_readonly(authority, true),
            ],
        ),
        &[
            (key, program_account(&program_id, data)),
            (authority, funded_account()),
        ],
    );

    assert!(result.program_result.is_err(), "should reject already closed");
}

#[test]
fn test_close_proposal_rejects_insufficient_accounts() {
    let (mollusk, program_id) = setup();
    let authority = Pubkey::new_unique();

    let result = mollusk.process_instruction(
        &Instruction::new_with_bytes(
            program_id,
            &[2u8],
            vec![AccountMeta::new_readonly(authority, true)],
        ),
        &[(authority, funded_account())],
    );

    assert!(result.program_result.is_err(), "should reject insufficient accounts");
}

// ── reveal_tally tests ──

fn build_decryption_request_data(ciphertext_digest: &[u8; 32], value: u64) -> Vec<u8> {
    let byte_width = 8usize; // Uint64
    let mut data = vec![0u8; 2 + 105 + byte_width];
    data[0] = 3; // DISC_DECRYPTION_REQUEST
    data[1] = 1; // VERSION
    data[34..66].copy_from_slice(ciphertext_digest);
    data[98] = 4; // fhe_type = EUint64
    data[99..103].copy_from_slice(&(byte_width as u32).to_le_bytes());
    data[103..107].copy_from_slice(&(byte_width as u32).to_le_bytes()); // complete
    data[107..115].copy_from_slice(&value.to_le_bytes());
    data
}

#[test]
fn test_reveal_tally_yes() {
    let (mollusk, program_id) = setup();
    let authority = Pubkey::new_unique();
    let digest = [0xABu8; 32];

    let mut proposal_data = build_proposal_data(
        &authority, &[5u8; 32], &Pubkey::new_unique(), &Pubkey::new_unique(), false, 10, 0,
    );
    proposal_data[154..186].copy_from_slice(&digest); // pending_yes_digest

    let request_data = build_decryption_request_data(&digest, 7);
    let prop_key = Pubkey::new_unique();
    let req_key = Pubkey::new_unique();

    let result = mollusk.process_instruction(
        &Instruction::new_with_bytes(
            program_id,
            &[4u8, 1u8], // reveal_tally, is_yes=1
            vec![
                AccountMeta::new(prop_key, false),
                AccountMeta::new_readonly(req_key, false),
                AccountMeta::new_readonly(authority, true),
            ],
        ),
        &[
            (prop_key, program_account(&program_id, proposal_data)),
            (req_key, program_account(&program_id, request_data)),
            (authority, funded_account()),
        ],
    );

    assert!(result.program_result.is_ok(), "reveal_tally yes should succeed");
    let revealed = u64::from_le_bytes(
        result.resulting_accounts[0].1.data[138..146].try_into().unwrap(),
    );
    assert_eq!(revealed, 7);
}

#[test]
fn test_reveal_tally_no() {
    let (mollusk, program_id) = setup();
    let authority = Pubkey::new_unique();
    let digest = [0xCDu8; 32];

    let mut proposal_data = build_proposal_data(
        &authority, &[6u8; 32], &Pubkey::new_unique(), &Pubkey::new_unique(), false, 10, 0,
    );
    proposal_data[186..218].copy_from_slice(&digest); // pending_no_digest

    let request_data = build_decryption_request_data(&digest, 3);
    let prop_key = Pubkey::new_unique();
    let req_key = Pubkey::new_unique();

    let result = mollusk.process_instruction(
        &Instruction::new_with_bytes(
            program_id,
            &[4u8, 0u8], // reveal_tally, is_yes=0
            vec![
                AccountMeta::new(prop_key, false),
                AccountMeta::new_readonly(req_key, false),
                AccountMeta::new_readonly(authority, true),
            ],
        ),
        &[
            (prop_key, program_account(&program_id, proposal_data)),
            (req_key, program_account(&program_id, request_data)),
            (authority, funded_account()),
        ],
    );

    assert!(result.program_result.is_ok(), "reveal_tally no should succeed");
    let revealed = u64::from_le_bytes(
        result.resulting_accounts[0].1.data[146..154].try_into().unwrap(),
    );
    assert_eq!(revealed, 3);
}

#[test]
fn test_reveal_tally_rejects_wrong_authority() {
    let (mollusk, program_id) = setup();
    let authority = Pubkey::new_unique();
    let wrong = Pubkey::new_unique();
    let digest = [0xAAu8; 32];

    let mut data = build_proposal_data(
        &authority, &[7u8; 32], &Pubkey::new_unique(), &Pubkey::new_unique(), false, 0, 0,
    );
    data[154..186].copy_from_slice(&digest);

    let req = build_decryption_request_data(&digest, 1);
    let pk = Pubkey::new_unique();
    let rk = Pubkey::new_unique();

    let result = mollusk.process_instruction(
        &Instruction::new_with_bytes(
            program_id,
            &[4u8, 1u8],
            vec![
                AccountMeta::new(pk, false),
                AccountMeta::new_readonly(rk, false),
                AccountMeta::new_readonly(wrong, true),
            ],
        ),
        &[
            (pk, program_account(&program_id, data)),
            (rk, program_account(&program_id, req)),
            (wrong, funded_account()),
        ],
    );

    assert!(result.program_result.is_err(), "should reject wrong authority");
}

#[test]
fn test_reveal_tally_rejects_open_proposal() {
    let (mollusk, program_id) = setup();
    let authority = Pubkey::new_unique();
    let digest = [0xBBu8; 32];

    let mut data = build_proposal_data(
        &authority, &[8u8; 32], &Pubkey::new_unique(), &Pubkey::new_unique(), true, 0, 0,
    );
    data[154..186].copy_from_slice(&digest);

    let req = build_decryption_request_data(&digest, 1);
    let pk = Pubkey::new_unique();
    let rk = Pubkey::new_unique();

    let result = mollusk.process_instruction(
        &Instruction::new_with_bytes(
            program_id,
            &[4u8, 1u8],
            vec![
                AccountMeta::new(pk, false),
                AccountMeta::new_readonly(rk, false),
                AccountMeta::new_readonly(authority, true),
            ],
        ),
        &[
            (pk, program_account(&program_id, data)),
            (rk, program_account(&program_id, req)),
            (authority, funded_account()),
        ],
    );

    assert!(result.program_result.is_err(), "should reject open proposal");
}

#[test]
fn test_reveal_tally_rejects_digest_mismatch() {
    let (mollusk, program_id) = setup();
    let authority = Pubkey::new_unique();

    let mut data = build_proposal_data(
        &authority, &[9u8; 32], &Pubkey::new_unique(), &Pubkey::new_unique(), false, 0, 0,
    );
    data[154..186].copy_from_slice(&[0xAAu8; 32]); // stored digest

    let req = build_decryption_request_data(&[0xBBu8; 32], 1); // different digest
    let pk = Pubkey::new_unique();
    let rk = Pubkey::new_unique();

    let result = mollusk.process_instruction(
        &Instruction::new_with_bytes(
            program_id,
            &[4u8, 1u8],
            vec![
                AccountMeta::new(pk, false),
                AccountMeta::new_readonly(rk, false),
                AccountMeta::new_readonly(authority, true),
            ],
        ),
        &[
            (pk, program_account(&program_id, data)),
            (rk, program_account(&program_id, req)),
            (authority, funded_account()),
        ],
    );

    assert!(result.program_result.is_err(), "should reject digest mismatch");
}
