// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Mollusk instruction-level tests for the confidential voting native example.
//!
//! Tests close_proposal and reveal_tally in isolation (no CPI needed).

use mollusk_svm::Mollusk;
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

const PROGRAM_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../../../target/deploy/confidential_voting_native"
);

const PROPOSAL_LEN: usize = 219;
const SYSTEM_PROGRAM: Pubkey = Pubkey::new_from_array([0u8; 32]);

fn setup() -> (Mollusk, Pubkey) {
    let program_id = Pubkey::new_unique();
    let mollusk = Mollusk::new(&program_id, PROGRAM_PATH);
    (mollusk, program_id)
}

fn funded_account() -> Account {
    Account { lamports: 10_000_000_000, data: vec![], owner: SYSTEM_PROGRAM, executable: false, rent_epoch: 0 }
}

fn program_account(owner: &Pubkey, data: Vec<u8>) -> Account {
    Account { lamports: 1_000_000, data, owner: *owner, executable: false, rent_epoch: 0 }
}

/// Native proposal layout:
/// disc(1) auth(32) proposal_id(32) yes_ct(32) no_ct(32) is_open(1)
/// total_votes(8) revealed_yes(8) revealed_no(8) pending_yes_digest(32) pending_no_digest(32) bump(1)
/// Offsets: 0, 1, 33, 65, 97, 129, 130, 138, 146, 154(!=155 see note), 186, 218
/// NOTE: native code reads pending_yes at 155..187 and pending_no at 187..219 (off-by-one from
/// the struct layout). We match the actual code behavior here.
fn build_proposal_data(authority: &Pubkey, proposal_id: &[u8; 32], is_open: bool, total_votes: u64) -> Vec<u8> {
    let mut data = vec![0u8; PROPOSAL_LEN];
    data[0] = 1; // PROPOSAL
    data[1..33].copy_from_slice(authority.as_ref());
    data[33..65].copy_from_slice(proposal_id);
    data[129] = is_open as u8;
    data[130..138].copy_from_slice(&total_votes.to_le_bytes());
    data
}

fn build_decryption_request_data(digest: &[u8; 32], value: u64) -> Vec<u8> {
    let bw = 8usize;
    let mut data = vec![0u8; 2 + 105 + bw];
    data[0] = 3; // DISC_DECRYPTION_REQUEST
    data[1] = 1; // VERSION
    data[34..66].copy_from_slice(digest);
    data[98] = 4; // fhe_type = EUint64
    data[99..103].copy_from_slice(&(bw as u32).to_le_bytes());
    data[103..107].copy_from_slice(&(bw as u32).to_le_bytes()); // complete
    data[107..115].copy_from_slice(&value.to_le_bytes());
    data
}

// ── close_proposal ──

#[test]
fn test_close_proposal_success() {
    let (mollusk, pid) = setup();
    let auth = Pubkey::new_unique();
    let prop = build_proposal_data(&auth, &[1u8; 32], true, 5);
    let pk = Pubkey::new_unique();

    let r = mollusk.process_instruction(
        &Instruction::new_with_bytes(pid, &[2u8], vec![
            AccountMeta::new(pk, false), AccountMeta::new_readonly(auth, true),
        ]),
        &[(pk, program_account(&pid, prop)), (auth, funded_account())],
    );
    assert!(r.program_result.is_ok());
    assert_eq!(r.resulting_accounts[0].1.data[129], 0);
}

#[test]
fn test_close_proposal_rejects_wrong_authority() {
    let (mollusk, pid) = setup();
    let auth = Pubkey::new_unique();
    let wrong = Pubkey::new_unique();
    let prop = build_proposal_data(&auth, &[2u8; 32], true, 0);
    let pk = Pubkey::new_unique();

    let r = mollusk.process_instruction(
        &Instruction::new_with_bytes(pid, &[2u8], vec![
            AccountMeta::new(pk, false), AccountMeta::new_readonly(wrong, true),
        ]),
        &[(pk, program_account(&pid, prop)), (wrong, funded_account())],
    );
    assert!(r.program_result.is_err());
}

#[test]
fn test_close_proposal_rejects_already_closed() {
    let (mollusk, pid) = setup();
    let auth = Pubkey::new_unique();
    let prop = build_proposal_data(&auth, &[3u8; 32], false, 0);
    let pk = Pubkey::new_unique();

    let r = mollusk.process_instruction(
        &Instruction::new_with_bytes(pid, &[2u8], vec![
            AccountMeta::new(pk, false), AccountMeta::new_readonly(auth, true),
        ]),
        &[(pk, program_account(&pid, prop)), (auth, funded_account())],
    );
    assert!(r.program_result.is_err());
}

#[test]
fn test_close_proposal_rejects_missing_signer() {
    let (mollusk, pid) = setup();
    let auth = Pubkey::new_unique();
    let prop = build_proposal_data(&auth, &[4u8; 32], true, 0);
    let pk = Pubkey::new_unique();

    let r = mollusk.process_instruction(
        &Instruction::new_with_bytes(pid, &[2u8], vec![
            AccountMeta::new(pk, false), AccountMeta::new_readonly(auth, false),
        ]),
        &[(pk, program_account(&pid, prop)), (auth, funded_account())],
    );
    assert!(r.program_result.is_err());
}

// ── reveal_tally ──

#[test]
fn test_reveal_tally_yes() {
    let (mollusk, pid) = setup();
    let auth = Pubkey::new_unique();
    let digest = [0xABu8; 32];
    let mut prop = build_proposal_data(&auth, &[5u8; 32], false, 10);
    // Native reads pending_yes_digest at 155..187
    prop[155..187].copy_from_slice(&digest);

    let req = build_decryption_request_data(&digest, 7);
    let pk = Pubkey::new_unique();
    let rk = Pubkey::new_unique();

    let r = mollusk.process_instruction(
        &Instruction::new_with_bytes(pid, &[4u8, 1u8], vec![
            AccountMeta::new(pk, false), AccountMeta::new_readonly(rk, false),
            AccountMeta::new_readonly(auth, true),
        ]),
        &[
            (pk, program_account(&pid, prop)),
            (rk, program_account(&pid, req)),
            (auth, funded_account()),
        ],
    );
    assert!(r.program_result.is_ok(), "reveal yes should succeed");
    let revealed = u64::from_le_bytes(r.resulting_accounts[0].1.data[138..146].try_into().unwrap());
    assert_eq!(revealed, 7);
}

#[test]
fn test_reveal_tally_no() {
    let (mollusk, pid) = setup();
    let auth = Pubkey::new_unique();
    let digest = [0xCDu8; 32];
    let mut prop = build_proposal_data(&auth, &[6u8; 32], false, 10);
    // Native reads pending_no_digest at 187..219
    prop[187..219].copy_from_slice(&digest);

    let req = build_decryption_request_data(&digest, 3);
    let pk = Pubkey::new_unique();
    let rk = Pubkey::new_unique();

    let r = mollusk.process_instruction(
        &Instruction::new_with_bytes(pid, &[4u8, 0u8], vec![
            AccountMeta::new(pk, false), AccountMeta::new_readonly(rk, false),
            AccountMeta::new_readonly(auth, true),
        ]),
        &[
            (pk, program_account(&pid, prop)),
            (rk, program_account(&pid, req)),
            (auth, funded_account()),
        ],
    );
    assert!(r.program_result.is_ok(), "reveal no should succeed");
    let revealed = u64::from_le_bytes(r.resulting_accounts[0].1.data[146..154].try_into().unwrap());
    assert_eq!(revealed, 3);
}

#[test]
fn test_reveal_tally_rejects_wrong_authority() {
    let (mollusk, pid) = setup();
    let auth = Pubkey::new_unique();
    let wrong = Pubkey::new_unique();
    let digest = [0xAAu8; 32];
    let mut prop = build_proposal_data(&auth, &[7u8; 32], false, 0);
    prop[155..187].copy_from_slice(&digest);

    let req = build_decryption_request_data(&digest, 1);
    let pk = Pubkey::new_unique();
    let rk = Pubkey::new_unique();

    let r = mollusk.process_instruction(
        &Instruction::new_with_bytes(pid, &[4u8, 1u8], vec![
            AccountMeta::new(pk, false), AccountMeta::new_readonly(rk, false),
            AccountMeta::new_readonly(wrong, true),
        ]),
        &[
            (pk, program_account(&pid, prop)),
            (rk, program_account(&pid, req)),
            (wrong, funded_account()),
        ],
    );
    assert!(r.program_result.is_err());
}

#[test]
fn test_reveal_tally_rejects_open_proposal() {
    let (mollusk, pid) = setup();
    let auth = Pubkey::new_unique();
    let digest = [0xBBu8; 32];
    let mut prop = build_proposal_data(&auth, &[8u8; 32], true, 0);
    prop[155..187].copy_from_slice(&digest);

    let req = build_decryption_request_data(&digest, 1);
    let pk = Pubkey::new_unique();
    let rk = Pubkey::new_unique();

    let r = mollusk.process_instruction(
        &Instruction::new_with_bytes(pid, &[4u8, 1u8], vec![
            AccountMeta::new(pk, false), AccountMeta::new_readonly(rk, false),
            AccountMeta::new_readonly(auth, true),
        ]),
        &[
            (pk, program_account(&pid, prop)),
            (rk, program_account(&pid, req)),
            (auth, funded_account()),
        ],
    );
    assert!(r.program_result.is_err());
}

#[test]
fn test_reveal_tally_rejects_digest_mismatch() {
    let (mollusk, pid) = setup();
    let auth = Pubkey::new_unique();
    let mut prop = build_proposal_data(&auth, &[9u8; 32], false, 0);
    prop[155..187].copy_from_slice(&[0xAAu8; 32]);

    let req = build_decryption_request_data(&[0xBBu8; 32], 1); // different digest
    let pk = Pubkey::new_unique();
    let rk = Pubkey::new_unique();

    let r = mollusk.process_instruction(
        &Instruction::new_with_bytes(pid, &[4u8, 1u8], vec![
            AccountMeta::new(pk, false), AccountMeta::new_readonly(rk, false),
            AccountMeta::new_readonly(auth, true),
        ]),
        &[
            (pk, program_account(&pid, prop)),
            (rk, program_account(&pid, req)),
            (auth, funded_account()),
        ],
    );
    assert!(r.program_result.is_err());
}
