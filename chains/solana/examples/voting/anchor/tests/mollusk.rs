// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Mollusk instruction-level tests for the confidential voting anchor example.
//!
//! Tests close_proposal and reveal_tally in isolation.
//! Anchor uses 8-byte account discriminators (sha256 of "account:<Name>").

use mollusk_svm::Mollusk;
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

const PROGRAM_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../../../target/deploy/confidential_voting_anchor"
);

const ANCHOR_PROGRAM_ID: Pubkey = Pubkey::new_from_array(
    solana_pubkey::pubkey!("VotingAnchor1111111111111111111111111111111").to_bytes(),
);

const SYSTEM_PROGRAM: Pubkey = Pubkey::new_from_array([0u8; 32]);

fn setup() -> (Mollusk, Pubkey) {
    let mollusk = Mollusk::new(&ANCHOR_PROGRAM_ID, PROGRAM_PATH);
    (mollusk, ANCHOR_PROGRAM_ID)
}

fn funded_account() -> Account {
    Account { lamports: 10_000_000_000, data: vec![], owner: SYSTEM_PROGRAM, executable: false, rent_epoch: 0 }
}

fn program_account(owner: &Pubkey, data: Vec<u8>) -> Account {
    Account { lamports: 1_000_000, data, owner: *owner, executable: false, rent_epoch: 0 }
}

/// Anchor close_proposal discriminator
fn close_proposal_disc() -> [u8; 8] {
    [213, 178, 139, 19, 50, 191, 82, 245]
}

/// Anchor reveal_tally discriminator
fn reveal_tally_disc() -> [u8; 8] {
    [70, 209, 50, 65, 190, 116, 226, 125]
}

/// Build Anchor Proposal account data.
/// Anchor layout: disc(8) + authority(32) + proposal_id(32) + yes_count(32) + no_count(32) +
///   is_open(1) + total_votes(8) + revealed_yes(8) + revealed_no(8) +
///   pending_yes_digest(32) + pending_no_digest(32) + bump(1)
/// = 8 + 226 = 234 bytes
const ANCHOR_PROPOSAL_LEN: usize = 8 + 32 + 32 + 32 + 32 + 1 + 8 + 8 + 8 + 32 + 32 + 1;

/// Anchor account discriminator for Proposal (sha256("account:Proposal")[..8])
fn proposal_account_disc() -> [u8; 8] {
    // This is computed by Anchor at compile time. We hardcode it here.
    // anchor_lang::prelude::Account uses sha256("account:Proposal")
    [26, 94, 189, 187, 116, 136, 53, 33]
}

fn build_anchor_proposal(
    authority: &Pubkey,
    proposal_id: &[u8; 32],
    is_open: bool,
    total_votes: u64,
) -> Vec<u8> {
    let mut data = vec![0u8; ANCHOR_PROPOSAL_LEN];
    data[0..8].copy_from_slice(&proposal_account_disc());
    data[8..40].copy_from_slice(authority.as_ref());
    data[40..72].copy_from_slice(proposal_id);
    // yes_count [72..104], no_count [104..136] — zeroed
    data[136] = is_open as u8;
    data[137..145].copy_from_slice(&total_votes.to_le_bytes());
    // revealed_yes [145..153], revealed_no [153..161] — zeroed
    // pending_yes_digest [161..193], pending_no_digest [193..225] — zeroed
    // bump [225]
    data
}

fn build_decryption_request_data(digest: &[u8; 32], value: u64) -> Vec<u8> {
    let bw = 8usize;
    let mut data = vec![0u8; 2 + 105 + bw];
    data[0] = 3;
    data[1] = 1;
    data[34..66].copy_from_slice(digest);
    data[98] = 4;
    data[99..103].copy_from_slice(&(bw as u32).to_le_bytes());
    data[103..107].copy_from_slice(&(bw as u32).to_le_bytes());
    data[107..115].copy_from_slice(&value.to_le_bytes());
    data
}

// ── close_proposal ──

#[test]
fn test_close_proposal_success() {
    let (mollusk, pid) = setup();
    let auth = Pubkey::new_unique();
    let prop = build_anchor_proposal(&auth, &[1u8; 32], true, 5);
    let pk = Pubkey::new_unique();

    let r = mollusk.process_instruction(
        &Instruction::new_with_bytes(pid, &close_proposal_disc(), vec![
            AccountMeta::new(pk, false), AccountMeta::new_readonly(auth, true),
        ]),
        &[(pk, program_account(&pid, prop)), (auth, funded_account())],
    );
    assert!(r.program_result.is_ok(), "close should succeed");
    assert_eq!(r.resulting_accounts[0].1.data[136], 0);
}

#[test]
fn test_close_proposal_rejects_wrong_authority() {
    let (mollusk, pid) = setup();
    let auth = Pubkey::new_unique();
    let wrong = Pubkey::new_unique();
    let prop = build_anchor_proposal(&auth, &[2u8; 32], true, 0);
    let pk = Pubkey::new_unique();

    let r = mollusk.process_instruction(
        &Instruction::new_with_bytes(pid, &close_proposal_disc(), vec![
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
    let prop = build_anchor_proposal(&auth, &[3u8; 32], false, 0);
    let pk = Pubkey::new_unique();

    let r = mollusk.process_instruction(
        &Instruction::new_with_bytes(pid, &close_proposal_disc(), vec![
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
    let prop = build_anchor_proposal(&auth, &[4u8; 32], true, 0);
    let pk = Pubkey::new_unique();

    let r = mollusk.process_instruction(
        &Instruction::new_with_bytes(pid, &close_proposal_disc(), vec![
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
    let mut prop = build_anchor_proposal(&auth, &[5u8; 32], false, 10);
    // pending_yes_digest at offset 161..193
    prop[161..193].copy_from_slice(&digest);

    let req = build_decryption_request_data(&digest, 7);
    let pk = Pubkey::new_unique();
    let rk = Pubkey::new_unique();

    // Anchor reveal_tally data: disc(8) + is_yes(1 = bool true, Borsh: 1)
    let mut ix_data = Vec::with_capacity(9);
    ix_data.extend_from_slice(&reveal_tally_disc());
    ix_data.push(1); // is_yes = true

    let r = mollusk.process_instruction(
        &Instruction::new_with_bytes(pid, &ix_data, vec![
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
    let revealed = u64::from_le_bytes(r.resulting_accounts[0].1.data[145..153].try_into().unwrap());
    assert_eq!(revealed, 7);
}

#[test]
fn test_reveal_tally_no() {
    let (mollusk, pid) = setup();
    let auth = Pubkey::new_unique();
    let digest = [0xCDu8; 32];
    let mut prop = build_anchor_proposal(&auth, &[6u8; 32], false, 10);
    // pending_no_digest at offset 193..225
    prop[193..225].copy_from_slice(&digest);

    let req = build_decryption_request_data(&digest, 3);
    let pk = Pubkey::new_unique();
    let rk = Pubkey::new_unique();

    let mut ix_data = Vec::with_capacity(9);
    ix_data.extend_from_slice(&reveal_tally_disc());
    ix_data.push(0); // is_yes = false

    let r = mollusk.process_instruction(
        &Instruction::new_with_bytes(pid, &ix_data, vec![
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
    let revealed = u64::from_le_bytes(r.resulting_accounts[0].1.data[153..161].try_into().unwrap());
    assert_eq!(revealed, 3);
}

#[test]
fn test_reveal_tally_rejects_wrong_authority() {
    let (mollusk, pid) = setup();
    let auth = Pubkey::new_unique();
    let wrong = Pubkey::new_unique();
    let digest = [0xEEu8; 32];
    let mut prop = build_anchor_proposal(&auth, &[7u8; 32], false, 0);
    prop[161..193].copy_from_slice(&digest);

    let req = build_decryption_request_data(&digest, 1);
    let pk = Pubkey::new_unique();
    let rk = Pubkey::new_unique();

    let mut ix_data = Vec::with_capacity(9);
    ix_data.extend_from_slice(&reveal_tally_disc());
    ix_data.push(1);

    let r = mollusk.process_instruction(
        &Instruction::new_with_bytes(pid, &ix_data, vec![
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
    let digest = [0xFFu8; 32];
    let mut prop = build_anchor_proposal(&auth, &[8u8; 32], true, 0);
    prop[161..193].copy_from_slice(&digest);

    let req = build_decryption_request_data(&digest, 1);
    let pk = Pubkey::new_unique();
    let rk = Pubkey::new_unique();

    let mut ix_data = Vec::with_capacity(9);
    ix_data.extend_from_slice(&reveal_tally_disc());
    ix_data.push(1);

    let r = mollusk.process_instruction(
        &Instruction::new_with_bytes(pid, &ix_data, vec![
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
