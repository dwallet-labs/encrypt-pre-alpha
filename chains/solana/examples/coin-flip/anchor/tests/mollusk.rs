// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Mollusk instruction-level tests for the encrypted coin flip anchor example.
//!
//! Tests cancel_game and reveal_result in isolation.
//! Anchor uses 8-byte account discriminators (sha256 of "account:<Name>").

use mollusk_svm::Mollusk;
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

const PROGRAM_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../../../target/deploy/encrypted_coin_flip_anchor"
);

const ANCHOR_PROGRAM_ID: Pubkey = Pubkey::new_from_array(
    solana_pubkey::pubkey!("CoinF1ipAnchor11111111111111111111111111111").to_bytes(),
);

const SYSTEM_PROGRAM: Pubkey = Pubkey::new_from_array([0u8; 32]);

fn setup() -> (Mollusk, Pubkey) {
    let mollusk = Mollusk::new(&ANCHOR_PROGRAM_ID, PROGRAM_PATH);
    (mollusk, ANCHOR_PROGRAM_ID)
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

fn program_account_with_lamports(owner: &Pubkey, data: Vec<u8>, lamports: u64) -> Account {
    Account { lamports, data, owner: *owner, executable: false, rent_epoch: 0 }
}

/// Anchor cancel_game discriminator: sha256("global:cancel_game")[..8]
fn cancel_game_disc() -> [u8; 8] {
    [121, 194, 154, 118, 103, 235, 149, 52]
}

/// Anchor reveal_result discriminator: sha256("global:reveal_result")[..8]
fn reveal_result_disc() -> [u8; 8] {
    [251, 165, 27, 86, 52, 234, 133, 173]
}

/// Anchor account discriminator for Game: sha256("account:Game")[..8]
fn game_account_disc() -> [u8; 8] {
    [27, 90, 166, 125, 74, 100, 121, 18]
}

/// Anchor Game layout:
/// disc(8) + side_a(32) + game_id(32) + commit_a(32) + result_ct(32)
/// + side_b(32) + is_active(1) + played(1) + pending_digest(32) + revealed_result(1)
/// + bet_lamports(8) + bump(1)
/// = 212 bytes
const ANCHOR_GAME_LEN: usize = 8 + 32 + 32 + 32 + 32 + 32 + 1 + 1 + 32 + 1 + 8 + 1;

fn build_anchor_game(
    side_a: &Pubkey, game_id: &[u8; 32], commit_a: &Pubkey,
    result_ct: &Pubkey, side_b: &Pubkey, is_active: bool, played: bool,
    pending_digest: &[u8; 32], revealed_result: u8, bet_lamports: u64, bump: u8,
) -> Vec<u8> {
    let mut data = vec![0u8; ANCHOR_GAME_LEN];
    data[0..8].copy_from_slice(&game_account_disc());
    data[8..40].copy_from_slice(side_a.as_ref());
    data[40..72].copy_from_slice(game_id);
    data[72..104].copy_from_slice(commit_a.as_ref());
    data[104..136].copy_from_slice(result_ct.as_ref());
    data[136..168].copy_from_slice(side_b.as_ref());
    data[168] = is_active as u8;
    data[169] = played as u8;
    data[170..202].copy_from_slice(pending_digest);
    data[202] = revealed_result;
    data[203..211].copy_from_slice(&bet_lamports.to_le_bytes());
    data[211] = bump;
    data
}

fn build_decryption_request_data(ciphertext_digest: &[u8; 32], value: u64) -> Vec<u8> {
    let byte_width = 8usize;
    let mut data = vec![0u8; 2 + 105 + byte_width];
    data[0] = 3; // DISC_DECRYPTION_REQUEST
    data[1] = 1; // VERSION
    data[34..66].copy_from_slice(ciphertext_digest);
    data[98] = 4; // fhe_type = EUint64
    data[99..103].copy_from_slice(&(byte_width as u32).to_le_bytes());
    data[103..107].copy_from_slice(&(byte_width as u32).to_le_bytes());
    data[107..115].copy_from_slice(&value.to_le_bytes());
    data
}

// ── cancel_game tests ──

#[test]
fn test_cancel_game_by_side_a() {
    let (mollusk, pid) = setup();
    let side_a = Pubkey::new_unique();
    let bet = 1_000_000u64;

    let game_data = build_anchor_game(
        &side_a, &[1u8; 32], &Pubkey::new_unique(), &Pubkey::new_unique(),
        &Pubkey::new_from_array([0u8; 32]), true, false, &[0u8; 32], 0, bet, 0,
    );
    let game_key = Pubkey::new_unique();

    let r = mollusk.process_instruction(
        &Instruction::new_with_bytes(pid, &cancel_game_disc(), vec![
            AccountMeta::new(game_key, false),
            AccountMeta::new(side_a, true),
        ]),
        &[
            (game_key, program_account_with_lamports(&pid, game_data, 2_000_000)),
            (side_a, funded_account()),
        ],
    );

    assert!(r.program_result.is_ok(), "cancel by side_a should succeed");
    assert_eq!(r.resulting_accounts[0].1.data[168], 0); // closed
    assert_eq!(r.resulting_accounts[1].1.lamports, 10_000_000_000 + bet);
}

#[test]
fn test_cancel_rejects_non_creator() {
    let (mollusk, pid) = setup();
    let side_a = Pubkey::new_unique();
    let random = Pubkey::new_unique();

    let game_data = build_anchor_game(
        &side_a, &[2u8; 32], &Pubkey::new_unique(), &Pubkey::new_unique(),
        &Pubkey::new_from_array([0u8; 32]), true, false, &[0u8; 32], 0, 0, 0,
    );
    let game_key = Pubkey::new_unique();

    let r = mollusk.process_instruction(
        &Instruction::new_with_bytes(pid, &cancel_game_disc(), vec![
            AccountMeta::new(game_key, false),
            AccountMeta::new_readonly(random, true),
        ]),
        &[(game_key, program_account(&pid, game_data)), (random, funded_account())],
    );

    assert!(r.program_result.is_err(), "random caller should be rejected");
}

#[test]
fn test_cancel_rejects_after_play() {
    let (mollusk, pid) = setup();
    let side_a = Pubkey::new_unique();

    let game_data = build_anchor_game(
        &side_a, &[3u8; 32], &Pubkey::new_unique(), &Pubkey::new_unique(),
        &Pubkey::new_unique(), true, true, &[0u8; 32], 0, 0, 0,
    );
    let game_key = Pubkey::new_unique();

    let r = mollusk.process_instruction(
        &Instruction::new_with_bytes(pid, &cancel_game_disc(), vec![
            AccountMeta::new(game_key, false),
            AccountMeta::new_readonly(side_a, true),
        ]),
        &[(game_key, program_account(&pid, game_data)), (side_a, funded_account())],
    );

    assert!(r.program_result.is_err(), "can't cancel after play");
}

#[test]
fn test_cancel_rejects_already_closed() {
    let (mollusk, pid) = setup();
    let side_a = Pubkey::new_unique();

    let game_data = build_anchor_game(
        &side_a, &[4u8; 32], &Pubkey::new_unique(), &Pubkey::new_unique(),
        &Pubkey::new_from_array([0u8; 32]), false, false, &[0u8; 32], 0, 0, 0,
    );
    let game_key = Pubkey::new_unique();

    let r = mollusk.process_instruction(
        &Instruction::new_with_bytes(pid, &cancel_game_disc(), vec![
            AccountMeta::new(game_key, false),
            AccountMeta::new_readonly(side_a, true),
        ]),
        &[(game_key, program_account(&pid, game_data)), (side_a, funded_account())],
    );

    assert!(r.program_result.is_err(), "should reject already closed game");
}

#[test]
fn test_cancel_rejects_missing_signer() {
    let (mollusk, pid) = setup();
    let side_a = Pubkey::new_unique();

    let game_data = build_anchor_game(
        &side_a, &[5u8; 32], &Pubkey::new_unique(), &Pubkey::new_unique(),
        &Pubkey::new_from_array([0u8; 32]), true, false, &[0u8; 32], 0, 0, 0,
    );
    let game_key = Pubkey::new_unique();

    let r = mollusk.process_instruction(
        &Instruction::new_with_bytes(pid, &cancel_game_disc(), vec![
            AccountMeta::new(game_key, false),
            AccountMeta::new_readonly(side_a, false), // NOT signer
        ]),
        &[(game_key, program_account(&pid, game_data)), (side_a, funded_account())],
    );

    assert!(r.program_result.is_err(), "should reject missing signer");
}

// ── reveal_result tests ──

#[test]
fn test_reveal_side_a_wins() {
    let (mollusk, pid) = setup();
    let side_a = Pubkey::new_unique();
    let side_b = Pubkey::new_unique();
    let caller = Pubkey::new_unique();
    let digest = [0xABu8; 32];
    let bet = 500_000u64;

    let game_data = build_anchor_game(
        &side_a, &[6u8; 32], &Pubkey::new_unique(), &Pubkey::new_unique(),
        &side_b, true, true, &digest, 0, bet, 0,
    );
    let request_data = build_decryption_request_data(&digest, 1); // XOR=1 -> side_a wins

    let game_key = Pubkey::new_unique();
    let req_key = Pubkey::new_unique();

    let r = mollusk.process_instruction(
        &Instruction::new_with_bytes(pid, &reveal_result_disc(), vec![
            AccountMeta::new(game_key, false),
            AccountMeta::new_readonly(req_key, false),
            AccountMeta::new_readonly(caller, true),
            AccountMeta::new(side_a, false), // winner
        ]),
        &[
            (game_key, program_account_with_lamports(&pid, game_data, 2_000_000)),
            (req_key, program_account(&pid, request_data)),
            (caller, funded_account()),
            (side_a, funded_account()),
        ],
    );

    assert!(r.program_result.is_ok());
    assert_eq!(r.resulting_accounts[0].1.data[202], 1, "side_a wins");
    assert_eq!(r.resulting_accounts[3].1.lamports, 10_000_000_000 + bet * 2);
}

#[test]
fn test_reveal_side_b_wins() {
    let (mollusk, pid) = setup();
    let side_a = Pubkey::new_unique();
    let side_b = Pubkey::new_unique();
    let caller = Pubkey::new_unique();
    let digest = [0xCDu8; 32];
    let bet = 500_000u64;

    let game_data = build_anchor_game(
        &side_a, &[7u8; 32], &Pubkey::new_unique(), &Pubkey::new_unique(),
        &side_b, true, true, &digest, 0, bet, 0,
    );
    let request_data = build_decryption_request_data(&digest, 0); // XOR=0 -> side_b wins

    let game_key = Pubkey::new_unique();
    let req_key = Pubkey::new_unique();

    let r = mollusk.process_instruction(
        &Instruction::new_with_bytes(pid, &reveal_result_disc(), vec![
            AccountMeta::new(game_key, false),
            AccountMeta::new_readonly(req_key, false),
            AccountMeta::new_readonly(caller, true),
            AccountMeta::new(side_b, false), // winner
        ]),
        &[
            (game_key, program_account_with_lamports(&pid, game_data, 2_000_000)),
            (req_key, program_account(&pid, request_data)),
            (caller, funded_account()),
            (side_b, funded_account()),
        ],
    );

    assert!(r.program_result.is_ok());
    assert_eq!(r.resulting_accounts[0].1.data[202], 2, "side_b wins");
    assert_eq!(r.resulting_accounts[3].1.lamports, 10_000_000_000 + bet * 2);
}

#[test]
fn test_reveal_rejects_wrong_winner() {
    let (mollusk, pid) = setup();
    let side_a = Pubkey::new_unique();
    let side_b = Pubkey::new_unique();
    let wrong = Pubkey::new_unique();
    let digest = [0xEEu8; 32];

    let game_data = build_anchor_game(
        &side_a, &[8u8; 32], &Pubkey::new_unique(), &Pubkey::new_unique(),
        &side_b, true, true, &digest, 0, 0, 0,
    );
    let request_data = build_decryption_request_data(&digest, 1); // side_a should win

    let game_key = Pubkey::new_unique();
    let req_key = Pubkey::new_unique();

    let r = mollusk.process_instruction(
        &Instruction::new_with_bytes(pid, &reveal_result_disc(), vec![
            AccountMeta::new(game_key, false),
            AccountMeta::new_readonly(req_key, false),
            AccountMeta::new_readonly(side_a, true),
            AccountMeta::new(wrong, false), // wrong winner
        ]),
        &[
            (game_key, program_account(&pid, game_data)),
            (req_key, program_account(&pid, request_data)),
            (side_a, funded_account()),
            (wrong, funded_account()),
        ],
    );

    assert!(r.program_result.is_err(), "wrong winner should be rejected");
}

#[test]
fn test_reveal_rejects_digest_mismatch() {
    let (mollusk, pid) = setup();
    let side_a = Pubkey::new_unique();
    let side_b = Pubkey::new_unique();

    let game_data = build_anchor_game(
        &side_a, &[9u8; 32], &Pubkey::new_unique(), &Pubkey::new_unique(),
        &side_b, true, true, &[0xAAu8; 32], 0, 0, 0,
    );
    let request_data = build_decryption_request_data(&[0xBBu8; 32], 1); // different digest

    let game_key = Pubkey::new_unique();
    let req_key = Pubkey::new_unique();

    let r = mollusk.process_instruction(
        &Instruction::new_with_bytes(pid, &reveal_result_disc(), vec![
            AccountMeta::new(game_key, false),
            AccountMeta::new_readonly(req_key, false),
            AccountMeta::new_readonly(side_a, true),
            AccountMeta::new(side_a, false),
        ]),
        &[
            (game_key, program_account(&pid, game_data)),
            (req_key, program_account(&pid, request_data)),
            (side_a, funded_account()),
        ],
    );

    assert!(r.program_result.is_err(), "should reject digest mismatch");
}

#[test]
fn test_reveal_rejects_double_reveal() {
    let (mollusk, pid) = setup();
    let side_a = Pubkey::new_unique();
    let side_b = Pubkey::new_unique();
    let digest = [0xFFu8; 32];

    let game_data = build_anchor_game(
        &side_a, &[10u8; 32], &Pubkey::new_unique(), &Pubkey::new_unique(),
        &side_b, false, true, &digest, 1, 0, 0, // already revealed (1)
    );
    let request_data = build_decryption_request_data(&digest, 1);

    let game_key = Pubkey::new_unique();
    let req_key = Pubkey::new_unique();

    let r = mollusk.process_instruction(
        &Instruction::new_with_bytes(pid, &reveal_result_disc(), vec![
            AccountMeta::new(game_key, false),
            AccountMeta::new_readonly(req_key, false),
            AccountMeta::new_readonly(side_a, true),
            AccountMeta::new(side_a, false),
        ]),
        &[
            (game_key, program_account(&pid, game_data)),
            (req_key, program_account(&pid, request_data)),
            (side_a, funded_account()),
        ],
    );

    assert!(r.program_result.is_err(), "double reveal should be rejected");
}
