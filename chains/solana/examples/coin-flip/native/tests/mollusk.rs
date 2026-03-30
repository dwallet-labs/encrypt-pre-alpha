// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Mollusk tests for encrypted coin flip native — cancel_game and reveal_result.

use mollusk_svm::Mollusk;
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

const PROGRAM_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../../../target/deploy/encrypted_coin_flip_native"
);

/// Native Game layout:
/// disc(1) + side_a(32) + game_id(32) + commit_a(32) + result_ct(32)
/// + side_b(32) + is_active(1) + played(1) + pending_digest(32) + revealed_result(1)
/// + bet_lamports(8) + bump(1)
/// = 205 bytes
const GAME_LEN: usize = 205;

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

fn program_account_with_lamports(owner: &Pubkey, data: Vec<u8>, lamports: u64) -> Account {
    Account { lamports, data, owner: *owner, executable: false, rent_epoch: 0 }
}

fn build_game_data(
    side_a: &Pubkey, game_id: &[u8; 32], commit_a: &Pubkey,
    result_ct: &Pubkey, side_b: &Pubkey, is_active: bool, played: bool,
    pending_digest: &[u8; 32], revealed_result: u8, bet_lamports: u64, bump: u8,
) -> Vec<u8> {
    let mut data = vec![0u8; GAME_LEN];
    data[0] = 1; // GAME discriminator
    data[1..33].copy_from_slice(side_a.as_ref());
    data[33..65].copy_from_slice(game_id);
    data[65..97].copy_from_slice(commit_a.as_ref());
    data[97..129].copy_from_slice(result_ct.as_ref());
    data[129..161].copy_from_slice(side_b.as_ref());
    data[161] = is_active as u8;
    data[162] = played as u8;
    data[163..195].copy_from_slice(pending_digest);
    data[195] = revealed_result;
    data[196..204].copy_from_slice(&bet_lamports.to_le_bytes());
    data[204] = bump;
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

// ── cancel_game (disc 4) ──

#[test]
fn test_cancel_game_by_side_a() {
    let (mollusk, pid) = setup();
    let side_a = Pubkey::new_unique();
    let bet = 1_000_000u64;

    let game_data = build_game_data(
        &side_a, &[1u8; 32], &Pubkey::new_unique(), &Pubkey::new_unique(),
        &Pubkey::new_from_array([0u8; 32]), true, false, &[0u8; 32], 0, bet, 0,
    );
    let game_key = Pubkey::new_unique();

    let result = mollusk.process_instruction(
        &Instruction::new_with_bytes(pid, &[4u8], vec![
            AccountMeta::new(game_key, false),
            AccountMeta::new(side_a, true),
        ]),
        &[
            (game_key, program_account_with_lamports(&pid, game_data, 2_000_000)),
            (side_a, funded_account()),
        ],
    );

    assert!(result.program_result.is_ok());
    assert_eq!(result.resulting_accounts[0].1.data[161], 0, "should be inactive");
    // Side A should get bet refunded
    assert_eq!(result.resulting_accounts[1].1.lamports, 10_000_000_000 + bet);
}

#[test]
fn test_cancel_rejects_non_creator() {
    let (mollusk, pid) = setup();
    let side_a = Pubkey::new_unique();
    let random = Pubkey::new_unique();

    let game_data = build_game_data(
        &side_a, &[2u8; 32], &Pubkey::new_unique(), &Pubkey::new_unique(),
        &Pubkey::new_from_array([0u8; 32]), true, false, &[0u8; 32], 0, 0, 0,
    );
    let game_key = Pubkey::new_unique();

    let result = mollusk.process_instruction(
        &Instruction::new_with_bytes(pid, &[4u8], vec![
            AccountMeta::new(game_key, false),
            AccountMeta::new_readonly(random, true),
        ]),
        &[
            (game_key, program_account(&pid, game_data)),
            (random, funded_account()),
        ],
    );

    assert!(result.program_result.is_err());
}

#[test]
fn test_cancel_rejects_after_play() {
    let (mollusk, pid) = setup();
    let side_a = Pubkey::new_unique();

    let game_data = build_game_data(
        &side_a, &[3u8; 32], &Pubkey::new_unique(), &Pubkey::new_unique(),
        &Pubkey::new_unique(), true, true, &[0u8; 32], 0, 0, 0,
    );
    let game_key = Pubkey::new_unique();

    let result = mollusk.process_instruction(
        &Instruction::new_with_bytes(pid, &[4u8], vec![
            AccountMeta::new(game_key, false),
            AccountMeta::new_readonly(side_a, true),
        ]),
        &[
            (game_key, program_account(&pid, game_data)),
            (side_a, funded_account()),
        ],
    );

    assert!(result.program_result.is_err(), "can't cancel after play");
}

// ── reveal_result (disc 3) ──

#[test]
fn test_reveal_side_a_wins() {
    let (mollusk, pid) = setup();
    let side_a = Pubkey::new_unique();
    let side_b = Pubkey::new_unique();
    let caller = Pubkey::new_unique();
    let digest = [0xABu8; 32];
    let bet = 500_000u64;

    let game_data = build_game_data(
        &side_a, &[4u8; 32], &Pubkey::new_unique(), &Pubkey::new_unique(),
        &side_b, true, true, &digest, 0, bet, 0,
    );
    let req_data = build_decryption_request_data(&digest, 1); // XOR=1 -> side_a wins
    let game_key = Pubkey::new_unique();
    let req_key = Pubkey::new_unique();

    let result = mollusk.process_instruction(
        &Instruction::new_with_bytes(pid, &[3u8], vec![
            AccountMeta::new(game_key, false),
            AccountMeta::new_readonly(req_key, false),
            AccountMeta::new_readonly(caller, true),
            AccountMeta::new(side_a, false), // winner
        ]),
        &[
            (game_key, program_account_with_lamports(&pid, game_data, 2_000_000)),
            (req_key, program_account(&pid, req_data)),
            (caller, funded_account()),
            (side_a, funded_account()),
        ],
    );

    assert!(result.program_result.is_ok());
    assert_eq!(result.resulting_accounts[0].1.data[195], 1, "side_a wins");
    assert_eq!(result.resulting_accounts[3].1.lamports, 10_000_000_000 + bet * 2);
}

#[test]
fn test_reveal_side_b_wins() {
    let (mollusk, pid) = setup();
    let side_a = Pubkey::new_unique();
    let side_b = Pubkey::new_unique();
    let caller = Pubkey::new_unique();
    let digest = [0xCDu8; 32];
    let bet = 500_000u64;

    let game_data = build_game_data(
        &side_a, &[5u8; 32], &Pubkey::new_unique(), &Pubkey::new_unique(),
        &side_b, true, true, &digest, 0, bet, 0,
    );
    let req_data = build_decryption_request_data(&digest, 0); // XOR=0 -> side_b wins
    let game_key = Pubkey::new_unique();
    let req_key = Pubkey::new_unique();

    let result = mollusk.process_instruction(
        &Instruction::new_with_bytes(pid, &[3u8], vec![
            AccountMeta::new(game_key, false),
            AccountMeta::new_readonly(req_key, false),
            AccountMeta::new_readonly(caller, true),
            AccountMeta::new(side_b, false), // winner
        ]),
        &[
            (game_key, program_account_with_lamports(&pid, game_data, 2_000_000)),
            (req_key, program_account(&pid, req_data)),
            (caller, funded_account()),
            (side_b, funded_account()),
        ],
    );

    assert!(result.program_result.is_ok());
    assert_eq!(result.resulting_accounts[0].1.data[195], 2, "side_b wins");
    assert_eq!(result.resulting_accounts[3].1.lamports, 10_000_000_000 + bet * 2);
}

#[test]
fn test_reveal_rejects_wrong_winner() {
    let (mollusk, pid) = setup();
    let side_a = Pubkey::new_unique();
    let side_b = Pubkey::new_unique();
    let wrong = Pubkey::new_unique();
    let digest = [0xEEu8; 32];

    let game_data = build_game_data(
        &side_a, &[6u8; 32], &Pubkey::new_unique(), &Pubkey::new_unique(),
        &side_b, true, true, &digest, 0, 0, 0,
    );
    let req_data = build_decryption_request_data(&digest, 1); // side_a should win
    let game_key = Pubkey::new_unique();
    let req_key = Pubkey::new_unique();

    let result = mollusk.process_instruction(
        &Instruction::new_with_bytes(pid, &[3u8], vec![
            AccountMeta::new(game_key, false),
            AccountMeta::new_readonly(req_key, false),
            AccountMeta::new_readonly(side_a, true),
            AccountMeta::new(wrong, false), // wrong winner
        ]),
        &[
            (game_key, program_account(&pid, game_data)),
            (req_key, program_account(&pid, req_data)),
            (side_a, funded_account()),
            (wrong, funded_account()),
        ],
    );

    assert!(result.program_result.is_err(), "wrong winner should be rejected");
}

#[test]
fn test_reveal_rejects_digest_mismatch() {
    let (mollusk, pid) = setup();
    let side_a = Pubkey::new_unique();
    let side_b = Pubkey::new_unique();

    let game_data = build_game_data(
        &side_a, &[7u8; 32], &Pubkey::new_unique(), &Pubkey::new_unique(),
        &side_b, true, true, &[0xAAu8; 32], 0, 0, 0,
    );
    let req_data = build_decryption_request_data(&[0xBBu8; 32], 1);
    let game_key = Pubkey::new_unique();
    let req_key = Pubkey::new_unique();

    let result = mollusk.process_instruction(
        &Instruction::new_with_bytes(pid, &[3u8], vec![
            AccountMeta::new(game_key, false),
            AccountMeta::new_readonly(req_key, false),
            AccountMeta::new_readonly(side_a, true),
            AccountMeta::new(side_a, false),
        ]),
        &[
            (game_key, program_account(&pid, game_data)),
            (req_key, program_account(&pid, req_data)),
            (side_a, funded_account()),
        ],
    );

    assert!(result.program_result.is_err(), "digest mismatch should be rejected");
}

#[test]
fn test_reveal_rejects_double_reveal() {
    let (mollusk, pid) = setup();
    let side_a = Pubkey::new_unique();
    let side_b = Pubkey::new_unique();
    let digest = [0xFFu8; 32];

    let game_data = build_game_data(
        &side_a, &[8u8; 32], &Pubkey::new_unique(), &Pubkey::new_unique(),
        &side_b, false, true, &digest, 1, 0, 0, // already revealed (1)
    );
    let req_data = build_decryption_request_data(&digest, 1);
    let game_key = Pubkey::new_unique();
    let req_key = Pubkey::new_unique();

    let result = mollusk.process_instruction(
        &Instruction::new_with_bytes(pid, &[3u8], vec![
            AccountMeta::new(game_key, false),
            AccountMeta::new_readonly(req_key, false),
            AccountMeta::new_readonly(side_a, true),
            AccountMeta::new(side_a, false),
        ]),
        &[
            (game_key, program_account(&pid, game_data)),
            (req_key, program_account(&pid, req_data)),
            (side_a, funded_account()),
        ],
    );

    assert!(result.program_result.is_err(), "double reveal should be rejected");
}
