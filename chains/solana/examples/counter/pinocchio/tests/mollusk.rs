// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Mollusk instruction-level tests for the confidential counter example.
//!
//! Tests reveal_value in isolation (no CPI needed).

use confidential_counter::Counter;
use mollusk_svm::Mollusk;
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

const PROGRAM_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../../../target/deploy/confidential_counter"
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

/// Build counter account data.
fn build_counter_data(
    authority: &Pubkey,
    counter_id: &[u8; 32],
    value_ct: &Pubkey,
    bump: u8,
) -> Vec<u8> {
    let mut data = vec![0u8; Counter::LEN];
    data[0] = 1; // discriminator = COUNTER
    data[1..33].copy_from_slice(authority.as_ref());
    data[33..65].copy_from_slice(counter_id);
    data[65..97].copy_from_slice(value_ct.as_ref()); // value (EUint64 = pubkey)
    // pending_digest at [97..129] = zeros
    // revealed_value at [129..137] = zeros
    data[137] = bump;
    data
}

/// Build counter data with a pending digest set.
fn build_counter_data_with_digest(
    authority: &Pubkey,
    counter_id: &[u8; 32],
    value_ct: &Pubkey,
    pending_digest: &[u8; 32],
    bump: u8,
) -> Vec<u8> {
    let mut data = build_counter_data(authority, counter_id, value_ct, bump);
    data[97..129].copy_from_slice(pending_digest);
    data
}

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

// ── reveal_value tests ──

#[test]
fn test_reveal_value_success() {
    let (mollusk, program_id) = setup();
    let authority = Pubkey::new_unique();
    let digest = [0xABu8; 32];

    let counter_data = build_counter_data_with_digest(
        &authority,
        &[1u8; 32],
        &Pubkey::new_unique(),
        &digest,
        0,
    );

    let request_data = build_decryption_request_data(&digest, 42);
    let counter_key = Pubkey::new_unique();
    let req_key = Pubkey::new_unique();

    let result = mollusk.process_instruction(
        &Instruction::new_with_bytes(
            program_id,
            &[4u8], // reveal_value
            vec![
                AccountMeta::new(counter_key, false),
                AccountMeta::new_readonly(req_key, false),
                AccountMeta::new_readonly(authority, true),
            ],
        ),
        &[
            (counter_key, program_account(&program_id, counter_data)),
            (req_key, program_account(&program_id, request_data)),
            (authority, funded_account()),
        ],
    );

    assert!(result.program_result.is_ok(), "reveal_value should succeed");
    let revealed = u64::from_le_bytes(
        result.resulting_accounts[0].1.data[129..137].try_into().unwrap(),
    );
    assert_eq!(revealed, 42);
}

#[test]
fn test_reveal_value_rejects_wrong_authority() {
    let (mollusk, program_id) = setup();
    let authority = Pubkey::new_unique();
    let wrong = Pubkey::new_unique();
    let digest = [0xCDu8; 32];

    let counter_data = build_counter_data_with_digest(
        &authority,
        &[2u8; 32],
        &Pubkey::new_unique(),
        &digest,
        0,
    );

    let request_data = build_decryption_request_data(&digest, 1);
    let counter_key = Pubkey::new_unique();
    let req_key = Pubkey::new_unique();

    let result = mollusk.process_instruction(
        &Instruction::new_with_bytes(
            program_id,
            &[4u8],
            vec![
                AccountMeta::new(counter_key, false),
                AccountMeta::new_readonly(req_key, false),
                AccountMeta::new_readonly(wrong, true),
            ],
        ),
        &[
            (counter_key, program_account(&program_id, counter_data)),
            (req_key, program_account(&program_id, request_data)),
            (wrong, funded_account()),
        ],
    );

    assert!(result.program_result.is_err(), "should reject wrong authority");
}

#[test]
fn test_reveal_value_rejects_missing_signer() {
    let (mollusk, program_id) = setup();
    let authority = Pubkey::new_unique();
    let digest = [0xEFu8; 32];

    let counter_data = build_counter_data_with_digest(
        &authority,
        &[3u8; 32],
        &Pubkey::new_unique(),
        &digest,
        0,
    );

    let request_data = build_decryption_request_data(&digest, 1);
    let counter_key = Pubkey::new_unique();
    let req_key = Pubkey::new_unique();

    let result = mollusk.process_instruction(
        &Instruction::new_with_bytes(
            program_id,
            &[4u8],
            vec![
                AccountMeta::new(counter_key, false),
                AccountMeta::new_readonly(req_key, false),
                AccountMeta::new_readonly(authority, false), // NOT signer
            ],
        ),
        &[
            (counter_key, program_account(&program_id, counter_data)),
            (req_key, program_account(&program_id, request_data)),
            (authority, funded_account()),
        ],
    );

    assert!(result.program_result.is_err(), "should reject missing signer");
}

#[test]
fn test_reveal_value_rejects_digest_mismatch() {
    let (mollusk, program_id) = setup();
    let authority = Pubkey::new_unique();

    let counter_data = build_counter_data_with_digest(
        &authority,
        &[4u8; 32],
        &Pubkey::new_unique(),
        &[0xAAu8; 32], // stored digest
        0,
    );

    let request_data = build_decryption_request_data(&[0xBBu8; 32], 1); // different digest
    let counter_key = Pubkey::new_unique();
    let req_key = Pubkey::new_unique();

    let result = mollusk.process_instruction(
        &Instruction::new_with_bytes(
            program_id,
            &[4u8],
            vec![
                AccountMeta::new(counter_key, false),
                AccountMeta::new_readonly(req_key, false),
                AccountMeta::new_readonly(authority, true),
            ],
        ),
        &[
            (counter_key, program_account(&program_id, counter_data)),
            (req_key, program_account(&program_id, request_data)),
            (authority, funded_account()),
        ],
    );

    assert!(result.program_result.is_err(), "should reject digest mismatch");
}
