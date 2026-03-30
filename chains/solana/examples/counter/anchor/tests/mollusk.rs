// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Mollusk instruction-level tests for the confidential counter anchor example.
//!
//! Tests reveal_value in isolation (no CPI needed).
//! Anchor uses 8-byte account discriminators (sha256 of "account:<Name>").

use mollusk_svm::Mollusk;
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

const PROGRAM_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../../../target/deploy/confidential_counter_anchor"
);

const ANCHOR_PROGRAM_ID: Pubkey = Pubkey::new_from_array(
    solana_pubkey::pubkey!("CntAnchr111111111111111111111111111111111111").to_bytes(),
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

/// Anchor reveal_value discriminator: sha256("global:reveal_value")[..8]
fn reveal_value_disc() -> [u8; 8] {
    [183, 128, 71, 133, 188, 49, 57, 213]
}

/// Anchor account discriminator for Counter: sha256("account:Counter")[..8]
fn counter_account_disc() -> [u8; 8] {
    [255, 176, 4, 245, 188, 253, 124, 25]
}

// Anchor Counter layout:
// disc(8) + authority(32) + counter_id(32) + value(32) + pending_digest(32) + revealed_value(8) + bump(1)
// = 145 bytes
const ANCHOR_COUNTER_LEN: usize = 8 + 32 + 32 + 32 + 32 + 8 + 1;

// Field offsets (including 8-byte Anchor discriminator)
const OFF_AUTHORITY: usize = 8;
const OFF_COUNTER_ID: usize = 40;
const OFF_VALUE: usize = 72;
const OFF_PENDING_DIGEST: usize = 104;
const OFF_REVEALED_VALUE: usize = 136;
const OFF_BUMP: usize = 144;

/// Build Anchor Counter account data.
fn build_anchor_counter(
    authority: &Pubkey,
    counter_id: &[u8; 32],
    value_ct: &Pubkey,
    bump: u8,
) -> Vec<u8> {
    let mut data = vec![0u8; ANCHOR_COUNTER_LEN];
    data[0..8].copy_from_slice(&counter_account_disc());
    data[OFF_AUTHORITY..OFF_COUNTER_ID].copy_from_slice(authority.as_ref());
    data[OFF_COUNTER_ID..OFF_VALUE].copy_from_slice(counter_id);
    data[OFF_VALUE..OFF_PENDING_DIGEST].copy_from_slice(value_ct.as_ref());
    // pending_digest [104..136] = zeros
    // revealed_value [136..144] = zeros
    data[OFF_BUMP] = bump;
    data
}

/// Build Anchor Counter account data with a pending digest set.
fn build_anchor_counter_with_digest(
    authority: &Pubkey,
    counter_id: &[u8; 32],
    value_ct: &Pubkey,
    pending_digest: &[u8; 32],
    bump: u8,
) -> Vec<u8> {
    let mut data = build_anchor_counter(authority, counter_id, value_ct, bump);
    data[OFF_PENDING_DIGEST..OFF_REVEALED_VALUE].copy_from_slice(pending_digest);
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
    let (mollusk, pid) = setup();
    let authority = Pubkey::new_unique();
    let digest = [0xABu8; 32];

    let counter_data = build_anchor_counter_with_digest(
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
            pid,
            &reveal_value_disc(),
            vec![
                AccountMeta::new(counter_key, false),
                AccountMeta::new_readonly(req_key, false),
                AccountMeta::new_readonly(authority, true),
            ],
        ),
        &[
            (counter_key, program_account(&pid, counter_data)),
            (req_key, program_account(&pid, request_data)),
            (authority, funded_account()),
        ],
    );

    assert!(result.program_result.is_ok(), "reveal_value should succeed");
    let revealed = u64::from_le_bytes(
        result.resulting_accounts[0].1.data[OFF_REVEALED_VALUE..OFF_BUMP].try_into().unwrap(),
    );
    assert_eq!(revealed, 42);
}

#[test]
fn test_reveal_value_rejects_wrong_authority() {
    let (mollusk, pid) = setup();
    let authority = Pubkey::new_unique();
    let wrong = Pubkey::new_unique();
    let digest = [0xCDu8; 32];

    let counter_data = build_anchor_counter_with_digest(
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
            pid,
            &reveal_value_disc(),
            vec![
                AccountMeta::new(counter_key, false),
                AccountMeta::new_readonly(req_key, false),
                AccountMeta::new_readonly(wrong, true),
            ],
        ),
        &[
            (counter_key, program_account(&pid, counter_data)),
            (req_key, program_account(&pid, request_data)),
            (wrong, funded_account()),
        ],
    );

    assert!(result.program_result.is_err(), "should reject wrong authority");
}

#[test]
fn test_reveal_value_rejects_missing_signer() {
    let (mollusk, pid) = setup();
    let authority = Pubkey::new_unique();
    let digest = [0xEFu8; 32];

    let counter_data = build_anchor_counter_with_digest(
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
            pid,
            &reveal_value_disc(),
            vec![
                AccountMeta::new(counter_key, false),
                AccountMeta::new_readonly(req_key, false),
                AccountMeta::new_readonly(authority, false), // NOT signer
            ],
        ),
        &[
            (counter_key, program_account(&pid, counter_data)),
            (req_key, program_account(&pid, request_data)),
            (authority, funded_account()),
        ],
    );

    assert!(result.program_result.is_err(), "should reject missing signer");
}

#[test]
fn test_reveal_value_rejects_digest_mismatch() {
    let (mollusk, pid) = setup();
    let authority = Pubkey::new_unique();

    let counter_data = build_anchor_counter_with_digest(
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
            pid,
            &reveal_value_disc(),
            vec![
                AccountMeta::new(counter_key, false),
                AccountMeta::new_readonly(req_key, false),
                AccountMeta::new_readonly(authority, true),
            ],
        ),
        &[
            (counter_key, program_account(&pid, counter_data)),
            (req_key, program_account(&pid, request_data)),
            (authority, funded_account()),
        ],
    );

    assert!(result.program_result.is_err(), "should reject digest mismatch");
}
