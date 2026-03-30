// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Mollusk instruction-level tests for the encrypted ACL example.
//!
//! Tests reveal_check and reveal_permissions in isolation (no CPI needed).

use encrypted_acl::{AccessCheck, Resource};
use mollusk_svm::Mollusk;
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

const PROGRAM_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../../../target/deploy/encrypted_acl"
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

/// Build Resource account data.
fn build_resource_data(
    admin: &Pubkey,
    resource_id: &[u8; 32],
    permissions_ct: &Pubkey,
    pending_digest: &[u8; 32],
    bump: u8,
) -> Vec<u8> {
    let mut data = vec![0u8; Resource::LEN];
    data[0] = 1; // discriminator = RESOURCE
    data[1..33].copy_from_slice(admin.as_ref());
    data[33..65].copy_from_slice(resource_id);
    data[65..97].copy_from_slice(permissions_ct.as_ref());
    data[97..129].copy_from_slice(pending_digest);
    // revealed_permissions [129..137] = 0
    data[137] = bump;
    data
}

/// Build AccessCheck account data.
fn build_access_check_data(
    checker: &Pubkey,
    result_ct: &Pubkey,
    pending_digest: &[u8; 32],
    bump: u8,
) -> Vec<u8> {
    let mut data = vec![0u8; AccessCheck::LEN];
    data[0] = 2; // discriminator = ACCESS_CHECK
    data[1..33].copy_from_slice(checker.as_ref());
    data[33..65].copy_from_slice(result_ct.as_ref());
    data[65..97].copy_from_slice(pending_digest);
    // revealed_result [97..105] = 0
    data[105] = bump;
    data
}

/// Build decryption request account data for Uint64.
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

// ── reveal_check tests ──

#[test]
fn test_reveal_check_success() {
    let (mollusk, program_id) = setup();
    let checker = Pubkey::new_unique();
    let digest = [0xABu8; 32];

    let check_data = build_access_check_data(
        &checker,
        &Pubkey::new_unique(),
        &digest,
        0,
    );
    let request_data = build_decryption_request_data(&digest, 1);

    let check_key = Pubkey::new_unique();
    let req_key = Pubkey::new_unique();

    let result = mollusk.process_instruction(
        &Instruction::new_with_bytes(
            program_id,
            &[5u8], // reveal_check
            vec![
                AccountMeta::new(check_key, false),
                AccountMeta::new_readonly(req_key, false),
                AccountMeta::new_readonly(checker, true),
            ],
        ),
        &[
            (check_key, program_account(&program_id, check_data)),
            (req_key, program_account(&program_id, request_data)),
            (checker, funded_account()),
        ],
    );

    assert!(result.program_result.is_ok(), "reveal_check should succeed");
    let revealed = u64::from_le_bytes(
        result.resulting_accounts[0].1.data[97..105].try_into().unwrap(),
    );
    assert_eq!(revealed, 1, "revealed_result should be 1");
}

#[test]
fn test_reveal_check_rejects_wrong_checker() {
    let (mollusk, program_id) = setup();
    let checker = Pubkey::new_unique();
    let wrong = Pubkey::new_unique();
    let digest = [0xCDu8; 32];

    let check_data = build_access_check_data(
        &checker,
        &Pubkey::new_unique(),
        &digest,
        0,
    );
    let request_data = build_decryption_request_data(&digest, 1);

    let check_key = Pubkey::new_unique();
    let req_key = Pubkey::new_unique();

    let result = mollusk.process_instruction(
        &Instruction::new_with_bytes(
            program_id,
            &[5u8],
            vec![
                AccountMeta::new(check_key, false),
                AccountMeta::new_readonly(req_key, false),
                AccountMeta::new_readonly(wrong, true),
            ],
        ),
        &[
            (check_key, program_account(&program_id, check_data)),
            (req_key, program_account(&program_id, request_data)),
            (wrong, funded_account()),
        ],
    );

    assert!(result.program_result.is_err(), "should reject wrong checker");
}

#[test]
fn test_reveal_check_rejects_digest_mismatch() {
    let (mollusk, program_id) = setup();
    let checker = Pubkey::new_unique();

    let check_data = build_access_check_data(
        &checker,
        &Pubkey::new_unique(),
        &[0xAAu8; 32], // stored digest
        0,
    );
    let request_data = build_decryption_request_data(&[0xBBu8; 32], 1); // different digest

    let check_key = Pubkey::new_unique();
    let req_key = Pubkey::new_unique();

    let result = mollusk.process_instruction(
        &Instruction::new_with_bytes(
            program_id,
            &[5u8],
            vec![
                AccountMeta::new(check_key, false),
                AccountMeta::new_readonly(req_key, false),
                AccountMeta::new_readonly(checker, true),
            ],
        ),
        &[
            (check_key, program_account(&program_id, check_data)),
            (req_key, program_account(&program_id, request_data)),
            (checker, funded_account()),
        ],
    );

    assert!(result.program_result.is_err(), "should reject digest mismatch");
}

// ── reveal_permissions tests ──

#[test]
fn test_reveal_permissions_success() {
    let (mollusk, program_id) = setup();
    let admin = Pubkey::new_unique();
    let digest = [0xEEu8; 32];

    let resource_data = build_resource_data(
        &admin,
        &[1u8; 32],
        &Pubkey::new_unique(),
        &digest,
        0,
    );
    let request_data = build_decryption_request_data(&digest, 7);

    let res_key = Pubkey::new_unique();
    let req_key = Pubkey::new_unique();

    let result = mollusk.process_instruction(
        &Instruction::new_with_bytes(
            program_id,
            &[7u8], // reveal_permissions
            vec![
                AccountMeta::new(res_key, false),
                AccountMeta::new_readonly(req_key, false),
                AccountMeta::new_readonly(admin, true),
            ],
        ),
        &[
            (res_key, program_account(&program_id, resource_data)),
            (req_key, program_account(&program_id, request_data)),
            (admin, funded_account()),
        ],
    );

    assert!(result.program_result.is_ok(), "reveal_permissions should succeed");
    let revealed = u64::from_le_bytes(
        result.resulting_accounts[0].1.data[129..137].try_into().unwrap(),
    );
    assert_eq!(revealed, 7, "revealed_permissions should be 7");
}

#[test]
fn test_reveal_permissions_rejects_wrong_admin() {
    let (mollusk, program_id) = setup();
    let admin = Pubkey::new_unique();
    let wrong = Pubkey::new_unique();
    let digest = [0xFFu8; 32];

    let resource_data = build_resource_data(
        &admin,
        &[2u8; 32],
        &Pubkey::new_unique(),
        &digest,
        0,
    );
    let request_data = build_decryption_request_data(&digest, 1);

    let res_key = Pubkey::new_unique();
    let req_key = Pubkey::new_unique();

    let result = mollusk.process_instruction(
        &Instruction::new_with_bytes(
            program_id,
            &[7u8],
            vec![
                AccountMeta::new(res_key, false),
                AccountMeta::new_readonly(req_key, false),
                AccountMeta::new_readonly(wrong, true),
            ],
        ),
        &[
            (res_key, program_account(&program_id, resource_data)),
            (req_key, program_account(&program_id, request_data)),
            (wrong, funded_account()),
        ],
    );

    assert!(result.program_result.is_err(), "should reject wrong admin");
}
