// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Mollusk instruction-level tests for the encrypted ACL anchor example.
//!
//! Tests reveal_check and reveal_permissions in isolation.
//! Anchor uses 8-byte account discriminators (sha256 of "account:<Name>").

use mollusk_svm::Mollusk;
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

const PROGRAM_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../../../target/deploy/encrypted_acl_anchor"
);

const ANCHOR_PROGRAM_ID: Pubkey = Pubkey::new_from_array(
    solana_pubkey::pubkey!("US517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx").to_bytes(),
);

const SYSTEM_PROGRAM: Pubkey = Pubkey::new_from_array([0u8; 32]);

// ── Anchor account sizes ──
// Resource:    disc(8) + admin(32) + resource_id(32) + permissions(32) +
//              pending_digest(32) + revealed_permissions(8) + bump(1) = 145
// AccessCheck: disc(8) + checker(32) + result_ct(32) + pending_digest(32) +
//              revealed_result(8) + bump(1) = 113
const ANCHOR_RESOURCE_LEN: usize = 8 + 32 + 32 + 32 + 32 + 8 + 1;
const ANCHOR_ACCESS_CHECK_LEN: usize = 8 + 32 + 32 + 32 + 8 + 1;

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

/// Anchor instruction discriminators.
fn reveal_check_disc() -> [u8; 8] {
    [58, 61, 62, 4, 15, 105, 45, 205]
}

fn reveal_permissions_disc() -> [u8; 8] {
    [185, 208, 237, 111, 175, 227, 51, 76]
}

/// Anchor account discriminator for Resource: sha256("account:Resource")[..8]
fn resource_account_disc() -> [u8; 8] {
    [10, 160, 2, 1, 42, 207, 51, 212]
}

/// Anchor account discriminator for AccessCheck: sha256("account:AccessCheck")[..8]
fn access_check_account_disc() -> [u8; 8] {
    [228, 121, 142, 133, 151, 223, 130, 65]
}

/// Build Anchor Resource account data.
/// Layout: disc(8) + admin(32) + resource_id(32) + permissions(32) +
///         pending_digest(32) + revealed_permissions(8) + bump(1) = 145
fn build_anchor_resource(
    admin: &Pubkey,
    resource_id: &[u8; 32],
    permissions_ct: &Pubkey,
    pending_digest: &[u8; 32],
    bump: u8,
) -> Vec<u8> {
    let mut data = vec![0u8; ANCHOR_RESOURCE_LEN];
    data[0..8].copy_from_slice(&resource_account_disc());
    data[8..40].copy_from_slice(admin.as_ref());
    data[40..72].copy_from_slice(resource_id);
    data[72..104].copy_from_slice(permissions_ct.as_ref());
    data[104..136].copy_from_slice(pending_digest);
    // revealed_permissions [136..144] = 0
    data[144] = bump;
    data
}

/// Build Anchor AccessCheck account data.
/// Layout: disc(8) + checker(32) + result_ct(32) + pending_digest(32) +
///         revealed_result(8) + bump(1) = 113
fn build_anchor_access_check(
    checker: &Pubkey,
    result_ct: &Pubkey,
    pending_digest: &[u8; 32],
    bump: u8,
) -> Vec<u8> {
    let mut data = vec![0u8; ANCHOR_ACCESS_CHECK_LEN];
    data[0..8].copy_from_slice(&access_check_account_disc());
    data[8..40].copy_from_slice(checker.as_ref());
    data[40..72].copy_from_slice(result_ct.as_ref());
    data[72..104].copy_from_slice(pending_digest);
    // revealed_result [104..112] = 0
    data[112] = bump;
    data
}

/// Build decryption request account data for Uint64.
fn build_decryption_request_data(ciphertext_digest: &[u8; 32], value: u64) -> Vec<u8> {
    let byte_width = 8usize;
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
    let (mollusk, pid) = setup();
    let checker = Pubkey::new_unique();
    let digest = [0xABu8; 32];

    let check_data = build_anchor_access_check(
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
            pid,
            &reveal_check_disc(),
            vec![
                AccountMeta::new(check_key, false),
                AccountMeta::new_readonly(req_key, false),
                AccountMeta::new_readonly(checker, true),
            ],
        ),
        &[
            (check_key, program_account(&pid, check_data)),
            (req_key, program_account(&pid, request_data)),
            (checker, funded_account()),
        ],
    );

    assert!(result.program_result.is_ok(), "reveal_check should succeed");
    // revealed_result at offset 104..112 (anchor layout)
    let revealed = u64::from_le_bytes(
        result.resulting_accounts[0].1.data[104..112].try_into().unwrap(),
    );
    assert_eq!(revealed, 1, "revealed_result should be 1");
}

#[test]
fn test_reveal_check_rejects_wrong_checker() {
    let (mollusk, pid) = setup();
    let checker = Pubkey::new_unique();
    let wrong = Pubkey::new_unique();
    let digest = [0xCDu8; 32];

    let check_data = build_anchor_access_check(
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
            pid,
            &reveal_check_disc(),
            vec![
                AccountMeta::new(check_key, false),
                AccountMeta::new_readonly(req_key, false),
                AccountMeta::new_readonly(wrong, true),
            ],
        ),
        &[
            (check_key, program_account(&pid, check_data)),
            (req_key, program_account(&pid, request_data)),
            (wrong, funded_account()),
        ],
    );

    assert!(result.program_result.is_err(), "should reject wrong checker");
}

#[test]
fn test_reveal_check_rejects_digest_mismatch() {
    let (mollusk, pid) = setup();
    let checker = Pubkey::new_unique();

    let check_data = build_anchor_access_check(
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
            pid,
            &reveal_check_disc(),
            vec![
                AccountMeta::new(check_key, false),
                AccountMeta::new_readonly(req_key, false),
                AccountMeta::new_readonly(checker, true),
            ],
        ),
        &[
            (check_key, program_account(&pid, check_data)),
            (req_key, program_account(&pid, request_data)),
            (checker, funded_account()),
        ],
    );

    assert!(result.program_result.is_err(), "should reject digest mismatch");
}

// ── reveal_permissions tests ──

#[test]
fn test_reveal_permissions_success() {
    let (mollusk, pid) = setup();
    let admin = Pubkey::new_unique();
    let digest = [0xEEu8; 32];

    let resource_data = build_anchor_resource(
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
            pid,
            &reveal_permissions_disc(),
            vec![
                AccountMeta::new(res_key, false),
                AccountMeta::new_readonly(req_key, false),
                AccountMeta::new_readonly(admin, true),
            ],
        ),
        &[
            (res_key, program_account(&pid, resource_data)),
            (req_key, program_account(&pid, request_data)),
            (admin, funded_account()),
        ],
    );

    assert!(result.program_result.is_ok(), "reveal_permissions should succeed");
    // revealed_permissions at offset 136..144 (anchor layout)
    let revealed = u64::from_le_bytes(
        result.resulting_accounts[0].1.data[136..144].try_into().unwrap(),
    );
    assert_eq!(revealed, 7, "revealed_permissions should be 7");
}

#[test]
fn test_reveal_permissions_rejects_wrong_admin() {
    let (mollusk, pid) = setup();
    let admin = Pubkey::new_unique();
    let wrong = Pubkey::new_unique();
    let digest = [0xFFu8; 32];

    let resource_data = build_anchor_resource(
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
            pid,
            &reveal_permissions_disc(),
            vec![
                AccountMeta::new(res_key, false),
                AccountMeta::new_readonly(req_key, false),
                AccountMeta::new_readonly(wrong, true),
            ],
        ),
        &[
            (res_key, program_account(&pid, resource_data)),
            (req_key, program_account(&pid, request_data)),
            (wrong, funded_account()),
        ],
    );

    assert!(result.program_result.is_err(), "should reject wrong admin");
}
