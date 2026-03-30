// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! LiteSVM end-to-end tests for the encrypted ACL anchor example.
//!
//! Uses Anchor's instruction discriminator scheme: first 8 bytes of sha256("global:<name>").

use encrypt_dsl::prelude::encrypt_fn;
use encrypt_solana_test::litesvm::EncryptTestContext;
use encrypt_types::encrypted::{EUint64, Uint64};
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Keypair;
use solana_sdk::signer::Signer;

const EXAMPLE_PROGRAM_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../../../target/deploy/encrypted_acl_anchor.so"
);

/// Anchor program ID must match declare_id! in the anchor lib.rs.
const ANCHOR_PROGRAM_ID: &str = "US517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx";

// ── Graph functions (needed for off-chain evaluation) ──

#[encrypt_fn]
fn grant_permission_graph(permissions: EUint64, permission_bit: EUint64) -> EUint64 {
    permissions | permission_bit
}

#[encrypt_fn]
fn revoke_permission_graph(permissions: EUint64, revoke_mask: EUint64) -> EUint64 {
    permissions & revoke_mask
}

#[encrypt_fn]
fn check_permission_graph(permissions: EUint64, permission_bit: EUint64) -> EUint64 {
    permissions & permission_bit
}

/// Anchor instruction discriminators: first 8 bytes of sha256("global:<name>").
fn anchor_disc(name: &str) -> [u8; 8] {
    match name {
        "create_resource" => [42, 4, 153, 170, 163, 159, 188, 194],
        "grant_permission" => [50, 6, 1, 242, 15, 73, 99, 164],
        "revoke_permission" => [116, 82, 33, 181, 121, 144, 249, 227],
        "check_permission" => [154, 199, 232, 242, 96, 72, 197, 236],
        "request_check_decryption" => [27, 97, 232, 56, 79, 216, 202, 32],
        "reveal_check" => [58, 61, 62, 4, 15, 105, 45, 205],
        "request_permissions_decryption" => [153, 50, 149, 80, 126, 243, 34, 19],
        "reveal_permissions" => [185, 208, 237, 111, 175, 227, 51, 76],
        _ => panic!("unknown anchor instruction: {name}"),
    }
}

fn setup_anchor_program(ctx: &mut EncryptTestContext) -> (Pubkey, Pubkey, u8) {
    let program_id = Pubkey::try_from(ANCHOR_PROGRAM_ID).unwrap();
    ctx.deploy_program_at(&program_id, EXAMPLE_PROGRAM_PATH);
    let (cpi_authority, cpi_bump) = ctx.cpi_authority_for(&program_id);
    (program_id, cpi_authority, cpi_bump)
}

/// Build create_resource instruction with Anchor encoding.
/// Anchor ix data: disc(8) + resource_id(32) + permissions_ct_id(32)
fn create_resource_ix(
    program_id: &Pubkey,
    resource_pda: &Pubkey,
    resource_id: &[u8; 32],
    permissions_ct_id: &Pubkey,
    admin: &Pubkey,
    payer: &Pubkey,
) -> Instruction {
    let mut data = Vec::with_capacity(8 + 32 + 32);
    data.extend_from_slice(&anchor_disc("create_resource"));
    data.extend_from_slice(resource_id);
    data.extend_from_slice(permissions_ct_id.as_ref());

    Instruction::new_with_bytes(
        *program_id,
        &data,
        vec![
            AccountMeta::new(*resource_pda, false),
            AccountMeta::new_readonly(*admin, true),
            AccountMeta::new(*payer, true),
            AccountMeta::new_readonly(Pubkey::new_from_array([0u8; 32]), false), // system_program
        ],
    )
}

/// Build grant_permission instruction.
/// Anchor data: disc(8) + cpi_authority_bump(1)
fn grant_permission_ix(
    program_id: &Pubkey,
    resource: &Pubkey,
    admin: &Pubkey,
    permissions_ct: &Pubkey,
    permission_bit_ct: &Pubkey,
    encrypt_program: &Pubkey,
    config: &Pubkey,
    deposit: &Pubkey,
    cpi_authority: &Pubkey,
    network_encryption_key: &Pubkey,
    payer: &Pubkey,
    event_authority: &Pubkey,
    cpi_authority_bump: u8,
) -> Instruction {
    let mut data = Vec::with_capacity(9);
    data.extend_from_slice(&anchor_disc("grant_permission"));
    data.push(cpi_authority_bump);

    Instruction::new_with_bytes(
        *program_id,
        &data,
        vec![
            AccountMeta::new(*resource, false),
            AccountMeta::new_readonly(*admin, true),
            AccountMeta::new(*permissions_ct, false),
            AccountMeta::new(*permission_bit_ct, false),
            AccountMeta::new_readonly(*encrypt_program, false),
            AccountMeta::new(*config, false),
            AccountMeta::new(*deposit, false),
            AccountMeta::new_readonly(*cpi_authority, false),
            AccountMeta::new_readonly(*program_id, false),
            AccountMeta::new_readonly(*network_encryption_key, false),
            AccountMeta::new(*payer, true),
            AccountMeta::new_readonly(*event_authority, false),
            AccountMeta::new_readonly(Pubkey::new_from_array([0u8; 32]), false),
        ],
    )
}

/// Build revoke_permission instruction.
/// Anchor data: disc(8) + cpi_authority_bump(1)
fn revoke_permission_ix(
    program_id: &Pubkey,
    resource: &Pubkey,
    admin: &Pubkey,
    permissions_ct: &Pubkey,
    revoke_mask_ct: &Pubkey,
    encrypt_program: &Pubkey,
    config: &Pubkey,
    deposit: &Pubkey,
    cpi_authority: &Pubkey,
    network_encryption_key: &Pubkey,
    payer: &Pubkey,
    event_authority: &Pubkey,
    cpi_authority_bump: u8,
) -> Instruction {
    let mut data = Vec::with_capacity(9);
    data.extend_from_slice(&anchor_disc("revoke_permission"));
    data.push(cpi_authority_bump);

    Instruction::new_with_bytes(
        *program_id,
        &data,
        vec![
            AccountMeta::new(*resource, false),
            AccountMeta::new_readonly(*admin, true),
            AccountMeta::new(*permissions_ct, false),
            AccountMeta::new(*revoke_mask_ct, false),
            AccountMeta::new_readonly(*encrypt_program, false),
            AccountMeta::new(*config, false),
            AccountMeta::new(*deposit, false),
            AccountMeta::new_readonly(*cpi_authority, false),
            AccountMeta::new_readonly(*program_id, false),
            AccountMeta::new_readonly(*network_encryption_key, false),
            AccountMeta::new(*payer, true),
            AccountMeta::new_readonly(*event_authority, false),
            AccountMeta::new_readonly(Pubkey::new_from_array([0u8; 32]), false),
        ],
    )
}

/// Build check_permission instruction.
/// Anchor data: disc(8) + cpi_authority_bump(1)
fn check_permission_ix(
    program_id: &Pubkey,
    resource: &Pubkey,
    access_check_pda: &Pubkey,
    checker: &Pubkey,
    permissions_ct: &Pubkey,
    permission_bit_ct: &Pubkey,
    result_ct: &Pubkey,
    encrypt_program: &Pubkey,
    config: &Pubkey,
    deposit: &Pubkey,
    cpi_authority: &Pubkey,
    network_encryption_key: &Pubkey,
    payer: &Pubkey,
    event_authority: &Pubkey,
    cpi_authority_bump: u8,
) -> Instruction {
    let mut data = Vec::with_capacity(9);
    data.extend_from_slice(&anchor_disc("check_permission"));
    data.push(cpi_authority_bump);

    Instruction::new_with_bytes(
        *program_id,
        &data,
        vec![
            AccountMeta::new_readonly(*resource, false),
            AccountMeta::new(*access_check_pda, false),
            AccountMeta::new_readonly(*checker, true),
            AccountMeta::new(*permissions_ct, false),
            AccountMeta::new(*permission_bit_ct, false),
            AccountMeta::new(*result_ct, false),
            AccountMeta::new_readonly(*encrypt_program, false),
            AccountMeta::new(*config, false),
            AccountMeta::new(*deposit, false),
            AccountMeta::new_readonly(*cpi_authority, false),
            AccountMeta::new_readonly(*program_id, false),
            AccountMeta::new_readonly(*network_encryption_key, false),
            AccountMeta::new(*payer, true),
            AccountMeta::new_readonly(*event_authority, false),
            AccountMeta::new_readonly(Pubkey::new_from_array([0u8; 32]), false),
        ],
    )
}

/// Helper: create a resource and return (resource_pda, permissions_ct_pubkey, resource_id).
fn create_resource(
    ctx: &mut EncryptTestContext,
    program_id: &Pubkey,
    admin: &Keypair,
) -> (Pubkey, Pubkey, [u8; 32]) {
    let resource_id = [1u8; 32];
    let (resource_pda, _bump) =
        Pubkey::find_program_address(&[b"resource", &resource_id], program_id);

    // Create permissions ciphertext via harness
    let permissions_ct = ctx.create_input::<Uint64>(0, program_id);

    let ix = create_resource_ix(
        program_id,
        &resource_pda,
        &resource_id,
        &permissions_ct,
        &admin.pubkey(),
        &ctx.payer().pubkey(),
    );

    ctx.send_transaction(&[ix], &[admin]);

    (resource_pda, permissions_ct, resource_id)
}

/// Helper: grant a permission and process the graph.
fn do_grant(
    ctx: &mut EncryptTestContext,
    program_id: &Pubkey,
    cpi_authority: &Pubkey,
    cpi_bump: u8,
    admin: &Keypair,
    resource_pda: &Pubkey,
    permissions_ct: &Pubkey,
    permission_value: u128,
) {
    let bit_ct = ctx.create_input::<Uint64>(permission_value, program_id);

    let ix = grant_permission_ix(
        program_id,
        resource_pda,
        &admin.pubkey(),
        permissions_ct,
        &bit_ct,
        ctx.program_id(),
        ctx.config_pda(),
        ctx.deposit_pda(),
        cpi_authority,
        ctx.network_encryption_key_pda(),
        &ctx.payer().pubkey(),
        ctx.event_authority(),
        cpi_bump,
    );
    ctx.send_transaction(&[ix], &[admin]);

    let graph = grant_permission_graph();
    ctx.enqueue_graph_execution(&graph, &[*permissions_ct, bit_ct], &[*permissions_ct]);
    ctx.process_pending();
    ctx.register_ciphertext(permissions_ct);
}

/// Helper: revoke a permission and process the graph.
fn do_revoke(
    ctx: &mut EncryptTestContext,
    program_id: &Pubkey,
    cpi_authority: &Pubkey,
    cpi_bump: u8,
    admin: &Keypair,
    resource_pda: &Pubkey,
    permissions_ct: &Pubkey,
    revoke_mask: u128,
) {
    let mask_ct = ctx.create_input::<Uint64>(revoke_mask, program_id);

    let ix = revoke_permission_ix(
        program_id,
        resource_pda,
        &admin.pubkey(),
        permissions_ct,
        &mask_ct,
        ctx.program_id(),
        ctx.config_pda(),
        ctx.deposit_pda(),
        cpi_authority,
        ctx.network_encryption_key_pda(),
        &ctx.payer().pubkey(),
        ctx.event_authority(),
        cpi_bump,
    );
    ctx.send_transaction(&[ix], &[admin]);

    let graph = revoke_permission_graph();
    ctx.enqueue_graph_execution(&graph, &[*permissions_ct, mask_ct], &[*permissions_ct]);
    ctx.process_pending();
    ctx.register_ciphertext(permissions_ct);
}

/// Helper: check a permission, process graph, and return decrypted result.
fn do_check(
    ctx: &mut EncryptTestContext,
    program_id: &Pubkey,
    cpi_authority: &Pubkey,
    cpi_bump: u8,
    checker: &Keypair,
    resource_pda: &Pubkey,
    permissions_ct: &Pubkey,
    resource_id: &[u8; 32],
    permission_value: u128,
) -> u128 {
    let bit_ct = ctx.create_input::<Uint64>(permission_value, program_id);
    let result_ct = ctx.create_input::<Uint64>(u64::MAX as u128, program_id);

    let (check_pda, _check_bump) = Pubkey::find_program_address(
        &[b"check", resource_id, checker.pubkey().as_ref()],
        program_id,
    );

    let ix = check_permission_ix(
        program_id,
        resource_pda,
        &check_pda,
        &checker.pubkey(),
        permissions_ct,
        &bit_ct,
        &result_ct,
        ctx.program_id(),
        ctx.config_pda(),
        ctx.deposit_pda(),
        cpi_authority,
        ctx.network_encryption_key_pda(),
        &ctx.payer().pubkey(),
        ctx.event_authority(),
        cpi_bump,
    );
    ctx.send_transaction(&[ix], &[checker]);

    ctx.register_ciphertext(&result_ct);

    let graph = check_permission_graph();
    ctx.enqueue_graph_execution(&graph, &[*permissions_ct, bit_ct], &[result_ct]);
    ctx.process_pending();
    ctx.register_ciphertext(&result_ct);

    ctx.decrypt_from_store(&result_ct)
}

#[test]
fn test_create_resource() {
    let mut ctx = EncryptTestContext::new_default();
    let (program_id, _cpi_authority, _cpi_bump) = setup_anchor_program(&mut ctx);
    let admin = ctx.new_funded_keypair();

    let (resource_pda, _perm_ct, _rid) =
        create_resource(&mut ctx, &program_id, &admin);

    // Anchor layout: 8-byte disc + admin(32) + ...
    let data = ctx.get_account_data(&resource_pda).expect("resource not found");
    assert!(data.len() >= 8 + 32, "should have anchor disc + data");
    // Verify admin is stored at offset 8..40
    assert_eq!(&data[8..40], admin.pubkey().as_ref());
}

#[test]
fn test_grant_and_check_permission() {
    let mut ctx = EncryptTestContext::new_default();
    let (program_id, cpi_authority, cpi_bump) = setup_anchor_program(&mut ctx);
    let admin = ctx.new_funded_keypair();

    let (resource_pda, perm_ct, resource_id) =
        create_resource(&mut ctx, &program_id, &admin);

    // Grant READ (bit 0 = value 1)
    do_grant(
        &mut ctx, &program_id, &cpi_authority, cpi_bump, &admin,
        &resource_pda, &perm_ct, 1,
    );

    // Check READ
    let checker = ctx.new_funded_keypair();
    let result = do_check(
        &mut ctx, &program_id, &cpi_authority, cpi_bump, &checker,
        &resource_pda, &perm_ct, &resource_id, 1,
    );
    assert_eq!(result, 1, "should have READ permission");
}

#[test]
fn test_revoke_permission() {
    let mut ctx = EncryptTestContext::new_default();
    let (program_id, cpi_authority, cpi_bump) = setup_anchor_program(&mut ctx);
    let admin = ctx.new_funded_keypair();

    let (resource_pda, perm_ct, resource_id) =
        create_resource(&mut ctx, &program_id, &admin);

    // Grant READ + WRITE (1 | 2 = 3)
    do_grant(
        &mut ctx, &program_id, &cpi_authority, cpi_bump, &admin,
        &resource_pda, &perm_ct, 1,
    );
    do_grant(
        &mut ctx, &program_id, &cpi_authority, cpi_bump, &admin,
        &resource_pda, &perm_ct, 2,
    );

    // Revoke READ (mask = 0xFFFFFFFFFFFFFFFE)
    do_revoke(
        &mut ctx, &program_id, &cpi_authority, cpi_bump, &admin,
        &resource_pda, &perm_ct, 0xFFFFFFFFFFFFFFFE,
    );

    // Check READ — should be gone
    let checker = ctx.new_funded_keypair();
    let result = do_check(
        &mut ctx, &program_id, &cpi_authority, cpi_bump, &checker,
        &resource_pda, &perm_ct, &resource_id, 1,
    );
    assert_eq!(result, 0, "READ should be revoked");
}

#[test]
fn test_check_missing_permission() {
    let mut ctx = EncryptTestContext::new_default();
    let (program_id, cpi_authority, cpi_bump) = setup_anchor_program(&mut ctx);
    let admin = ctx.new_funded_keypair();

    let (resource_pda, perm_ct, resource_id) =
        create_resource(&mut ctx, &program_id, &admin);

    // Grant WRITE only (bit 1 = value 2)
    do_grant(
        &mut ctx, &program_id, &cpi_authority, cpi_bump, &admin,
        &resource_pda, &perm_ct, 2,
    );

    // Check READ — should not be set
    let checker = ctx.new_funded_keypair();
    let result = do_check(
        &mut ctx, &program_id, &cpi_authority, cpi_bump, &checker,
        &resource_pda, &perm_ct, &resource_id, 1,
    );
    assert_eq!(result, 0, "should NOT have READ permission");
}

#[test]
fn test_full_acl_lifecycle() {
    let mut ctx = EncryptTestContext::new_default();
    let (program_id, cpi_authority, cpi_bump) = setup_anchor_program(&mut ctx);
    let admin = ctx.new_funded_keypair();

    // 1. Create resource
    let (resource_pda, perm_ct, resource_id) =
        create_resource(&mut ctx, &program_id, &admin);

    // 2. Grant READ (bit 0 = 1)
    do_grant(
        &mut ctx, &program_id, &cpi_authority, cpi_bump, &admin,
        &resource_pda, &perm_ct, 1,
    );

    // 3. Grant WRITE (bit 1 = 2)
    do_grant(
        &mut ctx, &program_id, &cpi_authority, cpi_bump, &admin,
        &resource_pda, &perm_ct, 2,
    );

    // 4. Check READ — should pass
    let checker1 = ctx.new_funded_keypair();
    let result = do_check(
        &mut ctx, &program_id, &cpi_authority, cpi_bump, &checker1,
        &resource_pda, &perm_ct, &resource_id, 1,
    );
    assert_eq!(result, 1, "should have READ after granting");

    // 5. Revoke READ (mask = 0xFFFFFFFFFFFFFFFE)
    do_revoke(
        &mut ctx, &program_id, &cpi_authority, cpi_bump, &admin,
        &resource_pda, &perm_ct, 0xFFFFFFFFFFFFFFFE,
    );

    // 6. Check READ — should fail
    let checker2 = ctx.new_funded_keypair();
    let result = do_check(
        &mut ctx, &program_id, &cpi_authority, cpi_bump, &checker2,
        &resource_pda, &perm_ct, &resource_id, 1,
    );
    assert_eq!(result, 0, "should NOT have READ after revoking");

    // 7. Decrypt permissions to verify = 2 (WRITE only)
    let perm_value = ctx.decrypt_from_store(&perm_ct);
    assert_eq!(perm_value, 2, "permissions should be 2 (WRITE only)");
}
