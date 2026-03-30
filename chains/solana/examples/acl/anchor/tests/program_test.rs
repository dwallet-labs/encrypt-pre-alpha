// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! solana-program-test end-to-end tests for the encrypted ACL anchor example.

use encrypt_dsl::prelude::encrypt_fn;
use encrypt_solana_test::program_test::ProgramTestEncryptContext;
use encrypt_types::encrypted::{EUint64, Uint64};
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signer::Signer;

const ANCHOR_PROGRAM_ID: &str = "US517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx";

#[encrypt_fn]
fn grant_permission_graph(permissions: EUint64, permission_bit: EUint64) -> EUint64 {
    permissions | permission_bit
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
        "check_permission" => [154, 199, 232, 242, 96, 72, 197, 236],
        _ => panic!("unknown anchor instruction: {name}"),
    }
}

fn setup() -> (ProgramTestEncryptContext, Pubkey, Pubkey, u8) {
    let program_id = Pubkey::try_from(ANCHOR_PROGRAM_ID).unwrap();
    let ctx = ProgramTestEncryptContext::builder()
        .add_program("encrypted_acl_anchor", program_id)
        .build();
    let (cpi_authority, cpi_bump) = ctx.cpi_authority_for(&program_id);
    (ctx, program_id, cpi_authority, cpi_bump)
}

fn create_resource_ix(
    program_id: &Pubkey, resource_pda: &Pubkey, resource_id: &[u8; 32],
    permissions_ct_id: &Pubkey, admin: &Pubkey, payer: &Pubkey,
) -> Instruction {
    let mut data = Vec::with_capacity(8 + 32 + 32);
    data.extend_from_slice(&anchor_disc("create_resource"));
    data.extend_from_slice(resource_id);
    data.extend_from_slice(permissions_ct_id.as_ref());

    Instruction::new_with_bytes(*program_id, &data, vec![
        AccountMeta::new(*resource_pda, false),
        AccountMeta::new_readonly(*admin, true),
        AccountMeta::new(*payer, true),
        AccountMeta::new_readonly(Pubkey::new_from_array([0u8; 32]), false),
    ])
}

fn grant_permission_ix(
    program_id: &Pubkey, resource: &Pubkey, admin: &Pubkey,
    permissions_ct: &Pubkey, permission_bit_ct: &Pubkey,
    encrypt_program: &Pubkey, config: &Pubkey, deposit: &Pubkey,
    cpi_authority: &Pubkey, network_encryption_key: &Pubkey,
    payer: &Pubkey, event_authority: &Pubkey,
    cpi_authority_bump: u8,
) -> Instruction {
    let mut data = Vec::with_capacity(9);
    data.extend_from_slice(&anchor_disc("grant_permission"));
    data.push(cpi_authority_bump);

    Instruction::new_with_bytes(*program_id, &data, vec![
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
    ])
}

fn check_permission_ix(
    program_id: &Pubkey, resource: &Pubkey, access_check_pda: &Pubkey,
    checker: &Pubkey, permissions_ct: &Pubkey, permission_bit_ct: &Pubkey,
    result_ct: &Pubkey, encrypt_program: &Pubkey, config: &Pubkey,
    deposit: &Pubkey, cpi_authority: &Pubkey, network_encryption_key: &Pubkey,
    payer: &Pubkey, event_authority: &Pubkey, cpi_authority_bump: u8,
) -> Instruction {
    let mut data = Vec::with_capacity(9);
    data.extend_from_slice(&anchor_disc("check_permission"));
    data.push(cpi_authority_bump);

    Instruction::new_with_bytes(*program_id, &data, vec![
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
    ])
}

#[test]
fn test_create_resource() {
    let (mut ctx, program_id, _cpi_authority, _cpi_bump) = setup();
    let admin = ctx.new_funded_keypair();

    let resource_id = [1u8; 32];
    let (resource_pda, _bump) =
        Pubkey::find_program_address(&[b"resource", &resource_id], &program_id);

    let permissions_ct = ctx.create_input::<Uint64>(0, &program_id);

    let ix = create_resource_ix(
        &program_id, &resource_pda, &resource_id, &permissions_ct,
        &admin.pubkey(), &ctx.payer().pubkey(),
    );
    ctx.send_transaction(&[ix], &[&admin]);

    let data = ctx.get_account_data(&resource_pda).expect("resource");
    // Verify admin at offset 8..40
    assert_eq!(&data[8..40], admin.pubkey().as_ref());
}

#[test]
fn test_grant_and_check() {
    let (mut ctx, program_id, cpi_authority, cpi_bump) = setup();
    let admin = ctx.new_funded_keypair();

    let resource_id = [2u8; 32];
    let (resource_pda, _bump) =
        Pubkey::find_program_address(&[b"resource", &resource_id], &program_id);

    let permissions_ct = ctx.create_input::<Uint64>(0, &program_id);

    let create_ix = create_resource_ix(
        &program_id, &resource_pda, &resource_id, &permissions_ct,
        &admin.pubkey(), &ctx.payer().pubkey(),
    );
    ctx.send_transaction(&[create_ix], &[&admin]);

    ctx.register_ciphertext(&permissions_ct);

    // Grant READ (bit 0 = 1)
    let bit_ct = ctx.create_input::<Uint64>(1, &program_id);
    let grant_ix = grant_permission_ix(
        &program_id, &resource_pda, &admin.pubkey(),
        &permissions_ct, &bit_ct,
        ctx.program_id(), ctx.config_pda(), ctx.deposit_pda(), &cpi_authority,
        ctx.network_encryption_key_pda(), &ctx.payer().pubkey(), ctx.event_authority(),
        cpi_bump,
    );
    ctx.send_transaction(&[grant_ix], &[&admin]);

    let graph = grant_permission_graph();
    ctx.enqueue_graph_execution(&graph, &[permissions_ct, bit_ct], &[permissions_ct]);
    ctx.process_pending();
    ctx.register_ciphertext(&permissions_ct);

    // Check READ
    let checker = ctx.new_funded_keypair();
    let check_bit_ct = ctx.create_input::<Uint64>(1, &program_id);
    let result_ct = ctx.create_input::<Uint64>(u64::MAX as u128, &program_id);

    let (check_pda, _check_bump) = Pubkey::find_program_address(
        &[b"check", &resource_id, checker.pubkey().as_ref()],
        &program_id,
    );

    let check_ix = check_permission_ix(
        &program_id, &resource_pda, &check_pda,
        &checker.pubkey(), &permissions_ct, &check_bit_ct, &result_ct,
        ctx.program_id(), ctx.config_pda(), ctx.deposit_pda(), &cpi_authority,
        ctx.network_encryption_key_pda(), &ctx.payer().pubkey(), ctx.event_authority(),
        cpi_bump,
    );
    ctx.send_transaction(&[check_ix], &[&checker]);

    ctx.register_ciphertext(&result_ct);

    let graph = check_permission_graph();
    ctx.enqueue_graph_execution(&graph, &[permissions_ct, check_bit_ct], &[result_ct]);
    ctx.process_pending();
    ctx.register_ciphertext(&result_ct);

    assert_eq!(ctx.decrypt_from_store(&result_ct), 1, "should have READ");
}
