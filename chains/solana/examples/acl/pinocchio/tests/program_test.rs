// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! solana-program-test end-to-end tests for the encrypted ACL example.

use encrypt_dsl::prelude::encrypt_fn;
use encrypt_solana_test::program_test::ProgramTestEncryptContext;
use encrypt_types::encrypted::{EUint64, Uint64};
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Keypair;
use solana_sdk::signer::Signer;

#[encrypt_fn]
fn grant_permission_graph(permissions: EUint64, permission_bit: EUint64) -> EUint64 {
    permissions | permission_bit
}

#[encrypt_fn]
fn check_permission_graph(permissions: EUint64, permission_bit: EUint64) -> EUint64 {
    permissions & permission_bit
}

fn setup() -> (ProgramTestEncryptContext, Pubkey, Pubkey, u8) {
    let program_id = Pubkey::new_unique();
    let ctx = ProgramTestEncryptContext::builder()
        .add_program("encrypted_acl", program_id)
        .build();
    let (cpi_authority, cpi_bump) = ctx.cpi_authority_for(&program_id);
    (ctx, program_id, cpi_authority, cpi_bump)
}

fn create_resource_ix(
    program_id: &Pubkey, resource_pda: &Pubkey, resource_bump: u8,
    cpi_authority_bump: u8, resource_id: &[u8; 32], admin: &Pubkey,
    permissions_ct: &Pubkey, encrypt_program: &Pubkey,
    config: &Pubkey, deposit: &Pubkey, cpi_authority: &Pubkey,
    network_encryption_key: &Pubkey, payer: &Pubkey, event_authority: &Pubkey,
) -> Instruction {
    let mut data = Vec::with_capacity(35);
    data.push(0u8);
    data.push(resource_bump);
    data.push(cpi_authority_bump);
    data.extend_from_slice(resource_id);

    Instruction::new_with_bytes(*program_id, &data, vec![
        AccountMeta::new(*resource_pda, false),
        AccountMeta::new_readonly(*admin, true),
        AccountMeta::new(*permissions_ct, true),
        AccountMeta::new_readonly(*encrypt_program, false),
        AccountMeta::new_readonly(*config, false),
        AccountMeta::new(*deposit, false),
        AccountMeta::new_readonly(*cpi_authority, false),
        AccountMeta::new_readonly(*program_id, false),
        AccountMeta::new_readonly(*network_encryption_key, false),
        AccountMeta::new(*payer, true),
        AccountMeta::new_readonly(*event_authority, false),
        AccountMeta::new_readonly(Pubkey::new_from_array([0u8; 32]), false),
    ])
}

fn grant_permission_ix(
    program_id: &Pubkey, resource: &Pubkey, admin: &Pubkey,
    permissions_ct: &Pubkey, permission_bit_ct: &Pubkey,
    cpi_authority_bump: u8, encrypt_program: &Pubkey,
    config: &Pubkey, deposit: &Pubkey, cpi_authority: &Pubkey,
    network_encryption_key: &Pubkey, payer: &Pubkey, event_authority: &Pubkey,
) -> Instruction {
    Instruction::new_with_bytes(*program_id, &[1u8, cpi_authority_bump], vec![
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
    program_id: &Pubkey, resource: &Pubkey, check_pda: &Pubkey,
    check_bump: u8, cpi_authority_bump: u8, checker: &Pubkey,
    permissions_ct: &Pubkey, permission_bit_ct: &Pubkey, result_ct: &Pubkey,
    encrypt_program: &Pubkey, config: &Pubkey, deposit: &Pubkey,
    cpi_authority: &Pubkey, network_encryption_key: &Pubkey,
    payer: &Pubkey, event_authority: &Pubkey,
) -> Instruction {
    Instruction::new_with_bytes(*program_id, &[3u8, check_bump, cpi_authority_bump], vec![
        AccountMeta::new_readonly(*resource, false),
        AccountMeta::new(*check_pda, false),
        AccountMeta::new_readonly(*checker, true),
        AccountMeta::new(*permissions_ct, false),
        AccountMeta::new(*permission_bit_ct, false),
        AccountMeta::new(*result_ct, true),
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
    let (mut ctx, program_id, cpi_authority, cpi_bump) = setup();
    let admin = ctx.new_funded_keypair();

    let resource_id = [1u8; 32];
    let (resource_pda, resource_bump) =
        Pubkey::find_program_address(&[b"resource", &resource_id], &program_id);

    let permissions_ct = Keypair::new();

    let ix = create_resource_ix(
        &program_id, &resource_pda, resource_bump, cpi_bump, &resource_id,
        &admin.pubkey(), &permissions_ct.pubkey(),
        ctx.program_id(), ctx.config_pda(), ctx.deposit_pda(), &cpi_authority,
        ctx.network_encryption_key_pda(), &ctx.payer().pubkey(), ctx.event_authority(),
    );
    ctx.send_transaction(&[ix], &[&admin, &permissions_ct]);

    let data = ctx.get_account_data(&resource_pda).expect("resource");
    assert_eq!(data[0], 1); // RESOURCE discriminator
}

#[test]
fn test_grant_and_check() {
    let (mut ctx, program_id, cpi_authority, cpi_bump) = setup();
    let admin = ctx.new_funded_keypair();

    let resource_id = [2u8; 32];
    let (resource_pda, resource_bump) =
        Pubkey::find_program_address(&[b"resource", &resource_id], &program_id);

    let permissions_ct = Keypair::new();

    let create_ix = create_resource_ix(
        &program_id, &resource_pda, resource_bump, cpi_bump, &resource_id,
        &admin.pubkey(), &permissions_ct.pubkey(),
        ctx.program_id(), ctx.config_pda(), ctx.deposit_pda(), &cpi_authority,
        ctx.network_encryption_key_pda(), &ctx.payer().pubkey(), ctx.event_authority(),
    );
    ctx.send_transaction(&[create_ix], &[&admin, &permissions_ct]);

    let perm_pubkey = permissions_ct.pubkey();
    ctx.register_ciphertext(&perm_pubkey);

    // Grant READ (bit 0 = 1)
    let bit_ct = ctx.create_input::<Uint64>(1, &program_id);
    let grant_ix = grant_permission_ix(
        &program_id, &resource_pda, &admin.pubkey(),
        &perm_pubkey, &bit_ct, cpi_bump,
        ctx.program_id(), ctx.config_pda(), ctx.deposit_pda(), &cpi_authority,
        ctx.network_encryption_key_pda(), &ctx.payer().pubkey(), ctx.event_authority(),
    );
    ctx.send_transaction(&[grant_ix], &[&admin]);

    let graph = grant_permission_graph();
    ctx.enqueue_graph_execution(&graph, &[perm_pubkey, bit_ct], &[perm_pubkey]);
    ctx.process_pending();
    ctx.register_ciphertext(&perm_pubkey);

    // Check READ
    let checker = ctx.new_funded_keypair();
    let check_bit_ct = ctx.create_input::<Uint64>(1, &program_id);
    let result_ct = Keypair::new();

    let (check_pda, check_bump) = Pubkey::find_program_address(
        &[b"check", &resource_id, checker.pubkey().as_ref()],
        &program_id,
    );

    let check_ix = check_permission_ix(
        &program_id, &resource_pda, &check_pda, check_bump, cpi_bump,
        &checker.pubkey(), &perm_pubkey, &check_bit_ct, &result_ct.pubkey(),
        ctx.program_id(), ctx.config_pda(), ctx.deposit_pda(), &cpi_authority,
        ctx.network_encryption_key_pda(), &ctx.payer().pubkey(), ctx.event_authority(),
    );
    ctx.send_transaction(&[check_ix], &[&checker, &result_ct]);

    let result_pubkey = result_ct.pubkey();
    ctx.register_ciphertext(&result_pubkey);

    let graph = check_permission_graph();
    ctx.enqueue_graph_execution(&graph, &[perm_pubkey, check_bit_ct], &[result_pubkey]);
    ctx.process_pending();
    ctx.register_ciphertext(&result_pubkey);

    assert_eq!(ctx.decrypt_from_store(&result_pubkey), 1, "should have READ");
}
