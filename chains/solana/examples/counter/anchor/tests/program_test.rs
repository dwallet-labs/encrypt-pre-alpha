// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! solana-program-test end-to-end tests for the confidential counter anchor example.

use encrypt_dsl::prelude::encrypt_fn;
use encrypt_solana_test::program_test::ProgramTestEncryptContext;
use encrypt_types::encrypted::{EUint64, Uint64};
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signer::Signer;

const ANCHOR_PROGRAM_ID: &str = "CntAnchr111111111111111111111111111111111111";

#[encrypt_fn]
fn increment_graph(value: EUint64) -> EUint64 {
    value + 1
}

#[encrypt_fn]
fn decrement_graph(value: EUint64) -> EUint64 {
    value - 1
}

fn anchor_disc(name: &str) -> [u8; 8] {
    match name {
        "create_counter" => [174, 255, 78, 222, 78, 250, 200, 80],
        "increment" => [11, 18, 104, 9, 104, 174, 59, 33],
        "decrement" => [106, 227, 168, 59, 248, 27, 150, 101],
        _ => panic!("unknown anchor instruction: {name}"),
    }
}

fn setup() -> (ProgramTestEncryptContext, Pubkey, Pubkey, u8) {
    let program_id = Pubkey::try_from(ANCHOR_PROGRAM_ID).unwrap();
    let ctx = ProgramTestEncryptContext::builder()
        .add_program("confidential_counter_anchor", program_id)
        .build();
    let (cpi_authority, cpi_bump) = ctx.cpi_authority_for(&program_id);
    (ctx, program_id, cpi_authority, cpi_bump)
}

fn create_counter_ix(
    program_id: &Pubkey, counter_pda: &Pubkey, counter_id: &[u8; 32],
    initial_value_id: &Pubkey, authority: &Pubkey, payer: &Pubkey,
) -> Instruction {
    let mut data = Vec::with_capacity(8 + 32 + 32);
    data.extend_from_slice(&anchor_disc("create_counter"));
    data.extend_from_slice(counter_id);
    data.extend_from_slice(initial_value_id.as_ref());

    Instruction::new_with_bytes(*program_id, &data, vec![
        AccountMeta::new(*counter_pda, false),
        AccountMeta::new_readonly(*authority, true),
        AccountMeta::new(*payer, true),
        AccountMeta::new_readonly(Pubkey::new_from_array([0u8; 32]), false),
    ])
}

fn increment_ix(
    program_id: &Pubkey, counter: &Pubkey, value_ct: &Pubkey,
    cpi_authority_bump: u8, encrypt_program: &Pubkey,
    config: &Pubkey, deposit: &Pubkey, cpi_authority: &Pubkey,
    network_encryption_key: &Pubkey, payer: &Pubkey, event_authority: &Pubkey,
) -> Instruction {
    let mut data = Vec::with_capacity(9);
    data.extend_from_slice(&anchor_disc("increment"));
    data.push(cpi_authority_bump);

    Instruction::new_with_bytes(*program_id, &data, vec![
        AccountMeta::new(*counter, false),
        AccountMeta::new(*value_ct, false),
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

fn decrement_ix(
    program_id: &Pubkey, counter: &Pubkey, value_ct: &Pubkey,
    cpi_authority_bump: u8, encrypt_program: &Pubkey,
    config: &Pubkey, deposit: &Pubkey, cpi_authority: &Pubkey,
    network_encryption_key: &Pubkey, payer: &Pubkey, event_authority: &Pubkey,
) -> Instruction {
    let mut data = Vec::with_capacity(9);
    data.extend_from_slice(&anchor_disc("decrement"));
    data.push(cpi_authority_bump);

    Instruction::new_with_bytes(*program_id, &data, vec![
        AccountMeta::new(*counter, false),
        AccountMeta::new(*value_ct, false),
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
fn test_create_counter() {
    let (mut ctx, program_id, _cpi_authority, _cpi_bump) = setup();
    let authority = ctx.new_funded_keypair();

    let counter_id = [1u8; 32];
    let (counter_pda, _) =
        Pubkey::find_program_address(&[b"counter", &counter_id], &program_id);

    let value_ct = Pubkey::new_unique();

    let ix = create_counter_ix(
        &program_id, &counter_pda, &counter_id,
        &value_ct, &authority.pubkey(), &ctx.payer().pubkey(),
    );
    ctx.send_transaction(&[ix], &[&authority]);

    // Anchor layout: 8-byte disc + authority(32) + counter_id(32) + value(32) + ...
    let data = ctx.get_account_data(&counter_pda).expect("counter");
    assert_eq!(&data[8..40], authority.pubkey().as_ref());
    assert_eq!(&data[40..72], &counter_id);
    assert_eq!(&data[72..104], value_ct.as_ref());
}

#[test]
fn test_increment_and_decrypt() {
    let (mut ctx, program_id, cpi_authority, cpi_bump) = setup();
    let authority = ctx.new_funded_keypair();

    let counter_id = [2u8; 32];
    let (counter_pda, _) =
        Pubkey::find_program_address(&[b"counter", &counter_id], &program_id);

    let value_ct = ctx.create_input::<Uint64>(0, &program_id);

    let create_ix = create_counter_ix(
        &program_id, &counter_pda, &counter_id,
        &value_ct, &authority.pubkey(), &ctx.payer().pubkey(),
    );
    ctx.send_transaction(&[create_ix], &[&authority]);

    // Increment
    let inc_ix = increment_ix(
        &program_id, &counter_pda, &value_ct, cpi_bump,
        ctx.program_id(), ctx.config_pda(), ctx.deposit_pda(), &cpi_authority,
        ctx.network_encryption_key_pda(), &ctx.payer().pubkey(), ctx.event_authority(),
    );
    ctx.send_transaction(&[inc_ix], &[]);

    let graph = increment_graph();
    ctx.enqueue_graph_execution(&graph, &[value_ct], &[value_ct]);
    ctx.process_pending();
    ctx.register_ciphertext(&value_ct);

    assert_eq!(ctx.decrypt_from_store(&value_ct), 1);
}
