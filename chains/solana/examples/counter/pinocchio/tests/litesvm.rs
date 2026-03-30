// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! LiteSVM end-to-end tests for the confidential counter example.
//!
//! Tests the full lifecycle: create_counter -> increment -> decrement -> decrypt -> reveal.

use encrypt_dsl::prelude::encrypt_fn;
use encrypt_solana_test::litesvm::EncryptTestContext;
use encrypt_types::encrypted::{EUint64, Uint64};
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Keypair;
use solana_sdk::signer::Signer;

/// The same graph functions as in the example — needed for off-chain evaluation.
#[encrypt_fn]
fn increment_graph(value: EUint64) -> EUint64 {
    value + 1
}

#[encrypt_fn]
fn decrement_graph(value: EUint64) -> EUint64 {
    value - 1
}

const EXAMPLE_PROGRAM_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../../../target/deploy/confidential_counter.so"
);

/// Helper: deploy the counter program and return (program_id, cpi_authority, cpi_bump).
fn setup_counter_program(ctx: &mut EncryptTestContext) -> (Pubkey, Pubkey, u8) {
    let program_id = ctx.deploy_program(EXAMPLE_PROGRAM_PATH);
    let (cpi_authority, cpi_bump) = ctx.cpi_authority_for(&program_id);
    (program_id, cpi_authority, cpi_bump)
}

/// Build a create_counter instruction.
fn create_counter_ix(
    program_id: &Pubkey,
    counter_pda: &Pubkey,
    counter_bump: u8,
    cpi_authority_bump: u8,
    counter_id: &[u8; 32],
    authority: &Pubkey,
    value_ct: &Pubkey,
    encrypt_program: &Pubkey,
    config: &Pubkey,
    deposit: &Pubkey,
    cpi_authority: &Pubkey,
    network_encryption_key: &Pubkey,
    payer: &Pubkey,
    event_authority: &Pubkey,
) -> Instruction {
    let mut data = Vec::with_capacity(35);
    data.push(0u8); // discriminator: create_counter
    data.push(counter_bump);
    data.push(cpi_authority_bump);
    data.extend_from_slice(counter_id);

    Instruction::new_with_bytes(
        *program_id,
        &data,
        vec![
            AccountMeta::new(*counter_pda, false),
            AccountMeta::new_readonly(*authority, true),
            AccountMeta::new(*value_ct, true),
            AccountMeta::new_readonly(*encrypt_program, false),
            AccountMeta::new_readonly(*config, false),
            AccountMeta::new(*deposit, false),
            AccountMeta::new_readonly(*cpi_authority, false),
            AccountMeta::new_readonly(*program_id, false),
            AccountMeta::new_readonly(*network_encryption_key, false),
            AccountMeta::new(*payer, true),
            AccountMeta::new_readonly(*event_authority, false),
            AccountMeta::new_readonly(Pubkey::new_from_array([0u8; 32]), false), // system_program
        ],
    )
}

/// Build an increment instruction.
fn increment_ix(
    program_id: &Pubkey,
    counter: &Pubkey,
    value_ct: &Pubkey,
    cpi_authority_bump: u8,
    encrypt_program: &Pubkey,
    config: &Pubkey,
    deposit: &Pubkey,
    cpi_authority: &Pubkey,
    network_encryption_key: &Pubkey,
    payer: &Pubkey,
    event_authority: &Pubkey,
) -> Instruction {
    Instruction::new_with_bytes(
        *program_id,
        &[1u8, cpi_authority_bump], // disc: increment
        vec![
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
        ],
    )
}

/// Build a decrement instruction.
fn decrement_ix(
    program_id: &Pubkey,
    counter: &Pubkey,
    value_ct: &Pubkey,
    cpi_authority_bump: u8,
    encrypt_program: &Pubkey,
    config: &Pubkey,
    deposit: &Pubkey,
    cpi_authority: &Pubkey,
    network_encryption_key: &Pubkey,
    payer: &Pubkey,
    event_authority: &Pubkey,
) -> Instruction {
    Instruction::new_with_bytes(
        *program_id,
        &[2u8, cpi_authority_bump], // disc: decrement
        vec![
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
        ],
    )
}

#[test]
fn test_create_counter() {
    let mut ctx = EncryptTestContext::new_default();
    let (program_id, cpi_authority, cpi_bump) = setup_counter_program(&mut ctx);
    let authority = ctx.new_funded_keypair();

    let counter_id = [1u8; 32];
    let (counter_pda, counter_bump) =
        Pubkey::find_program_address(&[b"counter", &counter_id], &program_id);

    let value_ct = Keypair::new();

    let ix = create_counter_ix(
        &program_id,
        &counter_pda,
        counter_bump,
        cpi_bump,
        &counter_id,
        &authority.pubkey(),
        &value_ct.pubkey(),
        ctx.program_id(),
        ctx.config_pda(),
        ctx.deposit_pda(),
        &cpi_authority,
        ctx.network_encryption_key_pda(),
        &ctx.payer().pubkey(),
        ctx.event_authority(),
    );

    ctx.send_transaction(&[ix], &[&authority, &value_ct]);

    // Verify counter was created
    let data = ctx.get_account_data(&counter_pda).expect("counter not found");
    assert_eq!(data[0], 1); // discriminator = COUNTER
    assert_eq!(&data[1..33], authority.pubkey().as_ref()); // authority
    assert_eq!(&data[33..65], &counter_id); // counter_id
}

#[test]
fn test_increment() {
    let mut ctx = EncryptTestContext::new_default();
    let (program_id, cpi_authority, cpi_bump) = setup_counter_program(&mut ctx);
    let authority = ctx.new_funded_keypair();

    let counter_id = [2u8; 32];
    let (counter_pda, counter_bump) =
        Pubkey::find_program_address(&[b"counter", &counter_id], &program_id);

    let value_ct = Keypair::new();

    let create_ix = create_counter_ix(
        &program_id,
        &counter_pda,
        counter_bump,
        cpi_bump,
        &counter_id,
        &authority.pubkey(),
        &value_ct.pubkey(),
        ctx.program_id(),
        ctx.config_pda(),
        ctx.deposit_pda(),
        &cpi_authority,
        ctx.network_encryption_key_pda(),
        &ctx.payer().pubkey(),
        ctx.event_authority(),
    );
    ctx.send_transaction(&[create_ix], &[&authority, &value_ct]);

    let value_pubkey = value_ct.pubkey();
    ctx.register_ciphertext(&value_pubkey);

    // Increment
    let inc_ix = increment_ix(
        &program_id,
        &counter_pda,
        &value_pubkey,
        cpi_bump,
        ctx.program_id(),
        ctx.config_pda(),
        ctx.deposit_pda(),
        &cpi_authority,
        ctx.network_encryption_key_pda(),
        &ctx.payer().pubkey(),
        ctx.event_authority(),
    );
    ctx.send_transaction(&[inc_ix], &[]);

    let graph = increment_graph();
    ctx.enqueue_graph_execution(&graph, &[value_pubkey], &[value_pubkey]);
    ctx.process_pending();
    ctx.register_ciphertext(&value_pubkey);

    // Verify via off-chain decrypt
    let result = ctx.decrypt_from_store(&value_pubkey);
    assert_eq!(result, 1, "counter should be 1 after one increment");
}

#[test]
fn test_multiple_increments() {
    let mut ctx = EncryptTestContext::new_default();
    let (program_id, cpi_authority, cpi_bump) = setup_counter_program(&mut ctx);
    let authority = ctx.new_funded_keypair();

    let counter_id = [3u8; 32];
    let (counter_pda, counter_bump) =
        Pubkey::find_program_address(&[b"counter", &counter_id], &program_id);

    let value_ct = Keypair::new();

    let create_ix = create_counter_ix(
        &program_id,
        &counter_pda,
        counter_bump,
        cpi_bump,
        &counter_id,
        &authority.pubkey(),
        &value_ct.pubkey(),
        ctx.program_id(),
        ctx.config_pda(),
        ctx.deposit_pda(),
        &cpi_authority,
        ctx.network_encryption_key_pda(),
        &ctx.payer().pubkey(),
        ctx.event_authority(),
    );
    ctx.send_transaction(&[create_ix], &[&authority, &value_ct]);

    let value_pubkey = value_ct.pubkey();
    ctx.register_ciphertext(&value_pubkey);

    // Increment 5 times
    for _ in 0..5 {
        let inc_ix = increment_ix(
            &program_id,
            &counter_pda,
            &value_pubkey,
            cpi_bump,
            ctx.program_id(),
            ctx.config_pda(),
            ctx.deposit_pda(),
            &cpi_authority,
            ctx.network_encryption_key_pda(),
            &ctx.payer().pubkey(),
            ctx.event_authority(),
        );
        ctx.send_transaction(&[inc_ix], &[]);

        let graph = increment_graph();
        ctx.enqueue_graph_execution(&graph, &[value_pubkey], &[value_pubkey]);
        ctx.process_pending();
        ctx.register_ciphertext(&value_pubkey);
    }

    let result = ctx.decrypt_from_store(&value_pubkey);
    assert_eq!(result, 5, "counter should be 5 after 5 increments");
}

#[test]
fn test_decrement() {
    let mut ctx = EncryptTestContext::new_default();
    let (program_id, cpi_authority, cpi_bump) = setup_counter_program(&mut ctx);
    let authority = ctx.new_funded_keypair();

    let counter_id = [4u8; 32];
    let (counter_pda, counter_bump) =
        Pubkey::find_program_address(&[b"counter", &counter_id], &program_id);

    let value_ct = Keypair::new();

    let create_ix = create_counter_ix(
        &program_id,
        &counter_pda,
        counter_bump,
        cpi_bump,
        &counter_id,
        &authority.pubkey(),
        &value_ct.pubkey(),
        ctx.program_id(),
        ctx.config_pda(),
        ctx.deposit_pda(),
        &cpi_authority,
        ctx.network_encryption_key_pda(),
        &ctx.payer().pubkey(),
        ctx.event_authority(),
    );
    ctx.send_transaction(&[create_ix], &[&authority, &value_ct]);

    let value_pubkey = value_ct.pubkey();
    ctx.register_ciphertext(&value_pubkey);

    // Increment 3 times
    for _ in 0..3 {
        let inc_ix = increment_ix(
            &program_id,
            &counter_pda,
            &value_pubkey,
            cpi_bump,
            ctx.program_id(),
            ctx.config_pda(),
            ctx.deposit_pda(),
            &cpi_authority,
            ctx.network_encryption_key_pda(),
            &ctx.payer().pubkey(),
            ctx.event_authority(),
        );
        ctx.send_transaction(&[inc_ix], &[]);

        let graph = increment_graph();
        ctx.enqueue_graph_execution(&graph, &[value_pubkey], &[value_pubkey]);
        ctx.process_pending();
        ctx.register_ciphertext(&value_pubkey);
    }

    // Decrement once
    let dec_ix = decrement_ix(
        &program_id,
        &counter_pda,
        &value_pubkey,
        cpi_bump,
        ctx.program_id(),
        ctx.config_pda(),
        ctx.deposit_pda(),
        &cpi_authority,
        ctx.network_encryption_key_pda(),
        &ctx.payer().pubkey(),
        ctx.event_authority(),
    );
    ctx.send_transaction(&[dec_ix], &[]);

    let graph = decrement_graph();
    ctx.enqueue_graph_execution(&graph, &[value_pubkey], &[value_pubkey]);
    ctx.process_pending();
    ctx.register_ciphertext(&value_pubkey);

    let result = ctx.decrypt_from_store(&value_pubkey);
    assert_eq!(result, 2, "counter should be 2 (3 increments - 1 decrement)");
}

#[test]
fn test_full_lifecycle() {
    let mut ctx = EncryptTestContext::new_default();
    let (program_id, cpi_authority, cpi_bump) = setup_counter_program(&mut ctx);
    let authority = ctx.new_funded_keypair();

    // ── 1. Create counter ──
    let counter_id = [5u8; 32];
    let (counter_pda, counter_bump) =
        Pubkey::find_program_address(&[b"counter", &counter_id], &program_id);

    let value_ct = Keypair::new();

    let create_ix = create_counter_ix(
        &program_id,
        &counter_pda,
        counter_bump,
        cpi_bump,
        &counter_id,
        &authority.pubkey(),
        &value_ct.pubkey(),
        ctx.program_id(),
        ctx.config_pda(),
        ctx.deposit_pda(),
        &cpi_authority,
        ctx.network_encryption_key_pda(),
        &ctx.payer().pubkey(),
        ctx.event_authority(),
    );
    ctx.send_transaction(&[create_ix], &[&authority, &value_ct]);

    let value_pubkey = value_ct.pubkey();
    ctx.register_ciphertext(&value_pubkey);

    // ── 2. Increment 3 times ──
    for _ in 0..3 {
        let inc_ix = increment_ix(
            &program_id,
            &counter_pda,
            &value_pubkey,
            cpi_bump,
            ctx.program_id(),
            ctx.config_pda(),
            ctx.deposit_pda(),
            &cpi_authority,
            ctx.network_encryption_key_pda(),
            &ctx.payer().pubkey(),
            ctx.event_authority(),
        );
        ctx.send_transaction(&[inc_ix], &[]);

        let graph = increment_graph();
        ctx.enqueue_graph_execution(&graph, &[value_pubkey], &[value_pubkey]);
        ctx.process_pending();
        ctx.register_ciphertext(&value_pubkey);
    }

    // ── 3. Decrement once ──
    let dec_ix = decrement_ix(
        &program_id,
        &counter_pda,
        &value_pubkey,
        cpi_bump,
        ctx.program_id(),
        ctx.config_pda(),
        ctx.deposit_pda(),
        &cpi_authority,
        ctx.network_encryption_key_pda(),
        &ctx.payer().pubkey(),
        ctx.event_authority(),
    );
    ctx.send_transaction(&[dec_ix], &[]);

    let graph = decrement_graph();
    ctx.enqueue_graph_execution(&graph, &[value_pubkey], &[value_pubkey]);
    ctx.process_pending();
    ctx.register_ciphertext(&value_pubkey);

    // ── 4. Verify via off-chain decrypt ──
    let result = ctx.decrypt_from_store(&value_pubkey);
    assert_eq!(result, 2, "counter should be 2 (3 inc - 1 dec)");
}
