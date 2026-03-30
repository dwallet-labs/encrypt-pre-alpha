// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! LiteSVM end-to-end tests for the confidential voting native example.

use encrypt_dsl::prelude::encrypt_fn;
use encrypt_solana_test::litesvm::EncryptTestContext;
use encrypt_types::encrypted::{EBool, EUint64, Bool, Uint64};
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Keypair;
use solana_sdk::signer::Signer;

#[encrypt_fn]
fn cast_vote_graph(
    yes_count: EUint64,
    no_count: EUint64,
    vote: EBool,
) -> (EUint64, EUint64) {
    let new_yes = if vote { yes_count + 1 } else { yes_count };
    let new_no = if vote { no_count } else { no_count + 1 };
    (new_yes, new_no)
}

const EXAMPLE_PROGRAM_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../../../target/deploy/confidential_voting_native.so"
);

fn setup_voting_program(ctx: &mut EncryptTestContext) -> (Pubkey, Pubkey, u8) {
    let program_id = ctx.deploy_program(EXAMPLE_PROGRAM_PATH);
    let (cpi_authority, cpi_bump) = ctx.cpi_authority_for(&program_id);
    (program_id, cpi_authority, cpi_bump)
}

fn create_proposal_ix(
    program_id: &Pubkey,
    proposal_pda: &Pubkey,
    proposal_bump: u8,
    cpi_authority_bump: u8,
    proposal_id: &[u8; 32],
    authority: &Pubkey,
    yes_ct: &Pubkey,
    no_ct: &Pubkey,
    encrypt_program: &Pubkey,
    config: &Pubkey,
    deposit: &Pubkey,
    cpi_authority: &Pubkey,
    network_encryption_key: &Pubkey,
    payer: &Pubkey,
    event_authority: &Pubkey,
) -> Instruction {
    let mut data = Vec::with_capacity(35);
    data.push(0u8);
    data.push(proposal_bump);
    data.push(cpi_authority_bump);
    data.extend_from_slice(proposal_id);

    Instruction::new_with_bytes(
        *program_id,
        &data,
        vec![
            AccountMeta::new(*proposal_pda, false),
            AccountMeta::new_readonly(*authority, true),
            AccountMeta::new(*yes_ct, true),
            AccountMeta::new(*no_ct, true),
            AccountMeta::new_readonly(*encrypt_program, false),
            AccountMeta::new_readonly(*config, false),
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

fn cast_vote_ix(
    program_id: &Pubkey,
    proposal: &Pubkey,
    vote_record: &Pubkey,
    vote_record_bump: u8,
    cpi_authority_bump: u8,
    voter: &Pubkey,
    vote_ct: &Pubkey,
    yes_ct: &Pubkey,
    no_ct: &Pubkey,
    encrypt_program: &Pubkey,
    config: &Pubkey,
    deposit: &Pubkey,
    cpi_authority: &Pubkey,
    network_encryption_key: &Pubkey,
    payer: &Pubkey,
    event_authority: &Pubkey,
) -> Instruction {
    let data = vec![1u8, vote_record_bump, cpi_authority_bump];

    Instruction::new_with_bytes(
        *program_id,
        &data,
        vec![
            AccountMeta::new(*proposal, false),
            AccountMeta::new(*vote_record, false),
            AccountMeta::new_readonly(*voter, true),
            AccountMeta::new(*vote_ct, false),
            AccountMeta::new(*yes_ct, false),
            AccountMeta::new(*no_ct, false),
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

fn close_proposal_ix(program_id: &Pubkey, proposal: &Pubkey, authority: &Pubkey) -> Instruction {
    Instruction::new_with_bytes(
        *program_id,
        &[2u8],
        vec![
            AccountMeta::new(*proposal, false),
            AccountMeta::new_readonly(*authority, true),
        ],
    )
}

#[test]
fn test_create_and_close_proposal() {
    let mut ctx = EncryptTestContext::new_default();
    let (program_id, cpi_authority, cpi_bump) = setup_voting_program(&mut ctx);
    let authority = ctx.new_funded_keypair();

    let proposal_id = [1u8; 32];
    let (proposal_pda, proposal_bump) =
        Pubkey::find_program_address(&[b"proposal", &proposal_id], &program_id);

    let yes_ct = Keypair::new();
    let no_ct = Keypair::new();

    let ix = create_proposal_ix(
        &program_id, &proposal_pda, proposal_bump, cpi_bump, &proposal_id,
        &authority.pubkey(), &yes_ct.pubkey(), &no_ct.pubkey(),
        ctx.program_id(), ctx.config_pda(), ctx.deposit_pda(), &cpi_authority,
        ctx.network_encryption_key_pda(), &ctx.payer().pubkey(), ctx.event_authority(),
    );
    ctx.send_transaction(&[ix], &[&authority, &yes_ct, &no_ct]);

    let data = ctx.get_account_data(&proposal_pda).expect("proposal");
    assert_eq!(data[0], 1);
    assert_eq!(data[129], 1);

    let close_ix = close_proposal_ix(&program_id, &proposal_pda, &authority.pubkey());
    ctx.send_transaction(&[close_ix], &[&authority]);

    let data = ctx.get_account_data(&proposal_pda).expect("proposal");
    assert_eq!(data[129], 0);
}

#[test]
fn test_full_voting_lifecycle_native() {
    let mut ctx = EncryptTestContext::new_default();
    let (program_id, cpi_authority, cpi_bump) = setup_voting_program(&mut ctx);
    let authority = ctx.new_funded_keypair();

    let proposal_id = [2u8; 32];
    let (proposal_pda, proposal_bump) =
        Pubkey::find_program_address(&[b"proposal", &proposal_id], &program_id);

    let yes_ct = Keypair::new();
    let no_ct = Keypair::new();

    let create_ix = create_proposal_ix(
        &program_id, &proposal_pda, proposal_bump, cpi_bump, &proposal_id,
        &authority.pubkey(), &yes_ct.pubkey(), &no_ct.pubkey(),
        ctx.program_id(), ctx.config_pda(), ctx.deposit_pda(), &cpi_authority,
        ctx.network_encryption_key_pda(), &ctx.payer().pubkey(), ctx.event_authority(),
    );
    ctx.send_transaction(&[create_ix], &[&authority, &yes_ct, &no_ct]);

    let yes_pubkey = yes_ct.pubkey();
    let no_pubkey = no_ct.pubkey();

    ctx.register_ciphertext(&yes_pubkey);
    ctx.register_ciphertext(&no_pubkey);

    // Vote yes
    let voter1 = ctx.new_funded_keypair();
    let vote_ct1 = ctx.create_input::<Bool>(1, &program_id);
    let (vr1, vr1_bump) = Pubkey::find_program_address(
        &[b"vote", &proposal_id, voter1.pubkey().as_ref()], &program_id,
    );
    let ix1 = cast_vote_ix(
        &program_id, &proposal_pda, &vr1, vr1_bump, cpi_bump,
        &voter1.pubkey(), &vote_ct1, &yes_pubkey, &no_pubkey,
        ctx.program_id(), ctx.config_pda(), ctx.deposit_pda(), &cpi_authority,
        ctx.network_encryption_key_pda(), &ctx.payer().pubkey(), ctx.event_authority(),
    );
    ctx.send_transaction(&[ix1], &[&voter1]);

    let graph = cast_vote_graph();
    ctx.enqueue_graph_execution(&graph, &[yes_pubkey, no_pubkey, vote_ct1], &[yes_pubkey, no_pubkey]);
    ctx.process_pending();
    ctx.register_ciphertext(&yes_pubkey);
    ctx.register_ciphertext(&no_pubkey);

    // Vote no
    let voter2 = ctx.new_funded_keypair();
    let vote_ct2 = ctx.create_input::<Bool>(0, &program_id);
    let (vr2, vr2_bump) = Pubkey::find_program_address(
        &[b"vote", &proposal_id, voter2.pubkey().as_ref()], &program_id,
    );
    let ix2 = cast_vote_ix(
        &program_id, &proposal_pda, &vr2, vr2_bump, cpi_bump,
        &voter2.pubkey(), &vote_ct2, &yes_pubkey, &no_pubkey,
        ctx.program_id(), ctx.config_pda(), ctx.deposit_pda(), &cpi_authority,
        ctx.network_encryption_key_pda(), &ctx.payer().pubkey(), ctx.event_authority(),
    );
    ctx.send_transaction(&[ix2], &[&voter2]);

    ctx.enqueue_graph_execution(&graph, &[yes_pubkey, no_pubkey, vote_ct2], &[yes_pubkey, no_pubkey]);
    ctx.process_pending();
    ctx.register_ciphertext(&yes_pubkey);
    ctx.register_ciphertext(&no_pubkey);

    // Close
    let close_ix = close_proposal_ix(&program_id, &proposal_pda, &authority.pubkey());
    ctx.send_transaction(&[close_ix], &[&authority]);

    let data = ctx.get_account_data(&proposal_pda).expect("proposal");
    let total = u64::from_le_bytes(data[130..138].try_into().unwrap());
    assert_eq!(total, 2);

    // Decrypt
    let yes_result = ctx.decrypt_from_store(&yes_pubkey);
    let no_result = ctx.decrypt_from_store(&no_pubkey);
    assert_eq!(yes_result, 1);
    assert_eq!(no_result, 1);
}
