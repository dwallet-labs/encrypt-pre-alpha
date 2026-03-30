// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! solana-program-test end-to-end tests for confidential voting anchor example.

use encrypt_dsl::prelude::encrypt_fn;
use encrypt_solana_test::program_test::ProgramTestEncryptContext;
use encrypt_types::encrypted::{EBool, EUint64, Bool, Uint64};
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Keypair;
use solana_sdk::signer::Signer;

const ANCHOR_PROGRAM_ID: &str = "VotingAnchor1111111111111111111111111111111";

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

fn anchor_disc(name: &str) -> [u8; 8] {
    match name {
        "create_proposal" => [132, 116, 68, 174, 216, 160, 198, 22],
        "close_proposal" => [213, 178, 139, 19, 50, 191, 82, 245],
        "cast_vote" => [20, 212, 15, 189, 69, 180, 69, 151],
        _ => panic!("unknown anchor instruction: {name}"),
    }
}

fn setup() -> (ProgramTestEncryptContext, Pubkey, Pubkey, u8) {
    let program_id = Pubkey::try_from(ANCHOR_PROGRAM_ID).unwrap();
    let ctx = ProgramTestEncryptContext::builder()
        .add_program("confidential_voting_anchor", program_id)
        .build();
    let (cpi_authority, cpi_bump) = ctx.cpi_authority_for(&program_id);
    (ctx, program_id, cpi_authority, cpi_bump)
}

fn create_proposal_ix(
    program_id: &Pubkey, proposal_pda: &Pubkey, proposal_id: &[u8; 32],
    yes_ct: &Pubkey, no_ct: &Pubkey, authority: &Pubkey, payer: &Pubkey,
) -> Instruction {
    let mut data = Vec::with_capacity(8 + 32 + 32 + 32);
    data.extend_from_slice(&anchor_disc("create_proposal"));
    data.extend_from_slice(proposal_id);
    data.extend_from_slice(yes_ct.as_ref());
    data.extend_from_slice(no_ct.as_ref());

    Instruction::new_with_bytes(*program_id, &data, vec![
        AccountMeta::new(*proposal_pda, false),
        AccountMeta::new_readonly(*authority, true),
        AccountMeta::new(*payer, true),
        AccountMeta::new_readonly(Pubkey::new_from_array([0u8; 32]), false),
    ])
}

fn close_proposal_ix(program_id: &Pubkey, proposal: &Pubkey, authority: &Pubkey) -> Instruction {
    Instruction::new_with_bytes(*program_id, &anchor_disc("close_proposal"), vec![
        AccountMeta::new(*proposal, false),
        AccountMeta::new_readonly(*authority, true),
    ])
}

#[test]
fn test_create_and_close_proposal() {
    let (mut ctx, program_id, _cpi_authority, _cpi_bump) = setup();
    let authority = ctx.new_funded_keypair();

    let proposal_id = [1u8; 32];
    let (proposal_pda, _) =
        Pubkey::find_program_address(&[b"proposal", &proposal_id], &program_id);

    let yes_ct = Pubkey::new_unique();
    let no_ct = Pubkey::new_unique();

    let ix = create_proposal_ix(
        &program_id, &proposal_pda, &proposal_id,
        &yes_ct, &no_ct, &authority.pubkey(), &ctx.payer().pubkey(),
    );
    ctx.send_transaction(&[ix], &[&authority]);

    // Anchor layout: 8-byte disc + fields
    let data = ctx.get_account_data(&proposal_pda).expect("proposal");
    assert_eq!(data[136], 1); // is_open = true

    let close_ix = close_proposal_ix(&program_id, &proposal_pda, &authority.pubkey());
    ctx.send_transaction(&[close_ix], &[&authority]);

    let data = ctx.get_account_data(&proposal_pda).expect("proposal");
    assert_eq!(data[136], 0); // is_open = false
}

#[test]
fn test_full_voting_lifecycle() {
    let (mut ctx, program_id, cpi_authority, cpi_bump) = setup();
    let authority = ctx.new_funded_keypair();

    let proposal_id = [2u8; 32];
    let (proposal_pda, _) =
        Pubkey::find_program_address(&[b"proposal", &proposal_id], &program_id);

    let yes_ct_kp = Keypair::new();
    let no_ct_kp = Keypair::new();
    let yes_pubkey = yes_ct_kp.pubkey();
    let no_pubkey = no_ct_kp.pubkey();

    let ix = create_proposal_ix(
        &program_id, &proposal_pda, &proposal_id,
        &yes_pubkey, &no_pubkey, &authority.pubkey(), &ctx.payer().pubkey(),
    );
    ctx.send_transaction(&[ix], &[&authority]);

    let yes_ct = ctx.create_input::<Uint64>(0, &program_id);
    let no_ct = ctx.create_input::<Uint64>(0, &program_id);

    // Cast YES vote
    let voter1 = ctx.new_funded_keypair();
    let vote_ct1 = ctx.create_input::<Bool>(1, &program_id);
    let (vr1, _vr1_bump) = Pubkey::find_program_address(
        &[b"vote", proposal_id.as_ref(), voter1.pubkey().as_ref()], &program_id,
    );

    let mut cast_data = Vec::with_capacity(9);
    cast_data.extend_from_slice(&anchor_disc("cast_vote"));
    cast_data.push(cpi_bump);

    let vote_ix = Instruction::new_with_bytes(program_id, &cast_data, vec![
        AccountMeta::new(proposal_pda, false),
        AccountMeta::new(vr1, false),
        AccountMeta::new_readonly(voter1.pubkey(), true),
        AccountMeta::new(vote_ct1, false),
        AccountMeta::new(yes_ct, false),
        AccountMeta::new(no_ct, false),
        AccountMeta::new_readonly(*ctx.program_id(), false),
        AccountMeta::new(*ctx.config_pda(), false),
        AccountMeta::new(*ctx.deposit_pda(), false),
        AccountMeta::new_readonly(cpi_authority, false),
        AccountMeta::new_readonly(program_id, false),
        AccountMeta::new_readonly(*ctx.network_encryption_key_pda(), false),
        AccountMeta::new(ctx.payer().pubkey(), true),
        AccountMeta::new_readonly(*ctx.event_authority(), false),
        AccountMeta::new_readonly(Pubkey::new_from_array([0u8; 32]), false),
    ]);
    ctx.send_transaction(&[vote_ix], &[&voter1]);

    let graph = cast_vote_graph();
    ctx.enqueue_graph_execution(&graph, &[yes_ct, no_ct, vote_ct1], &[yes_ct, no_ct]);
    ctx.process_pending();
    ctx.register_ciphertext(&yes_ct);
    ctx.register_ciphertext(&no_ct);

    // Close
    let close_ix = close_proposal_ix(&program_id, &proposal_pda, &authority.pubkey());
    ctx.send_transaction(&[close_ix], &[&authority]);

    assert_eq!(ctx.decrypt_from_store(&yes_ct), 1);
    assert_eq!(ctx.decrypt_from_store(&no_ct), 0);
}
