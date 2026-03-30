// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! LiteSVM end-to-end tests for the confidential voting anchor example.
//!
//! Uses Anchor's instruction discriminator scheme: first 8 bytes of sha256("global:<name>").

use encrypt_dsl::prelude::encrypt_fn;
use encrypt_solana_test::litesvm::EncryptTestContext;
use encrypt_types::encrypted::{EBool, EUint64, Bool, Uint64};
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Keypair;
use solana_sdk::signer::Signer;

const EXAMPLE_PROGRAM_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../../../target/deploy/confidential_voting_anchor.so"
);

/// Anchor program ID must match declare_id!
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

/// Anchor instruction discriminator: first 8 bytes of sha256("global:<name>")
fn anchor_disc(name: &str) -> [u8; 8] {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    // Simple approach: compute a stable 8-byte hash. Anchor actually uses sha256,
    // but we can't depend on sha2 here. Instead, we hardcode the known discriminators.
    match name {
        "create_proposal" => [132, 116, 68, 174, 216, 160, 198, 22],
        "cast_vote" => [20, 212, 15, 189, 69, 180, 69, 151],
        "close_proposal" => [213, 178, 139, 19, 50, 191, 82, 245],
        "request_tally_decryption" => [61, 92, 171, 137, 224, 220, 69, 113],
        "reveal_tally" => [70, 209, 50, 65, 190, 116, 226, 125],
        _ => panic!("unknown anchor instruction: {name}"),
    }
}

fn setup_anchor_program(ctx: &mut EncryptTestContext) -> (Pubkey, Pubkey, u8) {
    let program_id = Pubkey::try_from(ANCHOR_PROGRAM_ID).unwrap();
    ctx.deploy_program_at(&program_id, EXAMPLE_PROGRAM_PATH);
    let (cpi_authority, cpi_bump) = ctx.cpi_authority_for(&program_id);
    (program_id, cpi_authority, cpi_bump)
}

/// Build create_proposal instruction with Anchor encoding.
/// Anchor ix data: disc(8) + proposal_id(32) + initial_yes_id(32) + initial_no_id(32)
fn create_proposal_ix(
    program_id: &Pubkey,
    proposal_pda: &Pubkey,
    proposal_id: &[u8; 32],
    yes_ct: &Pubkey,
    no_ct: &Pubkey,
    authority: &Pubkey,
    payer: &Pubkey,
) -> Instruction {
    let mut data = Vec::with_capacity(8 + 32 + 32 + 32);
    data.extend_from_slice(&anchor_disc("create_proposal"));
    data.extend_from_slice(proposal_id);
    data.extend_from_slice(yes_ct.as_ref());
    data.extend_from_slice(no_ct.as_ref());

    Instruction::new_with_bytes(
        *program_id,
        &data,
        vec![
            AccountMeta::new(*proposal_pda, false),
            AccountMeta::new_readonly(*authority, true),
            AccountMeta::new(*payer, true),
            AccountMeta::new_readonly(Pubkey::new_from_array([0u8; 32]), false), // system_program
        ],
    )
}

/// Build close_proposal instruction.
fn close_proposal_ix(
    program_id: &Pubkey,
    proposal: &Pubkey,
    authority: &Pubkey,
) -> Instruction {
    Instruction::new_with_bytes(
        *program_id,
        &anchor_disc("close_proposal"),
        vec![
            AccountMeta::new(*proposal, false),
            AccountMeta::new_readonly(*authority, true),
        ],
    )
}

/// Build cast_vote instruction.
/// Anchor data: disc(8) + cpi_authority_bump(1)
fn cast_vote_ix(
    program_id: &Pubkey,
    proposal: &Pubkey,
    vote_record: &Pubkey,
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
    cpi_authority_bump: u8,
) -> Instruction {
    let mut data = Vec::with_capacity(9);
    data.extend_from_slice(&anchor_disc("cast_vote"));
    data.push(cpi_authority_bump);

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

#[test]
fn test_anchor_create_and_close_proposal() {
    let mut ctx = EncryptTestContext::new_default();
    let (program_id, _cpi_authority, _cpi_bump) = setup_anchor_program(&mut ctx);
    let authority = ctx.new_funded_keypair();

    let proposal_id = [1u8; 32];
    let (proposal_pda, _bump) =
        Pubkey::find_program_address(&[b"proposal", &proposal_id], &program_id);

    let yes_ct = Pubkey::new_unique();
    let no_ct = Pubkey::new_unique();

    let ix = create_proposal_ix(
        &program_id, &proposal_pda, &proposal_id,
        &yes_ct, &no_ct, &authority.pubkey(), &ctx.payer().pubkey(),
    );
    ctx.send_transaction(&[ix], &[&authority]);

    // Anchor layout: 8-byte disc + Proposal fields
    // authority(32) proposal_id(32) yes_count(32) no_count(32) is_open(1) total_votes(8) ...
    let data = ctx.get_account_data(&proposal_pda).expect("proposal");
    assert!(data.len() >= 8 + 32, "should have anchor disc + data");
    // is_open is at offset 8 + 32 + 32 + 32 + 32 = 136
    assert_eq!(data[136], 1, "is_open should be true");

    // Close
    let close_ix = close_proposal_ix(&program_id, &proposal_pda, &authority.pubkey());
    ctx.send_transaction(&[close_ix], &[&authority]);

    let data = ctx.get_account_data(&proposal_pda).expect("proposal");
    assert_eq!(data[136], 0, "is_open should be false");
}

#[test]
fn test_anchor_full_voting_lifecycle() {
    let mut ctx = EncryptTestContext::new_default();
    let (program_id, cpi_authority, cpi_bump) = setup_anchor_program(&mut ctx);
    let authority = ctx.new_funded_keypair();

    let proposal_id = [2u8; 32];
    let (proposal_pda, _bump) =
        Pubkey::find_program_address(&[b"proposal", &proposal_id], &program_id);

    // Create encrypted zeros for yes/no via harness (CPI-less for now)
    let yes_ct_kp = Keypair::new();
    let no_ct_kp = Keypair::new();
    let yes_pubkey = yes_ct_kp.pubkey();
    let no_pubkey = no_ct_kp.pubkey();

    // Create proposal — Anchor will init the PDA
    let ix = create_proposal_ix(
        &program_id, &proposal_pda, &proposal_id,
        &yes_pubkey, &no_pubkey, &authority.pubkey(), &ctx.payer().pubkey(),
    );
    ctx.send_transaction(&[ix], &[&authority]);

    // Create yes/no ciphertexts via harness (plaintext zeros, authorized to anchor program)
    let yes_ct = ctx.create_input::<Uint64>(0, &program_id);
    let no_ct = ctx.create_input::<Uint64>(0, &program_id);

    // Cast a YES vote
    let voter1 = ctx.new_funded_keypair();
    let vote_ct1 = ctx.create_input::<Bool>(1, &program_id);
    let (vr1, _vr1_bump) = Pubkey::find_program_address(
        &[b"vote", proposal_id.as_ref(), voter1.pubkey().as_ref()],
        &program_id,
    );

    let vote_ix = cast_vote_ix(
        &program_id, &proposal_pda, &vr1,
        &voter1.pubkey(), &vote_ct1, &yes_ct, &no_ct,
        ctx.program_id(), ctx.config_pda(), ctx.deposit_pda(),
        &cpi_authority, ctx.network_encryption_key_pda(),
        &ctx.payer().pubkey(), ctx.event_authority(), cpi_bump,
    );
    ctx.send_transaction(&[vote_ix], &[&voter1]);

    let graph = cast_vote_graph();
    ctx.enqueue_graph_execution(&graph, &[yes_ct, no_ct, vote_ct1], &[yes_ct, no_ct]);
    ctx.process_pending();
    ctx.register_ciphertext(&yes_ct);
    ctx.register_ciphertext(&no_ct);

    // Close
    let close_ix = close_proposal_ix(&program_id, &proposal_pda, &authority.pubkey());
    ctx.send_transaction(&[close_ix], &[&authority]);

    // Verify tallies via store
    let yes_result = ctx.decrypt_from_store(&yes_ct);
    let no_result = ctx.decrypt_from_store(&no_ct);
    assert_eq!(yes_result, 1);
    assert_eq!(no_result, 0);
}
