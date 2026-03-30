// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! LiteSVM end-to-end tests for the encrypted coin flip native example.
//!
//! Two-sided game: side A creates game (with result_ct), side B joins,
//! anyone can reveal/cancel.

use encrypt_dsl::prelude::encrypt_fn;
use encrypt_solana_test::litesvm::EncryptTestContext;
use encrypt_types::encrypted::{EUint64, Uint64};
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Keypair;
use solana_sdk::signer::Signer;

#[encrypt_fn]
fn coin_flip_graph(commit_a: EUint64, commit_b: EUint64) -> EUint64 {
    commit_a ^ commit_b
}

const EXAMPLE_PROGRAM_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../../../target/deploy/encrypted_coin_flip_native.so"
);

fn setup_program(ctx: &mut EncryptTestContext) -> (Pubkey, Pubkey, u8) {
    let program_id = ctx.deploy_program(EXAMPLE_PROGRAM_PATH);
    let (cpi_authority, cpi_bump) = ctx.cpi_authority_for(&program_id);
    (program_id, cpi_authority, cpi_bump)
}

fn create_game_ix(
    program_id: &Pubkey, game_pda: &Pubkey, game_bump: u8, cpi_bump: u8,
    game_id: &[u8; 32], authority: &Pubkey, commit_a_ct: &Pubkey,
    result_ct: &Pubkey, encrypt_program: &Pubkey, config: &Pubkey,
    deposit: &Pubkey, cpi_authority: &Pubkey, network_encryption_key: &Pubkey,
    payer: &Pubkey, event_authority: &Pubkey,
) -> Instruction {
    let mut data = Vec::with_capacity(43);
    data.push(0u8);
    data.push(game_bump);
    data.push(cpi_bump);
    data.extend_from_slice(game_id);
    data.extend_from_slice(&0u64.to_le_bytes()); // bet_lamports = 0 for tests

    Instruction::new_with_bytes(*program_id, &data, vec![
        AccountMeta::new(*game_pda, false),
        AccountMeta::new_readonly(*authority, true),
        AccountMeta::new_readonly(*commit_a_ct, false),
        AccountMeta::new(*result_ct, true),
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

fn play_ix(
    program_id: &Pubkey, game: &Pubkey, side_b: &Pubkey,
    commit_a_ct: &Pubkey, commit_b_ct: &Pubkey, result_ct: &Pubkey,
    cpi_bump: u8, encrypt_program: &Pubkey, config: &Pubkey,
    deposit: &Pubkey, cpi_authority: &Pubkey, network_encryption_key: &Pubkey,
    payer: &Pubkey, event_authority: &Pubkey,
) -> Instruction {
    Instruction::new_with_bytes(*program_id, &[1u8, cpi_bump], vec![
        AccountMeta::new(*game, false),
        AccountMeta::new_readonly(*side_b, true),
        AccountMeta::new(*commit_a_ct, false),
        AccountMeta::new(*commit_b_ct, false),
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

fn cancel_game_ix(program_id: &Pubkey, game: &Pubkey, side_a: &Pubkey) -> Instruction {
    Instruction::new_with_bytes(*program_id, &[4u8], vec![
        AccountMeta::new(*game, false),
        AccountMeta::new(*side_a, true),
    ])
}

/// Helper: create a game and return (game_pda, commit_a_pubkey, result_ct_pubkey).
fn create_game_helper(
    ctx: &mut EncryptTestContext,
    program_id: &Pubkey,
    cpi_authority: &Pubkey,
    cpi_bump: u8,
    side_a: &Keypair,
    game_id: &[u8; 32],
    side_a_value: u128,
) -> (Pubkey, Pubkey, Pubkey) {
    let (game_pda, game_bump) =
        Pubkey::find_program_address(&[b"game", game_id.as_ref()], program_id);

    let commit_a_pubkey = ctx.create_input::<Uint64>(side_a_value, program_id);
    let result_ct = Keypair::new();

    let ix = create_game_ix(
        program_id, &game_pda, game_bump, cpi_bump, game_id,
        &side_a.pubkey(), &commit_a_pubkey, &result_ct.pubkey(),
        ctx.program_id(), ctx.config_pda(), ctx.deposit_pda(), cpi_authority,
        ctx.network_encryption_key_pda(), &ctx.payer().pubkey(), ctx.event_authority(),
    );
    ctx.send_transaction(&[ix], &[side_a, &result_ct]);

    let result_pubkey = result_ct.pubkey();
    ctx.register_ciphertext(&result_pubkey);

    (game_pda, commit_a_pubkey, result_pubkey)
}

/// Helper: play and process the graph. Returns decrypted result.
fn play_and_decrypt(
    ctx: &mut EncryptTestContext,
    program_id: &Pubkey,
    cpi_authority: &Pubkey,
    cpi_bump: u8,
    game_pda: &Pubkey,
    side_b: &Keypair,
    commit_a_pubkey: &Pubkey,
    result_pubkey: &Pubkey,
    side_b_value: u128,
) -> u128 {
    let commit_b_pubkey = ctx.create_input::<Uint64>(side_b_value, program_id);

    let ix = play_ix(
        program_id, game_pda, &side_b.pubkey(),
        commit_a_pubkey, &commit_b_pubkey, result_pubkey,
        cpi_bump, ctx.program_id(), ctx.config_pda(), ctx.deposit_pda(),
        cpi_authority, ctx.network_encryption_key_pda(),
        &ctx.payer().pubkey(), ctx.event_authority(),
    );
    ctx.send_transaction(&[ix], &[side_b]);

    let graph = coin_flip_graph();
    ctx.enqueue_graph_execution(&graph, &[*commit_a_pubkey, commit_b_pubkey], &[*result_pubkey]);
    ctx.process_pending();
    ctx.register_ciphertext(result_pubkey);

    ctx.decrypt_from_store(result_pubkey)
}

#[test]
fn test_create_game() {
    let mut ctx = EncryptTestContext::new_default();
    let (program_id, cpi_authority, cpi_bump) = setup_program(&mut ctx);
    let side_a = ctx.new_funded_keypair();

    let game_id = [1u8; 32];
    let (game_pda, _, _) = create_game_helper(
        &mut ctx, &program_id, &cpi_authority, cpi_bump, &side_a, &game_id, 1,
    );

    let data = ctx.get_account_data(&game_pda).expect("game not found");
    assert_eq!(data[0], 1);   // discriminator = GAME
    assert_eq!(data[161], 1); // is_active
    assert_eq!(data[162], 0); // not played
}

#[test]
fn test_player_wins() {
    let mut ctx = EncryptTestContext::new_default();
    let (program_id, cpi_authority, cpi_bump) = setup_program(&mut ctx);
    let side_a = ctx.new_funded_keypair();

    // side_a=0, side_b=1 -> XOR=1 -> side_a wins
    let game_id = [2u8; 32];
    let (game_pda, commit_a_pubkey, result_pubkey) = create_game_helper(
        &mut ctx, &program_id, &cpi_authority, cpi_bump, &side_a, &game_id, 0,
    );

    let side_b = ctx.new_funded_keypair();
    let result = play_and_decrypt(
        &mut ctx, &program_id, &cpi_authority, cpi_bump,
        &game_pda, &side_b, &commit_a_pubkey, &result_pubkey, 1,
    );
    assert_eq!(result, 1, "0 XOR 1 = 1 (side_a wins)");

    // Verify played flag
    let data = ctx.get_account_data(&game_pda).expect("game");
    assert_eq!(data[162], 1); // played
}

#[test]
fn test_house_wins() {
    let mut ctx = EncryptTestContext::new_default();
    let (program_id, cpi_authority, cpi_bump) = setup_program(&mut ctx);
    let side_a = ctx.new_funded_keypair();

    // side_a=1, side_b=1 -> XOR=0 -> side_b wins
    let game_id = [3u8; 32];
    let (game_pda, commit_a_pubkey, result_pubkey) = create_game_helper(
        &mut ctx, &program_id, &cpi_authority, cpi_bump, &side_a, &game_id, 1,
    );

    let side_b = ctx.new_funded_keypair();
    let result = play_and_decrypt(
        &mut ctx, &program_id, &cpi_authority, cpi_bump,
        &game_pda, &side_b, &commit_a_pubkey, &result_pubkey, 1,
    );
    assert_eq!(result, 0, "1 XOR 1 = 0 (side_b wins)");
}

#[test]
fn test_cancel_game() {
    let mut ctx = EncryptTestContext::new_default();
    let (program_id, _cpi_authority, cpi_bump) = setup_program(&mut ctx);
    let side_a = ctx.new_funded_keypair();

    let game_id = [4u8; 32];
    let (game_pda, _, _) = create_game_helper(
        &mut ctx, &program_id, &_cpi_authority, cpi_bump, &side_a, &game_id, 0,
    );

    let ix = cancel_game_ix(&program_id, &game_pda, &side_a.pubkey());
    ctx.send_transaction(&[ix], &[&side_a]);

    let data = ctx.get_account_data(&game_pda).expect("game");
    assert_eq!(data[161], 0); // cancelled
}
