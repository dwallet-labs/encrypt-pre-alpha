// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! LiteSVM end-to-end tests for the encrypted coin flip example.
//!
//! Single-player game: house creates game (with result_ct), player flips,
//! either party can close/reveal.

use encrypt_dsl::prelude::encrypt_fn;
use encrypt_solana_test::litesvm::EncryptTestContext;
use encrypt_types::encrypted::{EUint64, Uint64};
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Keypair;
use solana_sdk::signer::Signer;

#[encrypt_fn]
fn coin_flip_graph(house_commit: EUint64, player_commit: EUint64) -> EUint64 {
    house_commit ^ player_commit
}

const EXAMPLE_PROGRAM_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../../../target/deploy/encrypted_coin_flip.so"
);

fn setup_program(ctx: &mut EncryptTestContext) -> (Pubkey, Pubkey, u8) {
    let program_id = ctx.deploy_program(EXAMPLE_PROGRAM_PATH);
    let (cpi_authority, cpi_bump) = ctx.cpi_authority_for(&program_id);
    (program_id, cpi_authority, cpi_bump)
}

fn create_game_ix(
    program_id: &Pubkey, game_pda: &Pubkey, game_bump: u8, cpi_bump: u8,
    game_id: &[u8; 32], authority: &Pubkey, house_commit_ct: &Pubkey,
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
        AccountMeta::new_readonly(*house_commit_ct, false),
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
    program_id: &Pubkey, game: &Pubkey, player: &Pubkey,
    house_commit_ct: &Pubkey, player_commit_ct: &Pubkey, result_ct: &Pubkey,
    cpi_bump: u8, encrypt_program: &Pubkey, config: &Pubkey,
    deposit: &Pubkey, cpi_authority: &Pubkey, network_encryption_key: &Pubkey,
    payer: &Pubkey, event_authority: &Pubkey,
) -> Instruction {
    Instruction::new_with_bytes(*program_id, &[1u8, cpi_bump], vec![
        AccountMeta::new(*game, false),
        AccountMeta::new_readonly(*player, true),
        AccountMeta::new(*house_commit_ct, false),
        AccountMeta::new(*player_commit_ct, false),
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

/// Helper: create a game and return (game_pda, house_commit_pubkey, result_ct_pubkey).
fn create_game_helper(
    ctx: &mut EncryptTestContext,
    program_id: &Pubkey,
    cpi_authority: &Pubkey,
    cpi_bump: u8,
    authority: &Keypair,
    game_id: &[u8; 32],
    house_value: u128,
) -> (Pubkey, Pubkey, Pubkey) {
    let (game_pda, game_bump) =
        Pubkey::find_program_address(&[b"game", game_id.as_ref()], program_id);

    let house_pubkey = ctx.create_input::<Uint64>(house_value, program_id);
    let result_ct = Keypair::new();

    let ix = create_game_ix(
        program_id, &game_pda, game_bump, cpi_bump, game_id,
        &authority.pubkey(), &house_pubkey, &result_ct.pubkey(),
        ctx.program_id(), ctx.config_pda(), ctx.deposit_pda(), cpi_authority,
        ctx.network_encryption_key_pda(), &ctx.payer().pubkey(), ctx.event_authority(),
    );
    ctx.send_transaction(&[ix], &[authority, &result_ct]);

    let result_pubkey = result_ct.pubkey();
    ctx.register_ciphertext(&result_pubkey);

    (game_pda, house_pubkey, result_pubkey)
}

/// Helper: play and process the graph. Returns decrypted result.
fn play_and_decrypt(
    ctx: &mut EncryptTestContext,
    program_id: &Pubkey,
    cpi_authority: &Pubkey,
    cpi_bump: u8,
    game_pda: &Pubkey,
    player: &Keypair,
    house_pubkey: &Pubkey,
    result_pubkey: &Pubkey,
    player_value: u128,
) -> u128 {
    let player_pubkey = ctx.create_input::<Uint64>(player_value, program_id);

    let ix = play_ix(
        program_id, game_pda, &player.pubkey(),
        house_pubkey, &player_pubkey, result_pubkey,
        cpi_bump, ctx.program_id(), ctx.config_pda(), ctx.deposit_pda(),
        cpi_authority, ctx.network_encryption_key_pda(),
        &ctx.payer().pubkey(), ctx.event_authority(),
    );
    ctx.send_transaction(&[ix], &[player]);

    let graph = coin_flip_graph();
    ctx.enqueue_graph_execution(&graph, &[*house_pubkey, player_pubkey], &[*result_pubkey]);
    ctx.process_pending();
    ctx.register_ciphertext(result_pubkey);

    ctx.decrypt_from_store(result_pubkey)
}

#[test]
fn test_create_game() {
    let mut ctx = EncryptTestContext::new_default();
    let (program_id, cpi_authority, cpi_bump) = setup_program(&mut ctx);
    let authority = ctx.new_funded_keypair();

    let game_id = [1u8; 32];
    let (game_pda, _, _) = create_game_helper(
        &mut ctx, &program_id, &cpi_authority, cpi_bump, &authority, &game_id, 1,
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
    let authority = ctx.new_funded_keypair();

    // house=0, player=1 → XOR=1 → player wins
    let game_id = [2u8; 32];
    let (game_pda, house_pubkey, result_pubkey) = create_game_helper(
        &mut ctx, &program_id, &cpi_authority, cpi_bump, &authority, &game_id, 0,
    );

    let player = ctx.new_funded_keypair();
    let result = play_and_decrypt(
        &mut ctx, &program_id, &cpi_authority, cpi_bump,
        &game_pda, &player, &house_pubkey, &result_pubkey, 1,
    );
    assert_eq!(result, 1, "0 XOR 1 = 1 (player wins)");

    // Verify played flag
    let data = ctx.get_account_data(&game_pda).expect("game");
    assert_eq!(data[162], 1); // played
}

#[test]
fn test_house_wins() {
    let mut ctx = EncryptTestContext::new_default();
    let (program_id, cpi_authority, cpi_bump) = setup_program(&mut ctx);
    let authority = ctx.new_funded_keypair();

    // house=1, player=1 → XOR=0 → house wins
    let game_id = [3u8; 32];
    let (game_pda, house_pubkey, result_pubkey) = create_game_helper(
        &mut ctx, &program_id, &cpi_authority, cpi_bump, &authority, &game_id, 1,
    );

    let player = ctx.new_funded_keypair();
    let result = play_and_decrypt(
        &mut ctx, &program_id, &cpi_authority, cpi_bump,
        &game_pda, &player, &house_pubkey, &result_pubkey, 1,
    );
    assert_eq!(result, 0, "1 XOR 1 = 0 (house wins)");
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
