// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! solana-program-test end-to-end tests for encrypted coin flip example.

use encrypt_dsl::prelude::encrypt_fn;
use encrypt_solana_test::program_test::ProgramTestEncryptContext;
use encrypt_types::encrypted::{EUint64, Uint64};
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Keypair;
use solana_sdk::signer::Signer;

#[encrypt_fn]
fn coin_flip_graph(house_commit: EUint64, player_commit: EUint64) -> EUint64 {
    house_commit ^ player_commit
}

fn setup() -> (ProgramTestEncryptContext, Pubkey, Pubkey, u8) {
    let program_id = Pubkey::new_unique();
    let ctx = ProgramTestEncryptContext::builder()
        .add_program("encrypted_coin_flip", program_id)
        .build();
    let (cpi_authority, cpi_bump) = ctx.cpi_authority_for(&program_id);
    (ctx, program_id, cpi_authority, cpi_bump)
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

fn cancel_game_ix(program_id: &Pubkey, game: &Pubkey, side_a: &Pubkey) -> Instruction {
    Instruction::new_with_bytes(*program_id, &[4u8], vec![
        AccountMeta::new(*game, false),
        AccountMeta::new(*side_a, true),
    ])
}

#[test]
fn test_create_and_cancel_game() {
    let (mut ctx, program_id, cpi_authority, cpi_bump) = setup();
    let authority = ctx.new_funded_keypair();

    let game_id = [1u8; 32];
    let (game_pda, game_bump) =
        Pubkey::find_program_address(&[b"game", &game_id], &program_id);

    let house_pubkey = ctx.create_input::<Uint64>(1, &program_id);
    let result_ct = Keypair::new();

    let ix = create_game_ix(
        &program_id, &game_pda, game_bump, cpi_bump, &game_id,
        &authority.pubkey(), &house_pubkey, &result_ct.pubkey(),
        ctx.program_id(), ctx.config_pda(), ctx.deposit_pda(), &cpi_authority,
        ctx.network_encryption_key_pda(), &ctx.payer().pubkey(), ctx.event_authority(),
    );
    ctx.send_transaction(&[ix], &[&authority, &result_ct]);

    let data = ctx.get_account_data(&game_pda).expect("game");
    assert_eq!(data[0], 1);   // GAME
    assert_eq!(data[161], 1); // is_active
    assert_eq!(data[162], 0); // not played

    let cancel_ix = cancel_game_ix(&program_id, &game_pda, &authority.pubkey());
    ctx.send_transaction(&[cancel_ix], &[&authority]);

    let data = ctx.get_account_data(&game_pda).expect("game");
    assert_eq!(data[161], 0); // cancelled
}

#[test]
fn test_play_and_decrypt() {
    let (mut ctx, program_id, cpi_authority, cpi_bump) = setup();
    let authority = ctx.new_funded_keypair();

    let game_id = [2u8; 32];
    let (game_pda, game_bump) =
        Pubkey::find_program_address(&[b"game", &game_id], &program_id);

    // House commits 0
    let house_pubkey = ctx.create_input::<Uint64>(0, &program_id);
    let result_ct = Keypair::new();

    let create_ix = create_game_ix(
        &program_id, &game_pda, game_bump, cpi_bump, &game_id,
        &authority.pubkey(), &house_pubkey, &result_ct.pubkey(),
        ctx.program_id(), ctx.config_pda(), ctx.deposit_pda(), &cpi_authority,
        ctx.network_encryption_key_pda(), &ctx.payer().pubkey(), ctx.event_authority(),
    );
    ctx.send_transaction(&[create_ix], &[&authority, &result_ct]);

    let result_pubkey = result_ct.pubkey();
    ctx.register_ciphertext(&result_pubkey);

    // Player commits 1 → XOR = 1 → player wins
    let player = ctx.new_funded_keypair();
    let player_pubkey = ctx.create_input::<Uint64>(1, &program_id);

    let play_ix = Instruction::new_with_bytes(program_id, &[1u8, cpi_bump], vec![
        AccountMeta::new(game_pda, false),
        AccountMeta::new_readonly(player.pubkey(), true),
        AccountMeta::new(house_pubkey, false),
        AccountMeta::new(player_pubkey, false),
        AccountMeta::new(result_pubkey, false),
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
    ctx.send_transaction(&[play_ix], &[&player]);

    let graph = coin_flip_graph();
    ctx.enqueue_graph_execution(&graph, &[house_pubkey, player_pubkey], &[result_pubkey]);
    ctx.process_pending();
    ctx.register_ciphertext(&result_pubkey);

    let result = ctx.decrypt_from_store(&result_pubkey);
    assert_eq!(result, 1, "0 XOR 1 = 1 (player wins)");
}
