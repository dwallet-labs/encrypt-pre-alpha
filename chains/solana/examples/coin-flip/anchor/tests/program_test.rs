// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! solana-program-test end-to-end tests for encrypted coin flip anchor example.

use encrypt_dsl::prelude::encrypt_fn;
use encrypt_solana_test::program_test::ProgramTestEncryptContext;
use encrypt_types::encrypted::{EUint64, Uint64};
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signer::Signer;

const ANCHOR_PROGRAM_ID: &str = "CoinF1ipAnchor11111111111111111111111111111";

#[encrypt_fn]
fn coin_flip_graph(commit_a: EUint64, commit_b: EUint64) -> EUint64 {
    commit_a ^ commit_b
}

/// Anchor instruction discriminator: first 8 bytes of sha256("global:<name>")
fn anchor_disc(name: &str) -> [u8; 8] {
    match name {
        "create_game" => [124, 69, 75, 66, 184, 220, 72, 206],
        "play" => [213, 157, 193, 142, 228, 56, 248, 150],
        "cancel_game" => [121, 194, 154, 118, 103, 235, 149, 52],
        _ => panic!("unknown anchor instruction: {name}"),
    }
}

fn setup() -> (ProgramTestEncryptContext, Pubkey, Pubkey, u8) {
    let program_id = Pubkey::try_from(ANCHOR_PROGRAM_ID).unwrap();
    let ctx = ProgramTestEncryptContext::builder()
        .add_program("encrypted_coin_flip_anchor", program_id)
        .build();
    let (cpi_authority, cpi_bump) = ctx.cpi_authority_for(&program_id);
    (ctx, program_id, cpi_authority, cpi_bump)
}

fn create_game_ix(
    program_id: &Pubkey, game_pda: &Pubkey, game_id: &[u8; 32],
    commit_a_ct: &Pubkey, result_ct: &Pubkey,
    side_a: &Pubkey, payer: &Pubkey,
) -> Instruction {
    let mut data = Vec::with_capacity(8 + 32 + 32 + 32 + 8);
    data.extend_from_slice(&anchor_disc("create_game"));
    data.extend_from_slice(game_id);
    data.extend_from_slice(commit_a_ct.as_ref());
    data.extend_from_slice(result_ct.as_ref());
    data.extend_from_slice(&0u64.to_le_bytes()); // bet_lamports = 0 for tests

    Instruction::new_with_bytes(*program_id, &data, vec![
        AccountMeta::new(*game_pda, false),
        AccountMeta::new_readonly(*side_a, true),
        AccountMeta::new(*payer, true),
        AccountMeta::new_readonly(Pubkey::new_from_array([0u8; 32]), false),
    ])
}

fn cancel_game_ix(program_id: &Pubkey, game: &Pubkey, side_a: &Pubkey) -> Instruction {
    Instruction::new_with_bytes(*program_id, &anchor_disc("cancel_game"), vec![
        AccountMeta::new(*game, false),
        AccountMeta::new(*side_a, true),
    ])
}

// Anchor Game offsets: [168] = is_active, [169] = played

#[test]
fn test_create_and_cancel_game() {
    let (mut ctx, program_id, _cpi_authority, _cpi_bump) = setup();
    let side_a = ctx.new_funded_keypair();

    let game_id = [1u8; 32];
    let (game_pda, _) =
        Pubkey::find_program_address(&[b"game", &game_id], &program_id);

    let commit_a_ct = Pubkey::new_unique();
    let result_ct = Pubkey::new_unique();

    let ix = create_game_ix(
        &program_id, &game_pda, &game_id,
        &commit_a_ct, &result_ct,
        &side_a.pubkey(), &ctx.payer().pubkey(),
    );
    ctx.send_transaction(&[ix], &[&side_a]);

    let data = ctx.get_account_data(&game_pda).expect("game");
    assert_eq!(data[168], 1); // is_active = true
    assert_eq!(data[169], 0); // played = false

    let cancel_ix = cancel_game_ix(&program_id, &game_pda, &side_a.pubkey());
    ctx.send_transaction(&[cancel_ix], &[&side_a]);

    let data = ctx.get_account_data(&game_pda).expect("game");
    assert_eq!(data[168], 0); // cancelled
}

#[test]
fn test_play_and_decrypt() {
    let (mut ctx, program_id, cpi_authority, cpi_bump) = setup();
    let side_a = ctx.new_funded_keypair();

    let game_id = [2u8; 32];
    let (game_pda, _) =
        Pubkey::find_program_address(&[b"game", &game_id], &program_id);

    // Side A commits 0
    let commit_a_pubkey = ctx.create_input::<Uint64>(0, &program_id);
    // Pre-create result ciphertext and store its pubkey in the game
    let result_ct = ctx.create_input::<Uint64>(0, &program_id);

    let create_ix = create_game_ix(
        &program_id, &game_pda, &game_id,
        &commit_a_pubkey, &result_ct,
        &side_a.pubkey(), &ctx.payer().pubkey(),
    );
    ctx.send_transaction(&[create_ix], &[&side_a]);

    // Side B commits 1 -> XOR = 1 -> side_a wins
    let side_b = ctx.new_funded_keypair();
    let commit_b_pubkey = ctx.create_input::<Uint64>(1, &program_id);

    let mut play_data = Vec::with_capacity(9);
    play_data.extend_from_slice(&anchor_disc("play"));
    play_data.push(cpi_bump);

    let play_ix = Instruction::new_with_bytes(program_id, &play_data, vec![
        AccountMeta::new(game_pda, false),
        AccountMeta::new(side_b.pubkey(), true),
        AccountMeta::new(commit_a_pubkey, false),
        AccountMeta::new(commit_b_pubkey, false),
        AccountMeta::new(result_ct, false),
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
    ctx.send_transaction(&[play_ix], &[&side_b]);

    let graph = coin_flip_graph();
    ctx.enqueue_graph_execution(&graph, &[commit_a_pubkey, commit_b_pubkey], &[result_ct]);
    ctx.process_pending();
    ctx.register_ciphertext(&result_ct);

    let result = ctx.decrypt_from_store(&result_ct);
    assert_eq!(result, 1, "0 XOR 1 = 1 (side_a wins)");
}
