// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! LiteSVM end-to-end tests for the encrypted coin flip anchor example.
//!
//! Uses Anchor's instruction discriminator scheme: first 8 bytes of sha256("global:<name>").

use encrypt_dsl::prelude::encrypt_fn;
use encrypt_solana_test::litesvm::EncryptTestContext;
use encrypt_types::encrypted::{EUint64, Uint64};
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Keypair;
use solana_sdk::signer::Signer;

const EXAMPLE_PROGRAM_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../../../target/deploy/encrypted_coin_flip_anchor.so"
);

/// Anchor program ID must match declare_id!
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
        "request_result_decryption" => [127, 255, 201, 251, 255, 73, 160, 131],
        "reveal_result" => [251, 165, 27, 86, 52, 234, 133, 173],
        "cancel_game" => [121, 194, 154, 118, 103, 235, 149, 52],
        _ => panic!("unknown anchor instruction: {name}"),
    }
}

fn setup_anchor_program(ctx: &mut EncryptTestContext) -> (Pubkey, Pubkey, u8) {
    let program_id = Pubkey::try_from(ANCHOR_PROGRAM_ID).unwrap();
    ctx.deploy_program_at(&program_id, EXAMPLE_PROGRAM_PATH);
    let (cpi_authority, cpi_bump) = ctx.cpi_authority_for(&program_id);
    (program_id, cpi_authority, cpi_bump)
}

/// Build create_game instruction with Anchor encoding.
/// Anchor ix data: disc(8) + game_id(32) + commit_a_id(32) + result_ct_id(32) + bet_lamports(8)
fn create_game_ix(
    program_id: &Pubkey,
    game_pda: &Pubkey,
    game_id: &[u8; 32],
    commit_a_ct: &Pubkey,
    result_ct: &Pubkey,
    side_a: &Pubkey,
    payer: &Pubkey,
) -> Instruction {
    let mut data = Vec::with_capacity(8 + 32 + 32 + 32 + 8);
    data.extend_from_slice(&anchor_disc("create_game"));
    data.extend_from_slice(game_id);
    data.extend_from_slice(commit_a_ct.as_ref());
    data.extend_from_slice(result_ct.as_ref());
    data.extend_from_slice(&0u64.to_le_bytes()); // bet_lamports = 0 for tests

    Instruction::new_with_bytes(
        *program_id,
        &data,
        vec![
            AccountMeta::new(*game_pda, false),
            AccountMeta::new_readonly(*side_a, true),
            AccountMeta::new(*payer, true),
            AccountMeta::new_readonly(Pubkey::new_from_array([0u8; 32]), false), // system_program
        ],
    )
}

/// Build play instruction.
/// Anchor data: disc(8) + cpi_authority_bump(1)
fn play_ix(
    program_id: &Pubkey,
    game: &Pubkey,
    side_b: &Pubkey,
    commit_a_ct: &Pubkey,
    commit_b_ct: &Pubkey,
    result_ct: &Pubkey,
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
    data.extend_from_slice(&anchor_disc("play"));
    data.push(cpi_authority_bump);

    Instruction::new_with_bytes(
        *program_id,
        &data,
        vec![
            AccountMeta::new(*game, false),
            AccountMeta::new(*side_b, true),
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
        ],
    )
}

/// Build cancel_game instruction.
fn cancel_game_ix(program_id: &Pubkey, game: &Pubkey, side_a: &Pubkey) -> Instruction {
    Instruction::new_with_bytes(
        *program_id,
        &anchor_disc("cancel_game"),
        vec![
            AccountMeta::new(*game, false),
            AccountMeta::new(*side_a, true),
        ],
    )
}

/// Helper: create a game and return (game_pda, commit_a_pubkey, result_ct_pubkey).
/// The result ciphertext is pre-created via the harness so it exists on chain.
fn create_game_helper(
    ctx: &mut EncryptTestContext,
    program_id: &Pubkey,
    side_a: &Keypair,
    game_id: &[u8; 32],
    side_a_value: u128,
) -> (Pubkey, Pubkey, Pubkey) {
    let (game_pda, _game_bump) =
        Pubkey::find_program_address(&[b"game", game_id.as_ref()], program_id);

    let commit_a_pubkey = ctx.create_input::<Uint64>(side_a_value, program_id);
    let result_ct = ctx.create_input::<Uint64>(0, program_id);

    let ix = create_game_ix(
        program_id, &game_pda, game_id,
        &commit_a_pubkey, &result_ct,
        &side_a.pubkey(), &ctx.payer().pubkey(),
    );
    ctx.send_transaction(&[ix], &[side_a]);

    ctx.register_ciphertext(&result_ct);

    (game_pda, commit_a_pubkey, result_ct)
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
        ctx.program_id(), ctx.config_pda(), ctx.deposit_pda(),
        cpi_authority, ctx.network_encryption_key_pda(),
        &ctx.payer().pubkey(), ctx.event_authority(), cpi_bump,
    );
    ctx.send_transaction(&[ix], &[side_b]);

    let graph = coin_flip_graph();
    ctx.enqueue_graph_execution(&graph, &[*commit_a_pubkey, commit_b_pubkey], &[*result_pubkey]);
    ctx.process_pending();
    ctx.register_ciphertext(result_pubkey);

    ctx.decrypt_from_store(result_pubkey)
}

// Anchor Game layout:
// [0..8]: anchor disc, [8..40]: side_a, [40..72]: game_id,
// [72..104]: commit_a, [104..136]: result_ct, [136..168]: side_b,
// [168]: is_active, [169]: played, [170..202]: pending_digest,
// [202]: revealed_result, [203..211]: bet_lamports, [211]: bump
// Total: 212 bytes

#[test]
fn test_create_game() {
    let mut ctx = EncryptTestContext::new_default();
    let (program_id, _cpi_authority, _cpi_bump) = setup_anchor_program(&mut ctx);
    let side_a = ctx.new_funded_keypair();

    let game_id = [1u8; 32];
    let (game_pda, _, _) = create_game_helper(
        &mut ctx, &program_id, &side_a, &game_id, 1,
    );

    let data = ctx.get_account_data(&game_pda).expect("game not found");
    assert!(data.len() >= 212, "should have anchor disc + data");
    assert_eq!(data[168], 1); // is_active = true
    assert_eq!(data[169], 0); // played = false
}

#[test]
fn test_cancel_game() {
    let mut ctx = EncryptTestContext::new_default();
    let (program_id, _cpi_authority, _cpi_bump) = setup_anchor_program(&mut ctx);
    let side_a = ctx.new_funded_keypair();

    let game_id = [2u8; 32];
    let (game_pda, _, _) = create_game_helper(
        &mut ctx, &program_id, &side_a, &game_id, 0,
    );

    let ix = cancel_game_ix(&program_id, &game_pda, &side_a.pubkey());
    ctx.send_transaction(&[ix], &[&side_a]);

    let data = ctx.get_account_data(&game_pda).expect("game");
    assert_eq!(data[168], 0); // closed
}

#[test]
fn test_player_wins() {
    let mut ctx = EncryptTestContext::new_default();
    let (program_id, cpi_authority, cpi_bump) = setup_anchor_program(&mut ctx);
    let side_a = ctx.new_funded_keypair();

    // side_a=0, side_b=1 -> XOR=1 -> side_a wins
    let game_id = [3u8; 32];
    let (game_pda, commit_a_pubkey, result_pubkey) = create_game_helper(
        &mut ctx, &program_id, &side_a, &game_id, 0,
    );

    let side_b = ctx.new_funded_keypair();
    let result = play_and_decrypt(
        &mut ctx, &program_id, &cpi_authority, cpi_bump,
        &game_pda, &side_b, &commit_a_pubkey, &result_pubkey, 1,
    );
    assert_eq!(result, 1, "0 XOR 1 = 1 (side_a wins)");

    // Verify played flag
    let data = ctx.get_account_data(&game_pda).expect("game");
    assert_eq!(data[169], 1); // played
}

#[test]
fn test_house_wins() {
    let mut ctx = EncryptTestContext::new_default();
    let (program_id, cpi_authority, cpi_bump) = setup_anchor_program(&mut ctx);
    let side_a = ctx.new_funded_keypair();

    // side_a=1, side_b=1 -> XOR=0 -> side_b wins
    let game_id = [4u8; 32];
    let (game_pda, commit_a_pubkey, result_pubkey) = create_game_helper(
        &mut ctx, &program_id, &side_a, &game_id, 1,
    );

    let side_b = ctx.new_funded_keypair();
    let result = play_and_decrypt(
        &mut ctx, &program_id, &cpi_authority, cpi_bump,
        &game_pda, &side_b, &commit_a_pubkey, &result_pubkey, 1,
    );
    assert_eq!(result, 0, "1 XOR 1 = 0 (side_b wins)");
}
