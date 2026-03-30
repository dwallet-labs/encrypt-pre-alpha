// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/// Encrypted Coin Flip — Native solana-program version with on-chain escrow.
///
/// Two sides each commit an encrypted value (0 or 1). Result = XOR.
/// Both deposit equal bets into the game PDA. Winner gets 2x.
///
/// ## Flow
///
/// 1. Side A creates game (deposits bet, commits encrypted value, pre-creates result_ct)
/// 2. Side B joins (matches bet, commits encrypted value, XOR graph executes)
/// 3. Anyone requests decryption + reveals result
/// 4. Winner gets 2x bet from escrow
///
/// ## Instructions
///
/// 0. `create_game` — side A creates game + deposits bet
/// 1. `play` — side B matches bet + commits, graph executes
/// 2. `request_result_decryption` — anyone (after both played)
/// 3. `reveal_result` — anyone, pays winner from escrow
/// 4. `cancel_game` — side A only, before side B joins, refunds bet

use encrypt_dsl::prelude::encrypt_fn;
use encrypt_native::EncryptContext;
use encrypt_types::encrypted::{EUint64, Uint64};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    msg,
    program::invoke,
    program::invoke_signed,
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::Rent,
    sysvar::Sysvar,
};
use solana_system_interface::instruction as system_instruction;

entrypoint!(process_instruction);

// ── Account discriminator ──

const GAME: u8 = 1;

// ── Account layout ──
// discriminator(1) + side_a(32) + game_id(32) + commit_a(32) + result_ct(32)
// + side_b(32) + is_active(1) + played(1) + pending_digest(32) + revealed_result(1)
// + bet_lamports(8) + bump(1) = 205

const GAME_LEN: usize = 205;

// Offsets into Game account data
const OFF_DISC: usize = 0;
const OFF_SIDE_A: usize = 1;
const OFF_GAME_ID: usize = 33;
const OFF_COMMIT_A: usize = 65;
const OFF_RESULT_CT: usize = 97;
const OFF_SIDE_B: usize = 129;
const OFF_IS_ACTIVE: usize = 161;
const OFF_PLAYED: usize = 162;
const OFF_PENDING_DIGEST: usize = 163;
const OFF_REVEALED_RESULT: usize = 195;
const OFF_BET_LAMPORTS: usize = 196;
const OFF_BUMP: usize = 204;

// ── FHE Graph ──

/// Coin flip: XOR side A and side B commitments.
///
/// Result = commit_a ^ commit_b.
/// XOR=1 -> side_a wins, XOR=0 -> side_b wins.
#[encrypt_fn]
fn coin_flip_graph(commit_a: EUint64, commit_b: EUint64) -> EUint64 {
    commit_a ^ commit_b
}

// ── Entrypoint ──

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    match data.first() {
        Some(&0) => create_game(program_id, accounts, &data[1..]),
        Some(&1) => play(accounts, &data[1..]),
        Some(&2) => request_result_decryption(accounts, &data[1..]),
        Some(&3) => reveal_result(accounts),
        Some(&4) => cancel_game(accounts),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

// ── 0: create_game ──
// data: game_bump(1) | cpi_authority_bump(1) | game_id(32) | bet_lamports(8)
// accounts: [game_pda(w), side_a(s), commit_a_ct, result_ct(w,s),
//            encrypt_program, config, deposit(w), cpi_authority,
//            caller_program, network_encryption_key, payer(s,w),
//            event_authority, system_program]

fn create_game(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    let iter = &mut accounts.iter();
    let game_acct = next_account_info(iter)?;
    let side_a = next_account_info(iter)?;
    let commit_a_ct = next_account_info(iter)?;
    let result_ct = next_account_info(iter)?;
    let encrypt_program = next_account_info(iter)?;
    let config = next_account_info(iter)?;
    let deposit = next_account_info(iter)?;
    let cpi_authority = next_account_info(iter)?;
    let caller_program = next_account_info(iter)?;
    let network_encryption_key = next_account_info(iter)?;
    let payer = next_account_info(iter)?;
    let event_authority = next_account_info(iter)?;
    let system_program = next_account_info(iter)?;

    if !side_a.is_signer || !payer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if data.len() < 42 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let game_bump = data[0];
    let cpi_authority_bump = data[1];
    let game_id: [u8; 32] = data[2..34].try_into().unwrap();
    let bet_lamports = u64::from_le_bytes(data[34..42].try_into().unwrap());

    // Create game PDA
    let seeds = &[b"game".as_ref(), game_id.as_ref(), &[game_bump]];
    let rent = Rent::get()?;
    let lamports = rent.minimum_balance(GAME_LEN);

    invoke_signed(
        &system_instruction::create_account(
            payer.key,
            game_acct.key,
            lamports,
            GAME_LEN as u64,
            program_id,
        ),
        &[payer.clone(), game_acct.clone(), system_program.clone()],
        &[seeds],
    )?;

    // Side A deposits bet
    if bet_lamports > 0 {
        invoke(
            &system_instruction::transfer(payer.key, game_acct.key, bet_lamports),
            &[payer.clone(), game_acct.clone(), system_program.clone()],
        )?;
    }

    // Pre-create result ciphertext (encrypted zero -- will be overwritten by graph)
    let ctx = EncryptContext {
        encrypt_program,
        config,
        deposit,
        cpi_authority,
        caller_program,
        network_encryption_key,
        payer,
        event_authority,
        system_program,
        cpi_authority_bump,
    };
    ctx.create_plaintext_typed::<Uint64>(&0u64, result_ct)?;

    // Write game state
    let mut d = game_acct.try_borrow_mut_data()?;
    d[OFF_DISC] = GAME;
    d[OFF_SIDE_A..OFF_SIDE_A + 32].copy_from_slice(side_a.key.as_ref());
    d[OFF_GAME_ID..OFF_GAME_ID + 32].copy_from_slice(&game_id);
    d[OFF_COMMIT_A..OFF_COMMIT_A + 32].copy_from_slice(commit_a_ct.key.as_ref());
    d[OFF_RESULT_CT..OFF_RESULT_CT + 32].copy_from_slice(result_ct.key.as_ref());
    d[OFF_SIDE_B..OFF_SIDE_B + 32].copy_from_slice(&[0u8; 32]);
    d[OFF_IS_ACTIVE] = 1;
    d[OFF_PLAYED] = 0;
    d[OFF_PENDING_DIGEST..OFF_PENDING_DIGEST + 32].copy_from_slice(&[0u8; 32]);
    d[OFF_REVEALED_RESULT] = 0;
    d[OFF_BET_LAMPORTS..OFF_BET_LAMPORTS + 8].copy_from_slice(&bet_lamports.to_le_bytes());
    d[OFF_BUMP] = game_bump;

    msg!("Game created");
    Ok(())
}

// ── 1: play ──
// data: cpi_authority_bump(1)
// accounts: [game(w), side_b(s,w), commit_a_ct, commit_b_ct,
//            result_ct(w), encrypt_program, config, deposit(w), cpi_authority,
//            caller_program, network_encryption_key, payer(s,w),
//            event_authority, system_program]

fn play(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let iter = &mut accounts.iter();
    let game_acct = next_account_info(iter)?;
    let side_b = next_account_info(iter)?;
    let commit_a_ct = next_account_info(iter)?;
    let commit_b_ct = next_account_info(iter)?;
    let result_ct = next_account_info(iter)?;
    let encrypt_program = next_account_info(iter)?;
    let config = next_account_info(iter)?;
    let deposit = next_account_info(iter)?;
    let cpi_authority = next_account_info(iter)?;
    let caller_program = next_account_info(iter)?;
    let network_encryption_key = next_account_info(iter)?;
    let payer = next_account_info(iter)?;
    let event_authority = next_account_info(iter)?;
    let system_program = next_account_info(iter)?;

    if !side_b.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }

    let cpi_authority_bump = data[0];

    // Verify game is active and not yet played
    let game_data = game_acct.try_borrow_data()?;
    if game_data[OFF_DISC] != GAME {
        return Err(ProgramError::InvalidAccountData);
    }
    if game_data[OFF_IS_ACTIVE] == 0 {
        return Err(ProgramError::InvalidArgument);
    }
    if game_data[OFF_PLAYED] != 0 {
        return Err(ProgramError::InvalidArgument); // already played
    }

    // Verify accounts match game state
    if commit_a_ct.key.as_ref() != &game_data[OFF_COMMIT_A..OFF_COMMIT_A + 32] {
        return Err(ProgramError::InvalidArgument);
    }
    if result_ct.key.as_ref() != &game_data[OFF_RESULT_CT..OFF_RESULT_CT + 32] {
        return Err(ProgramError::InvalidArgument);
    }

    // Side B matches bet
    let bet = u64::from_le_bytes(
        game_data[OFF_BET_LAMPORTS..OFF_BET_LAMPORTS + 8]
            .try_into()
            .unwrap(),
    );
    drop(game_data);

    if bet > 0 {
        invoke(
            &system_instruction::transfer(side_b.key, game_acct.key, bet),
            &[side_b.clone(), game_acct.clone(), system_program.clone()],
        )?;
    }

    // Execute coin flip via CPI: result = commit_a ^ commit_b
    let ctx = EncryptContext {
        encrypt_program,
        config,
        deposit,
        cpi_authority,
        caller_program,
        network_encryption_key,
        payer,
        event_authority,
        system_program,
        cpi_authority_bump,
    };

    ctx.coin_flip_graph(
        commit_a_ct.clone(),
        commit_b_ct.clone(),
        result_ct.clone(),
    )?;

    // Mark as played, record side_b
    let mut game_data = game_acct.try_borrow_mut_data()?;
    game_data[OFF_SIDE_B..OFF_SIDE_B + 32].copy_from_slice(side_b.key.as_ref());
    game_data[OFF_PLAYED] = 1;

    msg!("Side B played");
    Ok(())
}

// ── 2: request_result_decryption ──
// data: cpi_authority_bump(1)
// accounts: [game(w), request_acct(w), result_ciphertext,
//            encrypt_program, config, deposit(w), cpi_authority,
//            caller_program, network_encryption_key, payer(s,w),
//            event_authority, system_program]
//
// Anyone can call after both sides played.

fn request_result_decryption(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let iter = &mut accounts.iter();
    let game_acct = next_account_info(iter)?;
    let request_acct = next_account_info(iter)?;
    let result_ciphertext = next_account_info(iter)?;
    let encrypt_program = next_account_info(iter)?;
    let config = next_account_info(iter)?;
    let deposit = next_account_info(iter)?;
    let cpi_authority = next_account_info(iter)?;
    let caller_program = next_account_info(iter)?;
    let network_encryption_key = next_account_info(iter)?;
    let payer = next_account_info(iter)?;
    let event_authority = next_account_info(iter)?;
    let system_program = next_account_info(iter)?;

    if !payer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }

    let cpi_authority_bump = data[0];

    // Verify game was played
    let game_data = game_acct.try_borrow_data()?;
    if game_data[OFF_DISC] != GAME {
        return Err(ProgramError::InvalidAccountData);
    }
    if game_data[OFF_PLAYED] == 0 {
        return Err(ProgramError::InvalidArgument);
    }
    drop(game_data);

    let ctx = EncryptContext {
        encrypt_program,
        config,
        deposit,
        cpi_authority,
        caller_program,
        network_encryption_key,
        payer,
        event_authority,
        system_program,
        cpi_authority_bump,
    };

    let digest = ctx.request_decryption(request_acct, result_ciphertext)?;

    let mut game_data = game_acct.try_borrow_mut_data()?;
    game_data[OFF_PENDING_DIGEST..OFF_PENDING_DIGEST + 32].copy_from_slice(&digest);

    Ok(())
}

// ── 3: reveal_result ──
// accounts: [game(w), request_acct, caller(s), winner(w)]
//
// Anyone can call. Pays 2x bet to winner from escrow.
// XOR=1 -> side_a wins. XOR=0 -> side_b wins.

fn reveal_result(accounts: &[AccountInfo]) -> ProgramResult {
    let iter = &mut accounts.iter();
    let game_acct = next_account_info(iter)?;
    let request_acct = next_account_info(iter)?;
    let caller = next_account_info(iter)?;
    let winner_acct = next_account_info(iter)?;

    if !caller.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let game_data = game_acct.try_borrow_data()?;
    if game_data[OFF_DISC] != GAME {
        return Err(ProgramError::InvalidAccountData);
    }
    if game_data[OFF_PLAYED] == 0 {
        return Err(ProgramError::InvalidArgument);
    }
    if game_data[OFF_REVEALED_RESULT] != 0 {
        return Err(ProgramError::InvalidArgument); // already revealed
    }

    let expected_digest: [u8; 32] = game_data[OFF_PENDING_DIGEST..OFF_PENDING_DIGEST + 32]
        .try_into()
        .unwrap();

    let side_a: [u8; 32] = game_data[OFF_SIDE_A..OFF_SIDE_A + 32].try_into().unwrap();
    let side_b: [u8; 32] = game_data[OFF_SIDE_B..OFF_SIDE_B + 32].try_into().unwrap();
    let bet = u64::from_le_bytes(
        game_data[OFF_BET_LAMPORTS..OFF_BET_LAMPORTS + 8]
            .try_into()
            .unwrap(),
    );
    drop(game_data);

    let req_data = request_acct.try_borrow_data()?;
    let value =
        encrypt_native::accounts::read_decrypted_verified::<Uint64>(&req_data, &expected_digest)?;

    let side_a_wins = *value == 1;
    let expected_winner = if side_a_wins { &side_a } else { &side_b };
    if winner_acct.key.as_ref() != expected_winner {
        return Err(ProgramError::InvalidArgument);
    }

    // Pay winner
    let payout = bet * 2;
    if payout > 0 {
        **game_acct.lamports.borrow_mut() -= payout;
        **winner_acct.lamports.borrow_mut() += payout;
    }

    let mut game_data = game_acct.try_borrow_mut_data()?;
    game_data[OFF_REVEALED_RESULT] = if side_a_wins { 1 } else { 2 };
    game_data[OFF_IS_ACTIVE] = 0;

    msg!("Result revealed: {}", value);
    Ok(())
}

// ── 4: cancel_game ──
// accounts: [game(w), side_a(s,w)]
//
// Side A can cancel before side B joins. Refunds bet.

fn cancel_game(accounts: &[AccountInfo]) -> ProgramResult {
    let iter = &mut accounts.iter();
    let game_acct = next_account_info(iter)?;
    let side_a = next_account_info(iter)?;

    if !side_a.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let game_data = game_acct.try_borrow_data()?;
    if game_data[OFF_DISC] != GAME {
        return Err(ProgramError::InvalidAccountData);
    }
    if game_data[OFF_IS_ACTIVE] == 0 {
        return Err(ProgramError::InvalidArgument);
    }
    if game_data[OFF_PLAYED] != 0 {
        return Err(ProgramError::InvalidArgument); // can't cancel after play
    }
    if side_a.key.as_ref() != &game_data[OFF_SIDE_A..OFF_SIDE_A + 32] {
        return Err(ProgramError::InvalidArgument);
    }

    let bet = u64::from_le_bytes(
        game_data[OFF_BET_LAMPORTS..OFF_BET_LAMPORTS + 8]
            .try_into()
            .unwrap(),
    );
    drop(game_data);

    // Refund bet
    if bet > 0 {
        **game_acct.lamports.borrow_mut() -= bet;
        **side_a.lamports.borrow_mut() += bet;
    }

    let mut game_data = game_acct.try_borrow_mut_data()?;
    game_data[OFF_IS_ACTIVE] = 0;

    msg!("Game cancelled");
    Ok(())
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use encrypt_types::graph::{get_node, parse_graph, GraphNodeKind};
    use encrypt_types::identifier::*;
    use encrypt_types::types::FheType;

    use super::coin_flip_graph;

    fn run_mock(graph_fn: fn() -> Vec<u8>, inputs: &[u128], fhe_types: &[FheType]) -> Vec<u128> {
        let data = graph_fn();
        let pg = parse_graph(&data).unwrap();
        let num = pg.header().num_nodes() as usize;
        let mut digests: Vec<[u8; 32]> = Vec::with_capacity(num);
        let mut inp = 0usize;

        for i in 0..num {
            let n = get_node(pg.node_bytes(), i as u16).unwrap();
            let ft = FheType::from_u8(n.fhe_type()).unwrap_or(FheType::EUint64);

            let d = match n.kind() {
                k if k == GraphNodeKind::Input as u8 => {
                    let v = inputs[inp];
                    let t = fhe_types[inp];
                    inp += 1;
                    encode_mock_digest(t, v)
                }
                k if k == GraphNodeKind::Constant as u8 => {
                    let bw = ft.byte_width().min(16);
                    let off = n.const_offset() as usize;
                    let mut buf = [0u8; 16];
                    buf[..bw].copy_from_slice(&pg.constants()[off..off + bw]);
                    encode_mock_digest(ft, u128::from_le_bytes(buf))
                }
                k if k == GraphNodeKind::Op as u8 => {
                    let (a, b, c) = (
                        n.input_a() as usize,
                        n.input_b() as usize,
                        n.input_c() as usize,
                    );
                    if n.op_type() == 60 {
                        mock_select(&digests[a], &digests[b], &digests[c])
                    } else if b == 0xFFFF {
                        mock_unary_compute(
                            unsafe {
                                core::mem::transmute::<u8, encrypt_types::types::FheOperation>(
                                    n.op_type(),
                                )
                            },
                            &digests[a],
                            ft,
                        )
                    } else {
                        mock_binary_compute(
                            unsafe {
                                core::mem::transmute::<u8, encrypt_types::types::FheOperation>(
                                    n.op_type(),
                                )
                            },
                            &digests[a],
                            &digests[b],
                            ft,
                        )
                    }
                }
                k if k == GraphNodeKind::Output as u8 => digests[n.input_a() as usize],
                _ => panic!("bad node"),
            };
            digests.push(d);
        }

        (0..num)
            .filter(|&i| {
                get_node(pg.node_bytes(), i as u16).unwrap().kind() == GraphNodeKind::Output as u8
            })
            .map(|i| decode_mock_identifier(&digests[i]))
            .collect()
    }

    #[test]
    fn xor_same_side_b_wins() {
        let r = run_mock(
            coin_flip_graph,
            &[0, 0],
            &[FheType::EUint64, FheType::EUint64],
        );
        assert_eq!(r[0], 0, "0^0=0 -> side_b wins");
    }

    #[test]
    fn xor_diff_side_a_wins() {
        let r = run_mock(
            coin_flip_graph,
            &[0, 1],
            &[FheType::EUint64, FheType::EUint64],
        );
        assert_eq!(r[0], 1, "0^1=1 -> side_a wins");
    }

    #[test]
    fn xor_both_one_side_b_wins() {
        let r = run_mock(
            coin_flip_graph,
            &[1, 1],
            &[FheType::EUint64, FheType::EUint64],
        );
        assert_eq!(r[0], 0, "1^1=0 -> side_b wins");
    }

    #[test]
    fn xor_one_zero_side_a_wins() {
        let r = run_mock(
            coin_flip_graph,
            &[1, 0],
            &[FheType::EUint64, FheType::EUint64],
        );
        assert_eq!(r[0], 1, "1^0=1 -> side_a wins");
    }

    #[test]
    fn graph_shape() {
        let d = coin_flip_graph();
        let pg = parse_graph(&d).unwrap();
        assert_eq!(pg.header().num_inputs(), 2, "commit_a + commit_b");
        assert_eq!(pg.header().num_outputs(), 1, "single flip result");
    }
}
