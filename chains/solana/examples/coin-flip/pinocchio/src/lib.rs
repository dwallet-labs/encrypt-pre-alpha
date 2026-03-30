// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#![allow(unexpected_cfgs)]

/// Encrypted Coin Flip — Provably fair with on-chain escrow.
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
use encrypt_pinocchio::accounts;
use encrypt_pinocchio::EncryptContext;
use encrypt_types::encrypted::{EUint64, Uint64};
use pinocchio::{
    cpi::{Seed, Signer},
    entrypoint,
    error::ProgramError,
    AccountView, Address, ProgramResult,
};
use pinocchio_system::instructions::{CreateAccount, Transfer};

entrypoint!(process_instruction);

pub const ID: Address = Address::new_from_array([5u8; 32]);

const GAME: u8 = 1;

// ── Account layout ──

#[repr(C)]
pub struct Game {
    pub discriminator: u8,          // [0]
    pub side_a: [u8; 32],          // [1..33] — game creator
    pub game_id: [u8; 32],         // [33..65]
    pub commit_a: EUint64,          // [65..97] — side A's encrypted commitment
    pub result_ct: EUint64,         // [97..129] — result ciphertext
    pub side_b: [u8; 32],          // [129..161] — joiner (zeroed until play)
    pub is_active: u8,              // [161]
    pub played: u8,                 // [162] — 0=waiting, 1=both committed
    pub pending_digest: [u8; 32],   // [163..195]
    pub revealed_result: u8,        // [195] — 0=pending, 1=side_a wins, 2=side_b wins
    pub bet_lamports: [u8; 8],      // [196..204]
    pub bump: u8,                   // [204]
}

impl Game {
    pub const LEN: usize = core::mem::size_of::<Self>();

    pub fn from_bytes(data: &[u8]) -> Result<&Self, ProgramError> {
        if data.len() < Self::LEN || data[0] != GAME {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(unsafe { &*(data.as_ptr() as *const Self) })
    }

    pub fn from_bytes_mut(data: &mut [u8]) -> Result<&mut Self, ProgramError> {
        if data.len() < Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(unsafe { &mut *(data.as_mut_ptr() as *mut Self) })
    }

    pub fn bet(&self) -> u64 {
        u64::from_le_bytes(self.bet_lamports)
    }

    pub fn set_bet(&mut self, val: u64) {
        self.bet_lamports = val.to_le_bytes();
    }
}

fn minimum_balance(size: usize) -> u64 {
    (size as u64 + 128) * 6960
}

// ── FHE Graph ──

#[encrypt_fn]
fn coin_flip_graph(commit_a: EUint64, commit_b: EUint64) -> EUint64 {
    commit_a ^ commit_b
}

// ── Dispatch ──

fn process_instruction(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    match data.split_first() {
        Some((&0, rest)) => create_game(program_id, accounts, rest),
        Some((&1, rest)) => play(accounts, rest),
        Some((&2, rest)) => request_result_decryption(accounts, rest),
        Some((&3, _rest)) => reveal_result(accounts),
        Some((&4, _rest)) => cancel_game(accounts),
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
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    let [game_acct, side_a, commit_a_ct, result_ct, encrypt_program, config, deposit, cpi_authority, caller_program, network_encryption_key, payer, event_authority, system_program, ..] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !side_a.is_signer() || !payer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if data.len() < 42 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let game_bump = data[0];
    let cpi_authority_bump = data[1];
    let game_id: [u8; 32] = data[2..34].try_into().unwrap();
    let bet_lamports = u64::from_le_bytes(data[34..42].try_into().unwrap());

    let bump_byte = [game_bump];
    let seeds = [
        Seed::from(b"game" as &[u8]),
        Seed::from(game_id.as_ref()),
        Seed::from(&bump_byte),
    ];
    let signer = [Signer::from(&seeds)];

    CreateAccount {
        from: payer,
        to: game_acct,
        lamports: minimum_balance(Game::LEN),
        space: Game::LEN as u64,
        owner: program_id,
    }
    .invoke_signed(&signer)?;

    // Side A deposits bet
    if bet_lamports > 0 {
        Transfer { from: payer, to: game_acct, lamports: bet_lamports }.invoke()?;
    }

    // Pre-create result ciphertext
    let ctx = EncryptContext {
        encrypt_program, config, deposit, cpi_authority, caller_program,
        network_encryption_key, payer, event_authority, system_program,
        cpi_authority_bump,
    };
    ctx.create_plaintext_typed::<Uint64>(&0u64, result_ct)?;

    let d = unsafe { game_acct.borrow_unchecked_mut() };
    let game = Game::from_bytes_mut(d)?;
    game.discriminator = GAME;
    game.side_a.copy_from_slice(side_a.address().as_ref());
    game.game_id.copy_from_slice(&game_id);
    game.commit_a = EUint64::from_le_bytes(*commit_a_ct.address().as_array());
    game.result_ct = EUint64::from_le_bytes(*result_ct.address().as_array());
    game.side_b = [0u8; 32];
    game.is_active = 1;
    game.played = 0;
    game.pending_digest = [0u8; 32];
    game.revealed_result = 0;
    game.set_bet(bet_lamports);
    game.bump = game_bump;
    Ok(())
}

// ── 1: play ──
// data: cpi_authority_bump(1)
// accounts: [game(w), side_b(s,w), commit_a_ct, commit_b_ct,
//            result_ct(w), encrypt_program, config, deposit(w), cpi_authority,
//            caller_program, network_encryption_key, payer(s,w),
//            event_authority, system_program]

fn play(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [game_acct, side_b, commit_a_ct, commit_b_ct, result_ct, encrypt_program, config, deposit, cpi_authority, caller_program, network_encryption_key, payer, event_authority, system_program, ..] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !side_b.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }

    let cpi_authority_bump = data[0];

    let game_data = unsafe { game_acct.borrow_unchecked() };
    let game = Game::from_bytes(game_data)?;
    if game.is_active == 0 { return Err(ProgramError::InvalidArgument); }
    if game.played != 0 { return Err(ProgramError::InvalidArgument); }
    if commit_a_ct.address().as_array() != game.commit_a.id() {
        return Err(ProgramError::InvalidArgument);
    }
    if result_ct.address().as_array() != game.result_ct.id() {
        return Err(ProgramError::InvalidArgument);
    }

    // Side B matches bet
    let bet = game.bet();
    if bet > 0 {
        Transfer { from: side_b, to: game_acct, lamports: bet }.invoke()?;
    }

    // XOR graph
    let ctx = EncryptContext {
        encrypt_program, config, deposit, cpi_authority, caller_program,
        network_encryption_key, payer, event_authority, system_program,
        cpi_authority_bump,
    };
    ctx.coin_flip_graph(commit_a_ct, commit_b_ct, result_ct)?;

    let game_data_mut = unsafe { game_acct.borrow_unchecked_mut() };
    let game_mut = Game::from_bytes_mut(game_data_mut)?;
    game_mut.side_b.copy_from_slice(side_b.address().as_ref());
    game_mut.played = 1;
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

fn request_result_decryption(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [game_acct, request_acct, result_ciphertext, encrypt_program, config, deposit, cpi_authority, caller_program, network_encryption_key, payer, event_authority, system_program, ..] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !payer.is_signer() { return Err(ProgramError::MissingRequiredSignature); }
    if data.is_empty() { return Err(ProgramError::InvalidInstructionData); }

    let cpi_authority_bump = data[0];

    let game_data = unsafe { game_acct.borrow_unchecked() };
    let game = Game::from_bytes(game_data)?;
    if game.played == 0 { return Err(ProgramError::InvalidArgument); }

    let ctx = EncryptContext {
        encrypt_program, config, deposit, cpi_authority, caller_program,
        network_encryption_key, payer, event_authority, system_program,
        cpi_authority_bump,
    };
    let digest = ctx.request_decryption(request_acct, result_ciphertext)?;

    let game_data_mut = unsafe { game_acct.borrow_unchecked_mut() };
    let game_mut = Game::from_bytes_mut(game_data_mut)?;
    game_mut.pending_digest = digest;
    Ok(())
}

// ── 3: reveal_result ──
// accounts: [game(w), request_acct, caller(s), winner(w)]
//
// Anyone can call. Pays 2x bet to winner from escrow.
// XOR=1 → side_a wins. XOR=0 → side_b wins.

fn reveal_result(accounts: &[AccountView]) -> ProgramResult {
    let [game_acct, request_acct, caller, winner_acct, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !caller.is_signer() { return Err(ProgramError::MissingRequiredSignature); }

    let game_data = unsafe { game_acct.borrow_unchecked() };
    let game = Game::from_bytes(game_data)?;
    if game.played == 0 { return Err(ProgramError::InvalidArgument); }
    if game.revealed_result != 0 { return Err(ProgramError::InvalidArgument); } // already revealed

    let req_data = unsafe { request_acct.borrow_unchecked() };
    let value: &u64 = accounts::read_decrypted_verified::<Uint64>(req_data, &game.pending_digest)?;

    let side_a_wins = *value == 1;
    let expected_winner = if side_a_wins { &game.side_a } else { &game.side_b };
    if winner_acct.address().as_array() != expected_winner {
        return Err(ProgramError::InvalidArgument);
    }

    // Pay winner
    let payout = game.bet() * 2;
    if payout > 0 {
        game_acct.set_lamports(game_acct.lamports() - payout);
        winner_acct.set_lamports(winner_acct.lamports() + payout);
    }

    let game_data_mut = unsafe { game_acct.borrow_unchecked_mut() };
    let game_mut = Game::from_bytes_mut(game_data_mut)?;
    game_mut.revealed_result = if side_a_wins { 1 } else { 2 };
    game_mut.is_active = 0;
    Ok(())
}

// ── 4: cancel_game ──
// accounts: [game(w), side_a(s,w)]
//
// Side A can cancel before side B joins. Refunds bet.

fn cancel_game(accounts: &[AccountView]) -> ProgramResult {
    let [game_acct, side_a, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !side_a.is_signer() { return Err(ProgramError::MissingRequiredSignature); }

    let game_data = unsafe { game_acct.borrow_unchecked() };
    let game = Game::from_bytes(game_data)?;
    if game.is_active == 0 { return Err(ProgramError::InvalidArgument); }
    if game.played != 0 { return Err(ProgramError::InvalidArgument); } // can't cancel after play
    if side_a.address().as_array() != &game.side_a {
        return Err(ProgramError::InvalidArgument);
    }

    // Refund bet
    let bet = game.bet();
    if bet > 0 {
        game_acct.set_lamports(game_acct.lamports() - bet);
        side_a.set_lamports(side_a.lamports() + bet);
    }

    let game_data_mut = unsafe { game_acct.borrow_unchecked_mut() };
    let game_mut = Game::from_bytes_mut(game_data_mut)?;
    game_mut.is_active = 0;
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
                    let v = inputs[inp]; let t = fhe_types[inp]; inp += 1;
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
                    let (a, b, c) = (n.input_a() as usize, n.input_b() as usize, n.input_c() as usize);
                    if n.op_type() == 60 {
                        mock_select(&digests[a], &digests[b], &digests[c])
                    } else if b == 0xFFFF {
                        mock_unary_compute(
                            unsafe { core::mem::transmute::<u8, encrypt_types::types::FheOperation>(n.op_type()) },
                            &digests[a], ft,
                        )
                    } else {
                        mock_binary_compute(
                            unsafe { core::mem::transmute::<u8, encrypt_types::types::FheOperation>(n.op_type()) },
                            &digests[a], &digests[b], ft,
                        )
                    }
                }
                k if k == GraphNodeKind::Output as u8 => digests[n.input_a() as usize],
                _ => panic!("bad node"),
            };
            digests.push(d);
        }
        (0..num)
            .filter(|&i| get_node(pg.node_bytes(), i as u16).unwrap().kind() == GraphNodeKind::Output as u8)
            .map(|i| decode_mock_identifier(&digests[i]))
            .collect()
    }

    #[test]
    fn xor_same_side_b_wins() {
        let r = run_mock(coin_flip_graph, &[0, 0], &[FheType::EUint64, FheType::EUint64]);
        assert_eq!(r[0], 0, "0^0=0 → side_b wins");
    }

    #[test]
    fn xor_diff_side_a_wins() {
        let r = run_mock(coin_flip_graph, &[0, 1], &[FheType::EUint64, FheType::EUint64]);
        assert_eq!(r[0], 1, "0^1=1 → side_a wins");
    }

    #[test]
    fn xor_both_one_side_b_wins() {
        let r = run_mock(coin_flip_graph, &[1, 1], &[FheType::EUint64, FheType::EUint64]);
        assert_eq!(r[0], 0, "1^1=0 → side_b wins");
    }

    #[test]
    fn xor_one_zero_side_a_wins() {
        let r = run_mock(coin_flip_graph, &[1, 0], &[FheType::EUint64, FheType::EUint64]);
        assert_eq!(r[0], 1, "1^0=1 → side_a wins");
    }

    #[test]
    fn graph_shape() {
        let d = coin_flip_graph();
        let pg = parse_graph(&d).unwrap();
        assert_eq!(pg.header().num_inputs(), 2);
        assert_eq!(pg.header().num_outputs(), 1);
    }
}
