// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/// Encrypted Coin Flip — Anchor version with on-chain escrow.
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

use anchor_lang::prelude::*;
use anchor_lang::system_program;
use encrypt_anchor::EncryptContext;
use encrypt_dsl::prelude::encrypt_fn;
use encrypt_types::encrypted::EUint64;

declare_id!("CoinF1ipAnchor11111111111111111111111111111");

// ── FHE Graph ──

/// Coin flip: XOR side A and side B commitments.
///
/// Result = commit_a ^ commit_b.
/// XOR=1 -> side_a wins, XOR=0 -> side_b wins.
#[encrypt_fn]
fn coin_flip_graph(commit_a: EUint64, commit_b: EUint64) -> EUint64 {
    commit_a ^ commit_b
}

// ── State ──

#[account]
#[derive(InitSpace)]
pub struct Game {
    pub side_a: Pubkey,
    pub game_id: [u8; 32],
    pub commit_a: [u8; 32],             // ciphertext pubkey
    pub result_ct: [u8; 32],            // ciphertext pubkey
    pub side_b: Pubkey,
    pub is_active: bool,
    pub played: bool,
    pub pending_digest: [u8; 32],
    pub revealed_result: u8,            // 0=unknown, 1=side_a wins, 2=side_b wins
    pub bet_lamports: u64,
    pub bump: u8,
}

// ── Instructions ──

#[program]
pub mod encrypted_coin_flip {
    use super::*;

    pub fn create_game(
        ctx: Context<CreateGame>,
        game_id: [u8; 32],
        commit_a_id: [u8; 32],
        result_ct_id: [u8; 32],
        bet_lamports: u64,
    ) -> Result<()> {
        // Side A deposits bet
        if bet_lamports > 0 {
            system_program::transfer(
                CpiContext::new(
                    ctx.accounts.system_program.key(),
                    system_program::Transfer {
                        from: ctx.accounts.payer.to_account_info(),
                        to: ctx.accounts.game.to_account_info(),
                    },
                ),
                bet_lamports,
            )?;
        }

        let game = &mut ctx.accounts.game;
        game.side_a = ctx.accounts.side_a.key();
        game.game_id = game_id;
        game.commit_a = commit_a_id;
        game.result_ct = result_ct_id;
        game.side_b = Pubkey::default();
        game.is_active = true;
        game.played = false;
        game.pending_digest = [0u8; 32];
        game.revealed_result = 0;
        game.bet_lamports = bet_lamports;
        game.bump = ctx.bumps.game;
        Ok(())
    }

    pub fn play(ctx: Context<Play>, cpi_authority_bump: u8) -> Result<()> {
        let game = &ctx.accounts.game;
        require!(game.is_active, CoinFlipError::GameClosed);
        require!(!game.played, CoinFlipError::AlreadyPlayed);

        // Verify ciphertext accounts match game state
        require!(
            ctx.accounts.commit_a_ct.key().to_bytes() == game.commit_a,
            CoinFlipError::InvalidAccount
        );
        require!(
            ctx.accounts.result_ct.key().to_bytes() == game.result_ct,
            CoinFlipError::InvalidAccount
        );

        // Side B matches bet
        let bet = game.bet_lamports;
        if bet > 0 {
            system_program::transfer(
                CpiContext::new(
                    ctx.accounts.system_program.key(),
                    system_program::Transfer {
                        from: ctx.accounts.side_b.to_account_info(),
                        to: ctx.accounts.game.to_account_info(),
                    },
                ),
                bet,
            )?;
        }

        let encrypt_ctx = EncryptContext {
            encrypt_program: ctx.accounts.encrypt_program.to_account_info(),
            config: ctx.accounts.config.to_account_info(),
            deposit: ctx.accounts.deposit.to_account_info(),
            cpi_authority: ctx.accounts.cpi_authority.to_account_info(),
            caller_program: ctx.accounts.caller_program.to_account_info(),
            network_encryption_key: ctx.accounts.network_encryption_key.to_account_info(),
            payer: ctx.accounts.payer.to_account_info(),
            event_authority: ctx.accounts.event_authority.to_account_info(),
            system_program: ctx.accounts.system_program.to_account_info(),
            cpi_authority_bump,
        };

        let commit_a = ctx.accounts.commit_a_ct.to_account_info();
        let commit_b = ctx.accounts.commit_b_ct.to_account_info();
        let result = ctx.accounts.result_ct.to_account_info();
        encrypt_ctx.coin_flip_graph(commit_a, commit_b, result)?;

        // Mark as played, record side_b
        let game = &mut ctx.accounts.game;
        game.side_b = ctx.accounts.side_b.key();
        game.played = true;

        Ok(())
    }

    pub fn request_result_decryption(
        ctx: Context<RequestResultDecryption>,
        cpi_authority_bump: u8,
    ) -> Result<()> {
        let game = &ctx.accounts.game;
        require!(game.played, CoinFlipError::NotPlayed);

        let encrypt_ctx = EncryptContext {
            encrypt_program: ctx.accounts.encrypt_program.to_account_info(),
            config: ctx.accounts.config.to_account_info(),
            deposit: ctx.accounts.deposit.to_account_info(),
            cpi_authority: ctx.accounts.cpi_authority.to_account_info(),
            caller_program: ctx.accounts.caller_program.to_account_info(),
            network_encryption_key: ctx.accounts.network_encryption_key.to_account_info(),
            payer: ctx.accounts.payer.to_account_info(),
            event_authority: ctx.accounts.event_authority.to_account_info(),
            system_program: ctx.accounts.system_program.to_account_info(),
            cpi_authority_bump,
        };

        let digest = encrypt_ctx.request_decryption(
            &ctx.accounts.request_acct.to_account_info(),
            &ctx.accounts.result_ciphertext.to_account_info(),
        )?;

        let game = &mut ctx.accounts.game;
        game.pending_digest = digest;
        Ok(())
    }

    /// Anyone can call. Reads decrypted XOR result, pays winner from escrow.
    /// XOR=1 -> side_a wins, XOR=0 -> side_b wins.
    pub fn reveal_result(ctx: Context<RevealResult>) -> Result<()> {
        let game = &ctx.accounts.game;
        require!(game.played, CoinFlipError::NotPlayed);
        require!(game.revealed_result == 0, CoinFlipError::AlreadyRevealed);

        let expected_digest = &game.pending_digest;

        let req_data = ctx.accounts.request_acct.try_borrow_data()?;
        use encrypt_types::encrypted::Uint64;
        let value = encrypt_anchor::accounts::read_decrypted_verified::<Uint64>(
            &req_data,
            expected_digest,
        )
        .map_err(|_| CoinFlipError::DecryptionNotComplete)?;

        let side_a_wins = *value == 1;
        let expected_winner = if side_a_wins { game.side_a } else { game.side_b };
        require!(
            ctx.accounts.winner.key() == expected_winner,
            CoinFlipError::WrongWinner
        );

        // Pay winner
        let payout = game.bet_lamports * 2;
        if payout > 0 {
            let game_info = ctx.accounts.game.to_account_info();
            let winner_info = ctx.accounts.winner.to_account_info();
            **game_info.lamports.borrow_mut() -= payout;
            **winner_info.lamports.borrow_mut() += payout;
        }

        let game = &mut ctx.accounts.game;
        game.revealed_result = if side_a_wins { 1 } else { 2 };
        game.is_active = false;

        Ok(())
    }

    /// Side A can cancel before side B joins. Refunds bet.
    pub fn cancel_game(ctx: Context<CancelGame>) -> Result<()> {
        let game = &ctx.accounts.game;
        require!(game.is_active, CoinFlipError::GameClosed);
        require!(!game.played, CoinFlipError::AlreadyPlayed);
        require!(
            ctx.accounts.side_a.key() == game.side_a,
            CoinFlipError::Unauthorized
        );

        // Refund bet
        let bet = game.bet_lamports;
        if bet > 0 {
            let game_info = ctx.accounts.game.to_account_info();
            let side_a_info = ctx.accounts.side_a.to_account_info();
            **game_info.lamports.borrow_mut() -= bet;
            **side_a_info.lamports.borrow_mut() += bet;
        }

        let game = &mut ctx.accounts.game;
        game.is_active = false;
        Ok(())
    }
}

// ── Accounts ──

#[derive(Accounts)]
#[instruction(game_id: [u8; 32])]
pub struct CreateGame<'info> {
    #[account(
        init,
        payer = payer,
        space = 8 + Game::INIT_SPACE,
        seeds = [b"game", game_id.as_ref()],
        bump,
    )]
    pub game: Account<'info, Game>,
    pub side_a: Signer<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Play<'info> {
    #[account(mut)]
    pub game: Account<'info, Game>,
    #[account(mut)]
    pub side_b: Signer<'info>,
    /// CHECK: Side A commitment ciphertext account
    pub commit_a_ct: UncheckedAccount<'info>,
    /// CHECK: Side B commitment ciphertext account
    #[account(mut)]
    pub commit_b_ct: UncheckedAccount<'info>,
    /// CHECK: Result ciphertext account
    #[account(mut)]
    pub result_ct: UncheckedAccount<'info>,
    /// CHECK: Encrypt program
    pub encrypt_program: UncheckedAccount<'info>,
    /// CHECK: Encrypt config
    pub config: UncheckedAccount<'info>,
    /// CHECK: Encrypt deposit
    #[account(mut)]
    pub deposit: UncheckedAccount<'info>,
    /// CHECK: CPI authority PDA
    pub cpi_authority: UncheckedAccount<'info>,
    /// CHECK: Caller program
    pub caller_program: UncheckedAccount<'info>,
    /// CHECK: Network encryption key
    pub network_encryption_key: UncheckedAccount<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    /// CHECK: Event authority PDA
    pub event_authority: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RequestResultDecryption<'info> {
    #[account(mut)]
    pub game: Account<'info, Game>,
    /// CHECK: Decryption request account (created by encrypt program)
    #[account(mut)]
    pub request_acct: UncheckedAccount<'info>,
    /// CHECK: Result ciphertext account
    pub result_ciphertext: UncheckedAccount<'info>,
    /// CHECK: Encrypt program
    pub encrypt_program: UncheckedAccount<'info>,
    /// CHECK: Encrypt config
    pub config: UncheckedAccount<'info>,
    /// CHECK: Encrypt deposit
    #[account(mut)]
    pub deposit: UncheckedAccount<'info>,
    /// CHECK: CPI authority PDA
    pub cpi_authority: UncheckedAccount<'info>,
    /// CHECK: Caller program
    pub caller_program: UncheckedAccount<'info>,
    /// CHECK: Network encryption key
    pub network_encryption_key: UncheckedAccount<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    /// CHECK: Event authority PDA
    pub event_authority: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RevealResult<'info> {
    #[account(mut)]
    pub game: Account<'info, Game>,
    /// CHECK: Completed decryption request account
    pub request_acct: UncheckedAccount<'info>,
    pub caller: Signer<'info>,
    /// CHECK: Winner account to receive payout
    #[account(mut)]
    pub winner: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct CancelGame<'info> {
    #[account(mut)]
    pub game: Account<'info, Game>,
    #[account(mut)]
    pub side_a: Signer<'info>,
}

// ── Errors ──

#[error_code]
pub enum CoinFlipError {
    #[msg("Game is closed")]
    GameClosed,
    #[msg("Game already played")]
    AlreadyPlayed,
    #[msg("Game not yet played")]
    NotPlayed,
    #[msg("Invalid ciphertext account")]
    InvalidAccount,
    #[msg("Unauthorized")]
    Unauthorized,
    #[msg("Decryption not complete")]
    DecryptionNotComplete,
    #[msg("Already revealed")]
    AlreadyRevealed,
    #[msg("Wrong winner account")]
    WrongWinner,
}

#[cfg(test)]
mod tests {
    use encrypt_dsl::prelude::*;
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
