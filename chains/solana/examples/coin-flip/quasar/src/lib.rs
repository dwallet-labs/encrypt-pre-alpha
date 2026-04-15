// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Encrypted Coin Flip (Quasar version).
//!
//! Two sides each commit an encrypted value (0 or 1). Result = XOR.
//! Both deposit equal bets into the game PDA. Winner gets 2x.
//!
//! This is the Quasar equivalent of the Pinocchio `confidential-coin-flip` program.

#![cfg_attr(not(test), no_std)]
#![allow(unexpected_cfgs)]

extern crate alloc;
use alloc::vec::Vec;



use encrypt_dsl::prelude::encrypt_fn;
use encrypt_quasar::accounts;
use encrypt_quasar::EncryptContext;
use encrypt_types::encrypted::{EUint64, Uint64};
use quasar_lang::prelude::*;
use solana_address::Address;

declare_id!("99999999999999999999999999999997999999999999");

// ── FHE Graph ──

/// Coin flip: XOR of two commitments. XOR=1 means side A wins.
#[encrypt_fn]
fn coin_flip_graph(commit_a: EUint64, commit_b: EUint64) -> EUint64 {
    commit_a ^ commit_b
}

// ── Program ──

#[program]
mod confidential_coin_flip_quasar {
    use super::*;

    /// Side A creates a game, deposits bet, and pre-creates result ciphertext.
    #[instruction(discriminator = 0)]
    pub fn create_game(
        ctx: Ctx<CreateGame>,
        game_id: Address,
        cpi_authority_bump: u8,
        bet_lamports: u64,
    ) -> Result<(), ProgramError> {
        ctx.accounts.handler(game_id, cpi_authority_bump, bet_lamports)
    }

    /// Side B matches bet and commits; XOR graph executes.
    #[instruction(discriminator = 1)]
    pub fn play(
        ctx: Ctx<Play>,
        cpi_authority_bump: u8,
    ) -> Result<(), ProgramError> {
        ctx.accounts.handler(cpi_authority_bump)
    }

    /// Anyone requests decryption of the result after both sides played.
    #[instruction(discriminator = 2)]
    pub fn request_result_decryption(
        ctx: Ctx<RequestResultDecryption>,
        cpi_authority_bump: u8,
    ) -> Result<(), ProgramError> {
        ctx.accounts.handler(cpi_authority_bump)
    }

    /// Anyone reveals the result and pays the winner from escrow.
    #[instruction(discriminator = 3)]
    pub fn reveal_result(ctx: Ctx<RevealResult>) -> Result<(), ProgramError> {
        ctx.accounts.handler()
    }

    /// Side A cancels before side B joins. Refunds bet.
    #[instruction(discriminator = 4)]
    pub fn cancel_game(ctx: Ctx<CancelGame>) -> Result<(), ProgramError> {
        ctx.accounts.handler()
    }
}

// ── State ──

#[account(discriminator = 1, set_inner)]
#[seeds(b"game", game_id: Address)]
pub struct Game {
    pub side_a: Address,
    pub game_id: Address,
    pub commit_a: [u8; 32],
    pub result_ct: [u8; 32],
    pub side_b: Address,
    pub is_active: u8,
    pub played: u8,
    pub pending_digest: [u8; 32],
    pub revealed_result: [u8; 8],
    pub bet_lamports: u64,
    pub bump: u8,
}

// ── Errors ──

#[error_code]
pub enum CoinFlipError {
    GameNotActive = 6000,
    AlreadyPlayed,
    NotPlayed,
    AlreadyRevealed,
    NotSideA,
    CommitMismatch,
    ResultMismatch,
    InvalidWinner,
}

// ── Accounts: create_game ──

#[derive(Accounts)]
#[instruction(game_id: Address)]
pub struct CreateGame {
    #[account(init, payer = payer, seeds = Game::seeds(game_id), bump)]
    pub game: Account<Game>,

    pub side_a: Signer,

    /// Side A's encrypted commitment ciphertext.
    pub commit_a_ct: UncheckedAccount,

    /// Result ciphertext (pre-created as encrypted zero).
    #[account(mut)]
    pub result_ct: UncheckedAccount,

    // Encrypt CPI accounts.
    pub encrypt_program: UncheckedAccount,
    pub config: UncheckedAccount,
    #[account(mut)]
    pub deposit: UncheckedAccount,
    pub cpi_authority: UncheckedAccount,
    pub caller_program: UncheckedAccount,
    pub network_encryption_key: UncheckedAccount,
    #[account(mut)]
    pub payer: Signer,
    pub event_authority: UncheckedAccount,
    pub system_program: Program<System>,
}

impl CreateGame {
    pub fn handler(
        &mut self,
        game_id: Address,
        cpi_authority_bump: u8,
        bet_lamports: u64,
    ) -> Result<(), ProgramError> {
        let ctx = EncryptContext {
            encrypt_program: self.encrypt_program.to_account_view(),
            config: self.config.to_account_view(),
            deposit: self.deposit.to_account_view(),
            cpi_authority: self.cpi_authority.to_account_view(),
            caller_program: self.caller_program.to_account_view(),
            network_encryption_key: self.network_encryption_key.to_account_view(),
            payer: self.payer.to_account_view(),
            event_authority: self.event_authority.to_account_view(),
            system_program: self.system_program.to_account_view(),
            cpi_authority_bump,
        };

        ctx.create_plaintext_typed::<Uint64>(&0u64, self.result_ct.to_account_view())?;

        self.game.set_inner(GameInner {
            side_a: *self.side_a.address(),
            game_id,
            commit_a: *self.commit_a_ct.address().as_array(),
            result_ct: *self.result_ct.address().as_array(),
            side_b: Address::default(),
            is_active: 1,
            played: 0,
            pending_digest: [0u8; 32],
            revealed_result: [0u8; 8],
            bet_lamports,
            bump: 0,
        });
        Ok(())
    }
}

// ── Accounts: play ──

#[derive(Accounts)]
pub struct Play {
    #[account(mut)]
    pub game: Account<Game>,

    pub side_b: Signer,

    /// Side A's commitment ciphertext.
    pub commit_a_ct: UncheckedAccount,

    /// Side B's encrypted commitment ciphertext.
    pub commit_b_ct: UncheckedAccount,

    /// Result ciphertext (output of XOR).
    #[account(mut)]
    pub result_ct: UncheckedAccount,

    // Encrypt CPI accounts.
    pub encrypt_program: UncheckedAccount,
    pub config: UncheckedAccount,
    #[account(mut)]
    pub deposit: UncheckedAccount,
    pub cpi_authority: UncheckedAccount,
    pub caller_program: UncheckedAccount,
    pub network_encryption_key: UncheckedAccount,
    #[account(mut)]
    pub payer: Signer,
    pub event_authority: UncheckedAccount,
    pub system_program: Program<System>,
}

impl Play {
    pub fn handler(&mut self, cpi_authority_bump: u8) -> Result<(), ProgramError> {
        require!(self.game.is_active == 1, CoinFlipError::GameNotActive);
        require!(self.game.played == 0, CoinFlipError::AlreadyPlayed);
        require!(
            self.commit_a_ct.address().as_array() == &self.game.commit_a,
            CoinFlipError::CommitMismatch
        );
        require!(
            self.result_ct.address().as_array() == &self.game.result_ct,
            CoinFlipError::ResultMismatch
        );

        let ctx = EncryptContext {
            encrypt_program: self.encrypt_program.to_account_view(),
            config: self.config.to_account_view(),
            deposit: self.deposit.to_account_view(),
            cpi_authority: self.cpi_authority.to_account_view(),
            caller_program: self.caller_program.to_account_view(),
            network_encryption_key: self.network_encryption_key.to_account_view(),
            payer: self.payer.to_account_view(),
            event_authority: self.event_authority.to_account_view(),
            system_program: self.system_program.to_account_view(),
            cpi_authority_bump,
        };

        ctx.coin_flip_graph(
            self.commit_a_ct.to_account_view(),
            self.commit_b_ct.to_account_view(),
            self.result_ct.to_account_view(),
        )?;

        self.game.side_b = *self.side_b.address();
        self.game.played = 1;
        Ok(())
    }
}

// ── Accounts: request_result_decryption ──

#[derive(Accounts)]
pub struct RequestResultDecryption {
    #[account(mut)]
    pub game: Account<Game>,

    /// Decryption request account (created by CPI).
    #[account(mut)]
    pub request_acct: UncheckedAccount,

    /// Result ciphertext to decrypt.
    pub result_ciphertext: UncheckedAccount,

    // Encrypt CPI accounts.
    pub encrypt_program: UncheckedAccount,
    pub config: UncheckedAccount,
    #[account(mut)]
    pub deposit: UncheckedAccount,
    pub cpi_authority: UncheckedAccount,
    pub caller_program: UncheckedAccount,
    pub network_encryption_key: UncheckedAccount,
    #[account(mut)]
    pub payer: Signer,
    pub event_authority: UncheckedAccount,
    pub system_program: Program<System>,
}

impl RequestResultDecryption {
    pub fn handler(&mut self, cpi_authority_bump: u8) -> Result<(), ProgramError> {
        require!(self.game.played == 1, CoinFlipError::NotPlayed);

        let ctx = EncryptContext {
            encrypt_program: self.encrypt_program.to_account_view(),
            config: self.config.to_account_view(),
            deposit: self.deposit.to_account_view(),
            cpi_authority: self.cpi_authority.to_account_view(),
            caller_program: self.caller_program.to_account_view(),
            network_encryption_key: self.network_encryption_key.to_account_view(),
            payer: self.payer.to_account_view(),
            event_authority: self.event_authority.to_account_view(),
            system_program: self.system_program.to_account_view(),
            cpi_authority_bump,
        };

        let digest = ctx.request_decryption(
            self.request_acct.to_account_view(),
            self.result_ciphertext.to_account_view(),
        )?;

        self.game.pending_digest = digest;
        Ok(())
    }
}

// ── Accounts: reveal_result ──

#[derive(Accounts)]
pub struct RevealResult {
    #[account(mut)]
    pub game: Account<Game>,

    /// Completed decryption request.
    pub request_acct: UncheckedAccount,

    pub caller: Signer,

    /// Winner account to receive payout.
    #[account(mut)]
    pub winner: UncheckedAccount,
}

impl RevealResult {
    pub fn handler(&mut self) -> Result<(), ProgramError> {
        require!(self.game.played == 1, CoinFlipError::NotPlayed);
        require!(
            self.game.revealed_result == [0u8; 8],
            CoinFlipError::AlreadyRevealed
        );

        let req_data = unsafe {
            core::slice::from_raw_parts(
                self.request_acct.to_account_view().data_ptr(),
                256,
            )
        };
        let value: &u64 =
            accounts::read_decrypted_verified::<Uint64>(req_data, &self.game.pending_digest)?;

        let side_a_wins = *value == 1;
        let expected_winner = if side_a_wins {
            &self.game.side_a
        } else {
            &self.game.side_b
        };
        require!(
            self.winner.address() == expected_winner,
            CoinFlipError::InvalidWinner
        );

        self.game.revealed_result = value.to_le_bytes();
        self.game.is_active = 0;
        Ok(())
    }
}

// ── Accounts: cancel_game ──

#[derive(Accounts)]
pub struct CancelGame {
    #[account(mut)]
    pub game: Account<Game>,

    pub side_a: Signer,
}

impl CancelGame {
    pub fn handler(&mut self) -> Result<(), ProgramError> {
        require!(self.game.is_active == 1, CoinFlipError::GameNotActive);
        require!(self.game.played == 0, CoinFlipError::AlreadyPlayed);
        require!(
            self.side_a.address() == &self.game.side_a,
            CoinFlipError::NotSideA
        );

        self.game.is_active = 0;
        Ok(())
    }
}
