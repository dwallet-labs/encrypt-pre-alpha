// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Confidential Counter (Quasar version).
//!
//! An on-chain counter whose value is encrypted via FHE. Nobody can see the
//! current count, but anyone can increment or decrement it. The authority can
//! request decryption and reveal the plaintext value on-chain.
//!
//! This is the Quasar equivalent of the Pinocchio `confidential-counter` program.

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

declare_id!("99999999999999999999999999999999999999999999");

// ── FHE Graphs ──

/// Increment: value + 1
#[encrypt_fn]
fn increment_graph(value: EUint64) -> EUint64 {
    value + 1
}

/// Decrement: value - 1
#[encrypt_fn]
fn decrement_graph(value: EUint64) -> EUint64 {
    value - 1
}

// ── Program ──

#[program]
mod confidential_counter_quasar {
    use super::*;

    /// Create a new counter initialized to encrypted zero.
    #[instruction(discriminator = 0)]
    pub fn create_counter(
        ctx: Ctx<CreateCounter>,
        counter_id: Address,
        cpi_authority_bump: u8,
    ) -> Result<(), ProgramError> {
        ctx.accounts.handler(counter_id, cpi_authority_bump)
    }

    /// Increment the counter by 1 via FHE.
    #[instruction(discriminator = 1)]
    pub fn increment(
        ctx: Ctx<Increment>,
        cpi_authority_bump: u8,
    ) -> Result<(), ProgramError> {
        ctx.accounts.handler(cpi_authority_bump)
    }

    /// Decrement the counter by 1 via FHE.
    #[instruction(discriminator = 2)]
    pub fn decrement(
        ctx: Ctx<Decrement>,
        cpi_authority_bump: u8,
    ) -> Result<(), ProgramError> {
        ctx.accounts.handler(cpi_authority_bump)
    }

    /// Request decryption of the counter value.
    #[instruction(discriminator = 3)]
    pub fn request_value_decryption(
        ctx: Ctx<RequestValueDecryption>,
        cpi_authority_bump: u8,
    ) -> Result<(), ProgramError> {
        ctx.accounts.handler(cpi_authority_bump)
    }

    /// Reveal the decrypted counter value on-chain.
    #[instruction(discriminator = 4)]
    pub fn reveal_value(ctx: Ctx<RevealValue>) -> Result<(), ProgramError> {
        ctx.accounts.handler()
    }
}

// ── State ──

#[account(discriminator = 1, set_inner)]
#[seeds(b"counter", counter_id: Address)]
pub struct Counter {
    pub authority: Address,
    pub counter_id: Address,
    pub value: [u8; 32],
    pub pending_digest: [u8; 32],
    pub revealed_value: [u8; 8],
    pub bump: u8,
}

// ── Errors ──

#[error_code]
pub enum CounterError {
    NotAuthority = 6000,
    ValueMismatch,
}

// ── Accounts: create_counter ──

#[derive(Accounts)]
#[instruction(counter_id: Address)]
pub struct CreateCounter {
    #[account(init, payer = payer, seeds = Counter::seeds(counter_id), bump)]
    pub counter: Account<Counter>,

    pub authority: Signer,

    /// Ciphertext account for the encrypted counter value.
    #[account(mut)]
    pub value_ct: UncheckedAccount,

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

impl CreateCounter {
    pub fn handler(&mut self, counter_id: Address, cpi_authority_bump: u8) -> Result<(), ProgramError> {
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

        ctx.create_plaintext_typed::<Uint64>(&0u64, self.value_ct.to_account_view())?;

        self.counter.set_inner(CounterInner {
            authority: *self.authority.address(),
            counter_id,
            value: *self.value_ct.address().as_array(),
            pending_digest: [0u8; 32],
            revealed_value: [0u8; 8],
            bump: 0,
        });
        Ok(())
    }
}

// ── Accounts: increment ──

#[derive(Accounts)]
pub struct Increment {
    #[account(mut)]
    pub counter: Account<Counter>,

    /// Ciphertext account for the encrypted counter value.
    #[account(mut)]
    pub value_ct: UncheckedAccount,

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

impl Increment {
    pub fn handler(&mut self, cpi_authority_bump: u8) -> Result<(), ProgramError> {
        require!(
            self.value_ct.address().as_array() == &self.counter.value,
            CounterError::ValueMismatch
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

        ctx.increment_graph(
            self.value_ct.to_account_view(),
            self.value_ct.to_account_view(),
        )?;

        Ok(())
    }
}

// ── Accounts: decrement ──

#[derive(Accounts)]
pub struct Decrement {
    #[account(mut)]
    pub counter: Account<Counter>,

    /// Ciphertext account for the encrypted counter value.
    #[account(mut)]
    pub value_ct: UncheckedAccount,

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

impl Decrement {
    pub fn handler(&mut self, cpi_authority_bump: u8) -> Result<(), ProgramError> {
        require!(
            self.value_ct.address().as_array() == &self.counter.value,
            CounterError::ValueMismatch
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

        ctx.decrement_graph(
            self.value_ct.to_account_view(),
            self.value_ct.to_account_view(),
        )?;

        Ok(())
    }
}

// ── Accounts: request_value_decryption ──

#[derive(Accounts)]
pub struct RequestValueDecryption {
    #[account(mut)]
    pub counter: Account<Counter>,

    /// Decryption request account (created by CPI).
    #[account(mut)]
    pub request_acct: UncheckedAccount,

    /// Ciphertext to decrypt.
    pub ciphertext: UncheckedAccount,

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

impl RequestValueDecryption {
    pub fn handler(&mut self, cpi_authority_bump: u8) -> Result<(), ProgramError> {
        require!(
            self.payer.address() == &self.counter.authority,
            CounterError::NotAuthority
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

        let digest = ctx.request_decryption(
            self.request_acct.to_account_view(),
            self.ciphertext.to_account_view(),
        )?;

        self.counter.pending_digest = digest;
        Ok(())
    }
}

// ── Accounts: reveal_value ──

#[derive(Accounts)]
pub struct RevealValue {
    #[account(mut)]
    pub counter: Account<Counter>,

    /// Completed decryption request.
    pub request_acct: UncheckedAccount,

    pub authority: Signer,
}

impl RevealValue {
    pub fn handler(&mut self) -> Result<(), ProgramError> {
        require!(
            self.authority.address() == &self.counter.authority,
            CounterError::NotAuthority
        );

        let req_data = unsafe {
            core::slice::from_raw_parts(
                self.request_acct.to_account_view().data_ptr(),
                256,
            )
        };
        let value: &u64 =
            accounts::read_decrypted_verified::<Uint64>(req_data, &self.counter.pending_digest)?;

        self.counter.revealed_value = value.to_le_bytes();
        Ok(())
    }
}
