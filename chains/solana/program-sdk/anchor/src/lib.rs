// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Anchor CPI SDK for the Encrypt program.
//!
//! Provides `EncryptContext` implementing `EncryptCpi` for Anchor programs.

pub mod accounts;

use anchor_lang::prelude::*;
use encrypt_solana_types::cpi::EncryptCpi;

/// CPI authority PDA seed.
pub const CPI_AUTHORITY_SEED: &[u8] = b"__encrypt_cpi_authority";

/// Instruction discriminators.
const IX_TRANSFER_CIPHERTEXT: u8 = 7;
const IX_COPY_CIPHERTEXT: u8 = 8;
const IX_CLOSE_CIPHERTEXT: u8 = 9;
const IX_MAKE_PUBLIC: u8 = 10;
const IX_REQUEST_DECRYPTION: u8 = 11;
const IX_CLOSE_DECRYPTION_REQUEST: u8 = 13;

/// Full Encrypt program lifecycle context for Anchor developer programs.
pub struct EncryptContext<'info> {
    pub encrypt_program: AccountInfo<'info>,
    pub config: AccountInfo<'info>,
    pub deposit: AccountInfo<'info>,
    pub cpi_authority: AccountInfo<'info>,
    pub caller_program: AccountInfo<'info>,
    pub network_encryption_key: AccountInfo<'info>,
    pub payer: AccountInfo<'info>,
    pub event_authority: AccountInfo<'info>,
    pub system_program: AccountInfo<'info>,
    pub cpi_authority_bump: u8,
}

impl<'info> EncryptCpi for EncryptContext<'info> {
    type Error = anchor_lang::error::Error;
    type Account<'b> = AccountInfo<'info> where Self: 'b;

    fn read_fhe_type<'b>(&'b self, account: AccountInfo<'info>) -> Option<u8> {
        let data = account.try_borrow_data().ok()?;
        if data.len() < encrypt_solana_types::accounts::CT_LEN {
            return None;
        }
        Some(data[encrypt_solana_types::accounts::CT_FHE_TYPE])
    }

    fn type_mismatch_error(&self) -> anchor_lang::error::Error {
        anchor_lang::error::Error::from(anchor_lang::error::ErrorCode::ConstraintRaw)
    }

    fn invoke_execute_graph<'b>(
        &'b self,
        ix_data: &[u8],
        encrypt_execute_accounts: &[AccountInfo<'info>],
    ) -> Result<()> {
        let mut accounts = vec![
            AccountMeta::new(self.config.key(), false),
            AccountMeta::new(self.deposit.key(), false),
            AccountMeta::new_readonly(self.caller_program.key(), false),
            AccountMeta::new_readonly(self.cpi_authority.key(), true),
            AccountMeta::new_readonly(self.network_encryption_key.key(), false),
            AccountMeta::new(self.payer.key(), true),
            AccountMeta::new_readonly(self.event_authority.key(), false),
            AccountMeta::new_readonly(self.encrypt_program.key(), false),
        ];
        for acct in encrypt_execute_accounts {
            accounts.push(AccountMeta::new(acct.key(), false));
        }

        let ix = anchor_lang::solana_program::instruction::Instruction {
            program_id: self.encrypt_program.key(),
            accounts,
            data: ix_data.to_vec(),
        };

        let mut account_infos = vec![
            self.config.clone(), self.deposit.clone(), self.caller_program.clone(),
            self.cpi_authority.clone(), self.network_encryption_key.clone(), self.payer.clone(),
            self.event_authority.clone(), self.encrypt_program.clone(),
        ];
        account_infos.extend_from_slice(encrypt_execute_accounts);

        let seeds = &[CPI_AUTHORITY_SEED, &[self.cpi_authority_bump]];
        let signer_seeds = &[&seeds[..]];
        anchor_lang::solana_program::program::invoke_signed(&ix, &account_infos, signer_seeds)?;
        Ok(())
    }
}

impl<'info> EncryptContext<'info> {
    // ── Execute operations ──

    /// Execute an inline computation graph via CPI.
    pub fn execute_graph(
        &self,
        ix_data: &[u8],
        remaining: &[AccountInfo<'info>],
    ) -> Result<()> {
        let mut accounts = vec![
            AccountMeta::new(self.config.key(), false),
            AccountMeta::new(self.deposit.key(), false),
            AccountMeta::new_readonly(self.caller_program.key(), false),
            AccountMeta::new_readonly(self.cpi_authority.key(), true),
            AccountMeta::new_readonly(self.network_encryption_key.key(), false),
            AccountMeta::new(self.payer.key(), true),
            AccountMeta::new_readonly(self.event_authority.key(), false),
            AccountMeta::new_readonly(self.encrypt_program.key(), false),
        ];
        for acct in remaining {
            accounts.push(AccountMeta::new(acct.key(), false));
        }

        let ix = anchor_lang::solana_program::instruction::Instruction {
            program_id: self.encrypt_program.key(),
            accounts,
            data: ix_data.to_vec(),
        };

        let mut account_infos = vec![
            self.config.clone(), self.deposit.clone(), self.caller_program.clone(),
            self.cpi_authority.clone(), self.network_encryption_key.clone(), self.payer.clone(),
            self.event_authority.clone(), self.encrypt_program.clone(),
        ];
        account_infos.extend_from_slice(remaining);

        let seeds = &[CPI_AUTHORITY_SEED, &[self.cpi_authority_bump]];
        let signer_seeds = &[&seeds[..]];
        anchor_lang::solana_program::program::invoke_signed(&ix, &account_infos, signer_seeds)?;
        Ok(())
    }

    /// Execute a registered computation graph via CPI.
    pub fn execute_registered_graph(
        &self,
        graph_pda: &AccountInfo<'info>,
        ix_data: &[u8],
        remaining: &[AccountInfo<'info>],
    ) -> Result<()> {
        let mut accounts = vec![
            AccountMeta::new(self.config.key(), false),
            AccountMeta::new(self.deposit.key(), false),
            AccountMeta::new_readonly(graph_pda.key(), false),
            AccountMeta::new_readonly(self.caller_program.key(), false),
            AccountMeta::new_readonly(self.cpi_authority.key(), true),
            AccountMeta::new_readonly(self.network_encryption_key.key(), false),
            AccountMeta::new(self.payer.key(), true),
            AccountMeta::new_readonly(self.event_authority.key(), false),
            AccountMeta::new_readonly(self.encrypt_program.key(), false),
        ];
        for acct in remaining {
            accounts.push(AccountMeta::new(acct.key(), false));
        }

        let ix = anchor_lang::solana_program::instruction::Instruction {
            program_id: self.encrypt_program.key(),
            accounts,
            data: ix_data.to_vec(),
        };

        let mut account_infos = vec![
            self.config.clone(), self.deposit.clone(), graph_pda.clone(),
            self.caller_program.clone(), self.cpi_authority.clone(), self.network_encryption_key.clone(),
            self.payer.clone(), self.event_authority.clone(), self.encrypt_program.clone(),
        ];
        account_infos.extend_from_slice(remaining);

        let seeds = &[CPI_AUTHORITY_SEED, &[self.cpi_authority_bump]];
        let signer_seeds = &[&seeds[..]];
        anchor_lang::solana_program::program::invoke_signed(&ix, &account_infos, signer_seeds)?;
        Ok(())
    }

    /// Register a computation graph PDA for repeated execution.
    pub fn register_graph(
        &self,
        graph_pda: &AccountInfo<'info>,
        bump: u8,
        graph_hash: &[u8; 32],
        graph_data: &[u8],
    ) -> Result<()> {
        let graph_data_len = graph_data.len() as u16;
        let mut ix_data = Vec::with_capacity(1 + 1 + 32 + 2 + graph_data.len());
        ix_data.push(4u8);
        ix_data.push(bump);
        ix_data.extend_from_slice(graph_hash);
        ix_data.extend_from_slice(&graph_data_len.to_le_bytes());
        ix_data.extend_from_slice(graph_data);

        let accounts = vec![
            AccountMeta::new(graph_pda.key(), false),
            AccountMeta::new_readonly(self.caller_program.key(), true),
            AccountMeta::new(self.payer.key(), true),
            AccountMeta::new_readonly(self.system_program.key(), false),
        ];

        let ix = anchor_lang::solana_program::instruction::Instruction {
            program_id: self.encrypt_program.key(),
            accounts,
            data: ix_data,
        };

        let account_infos = vec![
            graph_pda.clone(), self.caller_program.clone(),
            self.payer.clone(), self.system_program.clone(), self.encrypt_program.clone(),
        ];

        let seeds = &[CPI_AUTHORITY_SEED, &[self.cpi_authority_bump]];
        let signer_seeds = &[&seeds[..]];
        anchor_lang::solana_program::program::invoke_signed(&ix, &account_infos, signer_seeds)?;
        Ok(())
    }

    // ── Ownership operations ──

    /// Transfer ciphertext authorization to a new party.
    pub fn transfer_ciphertext(
        &self,
        ciphertext: &AccountInfo<'info>,
        new_authorized: &AccountInfo<'info>,
    ) -> Result<()> {
        let ix_data = vec![IX_TRANSFER_CIPHERTEXT];

        let accounts = vec![
            AccountMeta::new(ciphertext.key(), false),
            AccountMeta::new_readonly(self.caller_program.key(), false),
            AccountMeta::new_readonly(self.cpi_authority.key(), true),
            AccountMeta::new_readonly(new_authorized.key(), false),
        ];

        let ix = anchor_lang::solana_program::instruction::Instruction {
            program_id: self.encrypt_program.key(),
            accounts,
            data: ix_data,
        };

        let account_infos = vec![
            ciphertext.clone(),
            self.caller_program.clone(),
            self.cpi_authority.clone(),
            new_authorized.clone(),
            self.encrypt_program.clone(),
        ];

        let seeds = &[CPI_AUTHORITY_SEED, &[self.cpi_authority_bump]];
        let signer_seeds = &[&seeds[..]];
        anchor_lang::solana_program::program::invoke_signed(&ix, &account_infos, signer_seeds)?;
        Ok(())
    }

    /// Copy a ciphertext with a different authorized party.
    pub fn copy_ciphertext(
        &self,
        source_ciphertext: &AccountInfo<'info>,
        new_ciphertext: &AccountInfo<'info>,
        new_authorized: &AccountInfo<'info>,
    ) -> Result<()> {
        let ix_data = vec![IX_COPY_CIPHERTEXT];

        let accounts = vec![
            AccountMeta::new_readonly(source_ciphertext.key(), false),
            AccountMeta::new(new_ciphertext.key(), false),
            AccountMeta::new_readonly(self.caller_program.key(), false),
            AccountMeta::new_readonly(self.cpi_authority.key(), true),
            AccountMeta::new_readonly(new_authorized.key(), false),
            AccountMeta::new(self.payer.key(), true),
            AccountMeta::new_readonly(self.system_program.key(), false),
        ];

        let ix = anchor_lang::solana_program::instruction::Instruction {
            program_id: self.encrypt_program.key(),
            accounts,
            data: ix_data,
        };

        let account_infos = vec![
            source_ciphertext.clone(),
            new_ciphertext.clone(),
            self.caller_program.clone(),
            self.cpi_authority.clone(),
            new_authorized.clone(),
            self.payer.clone(),
            self.system_program.clone(),
            self.encrypt_program.clone(),
        ];

        let seeds = &[CPI_AUTHORITY_SEED, &[self.cpi_authority_bump]];
        let signer_seeds = &[&seeds[..]];
        anchor_lang::solana_program::program::invoke_signed(&ix, &account_infos, signer_seeds)?;
        Ok(())
    }

    /// Mark a ciphertext as fully public.
    pub fn make_public(
        &self,
        ciphertext: &AccountInfo<'info>,
    ) -> Result<()> {
        let ix_data = vec![IX_MAKE_PUBLIC];

        let accounts = vec![
            AccountMeta::new(ciphertext.key(), false),
            AccountMeta::new_readonly(self.caller_program.key(), false),
            AccountMeta::new_readonly(self.cpi_authority.key(), true),
        ];

        let ix = anchor_lang::solana_program::instruction::Instruction {
            program_id: self.encrypt_program.key(),
            accounts,
            data: ix_data,
        };

        let account_infos = vec![
            ciphertext.clone(),
            self.caller_program.clone(),
            self.cpi_authority.clone(),
            self.encrypt_program.clone(),
        ];

        let seeds = &[CPI_AUTHORITY_SEED, &[self.cpi_authority_bump]];
        let signer_seeds = &[&seeds[..]];
        anchor_lang::solana_program::program::invoke_signed(&ix, &account_infos, signer_seeds)?;
        Ok(())
    }

    /// Request decryption of a ciphertext. Returns the `ciphertext_digest`
    /// snapshot — store it in your program state for verification at reveal time.
    pub fn request_decryption(
        &self,
        request_acct: &AccountInfo<'info>,
        ciphertext: &AccountInfo<'info>,
    ) -> Result<[u8; 32]> {
        let ct_data = ciphertext.try_borrow_data()
            .map_err(|_| anchor_lang::error::ErrorCode::AccountNotEnoughKeys)?;
        let digest = *encrypt_solana_types::accounts::parse_ciphertext_digest(&ct_data)
            .ok_or(anchor_lang::error::ErrorCode::ConstraintRaw)?;
        drop(ct_data);

        let ix_data = vec![IX_REQUEST_DECRYPTION];

        let accounts = vec![
            AccountMeta::new_readonly(self.config.key(), false),
            AccountMeta::new(self.deposit.key(), false),
            AccountMeta::new(request_acct.key(), false),
            AccountMeta::new_readonly(self.caller_program.key(), false),
            AccountMeta::new_readonly(self.cpi_authority.key(), true),
            AccountMeta::new_readonly(ciphertext.key(), false),
            AccountMeta::new(self.payer.key(), true),
            AccountMeta::new_readonly(self.system_program.key(), false),
            AccountMeta::new_readonly(self.event_authority.key(), false),
            AccountMeta::new_readonly(self.encrypt_program.key(), false),
        ];

        let ix = anchor_lang::solana_program::instruction::Instruction {
            program_id: self.encrypt_program.key(),
            accounts,
            data: ix_data,
        };

        let account_infos = vec![
            self.config.clone(),
            self.deposit.clone(),
            request_acct.clone(),
            self.caller_program.clone(),
            self.cpi_authority.clone(),
            ciphertext.clone(),
            self.payer.clone(),
            self.system_program.clone(),
            self.event_authority.clone(),
            self.encrypt_program.clone(),
        ];

        let seeds = &[CPI_AUTHORITY_SEED, &[self.cpi_authority_bump]];
        let signer_seeds = &[&seeds[..]];
        anchor_lang::solana_program::program::invoke_signed(&ix, &account_infos, signer_seeds)?;
        Ok(digest)
    }

    /// Close a completed decryption request and reclaim rent.
    pub fn close_decryption_request(
        &self,
        request: &AccountInfo<'info>,
        destination: &AccountInfo<'info>,
    ) -> Result<()> {
        let ix_data = vec![IX_CLOSE_DECRYPTION_REQUEST];

        let accounts = vec![
            AccountMeta::new(request.key(), false),
            AccountMeta::new_readonly(self.caller_program.key(), false),
            AccountMeta::new_readonly(self.cpi_authority.key(), true),
            AccountMeta::new(destination.key(), false),
        ];

        let ix = anchor_lang::solana_program::instruction::Instruction {
            program_id: self.encrypt_program.key(),
            accounts,
            data: ix_data,
        };

        let account_infos = vec![
            request.clone(),
            self.caller_program.clone(),
            self.cpi_authority.clone(),
            destination.clone(),
            self.encrypt_program.clone(),
        ];

        let seeds = &[CPI_AUTHORITY_SEED, &[self.cpi_authority_bump]];
        let signer_seeds = &[&seeds[..]];
        anchor_lang::solana_program::program::invoke_signed(&ix, &account_infos, signer_seeds)?;
        Ok(())
    }

    /// Close a ciphertext account and reclaim rent to the destination.
    pub fn close_ciphertext(
        &self,
        ciphertext: &AccountInfo<'info>,
        destination: &AccountInfo<'info>,
    ) -> Result<()> {
        let ix_data = vec![IX_CLOSE_CIPHERTEXT];

        let accounts = vec![
            AccountMeta::new(ciphertext.key(), false),
            AccountMeta::new_readonly(self.caller_program.key(), false),
            AccountMeta::new_readonly(self.cpi_authority.key(), true),
            AccountMeta::new(destination.key(), false),
            AccountMeta::new_readonly(self.event_authority.key(), false),
            AccountMeta::new_readonly(self.encrypt_program.key(), false),
        ];

        let ix = anchor_lang::solana_program::instruction::Instruction {
            program_id: self.encrypt_program.key(),
            accounts,
            data: ix_data,
        };

        let account_infos = vec![
            ciphertext.clone(),
            self.caller_program.clone(),
            self.cpi_authority.clone(),
            destination.clone(),
            self.event_authority.clone(),
            self.encrypt_program.clone(),
        ];

        let seeds = &[CPI_AUTHORITY_SEED, &[self.cpi_authority_bump]];
        let signer_seeds = &[&seeds[..]];
        anchor_lang::solana_program::program::invoke_signed(&ix, &account_infos, signer_seeds)?;
        Ok(())
    }
}
