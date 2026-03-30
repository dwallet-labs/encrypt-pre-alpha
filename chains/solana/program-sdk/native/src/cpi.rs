// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Native Solana CPI context for the full Encrypt program lifecycle.

use encrypt_solana_types::cpi::EncryptCpi;
use solana_program::account_info::AccountInfo;
use solana_program::entrypoint::ProgramResult;
use solana_program::instruction::{AccountMeta, Instruction};
use solana_program::program::invoke_signed;

// Instruction discriminators
const IX_TRANSFER_CIPHERTEXT: u8 = 7;
const IX_COPY_CIPHERTEXT: u8 = 8;
const IX_CLOSE_CIPHERTEXT: u8 = 9;
const IX_MAKE_PUBLIC: u8 = 10;
const IX_REQUEST_DECRYPTION: u8 = 11;
const IX_CLOSE_DECRYPTION_REQUEST: u8 = 13;

/// CPI authority PDA seed.
pub const CPI_AUTHORITY_SEED: &[u8] = b"__encrypt_cpi_authority";

/// Full Encrypt program lifecycle context for native Solana programs.
pub struct EncryptContext<'a, 'info> {
    pub encrypt_program: &'a AccountInfo<'info>,
    pub config: &'a AccountInfo<'info>,
    pub deposit: &'a AccountInfo<'info>,
    pub cpi_authority: &'a AccountInfo<'info>,
    pub caller_program: &'a AccountInfo<'info>,
    pub network_encryption_key: &'a AccountInfo<'info>,
    pub payer: &'a AccountInfo<'info>,
    pub event_authority: &'a AccountInfo<'info>,
    pub system_program: &'a AccountInfo<'info>,
    pub cpi_authority_bump: u8,
}

impl<'a, 'info> EncryptCpi for EncryptContext<'a, 'info> {
    type Error = solana_program::program_error::ProgramError;
    type Account<'b> = AccountInfo<'info> where Self: 'b;

    fn read_fhe_type<'b>(&'b self, account: AccountInfo<'info>) -> Option<u8> {
        let data = account.try_borrow_data().ok()?;
        if data.len() < encrypt_solana_types::accounts::CT_LEN {
            return None;
        }
        Some(data[encrypt_solana_types::accounts::CT_FHE_TYPE])
    }

    fn type_mismatch_error(&self) -> solana_program::program_error::ProgramError {
        solana_program::program_error::ProgramError::InvalidArgument
    }

    fn invoke_execute_graph<'b>(
        &'b self,
        ix_data: &[u8],
        encrypt_execute_accounts: &[AccountInfo<'info>],
    ) -> Result<(), Self::Error> {
        let mut accounts = vec![
            AccountMeta::new(*self.config.key, false),
            AccountMeta::new(*self.deposit.key, false),
            AccountMeta::new_readonly(*self.caller_program.key, false),
            AccountMeta::new_readonly(*self.cpi_authority.key, true),
            AccountMeta::new_readonly(*self.network_encryption_key.key, false),
            AccountMeta::new(*self.payer.key, true),
            AccountMeta::new_readonly(*self.event_authority.key, false),
            AccountMeta::new_readonly(*self.encrypt_program.key, false),
        ];
        for acct in encrypt_execute_accounts {
            accounts.push(AccountMeta::new(*acct.key, false));
        }

        let ix = Instruction {
            program_id: *self.encrypt_program.key,
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
        invoke_signed(&ix, &account_infos, signer_seeds)
    }
}

impl<'a, 'info> EncryptContext<'a, 'info> {
    // ── Plaintext ciphertext creation ──

    /// Create a ciphertext from a public plaintext value.
    pub fn create_plaintext(
        &self,
        fhe_type: u8,
        plaintext_bytes: &[u8],
        ciphertext: &'a AccountInfo<'info>,
    ) -> ProgramResult {
        let mut ix_data = Vec::with_capacity(1 + 1 + plaintext_bytes.len());
        ix_data.push(2u8); // create_plaintext_ciphertext discriminator
        ix_data.push(fhe_type);
        ix_data.extend_from_slice(plaintext_bytes);
        self.invoke_simple(
            &ix_data,
            vec![
                AccountMeta::new_readonly(*self.config.key, false),
                AccountMeta::new(*self.deposit.key, false),
                AccountMeta::new(*ciphertext.key, true),
                AccountMeta::new_readonly(*self.caller_program.key, false),
                AccountMeta::new_readonly(*self.cpi_authority.key, true),
                AccountMeta::new_readonly(*self.network_encryption_key.key, false),
                AccountMeta::new(*self.payer.key, true),
                AccountMeta::new_readonly(*self.system_program.key, false),
                AccountMeta::new_readonly(*self.event_authority.key, false),
                AccountMeta::new_readonly(*self.encrypt_program.key, false),
            ],
            &[
                self.config.clone(), self.deposit.clone(), ciphertext.clone(),
                self.caller_program.clone(), self.cpi_authority.clone(),
                self.network_encryption_key.clone(), self.payer.clone(),
                self.system_program.clone(), self.event_authority.clone(),
                self.encrypt_program.clone(),
            ],
        )
    }

    /// Typed version: create a ciphertext from a plaintext value.
    pub fn create_plaintext_typed<T: encrypt_types::encrypted::EncryptedType>(
        &self,
        value: &T::DecryptedValue,
        ciphertext: &'a AccountInfo<'info>,
    ) -> ProgramResult {
        let plaintext_bytes = unsafe {
            core::slice::from_raw_parts(value as *const T::DecryptedValue as *const u8, T::BYTE_WIDTH)
        };
        self.create_plaintext(T::FHE_TYPE_ID, plaintext_bytes, ciphertext)
    }

    // ── Execute operations ──

    /// Execute an inline computation graph via CPI.
    pub fn execute_graph(
        &self,
        ix_data: &[u8],
        remaining: &[AccountInfo<'info>],
    ) -> ProgramResult {
        let mut accounts = vec![
            AccountMeta::new(*self.config.key, false),
            AccountMeta::new(*self.deposit.key, false),
            AccountMeta::new_readonly(*self.caller_program.key, false),
            AccountMeta::new_readonly(*self.cpi_authority.key, true),
            AccountMeta::new_readonly(*self.network_encryption_key.key, false),
            AccountMeta::new(*self.payer.key, true),
            AccountMeta::new_readonly(*self.event_authority.key, false),
            AccountMeta::new_readonly(*self.encrypt_program.key, false),
        ];
        for acct in remaining {
            accounts.push(AccountMeta::new(*acct.key, false));
        }

        let mut account_infos = vec![
            self.config.clone(), self.deposit.clone(), self.caller_program.clone(),
            self.cpi_authority.clone(), self.network_encryption_key.clone(), self.payer.clone(),
            self.event_authority.clone(), self.encrypt_program.clone(),
        ];
        account_infos.extend_from_slice(remaining);

        self.invoke_simple(ix_data, accounts, &account_infos)
    }

    /// Execute a registered computation graph via CPI.
    pub fn execute_registered_graph(
        &self,
        graph_pda: &'a AccountInfo<'info>,
        ix_data: &[u8],
        remaining: &[AccountInfo<'info>],
    ) -> ProgramResult {
        let mut accounts = vec![
            AccountMeta::new(*self.config.key, false),
            AccountMeta::new(*self.deposit.key, false),
            AccountMeta::new_readonly(*graph_pda.key, false),
            AccountMeta::new_readonly(*self.caller_program.key, false),
            AccountMeta::new_readonly(*self.cpi_authority.key, true),
            AccountMeta::new_readonly(*self.network_encryption_key.key, false),
            AccountMeta::new(*self.payer.key, true),
            AccountMeta::new_readonly(*self.event_authority.key, false),
            AccountMeta::new_readonly(*self.encrypt_program.key, false),
        ];
        for acct in remaining {
            accounts.push(AccountMeta::new(*acct.key, false));
        }

        let mut account_infos = vec![
            self.config.clone(), self.deposit.clone(), graph_pda.clone(),
            self.caller_program.clone(), self.cpi_authority.clone(), self.network_encryption_key.clone(),
            self.payer.clone(), self.event_authority.clone(), self.encrypt_program.clone(),
        ];
        account_infos.extend_from_slice(remaining);

        self.invoke_simple(ix_data, accounts, &account_infos)
    }

    /// Register a computation graph PDA for repeated execution.
    pub fn register_graph(
        &self,
        graph_pda: &'a AccountInfo<'info>,
        bump: u8,
        graph_hash: &[u8; 32],
        graph_data: &[u8],
    ) -> ProgramResult {
        let graph_data_len = graph_data.len() as u16;
        let mut ix_data = Vec::with_capacity(1 + 1 + 32 + 2 + graph_data.len());
        ix_data.push(4u8); // register_graph discriminator
        ix_data.push(bump);
        ix_data.extend_from_slice(graph_hash);
        ix_data.extend_from_slice(&graph_data_len.to_le_bytes());
        ix_data.extend_from_slice(graph_data);

        self.invoke_simple(
            &ix_data,
            vec![
                AccountMeta::new(*graph_pda.key, false),
                AccountMeta::new_readonly(*self.caller_program.key, true),
                AccountMeta::new(*self.payer.key, true),
                AccountMeta::new_readonly(*self.system_program.key, false),
            ],
            &[
                graph_pda.clone(), self.caller_program.clone(),
                self.payer.clone(), self.system_program.clone(), self.encrypt_program.clone(),
            ],
        )
    }

    // ── Ownership operations ──

    /// Transfer ciphertext authorization to a new party.
    pub fn transfer_ciphertext(
        &self,
        ciphertext: &'a AccountInfo<'info>,
        new_authorized: &'a AccountInfo<'info>,
    ) -> ProgramResult {
        let ix_data = vec![IX_TRANSFER_CIPHERTEXT];
        self.invoke_simple(
            &ix_data,
            vec![
                AccountMeta::new(*ciphertext.key, false),
                AccountMeta::new_readonly(*self.caller_program.key, false),
                AccountMeta::new_readonly(*self.cpi_authority.key, true),
                AccountMeta::new_readonly(*new_authorized.key, false),
            ],
            &[
                ciphertext.clone(),
                self.caller_program.clone(),
                self.cpi_authority.clone(),
                new_authorized.clone(),
                self.encrypt_program.clone(),
            ],
        )
    }

    /// Copy a ciphertext with a different authorized party.
    pub fn copy_ciphertext(
        &self,
        source_ciphertext: &'a AccountInfo<'info>,
        new_ciphertext: &'a AccountInfo<'info>,
        new_authorized: &'a AccountInfo<'info>,
    ) -> ProgramResult {
        let ix_data = vec![IX_COPY_CIPHERTEXT];
        self.invoke_simple(
            &ix_data,
            vec![
                AccountMeta::new_readonly(*source_ciphertext.key, false),
                AccountMeta::new(*new_ciphertext.key, false),
                AccountMeta::new_readonly(*self.caller_program.key, false),
                AccountMeta::new_readonly(*self.cpi_authority.key, true),
                AccountMeta::new_readonly(*new_authorized.key, false),
                AccountMeta::new(*self.payer.key, true),
                AccountMeta::new_readonly(*self.system_program.key, false),
            ],
            &[
                source_ciphertext.clone(),
                new_ciphertext.clone(),
                self.caller_program.clone(),
                self.cpi_authority.clone(),
                new_authorized.clone(),
                self.payer.clone(),
                self.system_program.clone(),
                self.encrypt_program.clone(),
            ],
        )
    }

    /// Mark a ciphertext as fully public.
    pub fn make_public(
        &self,
        ciphertext: &'a AccountInfo<'info>,
    ) -> ProgramResult {
        let ix_data = vec![IX_MAKE_PUBLIC];
        self.invoke_simple(
            &ix_data,
            vec![
                AccountMeta::new(*ciphertext.key, false),
                AccountMeta::new_readonly(*self.caller_program.key, false),
                AccountMeta::new_readonly(*self.cpi_authority.key, true),
            ],
            &[
                ciphertext.clone(),
                self.caller_program.clone(),
                self.cpi_authority.clone(),
                self.encrypt_program.clone(),
            ],
        )
    }

    /// Request decryption of a ciphertext. Returns the `ciphertext_digest`
    /// snapshot — store it in your program state for verification at reveal time.
    pub fn request_decryption(
        &self,
        request_acct: &'a AccountInfo<'info>,
        ciphertext: &'a AccountInfo<'info>,
    ) -> Result<[u8; 32], solana_program::program_error::ProgramError> {
        let ct_data = ciphertext.try_borrow_data()
            .map_err(|_| solana_program::program_error::ProgramError::InvalidAccountData)?;
        let digest = *encrypt_solana_types::accounts::parse_ciphertext_digest(&ct_data)
            .ok_or(solana_program::program_error::ProgramError::InvalidAccountData)?;
        drop(ct_data);

        let ix_data = vec![IX_REQUEST_DECRYPTION];
        self.invoke_simple(
            &ix_data,
            vec![
                AccountMeta::new_readonly(*self.config.key, false),
                AccountMeta::new(*self.deposit.key, false),
                AccountMeta::new(*request_acct.key, true),
                AccountMeta::new_readonly(*self.caller_program.key, false),
                AccountMeta::new_readonly(*self.cpi_authority.key, true),
                AccountMeta::new_readonly(*ciphertext.key, false),
                AccountMeta::new(*self.payer.key, true),
                AccountMeta::new_readonly(*self.system_program.key, false),
                AccountMeta::new_readonly(*self.event_authority.key, false),
                AccountMeta::new_readonly(*self.encrypt_program.key, false),
            ],
            &[
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
            ],
        )?;
        Ok(digest)
    }

    /// Close a completed decryption request and reclaim rent.
    pub fn close_decryption_request(
        &self,
        request: &'a AccountInfo<'info>,
        destination: &'a AccountInfo<'info>,
    ) -> ProgramResult {
        let ix_data = vec![IX_CLOSE_DECRYPTION_REQUEST];
        self.invoke_simple(
            &ix_data,
            vec![
                AccountMeta::new(*request.key, false),
                AccountMeta::new_readonly(*self.caller_program.key, false),
                AccountMeta::new_readonly(*self.cpi_authority.key, true),
                AccountMeta::new(*destination.key, false),
            ],
            &[
                request.clone(),
                self.caller_program.clone(),
                self.cpi_authority.clone(),
                destination.clone(),
                self.encrypt_program.clone(),
            ],
        )
    }

    /// Close a ciphertext account and reclaim rent to the destination.
    pub fn close_ciphertext(
        &self,
        ciphertext: &'a AccountInfo<'info>,
        destination: &'a AccountInfo<'info>,
    ) -> ProgramResult {
        let ix_data = vec![IX_CLOSE_CIPHERTEXT];
        self.invoke_simple(
            &ix_data,
            vec![
                AccountMeta::new(*ciphertext.key, false),
                AccountMeta::new_readonly(*self.caller_program.key, false),
                AccountMeta::new_readonly(*self.cpi_authority.key, true),
                AccountMeta::new(*destination.key, false),
                AccountMeta::new_readonly(*self.event_authority.key, false),
                AccountMeta::new_readonly(*self.encrypt_program.key, false),
            ],
            &[
                ciphertext.clone(),
                self.caller_program.clone(),
                self.cpi_authority.clone(),
                destination.clone(),
                self.event_authority.clone(),
                self.encrypt_program.clone(),
            ],
        )
    }

    fn invoke_simple(
        &self,
        ix_data: &[u8],
        accounts: Vec<AccountMeta>,
        account_infos: &[AccountInfo<'info>],
    ) -> ProgramResult {
        let ix = Instruction {
            program_id: *self.encrypt_program.key,
            accounts,
            data: ix_data.to_vec(),
        };
        let seeds = &[CPI_AUTHORITY_SEED, &[self.cpi_authority_bump]];
        let signer_seeds = &[&seeds[..]];
        invoke_signed(&ix, account_infos, signer_seeds)
    }
}
