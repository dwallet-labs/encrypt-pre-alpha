// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Pinocchio CPI context for the full Encrypt program lifecycle.

extern crate alloc;
use alloc::vec::Vec;

pub use encrypt_solana_types::cpi::EncryptCpi;

use pinocchio::cpi::{invoke_signed, invoke_signed_with_bounds, Seed, Signer};
use pinocchio::error::ProgramError;
use pinocchio::instruction::{InstructionAccount, InstructionView};
use pinocchio::{AccountView, ProgramResult};

// Instruction discriminators
const IX_CREATE_PLAINTEXT_CIPHERTEXT: u8 = 2;
const IX_REGISTER_GRAPH: u8 = 5;
const IX_TRANSFER_CIPHERTEXT: u8 = 7;
const IX_COPY_CIPHERTEXT: u8 = 8;
const IX_CLOSE_CIPHERTEXT: u8 = 9;
const IX_MAKE_PUBLIC: u8 = 10;
const IX_REQUEST_DECRYPTION: u8 = 11;
const IX_CLOSE_DECRYPTION_REQUEST: u8 = 13;

/// CPI authority PDA seed.
pub const CPI_AUTHORITY_SEED: &[u8] = b"__encrypt_cpi_authority";

/// Full Encrypt program lifecycle context for Pinocchio developer programs.
pub struct EncryptContext<'a> {
    pub encrypt_program: &'a AccountView,
    pub config: &'a AccountView,
    pub deposit: &'a AccountView,
    pub cpi_authority: &'a AccountView,
    pub caller_program: &'a AccountView,
    pub network_encryption_key: &'a AccountView,
    pub payer: &'a AccountView,
    pub event_authority: &'a AccountView,
    pub system_program: &'a AccountView,
    pub cpi_authority_bump: u8,
}

impl<'a> EncryptCpi for EncryptContext<'a> {
    type Error = ProgramError;
    type Account<'b> = &'b AccountView where Self: 'b;

    fn read_fhe_type<'b>(&'b self, account: &'b AccountView) -> Option<u8> {
        let data = unsafe { account.borrow_unchecked() };
        if data.len() < encrypt_solana_types::accounts::CT_LEN {
            return None;
        }
        Some(data[encrypt_solana_types::accounts::CT_FHE_TYPE])
    }

    fn type_mismatch_error(&self) -> ProgramError {
        ProgramError::InvalidArgument
    }

    fn invoke_execute_graph<'b>(
        &'b self,
        ix_data: &[u8],
        encrypt_execute_accounts: &[&'b AccountView],
    ) -> Result<(), ProgramError> {
        let fixed = [
            InstructionAccount { address: self.config.address(), is_writable: true, is_signer: false },
            InstructionAccount { address: self.deposit.address(), is_writable: true, is_signer: false },
            InstructionAccount { address: self.caller_program.address(), is_writable: false, is_signer: false },
            InstructionAccount { address: self.cpi_authority.address(), is_writable: false, is_signer: true },
            InstructionAccount { address: self.network_encryption_key.address(), is_writable: false, is_signer: false },
            InstructionAccount { address: self.payer.address(), is_writable: true, is_signer: true },
            InstructionAccount { address: self.event_authority.address(), is_writable: false, is_signer: false },
            InstructionAccount { address: self.encrypt_program.address(), is_writable: false, is_signer: false },
        ];

        let mut accounts = Vec::with_capacity(8 + encrypt_execute_accounts.len());
        accounts.extend_from_slice(&fixed);
        for acct in encrypt_execute_accounts {
            accounts.push(InstructionAccount { address: acct.address(), is_writable: true, is_signer: false });
        }

        let ix = InstructionView {
            program_id: self.encrypt_program.address(),
            data: ix_data,
            accounts: &accounts,
        };
        let bump_byte = [self.cpi_authority_bump];
        let seeds = [Seed::from(CPI_AUTHORITY_SEED), Seed::from(&bump_byte)];
        let signer = [Signer::from(&seeds)];

        let mut views: Vec<&AccountView> = Vec::with_capacity(8 + encrypt_execute_accounts.len());
        views.extend_from_slice(&[self.config, self.deposit, self.caller_program, self.cpi_authority, self.network_encryption_key, self.payer, self.event_authority, self.encrypt_program]);
        views.extend_from_slice(encrypt_execute_accounts);
        invoke_signed_with_bounds::<64>(&ix, &views, &signer)
    }
}

impl<'a> EncryptContext<'a> {
    // ── Plaintext ciphertext creation ──

    /// Create a ciphertext from a public plaintext value.
    ///
    /// User-signed (not authority). The executor encrypts the value off-chain,
    /// then the authority commits the digest via `commit_ciphertext`.
    ///
    /// `plaintext_bytes` must be exactly `T::BYTE_WIDTH` bytes for the given fhe_type.
    pub fn create_plaintext(
        &self,
        fhe_type: u8,
        plaintext_bytes: &[u8],
        ciphertext: &'a AccountView,
    ) -> ProgramResult {
        let mut ix_data = Vec::with_capacity(1 + 1 + plaintext_bytes.len());
        ix_data.push(IX_CREATE_PLAINTEXT_CIPHERTEXT);
        ix_data.push(fhe_type);
        ix_data.extend_from_slice(plaintext_bytes);

        let accounts = [
            InstructionAccount { address: self.config.address(), is_writable: false, is_signer: false },
            InstructionAccount { address: self.deposit.address(), is_writable: true, is_signer: false },
            InstructionAccount { address: ciphertext.address(), is_writable: true, is_signer: true },
            InstructionAccount { address: self.caller_program.address(), is_writable: false, is_signer: false },
            InstructionAccount { address: self.cpi_authority.address(), is_writable: false, is_signer: true },
            InstructionAccount { address: self.network_encryption_key.address(), is_writable: false, is_signer: false },
            InstructionAccount { address: self.payer.address(), is_writable: true, is_signer: true },
            InstructionAccount { address: self.system_program.address(), is_writable: false, is_signer: false },
            InstructionAccount { address: self.event_authority.address(), is_writable: false, is_signer: false },
            InstructionAccount { address: self.encrypt_program.address(), is_writable: false, is_signer: false },
        ];
        let ix = InstructionView { program_id: self.encrypt_program.address(), data: &ix_data, accounts: &accounts };
        let bump_byte = [self.cpi_authority_bump];
        let seeds = [Seed::from(CPI_AUTHORITY_SEED), Seed::from(&bump_byte)];
        let signer = [Signer::from(&seeds)];
        invoke_signed(&ix, &[self.config, self.deposit, ciphertext, self.caller_program, self.cpi_authority, self.network_encryption_key, self.payer, self.system_program, self.event_authority, self.encrypt_program], &signer)
    }

    /// Typed version: create a ciphertext from a plaintext value.
    ///
    /// Derives `fhe_type` and serialization from the generic type `T`.
    /// ```ignore
    /// ctx.create_plaintext_typed::<Uint64>(&0u64, ciphertext)?;
    /// ```
    pub fn create_plaintext_typed<T: encrypt_types::encrypted::EncryptedType>(
        &self,
        value: &T::DecryptedValue,
        ciphertext: &'a AccountView,
    ) -> ProgramResult {
        let plaintext_bytes = unsafe {
            core::slice::from_raw_parts(value as *const T::DecryptedValue as *const u8, T::BYTE_WIDTH)
        };
        self.create_plaintext(
            T::FHE_TYPE_ID,
            plaintext_bytes,
            ciphertext,
        )
    }

    // ── Execute operations ──

    /// Execute an inline computation graph via CPI.
    ///
    /// `ix_data` is the fully serialized instruction data (built by `#[encrypt_fn]` macro).
    /// `remaining` contains input ciphertexts and output ciphertexts (no guards).
    pub fn execute_graph(
        &self,
        ix_data: &[u8],
        remaining: &[&'a AccountView],
    ) -> ProgramResult {
        let fixed = [
            InstructionAccount { address: self.config.address(), is_writable: true, is_signer: false },
            InstructionAccount { address: self.deposit.address(), is_writable: true, is_signer: false },
            InstructionAccount { address: self.caller_program.address(), is_writable: false, is_signer: false },
            InstructionAccount { address: self.cpi_authority.address(), is_writable: false, is_signer: true },
            InstructionAccount { address: self.network_encryption_key.address(), is_writable: false, is_signer: false },
            InstructionAccount { address: self.payer.address(), is_writable: true, is_signer: true },
            InstructionAccount { address: self.event_authority.address(), is_writable: false, is_signer: false },
            InstructionAccount { address: self.encrypt_program.address(), is_writable: false, is_signer: false },
        ];

        let mut accounts = Vec::with_capacity(8 + remaining.len());
        accounts.extend_from_slice(&fixed);
        for acct in remaining {
            accounts.push(InstructionAccount { address: acct.address(), is_writable: true, is_signer: false });
        }

        let ix = InstructionView { program_id: self.encrypt_program.address(), data: ix_data, accounts: &accounts };
        let bump_byte = [self.cpi_authority_bump];
        let seeds = [Seed::from(CPI_AUTHORITY_SEED), Seed::from(&bump_byte)];
        let signer = [Signer::from(&seeds)];

        let mut views: Vec<&AccountView> = Vec::with_capacity(8 + remaining.len());
        views.extend_from_slice(&[self.config, self.deposit, self.caller_program, self.cpi_authority, self.network_encryption_key, self.payer, self.event_authority, self.encrypt_program]);
        views.extend_from_slice(remaining);
        invoke_signed_with_bounds::<64>(&ix, &views, &signer)
    }

    /// Execute a registered computation graph via CPI.
    ///
    /// `graph_pda` is the RegisteredGraph account.
    /// `ix_data` contains the serialized input/output IDs.
    /// `remaining` contains input ciphertexts and output ciphertexts (no guards).
    pub fn execute_registered_graph(
        &self,
        graph_pda: &'a AccountView,
        ix_data: &[u8],
        remaining: &[&'a AccountView],
    ) -> ProgramResult {
        let fixed = [
            InstructionAccount { address: self.config.address(), is_writable: true, is_signer: false },
            InstructionAccount { address: self.deposit.address(), is_writable: true, is_signer: false },
            InstructionAccount { address: graph_pda.address(), is_writable: false, is_signer: false },
            InstructionAccount { address: self.caller_program.address(), is_writable: false, is_signer: false },
            InstructionAccount { address: self.cpi_authority.address(), is_writable: false, is_signer: true },
            InstructionAccount { address: self.network_encryption_key.address(), is_writable: false, is_signer: false },
            InstructionAccount { address: self.payer.address(), is_writable: true, is_signer: true },
            InstructionAccount { address: self.event_authority.address(), is_writable: false, is_signer: false },
            InstructionAccount { address: self.encrypt_program.address(), is_writable: false, is_signer: false },
        ];

        let mut accounts = Vec::with_capacity(9 + remaining.len());
        accounts.extend_from_slice(&fixed);
        for acct in remaining {
            accounts.push(InstructionAccount { address: acct.address(), is_writable: true, is_signer: false });
        }

        let ix = InstructionView { program_id: self.encrypt_program.address(), data: ix_data, accounts: &accounts };
        let bump_byte = [self.cpi_authority_bump];
        let seeds = [Seed::from(CPI_AUTHORITY_SEED), Seed::from(&bump_byte)];
        let signer = [Signer::from(&seeds)];

        let mut views: Vec<&AccountView> = Vec::with_capacity(9 + remaining.len());
        views.extend_from_slice(&[self.config, self.deposit, graph_pda, self.caller_program, self.cpi_authority, self.network_encryption_key, self.payer, self.event_authority, self.encrypt_program]);
        views.extend_from_slice(remaining);
        invoke_signed_with_bounds::<64>(&ix, &views, &signer)
    }

    /// Register a computation graph PDA for repeated execution.
    pub fn register_graph(
        &self,
        graph_pda: &'a AccountView,
        bump: u8,
        graph_hash: &[u8; 32],
        graph_data: &[u8],
    ) -> ProgramResult {
        let graph_data_len = graph_data.len() as u16;
        let mut ix_data = Vec::with_capacity(1 + 1 + 32 + 2 + graph_data.len());
        ix_data.push(IX_REGISTER_GRAPH);
        ix_data.push(bump);
        ix_data.extend_from_slice(graph_hash);
        ix_data.extend_from_slice(&graph_data_len.to_le_bytes());
        ix_data.extend_from_slice(graph_data);

        let accounts = [
            InstructionAccount { address: graph_pda.address(), is_writable: true, is_signer: false },
            InstructionAccount { address: self.caller_program.address(), is_writable: false, is_signer: true },
            InstructionAccount { address: self.payer.address(), is_writable: true, is_signer: true },
            InstructionAccount { address: self.system_program.address(), is_writable: false, is_signer: false },
        ];
        let ix = InstructionView { program_id: self.encrypt_program.address(), data: &ix_data, accounts: &accounts };
        let bump_byte = [self.cpi_authority_bump];
        let seeds = [Seed::from(CPI_AUTHORITY_SEED), Seed::from(&bump_byte)];
        let signer = [Signer::from(&seeds)];
        invoke_signed(&ix, &[graph_pda, self.caller_program, self.payer, self.system_program, self.encrypt_program], &signer)
    }

    // ── Ownership operations ──

    /// Transfer ciphertext authorization to a new party.
    pub fn transfer_ciphertext(
        &self,
        ciphertext: &'a AccountView,
        new_authorized: &'a AccountView,
    ) -> ProgramResult {
        let ix_data = [IX_TRANSFER_CIPHERTEXT];

        let accounts = [
            InstructionAccount { address: ciphertext.address(), is_writable: true, is_signer: false },
            InstructionAccount { address: self.caller_program.address(), is_writable: false, is_signer: false },
            InstructionAccount { address: self.cpi_authority.address(), is_writable: false, is_signer: true },
            InstructionAccount { address: new_authorized.address(), is_writable: false, is_signer: false },
        ];
        let ix = InstructionView { program_id: self.encrypt_program.address(), data: &ix_data, accounts: &accounts };
        let bump_byte = [self.cpi_authority_bump];
        let seeds = [Seed::from(CPI_AUTHORITY_SEED), Seed::from(&bump_byte)];
        let signer = [Signer::from(&seeds)];
        invoke_signed(&ix, &[ciphertext, self.caller_program, self.cpi_authority, new_authorized, self.encrypt_program], &signer)
    }

    /// Copy a ciphertext with a different authorized party.
    pub fn copy_ciphertext(
        &self,
        source_ciphertext: &'a AccountView,
        new_ciphertext: &'a AccountView,
        new_authorized: &'a AccountView,
    ) -> ProgramResult {
        let ix_data = [IX_COPY_CIPHERTEXT];

        let accounts = [
            InstructionAccount { address: source_ciphertext.address(), is_writable: false, is_signer: false },
            InstructionAccount { address: new_ciphertext.address(), is_writable: true, is_signer: false },
            InstructionAccount { address: self.caller_program.address(), is_writable: false, is_signer: false },
            InstructionAccount { address: self.cpi_authority.address(), is_writable: false, is_signer: true },
            InstructionAccount { address: new_authorized.address(), is_writable: false, is_signer: false },
            InstructionAccount { address: self.payer.address(), is_writable: true, is_signer: true },
            InstructionAccount { address: self.system_program.address(), is_writable: false, is_signer: false },
        ];
        let ix = InstructionView { program_id: self.encrypt_program.address(), data: &ix_data, accounts: &accounts };
        let bump_byte = [self.cpi_authority_bump];
        let seeds = [Seed::from(CPI_AUTHORITY_SEED), Seed::from(&bump_byte)];
        let signer = [Signer::from(&seeds)];
        invoke_signed(&ix, &[source_ciphertext, new_ciphertext, self.caller_program, self.cpi_authority, new_authorized, self.payer, self.system_program, self.encrypt_program], &signer)
    }

    /// Mark a ciphertext as fully public (anyone can compute + decrypt).
    pub fn make_public(
        &self,
        ciphertext: &'a AccountView,
    ) -> ProgramResult {
        let ix_data = [IX_MAKE_PUBLIC];

        let accounts = [
            InstructionAccount { address: ciphertext.address(), is_writable: true, is_signer: false },
            InstructionAccount { address: self.caller_program.address(), is_writable: false, is_signer: false },
            InstructionAccount { address: self.cpi_authority.address(), is_writable: false, is_signer: true },
        ];
        let ix = InstructionView { program_id: self.encrypt_program.address(), data: &ix_data, accounts: &accounts };
        let bump_byte = [self.cpi_authority_bump];
        let seeds = [Seed::from(CPI_AUTHORITY_SEED), Seed::from(&bump_byte)];
        let signer = [Signer::from(&seeds)];
        invoke_signed(&ix, &[ciphertext, self.caller_program, self.cpi_authority, self.encrypt_program], &signer)
    }

    // ── Decryption ──

    /// Request decryption of a ciphertext. Returns the `ciphertext_digest`
    /// snapshot — store it in your program state for verification at reveal time.
    pub fn request_decryption(
        &self,
        request_acct: &'a AccountView,
        ciphertext: &'a AccountView,
    ) -> Result<[u8; 32], ProgramError> {
        // Read digest before CPI — caller should store this for later verification
        let ct_data = unsafe { ciphertext.borrow_unchecked() };
        if ct_data.len() < encrypt_solana_types::accounts::CT_LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&ct_data[encrypt_solana_types::accounts::CT_CIPHERTEXT_DIGEST..encrypt_solana_types::accounts::CT_CIPHERTEXT_DIGEST + 32]);

        let ix_data = [IX_REQUEST_DECRYPTION];

        let accounts = [
            InstructionAccount { address: self.config.address(), is_writable: false, is_signer: false },
            InstructionAccount { address: self.deposit.address(), is_writable: true, is_signer: false },
            InstructionAccount { address: request_acct.address(), is_writable: true, is_signer: true },
            InstructionAccount { address: self.caller_program.address(), is_writable: false, is_signer: false },
            InstructionAccount { address: self.cpi_authority.address(), is_writable: false, is_signer: true },
            InstructionAccount { address: ciphertext.address(), is_writable: false, is_signer: false },
            InstructionAccount { address: self.payer.address(), is_writable: true, is_signer: true },
            InstructionAccount { address: self.system_program.address(), is_writable: false, is_signer: false },
            InstructionAccount { address: self.event_authority.address(), is_writable: false, is_signer: false },
            InstructionAccount { address: self.encrypt_program.address(), is_writable: false, is_signer: false },
        ];
        let ix = InstructionView { program_id: self.encrypt_program.address(), data: &ix_data, accounts: &accounts };
        let bump_byte = [self.cpi_authority_bump];
        let seeds = [Seed::from(CPI_AUTHORITY_SEED), Seed::from(&bump_byte)];
        let signer = [Signer::from(&seeds)];
        invoke_signed(&ix, &[self.config, self.deposit, request_acct, self.caller_program, self.cpi_authority, ciphertext, self.payer, self.system_program, self.event_authority, self.encrypt_program], &signer)?;
        Ok(digest)
    }

    /// Close a completed decryption request and reclaim rent.
    pub fn close_decryption_request(
        &self,
        request: &'a AccountView,
        destination: &'a AccountView,
    ) -> ProgramResult {
        let ix_data = [IX_CLOSE_DECRYPTION_REQUEST];

        let accounts = [
            InstructionAccount { address: request.address(), is_writable: true, is_signer: false },
            InstructionAccount { address: self.caller_program.address(), is_writable: false, is_signer: false },
            InstructionAccount { address: self.cpi_authority.address(), is_writable: false, is_signer: true },
            InstructionAccount { address: destination.address(), is_writable: true, is_signer: false },
        ];
        let ix = InstructionView { program_id: self.encrypt_program.address(), data: &ix_data, accounts: &accounts };
        let bump_byte = [self.cpi_authority_bump];
        let seeds = [Seed::from(CPI_AUTHORITY_SEED), Seed::from(&bump_byte)];
        let signer = [Signer::from(&seeds)];
        invoke_signed(&ix, &[request, self.caller_program, self.cpi_authority, destination, self.encrypt_program], &signer)
    }

    /// Close a ciphertext account and reclaim rent to the destination.
    pub fn close_ciphertext(
        &self,
        ciphertext: &'a AccountView,
        destination: &'a AccountView,
    ) -> ProgramResult {
        let ix_data = [IX_CLOSE_CIPHERTEXT];

        let accounts = [
            InstructionAccount { address: ciphertext.address(), is_writable: true, is_signer: false },
            InstructionAccount { address: self.caller_program.address(), is_writable: false, is_signer: false },
            InstructionAccount { address: self.cpi_authority.address(), is_writable: false, is_signer: true },
            InstructionAccount { address: destination.address(), is_writable: true, is_signer: false },
            InstructionAccount { address: self.event_authority.address(), is_writable: false, is_signer: false },
            InstructionAccount { address: self.encrypt_program.address(), is_writable: false, is_signer: false },
        ];
        let ix = InstructionView { program_id: self.encrypt_program.address(), data: &ix_data, accounts: &accounts };
        let bump_byte = [self.cpi_authority_bump];
        let seeds = [Seed::from(CPI_AUTHORITY_SEED), Seed::from(&bump_byte)];
        let signer = [Signer::from(&seeds)];
        invoke_signed(&ix, &[ciphertext, self.caller_program, self.cpi_authority, destination, self.event_authority, self.encrypt_program], &signer)
    }
}
