// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Quasar CPI context for the full Encrypt program lifecycle.

extern crate alloc;
use alloc::vec::Vec;

use quasar_lang::{
    cpi::{CpiAccount, InstructionAccount, InstructionView, Seed, Signer},
    prelude::{AccountView, ProgramError},
};

// Ciphertext account layout constants (inlined from encrypt-solana-types to avoid serde dep)
const CT_CIPHERTEXT_DIGEST: usize = 2;
const CT_FHE_TYPE: usize = 98;
const CT_LEN: usize = 100;

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

/// Full Encrypt program lifecycle context for Quasar developer programs.
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

impl<'a> encrypt_solana_types::cpi::EncryptCpi for EncryptContext<'a> {
    type Error = ProgramError;
    type Account<'b> = &'b AccountView where Self: 'b;

    fn read_fhe_type<'b>(&'b self, account: &'b AccountView) -> Option<u8> {
        let data = unsafe { core::slice::from_raw_parts(account.data_ptr(), CT_LEN) };
        Some(data[CT_FHE_TYPE])
    }

    fn type_mismatch_error(&self) -> ProgramError {
        ProgramError::InvalidArgument
    }

    fn invoke_execute_graph<'b>(
        &'b self,
        ix_data: &[u8],
        encrypt_execute_accounts: &[&'b AccountView],
    ) -> Result<(), ProgramError> {
        self.execute_graph(ix_data, encrypt_execute_accounts)
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
    ) -> Result<(), ProgramError> {
        let mut ix_data = Vec::with_capacity(1 + 1 + plaintext_bytes.len());
        ix_data.push(IX_CREATE_PLAINTEXT_CIPHERTEXT);
        ix_data.push(fhe_type);
        ix_data.extend_from_slice(plaintext_bytes);

        let ix_accounts = [
            InstructionAccount::new(self.config.address(), false, false),
            InstructionAccount::new(self.deposit.address(), true, false),
            InstructionAccount::new(ciphertext.address(), true, true),
            InstructionAccount::new(self.caller_program.address(), false, false),
            InstructionAccount::new(self.cpi_authority.address(), false, true),
            InstructionAccount::new(self.network_encryption_key.address(), false, false),
            InstructionAccount::new(self.payer.address(), true, true),
            InstructionAccount::new(self.system_program.address(), false, false),
            InstructionAccount::new(self.event_authority.address(), false, false),
            InstructionAccount::new(self.encrypt_program.address(), false, false),
        ];

        let cpi_accts = [
            CpiAccount::from(self.config),
            CpiAccount::from(self.deposit),
            CpiAccount::from(ciphertext),
            CpiAccount::from(self.caller_program),
            CpiAccount::from(self.cpi_authority),
            CpiAccount::from(self.network_encryption_key),
            CpiAccount::from(self.payer),
            CpiAccount::from(self.system_program),
            CpiAccount::from(self.event_authority),
            CpiAccount::from(self.encrypt_program),
        ];

        let bump_byte = [self.cpi_authority_bump];
        let signer_seeds: [Seed; 2] = [
            Seed::from(CPI_AUTHORITY_SEED),
            Seed::from(&bump_byte as &[u8]),
        ];
        let signers = [Signer::from(&signer_seeds[..])];

        let instruction = InstructionView {
            program_id: self.encrypt_program.address(),
            accounts: &ix_accounts,
            data: &ix_data,
        };

        unsafe {
            solana_instruction_view::cpi::invoke_signed_unchecked(
                &instruction,
                &cpi_accts,
                &signers,
            );
        }
        Ok(())
    }

    /// Typed version: create a ciphertext from a plaintext value.
    pub fn create_plaintext_typed<T: encrypt_types::encrypted::EncryptedType>(
        &self,
        value: &T::DecryptedValue,
        ciphertext: &'a AccountView,
    ) -> Result<(), ProgramError> {
        let plaintext_bytes = unsafe {
            core::slice::from_raw_parts(value as *const T::DecryptedValue as *const u8, T::BYTE_WIDTH)
        };
        self.create_plaintext(T::FHE_TYPE_ID, plaintext_bytes, ciphertext)
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
    ) -> Result<(), ProgramError> {
        let mut ix_accounts = Vec::with_capacity(8 + remaining.len());
        ix_accounts.extend_from_slice(&[
            InstructionAccount::new(self.config.address(), true, false),
            InstructionAccount::new(self.deposit.address(), true, false),
            InstructionAccount::new(self.caller_program.address(), false, false),
            InstructionAccount::new(self.cpi_authority.address(), false, true),
            InstructionAccount::new(self.network_encryption_key.address(), false, false),
            InstructionAccount::new(self.payer.address(), true, true),
            InstructionAccount::new(self.event_authority.address(), false, false),
            InstructionAccount::new(self.encrypt_program.address(), false, false),
        ]);
        for acct in remaining {
            ix_accounts.push(InstructionAccount::new(acct.address(), true, false));
        }

        let mut cpi_accts = Vec::with_capacity(8 + remaining.len());
        cpi_accts.extend_from_slice(&[
            CpiAccount::from(self.config),
            CpiAccount::from(self.deposit),
            CpiAccount::from(self.caller_program),
            CpiAccount::from(self.cpi_authority),
            CpiAccount::from(self.network_encryption_key),
            CpiAccount::from(self.payer),
            CpiAccount::from(self.event_authority),
            CpiAccount::from(self.encrypt_program),
        ]);
        for acct in remaining {
            cpi_accts.push(CpiAccount::from(*acct));
        }

        let bump_byte = [self.cpi_authority_bump];
        let signer_seeds: [Seed; 2] = [
            Seed::from(CPI_AUTHORITY_SEED),
            Seed::from(&bump_byte as &[u8]),
        ];
        let signers = [Signer::from(&signer_seeds[..])];

        let instruction = InstructionView {
            program_id: self.encrypt_program.address(),
            accounts: &ix_accounts,
            data: ix_data,
        };

        unsafe {
            solana_instruction_view::cpi::invoke_signed_unchecked(
                &instruction,
                &cpi_accts,
                &signers,
            );
        }
        Ok(())
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
    ) -> Result<(), ProgramError> {
        let mut ix_accounts = Vec::with_capacity(9 + remaining.len());
        ix_accounts.extend_from_slice(&[
            InstructionAccount::new(self.config.address(), true, false),
            InstructionAccount::new(self.deposit.address(), true, false),
            InstructionAccount::new(graph_pda.address(), false, false),
            InstructionAccount::new(self.caller_program.address(), false, false),
            InstructionAccount::new(self.cpi_authority.address(), false, true),
            InstructionAccount::new(self.network_encryption_key.address(), false, false),
            InstructionAccount::new(self.payer.address(), true, true),
            InstructionAccount::new(self.event_authority.address(), false, false),
            InstructionAccount::new(self.encrypt_program.address(), false, false),
        ]);
        for acct in remaining {
            ix_accounts.push(InstructionAccount::new(acct.address(), true, false));
        }

        let mut cpi_accts = Vec::with_capacity(9 + remaining.len());
        cpi_accts.extend_from_slice(&[
            CpiAccount::from(self.config),
            CpiAccount::from(self.deposit),
            CpiAccount::from(graph_pda),
            CpiAccount::from(self.caller_program),
            CpiAccount::from(self.cpi_authority),
            CpiAccount::from(self.network_encryption_key),
            CpiAccount::from(self.payer),
            CpiAccount::from(self.event_authority),
            CpiAccount::from(self.encrypt_program),
        ]);
        for acct in remaining {
            cpi_accts.push(CpiAccount::from(*acct));
        }

        let bump_byte = [self.cpi_authority_bump];
        let signer_seeds: [Seed; 2] = [
            Seed::from(CPI_AUTHORITY_SEED),
            Seed::from(&bump_byte as &[u8]),
        ];
        let signers = [Signer::from(&signer_seeds[..])];

        let instruction = InstructionView {
            program_id: self.encrypt_program.address(),
            accounts: &ix_accounts,
            data: ix_data,
        };

        unsafe {
            solana_instruction_view::cpi::invoke_signed_unchecked(
                &instruction,
                &cpi_accts,
                &signers,
            );
        }
        Ok(())
    }

    /// Register a computation graph PDA for repeated execution.
    pub fn register_graph(
        &self,
        graph_pda: &'a AccountView,
        bump: u8,
        graph_hash: &[u8; 32],
        graph_data: &[u8],
    ) -> Result<(), ProgramError> {
        let graph_data_len = graph_data.len() as u16;
        let mut ix_data = Vec::with_capacity(1 + 1 + 32 + 2 + graph_data.len());
        ix_data.push(IX_REGISTER_GRAPH);
        ix_data.push(bump);
        ix_data.extend_from_slice(graph_hash);
        ix_data.extend_from_slice(&graph_data_len.to_le_bytes());
        ix_data.extend_from_slice(graph_data);

        let ix_accounts = [
            InstructionAccount::new(graph_pda.address(), true, false),
            InstructionAccount::new(self.caller_program.address(), false, true),
            InstructionAccount::new(self.payer.address(), true, true),
            InstructionAccount::new(self.system_program.address(), false, false),
        ];

        let cpi_accts = [
            CpiAccount::from(graph_pda),
            CpiAccount::from(self.caller_program),
            CpiAccount::from(self.payer),
            CpiAccount::from(self.system_program),
        ];

        let bump_byte = [self.cpi_authority_bump];
        let signer_seeds: [Seed; 2] = [
            Seed::from(CPI_AUTHORITY_SEED),
            Seed::from(&bump_byte as &[u8]),
        ];
        let signers = [Signer::from(&signer_seeds[..])];

        let instruction = InstructionView {
            program_id: self.encrypt_program.address(),
            accounts: &ix_accounts,
            data: &ix_data,
        };

        unsafe {
            solana_instruction_view::cpi::invoke_signed_unchecked(
                &instruction,
                &cpi_accts,
                &signers,
            );
        }
        Ok(())
    }

    // ── Ownership operations ──

    /// Transfer ciphertext authorization to a new party.
    pub fn transfer_ciphertext(
        &self,
        ciphertext: &'a AccountView,
        new_authorized: &'a AccountView,
    ) -> Result<(), ProgramError> {
        let ix_data = [IX_TRANSFER_CIPHERTEXT];

        let ix_accounts = [
            InstructionAccount::new(ciphertext.address(), true, false),
            InstructionAccount::new(self.caller_program.address(), false, false),
            InstructionAccount::new(self.cpi_authority.address(), false, true),
            InstructionAccount::new(new_authorized.address(), false, false),
        ];

        let cpi_accts = [
            CpiAccount::from(ciphertext),
            CpiAccount::from(self.caller_program),
            CpiAccount::from(self.cpi_authority),
            CpiAccount::from(new_authorized),
        ];

        let bump_byte = [self.cpi_authority_bump];
        let signer_seeds: [Seed; 2] = [
            Seed::from(CPI_AUTHORITY_SEED),
            Seed::from(&bump_byte as &[u8]),
        ];
        let signers = [Signer::from(&signer_seeds[..])];

        let instruction = InstructionView {
            program_id: self.encrypt_program.address(),
            accounts: &ix_accounts,
            data: &ix_data,
        };

        unsafe {
            solana_instruction_view::cpi::invoke_signed_unchecked(
                &instruction,
                &cpi_accts,
                &signers,
            );
        }
        Ok(())
    }

    /// Copy a ciphertext with a different authorized party.
    pub fn copy_ciphertext(
        &self,
        source_ciphertext: &'a AccountView,
        new_ciphertext: &'a AccountView,
        new_authorized: &'a AccountView,
    ) -> Result<(), ProgramError> {
        let ix_data = [IX_COPY_CIPHERTEXT];

        let ix_accounts = [
            InstructionAccount::new(source_ciphertext.address(), false, false),
            InstructionAccount::new(new_ciphertext.address(), true, false),
            InstructionAccount::new(self.caller_program.address(), false, false),
            InstructionAccount::new(self.cpi_authority.address(), false, true),
            InstructionAccount::new(new_authorized.address(), false, false),
            InstructionAccount::new(self.payer.address(), true, true),
            InstructionAccount::new(self.system_program.address(), false, false),
        ];

        let cpi_accts = [
            CpiAccount::from(source_ciphertext),
            CpiAccount::from(new_ciphertext),
            CpiAccount::from(self.caller_program),
            CpiAccount::from(self.cpi_authority),
            CpiAccount::from(new_authorized),
            CpiAccount::from(self.payer),
            CpiAccount::from(self.system_program),
        ];

        let bump_byte = [self.cpi_authority_bump];
        let signer_seeds: [Seed; 2] = [
            Seed::from(CPI_AUTHORITY_SEED),
            Seed::from(&bump_byte as &[u8]),
        ];
        let signers = [Signer::from(&signer_seeds[..])];

        let instruction = InstructionView {
            program_id: self.encrypt_program.address(),
            accounts: &ix_accounts,
            data: &ix_data,
        };

        unsafe {
            solana_instruction_view::cpi::invoke_signed_unchecked(
                &instruction,
                &cpi_accts,
                &signers,
            );
        }
        Ok(())
    }

    /// Mark a ciphertext as fully public (anyone can compute + decrypt).
    pub fn make_public(
        &self,
        ciphertext: &'a AccountView,
    ) -> Result<(), ProgramError> {
        let ix_data = [IX_MAKE_PUBLIC];

        let ix_accounts = [
            InstructionAccount::new(ciphertext.address(), true, false),
            InstructionAccount::new(self.caller_program.address(), false, false),
            InstructionAccount::new(self.cpi_authority.address(), false, true),
        ];

        let cpi_accts = [
            CpiAccount::from(ciphertext),
            CpiAccount::from(self.caller_program),
            CpiAccount::from(self.cpi_authority),
        ];

        let bump_byte = [self.cpi_authority_bump];
        let signer_seeds: [Seed; 2] = [
            Seed::from(CPI_AUTHORITY_SEED),
            Seed::from(&bump_byte as &[u8]),
        ];
        let signers = [Signer::from(&signer_seeds[..])];

        let instruction = InstructionView {
            program_id: self.encrypt_program.address(),
            accounts: &ix_accounts,
            data: &ix_data,
        };

        unsafe {
            solana_instruction_view::cpi::invoke_signed_unchecked(
                &instruction,
                &cpi_accts,
                &signers,
            );
        }
        Ok(())
    }

    // ── Decryption ──

    /// Request decryption of a ciphertext. Returns the `ciphertext_digest`
    /// snapshot -- store it in your program state for verification at reveal time.
    pub fn request_decryption(
        &self,
        request_acct: &'a AccountView,
        ciphertext: &'a AccountView,
    ) -> Result<[u8; 32], ProgramError> {
        // Read digest before CPI -- caller should store this for later verification
        let ct_data = unsafe {
            core::slice::from_raw_parts(ciphertext.data_ptr(), CT_LEN)
        };
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&ct_data[CT_CIPHERTEXT_DIGEST..CT_CIPHERTEXT_DIGEST + 32]);

        let ix_data = [IX_REQUEST_DECRYPTION];

        let ix_accounts = [
            InstructionAccount::new(self.config.address(), false, false),
            InstructionAccount::new(self.deposit.address(), true, false),
            InstructionAccount::new(request_acct.address(), true, true),
            InstructionAccount::new(self.caller_program.address(), false, false),
            InstructionAccount::new(self.cpi_authority.address(), false, true),
            InstructionAccount::new(ciphertext.address(), false, false),
            InstructionAccount::new(self.payer.address(), true, true),
            InstructionAccount::new(self.system_program.address(), false, false),
            InstructionAccount::new(self.event_authority.address(), false, false),
            InstructionAccount::new(self.encrypt_program.address(), false, false),
        ];

        let cpi_accts = [
            CpiAccount::from(self.config),
            CpiAccount::from(self.deposit),
            CpiAccount::from(request_acct),
            CpiAccount::from(self.caller_program),
            CpiAccount::from(self.cpi_authority),
            CpiAccount::from(ciphertext),
            CpiAccount::from(self.payer),
            CpiAccount::from(self.system_program),
            CpiAccount::from(self.event_authority),
            CpiAccount::from(self.encrypt_program),
        ];

        let bump_byte = [self.cpi_authority_bump];
        let signer_seeds: [Seed; 2] = [
            Seed::from(CPI_AUTHORITY_SEED),
            Seed::from(&bump_byte as &[u8]),
        ];
        let signers = [Signer::from(&signer_seeds[..])];

        let instruction = InstructionView {
            program_id: self.encrypt_program.address(),
            accounts: &ix_accounts,
            data: &ix_data,
        };

        unsafe {
            solana_instruction_view::cpi::invoke_signed_unchecked(
                &instruction,
                &cpi_accts,
                &signers,
            );
        }
        Ok(digest)
    }

    /// Close a completed decryption request and reclaim rent.
    pub fn close_decryption_request(
        &self,
        request: &'a AccountView,
        destination: &'a AccountView,
    ) -> Result<(), ProgramError> {
        let ix_data = [IX_CLOSE_DECRYPTION_REQUEST];

        let ix_accounts = [
            InstructionAccount::new(request.address(), true, false),
            InstructionAccount::new(self.caller_program.address(), false, false),
            InstructionAccount::new(self.cpi_authority.address(), false, true),
            InstructionAccount::new(destination.address(), true, false),
        ];

        let cpi_accts = [
            CpiAccount::from(request),
            CpiAccount::from(self.caller_program),
            CpiAccount::from(self.cpi_authority),
            CpiAccount::from(destination),
        ];

        let bump_byte = [self.cpi_authority_bump];
        let signer_seeds: [Seed; 2] = [
            Seed::from(CPI_AUTHORITY_SEED),
            Seed::from(&bump_byte as &[u8]),
        ];
        let signers = [Signer::from(&signer_seeds[..])];

        let instruction = InstructionView {
            program_id: self.encrypt_program.address(),
            accounts: &ix_accounts,
            data: &ix_data,
        };

        unsafe {
            solana_instruction_view::cpi::invoke_signed_unchecked(
                &instruction,
                &cpi_accts,
                &signers,
            );
        }
        Ok(())
    }

    /// Close a ciphertext account and reclaim rent to the destination.
    pub fn close_ciphertext(
        &self,
        ciphertext: &'a AccountView,
        destination: &'a AccountView,
    ) -> Result<(), ProgramError> {
        let ix_data = [IX_CLOSE_CIPHERTEXT];

        let ix_accounts = [
            InstructionAccount::new(ciphertext.address(), true, false),
            InstructionAccount::new(self.caller_program.address(), false, false),
            InstructionAccount::new(self.cpi_authority.address(), false, true),
            InstructionAccount::new(destination.address(), true, false),
            InstructionAccount::new(self.event_authority.address(), false, false),
            InstructionAccount::new(self.encrypt_program.address(), false, false),
        ];

        let cpi_accts = [
            CpiAccount::from(ciphertext),
            CpiAccount::from(self.caller_program),
            CpiAccount::from(self.cpi_authority),
            CpiAccount::from(destination),
            CpiAccount::from(self.event_authority),
            CpiAccount::from(self.encrypt_program),
        ];

        let bump_byte = [self.cpi_authority_bump];
        let signer_seeds: [Seed; 2] = [
            Seed::from(CPI_AUTHORITY_SEED),
            Seed::from(&bump_byte as &[u8]),
        ];
        let signers = [Signer::from(&signer_seeds[..])];

        let instruction = InstructionView {
            program_id: self.encrypt_program.address(),
            accounts: &ix_accounts,
            data: &ix_data,
        };

        unsafe {
            solana_instruction_view::cpi::invoke_signed_unchecked(
                &instruction,
                &cpi_accts,
                &signers,
            );
        }
        Ok(())
    }
}
