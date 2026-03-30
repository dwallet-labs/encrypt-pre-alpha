// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! `EncryptTxBuilder` — production-safe transaction construction for the Encrypt program.
//!
//! Builds and submits transactions for all Encrypt program instructions.
//! Does NOT hold any test state (no store, no work queue, no compute engine).
//! Used by both the test harness and the CLI executor.

use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Keypair;
use solana_sdk::signer::Signer;
use solana_sdk::transaction::Transaction;

use crate::error::EncryptDevError;
use crate::runtime::SolanaRuntime;

/// System program ID.
const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::new_from_array([0u8; 32]);

/// Ciphertext account data size: 2 (disc+ver) + 98 (struct) = 100 bytes.
pub const CIPHERTEXT_ACCOUNT_SIZE: usize = 100;

/// Instruction discriminators (must match on-chain program).
pub mod disc {
    pub const INITIALIZE: u8 = 0;
    pub const CREATE_INPUT_CIPHERTEXT: u8 = 1;
    pub const CREATE_PLAINTEXT_CIPHERTEXT: u8 = 2;
    pub const COMMIT_CIPHERTEXT: u8 = 3;
    pub const EXECUTE_GRAPH: u8 = 4;
    pub const CLOSE_CIPHERTEXT: u8 = 9;
    pub const REQUEST_DECRYPTION: u8 = 11;
    pub const RESPOND_DECRYPTION: u8 = 12;
    pub const CREATE_DEPOSIT: u8 = 14;
    pub const REGISTER_NETWORK_ENCRYPTION_KEY: u8 = 22;
}

/// The Encrypt program's declared ID.
pub const ENCRYPT_PROGRAM_ID: &str = "Cq37zHSH1zB6xomYK2LjP6uXJvLR3uTehxA5W9wgHGvx";

/// Configuration for creating an `EncryptTxBuilder`.
pub struct EncryptTxConfig {
    pub program_id: Pubkey,
    pub authority: Keypair,
    pub authority_pda: Pubkey,
    pub config_pda: Pubkey,
    pub deposit_pda: Pubkey,
    pub network_encryption_key_pda: Pubkey,
    pub event_authority: Pubkey,
    pub payer: Keypair,
}

/// Production-safe transaction builder for the Encrypt program.
///
/// Builds and submits transactions. No mock state, no compute engine.
/// Used by both the test harness and the CLI.
pub struct EncryptTxBuilder<R: SolanaRuntime> {
    runtime: R,
    program_id: Pubkey,
    authority: Keypair,
    authority_pda: Pubkey,
    config_pda: Pubkey,
    deposit_pda: Pubkey,
    network_encryption_key_pda: Pubkey,
    event_authority: Pubkey,
    payer: Keypair,
}

impl<R: SolanaRuntime> EncryptTxBuilder<R> {
    pub fn new(runtime: R, config: EncryptTxConfig) -> Self {
        Self {
            runtime,
            program_id: config.program_id,
            authority: config.authority,
            authority_pda: config.authority_pda,
            config_pda: config.config_pda,
            deposit_pda: config.deposit_pda,
            network_encryption_key_pda: config.network_encryption_key_pda,
            event_authority: config.event_authority,
            payer: config.payer,
        }
    }

    // ── Executor operations (production) ──

    /// Authority commits a computed digest to a pending ciphertext.
    ///
    /// `previous_digest` must match the current on-chain digest (prevents stale commits).
    /// `new_digest` is the computed output digest to write.
    pub fn commit_ciphertext(
        &mut self,
        output_pk: &[u8; 32],
        previous_digest: &[u8; 32],
        new_digest: &[u8; 32],
    ) -> Result<(), EncryptDevError> {
        let mut ix_data = Vec::with_capacity(65);
        ix_data.push(disc::COMMIT_CIPHERTEXT);
        ix_data.extend_from_slice(previous_digest);
        ix_data.extend_from_slice(new_digest);

        let output_pubkey = Pubkey::from(*output_pk);

        let ix = Instruction::new_with_bytes(
            self.program_id,
            &ix_data,
            vec![
                AccountMeta::new_readonly(self.authority_pda, false),
                AccountMeta::new_readonly(self.authority.pubkey(), true),
                AccountMeta::new(output_pubkey, false),
                AccountMeta::new_readonly(self.event_authority, false),
                AccountMeta::new_readonly(self.program_id, false),
            ],
        );

        let blockhash = self.runtime.latest_blockhash();
        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&self.payer.pubkey()),
            &[&self.payer, &self.authority],
            blockhash,
        );
        self.runtime.send_transaction(&tx)
    }

    /// Authority writes decrypted plaintext to a decryption request.
    pub fn respond_decryption(
        &mut self,
        request_pk: &[u8; 32],
        plaintext: &[u8],
    ) -> Result<(), EncryptDevError> {
        let mut ix_data = Vec::with_capacity(1 + plaintext.len());
        ix_data.push(disc::RESPOND_DECRYPTION);
        ix_data.extend_from_slice(plaintext);

        let request_pubkey = Pubkey::from(*request_pk);

        let ix = Instruction::new_with_bytes(
            self.program_id,
            &ix_data,
            vec![
                AccountMeta::new_readonly(self.authority_pda, false),
                AccountMeta::new(request_pubkey, false),
                AccountMeta::new_readonly(self.authority.pubkey(), true),
                AccountMeta::new_readonly(self.event_authority, false),
                AccountMeta::new_readonly(self.program_id, false),
            ],
        );

        let blockhash = self.runtime.latest_blockhash();
        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&self.payer.pubkey()),
            &[&self.payer, &self.authority],
            blockhash,
        );
        self.runtime.send_transaction(&tx)
    }

    // ── User-facing operations ──

    /// Create a verified encrypted input ciphertext (authority-driven).
    ///
    /// `digest` is pre-computed (by MockComputeEngine in tests, by real FHE in production).
    pub fn create_input_ciphertext(
        &mut self,
        fhe_type: u8,
        digest: &[u8; 32],
        authorized: &Pubkey,
    ) -> Result<Pubkey, EncryptDevError> {
        let ct_keypair = Keypair::new();
        let ct_pubkey = ct_keypair.pubkey();

        let mut ix_data = Vec::with_capacity(34);
        ix_data.push(disc::CREATE_INPUT_CIPHERTEXT);
        ix_data.push(fhe_type);
        ix_data.extend_from_slice(digest);

        let ix = Instruction::new_with_bytes(
            self.program_id,
            &ix_data,
            vec![
                AccountMeta::new_readonly(self.authority_pda, false),
                AccountMeta::new_readonly(self.authority.pubkey(), true),
                AccountMeta::new_readonly(self.config_pda, false),
                AccountMeta::new(self.deposit_pda, false),
                AccountMeta::new(ct_pubkey, true),
                AccountMeta::new_readonly(*authorized, false),
                AccountMeta::new_readonly(self.network_encryption_key_pda, false),
                AccountMeta::new(self.payer.pubkey(), true),
                AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
                AccountMeta::new_readonly(self.event_authority, false),
                AccountMeta::new_readonly(self.program_id, false),
            ],
        );

        let blockhash = self.runtime.latest_blockhash();
        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&self.payer.pubkey()),
            &[&self.payer, &ct_keypair, &self.authority],
            blockhash,
        );
        self.runtime.send_transaction(&tx)?;
        Ok(ct_pubkey)
    }

    /// Create a plaintext ciphertext (user-signed).
    pub fn create_plaintext_ciphertext(
        &mut self,
        fhe_type: u8,
        plaintext_bytes: &[u8],
        creator: &Keypair,
    ) -> Result<Pubkey, EncryptDevError> {
        let ct_keypair = Keypair::new();
        let ct_pubkey = ct_keypair.pubkey();

        let mut ix_data = Vec::with_capacity(2 + plaintext_bytes.len());
        ix_data.push(disc::CREATE_PLAINTEXT_CIPHERTEXT);
        ix_data.push(fhe_type);
        ix_data.extend_from_slice(plaintext_bytes);

        let ix = Instruction::new_with_bytes(
            self.program_id,
            &ix_data,
            vec![
                AccountMeta::new_readonly(self.config_pda, false),
                AccountMeta::new(self.deposit_pda, false),
                AccountMeta::new(ct_pubkey, true),
                AccountMeta::new_readonly(creator.pubkey(), true),
                AccountMeta::new_readonly(self.network_encryption_key_pda, false),
                AccountMeta::new(self.payer.pubkey(), true),
                AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
                AccountMeta::new_readonly(self.event_authority, false),
                AccountMeta::new_readonly(self.program_id, false),
            ],
        );

        let blockhash = self.runtime.latest_blockhash();
        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&self.payer.pubkey()),
            &[&self.payer, &ct_keypair, creator],
            blockhash,
        );
        self.runtime.send_transaction(&tx)?;
        Ok(ct_pubkey)
    }

    /// Execute a computation graph on-chain.
    pub fn execute_graph(
        &mut self,
        graph_data: &[u8],
        input_pubkeys: &[Pubkey],
        num_new_outputs: usize,
        existing_output_pubkeys: &[Pubkey],
        caller: &Keypair,
    ) -> Result<Vec<Pubkey>, EncryptDevError> {
        let mut output_keypairs = Vec::new();
        for _ in 0..num_new_outputs {
            output_keypairs.push(Keypair::new());
        }

        let all_output_pubkeys: Vec<Pubkey> = output_keypairs
            .iter()
            .map(|kp| kp.pubkey())
            .chain(existing_output_pubkeys.iter().copied())
            .collect();

        let num_inputs = input_pubkeys.len() as u8;
        let graph_len = graph_data.len() as u16;
        let mut ix_data = Vec::with_capacity(1 + 2 + graph_data.len() + 1);
        ix_data.push(disc::EXECUTE_GRAPH);
        ix_data.extend_from_slice(&graph_len.to_le_bytes());
        ix_data.extend_from_slice(graph_data);
        ix_data.push(num_inputs);

        let mut account_metas = vec![
            AccountMeta::new_readonly(self.config_pda, false),
            AccountMeta::new(self.deposit_pda, false),
            AccountMeta::new_readonly(caller.pubkey(), true),
            AccountMeta::new_readonly(self.network_encryption_key_pda, false),
            AccountMeta::new(self.payer.pubkey(), true),
            AccountMeta::new_readonly(self.event_authority, false),
            AccountMeta::new_readonly(self.program_id, false),
        ];
        for pk in input_pubkeys {
            account_metas.push(AccountMeta::new_readonly(*pk, false));
        }
        for (i, pk) in all_output_pubkeys.iter().enumerate() {
            let is_new = i < num_new_outputs;
            account_metas.push(AccountMeta::new(*pk, is_new));
        }

        let ix = Instruction::new_with_bytes(self.program_id, &ix_data, account_metas);

        let mut signers: Vec<&Keypair> = vec![&self.payer, caller];
        for kp in &output_keypairs {
            signers.push(kp);
        }

        let blockhash = self.runtime.latest_blockhash();
        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&self.payer.pubkey()),
            &signers,
            blockhash,
        );
        self.runtime.send_transaction(&tx)?;
        Ok(all_output_pubkeys)
    }

    /// Request decryption of a ciphertext.
    ///
    /// `byte_width` determines the result account size.
    pub fn request_decryption(
        &mut self,
        ciphertext_pubkey: &Pubkey,
        byte_width: usize,
        requester: &Keypair,
    ) -> Result<Pubkey, EncryptDevError> {
        let req_keypair = Keypair::new();
        let req_pubkey = req_keypair.pubkey();

        let ix_data = vec![disc::REQUEST_DECRYPTION];

        let ix = Instruction::new_with_bytes(
            self.program_id,
            &ix_data,
            vec![
                AccountMeta::new_readonly(self.config_pda, false),
                AccountMeta::new(self.deposit_pda, false),
                AccountMeta::new(req_pubkey, true),
                AccountMeta::new_readonly(requester.pubkey(), true),
                AccountMeta::new_readonly(*ciphertext_pubkey, false),
                AccountMeta::new(self.payer.pubkey(), true),
                AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
                AccountMeta::new_readonly(self.event_authority, false),
                AccountMeta::new_readonly(self.program_id, false),
            ],
        );

        let blockhash = self.runtime.latest_blockhash();
        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&self.payer.pubkey()),
            &[&self.payer, &req_keypair, requester],
            blockhash,
        );
        self.runtime.send_transaction(&tx)?;
        Ok(req_pubkey)
    }

    /// Read decrypted value from a completed DecryptionRequest account.
    pub fn read_decrypted_on_chain(
        &self,
        request_pubkey: &Pubkey,
    ) -> Result<Vec<u8>, EncryptDevError> {
        let data = self
            .runtime
            .get_account_data(request_pubkey)?
            .ok_or_else(|| EncryptDevError::AccountNotFound(format!("{request_pubkey}")))?;

        if data.len() < 107 {
            return Err(EncryptDevError::InvalidAccountData(
                "request account too small".to_string(),
            ));
        }

        let total_len = u32::from_le_bytes(data[99..103].try_into().unwrap()) as usize;
        let bytes_written = u32::from_le_bytes(data[103..107].try_into().unwrap()) as usize;

        if bytes_written != total_len {
            return Err(EncryptDevError::DecryptionFailed(format!(
                "incomplete: {bytes_written}/{total_len}"
            )));
        }

        Ok(data[107..107 + total_len].to_vec())
    }

    // ── Initialize (for test/dev setup) ──

    /// Send the `initialize` instruction. Requires payer + authority as signers.
    /// `enc_vault` is the vault address for ENC token deposits (use payer address for dev).
    pub fn initialize(
        &mut self,
        config_bump: u8,
        authority_bump: u8,
        enc_vault: &Pubkey,
    ) -> Result<(), EncryptDevError> {
        let mut init_data = Vec::with_capacity(67);
        init_data.push(disc::INITIALIZE);
        init_data.push(config_bump);
        init_data.push(authority_bump);
        init_data.extend_from_slice(&[0u8; 32]); // enc_mint (zero for dev)
        init_data.extend_from_slice(enc_vault.as_ref()); // enc_vault

        let ix = Instruction::new_with_bytes(
            self.program_id,
            &init_data,
            vec![
                AccountMeta::new(self.config_pda, false),
                AccountMeta::new(self.authority_pda, false),
                AccountMeta::new_readonly(self.authority.pubkey(), true),
                AccountMeta::new(self.payer.pubkey(), true),
                AccountMeta::new_readonly(Pubkey::new_from_array([0u8; 32]), false),
            ],
        );

        let blockhash = self.runtime.latest_blockhash();
        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&self.payer.pubkey()),
            &[&self.payer, &self.authority],
            blockhash,
        );
        self.runtime.send_transaction(&tx)
    }

    // ── Accessors ──

    pub fn runtime(&self) -> &R {
        &self.runtime
    }

    pub fn runtime_mut(&mut self) -> &mut R {
        &mut self.runtime
    }

    pub fn program_id(&self) -> &Pubkey {
        &self.program_id
    }

    pub fn authority(&self) -> &Keypair {
        &self.authority
    }

    pub fn payer(&self) -> &Keypair {
        &self.payer
    }

    pub fn config_pda(&self) -> &Pubkey {
        &self.config_pda
    }

    pub fn deposit_pda(&self) -> &Pubkey {
        &self.deposit_pda
    }

    pub fn network_encryption_key_pda(&self) -> &Pubkey {
        &self.network_encryption_key_pda
    }

    pub fn event_authority(&self) -> &Pubkey {
        &self.event_authority
    }
}
