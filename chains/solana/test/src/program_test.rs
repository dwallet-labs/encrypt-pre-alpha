// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! `solana-program-test` based test context.
//!
//! Similar to `EncryptTestContext` (LiteSVM) but uses the official Solana runtime.
//! Programs must be declared upfront — they're loaded before the runtime starts.

use encrypt_compute::engine::ComputeEngine;
use encrypt_dev::runtime::{InProcessTestRuntime, SolanaRuntime, TestRuntime};
use encrypt_dev::tx_builder::ENCRYPT_PROGRAM_ID;
use encrypt_service::store::CiphertextStore;
use encrypt_types::encrypted::EncryptedType;
use encrypt_types::types::FheType;
use solana_sdk::hash::Hash;
use solana_sdk::instruction::Instruction;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Keypair;
use solana_sdk::signer::Signer;
use solana_sdk::transaction::Transaction;

use crate::harness::{EncryptTestConfig, EncryptTestHarness};
use crate::runtime_program_test::ProgramTestRuntime;

/// Test context using `solana-program-test` (official Solana runtime).
///
/// Programs must be declared at construction time — they're loaded before
/// the runtime starts. Use `ProgramTestEncryptContext::builder()` to add
/// extra programs beyond the Encrypt program.
pub struct ProgramTestEncryptContext {
    harness: EncryptTestHarness<ProgramTestRuntime>,
}

/// Builder for `ProgramTestEncryptContext` — allows adding extra programs.
pub struct ProgramTestBuilder {
    extra_programs: Vec<(String, Pubkey)>,
}

impl ProgramTestBuilder {
    pub fn new() -> Self {
        Self {
            extra_programs: Vec::new(),
        }
    }

    /// Add an extra program to load (e.g., your voting program).
    pub fn add_program(mut self, name: &str, program_id: Pubkey) -> Self {
        self.extra_programs.push((name.to_string(), program_id));
        self
    }

    /// Build the context. Loads the Encrypt program + any extra programs.
    pub fn build(self) -> ProgramTestEncryptContext {
        let encrypt_program_id: Pubkey = ENCRYPT_PROGRAM_ID
            .parse()
            .expect("invalid encrypt program id");

        let mut programs: Vec<(String, Pubkey)> = vec![
            ("encrypt_program".to_string(), encrypt_program_id),
        ];
        programs.extend(self.extra_programs);

        let runtime = ProgramTestRuntime::new(programs);

        // program_elf_path is unused for ProgramTestRuntime (programs pre-loaded)
        let config = EncryptTestConfig {
            program_elf_path: String::new(),
        };
        let harness = EncryptTestHarness::new(runtime, config)
            .expect("failed to create test harness");

        ProgramTestEncryptContext { harness }
    }
}

impl Default for ProgramTestBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ProgramTestEncryptContext {
    /// Create a builder to configure extra programs.
    pub fn builder() -> ProgramTestBuilder {
        ProgramTestBuilder::new()
    }

    /// Create with just the Encrypt program (no extra programs).
    pub fn new_default() -> Self {
        ProgramTestBuilder::new().build()
    }

    pub fn new_funded_keypair(&mut self) -> Keypair {
        let kp = Keypair::new();
        self.harness
            .tx_builder_mut()
            .runtime_mut()
            .airdrop(&kp.pubkey(), 10_000_000_000)
            .expect("airdrop failed");
        kp
    }

    pub fn create_input<T: EncryptedType>(&mut self, value: u128, authorized: &Pubkey) -> Pubkey {
        self.harness
            .create_input_ciphertext(
                FheType::from_u8(T::FHE_TYPE_ID).expect("invalid FHE type"),
                value,
                authorized,
            )
            .expect("create_input_ciphertext failed")
    }

    pub fn create_plaintext<T: EncryptedType>(
        &mut self,
        value: &T::DecryptedValue,
        creator: &Keypair,
    ) -> Pubkey {
        let fhe_type = FheType::from_u8(T::FHE_TYPE_ID).expect("invalid FHE type");
        let plaintext_bytes = unsafe {
            core::slice::from_raw_parts(
                value as *const T::DecryptedValue as *const u8,
                T::BYTE_WIDTH,
            )
        };
        self.harness
            .create_plaintext_ciphertext(fhe_type, plaintext_bytes, creator)
            .expect("create_plaintext_ciphertext failed")
    }

    pub fn execute_and_commit(
        &mut self,
        graph_data: &[u8],
        input_pubkeys: &[Pubkey],
        num_new_outputs: usize,
        existing_output_pubkeys: &[Pubkey],
        caller: &Keypair,
    ) -> Vec<Pubkey> {
        self.harness
            .execute_and_commit(
                graph_data, input_pubkeys, num_new_outputs, existing_output_pubkeys, caller,
            )
            .expect("execute_and_commit failed")
    }

    pub fn decrypt<T: EncryptedType>(
        &mut self,
        ciphertext_pubkey: &Pubkey,
        requester: &Keypair,
    ) -> u128 {
        let (_req, _plaintext) = self
            .harness
            .decrypt_and_respond(ciphertext_pubkey, requester)
            .expect("decrypt_and_respond failed");
        self.decrypt_from_store(ciphertext_pubkey)
    }

    pub fn program_id(&self) -> &Pubkey {
        self.harness.program_id()
    }

    pub fn payer(&self) -> &Keypair {
        self.harness.payer()
    }

    // ── CPI / e2e helpers ──

    pub fn cpi_authority_for(&self, caller_program_id: &Pubkey) -> (Pubkey, u8) {
        Pubkey::find_program_address(&[b"__encrypt_cpi_authority"], caller_program_id)
    }

    pub fn send_transaction(&mut self, ixs: &[Instruction], extra_signers: &[&Keypair]) {
        let blockhash = self.harness.tx_builder().runtime().latest_blockhash();
        let payer = self.harness.payer();
        let mut signers: Vec<&Keypair> = vec![payer];
        signers.extend_from_slice(extra_signers);
        let tx = Transaction::new_signed_with_payer(
            ixs,
            Some(&payer.pubkey()),
            &signers,
            blockhash,
        );
        self.harness
            .tx_builder_mut()
            .runtime_mut()
            .send_transaction(&tx)
            .expect("send_transaction failed");
    }

    pub fn get_account_data(&self, pubkey: &Pubkey) -> Option<Vec<u8>> {
        self.harness
            .tx_builder()
            .runtime()
            .get_account_data(pubkey)
            .expect("get_account_data failed")
    }

    pub fn process_pending(&mut self) -> usize {
        self.harness.process_pending().expect("process_pending failed")
    }

    pub fn config_pda(&self) -> &Pubkey {
        self.harness.config_pda()
    }

    pub fn deposit_pda(&self) -> &Pubkey {
        self.harness.deposit_pda()
    }

    pub fn network_encryption_key_pda(&self) -> &Pubkey {
        self.harness.network_encryption_key_pda()
    }

    pub fn event_authority(&self) -> &Pubkey {
        self.harness.event_authority()
    }

    pub fn decrypt_from_store(&mut self, ciphertext_pubkey: &Pubkey) -> u128 {
        let digest = self
            .harness
            .store()
            .get_digest(&ciphertext_pubkey.to_bytes())
            .expect("ciphertext not in store");
        let fhe_type = self
            .harness
            .store()
            .get(&ciphertext_pubkey.to_bytes())
            .map(|e| e.fhe_type)
            .unwrap_or(encrypt_types::types::FheType::EUint64);
        let bytes = self
            .harness
            .engine_mut()
            .decrypt(&digest, fhe_type)
            .expect("decrypt failed");
        let mut buf = [0u8; 16];
        let len = bytes.len().min(16);
        buf[..len].copy_from_slice(&bytes[..len]);
        u128::from_le_bytes(buf)
    }

    pub fn enqueue_graph_execution(
        &mut self,
        graph_data: &[u8],
        input_pubkeys: &[Pubkey],
        output_pubkeys: &[Pubkey],
    ) {
        self.harness.enqueue_execution(
            graph_data.to_vec(),
            input_pubkeys.iter().map(|pk| pk.to_bytes()).collect(),
            output_pubkeys.iter().map(|pk| pk.to_bytes()).collect(),
        );
    }

    pub fn register_ciphertext(&mut self, pubkey: &Pubkey) {
        let data = self
            .get_account_data(pubkey)
            .expect("ciphertext account not found");
        if data.len() < 100 {
            panic!("account too small for ciphertext");
        }
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&data[2..34]);
        let fhe_type = FheType::from_u8(data[98]).expect("invalid fhe_type");
        self.harness
            .store()
            .put(pubkey.to_bytes(), digest, fhe_type, None);
    }
}
