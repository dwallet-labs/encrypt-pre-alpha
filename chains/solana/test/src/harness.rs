// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! `EncryptTestHarness` — test harness wrapping `EncryptTxBuilder` with mock compute.
//!
//! Adds `MockComputeEngine`, `InMemoryCiphertextStore`, and `WorkQueue` on top of
//! the production-safe tx builder. Requires `InProcessTestRuntime` for test setup
//! (inject accounts, advance slots).

use std::sync::Arc;

use encrypt_compute::engine::ComputeEngine;
use encrypt_compute::evaluator::evaluate_graph;
use encrypt_compute::mock::MockComputeEngine;
use encrypt_dev::error::EncryptDevError;
use encrypt_dev::runtime::InProcessTestRuntime;
use encrypt_dev::tx_builder::{EncryptTxBuilder, EncryptTxConfig, ENCRYPT_PROGRAM_ID};
use encrypt_service::pipeline::{PendingDecryption, PendingGraphExecution, WorkQueue};
use encrypt_service::store::{CiphertextStore, InMemoryCiphertextStore};
use encrypt_types::types::FheType;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Keypair;
use solana_sdk::signer::Signer;

/// Configuration for the test harness.
pub struct EncryptTestConfig {
    pub program_elf_path: String,
}

impl EncryptTestConfig {
    pub fn default_paths() -> Self {
        Self {
            program_elf_path: concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../../bin/encrypt_program.so"
            )
            .to_string(),
        }
    }
}

/// Test harness wrapping `EncryptTxBuilder` with mock executor + decryptor.
pub struct EncryptTestHarness<R: InProcessTestRuntime> {
    tx_builder: EncryptTxBuilder<R>,
    store: Arc<InMemoryCiphertextStore>,
    work_queue: WorkQueue,
    engine: MockComputeEngine,
}

impl<R: InProcessTestRuntime> EncryptTestHarness<R> {
    /// Create a new test harness.
    ///
    /// Deploys the Encrypt program, initializes config, injects deposit + network key.
    pub fn new(mut runtime: R, config: EncryptTestConfig) -> Result<Self, EncryptDevError> {
        let program_id: Pubkey = ENCRYPT_PROGRAM_ID
            .parse()
            .expect("invalid encrypt program id");
        let authority = Keypair::new();
        let payer = Keypair::new();

        // Fund payer (TestRuntime)
        runtime.airdrop(&payer.pubkey(), 100_000_000_000)?;

        // Deploy program (TestRuntime)
        runtime.deploy_program(&program_id, &config.program_elf_path)?;

        // Derive PDAs
        let (config_pda, config_bump) =
            Pubkey::find_program_address(&[b"encrypt_config"], &program_id);
        let (authority_pda, authority_bump) =
            Pubkey::find_program_address(&[b"authority", authority.pubkey().as_ref()], &program_id);
        let (event_authority, _) =
            Pubkey::find_program_address(&[b"__event_authority"], &program_id);
        let (deposit_pda, deposit_bump) =
            Pubkey::find_program_address(&[b"encrypt_deposit", payer.pubkey().as_ref()], &program_id);
        let network_public_key = [0x55u8; 32];
        let (network_encryption_key_pda, nk_bump) = Pubkey::find_program_address(
            &[b"network_encryption_key", &network_public_key],
            &program_id,
        );

        // Build tx builder
        let tx_config = EncryptTxConfig {
            program_id,
            authority,
            authority_pda,
            config_pda,
            deposit_pda,
            network_encryption_key_pda,
            event_authority,
            payer,
        };
        let mut tx_builder = EncryptTxBuilder::new(runtime, tx_config);

        // Initialize program
        // Use payer as dummy enc_vault for test mode
        let payer_pk = tx_builder.payer().pubkey();
        tx_builder.initialize(config_bump, authority_bump, &payer_pk)?;

        // Inject deposit account with high balances (InProcessTestRuntime)
        // Extract values before mutable borrow
        let payer_bytes: [u8; 32] = tx_builder.payer().pubkey().to_bytes();
        let deposit_key = *tx_builder.deposit_pda();
        let nk_key = *tx_builder.network_encryption_key_pda();
        let pid = *tx_builder.program_id();

        let mut deposit_data = vec![0u8; 83];
        deposit_data[0] = 4; // DISC_DEPOSIT
        deposit_data[1] = 1; // VERSION
        deposit_data[2..34].copy_from_slice(&payer_bytes);
        deposit_data[34..42].copy_from_slice(&1_000_000_000u64.to_le_bytes());
        deposit_data[42..50].copy_from_slice(&1_000_000_000u64.to_le_bytes());
        deposit_data[82] = deposit_bump;
        let min_balance = tx_builder.runtime().minimum_balance(83);
        tx_builder.runtime_mut().set_account(
            &deposit_key, deposit_data, &pid, min_balance,
        )?;

        // Inject network encryption key account (active)
        let mut nk_data = vec![0u8; 36];
        nk_data[0] = 7; // DISC_NETWORK_ENCRYPTION_KEY
        nk_data[1] = 1; // VERSION
        nk_data[2..34].copy_from_slice(&network_public_key);
        nk_data[34] = 1; // active
        nk_data[35] = nk_bump;
        let min_balance = tx_builder.runtime().minimum_balance(36);
        tx_builder.runtime_mut().set_account(
            &nk_key, nk_data, &pid, min_balance,
        )?;

        Ok(Self {
            tx_builder,
            store: Arc::new(InMemoryCiphertextStore::new()),
            work_queue: WorkQueue::new(),
            engine: MockComputeEngine::new(),
        })
    }

    // ── High-level typed operations ──

    /// Create a verified encrypted input (computes mock digest internally).
    pub fn create_input_ciphertext(
        &mut self,
        fhe_type: FheType,
        plaintext_value: u128,
        authorized: &Pubkey,
    ) -> Result<Pubkey, EncryptDevError> {
        let digest = self
            .engine
            .encode_constant(fhe_type, plaintext_value)
            .map_err(|e| EncryptDevError::GraphEval(format!("{e:?}")))?;

        let ct_pubkey = self
            .tx_builder
            .create_input_ciphertext(fhe_type as u8, &digest, authorized)?;

        self.store
            .put(ct_pubkey.to_bytes(), digest, fhe_type, None);
        Ok(ct_pubkey)
    }

    /// Create a plaintext ciphertext (computes mock digest internally).
    pub fn create_plaintext_ciphertext(
        &mut self,
        fhe_type: FheType,
        plaintext_bytes: &[u8],
        creator: &Keypair,
    ) -> Result<Pubkey, EncryptDevError> {
        let ct_pubkey = self
            .tx_builder
            .create_plaintext_ciphertext(fhe_type as u8, plaintext_bytes, creator)?;

        let mut value_buf = [0u8; 16];
        let copy_len = plaintext_bytes.len().min(16);
        value_buf[..copy_len].copy_from_slice(&plaintext_bytes[..copy_len]);
        let value = u128::from_le_bytes(value_buf);
        let digest = self
            .engine
            .encode_constant(fhe_type, value)
            .map_err(|e| EncryptDevError::GraphEval(format!("{e:?}")))?;
        self.store
            .put(ct_pubkey.to_bytes(), digest, fhe_type, None);

        Ok(ct_pubkey)
    }

    /// Execute a computation graph and enqueue for processing.
    pub fn execute_graph(
        &mut self,
        graph_data: &[u8],
        input_pubkeys: &[Pubkey],
        num_new_outputs: usize,
        existing_output_pubkeys: &[Pubkey],
        caller: &Keypair,
    ) -> Result<Vec<Pubkey>, EncryptDevError> {
        let all_output_pubkeys = self.tx_builder.execute_graph(
            graph_data,
            input_pubkeys,
            num_new_outputs,
            existing_output_pubkeys,
            caller,
        )?;

        self.work_queue
            .enqueue_execution(PendingGraphExecution {
                source_chain: encrypt_service::requests::SourceChain::Solana,
                graph_data: graph_data.to_vec(),
                input_ids: input_pubkeys.iter().map(|pk| pk.to_bytes()).collect(),
                output_ids: all_output_pubkeys.iter().map(|pk| pk.to_bytes()).collect(),
            });

        Ok(all_output_pubkeys)
    }

    /// Request decryption and enqueue for processing.
    pub fn request_decryption(
        &mut self,
        ciphertext_pubkey: &Pubkey,
        requester: &Keypair,
    ) -> Result<Pubkey, EncryptDevError> {
        let entry = self
            .store
            .get(&ciphertext_pubkey.to_bytes())
            .ok_or(EncryptDevError::CiphertextNotFound(ciphertext_pubkey.to_bytes()))?;
        let byte_width = entry.fhe_type.byte_width();

        let req_pubkey = self
            .tx_builder
            .request_decryption(ciphertext_pubkey, byte_width, requester)?;

        self.work_queue
            .enqueue_decryption(PendingDecryption {
                source_chain: encrypt_service::requests::SourceChain::Solana,
                request_id: req_pubkey.to_bytes(),
                ciphertext_id: ciphertext_pubkey.to_bytes(),
                fhe_type: entry.fhe_type,
            });

        Ok(req_pubkey)
    }

    /// Process all pending graph executions and decryption requests.
    pub fn process_pending(&mut self) -> Result<usize, EncryptDevError> {
        self.tx_builder.runtime_mut().advance_slot()?;
        let (executions, decryptions) = self.work_queue.drain();
        let mut processed = 0;

        for exec in &executions {
            let mut input_digests = Vec::with_capacity(exec.input_ids.len());
            for pk in &exec.input_ids {
                let digest = self
                    .store
                    .get_digest(pk)
                    .ok_or(EncryptDevError::CiphertextNotFound(*pk))?;
                input_digests.push(digest);
            }

            let result = evaluate_graph(&mut self.engine, &exec.graph_data, &input_digests)
                .map_err(|e| EncryptDevError::GraphEval(format!("{e}")))?;

            for (i, output_pk) in exec.output_ids.iter().enumerate() {
                if i >= result.output_digests.len() {
                    break;
                }
                let new_digest = result.output_digests[i];
                // Read current on-chain digest as previous_digest for verification
                let previous_digest = self
                    .tx_builder
                    .runtime()
                    .get_account_data(&solana_sdk::pubkey::Pubkey::from(*output_pk))
                    .ok()
                    .flatten()
                    .and_then(|data| {
                        if data.len() >= 34 {
                            let mut d = [0u8; 32];
                            d.copy_from_slice(&data[2..34]);
                            Some(d)
                        } else {
                            None
                        }
                    })
                    .unwrap_or([0u8; 32]);
                self.tx_builder
                    .commit_ciphertext(output_pk, &previous_digest, &new_digest)?;

                let fhe_type = self
                    .store
                    .get(output_pk)
                    .map(|e| e.fhe_type)
                    .unwrap_or(FheType::EUint64);
                self.store.put(*output_pk, new_digest, fhe_type, None);
            }
            processed += 1;
        }

        for decrypt in &decryptions {
            let digest = self
                .store
                .get_digest(&decrypt.ciphertext_id)
                .ok_or(EncryptDevError::CiphertextNotFound(decrypt.ciphertext_id))?;

            let plaintext = self
                .engine
                .decrypt(&digest, decrypt.fhe_type)
                .map_err(|e| EncryptDevError::DecryptionFailed(format!("{e:?}")))?;

            self.tx_builder
                .respond_decryption(&decrypt.request_id, &plaintext)?;
            processed += 1;
        }

        Ok(processed)
    }

    /// Execute graph AND process pending in one call.
    pub fn execute_and_commit(
        &mut self,
        graph_data: &[u8],
        input_pubkeys: &[Pubkey],
        num_new_outputs: usize,
        existing_output_pubkeys: &[Pubkey],
        caller: &Keypair,
    ) -> Result<Vec<Pubkey>, EncryptDevError> {
        let outputs = self.execute_graph(
            graph_data, input_pubkeys, num_new_outputs, existing_output_pubkeys, caller,
        )?;
        self.process_pending()?;
        Ok(outputs)
    }

    /// Request decryption AND process pending in one call.
    pub fn decrypt_and_respond(
        &mut self,
        ciphertext_pubkey: &Pubkey,
        requester: &Keypair,
    ) -> Result<(Pubkey, Vec<u8>), EncryptDevError> {
        let entry = self
            .store
            .get(&ciphertext_pubkey.to_bytes())
            .ok_or(EncryptDevError::CiphertextNotFound(ciphertext_pubkey.to_bytes()))?;

        let req_pubkey = self.request_decryption(ciphertext_pubkey, requester)?;
        self.process_pending()?;

        let plaintext = self
            .engine
            .decrypt(&entry.digest, entry.fhe_type)
            .map_err(|e| EncryptDevError::DecryptionFailed(format!("{e:?}")))?;

        Ok((req_pubkey, plaintext))
    }

    /// Enqueue an external graph execution (e.g., from CPI).
    pub fn enqueue_execution(
        &mut self,
        graph_data: Vec<u8>,
        input_ids: Vec<[u8; 32]>,
        output_ids: Vec<[u8; 32]>,
    ) {
        self.work_queue
            .enqueue_execution(PendingGraphExecution {
                source_chain: encrypt_service::requests::SourceChain::Solana,
                graph_data,
                input_ids,
                output_ids,
            });
    }

    // ── Accessors ──

    pub fn store(&self) -> &InMemoryCiphertextStore {
        &self.store
    }

    pub fn engine_mut(&mut self) -> &mut MockComputeEngine {
        &mut self.engine
    }

    pub fn tx_builder(&self) -> &EncryptTxBuilder<R> {
        &self.tx_builder
    }

    pub fn tx_builder_mut(&mut self) -> &mut EncryptTxBuilder<R> {
        &mut self.tx_builder
    }

    pub fn program_id(&self) -> &Pubkey {
        self.tx_builder.program_id()
    }

    pub fn payer(&self) -> &Keypair {
        self.tx_builder.payer()
    }

    pub fn config_pda(&self) -> &Pubkey {
        self.tx_builder.config_pda()
    }

    pub fn deposit_pda(&self) -> &Pubkey {
        self.tx_builder.deposit_pda()
    }

    pub fn network_encryption_key_pda(&self) -> &Pubkey {
        self.tx_builder.network_encryption_key_pda()
    }

    pub fn event_authority(&self) -> &Pubkey {
        self.tx_builder.event_authority()
    }
}
