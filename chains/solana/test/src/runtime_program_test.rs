// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! `solana-program-test` runtime — in-process, uses the official Solana runtime.

use encrypt_dev::error::EncryptDevError;
use encrypt_dev::runtime::{InProcessTestRuntime, SolanaRuntime, TestRuntime};
use solana_program_test::{ProgramTest, ProgramTestContext};
use solana_sdk::hash::Hash;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Keypair;
use solana_sdk::signer::Signer;
use solana_sdk::transaction::Transaction;
use tokio::runtime::Runtime;

/// solana-program-test runtime.
pub struct ProgramTestRuntime {
    ctx: ProgramTestContext,
    payer_copy: Keypair,
    rt: Runtime,
}

impl ProgramTestRuntime {
    /// Create a new runtime with programs pre-loaded from `target/deploy/`.
    pub fn new(programs: Vec<(String, Pubkey)>) -> Self {
        let rt = Runtime::new().expect("failed to create tokio runtime");
        let mut pt = ProgramTest::default();
        for (name, id) in programs {
            // Leak the name so ProgramTest can borrow it for 'static (test-only, acceptable)
            let name: &'static str = Box::leak(name.into_boxed_str());
            pt.add_program(name, id, None);
        }
        let ctx = rt.block_on(pt.start_with_context());
        // Copy payer keypair bytes
        let payer_bytes = ctx.payer.to_bytes();
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&payer_bytes[..32]);
        let payer_copy = Keypair::new_from_array(secret);
        Self { ctx, payer_copy, rt }
    }

    pub fn genesis_payer(&self) -> &Keypair {
        &self.payer_copy
    }

    /// Convert solana-sdk Transaction to the format expected by BanksClient.
    fn convert_transaction(
        tx: &Transaction,
    ) -> Result<solana_transaction::versioned::VersionedTransaction, EncryptDevError> {
        let tx_bytes = bincode::serialize(tx)
            .map_err(|e| EncryptDevError::Transaction(format!("serialize: {e}")))?;
        bincode::deserialize(&tx_bytes)
            .map_err(|e| EncryptDevError::Transaction(format!("deserialize: {e}")))
    }
}

impl SolanaRuntime for ProgramTestRuntime {
    fn send_transaction(&mut self, tx: &Transaction) -> Result<(), EncryptDevError> {
        let versioned = Self::convert_transaction(tx)?;
        self.rt
            .block_on(self.ctx.banks_client.process_transaction(versioned))
            .map_err(|e| EncryptDevError::Transaction(format!("{e:?}")))?;
        self.ctx.last_blockhash = self
            .rt
            .block_on(self.ctx.banks_client.get_latest_blockhash())
            .unwrap_or(self.ctx.last_blockhash);
        Ok(())
    }

    fn get_account_data(&self, pubkey: &Pubkey) -> Result<Option<Vec<u8>>, EncryptDevError> {
        let account = self
            .rt
            .block_on(self.ctx.banks_client.get_account(*pubkey))
            .map_err(|e| EncryptDevError::AccountNotFound(format!("{e:?}")))?;
        Ok(account.map(|a| a.data))
    }

    fn minimum_balance(&self, data_len: usize) -> u64 {
        let rent = self
            .rt
            .block_on(self.ctx.banks_client.get_rent())
            .expect("failed to get rent");
        rent.minimum_balance(data_len)
    }

    fn latest_blockhash(&self) -> Hash {
        self.ctx.last_blockhash
    }
}

impl TestRuntime for ProgramTestRuntime {
    fn airdrop(&mut self, pubkey: &Pubkey, lamports: u64) -> Result<(), EncryptDevError> {
        let ix = solana_system_interface::instruction::transfer(
            &self.payer_copy.pubkey(),
            pubkey,
            lamports,
        );
        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&self.payer_copy.pubkey()),
            &[&self.payer_copy],
            self.ctx.last_blockhash,
        );
        self.send_transaction(&tx)
    }

    fn deploy_program(
        &mut self,
        _program_id: &Pubkey,
        _elf_path: &str,
    ) -> Result<(), EncryptDevError> {
        // Programs pre-loaded via ProgramTest::add_program. No-op.
        Ok(())
    }
}

impl InProcessTestRuntime for ProgramTestRuntime {
    fn advance_slot(&mut self) -> Result<(), EncryptDevError> {
        self.ctx.last_blockhash = self
            .rt
            .block_on(self.ctx.banks_client.get_latest_blockhash())
            .map_err(|e| EncryptDevError::Transaction(format!("advance: {e:?}")))?;
        Ok(())
    }

    fn set_account(
        &mut self,
        pubkey: &Pubkey,
        data: Vec<u8>,
        owner: &Pubkey,
        lamports: u64,
    ) -> Result<(), EncryptDevError> {
        let account = solana_account::AccountSharedData::from(solana_account::Account {
            lamports,
            data,
            owner: solana_pubkey::Pubkey::new_from_array(owner.to_bytes()),
            executable: false,
            rent_epoch: 0,
        });
        self.ctx.set_account(pubkey, &account);
        Ok(())
    }
}
