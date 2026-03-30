// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! LiteSVM-based runtime — in-process, no networking.

use encrypt_dev::error::EncryptDevError;
use encrypt_dev::runtime::{InProcessTestRuntime, SolanaRuntime, TestRuntime};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::transaction::Transaction;

pub struct LiteSvmRuntime {
    svm: litesvm::LiteSVM,
}

impl LiteSvmRuntime {
    pub fn new() -> Self {
        Self {
            svm: litesvm::LiteSVM::new(),
        }
    }

    pub fn inner(&self) -> &litesvm::LiteSVM {
        &self.svm
    }

    pub fn inner_mut(&mut self) -> &mut litesvm::LiteSVM {
        &mut self.svm
    }

    fn to_address(pubkey: &Pubkey) -> solana_address::Address {
        solana_address::Address::new_from_array(pubkey.to_bytes())
    }
}

impl Default for LiteSvmRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl SolanaRuntime for LiteSvmRuntime {
    fn send_transaction(&mut self, tx: &Transaction) -> Result<(), EncryptDevError> {
        let tx_bytes = bincode::serialize(tx)
            .map_err(|e| EncryptDevError::Transaction(format!("serialize: {e}")))?;
        let versioned: solana_transaction::versioned::VersionedTransaction =
            bincode::deserialize(&tx_bytes)
                .map_err(|e| EncryptDevError::Transaction(format!("deserialize: {e}")))?;
        self.svm
            .send_transaction(versioned)
            .map_err(|e| EncryptDevError::Transaction(format!("{e:?}")))?;
        Ok(())
    }

    fn get_account_data(&self, pubkey: &Pubkey) -> Result<Option<Vec<u8>>, EncryptDevError> {
        let addr = Self::to_address(pubkey);
        Ok(self.svm.get_account(&addr).map(|a| a.data.to_vec()))
    }

    fn minimum_balance(&self, data_len: usize) -> u64 {
        self.svm.minimum_balance_for_rent_exemption(data_len)
    }

    fn latest_blockhash(&self) -> solana_sdk::hash::Hash {
        let hash = self.svm.latest_blockhash();
        solana_sdk::hash::Hash::new_from_array(hash.to_bytes())
    }
}

impl TestRuntime for LiteSvmRuntime {
    fn airdrop(&mut self, pubkey: &Pubkey, lamports: u64) -> Result<(), EncryptDevError> {
        let addr = Self::to_address(pubkey);
        self.svm
            .airdrop(&addr, lamports)
            .map_err(|e| EncryptDevError::Transaction(format!("airdrop: {e:?}")))?;
        Ok(())
    }

    fn deploy_program(
        &mut self,
        program_id: &Pubkey,
        elf_path: &str,
    ) -> Result<(), EncryptDevError> {
        let addr = Self::to_address(program_id);
        let _ = self.svm.add_program_from_file(&addr, elf_path);
        Ok(())
    }
}

impl InProcessTestRuntime for LiteSvmRuntime {
    fn advance_slot(&mut self) -> Result<(), EncryptDevError> {
        self.svm.expire_blockhash();
        Ok(())
    }

    fn set_account(
        &mut self,
        pubkey: &Pubkey,
        data: Vec<u8>,
        owner: &Pubkey,
        lamports: u64,
    ) -> Result<(), EncryptDevError> {
        let addr = Self::to_address(pubkey);
        let account = solana_account::Account {
            lamports,
            data,
            owner: solana_pubkey::Pubkey::new_from_array(owner.to_bytes()),
            executable: false,
            rent_epoch: 0,
        };
        let _ = self.svm.set_account(addr, account);
        Ok(())
    }
}
