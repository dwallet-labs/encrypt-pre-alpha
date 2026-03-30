// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Runtime trait hierarchy for Solana execution environments.
//!
//! Three levels:
//! - `SolanaRuntime` — production (mainnet, devnet, any network)
//! - `TestRuntime` — dev/test only (adds airdrop, deploy)
//! - `InProcessTestRuntime` — in-process runtimes only (adds set_account, advance_slot)

use solana_sdk::pubkey::Pubkey;
use solana_sdk::transaction::Transaction;

use crate::error::EncryptDevError;

/// Production runtime — only what a real executor/decryptor needs.
///
/// Implementations:
/// - `RpcRuntime` (in `encrypt-cli-solana`): connects via RPC
pub trait SolanaRuntime {
    /// Send and confirm a transaction.
    fn send_transaction(&mut self, tx: &Transaction) -> Result<(), EncryptDevError>;

    /// Read raw account data. Returns None if account doesn't exist.
    fn get_account_data(&self, pubkey: &Pubkey) -> Result<Option<Vec<u8>>, EncryptDevError>;

    /// Get minimum balance for rent exemption.
    fn minimum_balance(&self, data_len: usize) -> u64;

    /// Get the latest blockhash for transaction construction.
    fn latest_blockhash(&self) -> solana_sdk::hash::Hash;
}

/// Dev/test runtime — adds operations only available on local/devnet/testnet.
///
/// Not available on mainnet.
pub trait TestRuntime: SolanaRuntime {
    /// Airdrop SOL to an address (local validator, devnet, testnet only).
    fn airdrop(&mut self, pubkey: &Pubkey, lamports: u64) -> Result<(), EncryptDevError>;

    /// Deploy a program from an ELF file path.
    fn deploy_program(
        &mut self,
        program_id: &Pubkey,
        elf_path: &str,
    ) -> Result<(), EncryptDevError>;
}

/// In-process test runtime — direct state manipulation.
///
/// Only for runtimes where we control the execution environment directly
/// (LiteSVM, solana-program-test). Not available via RPC.
pub trait InProcessTestRuntime: TestRuntime {
    /// Advance the slot to get a fresh blockhash.
    fn advance_slot(&mut self) -> Result<(), EncryptDevError>;

    /// Set raw account data directly.
    fn set_account(
        &mut self,
        pubkey: &Pubkey,
        data: Vec<u8>,
        owner: &Pubkey,
        lamports: u64,
    ) -> Result<(), EncryptDevError>;
}
