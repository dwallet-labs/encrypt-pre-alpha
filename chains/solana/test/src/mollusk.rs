// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Mollusk test helpers for single-instruction testing.
//!
//! Provides account data builders, discriminator constants, and setup helpers
//! for testing individual Encrypt program instructions in isolation.
//!
//! # Example
//!
//! ```ignore
//! use encrypt_solana_test::mollusk::*;
//! use solana_instruction::{AccountMeta, Instruction};
//!
//! let (mollusk, program_id) = setup();
//! let ct_data = build_ciphertext_data(&digest, &authorized, &nk, 4, 1);
//!
//! let result = mollusk.process_instruction(
//!     &Instruction::new_with_bytes(program_id, &ix_data, accounts),
//!     &[(key, program_account(&program_id, ct_data))],
//! );
//! assert!(!result.program_result.is_err());
//! ```

pub use mollusk_svm::Mollusk;
pub use solana_account::Account;
pub use solana_pubkey::Pubkey;

// ── Program constants ──

/// Default program ELF path (relative to test crate's CARGO_MANIFEST_DIR).
pub const DEFAULT_PROGRAM_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../bin/encrypt_program"
);

pub const SYSTEM_PROGRAM: Pubkey = Pubkey::new_from_array([0u8; 32]);

// ── Account discriminators ──

pub const DISC_CONFIG: u8 = 1;
pub const DISC_AUTHORITY: u8 = 2;
pub const DISC_DECRYPTION_REQUEST: u8 = 3;
pub const DISC_DEPOSIT: u8 = 4;
pub const DISC_REGISTERED_GRAPH: u8 = 5;
pub const DISC_CIPHERTEXT: u8 = 6;
pub const DISC_NETWORK_ENCRYPTION_KEY: u8 = 7;

// ── Instruction discriminators ──

pub const IX_INITIALIZE: u8 = 0;
pub const IX_CREATE_INPUT_CIPHERTEXT: u8 = 1;
pub const IX_CREATE_PLAINTEXT_CIPHERTEXT: u8 = 2;
pub const IX_COMMIT_CIPHERTEXT: u8 = 3;
pub const IX_EXECUTE_GRAPH: u8 = 4;
pub const IX_REGISTER_GRAPH: u8 = 5;
pub const IX_EXECUTE_REGISTERED_GRAPH: u8 = 6;
pub const IX_TRANSFER_CIPHERTEXT: u8 = 7;
pub const IX_COPY_CIPHERTEXT: u8 = 8;
pub const IX_CLOSE_CIPHERTEXT: u8 = 9;
pub const IX_MAKE_PUBLIC: u8 = 10;
pub const IX_REQUEST_DECRYPTION: u8 = 11;
pub const IX_RESPOND_DECRYPTION: u8 = 12;
pub const IX_CLOSE_DECRYPTION_REQUEST: u8 = 13;
pub const IX_CREATE_DEPOSIT: u8 = 14;
pub const IX_TOP_UP: u8 = 15;
pub const IX_WITHDRAW: u8 = 16;
pub const IX_UPDATE_CONFIG_FEES: u8 = 17;
pub const IX_REIMBURSE: u8 = 18;
pub const IX_REQUEST_WITHDRAW: u8 = 19;
pub const IX_ADD_AUTHORITY: u8 = 20;
pub const IX_REMOVE_AUTHORITY: u8 = 21;
pub const IX_REGISTER_NETWORK_ENCRYPTION_KEY: u8 = 22;
pub const IX_EMIT_EVENT: u8 = 228;

pub const VERSION: u8 = 1;

// ── Setup ──

/// Create a Mollusk instance with the Encrypt program loaded.
pub fn setup() -> (Mollusk, Pubkey) {
    setup_with_path(DEFAULT_PROGRAM_PATH)
}

/// Create a Mollusk instance with a custom program path.
pub fn setup_with_path(program_path: &str) -> (Mollusk, Pubkey) {
    let program_id = Pubkey::new_from_array(
        solana_pubkey::pubkey!("Cq37zHSH1zB6xomYK2LjP6uXJvLR3uTehxA5W9wgHGvx").to_bytes(),
    );
    let mollusk = Mollusk::new(&program_id, program_path);
    (mollusk, program_id)
}

/// Derive event authority PDA.
pub fn event_authority_pda(program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"__event_authority"], program_id)
}

// ── Account factories ──

/// Account with 10 SOL, no data.
pub fn funded_account() -> Account {
    Account {
        lamports: 10_000_000_000,
        data: vec![],
        owner: SYSTEM_PROGRAM,
        executable: false,
        rent_epoch: 0,
    }
}

/// Account owned by the given program with data.
pub fn program_account(owner: &Pubkey, data: Vec<u8>) -> Account {
    Account {
        lamports: 1_000_000,
        data,
        owner: *owner,
        executable: false,
        rent_epoch: 0,
    }
}

/// Account with custom lamports.
pub fn program_account_with_lamports(owner: &Pubkey, data: Vec<u8>, lamports: u64) -> Account {
    Account {
        lamports,
        data,
        owner: *owner,
        executable: false,
        rent_epoch: 0,
    }
}

// ── Account data builders ──

pub fn build_authority_data(pubkey: &Pubkey, active: bool, bump: u8) -> Vec<u8> {
    let mut data = vec![0u8; 36];
    data[0] = DISC_AUTHORITY;
    data[1] = VERSION;
    data[2..34].copy_from_slice(pubkey.as_ref());
    data[34] = active as u8;
    data[35] = bump;
    data
}

pub fn build_config_data(
    current_epoch: u64,
    enc_per_input: u64,
    enc_per_output: u64,
    max_enc_per_op: u64,
    gas_base: u64,
    gas_per_input: u64,
    gas_per_output: u64,
    gas_per_byte: u64,
    enc_mint: &[u8; 32],
    enc_vault: &[u8; 32],
    bump: u8,
) -> Vec<u8> {
    let mut data = vec![0u8; 133];
    data[0] = DISC_CONFIG;
    data[1] = VERSION;
    data[2..10].copy_from_slice(&current_epoch.to_le_bytes());
    data[10..18].copy_from_slice(&enc_per_input.to_le_bytes());
    data[18..26].copy_from_slice(&enc_per_output.to_le_bytes());
    data[26..34].copy_from_slice(&max_enc_per_op.to_le_bytes());
    data[34..36].copy_from_slice(&100u16.to_le_bytes());
    data[36..44].copy_from_slice(&gas_base.to_le_bytes());
    data[44..52].copy_from_slice(&gas_per_input.to_le_bytes());
    data[52..60].copy_from_slice(&gas_per_output.to_le_bytes());
    data[60..68].copy_from_slice(&gas_per_byte.to_le_bytes());
    data[68..100].copy_from_slice(enc_mint);
    data[100..132].copy_from_slice(enc_vault);
    data[132] = bump;
    data
}

pub fn build_default_config(enc_vault: &[u8; 32]) -> Vec<u8> {
    build_config_data(1, 100, 200, 500, 50, 10, 20, 5, &[0u8; 32], enc_vault, 0)
}

pub fn build_network_encryption_key_data(public_key: &[u8; 32], active: bool, bump: u8) -> Vec<u8> {
    let mut data = vec![0u8; 36];
    data[0] = DISC_NETWORK_ENCRYPTION_KEY;
    data[1] = VERSION;
    data[2..34].copy_from_slice(public_key);
    data[34] = active as u8;
    data[35] = bump;
    data
}

pub fn build_deposit_data(
    owner: &Pubkey,
    enc_balance: u64,
    gas_balance: u64,
    pending_enc: u64,
    pending_gas: u64,
    withdrawal_epoch: u64,
    num_txs: u64,
    bump: u8,
) -> Vec<u8> {
    let mut data = vec![0u8; 83];
    data[0] = DISC_DEPOSIT;
    data[1] = VERSION;
    data[2..34].copy_from_slice(owner.as_ref());
    data[34..42].copy_from_slice(&enc_balance.to_le_bytes());
    data[42..50].copy_from_slice(&gas_balance.to_le_bytes());
    data[50..58].copy_from_slice(&pending_enc.to_le_bytes());
    data[58..66].copy_from_slice(&pending_gas.to_le_bytes());
    data[66..74].copy_from_slice(&withdrawal_epoch.to_le_bytes());
    data[74..82].copy_from_slice(&num_txs.to_le_bytes());
    data[82] = bump;
    data
}

pub fn build_ciphertext_data(
    ciphertext_digest: &[u8; 32],
    authorized: &Pubkey,
    network_public_key: &[u8; 32],
    fhe_type: u8,
    status: u8,
) -> Vec<u8> {
    let mut data = vec![0u8; 100];
    data[0] = DISC_CIPHERTEXT;
    data[1] = VERSION;
    data[2..34].copy_from_slice(ciphertext_digest);
    data[34..66].copy_from_slice(authorized.as_ref());
    data[66..98].copy_from_slice(network_public_key);
    data[98] = fhe_type;
    data[99] = status;
    data
}

pub fn build_decryption_request_data(
    ciphertext: &[u8; 32],
    ciphertext_digest: &[u8; 32],
    requester: &Pubkey,
    fhe_type: u8,
    total_len: u32,
    bytes_written: u32,
) -> Vec<u8> {
    let mut data = vec![0u8; 107 + total_len as usize];
    data[0] = DISC_DECRYPTION_REQUEST;
    data[1] = VERSION;
    data[2..34].copy_from_slice(ciphertext);
    data[34..66].copy_from_slice(ciphertext_digest);
    data[66..98].copy_from_slice(requester.as_ref());
    data[98] = fhe_type;
    data[99..103].copy_from_slice(&total_len.to_le_bytes());
    data[103..107].copy_from_slice(&bytes_written.to_le_bytes());
    data
}

// ── Data readers ──

pub fn read_u64(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap())
}

pub fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}
