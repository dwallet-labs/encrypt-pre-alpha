// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Zero-copy account readers for Pinocchio developer programs.
//!
//! Thin wrappers around `encrypt_solana_types::accounts` that convert
//! `Option` → `Result<_, ProgramError>`.

use encrypt_types::encrypted::EncryptedType;
use pinocchio::error::ProgramError;

// Re-export the shared enum so callers don't need to import encrypt_solana_types directly.
pub use encrypt_solana_types::accounts::DecryptionRequestStatus;

use encrypt_solana_types::accounts as shared;

// ── Ciphertext readers ──

pub fn ciphertext_authorized(data: &[u8]) -> Result<&[u8; 32], ProgramError> {
    shared::parse_ciphertext_authorized(data).ok_or(ProgramError::InvalidAccountData)
}

pub fn ciphertext_digest(data: &[u8]) -> Result<&[u8; 32], ProgramError> {
    shared::parse_ciphertext_digest(data).ok_or(ProgramError::InvalidAccountData)
}

pub fn ciphertext_status(data: &[u8]) -> Result<u8, ProgramError> {
    shared::parse_ciphertext_status(data).ok_or(ProgramError::InvalidAccountData)
}

pub fn ciphertext_is_public(data: &[u8]) -> Result<bool, ProgramError> {
    shared::parse_ciphertext_is_public(data).ok_or(ProgramError::InvalidAccountData)
}

// ── Decryption request readers ──

/// Read the typed status of a decryption request.
pub fn decryption_status<'a, T: EncryptedType>(
    data: &'a [u8],
) -> Result<DecryptionRequestStatus<'a, T>, ProgramError> {
    shared::parse_decryption_status::<T>(data).ok_or(ProgramError::InvalidAccountData)
}

/// Read the decrypted value, only if complete.
pub fn read_decrypted<'a, T: EncryptedType>(
    data: &'a [u8],
) -> Result<&'a T::DecryptedValue, ProgramError> {
    shared::parse_decrypted::<T>(data).ok_or(ProgramError::InvalidArgument)
}

/// Read the decrypted value, verifying the request's digest matches the expected digest.
///
/// Use `ciphertext_digest(ct_data)?` to extract the digest from a ciphertext account.
pub fn read_decrypted_verified<'a, T: EncryptedType>(
    request_data: &'a [u8],
    expected_digest: &[u8; 32],
) -> Result<&'a T::DecryptedValue, ProgramError> {
    shared::parse_decrypted_verified::<T>(request_data, expected_digest)
        .ok_or(ProgramError::InvalidArgument)
}

pub fn decryption_requester(data: &[u8]) -> Result<&[u8; 32], ProgramError> {
    shared::parse_decryption_requester(data).ok_or(ProgramError::InvalidAccountData)
}

pub fn decryption_ciphertext(data: &[u8]) -> Result<&[u8; 32], ProgramError> {
    shared::parse_decryption_ciphertext(data).ok_or(ProgramError::InvalidAccountData)
}
