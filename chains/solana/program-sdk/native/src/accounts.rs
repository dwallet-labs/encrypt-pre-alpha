// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Account readers for native Solana programs.

use encrypt_types::encrypted::EncryptedType;
use solana_program::program_error::ProgramError;

pub use encrypt_solana_types::accounts::DecryptionRequestStatus;

use encrypt_solana_types::accounts as shared;

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

pub fn decryption_status<'a, T: EncryptedType>(
    data: &'a [u8],
) -> Result<DecryptionRequestStatus<'a, T>, ProgramError> {
    shared::parse_decryption_status::<T>(data).ok_or(ProgramError::InvalidAccountData)
}

pub fn read_decrypted<'a, T: EncryptedType>(
    data: &'a [u8],
) -> Result<&'a T::DecryptedValue, ProgramError> {
    shared::parse_decrypted::<T>(data).ok_or(ProgramError::InvalidArgument)
}

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
