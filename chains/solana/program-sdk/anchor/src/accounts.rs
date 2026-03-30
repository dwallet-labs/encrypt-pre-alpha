// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Account readers for Anchor programs.

use anchor_lang::prelude::*;
use encrypt_types::encrypted::EncryptedType;

pub use encrypt_solana_types::accounts::DecryptionRequestStatus;

use encrypt_solana_types::accounts as shared;

pub fn read_decrypted<'a, T: EncryptedType>(
    data: &'a [u8],
) -> std::result::Result<&'a T::DecryptedValue, ProgramError> {
    shared::parse_decrypted::<T>(data).ok_or(ProgramError::InvalidArgument)
}

pub fn read_decrypted_verified<'a, T: EncryptedType>(
    request_data: &'a [u8],
    expected_digest: &[u8; 32],
) -> std::result::Result<&'a T::DecryptedValue, ProgramError> {
    shared::parse_decrypted_verified::<T>(request_data, expected_digest)
        .ok_or(ProgramError::InvalidArgument)
}

pub fn ciphertext_digest(data: &[u8]) -> std::result::Result<&[u8; 32], ProgramError> {
    shared::parse_ciphertext_digest(data).ok_or(ProgramError::InvalidAccountData)
}

pub fn decryption_status<'a, T: EncryptedType>(
    data: &'a [u8],
) -> std::result::Result<DecryptionRequestStatus<'a, T>, ProgramError> {
    shared::parse_decryption_status::<T>(data).ok_or(ProgramError::InvalidAccountData)
}
