// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Mock implementations of `Encryptor` and `Verifier` traits.
//!
//! Uses keccak256 for digests (same hash as `MockComputeEngine`).

use encrypt_types::encryptor::*;
use encrypt_types::types::FheType;

use crate::mock::{mock_digest, mock_digest_bytes};

/// Mock encryptor for local development.
///
/// "Encrypts" by encoding the plaintext, then hashing with keccak256.
/// The ciphertext bytes are `fhe_type(1) || value_le(byte_width)` — enough
/// for the mock verifier to reconstruct the digest.
/// Proof is empty.
pub struct MockEncryptor;

impl Encryptor for MockEncryptor {
    fn encrypt_and_prove(
        &self,
        inputs: &[PlaintextInput<'_>],
        _network_key: &[u8; 32],
        _chain: Chain,
    ) -> EncryptResult {
        let ciphertexts = inputs
            .iter()
            .map(|input| {
                let fhe_type = FheType::from_u8(input.fhe_type as u8)
                    .unwrap_or(FheType::EUint64);
                let byte_width = fhe_type.byte_width();
                // Ciphertext = fhe_type(1) || plaintext_le(byte_width)
                let mut ct = Vec::with_capacity(1 + byte_width);
                ct.push(input.fhe_type as u8);
                let mut buf = vec![0u8; byte_width];
                let len = input.plaintext_bytes.len().min(byte_width);
                buf[..len].copy_from_slice(&input.plaintext_bytes[..len]);
                ct.extend_from_slice(&buf);
                ct
            })
            .collect();

        EncryptResult {
            ciphertexts,
            proof: Vec::new(),
        }
    }
}

/// Mock verifier for local development.
///
/// Accepts any proof. Extracts `fhe_type` and value from the mock ciphertext
/// format, then computes keccak256 digest.
pub struct MockVerifier;

#[derive(Debug)]
pub enum MockVerifyError {}

impl core::fmt::Display for MockVerifyError {
    fn fmt(&self, _f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        Ok(())
    }
}

impl std::error::Error for MockVerifyError {}

impl Verifier for MockVerifier {
    type Error = MockVerifyError;

    fn verify(
        &self,
        inputs: &[CiphertextInput<'_>],
        _proof: &[u8],
        _network_key: &[u8; 32],
        _chain: Chain,
    ) -> Result<VerifyResult, Self::Error> {
        let digests = inputs
            .iter()
            .map(|input| {
                let fhe_type_byte = input.ciphertext_bytes.first().copied().unwrap_or(0);
                let fhe_type = FheType::from_u8(fhe_type_byte)
                    .unwrap_or(input.fhe_type);
                let expected_len = 1 + fhe_type.byte_width();

                if input.ciphertext_bytes.len() == expected_len {
                    // Variable-length format: fhe_type(1) || value_le(byte_width)
                    let value_bytes = &input.ciphertext_bytes[1..];
                    mock_digest_bytes(fhe_type, value_bytes)
                } else if input.ciphertext_bytes.len() == 17 {
                    // Legacy 17-byte format: fhe_type(1) || value_le(16)
                    let value = u128::from_le_bytes(
                        input.ciphertext_bytes[1..17].try_into().unwrap(),
                    );
                    mock_digest(fhe_type, value)
                } else {
                    // Fallback: interpret raw bytes as value
                    mock_digest_bytes(input.fhe_type, input.ciphertext_bytes)
                }
            })
            .collect();

        Ok(VerifyResult { digests })
    }
}
