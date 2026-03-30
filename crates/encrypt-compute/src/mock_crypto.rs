// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Mock implementations of `Encryptor` and `Verifier` traits.
//!
//! Uses keccak256 for digests (same hash as `MockComputeEngine`).

use encrypt_types::encryptor::*;
use encrypt_types::types::FheType;

use crate::mock::mock_digest;

/// Mock encryptor for local development.
///
/// "Encrypts" by encoding the plaintext as u128 LE, then hashing with keccak256.
/// The ciphertext bytes are `fhe_type(1) || value_le(16)` — enough for the
/// mock verifier to reconstruct the digest.
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
                // Ciphertext = fhe_type(1) || plaintext_le(16)
                let mut ct = Vec::with_capacity(17);
                ct.push(input.fhe_type as u8);
                let mut buf = [0u8; 16];
                let len = input.plaintext_bytes.len().min(16);
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
/// format, then computes `keccak256(fhe_type || value_le)` to produce the
/// canonical digest (same as `MockComputeEngine::encode_constant`).
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
                // Mock ciphertext format: fhe_type(1) || value_le(16)
                // If ciphertext doesn't match this format, treat raw bytes as value
                if input.ciphertext_bytes.len() == 17 {
                    let fhe_type = FheType::from_u8(input.ciphertext_bytes[0])
                        .unwrap_or(input.fhe_type);
                    let value = u128::from_le_bytes(
                        input.ciphertext_bytes[1..17].try_into().unwrap(),
                    );
                    mock_digest(fhe_type, value)
                } else {
                    // Fallback: interpret raw bytes as LE u128 value
                    let mut buf = [0u8; 16];
                    let len = input.ciphertext_bytes.len().min(16);
                    buf[..len].copy_from_slice(&input.ciphertext_bytes[..len]);
                    let value = u128::from_le_bytes(buf);
                    mock_digest(input.fhe_type, value)
                }
            })
            .collect();

        Ok(VerifyResult { digests })
    }
}
