// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! BCS-serialized messages for signed gRPC requests.
//!
//! These structs define the payload that clients sign before submitting
//! to the Encrypt gRPC service. The server deserializes the BCS bytes
//! and verifies the ed25519 signature against the signer's public key.
//!
//! Following Sui's pattern: `signature = ed25519_sign(bcs_serialize(message))`.

extern crate alloc;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

/// BCS message for reading a ciphertext off-chain.
///
/// The client serializes this with BCS, signs the bytes with their ed25519 key,
/// and sends `(bcs_bytes, signature, signer_pubkey)` to the server.
///
/// The server:
/// 1. Verifies the signature against the signer
/// 2. Checks `signer == ciphertext.authorized` (or ciphertext is public)
/// 3. Returns the ciphertext re-encrypted under `reencryption_key`
///    (or plaintext in mock mode)
///
/// Responses are cached per `(ciphertext_identifier, signer, epoch)`.
/// When the epoch advances, old signatures are rejected.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReadCiphertextMessage {
    /// Target chain identifier.
    pub chain: u8,
    /// On-chain ciphertext identifier.
    /// Solana: 32 bytes (account pubkey). EVM: 20 bytes. Sui: 32 bytes.
    pub ciphertext_identifier: Vec<u8>,
    /// User's re-encryption key.
    /// Allows the server to convert from network encryption → user encryption.
    /// The user decrypts the result locally with their private key.
    /// In mock mode: present but unused (plaintext returned directly).
    pub reencryption_key: Vec<u8>,
    /// Network encryption key epoch.
    /// Binds this request to a specific key period. When the epoch advances,
    /// this request becomes invalid (prevents use of stale re-encryption keys).
    pub epoch: u64,
}

impl ReadCiphertextMessage {
    /// BCS-serialize this message (the bytes that get signed).
    pub fn to_bcs(&self) -> Vec<u8> {
        bcs::to_bytes(self).expect("BCS serialization cannot fail for this type")
    }

    /// Deserialize from BCS bytes.
    pub fn from_bcs(bytes: &[u8]) -> Result<Self, bcs::Error> {
        bcs::from_bytes(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn round_trip() {
        let msg = ReadCiphertextMessage {
            chain: 0,
            ciphertext_identifier: vec![1u8; 32],
            reencryption_key: vec![0xAB; 64],
            epoch: 42,
        };

        let bcs_bytes = msg.to_bcs();
        let decoded = ReadCiphertextMessage::from_bcs(&bcs_bytes).unwrap();

        assert_eq!(decoded.chain, 0);
        assert_eq!(decoded.ciphertext_identifier, vec![1u8; 32]);
        assert_eq!(decoded.reencryption_key, vec![0xAB; 64]);
        assert_eq!(decoded.epoch, 42);
    }

    #[test]
    fn deterministic_serialization() {
        let msg = ReadCiphertextMessage {
            chain: 0,
            ciphertext_identifier: vec![1u8; 32],
            reencryption_key: vec![],
            epoch: 1,
        };

        let a = msg.to_bcs();
        let b = msg.to_bcs();
        assert_eq!(a, b, "BCS serialization must be deterministic for signing");
    }
}
