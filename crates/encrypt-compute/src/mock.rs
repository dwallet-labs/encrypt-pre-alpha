// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Mock compute engine — stateful, plaintext arithmetic with keccak256 digests.
//!
//! Maintains a `digest → plaintext_value` lookup table. Operations:
//! 1. Look up operand digests → get plaintext values
//! 2. Compute the operation in plaintext
//! 3. Hash the result → new digest (keccak256(fhe_type || value))
//! 4. Store the mapping and return the digest
//!
//! Digests are collision-resistant and never `[0; 32]` for any valid value,
//! which avoids confusion with the zero-initialized on-chain state.

use std::collections::HashMap;

use sha3::{Digest, Keccak256};

use encrypt_types::identifier::{mock_binary_compute_value, mock_select_value, mock_unary_compute_value};
use encrypt_types::types::{FheOperation, FheType};

use crate::engine::{CiphertextDigest, ComputeEngine};

/// Mock compute engine for local development and testing.
///
/// Stateful: maintains a keccak256 digest → plaintext value table.
pub struct MockComputeEngine {
    /// Maps keccak256 digest → plaintext u128 value.
    table: HashMap<[u8; 32], u128>,
}

impl MockComputeEngine {
    pub fn new() -> Self {
        Self {
            table: HashMap::new(),
        }
    }
}

impl Default for MockComputeEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute keccak256(fhe_type || value_le_bytes) → 32-byte digest.
pub fn mock_digest(fhe_type: FheType, value: u128) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update([fhe_type as u8]);
    hasher.update(value.to_le_bytes());
    hasher.finalize().into()
}

impl ComputeEngine for MockComputeEngine {
    type Error = MockComputeError;

    fn binary_op(
        &mut self,
        op: FheOperation,
        lhs: &CiphertextDigest,
        rhs: &CiphertextDigest,
        fhe_type: FheType,
    ) -> Result<CiphertextDigest, Self::Error> {
        let a = self.lookup(lhs)?;
        let b = self.lookup(rhs)?;
        let result = mock_binary_compute_value(op, a, b, fhe_type);
        Ok(self.store(fhe_type, result))
    }

    fn unary_op(
        &mut self,
        op: FheOperation,
        operand: &CiphertextDigest,
        fhe_type: FheType,
    ) -> Result<CiphertextDigest, Self::Error> {
        let a = self.lookup(operand)?;
        let result = mock_unary_compute_value(op, a, fhe_type);
        Ok(self.store(fhe_type, result))
    }

    fn select(
        &mut self,
        condition: &CiphertextDigest,
        if_true: &CiphertextDigest,
        if_false: &CiphertextDigest,
    ) -> Result<CiphertextDigest, Self::Error> {
        let cond = self.lookup(condition)?;
        let t = self.lookup(if_true)?;
        let f = self.lookup(if_false)?;
        let (result, fhe_type) = mock_select_value(cond, t, f);
        Ok(self.store(fhe_type, result))
    }

    fn encode_constant(
        &mut self,
        fhe_type: FheType,
        value: u128,
    ) -> Result<CiphertextDigest, Self::Error> {
        Ok(self.store(fhe_type, value))
    }

    fn decrypt(
        &mut self,
        digest: &CiphertextDigest,
        fhe_type: FheType,
    ) -> Result<Vec<u8>, Self::Error> {
        let value = self.lookup(digest)?;
        let byte_width = fhe_type.byte_width();
        let mut bytes = vec![0u8; byte_width];
        let value_bytes = value.to_le_bytes();
        let copy_len = byte_width.min(16);
        bytes[..copy_len].copy_from_slice(&value_bytes[..copy_len]);
        Ok(bytes)
    }
}

impl MockComputeEngine {
    /// Look up a digest in the table.
    ///
    /// `[0; 32]` is treated as value 0 (the uninitialized on-chain state
    /// from `create_plaintext_ciphertext`).
    fn lookup(&self, digest: &[u8; 32]) -> Result<u128, MockComputeError> {
        if *digest == [0u8; 32] {
            return Ok(0);
        }
        self.table
            .get(digest)
            .copied()
            .ok_or(MockComputeError::UnknownDigest(*digest))
    }

    /// Compute digest, store mapping, return digest.
    fn store(&mut self, fhe_type: FheType, value: u128) -> [u8; 32] {
        let digest = mock_digest(fhe_type, value);
        self.table.insert(digest, value);
        digest
    }

    /// Register an external digest → value mapping.
    ///
    /// Used by the executor to populate the table with digests read from
    /// on-chain (e.g., input ciphertexts created by the gRPC server).
    pub fn register(&mut self, digest: [u8; 32], value: u128) {
        self.table.insert(digest, value);
    }
}

/// Errors from the mock compute engine.
#[derive(Debug)]
pub enum MockComputeError {
    /// Digest not found in the lookup table.
    UnknownDigest([u8; 32]),
}

impl core::fmt::Display for MockComputeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnknownDigest(d) => write!(f, "unknown digest: {}", hex(d)),
        }
    }
}

impl std::error::Error for MockComputeError {}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_add() {
        let mut engine = MockComputeEngine::new();
        let a = engine.encode_constant(FheType::EUint64, 10).unwrap();
        let b = engine.encode_constant(FheType::EUint64, 32).unwrap();
        let c = engine
            .binary_op(FheOperation::Add, &a, &b, FheType::EUint64)
            .unwrap();
        let result = engine.decrypt(&c, FheType::EUint64).unwrap();
        assert_eq!(u64::from_le_bytes(result[..8].try_into().unwrap()), 42);
    }

    #[test]
    fn mock_select_test() {
        let mut engine = MockComputeEngine::new();
        let cond = engine.encode_constant(FheType::EBool, 1).unwrap();
        let yes = engine.encode_constant(FheType::EUint64, 100).unwrap();
        let no = engine.encode_constant(FheType::EUint64, 200).unwrap();
        let result = engine.select(&cond, &yes, &no).unwrap();
        let decrypted = engine.decrypt(&result, FheType::EUint64).unwrap();
        assert_eq!(
            u64::from_le_bytes(decrypted[..8].try_into().unwrap()),
            100
        );
    }

    #[test]
    fn mock_decrypt_test() {
        let mut engine = MockComputeEngine::new();
        let digest = engine.encode_constant(FheType::EUint64, 42).unwrap();
        let bytes = engine.decrypt(&digest, FheType::EUint64).unwrap();
        assert_eq!(bytes.len(), 8);
        assert_eq!(u64::from_le_bytes(bytes[..8].try_into().unwrap()), 42);
    }

    #[test]
    fn zero_value_has_nonzero_digest() {
        let mut engine = MockComputeEngine::new();
        let digest = engine.encode_constant(FheType::EUint64, 0).unwrap();
        assert_ne!(digest, [0u8; 32], "zero value must not produce all-zero digest");
    }

    #[test]
    fn different_types_different_digests() {
        let mut engine = MockComputeEngine::new();
        let bool_zero = engine.encode_constant(FheType::EBool, 0).unwrap();
        let uint_zero = engine.encode_constant(FheType::EUint64, 0).unwrap();
        assert_ne!(bool_zero, uint_zero, "same value, different types → different digests");
    }
}
