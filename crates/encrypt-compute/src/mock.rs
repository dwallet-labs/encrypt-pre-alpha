// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Mock compute engine — stateful, plaintext arithmetic with keccak256 digests.
//!
//! Maintains a `digest → plaintext_bytes` lookup table. Operations:
//! 1. Look up operand digests → get plaintext byte values
//! 2. Compute the operation in plaintext (element-wise for vectors)
//! 3. Hash the result → new digest (keccak256(fhe_type || value_bytes))
//! 4. Store the mapping and return the digest
//!
//! Digests are collision-resistant and never `[0; 32]` for any valid value,
//! which avoids confusion with the zero-initialized on-chain state.

use std::collections::HashMap;

use sha3::{Digest, Keccak256};

use encrypt_types::identifier::{
    mock_binary_compute_value_bytes, mock_select_value_bytes, mock_ternary_compute_value_bytes,
    mock_unary_compute_value_bytes,
};
use encrypt_types::types::{FheOperation, FheType};

use crate::engine::{CiphertextDigest, ComputeEngine};

/// Mock compute engine for local development and testing.
///
/// Stateful: maintains a keccak256 digest → plaintext bytes table.
pub struct MockComputeEngine {
    /// Maps keccak256 digest → plaintext byte value.
    table: HashMap<[u8; 32], Vec<u8>>,
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

/// Compute keccak256(fhe_type || value_bytes) → 32-byte digest.
pub fn mock_digest_bytes(fhe_type: FheType, value_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update([fhe_type as u8]);
    hasher.update(value_bytes);
    hasher.finalize().into()
}

/// Compute keccak256(fhe_type || value_le_bytes) → 32-byte digest.
///
/// Backward-compatible: always hashes all 16 bytes of the u128 LE representation.
pub fn mock_digest(fhe_type: FheType, value: u128) -> [u8; 32] {
    mock_digest_bytes(fhe_type, &value.to_le_bytes())
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
        let a = self.lookup(lhs, fhe_type)?;
        let b = self.lookup(rhs, fhe_type)?;
        let result = mock_binary_compute_value_bytes(op, &a, &b, fhe_type);
        Ok(self.store_bytes(fhe_type, &result))
    }

    fn unary_op(
        &mut self,
        op: FheOperation,
        operand: &CiphertextDigest,
        fhe_type: FheType,
    ) -> Result<CiphertextDigest, Self::Error> {
        let a = self.lookup(operand, fhe_type)?;
        let result = mock_unary_compute_value_bytes(op, &a, fhe_type);
        Ok(self.store_bytes(fhe_type, &result))
    }

    fn select(
        &mut self,
        condition: &CiphertextDigest,
        if_true: &CiphertextDigest,
        if_false: &CiphertextDigest,
    ) -> Result<CiphertextDigest, Self::Error> {
        let cond = self.lookup(condition, FheType::EBool)?;
        // Infer result type from the true branch value length
        let t = self.lookup_raw(if_true)?;
        let f = self.lookup_raw(if_false)?;
        let result = mock_select_value_bytes(&cond, &t, &f);
        // Use EUint64 as default fhe_type for digest (same as before for scalars)
        // For vectors the digest just needs to be unique — type is tracked separately
        let fhe_type = self.infer_type_from_len(t.len());
        Ok(self.store_bytes(fhe_type, &result))
    }

    fn ternary_op(
        &mut self,
        op: FheOperation,
        a: &CiphertextDigest,
        b: &CiphertextDigest,
        c: &CiphertextDigest,
        fhe_type: FheType,
    ) -> Result<CiphertextDigest, Self::Error> {
        if op == FheOperation::Select {
            // Select uses EBool condition — special lookup
            return self.select(a, b, c);
        }
        let av = self.lookup(a, fhe_type)?;
        let bv = self.lookup(b, fhe_type)?;
        let cv = self.lookup(c, fhe_type)?;
        let result = mock_ternary_compute_value_bytes(op, &av, &bv, &cv, fhe_type);
        Ok(self.store_bytes(fhe_type, &result))
    }

    fn encode_constant(
        &mut self,
        fhe_type: FheType,
        value: u128,
    ) -> Result<CiphertextDigest, Self::Error> {
        Ok(self.store(fhe_type, value))
    }

    fn encode_constant_bytes(
        &mut self,
        fhe_type: FheType,
        bytes: &[u8],
    ) -> Result<CiphertextDigest, Self::Error> {
        Ok(self.store_bytes(fhe_type, bytes))
    }

    fn decrypt(
        &mut self,
        digest: &CiphertextDigest,
        fhe_type: FheType,
    ) -> Result<Vec<u8>, Self::Error> {
        let value = self.lookup(digest, fhe_type)?;
        let byte_width = fhe_type.byte_width();
        // Extend or truncate to expected byte_width
        let mut bytes = vec![0u8; byte_width];
        let copy_len = value.len().min(byte_width);
        bytes[..copy_len].copy_from_slice(&value[..copy_len]);
        Ok(bytes)
    }
}

impl MockComputeEngine {
    /// Look up a digest in the table, returning bytes of the expected width.
    ///
    /// `[0; 32]` is treated as a zero value of the given type (the uninitialized
    /// on-chain state from `create_plaintext_ciphertext`).
    fn lookup(&self, digest: &[u8; 32], fhe_type: FheType) -> Result<Vec<u8>, MockComputeError> {
        if *digest == [0u8; 32] {
            return Ok(vec![0u8; fhe_type.byte_width()]);
        }
        self.table
            .get(digest)
            .cloned()
            .ok_or(MockComputeError::UnknownDigest(*digest))
    }

    /// Look up raw bytes without type context. Used by select where we don't know
    /// the branch type upfront.
    fn lookup_raw(&self, digest: &[u8; 32]) -> Result<Vec<u8>, MockComputeError> {
        if *digest == [0u8; 32] {
            // Default to 16 bytes (u128-sized zero) for backward compat
            return Ok(vec![0u8; 16]);
        }
        self.table
            .get(digest)
            .cloned()
            .ok_or(MockComputeError::UnknownDigest(*digest))
    }

    /// Infer an approximate FheType from value byte length (for select digest).
    fn infer_type_from_len(&self, len: usize) -> FheType {
        match len {
            8192 => FheType::EVectorU32, // arbitrary vector type — digest is unique anyway
            _ => FheType::EUint64,
        }
    }

    /// Compute digest from bytes, store mapping, return digest.
    fn store_bytes(&mut self, fhe_type: FheType, value_bytes: &[u8]) -> [u8; 32] {
        let digest = mock_digest_bytes(fhe_type, value_bytes);
        self.table.insert(digest, value_bytes.to_vec());
        digest
    }

    /// Convenience: store a u128 scalar value (backward-compatible digest).
    fn store(&mut self, fhe_type: FheType, value: u128) -> [u8; 32] {
        let digest = mock_digest(fhe_type, value);
        self.table.insert(digest, value.to_le_bytes().to_vec());
        digest
    }

    /// Register an external digest → value mapping (u128, backward-compatible).
    pub fn register(&mut self, digest: [u8; 32], value: u128) {
        self.table.insert(digest, value.to_le_bytes().to_vec());
    }

    /// Register an external digest → byte value mapping.
    pub fn register_bytes(&mut self, digest: [u8; 32], value: Vec<u8>) {
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

    // ── Vector tests ──

    #[test]
    fn vector_add_elementwise() {
        let mut engine = MockComputeEngine::new();
        // Create two u32 vectors with a few nonzero elements
        let mut a_bytes = vec![0u8; 8192];
        let mut b_bytes = vec![0u8; 8192];
        // a = [10, 20, 30, 0, ...]
        a_bytes[0..4].copy_from_slice(&10u32.to_le_bytes());
        a_bytes[4..8].copy_from_slice(&20u32.to_le_bytes());
        a_bytes[8..12].copy_from_slice(&30u32.to_le_bytes());
        // b = [1, 2, 3, 0, ...]
        b_bytes[0..4].copy_from_slice(&1u32.to_le_bytes());
        b_bytes[4..8].copy_from_slice(&2u32.to_le_bytes());
        b_bytes[8..12].copy_from_slice(&3u32.to_le_bytes());

        let a = engine
            .encode_constant_bytes(FheType::EVectorU32, &a_bytes)
            .unwrap();
        let b = engine
            .encode_constant_bytes(FheType::EVectorU32, &b_bytes)
            .unwrap();
        let c = engine
            .binary_op(FheOperation::Add, &a, &b, FheType::EVectorU32)
            .unwrap();
        let result = engine.decrypt(&c, FheType::EVectorU32).unwrap();
        assert_eq!(result.len(), 8192);
        assert_eq!(u32::from_le_bytes(result[0..4].try_into().unwrap()), 11);
        assert_eq!(u32::from_le_bytes(result[4..8].try_into().unwrap()), 22);
        assert_eq!(u32::from_le_bytes(result[8..12].try_into().unwrap()), 33);
        assert_eq!(u32::from_le_bytes(result[12..16].try_into().unwrap()), 0);
    }

    #[test]
    fn vector_scalar_multiply() {
        let mut engine = MockComputeEngine::new();
        let mut v_bytes = vec![0u8; 8192];
        v_bytes[0..4].copy_from_slice(&5u32.to_le_bytes());
        v_bytes[4..8].copy_from_slice(&10u32.to_le_bytes());

        let v = engine
            .encode_constant_bytes(FheType::EVectorU32, &v_bytes)
            .unwrap();
        // Scalar constant — stored as u128 but used via AddScalar/MultiplyScalar
        let s = engine.encode_constant(FheType::EUint32, 3).unwrap();
        let r = engine
            .binary_op(FheOperation::MultiplyScalar, &v, &s, FheType::EVectorU32)
            .unwrap();
        let result = engine.decrypt(&r, FheType::EVectorU32).unwrap();
        assert_eq!(u32::from_le_bytes(result[0..4].try_into().unwrap()), 15);
        assert_eq!(u32::from_le_bytes(result[4..8].try_into().unwrap()), 30);
    }

    #[test]
    fn vector_decrypt_full_width() {
        let mut engine = MockComputeEngine::new();
        let mut v_bytes = vec![0u8; 8192];
        v_bytes[0..4].copy_from_slice(&42u32.to_le_bytes());
        v_bytes[8188..8192].copy_from_slice(&99u32.to_le_bytes());
        let d = engine
            .encode_constant_bytes(FheType::EVectorU32, &v_bytes)
            .unwrap();
        let result = engine.decrypt(&d, FheType::EVectorU32).unwrap();
        assert_eq!(result.len(), 8192);
        assert_eq!(u32::from_le_bytes(result[0..4].try_into().unwrap()), 42);
        assert_eq!(u32::from_le_bytes(result[8188..8192].try_into().unwrap()), 99);
    }
}
