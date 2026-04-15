// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! `ComputeEngine` trait — abstraction over FHE computation backends.

use encrypt_types::types::{FheOperation, FheType};

/// 32-byte ciphertext digest (on-chain commitment).
///
/// In mock mode: keccak256(fhe_type || plaintext_value).
/// In real REFHE mode: hash(ciphertext_metadata || ciphertext_blob).
pub type CiphertextDigest = [u8; 32];

/// Trait for computing FHE operations on ciphertext digests.
///
/// Methods take `&mut self` because engines may be stateful (e.g., the mock
/// engine maintains a digest → plaintext lookup table; the real FHE engine
/// will hold loaded keys and context).
///
/// Two implementations:
/// - [`MockComputeEngine`](crate::mock::MockComputeEngine): stateful, plaintext arithmetic + keccak256 digests
/// - `RefheComputeEngine` (future): operates on actual REFHE ciphertext blobs
pub trait ComputeEngine {
    type Error: core::fmt::Debug;

    /// Binary FHE operation (add, mul, compare, etc.).
    fn binary_op(
        &mut self,
        op: FheOperation,
        lhs: &CiphertextDigest,
        rhs: &CiphertextDigest,
        fhe_type: FheType,
    ) -> Result<CiphertextDigest, Self::Error>;

    /// Unary FHE operation (negate, not, etc.).
    fn unary_op(
        &mut self,
        op: FheOperation,
        operand: &CiphertextDigest,
        fhe_type: FheType,
    ) -> Result<CiphertextDigest, Self::Error>;

    /// Ternary select: if condition then if_true else if_false.
    fn select(
        &mut self,
        condition: &CiphertextDigest,
        if_true: &CiphertextDigest,
        if_false: &CiphertextDigest,
    ) -> Result<CiphertextDigest, Self::Error>;

    /// Ternary operation (e.g., assign: vec[indices] = values).
    ///
    /// Default dispatches to `select` for backward compatibility.
    fn ternary_op(
        &mut self,
        _op: FheOperation,
        a: &CiphertextDigest,
        b: &CiphertextDigest,
        c: &CiphertextDigest,
        _fhe_type: FheType,
    ) -> Result<CiphertextDigest, Self::Error> {
        // Default: treat as select for backward compat
        self.select(a, b, c)
    }

    /// Encode a plaintext constant into a ciphertext digest.
    fn encode_constant(
        &mut self,
        fhe_type: FheType,
        value: u128,
    ) -> Result<CiphertextDigest, Self::Error>;

    /// Encode a plaintext constant from raw bytes into a ciphertext digest.
    ///
    /// Handles types wider than 128 bits (vectors, large scalars).
    /// Default implementation truncates to u128 for backward compatibility.
    fn encode_constant_bytes(
        &mut self,
        fhe_type: FheType,
        bytes: &[u8],
    ) -> Result<CiphertextDigest, Self::Error> {
        let mut buf = [0u8; 16];
        let len = bytes.len().min(16);
        buf[..len].copy_from_slice(&bytes[..len]);
        self.encode_constant(fhe_type, u128::from_le_bytes(buf))
    }

    /// Decrypt a ciphertext digest to plaintext bytes.
    fn decrypt(
        &mut self,
        digest: &CiphertextDigest,
        fhe_type: FheType,
    ) -> Result<Vec<u8>, Self::Error>;
}
