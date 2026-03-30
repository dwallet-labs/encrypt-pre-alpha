// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Client-side encryption and server-side verification traits.
//!
//! Traits are defined here (no_std, zero deps). Mock implementations
//! live in `encrypt-compute` (which has the sha3 dependency for keccak256).

extern crate alloc;
use alloc::vec::Vec;

use crate::types::FheType;

/// Target chain identifier (part of the proof statement).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Chain {
    Solana = 0,
}

// ── Client side ──

/// A single plaintext input to encrypt.
pub struct PlaintextInput<'a> {
    /// Raw plaintext bytes (little-endian for primitives, raw for byte types).
    pub plaintext_bytes: &'a [u8],
    /// FHE type of this value.
    pub fhe_type: FheType,
}

/// Result of encryption: one ciphertext per input + one proof for the batch.
pub struct EncryptResult {
    /// Ciphertext bytes, one per input (same order).
    pub ciphertexts: Vec<Vec<u8>>,
    /// ZK proof covering all ciphertexts (bound to chain + network key).
    pub proof: Vec<u8>,
}

/// Client-side FHE encryptor.
pub trait Encryptor {
    /// Encrypt plaintext values and generate a ZK proof for the batch.
    fn encrypt_and_prove(
        &self,
        inputs: &[PlaintextInput<'_>],
        network_key: &[u8; 32],
        chain: Chain,
    ) -> EncryptResult;
}

// ── Server side ──

/// A single ciphertext submitted for verification.
pub struct CiphertextInput<'a> {
    /// Raw ciphertext bytes (as received from the client).
    pub ciphertext_bytes: &'a [u8],
    /// FHE type of this ciphertext.
    pub fhe_type: FheType,
}

/// Result of verification: one 32-byte digest per ciphertext.
pub struct VerifyResult {
    /// Ciphertext digests, one per input (same order).
    pub digests: Vec<[u8; 32]>,
}

/// Server-side proof verifier.
pub trait Verifier {
    /// Verification error type.
    type Error: core::fmt::Debug;

    /// Verify the proof and return the canonical digest for each ciphertext.
    fn verify(
        &self,
        inputs: &[CiphertextInput<'_>],
        proof: &[u8],
        network_key: &[u8; 32],
        chain: Chain,
    ) -> Result<VerifyResult, Self::Error>;
}
