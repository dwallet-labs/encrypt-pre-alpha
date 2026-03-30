// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Error types for the dev harness.

use std::fmt;

#[derive(Debug)]
pub enum EncryptDevError {
    /// Transaction failed.
    Transaction(String),
    /// Account not found.
    AccountNotFound(String),
    /// Invalid account data.
    InvalidAccountData(String),
    /// Graph evaluation error.
    GraphEval(String),
    /// Ciphertext not found in store.
    CiphertextNotFound([u8; 32]),
    /// Decryption failed.
    DecryptionFailed(String),
    /// Program deployment failed.
    DeployFailed(String),
    /// IO error.
    Io(std::io::Error),
}

impl fmt::Display for EncryptDevError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transaction(msg) => write!(f, "transaction failed: {msg}"),
            Self::AccountNotFound(msg) => write!(f, "account not found: {msg}"),
            Self::InvalidAccountData(msg) => write!(f, "invalid account data: {msg}"),
            Self::GraphEval(msg) => write!(f, "graph evaluation error: {msg}"),
            Self::CiphertextNotFound(pk) => write!(f, "ciphertext not found: {pk:?}"),
            Self::DecryptionFailed(msg) => write!(f, "decryption failed: {msg}"),
            Self::DeployFailed(msg) => write!(f, "program deployment failed: {msg}"),
            Self::Io(e) => write!(f, "IO error: {e}"),
        }
    }
}

impl std::error::Error for EncryptDevError {}

impl From<std::io::Error> for EncryptDevError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
