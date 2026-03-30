// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Encrypt Solana development internals — runtime abstraction and transaction builder.
//!
//! Framework-agnostic: no LiteSVM, no Mollusk, no test-validator dependencies.
//! Runtime implementations live in their respective crates:
//! - `LiteSvmRuntime` → `encrypt-solana-test`
//! - `RpcRuntime` (future) → `encrypt-cli-solana`

pub mod error;
pub mod runtime;
pub mod tx_builder;

pub use error::EncryptDevError;
pub use tx_builder::EncryptTxBuilder;
