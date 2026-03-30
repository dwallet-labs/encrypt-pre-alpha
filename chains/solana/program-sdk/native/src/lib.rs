// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Native Solana CPI SDK for the Encrypt program.
//!
//! Provides `EncryptContext` implementing `EncryptCpi` for programs
//! using `solana-program` directly (without Pinocchio or Anchor).

pub mod accounts;
pub mod cpi;

pub use cpi::EncryptContext;
pub use encrypt_solana_types::cpi::EncryptCpi;
