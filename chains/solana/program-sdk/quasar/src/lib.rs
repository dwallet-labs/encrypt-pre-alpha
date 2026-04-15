// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Quasar CPI SDK for the Encrypt program.

#![cfg_attr(not(test), no_std)]

pub mod accounts;
pub mod cpi;

pub use cpi::EncryptContext;
pub use encrypt_solana_types::cpi::EncryptCpi;
