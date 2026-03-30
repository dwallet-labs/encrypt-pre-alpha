// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Pinocchio CPI SDK for the Encrypt program.
//!
//! Provides `EncryptContext` implementing `EncryptCpi` for Pinocchio programs,
//! plus zero-copy account readers for reading Encrypt state.

#![no_std]

pub mod accounts;
pub mod cpi;

pub use cpi::EncryptContext;
pub use encrypt_solana_types::cpi::EncryptCpi;
