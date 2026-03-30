// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Encrypt Solana DSL — `#[encrypt_fn]` macro and graph utilities.
//!
//! Framework-agnostic within Solana: works with both Pinocchio and Anchor.
//! The CPI context implementations live in `encrypt-pinocchio` and `encrypt-anchor`.

#![no_std]

// Re-export all chain-agnostic DSL
pub use encrypt_dsl::graph;
pub use encrypt_dsl::traits;
pub use encrypt_dsl::types;

// Re-export the CPI trait (framework-agnostic)
pub use encrypt_solana_types::cpi;

pub mod prelude {
    pub use encrypt_dsl::prelude::*;
    pub use encrypt_solana_types::cpi::EncryptCpi;
    // The Solana macro that generates CPI wrappers generic over EncryptCpi
    pub use encrypt_solana_dsl_macros::encrypt_fn;
}
