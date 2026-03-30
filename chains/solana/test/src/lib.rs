// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Encrypt test framework for Solana program builders.
//!
//! Three testing modes:
//!
//! - **`litesvm`**: Fast in-process LiteSVM tests (sync, lightweight)
//! - **`program_test`**: Official Solana runtime via `solana-program-test` (async wrapped as sync)
//! - **`mollusk`**: Single-instruction unit tests with pre-built account data

pub mod harness;
pub mod litesvm;
pub mod mollusk;
pub mod program_test;
pub mod runtime_litesvm;
pub mod runtime_program_test;

pub use harness::EncryptTestHarness;
pub use runtime_litesvm::LiteSvmRuntime;
pub use runtime_program_test::ProgramTestRuntime;
