// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Pure FHE computation engine and graph evaluator.
//!
//! No Solana dependencies — reusable by both local dev and production executors.
//! Provides the `ComputeEngine` trait with a mock implementation today
//! and a real REFHE implementation in the future.

pub mod engine;
pub mod evaluator;
pub mod mock;
pub mod mock_crypto;
