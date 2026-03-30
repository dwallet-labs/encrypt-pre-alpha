// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Shared Solana-specific types for the Encrypt program.
//!
//! Contains types used by both Pinocchio and Anchor CPI SDKs.

#![no_std]

/// Shared account types and byte-level readers.
pub mod accounts;

/// CPI trait and constants for Encrypt program invocation.
pub mod cpi;
