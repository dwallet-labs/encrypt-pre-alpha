// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Framework-agnostic CPI trait for Encrypt program invocation.

/// Trait for invoking Encrypt program instructions via CPI.
///
/// The `#[encrypt_fn]` macro generates `_cpi()` functions that call
/// `invoke_execute_graph()` on any type implementing this trait.
///
/// Framework-specific account types:
/// - Pinocchio: `Account = &AccountView`
/// - Native: `Account = AccountInfo`
/// - Anchor: `Account = AccountInfo`
pub trait EncryptCpi {
    type Error;

    /// Framework-specific single account reference.
    type Account<'a>: Clone
    where
        Self: 'a;

    /// Invoke `execute_graph` on the Encrypt program via CPI.
    ///
    /// `ix_data` is the fully serialized instruction data (discriminator + graph + IDs).
    /// `encrypt_execute_accounts` contains input ciphertexts and output ciphertexts
    /// needed for the execute_graph CPI.
    fn invoke_execute_graph<'a>(
        &'a self,
        ix_data: &[u8],
        encrypt_execute_accounts: &[Self::Account<'a>],
    ) -> Result<(), Self::Error>;

    /// Read the `fhe_type` byte from a ciphertext account.
    ///
    /// Used by the generated `_cpi` functions for runtime type verification.
    /// Returns `None` if the account data is too short.
    fn read_fhe_type<'a>(&'a self, account: Self::Account<'a>) -> Option<u8>;

    /// Return an error for FHE type mismatch.
    ///
    /// Used by the generated `_cpi` functions when runtime type verification fails.
    fn type_mismatch_error(&self) -> Self::Error;
}
