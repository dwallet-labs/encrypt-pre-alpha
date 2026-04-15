// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Encrypted ACL (Quasar version).
//!
//! On-chain access control where permissions are stored as encrypted bitmasks.
//! Nobody can see the permission state, but operations (grant, revoke, check)
//! are performed via FHE bitwise operations.
//!
//! This is the Quasar equivalent of the Pinocchio `confidential-acl` program.

#![cfg_attr(not(test), no_std)]
#![allow(unexpected_cfgs)]

extern crate alloc;
use alloc::vec::Vec;



use encrypt_dsl::prelude::encrypt_fn;
use encrypt_quasar::accounts;
use encrypt_quasar::EncryptContext;
use encrypt_types::encrypted::{EUint64, Uint64};
use quasar_lang::prelude::*;
use solana_address::Address;

declare_id!("99999999999999999999999999999996999999999999");

// ── FHE Graphs ──

/// Grant: permissions = permissions | permission_bit
#[encrypt_fn]
fn grant_permission_graph(permissions: EUint64, permission_bit: EUint64) -> EUint64 {
    permissions | permission_bit
}

/// Revoke: permissions = permissions & revoke_mask
///
/// The caller passes the inverse mask (all bits set except the one to revoke).
#[encrypt_fn]
fn revoke_permission_graph(permissions: EUint64, revoke_mask: EUint64) -> EUint64 {
    permissions & revoke_mask
}

/// Check: result = permissions & permission_bit (nonzero means has permission)
#[encrypt_fn]
fn check_permission_graph(permissions: EUint64, permission_bit: EUint64) -> EUint64 {
    permissions & permission_bit
}

// ── Program ──

#[program]
mod confidential_acl_quasar {
    use super::*;

    /// Create a resource with zeroed encrypted permission bitmask.
    #[instruction(discriminator = 0)]
    pub fn create_resource(
        ctx: Ctx<CreateResource>,
        resource_id: Address,
        cpi_authority_bump: u8,
    ) -> Result<(), ProgramError> {
        ctx.accounts.handler(resource_id, cpi_authority_bump)
    }

    /// OR a permission bit into the bitmask.
    #[instruction(discriminator = 1)]
    pub fn grant_permission(
        ctx: Ctx<GrantPermission>,
        cpi_authority_bump: u8,
    ) -> Result<(), ProgramError> {
        ctx.accounts.handler(cpi_authority_bump)
    }

    /// AND with inverse mask to clear a permission bit.
    #[instruction(discriminator = 2)]
    pub fn revoke_permission(
        ctx: Ctx<RevokePermission>,
        cpi_authority_bump: u8,
    ) -> Result<(), ProgramError> {
        ctx.accounts.handler(cpi_authority_bump)
    }

    /// AND bitmask with permission bit, store encrypted result.
    #[instruction(discriminator = 3)]
    pub fn check_permission(
        ctx: Ctx<CheckPermission>,
        resource_id: Address,
        cpi_authority_bump: u8,
    ) -> Result<(), ProgramError> {
        ctx.accounts.handler(resource_id, cpi_authority_bump)
    }

    /// Request decryption of a check result.
    #[instruction(discriminator = 4)]
    pub fn request_check_decryption(
        ctx: Ctx<RequestCheckDecryption>,
        cpi_authority_bump: u8,
    ) -> Result<(), ProgramError> {
        ctx.accounts.handler(cpi_authority_bump)
    }

    /// Read decrypted check result.
    #[instruction(discriminator = 5)]
    pub fn reveal_check(ctx: Ctx<RevealCheck>) -> Result<(), ProgramError> {
        ctx.accounts.handler()
    }

    /// Admin requests decryption of full permission bitmask.
    #[instruction(discriminator = 6)]
    pub fn request_permissions_decryption(
        ctx: Ctx<RequestPermissionsDecryption>,
        cpi_authority_bump: u8,
    ) -> Result<(), ProgramError> {
        ctx.accounts.handler(cpi_authority_bump)
    }

    /// Read decrypted permissions.
    #[instruction(discriminator = 7)]
    pub fn reveal_permissions(ctx: Ctx<RevealPermissions>) -> Result<(), ProgramError> {
        ctx.accounts.handler()
    }
}

// ── State ──

#[account(discriminator = 1, set_inner)]
#[seeds(b"resource", resource_id: Address)]
pub struct Resource {
    pub admin: Address,
    pub resource_id: Address,
    pub permissions: [u8; 32],
    pub pending_digest: [u8; 32],
    pub revealed_permissions: [u8; 8],
    pub bump: u8,
}

#[account(discriminator = 2, set_inner)]
#[seeds(b"check", resource_id: Address, checker: Address)]
pub struct AccessCheck {
    pub checker: Address,
    pub result_ct: [u8; 32],
    pub pending_digest: [u8; 32],
    pub revealed_result: [u8; 8],
    pub bump: u8,
}

// ── Errors ──

#[error_code]
pub enum AclError {
    NotAdmin = 6000,
    NotChecker,
    PermissionsMismatch,
}

// ── Accounts: create_resource ──

#[derive(Accounts)]
#[instruction(resource_id: Address)]
pub struct CreateResource {
    #[account(init, payer = payer, seeds = Resource::seeds(resource_id), bump)]
    pub resource: Account<Resource>,

    pub admin: Signer,

    /// Ciphertext for the permission bitmask.
    #[account(mut)]
    pub permissions_ct: UncheckedAccount,

    // Encrypt CPI accounts.
    pub encrypt_program: UncheckedAccount,
    pub config: UncheckedAccount,
    #[account(mut)]
    pub deposit: UncheckedAccount,
    pub cpi_authority: UncheckedAccount,
    pub caller_program: UncheckedAccount,
    pub network_encryption_key: UncheckedAccount,
    #[account(mut)]
    pub payer: Signer,
    pub event_authority: UncheckedAccount,
    pub system_program: Program<System>,
}

impl CreateResource {
    pub fn handler(&mut self, resource_id: Address, cpi_authority_bump: u8) -> Result<(), ProgramError> {
        let ctx = EncryptContext {
            encrypt_program: self.encrypt_program.to_account_view(),
            config: self.config.to_account_view(),
            deposit: self.deposit.to_account_view(),
            cpi_authority: self.cpi_authority.to_account_view(),
            caller_program: self.caller_program.to_account_view(),
            network_encryption_key: self.network_encryption_key.to_account_view(),
            payer: self.payer.to_account_view(),
            event_authority: self.event_authority.to_account_view(),
            system_program: self.system_program.to_account_view(),
            cpi_authority_bump,
        };

        ctx.create_plaintext_typed::<Uint64>(&0u64, self.permissions_ct.to_account_view())?;

        self.resource.set_inner(ResourceInner {
            admin: *self.admin.address(),
            resource_id,
            permissions: *self.permissions_ct.address().as_array(),
            pending_digest: [0u8; 32],
            revealed_permissions: [0u8; 8],
            bump: 0,
        });
        Ok(())
    }
}

// ── Accounts: grant_permission ──

#[derive(Accounts)]
pub struct GrantPermission {
    #[account(mut)]
    pub resource: Account<Resource>,

    pub admin: Signer,

    /// Current permissions ciphertext.
    #[account(mut)]
    pub permissions_ct: UncheckedAccount,

    /// Permission bit ciphertext to OR in.
    pub permission_bit_ct: UncheckedAccount,

    // Encrypt CPI accounts.
    pub encrypt_program: UncheckedAccount,
    pub config: UncheckedAccount,
    #[account(mut)]
    pub deposit: UncheckedAccount,
    pub cpi_authority: UncheckedAccount,
    pub caller_program: UncheckedAccount,
    pub network_encryption_key: UncheckedAccount,
    #[account(mut)]
    pub payer: Signer,
    pub event_authority: UncheckedAccount,
    pub system_program: Program<System>,
}

impl GrantPermission {
    pub fn handler(&mut self, cpi_authority_bump: u8) -> Result<(), ProgramError> {
        require!(
            self.admin.address() == &self.resource.admin,
            AclError::NotAdmin
        );
        require!(
            self.permissions_ct.address().as_array() == &self.resource.permissions,
            AclError::PermissionsMismatch
        );

        let ctx = EncryptContext {
            encrypt_program: self.encrypt_program.to_account_view(),
            config: self.config.to_account_view(),
            deposit: self.deposit.to_account_view(),
            cpi_authority: self.cpi_authority.to_account_view(),
            caller_program: self.caller_program.to_account_view(),
            network_encryption_key: self.network_encryption_key.to_account_view(),
            payer: self.payer.to_account_view(),
            event_authority: self.event_authority.to_account_view(),
            system_program: self.system_program.to_account_view(),
            cpi_authority_bump,
        };

        ctx.grant_permission_graph(
            self.permissions_ct.to_account_view(),
            self.permission_bit_ct.to_account_view(),
            self.permissions_ct.to_account_view(),
        )?;

        Ok(())
    }
}

// ── Accounts: revoke_permission ──

#[derive(Accounts)]
pub struct RevokePermission {
    #[account(mut)]
    pub resource: Account<Resource>,

    pub admin: Signer,

    /// Current permissions ciphertext.
    #[account(mut)]
    pub permissions_ct: UncheckedAccount,

    /// Revoke mask ciphertext to AND with.
    pub revoke_mask_ct: UncheckedAccount,

    // Encrypt CPI accounts.
    pub encrypt_program: UncheckedAccount,
    pub config: UncheckedAccount,
    #[account(mut)]
    pub deposit: UncheckedAccount,
    pub cpi_authority: UncheckedAccount,
    pub caller_program: UncheckedAccount,
    pub network_encryption_key: UncheckedAccount,
    #[account(mut)]
    pub payer: Signer,
    pub event_authority: UncheckedAccount,
    pub system_program: Program<System>,
}

impl RevokePermission {
    pub fn handler(&mut self, cpi_authority_bump: u8) -> Result<(), ProgramError> {
        require!(
            self.admin.address() == &self.resource.admin,
            AclError::NotAdmin
        );
        require!(
            self.permissions_ct.address().as_array() == &self.resource.permissions,
            AclError::PermissionsMismatch
        );

        let ctx = EncryptContext {
            encrypt_program: self.encrypt_program.to_account_view(),
            config: self.config.to_account_view(),
            deposit: self.deposit.to_account_view(),
            cpi_authority: self.cpi_authority.to_account_view(),
            caller_program: self.caller_program.to_account_view(),
            network_encryption_key: self.network_encryption_key.to_account_view(),
            payer: self.payer.to_account_view(),
            event_authority: self.event_authority.to_account_view(),
            system_program: self.system_program.to_account_view(),
            cpi_authority_bump,
        };

        ctx.revoke_permission_graph(
            self.permissions_ct.to_account_view(),
            self.revoke_mask_ct.to_account_view(),
            self.permissions_ct.to_account_view(),
        )?;

        Ok(())
    }
}

// ── Accounts: check_permission ──

#[derive(Accounts)]
#[instruction(resource_id: Address)]
pub struct CheckPermission {
    pub resource: Account<Resource>,

    pub checker: Signer,

    #[account(init, payer = payer, seeds = AccessCheck::seeds(resource_id, checker), bump)]
    pub access_check: Account<AccessCheck>,

    /// Current permissions ciphertext.
    pub permissions_ct: UncheckedAccount,

    /// Permission bit ciphertext to check.
    pub permission_bit_ct: UncheckedAccount,

    /// Result ciphertext (pre-created).
    #[account(mut)]
    pub result_ct: UncheckedAccount,

    // Encrypt CPI accounts.
    pub encrypt_program: UncheckedAccount,
    pub config: UncheckedAccount,
    #[account(mut)]
    pub deposit: UncheckedAccount,
    pub cpi_authority: UncheckedAccount,
    pub caller_program: UncheckedAccount,
    pub network_encryption_key: UncheckedAccount,
    #[account(mut)]
    pub payer: Signer,
    pub event_authority: UncheckedAccount,
    pub system_program: Program<System>,
}

impl CheckPermission {
    pub fn handler(&mut self, _resource_id: Address, cpi_authority_bump: u8) -> Result<(), ProgramError> {
        require!(
            self.permissions_ct.address().as_array() == &self.resource.permissions,
            AclError::PermissionsMismatch
        );

        let ctx = EncryptContext {
            encrypt_program: self.encrypt_program.to_account_view(),
            config: self.config.to_account_view(),
            deposit: self.deposit.to_account_view(),
            cpi_authority: self.cpi_authority.to_account_view(),
            caller_program: self.caller_program.to_account_view(),
            network_encryption_key: self.network_encryption_key.to_account_view(),
            payer: self.payer.to_account_view(),
            event_authority: self.event_authority.to_account_view(),
            system_program: self.system_program.to_account_view(),
            cpi_authority_bump,
        };

        // Pre-create result ciphertext with sentinel value.
        ctx.create_plaintext_typed::<Uint64>(&u64::MAX, self.result_ct.to_account_view())?;

        // result = permissions & permission_bit
        ctx.check_permission_graph(
            self.permissions_ct.to_account_view(),
            self.permission_bit_ct.to_account_view(),
            self.result_ct.to_account_view(),
        )?;

        self.access_check.set_inner(AccessCheckInner {
            checker: *self.checker.address(),
            result_ct: *self.result_ct.address().as_array(),
            pending_digest: [0u8; 32],
            revealed_result: [0u8; 8],
            bump: 0,
        });
        Ok(())
    }
}

// ── Accounts: request_check_decryption ──

#[derive(Accounts)]
pub struct RequestCheckDecryption {
    #[account(mut)]
    pub access_check: Account<AccessCheck>,

    /// Decryption request account (created by CPI).
    #[account(mut)]
    pub request_acct: UncheckedAccount,

    /// Result ciphertext to decrypt.
    pub result_ciphertext: UncheckedAccount,

    // Encrypt CPI accounts.
    pub encrypt_program: UncheckedAccount,
    pub config: UncheckedAccount,
    #[account(mut)]
    pub deposit: UncheckedAccount,
    pub cpi_authority: UncheckedAccount,
    pub caller_program: UncheckedAccount,
    pub network_encryption_key: UncheckedAccount,
    #[account(mut)]
    pub payer: Signer,
    pub event_authority: UncheckedAccount,
    pub system_program: Program<System>,
}

impl RequestCheckDecryption {
    pub fn handler(&mut self, cpi_authority_bump: u8) -> Result<(), ProgramError> {
        let ctx = EncryptContext {
            encrypt_program: self.encrypt_program.to_account_view(),
            config: self.config.to_account_view(),
            deposit: self.deposit.to_account_view(),
            cpi_authority: self.cpi_authority.to_account_view(),
            caller_program: self.caller_program.to_account_view(),
            network_encryption_key: self.network_encryption_key.to_account_view(),
            payer: self.payer.to_account_view(),
            event_authority: self.event_authority.to_account_view(),
            system_program: self.system_program.to_account_view(),
            cpi_authority_bump,
        };

        let digest = ctx.request_decryption(
            self.request_acct.to_account_view(),
            self.result_ciphertext.to_account_view(),
        )?;

        self.access_check.pending_digest = digest;
        Ok(())
    }
}

// ── Accounts: reveal_check ──

#[derive(Accounts)]
pub struct RevealCheck {
    #[account(mut)]
    pub access_check: Account<AccessCheck>,

    /// Completed decryption request.
    pub request_acct: UncheckedAccount,

    pub checker: Signer,
}

impl RevealCheck {
    pub fn handler(&mut self) -> Result<(), ProgramError> {
        require!(
            self.checker.address() == &self.access_check.checker,
            AclError::NotChecker
        );

        let req_data = unsafe {
            core::slice::from_raw_parts(
                self.request_acct.to_account_view().data_ptr(),
                256,
            )
        };
        let value: &u64 = accounts::read_decrypted_verified::<Uint64>(
            req_data,
            &self.access_check.pending_digest,
        )?;

        self.access_check.revealed_result = value.to_le_bytes();
        Ok(())
    }
}

// ── Accounts: request_permissions_decryption ──

#[derive(Accounts)]
pub struct RequestPermissionsDecryption {
    #[account(mut)]
    pub resource: Account<Resource>,

    /// Decryption request account (created by CPI).
    #[account(mut)]
    pub request_acct: UncheckedAccount,

    /// Permissions ciphertext to decrypt.
    pub permissions_ciphertext: UncheckedAccount,

    // Encrypt CPI accounts.
    pub encrypt_program: UncheckedAccount,
    pub config: UncheckedAccount,
    #[account(mut)]
    pub deposit: UncheckedAccount,
    pub cpi_authority: UncheckedAccount,
    pub caller_program: UncheckedAccount,
    pub network_encryption_key: UncheckedAccount,
    #[account(mut)]
    pub payer: Signer,
    pub event_authority: UncheckedAccount,
    pub system_program: Program<System>,
}

impl RequestPermissionsDecryption {
    pub fn handler(&mut self, cpi_authority_bump: u8) -> Result<(), ProgramError> {
        let ctx = EncryptContext {
            encrypt_program: self.encrypt_program.to_account_view(),
            config: self.config.to_account_view(),
            deposit: self.deposit.to_account_view(),
            cpi_authority: self.cpi_authority.to_account_view(),
            caller_program: self.caller_program.to_account_view(),
            network_encryption_key: self.network_encryption_key.to_account_view(),
            payer: self.payer.to_account_view(),
            event_authority: self.event_authority.to_account_view(),
            system_program: self.system_program.to_account_view(),
            cpi_authority_bump,
        };

        let digest = ctx.request_decryption(
            self.request_acct.to_account_view(),
            self.permissions_ciphertext.to_account_view(),
        )?;

        self.resource.pending_digest = digest;
        Ok(())
    }
}

// ── Accounts: reveal_permissions ──

#[derive(Accounts)]
pub struct RevealPermissions {
    #[account(mut)]
    pub resource: Account<Resource>,

    /// Completed decryption request.
    pub request_acct: UncheckedAccount,

    pub admin: Signer,
}

impl RevealPermissions {
    pub fn handler(&mut self) -> Result<(), ProgramError> {
        require!(
            self.admin.address() == &self.resource.admin,
            AclError::NotAdmin
        );

        let req_data = unsafe {
            core::slice::from_raw_parts(
                self.request_acct.to_account_view().data_ptr(),
                256,
            )
        };
        let value: &u64 = accounts::read_decrypted_verified::<Uint64>(
            req_data,
            &self.resource.pending_digest,
        )?;

        self.resource.revealed_permissions = value.to_le_bytes();
        Ok(())
    }
}
