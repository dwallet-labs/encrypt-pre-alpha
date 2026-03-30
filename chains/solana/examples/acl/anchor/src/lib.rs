// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Encrypted ACL — Anchor version.
//!
//! Same FHE ACL logic as the Pinocchio example, but uses the Anchor
//! framework and `EncryptContext` for CPI.
//!
//! On-chain access control where permissions are stored as encrypted bitmasks.
//! Nobody can see the permission state, but operations (grant, revoke, check)
//! are performed via FHE bitwise operations.
//!
//! ## Permission bits
//!
//! bit 0 = READ, bit 1 = WRITE, bit 2 = EXECUTE, bit 3 = ADMIN, etc.
//! All operations work on EUint64 bitmasks.

use anchor_lang::prelude::*;
use encrypt_anchor::EncryptContext;
use encrypt_dsl::prelude::encrypt_fn;
#[allow(unused_imports)]
use encrypt_types::encrypted::EUint64;

declare_id!("US517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx");

// ── FHE Graphs ──

/// Grant: permissions = permissions | permission_bit
#[encrypt_fn]
fn grant_permission_graph(permissions: EUint64, permission_bit: EUint64) -> EUint64 {
    permissions | permission_bit
}

/// Revoke: permissions = permissions & revoke_mask
///
/// The caller passes the inverse mask (all bits set except the one to revoke).
/// For example, to revoke READ (bit 0): revoke_mask = 0xFFFFFFFFFFFFFFFE.
#[encrypt_fn]
fn revoke_permission_graph(permissions: EUint64, revoke_mask: EUint64) -> EUint64 {
    permissions & revoke_mask
}

/// Check: result = permissions & permission_bit (nonzero means has permission)
#[encrypt_fn]
fn check_permission_graph(permissions: EUint64, permission_bit: EUint64) -> EUint64 {
    permissions & permission_bit
}

// ── State ──

#[account]
#[derive(InitSpace)]
pub struct Resource {
    pub admin: Pubkey,
    pub resource_id: [u8; 32],
    pub permissions: [u8; 32],       // ciphertext pubkey
    pub pending_digest: [u8; 32],
    pub revealed_permissions: u64,
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct AccessCheck {
    pub checker: Pubkey,
    pub result_ct: [u8; 32],         // ciphertext pubkey
    pub pending_digest: [u8; 32],
    pub revealed_result: u64,
    pub bump: u8,
}

// ── Instructions ──

#[program]
pub mod encrypted_acl {
    use super::*;

    pub fn create_resource(
        ctx: Context<CreateResource>,
        resource_id: [u8; 32],
        permissions_ct_id: [u8; 32],
    ) -> Result<()> {
        let res = &mut ctx.accounts.resource;
        res.admin = ctx.accounts.admin.key();
        res.resource_id = resource_id;
        res.permissions = permissions_ct_id;
        res.pending_digest = [0u8; 32];
        res.revealed_permissions = 0;
        res.bump = ctx.bumps.resource;
        Ok(())
    }

    pub fn grant_permission(
        ctx: Context<GrantPermission>,
        cpi_authority_bump: u8,
    ) -> Result<()> {
        let res = &ctx.accounts.resource;
        require!(
            res.admin == ctx.accounts.admin.key(),
            AclError::Unauthorized
        );

        let encrypt_ctx = EncryptContext {
            encrypt_program: ctx.accounts.encrypt_program.to_account_info(),
            config: ctx.accounts.config.to_account_info(),
            deposit: ctx.accounts.deposit.to_account_info(),
            cpi_authority: ctx.accounts.cpi_authority.to_account_info(),
            caller_program: ctx.accounts.caller_program.to_account_info(),
            network_encryption_key: ctx.accounts.network_encryption_key.to_account_info(),
            payer: ctx.accounts.payer.to_account_info(),
            event_authority: ctx.accounts.event_authority.to_account_info(),
            system_program: ctx.accounts.system_program.to_account_info(),
            cpi_authority_bump,
        };

        let permissions_ct = ctx.accounts.permissions_ct.to_account_info();
        let permission_bit_ct = ctx.accounts.permission_bit_ct.to_account_info();
        encrypt_ctx.grant_permission_graph(
            permissions_ct.clone(),
            permission_bit_ct,
            permissions_ct,
        )?;

        Ok(())
    }

    pub fn revoke_permission(
        ctx: Context<RevokePermission>,
        cpi_authority_bump: u8,
    ) -> Result<()> {
        let res = &ctx.accounts.resource;
        require!(
            res.admin == ctx.accounts.admin.key(),
            AclError::Unauthorized
        );

        let encrypt_ctx = EncryptContext {
            encrypt_program: ctx.accounts.encrypt_program.to_account_info(),
            config: ctx.accounts.config.to_account_info(),
            deposit: ctx.accounts.deposit.to_account_info(),
            cpi_authority: ctx.accounts.cpi_authority.to_account_info(),
            caller_program: ctx.accounts.caller_program.to_account_info(),
            network_encryption_key: ctx.accounts.network_encryption_key.to_account_info(),
            payer: ctx.accounts.payer.to_account_info(),
            event_authority: ctx.accounts.event_authority.to_account_info(),
            system_program: ctx.accounts.system_program.to_account_info(),
            cpi_authority_bump,
        };

        let permissions_ct = ctx.accounts.permissions_ct.to_account_info();
        let revoke_mask_ct = ctx.accounts.revoke_mask_ct.to_account_info();
        encrypt_ctx.revoke_permission_graph(
            permissions_ct.clone(),
            revoke_mask_ct,
            permissions_ct,
        )?;

        Ok(())
    }

    pub fn check_permission(
        ctx: Context<CheckPermission>,
        cpi_authority_bump: u8,
    ) -> Result<()> {
        let encrypt_ctx = EncryptContext {
            encrypt_program: ctx.accounts.encrypt_program.to_account_info(),
            config: ctx.accounts.config.to_account_info(),
            deposit: ctx.accounts.deposit.to_account_info(),
            cpi_authority: ctx.accounts.cpi_authority.to_account_info(),
            caller_program: ctx.accounts.caller_program.to_account_info(),
            network_encryption_key: ctx.accounts.network_encryption_key.to_account_info(),
            payer: ctx.accounts.payer.to_account_info(),
            event_authority: ctx.accounts.event_authority.to_account_info(),
            system_program: ctx.accounts.system_program.to_account_info(),
            cpi_authority_bump,
        };

        let permissions_ct = ctx.accounts.permissions_ct.to_account_info();
        let permission_bit_ct = ctx.accounts.permission_bit_ct.to_account_info();
        let result_ct = ctx.accounts.result_ct.to_account_info();
        encrypt_ctx.check_permission_graph(
            permissions_ct,
            permission_bit_ct,
            result_ct,
        )?;

        // Write check state
        let chk = &mut ctx.accounts.access_check;
        chk.checker = ctx.accounts.checker.key();
        chk.result_ct = ctx.accounts.result_ct.key().to_bytes();
        chk.pending_digest = [0u8; 32];
        chk.revealed_result = 0;
        chk.bump = ctx.bumps.access_check;

        Ok(())
    }

    pub fn request_check_decryption(
        ctx: Context<RequestCheckDecryption>,
        cpi_authority_bump: u8,
    ) -> Result<()> {
        let encrypt_ctx = EncryptContext {
            encrypt_program: ctx.accounts.encrypt_program.to_account_info(),
            config: ctx.accounts.config.to_account_info(),
            deposit: ctx.accounts.deposit.to_account_info(),
            cpi_authority: ctx.accounts.cpi_authority.to_account_info(),
            caller_program: ctx.accounts.caller_program.to_account_info(),
            network_encryption_key: ctx.accounts.network_encryption_key.to_account_info(),
            payer: ctx.accounts.payer.to_account_info(),
            event_authority: ctx.accounts.event_authority.to_account_info(),
            system_program: ctx.accounts.system_program.to_account_info(),
            cpi_authority_bump,
        };

        let digest = encrypt_ctx.request_decryption(
            &ctx.accounts.request_acct.to_account_info(),
            &ctx.accounts.result_ciphertext.to_account_info(),
        )?;

        let chk = &mut ctx.accounts.access_check;
        chk.pending_digest = digest;

        Ok(())
    }

    pub fn reveal_check(ctx: Context<RevealCheck>) -> Result<()> {
        let chk = &ctx.accounts.access_check;
        require!(
            chk.checker == ctx.accounts.checker.key(),
            AclError::Unauthorized
        );

        let expected_digest = &chk.pending_digest;
        let req_data = ctx.accounts.request_acct.try_borrow_data()?;
        use encrypt_types::encrypted::Uint64;
        let value = encrypt_anchor::accounts::read_decrypted_verified::<Uint64>(
            &req_data,
            expected_digest,
        )
        .map_err(|_| AclError::DecryptionNotComplete)?;

        let chk = &mut ctx.accounts.access_check;
        chk.revealed_result = *value;

        Ok(())
    }

    pub fn request_permissions_decryption(
        ctx: Context<RequestPermissionsDecryption>,
        cpi_authority_bump: u8,
    ) -> Result<()> {
        let encrypt_ctx = EncryptContext {
            encrypt_program: ctx.accounts.encrypt_program.to_account_info(),
            config: ctx.accounts.config.to_account_info(),
            deposit: ctx.accounts.deposit.to_account_info(),
            cpi_authority: ctx.accounts.cpi_authority.to_account_info(),
            caller_program: ctx.accounts.caller_program.to_account_info(),
            network_encryption_key: ctx.accounts.network_encryption_key.to_account_info(),
            payer: ctx.accounts.payer.to_account_info(),
            event_authority: ctx.accounts.event_authority.to_account_info(),
            system_program: ctx.accounts.system_program.to_account_info(),
            cpi_authority_bump,
        };

        let digest = encrypt_ctx.request_decryption(
            &ctx.accounts.request_acct.to_account_info(),
            &ctx.accounts.permissions_ciphertext.to_account_info(),
        )?;

        let res = &mut ctx.accounts.resource;
        res.pending_digest = digest;

        Ok(())
    }

    pub fn reveal_permissions(ctx: Context<RevealPermissions>) -> Result<()> {
        let res = &ctx.accounts.resource;
        require!(
            res.admin == ctx.accounts.admin.key(),
            AclError::Unauthorized
        );

        let expected_digest = &res.pending_digest;
        let req_data = ctx.accounts.request_acct.try_borrow_data()?;
        use encrypt_types::encrypted::Uint64;
        let value = encrypt_anchor::accounts::read_decrypted_verified::<Uint64>(
            &req_data,
            expected_digest,
        )
        .map_err(|_| AclError::DecryptionNotComplete)?;

        let res = &mut ctx.accounts.resource;
        res.revealed_permissions = *value;

        Ok(())
    }
}

// ── Accounts ──

#[derive(Accounts)]
#[instruction(resource_id: [u8; 32])]
pub struct CreateResource<'info> {
    #[account(
        init,
        payer = payer,
        space = 8 + Resource::INIT_SPACE,
        seeds = [b"resource", resource_id.as_ref()],
        bump,
    )]
    pub resource: Account<'info, Resource>,
    pub admin: Signer<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct GrantPermission<'info> {
    #[account(mut)]
    pub resource: Account<'info, Resource>,
    pub admin: Signer<'info>,
    /// CHECK: Permissions ciphertext account
    #[account(mut)]
    pub permissions_ct: UncheckedAccount<'info>,
    /// CHECK: Permission bit ciphertext account
    pub permission_bit_ct: UncheckedAccount<'info>,
    /// CHECK: Encrypt program
    pub encrypt_program: UncheckedAccount<'info>,
    /// CHECK: Encrypt config
    pub config: UncheckedAccount<'info>,
    /// CHECK: Encrypt deposit
    #[account(mut)]
    pub deposit: UncheckedAccount<'info>,
    /// CHECK: CPI authority PDA
    pub cpi_authority: UncheckedAccount<'info>,
    /// CHECK: Caller program
    pub caller_program: UncheckedAccount<'info>,
    /// CHECK: Network encryption key
    pub network_encryption_key: UncheckedAccount<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    /// CHECK: Event authority PDA
    pub event_authority: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RevokePermission<'info> {
    #[account(mut)]
    pub resource: Account<'info, Resource>,
    pub admin: Signer<'info>,
    /// CHECK: Permissions ciphertext account
    #[account(mut)]
    pub permissions_ct: UncheckedAccount<'info>,
    /// CHECK: Revoke mask ciphertext account
    pub revoke_mask_ct: UncheckedAccount<'info>,
    /// CHECK: Encrypt program
    pub encrypt_program: UncheckedAccount<'info>,
    /// CHECK: Encrypt config
    pub config: UncheckedAccount<'info>,
    /// CHECK: Encrypt deposit
    #[account(mut)]
    pub deposit: UncheckedAccount<'info>,
    /// CHECK: CPI authority PDA
    pub cpi_authority: UncheckedAccount<'info>,
    /// CHECK: Caller program
    pub caller_program: UncheckedAccount<'info>,
    /// CHECK: Network encryption key
    pub network_encryption_key: UncheckedAccount<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    /// CHECK: Event authority PDA
    pub event_authority: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct CheckPermission<'info> {
    pub resource: Account<'info, Resource>,
    #[account(
        init,
        payer = payer,
        space = 8 + AccessCheck::INIT_SPACE,
        seeds = [b"check", resource.resource_id.as_ref(), checker.key().as_ref()],
        bump,
    )]
    pub access_check: Account<'info, AccessCheck>,
    pub checker: Signer<'info>,
    /// CHECK: Permissions ciphertext account
    pub permissions_ct: UncheckedAccount<'info>,
    /// CHECK: Permission bit ciphertext account
    pub permission_bit_ct: UncheckedAccount<'info>,
    /// CHECK: Result ciphertext account
    #[account(mut)]
    pub result_ct: UncheckedAccount<'info>,
    /// CHECK: Encrypt program
    pub encrypt_program: UncheckedAccount<'info>,
    /// CHECK: Encrypt config
    pub config: UncheckedAccount<'info>,
    /// CHECK: Encrypt deposit
    #[account(mut)]
    pub deposit: UncheckedAccount<'info>,
    /// CHECK: CPI authority PDA
    pub cpi_authority: UncheckedAccount<'info>,
    /// CHECK: Caller program
    pub caller_program: UncheckedAccount<'info>,
    /// CHECK: Network encryption key
    pub network_encryption_key: UncheckedAccount<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    /// CHECK: Event authority PDA
    pub event_authority: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RequestCheckDecryption<'info> {
    #[account(mut)]
    pub access_check: Account<'info, AccessCheck>,
    /// CHECK: Decryption request account (created by encrypt program)
    #[account(mut)]
    pub request_acct: UncheckedAccount<'info>,
    /// CHECK: Result ciphertext account
    pub result_ciphertext: UncheckedAccount<'info>,
    /// CHECK: Encrypt program
    pub encrypt_program: UncheckedAccount<'info>,
    /// CHECK: Encrypt config
    pub config: UncheckedAccount<'info>,
    /// CHECK: Encrypt deposit
    #[account(mut)]
    pub deposit: UncheckedAccount<'info>,
    /// CHECK: CPI authority PDA
    pub cpi_authority: UncheckedAccount<'info>,
    /// CHECK: Caller program
    pub caller_program: UncheckedAccount<'info>,
    /// CHECK: Network encryption key
    pub network_encryption_key: UncheckedAccount<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    /// CHECK: Event authority PDA
    pub event_authority: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RevealCheck<'info> {
    #[account(mut)]
    pub access_check: Account<'info, AccessCheck>,
    /// CHECK: Completed decryption request account
    pub request_acct: UncheckedAccount<'info>,
    pub checker: Signer<'info>,
}

#[derive(Accounts)]
pub struct RequestPermissionsDecryption<'info> {
    #[account(mut)]
    pub resource: Account<'info, Resource>,
    /// CHECK: Decryption request account (created by encrypt program)
    #[account(mut)]
    pub request_acct: UncheckedAccount<'info>,
    /// CHECK: Permissions ciphertext account
    pub permissions_ciphertext: UncheckedAccount<'info>,
    /// CHECK: Encrypt program
    pub encrypt_program: UncheckedAccount<'info>,
    /// CHECK: Encrypt config
    pub config: UncheckedAccount<'info>,
    /// CHECK: Encrypt deposit
    #[account(mut)]
    pub deposit: UncheckedAccount<'info>,
    /// CHECK: CPI authority PDA
    pub cpi_authority: UncheckedAccount<'info>,
    /// CHECK: Caller program
    pub caller_program: UncheckedAccount<'info>,
    /// CHECK: Network encryption key
    pub network_encryption_key: UncheckedAccount<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    /// CHECK: Event authority PDA
    pub event_authority: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RevealPermissions<'info> {
    #[account(mut)]
    pub resource: Account<'info, Resource>,
    /// CHECK: Completed decryption request account
    pub request_acct: UncheckedAccount<'info>,
    pub admin: Signer<'info>,
}

// ── Errors ──

#[error_code]
pub enum AclError {
    #[msg("Unauthorized")]
    Unauthorized,
    #[msg("Decryption not complete")]
    DecryptionNotComplete,
}

#[cfg(test)]
mod tests {
    use encrypt_dsl::prelude::*;
    use encrypt_types::graph::{get_node, parse_graph, GraphNodeKind};
    use encrypt_types::identifier::*;
    use encrypt_types::types::FheType;

    use super::{check_permission_graph, grant_permission_graph, revoke_permission_graph};

    fn run_mock(graph_fn: fn() -> Vec<u8>, inputs: &[u128], fhe_types: &[FheType]) -> Vec<u128> {
        let data = graph_fn();
        let pg = parse_graph(&data).unwrap();
        let num = pg.header().num_nodes() as usize;
        let mut digests: Vec<[u8; 32]> = Vec::with_capacity(num);
        let mut inp = 0usize;

        for i in 0..num {
            let n = get_node(pg.node_bytes(), i as u16).unwrap();
            let ft = FheType::from_u8(n.fhe_type()).unwrap_or(FheType::EUint64);

            let d = match n.kind() {
                k if k == GraphNodeKind::Input as u8 => {
                    let v = inputs[inp];
                    let t = fhe_types[inp];
                    inp += 1;
                    encode_mock_digest(t, v)
                }
                k if k == GraphNodeKind::Constant as u8 => {
                    let bw = ft.byte_width().min(16);
                    let off = n.const_offset() as usize;
                    let mut buf = [0u8; 16];
                    buf[..bw].copy_from_slice(&pg.constants()[off..off + bw]);
                    encode_mock_digest(ft, u128::from_le_bytes(buf))
                }
                k if k == GraphNodeKind::Op as u8 => {
                    let (a, b, c) = (
                        n.input_a() as usize,
                        n.input_b() as usize,
                        n.input_c() as usize,
                    );
                    if n.op_type() == 60 {
                        mock_select(&digests[a], &digests[b], &digests[c])
                    } else if b == 0xFFFF {
                        mock_unary_compute(
                            unsafe {
                                core::mem::transmute::<u8, encrypt_types::types::FheOperation>(
                                    n.op_type(),
                                )
                            },
                            &digests[a],
                            ft,
                        )
                    } else {
                        mock_binary_compute(
                            unsafe {
                                core::mem::transmute::<u8, encrypt_types::types::FheOperation>(
                                    n.op_type(),
                                )
                            },
                            &digests[a],
                            &digests[b],
                            ft,
                        )
                    }
                }
                k if k == GraphNodeKind::Output as u8 => digests[n.input_a() as usize],
                _ => panic!("bad node"),
            };
            digests.push(d);
        }

        (0..num)
            .filter(|&i| {
                get_node(pg.node_bytes(), i as u16).unwrap().kind()
                    == GraphNodeKind::Output as u8
            })
            .map(|i| decode_mock_identifier(&digests[i]))
            .collect()
    }

    #[test]
    fn grant_single_permission() {
        let r = run_mock(
            grant_permission_graph,
            &[0, 1],
            &[FheType::EUint64, FheType::EUint64],
        );
        assert_eq!(r[0], 1, "granting READ (bit 0) to 0 should yield 1");
    }

    #[test]
    fn grant_multiple_permissions() {
        let r = run_mock(
            grant_permission_graph,
            &[1, 2],
            &[FheType::EUint64, FheType::EUint64],
        );
        assert_eq!(r[0], 3, "granting WRITE (bit 1) to READ (1) should yield 3");
    }

    #[test]
    fn revoke_permission() {
        let r = run_mock(
            revoke_permission_graph,
            &[3, 0xFFFFFFFFFFFFFFFE],
            &[FheType::EUint64, FheType::EUint64],
        );
        assert_eq!(r[0], 2, "revoking READ (bit 0) from 3 should yield 2");
    }

    #[test]
    fn check_has_permission() {
        let r = run_mock(
            check_permission_graph,
            &[5, 1],
            &[FheType::EUint64, FheType::EUint64],
        );
        assert_eq!(r[0], 1, "checking READ on 5 (READ|EXECUTE) should yield 1");
    }

    #[test]
    fn check_missing_permission() {
        let r = run_mock(
            check_permission_graph,
            &[4, 1],
            &[FheType::EUint64, FheType::EUint64],
        );
        assert_eq!(r[0], 0, "checking READ on 4 (EXECUTE only) should yield 0");
    }

    #[test]
    fn graph_shapes() {
        let d = grant_permission_graph();
        let pg = parse_graph(&d).unwrap();
        assert_eq!(pg.header().num_inputs(), 2, "grant: 2 inputs");
        assert_eq!(pg.header().num_outputs(), 1, "grant: 1 output");

        let d = revoke_permission_graph();
        let pg = parse_graph(&d).unwrap();
        assert_eq!(pg.header().num_inputs(), 2, "revoke: 2 inputs");
        assert_eq!(pg.header().num_outputs(), 1, "revoke: 1 output");

        let d = check_permission_graph();
        let pg = parse_graph(&d).unwrap();
        assert_eq!(pg.header().num_inputs(), 2, "check: 2 inputs");
        assert_eq!(pg.header().num_outputs(), 1, "check: 1 output");
    }
}
