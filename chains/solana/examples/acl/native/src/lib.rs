// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Encrypted ACL — Native solana-program version.
//!
//! Same FHE ACL logic as the Pinocchio example, but uses solana-program's
//! `AccountInfo` and `EncryptContext` for CPI.
//!
//! On-chain access control where permissions are stored as encrypted bitmasks.
//! Nobody can see the permission state, but operations (grant, revoke, check)
//! are performed via FHE bitwise operations.
//!
//! ## Permission bits
//!
//! bit 0 = READ, bit 1 = WRITE, bit 2 = EXECUTE, bit 3 = ADMIN, etc.
//! All operations work on EUint64 bitmasks.
//!
//! ## Accounts
//!
//! - `Resource` PDA (`["resource", resource_id]`): resource state with encrypted permissions
//! - `AccessCheck` PDA (`["check", resource_id, checker]`): result of a permission check
//!
//! ## Instructions
//!
//! 0. `create_resource` — create a resource with zeroed encrypted permission bitmask
//! 1. `grant_permission` — OR a permission bit into the bitmask
//! 2. `revoke_permission` — AND with inverse mask to clear a permission bit
//! 3. `check_permission` — AND bitmask with permission bit, store encrypted result
//! 4. `request_check_decryption` — request decryption of check result
//! 5. `reveal_check` — read decrypted check result
//! 6. `request_permissions_decryption` — admin requests decryption of full bitmask
//! 7. `reveal_permissions` — read decrypted permissions

use encrypt_dsl::prelude::encrypt_fn;
use encrypt_native::EncryptContext;
use encrypt_types::encrypted::Uint64;
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    msg,
    program::invoke_signed,
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::Rent,
    sysvar::Sysvar,
};
use solana_system_interface::instruction as system_instruction;

entrypoint!(process_instruction);

// ── Account discriminators ──

const RESOURCE: u8 = 1;
const ACCESS_CHECK: u8 = 2;

// ── Account sizes ──
//
// Resource:     disc(1) + admin(32) + resource_id(32) + permissions(32) +
//               pending_digest(32) + revealed_permissions(8) + bump(1) = 138
// AccessCheck:  disc(1) + checker(32) + result_ct(32) + pending_digest(32) +
//               revealed_result(8) + bump(1) = 106

const RESOURCE_LEN: usize = 138;
const ACCESS_CHECK_LEN: usize = 106;

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

// ── Entrypoint ──

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    match data.first() {
        Some(&0) => create_resource(program_id, accounts, &data[1..]),
        Some(&1) => grant_permission(accounts, &data[1..]),
        Some(&2) => revoke_permission(accounts, &data[1..]),
        Some(&3) => check_permission(program_id, accounts, &data[1..]),
        Some(&4) => request_check_decryption(accounts, &data[1..]),
        Some(&5) => reveal_check(accounts),
        Some(&6) => request_permissions_decryption(accounts, &data[1..]),
        Some(&7) => reveal_permissions(accounts),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

// ── 0: create_resource ──
// data: resource_bump(1) | cpi_authority_bump(1) | resource_id(32)

fn create_resource(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    let iter = &mut accounts.iter();
    let resource_acct = next_account_info(iter)?;
    let admin = next_account_info(iter)?;
    let permissions_ct = next_account_info(iter)?;
    let encrypt_program = next_account_info(iter)?;
    let config = next_account_info(iter)?;
    let deposit = next_account_info(iter)?;
    let cpi_authority = next_account_info(iter)?;
    let caller_program = next_account_info(iter)?;
    let network_encryption_key = next_account_info(iter)?;
    let payer = next_account_info(iter)?;
    let event_authority = next_account_info(iter)?;
    let system_program = next_account_info(iter)?;

    if !admin.is_signer || !payer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if data.len() < 34 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let resource_bump = data[0];
    let cpi_authority_bump = data[1];
    let resource_id: [u8; 32] = data[2..34].try_into().unwrap();

    // Create resource PDA
    let seeds = &[b"resource".as_ref(), resource_id.as_ref(), &[resource_bump]];
    let rent = Rent::get()?;
    let lamports = rent.minimum_balance(RESOURCE_LEN);

    invoke_signed(
        &system_instruction::create_account(
            payer.key,
            resource_acct.key,
            lamports,
            RESOURCE_LEN as u64,
            program_id,
        ),
        &[payer.clone(), resource_acct.clone(), system_program.clone()],
        &[seeds],
    )?;

    // Create encrypted zero permissions via CPI
    let ctx = EncryptContext {
        encrypt_program,
        config,
        deposit,
        cpi_authority,
        caller_program,
        network_encryption_key,
        payer,
        event_authority,
        system_program,
        cpi_authority_bump,
    };

    ctx.create_plaintext_typed::<Uint64>(&0u64, permissions_ct)?;

    // Write resource state
    let mut d = resource_acct.try_borrow_mut_data()?;
    d[0] = RESOURCE;
    d[1..33].copy_from_slice(admin.key.as_ref());
    d[33..65].copy_from_slice(&resource_id);
    d[65..97].copy_from_slice(permissions_ct.key.as_ref());
    // pending_digest(97..129) already zeroed
    // revealed_permissions(129..137) already zeroed
    d[137] = resource_bump;

    msg!("Resource created");
    Ok(())
}

// ── 1: grant_permission ──
// data: cpi_authority_bump(1)

fn grant_permission(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let iter = &mut accounts.iter();
    let resource_acct = next_account_info(iter)?;
    let admin = next_account_info(iter)?;
    let permissions_ct = next_account_info(iter)?;
    let permission_bit_ct = next_account_info(iter)?;
    let encrypt_program = next_account_info(iter)?;
    let config = next_account_info(iter)?;
    let deposit = next_account_info(iter)?;
    let cpi_authority = next_account_info(iter)?;
    let caller_program = next_account_info(iter)?;
    let network_encryption_key = next_account_info(iter)?;
    let payer = next_account_info(iter)?;
    let event_authority = next_account_info(iter)?;
    let system_program = next_account_info(iter)?;

    if !admin.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }

    let cpi_authority_bump = data[0];

    // Verify admin and permissions_ct
    let res_data = resource_acct.try_borrow_data()?;
    if res_data[0] != RESOURCE {
        return Err(ProgramError::InvalidAccountData);
    }
    if &res_data[1..33] != admin.key.as_ref() {
        return Err(ProgramError::InvalidArgument);
    }
    if &res_data[65..97] != permissions_ct.key.as_ref() {
        return Err(ProgramError::InvalidArgument);
    }
    drop(res_data);

    let ctx = EncryptContext {
        encrypt_program,
        config,
        deposit,
        cpi_authority,
        caller_program,
        network_encryption_key,
        payer,
        event_authority,
        system_program,
        cpi_authority_bump,
    };

    // permissions = permissions | permission_bit (update mode: output overwrites input)
    ctx.grant_permission_graph(
        permissions_ct.clone(),
        permission_bit_ct.clone(),
        permissions_ct.clone(),
    )?;

    Ok(())
}

// ── 2: revoke_permission ──
// data: cpi_authority_bump(1)

fn revoke_permission(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let iter = &mut accounts.iter();
    let resource_acct = next_account_info(iter)?;
    let admin = next_account_info(iter)?;
    let permissions_ct = next_account_info(iter)?;
    let revoke_mask_ct = next_account_info(iter)?;
    let encrypt_program = next_account_info(iter)?;
    let config = next_account_info(iter)?;
    let deposit = next_account_info(iter)?;
    let cpi_authority = next_account_info(iter)?;
    let caller_program = next_account_info(iter)?;
    let network_encryption_key = next_account_info(iter)?;
    let payer = next_account_info(iter)?;
    let event_authority = next_account_info(iter)?;
    let system_program = next_account_info(iter)?;

    if !admin.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }

    let cpi_authority_bump = data[0];

    // Verify admin and permissions_ct
    let res_data = resource_acct.try_borrow_data()?;
    if res_data[0] != RESOURCE {
        return Err(ProgramError::InvalidAccountData);
    }
    if &res_data[1..33] != admin.key.as_ref() {
        return Err(ProgramError::InvalidArgument);
    }
    if &res_data[65..97] != permissions_ct.key.as_ref() {
        return Err(ProgramError::InvalidArgument);
    }
    drop(res_data);

    let ctx = EncryptContext {
        encrypt_program,
        config,
        deposit,
        cpi_authority,
        caller_program,
        network_encryption_key,
        payer,
        event_authority,
        system_program,
        cpi_authority_bump,
    };

    // permissions = permissions & revoke_mask (update mode)
    ctx.revoke_permission_graph(
        permissions_ct.clone(),
        revoke_mask_ct.clone(),
        permissions_ct.clone(),
    )?;

    Ok(())
}

// ── 3: check_permission ──
// data: check_bump(1) | cpi_authority_bump(1)

fn check_permission(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    let iter = &mut accounts.iter();
    let resource_acct = next_account_info(iter)?;
    let check_acct = next_account_info(iter)?;
    let checker = next_account_info(iter)?;
    let permissions_ct = next_account_info(iter)?;
    let permission_bit_ct = next_account_info(iter)?;
    let result_ct = next_account_info(iter)?;
    let encrypt_program = next_account_info(iter)?;
    let config = next_account_info(iter)?;
    let deposit = next_account_info(iter)?;
    let cpi_authority = next_account_info(iter)?;
    let caller_program = next_account_info(iter)?;
    let network_encryption_key = next_account_info(iter)?;
    let payer = next_account_info(iter)?;
    let event_authority = next_account_info(iter)?;
    let system_program = next_account_info(iter)?;

    if !checker.is_signer || !payer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if data.len() < 2 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let check_bump = data[0];
    let cpi_authority_bump = data[1];

    // Read resource to get resource_id and verify permissions_ct
    let res_data = resource_acct.try_borrow_data()?;
    if res_data[0] != RESOURCE {
        return Err(ProgramError::InvalidAccountData);
    }
    let resource_id: [u8; 32] = res_data[33..65].try_into().unwrap();
    if &res_data[65..97] != permissions_ct.key.as_ref() {
        return Err(ProgramError::InvalidArgument);
    }
    drop(res_data);

    // Create AccessCheck PDA
    let seeds = &[
        b"check".as_ref(),
        resource_id.as_ref(),
        checker.key.as_ref(),
        &[check_bump],
    ];
    let rent = Rent::get()?;
    let lamports = rent.minimum_balance(ACCESS_CHECK_LEN);

    invoke_signed(
        &system_instruction::create_account(
            payer.key,
            check_acct.key,
            lamports,
            ACCESS_CHECK_LEN as u64,
            program_id,
        ),
        &[payer.clone(), check_acct.clone(), system_program.clone()],
        &[seeds],
    )?;

    let ctx = EncryptContext {
        encrypt_program,
        config,
        deposit,
        cpi_authority,
        caller_program,
        network_encryption_key,
        payer,
        event_authority,
        system_program,
        cpi_authority_bump,
    };

    // Use u64::MAX as sentinel so the mock digest differs from any real result.
    ctx.create_plaintext_typed::<Uint64>(&u64::MAX, result_ct)?;

    // result = permissions & permission_bit
    ctx.check_permission_graph(
        permissions_ct.clone(),
        permission_bit_ct.clone(),
        result_ct.clone(),
    )?;

    // Write check state
    let mut d = check_acct.try_borrow_mut_data()?;
    d[0] = ACCESS_CHECK;
    d[1..33].copy_from_slice(checker.key.as_ref());
    d[33..65].copy_from_slice(result_ct.key.as_ref());
    // pending_digest(65..97) already zeroed
    // revealed_result(97..105) already zeroed
    d[105] = check_bump;

    msg!("Permission check created");
    Ok(())
}

// ── 4: request_check_decryption ──
// data: cpi_authority_bump(1)

fn request_check_decryption(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let iter = &mut accounts.iter();
    let check_acct = next_account_info(iter)?;
    let request_acct = next_account_info(iter)?;
    let result_ciphertext = next_account_info(iter)?;
    let encrypt_program = next_account_info(iter)?;
    let config = next_account_info(iter)?;
    let deposit = next_account_info(iter)?;
    let cpi_authority = next_account_info(iter)?;
    let caller_program = next_account_info(iter)?;
    let network_encryption_key = next_account_info(iter)?;
    let payer = next_account_info(iter)?;
    let event_authority = next_account_info(iter)?;
    let system_program = next_account_info(iter)?;

    if !payer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }

    let cpi_authority_bump = data[0];

    let ctx = EncryptContext {
        encrypt_program,
        config,
        deposit,
        cpi_authority,
        caller_program,
        network_encryption_key,
        payer,
        event_authority,
        system_program,
        cpi_authority_bump,
    };

    let digest = ctx.request_decryption(request_acct, result_ciphertext)?;

    let mut d = check_acct.try_borrow_mut_data()?;
    if d[0] != ACCESS_CHECK {
        return Err(ProgramError::InvalidAccountData);
    }
    d[65..97].copy_from_slice(&digest);

    Ok(())
}

// ── 5: reveal_check ──
// accounts: [check_pda(w), request_acct, checker(s)]

fn reveal_check(accounts: &[AccountInfo]) -> ProgramResult {
    let iter = &mut accounts.iter();
    let check_acct = next_account_info(iter)?;
    let request_acct = next_account_info(iter)?;
    let checker = next_account_info(iter)?;

    if !checker.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Verify checker
    let chk_data = check_acct.try_borrow_data()?;
    if chk_data[0] != ACCESS_CHECK {
        return Err(ProgramError::InvalidAccountData);
    }
    if &chk_data[1..33] != checker.key.as_ref() {
        return Err(ProgramError::InvalidArgument);
    }

    let expected_digest: [u8; 32] = chk_data[65..97].try_into().unwrap();
    drop(chk_data);

    let req_data = request_acct.try_borrow_data()?;
    let value = encrypt_native::accounts::read_decrypted_verified::<Uint64>(
        &req_data,
        &expected_digest,
    )?;

    let mut d = check_acct.try_borrow_mut_data()?;
    d[97..105].copy_from_slice(&value.to_le_bytes());

    msg!("Check revealed: {}", value);
    Ok(())
}

// ── 6: request_permissions_decryption ──
// data: cpi_authority_bump(1)

fn request_permissions_decryption(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let iter = &mut accounts.iter();
    let resource_acct = next_account_info(iter)?;
    let request_acct = next_account_info(iter)?;
    let permissions_ciphertext = next_account_info(iter)?;
    let encrypt_program = next_account_info(iter)?;
    let config = next_account_info(iter)?;
    let deposit = next_account_info(iter)?;
    let cpi_authority = next_account_info(iter)?;
    let caller_program = next_account_info(iter)?;
    let network_encryption_key = next_account_info(iter)?;
    let payer = next_account_info(iter)?;
    let event_authority = next_account_info(iter)?;
    let system_program = next_account_info(iter)?;

    if !payer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }

    let cpi_authority_bump = data[0];

    let ctx = EncryptContext {
        encrypt_program,
        config,
        deposit,
        cpi_authority,
        caller_program,
        network_encryption_key,
        payer,
        event_authority,
        system_program,
        cpi_authority_bump,
    };

    let digest = ctx.request_decryption(request_acct, permissions_ciphertext)?;

    let mut d = resource_acct.try_borrow_mut_data()?;
    if d[0] != RESOURCE {
        return Err(ProgramError::InvalidAccountData);
    }
    d[97..129].copy_from_slice(&digest);

    Ok(())
}

// ── 7: reveal_permissions ──
// accounts: [resource(w), request_acct, admin(s)]

fn reveal_permissions(accounts: &[AccountInfo]) -> ProgramResult {
    let iter = &mut accounts.iter();
    let resource_acct = next_account_info(iter)?;
    let request_acct = next_account_info(iter)?;
    let admin = next_account_info(iter)?;

    if !admin.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Verify admin
    let res_data = resource_acct.try_borrow_data()?;
    if res_data[0] != RESOURCE {
        return Err(ProgramError::InvalidAccountData);
    }
    if &res_data[1..33] != admin.key.as_ref() {
        return Err(ProgramError::InvalidArgument);
    }

    let expected_digest: [u8; 32] = res_data[97..129].try_into().unwrap();
    drop(res_data);

    let req_data = request_acct.try_borrow_data()?;
    let value = encrypt_native::accounts::read_decrypted_verified::<Uint64>(
        &req_data,
        &expected_digest,
    )?;

    let mut d = resource_acct.try_borrow_mut_data()?;
    d[129..137].copy_from_slice(&value.to_le_bytes());

    msg!("Permissions revealed: {}", value);
    Ok(())
}

// ── Tests ──

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
