// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#![allow(unexpected_cfgs)]

/// Encrypted ACL — A Solana program using the Encrypt DSL.
///
/// On-chain access control where permissions are stored as encrypted bitmasks.
/// Nobody can see the permission state, but operations (grant, revoke, check)
/// are performed via FHE bitwise operations.
///
/// ## Permission bits
///
/// bit 0 = READ, bit 1 = WRITE, bit 2 = EXECUTE, bit 3 = ADMIN, etc.
/// All operations work on EUint64 bitmasks.
///
/// ## Accounts
///
/// - `Resource` PDA (`["resource", resource_id]`): resource state with encrypted permissions
/// - `AccessCheck` PDA (`["check", resource_id, checker]`): result of a permission check
///
/// ## Instructions
///
/// 0. `create_resource` — create a resource with zeroed encrypted permission bitmask
/// 1. `grant_permission` — OR a permission bit into the bitmask
/// 2. `revoke_permission` — AND with inverse mask to clear a permission bit
/// 3. `check_permission` — AND bitmask with permission bit, store encrypted result
/// 4. `request_check_decryption` — request decryption of check result
/// 5. `reveal_check` — read decrypted check result
/// 6. `request_permissions_decryption` — admin requests decryption of full bitmask
/// 7. `reveal_permissions` — read decrypted permissions
use encrypt_dsl::prelude::encrypt_fn;
use encrypt_pinocchio::accounts::{self};
use encrypt_pinocchio::EncryptContext;
use encrypt_types::encrypted::{EUint64, Uint64};
use pinocchio::{
    cpi::{Seed, Signer},
    entrypoint,
    error::ProgramError,
    AccountView, Address, ProgramResult,
};
use pinocchio_system::instructions::CreateAccount;

entrypoint!(process_instruction);

pub const ID: Address = Address::new_from_array([6u8; 32]);

// ── Account discriminators ──

const RESOURCE: u8 = 1;
const ACCESS_CHECK: u8 = 2;

// ── Account layouts ──

/// Resource state — PDA seeds: `["resource", resource_id]`
///
/// `permissions` is an encrypted bitmask (EUint64).
#[repr(C)]
pub struct Resource {
    pub discriminator: u8,              // [0]
    pub admin: [u8; 32],               // [1..33]
    pub resource_id: [u8; 32],         // [33..65]
    pub permissions: EUint64,           // [65..97] — encrypted permission bitmask
    pub pending_digest: [u8; 32],      // [97..129] — for decryption verification
    pub revealed_permissions: [u8; 8], // [129..137] — plaintext after admin decryption
    pub bump: u8,                      // [137]
}

impl Resource {
    pub const LEN: usize = core::mem::size_of::<Self>();

    pub fn from_bytes(data: &[u8]) -> Result<&Self, ProgramError> {
        if data.len() < Self::LEN || data[0] != RESOURCE {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(unsafe { &*(data.as_ptr() as *const Self) })
    }

    pub fn from_bytes_mut(data: &mut [u8]) -> Result<&mut Self, ProgramError> {
        if data.len() < Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(unsafe { &mut *(data.as_mut_ptr() as *mut Self) })
    }
}

/// Access check result — PDA seeds: `["check", resource_id, checker]`
///
/// `result_ct` is the encrypted AND result (nonzero = has permission).
#[repr(C)]
pub struct AccessCheck {
    pub discriminator: u8,             // [0]
    pub checker: [u8; 32],            // [1..33]
    pub result_ct: EUint64,           // [33..65] — encrypted AND result
    pub pending_digest: [u8; 32],     // [65..97]
    pub revealed_result: [u8; 8],     // [97..105] — plaintext result after decryption
    pub bump: u8,                     // [105]
}

impl AccessCheck {
    pub const LEN: usize = core::mem::size_of::<Self>();

    pub fn from_bytes(data: &[u8]) -> Result<&Self, ProgramError> {
        if data.len() < Self::LEN || data[0] != ACCESS_CHECK {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(unsafe { &*(data.as_ptr() as *const Self) })
    }

    pub fn from_bytes_mut(data: &mut [u8]) -> Result<&mut Self, ProgramError> {
        if data.len() < Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(unsafe { &mut *(data.as_mut_ptr() as *mut Self) })
    }
}

// ── Rent helper ──

fn minimum_balance(size: usize) -> u64 {
    (size as u64 + 128) * 6960
}

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

// ── Instruction dispatch ──

fn process_instruction(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    match data.split_first() {
        Some((&0, rest)) => create_resource(program_id, accounts, rest),
        Some((&1, rest)) => grant_permission(accounts, rest),
        Some((&2, rest)) => revoke_permission(accounts, rest),
        Some((&3, rest)) => check_permission(program_id, accounts, rest),
        Some((&4, rest)) => request_check_decryption(accounts, rest),
        Some((&5, _rest)) => reveal_check(accounts),
        Some((&6, rest)) => request_permissions_decryption(accounts, rest),
        Some((&7, _rest)) => reveal_permissions(accounts),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

// ── 0: create_resource ──
// data: resource_bump(1) | cpi_authority_bump(1) | resource_id(32)
// accounts: [resource_pda(w), admin(s), permissions_ct(w),
//            encrypt_program, config, deposit(w), cpi_authority,
//            caller_program, network_encryption_key, payer(s,w),
//            event_authority, system_program]

fn create_resource(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    let [resource_acct, admin, permissions_ct, encrypt_program, config, deposit, cpi_authority, caller_program, network_encryption_key, payer, event_authority, system_program, ..] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !admin.is_signer() || !payer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if data.len() < 34 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let resource_bump = data[0];
    let cpi_authority_bump = data[1];
    let resource_id: [u8; 32] = data[2..34].try_into().unwrap();

    // Create resource PDA
    let bump_byte = [resource_bump];
    let seeds = [
        Seed::from(b"resource" as &[u8]),
        Seed::from(resource_id.as_ref()),
        Seed::from(&bump_byte),
    ];
    let signer = [Signer::from(&seeds)];

    CreateAccount {
        from: payer,
        to: resource_acct,
        lamports: minimum_balance(Resource::LEN),
        space: Resource::LEN as u64,
        owner: program_id,
    }
    .invoke_signed(&signer)?;

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
    let d = unsafe { resource_acct.borrow_unchecked_mut() };
    let res = Resource::from_bytes_mut(d)?;
    res.discriminator = RESOURCE;
    res.admin.copy_from_slice(admin.address().as_ref());
    res.resource_id.copy_from_slice(&resource_id);
    res.permissions = EUint64::from_le_bytes(*permissions_ct.address().as_array());
    res.pending_digest = [0u8; 32];
    res.revealed_permissions = [0u8; 8];
    res.bump = resource_bump;
    Ok(())
}

// ── 1: grant_permission ──
// data: cpi_authority_bump(1)
// accounts: [resource(w), admin(s), permissions_ct(w), permission_bit_ct,
//            encrypt_program, config, deposit(w), cpi_authority,
//            caller_program, network_encryption_key, payer(s,w),
//            event_authority, system_program]

fn grant_permission(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [resource_acct, admin, permissions_ct, permission_bit_ct, encrypt_program, config, deposit, cpi_authority, caller_program, network_encryption_key, payer, event_authority, system_program, ..] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !admin.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }

    let cpi_authority_bump = data[0];

    // Verify admin
    let res_data = unsafe { resource_acct.borrow_unchecked() };
    let res = Resource::from_bytes(res_data)?;
    if admin.address().as_array() != &res.admin {
        return Err(ProgramError::InvalidArgument);
    }
    // Verify permissions_ct matches resource
    if permissions_ct.address().as_array() != res.permissions.id() {
        return Err(ProgramError::InvalidArgument);
    }

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
    ctx.grant_permission_graph(permissions_ct, permission_bit_ct, permissions_ct)?;

    Ok(())
}

// ── 2: revoke_permission ──
// data: cpi_authority_bump(1)
// accounts: [resource(w), admin(s), permissions_ct(w), revoke_mask_ct,
//            encrypt_program, config, deposit(w), cpi_authority,
//            caller_program, network_encryption_key, payer(s,w),
//            event_authority, system_program]

fn revoke_permission(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [resource_acct, admin, permissions_ct, revoke_mask_ct, encrypt_program, config, deposit, cpi_authority, caller_program, network_encryption_key, payer, event_authority, system_program, ..] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !admin.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }

    let cpi_authority_bump = data[0];

    // Verify admin
    let res_data = unsafe { resource_acct.borrow_unchecked() };
    let res = Resource::from_bytes(res_data)?;
    if admin.address().as_array() != &res.admin {
        return Err(ProgramError::InvalidArgument);
    }
    // Verify permissions_ct matches resource
    if permissions_ct.address().as_array() != res.permissions.id() {
        return Err(ProgramError::InvalidArgument);
    }

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
    ctx.revoke_permission_graph(permissions_ct, revoke_mask_ct, permissions_ct)?;

    Ok(())
}

// ── 3: check_permission ──
// data: check_bump(1) | cpi_authority_bump(1)
// accounts: [resource, check_pda(w), checker(s), permissions_ct, permission_bit_ct, result_ct(w),
//            encrypt_program, config, deposit(w), cpi_authority,
//            caller_program, network_encryption_key, payer(s,w),
//            event_authority, system_program]

fn check_permission(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    let [resource_acct, check_acct, checker, permissions_ct, permission_bit_ct, result_ct, encrypt_program, config, deposit, cpi_authority, caller_program, network_encryption_key, payer, event_authority, system_program, ..] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !checker.is_signer() || !payer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if data.len() < 2 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let check_bump = data[0];
    let cpi_authority_bump = data[1];

    // Read resource to get resource_id and verify permissions_ct
    let res_data = unsafe { resource_acct.borrow_unchecked() };
    let res = Resource::from_bytes(res_data)?;
    let resource_id = res.resource_id;
    if permissions_ct.address().as_array() != res.permissions.id() {
        return Err(ProgramError::InvalidArgument);
    }

    // Create AccessCheck PDA
    let bump_byte = [check_bump];
    let seeds = [
        Seed::from(b"check" as &[u8]),
        Seed::from(resource_id.as_ref()),
        Seed::from(checker.address().as_ref()),
        Seed::from(&bump_byte),
    ];
    let signer = [Signer::from(&seeds)];

    CreateAccount {
        from: payer,
        to: check_acct,
        lamports: minimum_balance(AccessCheck::LEN),
        space: AccessCheck::LEN as u64,
        owner: program_id,
    }
    .invoke_signed(&signer)?;

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
    // In production, ciphertext digests are unique regardless of plaintext value.
    ctx.create_plaintext_typed::<Uint64>(&u64::MAX, result_ct)?;

    // result = permissions & permission_bit
    ctx.check_permission_graph(permissions_ct, permission_bit_ct, result_ct)?;

    // Write check state
    let d = unsafe { check_acct.borrow_unchecked_mut() };
    let chk = AccessCheck::from_bytes_mut(d)?;
    chk.discriminator = ACCESS_CHECK;
    chk.checker.copy_from_slice(checker.address().as_ref());
    chk.result_ct = EUint64::from_le_bytes(*result_ct.address().as_array());
    chk.pending_digest = [0u8; 32];
    chk.revealed_result = [0u8; 8];
    chk.bump = check_bump;
    Ok(())
}

// ── 4: request_check_decryption ──
// data: cpi_authority_bump(1)
// accounts: [check_pda(w), request_acct(w), result_ciphertext,
//            encrypt_program, config, deposit(w), cpi_authority,
//            caller_program, network_encryption_key, payer(s,w),
//            event_authority, system_program]

fn request_check_decryption(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [check_acct, request_acct, result_ciphertext, encrypt_program, config, deposit, cpi_authority, caller_program, network_encryption_key, payer, event_authority, system_program, ..] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !payer.is_signer() {
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

    let d = unsafe { check_acct.borrow_unchecked_mut() };
    let chk = AccessCheck::from_bytes_mut(d)?;
    chk.pending_digest = digest;

    Ok(())
}

// ── 5: reveal_check ──
// accounts: [check_pda(w), request_acct, checker(s)]

fn reveal_check(accounts: &[AccountView]) -> ProgramResult {
    let [check_acct, request_acct, checker, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !checker.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Verify checker
    let chk_data = unsafe { check_acct.borrow_unchecked() };
    let chk = AccessCheck::from_bytes(chk_data)?;
    if checker.address().as_array() != &chk.checker {
        return Err(ProgramError::InvalidArgument);
    }

    let expected_digest = &chk.pending_digest;
    let req_data = unsafe { request_acct.borrow_unchecked() };
    let value: &u64 = accounts::read_decrypted_verified::<Uint64>(req_data, expected_digest)?;

    let d = unsafe { check_acct.borrow_unchecked_mut() };
    let chk_mut = AccessCheck::from_bytes_mut(d)?;
    chk_mut.revealed_result = value.to_le_bytes();

    Ok(())
}

// ── 6: request_permissions_decryption ──
// data: cpi_authority_bump(1)
// accounts: [resource(w), request_acct(w), permissions_ciphertext,
//            encrypt_program, config, deposit(w), cpi_authority,
//            caller_program, network_encryption_key, payer(s,w),
//            event_authority, system_program]

fn request_permissions_decryption(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [resource_acct, request_acct, permissions_ciphertext, encrypt_program, config, deposit, cpi_authority, caller_program, network_encryption_key, payer, event_authority, system_program, ..] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !payer.is_signer() {
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

    let d = unsafe { resource_acct.borrow_unchecked_mut() };
    let res = Resource::from_bytes_mut(d)?;
    res.pending_digest = digest;

    Ok(())
}

// ── 7: reveal_permissions ──
// accounts: [resource(w), request_acct, admin(s)]

fn reveal_permissions(accounts: &[AccountView]) -> ProgramResult {
    let [resource_acct, request_acct, admin, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !admin.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Verify admin
    let res_data = unsafe { resource_acct.borrow_unchecked() };
    let res = Resource::from_bytes(res_data)?;
    if admin.address().as_array() != &res.admin {
        return Err(ProgramError::InvalidArgument);
    }

    let expected_digest = &res.pending_digest;
    let req_data = unsafe { request_acct.borrow_unchecked() };
    let value: &u64 = accounts::read_decrypted_verified::<Uint64>(req_data, expected_digest)?;

    let d = unsafe { resource_acct.borrow_unchecked_mut() };
    let res_mut = Resource::from_bytes_mut(d)?;
    res_mut.revealed_permissions = value.to_le_bytes();

    Ok(())
}

// ── Tests ──

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
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
                get_node(pg.node_bytes(), i as u16).unwrap().kind() == GraphNodeKind::Output as u8
            })
            .map(|i| decode_mock_identifier(&digests[i]))
            .collect()
    }

    #[test]
    fn grant_single_permission() {
        // 0 | 1 = 1 (grant READ to empty permissions)
        let r = run_mock(
            grant_permission_graph,
            &[0, 1],
            &[FheType::EUint64, FheType::EUint64],
        );
        assert_eq!(r[0], 1, "granting READ (bit 0) to 0 should yield 1");
    }

    #[test]
    fn grant_multiple_permissions() {
        // 1 | 2 = 3 (grant WRITE when READ already set)
        let r = run_mock(
            grant_permission_graph,
            &[1, 2],
            &[FheType::EUint64, FheType::EUint64],
        );
        assert_eq!(r[0], 3, "granting WRITE (bit 1) to READ (1) should yield 3");
    }

    #[test]
    fn revoke_permission() {
        // 3 & 0xFFFFFFFFFFFFFFFE = 2 (revoke READ from READ+WRITE)
        let r = run_mock(
            revoke_permission_graph,
            &[3, 0xFFFFFFFFFFFFFFFE],
            &[FheType::EUint64, FheType::EUint64],
        );
        assert_eq!(r[0], 2, "revoking READ (bit 0) from 3 should yield 2");
    }

    #[test]
    fn check_has_permission() {
        // 5 & 1 = 1 (has READ; 5 = READ|EXECUTE)
        let r = run_mock(
            check_permission_graph,
            &[5, 1],
            &[FheType::EUint64, FheType::EUint64],
        );
        assert_eq!(r[0], 1, "checking READ on 5 (READ|EXECUTE) should yield 1");
    }

    #[test]
    fn check_missing_permission() {
        // 4 & 1 = 0 (no READ; 4 = EXECUTE only)
        let r = run_mock(
            check_permission_graph,
            &[4, 1],
            &[FheType::EUint64, FheType::EUint64],
        );
        assert_eq!(r[0], 0, "checking READ on 4 (EXECUTE only) should yield 0");
    }

    #[test]
    fn graph_shapes() {
        // Grant graph: 2 inputs, 1 output
        let d = grant_permission_graph();
        let pg = parse_graph(&d).unwrap();
        assert_eq!(pg.header().num_inputs(), 2, "grant: 2 inputs");
        assert_eq!(pg.header().num_outputs(), 1, "grant: 1 output");

        // Revoke graph: 2 inputs, 1 output
        let d = revoke_permission_graph();
        let pg = parse_graph(&d).unwrap();
        assert_eq!(pg.header().num_inputs(), 2, "revoke: 2 inputs");
        assert_eq!(pg.header().num_outputs(), 1, "revoke: 1 output");

        // Check graph: 2 inputs, 1 output
        let d = check_permission_graph();
        let pg = parse_graph(&d).unwrap();
        assert_eq!(pg.header().num_inputs(), 2, "check: 2 inputs");
        assert_eq!(pg.header().num_outputs(), 1, "check: 1 output");
    }
}
