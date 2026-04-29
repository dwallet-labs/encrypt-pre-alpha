// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#![allow(unexpected_cfgs)]

/// PC-Swap — Confidential UniV2 AMM that composes with PC-Token via CPI.
///
/// Pool reserves are real PC-Token TokenAccounts owned by the pool PDA.
/// User → vault deposits go through `pc-token::TransferWithReceipt` (disc 22),
/// which emits a binary receipt ciphertext (= amount on success, 0 on
/// insufficient balance). The receipt is authorized to pc-swap and
/// becomes the *only* trusted input to the FHE math. Reserve mirrors and
/// payouts are functions of the receipt, never of the user-supplied
/// `amount_in` directly — so a user who lies about their balance produces
/// `receipt = 0` and the graph no-ops uniformly: reserves untouched,
/// vault → user payout = 0.
///
/// ## Instructions
///
/// 0. CreatePool          — init pool PDA, init pc-token vaults (owner = pool)
/// 1. Swap                — TransferWithReceipt + swap_graph + transfer (vault→user) + close receipt
/// 2. AddLiquidity        — 2× TransferWithReceipt + add_liquidity_graph + 2× close
/// 4. RemoveLiquidity     — remove_liquidity_graph + 2× pc-token::transfer (vault → user)
/// 5. CreateLpPosition    — internal LP balance account
use encrypt_dsl::prelude::encrypt_fn;
use encrypt_pinocchio::EncryptContext;
#[allow(unused_imports)]
use encrypt_types::encrypted::EUint64;
use encrypt_types::encrypted::Uint64;
use pinocchio::{
    AccountView, Address, ProgramResult,
    cpi::{Seed, Signer, invoke_signed},
    entrypoint,
    error::ProgramError,
    instruction::{InstructionAccount, InstructionView},
};
use pinocchio_system::instructions::CreateAccount;

entrypoint!(process_instruction);

pub const ID: Address = Address::new_from_array([6u8; 32]);

/// PC-Token program id (mirrors pc-token::ID).
pub const PC_TOKEN_ID: Address = Address::new_from_array([5u8; 32]);

/// PC-Token instruction discriminators we invoke via CPI.
const PC_TOKEN_IX_INIT_ACCT: u8 = 1;
const PC_TOKEN_IX_TRANSFER: u8 = 3;
const PC_TOKEN_IX_TRANSFER_WITH_RECEIPT: u8 = 22;

// ── Account layouts ──

/// Pool state — PDA: `["pc_pool", mint_a, mint_b]`.
#[repr(C)]
pub struct Pool {
    pub mint_a: [u8; 32],
    pub mint_b: [u8; 32],
    pub vault_a: [u8; 32],      // pc-token TokenAccount (owner = this pool PDA)
    pub vault_b: [u8; 32],      // pc-token TokenAccount (owner = this pool PDA)
    pub reserve_a: [u8; 32],    // encrypted reserve mirror (EUint64)
    pub reserve_b: [u8; 32],    // encrypted reserve mirror (EUint64)
    pub total_supply: [u8; 32], // encrypted LP total supply (EUint64)
    pub is_initialized: u8,
    pub bump: u8,
}

impl Pool {
    pub const LEN: usize = core::mem::size_of::<Self>();
    pub fn from_bytes(d: &[u8]) -> Result<&Self, ProgramError> {
        if d.len() < Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(unsafe { &*(d.as_ptr() as *const Self) })
    }
    pub fn from_bytes_mut(d: &mut [u8]) -> Result<&mut Self, ProgramError> {
        if d.len() < Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(unsafe { &mut *(d.as_mut_ptr() as *mut Self) })
    }
}

/// LP position — PDA: `["pc_lp", pool, owner]`.
/// pc-swap-internal accounting; not a real pc-token mint.
#[repr(C)]
pub struct LpPosition {
    pub pool: [u8; 32],
    pub owner: [u8; 32],
    pub balance: [u8; 32], // encrypted LP balance (EUint64)
    pub bump: u8,
}

impl LpPosition {
    pub const LEN: usize = core::mem::size_of::<Self>();
    pub fn from_bytes(d: &[u8]) -> Result<&Self, ProgramError> {
        if d.len() < Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(unsafe { &*(d.as_ptr() as *const Self) })
    }
    pub fn from_bytes_mut(d: &mut [u8]) -> Result<&mut Self, ProgramError> {
        if d.len() < Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(unsafe { &mut *(d.as_mut_ptr() as *mut Self) })
    }
}

fn minimum_balance(s: usize) -> u64 {
    (s as u64 + 128) * 6960
}

// ── FHE Graphs ──

/// Constant-product swap with 0.3% fee + slippage check + refund.
///
/// `receipt` is pc-token's TransferWithReceipt output: it equals `amount_in`
/// on a successful user→vault deposit, exactly `0` on insufficient balance.
/// All reserve and payout updates are functions of `receipt`, never of the
/// user-supplied `amount_in` directly — so a lying user produces `receipt=0`
/// and every output is 0/no-op uniformly.
///
/// `refund = receipt - final_in` is `0` on a successful swap and `receipt`
/// on slippage rejection. The dispatch CPIs `pc-token::transfer(vault→user)`
/// for `refund` after the graph, so a slipped deposit is returned to the
/// user instead of being stranded in the pool vault. `min_amount_out`
/// (always pc-swap-authorized) provides the typed zero source.
#[encrypt_fn]
fn swap_graph(
    reserve_in: EUint64,
    reserve_out: EUint64,
    receipt: EUint64,
    min_amount_out: EUint64,
) -> (EUint64, EUint64, EUint64, EUint64) {
    let amount_in_with_fee = receipt * 997;
    let numer = amount_in_with_fee * reserve_out;
    let denom = (reserve_in * 1000) + amount_in_with_fee;
    let amount_out = numer / denom;
    let slip_ok = amount_out >= min_amount_out;
    let zero = min_amount_out - min_amount_out;
    let final_in = if slip_ok { receipt } else { zero };
    let final_out = if slip_ok { amount_out } else { zero };
    let refund = receipt - final_in;
    let new_reserve_in = reserve_in + final_in;
    let new_reserve_out = reserve_out - final_out;
    (refund, final_out, new_reserve_in, new_reserve_out)
}

/// Add liquidity — atomic-deposit gated, with per-side refunds.
///
/// `receipt_a` / `receipt_b` are pc-token TransferWithReceipt outputs from
/// the two user→vault deposits (= amount on success, 0 on insufficient).
/// Reserves, supply, and LP only update when BOTH receipts are non-zero
/// AND the resulting `lp_to_mint` is positive (`settled = both_ok && lp_ok`).
/// On any other case nothing settles and `refund_a` / `refund_b` carry the
/// untouched receipts back to the user via vault→user CPIs in the dispatch.
///
/// First deposit: lp = receipt_a. Subsequent: proportional via min(lp_a, lp_b).
#[encrypt_fn]
fn add_liquidity_graph(
    reserve_a: EUint64,
    reserve_b: EUint64,
    total_supply: EUint64,
    receipt_a: EUint64,
    receipt_b: EUint64,
    user_lp: EUint64,
) -> (EUint64, EUint64, EUint64, EUint64, EUint64, EUint64) {
    let initial_lp = receipt_a;
    let lp_from_a = (receipt_a * total_supply) / (reserve_a + 1);
    let lp_from_b = (receipt_b * total_supply) / (reserve_b + 1);
    let subsequent_lp = if lp_from_a >= lp_from_b {
        lp_from_b
    } else {
        lp_from_a
    };
    let is_subsequent = total_supply >= 1;
    let lp_to_mint_proposed = if is_subsequent {
        subsequent_lp
    } else {
        initial_lp
    };

    // Atomic-deposit gate: settle only when both sides deposited AND minted.
    let pa_ok = receipt_a >= 1;
    let pb_ok = receipt_b >= 1;
    let both_ok = if pa_ok { pb_ok } else { pa_ok };
    let lp_ok = lp_to_mint_proposed >= 1;
    let settled = if both_ok { lp_ok } else { both_ok };

    let zero = total_supply - total_supply;
    let final_a = if settled { receipt_a } else { zero };
    let final_b = if settled { receipt_b } else { zero };
    let lp_to_mint = if settled { lp_to_mint_proposed } else { zero };
    let refund_a = receipt_a - final_a;
    let refund_b = receipt_b - final_b;
    let new_reserve_a = reserve_a + final_a;
    let new_reserve_b = reserve_b + final_b;
    let new_total_supply = total_supply + lp_to_mint;
    let new_user_lp = user_lp + lp_to_mint;
    (
        refund_a,
        refund_b,
        new_reserve_a,
        new_reserve_b,
        new_total_supply,
        new_user_lp,
    )
}

/// Remove liquidity — gates on user_lp >= burn. On insufficient LP, all
/// outputs are 0 → pc-token transfers no-op, reserves unchanged.
#[encrypt_fn]
fn remove_liquidity_graph(
    reserve_a: EUint64,
    reserve_b: EUint64,
    total_supply: EUint64,
    burn: EUint64,
    user_lp: EUint64,
) -> (EUint64, EUint64, EUint64, EUint64, EUint64, EUint64) {
    let sufficient = user_lp >= burn;
    let amount_a = (reserve_a * burn) / (total_supply + 1);
    let amount_b = (reserve_b * burn) / (total_supply + 1);
    let zero = burn - burn;
    let out_a = if sufficient { amount_a } else { zero };
    let out_b = if sufficient { amount_b } else { zero };
    let new_ra = if sufficient {
        reserve_a - out_a
    } else {
        reserve_a
    };
    let new_rb = if sufficient {
        reserve_b - out_b
    } else {
        reserve_b
    };
    let new_supply = if sufficient {
        total_supply - burn
    } else {
        total_supply
    };
    let new_user_lp = if sufficient { user_lp - burn } else { user_lp };
    (out_a, out_b, new_ra, new_rb, new_supply, new_user_lp)
}

// ── Dispatch ──

fn process_instruction(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    match data.split_first() {
        Some((&0, rest)) => create_pool(program_id, accounts, rest),
        Some((&1, rest)) => swap(accounts, rest),
        Some((&2, rest)) => add_liquidity(accounts, rest),
        Some((&4, rest)) => remove_liquidity(accounts, rest),
        Some((&5, rest)) => create_lp_position(program_id, accounts, rest),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

// ── Helpers ──

/// Build pc-token instruction account list. pc-token's encrypt CPI uses
/// `pc_token_program` as the caller and `pc_token_cpi_auth` as the cpi_authority.
fn pc_token_transfer_accounts<'a>(
    from_acct: &'a AccountView,
    to_acct: &'a AccountView,
    from_ct: &'a AccountView,
    to_ct: &'a AccountView,
    amt_ct: &'a AccountView,
    ep: &'a AccountView,
    cfg: &'a AccountView,
    dep: &'a AccountView,
    pc_token_cpi_auth: &'a AccountView,
    pc_token_program: &'a AccountView,
    nk: &'a AccountView,
    owner: &'a AccountView,
    evt: &'a AccountView,
    sys: &'a AccountView,
) -> ([InstructionAccount<'a>; 14], [&'a AccountView; 14]) {
    let metas = [
        InstructionAccount {
            address: from_acct.address(),
            is_writable: true,
            is_signer: false,
        },
        InstructionAccount {
            address: to_acct.address(),
            is_writable: true,
            is_signer: false,
        },
        InstructionAccount {
            address: from_ct.address(),
            is_writable: true,
            is_signer: false,
        },
        InstructionAccount {
            address: to_ct.address(),
            is_writable: true,
            is_signer: false,
        },
        InstructionAccount {
            address: amt_ct.address(),
            is_writable: true,
            is_signer: false,
        },
        InstructionAccount {
            address: ep.address(),
            is_writable: false,
            is_signer: false,
        },
        InstructionAccount {
            address: cfg.address(),
            is_writable: true,
            is_signer: false,
        },
        InstructionAccount {
            address: dep.address(),
            is_writable: true,
            is_signer: false,
        },
        InstructionAccount {
            address: pc_token_cpi_auth.address(),
            is_writable: false,
            is_signer: false,
        },
        InstructionAccount {
            address: pc_token_program.address(),
            is_writable: false,
            is_signer: false,
        },
        InstructionAccount {
            address: nk.address(),
            is_writable: false,
            is_signer: false,
        },
        // owner doubles as `payer` for pc-token's inner encrypt CPI, which marks it writable+signer.
        InstructionAccount {
            address: owner.address(),
            is_writable: true,
            is_signer: true,
        },
        InstructionAccount {
            address: evt.address(),
            is_writable: false,
            is_signer: false,
        },
        InstructionAccount {
            address: sys.address(),
            is_writable: false,
            is_signer: false,
        },
    ];
    let views = [
        from_acct,
        to_acct,
        from_ct,
        to_ct,
        amt_ct,
        ep,
        cfg,
        dep,
        pc_token_cpi_auth,
        pc_token_program,
        nk,
        owner,
        evt,
        sys,
    ];
    (metas, views)
}

fn cpi_pc_token_transfer<'a>(
    pc_token_program: &'a AccountView,
    pc_token_cpi_auth_bump: u8,
    metas: &[InstructionAccount; 14],
    views: &[&'a AccountView; 14],
    pool_signer: Option<&[Seed]>,
) -> ProgramResult {
    let data = [PC_TOKEN_IX_TRANSFER, pc_token_cpi_auth_bump];
    let ix = InstructionView {
        program_id: pc_token_program.address(),
        data: &data,
        accounts: metas,
    };
    match pool_signer {
        Some(seeds) => invoke_signed(&ix, views, &[Signer::from(seeds)]),
        None => invoke_signed(&ix, views, &[]),
    }
}

/// Build the metas/views and CPI a single pc-token::transfer in one call.
/// Lives in its own function so the metas+views arrays (~600B) get their
/// own stack frame instead of accumulating in the caller — keeps the
/// dispatch handlers under Solana's 4 KB frame limit.
#[inline(never)]
#[allow(clippy::too_many_arguments)]
fn pool_signed_transfer<'a>(
    from_acct: &'a AccountView,
    to_acct: &'a AccountView,
    from_bal_ct: &'a AccountView,
    to_bal_ct: &'a AccountView,
    amt_ct: &'a AccountView,
    ep: &'a AccountView,
    cfg: &'a AccountView,
    dep: &'a AccountView,
    pc_token_cpi_auth: &'a AccountView,
    pc_token_program: &'a AccountView,
    nk: &'a AccountView,
    pool_acct: &'a AccountView,
    evt: &'a AccountView,
    sys: &'a AccountView,
    token_cpi_bump: u8,
    pool_seeds: &[Seed],
) -> ProgramResult {
    let (metas, views) = pc_token_transfer_accounts(
        from_acct,
        to_acct,
        from_bal_ct,
        to_bal_ct,
        amt_ct,
        ep,
        cfg,
        dep,
        pc_token_cpi_auth,
        pc_token_program,
        nk,
        pool_acct,
        evt,
        sys,
    );
    cpi_pc_token_transfer(
        pc_token_program,
        token_cpi_bump,
        &metas,
        &views,
        Some(pool_seeds),
    )
}

/// Build pc-token::TransferWithReceipt account list.
/// `target_program` becomes the new authorized of the receipt — pass
/// pc-swap's own program id (the `caller_program` AccountView) so the
/// receipt can be read by the swap_graph and closed by pc-swap.
#[allow(clippy::too_many_arguments)]
fn pc_token_transfer_with_receipt_accounts<'a>(
    from_acct: &'a AccountView,
    to_acct: &'a AccountView,
    from_ct: &'a AccountView,
    to_ct: &'a AccountView,
    amt_ct: &'a AccountView,
    receipt_ct: &'a AccountView,
    target_program: &'a AccountView,
    ep: &'a AccountView,
    cfg: &'a AccountView,
    dep: &'a AccountView,
    pc_token_cpi_auth: &'a AccountView,
    pc_token_program: &'a AccountView,
    nk: &'a AccountView,
    owner: &'a AccountView,
    evt: &'a AccountView,
    sys: &'a AccountView,
) -> ([InstructionAccount<'a>; 16], [&'a AccountView; 16]) {
    let metas = [
        InstructionAccount {
            address: from_acct.address(),
            is_writable: true,
            is_signer: false,
        },
        InstructionAccount {
            address: to_acct.address(),
            is_writable: true,
            is_signer: false,
        },
        InstructionAccount {
            address: from_ct.address(),
            is_writable: true,
            is_signer: false,
        },
        InstructionAccount {
            address: to_ct.address(),
            is_writable: true,
            is_signer: false,
        },
        InstructionAccount {
            address: amt_ct.address(),
            is_writable: true,
            is_signer: false,
        },
        // Receipt is a fresh keypair account that the encrypt SDK will create —
        // outer tx must include the keypair as a signer; we propagate that flag.
        InstructionAccount {
            address: receipt_ct.address(),
            is_writable: true,
            is_signer: true,
        },
        InstructionAccount {
            address: target_program.address(),
            is_writable: false,
            is_signer: false,
        },
        InstructionAccount {
            address: ep.address(),
            is_writable: false,
            is_signer: false,
        },
        InstructionAccount {
            address: cfg.address(),
            is_writable: true,
            is_signer: false,
        },
        InstructionAccount {
            address: dep.address(),
            is_writable: true,
            is_signer: false,
        },
        InstructionAccount {
            address: pc_token_cpi_auth.address(),
            is_writable: false,
            is_signer: false,
        },
        InstructionAccount {
            address: pc_token_program.address(),
            is_writable: false,
            is_signer: false,
        },
        InstructionAccount {
            address: nk.address(),
            is_writable: false,
            is_signer: false,
        },
        InstructionAccount {
            address: owner.address(),
            is_writable: true,
            is_signer: true,
        },
        InstructionAccount {
            address: evt.address(),
            is_writable: false,
            is_signer: false,
        },
        InstructionAccount {
            address: sys.address(),
            is_writable: false,
            is_signer: false,
        },
    ];
    let views = [
        from_acct,
        to_acct,
        from_ct,
        to_ct,
        amt_ct,
        receipt_ct,
        target_program,
        ep,
        cfg,
        dep,
        pc_token_cpi_auth,
        pc_token_program,
        nk,
        owner,
        evt,
        sys,
    ];
    (metas, views)
}

fn cpi_pc_token_transfer_with_receipt<'a>(
    pc_token_program: &'a AccountView,
    pc_token_cpi_auth_bump: u8,
    metas: &[InstructionAccount; 16],
    views: &[&'a AccountView; 16],
) -> ProgramResult {
    let data = [PC_TOKEN_IX_TRANSFER_WITH_RECEIPT, pc_token_cpi_auth_bump];
    let ix = InstructionView {
        program_id: pc_token_program.address(),
        data: &data,
        accounts: metas,
    };
    invoke_signed(&ix, views, &[])
}

// ── 0: CreatePool ──
//
// Accounts:
//   pool_acct (write, PDA),
//   mint_a, mint_b                       (pc-token Mints, read)
//   vault_a, vault_b                     (pc-token TokenAccount PDAs to be created, write)
//   vault_a_bal_ct, vault_b_bal_ct       (empty keypairs, signers, write)
//   reserve_a_ct, reserve_b_ct, total_supply_ct  (empty keypairs, signers, write)
//   ep, cfg, dep,
//   cpi_authority (pc-swap),
//   caller_program (pc-swap, == this program),
//   pc_token_cpi_auth, pc_token_program,
//   nk, payer, evt, sys,
//
// Data: [0, pool_bump, vault_a_bump, vault_b_bump, swap_cpi_bump, token_cpi_bump]
fn create_pool(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [
        pool_acct,
        mint_a,
        mint_b,
        vault_a,
        vault_b,
        vault_a_bal_ct,
        vault_b_bal_ct,
        ra_ct,
        rb_ct,
        ts_ct,
        ep,
        cfg,
        dep,
        cpi_authority,
        caller_program,
        pc_token_cpi_auth,
        pc_token_program,
        nk,
        payer,
        evt,
        sys,
        ..,
    ] = accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !payer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if data.len() < 6 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let pool_bump = data[0];
    let vault_a_bump = data[1];
    let vault_b_bump = data[2];
    let swap_cpi_bump = data[3];
    let token_cpi_bump = data[4];
    let _reserved = data[5];

    // 1) Create pool PDA
    let bb = [pool_bump];
    let pool_seeds = [
        Seed::from(b"pc_pool" as &[u8]),
        Seed::from(mint_a.address().as_ref()),
        Seed::from(mint_b.address().as_ref()),
        Seed::from(&bb),
    ];
    CreateAccount {
        from: payer,
        to: pool_acct,
        lamports: minimum_balance(Pool::LEN),
        space: Pool::LEN as u64,
        owner: program_id,
    }
    .invoke_signed(&[Signer::from(&pool_seeds)])?;

    // 2) CPI pc-token::initialize_account for vault_a (owner = pool_acct PDA)
    cpi_pc_token_init_account(
        vault_a,
        mint_a,
        pool_acct,
        vault_a_bal_ct,
        ep,
        cfg,
        dep,
        pc_token_cpi_auth,
        pc_token_program,
        nk,
        payer,
        evt,
        sys,
        pc_token_program,
        vault_a_bump,
        token_cpi_bump,
    )?;

    // 3) CPI pc-token::initialize_account for vault_b
    cpi_pc_token_init_account(
        vault_b,
        mint_b,
        pool_acct,
        vault_b_bal_ct,
        ep,
        cfg,
        dep,
        pc_token_cpi_auth,
        pc_token_program,
        nk,
        payer,
        evt,
        sys,
        pc_token_program,
        vault_b_bump,
        token_cpi_bump,
    )?;

    // 4) Create pc-swap's encrypted mirrors (reserve_a, reserve_b, total_supply)
    let ctx = EncryptContext {
        encrypt_program: ep,
        config: cfg,
        deposit: dep,
        cpi_authority,
        caller_program,
        network_encryption_key: nk,
        payer,
        event_authority: evt,
        system_program: sys,
        cpi_authority_bump: swap_cpi_bump,
    };
    ctx.create_plaintext_typed::<Uint64>(&0u64, ra_ct)?;
    ctx.create_plaintext_typed::<Uint64>(&0u64, rb_ct)?;
    ctx.create_plaintext_typed::<Uint64>(&0u64, ts_ct)?;

    // 5) Write pool state
    let d = unsafe { pool_acct.borrow_unchecked_mut() };
    let pool = Pool::from_bytes_mut(d)?;
    pool.mint_a.copy_from_slice(mint_a.address().as_ref());
    pool.mint_b.copy_from_slice(mint_b.address().as_ref());
    pool.vault_a.copy_from_slice(vault_a.address().as_ref());
    pool.vault_b.copy_from_slice(vault_b.address().as_ref());
    pool.reserve_a.copy_from_slice(ra_ct.address().as_ref());
    pool.reserve_b.copy_from_slice(rb_ct.address().as_ref());
    pool.total_supply.copy_from_slice(ts_ct.address().as_ref());
    pool.is_initialized = 1;
    pool.bump = pool_bump;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cpi_pc_token_init_account<'a>(
    ta_acct: &'a AccountView,
    mint_acct: &'a AccountView,
    owner: &'a AccountView,
    bal_ct: &'a AccountView,
    ep: &'a AccountView,
    cfg: &'a AccountView,
    dep: &'a AccountView,
    pc_token_cpi_auth: &'a AccountView,
    pc_token_program_caller: &'a AccountView,
    nk: &'a AccountView,
    payer: &'a AccountView,
    evt: &'a AccountView,
    sys: &'a AccountView,
    pc_token_program_target: &'a AccountView,
    ta_bump: u8,
    token_cpi_bump: u8,
) -> ProgramResult {
    let metas = [
        InstructionAccount {
            address: ta_acct.address(),
            is_writable: true,
            is_signer: false,
        },
        InstructionAccount {
            address: mint_acct.address(),
            is_writable: false,
            is_signer: false,
        },
        InstructionAccount {
            address: owner.address(),
            is_writable: false,
            is_signer: false,
        },
        InstructionAccount {
            address: bal_ct.address(),
            is_writable: true,
            is_signer: true,
        },
        InstructionAccount {
            address: ep.address(),
            is_writable: false,
            is_signer: false,
        },
        InstructionAccount {
            address: cfg.address(),
            is_writable: false,
            is_signer: false,
        },
        InstructionAccount {
            address: dep.address(),
            is_writable: true,
            is_signer: false,
        },
        InstructionAccount {
            address: pc_token_cpi_auth.address(),
            is_writable: false,
            is_signer: false,
        },
        InstructionAccount {
            address: pc_token_program_caller.address(),
            is_writable: false,
            is_signer: false,
        },
        InstructionAccount {
            address: nk.address(),
            is_writable: false,
            is_signer: false,
        },
        InstructionAccount {
            address: payer.address(),
            is_writable: true,
            is_signer: true,
        },
        InstructionAccount {
            address: evt.address(),
            is_writable: false,
            is_signer: false,
        },
        InstructionAccount {
            address: sys.address(),
            is_writable: false,
            is_signer: false,
        },
    ];
    let views = [
        ta_acct,
        mint_acct,
        owner,
        bal_ct,
        ep,
        cfg,
        dep,
        pc_token_cpi_auth,
        pc_token_program_caller,
        nk,
        payer,
        evt,
        sys,
    ];
    let data = [PC_TOKEN_IX_INIT_ACCT, ta_bump, token_cpi_bump];
    let ix = InstructionView {
        program_id: pc_token_program_target.address(),
        data: &data,
        accounts: &metas,
    };
    invoke_signed(&ix, &views, &[])
}

// ── 5: CreateLpPosition ──
fn create_lp_position(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    let [
        lp_acct,
        pool_acct,
        owner,
        balance_ct,
        ep,
        cfg,
        dep,
        cpi_authority,
        caller_program,
        nk,
        payer,
        evt,
        sys,
        ..,
    ] = accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !payer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if data.len() < 2 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let (lp_bump, cpi_bump) = (data[0], data[1]);

    let pd = unsafe { pool_acct.borrow_unchecked() };
    let pool = Pool::from_bytes(pd)?;
    if pool.is_initialized != 1 {
        return Err(ProgramError::UninitializedAccount);
    }

    let bb = [lp_bump];
    let seeds = [
        Seed::from(b"pc_lp" as &[u8]),
        Seed::from(pool_acct.address().as_ref()),
        Seed::from(owner.address().as_ref()),
        Seed::from(&bb),
    ];
    CreateAccount {
        from: payer,
        to: lp_acct,
        lamports: minimum_balance(LpPosition::LEN),
        space: LpPosition::LEN as u64,
        owner: program_id,
    }
    .invoke_signed(&[Signer::from(&seeds)])?;

    let ctx = EncryptContext {
        encrypt_program: ep,
        config: cfg,
        deposit: dep,
        cpi_authority,
        caller_program,
        network_encryption_key: nk,
        payer,
        event_authority: evt,
        system_program: sys,
        cpi_authority_bump: cpi_bump,
    };
    ctx.create_plaintext_typed::<Uint64>(&0u64, balance_ct)?;

    let d = unsafe { lp_acct.borrow_unchecked_mut() };
    let lp = LpPosition::from_bytes_mut(d)?;
    lp.pool.copy_from_slice(pool_acct.address().as_ref());
    lp.owner.copy_from_slice(owner.address().as_ref());
    lp.balance.copy_from_slice(balance_ct.address().as_ref());
    lp.bump = lp_bump;
    Ok(())
}

// ── 1: Swap ──
//
// One-tx receipt-gated swap. The user→vault deposit goes through
// pc-token::TransferWithReceipt (disc 22), producing a binary receipt
// (= amount_in on success, 0 on insufficient balance) that becomes the
// only trusted input to swap_graph. Reserves and payout are functions
// of the receipt — a lying user produces receipt=0 and every output
// collapses to 0, leaving reserves and the user's out-account untouched.
//
// Accounts:
//   pool_acct (write),
//   user_in_acct, user_out_acct        (user's pc-token TokenAccounts)
//   vault_in_acct, vault_out_acct      (pool's pc-token vaults)
//   user_in_bal_ct, user_out_bal_ct    (cts referenced by user TAs)
//   vault_in_bal_ct, vault_out_bal_ct  (cts referenced by vault TAs)
//   reserve_in_ct, reserve_out_ct      (pc-swap's mirror, from pool)
//   amt_in_ct, min_out_ct, amt_out_ct  (user inputs + pre-allocated output)
//   receipt_ct                         (fresh keypair, signer)
//   ep, cfg, dep,
//   cpi_authority (pc-swap), caller_program (pc-swap),
//   pc_token_cpi_auth, pc_token_program,
//   nk, payer (signer), evt, sys
//
// Data: [1, swap_cpi_bump, token_cpi_bump, direction]
//   direction: 0 = A→B, 1 = B→A
fn swap(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [
        pool_acct,
        user_in_acct,
        user_out_acct,
        vault_in_acct,
        vault_out_acct,
        user_in_bal_ct,
        user_out_bal_ct,
        vault_in_bal_ct,
        vault_out_bal_ct,
        reserve_in_ct,
        reserve_out_ct,
        amt_in_ct,
        min_out_ct,
        amt_out_ct,
        receipt_ct,
        ep,
        cfg,
        dep,
        cpi_authority,
        caller_program,
        pc_token_cpi_auth,
        pc_token_program,
        nk,
        payer,
        evt,
        sys,
        ..,
    ] = accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !payer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if data.len() < 3 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let swap_cpi_bump = data[0];
    let token_cpi_bump = data[1];
    let direction = data[2];

    let pd = unsafe { pool_acct.borrow_unchecked() };
    let pool = Pool::from_bytes(pd)?;
    if pool.is_initialized != 1 {
        return Err(ProgramError::UninitializedAccount);
    }

    let (expected_vault_in, expected_vault_out, exp_reserve_in, exp_reserve_out) = if direction == 0
    {
        (
            &pool.vault_a,
            &pool.vault_b,
            &pool.reserve_a,
            &pool.reserve_b,
        )
    } else {
        (
            &pool.vault_b,
            &pool.vault_a,
            &pool.reserve_b,
            &pool.reserve_a,
        )
    };
    if vault_in_acct.address().as_ref() != expected_vault_in {
        return Err(ProgramError::InvalidArgument);
    }
    if vault_out_acct.address().as_ref() != expected_vault_out {
        return Err(ProgramError::InvalidArgument);
    }
    if reserve_in_ct.address().as_ref() != exp_reserve_in {
        return Err(ProgramError::InvalidArgument);
    }
    if reserve_out_ct.address().as_ref() != exp_reserve_out {
        return Err(ProgramError::InvalidArgument);
    }

    // 1) Hand amt_in_ct to pc-token, then CPI TransferWithReceipt (user → vault).
    //    target_program = pc-swap (caller_program) so the receipt is authorized
    //    back to us, readable by swap_graph and closeable below.
    let ctx = EncryptContext {
        encrypt_program: ep,
        config: cfg,
        deposit: dep,
        cpi_authority,
        caller_program,
        network_encryption_key: nk,
        payer,
        event_authority: evt,
        system_program: sys,
        cpi_authority_bump: swap_cpi_bump,
    };
    ctx.transfer_ciphertext(amt_in_ct, pc_token_program)?;
    let (metas, views) = pc_token_transfer_with_receipt_accounts(
        user_in_acct,
        vault_in_acct,
        user_in_bal_ct,
        vault_in_bal_ct,
        amt_in_ct,
        receipt_ct,
        caller_program,
        ep,
        cfg,
        dep,
        pc_token_cpi_auth,
        pc_token_program,
        nk,
        payer,
        evt,
        sys,
    );
    cpi_pc_token_transfer_with_receipt(pc_token_program, token_cpi_bump, &metas, &views)?;

    // 2) Run swap math against the receipt. min_out_ct slot becomes `refund`
    //    (= 0 on success, = receipt on slippage rejection). final_out is 0 if
    //    the deposit no-op'd or slippage failed; reserves move in lockstep.
    ctx.swap_graph(
        reserve_in_ct,
        reserve_out_ct,
        receipt_ct,
        min_out_ct,
        min_out_ct,     // out 0: refund (re-tags min_out_ct, paid back below)
        amt_out_ct,     // out 1: final_out
        reserve_in_ct,  // out 2: new_reserve_in
        reserve_out_ct, // out 3: new_reserve_out
    )?;

    // 3) Hand off final_out to pc-token, then CPI pc-token::transfer (vault → user) signed by pool PDA.
    ctx.transfer_ciphertext(amt_out_ct, pc_token_program)?;
    let bb = [pool.bump];
    let pool_seeds = [
        Seed::from(b"pc_pool" as &[u8]),
        Seed::from(pool.mint_a.as_ref()),
        Seed::from(pool.mint_b.as_ref()),
        Seed::from(&bb),
    ];
    let (metas, views) = pc_token_transfer_accounts(
        vault_out_acct,
        user_out_acct,
        vault_out_bal_ct,
        user_out_bal_ct,
        amt_out_ct,
        ep,
        cfg,
        dep,
        pc_token_cpi_auth,
        pc_token_program,
        nk,
        pool_acct,
        evt,
        sys,
    );
    cpi_pc_token_transfer(
        pc_token_program,
        token_cpi_bump,
        &metas,
        &views,
        Some(&pool_seeds),
    )?;

    // 4) Refund: vault_in → user. min_out_ct now holds the refund amount
    //    (= 0 on a successful swap, = receipt when slippage rejected the swap).
    //    Pays back the deposit so a slipped swap doesn't strand pc-tokens
    //    in the pool's vault. Authorized to pc-swap currently — re-tag to
    //    pc-token so the transfer CPI's input auth check passes.
    ctx.transfer_ciphertext(min_out_ct, pc_token_program)?;
    pool_signed_transfer(
        vault_in_acct,
        user_in_acct,
        vault_in_bal_ct,
        user_in_bal_ct,
        min_out_ct,
        ep,
        cfg,
        dep,
        pc_token_cpi_auth,
        pc_token_program,
        nk,
        pool_acct,
        evt,
        sys,
        token_cpi_bump,
        &pool_seeds,
    )?;

    // 5) Reclaim receipt rent. close_ciphertext signs as pc-swap's CPI auth and
    //    requires receipt.authorized == pc-swap, which holds (set by step 1).
    ctx.close_ciphertext(receipt_ct, payer)?;
    Ok(())
}

// ── 2: AddLiquidity ──
//
// Receipt-gated: each user→vault deposit goes through TransferWithReceipt;
// add_liquidity_graph reads both receipts as the trusted deposit amounts.
// If either deposit no-ops (insufficient balance), the corresponding
// receipt is 0 and reserves / LP supply stay consistent.
//
// Accounts:
//   pool_acct (write), lp_pos_acct (read),
//   user_a_acct, user_b_acct           (user's pc-token TAs)
//   vault_a_acct, vault_b_acct         (pool's pc-token vaults)
//   user_a_bal_ct, user_b_bal_ct, vault_a_bal_ct, vault_b_bal_ct,
//   reserve_a_ct, reserve_b_ct, total_supply_ct,
//   amt_a_ct, amt_b_ct, user_lp_ct,
//   receipt_a_ct, receipt_b_ct          (fresh keypairs, signers)
//   ep, cfg, dep,
//   cpi_authority (pc-swap), caller_program (pc-swap),
//   pc_token_cpi_auth, pc_token_program,
//   nk, payer (signer = user, also LP owner), evt, sys
//
// Data: [2, swap_cpi_bump, token_cpi_bump]
fn add_liquidity(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [
        pool_acct,
        lp_pos_acct,
        user_a_acct,
        user_b_acct,
        vault_a_acct,
        vault_b_acct,
        user_a_bal_ct,
        user_b_bal_ct,
        vault_a_bal_ct,
        vault_b_bal_ct,
        ra_ct,
        rb_ct,
        ts_ct,
        amt_a_ct,
        amt_b_ct,
        user_lp_ct,
        receipt_a_ct,
        receipt_b_ct,
        ep,
        cfg,
        dep,
        cpi_authority,
        caller_program,
        pc_token_cpi_auth,
        pc_token_program,
        nk,
        payer,
        evt,
        sys,
        ..,
    ] = accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !payer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if data.len() < 2 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let swap_cpi_bump = data[0];
    let token_cpi_bump = data[1];

    let pd = unsafe { pool_acct.borrow_unchecked() };
    let pool = Pool::from_bytes(pd)?;
    if pool.is_initialized != 1 {
        return Err(ProgramError::UninitializedAccount);
    }
    if vault_a_acct.address().as_ref() != &pool.vault_a {
        return Err(ProgramError::InvalidArgument);
    }
    if vault_b_acct.address().as_ref() != &pool.vault_b {
        return Err(ProgramError::InvalidArgument);
    }
    if ra_ct.address().as_ref() != &pool.reserve_a {
        return Err(ProgramError::InvalidArgument);
    }
    if rb_ct.address().as_ref() != &pool.reserve_b {
        return Err(ProgramError::InvalidArgument);
    }
    if ts_ct.address().as_ref() != &pool.total_supply {
        return Err(ProgramError::InvalidArgument);
    }

    let lpd = unsafe { lp_pos_acct.borrow_unchecked() };
    let lp_pos = LpPosition::from_bytes(lpd)?;
    if &lp_pos.pool != pool_acct.address().as_array() {
        return Err(ProgramError::InvalidArgument);
    }
    if &lp_pos.owner != payer.address().as_array() {
        return Err(ProgramError::InvalidArgument);
    }
    if user_lp_ct.address().as_ref() != &lp_pos.balance {
        return Err(ProgramError::InvalidArgument);
    }

    let ctx = EncryptContext {
        encrypt_program: ep,
        config: cfg,
        deposit: dep,
        cpi_authority,
        caller_program,
        network_encryption_key: nk,
        payer,
        event_authority: evt,
        system_program: sys,
        cpi_authority_bump: swap_cpi_bump,
    };

    // 1) Transfer A with receipt: user → vault_a, receipt authorized to pc-swap.
    ctx.transfer_ciphertext(amt_a_ct, pc_token_program)?;
    let (metas, views) = pc_token_transfer_with_receipt_accounts(
        user_a_acct,
        vault_a_acct,
        user_a_bal_ct,
        vault_a_bal_ct,
        amt_a_ct,
        receipt_a_ct,
        caller_program,
        ep,
        cfg,
        dep,
        pc_token_cpi_auth,
        pc_token_program,
        nk,
        payer,
        evt,
        sys,
    );
    cpi_pc_token_transfer_with_receipt(pc_token_program, token_cpi_bump, &metas, &views)?;

    // 2) Transfer B with receipt: user → vault_b.
    ctx.transfer_ciphertext(amt_b_ct, pc_token_program)?;
    let (metas, views) = pc_token_transfer_with_receipt_accounts(
        user_b_acct,
        vault_b_acct,
        user_b_bal_ct,
        vault_b_bal_ct,
        amt_b_ct,
        receipt_b_ct,
        caller_program,
        ep,
        cfg,
        dep,
        pc_token_cpi_auth,
        pc_token_program,
        nk,
        payer,
        evt,
        sys,
    );
    cpi_pc_token_transfer_with_receipt(pc_token_program, token_cpi_bump, &metas, &views)?;

    // 3) Run liquidity math against the receipts. Reserves, supply, and LP
    //    only update when both deposits settled; otherwise refund_a / refund_b
    //    carry the truthful side back unchanged.
    ctx.add_liquidity_graph(
        ra_ct,
        rb_ct,
        ts_ct,
        receipt_a_ct,
        receipt_b_ct,
        user_lp_ct,
        amt_a_ct,   // out 0: refund_a (re-tags amt_a_ct)
        amt_b_ct,   // out 1: refund_b (re-tags amt_b_ct)
        ra_ct,      // out 2: new_reserve_a
        rb_ct,      // out 3: new_reserve_b
        ts_ct,      // out 4: new_total_supply
        user_lp_ct, // out 5: new_user_lp
    )?;

    // 4) Refunds: vault → user for each side (= 0 on a fully-settled deposit,
    //    = receipt when the deposit didn't settle). amt_*_ct are already
    //    pc-token-authorized from steps 1 / 2, so no transfer_ciphertext needed.
    let bb = [pool.bump];
    let pool_seeds = [
        Seed::from(b"pc_pool" as &[u8]),
        Seed::from(pool.mint_a.as_ref()),
        Seed::from(pool.mint_b.as_ref()),
        Seed::from(&bb),
    ];
    pool_signed_transfer(
        vault_a_acct,
        user_a_acct,
        vault_a_bal_ct,
        user_a_bal_ct,
        amt_a_ct,
        ep,
        cfg,
        dep,
        pc_token_cpi_auth,
        pc_token_program,
        nk,
        pool_acct,
        evt,
        sys,
        token_cpi_bump,
        &pool_seeds,
    )?;
    pool_signed_transfer(
        vault_b_acct,
        user_b_acct,
        vault_b_bal_ct,
        user_b_bal_ct,
        amt_b_ct,
        ep,
        cfg,
        dep,
        pc_token_cpi_auth,
        pc_token_program,
        nk,
        pool_acct,
        evt,
        sys,
        token_cpi_bump,
        &pool_seeds,
    )?;

    // 5) Reclaim receipt rent.
    ctx.close_ciphertext(receipt_a_ct, payer)?;
    ctx.close_ciphertext(receipt_b_ct, payer)?;
    Ok(())
}

// ── 4: RemoveLiquidity ──
//
// Accounts: similar to AddLiquidity but vault → user, plus out_a_ct, out_b_ct.
// Data: [4, swap_cpi_bump, token_cpi_bump]
fn remove_liquidity(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [
        pool_acct,
        lp_pos_acct,
        user_a_acct,
        user_b_acct,
        vault_a_acct,
        vault_b_acct,
        user_a_bal_ct,
        user_b_bal_ct,
        vault_a_bal_ct,
        vault_b_bal_ct,
        ra_ct,
        rb_ct,
        ts_ct,
        burn_ct,
        user_lp_ct,
        out_a_ct,
        out_b_ct,
        ep,
        cfg,
        dep,
        cpi_authority,
        caller_program,
        pc_token_cpi_auth,
        pc_token_program,
        nk,
        payer,
        evt,
        sys,
        ..,
    ] = accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !payer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if data.len() < 2 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let swap_cpi_bump = data[0];
    let token_cpi_bump = data[1];

    let pd = unsafe { pool_acct.borrow_unchecked() };
    let pool = Pool::from_bytes(pd)?;
    if pool.is_initialized != 1 {
        return Err(ProgramError::UninitializedAccount);
    }
    if vault_a_acct.address().as_ref() != &pool.vault_a {
        return Err(ProgramError::InvalidArgument);
    }
    if vault_b_acct.address().as_ref() != &pool.vault_b {
        return Err(ProgramError::InvalidArgument);
    }
    if ra_ct.address().as_ref() != &pool.reserve_a {
        return Err(ProgramError::InvalidArgument);
    }
    if rb_ct.address().as_ref() != &pool.reserve_b {
        return Err(ProgramError::InvalidArgument);
    }
    if ts_ct.address().as_ref() != &pool.total_supply {
        return Err(ProgramError::InvalidArgument);
    }

    let lpd = unsafe { lp_pos_acct.borrow_unchecked() };
    let lp_pos = LpPosition::from_bytes(lpd)?;
    if &lp_pos.pool != pool_acct.address().as_array() {
        return Err(ProgramError::InvalidArgument);
    }
    if &lp_pos.owner != payer.address().as_array() {
        return Err(ProgramError::InvalidArgument);
    }
    if user_lp_ct.address().as_ref() != &lp_pos.balance {
        return Err(ProgramError::InvalidArgument);
    }

    // 1) Run remove math: out_a/out_b are 0 if user_lp < burn → transfers no-op.
    let ctx = EncryptContext {
        encrypt_program: ep,
        config: cfg,
        deposit: dep,
        cpi_authority,
        caller_program,
        network_encryption_key: nk,
        payer,
        event_authority: evt,
        system_program: sys,
        cpi_authority_bump: swap_cpi_bump,
    };
    ctx.remove_liquidity_graph(
        ra_ct, rb_ct, ts_ct, burn_ct, user_lp_ct, out_a_ct, out_b_ct, ra_ct, rb_ct, ts_ct,
        user_lp_ct,
    )?;

    // 2) vault_a → user_a, signed by pool PDA
    let bb = [pool.bump];
    let pool_seeds = [
        Seed::from(b"pc_pool" as &[u8]),
        Seed::from(pool.mint_a.as_ref()),
        Seed::from(pool.mint_b.as_ref()),
        Seed::from(&bb),
    ];

    ctx.transfer_ciphertext(out_a_ct, pc_token_program)?;
    let (metas, views) = pc_token_transfer_accounts(
        vault_a_acct,
        user_a_acct,
        vault_a_bal_ct,
        user_a_bal_ct,
        out_a_ct,
        ep,
        cfg,
        dep,
        pc_token_cpi_auth,
        pc_token_program,
        nk,
        pool_acct,
        evt,
        sys,
    );
    cpi_pc_token_transfer(
        pc_token_program,
        token_cpi_bump,
        &metas,
        &views,
        Some(&pool_seeds),
    )?;

    // 3) vault_b → user_b
    ctx.transfer_ciphertext(out_b_ct, pc_token_program)?;
    let (metas, views) = pc_token_transfer_accounts(
        vault_b_acct,
        user_b_acct,
        vault_b_bal_ct,
        user_b_bal_ct,
        out_b_ct,
        ep,
        cfg,
        dep,
        pc_token_cpi_auth,
        pc_token_program,
        nk,
        pool_acct,
        evt,
        sys,
    );
    cpi_pc_token_transfer(
        pc_token_program,
        token_cpi_bump,
        &metas,
        &views,
        Some(&pool_seeds),
    )?;
    Ok(())
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::{add_liquidity_graph, remove_liquidity_graph, swap_graph};
    use encrypt_types::graph::{GraphNodeKind, get_node, parse_graph};
    use encrypt_types::identifier::*;
    use encrypt_types::types::FheType;

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
                            unsafe { core::mem::transmute(n.op_type()) },
                            &digests[a],
                            ft,
                        )
                    } else {
                        mock_binary_compute(
                            unsafe { core::mem::transmute(n.op_type()) },
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

    const T: FheType = FheType::EUint64;

    #[test]
    fn swap_basic() {
        // reserve_in, reserve_out, receipt, min_out
        let r = run_mock(swap_graph, &[1000, 2000, 100, 0], &[T, T, T, T]);
        // r = (refund, final_out, new_reserve_in, new_reserve_out)
        assert_eq!(r[0], 0, "refund == 0 on success");
        assert!(r[1] > 0, "final_out > 0");
        assert_eq!(r[2], 1100);
        assert!(r[2] * r[3] >= 1000 * 2000);
    }
    #[test]
    fn swap_slippage() {
        let r = run_mock(swap_graph, &[1000, 2000, 100, 999], &[T, T, T, T]);
        assert_eq!(r[0], 100, "refund == receipt on slippage rejection");
        assert_eq!(r[1], 0, "final_out collapses to 0");
        assert_eq!(r[2], 1000, "reserve_in untouched");
        assert_eq!(r[3], 2000, "reserve_out untouched");
    }
    #[test]
    fn swap_lying_user_receipt_zero() {
        // user claims amount_in=100 but transfer no-op'd → receipt=0.
        // Reserves must stay 1000/2000, payout must be 0, refund must be 0.
        let r = run_mock(swap_graph, &[1000, 2000, 0, 0], &[T, T, T, T]);
        assert_eq!(r[0], 0, "refund == 0 (nothing was deposited)");
        assert_eq!(r[1], 0, "final_out collapses with receipt=0");
        assert_eq!(r[2], 1000, "reserve_in untouched");
        assert_eq!(r[3], 2000, "reserve_out untouched");
    }

    #[test]
    fn add_liq_first() {
        // reserve_a, reserve_b, total_supply, receipt_a, receipt_b, user_lp
        let r = run_mock(
            add_liquidity_graph,
            &[0, 0, 0, 1000, 2000, 0],
            &[T, T, T, T, T, T],
        );
        // r = (refund_a, refund_b, new_reserve_a, new_reserve_b, new_total_supply, new_user_lp)
        assert_eq!(r[0], 0, "refund_a == 0 on settled deposit");
        assert_eq!(r[1], 0, "refund_b == 0 on settled deposit");
        assert_eq!(r[2], 1000);
        assert_eq!(r[3], 2000);
        assert_eq!(r[4], 1000, "supply = receipt_a on first deposit");
        assert_eq!(r[5], 1000);
    }
    #[test]
    fn add_liq_second() {
        let supply = 1000u128;
        let r = run_mock(
            add_liquidity_graph,
            &[1000, 2000, supply, 500, 1000, 0],
            &[T, T, T, T, T, T],
        );
        assert_eq!(r[0], 0, "refund_a == 0");
        assert_eq!(r[1], 0, "refund_b == 0");
        assert_eq!(r[2], 1500);
        assert_eq!(r[3], 3000);
        assert!(r[4] > supply);
        assert!(r[5] > 0);
    }
    #[test]
    fn add_liq_lying_a_receipt_zero() {
        // user lied about token A: receipt_a=0, receipt_b=1000.
        // Atomic-deposit gate: settled=false → reserves untouched, supply
        // unchanged, full B-side receipt refunded.
        let supply = 1000u128;
        let r = run_mock(
            add_liquidity_graph,
            &[1000, 2000, supply, 0, 1000, 0],
            &[T, T, T, T, T, T],
        );
        assert_eq!(r[0], 0, "refund_a == 0 (nothing deposited)");
        assert_eq!(r[1], 1000, "refund_b == receipt_b (truthful side returned)");
        assert_eq!(r[2], 1000, "reserve_a untouched");
        assert_eq!(r[3], 2000, "reserve_b untouched (no donation)");
        assert_eq!(r[4], supply, "supply unchanged");
        assert_eq!(r[5], 0);
    }
    #[test]
    fn add_liq_lying_b_receipt_zero() {
        // user lied about token B: receipt_a=1000, receipt_b=0.
        // Symmetric to lying-A — A side gets refunded, no donation.
        let supply = 1000u128;
        let r = run_mock(
            add_liquidity_graph,
            &[1000, 2000, supply, 1000, 0, 0],
            &[T, T, T, T, T, T],
        );
        assert_eq!(r[0], 1000, "refund_a == receipt_a (truthful side returned)");
        assert_eq!(r[1], 0, "refund_b == 0");
        assert_eq!(r[2], 1000, "reserve_a untouched");
        assert_eq!(r[3], 2000, "reserve_b untouched");
        assert_eq!(r[4], supply);
        assert_eq!(r[5], 0);
    }

    #[test]
    fn remove_liq_sufficient() {
        // reserves 10000/20000, supply 100, burn 50, user_lp 50
        let r = run_mock(
            remove_liquidity_graph,
            &[10000, 20000, 100, 50, 50],
            &[T, T, T, T, T],
        );
        assert!(r[0] > 0);
        assert!(r[1] > 0);
        assert_eq!(r[5], 0, "user lp drained");
    }
    #[test]
    fn remove_liq_insufficient() {
        let r = run_mock(
            remove_liquidity_graph,
            &[10000, 20000, 100, 50, 30],
            &[T, T, T, T, T],
        );
        assert_eq!(r[0], 0);
        assert_eq!(r[1], 0);
        assert_eq!(r[2], 10000);
        assert_eq!(r[3], 20000);
        assert_eq!(r[4], 100);
        assert_eq!(r[5], 30);
    }

    #[test]
    fn graph_shapes() {
        let g = swap_graph();
        let pg = parse_graph(&g).unwrap();
        assert_eq!(pg.header().num_inputs(), 4);
        assert_eq!(pg.header().num_outputs(), 4);
        let g = add_liquidity_graph();
        let pg = parse_graph(&g).unwrap();
        assert_eq!(pg.header().num_inputs(), 6);
        assert_eq!(pg.header().num_outputs(), 6);
        let g = remove_liquidity_graph();
        let pg = parse_graph(&g).unwrap();
        assert_eq!(pg.header().num_inputs(), 5);
        assert_eq!(pg.header().num_outputs(), 6);
    }
}
