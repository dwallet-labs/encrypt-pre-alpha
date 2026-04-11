// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#![allow(unexpected_cfgs)]

/// PC-Token (Confidential Performant Token) — P-Token rebuilt with
/// Encrypt FHE for on-chain confidentiality.
///
/// All balances and transfer amounts are encrypted. There is no
/// decrypt instruction on the TokenAccount — balances are never
/// revealed on-chain. The only plaintext values that ever appear
/// are wrap/unwrap amounts at the SPL boundary, and those live on
/// temporary WithdrawalReceipt accounts that get closed immediately.
///
/// ## Instructions (P-Token discriminators)
///
///  0. InitializeMint
///  1. InitializeAccount
///  3. Transfer (encrypted amount)
///  4. Approve (encrypted allowance)
///  5. Revoke
///  7. MintTo (encrypted amount)
///  8. Burn (encrypted amount)
///  9. CloseAccount
/// 10. FreezeAccount
/// 11. ThawAccount
/// 20. TransferFrom (delegate, composability)
/// 23. InitializeVault
/// 30. Wrap (SPL → pcToken)
/// 31. UnwrapBurn (burn pcTokens + create withdrawal receipt)
/// 32. UnwrapDecrypt (request decryption of burned amount)
/// 33. UnwrapComplete (verify + release SPL tokens + close receipt)
use encrypt_dsl::prelude::encrypt_fn;
use encrypt_pinocchio::accounts;
use encrypt_pinocchio::EncryptContext;
use encrypt_types::encrypted::{EUint64, Uint64};
use pinocchio::{
    cpi::{Seed, Signer},
    entrypoint,
    error::ProgramError,
    AccountView, Address, ProgramResult,
};
use pinocchio_system::instructions::CreateAccount;
use pinocchio_token::instructions::Transfer as SplTransfer;

entrypoint!(process_instruction);

pub const ID: Address = Address::new_from_array([5u8; 32]);

// ── AccountState ──

#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum AccountState { Uninitialized = 0, Initialized = 1, Frozen = 2 }
impl From<u8> for AccountState { fn from(v: u8) -> Self { match v { 1 => Self::Initialized, 2 => Self::Frozen, _ => Self::Uninitialized } } }

const COPTION_NONE: [u8; 4] = [0, 0, 0, 0];
const COPTION_SOME: [u8; 4] = [1, 0, 0, 0];

// ── Account layouts ──

#[repr(C)]
pub struct Mint {
    pub mint_authority_flag: [u8; 4],
    pub mint_authority: [u8; 32],
    pub decimals: u8,
    pub is_initialized: u8,
    pub freeze_authority_flag: [u8; 4],
    pub freeze_authority: [u8; 32],
    pub bump: u8,
}
impl Mint {
    pub const LEN: usize = core::mem::size_of::<Self>();
    pub fn from_bytes(d: &[u8]) -> Result<&Self, ProgramError> { if d.len() < Self::LEN { return Err(ProgramError::InvalidAccountData); } Ok(unsafe { &*(d.as_ptr() as *const Self) }) }
    pub fn from_bytes_mut(d: &mut [u8]) -> Result<&mut Self, ProgramError> { if d.len() < Self::LEN { return Err(ProgramError::InvalidAccountData); } Ok(unsafe { &mut *(d.as_mut_ptr() as *mut Self) }) }
    pub fn is_initialized(&self) -> bool { self.is_initialized == 1 }
    pub fn has_mint_authority(&self) -> bool { self.mint_authority_flag == COPTION_SOME }
    pub fn has_freeze_authority(&self) -> bool { self.freeze_authority_flag == COPTION_SOME }
}

/// TokenAccount — NO plaintext fields. Balance is always encrypted.
#[repr(C)]
pub struct TokenAccount {
    pub mint: [u8; 32],
    pub owner: [u8; 32],
    pub balance: EUint64,
    pub delegate_flag: [u8; 4],
    pub delegate: [u8; 32],
    pub state: u8,
    pub allowance: EUint64,
    pub close_authority_flag: [u8; 4],
    pub close_authority: [u8; 32],
    pub bump: u8,
}
impl TokenAccount {
    pub const LEN: usize = core::mem::size_of::<Self>();
    pub fn from_bytes(d: &[u8]) -> Result<&Self, ProgramError> { if d.len() < Self::LEN { return Err(ProgramError::InvalidAccountData); } Ok(unsafe { &*(d.as_ptr() as *const Self) }) }
    pub fn from_bytes_mut(d: &mut [u8]) -> Result<&mut Self, ProgramError> { if d.len() < Self::LEN { return Err(ProgramError::InvalidAccountData); } Ok(unsafe { &mut *(d.as_mut_ptr() as *mut Self) }) }
    pub fn is_frozen(&self) -> bool { self.state == AccountState::Frozen as u8 }
    pub fn is_initialized(&self) -> bool { self.state != AccountState::Uninitialized as u8 }
    pub fn has_delegate(&self) -> bool { self.delegate_flag == COPTION_SOME }
    pub fn has_close_authority(&self) -> bool { self.close_authority_flag == COPTION_SOME }
}

#[repr(C)]
pub struct Vault { pub spl_mint: [u8; 32], pub bump: u8 }
impl Vault {
    pub const LEN: usize = core::mem::size_of::<Self>();
    pub fn from_bytes(d: &[u8]) -> Result<&Self, ProgramError> { if d.len() < Self::LEN { return Err(ProgramError::InvalidAccountData); } Ok(unsafe { &*(d.as_ptr() as *const Self) }) }
    pub fn from_bytes_mut(d: &mut [u8]) -> Result<&mut Self, ProgramError> { if d.len() < Self::LEN { return Err(ProgramError::InvalidAccountData); } Ok(unsafe { &mut *(d.as_mut_ptr() as *mut Self) }) }
}

/// Temporary receipt for unwrap — stores only the withdrawal amount + digest.
/// PDA: `["pc_receipt", burned_ct]`. Closed after unwrap completes.
#[repr(C)]
pub struct WithdrawalReceipt {
    pub owner: [u8; 32],
    pub amount: [u8; 8],           // requested plaintext amount
    pub pending_digest: [u8; 32],  // digest for decryption verification
    pub bump: u8,
}
impl WithdrawalReceipt {
    pub const LEN: usize = core::mem::size_of::<Self>();
    pub fn from_bytes(d: &[u8]) -> Result<&Self, ProgramError> { if d.len() < Self::LEN { return Err(ProgramError::InvalidAccountData); } Ok(unsafe { &*(d.as_ptr() as *const Self) }) }
    pub fn from_bytes_mut(d: &mut [u8]) -> Result<&mut Self, ProgramError> { if d.len() < Self::LEN { return Err(ProgramError::InvalidAccountData); } Ok(unsafe { &mut *(d.as_mut_ptr() as *mut Self) }) }
    pub fn requested_amount(&self) -> u64 { u64::from_le_bytes(self.amount) }
}

fn minimum_balance(s: usize) -> u64 { (s as u64 + 128) * 6960 }
fn assert_not_frozen(ta: &TokenAccount) -> ProgramResult { if ta.is_frozen() { Err(ProgramError::Custom(0x11)) } else { Ok(()) } }

// ── FHE Graphs ──

#[encrypt_fn] fn mint_to_graph(balance: EUint64, amount: EUint64) -> EUint64 { balance + amount }

#[encrypt_fn] fn transfer_graph(from_balance: EUint64, to_balance: EUint64, amount: EUint64) -> (EUint64, EUint64) {
    let s = from_balance >= amount;
    let nf = if s { from_balance - amount } else { from_balance };
    let nt = if s { to_balance + amount } else { to_balance };
    (nf, nt)
}

#[encrypt_fn] fn burn_graph(balance: EUint64, amount: EUint64) -> EUint64 {
    let s = balance >= amount; if s { balance - amount } else { balance }
}

#[encrypt_fn] fn transfer_from_graph(from_balance: EUint64, to_balance: EUint64, allowance: EUint64, amount: EUint64) -> (EUint64, EUint64, EUint64) {
    let sb = from_balance >= amount; let sa = allowance >= amount; let v = sb & sa;
    let nf = if v { from_balance - amount } else { from_balance };
    let nt = if v { to_balance + amount } else { to_balance };
    let na = if v { allowance - amount } else { allowance };
    (nf, nt, na)
}

/// Unwrap burn: conditional burn that outputs the actual burned amount.
/// burned = amount if sufficient, 0 if not.
#[encrypt_fn] fn unwrap_burn_graph(balance: EUint64, amount: EUint64) -> (EUint64, EUint64) {
    let s = balance >= amount;
    let new_balance = if s { balance - amount } else { balance };
    let burned = if s { amount } else { amount - amount };
    (new_balance, burned)
}

// ── Dispatch ──

fn process_instruction(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    match data.split_first() {
        Some((&0, rest)) => initialize_mint(program_id, accounts, rest),
        Some((&1, rest)) => initialize_account(program_id, accounts, rest),
        Some((&3, rest)) => transfer(accounts, rest),
        Some((&4, rest)) => approve(accounts, rest),
        Some((&5, rest)) => revoke(accounts, rest),
        // No standalone MintTo — tokens can only enter through Wrap (vault-backed)
        // No standalone Burn — tokens can only exit through Unwrap (releases backing SPL)
        Some((&10, rest)) => freeze_account(accounts, rest),
        Some((&11, rest)) => thaw_account(accounts, rest),
        Some((&20, rest)) => transfer_from(accounts, rest),
        Some((&23, rest)) => initialize_vault(program_id, accounts, rest),
        Some((&30, rest)) => wrap(accounts, rest),
        Some((&31, rest)) => unwrap_burn(program_id, accounts, rest),
        Some((&32, rest)) => unwrap_decrypt(accounts, rest),
        Some((&33, _rest)) => unwrap_complete(accounts),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

// ── 0: InitializeMint ──

fn initialize_mint(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [mint_acct, authority, payer, _sys, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys); };
    if !authority.is_signer() || !payer.is_signer() { return Err(ProgramError::MissingRequiredSignature); }
    if data.len() < 34 { return Err(ProgramError::InvalidInstructionData); }
    let (bump, decimals) = (data[0], data[1]);
    let mint_authority: [u8; 32] = data[2..34].try_into().unwrap();
    let has_freeze = data.len() > 34 && data[34] != 0;
    let freeze_authority: [u8; 32] = if has_freeze && data.len() >= 66 { data[35..67].try_into().unwrap() } else { [0u8; 32] };
    let bb = [bump];
    let seeds = [Seed::from(b"pc_mint" as &[u8]), Seed::from(authority.address().as_ref()), Seed::from(&bb)];
    CreateAccount { from: payer, to: mint_acct, lamports: minimum_balance(Mint::LEN), space: Mint::LEN as u64, owner: program_id }.invoke_signed(&[Signer::from(&seeds)])?;
    let d = unsafe { mint_acct.borrow_unchecked_mut() };
    let m = Mint::from_bytes_mut(d)?;
    m.mint_authority_flag = COPTION_SOME; m.mint_authority.copy_from_slice(&mint_authority);
    m.decimals = decimals; m.is_initialized = 1;
    if has_freeze { m.freeze_authority_flag = COPTION_SOME; m.freeze_authority.copy_from_slice(&freeze_authority); }
    else { m.freeze_authority_flag = COPTION_NONE; m.freeze_authority = [0u8; 32]; }
    m.bump = bump; Ok(())
}

// ── 1: InitializeAccount ──

fn initialize_account(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [ta_acct, mint_acct, owner, bal_ct, ep, cfg, dep, cpi_auth, caller, nk, payer, evt, sys, ..] = accounts
    else { return Err(ProgramError::NotEnoughAccountKeys); };
    if !payer.is_signer() { return Err(ProgramError::MissingRequiredSignature); }
    if data.len() < 2 { return Err(ProgramError::InvalidInstructionData); }
    let (ab, cb) = (data[0], data[1]);
    let md = unsafe { mint_acct.borrow_unchecked() };
    if !Mint::from_bytes(md)?.is_initialized() { return Err(ProgramError::UninitializedAccount); }
    let bb = [ab];
    let seeds = [Seed::from(b"pc_account" as &[u8]), Seed::from(mint_acct.address().as_ref()), Seed::from(owner.address().as_ref()), Seed::from(&bb)];
    CreateAccount { from: payer, to: ta_acct, lamports: minimum_balance(TokenAccount::LEN), space: TokenAccount::LEN as u64, owner: program_id }.invoke_signed(&[Signer::from(&seeds)])?;
    let ctx = EncryptContext { encrypt_program: ep, config: cfg, deposit: dep, cpi_authority: cpi_auth, caller_program: caller, network_encryption_key: nk, payer, event_authority: evt, system_program: sys, cpi_authority_bump: cb };
    ctx.create_plaintext_typed::<Uint64>(&0u64, bal_ct)?;
    let d = unsafe { ta_acct.borrow_unchecked_mut() };
    let ta = TokenAccount::from_bytes_mut(d)?;
    ta.mint.copy_from_slice(mint_acct.address().as_ref());
    ta.owner.copy_from_slice(owner.address().as_ref());
    ta.balance = EUint64::from_le_bytes(*bal_ct.address().as_array());
    ta.delegate_flag = COPTION_NONE; ta.delegate = [0u8; 32];
    ta.state = AccountState::Initialized as u8;
    ta.allowance = EUint64::from_le_bytes([0u8; 32]);
    ta.close_authority_flag = COPTION_NONE; ta.close_authority = [0u8; 32];
    ta.bump = ab; Ok(())
}

// ── 7: MintTo ──

fn mint_to(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [mint_acct, ta_acct, bal_ct, amt_ct, ep, cfg, dep, cpi_auth, caller, nk, authority, evt, sys, ..] = accounts
    else { return Err(ProgramError::NotEnoughAccountKeys); };
    if !authority.is_signer() { return Err(ProgramError::MissingRequiredSignature); }
    if data.is_empty() { return Err(ProgramError::InvalidInstructionData); }
    let md = unsafe { mint_acct.borrow_unchecked() };
    let m = Mint::from_bytes(md)?;
    if !m.has_mint_authority() || authority.address().as_array() != &m.mint_authority { return Err(ProgramError::InvalidArgument); }
    let td = unsafe { ta_acct.borrow_unchecked() };
    let ta = TokenAccount::from_bytes(td)?;
    if !ta.is_initialized() { return Err(ProgramError::UninitializedAccount); }
    assert_not_frozen(ta)?;
    if &ta.mint != mint_acct.address().as_array() { return Err(ProgramError::InvalidArgument); }
    if bal_ct.address().as_array() != ta.balance.id() { return Err(ProgramError::InvalidArgument); }
    let ctx = EncryptContext { encrypt_program: ep, config: cfg, deposit: dep, cpi_authority: cpi_auth, caller_program: caller, network_encryption_key: nk, payer: authority, event_authority: evt, system_program: sys, cpi_authority_bump: data[0] };
    ctx.mint_to_graph(bal_ct, amt_ct, bal_ct)?; Ok(())
}

// ── 3: Transfer ──

fn transfer(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [from_acct, to_acct, from_ct, to_ct, amt_ct, ep, cfg, dep, cpi_auth, caller, nk, owner, evt, sys, ..] = accounts
    else { return Err(ProgramError::NotEnoughAccountKeys); };
    if !owner.is_signer() { return Err(ProgramError::MissingRequiredSignature); }
    if data.is_empty() { return Err(ProgramError::InvalidInstructionData); }
    let fd = unsafe { from_acct.borrow_unchecked() };
    let ft = TokenAccount::from_bytes(fd)?;
    if !ft.is_initialized() { return Err(ProgramError::UninitializedAccount); }
    assert_not_frozen(ft)?;
    if owner.address().as_array() != &ft.owner { return Err(ProgramError::InvalidArgument); }
    let td = unsafe { to_acct.borrow_unchecked() };
    let tt = TokenAccount::from_bytes(td)?;
    if !tt.is_initialized() { return Err(ProgramError::UninitializedAccount); }
    assert_not_frozen(tt)?;
    if ft.mint != tt.mint { return Err(ProgramError::InvalidArgument); }
    if from_ct.address().as_array() != ft.balance.id() { return Err(ProgramError::InvalidArgument); }
    if to_ct.address().as_array() != tt.balance.id() { return Err(ProgramError::InvalidArgument); }
    let ctx = EncryptContext { encrypt_program: ep, config: cfg, deposit: dep, cpi_authority: cpi_auth, caller_program: caller, network_encryption_key: nk, payer: owner, event_authority: evt, system_program: sys, cpi_authority_bump: data[0] };
    ctx.transfer_graph(from_ct, to_ct, amt_ct, from_ct, to_ct)?; Ok(())
}

// ── 4: Approve ──

fn approve(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [ta_acct, delegate, amt_ct, allow_ct, ep, cfg, dep, cpi_auth, caller, nk, owner, evt, sys, ..] = accounts
    else { return Err(ProgramError::NotEnoughAccountKeys); };
    if !owner.is_signer() { return Err(ProgramError::MissingRequiredSignature); }
    if data.is_empty() { return Err(ProgramError::InvalidInstructionData); }
    let td = unsafe { ta_acct.borrow_unchecked() };
    let ta = TokenAccount::from_bytes(td)?;
    if !ta.is_initialized() { return Err(ProgramError::UninitializedAccount); }
    assert_not_frozen(ta)?;
    if owner.address().as_array() != &ta.owner { return Err(ProgramError::InvalidArgument); }
    let ctx = EncryptContext { encrypt_program: ep, config: cfg, deposit: dep, cpi_authority: cpi_auth, caller_program: caller, network_encryption_key: nk, payer: owner, event_authority: evt, system_program: sys, cpi_authority_bump: data[0] };
    ctx.create_plaintext_typed::<Uint64>(&0u64, allow_ct)?;
    ctx.mint_to_graph(allow_ct, amt_ct, allow_ct)?;
    let td2 = unsafe { ta_acct.borrow_unchecked_mut() };
    let ta2 = TokenAccount::from_bytes_mut(td2)?;
    ta2.delegate_flag = COPTION_SOME;
    ta2.delegate.copy_from_slice(delegate.address().as_ref());
    ta2.allowance = EUint64::from_le_bytes(*allow_ct.address().as_array());
    Ok(())
}

// ── 5: Revoke ──

fn revoke(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [ta_acct, allow_ct, owner, ep, cfg, dep, cpi_auth, caller, nk, payer, evt, sys, ..] = accounts
    else { return Err(ProgramError::NotEnoughAccountKeys); };
    if !owner.is_signer() { return Err(ProgramError::MissingRequiredSignature); }
    if data.is_empty() { return Err(ProgramError::InvalidInstructionData); }
    let td = unsafe { ta_acct.borrow_unchecked() };
    let ta = TokenAccount::from_bytes(td)?;
    if owner.address().as_array() != &ta.owner { return Err(ProgramError::InvalidArgument); }
    if !ta.has_delegate() { return Err(ProgramError::InvalidArgument); }
    if allow_ct.address().as_array() != ta.allowance.id() { return Err(ProgramError::InvalidArgument); }
    let ctx = EncryptContext { encrypt_program: ep, config: cfg, deposit: dep, cpi_authority: cpi_auth, caller_program: caller, network_encryption_key: nk, payer, event_authority: evt, system_program: sys, cpi_authority_bump: data[0] };
    ctx.close_ciphertext(allow_ct, payer)?;
    let td2 = unsafe { ta_acct.borrow_unchecked_mut() };
    let ta2 = TokenAccount::from_bytes_mut(td2)?;
    ta2.delegate_flag = COPTION_NONE; ta2.delegate = [0u8; 32]; ta2.allowance = EUint64::from_le_bytes([0u8; 32]); Ok(())
}

// ── 8: Burn ──

fn burn(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [ta_acct, mint_acct, bal_ct, amt_ct, ep, cfg, dep, cpi_auth, caller, nk, owner, evt, sys, ..] = accounts
    else { return Err(ProgramError::NotEnoughAccountKeys); };
    if !owner.is_signer() { return Err(ProgramError::MissingRequiredSignature); }
    if data.is_empty() { return Err(ProgramError::InvalidInstructionData); }
    let td = unsafe { ta_acct.borrow_unchecked() };
    let ta = TokenAccount::from_bytes(td)?;
    if !ta.is_initialized() { return Err(ProgramError::UninitializedAccount); }
    assert_not_frozen(ta)?;
    if owner.address().as_array() != &ta.owner { return Err(ProgramError::InvalidArgument); }
    if &ta.mint != mint_acct.address().as_array() { return Err(ProgramError::InvalidArgument); }
    if bal_ct.address().as_array() != ta.balance.id() { return Err(ProgramError::InvalidArgument); }
    let ctx = EncryptContext { encrypt_program: ep, config: cfg, deposit: dep, cpi_authority: cpi_auth, caller_program: caller, network_encryption_key: nk, payer: owner, event_authority: evt, system_program: sys, cpi_authority_bump: data[0] };
    ctx.burn_graph(bal_ct, amt_ct, bal_ct)?; Ok(())
}

// ── 10: FreezeAccount ──

fn freeze_account(accounts: &[AccountView], _data: &[u8]) -> ProgramResult {
    let [ta_acct, mint_acct, freeze_auth, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys); };
    if !freeze_auth.is_signer() { return Err(ProgramError::MissingRequiredSignature); }
    let md = unsafe { mint_acct.borrow_unchecked() };
    let m = Mint::from_bytes(md)?;
    if !m.has_freeze_authority() || freeze_auth.address().as_array() != &m.freeze_authority { return Err(ProgramError::InvalidArgument); }
    let td = unsafe { ta_acct.borrow_unchecked() };
    let ta = TokenAccount::from_bytes(td)?;
    if !ta.is_initialized() { return Err(ProgramError::UninitializedAccount); }
    if &ta.mint != mint_acct.address().as_array() { return Err(ProgramError::InvalidArgument); }
    let td2 = unsafe { ta_acct.borrow_unchecked_mut() };
    TokenAccount::from_bytes_mut(td2)?.state = AccountState::Frozen as u8; Ok(())
}

// ── 11: ThawAccount ──

fn thaw_account(accounts: &[AccountView], _data: &[u8]) -> ProgramResult {
    let [ta_acct, mint_acct, freeze_auth, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys); };
    if !freeze_auth.is_signer() { return Err(ProgramError::MissingRequiredSignature); }
    let md = unsafe { mint_acct.borrow_unchecked() };
    let m = Mint::from_bytes(md)?;
    if !m.has_freeze_authority() || freeze_auth.address().as_array() != &m.freeze_authority { return Err(ProgramError::InvalidArgument); }
    let td = unsafe { ta_acct.borrow_unchecked() };
    let ta = TokenAccount::from_bytes(td)?;
    if !ta.is_frozen() { return Err(ProgramError::InvalidArgument); }
    if &ta.mint != mint_acct.address().as_array() { return Err(ProgramError::InvalidArgument); }
    let td2 = unsafe { ta_acct.borrow_unchecked_mut() };
    TokenAccount::from_bytes_mut(td2)?.state = AccountState::Initialized as u8; Ok(())
}

// ── 20: TransferFrom ──

fn transfer_from(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [from_acct, to_acct, from_ct, to_ct, allow_ct, amt_ct, delegate, ep, cfg, dep, cpi_auth, caller, nk, payer, evt, sys, ..] = accounts
    else { return Err(ProgramError::NotEnoughAccountKeys); };
    if !delegate.is_signer() || !payer.is_signer() { return Err(ProgramError::MissingRequiredSignature); }
    if data.is_empty() { return Err(ProgramError::InvalidInstructionData); }
    let fd = unsafe { from_acct.borrow_unchecked() };
    let ft = TokenAccount::from_bytes(fd)?;
    if !ft.is_initialized() { return Err(ProgramError::UninitializedAccount); }
    assert_not_frozen(ft)?;
    if !ft.has_delegate() || delegate.address().as_array() != &ft.delegate { return Err(ProgramError::InvalidArgument); }
    let td = unsafe { to_acct.borrow_unchecked() };
    let tt = TokenAccount::from_bytes(td)?;
    if !tt.is_initialized() { return Err(ProgramError::UninitializedAccount); }
    assert_not_frozen(tt)?;
    if ft.mint != tt.mint { return Err(ProgramError::InvalidArgument); }
    if from_ct.address().as_array() != ft.balance.id() { return Err(ProgramError::InvalidArgument); }
    if to_ct.address().as_array() != tt.balance.id() { return Err(ProgramError::InvalidArgument); }
    if allow_ct.address().as_array() != ft.allowance.id() { return Err(ProgramError::InvalidArgument); }
    let ctx = EncryptContext { encrypt_program: ep, config: cfg, deposit: dep, cpi_authority: cpi_auth, caller_program: caller, network_encryption_key: nk, payer, event_authority: evt, system_program: sys, cpi_authority_bump: data[0] };
    ctx.transfer_from_graph(from_ct, to_ct, allow_ct, amt_ct, from_ct, to_ct, allow_ct)?; Ok(())
}

// ── 23: InitializeVault ──

fn initialize_vault(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [vault_acct, pc_mint, spl_mint, payer, _sys, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys); };
    if !payer.is_signer() { return Err(ProgramError::MissingRequiredSignature); }
    if data.is_empty() { return Err(ProgramError::InvalidInstructionData); }
    let vb = data[0]; let md = unsafe { pc_mint.borrow_unchecked() };
    if !Mint::from_bytes(md)?.is_initialized() { return Err(ProgramError::UninitializedAccount); }
    let bb = [vb];
    let seeds = [Seed::from(b"pc_vault" as &[u8]), Seed::from(pc_mint.address().as_ref()), Seed::from(&bb)];
    CreateAccount { from: payer, to: vault_acct, lamports: minimum_balance(Vault::LEN), space: Vault::LEN as u64, owner: program_id }.invoke_signed(&[Signer::from(&seeds)])?;
    let d = unsafe { vault_acct.borrow_unchecked_mut() };
    let v = Vault::from_bytes_mut(d)?;
    v.spl_mint.copy_from_slice(spl_mint.address().as_ref()); v.bump = vb; Ok(())
}

// ── 30: Wrap ──

fn wrap(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [vault_acct, ta_acct, user_ata, vault_ata, bal_ct, amt_ct, ep, cfg, dep, cpi_auth, caller, nk, owner, evt, sys, _spl, ..] = accounts
    else { return Err(ProgramError::NotEnoughAccountKeys); };
    if !owner.is_signer() { return Err(ProgramError::MissingRequiredSignature); }
    if data.len() < 9 { return Err(ProgramError::InvalidInstructionData); }
    let (cb, amount) = (data[0], u64::from_le_bytes(data[1..9].try_into().unwrap()));
    if amount == 0 { return Err(ProgramError::InvalidArgument); }
    let td = unsafe { ta_acct.borrow_unchecked() };
    let ta = TokenAccount::from_bytes(td)?;
    if !ta.is_initialized() { return Err(ProgramError::UninitializedAccount); }
    assert_not_frozen(ta)?;
    if owner.address().as_array() != &ta.owner { return Err(ProgramError::InvalidArgument); }
    if bal_ct.address().as_array() != ta.balance.id() { return Err(ProgramError::InvalidArgument); }
    let vd = unsafe { vault_acct.borrow_unchecked() };
    let vault = Vault::from_bytes(vd)?;
    let vad = unsafe { vault_ata.borrow_unchecked() };
    if vad.len() < 64 { return Err(ProgramError::InvalidAccountData); }
    if &vad[32..64] != vault_acct.address().as_ref() { return Err(ProgramError::InvalidArgument); }
    if &vad[0..32] != &vault.spl_mint { return Err(ProgramError::InvalidArgument); }
    SplTransfer { from: user_ata, to: vault_ata, authority: owner, amount }.invoke()?;
    let ctx = EncryptContext { encrypt_program: ep, config: cfg, deposit: dep, cpi_authority: cpi_auth, caller_program: caller, network_encryption_key: nk, payer: owner, event_authority: evt, system_program: sys, cpi_authority_bump: cb };
    ctx.mint_to_graph(bal_ct, amt_ct, bal_ct)?; Ok(())
}

// ── 31: UnwrapBurn ──
// Burns pcTokens and creates a temporary WithdrawalReceipt.
// The burned_ct (pre-created via gRPC) receives the actual burned amount
// (= amount if sufficient, 0 if not). Receipt tracks the requested amount.

fn unwrap_burn(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [vault_acct, ta_acct, receipt_acct, bal_ct, amt_ct, burned_ct, ep, cfg, dep, cpi_auth, caller, nk, owner, evt, sys, ..] = accounts
    else { return Err(ProgramError::NotEnoughAccountKeys); };
    if !owner.is_signer() { return Err(ProgramError::MissingRequiredSignature); }
    if data.len() < 10 { return Err(ProgramError::InvalidInstructionData); }
    let (rb, cb) = (data[0], data[1]);
    let amount = u64::from_le_bytes(data[2..10].try_into().unwrap());
    if amount == 0 { return Err(ProgramError::InvalidArgument); }
    let _vd = unsafe { vault_acct.borrow_unchecked() };
    Vault::from_bytes(_vd)?;
    let td = unsafe { ta_acct.borrow_unchecked() };
    let ta = TokenAccount::from_bytes(td)?;
    if !ta.is_initialized() { return Err(ProgramError::UninitializedAccount); }
    assert_not_frozen(ta)?;
    if owner.address().as_array() != &ta.owner { return Err(ProgramError::InvalidArgument); }
    if bal_ct.address().as_array() != ta.balance.id() { return Err(ProgramError::InvalidArgument); }

    // Create receipt PDA
    let bb = [rb];
    let seeds = [Seed::from(b"pc_receipt" as &[u8]), Seed::from(burned_ct.address().as_ref()), Seed::from(&bb)];
    CreateAccount { from: owner, to: receipt_acct, lamports: minimum_balance(WithdrawalReceipt::LEN),
        space: WithdrawalReceipt::LEN as u64, owner: program_id }.invoke_signed(&[Signer::from(&seeds)])?;

    let ctx = EncryptContext { encrypt_program: ep, config: cfg, deposit: dep, cpi_authority: cpi_auth, caller_program: caller, network_encryption_key: nk, payer: owner, event_authority: evt, system_program: sys, cpi_authority_bump: cb };
    // burned_ct is pre-created via gRPC (value=0). Graph writes actual burned amount.
    ctx.unwrap_burn_graph(bal_ct, amt_ct, bal_ct, burned_ct)?;

    let rd = unsafe { receipt_acct.borrow_unchecked_mut() };
    let r = WithdrawalReceipt::from_bytes_mut(rd)?;
    r.owner.copy_from_slice(owner.address().as_ref());
    r.amount = amount.to_le_bytes();
    r.pending_digest = [0u8; 32]; r.bump = rb; Ok(())
}

// ── 32: UnwrapDecrypt ──

fn unwrap_decrypt(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [receipt_acct, req_acct, burned_ct, ep, cfg, dep, cpi_auth, caller, nk, owner, evt, sys, ..] = accounts
    else { return Err(ProgramError::NotEnoughAccountKeys); };
    if !owner.is_signer() { return Err(ProgramError::MissingRequiredSignature); }
    if data.is_empty() { return Err(ProgramError::InvalidInstructionData); }
    let rd = unsafe { receipt_acct.borrow_unchecked() };
    let r = WithdrawalReceipt::from_bytes(rd)?;
    if owner.address().as_array() != &r.owner { return Err(ProgramError::InvalidArgument); }
    let ctx = EncryptContext { encrypt_program: ep, config: cfg, deposit: dep, cpi_authority: cpi_auth, caller_program: caller, network_encryption_key: nk, payer: owner, event_authority: evt, system_program: sys, cpi_authority_bump: data[0] };
    let digest = ctx.request_decryption(req_acct, burned_ct)?;
    let rd2 = unsafe { receipt_acct.borrow_unchecked_mut() };
    WithdrawalReceipt::from_bytes_mut(rd2)?.pending_digest = digest; Ok(())
}

// ── 33: UnwrapComplete ──

fn unwrap_complete(accounts: &[AccountView]) -> ProgramResult {
    let [receipt_acct, vault_acct, pc_mint, req_acct, vault_ata, user_ata, owner, destination, _spl, ..] = accounts
    else { return Err(ProgramError::NotEnoughAccountKeys); };
    if !owner.is_signer() { return Err(ProgramError::MissingRequiredSignature); }
    let rd = unsafe { receipt_acct.borrow_unchecked() };
    let r = WithdrawalReceipt::from_bytes(rd)?;
    if owner.address().as_array() != &r.owner { return Err(ProgramError::InvalidArgument); }
    let requested = r.requested_amount();
    let digest = r.pending_digest;

    let req_data = unsafe { req_acct.borrow_unchecked() };
    let burned: &u64 = accounts::read_decrypted_verified::<Uint64>(req_data, &digest)?;

    // Close receipt
    let rl = receipt_acct.lamports(); receipt_acct.set_lamports(0);
    destination.set_lamports(destination.lamports() + rl);
    let rd2 = unsafe { receipt_acct.borrow_unchecked_mut() };
    for b in rd2.iter_mut() { *b = 0; }

    if *burned != requested { return Ok(()); } // insufficient balance — no-op, receipt closed

    // SPL transfer: vault → user
    let vd = unsafe { vault_acct.borrow_unchecked() };
    let vault = Vault::from_bytes(vd)?;
    let vad = unsafe { vault_ata.borrow_unchecked() };
    if vad.len() < 64 { return Err(ProgramError::InvalidAccountData); }
    if &vad[32..64] != vault_acct.address().as_ref() { return Err(ProgramError::InvalidArgument); }
    let vbb = [vault.bump];
    let vs = [Seed::from(b"pc_vault" as &[u8]), Seed::from(pc_mint.address().as_ref()), Seed::from(&vbb)];
    SplTransfer { from: vault_ata, to: user_ata, authority: vault_acct, amount: requested }.invoke_signed(&[Signer::from(&vs)])?;
    Ok(())
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use encrypt_types::graph::{get_node, parse_graph, GraphNodeKind};
    use encrypt_types::identifier::*;
    use encrypt_types::types::FheType;
    use super::{burn_graph, mint_to_graph, transfer_from_graph, transfer_graph, unwrap_burn_graph};

    fn run_mock(graph_fn: fn() -> Vec<u8>, inputs: &[u128], fhe_types: &[FheType]) -> Vec<u128> {
        let data = graph_fn(); let pg = parse_graph(&data).unwrap();
        let num = pg.header().num_nodes() as usize;
        let mut digests: Vec<[u8; 32]> = Vec::with_capacity(num); let mut inp = 0usize;
        for i in 0..num {
            let n = get_node(pg.node_bytes(), i as u16).unwrap();
            let ft = FheType::from_u8(n.fhe_type()).unwrap_or(FheType::EUint64);
            let d = match n.kind() {
                k if k == GraphNodeKind::Input as u8 => { let v = inputs[inp]; let t = fhe_types[inp]; inp += 1; encode_mock_digest(t, v) }
                k if k == GraphNodeKind::Constant as u8 => { let bw = ft.byte_width().min(16); let off = n.const_offset() as usize;
                    let mut buf = [0u8; 16]; buf[..bw].copy_from_slice(&pg.constants()[off..off + bw]); encode_mock_digest(ft, u128::from_le_bytes(buf)) }
                k if k == GraphNodeKind::Op as u8 => { let (a, b, c) = (n.input_a() as usize, n.input_b() as usize, n.input_c() as usize);
                    if n.op_type() == 60 { mock_select(&digests[a], &digests[b], &digests[c]) }
                    else if b == 0xFFFF { mock_unary_compute(unsafe { core::mem::transmute(n.op_type()) }, &digests[a], ft) }
                    else { mock_binary_compute(unsafe { core::mem::transmute(n.op_type()) }, &digests[a], &digests[b], ft) } }
                k if k == GraphNodeKind::Output as u8 => digests[n.input_a() as usize],
                _ => panic!("bad node"),
            }; digests.push(d);
        }
        (0..num).filter(|&i| get_node(pg.node_bytes(), i as u16).unwrap().kind() == GraphNodeKind::Output as u8)
            .map(|i| decode_mock_identifier(&digests[i])).collect()
    }

    const T: FheType = FheType::EUint64;

    #[test] fn mint_to() { let r = run_mock(mint_to_graph, &[500, 300], &[T, T]); assert_eq!(r[0], 800); }
    #[test] fn transfer_ok() { let r = run_mock(transfer_graph, &[1000, 500, 300], &[T, T, T]); assert_eq!(r[0], 700); assert_eq!(r[1], 800); }
    #[test] fn transfer_insufficient() { let r = run_mock(transfer_graph, &[100, 500, 300], &[T, T, T]); assert_eq!(r[0], 100); assert_eq!(r[1], 500); }
    #[test] fn burn_ok() { let r = run_mock(burn_graph, &[1000, 300], &[T, T]); assert_eq!(r[0], 700); }
    #[test] fn burn_insufficient() { let r = run_mock(burn_graph, &[100, 300], &[T, T]); assert_eq!(r[0], 100); }
    #[test] fn transfer_from_ok() { let r = run_mock(transfer_from_graph, &[1000, 500, 400, 300], &[T, T, T, T]); assert_eq!(r[0], 700); assert_eq!(r[1], 800); assert_eq!(r[2], 100); }
    #[test] fn transfer_from_insufficient() { let r = run_mock(transfer_from_graph, &[100, 500, 400, 300], &[T, T, T, T]); assert_eq!(r[0], 100); assert_eq!(r[1], 500); assert_eq!(r[2], 400); }

    #[test] fn unwrap_burn_sufficient() { let r = run_mock(unwrap_burn_graph, &[1000, 300], &[T, T]); assert_eq!(r[0], 700); assert_eq!(r[1], 300); }
    #[test] fn unwrap_burn_insufficient() { let r = run_mock(unwrap_burn_graph, &[100, 300], &[T, T]); assert_eq!(r[0], 100); assert_eq!(r[1], 0); }

    #[test] fn graph_shapes() {
        let g = swap_shapes(mint_to_graph, 2, 1); let g = swap_shapes(transfer_graph, 3, 2);
        let g = swap_shapes(burn_graph, 2, 1); let g = swap_shapes(transfer_from_graph, 4, 3);
        let g = swap_shapes(unwrap_burn_graph, 2, 2);
    }
    fn swap_shapes(f: fn() -> Vec<u8>, ni: u8, no: u8) { let g = f(); let pg = parse_graph(&g).unwrap();
        assert_eq!(pg.header().num_inputs(), ni); assert_eq!(pg.header().num_outputs(), no); }
}
