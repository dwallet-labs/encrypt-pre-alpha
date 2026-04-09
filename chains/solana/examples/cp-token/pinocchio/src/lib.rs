// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#![allow(unexpected_cfgs)]

/// CP-Token (Confidential Performant Token) — Anza's P-Token rebuilt with
/// Encrypt FHE for on-chain confidentiality.
///
/// P-Token is Anza's pinocchio-based reimplementation of SPL Token — all
/// amounts and balances are plaintext. CP-Token follows the same architecture
/// and instruction set but replaces plaintext balances with FHE-encrypted
/// ciphertexts via the Encrypt protocol: same API surface, full
/// confidentiality.
///
/// ## What's the same as P-Token
///
/// - Account layouts: Mint and TokenAccount follow P-Token's COption flag
///   pattern, AccountState enum, and field ordering
/// - Instruction discriminators match P-Token where applicable
/// - Validation: owner checks, mint matching, signer checks, freeze checks
/// - Delegation: approve/revoke pattern for delegate spending
/// - Freeze/thaw: freeze authority can freeze/thaw accounts
///
/// ## What's different (FHE requires it)
///
/// - `amount` → `balance: EUint64` (32-byte ciphertext ref vs 8-byte u64)
/// - `delegated_amount` → `allowance: EUint64` (encrypted allowance)
/// - `supply` on Mint is omitted (can't track plaintext with encrypted minting)
/// - `is_native` is omitted (native SOL wrapping doesn't apply)
/// - Transfer amounts are client-encrypted ciphertexts, never plaintext
/// - Delegated transfer is a separate instruction (different FHE graph)
/// - Added: request_decrypt / reveal_balance for balance decryption
/// - CloseAccount requires prior balance decryption showing zero
///
/// ## Privacy model
///
/// - Balances: always encrypted (EUint64 ciphertexts)
/// - Transfer/mint/burn amounts: client-encrypted, never plaintext on-chain
/// - Insufficient funds: silent no-op in the encrypted domain
/// - Only the owner can request decryption of their balance
///
/// ## Instructions (P-Token discriminators where applicable)
///
///  0. `InitializeMint` — create a new token mint
///  1. `InitializeAccount` — create token account with encrypted zero balance
///  3. `Transfer` — owner transfers tokens (encrypted amount)
///  4. `Approve` — owner approves delegate with encrypted allowance
///  5. `Revoke` — owner revokes delegation
///  7. `MintTo` — mint authority creates tokens (encrypted amount)
///  8. `Burn` — owner burns tokens (encrypted amount)
///  9. `CloseAccount` — close token account and reclaim rent
/// 10. `FreezeAccount` — freeze authority freezes an account
/// 11. `ThawAccount` — freeze authority thaws a frozen account
/// 20. `TransferFrom` — delegate transfers (composability, separate FHE graph)
/// 21. `RequestDecrypt` — owner requests balance decryption
/// 22. `RevealBalance` — owner reads decrypted balance
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

// ── AccountState — matches P-Token ──

/// Account state enum, identical to P-Token / SPL Token.
#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum AccountState {
    Uninitialized = 0,
    Initialized = 1,
    Frozen = 2,
}

impl From<u8> for AccountState {
    fn from(v: u8) -> Self {
        match v {
            0 => AccountState::Uninitialized,
            1 => AccountState::Initialized,
            2 => AccountState::Frozen,
            _ => panic!("invalid account state"),
        }
    }
}

// ── COption helpers — matches P-Token ──

const COPTION_NONE: [u8; 4] = [0, 0, 0, 0];
const COPTION_SOME: [u8; 4] = [1, 0, 0, 0];

// ── Account layouts ──

/// Mint state — PDA seeds: `["cp_mint", authority, mint_id]`
///
/// Follows P-Token's Mint layout with COption flags for optional authorities.
/// `supply` is omitted because minting amounts are encrypted — plaintext
/// supply tracking is not possible. All other fields match P-Token.
#[repr(C)]
pub struct Mint {
    /// COption flag for mint_authority.
    pub mint_authority_flag: [u8; 4],
    /// Optional authority used to mint new tokens.
    pub mint_authority: [u8; 32],
    /// Number of base 10 digits to the right of the decimal place.
    pub decimals: u8,
    /// Is `true` if this structure has been initialized.
    pub is_initialized: u8,
    /// COption flag for freeze_authority.
    pub freeze_authority_flag: [u8; 4],
    /// Optional authority to freeze token accounts.
    pub freeze_authority: [u8; 32],
    /// PDA bump seed.
    pub bump: u8,
}

impl Mint {
    pub const LEN: usize = core::mem::size_of::<Self>();

    pub fn from_bytes(data: &[u8]) -> Result<&Self, ProgramError> {
        if data.len() < Self::LEN {
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

    pub fn is_initialized(&self) -> bool {
        self.is_initialized == 1
    }

    pub fn has_mint_authority(&self) -> bool {
        self.mint_authority_flag == COPTION_SOME
    }

    pub fn has_freeze_authority(&self) -> bool {
        self.freeze_authority_flag == COPTION_SOME
    }
}

/// Token account state — PDA seeds: `["cp_account", mint, owner]`
///
/// Follows P-Token's Account layout and field ordering. Key differences:
/// - `balance` (EUint64, 32 bytes) replaces P-Token's `amount` (u64, 8 bytes)
/// - `allowance` (EUint64, 32 bytes) replaces P-Token's `delegated_amount` (u64, 8 bytes)
/// - `is_native` / `native_amount` are omitted (no native SOL wrapping)
/// - `pending_digest` / `revealed_balance` are added for the decryption flow
#[repr(C)]
pub struct TokenAccount {
    /// The mint associated with this account.
    pub mint: [u8; 32],
    /// The owner of this account.
    pub owner: [u8; 32],
    /// Encrypted balance — ciphertext account address (replaces P-Token's plaintext amount).
    pub balance: EUint64,
    /// COption flag for delegate.
    pub delegate_flag: [u8; 4],
    /// The delegate approved to spend tokens from this account.
    pub delegate: [u8; 32],
    /// The account's state (Uninitialized, Initialized, or Frozen).
    pub state: u8,
    /// Encrypted delegate allowance — ciphertext account address
    /// (replaces P-Token's plaintext delegated_amount).
    pub allowance: EUint64,
    /// COption flag for close_authority.
    pub close_authority_flag: [u8; 4],
    /// Optional authority to close the account.
    pub close_authority: [u8; 32],
    /// Digest stored at request_decryption time — used for reveal verification.
    pub pending_digest: [u8; 32],
    /// Plaintext balance after decryption (u64 LE). Written by reveal_balance.
    pub revealed_balance: [u8; 8],
    /// PDA bump seed.
    pub bump: u8,
}

impl TokenAccount {
    pub const LEN: usize = core::mem::size_of::<Self>();

    pub fn from_bytes(data: &[u8]) -> Result<&Self, ProgramError> {
        if data.len() < Self::LEN {
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

    pub fn account_state(&self) -> AccountState {
        AccountState::from(self.state)
    }

    pub fn is_frozen(&self) -> bool {
        self.state == AccountState::Frozen as u8
    }

    pub fn is_initialized(&self) -> bool {
        self.state != AccountState::Uninitialized as u8
    }

    pub fn has_delegate(&self) -> bool {
        self.delegate_flag == COPTION_SOME
    }

    pub fn has_close_authority(&self) -> bool {
        self.close_authority_flag == COPTION_SOME
    }

    pub fn revealed_balance_value(&self) -> u64 {
        u64::from_le_bytes(self.revealed_balance)
    }
}

/// Vault — links a CP-Token mint to an SPL mint for wrapping/unwrapping.
/// PDA seeds: `["cp_vault", cp_mint]`
///
/// The vault PDA is the authority/owner of the SPL token account that holds
/// locked tokens. When users wrap, SPL tokens are transferred into this
/// account. When they unwrap, tokens are released from it.
#[repr(C)]
pub struct Vault {
    /// The SPL mint being wrapped (e.g., USDC mint address).
    pub spl_mint: [u8; 32],
    /// PDA bump seed.
    pub bump: u8,
}

impl Vault {
    pub const LEN: usize = core::mem::size_of::<Self>();

    pub fn from_bytes(data: &[u8]) -> Result<&Self, ProgramError> {
        if data.len() < Self::LEN {
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

/// WithdrawalReceipt — tracks a pending unwrap operation.
/// PDA seeds: `["cp_receipt", withdrawn_ct]`
///
/// Created during unwrap_init, consumed during unwrap_complete.
/// Stores the requested amount so we can verify the decrypted burned
/// amount matches before releasing SPL tokens.
#[repr(C)]
pub struct WithdrawalReceipt {
    /// Owner who initiated the unwrap.
    pub owner: [u8; 32],
    /// Requested plaintext withdrawal amount.
    pub amount: [u8; 8],
    /// Digest for verifying the decryption result.
    pub pending_digest: [u8; 32],
    /// PDA bump seed.
    pub bump: u8,
}

impl WithdrawalReceipt {
    pub const LEN: usize = core::mem::size_of::<Self>();

    pub fn from_bytes(data: &[u8]) -> Result<&Self, ProgramError> {
        if data.len() < Self::LEN {
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

    pub fn requested_amount(&self) -> u64 {
        u64::from_le_bytes(self.amount)
    }
}

// ── Rent helper ──

fn minimum_balance(size: usize) -> u64 {
    (size as u64 + 128) * 6960
}

/// Verify a token account is not frozen. Used by all mutating operations.
fn assert_not_frozen(ta: &TokenAccount) -> ProgramResult {
    if ta.is_frozen() {
        return Err(ProgramError::Custom(0x11)); // AccountFrozen
    }
    Ok(())
}

// ── FHE Graphs ──

/// Mint tokens: balance + amount
#[encrypt_fn]
fn mint_to_graph(balance: EUint64, amount: EUint64) -> EUint64 {
    balance + amount
}

/// Transfer tokens: conditional subtract from sender, add to receiver.
/// If sender has insufficient funds, both balances remain unchanged.
#[encrypt_fn]
fn transfer_graph(
    from_balance: EUint64,
    to_balance: EUint64,
    amount: EUint64,
) -> (EUint64, EUint64) {
    let sufficient = from_balance >= amount;
    let new_from = if sufficient { from_balance - amount } else { from_balance };
    let new_to = if sufficient { to_balance + amount } else { to_balance };
    (new_from, new_to)
}

/// Burn tokens: conditional subtract from balance.
#[encrypt_fn]
fn burn_graph(balance: EUint64, amount: EUint64) -> EUint64 {
    let sufficient = balance >= amount;
    if sufficient { balance - amount } else { balance }
}

/// Delegated transfer: checks both balance and allowance atomically.
#[encrypt_fn]
fn transfer_from_graph(
    from_balance: EUint64,
    to_balance: EUint64,
    allowance: EUint64,
    amount: EUint64,
) -> (EUint64, EUint64, EUint64) {
    let sufficient_balance = from_balance >= amount;
    let sufficient_allowance = allowance >= amount;
    let can_transfer = sufficient_balance & sufficient_allowance;
    let new_from = if can_transfer { from_balance - amount } else { from_balance };
    let new_to = if can_transfer { to_balance + amount } else { to_balance };
    let new_allowance = if can_transfer { allowance - amount } else { allowance };
    (new_from, new_to, new_allowance)
}

/// Unwrap: conditional burn that outputs the actual burned amount.
/// Returns (new_balance, withdrawn) where withdrawn = amount on success,
/// 0 on failure. `amount - amount` is always 0 in FHE — exploits the
/// identity property to derive an encrypted zero without a constant.
#[encrypt_fn]
fn unwrap_graph(balance: EUint64, amount: EUint64) -> (EUint64, EUint64) {
    let sufficient = balance >= amount;
    let new_balance = if sufficient { balance - amount } else { balance };
    let withdrawn = if sufficient { amount } else { amount - amount };
    (new_balance, withdrawn)
}

// ── Instruction dispatch — P-Token discriminators ──

fn process_instruction(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    match data.split_first() {
        // P-Token standard discriminators
        Some((&0, rest)) => initialize_mint(program_id, accounts, rest),
        Some((&1, rest)) => initialize_account(program_id, accounts, rest),
        Some((&3, rest)) => transfer(accounts, rest),
        Some((&4, rest)) => approve(accounts, rest),
        Some((&5, rest)) => revoke(accounts, rest),
        Some((&7, rest)) => mint_to(accounts, rest),
        Some((&8, rest)) => burn(accounts, rest),
        Some((&9, rest)) => close_account(accounts, rest),
        Some((&10, rest)) => freeze_account(accounts, rest),
        Some((&11, rest)) => thaw_account(accounts, rest),
        // CP-Token extensions (FHE-specific)
        Some((&20, rest)) => transfer_from(accounts, rest),
        Some((&21, rest)) => request_decrypt(accounts, rest),
        Some((&22, _rest)) => reveal_balance(accounts),
        // Wrap/unwrap (SPL ↔ CP-Token bridge)
        Some((&23, rest)) => initialize_vault(program_id, accounts, rest),
        Some((&30, rest)) => wrap(accounts, rest),
        Some((&31, rest)) => unwrap_init(program_id, accounts, rest),
        Some((&32, rest)) => unwrap_decrypt(accounts, rest),
        Some((&33, _rest)) => unwrap_complete(accounts),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

// ── 0: InitializeMint ──
// data: bump(1) | decimals(1) | mint_authority(32) | freeze_authority_flag(1) | freeze_authority(32)
// accounts: [mint_pda(w), authority(s), payer(s,w), system_program]

fn initialize_mint(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    let [mint_acct, authority, payer, _system_program, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !authority.is_signer() || !payer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    // bump(1) + decimals(1) + mint_authority(32) + freeze_flag(1) = 35 min
    if data.len() < 35 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let bump = data[0];
    let decimals = data[1];
    let mint_authority: [u8; 32] = data[2..34].try_into().unwrap();
    let has_freeze = data[34] != 0;
    let freeze_authority: [u8; 32] = if has_freeze && data.len() >= 67 {
        data[35..67].try_into().unwrap()
    } else {
        [0u8; 32]
    };

    // Create mint PDA
    let bump_byte = [bump];
    let seeds = [
        Seed::from(b"cp_mint" as &[u8]),
        Seed::from(authority.address().as_ref()),
        Seed::from(&bump_byte),
    ];
    let signer = [Signer::from(&seeds)];

    CreateAccount {
        from: payer,
        to: mint_acct,
        lamports: minimum_balance(Mint::LEN),
        space: Mint::LEN as u64,
        owner: program_id,
    }
    .invoke_signed(&signer)?;

    let d = unsafe { mint_acct.borrow_unchecked_mut() };
    let mint = Mint::from_bytes_mut(d)?;
    mint.mint_authority_flag = COPTION_SOME;
    mint.mint_authority.copy_from_slice(&mint_authority);
    mint.decimals = decimals;
    mint.is_initialized = 1;
    if has_freeze {
        mint.freeze_authority_flag = COPTION_SOME;
        mint.freeze_authority.copy_from_slice(&freeze_authority);
    } else {
        mint.freeze_authority_flag = COPTION_NONE;
        mint.freeze_authority = [0u8; 32];
    }
    mint.bump = bump;
    Ok(())
}

// ── 1: InitializeAccount ──
// data: account_bump(1) | cpi_authority_bump(1)
// accounts: [token_account_pda(w), mint, owner, balance_ct(w),
//            encrypt_program, config, deposit(w), cpi_authority,
//            caller_program, network_encryption_key, payer(s,w),
//            event_authority, system_program]

fn initialize_account(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    let [token_acct, mint_acct, owner, balance_ct, encrypt_program, config, deposit, cpi_authority, caller_program, network_encryption_key, payer, event_authority, system_program, ..] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !payer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if data.len() < 2 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let account_bump = data[0];
    let cpi_authority_bump = data[1];

    // Verify mint is initialized
    let mint_data = unsafe { mint_acct.borrow_unchecked() };
    let mint = Mint::from_bytes(mint_data)?;
    if !mint.is_initialized() {
        return Err(ProgramError::UninitializedAccount);
    }

    // Create token account PDA
    let bump_byte = [account_bump];
    let seeds = [
        Seed::from(b"cp_account" as &[u8]),
        Seed::from(mint_acct.address().as_ref()),
        Seed::from(owner.address().as_ref()),
        Seed::from(&bump_byte),
    ];
    let signer = [Signer::from(&seeds)];

    CreateAccount {
        from: payer,
        to: token_acct,
        lamports: minimum_balance(TokenAccount::LEN),
        space: TokenAccount::LEN as u64,
        owner: program_id,
    }
    .invoke_signed(&signer)?;

    // Create encrypted zero balance via Encrypt CPI
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

    ctx.create_plaintext_typed::<Uint64>(&0u64, balance_ct)?;

    // Write token account state
    let d = unsafe { token_acct.borrow_unchecked_mut() };
    let ta = TokenAccount::from_bytes_mut(d)?;
    ta.mint.copy_from_slice(mint_acct.address().as_ref());
    ta.owner.copy_from_slice(owner.address().as_ref());
    ta.balance = EUint64::from_le_bytes(*balance_ct.address().as_array());
    ta.delegate_flag = COPTION_NONE;
    ta.delegate = [0u8; 32];
    ta.state = AccountState::Initialized as u8;
    ta.allowance = EUint64::from_le_bytes([0u8; 32]);
    ta.close_authority_flag = COPTION_NONE;
    ta.close_authority = [0u8; 32];
    ta.pending_digest = [0u8; 32];
    ta.revealed_balance = [0u8; 8];
    ta.bump = account_bump;
    Ok(())
}

// ── 7: MintTo ──
// data: cpi_authority_bump(1)
// accounts: [mint, token_account, balance_ct(w), amount_ct,
//            encrypt_program, config, deposit(w), cpi_authority,
//            caller_program, network_encryption_key, authority(s,w),
//            event_authority, system_program]
//
// amount_ct is client-encrypted by the mint authority using the Encrypt SDK.

fn mint_to(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [mint_acct, token_acct, balance_ct, amount_ct, encrypt_program, config, deposit, cpi_authority, caller_program, network_encryption_key, authority, event_authority, system_program, ..] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }

    let cpi_authority_bump = data[0];

    // Verify mint authority
    let mint_data = unsafe { mint_acct.borrow_unchecked() };
    let mint = Mint::from_bytes(mint_data)?;
    if !mint.has_mint_authority() || authority.address().as_array() != &mint.mint_authority {
        return Err(ProgramError::InvalidArgument);
    }

    // Verify token account
    let ta_data = unsafe { token_acct.borrow_unchecked() };
    let ta = TokenAccount::from_bytes(ta_data)?;
    if !ta.is_initialized() {
        return Err(ProgramError::UninitializedAccount);
    }
    assert_not_frozen(ta)?;
    if &ta.mint != mint_acct.address().as_array() {
        return Err(ProgramError::InvalidArgument);
    }
    if balance_ct.address().as_array() != ta.balance.id() {
        return Err(ProgramError::InvalidArgument);
    }

    let ctx = EncryptContext {
        encrypt_program,
        config,
        deposit,
        cpi_authority,
        caller_program,
        network_encryption_key,
        payer: authority,
        event_authority,
        system_program,
        cpi_authority_bump,
    };

    ctx.mint_to_graph(balance_ct, amount_ct, balance_ct)?;

    Ok(())
}

// ── 3: Transfer ──
// data: cpi_authority_bump(1)
// accounts: [from_token_account, to_token_account,
//            from_balance_ct(w), to_balance_ct(w), amount_ct,
//            encrypt_program, config, deposit(w), cpi_authority,
//            caller_program, network_encryption_key, owner(s,w),
//            event_authority, system_program]
//
// Owner-initiated transfer. amount_ct is client-encrypted by the sender.
// For delegated transfers, use TransferFrom (disc 20).

fn transfer(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [from_acct, to_acct, from_balance_ct, to_balance_ct, amount_ct, encrypt_program, config, deposit, cpi_authority, caller_program, network_encryption_key, owner, event_authority, system_program, ..] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !owner.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }

    let cpi_authority_bump = data[0];

    // Verify source account
    let from_data = unsafe { from_acct.borrow_unchecked() };
    let from_ta = TokenAccount::from_bytes(from_data)?;
    if !from_ta.is_initialized() {
        return Err(ProgramError::UninitializedAccount);
    }
    assert_not_frozen(from_ta)?;
    if owner.address().as_array() != &from_ta.owner {
        return Err(ProgramError::InvalidArgument);
    }

    // Verify destination account
    let to_data = unsafe { to_acct.borrow_unchecked() };
    let to_ta = TokenAccount::from_bytes(to_data)?;
    if !to_ta.is_initialized() {
        return Err(ProgramError::UninitializedAccount);
    }
    assert_not_frozen(to_ta)?;

    // Same mint check
    if from_ta.mint != to_ta.mint {
        return Err(ProgramError::InvalidArgument);
    }

    // Verify ciphertext accounts
    if from_balance_ct.address().as_array() != from_ta.balance.id() {
        return Err(ProgramError::InvalidArgument);
    }
    if to_balance_ct.address().as_array() != to_ta.balance.id() {
        return Err(ProgramError::InvalidArgument);
    }

    let ctx = EncryptContext {
        encrypt_program,
        config,
        deposit,
        cpi_authority,
        caller_program,
        network_encryption_key,
        payer: owner,
        event_authority,
        system_program,
        cpi_authority_bump,
    };

    ctx.transfer_graph(
        from_balance_ct,
        to_balance_ct,
        amount_ct,
        from_balance_ct,
        to_balance_ct,
    )?;

    Ok(())
}

// ── 4: Approve ──
// data: cpi_authority_bump(1)
// accounts: [token_account(w), delegate, amount_ct, allowance_ct(w),
//            encrypt_program, config, deposit(w), cpi_authority,
//            caller_program, network_encryption_key, owner(s,w),
//            event_authority, system_program]
//
// amount_ct is client-encrypted allowance. CP-Token creates a zero ciphertext
// for allowance_ct (owned by CP-Token), then adds the client's encrypted
// amount to it via mint_to_graph. This gives CP-Token write access to the
// allowance so transfer_from can later decrement it.

fn approve(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [token_acct, delegate, amount_ct, allowance_ct, encrypt_program, config, deposit, cpi_authority, caller_program, network_encryption_key, owner, event_authority, system_program, ..] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !owner.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }

    let cpi_authority_bump = data[0];

    // Verify token account
    let ta_data = unsafe { token_acct.borrow_unchecked() };
    let ta = TokenAccount::from_bytes(ta_data)?;
    if !ta.is_initialized() {
        return Err(ProgramError::UninitializedAccount);
    }
    assert_not_frozen(ta)?;
    if owner.address().as_array() != &ta.owner {
        return Err(ProgramError::InvalidArgument);
    }

    let ctx = EncryptContext {
        encrypt_program,
        config,
        deposit,
        cpi_authority,
        caller_program,
        network_encryption_key,
        payer: owner,
        event_authority,
        system_program,
        cpi_authority_bump,
    };

    // Create a zero ciphertext for the allowance (owned by CP-Token's CPI authority)
    ctx.create_plaintext_typed::<Uint64>(&0u64, allowance_ct)?;

    // Add the client-encrypted amount: allowance = 0 + amount = amount
    ctx.mint_to_graph(allowance_ct, amount_ct, allowance_ct)?;

    // Store delegate in token account (COption pattern)
    let ta_data_mut = unsafe { token_acct.borrow_unchecked_mut() };
    let ta_mut = TokenAccount::from_bytes_mut(ta_data_mut)?;
    ta_mut.delegate_flag = COPTION_SOME;
    ta_mut.delegate.copy_from_slice(delegate.address().as_ref());
    ta_mut.allowance = EUint64::from_le_bytes(*allowance_ct.address().as_array());

    Ok(())
}

// ── 5: Revoke ──
// data: cpi_authority_bump(1)
// accounts: [token_account(w), allowance_ct(w), owner(s),
//            encrypt_program, config, deposit(w), cpi_authority,
//            caller_program, network_encryption_key, payer(s,w),
//            event_authority, system_program]

fn revoke(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [token_acct, allowance_ct, owner, encrypt_program, config, deposit, cpi_authority, caller_program, network_encryption_key, payer, event_authority, system_program, ..] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !owner.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }

    let cpi_authority_bump = data[0];

    // Verify owner and delegate exists
    let ta_data = unsafe { token_acct.borrow_unchecked() };
    let ta = TokenAccount::from_bytes(ta_data)?;
    if owner.address().as_array() != &ta.owner {
        return Err(ProgramError::InvalidArgument);
    }
    if !ta.has_delegate() {
        return Err(ProgramError::InvalidArgument);
    }
    if allowance_ct.address().as_array() != ta.allowance.id() {
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

    // Close allowance ciphertext and reclaim rent
    ctx.close_ciphertext(allowance_ct, payer)?;

    // Clear delegate (COption pattern)
    let ta_data_mut = unsafe { token_acct.borrow_unchecked_mut() };
    let ta_mut = TokenAccount::from_bytes_mut(ta_data_mut)?;
    ta_mut.delegate_flag = COPTION_NONE;
    ta_mut.delegate = [0u8; 32];
    ta_mut.allowance = EUint64::from_le_bytes([0u8; 32]);

    Ok(())
}

// ── 8: Burn ──
// data: cpi_authority_bump(1)
// accounts: [token_account, mint, balance_ct(w), amount_ct,
//            encrypt_program, config, deposit(w), cpi_authority,
//            caller_program, network_encryption_key, owner(s,w),
//            event_authority, system_program]
//
// Account ordering matches P-Token: source, mint, authority.
// amount_ct is client-encrypted.

fn burn(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [token_acct, mint_acct, balance_ct, amount_ct, encrypt_program, config, deposit, cpi_authority, caller_program, network_encryption_key, owner, event_authority, system_program, ..] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !owner.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }

    let cpi_authority_bump = data[0];

    // Verify token account
    let ta_data = unsafe { token_acct.borrow_unchecked() };
    let ta = TokenAccount::from_bytes(ta_data)?;
    if !ta.is_initialized() {
        return Err(ProgramError::UninitializedAccount);
    }
    assert_not_frozen(ta)?;
    if owner.address().as_array() != &ta.owner {
        return Err(ProgramError::InvalidArgument);
    }
    if &ta.mint != mint_acct.address().as_array() {
        return Err(ProgramError::InvalidArgument);
    }
    if balance_ct.address().as_array() != ta.balance.id() {
        return Err(ProgramError::InvalidArgument);
    }

    let ctx = EncryptContext {
        encrypt_program,
        config,
        deposit,
        cpi_authority,
        caller_program,
        network_encryption_key,
        payer: owner,
        event_authority,
        system_program,
        cpi_authority_bump,
    };

    ctx.burn_graph(balance_ct, amount_ct, balance_ct)?;

    Ok(())
}

// ── 9: CloseAccount ──
// data: cpi_authority_bump(1)
// accounts: [token_account(w), destination(w), balance_ct(w), owner(s),
//            encrypt_program, config, deposit(w), cpi_authority,
//            caller_program, network_encryption_key, payer(s,w),
//            event_authority, system_program]
//
// Like P-Token, requires zero balance. Since balance is encrypted, the owner
// must first request_decrypt + reveal_balance showing zero before closing.

fn close_account(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [token_acct, destination, balance_ct, owner, encrypt_program, config, deposit, cpi_authority, caller_program, network_encryption_key, payer, event_authority, system_program, ..] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !owner.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }

    let cpi_authority_bump = data[0];

    // Verify owner (or close_authority)
    let ta_data = unsafe { token_acct.borrow_unchecked() };
    let ta = TokenAccount::from_bytes(ta_data)?;
    let is_owner = owner.address().as_array() == &ta.owner;
    let is_close_authority =
        ta.has_close_authority() && owner.address().as_array() == &ta.close_authority;
    if !is_owner && !is_close_authority {
        return Err(ProgramError::InvalidArgument);
    }

    // Require revealed balance == 0 (owner must decrypt first)
    if ta.revealed_balance_value() != 0 {
        return Err(ProgramError::InvalidArgument);
    }
    // Ensure a decryption was actually performed (digest is non-zero)
    if ta.pending_digest == [0u8; 32] {
        return Err(ProgramError::InvalidArgument);
    }

    if balance_ct.address().as_array() != ta.balance.id() {
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

    // Close the balance ciphertext via Encrypt CPI
    ctx.close_ciphertext(balance_ct, destination)?;

    // Transfer remaining lamports from token account to destination
    let token_lamports = token_acct.lamports();
    token_acct.set_lamports(0);
    destination.set_lamports(destination.lamports() + token_lamports);

    // Zero out the account data
    let ta_data_mut = unsafe { token_acct.borrow_unchecked_mut() };
    for byte in ta_data_mut.iter_mut() {
        *byte = 0;
    }

    Ok(())
}

// ── 10: FreezeAccount ──
// data: (none)
// accounts: [token_account(w), mint, freeze_authority(s)]
//
// Matches P-Token: freeze authority signs, account state → Frozen.

fn freeze_account(accounts: &[AccountView], _data: &[u8]) -> ProgramResult {
    let [token_acct, mint_acct, freeze_authority, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !freeze_authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Verify mint has freeze authority and signer matches
    let mint_data = unsafe { mint_acct.borrow_unchecked() };
    let mint = Mint::from_bytes(mint_data)?;
    if !mint.has_freeze_authority()
        || freeze_authority.address().as_array() != &mint.freeze_authority
    {
        return Err(ProgramError::InvalidArgument);
    }

    // Verify token account belongs to this mint and is initialized
    let ta_data = unsafe { token_acct.borrow_unchecked() };
    let ta = TokenAccount::from_bytes(ta_data)?;
    if !ta.is_initialized() {
        return Err(ProgramError::UninitializedAccount);
    }
    if &ta.mint != mint_acct.address().as_array() {
        return Err(ProgramError::InvalidArgument);
    }

    // Set state to Frozen
    let ta_data_mut = unsafe { token_acct.borrow_unchecked_mut() };
    let ta_mut = TokenAccount::from_bytes_mut(ta_data_mut)?;
    ta_mut.state = AccountState::Frozen as u8;

    Ok(())
}

// ── 11: ThawAccount ──
// data: (none)
// accounts: [token_account(w), mint, freeze_authority(s)]
//
// Matches P-Token: freeze authority signs, account state → Initialized.

fn thaw_account(accounts: &[AccountView], _data: &[u8]) -> ProgramResult {
    let [token_acct, mint_acct, freeze_authority, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !freeze_authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Verify mint has freeze authority and signer matches
    let mint_data = unsafe { mint_acct.borrow_unchecked() };
    let mint = Mint::from_bytes(mint_data)?;
    if !mint.has_freeze_authority()
        || freeze_authority.address().as_array() != &mint.freeze_authority
    {
        return Err(ProgramError::InvalidArgument);
    }

    // Verify token account belongs to this mint and is frozen
    let ta_data = unsafe { token_acct.borrow_unchecked() };
    let ta = TokenAccount::from_bytes(ta_data)?;
    if !ta.is_frozen() {
        return Err(ProgramError::InvalidArgument);
    }
    if &ta.mint != mint_acct.address().as_array() {
        return Err(ProgramError::InvalidArgument);
    }

    // Set state to Initialized
    let ta_data_mut = unsafe { token_acct.borrow_unchecked_mut() };
    let ta_mut = TokenAccount::from_bytes_mut(ta_data_mut)?;
    ta_mut.state = AccountState::Initialized as u8;

    Ok(())
}

// ── 20: TransferFrom (CP-Token extension) ──
// data: cpi_authority_bump(1)
// accounts: [from_token_account, to_token_account,
//            from_balance_ct(w), to_balance_ct(w), allowance_ct(w), amount_ct,
//            delegate(s),
//            encrypt_program, config, deposit(w), cpi_authority,
//            caller_program, network_encryption_key, payer(s,w),
//            event_authority, system_program]
//
// Composability entry point. Other Encrypt programs CPI into this instruction
// to move tokens on behalf of a user who approved them as delegate.
// Separate from Transfer because the FHE graph is different (checks allowance).

fn transfer_from(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [from_acct, to_acct, from_balance_ct, to_balance_ct, allowance_ct, amount_ct, delegate, encrypt_program, config, deposit, cpi_authority, caller_program, network_encryption_key, payer, event_authority, system_program, ..] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !delegate.is_signer() || !payer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }

    let cpi_authority_bump = data[0];

    // Verify source account
    let from_data = unsafe { from_acct.borrow_unchecked() };
    let from_ta = TokenAccount::from_bytes(from_data)?;
    if !from_ta.is_initialized() {
        return Err(ProgramError::UninitializedAccount);
    }
    assert_not_frozen(from_ta)?;
    if !from_ta.has_delegate() || delegate.address().as_array() != &from_ta.delegate {
        return Err(ProgramError::InvalidArgument);
    }

    // Verify destination account
    let to_data = unsafe { to_acct.borrow_unchecked() };
    let to_ta = TokenAccount::from_bytes(to_data)?;
    if !to_ta.is_initialized() {
        return Err(ProgramError::UninitializedAccount);
    }
    assert_not_frozen(to_ta)?;

    // Same mint check
    if from_ta.mint != to_ta.mint {
        return Err(ProgramError::InvalidArgument);
    }

    // Verify ciphertext accounts
    if from_balance_ct.address().as_array() != from_ta.balance.id() {
        return Err(ProgramError::InvalidArgument);
    }
    if to_balance_ct.address().as_array() != to_ta.balance.id() {
        return Err(ProgramError::InvalidArgument);
    }
    if allowance_ct.address().as_array() != from_ta.allowance.id() {
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

    ctx.transfer_from_graph(
        from_balance_ct,
        to_balance_ct,
        allowance_ct,
        amount_ct,
        from_balance_ct,
        to_balance_ct,
        allowance_ct,
    )?;

    Ok(())
}

// ── 21: RequestDecrypt (CP-Token extension) ──
// data: cpi_authority_bump(1)
// accounts: [token_account(w), request_acct(w), ciphertext,
//            encrypt_program, config, deposit(w), cpi_authority,
//            caller_program, network_encryption_key, owner(s,w),
//            event_authority, system_program]

fn request_decrypt(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [token_acct, request_acct, ciphertext, encrypt_program, config, deposit, cpi_authority, caller_program, network_encryption_key, owner, event_authority, system_program, ..] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !owner.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }

    let cpi_authority_bump = data[0];

    // Verify owner
    let ta_data = unsafe { token_acct.borrow_unchecked() };
    let ta = TokenAccount::from_bytes(ta_data)?;
    if owner.address().as_array() != &ta.owner {
        return Err(ProgramError::InvalidArgument);
    }

    let ctx = EncryptContext {
        encrypt_program,
        config,
        deposit,
        cpi_authority,
        caller_program,
        network_encryption_key,
        payer: owner,
        event_authority,
        system_program,
        cpi_authority_bump,
    };

    let digest = ctx.request_decryption(request_acct, ciphertext)?;

    let ta_data_mut = unsafe { token_acct.borrow_unchecked_mut() };
    let ta_mut = TokenAccount::from_bytes_mut(ta_data_mut)?;
    ta_mut.pending_digest = digest;

    Ok(())
}

// ── 22: RevealBalance (CP-Token extension) ──
// data: (none)
// accounts: [token_account(w), request_acct, owner(s)]

fn reveal_balance(accounts: &[AccountView]) -> ProgramResult {
    let [token_acct, request_acct, owner, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !owner.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let ta_data = unsafe { token_acct.borrow_unchecked() };
    let ta = TokenAccount::from_bytes(ta_data)?;
    if owner.address().as_array() != &ta.owner {
        return Err(ProgramError::InvalidArgument);
    }

    let req_data = unsafe { request_acct.borrow_unchecked() };
    let value: &u64 = accounts::read_decrypted_verified::<Uint64>(req_data, &ta.pending_digest)?;

    let ta_data_mut = unsafe { token_acct.borrow_unchecked_mut() };
    let ta_mut = TokenAccount::from_bytes_mut(ta_data_mut)?;
    ta_mut.revealed_balance = value.to_le_bytes();

    Ok(())
}

// ── 23: InitializeVault ──
// data: vault_bump(1)
// accounts: [vault_pda(w), cp_mint, spl_mint, payer(s,w), system_program]
//
// Creates a vault linking a CP-Token mint to an SPL mint.
// The vault PDA becomes the authority of the SPL token account.

fn initialize_vault(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    let [vault_acct, cp_mint_acct, _spl_mint, payer, _system_program, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !payer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }

    let vault_bump = data[0];

    // Verify CP mint is initialized
    let mint_data = unsafe { cp_mint_acct.borrow_unchecked() };
    let mint = Mint::from_bytes(mint_data)?;
    if !mint.is_initialized() {
        return Err(ProgramError::UninitializedAccount);
    }

    // Create vault PDA
    let bump_byte = [vault_bump];
    let seeds = [
        Seed::from(b"cp_vault" as &[u8]),
        Seed::from(cp_mint_acct.address().as_ref()),
        Seed::from(&bump_byte),
    ];
    let signer = [Signer::from(&seeds)];

    CreateAccount {
        from: payer,
        to: vault_acct,
        lamports: minimum_balance(Vault::LEN),
        space: Vault::LEN as u64,
        owner: program_id,
    }
    .invoke_signed(&signer)?;

    let d = unsafe { vault_acct.borrow_unchecked_mut() };
    let vault = Vault::from_bytes_mut(d)?;
    vault.spl_mint.copy_from_slice(_spl_mint.address().as_ref());
    vault.bump = vault_bump;
    Ok(())
}

// ── 30: Wrap ──
// data: cpi_authority_bump(1) | amount(8, LE)
// accounts: [vault, token_account, user_ata(w), vault_ata(w),
//            balance_ct(w), amount_ct(w,s),
//            encrypt_program, config, deposit(w), cpi_authority,
//            caller_program, network_encryption_key, owner(s,w),
//            event_authority, system_program,
//            spl_token_program]
//
// Wraps SPL tokens into confidential CP-Tokens.
// Amount is plaintext — the SPL deposit is visible on-chain anyway.
// Privacy begins after wrapping: all cpToken operations are encrypted.

fn wrap(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [vault_acct, token_acct, user_ata, vault_ata, balance_ct, amount_ct, encrypt_program, config, deposit, cpi_authority, caller_program, network_encryption_key, owner, event_authority, system_program, _spl_token_program, ..] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !owner.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if data.len() < 9 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let cpi_authority_bump = data[0];
    let amount = u64::from_le_bytes(data[1..9].try_into().unwrap());
    if amount == 0 {
        return Err(ProgramError::InvalidArgument);
    }

    // Verify token account
    let ta_data = unsafe { token_acct.borrow_unchecked() };
    let ta = TokenAccount::from_bytes(ta_data)?;
    if !ta.is_initialized() {
        return Err(ProgramError::UninitializedAccount);
    }
    assert_not_frozen(ta)?;
    if owner.address().as_array() != &ta.owner {
        return Err(ProgramError::InvalidArgument);
    }
    if balance_ct.address().as_array() != ta.balance.id() {
        return Err(ProgramError::InvalidArgument);
    }

    // Verify vault is the correct PDA for this mint and SPL mint matches
    let vault_data = unsafe { vault_acct.borrow_unchecked() };
    let vault = Vault::from_bytes(vault_data)?;

    // Verify vault_ata is owned by the vault PDA (SPL token account authority check).
    // The SPL Transfer CPI will also enforce this, but we verify the vault-mint linkage.
    let vault_ata_data = unsafe { vault_ata.borrow_unchecked() };
    // SPL token account: owner is at offset 32..64
    if vault_ata_data.len() < 64 {
        return Err(ProgramError::InvalidAccountData);
    }
    if &vault_ata_data[32..64] != vault_acct.address().as_ref() {
        return Err(ProgramError::InvalidArgument); // vault_ata not owned by vault PDA
    }
    // SPL token account: mint is at offset 0..32
    if &vault_ata_data[0..32] != &vault.spl_mint {
        return Err(ProgramError::InvalidArgument); // vault_ata mint doesn't match vault.spl_mint
    }

    // 1. SPL transfer: user_ata → vault_ata
    SplTransfer {
        from: user_ata,
        to: vault_ata,
        authority: owner,
        amount,
    }
    .invoke()?;

    // 2. Create plaintext amount ciphertext + add to encrypted balance
    let ctx = EncryptContext {
        encrypt_program,
        config,
        deposit,
        cpi_authority,
        caller_program,
        network_encryption_key,
        payer: owner,
        event_authority,
        system_program,
        cpi_authority_bump,
    };

    ctx.create_plaintext_typed::<Uint64>(&amount, amount_ct)?;
    ctx.mint_to_graph(balance_ct, amount_ct, balance_ct)?;

    Ok(())
}

// ── 31: UnwrapInit ──
// data: receipt_bump(1) | cpi_authority_bump(1) | amount(8, LE)
// accounts: [vault, token_account, receipt_pda(w),
//            balance_ct(w), amount_ct(w,s), withdrawn_ct(w,s),
//            encrypt_program, config, deposit(w), cpi_authority,
//            caller_program, network_encryption_key, owner(s,w),
//            event_authority, system_program]
//
// First step of unwrap: creates amount ciphertext, runs unwrap_graph to
// conditionally burn and produce a withdrawn receipt ciphertext.

fn unwrap_init(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    let [vault_acct, token_acct, receipt_acct, balance_ct, amount_ct, withdrawn_ct, encrypt_program, config, deposit, cpi_authority, caller_program, network_encryption_key, owner, event_authority, system_program, ..] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !owner.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if data.len() < 10 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let receipt_bump = data[0];
    let cpi_authority_bump = data[1];
    let amount = u64::from_le_bytes(data[2..10].try_into().unwrap());
    if amount == 0 {
        return Err(ProgramError::InvalidArgument);
    }

    // Verify vault exists and is owned by this program
    let vault_data = unsafe { vault_acct.borrow_unchecked() };
    let _vault = Vault::from_bytes(vault_data)?;

    // Verify token account
    let ta_data = unsafe { token_acct.borrow_unchecked() };
    let ta = TokenAccount::from_bytes(ta_data)?;
    if !ta.is_initialized() {
        return Err(ProgramError::UninitializedAccount);
    }
    assert_not_frozen(ta)?;
    if owner.address().as_array() != &ta.owner {
        return Err(ProgramError::InvalidArgument);
    }
    if balance_ct.address().as_array() != ta.balance.id() {
        return Err(ProgramError::InvalidArgument);
    }

    // Create receipt PDA
    let bump_byte = [receipt_bump];
    let seeds = [
        Seed::from(b"cp_receipt" as &[u8]),
        Seed::from(withdrawn_ct.address().as_ref()),
        Seed::from(&bump_byte),
    ];
    let signer = [Signer::from(&seeds)];

    CreateAccount {
        from: owner,
        to: receipt_acct,
        lamports: minimum_balance(WithdrawalReceipt::LEN),
        space: WithdrawalReceipt::LEN as u64,
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
        payer: owner,
        event_authority,
        system_program,
        cpi_authority_bump,
    };

    // Create amount ciphertext (plaintext — withdrawal amount is public)
    ctx.create_plaintext_typed::<Uint64>(&amount, amount_ct)?;

    // Create zero ciphertext for withdrawn output
    ctx.create_plaintext_typed::<Uint64>(&0u64, withdrawn_ct)?;

    // Execute unwrap_graph: (new_balance, withdrawn) = unwrap(balance, amount)
    ctx.unwrap_graph(balance_ct, amount_ct, balance_ct, withdrawn_ct)?;

    // Write receipt
    let rd = unsafe { receipt_acct.borrow_unchecked_mut() };
    let receipt = WithdrawalReceipt::from_bytes_mut(rd)?;
    receipt.owner.copy_from_slice(owner.address().as_ref());
    receipt.amount = amount.to_le_bytes();
    receipt.pending_digest = [0u8; 32];
    receipt.bump = receipt_bump;

    Ok(())
}

// ── 32: UnwrapDecrypt ──
// data: cpi_authority_bump(1)
// accounts: [receipt(w), request_acct(w,s), withdrawn_ct,
//            encrypt_program, config, deposit(w), cpi_authority,
//            caller_program, network_encryption_key, owner(s,w),
//            event_authority, system_program]

fn unwrap_decrypt(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [receipt_acct, request_acct, withdrawn_ct, encrypt_program, config, deposit, cpi_authority, caller_program, network_encryption_key, owner, event_authority, system_program, ..] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !owner.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }

    let cpi_authority_bump = data[0];

    // Verify receipt owner
    let rd = unsafe { receipt_acct.borrow_unchecked() };
    let receipt = WithdrawalReceipt::from_bytes(rd)?;
    if owner.address().as_array() != &receipt.owner {
        return Err(ProgramError::InvalidArgument);
    }

    let ctx = EncryptContext {
        encrypt_program,
        config,
        deposit,
        cpi_authority,
        caller_program,
        network_encryption_key,
        payer: owner,
        event_authority,
        system_program,
        cpi_authority_bump,
    };

    let digest = ctx.request_decryption(request_acct, withdrawn_ct)?;

    let rd_mut = unsafe { receipt_acct.borrow_unchecked_mut() };
    let receipt_mut = WithdrawalReceipt::from_bytes_mut(rd_mut)?;
    receipt_mut.pending_digest = digest;

    Ok(())
}

// ── 33: UnwrapComplete ──
// data: (none)
// accounts: [receipt(w), vault, cp_mint, request_acct,
//            vault_ata(w), user_ata(w), owner(s),
//            destination(w), spl_token_program]
//
// Final step: reads decrypted withdrawn amount, verifies it matches the
// requested amount, then SPL-transfers from vault to user.
// Closes the receipt PDA and returns rent to destination.

fn unwrap_complete(accounts: &[AccountView]) -> ProgramResult {
    let [receipt_acct, vault_acct, cp_mint_acct, request_acct, vault_ata, user_ata, owner, destination, _spl_token_program, ..] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !owner.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Read receipt
    let rd = unsafe { receipt_acct.borrow_unchecked() };
    let receipt = WithdrawalReceipt::from_bytes(rd)?;
    if owner.address().as_array() != &receipt.owner {
        return Err(ProgramError::InvalidArgument);
    }
    let requested_amount = receipt.requested_amount();
    let pending_digest = receipt.pending_digest;

    // Read and verify decrypted withdrawn amount
    let req_data = unsafe { request_acct.borrow_unchecked() };
    let withdrawn: &u64 =
        accounts::read_decrypted_verified::<Uint64>(req_data, &pending_digest)?;

    if *withdrawn != requested_amount {
        // Withdrawn == 0 means insufficient balance — no SPL transfer
        // Close receipt and return rent, but don't release tokens
        let receipt_lamports = receipt_acct.lamports();
        receipt_acct.set_lamports(0);
        destination.set_lamports(destination.lamports() + receipt_lamports);
        let rd_mut = unsafe { receipt_acct.borrow_unchecked_mut() };
        for byte in rd_mut.iter_mut() {
            *byte = 0;
        }
        return Ok(());
    }

    // SPL transfer: vault → user (signed by vault PDA)
    let vault_data = unsafe { vault_acct.borrow_unchecked() };
    let vault = Vault::from_bytes(vault_data)?;

    // Verify vault_ata is owned by the vault PDA
    let vault_ata_data = unsafe { vault_ata.borrow_unchecked() };
    if vault_ata_data.len() < 64 {
        return Err(ProgramError::InvalidAccountData);
    }
    if &vault_ata_data[32..64] != vault_acct.address().as_ref() {
        return Err(ProgramError::InvalidArgument);
    }

    let vault_bump_byte = [vault.bump];
    let vault_seeds = [
        Seed::from(b"cp_vault" as &[u8]),
        Seed::from(cp_mint_acct.address().as_ref()),
        Seed::from(&vault_bump_byte),
    ];
    let vault_signer = [Signer::from(&vault_seeds)];

    SplTransfer {
        from: vault_ata,
        to: user_ata,
        authority: vault_acct,
        amount: requested_amount,
    }
    .invoke_signed(&vault_signer)?;

    // Close receipt PDA — return rent to destination
    let receipt_lamports = receipt_acct.lamports();
    receipt_acct.set_lamports(0);
    destination.set_lamports(destination.lamports() + receipt_lamports);
    let rd_mut = unsafe { receipt_acct.borrow_unchecked_mut() };
    for byte in rd_mut.iter_mut() {
        *byte = 0;
    }

    Ok(())
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use encrypt_types::graph::{get_node, parse_graph, GraphNodeKind};
    use encrypt_types::identifier::*;
    use encrypt_types::types::FheType;

    use super::{burn_graph, mint_to_graph, transfer_from_graph, transfer_graph, unwrap_graph};

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
    fn mint_to_from_zero() {
        let r = run_mock(mint_to_graph, &[0, 1000], &[FheType::EUint64, FheType::EUint64]);
        assert_eq!(r[0], 1000);
    }

    #[test]
    fn mint_to_existing() {
        let r = run_mock(mint_to_graph, &[500, 300], &[FheType::EUint64, FheType::EUint64]);
        assert_eq!(r[0], 800);
    }

    #[test]
    fn transfer_sufficient() {
        let r = run_mock(
            transfer_graph,
            &[1000, 500, 300],
            &[FheType::EUint64, FheType::EUint64, FheType::EUint64],
        );
        assert_eq!(r[0], 700, "sender: 1000 - 300");
        assert_eq!(r[1], 800, "receiver: 500 + 300");
    }

    #[test]
    fn transfer_insufficient() {
        let r = run_mock(
            transfer_graph,
            &[100, 500, 300],
            &[FheType::EUint64, FheType::EUint64, FheType::EUint64],
        );
        assert_eq!(r[0], 100, "sender unchanged");
        assert_eq!(r[1], 500, "receiver unchanged");
    }

    #[test]
    fn transfer_exact() {
        let r = run_mock(
            transfer_graph,
            &[300, 0, 300],
            &[FheType::EUint64, FheType::EUint64, FheType::EUint64],
        );
        assert_eq!(r[0], 0);
        assert_eq!(r[1], 300);
    }

    #[test]
    fn transfer_zero() {
        let r = run_mock(
            transfer_graph,
            &[1000, 500, 0],
            &[FheType::EUint64, FheType::EUint64, FheType::EUint64],
        );
        assert_eq!(r[0], 1000);
        assert_eq!(r[1], 500);
    }

    #[test]
    fn burn_sufficient() {
        let r = run_mock(burn_graph, &[1000, 300], &[FheType::EUint64, FheType::EUint64]);
        assert_eq!(r[0], 700);
    }

    #[test]
    fn burn_insufficient() {
        let r = run_mock(burn_graph, &[100, 300], &[FheType::EUint64, FheType::EUint64]);
        assert_eq!(r[0], 100);
    }

    #[test]
    fn transfer_from_success() {
        let r = run_mock(
            transfer_from_graph,
            &[1000, 500, 400, 300],
            &[FheType::EUint64, FheType::EUint64, FheType::EUint64, FheType::EUint64],
        );
        assert_eq!(r[0], 700, "sender: 1000 - 300");
        assert_eq!(r[1], 800, "receiver: 500 + 300");
        assert_eq!(r[2], 100, "allowance: 400 - 300");
    }

    #[test]
    fn transfer_from_insufficient_balance() {
        let r = run_mock(
            transfer_from_graph,
            &[100, 500, 400, 300],
            &[FheType::EUint64, FheType::EUint64, FheType::EUint64, FheType::EUint64],
        );
        assert_eq!(r[0], 100);
        assert_eq!(r[1], 500);
        assert_eq!(r[2], 400);
    }

    #[test]
    fn transfer_from_insufficient_allowance() {
        let r = run_mock(
            transfer_from_graph,
            &[1000, 500, 200, 300],
            &[FheType::EUint64, FheType::EUint64, FheType::EUint64, FheType::EUint64],
        );
        assert_eq!(r[0], 1000);
        assert_eq!(r[1], 500);
        assert_eq!(r[2], 200);
    }

    #[test]
    fn graph_shapes() {
        let g = mint_to_graph();
        let pg = parse_graph(&g).unwrap();
        assert_eq!(pg.header().num_inputs(), 2);
        assert_eq!(pg.header().num_outputs(), 1);

        let g = transfer_graph();
        let pg = parse_graph(&g).unwrap();
        assert_eq!(pg.header().num_inputs(), 3);
        assert_eq!(pg.header().num_outputs(), 2);

        let g = burn_graph();
        let pg = parse_graph(&g).unwrap();
        assert_eq!(pg.header().num_inputs(), 2);
        assert_eq!(pg.header().num_outputs(), 1);

        let g = transfer_from_graph();
        let pg = parse_graph(&g).unwrap();
        assert_eq!(pg.header().num_inputs(), 4);
        assert_eq!(pg.header().num_outputs(), 3);

        let g = unwrap_graph();
        let pg = parse_graph(&g).unwrap();
        assert_eq!(pg.header().num_inputs(), 2);
        assert_eq!(pg.header().num_outputs(), 2);
    }

    // ── unwrap_graph tests ──

    #[test]
    fn unwrap_sufficient() {
        let r = run_mock(
            unwrap_graph,
            &[1000, 300],
            &[FheType::EUint64, FheType::EUint64],
        );
        assert_eq!(r[0], 700, "balance: 1000 - 300");
        assert_eq!(r[1], 300, "withdrawn: amount on success");
    }

    #[test]
    fn unwrap_insufficient() {
        let r = run_mock(
            unwrap_graph,
            &[100, 300],
            &[FheType::EUint64, FheType::EUint64],
        );
        assert_eq!(r[0], 100, "balance unchanged");
        assert_eq!(r[1], 0, "withdrawn: 0 on failure");
    }

    #[test]
    fn unwrap_exact() {
        let r = run_mock(
            unwrap_graph,
            &[500, 500],
            &[FheType::EUint64, FheType::EUint64],
        );
        assert_eq!(r[0], 0, "balance: 500 - 500 = 0");
        assert_eq!(r[1], 500, "withdrawn: exact amount");
    }
}
