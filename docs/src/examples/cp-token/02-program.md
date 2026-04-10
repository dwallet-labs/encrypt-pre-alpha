# CP-Token: Building the Program

## Account Layouts

### Mint

Follows P-Token's COption pattern for optional authorities:

```rust
pub struct Mint {
    pub mint_authority_flag: [u8; 4],   // COption
    pub mint_authority: [u8; 32],
    pub decimals: u8,
    pub is_initialized: u8,
    pub freeze_authority_flag: [u8; 4], // COption
    pub freeze_authority: [u8; 32],
    pub bump: u8,
}
```

### TokenAccount

No plaintext fields. Balance is always encrypted:

```rust
pub struct TokenAccount {
    pub mint: [u8; 32],
    pub owner: [u8; 32],
    pub balance: EUint64,              // encrypted balance
    pub delegate_flag: [u8; 4],        // COption
    pub delegate: [u8; 32],
    pub state: u8,                     // Uninitialized/Initialized/Frozen
    pub allowance: EUint64,            // encrypted delegate allowance
    pub close_authority_flag: [u8; 4], // COption
    pub close_authority: [u8; 32],
    pub bump: u8,
}
```

## FHE Graphs

### Transfer (conditional)

```rust
#[encrypt_fn]
fn transfer_graph(
    from_balance: EUint64, to_balance: EUint64, amount: EUint64,
) -> (EUint64, EUint64) {
    let sufficient = from_balance >= amount;
    let new_from = if sufficient { from_balance - amount } else { from_balance };
    let new_to = if sufficient { to_balance + amount } else { to_balance };
    (new_from, new_to)
}
```

If the sender has insufficient funds, both balances remain unchanged — a privacy-preserving silent no-op. The chain cannot distinguish success from failure.

### Delegated Transfer (composability)

```rust
#[encrypt_fn]
fn transfer_from_graph(
    from_balance: EUint64, to_balance: EUint64,
    allowance: EUint64, amount: EUint64,
) -> (EUint64, EUint64, EUint64) {
    let sufficient_balance = from_balance >= amount;
    let sufficient_allowance = allowance >= amount;
    let can_transfer = sufficient_balance & sufficient_allowance;
    // if either check fails → no-op
    let new_from = if can_transfer { from_balance - amount } else { from_balance };
    let new_to = if can_transfer { to_balance + amount } else { to_balance };
    let new_allowance = if can_transfer { allowance - amount } else { allowance };
    (new_from, new_to, new_allowance)
}
```

Both balance AND allowance are checked atomically in the encrypted domain.

## Wrap / Unwrap

### Wrap (SPL → cpToken)

1. SPL transfer from user to vault (plaintext — the deposit is visible)
2. `mint_to_graph(balance, amount)` adds to encrypted balance
3. Amount ciphertext pre-created via gRPC (not `create_plaintext_typed`)

### Unwrap (cpToken → SPL)

Three-step flow that only reveals the withdrawal amount:

1. **UnwrapBurn** — `unwrap_burn_graph(balance, amount) → (new_balance, burned)`. `burned` = amount if sufficient, 0 if not. Creates a temporary `WithdrawalReceipt`.
2. **UnwrapDecrypt** — requests decryption of `burned` ciphertext.
3. **UnwrapComplete** — verifies `burned == requested_amount`. If yes → SPL transfer from vault. If no → no-op. Closes receipt.

The balance is never decrypted. Only the withdrawal amount appears on the temporary receipt.
