# PC-Token: Building the Program

> **Pre-Alpha Disclaimer:** This is an early pre-alpha release for exploring the SDK and starting development only. There is no real encryption — all data is completely public and stored as plaintext on-chain. Do not submit any sensitive or real data. Encryption keys and the trust model are not final; do not rely on any encryption guarantees or key material until mainnet. All interfaces, APIs, and data formats are subject to change without notice. The Solana program and all on-chain data will be wiped periodically and everything will be deleted when we transition to Encrypt Alpha 1. This software is provided "as is" without warranty of any kind; use is entirely at your own risk and dWallet Labs assumes no liability for any damages arising from its use.

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

### Delegated Transfer (allowance composability)

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

### Transfer with Receipt (receipt-gated composability)

Same balance arithmetic as `transfer_graph`, plus a third output that is a *binary* receipt — exactly `amount` on a successful transfer, exactly `0` on insufficient balance, never a partial value. Downstream programs multiply their state updates by the receipt to gate them in lockstep with the actual transfer:

```rust
#[encrypt_fn]
fn transfer_receipt_graph(
    from_balance: EUint64, to_balance: EUint64, amount: EUint64,
) -> (EUint64, EUint64, EUint64) {
    let sufficient = from_balance >= amount;
    let zero = amount - amount;
    let actual = if sufficient { amount } else { zero };
    let new_from = from_balance - actual;
    let new_to   = to_balance   + actual;
    (new_from, new_to, actual)
}
```

The `TransferWithReceipt` handler:

1. Authorizes the transfer (owner-signer only — there is no delegated variant).
2. Calls `create_plaintext_typed::<Uint64>(0, receipt_ct)` to allocate the receipt account at a caller-supplied keypair, initially authorized to `pc-token`.
3. Runs `transfer_receipt_graph` with the three balance ciphertexts plus the receipt as outputs.
4. Calls `transfer_ciphertext(receipt_ct, target_program)` to move the receipt's ACL to whatever program the caller asked for.

After the instruction returns, the receipt sits Pending on-chain with its digest still being committed by the executor's normal event processing. By the time a downstream graph in the same transaction reads it, the digest has been written.

The **receipt invariant** (`actual ∈ {amount, 0}`, never partial) is what makes downstream gating work cleanly: a program that multiplies its state updates by the receipt either advances by the full intended amount or doesn't advance at all — there's no partial-credit edge case to write FHE branches for.

## Wrap / Unwrap

### Wrap (SPL → pcToken)

1. SPL transfer from user to vault (plaintext — the deposit is visible)
2. `mint_to_graph(balance, amount)` adds to encrypted balance
3. Amount ciphertext pre-created via gRPC (not `create_plaintext_typed`)

### Unwrap (pcToken → SPL)

Three-step flow that only reveals the withdrawal amount:

1. **UnwrapBurn** — `unwrap_burn_graph(balance, amount) → (new_balance, burned)`. `burned` = amount if sufficient, 0 if not. Creates a temporary `WithdrawalReceipt`.
2. **UnwrapDecrypt** — requests decryption of `burned` ciphertext.
3. **UnwrapComplete** — verifies `burned == requested_amount`. If yes → SPL transfer from vault. If no → no-op. Closes receipt.

The balance is never decrypted. Only the withdrawal amount appears on the temporary receipt.
