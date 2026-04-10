# CP-Swap: Building the Program

> **Pre-Alpha Disclaimer:** This is an early pre-alpha release for exploring the SDK and starting development only. There is no real encryption — all data is completely public and stored as plaintext on-chain. Do not submit any sensitive or real data. Encryption keys and the trust model are not final; do not rely on any encryption guarantees or key material until mainnet. All interfaces, APIs, and data formats are subject to change without notice. The Solana program and all on-chain data will be wiped periodically and everything will be deleted when we transition to Encrypt Alpha 1. This software is provided "as is" without warranty of any kind; use is entirely at your own risk and dWallet Labs assumes no liability for any damages arising from its use.

## Account Layouts

### Pool

```rust
pub struct Pool {
    pub mint_a: [u8; 32],
    pub mint_b: [u8; 32],
    pub reserve_a: [u8; 32],     // encrypted reserve A ciphertext
    pub reserve_b: [u8; 32],     // encrypted reserve B ciphertext
    pub total_supply: [u8; 32],  // encrypted LP total supply
    pub price_ct: [u8; 32],      // PUBLIC ciphertext (anyone can read)
    pub is_initialized: u8,
    pub bump: u8,
}
```

### LpPosition

Per-user encrypted LP balance. PDA: `["cp_lp", pool, owner]`.

```rust
pub struct LpPosition {
    pub pool: [u8; 32],
    pub owner: [u8; 32],
    pub balance: [u8; 32],  // encrypted LP balance ciphertext
    pub bump: u8,
}
```

## FHE Graphs

### Swap

```rust
#[encrypt_fn]
fn swap_graph(
    reserve_in: EUint128, reserve_out: EUint128,
    amount_in: EUint128, min_amount_out: EUint128,
    current_price: EUint128,
) -> (EUint128, EUint128, EUint128, EUint128) {
    // UniV2 formula with 0.3% fee
    let amount_in_with_fee = amount_in * 997;
    let numerator = amount_in_with_fee * reserve_out;
    let denominator = (reserve_in * 1000) + amount_in_with_fee;
    let amount_out = numerator / denominator;

    // k-invariant + slippage check
    // if invalid → no-op (reserves + price unchanged)

    // price = reserve_out * 1_000_000 / (reserve_in + 1)
    (final_out, final_reserve_in, final_reserve_out, final_price)
}
```

Uses `EUint128` for overflow safety (u64 reserves multiplied can exceed u64).

### Add Liquidity

```rust
#[encrypt_fn]
fn add_liquidity_graph(
    reserve_a: EUint128, reserve_b: EUint128, total_supply: EUint128,
    amount_a: EUint128, amount_b: EUint128, user_lp: EUint128,
) -> (EUint128, EUint128, EUint128, EUint128) {
    // First deposit: LP = amount_a * amount_b
    // Subsequent: LP = min(a * supply / ra, b * supply / rb)
    // Atomically updates: reserves + supply + user LP balance
}
```

### Remove Liquidity

```rust
#[encrypt_fn]
fn remove_liquidity_graph(
    reserve_a: EUint128, reserve_b: EUint128, total_supply: EUint128,
    burn_amount: EUint128, user_lp: EUint128,
) -> (EUint128, EUint128, EUint128, EUint128, EUint128, EUint128) {
    let sufficient = user_lp >= burn_amount;
    // If insufficient → entire operation is a no-op
    // Proportional withdrawal: amount = reserve * burn / supply
}
```

## Instructions

| Disc | Instruction | Description |
|------|-------------|-------------|
| 0 | CreatePool | Create pool with reserves + LP supply + public price |
| 1 | Swap | Constant product swap with price update |
| 2 | AddLiquidity | Deposit tokens, mint LP shares |
| 4 | RemoveLiquidity | Burn LP shares, withdraw reserves |
| 5 | CreateLpPosition | Create user's LP position account |

## Security

- **LP ownership**: `lp_pos.owner == payer` checked on every add/remove
- **LP balance**: `user_lp >= burn_amount` checked in FHE graph
- **K-invariant**: `new_k >= old_k` checked in FHE graph
- **Slippage**: `amount_out >= min_amount_out` checked in FHE graph
- **No drain**: can't use another user's LpPosition (owner check)
- **No decrypt**: reserves, LP positions are permanently encrypted