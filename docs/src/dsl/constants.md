# Constants

> **Pre-Alpha Disclaimer:** This is an early pre-alpha release for exploring the SDK and starting development only. There is no real encryption — all data is completely public and stored as plaintext on-chain. Do not submit any sensitive or real data. Encryption keys and the trust model are not final; do not rely on any encryption guarantees or key material until mainnet. All interfaces, APIs, and data formats are subject to change without notice. The Solana program and all on-chain data will be wiped periodically and everything will be deleted when we transition to Encrypt Alpha 1. This software is provided "as is" without warranty of any kind; use is entirely at your own risk and dWallet Labs assumes no liability for any damages arising from its use.


Constants are plaintext values embedded directly in the computation graph. The executor applies encryption automatically.

## Bare Literals

The simplest way — integer literals in expressions auto-promote:

```rust
#[encrypt_fn]
fn increment(count: EUint64) -> EUint64 {
    count + 1  // 1 is auto-promoted to an encrypted EUint64 constant
}
```

## Explicit Construction

For types that need explicit creation:

```rust
// Scalars (up to 128 bits)
let zero = EUint64::from(0u64);
let max = EUint128::from(u128::MAX);

// Big types (byte arrays)
let addr = EUint256::from([0xABu8; 32]);

// Vectors — from elements
let vec = EVectorU32::from_elements([1u32, 2, 3, 4]);

// Vectors — all same value
let ones = EVectorU64::splat(1u128);

// Boolean vectors — from bitmask
let mask = EBitVector16::from(0b1010_1010u128);
```

## Deduplication

Constants with the same `(fhe_type, bytes)` are automatically deduplicated in the graph. Writing `count + 1` twice produces a single constant node, not two.
