# Encrypt Developer Guide

> **Pre-Alpha Disclaimer:** This is an early pre-alpha release for exploring the SDK and starting development only. There is no real encryption — all data is completely public and stored as plaintext on-chain. Do not submit any sensitive or real data. Encryption keys and the trust model are not final; do not rely on any encryption guarantees or key material until mainnet. All interfaces, APIs, and data formats are subject to change without notice. The Solana program and all on-chain data will be wiped periodically and everything will be deleted when we transition to Encrypt Alpha 1. This software is provided "as is" without warranty of any kind; use is entirely at your own risk and dWallet Labs assumes no liability for any damages arising from its use.

Encrypt enables smart contracts to **compute on encrypted data** without ever decrypting it on-chain. Your program operates on ciphertexts — the actual values are never visible to validators, indexers, or anyone else.

## How It Works

1. **You write FHE logic** using the `#[encrypt_fn]` DSL — it looks like normal Rust
2. **The macro compiles it** into a computation graph (a DAG of FHE operations)
3. **On-chain**, `execute_graph` creates output ciphertext accounts and emits events
4. **Off-chain**, the executor evaluates the graph using real FHE and commits results
5. **When needed**, you request decryption — the decryptor responds with plaintext

```rust
#[encrypt_fn]
fn transfer(from: EUint64, to: EUint64, amount: EUint64) -> (EUint64, EUint64) {
    let has_funds = from >= amount;
    let new_from = if has_funds { from - amount } else { from };
    let new_to = if has_funds { to + amount } else { to };
    (new_from, new_to)
}
```

This compiles into an FHE computation graph that operates on encrypted balances. Nobody on-chain ever sees the actual amounts.

## What You'll Learn

- **Getting Started**: Install dependencies, create your first encrypted program
- **Tutorial**: Build a complete confidential voting application step by step
- **DSL Reference**: All supported types, operations, and patterns
- **On-Chain Integration**: Ciphertext accounts, access control, graph execution, decryption
- **Framework Guides**: Pinocchio, Anchor, and Native examples
- **Testing**: Local test framework, CLI tools, mock vs real FHE
- **Reference**: Complete instruction, account, event, and fee documentation

## Supported Frameworks

Encrypt works with all three major Solana program frameworks:

| Framework | SDK Crate | Best For |
|-----------|-----------|----------|
| **Pinocchio** | `encrypt-pinocchio` | Maximum CU efficiency, `#![no_std]` programs |
| **Anchor** | `encrypt-anchor` | Rapid development, declarative accounts |
| **Native** | `encrypt-native` | `solana-program` users, no framework lock-in |

All three use the same `#[encrypt_fn]` DSL and the same `EncryptCpi` trait.
