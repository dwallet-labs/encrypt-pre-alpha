# Tutorial: Confidential Voting

> **Pre-Alpha Disclaimer:** This is an early pre-alpha release for exploring the SDK and starting development only. There is no real encryption — all data is completely public and stored as plaintext on-chain. Do not submit any sensitive or real data. Encryption keys and the trust model are not final; do not rely on any encryption guarantees or key material until mainnet. All interfaces, APIs, and data formats are subject to change without notice. The Solana program and all on-chain data will be wiped periodically and everything will be deleted when we transition to Encrypt Alpha 1. This software is provided "as is" without warranty of any kind; use is entirely at your own risk and dWallet Labs assumes no liability for any damages arising from its use.


This tutorial builds a complete **confidential voting** program on Solana using Encrypt. Individual votes are encrypted -- nobody can see how anyone voted -- but the final tally is computed via FHE and can be decrypted by the proposal authority.

## What You Will Build

A Solana program with five instructions:

| Instruction | Description |
|-------------|-------------|
| `create_proposal` | Creates a proposal with two encrypted-zero tallies (yes, no) |
| `cast_vote` | Adds an encrypted vote to the tally via FHE computation |
| `close_proposal` | Authority closes voting |
| `request_tally_decryption` | Authority requests decryption of yes or no tally |
| `reveal_tally` | Authority reads decrypted result and writes plaintext to proposal |

## How It Works

1. The authority creates a proposal. Two ciphertext accounts are initialized to encrypted zero (`EUint64`).
2. Each voter provides an encrypted boolean vote (`EBool`): 1 = yes, 0 = no.
3. The `cast_vote_graph` FHE function conditionally increments the correct counter:
   - If vote == 1: `yes_count += 1`, `no_count` unchanged
   - If vote == 0: `no_count += 1`, `yes_count` unchanged
4. The tally ciphertext accounts are updated **in-place** (update mode) -- the same account serves as both input and output.
5. A `VoteRecord` PDA prevents double-voting. Its existence proves the voter already voted.
6. After closing, the authority requests decryption and verifies the result against a stored digest.

## Key Concepts Covered

- **`#[encrypt_fn]`** -- writing FHE computation as normal Rust
- **Plaintext ciphertext creation** -- initializing encrypted zeros via `create_plaintext_typed`
- **Update mode** -- passing the same account as both input and output to `execute_graph`
- **Digest verification** -- store-and-verify pattern for safe decryption
- **`EncryptTestContext`** -- testing the full lifecycle in a single test

## Framework Variants

The tutorial uses Pinocchio for maximum CU efficiency. Equivalent examples exist for all three frameworks:

| Framework | Source |
|-----------|--------|
| Pinocchio | `chains/solana/examples/confidential-voting-pinocchio/` |
| Anchor | `chains/solana/examples/confidential-voting-anchor/` |
| Native | `chains/solana/examples/confidential-voting-native/` |

## Prerequisites

- [Installation](../getting-started/installation.md) complete
- Familiarity with [Core Concepts](../getting-started/concepts.md)
- Basic Solana program development experience
