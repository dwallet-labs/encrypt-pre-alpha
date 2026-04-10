# Examples

> **Pre-Alpha Disclaimer:** This is an early pre-alpha release for exploring the SDK and starting development only. There is no real encryption — all data is completely public and stored as plaintext on-chain. Do not submit any sensitive or real data. Encryption keys and the trust model are not final; do not rely on any encryption guarantees or key material until mainnet. All interfaces, APIs, and data formats are subject to change without notice. The Solana program and all on-chain data will be wiped periodically and everything will be deleted when we transition to Encrypt Alpha 1. This software is provided "as is" without warranty of any kind; use is entirely at your own risk and dWallet Labs assumes no liability for any damages arising from its use.

Complete example programs demonstrating Encrypt on Solana. Each example includes the on-chain program (Anchor), tests, and where applicable a React frontend that runs against the pre-alpha executor on devnet.

All examples connect to the pre-alpha environment automatically:

| Resource           | Endpoint                                              |
| ------------------ | ----------------------------------------------------- |
| **Encrypt gRPC**   | `https://pre-alpha-dev-1.encrypt.ika-network.net:443` |
| **Solana Network** | Devnet (`https://api.devnet.solana.com`)              |

## Confidential Counter

An always-encrypted counter. Increment and decrement happen via FHE -- the on-chain program never sees the plaintext. Demonstrates the core Encrypt patterns: `#[encrypt_fn]`, CPI via `EncryptContext`, and the store-and-verify digest pattern for decryption.

**Covers:** FHE graphs, in-place ciphertext updates, polling for executor completion, React frontend with wallet adapter.

## Encrypted Coin Flip

Provably fair coin flip with on-chain escrow. Two sides commit encrypted values, the executor computes XOR via FHE, and the winner receives 2x from escrow. Neither side can see the other's value before committing.

**Covers:** XOR-based fairness, escrow pattern, player-vs-house architecture with automated Bun backend, full-stack React app.

## Confidential Voting

Encrypted voting where individual votes are hidden but the tally is computed via FHE. Voters cast encrypted yes/no votes (EBool), and the program conditionally increments encrypted counters using a Select operation. Only the authority can reveal final tallies.

**Covers:** Conditional FHE logic (if/else → Select), multi-output graphs, double-vote prevention via VoteRecord PDA, multi-wallet URL sharing, E2E demos in Rust + TypeScript (web3.js, kit, gill).

## Encrypted ACL

An on-chain access control list where permissions are stored as encrypted 64-bit bitmasks. Grant, revoke, and check operations use FHE bitwise operations (OR, AND). Nobody can see what permissions are set.

**Covers:** Multiple FHE graphs in one program, inverse mask pattern for revocation, separate state accounts with independent decryption flows, admin-gated vs public operations.

## CP-Token (Confidential Performant Token)

A composable confidential token program — Anza's [P-Token](https://github.com/anza-xyz/pinocchio/tree/main/programs/token) architecture rebuilt with Encrypt FHE. All balances and transfer amounts are encrypted; nobody can see how many tokens any account holds or how much is being transferred. Follows P-Token's COption flags, AccountState enum, instruction discriminators, and freeze/thaw patterns.

**Covers:** Encrypted balances (EUint64), client-encrypted transfer amounts, conditional FHE logic (insufficient funds → silent no-op), approve/transfer_from delegation for composability, freeze/thaw, vault-backed wrap/unwrap. Demonstrates how existing Solana token standards can be made confidential with Encrypt.

## CP-Swap (Confidential UniV2 AMM)

A confidential constant-product AMM that composes with CP-Token. All reserves, swap amounts, and LP positions are encrypted. The swap formula (x × y = k), fee calculation (0.3%), slippage protection, and LP ownership checks all run in the encrypted domain via FHE. The only public value is the price, published as a public ciphertext readable by anyone via gRPC.

**Covers:** FHE arithmetic (multiply, divide) on EUint128, composability (AMM CPI into Encrypt for swap math), public ciphertexts (`make_public` for price oracle), LP position enforcement in FHE graphs, self-settling no-ops for invalid swaps.
