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
