# Confidential Counter: Overview

> **Pre-Alpha Disclaimer:** This is an early pre-alpha release for exploring the SDK and starting development only. There is no real encryption — all data is completely public and stored as plaintext on-chain. Do not submit any sensitive or real data. Encryption keys and the trust model are not final; do not rely on any encryption guarantees or key material until mainnet. All interfaces, APIs, and data formats are subject to change without notice. The Solana program and all on-chain data will be wiped periodically and everything will be deleted when we transition to Encrypt Alpha 1. This software is provided "as is" without warranty of any kind; use is entirely at your own risk and dWallet Labs assumes no liability for any damages arising from its use.

## What We're Building

A Solana counter whose value is always encrypted. Increment and decrement
happen via FHE -- the on-chain program never sees the plaintext. Only the
owner can request decryption to reveal the current count.

## Architecture

```
User (React app)
  |
  v
Solana Program (Anchor)
  |  CPI
  v
Encrypt Program
  |  emit_event
  v
Executor (off-chain)
  |  FHE computation
  v
Commit result on-chain
  |
  v
Decryptor (threshold MPC)
  |
  v
Plaintext available to owner
```

1. The **Anchor program** stores a `Counter` PDA with a reference to a ciphertext account.
2. When you call `increment`, the program issues a CPI to the Encrypt program
   with a precompiled FHE graph (`value + 1`). No computation happens on-chain.
3. An off-chain **executor** picks up the event, evaluates the graph using FHE,
   and commits the result back to the same ciphertext account.
4. To read the value, the owner calls `request_value_decryption`. A threshold
   **decryptor** network processes the request and writes the plaintext into a
   decryption request account.
5. The owner calls `reveal_value` to copy the verified plaintext into the
   counter state.

## What You'll Learn

- Writing FHE graphs with `#[encrypt_fn]`
- CPI to the Encrypt program via `EncryptContext`
- The store-and-verify digest pattern for decryption
- Building a React frontend that polls for executor/decryptor completion

## Prerequisites

- Rust (edition 2024, nightly or stable with Solana toolchain)
- Solana CLI + Platform Tools v1.54
- Anchor framework
- Bun (for the React frontend)

The executor and gRPC server are running on the pre-alpha environment at `https://pre-alpha-dev-1.encrypt.ika-network.net:443` -- no local setup needed.
