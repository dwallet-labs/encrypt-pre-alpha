# Encrypted ACL: Overview

> **Pre-Alpha Disclaimer:** This is an early pre-alpha release for exploring the SDK and starting development only. There is no real encryption — all data is completely public and stored as plaintext on-chain. Do not submit any sensitive or real data. Encryption keys and the trust model are not final; do not rely on any encryption guarantees or key material until mainnet. All interfaces, APIs, and data formats are subject to change without notice. The Solana program and all on-chain data will be wiped periodically and everything will be deleted when we transition to Encrypt Alpha 1. This software is provided "as is" without warranty of any kind; use is entirely at your own risk and dWallet Labs assumes no liability for any damages arising from its use.

## What We're Building

An on-chain access control list where permissions are stored as encrypted
bitmasks. Nobody -- not validators, not explorers, not other users -- can see
what permissions are set. Grant, revoke, and check operations happen via FHE
bitwise operations on encrypted `u64` values.

## Permission Model

Permissions are a 64-bit bitmask. Each bit represents a capability:

| Bit | Value | Permission |
|-----|-------|------------|
| 0   | 1     | READ       |
| 1   | 2     | WRITE      |
| 2   | 4     | EXECUTE    |
| 3   | 8     | ADMIN      |
| ... | ...   | Custom     |

All operations work on `EUint64` (encrypted unsigned 64-bit integer).

## Architecture

```
Admin                          Checker
  |                               |
  v                               v
grant_permission               check_permission
revoke_permission                 |
  |                               v
  v                         request_check_decryption
Encrypt CPI (FHE OR/AND)         |
  |                               v
  v                         reveal_check (nonzero = has permission)
Executor (off-chain FHE)
  |
  v
Commit result on-chain
```

Three FHE operations:
- **Grant**: `permissions | permission_bit` (bitwise OR)
- **Revoke**: `permissions & revoke_mask` (bitwise AND with inverse mask)
- **Check**: `permissions & permission_bit` (bitwise AND; nonzero = permitted)

## What You'll Learn

- Multiple FHE graphs in one program (grant, revoke, check)
- The inverse mask pattern for revocation
- Two state accounts (`Resource` + `AccessCheck`) with separate decryption flows
- Admin-gated operations vs. public permission checks

## Prerequisites

- Rust (edition 2024)
- Solana CLI + Platform Tools v1.54
- Anchor framework
