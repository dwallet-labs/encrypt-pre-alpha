# PC-Token: Overview

> **Pre-Alpha Disclaimer:** This is an early pre-alpha release for exploring the SDK and starting development only. There is no real encryption — all data is completely public and stored as plaintext on-chain. Do not submit any sensitive or real data. Encryption keys and the trust model are not final; do not rely on any encryption guarantees or key material until mainnet. All interfaces, APIs, and data formats are subject to change without notice. The Solana program and all on-chain data will be wiped periodically and everything will be deleted when we transition to Encrypt Alpha 1. This software is provided "as is" without warranty of any kind; use is entirely at your own risk and dWallet Labs assumes no liability for any damages arising from its use.

## What It Is

PC-Token (Confidential Performant Token) is a confidential token standard built on Encrypt FHE, modeled after Anza's [P-Token](https://github.com/anza-xyz/pinocchio/tree/main/programs/token). It replaces all plaintext balances and amounts with FHE-encrypted ciphertexts — same API surface as P-Token, full confidentiality.

## What's Confidential

- **Balances** — always encrypted. Nobody can see how much anyone holds.
- **Transfer amounts** — client-encrypted via gRPC. Never plaintext on-chain.
- **Allowances** — encrypted delegation for composability.
- **LP positions** — when used with PC-Swap, LP ownership is encrypted.

The only plaintext that ever appears is the withdrawal amount during unwrap, on a temporary receipt account that gets closed immediately.

## Architecture

```
Public Domain (SPL Token)         Confidential Domain (PC-Token)
┌─────────────────────┐           ┌──────────────────────────┐
│ USDC, SOL, etc.     │           │ pcUSDC, pcSOL, etc.      │
│ Balances visible    │── Wrap ──>│ Balances encrypted       │
│ Transfers visible   │<─ Unwrap ─│ Transfers encrypted      │
└─────────────────────┘           │ Composable with DeFi     │
                                  └──────────────────────────┘
```

## Instructions

| Disc | Instruction          | Description                                                  |
| ---- | -------------------- | ------------------------------------------------------------ |
| 0    | InitializeMint       | Create a new token mint                                      |
| 1    | InitializeAccount    | Create token account with encrypted zero balance             |
| 3    | Transfer             | Encrypted owner transfer                                     |
| 4    | Approve              | Approve delegate with encrypted allowance                    |
| 5    | Revoke               | Revoke delegation                                            |
| 10   | FreezeAccount        | Freeze authority freezes account                             |
| 11   | ThawAccount          | Freeze authority thaws account                               |
| 20   | TransferFrom         | Delegated transfer (allowance-based composability)           |
| 22   | TransferWithReceipt  | Owner-signed transfer that emits a binary receipt ciphertext |
| 23   | InitializeVault      | Create vault linking PC-Token mint to SPL mint               |
| 30   | Wrap                 | Deposit SPL → mint pcTokens (vault-backed)                   |
| 31   | UnwrapBurn           | Burn pcTokens, create withdrawal receipt                     |
| 32   | UnwrapDecrypt        | Decrypt burned amount                                        |
| 33   | UnwrapComplete       | Verify + release SPL, close receipt                          |

## Vault-Backed Only

There is no standalone `MintTo` or `Burn`. Tokens can only enter through `Wrap` (backed 1:1 by SPL tokens in the vault) and exit through the 3-step unwrap. Every pcToken is backed.

## Composability

PC-Token offers two composition patterns. Pick the one that matches the trust the calling program needs.

### Allowance-based (`Approve` + `TransferFrom`)

The user `Approve`s a delegate program with an encrypted allowance, then the delegate calls `TransferFrom` to move tokens. The delegate never sees plaintext — the allowance and amount are checked in FHE atomically. Suitable for flows where the calling program's only role is *authorized delivery* and it never needs proof that the transfer actually happened (e.g. a streaming-payments program that never reads downstream state).

### Receipt-based (`TransferWithReceipt`)

The owner CPIs (or directly calls) `TransferWithReceipt`, supplying a fresh receipt-ciphertext keypair and a `target_program` (typically the calling program's ID). The same FHE graph that updates `from.balance` and `to.balance` also outputs a *binary* receipt ciphertext:

```
receipt = amount    if from_balance >= amount
receipt = 0         otherwise
```

`TransferWithReceipt` then transfers the receipt's ACL to `target_program`, so the caller can read it in its own FHE graphs. This gives a downstream program a faithful, encrypted, *gated* signal of the deposit — never a partial value, never the from-balance — without any plaintext crossing the boundary. It is the pattern PC-Swap uses to keep its reserves consistent with what users actually deposited (see [PC-Swap: Overview](../pc-swap/01-overview.md)).

```rust
// In the calling program (e.g. PC-Swap):
//   1. Make sure amount_ct is authorized to pc-token
ctx.transfer_ciphertext(amount_ct, pc_token_program)?;
//   2. CPI TransferWithReceipt — emits receipt_ct, ACL goes to caller
cpi_pc_token_transfer_with_receipt(receipt_ct, target = caller_program_id)?;
//   3. Use receipt_ct in the calling program's own graphs (gates state updates)
ctx.my_graph(reserve_in, reserve_out, receipt_ct, ...)?;
//   4. Reclaim the receipt's rent
ctx.close_ciphertext(receipt_ct, payer)?;
```

The receipt is **owner-signed only** — there is no delegated variant. The receipt's `authorized` ACL is the calling program, so the receipt can also be decrypted by that program if it explicitly requests decryption; in practice composable programs never call `request_decryption` on intermediate ciphertexts and the audit trail of the source code is the assurance that they don't.
