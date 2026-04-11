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

| Disc | Instruction       | Description                                      |
| ---- | ----------------- | ------------------------------------------------ |
| 0    | InitializeMint    | Create a new token mint                          |
| 1    | InitializeAccount | Create token account with encrypted zero balance |
| 3    | Transfer          | Encrypted owner transfer                         |
| 4    | Approve           | Approve delegate with encrypted allowance        |
| 5    | Revoke            | Revoke delegation                                |
| 10   | FreezeAccount     | Freeze authority freezes account                 |
| 11   | ThawAccount       | Freeze authority thaws account                   |
| 20   | TransferFrom      | Delegated transfer (composability entry point)   |
| 23   | InitializeVault   | Create vault linking PC-Token mint to SPL mint   |
| 30   | Wrap              | Deposit SPL → mint pcTokens (vault-backed)       |
| 31   | UnwrapBurn        | Burn pcTokens, create withdrawal receipt         |
| 32   | UnwrapDecrypt     | Decrypt burned amount                            |
| 33   | UnwrapComplete    | Verify + release SPL, close receipt              |

## Vault-Backed Only

There is no standalone `MintTo` or `Burn`. Tokens can only enter through `Wrap` (backed 1:1 by SPL tokens in the vault) and exit through the 3-step unwrap. Every pcToken is backed.

## Composability

Other programs CPI into PC-Token via `Approve` + `TransferFrom`. The delegate (another program's PDA) can move tokens on behalf of the user, with encrypted allowance enforcement:

```rust
// DeFi program (e.g., AMM, lending, dark pool)
fn execute_trade(accounts) {
    // CPI into PC-Token — move pcUSDC from user to pool
    pc_token::transfer_from(user_account, pool_account, amount_ct, delegate_pda);
}
```

The DeFi program never sees plaintext amounts. It just passes encrypted ciphertexts through CPI.