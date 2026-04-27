# PC-Swap: Overview

> **Pre-Alpha Disclaimer:** This is an early pre-alpha release for exploring the SDK and starting development only. There is no real encryption — all data is completely public and stored as plaintext on-chain. Do not submit any sensitive or real data. Encryption keys and the trust model are not final; do not rely on any encryption guarantees or key material until mainnet. All interfaces, APIs, and data formats are subject to change without notice. The Solana program and all on-chain data will be wiped periodically and everything will be deleted when we transition to Encrypt Alpha 1. This software is provided "as is" without warranty of any kind; use is entirely at your own risk and dWallet Labs assumes no liability for any damages arising from its use.

## What It Is

PC-Swap is a confidential UniV2-style AMM built on Encrypt FHE. Reserves, swap amounts, and LP positions are all encrypted, and the pool's vaults are real PC-Token TokenAccounts owned by the pool PDA — so deposits and payouts compose with the rest of the confidential token domain through Encrypt CPI rather than through any plaintext bridge.

## What's Confidential

| Data                       | Visibility                                  |
| -------------------------- | ------------------------------------------- |
| Pool reserves (TVL)        | **Encrypted**                               |
| Swap amounts (trade sizes) | **Encrypted**                               |
| LP positions               | **Encrypted**                               |
| Withdrawn amounts          | **Encrypted**                               |
| Transaction activity       | **Visible** — that swaps happened, not what |

## Composability with PC-Token

The pool keeps its own encrypted reserve mirrors (`reserve_a`, `reserve_b`, `total_supply`) inside the `Pool` account, and a pair of vault PC-Token accounts (`vault_a`, `vault_b`) owned by the pool PDA holds the actual encrypted balances of the two underlying tokens.

Every flow goes through PC-Token's `TransferWithReceipt` (disc 22, see [PC-Token: Composability](../pc-token/01-overview.md#receipt-based-transferwithreceipt)). The receipt that comes out is binary — `amount` on a successful deposit, `0` on insufficient balance — and PC-Swap multiplies its mirror updates and payouts by it. That single design choice keeps the pool sound under any user-supplied `amount_in`:

```
User
  │
  ├── (no Approve needed — the user signs the swap tx as owner of the pcUSDC TA)
  │
  └── Swap pcUSDC → pcSOL  (PC-Swap)
       ├── CPI → PC-Token: TransferWithReceipt   (user pcUSDC → pool vault A,
       │                                          emits receipt_ct authorized
       │                                          to PC-Swap)
       ├── CPI → Encrypt:   swap_graph           (FHE math — every output gated
       │                                          on receipt_ct, never on the
       │                                          user's amount_in claim)
       ├── CPI → PC-Token: Transfer              (vault B → user pcSOL,
       │                                          signed by pool PDA)
       └── CPI → Encrypt:   close_ciphertext     (reclaim receipt rent)
```

`add_liquidity` is the same idea with two `TransferWithReceipt` calls (one per side) feeding `add_liquidity_graph`. `remove_liquidity` doesn't need a receipt — it gates on the user's encrypted `LpPosition.balance`, which is PC-Swap-internal and already trusted.

## Constant-Product Math, Receipt-Gated

The swap graph computes UniV2's `x · y = k` entirely in the encrypted domain, treating the **receipt** as the authoritative input — not the user's claim:

```rust
amount_in_with_fee = receipt * 997
amount_out         = (amount_in_with_fee * reserve_out)
                   / (reserve_in * 1000 + amount_in_with_fee)
```

- 0.3% fee baked in via the 997/1000 constants.
- Slippage protection: `amount_out >= min_amount_out`.
- If slippage fails → `final_in` and `final_out` collapse to 0 (no-op).
- If the user lied about `amount_in` (claimed more than they have) → `receipt = 0` from PC-Token → `final_in`, `final_out`, and both reserve deltas are all 0. The pool stays consistent, the user gets nothing.

## LP Token Enforcement

LP shares are per-user encrypted balances in `LpPosition` accounts (PC-Swap-internal — not real PC-Token mints). The graphs atomically update reserves, total supply, and the user's LP balance:

- **AddLiquidity** — first deposit: `lp = receipt_a`. Subsequent: proportional to `min(receipt_a · supply / reserve_a, receipt_b · supply / reserve_b)`. Both arms gated on the receipts.
- **RemoveLiquidity** — checks `user_lp >= burn_amount` in FHE. If insufficient, the entire operation is a no-op — reserves, supply, and LP balance unchanged.

Nobody can drain more LP than they own, and the ownership check happens inside the encrypted computation.

## Soundness Note

The receipt's ACL after `TransferWithReceipt` is PC-Swap. That means an audited PC-Swap binary that never calls `request_decryption` cannot leak the receipt's value — and the receipt's only value is one bit ("user was solvent for `amount_in`"). The user's signature on the swap transaction is consent for this. The principled long-term fix — splitting Encrypt's `authorized` into separate `compute_authorized` / `decrypt_authorized` ACLs so a program can read a ciphertext without being able to decrypt it — lives in the Encrypt program itself; until then, audited program source is the trust anchor.
