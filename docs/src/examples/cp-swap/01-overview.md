# CP-Swap: Overview

> **Pre-Alpha Disclaimer:** This is an early pre-alpha release for exploring the SDK and starting development only. There is no real encryption — all data is completely public and stored as plaintext on-chain. Do not submit any sensitive or real data. Encryption keys and the trust model are not final; do not rely on any encryption guarantees or key material until mainnet. All interfaces, APIs, and data formats are subject to change without notice. The Solana program and all on-chain data will be wiped periodically and everything will be deleted when we transition to Encrypt Alpha 1. This software is provided "as is" without warranty of any kind; use is entirely at your own risk and dWallet Labs assumes no liability for any damages arising from its use.

## What It Is

CP-Swap is a confidential UniV2 AMM built on Encrypt FHE. All reserves, swap amounts, and LP positions are encrypted. The only public value is the **price** — a public ciphertext readable by anyone via gRPC. Everything else is hidden.

## What's Confidential

| Data | Visibility |
|------|-----------|
| Pool reserves (TVL) | **Encrypted** — nobody can see |
| Swap amounts (trade sizes) | **Encrypted** — nobody can see |
| LP positions | **Encrypted** — nobody can see |
| Withdrawn amounts | **Encrypted** — nobody can see |
| Price (B per A) | **Public** — readable via gRPC |
| Transaction activity | **Visible** — that swaps happened, not what |

## Composability with CP-Token

CP-Swap demonstrates Encrypt's composability — it operates on encrypted ciphertexts through Encrypt CPI without seeing any plaintext:

```
User
  │
  ├── Approve CP-Swap as delegate on cpUSDC account (CP-Token)
  │
  ├── Swap cpUSDC → cpSOL (CP-Swap)
  │   ├── CPI → Encrypt: swap_graph (FHE math on encrypted reserves)
  │   └── CPI → CP-Token: transfer_from (move encrypted tokens)
  │
  └── Read price off-chain (gRPC readCiphertext — zero cost)
```

## Constant Product Formula

The swap graph computes UniV2's `x * y = k` entirely in the encrypted domain:

```rust
amount_out = (amount_in * 997 * reserve_out) / (reserve_in * 1000 + amount_in * 997)
```

- 0.3% fee baked as constants (997/1000)
- K-invariant enforced: `new_k >= old_k`
- Slippage protection: `amount_out >= min_amount_out`
- If either check fails → silent no-op (reserves unchanged)

## LP Token Enforcement

LP shares are per-user encrypted balances in `LpPosition` accounts. The FHE graphs atomically update reserves, total supply, AND the user's LP balance:

- **AddLiquidity**: computes proportional LP tokens, adds to user's balance
- **RemoveLiquidity**: checks `user_lp >= burn_amount` in FHE — if insufficient, entire operation is a no-op

Nobody can drain more LP than they own. The ownership check happens inside the encrypted computation.

## Public Price Oracle

The pool has a `price_ct` ciphertext made public via `make_public` during pool creation. After each swap, the graph outputs the new price. Anyone reads it via gRPC `readCiphertext` — zero on-chain cost.

For quotes: `expected_out ≈ amount_in × price / 1_000_000`. Client-side math, no on-chain transaction.

### Privacy Trade-off

The price leaks the reserve *ratio*, not the absolute values. A 10% price move could be a $100 trade on a $1,000 pool or a $1M trade on a $10M pool — observers can't tell. For maximum privacy (hidden price), remove the public price ciphertext and use blind swaps with slippage protection.