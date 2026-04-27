# PC-Swap: Building the Program

> **Pre-Alpha Disclaimer:** This is an early pre-alpha release for exploring the SDK and starting development only. There is no real encryption — all data is completely public and stored as plaintext on-chain. Do not submit any sensitive or real data. Encryption keys and the trust model are not final; do not rely on any encryption guarantees or key material until mainnet. All interfaces, APIs, and data formats are subject to change without notice. The Solana program and all on-chain data will be wiped periodically and everything will be deleted when we transition to Encrypt Alpha 1. This software is provided "as is" without warranty of any kind; use is entirely at your own risk and dWallet Labs assumes no liability for any damages arising from its use.

## Account Layouts

### Pool

The pool stores its own encrypted reserve mirrors plus the two vault accounts (real PC-Token TokenAccounts owned by the pool PDA — that's where the actual confidential balances live). PDA: `["pc_pool", mint_a, mint_b]`.

```rust
pub struct Pool {
    pub mint_a: [u8; 32],
    pub mint_b: [u8; 32],
    pub vault_a: [u8; 32],      // pc-token TokenAccount, owner = pool PDA
    pub vault_b: [u8; 32],      // pc-token TokenAccount, owner = pool PDA
    pub reserve_a: [u8; 32],    // encrypted reserve mirror (EUint64)
    pub reserve_b: [u8; 32],    // encrypted reserve mirror (EUint64)
    pub total_supply: [u8; 32], // encrypted LP total supply (EUint64)
    pub is_initialized: u8,
    pub bump: u8,
}
```

The reserve mirrors are kept encrypted alongside the vault state because the FHE swap math needs ciphertexts as inputs — pulling them out of the vault accounts on every swap would mean re-reading and re-validating those accounts in the graph, which would couple the pool layout to PC-Token's. Keeping the mirrors as the source of truth for the math while the vaults hold the *actual* tokens is the same separation P-Token uses for `Mint.supply` versus per-account `balance`.

### LpPosition

Per-user encrypted LP balance. PC-Swap-internal accounting — not a real PC-Token mint. PDA: `["pc_lp", pool, owner]`.

```rust
pub struct LpPosition {
    pub pool: [u8; 32],
    pub owner: [u8; 32],
    pub balance: [u8; 32],  // encrypted LP balance (EUint64)
    pub bump: u8,
}
```

## FHE Graphs

Every reserve update, payout amount, and LP balance change is a function of an encrypted *receipt* — never of a user-supplied amount directly. That's the soundness invariant the graphs are organized around.

### Swap

```rust
#[encrypt_fn]
fn swap_graph(
    reserve_in: EUint64,
    reserve_out: EUint64,
    receipt: EUint64,            // from pc-token::TransferWithReceipt
    min_amount_out: EUint64,
) -> (EUint64, EUint64, EUint64, EUint64) {
    let amount_in_with_fee = receipt * 997;
    let numer = amount_in_with_fee * reserve_out;
    let denom = (reserve_in * 1000) + amount_in_with_fee;
    let amount_out = numer / denom;

    let slip_ok = amount_out >= min_amount_out;
    let zero    = min_amount_out - min_amount_out;        // typed-zero source
    let final_in  = if slip_ok { receipt    } else { zero };
    let final_out = if slip_ok { amount_out } else { zero };

    let new_reserve_in  = reserve_in  + final_in;
    let new_reserve_out = reserve_out - final_out;

    (final_in, final_out, new_reserve_in, new_reserve_out)
}
```

Note that the user's `amount_in_ct` is not an input to `swap_graph` — it has already been handed over to PC-Token for `TransferWithReceipt`. The only gate that matters for soundness is `receipt`, which is `amount_in` on a real deposit and `0` on a no-op. `min_amount_out` doubles as the typed-zero source (`min_amount_out - min_amount_out`) for the slippage no-op branch.

### Add Liquidity

Two receipts (one per token) gate everything: reserve mirrors, total supply, and the user's LP balance.

```rust
#[encrypt_fn]
fn add_liquidity_graph(
    reserve_a: EUint64, reserve_b: EUint64, total_supply: EUint64,
    receipt_a: EUint64, receipt_b: EUint64,
    user_lp: EUint64,
) -> (EUint64, EUint64, EUint64, EUint64, EUint64, EUint64) {
    let new_reserve_a = reserve_a + receipt_a;
    let new_reserve_b = reserve_b + receipt_b;

    let initial_lp     = receipt_a;
    let lp_from_a      = (receipt_a * total_supply) / (reserve_a + 1);
    let lp_from_b      = (receipt_b * total_supply) / (reserve_b + 1);
    let subsequent_lp  = if lp_from_a >= lp_from_b { lp_from_b } else { lp_from_a };
    let is_subsequent  = total_supply >= 1;
    let lp_to_mint     = if is_subsequent { subsequent_lp } else { initial_lp };

    let new_total_supply = total_supply + lp_to_mint;
    let new_user_lp      = user_lp + lp_to_mint;

    (receipt_a, receipt_b, new_reserve_a, new_reserve_b,
     new_total_supply, new_user_lp)
}
```

If either `TransferWithReceipt` no-ops (insufficient balance on that side), the corresponding receipt is `0` and that arm of the LP math collapses, so reserves and supply stay consistent.

### Remove Liquidity

The withdrawal direction doesn't need a receipt — it's gated on the user's `LpPosition.balance`, which is PC-Swap-internal and already trusted.

```rust
#[encrypt_fn]
fn remove_liquidity_graph(
    reserve_a: EUint64, reserve_b: EUint64, total_supply: EUint64,
    burn: EUint64, user_lp: EUint64,
) -> (EUint64, EUint64, EUint64, EUint64, EUint64, EUint64) {
    let sufficient_lp = user_lp >= burn;
    // proportional withdrawal: amount = reserve * burn / supply
    // if !sufficient_lp → all outputs collapse to no-op
}
```

## Instructions

| Disc | Instruction      | Description                                                            |
| ---- | ---------------- | ---------------------------------------------------------------------- |
| 0    | CreatePool       | Create pool, vaults, encrypted reserves + LP supply (zero plaintexts)  |
| 1    | Swap             | TransferWithReceipt → swap_graph → vault→user transfer → close receipt |
| 2    | AddLiquidity     | TransferWithReceipt × 2 → add_liquidity_graph → close both receipts    |
| 4    | RemoveLiquidity  | remove_liquidity_graph → vault→user transfer × 2                       |
| 5    | CreateLpPosition | Create user's LP position account                                      |

### Dispatch — `swap` step by step

```
1. transfer_ciphertext(amount_in_ct, target = pc-token-program)
   ↳ hand the user's swap-amount ciphertext over to pc-token so it can read it

2. CPI pc-token::TransferWithReceipt
   ↳ user → vault_in deposit, emits receipt_ct, ACL goes back to pc-swap

3. swap_graph(reserve_in, reserve_out, receipt_ct, min_out_ct)
   ↳ receipt-gated math; outputs final_in, final_out, new reserves

4. transfer_ciphertext(amount_out_ct, target = pc-token-program)
   ↳ hand the payout ciphertext to pc-token for the second leg

5. CPI pc-token::Transfer (signed by pool PDA)
   ↳ vault_out → user payout

6. close_ciphertext(receipt_ct, payer)
   ↳ reclaim the receipt's rent
```

`add_liquidity` is two of step (2) before its graph; `remove_liquidity` is just steps (3)-(5) in the reverse direction with no receipt because the gate is `user_lp` instead.

## Security

- **Receipt-gated soundness** — every reserve / payout / LP-supply update is a function of a `TransferWithReceipt` receipt. A user lying about `amount_in` produces `receipt = 0` and every output collapses uniformly.
- **LP ownership** — `lp_pos.owner == payer` checked on every add/remove.
- **LP balance** — `user_lp >= burn_amount` checked in FHE on remove.
- **Slippage** — `amount_out >= min_amount_out` checked in FHE on swap.
- **No drain** — can't use another user's LpPosition (owner check).
- **No decrypt** — reserves and LP positions are permanently encrypted; the binary receipt is the only ciphertext PC-Swap holds an ACL for, and PC-Swap never calls `request_decryption`.
