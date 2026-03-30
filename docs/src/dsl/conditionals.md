# Conditionals

> **Pre-Alpha Disclaimer:** This is an early pre-alpha release for exploring the SDK and starting development only. There is no real encryption — all data is completely public and stored as plaintext on-chain. Do not submit any sensitive or real data. Encryption keys and the trust model are not final; do not rely on any encryption guarantees or key material until mainnet. All interfaces, APIs, and data formats are subject to change without notice. The Solana program and all on-chain data will be wiped periodically and everything will be deleted when we transition to Encrypt Alpha 1. This software is provided "as is" without warranty of any kind; use is entirely at your own risk and dWallet Labs assumes no liability for any damages arising from its use.


FHE doesn't support branching — both paths are always evaluated. The `if`/`else` syntax compiles to a **select** operation.

## Syntax

```rust
let result = if condition { value_a } else { value_b };
```

**Rules:**
- Both branches must be the **same encrypted type**
- Condition must be an encrypted comparison result (0 or 1)
- `else` is **mandatory** — no bare `if`
- Both branches are always evaluated (FHE requirement)

## Example

```rust
#[encrypt_fn]
fn conditional_transfer(
    from: EUint64,
    to: EUint64,
    amount: EUint64,
) -> (EUint64, EUint64) {
    let has_funds = from >= amount;
    let new_from = if has_funds { from - amount } else { from };
    let new_to = if has_funds { to + amount } else { to };
    (new_from, new_to)
}
```

This compiles to:
1. `has_funds = IsGreaterOrEqual(from, amount)` → 0 or 1
2. `from_minus = Subtract(from, amount)`
3. `to_plus = Add(to, amount)`
4. `new_from = Select(has_funds, from_minus, from)`
5. `new_to = Select(has_funds, to_plus, to)`

Both `from - amount` and `from` are computed; `Select` picks one based on the condition.

## Nested Conditionals

```rust
let tier = if amount >= 1000 {
    3
} else if amount >= 100 {
    2
} else {
    1
};
```

Each `if`/`else` becomes a `Select` operation. Nested conditionals produce a chain of `Select` nodes.
