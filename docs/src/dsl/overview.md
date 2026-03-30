# The Encrypt DSL

> **Pre-Alpha Disclaimer:** This is an early pre-alpha release for exploring the SDK and starting development only. There is no real encryption — all data is completely public and stored as plaintext on-chain. Do not submit any sensitive or real data. Encryption keys and the trust model are not final; do not rely on any encryption guarantees or key material until mainnet. All interfaces, APIs, and data formats are subject to change without notice. The Solana program and all on-chain data will be wiped periodically and everything will be deleted when we transition to Encrypt Alpha 1. This software is provided "as is" without warranty of any kind; use is entirely at your own risk and dWallet Labs assumes no liability for any damages arising from its use.


The `#[encrypt_fn]` attribute macro lets you write FHE computation as normal Rust. The macro compiles it into a computation graph at compile time.

## Two Macros

| Macro | Crate | Generates |
|-------|-------|-----------|
| `#[encrypt_fn_graph]` | `encrypt-dsl` | Graph bytes function only (`fn name() -> Vec<u8>`) |
| `#[encrypt_fn]` | `encrypt-solana-dsl` | Graph bytes + Solana CPI extension trait |

Use `#[encrypt_fn]` for Solana programs. Use `#[encrypt_fn_graph]` for chain-agnostic graph generation (testing, analysis).

## What Gets Generated

```rust
#[encrypt_fn]
fn transfer(from: EUint64, to: EUint64, amount: EUint64) -> (EUint64, EUint64) {
    let has_funds = from >= amount;
    let new_from = if has_funds { from - amount } else { from };
    let new_to = if has_funds { to + amount } else { to };
    (new_from, new_to)
}
```

This generates:

1. **`transfer()`** → `Vec<u8>` — the serialized computation graph
2. **`TransferCpi`** — an extension trait implemented for all `EncryptCpi` types:

```rust
// Generated (simplified):
trait TransferCpi: EncryptCpi {
    fn transfer(
        &self,
        from: Self::Account<'_>,     // EUint64 input
        to: Self::Account<'_>,       // EUint64 input
        amount: Self::Account<'_>,   // EUint64 input
        __out_0: Self::Account<'_>,  // EUint64 output
        __out_1: Self::Account<'_>,  // EUint64 output
    ) -> Result<(), Self::Error>;
}

impl<T: EncryptCpi> TransferCpi for T {}
```

## Method Syntax

Call the generated function as a method on your `EncryptContext`:

```rust
ctx.transfer(from_ct, to_ct, amount_ct, new_from_ct, new_to_ct)?;
```

The trait is automatically in scope (generated in the same module as your `#[encrypt_fn]`).

## Type Safety

The generated function:
- Has one parameter per encrypted input (in order)
- Has one parameter per output (in order)
- Verifies each input's `fhe_type` matches the graph at runtime
- Returns an error if types don't match

This catches bugs like passing an `EBool` where an `EUint64` is expected.

## Update Mode

Output accounts can be either:
- **New accounts** (empty) → `execute_graph` creates a new Ciphertext
- **Existing accounts** (already has data) → `execute_graph` resets digest/status (reuses the account)

For update mode, pass the same account as both input and output:

```rust
// yes_ct is both input[0] and output[0]
ctx.cast_vote_graph(yes_ct, no_ct, vote_ct, yes_ct, no_ct)?;
```
