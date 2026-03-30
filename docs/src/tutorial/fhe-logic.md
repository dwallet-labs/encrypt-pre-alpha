# Write FHE Logic

> **Pre-Alpha Disclaimer:** This is an early pre-alpha release for exploring the SDK and starting development only. There is no real encryption — all data is completely public and stored as plaintext on-chain. Do not submit any sensitive or real data. Encryption keys and the trust model are not final; do not rely on any encryption guarantees or key material until mainnet. All interfaces, APIs, and data formats are subject to change without notice. The Solana program and all on-chain data will be wiped periodically and everything will be deleted when we transition to Encrypt Alpha 1. This software is provided "as is" without warranty of any kind; use is entirely at your own risk and dWallet Labs assumes no liability for any damages arising from its use.


The core of confidential voting is a single FHE function that conditionally increments the yes or no counter based on an encrypted vote.

## The `cast_vote_graph` Function

```rust
use encrypt_dsl::prelude::encrypt_fn;
use encrypt_types::encrypted::{EBool, EUint64};

#[encrypt_fn]
fn cast_vote_graph(
    yes_count: EUint64,
    no_count: EUint64,
    vote: EBool,
) -> (EUint64, EUint64) {
    let new_yes = if vote { yes_count + 1 } else { yes_count };
    let new_no = if vote { no_count } else { no_count + 1 };
    (new_yes, new_no)
}
```

## What the Macro Generates

The `#[encrypt_fn]` macro generates two things:

### 1. Graph bytes function

```rust
fn cast_vote_graph() -> Vec<u8>
```

Returns the serialized computation graph. The graph has:
- 3 inputs: `yes_count` (EUint64), `no_count` (EUint64), `vote` (EBool)
- 1 constant: the literal `1` (auto-promoted to an encrypted EUint64 constant)
- Operations: two `Add`, two `Select` (from the `if`/`else` expressions)
- 2 outputs: `new_yes` (EUint64), `new_no` (EUint64)

### 2. CPI extension trait

```rust
trait CastVoteGraphCpi: EncryptCpi {
    fn cast_vote_graph(
        &self,
        yes_count: Self::Account<'_>,   // EUint64 input
        no_count: Self::Account<'_>,    // EUint64 input
        vote: Self::Account<'_>,        // EBool input
        __out_0: Self::Account<'_>,     // EUint64 output
        __out_1: Self::Account<'_>,     // EUint64 output
    ) -> Result<(), Self::Error>;
}

impl<T: EncryptCpi> CastVoteGraphCpi for T {}
```

The trait is automatically implemented for all `EncryptCpi` types, so you call it as a method on `EncryptContext`.

## How `if`/`else` Works in FHE

FHE does not support branching -- both branches are always evaluated. The `if`/`else` syntax compiles to a **Select** operation:

```
1. has_funds = IsEqual(vote, 1)     -- condition (already EBool)
2. yes_plus  = Add(yes_count, 1)    -- both branches computed
3. no_plus   = Add(no_count, 1)
4. new_yes   = Select(vote, yes_plus, yes_count)
5. new_no    = Select(vote, no_count, no_plus)
```

Both `yes_count + 1` and `yes_count` (unchanged) are computed; `Select` picks one based on the condition. This is secure because the executor never learns which path was "taken."

## The Literal `1`

The integer literal `1` in `yes_count + 1` is auto-promoted to an encrypted constant in the graph. The constant is stored in the graph's constants section and deduplicated -- both occurrences of `+ 1` share the same constant node.

## Type Safety

The generated CPI method verifies each input account's `fhe_type` at runtime before making the CPI call:
- `yes_count` must be a Ciphertext with `fhe_type == EUint64`
- `no_count` must be a Ciphertext with `fhe_type == EUint64`
- `vote` must be a Ciphertext with `fhe_type == EBool`

If any type mismatches, the transaction fails before the CPI is invoked.

## Graph Shape

You can verify the graph structure in tests:

```rust
#[test]
fn graph_shape() {
    let d = cast_vote_graph();
    let pg = parse_graph(&d).unwrap();
    assert_eq!(pg.header().num_inputs(), 3, "yes_count + no_count + vote");
    assert_eq!(pg.header().num_outputs(), 2, "new_yes + new_no");
}
```

## Next Step

With the FHE logic defined, the next chapter implements proposal creation and encrypted-zero initialization.
